"""Machine Learning-based sensitive field analyzer.

Uses a Random Forest classifier for sensitive-field classification and optional
sentence-transformer embeddings for semantic support when available.
"""

from typing import Dict, List, Optional, Tuple
import os
import re
from dataclasses import dataclass
import numpy as np
from src.scanner.base_scanner import BaseScanner
from src.reporters.models import Finding
from src.config import SEVERITY_HIGH, SEVERITY_MEDIUM, CATEGORY_AUDIT

# Suppress noisy tqdm/transformers/safetensors progress bars on stderr
os.environ.setdefault('TRANSFORMERS_NO_ADVISORY_WARNINGS', '1')
os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
os.environ['TQDM_DISABLE'] = '1'

# Optional embedding dependency
try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics.pairwise import cosine_similarity
    RANDOM_FOREST_AVAILABLE = True
except ImportError:
    RANDOM_FOREST_AVAILABLE = False


@dataclass
class FieldFeatures:
    """Features extracted from a GraphQL field for ML analysis."""
    name: str
    type_name: str
    parent_type: str
    is_nullable: bool
    has_args: bool
    depth_in_schema: int
    
    # Semantic features
    name_length: int
    has_id_suffix: bool
    has_sensitive_substrings: int
    camel_case_parts: List[str]
    type_is_custom: bool
    parent_is_query: bool
    parent_is_mutation: bool
    
    # Context features
    sibling_field_count: int
    has_sensitive_siblings: bool


class MLSemanticAnalyzer(BaseScanner):
    """
    ML-powered analyzer for sensitive GraphQL fields.
    
    Approach:
    1. Extracts lexical, type, parent, argument, and context features
    2. Uses a Random Forest classifier trained from labelled seed examples
    3. Optionally adds sentence-transformer semantic similarity when installed
    4. Falls back to deterministic heuristic scoring if scikit-learn is missing
    
    Scoring formula:
        score = weighted(RandomForest, lexical, fuzzy, embedding, context)
    """
    
    # PII concept list for semantic similarity (SGAFuzzer-inspired)
    PII_CONCEPTS = [
        # Authentication & Authorization
        "password secret credential authentication token",
        "api key access token authorization bearer",
        "session id refresh token jwt",
        "oauth secret client secret",
        
        # Personal Identifiable Information
        "email address contact email",
        "phone number mobile telephone contact number",
        "social security number SSN national id NRIC passport",
        "credit card number bank account card CVV PIN",
        "date of birth birthday age",
        "home address street address postal code",
        
        # Sensitive Personal Data
        "medical record health information diagnosis",
        "salary income financial information",
        "biometric fingerprint face recognition",
        "ip address location gps coordinates",
        
        # Security-sensitive
        "private key encryption key cryptographic key",
        "hash salt cryptographic hash",
        "otp one time password verification code",
    ]
    
    # Keyword patterns with weights (lexical matching - w1)
    SENSITIVE_PATTERNS = {
        'password': 1.0,
        'passwd': 1.0,
        'pwd': 0.9,
        'secret': 1.0,
        'token': 0.9,
        'key': 0.7,
        'auth': 0.8,
        'credential': 1.0,
        'ssn': 1.0,
        'social_security': 1.0,
        'nric': 1.0,
        'passport': 0.9,
        'credit_card': 1.0,
        'card_number': 1.0,
        'cvv': 1.0,
        'pin': 0.8,
        'otp': 0.8,
        'salt': 0.9,
        'hash': 0.7,
        'private': 0.8,
        'confidential': 0.9,
        'session': 0.7,
        'api_key': 1.0,
        'access': 0.6,
        'refresh': 0.7,
        'email': 0.8,
        'phone': 0.8,
        'address': 0.7,
        'medical': 0.9,
        'salary': 0.9,
        'income': 0.8,
    }
    
    # Type patterns that reduce sensitivity (common patterns)
    SAFE_TYPE_PATTERNS = {
        'ID': -0.3,
        'Boolean': -0.2,
        'Int': -0.1,
        'DateTime': -0.2,
    }
    
    # Context modifiers
    SAFE_PARENT_NAMES = ['Config', 'Settings', 'Metadata', 'Status']
    SAFE_FIELD_SUFFIXES = ['Id', 'Count', 'Total', 'Status', 'Type', 'Date', 'Policy']

    MODEL_PATTERNS = (
        'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth',
        'credential', 'ssn', 'nric', 'passport', 'credit', 'card', 'cvv',
        'pin', 'otp', 'salt', 'hash', 'private', 'session', 'email',
        'phone', 'address', 'medical', 'salary', 'income'
    )

    TRAINING_FIELDS = (
        # Sensitive authentication and secret material
        ('password', 'String', 'User', 1),
        ('passwordHash', 'String', 'User', 1),
        ('oldPassword', 'String', 'Mutation', 1),
        ('accessToken', 'String', 'Login', 1),
        ('refreshToken', 'String', 'Login', 1),
        ('apiKey', 'String', 'Integration', 1),
        ('clientSecret', 'String', 'OAuthClient', 1),
        ('privateKey', 'String', 'KeyPair', 1),
        ('sessionToken', 'String', 'Session', 1),
        ('otpCode', 'String', 'MfaChallenge', 1),
        ('pin', 'String', 'PaymentAccount', 1),
        ('cvv', 'String', 'Card', 1),
        ('creditCardNumber', 'String', 'PaymentMethod', 1),
        ('ssn', 'String', 'Profile', 1),
        ('nric', 'String', 'Profile', 1),
        ('passportNumber', 'String', 'Profile', 1),
        ('medicalRecordNumber', 'String', 'Patient', 1),
        ('salary', 'Float', 'Employee', 1),
        ('income', 'Float', 'TaxProfile', 1),
        ('email', 'String', 'User', 1),
        ('phoneNumber', 'String', 'User', 1),
        ('homeAddress', 'String', 'User', 1),
        # Common non-sensitive or lower-risk fields
        ('id', 'ID', 'User', 0),
        ('userId', 'ID', 'Post', 0),
        ('title', 'String', 'Post', 0),
        ('content', 'String', 'Post', 0),
        ('createdAt', 'DateTime', 'Post', 0),
        ('updatedAt', 'DateTime', 'Post', 0),
        ('status', 'String', 'Job', 0),
        ('type', 'String', 'Event', 0),
        ('count', 'Int', 'PageInfo', 0),
        ('total', 'Int', 'PageInfo', 0),
        ('isActive', 'Boolean', 'User', 0),
        ('displayName', 'String', 'User', 0),
        ('username', 'String', 'User', 0),
        ('avatarUrl', 'String', 'User', 0),
        ('publicKeyId', 'ID', 'KeyMetadata', 0),
        ('tokenCount', 'Int', 'Usage', 0),
        ('passwordPolicy', 'String', 'Config', 0),
        ('emailVerified', 'Boolean', 'User', 0),
        ('addressId', 'ID', 'Order', 0),
        ('sessionCount', 'Int', 'Analytics', 0),
    )
    
    def __init__(self, endpoint: str, schema: Dict, config: Dict = None, graph: Dict = None):
        super().__init__(endpoint, schema, config, graph)
        self.sensitivity_threshold = 0.65  # Configurable threshold
        
        # Scoring weights (can be tuned with labeled data later)
        self.w_rf = 0.45
        self.w1_lexical = 0.25
        self.w2_fuzzy = 0.10
        self.w3_embedding = 0.10
        self.w4_context = 0.10
        
        self.rf_model = None
        self._init_random_forest()

        # Initialize optional pretrained embedding model (lazy loading)
        self.embedding_model = None
        self.pii_embeddings = None
        self._init_embeddings()

    def _init_random_forest(self):
        """Train a small Random Forest classifier from labelled seed fields."""
        if not RANDOM_FOREST_AVAILABLE:
            self.logger.warning("Random Forest unavailable - using heuristic ML scoring")
            return

        try:
            rows = []
            labels = []
            for name, type_name, parent_type, label in self.TRAINING_FIELDS:
                features = self._training_features(name, type_name, parent_type)
                lexical_score = self._compute_lexical_score(features.name)
                fuzzy_score = self.compute_fuzzy_match_score(features.name)
                context_score = self._compute_context_score(features)
                rows.append(
                    self._model_vector(
                        features,
                        lexical_score=lexical_score,
                        fuzzy_score=fuzzy_score,
                        embedding_score=0.0,
                        context_score=context_score,
                    )
                )
                labels.append(label)

            self.rf_model = RandomForestClassifier(
                n_estimators=80,
                max_depth=6,
                min_samples_leaf=1,
                class_weight="balanced",
                random_state=42,
            )
            self.rf_model.fit(np.array(rows, dtype=float), np.array(labels, dtype=int))
            self.logger.info("Random Forest sensitive-field classifier initialized")
        except Exception as exc:
            self.logger.warning(f"Failed to initialize Random Forest: {exc}")
            self.rf_model = None

    def _training_features(self, name: str, type_name: str, parent_type: str) -> FieldFeatures:
        lower_name = name.lower()
        camel_parts = self._split_camel_case(name)
        sensitive_count = sum(
            1 for pattern in self.SENSITIVE_PATTERNS
            if self._pattern_matches_field(pattern, name, lower_name)
        )
        return FieldFeatures(
            name=name,
            type_name=type_name,
            parent_type=parent_type,
            is_nullable=True,
            has_args=False,
            depth_in_schema=1,
            name_length=len(name),
            has_id_suffix=name.endswith('Id') or name.endswith('ID'),
            has_sensitive_substrings=sensitive_count,
            camel_case_parts=camel_parts,
            type_is_custom=type_name not in ['String', 'Int', 'Float', 'Boolean', 'ID'],
            parent_is_query=parent_type in ['Query', 'query'],
            parent_is_mutation=parent_type in ['Mutation', 'Mutations', 'mutation'],
            sibling_field_count=0,
            has_sensitive_siblings=False,
        )

    def _compute_lexical_score(self, field_name: str) -> float:
        field_lower = field_name.lower()
        lexical_score = 0.0
        for pattern, weight in self.SENSITIVE_PATTERNS.items():
            if self._pattern_matches_field(pattern, field_name, field_lower):
                lexical_score = max(lexical_score, weight)
        return min(lexical_score, 1.0)

    def _field_tokens(self, field_name: str) -> List[str]:
        tokens = []
        for part in self._split_camel_case(field_name):
            tokens.extend(token for token in re.split(r"[^a-zA-Z0-9]+", part.lower()) if token)
        if not tokens:
            tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", field_name.lower()) if token]
        return tokens

    def _pattern_matches_field(self, pattern: str, field_name: str, field_lower: str | None = None) -> bool:
        tokens = self._field_tokens(field_name)
        normalized = "".join(tokens)
        pattern_tokens = [token for token in pattern.lower().split("_") if token]
        field_lower = field_lower or field_name.lower()

        if not pattern_tokens:
            return False

        if len(pattern_tokens) > 1:
            return "".join(pattern_tokens) in normalized

        token = pattern_tokens[0]
        if token in tokens:
            return True

        if token in {"key", "pin", "id"}:
            return False

        return token in field_lower

    def _looks_like_sensitive_value_name(self, field_name: str) -> bool:
        if any(field_name.endswith(suffix) for suffix in self.SAFE_FIELD_SUFFIXES):
            return False
        if field_name.endswith('Id') or field_name.endswith('ID'):
            return False
        return self._compute_lexical_score(field_name) >= 0.7

    def _compute_context_score(self, features: FieldFeatures) -> float:
        context_score = 0.5

        if features.type_name == 'String':
            context_score += 0.2
        if not features.is_nullable:
            context_score += 0.1
        if features.has_sensitive_siblings:
            context_score += 0.2
        if features.has_sensitive_substrings > 1:
            context_score += 0.1

        if features.has_id_suffix:
            context_score -= 0.3
        if any(safe in features.parent_type for safe in self.SAFE_PARENT_NAMES):
            context_score -= 0.2
        if any(features.name.endswith(suffix) for suffix in self.SAFE_FIELD_SUFFIXES):
            context_score -= 0.15
        if features.name_length < 4:
            context_score -= 0.1
        if features.type_is_custom:
            context_score -= 0.1

        for type_pattern, adjustment in self.SAFE_TYPE_PATTERNS.items():
            if type_pattern in features.type_name:
                context_score += adjustment

        return min(max(context_score, 0.0), 1.0)

    def _model_vector(
        self,
        features: FieldFeatures,
        lexical_score: float,
        fuzzy_score: float,
        embedding_score: float,
        context_score: float,
    ) -> List[float]:
        name_lower = features.name.lower()
        parent_lower = features.parent_type.lower()
        type_name = features.type_name

        vector = [
            lexical_score,
            fuzzy_score,
            embedding_score,
            context_score,
            min(features.name_length / 40.0, 1.0),
            float(features.has_id_suffix),
            min(features.has_sensitive_substrings / 3.0, 1.0),
            float(features.is_nullable),
            float(features.has_args),
            float(features.type_is_custom),
            float(features.parent_is_query),
            float(features.parent_is_mutation),
            min(features.sibling_field_count / 20.0, 1.0),
            float(features.has_sensitive_siblings),
            float(type_name == 'String'),
            float(type_name == 'ID'),
            float(type_name in ['Int', 'Float']),
            float(type_name == 'Boolean'),
            float(any(token in parent_lower for token in ('user', 'login', 'auth', 'session', 'account', 'profile', 'payment'))),
        ]
        vector.extend(float(pattern in name_lower) for pattern in self.MODEL_PATTERNS)
        return vector

    def _predict_random_forest_score(
        self,
        features: FieldFeatures,
        lexical_score: float,
        fuzzy_score: float,
        embedding_score: float,
        context_score: float,
    ) -> float:
        if self.rf_model is None:
            return 0.0

        try:
            vector = self._model_vector(
                features,
                lexical_score=lexical_score,
                fuzzy_score=fuzzy_score,
                embedding_score=embedding_score,
                context_score=context_score,
            )
            probabilities = self.rf_model.predict_proba(np.array([vector], dtype=float))[0]
            return float(probabilities[1])
        except Exception as exc:
            self.logger.debug(f"Random Forest scoring failed for {features.name}: {exc}")
            return 0.0
    
    def _init_embeddings(self):
        """Initialize pretrained embedding model and PII concept embeddings."""
        if not self.config.get("ml_embeddings", False):
            self.logger.info("Embedding model disabled - using Random Forest classifier only")
            return

        if not EMBEDDINGS_AVAILABLE:
            self.logger.warning("Embeddings not available - using Random Forest classifier only")
            return
        
        try:
            self.logger.info("Loading pretrained embedding model (all-MiniLM-L6-v2)...")
            # Use lightweight, fast model (22MB, 384 dims)
            # Alternative: 'all-mpnet-base-v2' (420MB, better quality)
            import io
            import sys
            import contextlib

            # Redirect stderr to suppress safetensors tqdm progress bars
            _real_stderr = sys.stderr
            sys.stderr = io.StringIO()
            try:
                self.embedding_model = SentenceTransformer(
                    'sentence-transformers/all-MiniLM-L6-v2'
                )
            finally:
                sys.stderr = _real_stderr
            
            # Precompute PII concept embeddings
            self.pii_embeddings = self.embedding_model.encode(
                self.PII_CONCEPTS,
                convert_to_numpy=True,
                show_progress_bar=False
            )
            self.logger.info(f"Loaded embeddings: {len(self.PII_CONCEPTS)} PII concepts")
            
        except Exception as e:
            self.logger.warning(f"Failed to load embeddings: {e}. Falling back to keywords only.")
            self.embedding_model = None
            self.pii_embeddings = None
    
    def compute_semantic_similarity(self, field_name: str, field_description: str = "") -> float:
        """Compute semantic similarity between field and PII concepts using embeddings.
        
        This is the core ML inference component (w3).
        
        Args:
            field_name: GraphQL field name
            field_description: Field description from schema (if available)
            
        Returns:
            Maximum cosine similarity score (0.0 to 1.0)
        """
        if not self.embedding_model or self.pii_embeddings is None:
            return 0.0  # Fallback to 0 if embeddings unavailable
        
        try:
            # Combine name and description for richer semantic context
            # Split camelCase: "accessToken" -> "access token"
            name_parts = ' '.join(self._split_camel_case(field_name)).lower()
            text = f"{name_parts} {field_description}".strip()
            
            # Encode field text
            field_embedding = self.embedding_model.encode(
                [text],
                convert_to_numpy=True,
                show_progress_bar=False
            )
            
            # Compute cosine similarity with all PII concepts
            similarities = cosine_similarity(field_embedding, self.pii_embeddings)[0]
            
            # Return max similarity (best match)
            max_similarity = float(np.max(similarities))
            
            return max_similarity
            
        except Exception as e:
            self.logger.debug(f"Embedding similarity failed for {field_name}: {e}")
            return 0.0
    
    def compute_fuzzy_match_score(self, field_name: str) -> float:
        """Compute fuzzy string matching score (w2).
        
        Uses character-level overlap with PII keywords.
        
        Args:
            field_name: GraphQL field name
            
        Returns:
            Fuzzy match score (0.0 to 1.0)
        """
        field_lower = field_name.lower()
        max_overlap = 0.0
        
        for pattern in self.SENSITIVE_PATTERNS.keys():
            if pattern in field_lower:
                # Exact substring match
                overlap = len(pattern) / len(field_lower)
                max_overlap = max(max_overlap, overlap)
            else:
                # Character overlap (simple Jaccard)
                set_field = set(field_lower)
                set_pattern = set(pattern)
                intersection = len(set_field & set_pattern)
                union = len(set_field | set_pattern)
                if union > 0:
                    jaccard = intersection / union
                    max_overlap = max(max_overlap, jaccard * 0.5)  # Discount partial matches
        
        return min(max_overlap, 1.0)
        
    def extract_features(self, field: Dict, parent_type: Dict, type_map: Dict) -> FieldFeatures:
        """
        Extract features from a field for ML-based analysis.
        
        Args:
            field: Field definition from schema
            parent_type: Parent type containing this field
            type_map: Schema type map
            
        Returns:
            FieldFeatures object with extracted features
        """
        field_name = field['name']
        field_type = field['type']
        
        # Unwrap type to get base type
        type_name = self._get_scalar_type_name(field_type)
        is_nullable = field_type.get('kind') != 'NON_NULL'
        
        # Extract camel case parts
        camel_parts = self._split_camel_case(field_name)
        
        # Check if type is custom
        type_is_custom = type_name not in ['String', 'Int', 'Float', 'Boolean', 'ID']
        
        # Parent context
        parent_name = parent_type['name']
        parent_is_query = parent_name in ['Query', 'query']
        parent_is_mutation = parent_name in ['Mutation', 'Mutations', 'mutation']
        
        # Sibling analysis
        sibling_count = len(parent_type.get('fields', []))
        sibling_names = [f['name'] for f in parent_type.get('fields', []) if f.get('name') != field_name]
        has_sensitive_siblings = any(
            self._looks_like_sensitive_value_name(name)
            for name in sibling_names
        )
        
        # Count sensitive substrings
        field_lower = field_name.lower()
        sensitive_count = sum(
            1 for pattern in self.SENSITIVE_PATTERNS.keys()
            if self._pattern_matches_field(pattern, field_name, field_lower)
        )
        
        return FieldFeatures(
            name=field_name,
            type_name=type_name,
            parent_type=parent_name,
            is_nullable=is_nullable,
            has_args=len(field.get('args', [])) > 0,
            depth_in_schema=1,  # Could be calculated from graph
            name_length=len(field_name),
            has_id_suffix=field_name.endswith('Id') or field_name.endswith('ID'),
            has_sensitive_substrings=sensitive_count,
            camel_case_parts=camel_parts,
            type_is_custom=type_is_custom,
            parent_is_query=parent_is_query,
            parent_is_mutation=parent_is_mutation,
            sibling_field_count=sibling_count,
            has_sensitive_siblings=has_sensitive_siblings
        )
    
    def calculate_sensitivity_score(self, features: FieldFeatures, field_description: str = "") -> Tuple[float, Dict[str, float]]:
        """Calculate sensitivity score using weighted ML approach.
        
        Formula: score = w1*(lexical) + w2*(fuzzy) + w3*(embedding_similarity) + w4*(context)
        
        Args:
            features: Extracted field features
            field_description: Field description from schema
            
        Returns:
            Tuple of (final_score, component_scores)
        """
        # Component 1: Lexical keyword matching (w1)
        lexical_score = self._compute_lexical_score(features.name)
        
        # Component 2: Fuzzy string matching (w2)
        fuzzy_score = self.compute_fuzzy_match_score(features.name)
        
        # Component 3: Semantic similarity using embeddings (w3) - THE ML PART
        embedding_score = self.compute_semantic_similarity(features.name, field_description)
        
        # Component 4: Context features (w4)
        context_score = self._compute_context_score(features)

        # Component 5: Random Forest classifier probability
        random_forest_score = self._predict_random_forest_score(
            features,
            lexical_score=lexical_score,
            fuzzy_score=fuzzy_score,
            embedding_score=embedding_score,
            context_score=context_score,
        )
        
        if self.rf_model is not None:
            final_score = (
                self.w_rf * random_forest_score +
                self.w1_lexical * lexical_score +
                self.w2_fuzzy * fuzzy_score +
                self.w3_embedding * embedding_score +
                self.w4_context * context_score
            )
        else:
            final_score = (
                0.45 * lexical_score +
                0.20 * fuzzy_score +
                0.20 * embedding_score +
                0.15 * context_score
            )
        
        # Normalize to 0-1 range
        final_score = min(max(final_score, 0.0), 1.0)
        
        # Component breakdown for debugging
        components = {
            'random_forest': random_forest_score,
            'lexical': lexical_score,
            'fuzzy': fuzzy_score,
            'embedding': embedding_score,
            'context': context_score,
            'final': final_score
        }
        
        return final_score, components
    
    def analyze_field(self, field: Dict, parent_type: Dict, type_map: Dict) -> Optional[Tuple[FieldFeatures, float, str, Dict]]:
        """Analyze a single field for sensitivity.
        
        Args:
            field: Field definition
            parent_type: Parent type
            type_map: Schema type map
            
        Returns:
            Tuple of (features, score, reasoning, components) if sensitive, None otherwise
        """
        features = self.extract_features(field, parent_type, type_map)
        field_description = field.get('description', '')
        score, components = self.calculate_sensitivity_score(features, field_description)
        
        # Only return fields that pass the configured sensitivity threshold.
        if score >= self.sensitivity_threshold:
            # Generate reasoning
            reasoning = self._generate_reasoning(features, score, components)
            return (features, score, reasoning, components)
        
        return None
    
    def _generate_reasoning(self, features: FieldFeatures, score: float, components: Dict[str, float]) -> str:
        """Generate human-readable reasoning for sensitivity detection."""
        reasons = []
        field_lower = features.name.lower()
        
        # Highlight strongest signal
        if components.get('random_forest', 0.0) >= 0.7:
            reasons.append(f"Random Forest classified the field as sensitive (probability: {components['random_forest']:.2f})")
        elif components['embedding'] >= 0.7:
            reasons.append(f"High semantic similarity to PII concepts (ML: {components['embedding']:.2f})")
        elif components['lexical'] >= 0.7:
            matched_patterns = [
                pattern for pattern in self.SENSITIVE_PATTERNS.keys()
                if self._pattern_matches_field(pattern, features.name, field_lower)
            ]
            if matched_patterns:
                reasons.append(f"Keyword match: {', '.join(matched_patterns[:3])}")
        elif components['fuzzy'] >= 0.5:
            reasons.append(f"Fuzzy string similarity (score: {components['fuzzy']:.2f})")
        
        # Context signals
        if features.type_name == 'String':
            reasons.append("String type can store sensitive text")
        
        if not features.is_nullable:
            reasons.append("Required field (NON_NULL)")
        
        if features.has_sensitive_siblings:
            reasons.append("Adjacent to other sensitive fields")
        
        # Score breakdown
        reasons.append(
            f"Score breakdown: rf={components.get('random_forest', 0.0):.2f}, "
            f"lexical={components['lexical']:.2f}, "
            f"fuzzy={components['fuzzy']:.2f}, embedding={components['embedding']:.2f}, "
            f"context={components['context']:.2f}"
        )
        
        if not reasons:
            reasons.append("ML scoring indicates sensitivity")
        
        return "; ".join(reasons)
    
    def _split_camel_case(self, name: str) -> List[str]:
        """Split camelCase or PascalCase into parts."""
        return re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|\W|$)|\d+', name)
    
    def _get_scalar_type_name(self, type_ref: Dict) -> str:
        """Unwrap type reference to get scalar type name."""
        while type_ref.get('kind') in ['NON_NULL', 'LIST']:
            type_ref = type_ref['ofType']
        return type_ref.get('name', 'Unknown')
    
    def run(self) -> List[Finding]:
        """
        Execute ML-based semantic analysis on the schema.
        
        Returns:
            List of findings for sensitive fields
        """
        self.logger.info("Starting ML semantic analysis")
        
        type_map = self.get_type_map()
        analyzed_count = 0
        
        # Analyze all object types
        for type_name, type_def in type_map.items():
            if type_def.get('kind') != 'OBJECT':
                continue
            
            # Skip internal types
            if type_name.startswith('__'):
                continue
            
            fields = type_def.get('fields', [])
            for field in fields:
                analyzed_count += 1
                result = self.analyze_field(field, type_def, type_map)
                
                if result:
                    features, score, reasoning, components = result
                    
                    # Determine severity based on score
                    if score >= 0.85:
                        severity = SEVERITY_HIGH
                    elif score >= 0.7:
                        severity = SEVERITY_MEDIUM
                    else:
                        severity = SEVERITY_MEDIUM
                    
                    self.add_finding(
                        title=f"ML-Detected Sensitive Field: {features.parent_type}.{features.name}",
                        description=(
                            f"Random Forest ML model identified this field as potentially sensitive.\n"
                            f"Classifier probability: {components['random_forest']:.2f}\n"
                            f"Semantic similarity (embedding): {components['embedding']:.2f}\n"
                            f"Confidence: {score:.2f}"
                        ),
                        severity=severity,
                        category=CATEGORY_AUDIT,
                        field=f"{features.parent_type}.{features.name}",
                        # Store score details so later review and reports can explain the ML decision.
                        evidence={
                            "candidate_source": "ml",
                            "candidate_kind": "ml_sensitive_field",
                            "location": f"{features.parent_type}.{features.name}",
                            "field_type": features.type_name,
                            "matched_keywords": [
                                pattern
                                for pattern in self.SENSITIVE_PATTERNS.keys()
                                if self._pattern_matches_field(pattern, features.name, features.name.lower())
                            ],
                            "ml_score": round(score, 2),
                            "ml_model": "random_forest_sensitive_field_classifier",
                            "ml_components": {
                                key: round(value, 2) for key, value in components.items()
                            },
                            "reasoning": reasoning,
                        },
                    )
                    
                    self.logger.info(
                        f"Sensitive field detected: {features.parent_type}.{features.name} "
                        f"(score: {score:.2f})"
                    )
        
        self.logger.info(
            f"ML semantic analysis complete: Analyzed {analyzed_count} fields, "
            f"found {len(self.findings)} sensitive fields"
        )
        
        return self.findings
