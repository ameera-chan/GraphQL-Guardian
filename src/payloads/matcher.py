from src.payloads.payload_db import PAYLOADS, PAYLOAD_MAPPING

def select_payloads(field_name: str, field_type: str, limit: int = 5) -> list:
    """
    Selects appropriate payloads based on the field name and GraphQL type.
    
    Args:
        field_name (str): The name of the argument or field (e.g., "username", "id").
        field_type (str): The GraphQL scalar type (e.g., "String", "Int", "ID").
        limit (int): Maximum number of payloads to return.
        
    Returns:
        list: A list of payload strings.
    """
    selected_payloads = []
    field_name_lower = field_name.lower()
    
    # 1. Check for keyword matches in specific categories
    for category, config in PAYLOAD_MAPPING.items():
        if category == "Generic":
            continue
            
        # Check if type matches
        if field_type in config["types"]:
            # Check if any keyword is in the field name
            if any(keyword in field_name_lower for keyword in config["keywords"]):
                selected_payloads.extend(PAYLOADS[category])
    
    # 2. If no specific keywords matched, or we want more variety, add Generic payloads if type allows
    # For now, let's prioritize specific ones. If we have enough, return.
    
    # Deduplicate preserving order
    unique_payloads = []
    seen = set()
    for p in selected_payloads:
        if p not in seen:
            unique_payloads.append(p)
            seen.add(p)
            
    if len(unique_payloads) >= limit:
        return unique_payloads[:limit]
        
    # 3. Fallback/Fill with Generic or Type-based payloads
    # If we didn't match keywords, maybe we matched the type?
    # For SQLi, "Int" types are good candidates even without keywords like "id" (though "id" is common).
    # But let's be careful not to fuzz every String with SSRF payloads.
    
    # Let's add Generic payloads if type matches
    if field_type in PAYLOAD_MAPPING["Generic"]["types"]:
        for p in PAYLOADS["Generic"]:
            if p not in seen:
                unique_payloads.append(p)
                seen.add(p)
                
    # 4. If still need more, maybe add SQLi for String/ID even if no keyword?
    # That might be too noisy. Let's stick to the plan.
    
    return unique_payloads[:limit]
