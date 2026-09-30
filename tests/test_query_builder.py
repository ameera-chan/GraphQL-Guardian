from src.scanner.query_builder import EnumLiteral, QueryBuilder


def make_type_map():
    return {
        "Query": {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "searchUsers",
                    "args": [
                        {
                            "name": "status",
                            "type": {"kind": "ENUM", "name": "Status"},
                        }
                    ],
                    "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}},
                },
                {
                    "name": "node",
                    "args": [
                        {
                            "name": "id",
                            "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}},
                        },
                        {
                            "name": "preview",
                            "type": {"kind": "SCALAR", "name": "Boolean"},
                        },
                    ],
                    "type": {"kind": "INTERFACE", "name": "Node"},
                },
            ],
        },
        "Mutation": {
            "kind": "OBJECT",
            "name": "Mutation",
            "fields": [
                {
                    "name": "createUser",
                    "args": [
                        {
                            "name": "input",
                            "type": {"kind": "NON_NULL", "ofType": {"kind": "INPUT_OBJECT", "name": "CreateUserInput"}},
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "User"},
                }
            ],
        },
        "Status": {
            "kind": "ENUM",
            "name": "Status",
            "enumValues": [
                {"name": "ACTIVE", "isDeprecated": False},
                {"name": "DISABLED", "isDeprecated": True},
            ],
        },
        "CreateUserInput": {
            "kind": "INPUT_OBJECT",
            "name": "CreateUserInput",
            "inputFields": [
                {"name": "email", "type": {"kind": "SCALAR", "name": "Email"}},
                {"name": "role", "type": {"kind": "ENUM", "name": "Status"}},
            ],
        },
        "Node": {
            "kind": "INTERFACE",
            "name": "Node",
            "possibleTypes": [{"name": "User"}],
        },
        "User": {
            "kind": "OBJECT",
            "name": "User",
            "fields": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                {"name": "email", "type": {"kind": "SCALAR", "name": "Email"}},
                {"name": "status", "type": {"kind": "ENUM", "name": "Status"}},
            ],
        },
        "ID": {"kind": "SCALAR", "name": "ID"},
        "Email": {"kind": "SCALAR", "name": "Email"},
        "Boolean": {"kind": "SCALAR", "name": "Boolean"},
    }


def test_enum_arguments_are_unquoted():
    builder = QueryBuilder(make_type_map())

    operation = builder.construct_operation("Query", "searchUsers")

    assert "status: ACTIVE" in operation
    assert 'status: "ACTIVE"' not in operation
    assert "status" in operation


def test_input_objects_format_nested_enum_and_custom_scalar_values():
    builder = QueryBuilder(make_type_map())

    operation = builder.construct_operation("Mutation", "createUser")

    assert "mutation" in operation
    assert 'email: "test@example.com"' in operation
    assert "role: ACTIVE" in operation
    assert "id" in operation


def test_optional_arguments_can_be_skipped_unless_overridden():
    builder = QueryBuilder(make_type_map())

    args = builder.build_args(
        make_type_map()["Query"]["fields"][1]["args"],
        include_optional=False,
    )

    assert args == {"id": "1"}


def test_abstract_return_types_use_inline_fragments():
    builder = QueryBuilder(make_type_map())

    operation = builder.construct_operation(
        "Query",
        "node",
        args_overrides={"id": "123", "preview": True},
    )

    assert "node(id: \"123\", preview: true)" in operation
    assert "__typename" in operation
    assert "... on User" in operation


def test_format_arg_value_escapes_strings_and_formats_enums():
    builder = QueryBuilder(make_type_map())

    assert builder.format_arg_value('a "quoted" value') == '"a \\"quoted\\" value"'
    assert builder.format_arg_value(EnumLiteral("ACTIVE")) == "ACTIVE"
