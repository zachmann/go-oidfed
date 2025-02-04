package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

var tags = map[string]string{
	"OpenIDProviderMetadata":           "openid_provider",
	"OpenIDRelyingPartyMetadata":       "openid_relying_party",
	"OAuthAuthorizationServerMetadata": "oauth_authorization_server",
	"OAuthClientMetadata":              "oauth_client",
	"OAuthProtectedResourceMetadata":   "oauth_resource",
	"FederationEntityMetadata":         "federation_entity",
}

func main() {
	fileName := "metadata_input.go"
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, fileName, nil, parser.AllErrors)
	if err != nil {
		fmt.Println("Error parsing file:", err)
		os.Exit(1)
	}

	var commonMetadata *ast.StructType
	others := make(map[string]*ast.StructType)

	// Iterate over all declarations in the file
	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}

			if typeSpec.Name.Name == "commonMetadata" {
				commonMetadata = structType
			} else {
				others[typeSpec.Name.Name] = structType
			}
		}
	}

	if commonMetadata == nil {
		fmt.Println("Error: 'commonMetadata' not present in the input file.")
		os.Exit(1)
	}

	out, err := os.Create("metadata_generated.go")
	if err != nil {
		fmt.Println("Error: could not open output file.")
		os.Exit(1)
	}

	const header = `// Code generated by go generate; DO NOT EDIT.
package pkg

import (
	"encoding/json"

	"github.com/zachmann/go-oidfed/pkg/jwk"
	
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
)

`
	_, _ = out.WriteString(header)

	// Generate the new structs that include commonMetadata
	for name, other := range others {
		name = fmt.Sprintf("%s%s", strings.ToUpper(name[0:1]), name[1:])
		_, _ = out.WriteString(generateCombinedStruct(name, other, commonMetadata))
		_, _ = out.WriteString(generateMarshalUnmarshalFunctions(name))
		_, _ = out.WriteString(generateApplyPolicyFunction(name))
	}
}

// Generate a new struct that combines fields from both input structs
func generateCombinedStruct(
	newStructName string, structA,
	structB *ast.StructType,
) string {
	var sb strings.Builder
	seenFields := make(map[string]bool) // Keep track of field names

	sb.WriteString(fmt.Sprintf("type %s struct {\n", newStructName))

	// Add fields from struct A
	for _, field := range structA.Fields.List {
		for _, fieldName := range field.Names {
			if !seenFields[fieldName.Name] {
				seenFields[fieldName.Name] = true
				sb.WriteString(fmt.Sprintf("    %s %s", fieldName.Name, fieldTypeAsString(field.Type)))
				if field.Tag != nil {
					sb.WriteString(fmt.Sprintf(" %s", field.Tag.Value))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Add fields from struct B
	for _, field := range structB.Fields.List {
		for _, fieldName := range field.Names {
			if newStructName == "FederationEntityMetadata" && strings.Contains(fieldName.Name, "JWKS") {
				continue
			}
			if !seenFields[fieldName.Name] {
				seenFields[fieldName.Name] = true
				sb.WriteString(fmt.Sprintf("    %s %s", fieldName.Name, fieldTypeAsString(field.Type)))
				if field.Tag != nil {
					sb.WriteString(fmt.Sprintf(" %s", field.Tag.Value))
				}
				sb.WriteString("\n")
			}
		}
	}
	sb.WriteString("}\n")
	return sb.String()
}

// Convert field type to string
func fieldTypeAsString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", t.X, t.Sel.Name)
	case *ast.StarExpr:
		return "*" + fieldTypeAsString(t.X)
	case *ast.ArrayType:
		return "[]" + fieldTypeAsString(t.Elt)
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", fieldTypeAsString(t.Key), fieldTypeAsString(t.Value))
	default:
		return ""
	}
}

func generateMarshalUnmarshalFunctions(name string) string {
	var sb strings.Builder

	sb.WriteString(
		fmt.Sprintf(
			`
// MarshalJSON implements the json.Marshaler interface
func (m %s) MarshalJSON() ([]byte, error) {
	type Alias %s
	explicitFields, err := json.Marshal(Alias(m))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}
`, name, name,
		),
	)

	sb.WriteString(
		fmt.Sprintf(
			`
// UnmarshalJSON implements the json.Unmarshaler interface
func (m *%s) UnmarshalJSON(data []byte) error {
	type Alias %s
	mm := Alias(*m)

	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	mm.Extra = extra
	*m = %s(mm)
	return nil
}
`, name, name, name,
		),
	)

	sb.WriteString(
		fmt.Sprintf(
			`
// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (m *%s) UnmarshalMsgpack(data []byte) error {
	type Alias %s
	mm := Alias(*m)
	err := msgpack.Unmarshal(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	*m = %s(mm)
	return nil
}
`, name, name, name,
		),
	)

	return sb.String()
}

func generateApplyPolicyFunction(name string) string {
	var sb strings.Builder

	sb.WriteString(
		fmt.Sprintf(
			`
// ApplyPolicy applies a MetadataPolicy to the %s
func (m %s) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "%s")
}

`, name, name, tags[name],
		),
	)
	return sb.String()
}
