/**
 * Content Security Policy (CSP) parser
 * Parses CSP header values into structured data using Lezer parser
 */

import { parser } from "./__generated__.js";
import {
  Directive,
  DirectiveName,
  SourceValue,
} from "./__generated__.terms.js";

type CSPDirective = {
  name: string;
  values: string[];
};

type ParserResult =
  | {
      kind: "Success";
      directives: CSPDirective[];
      raw: string;
    }
  | {
      kind: "Failed";
    };

const parse = (cspHeader: string): ParserResult => {
  if (!cspHeader || cspHeader.trim() === "") {
    return {
      kind: "Success",
      directives: [],
      raw: cspHeader,
    };
  }

  const tree = parser.parse(cspHeader);
  const directives: CSPDirective[] = [];

  let isError = false;
  tree.iterate({
    enter: (node) => {
      if (node.type.isError) {
        isError = true;
      }

      if (node.type.id === Directive) {
        const directiveName = node.node.getChild(DirectiveName);
        const values = node.node.getChildren(SourceValue);

        if (directiveName) {
          directives.push({
            name: cspHeader.slice(
              directiveName.node.from,
              directiveName.node.to,
            ),
            values: values.map((value) =>
              cspHeader.slice(value.node.from, value.node.to),
            ),
          });
        }
      }
    },
  });

  if (isError) {
    return {
      kind: "Failed",
    };
  }

  return {
    kind: "Success",
    directives,
    raw: cspHeader,
  };
};

export const CSPParser = {
  parse,
};
