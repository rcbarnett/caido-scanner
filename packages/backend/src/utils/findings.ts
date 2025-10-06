import { type Request } from "caido:utils";
import { type Finding, type Severity } from "engine";

type FindingBuilder = {
  withDescription: (description: string) => FindingBuilder;
  withImpact: (impact: string) => FindingBuilder;
  withRecommendation: (recommendation: string) => FindingBuilder;
  withArtifacts: (title: string, artifacts: string[]) => FindingBuilder;
  build: () => Finding;
};

export const findingBuilder = (options: {
  name: string;
  severity: Severity;
  request: Request;
}): FindingBuilder => {
  const { name, severity, request } = options;

  let description = "";
  let impact = "";
  let recommendation = "";
  let artifactsTitle = "";
  let artifacts: string[] = [];

  const builder: FindingBuilder = {
    withDescription: (desc: string) => {
      description = desc;
      return builder;
    },
    withImpact: (imp: string) => {
      impact = imp;
      return builder;
    },
    withRecommendation: (rec: string) => {
      recommendation = rec;
      return builder;
    },
    withArtifacts: (title: string, art: string[]) => {
      artifactsTitle = title;
      artifacts = art;
      return builder;
    },
    build: () => {
      const descriptionParts = [`# ${name}`, description];

      if (artifactsTitle && artifacts.length > 0) {
        descriptionParts.push("", `### ${artifactsTitle}`);
        artifacts.forEach((artifact) => {
          descriptionParts.push(`- ${artifact}`);
        });
      }

      descriptionParts.push(
        "",
        `## Impact`,
        impact,
        "",
        `## Recommendation`,
        recommendation,
      );

      const fullDescription = descriptionParts.join("\n");

      return {
        name,
        description: fullDescription,
        severity,
        correlation: {
          requestID: request.getId(),
          locations: [],
        },
      };
    },
  };

  return builder;
};
