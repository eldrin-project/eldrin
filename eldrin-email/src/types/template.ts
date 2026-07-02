export interface TemplateSummary {
  id: string;
  name: string;
  subject: string;
  category: string | null;
  isShared: boolean;
  usageCount: number;
  mergeFields: string[];
  ownerId: string;
  isOwner: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface TemplateDetail extends TemplateSummary {
  bodyHtml: string;
  bodyText: string | null;
}

export interface CreateTemplateParams {
  name: string;
  subject: string;
  bodyHtml: string;
  bodyText?: string;
  category?: string;
  isShared?: boolean;
}

export interface UpdateTemplateParams {
  name?: string;
  subject?: string;
  bodyHtml?: string;
  bodyText?: string;
  category?: string;
  isShared?: boolean;
}
