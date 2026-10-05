export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired'
export type EntityType = 'asset' | 'vulnerability' | 'task' | 'knowledge' | 'approval'
export interface Asset { id?: number; type: string; value: string; metadata?: Record<string, unknown> }
export interface Vulnerability { id?: number; title: string; severity: string; status?: string; asset_id?: number; description?: string; evidence?: unknown }
export interface Task { id?: number; type: string; status?: string; recipe?: string; params?: unknown; result?: unknown }
export interface Approval { id?: number; action: string; target: string; risk: RiskLevel; status?: ApprovalStatus; requested_by?: string; decided_by?: string; reason?: string }
export interface KnowledgeChunk { id?: number; source: string; content: string; metadata?: unknown }
export interface AttackEdge { id?: number; from_type: EntityType; from_id: number; to_type: EntityType; to_id: number; relation: string; metadata?: unknown }
export interface ToolArg { name: string; type?: string; required?: boolean; default?: unknown; description?: string }
export interface ToolRecipe { name: string; display_name?: string; category?: string; description?: string; command: string; args?: ToolArg[]; timeout?: number; max_output?: number; risk_level?: RiskLevel; requires_approval?: boolean; output_parser?: string }
export interface ToolResult { recipe: string; params: Record<string, unknown>; stdout: string; stderr: string; exitCode: number | null; duration: number; timedOut?: boolean; cancelled?: boolean; timestamp: string }
export interface CyberConfig { dataPath?: string; recipesPath?: string; maxOutputBytes?: number; defaultTimeoutMs?: number }
