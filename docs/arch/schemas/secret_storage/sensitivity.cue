// DDD role: ValueObject

package secret_storage

// #Sensitivity is the closed enum that determines reveal authorization rules
// and the default rate-limit class for a Secret.
//
// "low"    — OOB confirmation not required; standard rate limit.
// "medium" — OOB confirmation required unless the Namespace Policy grants
//            slash-command-only override; elevated rate limit.
// "high"   — OOB confirmation always required; strictest rate limit;
//            default-denied for vault.reveal unless the Namespace Policy
//            explicitly permits it.
#Sensitivity: "low" | "medium" | "high"
