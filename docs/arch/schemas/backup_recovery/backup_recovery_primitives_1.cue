// DDD role: ValueObject

package backup_recovery

// Primitive wrappers chunk 1

#MaxInterval: int & >=3600 | *86400
#MaxIntervalSeconds: int & >=60 | *86400
#MinInterval: int & >=60 | *3600
#MinIntervalSeconds: int & >=60 | *3600
#NamespacesCount: int & >=0
#OnChangeCount: int & >=1 | *50
#OnIdle: int & >=60 | *300
#PreviewGeneratedAt: string
#Reason: string
