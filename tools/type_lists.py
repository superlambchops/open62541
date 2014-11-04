existing_types = set(["Boolean", "SByte", "Byte", "Int16", "UInt16", "Int32", "UInt32",
                      "Int64", "UInt64", "Float", "Double", "String", "DateTime", "Guid",
                      "ByteString", "XmlElement", "NodeId", "ExpandedNodeId", "StatusCode", 
                      "QualifiedName", "LocalizedText", "ExtensionObject", "DataValue",
                      "Variant", "DiagnosticInfo"])
                      
only_needed_types = set([	"InvalidType", "Node", "NodeClass", "ReferenceNode", "ApplicationDescription", "ApplicationType",
							"ChannelSecurityToken", "OpenSecureChannelRequest", "OpenSecureChannelResponse", 
							"CloseSecureChannelRequest", "CloseSecureChannelResponse", "RequestHeader", "ResponseHeader",
							"SecurityTokenRequestType", "MessageSecurityMode", "CloseSessionResponse", "CloseSessionRquest",
							"ActivateSessionRequest", "ActivateSessionResponse", "SignatureData", "SignedSoftwareCertificate",
							"CreateSessionResponse", "CreateSessionRequest", "EndpointDescription", "UserTokenPolicy", "UserTokenType",
							"GetEndpointsRequest", "GetEndpointsResponse", "PublishRequest", "PublishResponse", "SetPublishingModeResponse",
							"SubscriptionAcknowledgement", "NotificationMessage", "ExtensionObject", "Structure",
							"ReadRequest", "ReadResponse", "ReadValueId", "TimestampsToReturn", "WriteRequest", "WriteResponse",
							"WriteValue", "SetPublishingModeRequest", "CreateMonitoredItemsResponse", "MonitoredItemCreateResult",
							"CreateMonitoredItemsRequest", "MonitoredItemCreateRequest", "MonitoringMode", "MonitoringParameters",
							"TranslateBrowsePathsToNodeIdsRequest", "TranslateBrowsePathsToNodeIdsResponse", "BrowsePath", "BrowsePathResult",
							"RelativePath", "BrowsePathTarget", "RelativePathElement", "CreateSubscriptionRequest", "CreateSubscriptionResponse",
							"BrowseResponse", "BrowseResult", "ReferenceDescription", "BrowseRequest", "ViewDescription", "BrowseDescription",
							"BrowseDirection", "CloseSessionRequest", "AddNodesRequest", "AddNodesResponse", "AddNodesItem", "AddNodesResult",
							"DeleteNodesItem","AddReferencesRequest", "AddReferencesResponse", "AddReferencesItem","DeleteReferencesItem", "VariableNode", "MethodNode", 								"VariableTypeNode","ViewNode", "ReferenceTypeNode", "BrowseResultMask", "ServerState", "ServerStatusDataType", "BuildInfo", "ObjectNode",
							"DataTypeNode", "ObjectTypeNode", "IdType", "VariableAttributes","ObjectAttributes","NodeAttributes","ReferenceTypeAttributes","ViewAttributes","ObjectTypeAttributes","NodeAttributesMask" ])
only_needed_types = only_needed_types.union(existing_types)
