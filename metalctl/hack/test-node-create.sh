make build
bin/metalctl node create test-node --broker https://metal-broker.lucy.sh --cert-file /Users/intunderflow/Documents/metal-pki/admin-indigo-1.pem --key-file /Users/intunderflow/Documents/metal-pki/admin-indigo-1.key --wireguard-mesh-member --etcd-member --mtls-cert-file-path /Users/intunderflow/Documents/metal-pki/admin-indigo-1.pem --mtls-key-file-path /Users/intunderflow/Documents/metal-pki/admin-indigo-1.key
bin/metalctl node create test-node-2 --broker https://metal-broker.lucy.sh --cert-file /Users/intunderflow/Documents/metal-pki/admin-indigo-1.pem --key-file /Users/intunderflow/Documents/metal-pki/admin-indigo-1.key --wireguard-mesh-member --etcd-member --mtls-cert-file-path /Users/intunderflow/Documents/metal-pki/admin-indigo-1.pem --mtls-key-file-path /Users/intunderflow/Documents/metal-pki/admin-indigo-1.key