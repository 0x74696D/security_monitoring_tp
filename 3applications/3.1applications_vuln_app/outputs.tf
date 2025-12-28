output "api_gateway_url" {
  description = "API Gateway base URL"
  value       = "https://${google_api_gateway_gateway.gateway.default_hostname}"
}

output "function_url" {
  description = "Cloud Function direct URL (for debugging only - use API Gateway in production)"
  value       = google_cloudfunctions2_function.api.service_config[0].uri
}

output "storage_bucket" {
  description = "Cloud Storage bucket name for images"
  value       = google_storage_bucket.images.name
}

output "identity_platform_api_key_url" {
  description = "URL to get Identity Platform API key from GCP Console"
  value       = "https://console.cloud.google.com/apis/credentials?project=${var.project_id}"
}

output "logs_explorer_url" {
  description = "Cloud Logging Explorer URL for security events"
  value       = "https://console.cloud.google.com/logs/query;query=resource.type%3D%22cloud_function%22%0Aresource.labels.function_name%3D%22${local.function_name}%22%0AjsonPayload.event_type%3D~%22.*%22?project=${var.project_id}"
}

output "firestore_enabled" {
  description = "Whether Firestore is enabled"
  value       = var.enable_firestore
}

output "lab_modes_status" {
  description = "Current lab mode settings (SECURITY WARNING IF ENABLED)"
  value = {
    skip_ownership_check   = var.lab_mode_skip_object_ownership_check
    weak_token_validation = var.lab_mode_weak_token_validation
  }
}

output "security_warnings" {
  description = "Security configuration warnings"
  value = var.lab_mode_skip_object_ownership_check || var.lab_mode_weak_token_validation ? "⚠️  WARNING: Lab modes are ENABLED - INSECURE BY DESIGN - DO NOT USE IN PRODUCTION" : "✅ Lab modes are disabled - secure configuration"
}

output "test_commands" {
  description = "Example test commands"
  value = <<-EOT
    # 1. Get Identity Platform API Key from GCP Console (see identity_platform_api_key_url output)
    
    # 2. Sign up a test user:
    curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=YOUR_API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"email":"testuser@example.com","password":"TestPass123!","returnSecureToken":true}'
    
    # 3. Sign in to get ID token:
    curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=YOUR_API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"email":"testuser@example.com","password":"TestPass123!","returnSecureToken":true}'
    
    # Save the idToken from response as TOKEN variable
    
    # 4. Test protected endpoint:
    curl -H "Authorization: Bearer $$TOKEN" https://${google_api_gateway_gateway.gateway.default_hostname}/profile
    
    # 5. Upload an image:
    curl -X POST -H "Authorization: Bearer $$TOKEN" \
      -F "image=@test.jpg" \
      https://${google_api_gateway_gateway.gateway.default_hostname}/images/upload
    
    # 6. View logs:
    gcloud logging read "resource.type=cloud_function resource.labels.function_name=${local.function_name}" --limit 50 --format json
  EOT
}

