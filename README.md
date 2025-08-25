# API Gateway


**API Gateway** is a modular, developer-friendly Python project designed to become a **full-featured API Gateway framework**.  
Right now (v1.0.0) it ships with **request validation utilities** powered by [Pydantic](https://docs.pydantic.dev).  
In the coming weeks, it will expand into routing, authentication, rate limiting, logging, and more.

---

##  Vision
The goal of **API Gateway** is to provide:
-  **Validation**: Ensure only clean, schema-compliant data enters your services. *(available today)*  
-  **Authentication & Authorization**: Pluggable security layers. *(coming soon)*  
-  **Observability**: Metrics, logging, tracing. *(coming soon)*  
-  **Routing**: Intelligent request routing and proxying. *(coming soon)*  
-  **Rate Limiting & QoS**: Keep traffic fair and resilient. *(coming soon)*  

---

##  Features (v1.0.0)
-  **Validation Modes**:
  - `STRICT` → reject unknown/extra fields  
  - `LAX` → allow but ignore extras  
-  **Schema First**: Contracts via Pydantic models  
-  **Customizable Errors**  
-  **Idempotent**: Input payloads aren’t mutated  
-  **Pytest suite included**  

---

##  Installation

To get started you need [`uv`](https://docs.astral.sh/uv/), a fast Python package manager. Install it first with:

```bash
# On Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"


git clone https://github.com/PrabhbirJ/apigateway.git
cd apigateway
uv sync --extra dev

# Run tests
uv run pytest
```


---

##  Project Structure

```bash
apigateway/
├── core/
│   ├── validation.py          # Validation decorator and utilities
│   └── enums/
│       └── validation_modes.py # STRICT / LAX validation modes
├── tests/
│   └── test_validation.py     # Pytest suite
├── LICENSE            
├── CHANGELOG.md         
├── pyproject.toml             # Project metadata & dependencies
└── README.md
```
---

## Error Handling

All validation errors are raised as GatewayValidationError with this schema:
```bash
{
  "error": "Validation Failed",
  "code": "validation_error",
  "details": [
    {
      "field": "id",
      "message": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}
```
You can customize formatting by supplying your own error_formatter