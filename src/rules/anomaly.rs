use once_cell::sync::Lazy;
use std::path::Path;
use tract_onnx::prelude::*;

type RunnableAnomalyModel =
    RunnableModel<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Struct to hold the loaded ONNX model, or None if it's missing/failed
pub struct AnomalyModel {
    model: Option<RunnableAnomalyModel>,
}

pub struct AnomalyDetector {
    // Internal state can be added here if we want to retain Markov Chain functionality,
    // but for ONNX/Heuristic we rely on the static MODEL.
}

pub static ANOMALY_DETECTOR: Lazy<AnomalyDetector> = Lazy::new(|| AnomalyDetector {});

static MODEL: Lazy<AnomalyModel> = Lazy::new(|| {
    let model_path = "config/anomaly.onnx";
    if Path::new(model_path).exists() {
        match tract_onnx::onnx()
            .model_for_path(model_path)
            .and_then(|mut model| {
                // Assuming a model that takes a string/tensor of length 256
                // and outputs a single float [0.0 - 1.0]
                model.set_input_fact(
                    0,
                    TypedFact::dt_shape(f32::datum_type(), tvec!(1, 256)).into(),
                )?;
                model.into_optimized()
            })
            .and_then(|model| model.into_runnable())
        {
            Ok(runnable) => {
                tracing::info!("ONNX Anomaly Model loaded successfully from {}", model_path);
                AnomalyModel {
                    model: Some(runnable),
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to load ONNX model: {}. Falling back to heuristic mode.",
                    e
                );
                AnomalyModel { model: None }
            }
        }
    } else {
        tracing::warn!(
            "ONNX model not found at {}. Using lightweight heuristic fallback.",
            model_path
        );
        AnomalyModel { model: None }
    }
});

impl AnomalyDetector {
    /// Computes the anomaly score of a payload.
    /// Returns a float between 0.0 (normal) and 1.0 (highly anomalous).
    pub fn calculate_anomaly_score(&self, payload: &str) -> f64 {
        // If we have an ONNX model, use it for inference
        if let Some(ref runnable) = MODEL.model {
            return run_onnx_inference(runnable, payload) as f64;
        }

        // Fallback: Statistical Heuristic (Lightweight)
        run_heuristic_inference(payload) as f64
    }

    /// Placeholder for learning mode (e.g. updating Markov chain states)
    pub fn learn(&self, _payload: &str) {
        // In ONNX/Heuristic mode, learning is done offline.
        // For plug-and-play, this is a no-op unless we add back Markov chains.
    }
}

/// Runs the actual ONNX inference (placeholder for vectorization)
fn run_onnx_inference(runnable: &RunnableAnomalyModel, payload: &str) -> f32 {
    // 1. Vectorize the string into a [1, 256] tensor
    let payload_bytes = payload.as_bytes();
    let tensor = tract_ndarray::Array2::from_shape_fn((1, 256), |(_, j)| {
        if j < payload_bytes.len() {
            (payload_bytes[j] as f32) / 255.0
        } else {
            0.0
        }
    })
    .into_tensor()
    .into_tvalue();

    // 2. Run inference
    match runnable.run(tvec!(tensor)) {
        Ok(result) => {
            if let Ok(view) = result[0].to_array_view::<f32>() {
                if let Some(&score) = view.iter().next() {
                    return score.clamp(0.0, 1.0);
                }
            }
            0.0
        }
        Err(e) => {
            tracing::warn!("ONNX inference failed: {}", e);
            run_heuristic_inference(payload) // Fallback if inference fails
        }
    }
}

/// Lightweight statistical heuristic (Zero-day protection fallback)
/// Analyzes character entropy, non-alphanumeric ratio, and path traversal markers.
fn run_heuristic_inference(payload: &str) -> f32 {
    let len = payload.len();
    if len == 0 {
        return 0.0;
    }

    let mut non_alpha = 0;
    let mut sql_chars = 0;
    let mut xss_chars = 0;

    for c in payload.chars() {
        if !c.is_ascii_alphanumeric() && c != ' ' && c != '/' {
            non_alpha += 1;
        }
        if c == '\'' || c == ';' || c == '-' || c == '"' {
            sql_chars += 1;
        }
        if c == '<' || c == '>' || c == '(' || c == ')' {
            xss_chars += 1;
        }
    }

    let non_alpha_ratio = non_alpha as f32 / len as f32;

    let mut score: f32 = 0.0;

    // High non-alphanumeric ratio often indicates shellcode or obfuscation
    if non_alpha_ratio > 0.3 {
        score += 0.4;
    }

    // Density of injection characters
    if sql_chars > 3 {
        score += 0.3;
    }
    if xss_chars > 3 {
        score += 0.3;
    }

    // Path traversal check
    if payload.contains("../") || payload.contains("..\\") {
        score += 0.5;
    }

    // Explicit SQLi Patterns (Heuristic 2.0)
    let payload_upper = payload.to_uppercase();
    if payload_upper.contains("UNION SELECT")
        || payload_upper.contains("OR 1=1")
        || payload_upper.contains("WAITFOR DELAY")
        || payload_upper.contains("EXEC(")
    {
        score += 0.8;
    }

    // Explicit XSS Patterns (Heuristic 2.0)
    let payload_lower = payload.to_lowercase();
    if payload_lower.contains("<script")
        || payload_lower.contains("javascript:")
        || payload_lower.contains("onerror=")
        || payload_lower.contains("onload=")
        || payload_lower.contains("eval(")
    {
        score += 0.8;
    }

    score.clamp(0.0, 1.0)
}
