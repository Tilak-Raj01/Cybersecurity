"""Export a lightweight PyTorch model for edge inference as ONNX."""

import torch
from torch import nn


class LightweightIoTModel(nn.Module):
    """Lightweight PyTorch model for edge inference on gateways."""

    def __init__(self):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(6, 16),
            nn.ReLU(),
            nn.Linear(16, 2),
        )

    def forward(self, x):
        """Run the model forward pass on the provided features."""
        return self.fc(x)


def export_to_onnx(output_path="iot_nids_edge.onnx"):
    """Export the lightweight edge model to an ONNX file."""
    model = LightweightIoTModel()
    model.eval()
    dummy_input = torch.randn(1, 6)
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        verbose=False,
        input_names=['features'],
        output_names=['output'],
    )
    print(f"Model exported to {output_path}")

if __name__ == '__main__':
    export_to_onnx()
