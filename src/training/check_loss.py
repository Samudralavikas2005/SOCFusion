import torch
import torch.nn.functional as F

outputs = torch.randn(10, 15)
targets = torch.zeros(10, dtype=torch.long)

alpha = torch.tensor([1.0714e-04, 1.0714e+00, 1.0714e+00, 1.0714e+00, 1.0714e+00, 1.0714e+00,
        1.0714e+00, 1.0714e+00, 1.0714e+00, 1.0714e+00, 1.0714e+00, 1.0714e+00,
        1.0714e+00, 1.0714e+00, 1.0714e+00])

ce_loss = F.cross_entropy(outputs, targets, reduction='none', weight=alpha)
pt = torch.exp(-ce_loss)
print("ce_loss:", ce_loss)
print("pt:", pt)
print("1-pt:", 1-pt)

# Unweighted ce
ce_unweighted = F.cross_entropy(outputs, targets, reduction='none')
print("ce_unweighted:", ce_unweighted)

