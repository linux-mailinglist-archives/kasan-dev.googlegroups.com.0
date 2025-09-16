Return-Path: <kasan-dev+bncBDP53XW3ZQCBB2GOUTDAMGQE4EAN3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 30798B59181
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:30 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-350dc421109sf19677111fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013289; cv=pass;
        d=google.com; s=arc-20240605;
        b=cOKvbrhR4aPsNBa5KKdyQMd9Avva4AwD+YA+DsRMWjl9fNMQbvhaAbFMHbWRr/eWc9
         yIVhzSfrwRAymmoyl44F7atByakfmopuMLuKBYRJPx5ls0w7UXmQxfANpNu4gKOpL90t
         8uecLDfaabDFBXNgsRkThIN6zHf80i2fxEWBbdt/8AWOKArk4zy032wEKKPT7OsyUFes
         l64g6tTbYF+cMOBaD5VufOFMXP+dV376AzZjvHewtpYWXKlqVIMvFR7O4l2Uqw7ksD/2
         hzw7PeMl1zF0C7tAgq7czHsqKDsUyfiP+zTOER4NII44kganedmfJAR36ZpuiMJa3F5i
         D7zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=rVNOcRtj+tZh14ac0gJVAL6ydo6fo6vhZ+tFIckmhTE=;
        fh=ts3zTSQPUUFgg9vasr5Z8lZYdpQRLLKFnf2BykH/EYk=;
        b=Lk6OOL7gp47chNvGlh2/63NuuYelnfvYtwTb8+9AhAMAzy9yHX19ti589OYiKPGT5l
         tzy/L87q+I9bbyb70vEHWebZIhx72j+zFYBX2GQPsfC+pHiAZzwdGcC1QcAPkG9jVJry
         X6HHcBsp6NGiqYR1gHri8NynqGrHsnB0rfmgG55qgstxaINWExq0Agh5arD3ELopDGZn
         /Edfvy7v+GyqiwtMsdrGIy1L2GYicuH6YB0T1iiROmwitbtH0Ou5Izs6BaGbcCUir0/5
         LS2rSIC0TTCVNACVUcPWt+IIZ0wC4nYF/NzX1nVTIGX4mt/PztxjeXdjrzOgZYMLVn1J
         sbnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K1sriWIw;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013289; x=1758618089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rVNOcRtj+tZh14ac0gJVAL6ydo6fo6vhZ+tFIckmhTE=;
        b=U1ZZhDn6KckMawnuFdiJkHQCYINdoMVMV3AClIusx8PBynxtZn6Netm4pq2FpSEAfC
         Xr+hkkF9Yl/SAXbwwlXgfXhO2/guSLlZuOKQ2LGg5cZmmqlH//VqeCfAEDOQjOA2VIxn
         vTG8Xx7vqyWZ/JdorK6eSSXaQ9X2ZKYTYrX4Nqh13i2K/d4VQcx+TS7CO2MRfqCFni/+
         MUoshAu0cMtvHi6xaT8FjPWMjkZGjXU8CfWdYg+JzLiKGWldTBzedNVwB+JlvhGaOzRC
         QkkmpTLDib20j8nvz9xCZWVszSLj/FPkuWj43W96txNBzaZ6O2wl63NGuG2JqHQrNy1E
         EfeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013289; x=1758618089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=rVNOcRtj+tZh14ac0gJVAL6ydo6fo6vhZ+tFIckmhTE=;
        b=ewNVdBd1iAHTzhkUgTOXVDzdtVC3U1fyoOGzJUYqjcCsupa03BOyycTN+5/K2f0Ko2
         p5JAmTMmtZ9jJw+KEamkA7GDqcq6A5YnSm0P65g6+YIF67kc2sSkEchp8rbVuXjlFxy2
         zuqaQweIfYH/T+hWytup2UQQFcP8RexOhiauQWgp6RhqgUPAmpNxOudbezmRLVkEUXtr
         e5UEt+NIy4KyjeIVxJ7rnxw5ONBQ4s6ad3QnzYD30FcpFFajFRvX1NBpCB5ZmM5S5+SO
         3sKiiiVhFRH7S9+TLUYqV1q9WF1rlR1n5Ywd8Zzqz+In1h8rHlyy5fJzUmeX2gmzytuw
         lMYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013289; x=1758618089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rVNOcRtj+tZh14ac0gJVAL6ydo6fo6vhZ+tFIckmhTE=;
        b=sujYCmyoICYcnS7yi16zzuIJ/R0pohHyC7XSQ1XesnuU9r48T4XN40M3v/IOHMIAhb
         XwJYxBzJVy1koATWUxDIiwllVMpH/H611OVyG/GKZzLtMQ5kYoCSc6Xfoe8x7KwLcAEa
         49e79V+wmcu8nlwNb/7Vi3F5rT6SqvXxl4rzziaQ+4uq0CoI/o16t09nQFBTOIoPcCD6
         w/b3IqkdcUgWYG0Y1t19FXYDfiCns44Vzhm+MmK7TOe8wH3zB2uMaKmOgbCtxMz8IcF3
         5i3/AR+QtiPiiUUu1P3zMg043yCsetS0U0FOylTnxiioF87OxQoWgieVcefShQe+4F3S
         Sm7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV72TjQgLrpaC0N3wNVt1C8WVS80dS7SYoqPNZXb2IqOoyjVYy/iqY8x3ERmwIojPjm6qB49g==@lfdr.de
X-Gm-Message-State: AOJu0Yyelb3qNTfnfxWeRY6WcYbkrl3gkXRRZzGL90jHX6CuDesq0aAp
	nacfTE6hds7+CCY+AEvNf683D4RcQFmEVk9iUn+DVgzWgQR6Cyx2JIH6
X-Google-Smtp-Source: AGHT+IHi3qn+kZbFFIhtELImWSyZjti3o1BrJCbzD2rs4SLTiRrZMq2JUYLKsrNWiLLRJKTeXnpmOQ==
X-Received: by 2002:a05:651c:2123:b0:336:51d4:16b3 with SMTP id 38308e7fff4ca-3513a8ee5f1mr54680941fa.10.1758013288924;
        Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5Re9AVuWu4wVds8ukh0RFTuZXAnIJOMuN5CCIaKvRsgA==
Received: by 2002:a2e:ae0a:0:10b0:342:2914:6884 with SMTP id
 38308e7fff4ca-34eb2598254ls7092401fa.2.-pod-prod-06-eu; Tue, 16 Sep 2025
 02:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMO0ERIdxA/KMHGmcCPw2JTjJ3Lwb2Jc9vqjHXkN9VmMUbqzrIlILC6AJjjxXGQNyKK6yfwhCtMh8=@googlegroups.com
X-Received: by 2002:a05:651c:23c8:10b0:336:c080:4149 with SMTP id 38308e7fff4ca-3513b294a5amr31215721fa.18.1758013285139;
        Tue, 16 Sep 2025 02:01:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013285; cv=none;
        d=google.com; s=arc-20240605;
        b=FSewJnI+B6QlNQ1OI6cnIDq5z2RWibYlyYsp01JFHidm/PdodpF55cQ9AnvWybGn2H
         EstKUZDAACuLoYWGtCK1/dFlRnAxWO3cyzTdFhtQGHsjsY3YLmIU/OKVz6mtel8b8H3u
         YOidUKfTEbdUPobL3zMWA6zKDrvQLpuwOXKvYGEH/9XDT89MMFoRhLepBkJ1EIm3YZem
         sWAEU2oZk3wVue6Uv9SDZKxrNlHZ3iMcMCbl2bTLVBYQqIHAV3klvwHzfVGM/SdMY6OC
         nPYGAXLhA7odENKMogajx//gI3QqQ94NYDdQH0Cx9DfNUiU76RieZND9sUJaJ8Jf/mqI
         Rtyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gp0wKR4UFIJ4rSEY85b8LtOArZzZXgf5YyWmJJ8KcKg=;
        fh=kVN80VsojGMzQE6s/qpYPMwEmW+gKhuZKM/MO7aSC+E=;
        b=OS9GVcH9RMYci+s08f+63ys5CqItDizCHNNsa63E6F15WS9i3xcKt4ulJMlpMIsHpy
         Pa3O89A3ZnOaHGd5Smp9n8TkfBsGvlQYcmUm9f6rA5pbaYhtHZ2u8p1d1WLsN7eU1lhu
         8u97TZ7767BJ78HkD0XecOasqcjoDh6m/yC9y4zx6QIxqVW4CZrq7qq1Q5LLCxqkec2a
         rpNCk77/UrP3J6gqlMo3RBcsDkEgp5cpzE6iocZ4NyJVYhJOXmZXL1IaOy7xBi+8DCfF
         rVvHdeti0XCBbNf4niv9txeKOzfvxDxT0283+UxKAkkdHWnAKDmqBTYbFLYmYNvxQ5lO
         ED8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=K1sriWIw;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-351265bfd12si2167321fa.2.2025.09.16.02.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3ec4d6ba12eso454185f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVF077c2n3e7h5lho0bbjjaRYbvjbQTpMzxyzanus9tFdXAk2Lj1kglgFaHEGUZAOymSXkyxWOergI=@googlegroups.com
X-Gm-Gg: ASbGnct6TXO+YFY57XXOOEM7G9Ua1ybkvob1nwzDaKjkvk2eXj2mXTqN/ulmV42MgTs
	EcxruEOhHFnNAPE6KtaDd5+s1csFGvNOTtJwILAbjByEGiacoL0dZoNgYuBegQQWciomfpTJVOZ
	FLck5AXdPTtPRBayyvF1MTS3nBVTCW6pZxNLg2hgrC4slgrC3CG8yU/t7hJ+1Qvhi1gJe5ip1aE
	G5sb6E02WkFBwiuiT7yyH5Pr8m7/FZSTUF0btTkl96q/w9VHQzQXEFonEJoQMDC40+6bfhk5KR2
	MeFazNNKvZGdDrxGY6NmZTn+j4W+A7QjHdIPjPKZ1a6W5TLuJO6fi859OB1/VfNQBq5sbWhKg9Q
	a4GVkBARHXRXWd+vpPRu0VVNTL5Nn/v/BNum1YC7HRU5a5xiv4RGX1429IG04UEdzNEfOntBISa
	KOa5GnMha8wN1kIy9wb/7fmEo=
X-Received: by 2002:a5d:4105:0:b0:3e9:d54:199f with SMTP id ffacd0b85a97d-3e90d541c27mr4925951f8f.32.1758013283923;
        Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v1 05/10] kfuzztest: add ReST documentation
Date: Tue, 16 Sep 2025 09:01:04 +0000
Message-ID: <20250916090109.91132-6-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=K1sriWIw;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: Ethan Graham <ethangraham@google.com>

Add Documentation/dev-tools/kfuzztest.rst and reference it in the
dev-tools index.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
v3:
- Fix some typos and reword some sections.
- Correct kfuzztest-bridge grammar description.
- Reference documentation in kfuzztest-bridge/input_parser.c header
  comment.
v2:
- Add documentation for kfuzztest-bridge tool introduced in patch 4.
---
---
 Documentation/dev-tools/index.rst     |   1 +
 Documentation/dev-tools/kfuzztest.rst | 385 ++++++++++++++++++++++++++
 tools/kfuzztest-bridge/input_parser.c |   2 +
 3 files changed, 388 insertions(+)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 65c54b27a60b..00ccc4da003b 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -32,6 +32,7 @@ Documentation/process/debugging/index.rst
    kfence
    kselftest
    kunit/index
+   kfuzztest
    ktap
    checkuapi
    gpio-sloppy-logic-analyzer
diff --git a/Documentation/dev-tools/kfuzztest.rst b/Documentation/dev-tools/kfuzztest.rst
new file mode 100644
index 000000000000..2dfa50f35a01
--- /dev/null
+++ b/Documentation/dev-tools/kfuzztest.rst
@@ -0,0 +1,385 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright 2025 Google LLC
+
+=========================================
+Kernel Fuzz Testing Framework (KFuzzTest)
+=========================================
+
+Overview
+========
+
+The Kernel Fuzz Testing Framework (KFuzzTest) is a framework designed to expose
+internal kernel functions to a userspace fuzzing engine.
+
+It is intended for testing stateless or low-state functions that are difficult
+to reach from the system call interface, such as routines involved in file
+format parsing or complex data transformations. This provides a method for
+in-situ fuzzing of kernel code without requiring that it be built as a separate
+userspace library or that its dependencies be stubbed out.
+
+The framework consists of four main components:
+
+1.  An API, based on the ``FUZZ_TEST`` macro, for defining test targets
+    directly in the kernel tree.
+2.  A binary serialization format for passing complex, pointer-rich data
+    structures from userspace to the kernel.
+3.  A ``debugfs`` interface through which a userspace fuzzer submits
+    serialized test inputs.
+4.  Metadata embedded in dedicated ELF sections of the ``vmlinux`` binary to
+    allow for the discovery of available fuzz targets by external tooling.
+
+.. warning::
+   KFuzzTest is a debugging and testing tool. It exposes internal kernel
+   functions to userspace with minimal sanitization and is designed for
+   use in controlled test environments only. It must **NEVER** be enabled
+   in production kernels.
+
+Supported Architectures
+=======================
+
+KFuzzTest is designed for generic architecture support. It has only been
+explicitly tested on x86_64.
+
+Usage
+=====
+
+To enable KFuzzTest, configure the kernel with::
+
+	CONFIG_KFUZZTEST=y
+
+which depends on ``CONFIG_DEBUGFS`` for receiving userspace inputs, and
+``CONFIG_DEBUG_KERNEL`` as an additional guardrail for preventing KFuzzTest
+from finding its way into a production build accidentally.
+
+The KFuzzTest sample fuzz targets can be built in with
+``CONFIG_SAMPLE_KFUZZTEST``.
+
+KFuzzTest currently only supports targets that are built into the kernel, as the
+core module's startup process discovers fuzz targets from a dedicated ELF
+section during startup. Furthermore, constraints and annotations emit metadata
+that can be scanned from a ``vmlinux`` binary by a userspace fuzzing engine.
+
+Declaring a KFuzzTest target
+----------------------------
+
+A fuzz target should be defined in a .c file. The recommended place to define
+this is under the subsystem's ``/tests`` directory in a ``<file-name>_kfuzz.c``
+file, following the convention used by KUnit. The only strict requirement is
+that the function being fuzzed is visible to the fuzz target.
+
+Defining a fuzz target involves three main parts: defining an input structure,
+writing the test body using the ``FUZZ_TEST`` macro, and optionally adding
+metadata for the fuzzer.
+
+The following example illustrates how to create a fuzz target for a function
+``int process_data(const char *data, size_t len)``.
+
+.. code-block:: c
+
+	/*
+	 * 1. Define a struct to model the inputs for the function under test.
+	 *    Each field corresponds to an argument needed by the function.
+	 */
+	struct process_data_inputs {
+		const char *data;
+		size_t len;
+	};
+
+	/*
+	 * 2. Define the fuzz target using the FUZZ_TEST macro.
+	 *    The first parameter is a unique name for the target.
+	 *    The second parameter is the input struct defined above.
+	 */
+	FUZZ_TEST(test_process_data, struct process_data_inputs)
+	{
+		/*
+		 * Within this body, the 'arg' variable is a pointer to a
+		 * fully initialized 'struct process_data_inputs'.
+		 */
+
+		/*
+		 * 3. (Optional) Add constraints to define preconditions.
+		 *    This check ensures 'arg->data' is not NULL. If the condition
+		 *    is not met, the test exits early. This also creates metadata
+		 *    to inform the fuzzer.
+		 */
+		KFUZZTEST_EXPECT_NOT_NULL(process_data_inputs, data);
+
+		/*
+		 * 4. (Optional) Add annotations to provide semantic hints to the
+		 *    fuzzer. This annotation informs the fuzzer that the 'len' field is
+		 *    the length of the buffer pointed to by 'data'. Annotations do not
+		 *    add any runtime checks.
+		 */
+		KFUZZTEST_ANNOTATE_LEN(process_data_inputs, len, data);
+
+		/*
+		 * 5. Call the kernel function with the provided inputs.
+		 *    Memory errors like out-of-bounds accesses on 'arg->data' will
+		 *    be detected by KASAN or other memory error detection tools.
+		 */
+		process_data(arg->data, arg->len);
+	}
+
+KFuzzTest provides two families of macros to improve the quality of fuzzing:
+
+- ``KFUZZTEST_EXPECT_*``: These macros define constraints, which are
+  preconditions that must be true for the test to proceed. They are enforced
+  with a runtime check in the kernel. If a check fails, the current test run is
+  aborted. This metadata helps the userspace fuzzer avoid generating invalid
+  inputs.
+
+- ``KFUZZTEST_ANNOTATE_*``: These macros define annotations, which are purely
+  semantic hints for the fuzzer. They do not add any runtime checks and exist
+  only to help the fuzzer generate more intelligent and structurally correct
+  inputs. For example, KFUZZTEST_ANNOTATE_LEN links a size field to a pointer
+  field, which is a common pattern in C APIs.
+
+Metadata
+--------
+
+Macros ``FUZZ_TEST``, ``KFUZZTEST_EXPECT_*`` and ``KFUZZTEST_ANNOTATE_*`` embed
+metadata into several sections within the main ``.data`` section of the final
+``vmlinux`` binary; ``.kfuzztest_target``, ``.kfuzztest_constraint`` and
+``.kfuzztest_annotation`` respectively.
+
+This serves two purposes:
+
+1. The core module uses the ``.kfuzztest_target`` section at boot to discover
+   every ``FUZZ_TEST`` instance and create its ``debugfs`` directory and
+   ``input`` file.
+2. Userspace fuzzers can read this metadata from the ``vmlinux`` binary to
+   discover targets and learn about their rules and structure in order to
+   generate correct and effective inputs.
+
+The metadata in the ``.kfuzztest_*`` sections consists of arrays of fixed-size C
+structs (e.g., ``struct kfuzztest_target``). Fields within these structs that
+are pointers, such as ``name`` or ``arg_type_name``, contain addresses that
+point to other locations in the ``vmlinux`` binary. A userspace tool that
+parsing the ELF file must resolve these pointers to read the data that they
+reference. For example, to get a target's name, a tool must:
+
+1. Read the ``struct kfuzztest_target`` from the ``.kfuzztest_target`` section.
+2. Read the address in the ``.name`` field.
+3. Use that address to locate and read null-terminated string from its position
+   elsewhere in the binary (e.g., ``.rodata``).
+
+Tooling Dependencies
+--------------------
+
+For userspace tools to parse the ``vmlinux`` binary and make use of emitted
+KFuzzTest metadata, the kernel must be compiled with DWARF debug information.
+This is required for tools to understand the layout of C structs, resolve type
+information, and correctly interpret constraints and annotations.
+
+When using KFuzzTest with automated fuzzing tools, either
+``CONFIG_DEBUG_INFO_DWARF4`` or ``CONFIG_DEBUG_INFO_DWARF5`` should be enabled.
+
+Input Format
+============
+
+KFuzzTest targets receive their inputs from userspace via a write to a dedicated
+debugfs file ``/sys/kernel/debug/kfuzztest/<test-name>/input``.
+
+The data written to this file must be a single binary blob that follows a
+specific serialization format. This format is designed to allow complex,
+pointer-rich C structures to be represented in a flat buffer, requiring only a
+single kernel allocation and copy from userspace.
+
+An input is first prefixed by an 8-byte header containing a magic value in the
+first four bytes, defined as ``KFUZZTEST_HEADER_MAGIC`` in
+`<include/linux/kfuzztest.h>``, and a version number in the subsequent four
+bytes.
+
+Version 0
+---------
+
+In version 0 (i.e., when the version number in the 8-byte header is equal to 0),
+the input format consists of three main parts laid out sequentially: a region
+array, a relocation table, and the payload.::
+
+    +----------------+---------------------+-----------+----------------+
+    |  region array  |  relocation table   |  padding  |    payload     |
+    +----------------+---------------------+-----------+----------------+
+
+Region Array
+^^^^^^^^^^^^
+
+This component is a header that describes how the raw data in the Payload is
+partitioned into logical memory regions. It consists of a count of regions
+followed by an array of ``struct reloc_region``, where each entry defines a
+single region with its size and offset from the start of the payload.
+
+.. code-block:: c
+
+	struct reloc_region {
+		uint32_t offset;
+		uint32_t size;
+	};
+
+	struct reloc_region_array {
+		uint32_t num_regions;
+		struct reloc_region regions[];
+	};
+
+By convention, region 0 represents the top-level input struct that is passed
+as the arg variable to the ``FUZZ_TEST`` body. Subsequent regions typically
+represent data buffers or structs pointed to by fields within that struct.
+Region array entries must be ordered by ascending offset, and must not overlap
+with one another.
+
+Relocation Table
+^^^^^^^^^^^^^^^^
+
+The relocation table contains the instructions for the kernel to "hydrate" the
+payload by patching pointer fields. It contains an array of
+``struct reloc_entry`` items. Each entry acts as a linking instruction,
+specifying:
+
+- The location of a pointer that needs to be patched (identified by a region
+  ID and an offset within that region).
+
+- The target region that the pointer should point to (identified by the
+  target's region ID) or ``KFUZZTEST_REGIONID_NULL`` if the pointer is ``NULL``.
+
+This table also specifies the amount of padding between its end and the start
+of the payload, which should be at least 8 bytes.
+
+.. code-block:: c
+
+	struct reloc_entry {
+		uint32_t region_id;
+		uint32_t region_offset;
+		uint32_t value;
+	};
+
+	struct reloc_table {
+		uint32_t num_entries;
+		uint32_t padding_size;
+		struct reloc_entry entries[];
+    };
+
+Payload
+^^^^^^^
+
+The payload contains the raw binary data for all regions, concatenated together
+according to their specified offsets.
+
+- Region specific alignment: The data for each individual region must start at
+  an offset that is aligned to its own C type's requirements. For example, a
+  ``uint64_t`` must begin on an 8-byte boundary.
+
+- Minimum alignment: The offset of each region, as well as the beginning of the
+  payload, must also be a multiple of the overall minimum alignment value. This
+  value is determined by the greater of ``ARCH_KMALLOC_MINALIGN`` and
+  ``KASAN_GRANULE_SIZE`` (which is represented by ``KFUZZTEST_POISON_SIZE`` in
+  ``/include/linux/kfuzztest.h``). This minimum alignment ensures that all
+  function inputs respect C calling conventions.
+
+- Padding: The space between the end of one region's data and the beginning of
+  the next must be sufficient for padding. The padding must also be at least
+  the same minimum alignment value mentioned above. This is crucial for KASAN
+  builds, as it allows KFuzzTest to poison this unused space enabling precise
+  detection of out-of-bounds memory accesses between adjacent buffers.
+
+The minimum alignment value is architecture-dependent and is exposed to
+userspace via the read-only file
+``/sys/kernel/debug/kfuzztest/_config/minalign``. The framework relies on
+userspace tooling to construct the payload correctly, adhering to all three of
+these rules for every region.
+
+KFuzzTest Bridge Tool
+=====================
+
+The ``kfuzztest-bridge`` program is a userspace utility that encodes a random
+byte stream into the structured binary format expected by a KFuzzTest harness.
+It allows users to describe the target's input structure textually, making it
+easy to perform smoke tests or connect harnesses to blob-based fuzzing engines.
+
+This tool is intended to be simple, both in usage and implementation. Its
+structure and DSL are sufficient for simpler use-cases. For more advanced
+coverage-guided fuzzing it is recommended to use
+`syzkaller <https://github.com/google/syzkaller>` which implements deeper
+support for KFuzzTest targets.
+
+Usage
+-----
+
+The tool can be built with ``make tools/kfuzztest-bridge``. In the case of libc
+incompatibilities, the tool will have to be linked statically or built on the
+target system.
+
+Example:
+
+.. code-block:: sh
+
+    ./kfuzztest-bridge \
+        "foo { u32 ptr[bar] }; bar { ptr[data] len[data, u64]}; data { arr[u8, 42] };" \
+        "my-fuzz-target" /dev/urandom
+
+The command takes three arguments
+
+1.  A string describing the input structure (see `Textual Format`_ sub-section).
+2.  The name of the target test, which corresponds to its directory in
+    ``/sys/kernel/debug/kfuzztest/``.
+3.  A path to a file providing a stream of random data, such as
+    ``/dev/urandom``.
+
+The structure string in the example corresponds to the following C data
+structures:
+
+.. code-block:: c
+
+	struct foo {
+		u32 a;
+		struct bar *b;
+	};
+
+	struct bar {
+		struct data *d;
+		u64 data_len; /* Equals 42. */
+	};
+
+	struct data {
+		char arr[42];
+	};
+
+Textual Format
+--------------
+
+The textual format is a human-readable representation of the region-based binary
+format used by KFuzzTest. It is described by the following grammar:
+
+.. code-block:: text
+
+	schema     ::= region ( ";" region )* [";"]
+	region     ::= identifier "{" type ( " " type )* "}"
+	type       ::= primitive | pointer | array | length | string
+	primitive  ::= "u8" | "u16" | "u32" | "u64"
+	pointer    ::= "ptr" "[" identifier "]"
+	array      ::= "arr" "[" primitive "," integer "]"
+	length     ::= "len" "[" identifier "," primitive "]"
+	string     ::= "str" "[" integer "]"
+	identifier ::= [a-zA-Z_][a-zA-Z1-9_]*
+	integer    ::= [0-9]+
+
+Pointers must reference a named region.
+
+To fuzz a raw buffer, the buffer must be defined in its own region, as shown
+below:
+
+.. code-block:: c
+
+	struct my_struct {
+		char *buf;
+		size_t buflen;
+	};
+
+This would correspond to the following textual description:
+
+.. code-block:: text
+
+	my_struct { ptr[buf] len[buf, u64] }; buf { arr[u8, n] };
+
+Here, ``n`` is some integer value defining the size of the byte array inside of
+the ``buf`` region.
diff --git a/tools/kfuzztest-bridge/input_parser.c b/tools/kfuzztest-bridge/input_parser.c
index 61d324b9dc0e..e07dcb4d21cc 100644
--- a/tools/kfuzztest-bridge/input_parser.c
+++ b/tools/kfuzztest-bridge/input_parser.c
@@ -16,6 +16,8 @@
  * and its corresponding length encoded over 8 bytes, where `buf` itself
  * contains a 42-byte array.
  *
+ * The full grammar is documented in Documentation/dev-tools/kfuzztest.rst.
+ *
  * Copyright 2025 Google LLC
  */
 #include <errno.h>
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-6-ethan.w.s.graham%40gmail.com.
