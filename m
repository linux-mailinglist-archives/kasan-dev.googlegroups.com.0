Return-Path: <kasan-dev+bncBDP53XW3ZQCBBJE227CQMGQE72FXA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC9F0B3EC7C
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:43:17 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45b87bc6869sf13784385e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:43:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756744997; cv=pass;
        d=google.com; s=arc-20240605;
        b=L9Ca7uYAguaJgE/hFJZwTxVFSfOwFxFE8bzdBsqrKKgoc8OZKb/frz9T6wEHsuvyQR
         p+HAnSYfyTe8KIo2Ia6DeGoYyhwhCXre08x9th9JIJSZD7yQMtwv8kISEeH08HD8ko01
         Ety+DHOzbir7k2Tm6IPOtamt+JrmhLDdZbW/jdONxdAJ9HeGyArQFXDw1MxmEXBjGDas
         yBD/+u08Ir8173tOSr1QslubYUeM8V09wyQ9c7DsibWBRRV7e9oRGc69nQue/bltChIC
         qSbkFdqc8hVEcGneQtXU76fuA3z+COo4YeFSV4r6aRdFxUOA5i3POyXif+1XUsGdPR1H
         oJKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=it+bqVFV7hXqzYiydIKEsBfQyrONjOWv1XEg+hb19Eo=;
        fh=BXnXWPsOGVFx5k87LC0KWbODig5xbEm5dEm4T7agxL0=;
        b=PnXn7C65qEGHYy6DLcCy1SaIB2/KczZmyNQ+G/APPMgZx89NCHri4a4WiCDUFz56hR
         zmGgX22yUMBs2/ctPtcPHWhAe30+oFPYTgmM9J7pBgvQkpcGjNvsybM2p7WI4o5AHnE1
         qr183JuPqQFN8Ps8+kWu8ADpr1mkTHXxPmduV/6m83GPE9PkM/DBUi7o0MuARqR19Osa
         0YIKk3eZoCSZsXKGPkCacU9aFLYbGh3QVMK2q4ZdnWZ/zU0QksqZYGWozOpFMQv7mXok
         IU9iEinAobOoQhY+kr9+AcoGhkgpd6ncXCALRJAj/ZPRKjVcWvEKTXu73pxMuian43tg
         YC6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="R/2Rc0uo";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756744997; x=1757349797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=it+bqVFV7hXqzYiydIKEsBfQyrONjOWv1XEg+hb19Eo=;
        b=xV39M/Mzx7japun85y1LP5sgKdLkDXzIVdc0obGIxYllS1kbmvj0h7b/H7cFurLMRP
         4UnUkSHxkS91/9X2QlNELRpdQXtEzvoRU5GzQw3If77947Elq20VrqJgBdd3danmVGIN
         daoRXaZ3NnZl/cFdtTEcD5eK7aFY2sXld4VDk50+Xwon2IzXwLU6XR3bA0hbjeiCt/fZ
         GddeMsVAlOP9SdyMFavW5Y6z1xjLmgQyosu91Q5cEmfOtNc1+QIt85c6NhX1hXL2xcQi
         TWT+Xck6x5kMzDfbegzGP9w/hn0kb0bXSau/jgkczwcRsdL7Oi5xiZu+WTQxjl/ZVDeD
         KRuA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756744997; x=1757349797; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=it+bqVFV7hXqzYiydIKEsBfQyrONjOWv1XEg+hb19Eo=;
        b=KthGXP4t9xoxkArky2mjFnm3k7sz5GSAPJIzTfhiWF4mN/MNpBpyfzrR01sOum1u/u
         Atp8AZoWKMUbYL9fJ1y64CmY60gLzs/QXgjmUlIyjAMwsMT6MCmaLyy9M0UWH492UuZo
         J3NJlKCh6fidrmoGGiHKc9ow5bZAr/tjXZvbFP2/Fqs5B3xch4wtK+4hO+NPGyqJPtOA
         6Jk0MRCyTm4vGhnnfIw95OnYD99ltF9PoF3OGJwiGuq2waJlKqBxUQv4AsohXXp0P6Bv
         Nwn7dnnd27MVxp/3d6/wuzGleCZ7FI8wRTurfesKEij7dZRBiY/307R4V83i+/C3iwlJ
         CQeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756744997; x=1757349797;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=it+bqVFV7hXqzYiydIKEsBfQyrONjOWv1XEg+hb19Eo=;
        b=Ebq6v0Nn730HhznD6EwJVzO2iPTGlZ7YVMEEqzT9fP/3JmIeYtmAxhRNM5+V4KFJdA
         EQvhDZPjw6/48Ixgvt7bWfPquvpwJ24bdJI6dTuwXAhrVZlwEdVoBvPDPcyTT4IRRWvt
         /BDFiud1AJ79c6rbBtDW9XI9R6tbfAzJOK0QCgp4rrOlwAqDy6JCwPsgEv2jz5kpw1iv
         0y5ipXKtQYtt+CNwmIw2de1GRz0bMkyZCDOzaIqvO6tIFu0Y4Lcd4GwjXbC8whIedkEW
         eVpRB+qqeiP/uWMdlv7Vpt+25El44SLIpifRmtqSxprS9dFW6LqIZMcbpeyWEJont5uS
         RN5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwtofQtfB7ITYzFmFKJZcplO+hPHNeWViS4LzF5Lt9ycC0jPdHNUjUTeuyriqtfzJNv8yZRA==@lfdr.de
X-Gm-Message-State: AOJu0YzLXS0CrHjXqbVZhHcrXrstVE4h9bb6xOYIOtAcOmaLoSQPNwxn
	8TIuUtOha/9ZXIgkH45tlI82Jk8SyAuSXn7uztmfzZ/SM/95HuOAGFTL
X-Google-Smtp-Source: AGHT+IGecIOGgf3hyRo3cVreNx7Ehm9JaZVzrbukl861pXbsCGEUO4A4i2qwCqDsepJG+gunSTu0zQ==
X-Received: by 2002:a05:600c:1c98:b0:45b:8cee:580a with SMTP id 5b1f17b1804b1-45b8cee5b84mr35481765e9.35.1756744996925;
        Mon, 01 Sep 2025 09:43:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeveEeSrkoMO68W8sbTBLvESOX237k8JyOcGhEulVV2mg==
Received: by 2002:a05:6000:1ac9:b0:3c5:6664:2a88 with SMTP id
 ffacd0b85a97d-3cddf503e56ls2210503f8f.0.-pod-prod-08-eu; Mon, 01 Sep 2025
 09:43:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxRS9gsJZUMMRPwhbJY4HV5xTwQdJIICl7xJJB+HSDbOXc8iTP/gw15tQpbIQ19QJz47wd9HyUN1w=@googlegroups.com
X-Received: by 2002:a05:6000:4312:b0:3ca:7d27:6d6e with SMTP id ffacd0b85a97d-3d1de4ba747mr7004541f8f.28.1756744994040;
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756744994; cv=none;
        d=google.com; s=arc-20240605;
        b=WVLvZU7DMgtDmw1v/XXmA4FGbFB/OqAAJx7pjfdzGhaMsA7kqzNQ0wqsbhBH9ydcEZ
         ys7Xq3uiPIYrjHDnzgLJbh/bvThAHXDyJvClt+LNcYu8ykd/dx4EWb2G6JbhMbcElL0R
         AgAuBWHpB3MT61/i5yXY9R/hrsxutWVvzFDODr2t2cj7zhvpLBCPqGxFh2JW7q+yb4K3
         pyeYWlZRCrVuikdNpVxF0NMYhXOp7AQ6+ZbxGh4lgkXPAYb5fcK1icr87tad27iqUy9H
         eNikOACWiJDucoX5evQiOKhqCGgmiBteP8RuC4G5tH9C2NuzxBnepT+v6YvTWekBMukM
         ietQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+Q+lnz5hfxAJyxjEQHB9/QTS15Vi2TY+Ow6yqCRyLm4=;
        fh=/O+03MRfw1tgbjozneDKgNmpFBAOyQq62i23Fh3ORZM=;
        b=ji1kRWEgYoKBFMPo4yf5Fpe2ijO1vVOxaGtvSU4sA3PrXu52PgImekS6WF5an7QImH
         YhRMSJvCVdW05QS40XfYfMf5LYuWuVnsXj6a1RWsvsH2Zioaa6wlEjyw8fvcAh+TKoWi
         uvHuMV0J9bcKSo2qjFwmDV5/At/1YJbaCsl3EpbIamK6cxtPVf+vjeNLjGJFQHMIBwCl
         TnD7dEDG+jAJRe+FxcG6O6XrI43QLNXOhNIiiOl1JT4NWTqYDZuVAZMZFuaj/oxPp1bK
         6DuJ21ZzWjDH6IdKx9btfHWpdyNBRF12rhGdzOmQS3nv2+4//CTe1WN4SXzZ49zybZh4
         OhfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="R/2Rc0uo";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf19e76b95si221188f8f.0.2025.09.01.09.43.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 09:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3cbb3ff70a0so2831135f8f.2;
        Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5upVVeDnWvCu0XBrxnGgJsV0MLyKZ2EroFiJuPf2t/Oigs25pOzzKbA+UQcQO0TENv055D/p7qVk=@googlegroups.com, AJvYcCVycFvXDZS7eiwsRGrRa6ad5bP0Pr2YVhQmxsxVucFeY+1EQle/nnjz7Ejo21D2xy5fLmBT+jEGiwby@googlegroups.com
X-Gm-Gg: ASbGncvlRsFEgS7FB8to63u9rzro6tyilAHp9fpKjo5BZcT//2tYi4fDdD2erLXaSv7
	cAg/G4NGOwpQ8LYiKivOw/yybvWUNDX1WMeZmRo72I+51k+tNFUB001D+gsWU+AEYh1w/es3WVI
	fcW47oI5FYvfSEeYPRRn+cIuoh/vkxrqAj5+gVTcgksXTMoKnj6/3zblmUmEtXbv0yFjniZyXdl
	NvO0Nk2Ay0L7y85eUgZSxuBwzzIFxbRVQKxhMJeAlnBnNq1SIRemACXI26q7/wF4jtLFlK56T5Q
	NNjsXgRT4rDBBMFNN4MqQruvjfTTfhGxF10VaXBhenKq5of/rAzo+pw59aqf1qNQ4efIpOgnolr
	DKJkpjtSH5i7QujyjmStlSqAjBdIKLOCRJ7Bq37qrKLjwPv7mEISUFL0Fm9d5epAzmuRqgrJ82Z
	KF8RjGAKlzL1azegciUw==
X-Received: by 2002:a5d:5886:0:b0:3d1:bb77:9119 with SMTP id ffacd0b85a97d-3d1e0a953a3mr6820630f8f.61.1756744993046;
        Mon, 01 Sep 2025 09:43:13 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (140.225.77.34.bc.googleusercontent.com. [34.77.225.140])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf274dde69sm15955362f8f.14.2025.09.01.09.43.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:43:12 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	brendan.higgins@linux.dev,
	davidgow@google.com,
	dvyukov@google.com,
	jannh@google.com,
	elver@google.com,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	dhowells@redhat.com,
	lukas@wunner.de,
	ignat@cloudflare.com,
	herbert@gondor.apana.org.au,
	davem@davemloft.net,
	linux-crypto@vger.kernel.org
Subject: [PATCH v2 RFC 5/7] kfuzztest: add ReST documentation
Date: Mon,  1 Sep 2025 16:42:10 +0000
Message-ID: <20250901164212.460229-6-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.318.gd7df087d1a-goog
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="R/2Rc0uo";       spf=pass
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

---
v2:
- Add documentation for kfuzztest-bridge tool introduced in patch 4.
---
---
 Documentation/dev-tools/index.rst     |   1 +
 Documentation/dev-tools/kfuzztest.rst | 371 ++++++++++++++++++++++++++
 2 files changed, 372 insertions(+)
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
index 000000000000..aeaf433a320e
--- /dev/null
+++ b/Documentation/dev-tools/kfuzztest.rst
@@ -0,0 +1,371 @@
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
+KFuzzTest is currently only supported for x86_64.
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
+KFuzzTest currently only supports code that is built into the kernel, as the
+core module's startup process discovers fuzz targets, constraints, and
+annotations from a dedicated ELF section during startup.
+
+Declaring a KFuzzTest target
+----------------------------
+
+A fuzz target is defined directly in a .c file, typically alongside the function
+being tested. This process involves three main parts: defining an input
+structure, writing the test body using the ``FUZZ_TEST`` macro, and optionally
+adding metadata for the fuzzer.
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
+		 * 4. (Optional) Add annotations to provide semantic hints.
+		 *    This annotation informs the fuzzer that the 'len' field
+		 *    is the length of the buffer pointed to by 'data'.
+		 *    Annotations do not add any runtime checks.
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
+Macros ``FUZZ_TEST``, `KFUZZTEST_EXPECT_*`` and ``KFUZZTEST_ANNOTATE_*`` embed
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
+debugfs ``/sys/kernel/debug/kfuzztest/<test-name>/input``.
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
+as the arg variable to the FUZZ_TEST body. Subsequent regions typically
+represent data buffers pointed to by fields within that struct. Region array
+entries must be ordered by offset ascending, and must not overlap with one
+another.
+
+To satisfy C language alignment requirements and prevent potential hardware
+faults, the memory address of each region's data must be correctly aligned for
+the type it represents. The framework allocates a base buffer that is suitably
+aligned for any C type. Therefore, the userspace tool that generates the input
+is responsible for calculating each region's offset within the payload to ensure
+this alignment is maintained.
+
+Relocation Table
+^^^^^^^^^^^^^^^^
+
+The relocation table provides the instructions for the kernel to "hydrate" the
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
+- Alignment: The start of the payload must be aligned to the most restrictive
+  alignment requirement of all its constituent regions. The framework ensures
+  that each region within the payload is then placed at an offset that respects
+  its own type's alignment.
+
+- Padding and Poisoning: The space between the end of one region's data and the
+  beginning of the next must be sufficient for padding. In KASAN builds,
+  KFuzzTest poisons this unused padding, allowing for precise detection of
+  out-of-bounds memory accesses between adjacent buffers. This padding should
+  be at least ``KFUZZTEST_POISON_SIZE`` bytes as defined in
+  `include/linux/kfuzztest.h``.
+
+KFuzzTest Bridge Tool
+=====================
+
+The kfuzztest-bridge program is a userspace utility that encodes a random byte
+stream into the structured binary format expected by a KFuzzTest harness. It
+allows users to describe the target's input structure textually, making it easy
+to perform smoke tests or connect harnesses to blob-based fuzzing engines.
+
+This tool is intended to be simple, both in usage and implementation. Its
+structure and DSL are sufficient for simpler use-cases. For more advanced
+coverage-guided fuzzing it is recommended to use syzkaller which implements
+deeper support for KFuzzTest targets.
+
+Usage
+-----
+
+The tool can be built with ``make tools/kfuzztest-bridge``. In the case of libc
+incompatibilities, the tool may have to be built on the target system.
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
+	region     ::= identifier "{" type+ "}"
+	type       ::= primitive | pointer | array | length | string
+	primitive  ::= "u8" | "u16" | "u32" | "u64"
+	pointer    ::= "ptr" "[" identifier "]"
+	array      ::= "arr" "[" primitive "," integer "]"
+	length     ::= "len" "[" identifier "," primitive "]"
+	string     ::= "str" "[" integer "]"
+	identifier ::= [a-zA-Z_][a-zA-Z1-9_]*
+	integer    ::= [0-9]+
+
+Pointers must reference a named region. To fuzz a raw buffer, the buffer must be
+defined in its own region, as shown below:
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
+Where ``n`` is some integer value defining the size of the byte array inside of
+the ``buf`` region.
-- 
2.51.0.318.gd7df087d1a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901164212.460229-6-ethan.w.s.graham%40gmail.com.
