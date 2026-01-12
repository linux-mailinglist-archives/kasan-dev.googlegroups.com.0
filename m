Return-Path: <kasan-dev+bncBDP53XW3ZQCBB34WSXFQMGQEDBFBUQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 823E7D1500F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:48 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6509eb7c54dsf7884165a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246128; cv=pass;
        d=google.com; s=arc-20240605;
        b=c8/+LTSNQ2rar7pdPPv5CpEj8WU617TtUb0DSTcOY9sNMzzyjHPgUX8DS4Q5/DJF6K
         ItBl03GLEQXFFESNk/pThh2BU5741rqGL8eljDd2LEmbqRCdT4zNRjYQtCFg34p4MkDz
         Y0SRNroyTbfkmcqxixz5U+tpTIFWsFw8jg2Fj+z6DFni2lIEZC5xN0Xy5qp7+p55KUBg
         DRh5/MBlNFgqnd2M1FiPPza1tbp2wMeVMI2hho0TkYPrWN5EEB3vmtrTj97uM5oO4PbZ
         qwztpjk3Lh5c1N97aax4qFhjEuslti1J+F++4/3SC79dxjvXzkf548Vg8FaUUBZPaQBp
         w/GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=LU8X3CbljwbGW6FHMIsO/5Cy0fvMjZi5ywnus4w09bs=;
        fh=X3nQs+XpNglUemCzFEcrezN/NIbL39F1rxlKCJxgNq8=;
        b=PZdq3itSKRGbURQUhzaplLOVCpfkEbQJS8w0d2XDlLbRzor9svFIEzRyzER8NI58Fp
         vbpXFrtKKQkq/HtK5g1djOr2w2q7K16tKY+W42Da2NO8X9eaCgoIu8F/JAAycJD932Fu
         H2uppvZg+TGMmerkQfUo7h4odFweDz2j/XpVR3YBXNWifCAbITMexJa/4ImHl4QgM6G5
         B7J3fKxC+JVl+GF9HKgQT1FITrwhlahs5LFRNK62VDsa/YorLbeTyRSUdjp97EhNiHbe
         CZZmxE+spjRFfcRTCJOCF14nhCy3WmCOIOggOSMvniqYnSaxOeW2aBQX0/7uLZ91PmPD
         550A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DhS+8fPN;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246128; x=1768850928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LU8X3CbljwbGW6FHMIsO/5Cy0fvMjZi5ywnus4w09bs=;
        b=passrcdb5RztKJKKByne+7aM0z/VG8I+2VUPZ/aAI4H2pOnuDTLFaSiOf38qekLba8
         N6TnkZvm+NbualbV0xFdLPggo/PQbKyAjgblx45bmbifGAnqjfq0+cmaSAjFh+qpC2/+
         53AvXFFIOkkt0dIj1GD4M0NaNA3sOq3nFOXw6JMYxPRBFRxV+GVkkdu3vTDXJV6ea6nU
         447d+O2EvRZmVp4bhCk0s8aXVlyRmb9qKmy5U2kjsjLJNVcQIn9amiXpYnzXVA0h4l4Z
         ggOuaOiwoTUOacMaGT72m9Zr5ce9Ry26sdd78G7wtT4nSLwHsXicslFP5MRs8pa38INz
         qgUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246128; x=1768850928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=LU8X3CbljwbGW6FHMIsO/5Cy0fvMjZi5ywnus4w09bs=;
        b=dA7PvmgKSrcrQhhkbNQn6QZrVRg+hgoQLnHlVc0q9aIv0GkYMtNz7ePJ26Zij+H8o4
         rft0db1UvvzXqSrjfY0DjLJHGh+WCM7/UotIVVfl6T+251JMlMUYNboQj5Rwf014utDu
         cXGye5fwL7ovXHnwfa2y3kblwJdrIbU9Sef90GE2sjqYKdwjV+Ipjd+TKSDfLl8hsM6s
         1vStg5hMn8uRL5T3wzRDFdiFLWKGO+iVED+euyptP7eMcQSD4SBm9lkRPa4G0/jwZFBy
         v4nZsT+Wlu07sQEsrVg7m9cWzmIHyO28HYBbDt5xUjN3TPBqzRhsQzmrF4ASAYDrVBxH
         pqdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246128; x=1768850928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LU8X3CbljwbGW6FHMIsO/5Cy0fvMjZi5ywnus4w09bs=;
        b=AXtr3J+/X34wz1tQ/OCysar81WDsNWLYMgWDCgwODkftaWvXIMLXLwENjq+1wRC7tE
         Uyz+31+FhjGPX6EqtW6cksHRCIttrk5nCCeCOwwPVqJ/mnRHkivg57Qf0+JIdV/TpQcS
         CujdL4ZpO/VpxI2nZTGx3G5wyTfg/gc4pN/hJSB8atjjCh3jGqNRkkbBPnmRimD4DPdX
         L7A0q3OdVNS14ko6f8JBz/5MtXBMHBB0+ViMP9zAkx0/RmmxGDM3xxbaf2Z4VNu3KDoN
         UcixxKqgu+7UE5Wr8AdabuEUrwW+Hz5biA2Rtla5nAOC5qSbxrmbgYIIo2kU8P1PpMPz
         ioXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeUYmSpnEVppVHicLxsOY3Wg3EGaAj82lQEyhbwd2oaSdUkQLwcAXkz/yph8Vg00Eag0jD9Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw/LTNJupa7QXaWTE6SiccINi9MeO1YhU5yOE0eYYhAZ4j8lG4Q
	RtKdZfmkLUD+rxEHO7dMmDycrTzlsoaxZTsxpmuh1lUgSI3c+LiNpaO5
X-Google-Smtp-Source: AGHT+IEFF4vw+ErEtqS9VT1atuy47cZOc5VxpakHacmNP7Jt9G+9IIiowRkAZH2MB7tLm0R94wB5SQ==
X-Received: by 2002:aa7:c1d9:0:b0:640:a9b1:870b with SMTP id 4fb4d7f45d1cf-65097e0740dmr13238551a12.14.1768246127885;
        Mon, 12 Jan 2026 11:28:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HJCLVrq1NFvzoSYXyLkW/g+7h7M7BYvsLS+8E9Wuu6sA=="
Received: by 2002:a05:6402:5154:b0:641:5a07:215b with SMTP id
 4fb4d7f45d1cf-650747c86dfls7188379a12.2.-pod-prod-06-eu; Mon, 12 Jan 2026
 11:28:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUTl6YrizHFAnSFSf7KAaSh/kbuc6ae3BL5Odo8Zqy3P400u6ayZcmicfD/ByKjePazIV3sQ8f1Ye4=@googlegroups.com
X-Received: by 2002:a05:6402:330:b0:64b:8d7a:71cf with SMTP id 4fb4d7f45d1cf-65097e71266mr13110735a12.26.1768246125282;
        Mon, 12 Jan 2026 11:28:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246125; cv=none;
        d=google.com; s=arc-20240605;
        b=XnDF+yWifxFX2DeuLxDZxaWK0Jk2Ol6E52wj55mwSb3+e+U5cvw+qUFDf6ODWT7070
         4iE+niUVYWJMt4b2tN5dcMnZlJn+7VoIIu+MSxL/MSNnAdkRenE66odCwaqTrVQ7dUWL
         xZQi8I5AVqxRZHYUl468w/QerL2sfpfCmnFKs1UZutG7+c/hfm2IxaQaZFLu6W9pj71N
         zoijgklZHwMMCCTjq4pTrqCdbZvmR1BAyIOMsYu1HxpzUGKqh0bGLey7H6WPhDRW3ADm
         ttxmglHy8bwiOVdMs2Nm2S6DnDNMyPLew7+1dqLrIjKWWstHVqI9OYqxrNIJa9mwGIbf
         j7mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CTAiuUIttCbMVHuYgOxGCwhf3npydnD/rY6k0kTCwMc=;
        fh=SIzcHFWyjdm1W1v+racnb12P/ZwU3xEWgS4OUrCMWUA=;
        b=AxcUKwPTZhWkULgD1s+Vx+capTk3EV1BTeMGAOCT6ed1T7baKvvmiJpxzodPrCwC8R
         Y2fV0rUkr1LUBYxz9XtRMHM7BkuutLlJu4T+oGiBxiqzRPEVDsAeeWjPe04XoPhQPrSE
         UopgKk8d6ZAhtd6Ja5130iD2UO1r36Ze8dr0S6A5ybtOOCfZUQds69HRNoHUOalJMUSJ
         bFphssFVQXHw32PWmzM2J9BDt31pBee5Z4adVjV5UiUmmlcgNFJmIp5nDEiwnCd65HQj
         dd8m6l2PL6JJ6BntQXc/YOHpoHMHzqze1R5YdRZz+GWVebI/s4PP07XUQJLg4Ac7Pybf
         ZTJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DhS+8fPN;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d70535dsi367513a12.3.2026.01.12.11.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id a640c23a62f3a-b8010b8f078so1126969566b.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVQ9AYS8Y3EnmQHzFI0RxJYE3mU6uyOOy47/NMdEi5XNCHpwwRDq5RWnK47fwZ8JraNgciVDtUDAfY=@googlegroups.com
X-Gm-Gg: AY/fxX5F8V/FFzo9onVsUvbRdJDBuOqO0dH39DV7nUI+qTLccBRCHwoBRMY7vKDyANN
	wv6i+ZvysWeKYb+4loYw882/CtlogzbrRT2DJTn9A90KCb5Esbi5ZcDgf6bmi1H/30fPsU8U10b
	cpBa9Yjhv/D6SAQPvx6z6BztRMechySDuN1VcGHK/xjz2re4J/3tKupy93g3Wyd4RSv47DPP1ej
	0rQ87zZpf/+J1kYin5XAGEqbAbfca2ZCKYbn9Kxd3R+nSl34/AduAmgcC/AE7GtM8lw6RV4FagG
	EXcWLSu3EBFxyoDXhwYg72OmerNTcApVj0DQGI4QXlAxMQJruBhfblx6I1KEn2jaIeiUVc9Ez0b
	P+8Ul7MH4PyD+tq9HUJ4WBBDqehGhxcB6g9f1CUqYPM1Jye+xfml/TFCFeaSYsU5k9zhMcYQy23
	29vqqn5RByU4emDmqREO3aO2o19bKIOCXxP/cqNr0U30RFBzZ01A==
X-Received: by 2002:a17:906:c141:b0:b87:1c74:a8c6 with SMTP id a640c23a62f3a-b871c74ab49mr405692366b.57.1768246124624;
        Mon, 12 Jan 2026 11:28:44 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:44 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	gregkh@linuxfoundation.org,
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
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: [PATCH v4 3/6] kfuzztest: add ReST documentation
Date: Mon, 12 Jan 2026 20:28:24 +0100
Message-ID: <20260112192827.25989-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DhS+8fPN;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add Documentation/dev-tools/kfuzztest.rst and reference it in the
dev-tools index.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>

---
PR v4:
- Rework documentation to focus exclusively on the `FUZZ_TEST_SIMPLE`
  macro, removing all references to the legacy complex targets and
  serialization format.
- Remove obsolete sections describing DWARF constraints, annotations,
  and the userspace bridge tool.
- Add examples demonstrating basic usage with standard command-line
  tools.
---
---
 Documentation/dev-tools/index.rst     |   1 +
 Documentation/dev-tools/kfuzztest.rst | 152 ++++++++++++++++++++++++++
 include/linux/kfuzztest.h             |   2 +
 3 files changed, 155 insertions(+)
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
index 000000000000..f5ccf545d45d
--- /dev/null
+++ b/Documentation/dev-tools/kfuzztest.rst
@@ -0,0 +1,152 @@
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
+The framework consists of two main components:
+
+1.  An API, based on the ``FUZZ_TEST_SIMPLE`` macro, for defining test targets
+    directly in the kernel tree.
+2.  A ``debugfs`` interface through which a userspace fuzzer submits raw
+    binary test inputs.
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
+section during startup.
+
+Defining a KFuzzTest target
+---------------------------
+
+A fuzz target should be defined in a .c file. The recommended place to define
+this is under the subsystem's ``/tests`` directory in a ``<file-name>_kfuzz.c``
+file, following the convention used by KUnit. The only strict requirement is
+that the function being fuzzed is visible to the fuzz target.
+
+Use the ``FUZZ_TEST_SIMPLE`` macro to define a fuzz target. This macro is
+designed for functions that accept a buffer and its length (e.g.,
+``(const char *data, size_t datalen)``).
+
+This macro provides ``data`` and ``datalen`` variables implicitly to the test
+body.
+
+.. code-block:: c
+
+	/* 1. The kernel function that we want to fuzz. */
+	int process_data(const char *data, size_t len);
+
+	/* 2. Define the fuzz target with the FUZZ_TEST_SIMPLE macro. */
+	FUZZ_TEST_SIMPLE(test_process_data)
+	{
+		/* 3. Call the kernel function with the provided input. */
+		process_data(data, datalen);
+	}
+
+A ``FUZZ_TEST_SIMPLE`` target creates a debugfs directory
+(``/sys/kernel/debug/kfuzztest/<test-name>``) containing a single write-only
+file ``input_simple``: writing a raw blob to this file will invoke the fuzz
+target, passing the blob as ``(data, datalen)``.
+
+Basic Usage
+^^^^^^^^^^^
+
+Because the interface accepts raw binary data, targets can be smoke-tested or
+fuzzed naively using standard command-line tools without any external
+dependencies.
+
+For example, to feed 128 bytes of random data to the target defined above:
+
+.. code-block:: sh
+
+   head -c 128 /dev/urandom > \
+       /sys/kernel/debug/kfuzztest/test_process_data/input_simple
+
+Integration with Fuzzers
+^^^^^^^^^^^^^^^^^^^^^^^^
+
+The simple interface makes it easy to integrate with userspace fuzzers (e.g.,
+LibFuzzer, AFL++, honggfuzz). A LibFuzzer, for example, harness may look like
+so:
+
+.. code-block:: c
+
+    /* Path to the simple target's input file */
+    const char *filepath = "/sys/kernel/debug/kfuzztest/test_process_data/input_simple";
+
+    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
+        FILE *f = fopen(filepath, "w");
+        if (!f) {
+            return 0; /* Fuzzer should not stop. */
+        }
+        /* Write the raw fuzzer input directly. */
+        fwrite(Data, 1, Size, f);
+        fclose(f);
+        return 0;
+    }
+
+Note that while it is simple to feed inputs to KFuzzTest targets, kernel
+coverage collection is key for the effectiveness of a coverage-guided fuzzer;
+setup of KCOV or other coverage mechanisms is outside of KFuzzTest's scope.
+
+Metadata
+--------
+
+The ``FUZZ_TEST_SIMPLE`` macro embeds metadata into a dedicated section within
+the main ``.data`` section of the final ``vmlinux`` binary:
+``.kfuzztest_simple_target``, delimited by ``__kfuzztest_simple_targets_start``
+and ``__kfuzztest_simple_targets_end``.
+
+The metadata serves two purposes:
+
+1. The core module uses the ``.kfuzztest_simple_target`` section at boot to
+   discover every test instance and create its ``debugfs`` directory and
+   ``input_simple`` file.
+2. Tooling can use this section for offline discovery. While available fuzz
+   targets can be trivially enumerated at runtime by listing the directories
+   under ``/sys/kernel/debug/kfuzztest``, the metadata allows fuzzing
+   orchestrators to index available fuzz targets directly from the ``vmlinux``
+   binary without needing to boot the kernel.
+
+This metadata consists of an array of ``struct kfuzztest_simple_target``. The
+``name`` field within this struct references data in other locations of the
+``vmlinux`` binary, and therefore a userspace tool that parses the ELF must
+resolve these pointers to read the underlying data.
diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
index 62fce9267761..4f210c5ec919 100644
--- a/include/linux/kfuzztest.h
+++ b/include/linux/kfuzztest.h
@@ -3,6 +3,8 @@
  * The Kernel Fuzz Testing Framework (KFuzzTest) API for defining fuzz targets
  * for internal kernel functions.
  *
+ * For more information please see Documentation/dev-tools/kfuzztest.rst.
+ *
  * Copyright 2025 Google LLC
  */
 #ifndef KFUZZTEST_H
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-4-ethan.w.s.graham%40gmail.com.
