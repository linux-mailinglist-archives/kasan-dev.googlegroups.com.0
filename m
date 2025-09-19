Return-Path: <kasan-dev+bncBDP53XW3ZQCBB7W6WXDAMGQEYEE3BTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BA82B8A1F2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:08 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3e8c4aa37bbsf757519f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293888; cv=pass;
        d=google.com; s=arc-20240605;
        b=F39IWdM54nmYdYekjeE9xXQwMkFW45L8JYeowLTegf+YhD/3feA3t1R+UZdkbv7wr+
         dyfE9dW0ju9c3PNK721Fptwha5Ee3UVlA0gp20P13Yo4Y9jra4hco751p+hJGu0fw7QH
         nqlH1gpwtr/Rsl2TBdxNbZTel6Natq8BtzkpyF1BiZDv5uEdy2erj9tBp8PYl7lGr4HL
         kJoxvbmLgTFSzMhLtxYJIqQNgGAKz1+L0WRYEuMRz4IACgqGjxRngr1Wx0ECW/9oH6yb
         6ehAZlWU1uHOCb5VgDt5LI8ywnjaS3dHURsrnVJeeuALdvqY300PX8pDHYJ1mmVHa4s5
         t9Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Xuc3qwerkFz9vy79ZC4pml9CXaYRKr1tcVEeg0uPWnE=;
        fh=LFD6pLGiLqFCmOKPZSPwQ3mT0Qhr8HowvDcGQGj4NpE=;
        b=FF8D0ZK36+1x7ysXEWhoD/E/v21qzmOzbxKo+i9Fwmrr6Ss9yc76CCpAyadDhUacpC
         XNmzcNFLv+S+o5zFfg8p7RrLE4HzGbOguTh8ndhoFWFPaB+UQCxhGO+g6qSrb+6yTkLn
         hLJDheJxEH/p4xwjzAh3yHHSk3NIDJOQ2wSIif9eNSXkXXkngPx+wF9rrQvnvt27+YhN
         Z6EA0LSdkn3ZB2atZMMDrOhUCn2mlI/WwLhP98bKf11sZge7jkXmg/Sd21lVc4tDshGa
         OnyYkPZI/qY1egQ4/isUHXltMgt3/69ylQBzUtq1slP/P1getMQV6XdZyla9/UyiRTmq
         agzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=j2xblvp7;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293887; x=1758898687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xuc3qwerkFz9vy79ZC4pml9CXaYRKr1tcVEeg0uPWnE=;
        b=v7GKAx541bRO4C5xnt7d0eSO316elnkxZJAyiCBLcB0h3bW/uBJAOivYSgwWsmxL39
         yqtn4gW/pcivre9dDPMyCiIpQcUCPfRdO690UXn77i+LvVkJ0FW8gNPgkS/rJNEVazjw
         fT+7zcea3lR8onySBNqDeaPfO2LL0O6kmvnRhekSpRdl9ZjFn8RsN5oEYy1xitiaI1cZ
         e2bXjBdbNxAN/8kAMZj/cCiSZ1W9oO6qxFqUTsiDK4p2d2xjTB9pBHbzQKnWkTekMsSh
         b3UbKjP9E3w2JU8QCa8XpJFdH8Xyi7l27NwEeYEe/2ULP9RC7pJMOvydkrJcuLLxsvB3
         X8Tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293887; x=1758898687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Xuc3qwerkFz9vy79ZC4pml9CXaYRKr1tcVEeg0uPWnE=;
        b=Hl/V8uC+/80maabEtnFFSkhy3NxyOF5MT0mHTqSfWGWtkv2+Riwf3ppXvaun6b9gQy
         KHbd2gZxZ2FmV4F0qh+IaUZTFM8fDwnd0motg+UbhUJwtYKv+jGVPQlP60A7DYVXYMFm
         3670dLvtHcYUQ0DMnFJWZUfw4d9QzOhbaR34FTfGyoP9Xpv0RY46YAAzO4vPmic2rHga
         8hANqjEH5lW2f8a/WeZ9Tf5xPw67Q2Y1Wn48ysth25KuI/99fdnFoPTj3hW1iGI+EP8g
         KMGJSestAX+PyGwn8H4pCuzoAJIM5znlOm88Yz92WFB2C/4FtzlJl/fAgdxnCfwSji0d
         Yf4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293888; x=1758898688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xuc3qwerkFz9vy79ZC4pml9CXaYRKr1tcVEeg0uPWnE=;
        b=erTXmcUfeq+tHNCSvgAx423Xi26lQvEMHD6d1EB6xCenXsq2CSW1Pe3W8v4Gi/w2hp
         VrZV0PkWiU/Q8+qZA1OLo5S/1vJcoFxAnPwlgxnKvpYsaxd8u+Qj9K30oWhfQRQ9Rm26
         gBQwq3Wg64uTAK8g5Jh/2aPwaCCdGZTQmqkBPQP48YXSlTPmyOUOvExjYMwYNzblObbg
         mpqaMeBwrVJj9EeUBAH6El6I850q4Zl1zkWjcZtBQGQGrEZ9oQf5ruHYcmvKTovntRas
         JqTi0/oqhbfGyC2igRrKkUg//ygoIVKD7XcNHKlkajLqAZiMbwR2qAhCjVwHTCbWvl8A
         DXHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmQck8IWwi5V7dWmKsxVSOkEO1QJIWrrif9ho+W+YpP1F3aOkroaKuC///i26U8azdlzRUmA==@lfdr.de
X-Gm-Message-State: AOJu0YxCNdxoOGSdCDRf0fuaMBow5OibGf1L00dnUXIDN1gUxt/2CGdN
	EN0in19J3hQZ/l4ZRAgt5zuhaB+TMKEgRiqVjGKFIVj8ndrA9nLBlMzl
X-Google-Smtp-Source: AGHT+IFREmcLZ7Az6TrNYB96xkF2HExfvzjxyt4darqPFmqUlOXrtBe76fCPEss325LSDzCqX/WgYw==
X-Received: by 2002:a05:6000:2505:b0:3eb:5ff:cb33 with SMTP id ffacd0b85a97d-3ee862edcaamr3652503f8f.53.1758293887283;
        Fri, 19 Sep 2025 07:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6cT3CN9wqNmt7cRJwY2KIMhEyaVj+XEisk7R9x0eNHJw==
Received: by 2002:a05:6000:4013:b0:3e1:7964:2c28 with SMTP id
 ffacd0b85a97d-3ee106a1761ls1252882f8f.1.-pod-prod-01-eu; Fri, 19 Sep 2025
 07:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0KWkE6wQF4TpV+I79YmRdQlNyWxex2l4Ag+FTWR6wnz+rOmBVvHZf1ZIdtwyY6tF7ySMUjuhKdCg=@googlegroups.com
X-Received: by 2002:a05:6000:2902:b0:3e9:df10:c135 with SMTP id ffacd0b85a97d-3ee7c5535e4mr3127973f8f.13.1758293883882;
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293883; cv=none;
        d=google.com; s=arc-20240605;
        b=JBLJhs3pYME+SiUSgd6KRKHPbnbucAS71aMreJDAOFJTK2s/KU+iGCnzwJl0wKAp+C
         aSP6E7InYqN/YeTLL1SkSDg6uJRt7QhDMLzBT3EOdzpfsSRUfxnJ5qVyGgUEHqAt7XDZ
         ctyjn/ZRae7QlemLG17uHZEWYapJ9jMOo42pl6AvsJ6dbrFoixCpvSIz5qLG/93Do//R
         t25evTGEzGMuZX8+aYTc1qqkM225ZsZqjjOlOpWlApj0vlxLxh2ml/FuGb4Vef/qrim6
         FW4JvZels0hMnBlPJYvhF0EXo6kEcFNtUJDXy4f7ahG05DuV/uJQgRm+RFygAq5Fg7FP
         YL8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zunbl6fvIHEqkfAd29udw7Y98ixve3unSQwmEkkt7GA=;
        fh=GYI4S1giZhwzjqBrQ5lCAH9Gam0JPoByRK4db3d0Xv0=;
        b=f+awja9q+vjDb7OOd6421zh0FcPVoMhwjQIgitC2DgZ2mwK2DAdTPojBHw5AKJdPIj
         7Y1e0eY7k0/pkefb92l93Jqg36LvWxR/LRlwrIq+JeFmKxd69M+uDCwrIam9tLo1yCHK
         U8S+h7qwc4riNxxs3SDAkrJcwfl63rnO/LxWFQ/ZcGbosyH2fJ++1YHivq0IGi6QAyvo
         esskP9CLtZOzCLbBA6b77zjWvAVS+MpnSPuKXe6bqNqN+fB05lL4iRBaZ/h2FvcCG/wv
         p3AxLpMhlKbBva9dP5Z9cYN6a3N3u0tySzkRRiZtqracue0f9+0BwWgdHAbuuob1cdFe
         t4Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=j2xblvp7;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f3208575dsi3161685e9.0.2025.09.19.07.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3ee15b5435bso915077f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWsGwGOHKSTcGwsjm74CA0hXDIyKNT7CRCLcc+wn8tNVOaTdjK31bzFGNRvpFtMdgqzUaEv5qcm4cA=@googlegroups.com
X-Gm-Gg: ASbGnctDJ/xRxq+zTiL64WukEiTqzR0tVE3iSY7ngfkdLukSg2Y/h75WzDnWF3wqqtl
	zUvZWuDxByP36ey37JuW1GfF/gxkyuF6yH0XOAn5VAcHM7mA4sVprtmn4RfuEfbERkdiB/pY11D
	nJnpTR52/nBxCeMTAxCWKKIiIfKw7f3Yoe9iwPPQvqoqeEN9YWz5rLjoAzLWwPD2la/ulw7SB5A
	cmY1xbiDCqQ2q7QygwVbe3G1e0y8f1Yo8brXm7daSUyeo0hAqv3Dxtt0mQ2H2FNqam037n07AEy
	SoHVnbg7d3KsEJjwL7NH1flTVJxiiF2hT5ao07C5h6dhXCtsWOf/PDAxibgXMZjn9jInw99l2Mw
	GD1k85x/08ulbcnqk34G1I0jeC8Q8coqHDpGBxHG7wsXyWVMN4KEunOn5KbmNBg4MXkbvK43O0J
	s1fxyBp9XxCLD4SaM=
X-Received: by 2002:a05:6000:2408:b0:3ee:15b4:846c with SMTP id ffacd0b85a97d-3ee7f606f17mr3174553f8f.28.1758293882976;
        Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
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
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 05/10] kfuzztest: add ReST documentation
Date: Fri, 19 Sep 2025 14:57:45 +0000
Message-ID: <20250919145750.3448393-6-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=j2xblvp7;       spf=pass
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
PR v2:
- Update documentation to reflect new location of kfuzztest-bridge,
  under tools/testing.
PR v1:
- Fix some typos and reword some sections.
- Correct kfuzztest-bridge grammar description.
- Reference documentation in kfuzztest-bridge/input_parser.c header
  comment.
RFC v2:
- Add documentation for kfuzztest-bridge tool introduced in patch 4.
---
---
 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/kfuzztest.rst         | 385 ++++++++++++++++++
 tools/testing/kfuzztest-bridge/input_parser.c |   2 +
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
index 000000000000..0c74732ecf21
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
+The tool can be built with ``make tools/testing/kfuzztest-bridge``. In the case
+of libc incompatibilities, the tool will have to be linked statically or built
+on the target system.
+
+Example:
+
+.. code-block:: sh
+
+    ./tools/testing/kfuzztest-bridge \
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
diff --git a/tools/testing/kfuzztest-bridge/input_parser.c b/tools/testing/kfuzztest-bridge/input_parser.c
index b1fd8ba5217e..feaa59de49d7 100644
--- a/tools/testing/kfuzztest-bridge/input_parser.c
+++ b/tools/testing/kfuzztest-bridge/input_parser.c
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
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-6-ethan.w.s.graham%40gmail.com.
