Return-Path: <kasan-dev+bncBDP53XW3ZQCBB2GOUTDAMGQE4EAN3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24DF3B59180
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:30 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45f29eb22f8sf11640705e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013289; cv=pass;
        d=google.com; s=arc-20240605;
        b=fcZ6nVsX4tN2jk0wu75gj6dzPnJlJp1jaBtmSg5Q2/pScfMQMdLqY2l+iIQCSPRToS
         jFUzwoDgbdKdtDPBWHA+K3xwriIlIst4Jm9SsBmtVZgqjJHCo3supggCirPuCfO8iPxg
         MpmbkmCn80HGNpYr63g5AlZZObSpev8zXdWeBo2j0qLGo00WbSj/IwrX936Iln/HwJx1
         G+5mhhC4AtJz/fnF5rdWbHcKJ7CgtF2EFQUMkES884PnahucFKyGKw4m6VkV+6U+NqVM
         5LwwzG7AwjILKc/2qfqZ9SqJcK8LniYuSwpTmCEQZSwJguP86R245iYI0MOLaDKO5Sup
         fWEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=F4GwT+k/dq7EWW4tlrAOkRQj24oRkCt2xH+27Rh0nbk=;
        fh=vdF64GSizNp6mrb1s8UdlxcVlwnUB4REyrD/Eo3weQE=;
        b=Yk8Xj+48SR40lTx/9GAB4cAuHR1pxk5VRmFEJ6gdSOv69EpAxHVAQ2uZSJPn4bRjIr
         P8YEGEJXKwIMPowa3V0tQuhyCLLyM0P9z28Hirapwrwv3S2/ehSQdBzo958THS2OxZiy
         Krbnnfe0CfftADtEQ+ns6HEFlEe8JZZTvDviRUmo3K6/PDCAmgXGNGcXesnm3NyicH5T
         yg5I7cDR3aWIcTWhTO6tydHvmjMWOheqKDAuwBSGrbe9cFz9Vq5+AgOxaTpYc+V9U+Pu
         S2F8fdc+5qDtJIwBF2sSQnVguAVCS/pX3IYhHwVNetehqmevVl78x/Am7Mcl7lZHuwpC
         C2OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LrJj3LMd;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013289; x=1758618089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F4GwT+k/dq7EWW4tlrAOkRQj24oRkCt2xH+27Rh0nbk=;
        b=V0t14uBVKgh62H/n6YCy8O2Up/lozITKdBBgkfg/NCfIlBMXyDAsNvD9OKDvIMbcUB
         7xoTPVJ2wPiKqyqqpBcAON5XukldPujRboaD1obMSNhy/so3wHs2uknKDQ3E5aUrQaiM
         VqXhavaf6zkNTrsTtvk9EKOHJmBG0tCDNGCaM0Q93HFjMBBjfRjWIY4TjskHsZ0bgTiS
         3yIzYfVebidzImCAr1Sg69C4QporUyp1TGRufunH/Akv1lLJrjUM04g4R6rTFaop0QfC
         WqMQ0djxXf/C7bIrYCAJ9dnlK9sb8e8qmB2Ykp35lK7ZP2SKMkoJwGqQjeKHPmd0Grs8
         ePEA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013289; x=1758618089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=F4GwT+k/dq7EWW4tlrAOkRQj24oRkCt2xH+27Rh0nbk=;
        b=Sh7uPGugNKi+DxzQJ32y92muSg0K+TH5m7gLnz4KKXFXnLbp4H2KLer7hxrBwpnk53
         ft6nbWsqRLxBDg94xRBLfld2Eyag6whaKcHEMf9TuB/HdO5MV9CX0XMdNIw7SpAevq+E
         c6JsY9vhR8HyTg/vB2C2DPKoU13zAo+WDUqPHxlKUSXOBBPh9S/wojtnyFA+z/cgqq3I
         FoEQyzhKDOBVckgDfKEISpmGpLBTBTmyByBuz0cSZr2GJVAbM9XMGn3fOv94Nc5IB7t9
         6mW0RyBTWrsiQVVC4DGfDGt7iurqxUQxl9vNyCGW8aeNlwgTo5zrnVa0zkntfVkkOa3+
         Sirg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013289; x=1758618089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F4GwT+k/dq7EWW4tlrAOkRQj24oRkCt2xH+27Rh0nbk=;
        b=B8Z1v7r9kuGIhbLSlzivI77Q5G/4kYq72JZG1KO6bmS36GfCEWivX3oNPEnxNOoBex
         HWKwIrXi24XOW2FUi5Y4po/aR0Z1kuLSKt7hCh7ZBX6+Bcb0Sstw0Pll3LdgfwEe47+H
         m4T1/mF6HrtgxxaB+yX5SjdgbIfe0oFh1ADuPGjMiJnfIPb6lgED3sWLWjypUy4/fS1j
         SsKbh3vCl1JwYyM8TCSvDx12dctpmxA9NYoEP9nFUChwXPzyStjm2SesaA825JhPjJJZ
         TYmnRUZhBTy4gSyY9dxcI27nwpcDH4EJZsyRC4L+BIffs9/B5aADXTNlzG1ktqrWP7HQ
         bALQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCcCtNRFx0FFYWsFUEvtUb2ejKqCuu/sIUrfiRl5fIhfMVajeFB1rAa41AmRUYimtXmvYCOw==@lfdr.de
X-Gm-Message-State: AOJu0Yw+hMPUP2Lim0RRlhAVXv5QKHqKmVBm3Gz/niVv2xEds2Zo625c
	aKpBVSmNGGcGvuy57qiTrh9uUjFX4WDXstXSaOw+8ziXp/949n4AhHfE
X-Google-Smtp-Source: AGHT+IFMPM5cOo1eTkzE4cQz5/QtUUY0mes1Tc4faR5/EJ7cGLA0HNB+3JXvg0K8ssE1LHv1H17KvA==
X-Received: by 2002:a05:600c:45c5:b0:45d:f7ca:1a9e with SMTP id 5b1f17b1804b1-45f211c842cmr132413575e9.1.1758013289504;
        Tue, 16 Sep 2025 02:01:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfeECbPclpoXHQyguLFKv3v6pQWs2g1Wrw68q2vd6QpWQ==
Received: by 2002:a05:600c:1c82:b0:45b:5fbd:3012 with SMTP id
 5b1f17b1804b1-45e029f1e45ls28480905e9.1.-pod-prod-01-eu; Tue, 16 Sep 2025
 02:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/jQxCMiR7x5uZPYAVUKVYlE7nPCkrNgIwmhX69CDT7sCbYFXL7wFo8y6hqoYrPUrSprWi8I5Z320=@googlegroups.com
X-Received: by 2002:a05:600c:1911:b0:459:d5d1:d602 with SMTP id 5b1f17b1804b1-45f211c8371mr137266465e9.3.1758013286498;
        Tue, 16 Sep 2025 02:01:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013286; cv=none;
        d=google.com; s=arc-20240605;
        b=Zl7KTx8nxWh5vAblq6Gdy9t+vtWoM/4OITLkBbk+oJUr6RV6vjHcjGIT4dhN/pOfb6
         BsfOGn8s494+bhsXY6UOnbFcflaZNbGv6eASQ7e5Mr5bS3fDArre4jJ9cug8DzYPBz46
         i/KKyaUgjfiFsKOG/RAGjgWfw0jFt0J2YVOTvhUpb+TuH22fHmAwxY1oq2LZ7ewEW1qt
         0KCTO19hkaoDLCxUuMmpvxh2RsvyaUyq9UVaJkhAog07exqYao65Tn/C8+Fzty9QLkkn
         BaQBeoYzAlxtN5p3oxHxBVbC9F4qo0fuobi7QF7FWhA6JiDB5io/c0J5ToToePKeS0Jr
         GbNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xdmcBIJJ/dIrmboz2dj1USPN5mnOnIS9n3oFxB4eaBc=;
        fh=A6DLn4436x3EUbOuhGPbMU/Dz90q1jjA+0hdaT92l0s=;
        b=HGF/CvnOC8xH4zbn2KX/5s3Q/Z3OhKojvEeLIkTjJQDZubHumMKmX+4f5bqflSnQhh
         NsL5BgmDR3yXGAFg/3a1FCdQzaTu1i1uUDLb8LyZFsd5sR0CeNp+ZfwjT023BjzoG/3S
         oSLby/UD3wvsQoqw5EV/2bO1PeNw6G3mRNQYZEsbKGymfWTOKm7HA+y5Ae6PXsJe2R17
         EfLB1h/7lj6J6YHYb0tftgBBZzPPO/vUJY1HnX5xORcMZAsdv02z2EttO1jLgK4gedmY
         p2RtlFqH/9NBde7vhmtkCxiErLSaCtbc/cYbbYO+EjAdIpZGdg3vvkBoKaWVGjz41w83
         Da3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LrJj3LMd;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ec4efa8d18si37337f8f.3.2025.09.16.02.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-45df7dc1b98so35313485e9.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvgUA4d1BmgLhsUEUby8yYT/ESpflfCg5HoPmAVctLgzGN9X8rJi4X71E+nIQ3VAB9oaGmu6fvY1M=@googlegroups.com
X-Gm-Gg: ASbGncvFGwu7BCVLeNpiV8jaaAJWfOPlCA0i3+EmwSphMFzP/pH6SBQKKiHq1aH5Yt4
	/YWjaPJXbK1ztr4X9GwIrH+IdbPw3yPkbsdDig2Je1hbLd3I4v3A0DyuJa5cafs5bYjQFPNfq+M
	B8tLeNujs136GXtn9Wx5mTCo6D5aRP296wy4SjxotFJBCQirsvmAeukqVDtigqwcV6nDjiySUGY
	605ItY0qn7D461eY6Wys/7zjb+hN+Kg+tOcdS5A+dmfJYYDOLY/QE4Pu20ZoGt+rU3kzXQAnG6O
	hQu0lUxifd3QeFsX5/4iLdjp6YOkj5Nb3bn69j2hTo1Yv6I5kMb6b+OFnHTkuQVx9unfD0mhquv
	MdtUPRxt9b9MNUVg0c9bLZWFFlgyvBkPZOrmlKYYRX5RJLEFpJHfASf91AtAPxAOUn3BCvXoF56
	RYdiDCb6IdMNnX
X-Received: by 2002:a05:600c:12c8:b0:459:d645:bff7 with SMTP id 5b1f17b1804b1-45f211d075emr98840705e9.12.1758013285667;
        Tue, 16 Sep 2025 02:01:25 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:24 -0700 (PDT)
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
Subject: [PATCH v1 06/10] kfuzztest: add KFuzzTest sample fuzz targets
Date: Tue, 16 Sep 2025 09:01:05 +0000
Message-ID: <20250916090109.91132-7-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LrJj3LMd;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add two simple fuzz target samples to demonstrate the KFuzzTest API and
provide basic self-tests for the framework.

These examples showcase how a developer can define a fuzz target using
the FUZZ_TEST(), constraint, and annotation macros, and serve as runtime
sanity checks for the core logic. For example, they test that
out-of-bounds memory accesses into poisoned padding regions are
correctly detected in a KASAN build.

These have been tested by writing syzkaller-generated inputs into their
debugfs 'input' files and verifying that the correct KASAN reports were
triggered.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
---
 samples/Kconfig                               |  7 ++
 samples/Makefile                              |  1 +
 samples/kfuzztest/Makefile                    |  3 +
 samples/kfuzztest/overflow_on_nested_buffer.c | 71 +++++++++++++++++++
 samples/kfuzztest/underflow_on_buffer.c       | 59 +++++++++++++++
 5 files changed, 141 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index 6e072a5f1ed8..5209dd9d7a5c 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -320,6 +320,13 @@ config SAMPLE_HUNG_TASK
 	  Reading these files with multiple processes triggers hung task
 	  detection by holding locks for a long time (256 seconds).
 
+config SAMPLE_KFUZZTEST
+	bool "Build KFuzzTest sample targets"
+	depends on KFUZZTEST
+	help
+	  Build KFuzzTest sample targets that serve as selftests for input
+	  deserialization and inter-region redzone poisoning logic.
+
 source "samples/rust/Kconfig"
 
 source "samples/damon/Kconfig"
diff --git a/samples/Makefile b/samples/Makefile
index 07641e177bd8..3a0e7f744f44 100644
--- a/samples/Makefile
+++ b/samples/Makefile
@@ -44,4 +44,5 @@ obj-$(CONFIG_SAMPLE_DAMON_WSSE)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_PRCL)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_MTIER)	+= damon/
 obj-$(CONFIG_SAMPLE_HUNG_TASK)		+= hung_task/
+obj-$(CONFIG_SAMPLE_KFUZZTEST)		+= kfuzztest/
 obj-$(CONFIG_SAMPLE_TSM_MR)		+= tsm-mr/
diff --git a/samples/kfuzztest/Makefile b/samples/kfuzztest/Makefile
new file mode 100644
index 000000000000..4f8709876c9e
--- /dev/null
+++ b/samples/kfuzztest/Makefile
@@ -0,0 +1,3 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+obj-$(CONFIG_SAMPLE_KFUZZTEST) += overflow_on_nested_buffer.o underflow_on_buffer.o
diff --git a/samples/kfuzztest/overflow_on_nested_buffer.c b/samples/kfuzztest/overflow_on_nested_buffer.c
new file mode 100644
index 000000000000..2f1c3ff9f750
--- /dev/null
+++ b/samples/kfuzztest/overflow_on_nested_buffer.c
@@ -0,0 +1,71 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * overflow on a nested region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_overflow_on_nested_buffer
+ *
+ * This test uses a struct with two distinct dynamically allocated buffers.
+ * It checks that KFuzzTest's memory layout correctly poisons the memory
+ * regions and that KASAN can detect an overflow when reading one byte past the
+ * end of the first buffer (`a`).
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "nested_buffers { ptr[a] len[a, u64] ptr[b] len[b, u64] }; \
+ *   a { arr[u8, 64] }; b { arr[u8, 64] };" \
+ *   "test_overflow_on_nested_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `nested_buffers` and specifies that
+ * both `a` and `b` are pointers to arrays of 64 bytes.
+ */
+#include <linux/kfuzztest.h>
+
+static void overflow_on_nested_buffer(const char *a, size_t a_len, const char *b, size_t b_len)
+{
+	size_t i;
+	pr_info("a = [%px, %px)", a, a + a_len);
+	pr_info("b = [%px, %px)", b, b + b_len);
+
+	/* Ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < b_len; i++)
+		READ_ONCE(b[i]);
+	/*
+	 * Check that all bytes in arg->a are accessible, and provoke an OOB on
+	 * the first byte to the right of the buffer which will trigger a KASAN
+	 * report.
+	 */
+	for (i = 0; i <= a_len; i++)
+		READ_ONCE(a[i]);
+}
+
+struct nested_buffers {
+	const char *a;
+	size_t a_len;
+	const char *b;
+	size_t b_len;
+};
+
+/**
+ * The KFuzzTest input format specifies that struct nested buffers should
+ * be expanded as:
+ *
+ * | a | b | pad[8] | *a | pad[8] | *b |
+ *
+ * where the padded regions are poisoned. We expect to trigger a KASAN report by
+ * overflowing one byte into the `a` buffer.
+ */
+FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);
+
+	overflow_on_nested_buffer(arg->a, arg->a_len, arg->b, arg->b_len);
+}
diff --git a/samples/kfuzztest/underflow_on_buffer.c b/samples/kfuzztest/underflow_on_buffer.c
new file mode 100644
index 000000000000..02704a1bfebb
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,59 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_underflow_on_buffer
+ *
+ * This test ensures that the region between the metadata struct and the
+ * dynamically allocated buffer is poisoned. It provokes a one-byte underflow
+ * on the buffer, which should be caught by KASAN.
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "some_buffer { ptr[buf] len[buf, u64]}; buf { arr[u8, 128] };" \
+ *   "test_underflow_on_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `some_buffer` and specifies that
+ * `buf` is a pointer to an array of 128 bytes. The second argument is the test
+ * name, and the third is a seed file.
+ */
+#include <linux/kfuzztest.h>
+
+static void underflow_on_buffer(char *buf, size_t buflen)
+{
+	size_t i;
+
+	pr_info("buf = [%px, %px)", buf, buf + buflen);
+
+	/* First ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < buflen; i++)
+		READ_ONCE(buf[i]);
+	/*
+	 * Provoke a buffer overflow on the first byte preceding b, triggering
+	 * a KASAN report.
+	 */
+	READ_ONCE(*((char *)buf - 1));
+}
+
+struct some_buffer {
+	char *buf;
+	size_t buflen;
+};
+
+/**
+ * Tests that the region between struct some_buffer and the expanded *buf field
+ * is correctly poisoned by accessing the first byte before *buf.
+ */
+FUZZ_TEST(test_underflow_on_buffer, struct some_buffer)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(some_buffer, buf);
+	KFUZZTEST_ANNOTATE_LEN(some_buffer, buflen, buf);
+
+	underflow_on_buffer(arg->buf, arg->buflen);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-7-ethan.w.s.graham%40gmail.com.
