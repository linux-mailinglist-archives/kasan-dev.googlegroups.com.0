Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZWOUTDAMGQEJLRPKJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C58EB5917E
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:28 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-574d06a3a7dsf1027629e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013288; cv=pass;
        d=google.com; s=arc-20240605;
        b=NkIdaVPc86lf/KjZq4Pk232t7WHkzTCp06jKJheDfuB1qVcl+nzoQI7qV6pSj/q28M
         6pS2OLnPiHljrbpc3Rmc8WKSCZrMeCSi/xJxnuqMGGusSYGbVnnDbi4dZ+sh5ZrDizho
         XIEfHP2msCPnG+UILL5F1yZjAExIMlqKBCBuVCKiYBgPIL1qLeiXhVC6qmhRbWji12Kh
         an9YLVP0hGC+vhmm593blAQbucDlN+r7n3W8fhmz9uDp3mJYtmXbnVEaUH3L9gb1xX5o
         sHl+TfPyynru83pEnzBFUkheWn74I6F3LIcGMA/JrUqzIMG4bNDXaJ28xZuIsykK+7Fc
         313g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FgUt/gpT5RvOM0Tonlq2G0Gid5caiByJ+vue+OfiNtg=;
        fh=tpzh2nCo/e5QJYl1JXK2px9SaHXvHgCJa0iqYvMynAg=;
        b=DSSc8rH091LrjsebASpRU4V8gdbB7Qc+ObmsL0M2NvL8Qi4BuiYZ5c2LuSzGCnosS0
         YIm4ymjwB9woXXS62UZ2/5e8zVUZz14PCXy4dzKfVi8YULS4WNGddlOM1pupFGYLEotP
         dqMIpF8Qk99LUw675Xq6VAjmJPeL+hJDWBiaDbYjFYkYlfe2MwJTFq4xLxHOQVgnvEIt
         QeW0D4RIYc61lpsUpOjAaqkAmv1/elE4FSfKGxIgARm+YDNpSdH+kiXkb+/dbAqzwXX+
         W0JNoRz6Z2DOjpFMqmao7em+OKellH7+YwCukEo5gev+iKBpW6Rv5SJG7DdICYKsTdWI
         bUlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Aod5fYi4;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013288; x=1758618088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FgUt/gpT5RvOM0Tonlq2G0Gid5caiByJ+vue+OfiNtg=;
        b=C3dzAx3dUF68w/X6BuP1+HFqdMNGGhY4gLOMYyYzvwUeEm8wFipAnBLoxG7cJizDfh
         yHKk5A/tles7TBZbPrxGRW/3zL8OVK4+QqOWSKvv29eZ7jivhxzGY5zqEaz1gSFzAe4N
         TAxbT5FJ34uvOGPpjiquY1pKP4kRhtCLDOGn8ckKfyb+VObFQ4lnN/tcRVmh7OfQIIbm
         OKDJsO5rmLJRkU567fONw6mQXKkc9ZfwPUml0XWfSGGWzFirhpcQmBzgd/VB1Tum571o
         55gSMkFhMeo/+Kpkypn+x1IJ4vGEz12rFBldu1tDm/5N+Omdkod3Cvb1bgfZ7fZWeO6q
         jw4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013288; x=1758618088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FgUt/gpT5RvOM0Tonlq2G0Gid5caiByJ+vue+OfiNtg=;
        b=gQuY/NDmRagVeZ+ysEfLDrUp7Dd+uig2xalqxDndMn28ijQEhxP7isFozCEZY0qcx1
         9fybx2wMBq4A4d33AR2yg2i11xHN5gXZNOwnpC637I3vFc0MUZAfHAwMIAaVCqK2+Y5w
         7F3b98hLQ7yy/4Ub19IAY7kXpMiUD082SJyo5Rt+D8n9mzRZvkflIMViSn1jtfw24FF5
         CF1ahzH1Qoq6lK0Hzu8DQ/Nv2QarNN6alflp2RkZgbr6SFZz97qJe9PbvnU2ghVvto3X
         wVGEwQ+Udha93aKBM4em/LUVgpMhdRFavk95ioq3kb/WpGu8C3p+bf8ubayU5PGf5H3K
         rd4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013288; x=1758618088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FgUt/gpT5RvOM0Tonlq2G0Gid5caiByJ+vue+OfiNtg=;
        b=gbhvil6/5u5OLM88liTR7SFNOnQW3ptzYz/Oa6uG9inYUsJxxJJEWr5UyyYewtZHnK
         AZYq2pxqmd+Ay9tUKCPwHA7LdtinyhJl8oo0dDMvVwE2ppjxt1UgAGiT8LBjPpeWgKdg
         62G8Foav1boT4AAYqxJaSiiqU22lP2DDOwNjNBCVvL1Auv8op3ae3D5vMDE/4C7n99gv
         9DZ4T/KKy8Ks2QF0r13qv7vx/tvtLYP1Pc1uOaepqq5dFwUbBZjQX9Er0ZH363q36WKc
         1p2dW65sr+b8vuI2X0rerq/+8oA7nK5OkoP5tNyaJwpEpTRxl0An3EndrXHCgHALE2I8
         wy3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYBHVKuM0+KBnuwDi7Lg+J8UqJsKo2HZUGeU+tXaJ76vsPAYEVZ3QFk9Rni6sl/5CnKiga0w==@lfdr.de
X-Gm-Message-State: AOJu0Yxa5AA2qlRhKswqDRV3J5GQmfxUtP9uhFmGeKXdlGhRV+O6nX5K
	mCWgNi7f8sxLkF5Ktu//zZVTNdOunOTLUsvnrqebDgiAbpobNPHNRnTk
X-Google-Smtp-Source: AGHT+IEL9UijfDXZKm5NDYXfCQDkuU4PMn+o0r+yZ+ESFUb+c1h5P6gOvgFh28I4NcnUw4pbsDobuA==
X-Received: by 2002:a05:6512:79a:b0:55f:536f:e89b with SMTP id 2adb3069b0e04-5704fd772d9mr3364954e87.53.1758013286844;
        Tue, 16 Sep 2025 02:01:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5jIQrzBzjFrfNdrNZwKOYpM76P7lrfsM4icDU2oww2og==
Received: by 2002:a05:6512:4606:b0:571:9398:826b with SMTP id
 2adb3069b0e04-57193a7c7eals1067147e87.2.-pod-prod-06-eu; Tue, 16 Sep 2025
 02:01:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdG3c1s9yevL136hm+y8Z1Xthm6DA/oUoeBKv+pJ4MzhZ+/ps/CzDv86NOIIVrKBoQPsf5AagA3zE=@googlegroups.com
X-Received: by 2002:a05:6512:798:b0:55f:51b3:9410 with SMTP id 2adb3069b0e04-5704f5b1386mr3235565e87.49.1758013283071;
        Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013283; cv=none;
        d=google.com; s=arc-20240605;
        b=Sk3rWR6HMV20LpM/YbQTTlzOUljE6OHcjHlOXmOE/G7352q+Q43G3Twf+6fyMAzE31
         kSeO0ntVHv9KYRlAc4Nc2ofChv+1EJr3MutEoHdwaAvTKasSoqR0JLUtvrPQ2HonqhtY
         zd0Gbsg2aZO/SPRy+a7UlRFtxRadfgBeMracIDoqggmJ0QyXBcoZfi6PxvtwbZqpKtlf
         eZDChXTJTmT7lr+pbgJ0lS2RkynohXE9x2pp+Fr4YYYrN259xF3uoDy02FbaQL4+h8+k
         qwI9mdqaXcz2NFoblI7PH/qnEmrM4O/2wd/DT1L20Z0LLO/mU/KX10PvGebIYdbGAauI
         L4pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wAOqPYvSWVeN9/yE7pImb3Dnjd/YBm0aGHPiEL/y/Dw=;
        fh=yhoHDGl7GxHWp7ESofqOq7l5SFjKI3jficuyXzvsmAI=;
        b=HYmzqzv7Yx5gRYVXOaSvyVAuEGBWz6G/jlCxM+Bx6bp/7WFLCdLEf3ucwR7esIk4uI
         eNH6nEgS+osy+ATJj5B3MFesEHyLdG7a0lbQ3a1LuqPd7EneTTguVtloghCTH25Bpv5O
         1pbDUtxEaD4CbGiGGqagDqg0bFlwBKkcRY3q6Oat7X4NMpIZ+xP7kZ+9KuOElut/uQ/p
         abkqwmJRwSBiGLV9hf9grIC3nJgpaUs26+WgfRdpUVQ08x5I8sVwWUNUiDwrOHZ8DeWG
         gBYr0T052i+qE+rUe1p5v/EYv7Pp5CyIq2jcaOyhYVetX5aE9VRWaimojmw06mVGe4vw
         moQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Aod5fYi4;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5707b9a8c99si230231e87.8.2025.09.16.02.01.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-3ec4d6ba12eso454162f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX+/qlmehrM725EKeuyCdW/hQi2/iof5BmdFDFvOEV05VWSc+86Yj0Oud8NUoVURJpI7tejhRypf7w=@googlegroups.com
X-Gm-Gg: ASbGncsacZmpiYjKBnOtDHi0rIVsEeaKknY0luqpzfD9MrNSfar3ogAsnKap+eJJz2H
	+XCJkvhYQCE8KshkSEo0lKQ+EikpxREnHk7h1QcQIUlwGETzV8N6m7Jl0naZI8moynyMGv5Lykj
	KnRweLy+GVyGdphXVAnvV5Mak2Kw6YuxA91KDpofFZlU8wzRwk5t6YP5h2sdniWUSlfYcE7Ai9E
	JZNrWxR0LG/k3kRqTYb4jbfglQh2kAQTeTdyhcOEMfj0xWE4L4eF2TaOVGz6a7xl41c5W/c2fuY
	xcn+KQSsBqXYHvfWHoRFa766CIy2h0INtbjLDatjWqSBGAkc6O+84zA3Bk/Sq2ySxOxsaOZbF18
	cbOUee2ueFcDl65T8zewTjkj+GuaEZpLPNgB0nzbRb685Z7r1n17FuNSDAGgTYGinYc4CSn4icU
	zCiO+n8HtfRy6z
X-Received: by 2002:a5d:5f53:0:b0:3ec:9a32:3642 with SMTP id ffacd0b85a97d-3ec9a323866mr1190593f8f.62.1758013281461;
        Tue, 16 Sep 2025 02:01:21 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:20 -0700 (PDT)
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
Subject: [PATCH v1 03/10] kfuzztest: implement core module and input processing
Date: Tue, 16 Sep 2025 09:01:02 +0000
Message-ID: <20250916090109.91132-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Aod5fYi4;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add the core runtime implementation for KFuzzTest. This includes the
module initialization, and the logic for receiving and processing
user-provided inputs through debugfs.

On module load, the framework discovers all test targets by iterating
over the .kfuzztest_target section, creating a corresponding debugfs
directory with a write-only 'input' file for each of them.

Writing to an 'input' file triggers the main fuzzing sequence:
1. The serialized input is copied from userspace into a kernel buffer.
2. The buffer is parsed to validate the region array and relocation
   table.
3. Pointers are patched based on the relocation entries, and in KASAN
   builds the inter-region padding is poisoned.
4. The resulting struct is passed to the user-defined test logic.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
v3:
- Update kfuzztest/parse.c interfaces to take `unsigned char *` instead
  of `void *`, reducing the number of pointer casts.
- Expose minimum region alignment via a new debugfs file.
- Expose number of successful invocations via a new debugfs file.
- Refactor module init function, add _config directory with entries
  containing KFuzzTest state information.
- Account for kasan_poison_range() return value in input parsing logic.
- Validate alignment of payload end.
- Move static sizeof assertions into /lib/kfuzztest/main.c.
- Remove the taint in kfuzztest/main.c. We instead taint the kernel as
  soon as a fuzz test is invoked for the first time, which is done in
  the primary FUZZ_TEST macro.
v2:
- The module's init function now taints the kernel with TAINT_TEST.
---
---
 include/linux/kfuzztest.h |   4 +
 lib/Makefile              |   2 +
 lib/kfuzztest/Makefile    |   4 +
 lib/kfuzztest/main.c      | 240 ++++++++++++++++++++++++++++++++++++++
 lib/kfuzztest/parse.c     | 204 ++++++++++++++++++++++++++++++++
 5 files changed, 454 insertions(+)
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c

diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
index 1e5ed517f291..d90dabba23c4 100644
--- a/include/linux/kfuzztest.h
+++ b/include/linux/kfuzztest.h
@@ -150,6 +150,9 @@ struct kfuzztest_target {
 
 #define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)
 
+/* Increments a global counter after a successful invocation. */
+void record_invocation(void);
+
 /**
  * FUZZ_TEST - defines a KFuzzTest target
  *
@@ -243,6 +246,7 @@ struct kfuzztest_target {
 		if (ret < 0)											\
 			goto out;										\
 		kfuzztest_logic_##test_name(arg);								\
+		record_invocation();										\
 		ret = len;											\
 out:														\
 		kfree(buffer);											\
diff --git a/lib/Makefile b/lib/Makefile
index 392ff808c9b9..02789bf88499 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -325,6 +325,8 @@ obj-$(CONFIG_GENERIC_LIB_CMPDI2) += cmpdi2.o
 obj-$(CONFIG_GENERIC_LIB_UCMPDI2) += ucmpdi2.o
 obj-$(CONFIG_OBJAGG) += objagg.o
 
+obj-$(CONFIG_KFUZZTEST) += kfuzztest/
+
 # pldmfw library
 obj-$(CONFIG_PLDMFW) += pldmfw/
 
diff --git a/lib/kfuzztest/Makefile b/lib/kfuzztest/Makefile
new file mode 100644
index 000000000000..142d16007eea
--- /dev/null
+++ b/lib/kfuzztest/Makefile
@@ -0,0 +1,4 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFUZZTEST) += kfuzztest.o
+kfuzztest-objs := main.o parse.o
diff --git a/lib/kfuzztest/main.c b/lib/kfuzztest/main.c
new file mode 100644
index 000000000000..06f4e3c3c9b2
--- /dev/null
+++ b/lib/kfuzztest/main.c
@@ -0,0 +1,240 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest core module initialization and debugfs interface.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/atomic.h>
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/kfuzztest.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+#include <linux/kasan.h>
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
+MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");
+
+/*
+ * Enforce a fixed struct size to ensure a consistent stride when iterating over
+ * the array of these structs in the dedicated ELF section.
+ */
+static_assert(sizeof(struct kfuzztest_target) == 32, "struct kfuzztest_target should have size 32");
+static_assert(sizeof(struct kfuzztest_constraint) == 64, "struct kfuzztest_constraint should have size 64");
+static_assert(sizeof(struct kfuzztest_annotation) == 32, "struct kfuzztest_annotation should have size 32");
+
+extern const struct kfuzztest_target __kfuzztest_targets_start[];
+extern const struct kfuzztest_target __kfuzztest_targets_end[];
+
+/**
+ * struct kfuzztest_state - global state for the KFuzzTest module
+ *
+ * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
+ * @num_targets: number of registered KFuzzTest targets.
+ * @target_fops: array of file operations for each registered target.
+ * @minalign_fops: file operations for the /_config/minalign file.
+ * @num_invocations_fops: file operations for the /_config/num_invocations file.
+ */
+struct kfuzztest_state {
+	struct dentry *kfuzztest_dir;
+	atomic_t num_invocations;
+	size_t num_targets;
+
+	struct file_operations *target_fops;
+	struct file_operations minalign_fops;
+	struct file_operations num_invocations_fops;
+};
+
+static struct kfuzztest_state state;
+
+void record_invocation(void)
+{
+	atomic_inc(&state.num_invocations);
+}
+
+static void cleanup_kfuzztest_state(struct kfuzztest_state *st)
+{
+	debugfs_remove_recursive(st->kfuzztest_dir);
+	st->num_targets = 0;
+	st->num_invocations = (atomic_t)ATOMIC_INIT(0);
+	kfree(st->target_fops);
+	st->target_fops = NULL;
+}
+
+const umode_t KFUZZTEST_INPUT_PERMS = 0222;
+const umode_t KFUZZTEST_MINALIGN_PERMS = 0444;
+
+static ssize_t read_cb_integer(struct file *filp, char __user *buf, size_t count, loff_t *f_pos, size_t value)
+{
+	char buffer[64];
+	int len;
+
+	len = scnprintf(buffer, sizeof(buffer), "%zu\n", value);
+	return simple_read_from_buffer(buf, count, f_pos, buffer, len);
+}
+
+/*
+ * Callback for /sys/kernel/debug/kfuzztest/_config/minalign. Minalign
+ * corresponds to the minimum alignment that regions in a KFuzzTest input must
+ * satisfy. This callback returns that value in string format.
+ */
+static ssize_t minalign_read_cb(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
+{
+	int minalign = MAX(KFUZZTEST_POISON_SIZE, ARCH_KMALLOC_MINALIGN);
+	return read_cb_integer(filp, buf, count, f_pos, minalign);
+}
+
+/*
+ * Callback for /sys/kernel/debug/kfuzztest/_config/num_targets, which returns
+ * the value in string format.
+ */
+static ssize_t num_invocations_read_cb(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
+{
+	return read_cb_integer(filp, buf, count, f_pos, atomic_read(&state.num_invocations));
+}
+
+static int create_read_only_file(struct dentry *parent, const char *name, struct file_operations *fops)
+{
+	struct dentry *file;
+	int err = 0;
+
+	file = debugfs_create_file(name, KFUZZTEST_MINALIGN_PERMS, parent, NULL, fops);
+	if (!file)
+		err = -ENOMEM;
+	else if (IS_ERR(file))
+		err = PTR_ERR(file);
+	return err;
+}
+
+static int initialize_config_dir(struct kfuzztest_state *st)
+{
+	struct dentry *dir;
+	int err = 0;
+
+	dir = debugfs_create_dir("_config", st->kfuzztest_dir);
+	if (!dir)
+		err = -ENOMEM;
+	else if (IS_ERR(dir))
+		err = PTR_ERR(dir);
+	if (err) {
+		pr_info("kfuzztest: failed to create /_config dir");
+		goto out;
+	}
+
+	st->minalign_fops = (struct file_operations){
+		.owner = THIS_MODULE,
+		.read = minalign_read_cb,
+	};
+	err = create_read_only_file(dir, "minalign", &st->minalign_fops);
+	if (err) {
+		pr_info("kfuzztest: failed to create /_config/minalign");
+		goto out;
+	}
+
+	st->num_invocations_fops = (struct file_operations){
+		.owner = THIS_MODULE,
+		.read = num_invocations_read_cb,
+	};
+	err = create_read_only_file(dir, "num_invocations", &st->num_invocations_fops);
+	if (err)
+		pr_info("kfuzztest: failed to create /_config/num_invocations");
+out:
+	return err;
+}
+
+static int initialize_target_dir(struct kfuzztest_state *st, const struct kfuzztest_target *targ,
+				 struct file_operations *fops)
+{
+	struct dentry *dir, *input;
+	int err = 0;
+
+	dir = debugfs_create_dir(targ->name, st->kfuzztest_dir);
+	if (!dir)
+		err = -ENOMEM;
+	else if (IS_ERR(dir))
+		err = PTR_ERR(dir);
+	if (err) {
+		pr_info("kfuzztest: failed to create /kfuzztest/%s dir", targ->name);
+		goto out;
+	}
+
+	input = debugfs_create_file("input", KFUZZTEST_INPUT_PERMS, dir, NULL, fops);
+	if (!input)
+		err = -ENOMEM;
+	else if (IS_ERR(input))
+		err = PTR_ERR(input);
+	if (err)
+		pr_info("kfuzztest: failed to create /kfuzztest/%s/input", targ->name);
+out:
+	return err;
+}
+
+/**
+ * kfuzztest_init - initializes the debug filesystem for KFuzzTest
+ *
+ * Each registered target in the ".kfuzztest_targets" section gets its own
+ * subdirectory under "/sys/kernel/debug/kfuzztest/<test-name>" containing one
+ * write-only "input" file used for receiving inputs from userspace.
+ * Furthermore, a directory "/sys/kernel/debug/kfuzztest/_config" is created,
+ * containing two read-only files "minalign" and "num_targets", that return
+ * the minimum required region alignment and number of targets respectively.
+ *
+ * @return 0 on success or an error
+ */
+static int __init kfuzztest_init(void)
+{
+	const struct kfuzztest_target *targ;
+	int err = 0;
+	int i = 0;
+
+	state.num_targets = __kfuzztest_targets_end - __kfuzztest_targets_start;
+	state.target_fops = kzalloc(sizeof(struct file_operations) * state.num_targets, GFP_KERNEL);
+	if (!state.target_fops)
+		return -ENOMEM;
+
+	/* Create the main "kfuzztest" directory in /sys/kernel/debug. */
+	state.kfuzztest_dir = debugfs_create_dir("kfuzztest", NULL);
+	if (!state.kfuzztest_dir) {
+		pr_warn("kfuzztest: could not create 'kfuzztest' debugfs directory");
+		return -ENOMEM;
+	}
+	if (IS_ERR(state.kfuzztest_dir)) {
+		pr_warn("kfuzztest: could not create 'kfuzztest' debugfs directory");
+		err = PTR_ERR(state.kfuzztest_dir);
+		state.kfuzztest_dir = NULL;
+		return err;
+	}
+
+	err = initialize_config_dir(&state);
+	if (err)
+		goto cleanup_failure;
+
+	for (targ = __kfuzztest_targets_start; targ < __kfuzztest_targets_end; targ++, i++) {
+		state.target_fops[i] = (struct file_operations){
+			.owner = THIS_MODULE,
+			.write = targ->write_input_cb,
+		};
+		err = initialize_target_dir(&state, targ, &state.target_fops[i]);
+		/* Bail out if a single target fails to initialize. This avoids
+		 * partial setup, and a failure here likely indicates an issue
+		 * with debugfs. */
+		if (err)
+			goto cleanup_failure;
+		pr_info("kfuzztest: registered target %s", targ->name);
+	}
+	return 0;
+
+cleanup_failure:
+	cleanup_kfuzztest_state(&state);
+	return err;
+}
+
+static void __exit kfuzztest_exit(void)
+{
+	pr_info("kfuzztest: exiting");
+	cleanup_kfuzztest_state(&state);
+}
+
+module_init(kfuzztest_init);
+module_exit(kfuzztest_exit);
diff --git a/lib/kfuzztest/parse.c b/lib/kfuzztest/parse.c
new file mode 100644
index 000000000000..5aaeca6a7fde
--- /dev/null
+++ b/lib/kfuzztest/parse.c
@@ -0,0 +1,204 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFuzzTest input parsing and validation.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <linux/kasan.h>
+
+static int kfuzztest_relocate_v0(struct reloc_region_array *regions, struct reloc_table *rt,
+				 unsigned char *payload_start, unsigned char *payload_end)
+{
+	unsigned char *poison_start, *poison_end;
+	struct reloc_region reg, src, dst;
+	uintptr_t *ptr_location;
+	struct reloc_entry re;
+	size_t i;
+	int ret;
+
+	/* Patch pointers. */
+	for (i = 0; i < rt->num_entries; i++) {
+		re = rt->entries[i];
+		src = regions->regions[re.region_id];
+		ptr_location = (uintptr_t *)(payload_start + src.offset + re.region_offset);
+		if (re.value == KFUZZTEST_REGIONID_NULL)
+			*ptr_location = (uintptr_t)NULL;
+		else if (re.value < regions->num_regions) {
+			dst = regions->regions[re.value];
+			*ptr_location = (uintptr_t)(payload_start + dst.offset);
+		} else {
+			return -EINVAL;
+		}
+	}
+
+	/* Poison the padding between regions. */
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+
+		/* Points to the beginning of the inter-region padding */
+		poison_start = payload_start + reg.offset + reg.size;
+		if (i < regions->num_regions - 1)
+			poison_end = payload_start + regions->regions[i + 1].offset;
+		else
+			poison_end = payload_end;
+
+		if (poison_end > payload_end)
+			return -EINVAL;
+
+		ret = kasan_poison_range(poison_start, poison_end - poison_start);
+		if (ret)
+			return ret;
+	}
+
+	/* Poison the padded area preceding the payload. */
+	return kasan_poison_range(payload_start - rt->padding_size, rt->padding_size);
+}
+
+static bool kfuzztest_input_is_valid(struct reloc_region_array *regions, struct reloc_table *rt,
+				     unsigned char *payload_start, unsigned char *payload_end)
+{
+	size_t payload_size = payload_end - payload_start;
+	struct reloc_region reg, next_reg;
+	size_t usable_payload_size;
+	uint32_t region_end_offset;
+	struct reloc_entry reloc;
+	uint32_t i;
+
+	if (payload_start > payload_end)
+		return false;
+	if (payload_size < KFUZZTEST_POISON_SIZE)
+		return false;
+	if ((uintptr_t)payload_end % KFUZZTEST_POISON_SIZE)
+		return false;
+	usable_payload_size = payload_size - KFUZZTEST_POISON_SIZE;
+
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+		if (check_add_overflow(reg.offset, reg.size, &region_end_offset))
+			return false;
+		if ((size_t)region_end_offset > usable_payload_size)
+			return false;
+
+		if (i < regions->num_regions - 1) {
+			next_reg = regions->regions[i + 1];
+			if (reg.offset > next_reg.offset)
+				return false;
+			/* Enforce the minimum poisonable gap between
+			 * consecutive regions. */
+			if (reg.offset + reg.size + KFUZZTEST_POISON_SIZE > next_reg.offset)
+				return false;
+		}
+	}
+
+	if (rt->padding_size < KFUZZTEST_POISON_SIZE) {
+		pr_info("validation failed because rt->padding_size = %u", rt->padding_size);
+		return false;
+	}
+
+	for (i = 0; i < rt->num_entries; i++) {
+		reloc = rt->entries[i];
+		if (reloc.region_id >= regions->num_regions)
+			return false;
+		if (reloc.value != KFUZZTEST_REGIONID_NULL && reloc.value >= regions->num_regions)
+			return false;
+
+		reg = regions->regions[reloc.region_id];
+		if (reloc.region_offset % (sizeof(uintptr_t)) || reloc.region_offset + sizeof(uintptr_t) > reg.size)
+			return false;
+	}
+
+	return true;
+}
+
+static int kfuzztest_parse_input_v0(unsigned char *input, size_t input_size, struct reloc_region_array **ret_regions,
+				    struct reloc_table **ret_reloc_table, unsigned char **ret_payload_start,
+				    unsigned char **ret_payload_end)
+{
+	size_t reloc_entries_size, reloc_regions_size;
+	unsigned char *payload_end, *payload_start;
+	size_t reloc_table_size, regions_size;
+	struct reloc_region_array *regions;
+	struct reloc_table *rt;
+	size_t curr_offset = 0;
+
+	if (input_size < sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
+		return -EINVAL;
+
+	regions = (struct reloc_region_array *)input;
+	if (check_mul_overflow(regions->num_regions, sizeof(struct reloc_region), &reloc_regions_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*regions), reloc_regions_size, &regions_size))
+		return -EINVAL;
+
+	curr_offset = regions_size;
+	if (curr_offset > input_size)
+		return -EINVAL;
+	if (input_size - curr_offset < sizeof(struct reloc_table))
+		return -EINVAL;
+
+	rt = (struct reloc_table *)(input + curr_offset);
+
+	if (check_mul_overflow((size_t)rt->num_entries, sizeof(struct reloc_entry), &reloc_entries_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*rt), reloc_entries_size, &reloc_table_size))
+		return -EINVAL;
+	if (check_add_overflow(reloc_table_size, rt->padding_size, &reloc_table_size))
+		return -EINVAL;
+
+	if (check_add_overflow(curr_offset, reloc_table_size, &curr_offset))
+		return -EINVAL;
+	if (curr_offset > input_size)
+		return -EINVAL;
+
+	payload_start = input + curr_offset;
+	payload_end = input + input_size;
+
+	if (!kfuzztest_input_is_valid(regions, rt, payload_start, payload_end))
+		return -EINVAL;
+
+	*ret_regions = regions;
+	*ret_reloc_table = rt;
+	*ret_payload_start = payload_start;
+	*ret_payload_end = payload_end;
+	return 0;
+}
+
+static int kfuzztest_parse_and_relocate_v0(unsigned char *input, size_t input_size, void **arg_ret)
+{
+	unsigned char *payload_start, *payload_end;
+	struct reloc_region_array *regions;
+	struct reloc_table *reloc_table;
+	int ret;
+
+	ret = kfuzztest_parse_input_v0(input, input_size, &regions, &reloc_table, &payload_start, &payload_end);
+	if (ret < 0)
+		return ret;
+
+	ret = kfuzztest_relocate_v0(regions, reloc_table, payload_start, payload_end);
+	if (ret < 0)
+		return ret;
+	*arg_ret = (void *)payload_start;
+	return 0;
+}
+
+int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret)
+{
+	size_t header_size = 2 * sizeof(u32);
+	u32 version, magic;
+
+	if (input_size < sizeof(u32) + sizeof(u32))
+		return -EINVAL;
+
+	magic = *(u32 *)input;
+	if (magic != KFUZZTEST_HEADER_MAGIC)
+		return -EINVAL;
+
+	version = *(u32 *)(input + sizeof(u32));
+	switch (version) {
+	case KFUZZTEST_V0:
+		return kfuzztest_parse_and_relocate_v0(input + header_size, input_size - header_size, arg_ret);
+	}
+
+	return -EINVAL;
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-4-ethan.w.s.graham%40gmail.com.
