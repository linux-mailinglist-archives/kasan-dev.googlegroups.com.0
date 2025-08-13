Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZVK6LCAMGQE4YRQK3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D990B24AC1
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:48 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-555024588e2sf3469140e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092327; cv=pass;
        d=google.com; s=arc-20240605;
        b=hoAa5ShmfpgktCLqxc9GSljSP+3d7JDeXzx1rTYcSsBJtrikk60fY9P7xWDd2VJyWB
         86moXok5CAyL66BPxQLe2neDHFhhJtKKwhYS7ycmUIblScFun9097KQm+/91yoCCu3gk
         Un2wRpgCbYIlWcsIa+UT3ddheBCHtakSK9zAvQEDpE1e57Xfh3bNS3Booj62M5WjhhrZ
         dnoQc1Ae4OPBgnYRatww3ydkb9g2WyPJv0jxZqxV/DjEskzdJG/OBxshon4fSCNHOGUv
         7d3Rh+bEzJbGfDuAcu0uezoUgg9LGGlrEcKChWnrF4PlbPPtzKMkxSH0gh2njuPmLRwa
         7oSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=7dW+BTEmuy6gjzWHmAjlnkzUAEdJwKsAXEYbzoH1qcY=;
        fh=wcZxt2QjubeEnyNNODTrwbUDPDhgfe5bmEX6EpnK0lY=;
        b=JIVq3uzu9YM7atlrKpYG9sAqvA7ztDvgBhDABRLGKv9Fs0dpEFHmXzYztX3GKa/xXU
         ERRUGAkZfG2yq8b5m3Ac/hmCUyXm3c/sIGCpIvJ/lMektxoQVJqWmn/xU4GkQnk6KS9i
         chRpjgrbzRRYRfUVvyN/IkpYrYdupa1ZRBZkzDL6mAPJqpoHsNHZ9Btqi8c3OBZ+nOqd
         HYq38Nu/aqXFQ0wfypwvOPBgnRcK85XH6dhFKD1XgEr1UdhRnVGps91JxtpdD4rpa53W
         T71n4U20XWns9iJp0t6Uz7AoICKMgG/krywP9K6pzSzct01aT4p5TGtKWMwIfVqX8dF6
         7mRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wq93JfTv;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092327; x=1755697127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7dW+BTEmuy6gjzWHmAjlnkzUAEdJwKsAXEYbzoH1qcY=;
        b=AqQws/tkSZ3gRPqtrTGxkGn6iDUhzhb/tYDxg0Ib/nfkUpAn7AlMeoeFoY/OxI0Q0M
         p6UEbR1WQ53okYOvmLtZBkeLmrn/OFU+7i2hJnovyNPu75lB2F+0b06wb2G8mx7fH3J0
         nQEbk96+yWeZcgQRWhluFh7PEdkTX0iIHUtziTOokJz6LPZiHDgX1djMuHlvA3x3Ueq+
         VpIuQYOaVLqZBv3Dm4i4gmj3bNEXjC6SS0vKFWXMi8DZ911shud9ori5F8kCjL0wWSRT
         ifHGXujRMxXzJbAryuqp2CwQAPpdAGm3HkcfSVT4farktiC0gSGflDzSKxFk0iy5OE6Y
         vOnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092327; x=1755697127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=7dW+BTEmuy6gjzWHmAjlnkzUAEdJwKsAXEYbzoH1qcY=;
        b=RMs6mZL1FRysEU4cBgIwvZbT5g9PkrD4jIAjyt85RPzeucX0x4rK3PGRIa0DNcB8z8
         Fhit+W40WNzapgUtdvJNK2xakIUeO2y/amGIss2PNz0bsbYgzHGW3iZZtDMhHYdCReFu
         p41tmZSdiR0OsUcQd+N7Y0uvWlrUH/leJ2do8IlzKaN2xC2GOW96gWj5hzxH8D7/YO3U
         O//HwBeNXBkz5nYYtfDOFGM/990O8dUUg8O/q+LrAbLgJSBdY+27t2XP6xNAPvUpKCHj
         mziJo0dzp3VF5ayRQODC1lqhKKME/pUg7w/3RkeTHLnu2JL4Ys0g+6ibNgQTL07mh0Ki
         7vzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092327; x=1755697127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7dW+BTEmuy6gjzWHmAjlnkzUAEdJwKsAXEYbzoH1qcY=;
        b=BM4ZqZKpMyFL6QtOslwDZoBn9bJMORpAtt81t5K5UhvA3u9GlstBl/nOOvKdRVeBTx
         9uewRT9xOpa6+Oj0nFE8OOsEeqSpYKs+W8Miv3L6g7zDeUybBmbxWxXuW3QxC37vD209
         5r4Yj8Xhh+1W3TQ90kCdflJybYBBKwUwNjXT783vqLr6Pqij+mTe3wArf0xOUUUwBYmk
         ag0ybe1JLLxsvg2Dy0pyDdOW4iK/lQTBPA0rz6AhFRfVEvhOxVd55XPxrthWkyDjMM1G
         4buVMWYq3Xj7jzChzkIV+AcJ2tqY3w6MqLhL30BjYDhzP7E/o12qmxGtv+kO52Wc5Jku
         tzsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRWINP06/PsAFbThPB9Kb1uBh4LjpH0HYR7s6nWB+fE2OemfIxK//pwzJ41+ArUbwGreRdZg==@lfdr.de
X-Gm-Message-State: AOJu0YzpNxwjr/ASr2yFaIf3gYQNSrPhUd3uCHquT1LMpXplgrPGtImK
	AYdiKS9xqVhYtfgS4B13OyX78C3dw2Rrnq93Pw6arrK5b+b1tEY7kmaU
X-Google-Smtp-Source: AGHT+IH097MHUjU2kvy6yExhAbYEeF1VijLSks17XLnhGUHCWrjA/nF6H62h2foQVFBI0QeSeoU0vA==
X-Received: by 2002:a05:6512:401e:b0:55b:5adc:51ff with SMTP id 2adb3069b0e04-55ce03bf06fmr1042439e87.38.1755092327200;
        Wed, 13 Aug 2025 06:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfKsurH4v1nwvnPv9DgV0BpEPKnnj/ohLbFoabw06NP3A==
Received: by 2002:a05:651c:421b:b0:333:cb55:f585 with SMTP id
 38308e7fff4ca-333cb55fe96ls3592231fa.1.-pod-prod-02-eu; Wed, 13 Aug 2025
 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzCb6yRhBjgRV7wTG4DOuQQJJlJjxbzQ2ct09I+n1yDO2+uRxOS0HJeum2Y3yW4paI/d/YfAMeVXk=@googlegroups.com
X-Received: by 2002:a2e:5159:0:b0:333:b621:2d5c with SMTP id 38308e7fff4ca-333e9b5b6bemr7330771fa.35.1755092323989;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092323; cv=none;
        d=google.com; s=arc-20240605;
        b=joOD+TSe87HHl/RNy//rJ/rA20zPgjmQt6mHE7mmd+tjyEVvuFnJWJxZkdmSNKoDGW
         4+m5w+VXxiVz376lMLUk1WY1Q7nHVgLGTiSr+07wNoPpQuLdEfLswoWPMjBr/fHiWO6V
         Rj/SnzGRr5N3Wpbr/kY18hag9dXcZNRPiknfT2i3KuE6Lp3WKC4aU5m4Zc9iYDEFmHQA
         IbimgDK8pPDZD7u2BdR7IxPaLyeW0giz1yUUelzi1AQuNWeqz5wMJcrBvAru3VNz3kWQ
         x3ZpP7C1sscemH8VrP5o894h40gLvQmGkoIXdWwU9ypeHPOUgA7rbJ9eH1i5Ii44tN76
         B/IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=08hbUSvRcagfemg83g47pFkXwfN5ra3fR8Zxn3xb4d4=;
        fh=QbBYabZqnS6Ky1x33RYMcPgxty+rcO+nCH6psl+3U0I=;
        b=g93xLXuq1lZ/GFlLMdSxW245FEk+6IGrujjn5mc2epDGZtL7vCy6MEDSMk9TNBiIy8
         2Vk/IGTkM+CTm/v3h+KX2P6N6vkzFGlaUV1QaisDk/VqYa3zjEJlFyUxwjFduTh+Q96E
         3M3DEOn/lkaedu2MG2huFsSW9L09x/eGkLtLzLGlVIlSfmdBbrcay5IR3fkAFzxxRtoC
         yPg8m+x/JaYutVX+WS/DIc4E/NwBj8DhpHdKjy7W3ztNM1pJVnCqjiL0UqG52p9UE4k7
         u+zb4d3m0XRrBeJ1BxeEs1dBxHPYul9kJK3yV32QIzudglIWJtohaUECbcHjpcW+OFPy
         +4nw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wq93JfTv;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33250b8b9d2si6451341fa.5.2025.08.13.06.38.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-459e3926cbbso28420515e9.1;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZa+LLkKucv9uZ8FqkQS/xOrPxoYkT2lhC1f2xZm+XidJPJerkmrt4RcOHBYPURKks8aPS5o9c8FXO@googlegroups.com, AJvYcCW+Luu1W/FV2BQ/0cbiJ09gA7Y1mkEul84rmL7cJ4/hJqlLydtc6+3+Dj6HEyBG9bzRn14dz15cqLg=@googlegroups.com
X-Gm-Gg: ASbGncsI25yO3pohOweKPIHC+mEEy7yVqrqF4lExqNGhG5+SBz6pOiNZX9ffwrWpd5f
	MkrEAfru1bWFkPzoDLKcW+44cp+XnjYISNEzVonsYLyzWDAFC0NqL9lAhnTfPVRZehK0X7iI1FS
	F59RXLYAn24mtLoJWXrkGkPS5+3XO2xEWZ4Q71Fcs9/ZqA8YMgMxvJVjmR6LfmiZUEJFKzIwQ3T
	KsUQLJ0kx3M9yWk8TcWzgObPulsX4Lzudl3Pj+0PphDyGzeJQZFKYJ/djSeUtrllqt2FlIoPhTS
	kZ/5Si0euY0HTtJM6SQ7bo0AunlbTDTfxOiKxfP0L7l0X2sxCUWHkVfKdF1sHQdtPmC+VrNaH/r
	PsZIFOemQWjBmpC7YyOggkqN60/g0giMC9QRecAReBeAUHsLGKUeMb2S1UaAd+lZfO31f2Mok3y
	mQrtwGiE3Okqn1qM6ycEx3U1n7Mg==
X-Received: by 2002:a05:600c:1c86:b0:458:b01c:8f with SMTP id 5b1f17b1804b1-45a1a80e6femr1190105e9.8.1755092323030;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
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
	linux-mm@kvack.org
Subject: [PATCH v1 RFC 5/6] kfuzztest: add KFuzzTest sample fuzz targets
Date: Wed, 13 Aug 2025 13:38:11 +0000
Message-ID: <20250813133812.926145-6-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
In-Reply-To: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Wq93JfTv;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
sanity checks for the core logic. For example, they test that out-of-bounds
memory accesses into poisoned padding regions are correctly detected in a
KASAN build.

These have been tested by writing syzkaller-generated inputs into their
debugfs 'input' files and verifying that the correct KASAN reports were
triggered.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 samples/Kconfig                               |  7 +++
 samples/Makefile                              |  1 +
 samples/kfuzztest/Makefile                    |  3 ++
 samples/kfuzztest/overflow_on_nested_buffer.c | 52 +++++++++++++++++++
 samples/kfuzztest/underflow_on_buffer.c       | 41 +++++++++++++++
 5 files changed, 104 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index ffef99950206..4be51a21d010 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -321,6 +321,13 @@ config SAMPLE_HUNG_TASK
 	  if 2 or more processes read the same file concurrently, it will
 	  be detected by the hung_task watchdog.
 
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
index 000000000000..8b4bab1d6d4a
--- /dev/null
+++ b/samples/kfuzztest/overflow_on_nested_buffer.c
@@ -0,0 +1,52 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * overflow on a nested region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
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
index 000000000000..fbe214274037
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,41 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
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
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-6-ethan.w.s.graham%40gmail.com.
