Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSE46XBAMGQEFQS5WIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 091C6AE9F34
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:34 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-451deff247csf10663235e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945353; cv=pass;
        d=google.com; s=arc-20240605;
        b=ITC0WHj8y+Pvx2WjvGesohkmMJ6HCjeUqWTlVSRcex5ABJ25JmQbbVSklCie/f+9iq
         kRLkNPeLKY7adLiAW6UNEkUHKxt606foT6xjlcGggifN2C/9f5S1SyuBSOGTYTE5t/ZF
         HLkcHT5d3kWt3F4cEx8aG0NoUbw2qGFsf+9TOB8iXBVugzuNbbMzs09/XpLwcWrS/Xj/
         mpiQeKhHpAvD3UTeS57sxCndGGx2p3RLVg44xobetLwiRXnOinOWM3SKwzd8CTIP/IeJ
         RmqxHkW+ccVxc20w7vOwnWJwsqUANGxaYOL4we6uKZMi++3SFhR6IFViuHMTZ/+O43Ip
         levw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=r3en+WRVm35r1QdpxkLNr0ERNXAXJbvDSu5YyQJGq4w=;
        fh=1cBAYKfBlAlUVZfEB4R/CSgrIsqLEQd3eHTXN+HTLw0=;
        b=V3RGg4fKBIR6m2frLFbX2O1SHeKnTqIZ7Y0FLfN4C/n2yFYhHAhKFCHW3sTcdQhxp4
         eH1Njolk+ClQtRDv5y/vlrxWkHgP/6f/Z2CojjKYQ5KLv/iEJW7lkIdnnaPAApbQ+ha7
         ndZ6UzAOgGpbeuGDv1BrLEUI5dDEw/yL9yYIW3SEm9a4avBhu9n3gThujlRLbyBIurs1
         Haw2ttPJIB3dw1MJCkVyT3T07N3KbKAy2ONdYRuRyCdXfqYWpU7kDfClWBp/96CrY17A
         UyxwwXEqq9orPfw9AERbAueBvDWRfMCO7UxXA3gL2e6LlVlpiHyi+3Kkl6/EblNdngYd
         DOkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y62V0Cpn;
       spf=pass (google.com: domain of 3ru5daaykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RU5daAYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945353; x=1751550153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=r3en+WRVm35r1QdpxkLNr0ERNXAXJbvDSu5YyQJGq4w=;
        b=Y4cJss7Az+zmOhRfHBY+BbPBGvEoG3WDgoo2M1CjKb01bJuoYoht6VWGbjQ+f1n5b6
         01bFt2A03cHgfwJF9+cPhhXopTehovBwkpJNxIgw3qkM4HOTUZfOv94yAeZe5ymuHQv7
         IQJfvNdCowlFVk5bc/Nt/aRSzjs2ecTm4+xheVBP6U52m9IdAWbMWoZMkWJWNzeJ1wJv
         UZsH8Qj0ttqGPX3Jeya2JFpgKNz/wGCTTv5MABTQyf5zisSY60wb8QVW2bdk4jnJhSB7
         SWkwqVz8zUhUeskoRX/cg0TJkAq+k6OfVNALmzZZ9Bk4E/WY4tifjD7h9IK4YUNEQWeB
         yVaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945353; x=1751550153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r3en+WRVm35r1QdpxkLNr0ERNXAXJbvDSu5YyQJGq4w=;
        b=eS572wUc2w94oHH/9iqDTiIs80mq1aR4/za+sYcxyYWY/mef6rzRmrnBOnRi0VNlz+
         qiZk71MHaKfhy9G4TMAtuRJSyClXI/KGwr9MGygS2HzShIIxdbMd43dPiqfmYeNSC9om
         1x16wSuslmQRYo+tZh6nfF6f2+rOOvUpmGsx/H6DLjY92JaHLxMydSn8fammbqZ3MKYJ
         hqoiFWzYEeaB0C86FKVy6pfuWKrriCWD6cDLl58YvTd6+ASyTfK7DVPbk3AJcV1yeS2m
         jwjVonJO5F9SMxNy5Z/LGsotgY1UvnoEmxuolfNpXh7r2rXRi1Snkh4nqTSrk8cW24IP
         3eGw==
X-Forwarded-Encrypted: i=2; AJvYcCUWpPS3QKCm4/SqobsVNLyNvYg4+f0liqg3NelBF2aIQIZBcTEKskJqG1XE3nZCgB0Q2KR+HA==@lfdr.de
X-Gm-Message-State: AOJu0YzT+NQvXwTnEfn2Pct/fSGTBnbYAYLpjrMP1+u4db1pI+dWGqQ0
	+ZT0Z3U0Y750KDcfFYxXfhDWuodxLyMpme7r39t8kha4K8HoupKq57yF
X-Google-Smtp-Source: AGHT+IFAKLhtsvcuJZwKFgDQ1IukT0WJnFjWNz8IzRQbuwVhhlkQ0hOLOTbwfP4tctRU0Y453OZFAw==
X-Received: by 2002:a05:600c:8184:b0:453:92e:a459 with SMTP id 5b1f17b1804b1-4538ad600f0mr24452245e9.16.1750945352729;
        Thu, 26 Jun 2025 06:42:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdO5Glp7pCQuAnn4jHtw2el1uqk0eNNi0HvPy5hisj3hg==
Received: by 2002:a05:600c:3d8e:b0:453:8caa:8fc6 with SMTP id
 5b1f17b1804b1-4538caa9354ls2401935e9.2.-pod-prod-00-eu-canary; Thu, 26 Jun
 2025 06:42:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPAEfpFDvrxymlP8T5OPtvrh5puleBQJC6P/jRxgMKwBqmFhTzcgxeczqC3I8NlTNM1ntHx6FLg0U=@googlegroups.com
X-Received: by 2002:a05:6000:2d87:b0:3a4:da0e:517a with SMTP id ffacd0b85a97d-3a6f31535c9mr2786101f8f.23.1750945350302;
        Thu, 26 Jun 2025 06:42:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945350; cv=none;
        d=google.com; s=arc-20240605;
        b=X5SHwh89y+ieDQm9nMgCpYls4PUZUHUSeMAPzka/qxxFmYZsyU4UvOE3ZE4h6iq/Ei
         Tyme9Oy+34/sZ0YmoQlQBipuV3yghaWpy4j61kZhuhvDfmWfiGr0qnQ+w4ekggOT76Gw
         Ka5tc9dtEstzmdCmnx1pUQo4Qc7B09eZPoyp3iapEvHBLsJoiDSgpFnpf9/i81P+eoJ9
         tsaX7qEoXpqUptkt1y+rv0aZ/V7vSZZjHESilMUFMeUyER2/zGEy/x/6tjO/oIU04dVy
         YANLqtPvlfPogWtLJnqaJ6d3XCiaJcWhSim2OHRUCrqTW3P1Xfe35AJ852ybEBQIBbVZ
         X1Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=27NsffT4riRoTxmVby2GFeNcIx8l/sjMhtQmARW+nyU=;
        fh=93voSijCTiQWUoJC9eOc6wEarSUDHprZyDGDphtK5jM=;
        b=RrnnDVE9ylMESA7ws9oQrhXCfOxDrpPpod9Jm/yQJNLH0cPP68eR0ffyg3uYvDqXJl
         gInMXEeAtSOkAV3trfn4RW7ntZzxa2YUyUQMxDTzoacVWUSKbDxjsBD8lCeVrHycP6VA
         iZ1pH9w3YyVnJyORQbNnQdANT9VrGW1PodTfhPca7qmEwE+rSUizk7bR3q54PLk7MLLy
         TJtOHZefVt2sFVA63d55lQehrzZQLyGfnyaZ7NvVmNsUFl8Lbrb/QPVwEe+XJhEpi5a+
         yM7FgJzanh3P7lu0mWk/TmuPqs7e/RGFOzAsVmey98Ff2VKmYI5gr9hYUZ5j90Wo69yv
         a4UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y62V0Cpn;
       spf=pass (google.com: domain of 3ru5daaykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RU5daAYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453822d256dsi1027555e9.0.2025.06.26.06.42.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ru5daaykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-450eaae2934so7694705e9.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVaz1m7PM/lYWqNe89+GpV+BI6q8VkIdaBYR5Zwl9y0ewrAczSOMlDHj6gYHb9ffnsKDuDmzC8QmfE=@googlegroups.com
X-Received: from wmbhj16.prod.google.com ([2002:a05:600c:5290:b0:440:60ac:3f40])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3b03:b0:453:a88:d509
 with SMTP id 5b1f17b1804b1-45381aa4972mr90416265e9.10.1750945349795; Thu, 26
 Jun 2025 06:42:29 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:57 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-11-glider@google.com>
Subject: [PATCH v2 10/11] kcov: selftests: add kcov_test
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=y62V0Cpn;       spf=pass
 (google.com: domain of 3ru5daaykcaaglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RU5daAYKCaAGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Implement test fixtures for testing different combinations of coverage
collection modes:
 - unique and non-unique coverage;
 - collecting PCs and comparison arguments;
 - mapping the buffer as RO and RW.

To build:
 $ make -C tools/testing/selftests/kcov kcov_test

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 MAINTAINERS                              |   1 +
 tools/testing/selftests/kcov/Makefile    |   6 +
 tools/testing/selftests/kcov/kcov_test.c | 364 +++++++++++++++++++++++
 3 files changed, 371 insertions(+)
 create mode 100644 tools/testing/selftests/kcov/Makefile
 create mode 100644 tools/testing/selftests/kcov/kcov_test.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 5bbc78b0fa6ed..0ec909e085077 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -12833,6 +12833,7 @@ F:	include/linux/kcov_types.h
 F:	include/uapi/linux/kcov.h
 F:	kernel/kcov.c
 F:	scripts/Makefile.kcov
+F:	tools/testing/selftests/kcov/
 
 KCSAN
 M:	Marco Elver <elver@google.com>
diff --git a/tools/testing/selftests/kcov/Makefile b/tools/testing/selftests/kcov/Makefile
new file mode 100644
index 0000000000000..08abf8b60bcf9
--- /dev/null
+++ b/tools/testing/selftests/kcov/Makefile
@@ -0,0 +1,6 @@
+# SPDX-License-Identifier: GPL-2.0-only
+LDFLAGS += -static
+
+TEST_GEN_PROGS := kcov_test
+
+include ../lib.mk
diff --git a/tools/testing/selftests/kcov/kcov_test.c b/tools/testing/selftests/kcov/kcov_test.c
new file mode 100644
index 0000000000000..4d3ca41f28af4
--- /dev/null
+++ b/tools/testing/selftests/kcov/kcov_test.c
@@ -0,0 +1,364 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * Test the kernel coverage (/sys/kernel/debug/kcov).
+ *
+ * Copyright 2025 Google LLC.
+ */
+#include <fcntl.h>
+#include <linux/kcov.h>
+#include <stdint.h>
+#include <stddef.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <sys/ioctl.h>
+#include <sys/mman.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include "../kselftest_harness.h"
+
+/* Normally these defines should be provided by linux/kcov.h, but they aren't there yet. */
+#define KCOV_UNIQUE_ENABLE _IOW('c', 103, unsigned long)
+#define KCOV_RESET_TRACE _IO('c', 104)
+
+#define COVER_SIZE (64 << 10)
+#define BITMAP_SIZE (4 << 10)
+
+#define DEBUG_COVER_PCS 0
+
+FIXTURE(kcov)
+{
+	int fd;
+	unsigned long *mapping;
+	size_t mapping_size;
+};
+
+FIXTURE_VARIANT(kcov)
+{
+	int mode;
+	bool fast_reset;
+	bool map_readonly;
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov, mode_trace_pc)
+{
+	/* clang-format on */
+	.mode = KCOV_TRACE_PC,
+	.fast_reset = true,
+	.map_readonly = false,
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov, mode_trace_cmp)
+{
+	/* clang-format on */
+	.mode = KCOV_TRACE_CMP,
+	.fast_reset = true,
+	.map_readonly = false,
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov, reset_ioctl_rw)
+{
+	/* clang-format on */
+	.mode = KCOV_TRACE_PC,
+	.fast_reset = false,
+	.map_readonly = false,
+};
+
+FIXTURE_VARIANT_ADD(kcov, reset_ioctl_ro)
+/* clang-format off */
+{
+	/* clang-format on */
+	.mode = KCOV_TRACE_PC,
+	.fast_reset = false,
+	.map_readonly = true,
+};
+
+int kcov_open_init(struct __test_metadata *_metadata, unsigned long size,
+		   int prot, unsigned long **out_mapping)
+{
+	unsigned long *mapping;
+
+	/* A single fd descriptor allows coverage collection on a single thread. */
+	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
+
+	ASSERT_NE(fd, -1)
+	{
+		perror("open");
+	}
+
+	EXPECT_EQ(ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE), 0)
+	{
+		perror("ioctl KCOV_INIT_TRACE");
+		close(fd);
+	}
+
+	/* Mmap buffer shared between kernel- and user-space. */
+	mapping = (unsigned long *)mmap(NULL, size * sizeof(unsigned long),
+					prot, MAP_SHARED, fd, 0);
+	ASSERT_NE((void *)mapping, MAP_FAILED)
+	{
+		perror("mmap");
+		close(fd);
+	}
+	*out_mapping = mapping;
+
+	return fd;
+}
+
+FIXTURE_SETUP(kcov)
+{
+	int prot = variant->map_readonly ? PROT_READ : (PROT_READ | PROT_WRITE);
+
+	/* Read-only mapping is incompatible with fast reset. */
+	ASSERT_FALSE(variant->map_readonly && variant->fast_reset);
+
+	self->mapping_size = COVER_SIZE;
+	self->fd = kcov_open_init(_metadata, self->mapping_size, prot,
+				  &(self->mapping));
+
+	/* Enable coverage collection on the current thread. */
+	EXPECT_EQ(ioctl(self->fd, KCOV_ENABLE, variant->mode), 0)
+	{
+		perror("ioctl KCOV_ENABLE");
+		munmap(self->mapping, COVER_SIZE * sizeof(unsigned long));
+		close(self->fd);
+	}
+}
+
+void kcov_uninit_close(struct __test_metadata *_metadata, int fd,
+		       unsigned long *mapping, size_t size)
+{
+	/* Disable coverage collection for the current thread. */
+	EXPECT_EQ(ioctl(fd, KCOV_DISABLE, 0), 0)
+	{
+		perror("ioctl KCOV_DISABLE");
+	}
+
+	/* Free resources. */
+	EXPECT_EQ(munmap(mapping, size * sizeof(unsigned long)), 0)
+	{
+		perror("munmap");
+	}
+
+	EXPECT_EQ(close(fd), 0)
+	{
+		perror("close");
+	}
+}
+
+FIXTURE_TEARDOWN(kcov)
+{
+	kcov_uninit_close(_metadata, self->fd, self->mapping,
+			  self->mapping_size);
+}
+
+void dump_collected_pcs(struct __test_metadata *_metadata, unsigned long *cover,
+			size_t start, size_t end)
+{
+	int i = 0;
+
+	TH_LOG("Collected %lu PCs", end - start);
+#if DEBUG_COVER_PCS
+	for (i = start; i < end; i++)
+		TH_LOG("0x%lx", cover[i + 1]);
+#endif
+}
+
+/* Coverage collection helper without assertions. */
+unsigned long collect_coverage_unchecked(struct __test_metadata *_metadata,
+					 unsigned long *cover, bool dump)
+{
+	unsigned long before, after;
+
+	before = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+	/*
+	 * Call the target syscall call. Here we use read(-1, NULL, 0) as an example.
+	 * This will likely return an error (-EFAULT or -EBADF), but the goal is to
+	 * collect coverage for the syscall's entry/exit paths.
+	 */
+	read(-1, NULL, 0);
+
+	after = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+
+	if (dump)
+		dump_collected_pcs(_metadata, cover, before, after);
+	return after - before;
+}
+
+unsigned long collect_coverage_once(struct __test_metadata *_metadata,
+				    unsigned long *cover)
+{
+	unsigned long collected =
+		collect_coverage_unchecked(_metadata, cover, /*dump*/ true);
+
+	/* Coverage must be non-zero. */
+	EXPECT_GT(collected, 0);
+	return collected;
+}
+
+void reset_coverage(struct __test_metadata *_metadata, bool fast, int fd,
+		    unsigned long *mapping)
+{
+	unsigned long count;
+
+	if (fast) {
+		__atomic_store_n(&mapping[0], 0, __ATOMIC_RELAXED);
+	} else {
+		EXPECT_EQ(ioctl(fd, KCOV_RESET_TRACE, 0), 0)
+		{
+			perror("ioctl KCOV_RESET_TRACE");
+		}
+		count = __atomic_load_n(&mapping[0], __ATOMIC_RELAXED);
+		EXPECT_NE(count, 0);
+	}
+}
+
+TEST_F(kcov, kcov_basic_syscall_coverage)
+{
+	unsigned long first, second, before, after, i;
+
+	/* Reset coverage that may be left over from the fixture setup. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+
+	/* Collect the coverage for a single syscall two times in a row. */
+	first = collect_coverage_once(_metadata, self->mapping);
+	second = collect_coverage_once(_metadata, self->mapping);
+	/* Collected coverage should not differ too much. */
+	EXPECT_GT(first * 10, second);
+	EXPECT_GT(second * 10, first);
+
+	/* Now reset the buffer and collect the coverage again. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	collect_coverage_once(_metadata, self->mapping);
+
+	/* Now try many times to fill up the buffer. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	while (collect_coverage_unchecked(_metadata, self->mapping,
+					  /*dump*/ false)) {
+		/* Do nothing. */
+	}
+	before = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
+	/*
+	 * Resetting with ioctl may still generate some coverage, but much less
+	 * than there was before.
+	 */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	after = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
+	EXPECT_GT(before, after);
+	/* Collecting coverage after reset will now succeed. */
+	collect_coverage_once(_metadata, self->mapping);
+}
+
+FIXTURE(kcov_uniq)
+{
+	int fd;
+	unsigned long *mapping;
+	size_t mapping_size;
+	unsigned long *bitmap;
+	size_t bitmap_size;
+	unsigned long *cover;
+	size_t cover_size;
+};
+
+FIXTURE_VARIANT(kcov_uniq)
+{
+	bool fast_reset;
+	bool map_readonly;
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov_uniq, fast_rw)
+{
+	/* clang-format on */
+	.fast_reset = true,
+	.map_readonly = false,
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov_uniq, slow_rw)
+{
+	/* clang-format on */
+	.fast_reset = false,
+	.map_readonly = false,
+};
+
+/* clang-format off */
+FIXTURE_VARIANT_ADD(kcov_uniq, slow_ro)
+{
+	/* clang-format on */
+	.fast_reset = false,
+	.map_readonly = true,
+};
+
+FIXTURE_SETUP(kcov_uniq)
+{
+	int prot = variant->map_readonly ? PROT_READ : (PROT_READ | PROT_WRITE);
+
+	/* Read-only mapping is incompatible with fast reset. */
+	ASSERT_FALSE(variant->map_readonly && variant->fast_reset);
+
+	self->mapping_size = COVER_SIZE;
+	self->fd = kcov_open_init(_metadata, self->mapping_size, prot,
+				  &(self->mapping));
+
+	/* Enable coverage collection on the current thread. */
+	EXPECT_EQ(ioctl(self->fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE), 0)
+	{
+		perror("ioctl KCOV_ENABLE");
+		munmap(self->mapping, COVER_SIZE * sizeof(unsigned long));
+		close(self->fd);
+	}
+}
+
+FIXTURE_TEARDOWN(kcov_uniq)
+{
+	kcov_uninit_close(_metadata, self->fd, self->mapping,
+			  self->mapping_size);
+}
+
+TEST_F(kcov_uniq, kcov_uniq_coverage)
+{
+	unsigned long first, second, before, after, i;
+
+	/* Reset coverage that may be left over from the fixture setup. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+
+	/*
+	 * Collect the coverage for a single syscall two times in a row.
+	 * Use collect_coverage_unchecked(), because it may return zero coverage.
+	 */
+	first = collect_coverage_unchecked(_metadata, self->mapping,
+					   /*dump*/ true);
+	second = collect_coverage_unchecked(_metadata, self->mapping,
+					    /*dump*/ true);
+
+	/* Now reset the buffer and collect the coverage again. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	collect_coverage_once(_metadata, self->mapping);
+
+	/* Now try many times to saturate the unique coverage bitmap. */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	for (i = 0; i < 1000; i++)
+		collect_coverage_unchecked(_metadata, self->mapping,
+					   /*dump*/ false);
+	/* Another invocation of collect_coverage_unchecked() should not produce new coverage. */
+	EXPECT_EQ(collect_coverage_unchecked(_metadata, self->mapping,
+					     /*dump*/ false),
+		  0);
+
+	before = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
+	/*
+	 * Resetting with ioctl may still generate some coverage, but much less
+	 * than there was before.
+	 */
+	reset_coverage(_metadata, variant->fast_reset, self->fd, self->mapping);
+	after = __atomic_load_n(&(self->mapping[0]), __ATOMIC_RELAXED);
+	EXPECT_GT(before, after);
+	/* Collecting coverage after reset will now succeed. */
+	collect_coverage_once(_metadata, self->mapping);
+}
+
+TEST_HARNESS_MAIN
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-11-glider%40google.com.
