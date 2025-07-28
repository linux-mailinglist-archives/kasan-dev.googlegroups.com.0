Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHVNT3CAMGQEGKTRABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 128D8B13E41
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:24 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4560a30a793sf15560825e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716383; cv=pass;
        d=google.com; s=arc-20240605;
        b=avZR+aYJN6OnVUU6Fy+5goGBJd9z1riqxD/nuSmj4IFsjEu9PTnMWR0/u/WcFep/I2
         BlNmLa7hYRYz2QY0aGJPUVeNQakJikggxgjYwVqI0BJMsqNvHiZJXO98jEKvV1fCZ2UR
         3trZPN78p0FNzvwI/mbtRwqMzyljz8p4FYpwUk+grWe/BJ1xzOaU9zXr5Io/b0I9y2My
         XAfEoWVi3maubCgaVptrtKDZDgCvHENP3HI3kkBmADTA2yk0jI1FXmQhGLHsOuf+rw4x
         AQOvCXEmBYqyXhLjEsIlkSjp3BC0Uv4dB7PExcn7xh+JWVb+/5+iW5nj23NbR6G0KdT3
         h2KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SXOgCm49H7fX4QIx7d1iqAOKDg8YuYd0DL5/3t49nQc=;
        fh=b17F3DmdPj+mkWIN+8jmo6HqauyEfzpOdR8YFRB41f8=;
        b=Xj8b3WMLw3gGEPwS/nWaX7h0OK7+5F7ZR8Q8uB70wb1ecpn+tOcPy+ZWBP7yVc8PSo
         EctvkQZP7Uy7TE281AkPj1U2wTXBYUwEocTmaZ9NtzIj0dgfXJUHECO7DSOr1nCsXYnM
         0VO3pp9SaZvJdrXkgTaq218EqdNAYBpAAlmPuyE4WPwAo4cuKoSlLXQiKBl8H3Fb8xwI
         h8JP0CQle1YwMCIbKMSustgNBFYq/cNsvUy6jEjW1XX1JhapK1mj5vENf2qm5l6PFDKX
         BPzlk2lWqR3hQVWPte1jxFGRuDDPMGFFJx4nMJw4t4pQPHnbi7S4g1102qDVPoyyU5Pp
         QeVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NO0Tby/c";
       spf=pass (google.com: domain of 3njahaaykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nJaHaAYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716383; x=1754321183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SXOgCm49H7fX4QIx7d1iqAOKDg8YuYd0DL5/3t49nQc=;
        b=tibVE/L7BybNbaOEwjIjRa03mI1zEkYvtYvt3azwDCW4nzlSRlQHgelRBYMR3EiT8+
         bT7M6A9vS6z41vqN3qoSjl3jf0LDQqIVAtTI8+HOmVfLWXwezoPQ1xhlyDH4EYSNsq+m
         q6VHqQXUUfrzTS8W5NPY8KQzMd/o4jrbyq0gGKOnAFoTRyUuMVMjDlOXhDZyhy5BuciF
         ngF6/x+N7Zu4Xt/s0OClMkaWpmLNtJJmc4ItMRQVsK8NP69C9gkwSlDToTCI979vzOpO
         97Nhkhw5Io2diY7zRvUZFb5Hs6PEUeF+ZrcZzlkLaB0vg/OU+omua78mic8urgd5Zj2L
         36fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716383; x=1754321183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SXOgCm49H7fX4QIx7d1iqAOKDg8YuYd0DL5/3t49nQc=;
        b=HoXWf0dhdx9WIgyB3oupCCr4KAsh01YvXLGd/rahSCpNwrx468f6wOp6Dr+p54QR0n
         sVjAEfUuwCjIXw3QjcnX0Sx9E+aRxKZWzdnOJdYMSAoSaeLam++ZHrkiJnfcDn+GfBkO
         C0ckCfJXIMkcLigNuv4n72w8N2K2irfsY0+9g1vmWxZ1AgrI2YDLuaf6GZcB+jr5kOoa
         pbQlxdJHbIDovmr8p/ce9x0/Z9cADpgSvMpTynXSfmYoPrsrLx3Dl3X+2jlODuxgCngC
         PBetVoUTE5WaYKb8rAGHQ2gI9OAt/WXWw7rIdZdUCFCRE/4YKsiFIUAfX5HW31a1I12e
         effQ==
X-Forwarded-Encrypted: i=2; AJvYcCWrzp9c6v/udO+iFbq1lkQ6cH7PvFjPG5Wc5+W9m8ej8xX7lpWU46SkFsOMy6YyZmzoOSEoeg==@lfdr.de
X-Gm-Message-State: AOJu0Yyx7YBZewynj3dkDLVVAbrYhnvpDHfO2aLmuxB98bWuQ7o/Q06O
	Dhta2xDU2Mi06mC7+0rX0ZbnE1yxq5U8BbHDRlfZrCp3VzJl5+hH58mZ
X-Google-Smtp-Source: AGHT+IFxsKhLdSHQNvFLsHbDI4GUNyGQAhsXdto94TRtCKFphjuA8wwBWpNSgjh9i995gwyic4H5og==
X-Received: by 2002:a05:600c:548a:b0:450:d30e:ff96 with SMTP id 5b1f17b1804b1-4587631c069mr108614405e9.0.1753716383528;
        Mon, 28 Jul 2025 08:26:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcSAfCwm06d1xYn2FCLHrQIeD31Y9qCASrvAjbSp1WIRA==
Received: by 2002:a05:600c:45c5:b0:455:97ce:dc34 with SMTP id
 5b1f17b1804b1-4586ea28d7els28638795e9.2.-pod-prod-08-eu; Mon, 28 Jul 2025
 08:26:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV56D+bsKSwmcEKofWvwPECtYG5BZjYdaE1iLstc+DyOc6UqTEOYZAoS2k/pl/gEeReVRg4MFrcCVI=@googlegroups.com
X-Received: by 2002:a05:600c:6309:b0:456:161c:3d77 with SMTP id 5b1f17b1804b1-4588072e3femr68395395e9.16.1753716380884;
        Mon, 28 Jul 2025 08:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716380; cv=none;
        d=google.com; s=arc-20240605;
        b=ZnWc7v5/v6uLbnRkA+v2uQW18Ab3Drk8oof9OzYOr+tivVHk68vIFhAhwIYweo4e0V
         p1esgXCpRx0sw3jpOdD6igihPJ4JQd+IA+923M90wf/082gFHGs0BI9rPr1ZfGwXkCus
         P+zmMZzUXVEP+QMJO+mbuQO5ZTmzTZ7n0V5updbu03zAofBcn38a2DDi3X3raoKXdzkK
         +Ip9UvpcMIdvIsWcjA0Lt4JqOuZCwYC+TiW2uAE/GsZ/0zOZPuAqHF5W0go6LO7WwTZN
         qLDcuN0SHXaOx4G3MudKxsNjl5brYDFHmlUd3cwK9fObRWZ1rEV1eZ3I6HhwmamvdX4M
         yWJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RM3rYcVJaPkMmvCtgqhtUuIHqeUyU5KTFhX1F5xwLi8=;
        fh=bYZin638b6ThGWQVnFKAtLY90gXDQ/YMj4m4s+rrDMI=;
        b=Rsm8NpUIFKRDYeB7xOoT3iSZjMZYhaGYiyUgZq4SpxSubDfiysWCQj9ful1QheDQXt
         kpjyAGaraC+uOCeaK05EmeSRMVfl6fULzgvdpX0xdp4vtvMPKD6Irj5qWJRpLd4B/jZ7
         YQBHAAI/nE/y66AZldSWbquUUAPI9wcqfQ9KQm51p5Rsv+44yYuHgyFJwRYBgTKPSb8n
         5Zx+MeU09odLjfBD+OqIZfYWZIh+H3uKSQHUnCXRoV0DZyO5xwX5k4ppwQFmMvrhCtxV
         CS6Li1BsQSC47+zp3JhSM1OS+BSegOe3jySem/YmwDEVi747V79cz3ps3QUl4osK4Z3m
         4HLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="NO0Tby/c";
       spf=pass (google.com: domain of 3njahaaykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nJaHaAYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b787dc0640si64192f8f.7.2025.07.28.08.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3njahaaykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b7865dc367so905441f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUDgeYuqsqzbu5G12GuR8fgkitXLNSCyvsN9WNSe58IhJBpAe1gr/IaUEVBT7hEYKHMg8ygDA5RQ0=@googlegroups.com
X-Received: from wrf6-n1.prod.google.com ([2002:a05:6000:43c6:10b0:3b7:887e:816])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2582:b0:3b7:868d:435e
 with SMTP id ffacd0b85a97d-3b7868d4705mr3391930f8f.41.1753716380342; Mon, 28
 Jul 2025 08:26:20 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:47 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-10-glider@google.com>
Subject: [PATCH v3 09/10] kcov: selftests: add kcov_test
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
 header.i=@google.com header.s=20230601 header.b="NO0Tby/c";       spf=pass
 (google.com: domain of 3njahaaykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3nJaHaAYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
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
v3:
 - Address comments by Dmitry Vyukov:
   - add tools/testing/selftests/kcov/config
   - add ifdefs to KCOV_UNIQUE_ENABLE and KCOV_RESET_TRACE
 - Properly handle/reset the coverage buffer when collecting unique
   coverage

Change-Id: I0793f1b91685873c77bcb222a03f64321244df8f
---
 MAINTAINERS                              |   1 +
 tools/testing/selftests/kcov/Makefile    |   6 +
 tools/testing/selftests/kcov/config      |   1 +
 tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
 4 files changed, 409 insertions(+)
 create mode 100644 tools/testing/selftests/kcov/Makefile
 create mode 100644 tools/testing/selftests/kcov/config
 create mode 100644 tools/testing/selftests/kcov/kcov_test.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 6906eb9d88dae..c1d64cef693b9 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13018,6 +13018,7 @@ F:	include/linux/kcov_types.h
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
diff --git a/tools/testing/selftests/kcov/config b/tools/testing/selftests/kcov/config
new file mode 100644
index 0000000000000..75726b2aa9979
--- /dev/null
+++ b/tools/testing/selftests/kcov/config
@@ -0,0 +1 @@
+CONFIG_KCOV=y
diff --git a/tools/testing/selftests/kcov/kcov_test.c b/tools/testing/selftests/kcov/kcov_test.c
new file mode 100644
index 0000000000000..daf12aeb374b5
--- /dev/null
+++ b/tools/testing/selftests/kcov/kcov_test.c
@@ -0,0 +1,401 @@
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
+#ifndef KCOV_UNIQUE_ENABLE
+#define KCOV_UNIQUE_ENABLE _IOW('c', 103, unsigned long)
+#endif
+#ifndef KCOV_RESET_TRACE
+#define KCOV_RESET_TRACE _IO('c', 104)
+#endif
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
+	EXPECT_EQ(ioctl(fd, KCOV_INIT_TRACE, size), 0)
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
+		/* Cleanup will be handled by FIXTURE_TEARDOWN. */
+		return;
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
+	self->bitmap = self->mapping;
+	self->bitmap_size = BITMAP_SIZE;
+	/*
+	 * Enable unique coverage collection on the current thread. Carve out
+	 * self->bitmap_size unsigned long's for the bitmap.
+	 */
+	EXPECT_EQ(ioctl(self->fd, KCOV_UNIQUE_ENABLE, self->bitmap_size), 0)
+	{
+		perror("ioctl KCOV_ENABLE");
+		/* Cleanup will be handled by FIXTURE_TEARDOWN. */
+		return;
+	}
+	self->cover = self->mapping + BITMAP_SIZE;
+	self->cover_size = self->mapping_size - BITMAP_SIZE;
+}
+
+FIXTURE_TEARDOWN(kcov_uniq)
+{
+	kcov_uninit_close(_metadata, self->fd, self->mapping,
+			  self->mapping_size);
+}
+
+void reset_uniq_coverage(struct __test_metadata *_metadata, bool fast, int fd,
+			 unsigned long *bitmap, unsigned long *cover)
+{
+	unsigned long count;
+
+	if (fast) {
+		/*
+		 * Resetting the buffer for unique coverage collection requires
+		 * zeroing out the bitmap and cover[0]. We are assuming that
+		 * the coverage buffer immediately follows the bitmap, as they
+		 * belong to the same memory mapping.
+		 */
+		if (cover > bitmap)
+			memset(bitmap, 0, sizeof(unsigned long) * (cover - bitmap));
+		__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
+	} else {
+		EXPECT_EQ(ioctl(fd, KCOV_RESET_TRACE, 0), 0)
+		{
+			perror("ioctl KCOV_RESET_TRACE");
+		}
+		count = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+		EXPECT_NE(count, 0);
+	}
+}
+
+TEST_F(kcov_uniq, kcov_uniq_coverage)
+{
+	unsigned long first, second, before, after, i;
+
+	/* Reset coverage that may be left over from the fixture setup. */
+	reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
+
+	/*
+	 * Collect the coverage for a single syscall two times in a row.
+	 * Use collect_coverage_unchecked(), because it may return zero coverage.
+	 */
+	first = collect_coverage_unchecked(_metadata, self->cover,
+					   /*dump*/ true);
+	second = collect_coverage_unchecked(_metadata, self->cover,
+					    /*dump*/ true);
+
+	/* Now reset the buffer and collect the coverage again. */
+	reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
+	collect_coverage_once(_metadata, self->cover);
+
+	/* Now try many times to saturate the unique coverage bitmap. */
+	reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
+	for (i = 0; i < 1000; i++)
+		collect_coverage_unchecked(_metadata, self->cover,
+					   /*dump*/ false);
+
+	/* Another invocation of collect_coverage_unchecked() should not produce new coverage. */
+	EXPECT_EQ(collect_coverage_unchecked(_metadata, self->cover,
+					     /*dump*/ false),
+		  0);
+
+	before = __atomic_load_n(&(self->cover[0]), __ATOMIC_RELAXED);
+	/*
+	 * Resetting with ioctl may still generate some coverage, but much less
+	 * than there was before.
+	 */
+	reset_uniq_coverage(_metadata, variant->fast_reset, self->fd, self->bitmap, self->cover);
+	after = __atomic_load_n(&(self->cover[0]), __ATOMIC_RELAXED);
+	EXPECT_GT(before, after);
+	/* Collecting coverage after reset will now succeed. */
+	collect_coverage_once(_metadata, self->cover);
+}
+
+TEST_HARNESS_MAIN
-- 
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-10-glider%40google.com.
