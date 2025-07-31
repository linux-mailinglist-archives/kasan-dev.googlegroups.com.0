Return-Path: <kasan-dev+bncBCCMH5WKTMGRB45RVXCAMGQEVYOHMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C19FB170A6
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:21 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-33231dba44bsf5472041fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962740; cv=pass;
        d=google.com; s=arc-20240605;
        b=BPrInQecjKzc5+omIIRq4wE1IcdfipFXXKA7z6jckrYgIdCIqdccD7yhC5kBLljYn5
         qyx7DUEM/zQ8Mkl0BDSEtv+az3Lzyeh9jdaA5MJ6Hn7OvXp7kRekBra4b0Vws5oy01jY
         xQw/Hi2h/kZ44OHzT/LaA2I0y7tKDS3pH7wSJKtIjGgG9UuPtZ1BCpzzuE2Zlxo+QlWP
         6+EVdgeXNNYr1MKH4VVLOjzKcGkg6GXHV6o9LuP6xlv1bweuSCAJb4VUI91wE8iC6JNn
         QJ68IqoxYjOkofGa6cu8F/8+14O5yCL8dro3b9OzfMYvsNAEjUTp0U9XWTjlW0/2b1wg
         dwFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Cz97fqavhM7PhmNjqldkQlAirk2fzgjsyQg7bJOTWOc=;
        fh=VGopRar+C6yjae1KBPWxCdZaL9ujYqLH63d3V06z6sg=;
        b=eZdP9/wxLE03fca2X4g0AOYwii67wh/2hsI9MOmqOgJJuuX8kxIgoB7ueME55KzElX
         Zl7jTZZAOUpdR8kzh/InD2kvret08ahzOoUMYbt29IqY+TLo6CO3auvi604Y7XRxkDFN
         XNW0kTcl02gKsb1qbY7qSizweopaK1wz2hQHJI6STnvtSpwL4OpsTINdISTcAN2bfbOJ
         /gl/elYgQSkcTHQuEHUDoCwRKjJetPWB0iLlD69pRgutelLlVx5Ess23uHh8RFcgsgfO
         63bv3E0EZHyCyW/W0CTY52k92McrXoGshXbFVNTARTW0saczXNVxpenGdwqcuMvgQaLl
         XAzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=c7DcUsLN;
       spf=pass (google.com: domain of 38filaaykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38FiLaAYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962740; x=1754567540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Cz97fqavhM7PhmNjqldkQlAirk2fzgjsyQg7bJOTWOc=;
        b=hxSwBnblC31OdEgMGX8afrcmoEnyJjBu0NZMg1NggqSYXWPUuSI6QKQy0cOkgDi9mc
         aEAJLSvq1EhxfDVe+4OvKoBYpbQ7wfTJ779w8Yli/Yf6JX8pK01BJaeWU1jejv9BguAa
         b6rMerYvhspuH6V6rDEn36O+MV0+I0QStwd3PLGyzFiluOqhB0p9FRWTaRK3KsYahSI+
         kCWWfl7aUh6wKMBfGN3AhrLJhFNcIn+uxBAQnlL2bJ3K1D7ZiCOmGM8grI84mJazNK5a
         blg8QO7TGVxQjWXl5GjEXVSl1CYaYYpdnhC7tJ3ps8sJksLKsW5EIHp7hKRCb7yC83ix
         /Lvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962740; x=1754567540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cz97fqavhM7PhmNjqldkQlAirk2fzgjsyQg7bJOTWOc=;
        b=xPLFYDTASmM0CV7FezWmGb11khIE0pSWziz/VIa50+EgAtbqGDTDmEIyc8TxPQeciI
         ikFVp/uTTPOeoweXOHb5nTWIaIjBCPtMQ39NHzFgxjewZAT03hCpd3s7tf2RlKKjA5Kz
         rHDbYXAK49FuQqNDc3H/KPIWxlDqTco3+k0jw5m26wiaDI4DzHb8ni7pzwz3SdCOy79K
         nXhdWds/sz5Ky+Db73/LMnd9C26KEZj+T4j13wLeVfOjiRv5tsAWoGH4p/QTkwSnqwKY
         OvVHsalZ7LAm1Kb/F/t5kp99q8QLXA/DbGBAIKsFk6SRZZYsrc3OuSwvhqcHRSAc1ysw
         nVdg==
X-Forwarded-Encrypted: i=2; AJvYcCXF3ZZOAlbcKViZ9nLHE/26flAfGZe9qyEpQu7rWNVxs3UxZWADF628JoKF0eBWYuiUj+z4Hg==@lfdr.de
X-Gm-Message-State: AOJu0YxbJqDRZrPXehfxgel8et0i9O5Z4GFPtm0kXWES36sFp2sP83dz
	Xa1ahmgZpWU64tZXt1eK50xZSe3MhDbKe0E668pWe5sgghq2Och3qy9d
X-Google-Smtp-Source: AGHT+IEA8al6S5bYqUCrn1UM2/rLzaTEC7pt/+E0iyc1QXu7jW36FTfMVuCmi7qEAgIaExBMknJxHA==
X-Received: by 2002:a05:651c:608:b0:32b:2e45:c403 with SMTP id 38308e7fff4ca-33224c22869mr17081561fa.39.1753962740433;
        Thu, 31 Jul 2025 04:52:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdRdxfvXzXvQjzLp462AgCZCSUfg90qeCB76wpH52ZhwA==
Received: by 2002:a05:651c:10a9:b0:332:2a32:2846 with SMTP id
 38308e7fff4ca-332381981dcls2185901fa.0.-pod-prod-02-eu; Thu, 31 Jul 2025
 04:52:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDM3lB7z/dopK2YLIUDIKpyAbhs6hPitvPOilPOh/EdAxxyTYZ17wL+x6shm046XYebHSCCKnYBHU=@googlegroups.com
X-Received: by 2002:a2e:b8c3:0:b0:309:1e89:8518 with SMTP id 38308e7fff4ca-33224bc9afbmr18680921fa.27.1753962737443;
        Thu, 31 Jul 2025 04:52:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962737; cv=none;
        d=google.com; s=arc-20240605;
        b=E4pklza2LnQBeRShjTNaYr9SXfUutGQ4ApWn4EVXkahPlLKURNM9a32MdtM9ZhFOBu
         aGfAj7clpDlnxgomwix/3r0nXX0QFtiX5LBswOFl4VD2IZM1HZtNpI5y0zLuvWcveOGV
         cLF4piYINvPHwFcIdyhF81YBVnrjQu3DKx12bYTadApGULRfgGoDfXtxoM7nFluawbom
         GmOFUE68VKhLnYTjzQmfVJgTfjme0xy+8LJsCccmuSwUzJKeV+MGYNzWt6H8xbC+gFjA
         HOxrNuWvNk/g7LE5iKun7ok5KpqASmdrYiJfwBfp3BrE4ff/3rqT57y5xNE8bQHxPWXN
         hbNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=h3x7t3g1azUi3Bhe5e/NuO4vXpKA7reEhObrUhymgs0=;
        fh=KvjCw+wgckRM9KGLcuN9q4mwcKiYDWAD2h1+mmFAsiw=;
        b=UsrkiGuCACTOjsAOrrEZDoYZSx1x43pFVJxJajaHBkdhFUyEdJLlylj+C9EcxtV5pX
         a7XXMY7DgSGV3wTyW8PPS0Qjk5GPIGAAAAJiNvfokLoSFBj/btgzyOsTvQeXFslJvMcX
         6aLm4fR1BYNMZPbu0PCKHz1hRv7PS0mobYo5TyDJfLaxdsMPfRvhQFNxnNGwdFvlWPqT
         V6rpaMHdCoDXt4jdqU59ICTgvPvlS0cUdx3x5sMvx1BgL3YTG/Wz1yBFxx2QcUL6Ss0o
         fElUEvut+LbBobH9r3kA7YmGXZazHZbMjGdKxs6K8dg0GJaHntUJprIGAHmZ/8VAS/gg
         5G0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=c7DcUsLN;
       spf=pass (google.com: domain of 38filaaykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38FiLaAYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3323819ea89si397551fa.8.2025.07.31.04.52.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:52:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38filaaykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45597cc95d5so3254135e9.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:52:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC5C9h5bjPg7yo8QIjNZn1DVakw9hl8RGDYlEEbvxkLtMJVpRtuUyFLqa2DWJgSM1ht2dnmHGR3CY=@googlegroups.com
X-Received: from wmbet10.prod.google.com ([2002:a05:600c:818a:b0:458:8d91:62dd])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b6e:b0:456:27a4:50ad
 with SMTP id 5b1f17b1804b1-45892be4bf9mr54021785e9.33.1753962736912; Thu, 31
 Jul 2025 04:52:16 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:38 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-10-glider@google.com>
Subject: [PATCH v4 09/10] kcov: selftests: add kcov_test
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
 header.i=@google.com header.s=20230601 header.b=c7DcUsLN;       spf=pass
 (google.com: domain of 38filaaykcrs7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=38FiLaAYKCRs7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
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
v4:
 - Per Dmitry Vyukov's request, add CONFIG_KCOV_UNIQUE=y to the
   list of required configs
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
 tools/testing/selftests/kcov/config      |   2 +
 tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
 4 files changed, 410 insertions(+)
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
index 0000000000000..ba0c1a0bc8bf2
--- /dev/null
+++ b/tools/testing/selftests/kcov/config
@@ -0,0 +1,2 @@
+CONFIG_KCOV=y
+CONFIG_KCOV_UNIQUE=y
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
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-10-glider%40google.com.
