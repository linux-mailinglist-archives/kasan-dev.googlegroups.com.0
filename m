Return-Path: <kasan-dev+bncBCMIFTP47IJBBHXE5SZQMGQEH5PII3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id DC2269172F9
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:51 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4434fd118adsf34461cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349791; cv=pass;
        d=google.com; s=arc-20160816;
        b=xqOulw17k7UJe1PpAJbpEnosxHwMPB9oNLg0WU4kvuLqvONGsQ4Fq5Wgw6jWwoGLx4
         zVJ68BwxtDw6p3r2gh0hRW+Hh05iuFWsoJ75ob0JFhu6laNhE8DKpFCTM6PHL1Pi15Ea
         LKqJQv4wccvemw9VhDac0RTplMVcEv2WQDnk1l0BYUswSPCOD+MO70mCC1yJ9LXurjqc
         QRS+pdD0+rILs+XOWZNRpsP+M0LJLGmby65Ezi34jnF+TRubnZPeZ++fhveyfL8yMxDg
         LDVfsT3UOmmsM7SqW7w2PILEs+5JQXwOfUATkS+m3IACeE5QohiXbWnuMz9LwcPAhD41
         3CrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=juqnbIahu1xE/aHcyhx2agiHigHcd4ZAAfYlQAQ8Zzw=;
        fh=bjp8Nog7BIps2dTNqY0wFlkbFuoeYSyBVjX9mjvl65Y=;
        b=iJ+xGWfCKo6XYOigWT5Wyz1ZROrUqXlNycpIT9WU3qG2P+PWWTw/qceDlWuATiWo//
         oMRk2Noga29u8QSzPAUWqU8TxVbNke0eA/Pv2U9886qriSyiokMoGlLR54bfqy8h3/ys
         2wG/Ta7PU4qCkDaP0hbrhLgaJzo5dBuxXIekkUMjgWDYHWYg68YkrBoZR6zXS6HstR7m
         XpYi2u9AcKLT3fpGGjlRZ3qm6Y64qsw9YzcO+A1Q5Cl//N3XooLpUbD5Htp4MtgzIkH8
         Q3RJSjgsvrWesPeh1GGSg1wZix4wLuYoyLqGSTQaVVDOtb2TSdIylKDeUmkOqHE6Hd/1
         vkeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ZXvKcQaI;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349790; x=1719954590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=juqnbIahu1xE/aHcyhx2agiHigHcd4ZAAfYlQAQ8Zzw=;
        b=izeSQ6ixoe3oE6C+/kfLafTz3HhkiuFMlc2eS5LiRjAsggfFSwER6EVzyd/UHHPy+5
         vauwtUDozattmsS8shNSaBcsAzm2ku4/BolgMo5Escb9PZnzV9ZFkRIRsoo0MzC7Td5f
         a6w9XHdoR4r2+kM6Afk/i4E0Rh4ouEJ0KoRX8NCjzBw7Iikso2utBL9OoEnAPTDH1Wjb
         M9CpqQPbv8D1HGveRGtwIgcmyk5CXI6ezkZccjnYQ6uNUz+MVukbsbpwUjGHE88XykhY
         +RFllKY4ZNKMo/jn0PhnLx5ZG/n4S89vTt/pnt6M/W6iPE/P1nkcqz+kpBhrNKVFDrbz
         J+eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349790; x=1719954590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=juqnbIahu1xE/aHcyhx2agiHigHcd4ZAAfYlQAQ8Zzw=;
        b=CLtQiX8GnmCSWzQRa+mniC8nezTm+y5HX6wMnveA0TOCxe3c5fwaKUaaVRn+fyLEnp
         MfCEN+jAADgzRLjJ1cII0S5J/ClDkLNevnGVdz2glzKlMYrFiNypFttdhRWQDE9hEmUr
         9cnSP+5qZKjV9Y7oKneZpso5W2YHqqD1B5OgwDGoZZWxprUX67Qnfa+b6HbcOgP2UzdI
         ryvlANcYtxvmrJkA9nU4sSTeNEEFYAbc75/vmjNUg+RG/Y3jpGrZ3FhEMvTPZBukt79w
         9s8iVy7nMNSmgzFdPQ2ZA2jV8tg3vJ40w0zI1zO8Uem15e7ajKOTcsOBruAJUCGtlGUe
         ENvg==
X-Forwarded-Encrypted: i=2; AJvYcCXpSeDadg2QTt73gG+Q43lTmPfd0nTISFSUv/OJWVla2dw4NSavsuNH/Nu4V3MSyvANKOA3N3Z7v289uKwawJa024HzTvZs0g==
X-Gm-Message-State: AOJu0Yyc8X/g/5HhXogI1jbWfwnWiTWUNZGssSiuG8n17uODs1siqpPQ
	LM1cwoa4BzWB8k8X1UV5gzN2zKjt7v4dGBSRUVytqYujE2acEoMV
X-Google-Smtp-Source: AGHT+IHZqfaj/Iv2yKtqww4YCKZvf6HR3I8b69DGoTWEoLZgrdxYTK4dkr+i3dBTqk35O8dMfLb1Tg==
X-Received: by 2002:ac8:5f10:0:b0:444:ebff:37e4 with SMTP id d75a77b69052e-44504c26333mr967051cf.26.1719349790693;
        Tue, 25 Jun 2024 14:09:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7d04:b0:24f:f4eb:3558 with SMTP id
 586e51a60fabf-25cb5f5e6a5ls282445fac.2.-pod-prod-01-us; Tue, 25 Jun 2024
 14:09:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUX58GNEH7GjIO6Mb7gwtTPyVPhJS7YEPGtbbgyaoYUd4++in41F0+5AaId4u1vU6YHjgEd0vbW0huyEgEhS9sSrBBDrofhmjLWA==
X-Received: by 2002:a05:6870:2256:b0:254:7e86:ab86 with SMTP id 586e51a60fabf-25cfce44922mr6759443fac.29.1719349789879;
        Tue, 25 Jun 2024 14:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349789; cv=none;
        d=google.com; s=arc-20160816;
        b=Gag8Vyp0QqGKglmt6yJslJSnmIc4pFBvedArGq+UbFEFwUNBV4ksLr9z5Y5xLnaEfU
         JznY3S+vPtgY95Xy9Eba5mGezKxNsZYM71ARpDXn/y1cnk696qivhreivdW7Doln862W
         9Wql5f94hTL/xM6WyGhkPJSUzHPAFwO/XZ7c+8u1fNsWuXfZMjGgQZpCgc4cfzZ3DKz0
         qLLSGvRXQ9mf5XHexc3cCgWB8gbxRSX8EkNw9hRLheaXaFIOERa/xoprPhu3sXtfxR/u
         xtSDyLKR8TO/JqUzBqRs3uS25VSy6K1t7nIoXYbdmDHpIjA/o1STgBj7z4JbgB/HLUz0
         rZbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TPuofY2kiE0LkR878/Zu2IFTHH09jSBTsb0Rtm6Nb1g=;
        fh=EY9ysGlNh9ec2RnUfV5wcrxEInK8O7SdYxySvjHffXM=;
        b=smulZOoakfV9GdNJ2FWz/RuhLgm1U2LvdAgLLn4gPuYn+KBHoyDd0hgSqaRJRgSU8g
         5Tq7qCp8G9kITudzT19AOZabifJOUDncPCE9WiF/TyT/Pti/PSyIs11V7+vs8mv3l5XX
         GZMtjvSFZCE/X/N/2uIaONsEZ23nKUV9t6qXjiB4gs2EZADgOhIpFJW4DC42Q78FQo4R
         viCXCIrECYZ5JbE9oqLuY+TylRI2rwHo6P17PCvQTb001n+Nmm6FtnQmLC4YaEsH6bKG
         TwlzC8qlUAATlj6+K6iZc8F/Rz7teSVfGXb4qRFyyOth/DJPA2tsnCTolAwXfn48Y/0O
         0y9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=ZXvKcQaI;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25cd4c7d3c6si437395fac.4.2024.06.25.14.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1f9c2847618so50272915ad.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQ3Be93DWkQuKIFyiu2g4hDlcLBBOt+wG/n66rQPlBLER2YX3PMXVKw98mcEzvmBQifDGxNybItYpzMYRz7ZOjQPPAMTWltU4E/w==
X-Received: by 2002:a17:902:c950:b0:1f9:e7b4:5df6 with SMTP id d9443c01a7336-1fa158d0d2emr100281835ad.3.1719349788079;
        Tue, 25 Jun 2024 14:09:48 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:47 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 07/10] selftests: riscv: Add a pointer masking test
Date: Tue, 25 Jun 2024 14:09:18 -0700
Message-ID: <20240625210933.1620802-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=ZXvKcQaI;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

This test covers the behavior of the PR_SET_TAGGED_ADDR_CTRL and
PR_GET_TAGGED_ADDR_CTRL prctl() operations, their effects on the
userspace ABI, and their effects on the system call ABI.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Rename "tags" directory to "pm" to avoid .gitignore rules
 - Add .gitignore file to ignore the compiled selftest binary
 - Write to a pipe to force dereferencing the user pointer
 - Handle SIGSEGV in the child process to reduce dmesg noise

 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/pm/.gitignore   |   1 +
 tools/testing/selftests/riscv/pm/Makefile     |  10 +
 .../selftests/riscv/pm/pointer_masking.c      | 330 ++++++++++++++++++
 4 files changed, 342 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
 create mode 100644 tools/testing/selftests/riscv/pm/Makefile
 create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c

diff --git a/tools/testing/selftests/riscv/Makefile b/tools/testing/selftests/riscv/Makefile
index 7ce03d832b64..2ee1d1548c5f 100644
--- a/tools/testing/selftests/riscv/Makefile
+++ b/tools/testing/selftests/riscv/Makefile
@@ -5,7 +5,7 @@
 ARCH ?= $(shell uname -m 2>/dev/null || echo not)
 
 ifneq (,$(filter $(ARCH),riscv))
-RISCV_SUBTARGETS ?= hwprobe vector mm sigreturn
+RISCV_SUBTARGETS ?= hwprobe mm pm sigreturn vector
 else
 RISCV_SUBTARGETS :=
 endif
diff --git a/tools/testing/selftests/riscv/pm/.gitignore b/tools/testing/selftests/riscv/pm/.gitignore
new file mode 100644
index 000000000000..b38358f91c4d
--- /dev/null
+++ b/tools/testing/selftests/riscv/pm/.gitignore
@@ -0,0 +1 @@
+pointer_masking
diff --git a/tools/testing/selftests/riscv/pm/Makefile b/tools/testing/selftests/riscv/pm/Makefile
new file mode 100644
index 000000000000..ed82ff9c664e
--- /dev/null
+++ b/tools/testing/selftests/riscv/pm/Makefile
@@ -0,0 +1,10 @@
+# SPDX-License-Identifier: GPL-2.0
+
+CFLAGS += -I$(top_srcdir)/tools/include
+
+TEST_GEN_PROGS := pointer_masking
+
+include ../../lib.mk
+
+$(OUTPUT)/pointer_masking: pointer_masking.c
+	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
diff --git a/tools/testing/selftests/riscv/pm/pointer_masking.c b/tools/testing/selftests/riscv/pm/pointer_masking.c
new file mode 100644
index 000000000000..0fe80f963ace
--- /dev/null
+++ b/tools/testing/selftests/riscv/pm/pointer_masking.c
@@ -0,0 +1,330 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <errno.h>
+#include <fcntl.h>
+#include <setjmp.h>
+#include <signal.h>
+#include <stdbool.h>
+#include <sys/prctl.h>
+#include <sys/wait.h>
+#include <unistd.h>
+
+#include "../../kselftest.h"
+
+#ifndef PR_PMLEN_SHIFT
+#define PR_PMLEN_SHIFT			24
+#endif
+#ifndef PR_PMLEN_MASK
+#define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
+#endif
+
+static int dev_zero;
+
+static int pipefd[2];
+
+static sigjmp_buf jmpbuf;
+
+static void sigsegv_handler(int sig)
+{
+	siglongjmp(jmpbuf, 1);
+}
+
+static int min_pmlen;
+static int max_pmlen;
+
+static inline bool valid_pmlen(int pmlen)
+{
+	return pmlen == 0 || pmlen == 7 || pmlen == 16;
+}
+
+static void test_pmlen(void)
+{
+	ksft_print_msg("Testing available PMLEN values\n");
+
+	for (int request = 0; request <= 16; request++) {
+		int pmlen, ret;
+
+		ret = prctl(PR_SET_TAGGED_ADDR_CTRL, request << PR_PMLEN_SHIFT, 0, 0, 0);
+		if (ret)
+			goto pr_set_error;
+
+		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+		ksft_test_result(ret >= 0, "PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
+		if (ret < 0)
+			goto pr_get_error;
+
+		pmlen = (ret & PR_PMLEN_MASK) >> PR_PMLEN_SHIFT;
+		ksft_test_result(pmlen >= request, "PMLEN=%d constraint\n", request);
+		ksft_test_result(valid_pmlen(pmlen), "PMLEN=%d validity\n", request);
+
+		if (min_pmlen == 0)
+			min_pmlen = pmlen;
+		if (max_pmlen < pmlen)
+			max_pmlen = pmlen;
+
+		continue;
+
+pr_set_error:
+		ksft_test_result_skip("PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
+pr_get_error:
+		ksft_test_result_skip("PMLEN=%d constraint\n", request);
+		ksft_test_result_skip("PMLEN=%d validity\n", request);
+	}
+
+	if (max_pmlen == 0)
+		ksft_exit_fail_msg("Failed to enable pointer masking\n");
+}
+
+static int set_tagged_addr_ctrl(int pmlen, bool tagged_addr_abi)
+{
+	int arg, ret;
+
+	arg = pmlen << PR_PMLEN_SHIFT | tagged_addr_abi;
+	ret = prctl(PR_SET_TAGGED_ADDR_CTRL, arg, 0, 0, 0);
+	if (!ret) {
+		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+		if (ret == arg)
+			return 0;
+	}
+
+	return ret < 0 ? -errno : -ENODATA;
+}
+
+static void test_dereference_pmlen(int pmlen)
+{
+	static volatile int i;
+	volatile int *p;
+	int ret;
+
+	ret = set_tagged_addr_ctrl(pmlen, false);
+	if (ret)
+		return ksft_test_result_error("PMLEN=%d setup (%d)\n", pmlen, ret);
+
+	i = pmlen;
+
+	if (pmlen) {
+		p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);
+
+		/* These dereferences should succeed. */
+		if (sigsetjmp(jmpbuf, 1))
+			return ksft_test_result_fail("PMLEN=%d valid tag\n", pmlen);
+		if (*p != pmlen)
+			return ksft_test_result_fail("PMLEN=%d bad value\n", pmlen);
+		*p++;
+	}
+
+	p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);
+
+	/* These dereferences should raise SIGSEGV. */
+	if (sigsetjmp(jmpbuf, 1))
+		return ksft_test_result_pass("PMLEN=%d dereference\n", pmlen);
+	*p++;
+	ksft_test_result_fail("PMLEN=%d invalid tag\n", pmlen);
+}
+
+static void test_dereference(void)
+{
+	ksft_print_msg("Testing userspace pointer dereference\n");
+
+	signal(SIGSEGV, sigsegv_handler);
+
+	test_dereference_pmlen(0);
+	test_dereference_pmlen(min_pmlen);
+	test_dereference_pmlen(max_pmlen);
+
+	signal(SIGSEGV, SIG_DFL);
+}
+
+static void execve_child_sigsegv_handler(int sig)
+{
+	exit(42);
+}
+
+static int execve_child(void)
+{
+	static volatile int i;
+	volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - 7);
+
+	signal(SIGSEGV, execve_child_sigsegv_handler);
+
+	/* This dereference should raise SIGSEGV. */
+	return *p;
+}
+
+static void test_fork_exec(void)
+{
+	int ret, status;
+
+	ksft_print_msg("Testing fork/exec behavior\n");
+
+	ret = set_tagged_addr_ctrl(min_pmlen, false);
+	if (ret)
+		return ksft_test_result_error("setup (%d)\n", ret);
+
+	if (fork()) {
+		wait(&status);
+		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42,
+				 "dereference after fork\n");
+	} else {
+		static volatile int i = 42;
+		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - min_pmlen);
+
+		/* This dereference should succeed. */
+		exit(*p);
+	}
+
+	if (fork()) {
+		wait(&status);
+		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42,
+				 "dereference after fork+exec\n");
+	} else {
+		/* Will call execve_child(). */
+		execve("/proc/self/exe", (char *const []) { "", NULL }, NULL);
+	}
+}
+
+static void test_tagged_addr_abi_sysctl(void)
+{
+	char value;
+	int fd;
+
+	ksft_print_msg("Testing tagged address ABI sysctl\n");
+
+	fd = open("/proc/sys/abi/tagged_addr_disabled", O_WRONLY);
+	if (fd < 0) {
+		ksft_test_result_skip("failed to open sysctl file\n");
+		ksft_test_result_skip("failed to open sysctl file\n");
+		return;
+	}
+
+	value = '1';
+	pwrite(fd, &value, 1, 0);
+	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == -EINVAL,
+			 "sysctl disabled\n");
+
+	value = '0';
+	pwrite(fd, &value, 1, 0);
+	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == 0,
+			 "sysctl enabled\n");
+
+	set_tagged_addr_ctrl(0, false);
+
+	close(fd);
+}
+
+static void test_tagged_addr_abi_pmlen(int pmlen)
+{
+	int i, *p, ret;
+
+	i = ~pmlen;
+
+	if (pmlen) {
+		p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);
+
+		ret = set_tagged_addr_ctrl(pmlen, false);
+		if (ret)
+			return ksft_test_result_error("PMLEN=%d ABI disabled setup (%d)\n",
+						      pmlen, ret);
+
+		ret = write(pipefd[1], p, sizeof(*p));
+		if (ret >= 0 || errno != EFAULT)
+			return ksft_test_result_fail("PMLEN=%d ABI disabled write\n", pmlen);
+
+		ret = read(dev_zero, p, sizeof(*p));
+		if (ret >= 0 || errno != EFAULT)
+			return ksft_test_result_fail("PMLEN=%d ABI disabled read\n", pmlen);
+
+		if (i != ~pmlen)
+			return ksft_test_result_fail("PMLEN=%d ABI disabled value\n", pmlen);
+
+		ret = set_tagged_addr_ctrl(pmlen, true);
+		if (ret)
+			return ksft_test_result_error("PMLEN=%d ABI enabled setup (%d)\n",
+						      pmlen, ret);
+
+		ret = write(pipefd[1], p, sizeof(*p));
+		if (ret != sizeof(*p))
+			return ksft_test_result_fail("PMLEN=%d ABI enabled write\n", pmlen);
+
+		ret = read(dev_zero, p, sizeof(*p));
+		if (ret != sizeof(*p))
+			return ksft_test_result_fail("PMLEN=%d ABI enabled read\n", pmlen);
+
+		if (i)
+			return ksft_test_result_fail("PMLEN=%d ABI enabled value\n", pmlen);
+
+		i = ~pmlen;
+	} else {
+		/* The tagged address ABI cannot be enabled when PMLEN == 0. */
+		ret = set_tagged_addr_ctrl(pmlen, true);
+		if (ret != -EINVAL)
+			return ksft_test_result_error("PMLEN=%d ABI setup (%d)\n",
+						      pmlen, ret);
+	}
+
+	p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);
+
+	ret = write(pipefd[1], p, sizeof(*p));
+	if (ret >= 0 || errno != EFAULT)
+		return ksft_test_result_fail("PMLEN=%d invalid tag write (%d)\n", pmlen, errno);
+
+	ret = read(dev_zero, p, sizeof(*p));
+	if (ret >= 0 || errno != EFAULT)
+		return ksft_test_result_fail("PMLEN=%d invalid tag read\n", pmlen);
+
+	if (i != ~pmlen)
+		return ksft_test_result_fail("PMLEN=%d invalid tag value\n", pmlen);
+
+	ksft_test_result_pass("PMLEN=%d tagged address ABI\n", pmlen);
+}
+
+static void test_tagged_addr_abi(void)
+{
+	ksft_print_msg("Testing tagged address ABI\n");
+
+	test_tagged_addr_abi_pmlen(0);
+	test_tagged_addr_abi_pmlen(min_pmlen);
+	test_tagged_addr_abi_pmlen(max_pmlen);
+}
+
+static struct test_info {
+	unsigned int nr_tests;
+	void (*test_fn)(void);
+} tests[] = {
+	{ .nr_tests = 17 * 3, test_pmlen },
+	{ .nr_tests = 3, test_dereference },
+	{ .nr_tests = 2, test_fork_exec },
+	{ .nr_tests = 2, test_tagged_addr_abi_sysctl },
+	{ .nr_tests = 3, test_tagged_addr_abi },
+};
+
+int main(int argc, char **argv)
+{
+	unsigned int plan = 0;
+	int ret;
+
+	/* Check if this is the child process after execve(). */
+	if (!argv[0][0])
+		return execve_child();
+
+	dev_zero = open("/dev/zero", O_RDWR);
+	if (dev_zero < 0)
+		return 1;
+
+	/* Write to a pipe so the kernel must dereference the buffer pointer. */
+	ret = pipe(pipefd);
+	if (ret)
+		return 1;
+
+	ksft_print_header();
+
+	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
+		plan += tests[i].nr_tests;
+
+	ksft_set_plan(plan);
+
+	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
+		tests[i].test_fn();
+
+	ksft_finished();
+}
-- 
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-8-samuel.holland%40sifive.com.
