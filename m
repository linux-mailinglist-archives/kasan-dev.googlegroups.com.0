Return-Path: <kasan-dev+bncBCMIFTP47IJBBD4RX63AMGQETLNRKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BD3C963734
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:08 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2706005dbcbsf90340fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893327; cv=pass;
        d=google.com; s=arc-20240605;
        b=D92Na3eB0ZQjfu4Zkq4OZQR0yUR2GLk61cDVoCSo7H8Z11PmdpqhV27rJtzo2PgMm6
         be1xcviVhQSB5JtA9i0te0rJauivC9Of0glev51LeZyy89qTNVqop14ygUm3ifUbkhZI
         H07d2yDuzLJirdi5H1MrTkpmHuT/b3t4RSnwBFoo/YV3uZ7y+c+s2MTPvtdCNWT8cEfm
         on4TFgOynoirphpQdPcbzpcwi3lTFPg5mkv6DNAKcBLK+s/5TBnQgHEXGtmkFjVq/NLe
         MGSPMqQpVQRtjPR7ZGlj+8C9eGiSRaI21SEjMb+Eh+RdsT04+5Zf8LCnF6wPikp8R8FL
         AsHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IJuVJXCIIGm2doYaQCYw7NriLReCAKm1hQUgB2TT+gk=;
        fh=7Wh7bvRpAyU/3ccuW6Cq3ocHoxn6ZbAaXQET7ACXr6g=;
        b=ODtyffU66+ulsR4jKZhRdDaOkv7y0KySjPrQER3lHlp/7drUA4IY3m89te2V6xhMY5
         fD2DfR5NKEoBZjxfW7cgtlRjcuTCMYWUXm0izbrktZ9GKZCD5ydHrw81WHdhaz9/1B0b
         kLPajh9clH574K3NqaClLwDP6Y4CX1Kuu0Mj7beCgBJF/uVPx7eL5YRte1U3dp8ablOs
         nNFtSMZ2lpm+QOj00Wr4K6Seki+KmHMnm/MMhmffY+vvxGSSHHTVXPA5tMV/s8LtIoWs
         xP6KUsx8i0tQP2LB7rsi0Jr5eNuhQufVM9yxxF96b5GDqlicDUcXvDdz0GzghCXNsG0I
         gfeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=U1SIptP0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893327; x=1725498127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IJuVJXCIIGm2doYaQCYw7NriLReCAKm1hQUgB2TT+gk=;
        b=Lqma5Hwc+NbRFENFqSLaLrBwjcEI/xvjxTJSHQLLyzz+CVLIdKIaBNRlu5hA80OOsC
         rkNbjeWHulLPRlr+F71YvRK6xpcZfSQCWLP8lW7dfu7l5XNb2yLUavUvN5Ds2eb3PMtu
         s7Ji0Q6xeUDmA6FBmWwLKTLz/ia0WvgRM7X5fxhXIwzP96cmmpyiHcF+WmGdpXEmgKN+
         /Ac5wueAsXT0/RXVQ0kxxLmn03yu9JjkxQRNeDDsQANQAK07fwMTItO1ugywjOvkEfV4
         L+zCRYhiZ6kDRz9SqOmb9UhOfzKh6thB1qcYWL7nznk3BEkCvpI8agMF9oGxfoCISMgY
         78cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893327; x=1725498127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IJuVJXCIIGm2doYaQCYw7NriLReCAKm1hQUgB2TT+gk=;
        b=WoeA0HcZ7od98UqpuuWcWqJ1Qt/MnMR1ZM75NCE94oHOeDAIq8tI9jL48PgWYeqPgB
         0ZjBUi2uOeZ6Wx7nPzARwJuYRCWFN+rZlHDMurHuDrM2BcydQzDVX/AW7dsxhZRZDI0Y
         CN2t+hPHPWhTsHbCyIrFB0vB1W7NlkUyEjq8dTDV+spjmEEBx2ARxzNfep+O9VSyjjJt
         BuPqj0vqj1az9nB+l2fXiXrMjszzoYXtNZKMPSLl2N1VS8qxDdGWoDSvpYATTxGV2PYN
         tt3ZmrmDXusshDxPypdhDv2Kgq8/SxrF5oVDhxnI+iDSP0PsswLGypXopwBtu8sKE38b
         PCKg==
X-Forwarded-Encrypted: i=2; AJvYcCVeJ1fiEEWE/pvVJWu5DuYC15jfAPh3ESqSiy0ti3EHYpxWw07zNWyX9y1YBIB+ggCt/WYBxQ==@lfdr.de
X-Gm-Message-State: AOJu0YzLECrFppGvSxaVyd1lNI124BFNdIaHIY2WsLOKCuI+f/fpNtd/
	s5jOv4y+gYS4rV+GLr0z4FNt7OSV7blOLAmV3pGmzMqwyyiSq1hA
X-Google-Smtp-Source: AGHT+IGLn3JVFvs3S4zq7smdX/nwu2/Y7PDAr1g+KYFK+nnJ0jZvP4t0C+6cC39qRkFCuBJwVE7jcw==
X-Received: by 2002:a05:6870:b68e:b0:259:8371:513f with SMTP id 586e51a60fabf-27793544d83mr410427fac.21.1724893327274;
        Wed, 28 Aug 2024 18:02:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:758c:b0:24f:f6d5:2d15 with SMTP id
 586e51a60fabf-2778f0c2720ls204942fac.0.-pod-prod-00-us; Wed, 28 Aug 2024
 18:02:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSIWrMDjwsQFhZPJnoJol70JwBKOyVaH1vyuQqJNuEJNbv6q/bFhENIUcVibjDyJKHmo+Vp3isYTQ=@googlegroups.com
X-Received: by 2002:a05:6871:553:b0:267:ab12:7fbe with SMTP id 586e51a60fabf-27792f148bfmr427607fac.0.1724893326532;
        Wed, 28 Aug 2024 18:02:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893326; cv=none;
        d=google.com; s=arc-20160816;
        b=sp2QMYZPoNocDVGpGdQH2cCSLvLbrwvE9xXLQP0+lezcRzAs3yj0hQQB0+3AO+IQMx
         V3d3mM7dLb2Xs75GNrt+FVbLVwUZqRxMmhgnr6AD49eOE1vo+C3c5cvn9nzZIY6OnK6K
         DtfdPnjKgIZLtvftphrG04tG2Wa++Y/Y3KSTPxtw8nUB2jntdJVTOr/mOhedhj40XQM5
         msUZWXTtzMeql2ry5CP+fhq6c4CO2fbyKw6JsJaaG1zda5qx+ws6+C+5mYGGA9IWpBnh
         le8bsp3dyP+7AfAaQVJC5voS/6upW6+AZsElU88d7T2weLiEwJ60eF/DGCntLooutFOT
         mrFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QdTr6WFexikZD5z5SMB0wNcwIFtpGfuIsUFT4S+mZyo=;
        fh=tSKJNg+VT8o4AkCmcp6kQW8uDkS4pyfS2de9CaH0Izc=;
        b=SjJyq2/KhSyvhVjxrR6Xa2kQjGls+l1dgkfddh6bZfN21EKDf6LuA7BYclQjrMFzNf
         m5HUg5OZXY1JAueDUAsub1Tn+HEZ0TlEYfcgdgeyheDRMcIo+yxBKNoqUc51jzuHRzVi
         xW251whDu2rCIsr+/06AM7OV6XGTgXvXZo0KTxb6FdJFKcmlNJaTiJd0YRzJYMCFpdRk
         Gzlp//F3cXCk0SXCTVgqecAPC5bM7cOkr4sxpM5CidWGhgbA3HX5yvjWS5qReCB3oQVr
         4SlxN5OoJdm+Ftzrcj9MKfRr2Cih5ut6gArogeG/pJND0P+J4PqicvGTSGMblu6/Rg36
         RT3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=U1SIptP0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-27799f3162dsi4013fac.1.2024.08.28.18.02.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7142448aaf9so82679b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWtVajR40CSczU02YrRvtTS67k0v8cP5aHeB1/83uuxkhSbAgGnQFIUNhHPHN7UFV4n2ED/RrC975c=@googlegroups.com
X-Received: by 2002:a05:6a00:3a99:b0:70e:ce95:b87 with SMTP id d2e1a72fcca58-715e0d94b8cmr1199293b3a.0.1724893325492;
        Wed, 28 Aug 2024 18:02:05 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.02.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:02:05 -0700 (PDT)
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
Subject: [PATCH v4 07/10] selftests: riscv: Add a pointer masking test
Date: Wed, 28 Aug 2024 18:01:29 -0700
Message-ID: <20240829010151.2813377-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=U1SIptP0;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
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

(no changes since v2)

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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-8-samuel.holland%40sifive.com.
