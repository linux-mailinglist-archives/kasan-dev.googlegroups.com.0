Return-Path: <kasan-dev+bncBCMIFTP47IJBB36DYC4AMGQEN7DAHFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C049A13CC
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:33 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a3b506c87csf3138865ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110511; cv=pass;
        d=google.com; s=arc-20240605;
        b=GzoXdgkB1zDPaUI7s2i5m+g+/OAt+g9hRGEqL9lWgoCFvUzL1wLwW78618C2VPIhsN
         aF4Z1FUR+/YeYXDHe4HTbsThT094qDvcg4IFh8gb9KVeacwYVWB8MfKKTtIWNEjLjyeQ
         //BzOUf21fKIENAfjIIPZbqV94geJdNwvTdaTJFEkAfwt5WwiNDIHcTnOmy2lBMWzISG
         pPJdHGsHCGZ+OFh95hTV3FWM0eg6lbKD2fJTv694lUcEdg74e8MLzTXy2wygBVszOM10
         7gQ7p2glIulIdfVGE8VmtDw2/QzjLI0AQ3ictR2dpN43dCeqAld9EjxrOC3AbMplLNaD
         gzVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XygzRfMysrakRw5IuEJ0wTN84ZWE74Mp1BpK0MIOJ/4=;
        fh=zJm4d/WAeiMn9HbW8+CAeHxMfYa4xKn+rOCp+Akjdpk=;
        b=PNbfoOiZoMe21z3HbrmJZaZnaZP2SHl87824Ym7u6wkLgugOZazaQHNjS3AQda+NEp
         OdEpkH7Vwjc6I+14v8MpeHfWVU3GQ2YfxBPbPpihRIEOgxKlrsYmSKmdRwbQOg17zhzX
         DJElWtw0M0cRKTpCBLW9IYrOMXbDj+k1ntu3CCYeNaFHdHLq4Z5pNWrms5z5JX7pl355
         3AE27c7iuEsyu2idmYJYj9+pT0CI+aJXDUEuY6ca8Je3RgESv0q+/Zy2fum7W91e9VqI
         XZpF7yKQjDUsDu/6Zp/qS0caJQQjcSFbGJ/TpX3memvxlCWK1+MrNBdWvpLqRCazcf1G
         f8hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=QDllrYwr;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110511; x=1729715311; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XygzRfMysrakRw5IuEJ0wTN84ZWE74Mp1BpK0MIOJ/4=;
        b=RGaNvwRJByQVaWMltTXeupTT72BQSlUKoZWJoepaxRLnvmwzx/BE8ZFxTYvb3gN4pq
         BE9SKzq1NpFOGqVUPlEa0QcYPyYnRJSu2WZVAEIGO0rq3CX7HGuMP0avxQsDJH85k6vX
         57Hpj0uxhuHJ4foqEIH7vxJR5xpgtx3IwODEmxLWWDrHa9Kqmn0ILpWtDFCai21dALJA
         LzJkm3lsF2is8OjC7K6oET6ed3dcuclGhE4M1M4aeVA6p9nJbzVHFmlsuG4Kvdshz7mm
         VLnz/6BGRq0Skf6tU3gmgoDEmocj8evjHdch4RiP7x+VBzHpXRYz1jydg9+lNl0QvKZ5
         gB6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110511; x=1729715311;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XygzRfMysrakRw5IuEJ0wTN84ZWE74Mp1BpK0MIOJ/4=;
        b=hnTSJlPZOpzSr6wuxUVcll3g8LXd1uw6s4G8G8xO41ZbjGaEJyLzE8CXHTG/LyfpFM
         by4HyRHJfpnLKIdN+SeOdQeweKqaj2EsHc1wO29praJ8zmF12ksHFu8NhfDCWL5DeShF
         7oVruJT5wiGZG0o/0oJ5DSyJZOG/eq0JvmZDri6cDDV3IGmcJlSfH3PFmOY6ZFC64mJE
         p4QcCP19H5on0SLx2vIGKCkJhh/mqv8+PdGQQzp+JFv2wTKP1C1/gD1ZvEpCdz0y6pj6
         RlFLC/Ru+LBcY2RMjvLvYBF+Jda4owT2LBmTStSld9Zvp7HaPBaxruGJr0UykzrQ28O3
         I36A==
X-Forwarded-Encrypted: i=2; AJvYcCXb/usJg2/lWVIBWZ/kT4FZS8SDY02hv5bCjjEBgY2xTDCiXQTcyz2LXzxiep8e9nc8LXudmw==@lfdr.de
X-Gm-Message-State: AOJu0YzUPV7rOiaHUKUEqwrAXwn/s6m8IGQUzuiQg9Jcpks6uYGSWJtb
	Hi+78j4XO2duZ1eym3+mvLkqakzgDq07FiAO/P+xfoPfIwFlInR9
X-Google-Smtp-Source: AGHT+IG2oXLiDeYiKCx1cOsthALgDvvhk7M933ax8vn+ZSEuINgOM91UPKR1t3bHnfDOKpJThxIzEg==
X-Received: by 2002:a05:6e02:138a:b0:3a3:b4ec:b3ea with SMTP id e9e14a558f8ab-3a3dc4e5788mr54525735ab.16.1729110511606;
        Wed, 16 Oct 2024 13:28:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b4e:b0:3a3:6ada:9a4d with SMTP id
 e9e14a558f8ab-3a3e4b0bf39ls1757695ab.2.-pod-prod-09-us; Wed, 16 Oct 2024
 13:28:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8kBzjcZpM8t/uYK4NGGYMTUSy8zY26s1ReF02opRQ5UQQZr3Wbj0XDrx0a0ism7U0NcCCVPxShA4=@googlegroups.com
X-Received: by 2002:a05:6e02:1e0c:b0:3a3:da4f:79ec with SMTP id e9e14a558f8ab-3a3dc4a3fc1mr58447425ab.7.1729110510651;
        Wed, 16 Oct 2024 13:28:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110510; cv=none;
        d=google.com; s=arc-20240605;
        b=E0WE/7sUfRej14hbmjt/JNcZbJe8w3mrHcMdzBt5gozsYoSYl8jxnVKz5ZDv+4SsBR
         lxn/sP0GGupMAPUnLZQisYDUxhQzB5jpAnS2PiffnGeWNWwTDOFfPG2REjx4XenQY2Ux
         /UiZUGf4oAkyB1vTYjwyUwr0sCNGqWAKFzNCgdrvqALMpknSRk6ut8R5iNWQRHKVkUd4
         SCZGyVX0jR1JXtIu8BMaNeQGl6mYY+24mDCYZWLVB0auR0GhkFEuMiynjw/kH5GENW38
         aT+vM+PChFGJM9V2GalEifra86q5CMYkVw6lbu1LX/GFsrE4UpiJL2QIdD6vDuW3+xRe
         UGZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rv10ipSUZUspRTnhL9JfvW8gxx9UoZi8WAdsMyxYUqw=;
        fh=7Rz8kIC+BSkjkqxBPFp17qI9oIqQFGZWotknzd/Fq9E=;
        b=lD4UEfg6pYt+waDOymLRynqhCxlMbAXmnLQNkLUybeQDiNFLWDgA09AIim73TFqsPB
         1qdOBUGJPVi5yiAWEBpm/IJ3wNLuReokZcg3OSagr/PTn9xLHJU6J+vEkjfGWU7RBCnl
         qXg9cYUy3p26mMpkdoifPMlwRlbQHVQliyHlSC9tcXAsP1NUh8c0V3k5Bap1/4rasr4C
         yZTdy2ew2dV/dyyJBsDVV8JESBSdR2wtCqmPNHqQ0Cbc2250b9d3X2YUCgSVpcFQ+T+B
         HQRZIRTRebeVuGYPKeHb/bIIaTZbrCY//uVnWRwgDa4X67ULunhqq5YA/MD1HuL/CSZ5
         WiRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=QDllrYwr;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dbec9b3b10si200753173.1.2024.10.16.13.28.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2e2d1858cdfso162303a91.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9KqBNGA6bVjiiWncVHdepnugr7H2DHKh07TxV5Z0ziWv5GpgqG9z9WMEuDbcKgpbMaPRS207x0lk=@googlegroups.com
X-Received: by 2002:a17:90b:4c8c:b0:2e2:ad29:11a4 with SMTP id 98e67ed59e1d1-2e3ab8bc829mr5746417a91.25.1729110509973;
        Wed, 16 Oct 2024 13:28:29 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:29 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 07/10] riscv: selftests: Add a pointer masking test
Date: Wed, 16 Oct 2024 13:27:48 -0700
Message-ID: <20241016202814.4061541-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=QDllrYwr;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Rename "pm" selftests directory to "abi" to be more generic
 - Fix -Wparentheses warnings
 - Fix order of operations when writing via the tagged pointer

Changes in v2:
 - Rename "tags" directory to "pm" to avoid .gitignore rules
 - Add .gitignore file to ignore the compiled selftest binary
 - Write to a pipe to force dereferencing the user pointer
 - Handle SIGSEGV in the child process to reduce dmesg noise

 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/abi/.gitignore  |   1 +
 tools/testing/selftests/riscv/abi/Makefile    |  10 +
 .../selftests/riscv/abi/pointer_masking.c     | 332 ++++++++++++++++++
 4 files changed, 344 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/riscv/abi/.gitignore
 create mode 100644 tools/testing/selftests/riscv/abi/Makefile
 create mode 100644 tools/testing/selftests/riscv/abi/pointer_masking.c

diff --git a/tools/testing/selftests/riscv/Makefile b/tools/testing/selftests/riscv/Makefile
index 7ce03d832b64..099b8c1f46f8 100644
--- a/tools/testing/selftests/riscv/Makefile
+++ b/tools/testing/selftests/riscv/Makefile
@@ -5,7 +5,7 @@
 ARCH ?= $(shell uname -m 2>/dev/null || echo not)
 
 ifneq (,$(filter $(ARCH),riscv))
-RISCV_SUBTARGETS ?= hwprobe vector mm sigreturn
+RISCV_SUBTARGETS ?= abi hwprobe mm sigreturn vector
 else
 RISCV_SUBTARGETS :=
 endif
diff --git a/tools/testing/selftests/riscv/abi/.gitignore b/tools/testing/selftests/riscv/abi/.gitignore
new file mode 100644
index 000000000000..b38358f91c4d
--- /dev/null
+++ b/tools/testing/selftests/riscv/abi/.gitignore
@@ -0,0 +1 @@
+pointer_masking
diff --git a/tools/testing/selftests/riscv/abi/Makefile b/tools/testing/selftests/riscv/abi/Makefile
new file mode 100644
index 000000000000..ed82ff9c664e
--- /dev/null
+++ b/tools/testing/selftests/riscv/abi/Makefile
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
diff --git a/tools/testing/selftests/riscv/abi/pointer_masking.c b/tools/testing/selftests/riscv/abi/pointer_masking.c
new file mode 100644
index 000000000000..dee41b7ee3e3
--- /dev/null
+++ b/tools/testing/selftests/riscv/abi/pointer_masking.c
@@ -0,0 +1,332 @@
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
+		p = (volatile int *)((uintptr_t)&i | 1UL << (__riscv_xlen - pmlen));
+
+		/* These dereferences should succeed. */
+		if (sigsetjmp(jmpbuf, 1))
+			return ksft_test_result_fail("PMLEN=%d valid tag\n", pmlen);
+		if (*p != pmlen)
+			return ksft_test_result_fail("PMLEN=%d bad value\n", pmlen);
+		++*p;
+	}
+
+	p = (volatile int *)((uintptr_t)&i | 1UL << (__riscv_xlen - pmlen - 1));
+
+	/* These dereferences should raise SIGSEGV. */
+	if (sigsetjmp(jmpbuf, 1))
+		return ksft_test_result_pass("PMLEN=%d dereference\n", pmlen);
+	++*p;
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
+	volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << (__riscv_xlen - 7));
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
+		volatile int *p;
+
+		p = (volatile int *)((uintptr_t)&i | 1UL << (__riscv_xlen - min_pmlen));
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
+		p = (int *)((uintptr_t)&i | 1UL << (__riscv_xlen - pmlen));
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
+	p = (int *)((uintptr_t)&i | 1UL << (__riscv_xlen - pmlen - 1));
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
+	for (int i = 0; i < ARRAY_SIZE(tests); i++)
+		plan += tests[i].nr_tests;
+
+	ksft_set_plan(plan);
+
+	for (int i = 0; i < ARRAY_SIZE(tests); i++)
+		tests[i].test_fn();
+
+	ksft_finished();
+}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-8-samuel.holland%40sifive.com.
