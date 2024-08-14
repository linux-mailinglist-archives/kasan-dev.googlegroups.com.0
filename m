Return-Path: <kasan-dev+bncBCMIFTP47IJBB7GO6G2QMGQESE5O3EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 214EB95164E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:54 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2611a4d4fa5sf8153359fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623292; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mko6NyKg5zFN2XCVRx5HhG3ExDMz7yQukVq1eydGvV20Qq7BVQmhqwTPo96V7Py1D2
         /oqMz0dqAEgtAj5vkHKRSXBUkMAe6xCfdIgk5lcvAPyYfHOCt0/qvdpJqlEthXh3t7Cs
         iZvsxR6vXhUO+sN2Wp5DCOk5ybK9+AFc3brC4UE+r3nMsqLlCjvbp/Jra5mdCgTUoT0r
         ZWN7A+tqzQAoYoHjVOXYMCFNbBnDlUoume7nmXeQJCSNlBc6gxH+ldif8LMzWKcPX9m2
         AuSSp3L4V1YO7GgJGOR82LqkiotSSbo5I+TClQ1OC+A13wbF5ghpzhndund/+IZPrOGd
         KoaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=mnWFE3T73vghuDF8Dfp6F/KpHBLVgpg97nTporIAE7g=;
        fh=tevMe1cfqw6kkT7ywfioEJC6a5/CwWMSRs5BmhIuukY=;
        b=yXNKotwHHtAZnRoC4B1EsD3zNCcLBBBRYeLpQHwqL/t67Lvbm/MtZulhI7VV8wqeUJ
         qtBBkFnsK0RSnPGmpR9qVvsnreRWoDRW5FWjtvO73uICKQ2IVRGpqYPIAgmfwzCzyRWv
         awuRV9D6FV2Ia/wnrmb+WBjpQZAlRQV0s7mw2znlKM69tsnd35KSU9fEehK2haA/vxig
         3WH/lJWTGQRiPkrU4HQoLgDCZ9X8y1LOgD8xKTbYyeFnJewP+FXX83d2Vy46VWa3NeXe
         1eImSoVGpQwdQYOOVqUrwOqS5mYhzPhP/cbwD6lfNIzKnSUceRhsdcTRWviwiVRa1tsA
         SNTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=D1QOXsmB;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623292; x=1724228092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mnWFE3T73vghuDF8Dfp6F/KpHBLVgpg97nTporIAE7g=;
        b=MjMNRXQyxs0pir8sBj+xqdNO9cNqGVtzS8W129UC6iQdToubdhrflYI1qauzfH4NOw
         1hjUKkIjUv7ajznNJACtfV9yHQ63CfaRtCHpZwYVxc3Qy5rEuVMcVzYgOoywDSSQrR4g
         kwUN6/eJK44W0dglmlNs3DdeVS30U6gh15PYGS09PKkVqcy1Mr06gk1ATJF8duSPTRYM
         BRO1Fpv+jOpfLSna4Xxjw2AC0+edHuAYP0YBPKvFT9n4MWOtcSqOqbM1kVwqq7Hq4VxT
         7st6K1qmaDGx0e/c2GwvT+pLPXSYByPuKMM/I/8GyYOtvFvUozPKMwHLrK+OJFGgmqMe
         M8sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623292; x=1724228092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mnWFE3T73vghuDF8Dfp6F/KpHBLVgpg97nTporIAE7g=;
        b=tB7zRMLofi5n/GCW+6j4iPPGfkCFfFAcYfVqZQarTiMjT/Z2TxVKt4X4CbqPyPSbvY
         dyOoN6ILcUaskFu+4m8kxJiJANNoU6WahbAHD74rshZYAMh6uGeC5vS4CmAH3cVBCyy8
         JXwJb+ohlCy/pEznhSQP17tY01LR+A2WaSMwBZK15VLmwkisn2UWYY3BM/9GI4CTA6nv
         dhla8+w+l3BxCa5hj4S+pyy2QAsTDXvFGkrqSHcl+nvsqJ0tfKwHGKzk1o7vcjDqDACe
         UXGM0ilTNgOU1hVC+Dfgjcxw+kbekK3gp/X0OLl7Y/dbVmqQiO22zchLmWPtLioOXpUi
         QAWQ==
X-Forwarded-Encrypted: i=2; AJvYcCXU5doviSdeZiwy6u9csB8jM2UPyYjbHPOODuchmXnSJpSv5jWWXo90E5fZqS/qQpu0x/Cef8wYh2qtmdHdcpzeE/76wm0f5A==
X-Gm-Message-State: AOJu0YyIrRUmY+I73lmkU2X4JgVDYaA4p0+VMkuDB/FPOimv0NvPqJI3
	z1QKT7gCUcC+MKpvbJxcdb9LpqJw0hJUXR5StxKPgCm1e30h4P+s
X-Google-Smtp-Source: AGHT+IHRJJIpfAXhiA+iP1dCS0Qi+Kay6kdcQ8BuUHg5Bt6wNoFE6ApxKsOuV4kQKA90akkclyqv0Q==
X-Received: by 2002:a05:6871:b26:b0:25d:8d4:68ab with SMTP id 586e51a60fabf-26fe5c3b4c3mr2451975fac.40.1723623292701;
        Wed, 14 Aug 2024 01:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7819:b0:254:6df2:beae with SMTP id
 586e51a60fabf-2692505ecf4ls8822086fac.0.-pod-prod-04-us; Wed, 14 Aug 2024
 01:14:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXU370GE4Ck0nufZTD08W7LSAdUjjDcMxtFuHCltgM6rKd6CROCVV3qMbXYRCAoXgFiHP1EeOyhVuQ2wzSqSdYWoolKWCemRFtStQ==
X-Received: by 2002:a05:6808:e8b:b0:3d9:da81:6d59 with SMTP id 5614622812f47-3dd2996c508mr2459834b6e.34.1723623291826;
        Wed, 14 Aug 2024 01:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623291; cv=none;
        d=google.com; s=arc-20160816;
        b=N4340MZkjSQXpNA8Ku7iSGDpyLUJWl4eROhiMFxHRjgriXLQnUnYkPcqo6Od2P0ijw
         w3Elr/83viabpV0oOAdgc4Zk6PLMSy894oc34V8PqJfxYqXG8det6w33zyds2p0g2euz
         KtOlLEY3zEu23Xh1DZc94n1GiI1f3AY8uI+c2Q8uwESkupJKOH1SGrt4SEquh0RHjA4e
         twZ1Ckm0eCgsztxbx1lgK+Jv31VdNQb8+XZ58+rXFrDumZvW2Weu3MS0ielUTE0/NcJI
         Go1JVoDvZaT3SZhgaF8BY4YBAjjN0VNhk/zu5Dg4/w50wj3/fpn23zrsRJvZSq4Tx6Gw
         BJzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QdTr6WFexikZD5z5SMB0wNcwIFtpGfuIsUFT4S+mZyo=;
        fh=jX22iCA8Cd+DY3+ewNOTykYqz2mHPeyo+oo+BzBBT6k=;
        b=YHYm5APZRQWwwy+s+uuijPB9flds/C6/Pc43FI+UWjyL0sy9BdVX/bwnUfvly8EEBR
         koHhdAq17lsIKW6Dxubk429ZLo72LAZkPpAkbtKjh1kLJtQ9RTLjohDSNgFpelCq89lE
         W+kuMzMRKbm2g0wQM4ycscysET6X5NbDmDt3USWlQqPoOEebX6lYsgeodsmz7M9YT53v
         rCxWZ7+UVYkaA5KBQzw5GicDI3UiTbRnnmsjcbUSwqvRJR8mAek5ZVWN/hnLv3WSPxBZ
         ZkrWCDZVg4R+eNX3C83xPhrgM2KSmskEBtBrKuAWBVNJuTMWUYuB2SOvga0ux0IP/zj4
         1L0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=D1QOXsmB;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3dd05848a70si355054b6e.0.2024.08.14.01.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-6e7b121be30so4105251a12.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNjafVMnBoQ9nPlllWote3/EE5OdNURWbTGPyHEm1rNAWSCfnBgpHHSdasjM+l6dKSwEu2jbuxOKVTQXDPGrHCEr5iH74fGTaK/w==
X-Received: by 2002:a05:6a20:c78d:b0:1c3:b20e:8bbf with SMTP id adf61e73a8af0-1c8eae813femr2821023637.14.1723623290943;
        Wed, 14 Aug 2024 01:14:50 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:50 -0700 (PDT)
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
Subject: [PATCH v3 07/10] selftests: riscv: Add a pointer masking test
Date: Wed, 14 Aug 2024 01:13:34 -0700
Message-ID: <20240814081437.956855-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=D1QOXsmB;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-8-samuel.holland%40sifive.com.
