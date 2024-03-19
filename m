Return-Path: <kasan-dev+bncBCMIFTP47IJBBQMV5CXQMGQEVVQGF4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id F0C5E880705
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:30 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-60a3bb05c9bsf113082887b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885570; cv=pass;
        d=google.com; s=arc-20160816;
        b=pUUWCDRLoSmMzgWkUSx76AyeXv6E76GZKqxHn3TFyPGSIu5UwljwlkAkl8bnPm4gH2
         4FTfbCJp6dwSLNQ0Bmm4Hw9fSU51hmcMvhfT8hcF4yKNlTvtIKxmF1CcMBofnWpMSsE5
         aSoysDydsQd9XLZBJQytAmTtp1CM9NJI6Mgr2pZAqARtIRm2wAHpE8z1x0zsKnwO+s6i
         Ns9haN2TZSYf3iLPW4ZJNh06LPcqlM+npZpCcOo4JS6TqYQba/42QorqR5JRBhwSuz0f
         uFRpDPsZQflUw3bvVdFEEmPgCl7LjIia02c6i4oWvj73dyjzsYNm/y7yQethRgfEBz5Y
         slGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gBaIVUe26dLw/MdCbkxZDkaSk8Eco7RTehFID5VcFok=;
        fh=p+KZYVfinUfxE5wFjAIJTJ93h/hW/60GtSWg/yozDtQ=;
        b=rGfsPZNjzRUspVHFxYDry8jUQbE2bZu/eGDhZBaH1d5DW+GFVMdC+dBRil+8iE2XCu
         OjfI+E2UgDSN0xpYmlNulEXxjT1A0dbZCqn14xZtXYFGMh147ZD6NQXZD8khhzXFXEwu
         n295D1SvZFvpviksAInwjqy+zJaSsq0X7Qnd1nkvYlcbHLzdv7dXvxZ11m4AynMOxNzd
         xdLSdNhOC//mBZzmCtK2nCA/4LG2hxogHSRoKtv9yI4kMCSRcj2hWTU4eMOXD/QyPFob
         TJKkKSh9Yv3U65KwMD89irKH1qbx1tt3cNahHzJoNsoGD1IYb6XsqvMXqKod+5tA2xtP
         7qTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SVT7t2CS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885570; x=1711490370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gBaIVUe26dLw/MdCbkxZDkaSk8Eco7RTehFID5VcFok=;
        b=rLxq/yclbTxjZxbngKNurBDVcPIXsrH+21GWtz2r0BxyjZjOoX1ou1kN2j4kppgFuk
         kM2SwOIBhLhEcmb34z66N0JnJ7oyTdbet2VTLLRU7qdO7U5V/Uma5uXHvisWm2/ai3Ot
         3dy/Web4ttHj1T2cU8PpOrOz6nqVDAG01KZ7H03l2yvyO3sQCv3odXaHMTX7znPninRh
         q+wkoaaYGWnHEUmyy0U+OImsk1kY6Q94yl0omKrH8zlY2VrjA9QWc8RYmRyTjBbUNYIG
         w6Lm4M6rNNfUu4qTG1uA+4kTg1wDtLHxWR6Q31ZAUiXFGKD4NcTzLNaEMy8PRAr93HA6
         jyyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885570; x=1711490370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gBaIVUe26dLw/MdCbkxZDkaSk8Eco7RTehFID5VcFok=;
        b=sTrBaWitf/Jl2nFhSAk8cTxlew+doYslaRYc7F1aVsGGEQ3j3lxEbbcxbqt0ARpx7F
         VMsEq+F8s15dBDLetxZxL5oun1qIh1Ajqznc/ERQP5t4f6a+GBtZgzMe+ZvZF/CVxWOy
         +pLHIm8iB5IgyuNYhsHyLkh60ayb8Bp6cpLUcuT5gj00y9cPwyleYn9UD/XDwNjF8d3A
         YgIzLdBzZGGenSMwd7tKOtViwLqNpkjNjE2IPgOQVC4ci5VF5QoqLTQg6UamkuYOK02Y
         7PPyDMBWhKP/KeRMYcUjQVMwlPz82VxBLLrxWwItgqSeo+VMdkZjc/tXzbdcWp+/wjfG
         ngjw==
X-Forwarded-Encrypted: i=2; AJvYcCWdn39jVdJ5qsW6rcS6Mw/jd3d5ksueY80CkGz6GJLTnrMsaKnVOWnpKfFxwc0LWeS4SrTzbOop8ZBBAWi3R/zqnNtdHQtMow==
X-Gm-Message-State: AOJu0YwFeEDHRaZZAKvjdLIiD+eAFAHjFsOmoIlA6t1mywA20FFPJGFG
	sc6V4XuoR6V3V5m/HiuABWObH0kP+FcaztK2uSQ9bK44gV7nTdMy
X-Google-Smtp-Source: AGHT+IF/stxgZdVwBOt1SzgzDrKChb1rvSt9OuuU8dc/IwdSEE9L9vK7unjd+EyBQHtlidcd6GDEcg==
X-Received: by 2002:a25:dbca:0:b0:dcc:273e:1613 with SMTP id g193-20020a25dbca000000b00dcc273e1613mr14049011ybf.40.1710885569790;
        Tue, 19 Mar 2024 14:59:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc4e:0:b0:dcc:4059:deae with SMTP id y75-20020a25dc4e000000b00dcc4059deaels602043ybe.2.-pod-prod-01-us;
 Tue, 19 Mar 2024 14:59:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzYGMA4Xia2D8QVW9gevqrq6F0v74WKV+RotQ8wT/nNOJ2dpRagh+0cd++qyInJLKpt9s24xvQZuslA1yFEp/ZzEKPVN52EcHxLw==
X-Received: by 2002:a5b:12:0:b0:dc2:3936:5fa5 with SMTP id a18-20020a5b0012000000b00dc239365fa5mr12834909ybp.51.1710885568786;
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885568; cv=none;
        d=google.com; s=arc-20160816;
        b=G7+0mKlf1lrRKxEeJQalqiFG//BqCJmiPFIcChofyhbfgt8YFA5BgX0oTqwfUrpO5P
         iKDBFw8/mudqaxkckQw9UqubUiLqsgYMM69NFyyVBIDvlGB3GTXhLuQPJl/t4Idhi08p
         PUwLzUg6IkVre3NHBNrvGfWZoe3J0roO1B193X9AUquUGAJAWiu1KgnKsX4CwEcOXl+R
         AfYV77wtToJ3NqgY8paMQA1UTMAXEORbHb7R4M6i0c6iWypx77V8XNJQV9NQMO5XtJ4+
         FUDMmMMRZUEfhKHd48e4+w9Dh2TQaEfbF5Qm4rzkGDaODYxHS8+qnuilk0iB5PJrbkS0
         O9ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Pby1JczWDGJraZTWE5gkOPCKAXwxysMeCn/eal1+wiY=;
        fh=K74A01+6bfdJvBnSNnrZHYYuaobqjJyc/YZVcAxy3AI=;
        b=gRTTPHqHjI/oWyJTRw0LsAzMKI+NMcljPz2JVsaczmNr4IowCLBPIVYCX/Yd1m0sau
         3kOf7rq+9fN6YC4AzMvGfws8dOX1ycXpbI6kpEW8Wn6addBZzqsksTTMsA7556w/Obia
         GsBjropCWXuXswJP0tZYRe3wDlmPIXU0VxrP45Wj9uZmUN8/OlGkx7m6+pbybw2X4C5A
         KwMX9EGtYnaoIKZuRydZrcKWUFec9f9UEW/xcQy8Rv5eoNGuTlL9b7Md9BeTWK0u5nw2
         R/4XhySXkbmBYxvYLifaXIzAGwWPVOSd4ZNzm+niDsSYCn4oK4A6IrSnIAQPihpwmV8F
         FCzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SVT7t2CS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id u36-20020a25ab27000000b00dcd162eec7esi1226014ybi.2.2024.03.19.14.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6e6b54a28ebso5898808b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfhnzkt9ECT3Kuo27/FFJe48i09/yLTZ6T0wCajBqkfeub4N4x2jD7kq+TqWurkRUUpwW12dkO0g9XosuudEP3OMMSkb4Zt53PUg==
X-Received: by 2002:a05:6a20:c91b:b0:1a1:15ff:43b with SMTP id gx27-20020a056a20c91b00b001a115ff043bmr15335731pzb.23.1710885568321;
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:28 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Shuah Khan <shuah@kernel.org>
Subject: [RFC PATCH 9/9] selftests: riscv: Add a pointer masking test
Date: Tue, 19 Mar 2024 14:58:35 -0700
Message-ID: <20240319215915.832127-10-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=SVT7t2CS;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

 tools/testing/selftests/riscv/Makefile        |   2 +-
 tools/testing/selftests/riscv/tags/Makefile   |  10 +
 .../selftests/riscv/tags/pointer_masking.c    | 307 ++++++++++++++++++
 3 files changed, 318 insertions(+), 1 deletion(-)
 create mode 100644 tools/testing/selftests/riscv/tags/Makefile
 create mode 100644 tools/testing/selftests/riscv/tags/pointer_masking.c

diff --git a/tools/testing/selftests/riscv/Makefile b/tools/testing/selftests/riscv/Makefile
index 4a9ff515a3a0..6e7e6621a71a 100644
--- a/tools/testing/selftests/riscv/Makefile
+++ b/tools/testing/selftests/riscv/Makefile
@@ -5,7 +5,7 @@
 ARCH ?= $(shell uname -m 2>/dev/null || echo not)
 
 ifneq (,$(filter $(ARCH),riscv))
-RISCV_SUBTARGETS ?= hwprobe vector mm
+RISCV_SUBTARGETS ?= hwprobe mm tags vector
 else
 RISCV_SUBTARGETS :=
 endif
diff --git a/tools/testing/selftests/riscv/tags/Makefile b/tools/testing/selftests/riscv/tags/Makefile
new file mode 100644
index 000000000000..ed82ff9c664e
--- /dev/null
+++ b/tools/testing/selftests/riscv/tags/Makefile
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
diff --git a/tools/testing/selftests/riscv/tags/pointer_masking.c b/tools/testing/selftests/riscv/tags/pointer_masking.c
new file mode 100644
index 000000000000..c9f66e8436ab
--- /dev/null
+++ b/tools/testing/selftests/riscv/tags/pointer_masking.c
@@ -0,0 +1,307 @@
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
+		if (ret) {
+			ksft_test_result_skip("PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
+			ksft_test_result_skip("PMLEN=%d constraint\n", request);
+			ksft_test_result_skip("PMLEN=%d validity\n", request);
+			continue;
+		}
+
+		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+		ksft_test_result(ret >= 0, "PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
+		if (ret < 0) {
+			ksft_test_result_skip("PMLEN=%d constraint\n", request);
+			ksft_test_result_skip("PMLEN=%d validity\n", request);
+			continue;
+		}
+
+		pmlen = (ret & PR_PMLEN_MASK) >> PR_PMLEN_SHIFT;
+		ksft_test_result(pmlen >= request, "PMLEN=%d constraint\n", request);
+		ksft_test_result(valid_pmlen(pmlen), "PMLEN=%d validity\n", request);
+
+		if (min_pmlen == 0)
+			min_pmlen = pmlen;
+		if (max_pmlen < pmlen)
+			max_pmlen = pmlen;
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
+		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 0,
+				 "dereference after fork\n");
+	} else {
+		static volatile int i;
+		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - min_pmlen);
+
+		exit(*p);
+	}
+
+	if (fork()) {
+		wait(&status);
+		ksft_test_result(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
+				 "dereference after fork+exec\n");
+	} else {
+		execl("/proc/self/exe", "", NULL);
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
+		ret = write(dev_zero, p, sizeof(*p));
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
+		ret = write(dev_zero, p, sizeof(*p));
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
+	ret = write(dev_zero, p, sizeof(*p));
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
+
+	/* Check if this is the child process after execl(). */
+	if (!argv[0][0]) {
+		static volatile int i;
+		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - 7);
+
+		return *p;
+	}
+
+	dev_zero = open("/dev/zero", O_RDWR);
+	if (dev_zero < 0)
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
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-10-samuel.holland%40sifive.com.
