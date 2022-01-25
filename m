Return-Path: <kasan-dev+bncBAABBKGYYCHQMGQEZ3HTXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0192249B961
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 17:58:17 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id a11-20020adffb8b000000b001a0b0f4afe9sf3325914wrr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 08:58:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643129896; cv=pass;
        d=google.com; s=arc-20160816;
        b=wygZiogvsvEo7nQldblIEUHrbN3FACYrODigo7j06bDr74mYdeNTeJ+DXquJkS0cQu
         yUQ/cxcfe5MsV5HVmujMUN8/Ri5Ha5J+bnIVAzlD2pyXxy3iPU7Ie2anLS+GIPlewmOi
         1nX4vNgIVvt4/NOQGpkQuiK3j6oV2lV782nLwUR+zSvtD3PgO5Zy6CJIIAIlpPCdeNzb
         hgQ8bS4Rv87Zbg45/OKTa88izXJtD1nMbguUC2UDOLGwTEBGoZhbbxaq0gRQnNpkf2tb
         7+65PtxX4lxuYq6S2tqK0q70w/DFB5UOZH9lUNsTsUmxd6ANRpb4OAThrwlvOzclql2j
         wdzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h7nKF2SGTZP1fgQhJlKuyU3xfiAAdMnEGuTR1oH6LFo=;
        b=FSWv/DzlqKP1LZ9tOSMfLu8B8XpO7opE9kThqpABDCU92X8Vytivg7kp/78QuFJGPF
         Qjsb5LL0taiH0blY1aoO4nhjhl+jXF66ISfle/r72jLi4wLHTi/5uUrlhjqvbttd3lDK
         gmimCSdwp/XX0aLOAaJwkPfTE+YAR+dZPzYjk3RXPxjdFm0855NRJ7Pji3vk5mM12F12
         lCBr5iWTnr9TZPlyuA+zZV7immHzGMgiMDPEBaDN1KoRPkVSrsPQtIPZdME3L9z4LV+x
         FkrImEOLkop/JIEoTULhdT0oVPra9kX0e3eHgCT/i60lP25TMEXIWw+7KROwleEBgYym
         Gieg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fNch9TQE;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h7nKF2SGTZP1fgQhJlKuyU3xfiAAdMnEGuTR1oH6LFo=;
        b=C23Qx8hF01K6svmWa41dPwPTamN+8Lp6b+LnL97xd8dibq47C8AuSOTHo4NaUXB5LZ
         1PQR9ZzlT7PL299SjUOrwYD5ZS6NOGT4Jqeiu4g1Lzvy+gTox8AHiApErAu9utIxDFDG
         jexltaV05Uk56zhtl/y1kp3bjU5HcIuFWkviWDDjQxhfR+PopKnX0gQKS0q3bOWazmZx
         qCEdz9/9gqygrt8DeS6EJHkHgztC72tiErJgUn6piaeGvHnCDy/Z9zKfjE9fEW0nn9NK
         q7z+h5IHbZzXMM88LeFRMKwdngbhoWXjoiaCOSZylyhFYAnnJGjIATONRk4vRgQOFvYO
         S+WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h7nKF2SGTZP1fgQhJlKuyU3xfiAAdMnEGuTR1oH6LFo=;
        b=n/wC/5nqs13kQuEuK3B3JgGM6MUlInJr4GaBkjp2d6KcuhvW0hMtJQCap9WpjGzG3w
         BpRDroNdBbs2bkuNKwzmX+qtZ/VcKYyYkm+Ut0u1x4W+hIbWFv20ClpOQi39wKk1HUrE
         Q9Vqp5/KiLMjEch6ppLcByYs75u2u2UoNOjP9zhpKR6UPSZWcbv2PVukQB1H+InQzcfG
         YEU9l/x5ByZxWA5SwbiJty8GAubW20d50araqDrDNBHShVIRDONmyxk+y6bjHq2OW+I5
         Py2eEggvx1pxapEjDiNBypDPcnx1u+iH0lryhWLa48nZHydKiQpPi92rTzwT7ylyphoz
         8axQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+BikU9PPWt8i0o1/9n+1MLpQfhyCJRAq3MkzLcd8qe2mSBYX5
	rc1pvKu3e7TlPwd9U0Cximg=
X-Google-Smtp-Source: ABdhPJyNy8pzEIM+clFlx1l+kcp2aYB/+6Orsu+ca4a0KfxIlVLgxI+mWn2tS+kbOUOGi7MH34gC9A==
X-Received: by 2002:adf:f7cd:: with SMTP id a13mr3822390wrq.517.1643129896555;
        Tue, 25 Jan 2022 08:58:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6013:: with SMTP id az19ls16099wmb.3.canary-gmail;
 Tue, 25 Jan 2022 08:58:15 -0800 (PST)
X-Received: by 2002:a05:600c:24d3:: with SMTP id 19mr3819111wmu.178.1643129895855;
        Tue, 25 Jan 2022 08:58:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643129895; cv=none;
        d=google.com; s=arc-20160816;
        b=eiY0l3yywjU9Lqk3Irwkw6PFVrygqZ2ApblYBvDtWHw703fxYHQNX+rIVzL1oAcJJV
         2WUdMSKA09FcMLplunVQa3+sAakodIMnjrCimFQezwJWZIBhIRtAKqw4LCGjNHDSWPpX
         3LA2BbAS1xL3UtxHtm9rLOGjHmo85GgUGnyPqQ3189xMZVTj59LevWolGGKf1PXt/K7p
         1kMUeMJSI29ypxS/DE4RjAcz2cd/nMl7hwOlicNVfkZBpJTyERqDrjPn7DSXXGGIuZ6H
         tPwiaZK8aYsKwWVcsm+KzTpWo4LyrTgQllYst6o57kJ8XiSZixmb39nTH4L4X1aRp8/n
         dfPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WLg2BeBvW/j0sV2P8p2IWf4T8GWUW5KyuZAg98ro1Fs=;
        b=YwXQl8EQVi8dEwqja6NFUx9BmDGiGNCJiasYfTgQdBB3bcU2uIEcENUy4i0FjU7ceq
         A3SDzSc8q4oHzdiKS7m1gC398GLHdZc4BfKxlS3K59BtOXodgntyCHRJBQfHTCMrqdGB
         6vw+RIZ3Qxrnt9Eb+JdpsWPGgN733WJYw9ssPMknhlNAf8bskLKu2jWgUyQmflW+YNdC
         2AIrYj5bi2tHXGYAC5R8HA20c2sKzVXMdQ3PmTxoEkWlJWBNrm55lyPr80kW6YQrQhX8
         5P95UHNBoRBgYDm88m8eAX6MAAr20GrtMk1nT0JDC1ZOvETbyt4dc7wBEP9mKCcabNX7
         DNdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fNch9TQE;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id l24si220069wmg.1.2022.01.25.08.58.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jan 2022 08:58:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5A4D1B81912;
	Tue, 25 Jan 2022 16:58:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 942B9C340E0;
	Tue, 25 Jan 2022 16:58:11 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 1/3] riscv: introduce unified static key mechanism for CPU features
Date: Wed, 26 Jan 2022 00:50:34 +0800
Message-Id: <20220125165036.987-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220125165036.987-1-jszhang@kernel.org>
References: <20220125165036.987-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fNch9TQE;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Currently, riscv has several features why may not be supported on all
riscv platforms, for example, FPU, SV48 and so on. To support unified
kernel Image style, we need to check whether the feature is suportted
or not. If the check sits at hot code path, then performance will be
impacted a lot. static key can be used to solve the issue. In the past
FPU support has been converted to use static key mechanism. I believe
we will have similar cases in the future.

Similar as arm64 does(in fact, some code is borrowed from arm64), this
patch tries to add an unified mechanism to use static keys for all
the cpu features by implementing an array of default-false static keys
and enabling them when detected. The cpus_have_*_cap() check uses the
static keys if riscv_const_caps_ready is finalized, otherwise the
compiler generates the bitmap test.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/Makefile                 |  3 +
 arch/riscv/include/asm/cpufeature.h | 94 +++++++++++++++++++++++++++++
 arch/riscv/kernel/cpufeature.c      | 23 +++++++
 arch/riscv/tools/Makefile           | 22 +++++++
 arch/riscv/tools/cpucaps            |  5 ++
 arch/riscv/tools/gen-cpucaps.awk    | 40 ++++++++++++
 6 files changed, 187 insertions(+)
 create mode 100644 arch/riscv/include/asm/cpufeature.h
 create mode 100644 arch/riscv/tools/Makefile
 create mode 100644 arch/riscv/tools/cpucaps
 create mode 100755 arch/riscv/tools/gen-cpucaps.awk

diff --git a/arch/riscv/Makefile b/arch/riscv/Makefile
index 8a107ed18b0d..65c63023c8a8 100644
--- a/arch/riscv/Makefile
+++ b/arch/riscv/Makefile
@@ -148,3 +148,6 @@ PHONY += rv64_randconfig
 rv64_randconfig:
 	$(Q)$(MAKE) KCONFIG_ALLCONFIG=$(srctree)/arch/riscv/configs/64-bit.config \
 		-f $(srctree)/Makefile randconfig
+
+archprepare:
+	$(Q)$(MAKE) $(build)=arch/riscv/tools kapi
diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
new file mode 100644
index 000000000000..d80ddd2f3b49
--- /dev/null
+++ b/arch/riscv/include/asm/cpufeature.h
@@ -0,0 +1,94 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
+ * Copyright (C) 2022 Jisheng Zhang <jszhang@kernel.org>
+ */
+
+#ifndef __ASM_CPUFEATURE_H
+#define __ASM_CPUFEATURE_H
+
+#include <asm/cpucaps.h>
+
+#include <linux/bug.h>
+#include <linux/jump_label.h>
+#include <linux/kernel.h>
+
+extern DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
+extern struct static_key_false cpu_hwcap_keys[RISCV_NCAPS];
+extern struct static_key_false riscv_const_caps_ready;
+
+static __always_inline bool system_capabilities_finalized(void)
+{
+	return static_branch_likely(&riscv_const_caps_ready);
+}
+
+/*
+ * Test for a capability with a runtime check.
+ *
+ * Before the capability is detected, this returns false.
+ */
+static inline bool cpus_have_cap(unsigned int num)
+{
+	if (num >= RISCV_NCAPS)
+		return false;
+	return test_bit(num, cpu_hwcaps);
+}
+
+/*
+ * Test for a capability without a runtime check.
+ *
+ * Before capabilities are finalized, this returns false.
+ * After capabilities are finalized, this is patched to avoid a runtime check.
+ *
+ * @num must be a compile-time constant.
+ */
+static __always_inline bool __cpus_have_const_cap(int num)
+{
+	if (num >= RISCV_NCAPS)
+		return false;
+	return static_branch_unlikely(&cpu_hwcap_keys[num]);
+}
+
+/*
+ * Test for a capability without a runtime check.
+ *
+ * Before capabilities are finalized, this will BUG().
+ * After capabilities are finalized, this is patched to avoid a runtime check.
+ *
+ * @num must be a compile-time constant.
+ */
+static __always_inline bool cpus_have_final_cap(int num)
+{
+	if (system_capabilities_finalized())
+		return __cpus_have_const_cap(num);
+	else
+		BUG();
+}
+
+/*
+ * Test for a capability, possibly with a runtime check.
+ *
+ * Before capabilities are finalized, this behaves as cpus_have_cap().
+ * After capabilities are finalized, this is patched to avoid a runtime check.
+ *
+ * @num must be a compile-time constant.
+ */
+static __always_inline bool cpus_have_const_cap(int num)
+{
+	if (system_capabilities_finalized())
+		return __cpus_have_const_cap(num);
+	else
+		return cpus_have_cap(num);
+}
+
+static inline void cpus_set_cap(unsigned int num)
+{
+	if (num >= RISCV_NCAPS) {
+		pr_warn("Attempt to set an illegal CPU capability (%d >= %d)\n",
+			num, RISCV_NCAPS);
+	} else {
+		__set_bit(num, cpu_hwcaps);
+	}
+}
+
+#endif
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index d959d207a40d..09331abfa70c 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -8,6 +8,7 @@
 
 #include <linux/bitmap.h>
 #include <linux/of.h>
+#include <asm/cpufeature.h>
 #include <asm/processor.h>
 #include <asm/hwcap.h>
 #include <asm/smp.h>
@@ -22,6 +23,15 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
 __ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
 #endif
 
+DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
+EXPORT_SYMBOL(cpu_hwcaps);
+
+DEFINE_STATIC_KEY_ARRAY_FALSE(cpu_hwcap_keys, RISCV_NCAPS);
+EXPORT_SYMBOL(cpu_hwcap_keys);
+
+DEFINE_STATIC_KEY_FALSE(riscv_const_caps_ready);
+EXPORT_SYMBOL(riscv_const_caps_ready);
+
 /**
  * riscv_isa_extension_base() - Get base extension word
  *
@@ -59,6 +69,17 @@ bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
 }
 EXPORT_SYMBOL_GPL(__riscv_isa_extension_available);
 
+static void __init enable_cpu_capabilities(void)
+{
+	int i;
+
+	for (i = 0; i < RISCV_NCAPS; i++) {
+		if (!cpus_have_cap(i))
+			continue;
+		static_branch_enable(&cpu_hwcap_keys[i]);
+	}
+}
+
 void __init riscv_fill_hwcap(void)
 {
 	struct device_node *node;
@@ -148,4 +169,6 @@ void __init riscv_fill_hwcap(void)
 	if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
 		static_branch_enable(&cpu_hwcap_fpu);
 #endif
+	enable_cpu_capabilities();
+	static_branch_enable(&riscv_const_caps_ready);
 }
diff --git a/arch/riscv/tools/Makefile b/arch/riscv/tools/Makefile
new file mode 100644
index 000000000000..932b4fe5c768
--- /dev/null
+++ b/arch/riscv/tools/Makefile
@@ -0,0 +1,22 @@
+# SPDX-License-Identifier: GPL-2.0
+
+gen := arch/$(ARCH)/include/generated
+kapi := $(gen)/asm
+
+kapi-hdrs-y := $(kapi)/cpucaps.h
+
+targets += $(addprefix ../../../,$(gen-y) $(kapi-hdrs-y))
+
+PHONY += kapi
+
+kapi:   $(kapi-hdrs-y) $(gen-y)
+
+# Create output directory if not already present
+_dummy := $(shell [ -d '$(kapi)' ] || mkdir -p '$(kapi)')
+
+quiet_cmd_gen_cpucaps = GEN     $@
+      cmd_gen_cpucaps = mkdir -p $(dir $@) && \
+                     $(AWK) -f $(filter-out $(PHONY),$^) > $@
+
+$(kapi)/cpucaps.h: $(src)/gen-cpucaps.awk $(src)/cpucaps FORCE
+	$(call if_changed,gen_cpucaps)
diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
new file mode 100644
index 000000000000..cb1ff2747859
--- /dev/null
+++ b/arch/riscv/tools/cpucaps
@@ -0,0 +1,5 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# Internal CPU capabilities constants, keep this list sorted
+
+HAS_NO_FPU
diff --git a/arch/riscv/tools/gen-cpucaps.awk b/arch/riscv/tools/gen-cpucaps.awk
new file mode 100755
index 000000000000..52a1e1b064ad
--- /dev/null
+++ b/arch/riscv/tools/gen-cpucaps.awk
@@ -0,0 +1,40 @@
+#!/bin/awk -f
+# SPDX-License-Identifier: GPL-2.0
+# gen-cpucaps.awk: riscv cpucaps header generator
+#
+# Usage: awk -f gen-cpucaps.awk cpucaps.txt
+
+# Log an error and terminate
+function fatal(msg) {
+	print "Error at line " NR ": " msg > "/dev/stderr"
+	exit 1
+}
+
+# skip blank lines and comment lines
+/^$/ { next }
+/^#/ { next }
+
+BEGIN {
+	print "#ifndef __ASM_CPUCAPS_H"
+	print "#define __ASM_CPUCAPS_H"
+	print ""
+	print "/* Generated file - do not edit */"
+	cap_num = 0
+	print ""
+}
+
+/^[vA-Z0-9_]+$/ {
+	printf("#define RISCV_%-30s\t%d\n", $0, cap_num++)
+	next
+}
+
+END {
+	printf("#define RISCV_NCAPS\t\t\t\t%d\n", cap_num)
+	print ""
+	print "#endif /* __ASM_CPUCAPS_H */"
+}
+
+# Any lines not handled by previous rules are unexpected
+{
+	fatal("unhandled statement")
+}
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220125165036.987-2-jszhang%40kernel.org.
