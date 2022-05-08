Return-Path: <kasan-dev+bncBAABBZGZ36JQMGQE6GABC4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE73151EEE4
	for <lists+kasan-dev@lfdr.de>; Sun,  8 May 2022 18:16:37 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id k2-20020a0566022d8200b0065ad142f8c1sf2605459iow.12
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 09:16:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652026596; cv=pass;
        d=google.com; s=arc-20160816;
        b=uOeJ8flzkoNEFugLLiMXN8zglOeUmT0KmgdkGl38gbQ5Vf8rS8WgrOvv/1Jx9cK8Uz
         ZUIKLde0iKZJgnZzjFmEwSWnF/tCzT00MRpg7/vXWv8Hi3wgxc8uvajf15dA6xpxVCpk
         7S2NdwK2MbPzopOnX9FnyCZgrf9mnptuW5L/ryC8xhKwZakLhKfizJpckgreFb1+/jQ1
         3sroAWSGj0oc8i6poa5j44tlqEKe9HivvqshWm9CCzJ98JwaM0w4qKDmGksS3huaQo6r
         zbl4jC2Hf3f2xPlexClRzwNUCKCjhQxAUo+EIMJyGZWBeaTRuqbv3m/KYOkYxGj0nkJb
         YtWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gFNsNgpVtDx18MMqICRFfQJoaFLkxG0ikrZ0BRWs+Mg=;
        b=uvJa+a4Oz40h2I3IZKXKu1B8Z6svIpVQbpZK9WNAYh0MfPHnyrZCZEP3HVLyXbCDB+
         N32BLbZUxlvDTHv79j971xBoCzcrU3QCMV7UlysofRGtMoJRQioqbyfkNSdqfuDQtn22
         XVWcsJze7G/G98VMIIVzdkdOXkPTfWBgzGa+PVJZSvfvLtde55wXY5oSM0EPYXwWk/Oy
         ekV2NnzllM4zz8dbBZJDLXGCa3YSNYcbSYyuv6A83dP3+rpMqbcqHDcadGIE0XWGOHJZ
         gh3qwXPfIkq1lvrn/0azbkxXKqhm3RUFNTBUcFMMzaG3q+tUbuSpSPyR023g8cSyC7z7
         kOyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bkxkj8L1;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gFNsNgpVtDx18MMqICRFfQJoaFLkxG0ikrZ0BRWs+Mg=;
        b=CE3TbfNiRvcp7LB6tEpWWjGiWBVCVEaDhxqkQGG9oOGUEwZ+vp0ybNqM2hgjEZI+cX
         JYvPFvsdczeiyT3cDlSpFFiuMbK2psfV3vOvAeTztCfRIGXWtpj1lFzEFwh62yp5F0Rm
         0ypxlw1pBdkkZy1U8IZ5qHp7tYyppTbwJUqlxX0zxpkVlXPrgL7d8ZzQkRbp3dGRDmRI
         NRivHQiUlzYSY8ckzpn9nMeKwDwpzgKFgbENSR9OLIMqyxssfCyp7/tvKB9QtrGl9R3a
         eqY7BOp5u8Q+OeANt22xyYKr4MBZM6KSN8zdBwJsgmC7px2VzRdyZz1DKTfP8LcQcR1Z
         OMkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gFNsNgpVtDx18MMqICRFfQJoaFLkxG0ikrZ0BRWs+Mg=;
        b=ks8ptDgfoecvWGn5Kw14p7z0nrunmS+0RjBJ2te4sViuGWZYERc+ZOLv/5Ejdbze80
         IZGVm8C/swb9cJAs9C/y8ilJXNLTrIftUVcou3MhwzSWZ6H12wjZX7Qcat44BWEJEi3N
         kj6H6uNbTVHRFwALQyLS+0tbDXv9ejhrw7jhFNXoyvK3TB6XfTmvD/33AuTS1H1VSPph
         tmhMas1dDW69RHfmL4ZocVcgtk40z/1+EvwZde2ibsh+NuhwZvzuJeOMWJYYMG+kP6nm
         IXfKIMYbpQxJjyQeC8Iy9Qe7pZ4XcTFOIuU5Trzwo6iiKzK/LUny7jL0VxkPTR0lL8Jx
         JLDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NdVFfc9695WAHihKdd6A6DRx0KW7JCBqzeh0jCerjuOVSahjH
	Ai2h3eLCSnhhKZ3edAHkVuQ=
X-Google-Smtp-Source: ABdhPJwl25F77uV94iAbNzulAxNRkD69gCIxs7x+UzApO1cX0oYwOlVVsqCRBR1WZXQNT/PSIYLkVQ==
X-Received: by 2002:a05:6638:1446:b0:32b:75b9:7ff8 with SMTP id l6-20020a056638144600b0032b75b97ff8mr5505344jad.242.1652026596643;
        Sun, 08 May 2022 09:16:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2b8a:b0:645:b6c7:1c9c with SMTP id
 r10-20020a0566022b8a00b00645b6c71c9cls1325438iov.4.gmail; Sun, 08 May 2022
 09:16:36 -0700 (PDT)
X-Received: by 2002:a6b:2a88:0:b0:65a:4e0e:7f35 with SMTP id q130-20020a6b2a88000000b0065a4e0e7f35mr4637986ioq.216.1652026596314;
        Sun, 08 May 2022 09:16:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652026596; cv=none;
        d=google.com; s=arc-20160816;
        b=Um3xktrJ3MkLNGtiFMtM9H+mJxuc5dZ6wOjVe2b4EA4RRmGdqSetVEQgoi83gLeheu
         XUISbpZDVdJt78rdBXNeZntiDThbAcRA+eNjaM+I+zgVmaE4hUSZ9Ou7OQkFmx0Lis1y
         VFtgu3Sma6Vew8Ke2TGGL8nB/wP926USic2UrIMbMO4zsKZA0Fmkl9M9imv4OHSylZIc
         hS3aiakECooi0F6p/YwusqQ3ffkxSck4HmfuSfBCAGK+iIi9B84BWa4SmzxDrBs1xw02
         v55NR6KtuAG7TMjwRX52dQRNiQVftbNZnv/u2NuUZCAijjTDkCfgq6d4f1QUDJzCxs6/
         ibQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kWiAzL1XgB8kEqmHEgehjoPHHFRxXOEWNZk0fRIUWmw=;
        b=zIHFgUt3LB514xu0Rb1610GwuiIwo/HIrIidH6BLpJ0/Au6BiYdVFlAzH7urwhis3E
         k0hf/A0eQ4k3743buh7pzQWJZ5J52SnOCXtPHBTWo/J8Z+QD+ZTy12jXzviV2ig5CNWu
         LYN4PM6QhS66uc8OR2pit2u0L0aYAyJ731OwjbkSjhghR49Zb/KrK7GZDhNZlxsljQzV
         VDTEEDdeqyqu3b3MoJG2WX6ZYlh5EtqTdcWnTe/xqEyQhZMhPlfRr2K9XfEcL3H3Kb43
         dvyK3hFn92ZC5hMG2v1BFd4D69fWjukM8wTFBoGfr03aCXc4urmsXKOZeGZXXU/72jEe
         2+sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bkxkj8L1;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n13-20020a056638210d00b0032b64ddde01si1124314jaj.3.2022.05.08.09.16.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 May 2022 09:16:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EFA5C6121C;
	Sun,  8 May 2022 16:16:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1CDC1C385C0;
	Sun,  8 May 2022 16:16:30 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 2/4] riscv: introduce unified static key mechanism for CPU features
Date: Mon,  9 May 2022 00:07:47 +0800
Message-Id: <20220508160749.984-3-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220508160749.984-1-jszhang@kernel.org>
References: <20220508160749.984-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Bkxkj8L1;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
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
index 7d81102cffd4..f4df67369d84 100644
--- a/arch/riscv/Makefile
+++ b/arch/riscv/Makefile
@@ -154,3 +154,6 @@ PHONY += rv64_randconfig
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
index 1b2d42d7f589..e6c72cad0c1c 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -9,6 +9,7 @@
 #include <linux/bitmap.h>
 #include <linux/ctype.h>
 #include <linux/of.h>
+#include <asm/cpufeature.h>
 #include <asm/processor.h>
 #include <asm/hwcap.h>
 #include <asm/smp.h>
@@ -25,6 +26,15 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
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
@@ -62,6 +72,17 @@ bool __riscv_isa_extension_available(const unsigned long *isa_bitmap, int bit)
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
@@ -236,4 +257,6 @@ void __init riscv_fill_hwcap(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220508160749.984-3-jszhang%40kernel.org.
