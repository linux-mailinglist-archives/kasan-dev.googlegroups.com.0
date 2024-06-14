Return-Path: <kasan-dev+bncBCWPLY7W6EARBAP5V2ZQMGQEBIWMQ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DD3839082B4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:34 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5bb0d301d1dsf1057665eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337153; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wez3bQRVIvb+fVe0dtkCNjTD8jU9bycxvYACXDs1eyCZUT1BRCsbCDdHs3zKYQZNBl
         1QGiAL5DOmOtbvyYK7iyOr8Jq7tda6TRBn9oOeRWp+YVgLuoYnVplZv3TrauhucUkYhH
         DKgrYa+y1o5QLjBxP0TTQMDl7mXifGrzHA/taaLy1Y8yLtrOxqwcfUff4NB6tId45OMe
         /zNIPg1eKBJdW8aGFloGrBkoauuhsMNPaxef67uJOrn6GQVNcE0wWirCA6Yal0t4+ZUS
         AVzu1OC2lXsoAD0qi5LZcAHaf2Sm0CMLhYaKywIwedGeKHAzi+kVz/21NO+LJO41oZ/l
         7c+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=LeTx/98yJnkQ0BYC3i1eZVMDvvJRrpL6OKyqaZdmrP8=;
        fh=l4SVAHHG254S3YlNltFBKwoiGf/PeREddIuQ+h5lr3Y=;
        b=AeJ756I1YdQ4pEITYE57V0KgOGbFldlHfadjUrMrdtXlpsMdB6S2HH685r9ZmFqaJ1
         s54JtjK2o0OCOoKFxoY6vC8152p/NTg5IsBSgW5nwZD1r5ZdUzmvFG8enm98MRsgcO9W
         xto/DKkKSJzv/xARHUedJiswFW2rkTV3ch9Uit/BOqCse6ZKibh5QaPryyJlGgFUP9HY
         PpefJE7Ni7NCiho/M3HptcvsYoVN8jpi3O/sw6OjpHHlCs9aBkWyKeJ9pVpvEV/hnrsj
         h94xE8sA8RTtq7+qK94a7H5/Q7ys1+BlzHwlE8k093LKLtv87StY1hlSu42fqG8uRVMB
         zFLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337153; x=1718941953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LeTx/98yJnkQ0BYC3i1eZVMDvvJRrpL6OKyqaZdmrP8=;
        b=WBBcHTClpW38cH25lmAMnVMYx3GvxbrhwijA0osNTwP347u22SUgaNq845BJ5AobFh
         KfBw0rfammtOixdwjDLxaCPFwWtM4z5U5OzW7ZqPOK/ODB1MNYCCaUup8Dl4pjnH61Lz
         p6YcrzsgQrILvxsXXTlwUKeL+ESYAESabzxaQwsHX63xQVVRuHf2rwrL5ytABmvVBOqN
         HAyCYsaOoBG1QIV+kzio0bSLKUCRAKpyWJZedWMPExQSnuoVSRrTY9k2MdOH6jGSMNSu
         G7QjoZLdG+x80jgDWbUSzi6eo657Vn7ROOOMWM3EvYH2eYpsBjU9LAsuVEsvGxrcvleL
         2Wrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337153; x=1718941953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LeTx/98yJnkQ0BYC3i1eZVMDvvJRrpL6OKyqaZdmrP8=;
        b=GJ0FWs3g1B8uong705WW2KKTVKmYki5CeuakgjNZmWwdwZi4tP0ckEfb0JC/E/6ZAk
         FOtN1dQwIkaATm2wKeq3jle+NZHHLckScLwb1nSVzQxgfdLH75Um23an7kLsiETAEqEh
         5xyH6zK0hfYwLmBhw7ApHA+n5aLCg0n8xGw9EEdkKMTqkqRE+gi1qHViAmCOt993OVDr
         AMRZTx7a2iuxbgntGXRoyWxk82tNrdhJsnwYKLcrtgQZYW5Bg9cvA/L5GmCEOCLBFQQr
         G0F7ZiOeFTGshUvsr1jb2Y2MDS9ftsUsiV6r9tZ/UJ4X0g5y1wogoeA08qnHarzHXFji
         VTow==
X-Forwarded-Encrypted: i=2; AJvYcCVSOcn+wuVSJnfZ5gm33VQjnBXzJSOpnN6bloBsraMKok9cn9ja1mW1E/MGEuC9tx96QlVbs9lXROWyC9S+3PUTq8zIp8DUzQ==
X-Gm-Message-State: AOJu0YzX4uLGsDhXPlX/7Sy+zRSU0QRiEWtrt7dgpos22IOACa97T3RH
	9elCrD7jtPSlrOxf63JDUcLYqubbqath0ohAQTvSq1x1Rz1wZg3w
X-Google-Smtp-Source: AGHT+IEojIAtS35KT6M051lW7a9zTDQJDga4fhF4pHpsa7gR3LC/CK+scRXaOy4euMrMGttwUQLn5A==
X-Received: by 2002:a05:6820:554:b0:5ba:ea6f:acb8 with SMTP id 006d021491bc7-5bdadbdecefmr1588184eaf.3.1718337153581;
        Thu, 13 Jun 2024 20:52:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af0a:0:b0:5b9:8998:877 with SMTP id 006d021491bc7-5bcbd932cc6ls1367958eaf.0.-pod-prod-05-us;
 Thu, 13 Jun 2024 20:52:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8DrWErtRfYWN9u4ts98DLsKpiCXqFPCwiNA/W/URi+guHlU1ypt9OOp8QBUhRUoIfWwHf4BKmkbV5GtSyIuye8N+ccgrwm0kmFQ==
X-Received: by 2002:a05:6808:f11:b0:3d2:4f9f:f5c5 with SMTP id 5614622812f47-3d24f9ffcfbmr1392195b6e.59.1718337152727;
        Thu, 13 Jun 2024 20:52:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337152; cv=none;
        d=google.com; s=arc-20160816;
        b=QE54jvth6mulmovJggXLuWvZo9a4o4T34xf8RUVsMgqnwhitwyaP0+P12j1afwlPHZ
         GuPbSmDvje+wyTdTQbAGV1kBdyB8DjA7Y8nfc1SEriuvTOP+ft9a+bq04kaZnGPrUyLt
         x/NGnaGvcZu/fNZjRxl8JPfj30vE4zcCP3qNIdpx22EvdDWwitjVayaxEgJW0rZ5RxGB
         GlvMEsCRqaywlFi32IcuxX4QMXFl+p/5wy6GNSMbPs6mI0rbMCGdoBbXi0ZOMDBY+KIV
         EAMnwjgg+XkAHstzpAkZwH6PgjpnlY7N1VyoO2R2xlIcazt3jO1xT4JJ0Eyqx12fRVak
         Hmbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Zesixi9ZBxf/YEktDpgL2Jgp4IC089EyLeF20MNZD6I=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=p8Te92yKAIZID2uvEN3gHi9OfpQe2Bm6AhnLK8HBQuzPL+waXMrDIbFRX8nAkkMdLM
         DJYs9qwSu+7EatXcF/1wqAzUuiC9SJ4NbWvBNwAZkQnpJB59Umt5AeDm0U3917fiXlYi
         BeeUvkiQElpk5dg9GSXvrKweqBUCIQGtU6y9K4W0dkK+lSNRflxjqfMkD/cbQhoa5zxK
         kD8tBJ/Nl17/6JY1KEBASIg/T5oIlWTXXaYajds/sFyUgBK0pug6YWj5SB7fPUTIJbWE
         juKJyRA1yzcPSLQItUQ2hq9tN+Cyuit6kt8tJ35PbMbOUHyUJTBKzY4PBzfhvPp2RPgD
         VEVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247740eb2si130959b6e.3.2024.06.13.20.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.163.48])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4W0lcR4k4czxRVm;
	Fri, 14 Jun 2024 11:48:23 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id EABD9180060;
	Fri, 14 Jun 2024 11:52:29 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:27 +0800
From: "'Liao Chang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>, <maz@kernel.org>, <oliver.upton@linux.dev>,
	<james.morse@arm.com>, <suzuki.poulose@arm.com>, <yuzenghui@huawei.com>,
	<mark.rutland@arm.com>, <lpieralisi@kernel.org>, <tglx@linutronix.de>,
	<ardb@kernel.org>, <broonie@kernel.org>, <liaochang1@huawei.com>,
	<steven.price@arm.com>, <ryan.roberts@arm.com>, <pcc@google.com>,
	<anshuman.khandual@arm.com>, <eric.auger@redhat.com>,
	<miguel.luis@oracle.com>, <shiqiliu@hust.edu.cn>, <quic_jiles@quicinc.com>,
	<rafael@kernel.org>, <sudeep.holla@arm.com>, <dwmw@amazon.co.uk>,
	<joey.gouly@arm.com>, <jeremy.linton@arm.com>, <robh@kernel.org>,
	<scott@os.amperecomputing.com>, <songshuaishuai@tinylab.org>,
	<swboyd@chromium.org>, <dianders@chromium.org>,
	<shijie@os.amperecomputing.com>, <bhe@redhat.com>,
	<akpm@linux-foundation.org>, <rppt@kernel.org>, <mhiramat@kernel.org>,
	<mcgrof@kernel.org>, <rmk+kernel@armlinux.org.uk>,
	<Jonathan.Cameron@huawei.com>, <takakura@valinux.co.jp>,
	<sumit.garg@linaro.org>, <frederic@kernel.org>, <tabba@google.com>,
	<kristina.martsenko@arm.com>, <ruanjinjie@huawei.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <kvmarm@lists.linux.dev>
Subject: [PATCH v4 04/10] arm64: daifflags: Introduce logical interrupt masking
Date: Fri, 14 Jun 2024 03:44:27 +0000
Message-ID: <20240614034433.602622-5-liaochang1@huawei.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240614034433.602622-1-liaochang1@huawei.com>
References: <20240614034433.602622-1-liaochang1@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.174.28]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemd200013.china.huawei.com (7.221.188.133)
X-Original-Sender: liaochang1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liaochang1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Liao Chang <liaochang1@huawei.com>
Reply-To: Liao Chang <liaochang1@huawei.com>
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

Motivation
----------

This patch introduces a series of functions for managing interrupt
masking on ARM64, adopting a "logical" approach. This approach builds
upon the suggestion made by Mark Rutland in th FEAT_NMI patchset [1] to
refactor DAIF management.

Implementation
--------------

- A new union data type is defined to represent the combined interrupt
  masking context, includes ICC_PMR, PSTATE.DAIF and PSTATE.ALLINT.

- New helper functions offer a similar interface (starting with
  "local_allint_") to their existing couterparts (starting with
  "local_daif_"), ensuing compatibility with existing code.

- For platform or kernel that does not support FEAT_NMI, this patch uses
  local_allint_save_flags() to determine NMI masking behavior instead of
  relying on the PSTATE.A field which is not a straightforward way to
  understand and maintain for kernel with PSEUDO_NMI enabled.

Benefits
--------

This patch introduces a robust approach for managing interrupt context,
it removes the need to explicitly check the PSTATE.A field to determine
NMIs masking status. Additionally, the new series of interrupt context
save/restore/mask/inherit functions uses names that reflect their
purpose directly, ensuring consistent behavior regardless of platform
support for FEAT_NMI or PSEUDO_NMI.

[1] https://lore.kernel.org/linux-arm-kernel/Y4sH5qX5bK9xfEBp@lpieralisi/

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/daifflags.h   | 243 +++++++++++++++++++++++++++
 arch/arm64/include/uapi/asm/ptrace.h |   1 +
 2 files changed, 244 insertions(+)

diff --git a/arch/arm64/include/asm/daifflags.h b/arch/arm64/include/asm/daifflags.h
index 55f57dfa8e2f..5d502cc0dac2 100644
--- a/arch/arm64/include/asm/daifflags.h
+++ b/arch/arm64/include/asm/daifflags.h
@@ -141,4 +141,247 @@ static inline void local_daif_inherit(struct pt_regs *regs)
 	 */
 	write_sysreg(flags, daif);
 }
+
+/*
+ * For Arm64 processor support Armv8.8 or later, kernel supports three types
+ * of irqflags, they used for corresponding configuration depicted as below:
+ *
+ * 1. When CONFIG_ARM64_PSEUDO_NMI and CONFIG_ARM64_NMI are not 'y', kernel
+ *    does not support handling NMI.
+ *
+ * 2. When CONFIG_ARM64_PSEUDO_NMI=y and irqchip.gicv3_pseudo_nmi=1, kernel
+ *    makes use of the CPU Interface PMR and GIC priority feature to support
+ *    handling NMI.
+ *
+ * 3. When CONFIG_ARM64_NMI=y and irqchip.gicv3_pseudo_nmi is not enabled,
+ *    kernel makes use of the FEAT_NMI extension added since Armv8.8 to
+ *    support handling NMI.
+ *
+ * The table below depicts the relationship between fields in struct
+ * arch_irqflags and corresponding interrupt masking behavior reflected in
+ * hardware registers.
+ *
+ * Legend:
+ *  IRQ = IRQ and FIQ.
+ *  NMI = PSEUDO_NMI or IRQ with superpriority for ARMv8.8.
+ *    M = Interrupt is masked.
+ *    U = Interrupt is unmasked.
+ *    * = Non relevant.
+ *
+ * IRQ | NMI | SError | ICC_PMR_EL1                       | PSR.DAIF | PSR.ALLINT
+ * ------------------------------------------------------------------------------
+ *  U  |  U  |   *    | GIC_PRIO_IRQON                    | 0b **00  | 0b 0
+ * ------------------------------------------------------------------------------
+ *  M  |  U  |   *    | GIC_PRIO_IRQOFF                   | 0b **00  | 0b 0
+ * ------------------------------------------------------------------------------
+ *  M  |  M  |   *    | (GIC_PRIO_IRQON | GIC_PRIO_I_SET) | 0b **11  | 0b 1
+ * ------------------------------------------------------------------------------
+ *  M  |  M  |   M    | (GIC_PRIO_IRQON | GIC_PRIO_I_SET) | 0b *111  | 0b 1
+ */
+union arch_irqflags {
+	unsigned long flags;
+	struct {
+		unsigned long pmr : 8;     // SYS_ICC_PMR_EL1
+		unsigned long daif : 10;   // PSTATE.DAIF at bits[6-9]
+		unsigned long allint : 14; // PSTATE.ALLINT at bits[13]
+	} fields;
+};
+
+typedef union arch_irqflags arch_irqflags_t;
+
+static inline void __local_pmr_mask(void)
+{
+	WARN_ON(system_has_prio_mask_debugging() &&
+		(read_sysreg_s(SYS_ICC_PMR_EL1) ==
+		 (GIC_PRIO_IRQOFF | GIC_PRIO_PSR_I_SET)));
+	/*
+	 * Don't really care for a dsb here, we don't intend to enable
+	 * IRQs.
+	 */
+	gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
+}
+
+static inline void __local_nmi_mask(void)
+{
+	msr_pstate_allint(1);
+}
+
+static inline void local_allint_mask_notrace(void)
+{
+	asm volatile ("msr daifset, #0xf" : : : "memory");
+
+	if (system_uses_irq_prio_masking())
+		__local_pmr_mask();
+	else if (system_uses_nmi())
+		__local_nmi_mask();
+}
+
+static inline void local_allint_mask(void)
+{
+	local_allint_mask_notrace();
+	trace_hardirqs_off();
+}
+
+static inline arch_irqflags_t __local_save_pmr_daif_flags(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags.fields.pmr = read_sysreg_s(SYS_ICC_PMR_EL1);
+	irqflags.fields.daif = read_sysreg(daif);
+
+	/*
+	 * If IRQs are masked with PMR, reflect it in the daif of irqflags.
+	 * If NMIs and IRQs are masked with PMR, reflect it in the allint
+	 * of irqflags, this avoid the need of checking PSTATE.A in
+	 * local_allint_restore() to determine if NMIs are masked.
+	 */
+	switch (irqflags.fields.pmr) {
+	case GIC_PRIO_IRQON:
+		irqflags.fields.allint = 0;
+		break;
+
+	case __GIC_PRIO_IRQOFF:
+	case __GIC_PRIO_IRQOFF_NS:
+		irqflags.fields.daif |= PSR_I_BIT | PSR_F_BIT;
+		irqflags.fields.allint = 0;
+		break;
+
+	case GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET:
+		irqflags.fields.daif |= PSR_I_BIT | PSR_F_BIT;
+		irqflags.fields.allint = PSR_ALLINT_BIT;
+		break;
+
+	default:
+		WARN_ON(1);
+	}
+
+	return irqflags;
+}
+
+static inline arch_irqflags_t __local_save_nmi_daif_flags(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags.fields.daif = read_sysreg(daif);
+	irqflags.fields.allint = read_sysreg_s(SYS_ALLINT);
+
+	return irqflags;
+}
+
+static inline arch_irqflags_t local_allint_save_flags(void)
+{
+	arch_irqflags_t irqflags = { .flags = 0UL };
+
+	if (system_uses_irq_prio_masking())
+		return __local_save_pmr_daif_flags();
+
+	if (system_uses_nmi())
+		return __local_save_nmi_daif_flags();
+
+	irqflags.fields.daif = read_sysreg(daif);
+	return irqflags;
+}
+
+static inline arch_irqflags_t local_allint_save(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags = local_allint_save_flags();
+
+	local_allint_mask();
+
+	return irqflags;
+}
+
+static inline void __local_pmr_restore(arch_irqflags_t irqflags)
+{
+	/*
+	 * There has been concern that the write to daif
+	 * might be reordered before this write to PMR.
+	 * From the ARM ARM DDI 0487D.a, section D1.7.1
+	 * "Accessing PSTATE fields":
+	 *   Writes to the PSTATE fields have side-effects on
+	 *   various aspects of the PE operation. All of these
+	 *   side-effects are guaranteed:
+	 *     - Not to be visible to earlier instructions in
+	 *       the execution stream.
+	 *     - To be visible to later instructions in the
+	 *       execution stream
+	 *
+	 * Also, writes to PMR are self-synchronizing, so no
+	 * interrupts with a lower priority than PMR is signaled
+	 * to the PE after the write.
+	 *
+	 * So we don't need additional synchronization here.
+	 */
+	gic_write_pmr(irqflags.fields.pmr);
+}
+
+static inline void __local_nmi_restore(arch_irqflags_t irqflags)
+{
+	msr_pstate_allint(!!irqflags.fields.allint ? 1 : 0);
+}
+
+static inline int local_hardirqs_disabled(arch_irqflags_t irqflags)
+{
+	return irqflags.fields.allint || (irqflags.fields.daif & PSR_I_BIT);
+}
+
+static inline void __local_allint_restore(arch_irqflags_t irqflags)
+{
+	if (system_uses_irq_prio_masking())
+		__local_pmr_restore(irqflags);
+	else if (system_uses_nmi())
+		__local_nmi_restore(irqflags);
+
+	write_sysreg(irqflags.fields.daif, daif);
+}
+
+static inline void local_allint_restore_notrace(arch_irqflags_t irqflags)
+{
+	/*
+	 * Use arch_allint.fields.allint to indicates we can take
+	 * NMIs, instead of the old hacking style that use PSTATE.A.
+	 */
+	if (system_uses_irq_prio_masking() && !irqflags.fields.allint)
+		irqflags.fields.daif &= ~(PSR_I_BIT | PSR_F_BIT);
+
+	__local_allint_restore(irqflags);
+}
+
+/*
+ * It has to conside the different kernel configure and parameters, that need
+ * to use corresponding operations to mask interrupts properly. For example,
+ * the kernel disable PSEUDO_NMI, the kernel uses prio masking to support
+ * PSEUDO_NMI, or the kernel uses FEAT_NMI extension to support ARM64_NMI.
+ */
+static inline void local_allint_restore(arch_irqflags_t irqflags)
+{
+	int irq_disabled = local_hardirqs_disabled(irqflags);
+
+	if (!irq_disabled)
+		trace_hardirqs_on();
+
+	local_allint_restore_notrace(irqflags);
+
+	if (irq_disabled)
+		trace_hardirqs_off();
+}
+
+/*
+ * Called by synchronous exception handlers to restore the DAIF bits that were
+ * modified by taking an exception.
+ */
+static inline void local_allint_inherit(struct pt_regs *regs)
+{
+	arch_irqflags_t irqflags;
+
+	if (interrupts_enabled(regs))
+		trace_hardirqs_on();
+
+	irqflags.fields.pmr = regs->pmr_save;
+	irqflags.fields.daif = regs->pstate & DAIF_MASK;
+	irqflags.fields.allint = regs->pstate & PSR_ALLINT_BIT;
+	__local_allint_restore(irqflags);
+}
 #endif
diff --git a/arch/arm64/include/uapi/asm/ptrace.h b/arch/arm64/include/uapi/asm/ptrace.h
index 7fa2f7036aa7..8a125a1986be 100644
--- a/arch/arm64/include/uapi/asm/ptrace.h
+++ b/arch/arm64/include/uapi/asm/ptrace.h
@@ -48,6 +48,7 @@
 #define PSR_D_BIT	0x00000200
 #define PSR_BTYPE_MASK	0x00000c00
 #define PSR_SSBS_BIT	0x00001000
+#define PSR_ALLINT_BIT	0x00002000
 #define PSR_PAN_BIT	0x00400000
 #define PSR_UAO_BIT	0x00800000
 #define PSR_DIT_BIT	0x01000000
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-5-liaochang1%40huawei.com.
