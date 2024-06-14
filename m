Return-Path: <kasan-dev+bncBCWPLY7W6EARB7X4V2ZQMGQEJM5FAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id EEB059082B2
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:32 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f682664703sf18912465ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337151; cv=pass;
        d=google.com; s=arc-20160816;
        b=KtLM+OIjjMcWmkWhwr/AC7K2sH0Yj0rH5Sptrd5DobgmGs5dFzKpW8MrbqfHiXvkRK
         iT93rXyQf3iDD8XHztGKYcBuC+jpyK9cD4jiPDrIteSE24dH+mhb5aJhj5psNxC5hMp9
         PuW0dnU0bM5yuXdPdi/uEKpnKgDY7rZ6M0zly6YnJbF5N6EJpgxyf+qs+bTPiD8BtEqL
         axamABLFLMrtCgsN2u1mTOy1iUQmHSKUDMPxgL/kdcbwQhk08iBgK84TtYUkzcTqZPqb
         KhcCsHikz03OC5uy+5nDcWpvk6gDcuA1xNYjfkeOOwoVhcqW/Wv5O9YPii2u0wIozYZq
         aiHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=V63IXni2+wFRGilAY6Mc3jmQnmjIhWV6wSPSKKK9p0E=;
        fh=IGgNWrg/Ly/lKVFV68NeqOA8XVZFG+XpxV39HPtGLvA=;
        b=bhWbUXmIBG8RlAeOO38P15DoVAWzDLf2zqVoTM0bbbdinOOgknIRB+kAERKibxmvoj
         djBjVVLMc7plmN1HO61ls6ouQAFkdY1pOxWzt2rs0U5oV6y8IFYtBWpvkPfQzeW0mL2a
         eQpdQzLTYtcRss/XiE7tY0p/X7RPQbAiHMGhllIm+mdWPfXGnnRY9tJqjk9d5MCA3Oo7
         I6uzw40EuG0MyQOzA4GzchdDai71lxoFhRNEzTIZyBrUJuqWAw9c8VrMGu7iVjpGZzps
         dKat30HSSdjbNsjCPg1zqD/7V0HMDwYd/7iHxcM2C4+KAIvracFS82hitzMqFQ7ganeg
         E+dg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337151; x=1718941951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=V63IXni2+wFRGilAY6Mc3jmQnmjIhWV6wSPSKKK9p0E=;
        b=IVFilj/OAh15g5zSuhfj3GDgVRFj4Y/mHJqfPv4U0uMbD3+NWxXSij8kUU+oJLo//g
         KPMiZqy9qtyXEL2g8CFfdQY0TkYEabqpaX+x70d25QwPzcThynvQhyzs61cavL6/s1Kr
         MWAN9lxRl5nuUcMFICF53OYCITzrge58Y4EjphoeHRVElFnAhVFl2QVnmM9wn/BrlP6Y
         AxSshZpysmaIQ7eOUVIL7et0l2IfXYDAUS8B9ZpFLL/g/dOl206zg7Wml1SsECCmJTKe
         uasvidT4ownLpMxQ7Pi5ntk0hegJG3/s/mdEEqH36K3abROinfRmRQakNicBVOD84APt
         c/+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337151; x=1718941951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V63IXni2+wFRGilAY6Mc3jmQnmjIhWV6wSPSKKK9p0E=;
        b=OXPcWmzpY8RPnYVpGsiTjwyUKfYROf3yDfq4NyzBr3zwisiLcXhm1PmfMsgL5M51RV
         WPeK0fPi7SM6HL+q+HGUOMuMKlIJHKVOh9rEMoPW2W/JVan810BCLRkSmcN1K1c+VT0K
         RbG3TUgppVTSsFvxYzIKasRlEWOUkLNPx+YLEVIfysaUCN5NoR0Sm9BqsFSxwoA46KO2
         2d5xByASoCGZzCXGfSbaWySrMstni1suW6wI085Ei4RYevc70FdeSvue9zrhJEDhL2eH
         9B/PGZ90C00QOfPUGnsOEFCts5IrB1S7xclcyHBv5NJbbHV46pbSaRgY3h4IQUqDbI7z
         /V8g==
X-Forwarded-Encrypted: i=2; AJvYcCW1NHDvlViXVxOpk/g/sp6XL2WIJ1W/7CY+MOWJWa0XUrjdUbyai0R/sw4sp/yx5DiToftok4HLXBmiVFh4qCGqxyfV/ag8ng==
X-Gm-Message-State: AOJu0Yz61xF/8BsY1GAttHmZhmNVn7cL0J3qsWDq1sUW8phF/KjTuqrd
	ZklZaN2iqC06Vm4evrwkaLr3msqMPUz4FrXSDe3RewYpXk79nvzN
X-Google-Smtp-Source: AGHT+IFzkLo9PDcXJyLbTEqwWLS6oerSQgCz82xAcfjbhF8f07WMy2tXH3oeu9E1kJ+jz+7miUiaMQ==
X-Received: by 2002:a17:903:228f:b0:1f7:317f:5454 with SMTP id d9443c01a7336-1f862804bb9mr20600895ad.51.1718337151080;
        Thu, 13 Jun 2024 20:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80a:b0:1e2:306e:bcec with SMTP id
 d9443c01a7336-1f84d41d0c4ls14135135ad.0.-pod-prod-03-us; Thu, 13 Jun 2024
 20:52:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuv5JCi1YuolnN/SZj3HxKzb+INe4QjJ/PKaDdDK3tdwSovkYzSFb4hS4TQRQgWMMQQCMXxQF9LwailA12Vam4fK6KQO4dhHk4yw==
X-Received: by 2002:a17:902:ced0:b0:1f6:da67:830b with SMTP id d9443c01a7336-1f8629fcb67mr18700925ad.59.1718337148362;
        Thu, 13 Jun 2024 20:52:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337148; cv=none;
        d=google.com; s=arc-20160816;
        b=Vw8luaH3x8SQUfsYkTBLEDDCA07tmpXfpPuj1sGhx6PMde9Ncv7+A+Tn5fQSd9b6d/
         d4YK5DjngLYv1snJfVuDmpZ55sjSuh3+y4L4JgkJh6KSj9quB6AsXaJNI4250aya3Pc8
         6udXt1osVcUlo5WgnbEOe0bdn6kl50Gl/7WNYuyVzsxIMGwWY8Eja3Zta+MkMQADLuUY
         91FM3e8KmM4Xw+wgrjlRV/seKMW6DXpXmTTmH7tKxfBcHyEqjtbtUe72WgIOT3GHV+nM
         cor397KVi1jYV6T32R1I4dmP4cbfQNze0Y+miFQmHFP3CSNEL7QEHVL5cWLjzsa2dS3b
         Aeug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eqyay/aI9/T1f1svE3ZmI9XiP3UmUnIqqYUiQUqQHEg=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=yQj+blILocKiZKtd+iry28yXe4ijX+LgTp/5XPbnn+GGaA3+Z+m6F8XFosLvgWHDW7
         59iVHHGazxSzYSyQAB1+4+ed0BFB+xiHLsP4cOXLzxrgz7bgTejFKDjwJoKV0A4ZxOhU
         3EOFqFDE/KWGyiZuScvNxBwqpnNrH+Cld/nRldsK6J5q98UC/hyStMB8PGDXyhFw/mIK
         z99KO9rcrBQxEK934Fkrmg5FjI1/tAUgd1okbtVEYuSCsu4vvZ6SgIIoCg7yIzlo2f6m
         RfyeIKkLHI/PfwQymCnnlyG/wbVXxr0dxlOOBfN2YTXnuqKaZNwcsvLV94+uETs7MlQL
         hRLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855ebd9b1si1199935ad.10.2024.06.13.20.52.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.163.252])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4W0lgQ1FdHzdbCD;
	Fri, 14 Jun 2024 11:50:58 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 47C0E180AA6;
	Fri, 14 Jun 2024 11:52:26 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:24 +0800
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
Subject: [PATCH v4 02/10] arm64/cpufeature: Detect PE support for FEAT_NMI
Date: Fri, 14 Jun 2024 03:44:25 +0000
Message-ID: <20240614034433.602622-3-liaochang1@huawei.com>
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
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as
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

From: Mark Brown <broonie@kernel.org>

Use of FEAT_NMI requires that all the PEs in the system and the GIC have
NMI support. This patch implements the PE part of that detection.

In order to avoid problematic interactions between real and pseudo NMIs
we disable the architected feature if the user has enabled pseudo NMIs
on the command line. If this is done on a system where support for the
architected feature is detected then a warning is printed during boot in
order to help users spot what is likely to be a misconfiguration.

In order to allow KVM to offer the feature to guests even if pseudo NMIs
are in use by the host we have a separate feature for the raw feature
which is used in KVM.

Signed-off-by: Mark Brown <broonie@kernel.org>
Signed-off-by: Liao Chang <liaochang1@huawei.com>
Signed-off-by: Jinjie Ruan <ruanjinjie@huawei.com>
---
 arch/arm64/include/asm/cpufeature.h |  6 +++
 arch/arm64/kernel/cpufeature.c      | 57 ++++++++++++++++++++++++++++-
 arch/arm64/tools/cpucaps            |  2 +
 3 files changed, 64 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/cpufeature.h b/arch/arm64/include/asm/cpufeature.h
index 8b904a757bd3..4c35565ad656 100644
--- a/arch/arm64/include/asm/cpufeature.h
+++ b/arch/arm64/include/asm/cpufeature.h
@@ -800,6 +800,12 @@ static __always_inline bool system_uses_irq_prio_masking(void)
 	return alternative_has_cap_unlikely(ARM64_HAS_GIC_PRIO_MASKING);
 }
 
+static __always_inline bool system_uses_nmi(void)
+{
+	return IS_ENABLED(CONFIG_ARM64_NMI) &&
+		alternative_has_cap_likely(ARM64_USES_NMI);
+}
+
 static inline bool system_supports_mte(void)
 {
 	return alternative_has_cap_unlikely(ARM64_MTE);
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 03a37a21fc99..0ac08d5a7ef9 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -291,6 +291,7 @@ static const struct arm64_ftr_bits ftr_id_aa64pfr0[] = {
 };
 
 static const struct arm64_ftr_bits ftr_id_aa64pfr1[] = {
+	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_NMI_SHIFT, 4, 0),
 	ARM64_FTR_BITS(FTR_VISIBLE_IF_IS_ENABLED(CONFIG_ARM64_SME),
 		       FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_SME_SHIFT, 4, 0),
 	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR1_EL1_MPAM_frac_SHIFT, 4, 0),
@@ -1076,9 +1077,11 @@ static void init_32bit_cpu_features(struct cpuinfo_32bit *info)
 	init_cpu_ftr_reg(SYS_MVFR2_EL1, info->reg_mvfr2);
 }
 
-#ifdef CONFIG_ARM64_PSEUDO_NMI
+#if IS_ENABLED(CONFIG_ARM64_PSEUDO_NMI) || IS_ENABLED(CONFIG_ARM64_NMI)
 static bool enable_pseudo_nmi;
+#endif
 
+#ifdef CONFIG_ARM64_PSEUDO_NMI
 static int __init early_enable_pseudo_nmi(char *p)
 {
 	return kstrtobool(p, &enable_pseudo_nmi);
@@ -2263,6 +2266,41 @@ static bool has_gic_prio_relaxed_sync(const struct arm64_cpu_capabilities *entry
 }
 #endif
 
+#ifdef CONFIG_ARM64_NMI
+static bool use_nmi(const struct arm64_cpu_capabilities *entry, int scope)
+{
+	if (!has_cpuid_feature(entry, scope))
+		return false;
+
+	/*
+	 * Having both real and pseudo NMIs enabled simultaneously is
+	 * likely to cause confusion.  Since pseudo NMIs must be
+	 * enabled with an explicit command line option, if the user
+	 * has set that option on a system with real NMIs for some
+	 * reason assume they know what they're doing.
+	 */
+	if (IS_ENABLED(CONFIG_ARM64_PSEUDO_NMI) && enable_pseudo_nmi) {
+		pr_info("Pseudo NMI enabled, not using architected NMI\n");
+		return false;
+	}
+
+	return true;
+}
+
+static void nmi_enable(const struct arm64_cpu_capabilities *__unused)
+{
+	/*
+	 * Enable use of NMIs controlled by ALLINT, SPINTMASK should
+	 * be clear by default but make it explicit that we are using
+	 * this mode.  Ensure that ALLINT is clear first in order to
+	 * avoid leaving things masked.
+	 */
+	msr_pstate_allint(0);
+	sysreg_clear_set(sctlr_el1, SCTLR_EL1_SPINTMASK, SCTLR_EL1_NMI);
+	isb();
+}
+#endif
+
 #ifdef CONFIG_ARM64_BTI
 static void bti_enable(const struct arm64_cpu_capabilities *__unused)
 {
@@ -2869,6 +2907,23 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.matches = has_nv1,
 		ARM64_CPUID_FIELDS_NEG(ID_AA64MMFR4_EL1, E2H0, NI_NV1)
 	},
+#ifdef CONFIG_ARM64_NMI
+	{
+		.desc = "Non-maskable Interrupts present",
+		.capability = ARM64_HAS_NMI,
+		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
+		.matches = has_cpuid_feature,
+		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, NMI, IMP)
+	},
+	{
+		.desc = "Non-maskable Interrupts enabled",
+		.capability = ARM64_USES_NMI,
+		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
+		.matches = use_nmi,
+		.cpu_enable = nmi_enable,
+		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, NMI, IMP)
+	},
+#endif
 	{},
 };
 
diff --git a/arch/arm64/tools/cpucaps b/arch/arm64/tools/cpucaps
index ac3429d892b9..e40437e61677 100644
--- a/arch/arm64/tools/cpucaps
+++ b/arch/arm64/tools/cpucaps
@@ -43,6 +43,7 @@ HAS_LPA2
 HAS_LSE_ATOMICS
 HAS_MOPS
 HAS_NESTED_VIRT
+HAS_NMI
 HAS_PAN
 HAS_S1PIE
 HAS_RAS_EXTN
@@ -71,6 +72,7 @@ SPECTRE_BHB
 SSBS
 SVE
 UNMAP_KERNEL_AT_EL0
+USES_NMI
 WORKAROUND_834220
 WORKAROUND_843419
 WORKAROUND_845719
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-3-liaochang1%40huawei.com.
