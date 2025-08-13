Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBLFC6PCAMGQEPGCVNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A1A1B25295
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 19:53:50 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-32326e017efsf149963a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 10:53:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755107628; cv=pass;
        d=google.com; s=arc-20240605;
        b=CoVLYSxex9CK/lWYXIVHuVlZyVaMBM5B6GfPZL9iS+up4x60ASFP/VMb2+b0C6NYEy
         sQVTWlkdqUwOffKu5etN3TP42i0oei0dtFy9czdfzL/hFLbeXxD4/ql9ZV5aJVE0b2aY
         EKoEtZVnoaG7k+xDRFicYJrtU6rDTHe9+JYollCqhuxujvJXjnrvXDFzrhNO/SrulKAh
         ild1iJ0RKG+TCUgtGlNDojuvh8e1HyasBYFni5jQ+hJPAZQMNTZHyJNHLTMs+9fR1BuW
         sBeMwV1VPWDWlC41KeBRmElDH7Ja4idMJ4YtWH2O2BqQpYhryx4yZVZAcJiELnLqmHGs
         QWlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XQxkxjbtiCCgq3Y9Qlxc9bCrpSftTgndRpw7vZCo2Pk=;
        fh=S+k5o7i7XXkN94Elc6jWMoSfLGEWqppcOPK5JjmMkV0=;
        b=Cad1NcQFc+rN7tt8fi/X5HvxuAE42I5CNY26kAiY9AcZ6MVTpat8u7oatbT/g9PTz7
         eFspp0OnqxsHNAGtYB0cpX1yfq3eVutBZb8ps7BUgQ7ThrhEzzMhse0QpOySeMam2Ohw
         KZOoBp75AtuLawUCS2/JgtGrDItj/SAKc20R04qkarYCKWtkuxnP/LY7yZZ+jEaBe+8I
         NHRoPyo7QxikvsEM8Ji9O/35LR8TJpu5jAskwBK1CEgvk2ewI9fZ00Zr+cWYW7mAw/yL
         CQI4DQ7kYT9aW/0aWIrb8N6Z8svAh/ra6fWbxdLxSceudqvVeAI7m25WAxmiaA3D8fQs
         p3Eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755107628; x=1755712428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XQxkxjbtiCCgq3Y9Qlxc9bCrpSftTgndRpw7vZCo2Pk=;
        b=pDDeUZ83nV0kgonAAV0C71TiKqE6xRXPPpUGylPfDMDlVb+88/xN/KeqM4zyncxtij
         J+jVRp9s63pyH0c/mu4xS6mIsE9zMAdk2917KuABcc4Dqax5xbzKZy4MoWH0QnrLYfBW
         eizyjyM2GYvTALQTNSA1phYfkr5saDuJ5Ndfd7xNUjWviOy3K4d5SOKp5s8gS1a+4SBs
         ISUK6Lk1KVzBaPqLUBjkh/JMsy8O0VabGjYQZPA0I/0mManGw7rr1iYKRXwe1d3h/y58
         Ii79EG59E6pEtagAP3HwqaGeVVNBfbVxWztStMyi7qGaj5YttTUFi/k4kR8YEaDDvY5y
         s+zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755107628; x=1755712428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XQxkxjbtiCCgq3Y9Qlxc9bCrpSftTgndRpw7vZCo2Pk=;
        b=KQ5UwuGQ/fkkk4CysdN2EocsRzYoSnt5jYDMvxg+vrKLXakND1O97cHCKiWeSMYV8T
         kyqLE8I8SvjLrcvykJYpcu6ARfC/UUfKQtYtQC/y5JbDGn6UxpD3vUEZUha+pN0KLTwf
         M09qKAGDFBOG1RS8Yz9NXAl1MyX0/G+qAm5azCmZ2PC0TyJfihXBIA2yBevZhgLc+YYk
         xtfW+jW91cBgI0qI0Q/naKuMAF1bFBLvnsA3/QsDaPkhdNI06R2/W8SuGicIMsxZOjKG
         ux5nRUis3rXD28LerXFZ3jRnQncQuYdENNSUT8Gs2SZ/GBS3WDnVxA3ibQ0O9WTjaJrR
         SOaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjrB+/jDRkvlTDzfqISNwNYuDg5/+VpFKLuKIMe2ODS4oVL0mCxygS2sP+HRa0C3H8TY0H9Q==@lfdr.de
X-Gm-Message-State: AOJu0YwPwZf/hKiTQXrRTPSEo4FZsAvh4Vd/lSkpNYZnArEIAq0zpkx5
	J+p8ztyX5OOgjFyOwZ60HHyreLadYedDaFzSuCjFUTv1YFpf05X/wgP4
X-Google-Smtp-Source: AGHT+IFgXW4PuiwoL3O9AHTvTskCoUlmDL/oNpS3HbzarmLEGTnShWxb5LEoJ0cwOnp2COl8BfU/1w==
X-Received: by 2002:a17:90b:38d1:b0:321:8a3b:93c with SMTP id 98e67ed59e1d1-32327b61127mr282798a91.33.1755107628304;
        Wed, 13 Aug 2025 10:53:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc3B4pKElSEl5md9KgsRMBypO8nDMtz/OJzEeYBMVSMDw==
Received: by 2002:a17:90b:1c82:b0:322:129c:381d with SMTP id
 98e67ed59e1d1-32326741c26ls126372a91.0.-pod-prod-05-us; Wed, 13 Aug 2025
 10:53:46 -0700 (PDT)
X-Received: by 2002:a05:6a20:748d:b0:232:7c7b:1c7b with SMTP id adf61e73a8af0-240a8a7d35amr7216068637.14.1755107626667;
        Wed, 13 Aug 2025 10:53:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755107626; cv=none;
        d=google.com; s=arc-20240605;
        b=WtzMLYcBrP+tTfaE4ZwmXGPQZOPMudiT5H2xp39QTaQeJ86WPQHuN41RUg5EZQHuGj
         0ySdeMpcK2NFN2KCxbd1VHtcPg70IJf4l5vEf8bOtJTXWKtzRGbPRt12V1akUzkB72BZ
         SrrdXDQ3stlKOzVy9ZlWpuduYM+/G7cyeQJvCVs9TkzoARaGhDgnIoAGAoa/OGxX6aaa
         gAK//+NuZZMoXt4ds7dgz6ZZ0hLDzMdGF2b0R5zlSlRR4ZQRVJeWDWVTkMtgdrDwZ7Wn
         SBUUOxcrB0eM/OBU9j7ZEEPqzJLotwYv04D4jnL2hMK3HeRSPELa4nttW9xQSAU36/Xr
         xDkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=jqxOFgCfRl5wZ83QA7FvuO3ex3Ygy/hpF6Az2tCTtf8=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=AyX35tWElGGNr4kEFqkGzd1uLP3No7PpxlD5EMy2gl9gobF7z8pY2FOVC7CAdwTcHd
         EKVz0+yGfus4D0DdkpPSTTiXHCABWDLQTZRR7Pd5i6Xg2ROVoBNRAfeMs4eNr5Ry1L1u
         wPH73vUCnjPCFjpG1sP3Dxf3T+6Bpw9ZoMOH3YXULDsHbACoxe7yKq/BYi/q3hnF1Pmy
         ysYjSNT1seZpqCA83pIg85wrcNQsFa5/bmZs7zrWJPl/EybaPTo3FkvU8Vsyoj8Gty4K
         h7IkyTIvhvHOIKpSqzYqMXRTOts2RrA6DkgmQO/UJjWGa5On624bxhwdMokOaZcnVI5u
         uHNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-76be8650093si1409756b3a.1.2025.08.13.10.53.46
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Aug 2025 10:53:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4D8C814BF;
	Wed, 13 Aug 2025 10:53:37 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 8C8493F5A1;
	Wed, 13 Aug 2025 10:53:41 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	catalin.marinas@arm.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	scott@os.amperecomputing.com,
	jhubbard@nvidia.com,
	pankaj.gupta@amd.com,
	leitao@debian.org,
	kaleshsingh@google.com,
	maz@kernel.org,
	broonie@kernel.org,
	oliver.upton@linux.dev,
	james.morse@arm.com,
	ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io,
	david@redhat.com,
	yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Date: Wed, 13 Aug 2025 18:53:34 +0100
Message-Id: <20250813175335.3980268-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250813175335.3980268-1-yeoreum.yun@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
raise of tag check fault on store operation only.
Introcude KASAN store only mode based on this feature.

KASAN store only mode restricts KASAN checks operation for store only and
omits the checks for fetch/read operation when accessing memory.
So it might be used not only debugging enviroment but also normal
enviroment to check memory safty.

This features can be controlled with "kasan.store_only" arguments.
When "kasan.store_only=on", KASAN checks store only mode otherwise
KASAN checks all operations.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 Documentation/dev-tools/kasan.rst  |  3 ++
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  6 +++
 arch/arm64/kernel/cpufeature.c     |  6 +++
 arch/arm64/kernel/mte.c            | 14 ++++++
 include/linux/kasan.h              |  2 +
 mm/kasan/hw_tags.c                 | 76 +++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                   | 10 ++++
 8 files changed, 116 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0a1418ab72fd..fcb70dd821ec 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.store_only=off`` or ``kasan.store_only=on`` controls whether KASAN
+  checks the store (write) accesses only or all accesses (default: ``off``)
+
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 5213248e081b..ae29cd3db78d 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_enable_tag_checks_store_only()	mte_enable_kernel_store_only()
 #define arch_suppress_tag_checks_start()	mte_enable_tco()
 #define arch_suppress_tag_checks_stop()		mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 2e98028c1965..3e1cc341d47a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
 void mte_enable_kernel_asymm(void);
+int mte_enable_kernel_store_only(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
 {
 }
 
+static inline int mte_enable_kenrel_store_only(void)
+{
+	return -EINVAL;
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 9ad065f15f1d..7b724fcf20a7 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	kasan_init_hw_tags_cpu();
 }
+
+static void cpu_enable_mte_store_only(struct arm64_cpu_capabilities const *cap)
+{
+	kasan_late_init_hw_tags_cpu();
+}
 #endif /* CONFIG_ARM64_MTE */
 
 static void user_feature_fixup(void)
@@ -2922,6 +2927,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.capability = ARM64_MTE_STORE_ONLY,
 		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
 		.matches = has_cpuid_feature,
+		.cpu_enable = cpu_enable_mte_store_only,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
 	},
 #endif /* CONFIG_ARM64_MTE */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e773844889..8eb1f66f2ccd 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
 		mte_enable_kernel_sync();
 	}
 }
+
+int mte_enable_kernel_store_only(void)
+{
+	if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
+		return -EINVAL;
+
+	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
+			 SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
+	isb();
+
+	pr_info_once("MTE: enabled stonly mode at EL1\n");
+
+	return 0;
+}
 #endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..28951b29c593 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -552,9 +552,11 @@ static inline void kasan_init_sw_tags(void) { }
 #ifdef CONFIG_KASAN_HW_TAGS
 void kasan_init_hw_tags_cpu(void);
 void __init kasan_init_hw_tags(void);
+void kasan_late_init_hw_tags_cpu(void);
 #else
 static inline void kasan_init_hw_tags_cpu(void) { }
 static inline void kasan_init_hw_tags(void) { }
+static inline void kasan_late_init_hw_tags_cpu(void) { }
 #endif
 
 #ifdef CONFIG_KASAN_VMALLOC
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..c2f90c06076e 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
+enum kasan_arg_store_only {
+	KASAN_ARG_STORE_ONLY_DEFAULT,
+	KASAN_ARG_STORE_ONLY_OFF,
+	KASAN_ARG_STORE_ONLY_ON,
+};
+
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
+static enum kasan_arg_store_only kasan_arg_store_only __ro_after_init;
 
 /*
  * Whether KASAN is enabled at all.
@@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
 EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
+DEFINE_STATIC_KEY_FALSE(kasan_flag_store_only);
+EXPORT_SYMBOL_GPL(kasan_flag_store_only);
+
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
 
@@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
+/* kasan.store_only=off/on */
+static int __init early_kasan_flag_store_only(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_store_only = KASAN_ARG_STORE_ONLY_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_store_only = KASAN_ARG_STORE_ONLY_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.store_only", early_kasan_flag_store_only);
+
 static inline const char *kasan_mode_info(void)
 {
 	if (kasan_mode == KASAN_MODE_ASYNC)
@@ -219,6 +246,20 @@ void kasan_init_hw_tags_cpu(void)
 	kasan_enable_hw_tags();
 }
 
+/*
+ * kasan_late_init_hw_tags_cpu_post() is called for each CPU after
+ * all cpus are bring-up at boot.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
+void kasan_late_init_hw_tags_cpu(void)
+{
+	/*
+	 * Enable stonly mode only when explicitly requested through the command line.
+	 * If system doesn't support, kasan checks all operation.
+	 */
+	kasan_enable_store_only();
+}
+
 /* kasan_init_hw_tags() is called once on boot CPU. */
 void __init kasan_init_hw_tags(void)
 {
@@ -257,15 +298,28 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_store_only) {
+	case KASAN_ARG_STORE_ONLY_DEFAULT:
+		/* Default is specified by kasan_flag_store_only definition. */
+		break;
+	case KASAN_ARG_STORE_ONLY_OFF:
+		static_branch_disable(&kasan_flag_store_only);
+		break;
+	case KASAN_ARG_STORE_ONLY_ON:
+		static_branch_enable(&kasan_flag_store_only);
+		break;
+	}
+
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s store_only=%s\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
-		str_on_off(kasan_stack_collection_enabled()));
+		str_on_off(kasan_stack_collection_enabled()),
+		str_on_off(kasan_store_only_enabled()));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
@@ -394,6 +448,22 @@ void kasan_enable_hw_tags(void)
 		hw_enable_tag_checks_sync();
 }
 
+void kasan_enable_store_only(void)
+{
+	if (kasan_arg_store_only == KASAN_ARG_STORE_ONLY_ON) {
+		if (hw_enable_tag_checks_store_only()) {
+			static_branch_disable(&kasan_flag_store_only);
+			kasan_arg_store_only = KASAN_ARG_STORE_ONLY_OFF;
+			pr_warn_once("KernelAddressSanitizer: store only mode isn't supported (hw-tags)\n");
+		}
+	}
+}
+
+bool kasan_store_only_enabled(void)
+{
+	return static_branch_unlikely(&kasan_flag_store_only);
+}
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
@@ -404,4 +474,6 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
 }
 EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
 
+EXPORT_SYMBOL_IF_KUNIT(kasan_store_only_enabled);
+
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..1d853de1c499 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -33,6 +33,7 @@ static inline bool kasan_stack_collection_enabled(void)
 #include "../slab.h"
 
 DECLARE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
+DECLARE_STATIC_KEY_FALSE(kasan_flag_stonly);
 
 enum kasan_mode {
 	KASAN_MODE_SYNC,
@@ -428,6 +429,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
 #define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
 #define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
+#define hw_enable_tag_checks_store_only()	arch_enable_tag_checks_store_only()
 #define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
 #define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
@@ -437,10 +439,18 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
 void kasan_enable_hw_tags(void);
+void kasan_enable_store_only(void);
+bool kasan_store_only_enabled(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_enable_hw_tags(void) { }
+static inline void kasan_enable_store_only(void) { }
+
+static inline bool kasan_store_only_enabled(void)
+{
+	return false;
+}
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813175335.3980268-2-yeoreum.yun%40arm.com.
