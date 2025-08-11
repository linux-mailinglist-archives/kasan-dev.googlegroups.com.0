Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBKOU5DCAMGQEQAEQWXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C501B21354
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 19:36:43 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-31f3cfdd3d3sf4955232a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:36:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754933801; cv=pass;
        d=google.com; s=arc-20240605;
        b=IhBp6K+Tb19pSDpHfG5An8h8sqnjelKyxRb9Le2ZSvKVE7zDEFBivowVXSFpYr6eic
         ek6yICk5pXpjt80v7NYfsOd56q373C0M/ICZsq/cRfzOsMhm8sWeoYxj9T0YkKnU3+Yh
         Er6RQPV8dxvaL8R+xcrAaXoZ4jFUJUYo/WzydNNjtQ1G0ljtVyUTAFkHkogScXReZGAV
         0guVAFPAAW1xWwO/i6ZM64YR3+w75wlnE31neJR6jm4N4PrsMmmkBlft6/zxIcapm7UV
         GuaPDC2Ub/2YVh8yw5uHM8tgnmMHqZsKQepZtLqHSeFZbIG5IL03ip9L3Q43TSdBncvC
         lmzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YpLL8ywBrjVh+lVqTN2Ot4gMNBMqe/9cUrkZekSxQHU=;
        fh=Y0fwluKDj8WAQpbeNgrIBMftep7gUS3qCpaToe2xtG8=;
        b=YLTCRUstItfPppxJX9y48D2qa+2klEpDufn0vj/DiNrbhLmT1G8aTPdMXmwYidEjt6
         4u2oHnqBOtCd7w0Bwedn1VoGdjxF2EICNdH5i5IZOauW/dbzu7H1WLRrwVTO9qUk9ib+
         pww3i2PDQ2E9zFjWpAX4eFr9nYJOtpfp50YoG33XCsaEgvR8dg7Kv+V9QIjpEMKG0Boe
         Jj4bPnjX5pCOg884huBAsoz0R2RZ1octDBl+r4gQy0rOnUjCVDH2ENZUMfgCHjtAe8HL
         dXXQsozvK9t523b8TfDCRrFnjCOkGidVA01wxq7ACTswOGVSofQ/OISC190U22zHxDJz
         VNDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754933801; x=1755538601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YpLL8ywBrjVh+lVqTN2Ot4gMNBMqe/9cUrkZekSxQHU=;
        b=JNsBhWceN5otiMbmLt5D4iG0TkOkCqDrsvP8ulZquOdNG/bijvq2noS6ajWTyhc3Jf
         ZV2J37MptTwdzSY2xe8JeWbXK2XsZXPMWG74X9/+15gsDDWajfQZnMAW5H4dJn3miECV
         +0qDMBGCBQX5kTqZPekauLUBLBp7xETna7xgbx17XJFikdeWjeYX4XLUGsEqacXimT20
         JJDTz7L7ZH6vWTNvTPRoWb3U0cJfH5813hdJHjue4Fe9T33aCxccDMZMfyFHwkUpGpRq
         I4iUrdg/ZgU7Ddt31AIL9rm1FLbroOZfFxi7E7JOSmvVGZPcivWAs5YcQHgqe332Fg2W
         qzfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754933801; x=1755538601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YpLL8ywBrjVh+lVqTN2Ot4gMNBMqe/9cUrkZekSxQHU=;
        b=gd2x4Bs5ZwDmSqC+bZX16wtkmte6W/1gRVaoEOoUFg80KAHL08Ff1JDln6EydSfasg
         rLZHYbYBl2wBX+DoWjLbH+uXeBdv47pSpBullyqX/Ssq1MpknIj8gmfVehfGiwGUnYIf
         yLhuurH+j4xm/oOLoCneXC1u8pvNN1zAXnMZd2dOCZyQfyOi6tOTW9zwerk35QnkyS/e
         edvBGOerP4E6yyfEO29qrZpLRMeqZGrCp3N1s2lT0LvJ76nQJMJ5966WzOAe4QGFCY+f
         fOImp0NzYQRc+H5pBo+1ZJK160Q3K8Tu1MB5cQwpoYtJsaRv5nCiWzY7g0pMBdr2eK5a
         ouQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlHHk5ZJa4hsQeJDeJHRF9saQWKG4FK0oeGzSdGHapNo+DELxLSB39wJTZYVu3bhMmSGxd4A==@lfdr.de
X-Gm-Message-State: AOJu0YxLXe3UyaHXFItxCetvBLo6E4hhCBp+FwzE7AMrKHyaHJNDib95
	rZ4IakdPnCvuZ2HbrB4Zgg0dwFv9cc8kQ6LJoFDePQxTMpCBHGKgqG2g
X-Google-Smtp-Source: AGHT+IGfOYtkatJ0RBiMdN79CSDffxd9vJB9wYUeMR8odJ0wd5u6q4IwEbngymGAmyfLBrM1BJMlqQ==
X-Received: by 2002:a17:90b:2e45:b0:31f:1744:e7fd with SMTP id 98e67ed59e1d1-32183e7ed80mr18027925a91.31.1754933801373;
        Mon, 11 Aug 2025 10:36:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSW5AKIVDHM3G6qUabztlDFQDnDZvW/ztL4kEP3VHT6A==
Received: by 2002:a17:90b:4b08:b0:31e:cf05:e731 with SMTP id
 98e67ed59e1d1-32174fc5b5dls5324801a91.0.-pod-prod-07-us; Mon, 11 Aug 2025
 10:36:40 -0700 (PDT)
X-Received: by 2002:a17:90b:55cb:b0:31f:ca:63cd with SMTP id 98e67ed59e1d1-321839e9a33mr19735310a91.2.1754933799979;
        Mon, 11 Aug 2025 10:36:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754933799; cv=none;
        d=google.com; s=arc-20240605;
        b=DKPKvS3SxslLuIhvH/mmK5BLW2Z71cFkdhq43N2CoD5WO8HFqYzmLn18/Wq87PEhG5
         NV9Om0aRPs2FZSri2bzcn/rt4UXlcDyMoSoO6Td6KBeo2vb5gV0vH46fIJmqz+Oxr7du
         pflw07CQ9GFWtORnqmjv7w454K96b7WN5vOJg0k3ZQok9RHRhxjkIj2rYPxLgeUPhEIC
         8A4SoJuk7qg78SlGelrP6ciq7Pl9AHzZDU8GF2dZhfWi3QtZBFoQ6mRA+v9GBb+siwgt
         oai6CYtY1WP6g5oH8c8adCjXMweQUVCjiqNo0gfqCOaD4ioN7zouFx3bAyhN7PWSK4Xn
         hWwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=+31wXn/low5JC7UymuA++AaJ/YjM9ZTp4UXMP2CfMoA=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=h912EEygHOBy44h1V8xkFpsLDl/3iTyLMpokc6Qn2SVjzjI4YpuUknR4u+Pvo00WSn
         jKTM+eY4gCPjbeHklBcYTY+ekJ5IPnMhWJMIh7FAjbFBidXFLpN8Bzf3mrR030DtuEA0
         zzp9kIqc9SPEP7NQbdnFiZ94nQpUSC2eut8oztzxgzKbxZuoR9aRIq9MJI8CZceakcuT
         WYsprF1AIcT8AWtjFN4dOJeDTqsFHjvLv6IE7FgvGKsCGyg9rUts6aSy12CzDqpG/9Hs
         Cet49jj/dq7KmvQGShX3T8AincA3ACynPFQ7KMdVxTZGB+M11AYXbzHrBZRnrjo4y5kU
         DAow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-32102854444si561542a91.0.2025.08.11.10.36.39
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Aug 2025 10:36:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C99A22680;
	Mon, 11 Aug 2025 10:36:30 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 0E3AD3F63F;
	Mon, 11 Aug 2025 10:36:34 -0700 (PDT)
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
Subject: [PATCH 1/2] kasan/hw-tags: introduce store only mode
Date: Mon, 11 Aug 2025 18:36:25 +0100
Message-Id: <20250811173626.1878783-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250811173626.1878783-1-yeoreum.yun@arm.com>
References: <20250811173626.1878783-1-yeoreum.yun@arm.com>
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

This features can be controlled with "kasan.stonly" arguments.
When "kasan.stonly=on", KASAN checks store only mode otherwise
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
index 0a1418ab72fd..7567a2ca0e39 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -163,6 +163,9 @@ disabling KASAN altogether or controlling its features:
   This parameter is intended to allow sampling only large page_alloc
   allocations, which is the biggest source of the performance overhead.
 
+- ``kasan.stonly=off`` or ``kasan.stonly=on`` controls whether KASAN checks
+  store operation only or all operation.
+
 Error reports
 ~~~~~~~~~~~~~
 
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 5213248e081b..9d8c72c9c91f 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_enable_tag_checks_stonly()	mte_enable_kernel_stonly()
 #define arch_suppress_tag_checks_start()	mte_enable_tco()
 #define arch_suppress_tag_checks_stop()		mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 2e98028c1965..d75908ed9d0f 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
 void mte_enable_kernel_asymm(void);
+int mte_enable_kernel_stonly(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
 {
 }
 
+static inline int mte_enable_kenrel_stonly(void)
+{
+	return -EINVAL;
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 9ad065f15f1d..fdc510fe0187 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	kasan_init_hw_tags_cpu();
 }
+
+static void cpu_enable_mte_stonly(struct arm64_cpu_capabilities const *cap)
+{
+	kasan_late_init_hw_tags_cpu();
+}
 #endif /* CONFIG_ARM64_MTE */
 
 static void user_feature_fixup(void)
@@ -2922,6 +2927,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.capability = ARM64_MTE_STORE_ONLY,
 		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
 		.matches = has_cpuid_feature,
+		.cpu_enable = cpu_enable_mte_stonly,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
 	},
 #endif /* CONFIG_ARM64_MTE */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e773844889..a1cb2a8a79a1 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
 		mte_enable_kernel_sync();
 	}
 }
+
+int mte_enable_kernel_stonly(void)
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
index 9a6927394b54..2caa6fe5ed47 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
+enum kasan_arg_stonly {
+	KASAN_ARG_STONLY_DEFAULT,
+	KASAN_ARG_STONLY_OFF,
+	KASAN_ARG_STONLY_ON,
+};
+
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
+static enum kasan_arg_stonly kasan_arg_stonly __ro_after_init;
 
 /*
  * Whether KASAN is enabled at all.
@@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
 EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
+DEFINE_STATIC_KEY_FALSE(kasan_flag_stonly);
+EXPORT_SYMBOL_GPL(kasan_flag_stonly);
+
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
 
@@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
+/* kasan.stonly=off/on */
+static int __init early_kasan_flag_stonly(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_stonly = KASAN_ARG_STONLY_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_stonly = KASAN_ARG_STONLY_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.stonly", early_kasan_flag_stonly);
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
+	kasan_enable_stonly();
+}
+
 /* kasan_init_hw_tags() is called once on boot CPU. */
 void __init kasan_init_hw_tags(void)
 {
@@ -257,15 +298,28 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_stonly) {
+	case KASAN_ARG_STONLY_DEFAULT:
+		/* Default is specified by kasan_flag_stonly definition. */
+		break;
+	case KASAN_ARG_STONLY_OFF:
+		static_branch_disable(&kasan_flag_stonly);
+		break;
+	case KASAN_ARG_STONLY_ON:
+		static_branch_enable(&kasan_flag_stonly);
+		break;
+	}
+
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s stonly=%s\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
-		str_on_off(kasan_stack_collection_enabled()));
+		str_on_off(kasan_stack_collection_enabled()),
+		str_on_off(kasan_stonly_enabled()));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
@@ -394,6 +448,22 @@ void kasan_enable_hw_tags(void)
 		hw_enable_tag_checks_sync();
 }
 
+void kasan_enable_stonly(void)
+{
+	if (kasan_arg_stonly == KASAN_ARG_STONLY_ON) {
+		if (hw_enable_tag_checks_stonly()) {
+			static_branch_disable(&kasan_flag_stonly);
+			kasan_arg_stonly = KASAN_ARG_STONLY_OFF;
+			pr_warn_once("KernelAddressSanitizer: store only mode isn't supported (hw-tags)\n");
+		}
+	}
+}
+
+bool kasan_stonly_enabled(void)
+{
+	return static_branch_unlikely(&kasan_flag_stonly);
+}
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
@@ -404,4 +474,6 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
 }
 EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
 
+EXPORT_SYMBOL_IF_KUNIT(kasan_stonly_enabled);
+
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..cfbcebdbcbec 100644
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
+#define hw_enable_tag_checks_stonly()		arch_enable_tag_checks_stonly()
 #define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
 #define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
@@ -437,10 +439,18 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
 void kasan_enable_hw_tags(void);
+void kasan_enable_stonly(void);
+bool kasan_stonly_enabled(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_enable_hw_tags(void) { }
+static inline void kasan_enable_stonly(void) { }
+
+static inline bool kasan_stonly_enabled(void)
+{
+	return false;
+}
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811173626.1878783-2-yeoreum.yun%40arm.com.
