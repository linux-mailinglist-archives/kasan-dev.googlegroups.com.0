Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBTOJQHCQMGQEK5U4MHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 13FB8B28D36
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 13:00:33 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b10990a1f0sf59817531cf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 04:00:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755342030; cv=pass;
        d=google.com; s=arc-20240605;
        b=lbOMHe78ciaJ/E6pm+Q+/eJlsYrVPUyF0hbM2abwDUuDdQH3DL72SuQ3zLE7Nx9LNS
         MoczbXTw5c0K6ZoyIjHrYYyNMGeu7AGuZfgqD8RRSFQYXIpu+0r2XZ4DBbwfsyzJBWTW
         UCvi9G1hxRDGD3/gj3YsiPEJrogxp4tG23VWz3ASd3f2xfxh0ozEnS788vkqJfd9HCeJ
         ihQLPDAkPR96Cjk55NpTbNBzXfy2/cfpKFhSHdBipi2Q2//YygWalPy4huuaCZJbxW3b
         MtzneFceW1W4l6UTGn/uBll107j/Juf1AIA9vZ9OMEMKu3rn1H5jXWlSeyN1kZLMWXhQ
         y0jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T06lT88p/YzbZLXicLV0Iru04vZk4wnjFQ2fKYVU48I=;
        fh=O5MK7Mvk0TAaN3g+YhRH8cAByUM/KEyUjvo7vDxOUY8=;
        b=g209Vri+WCckrPKMMpBx6VLYliQ0wSHAAN6n/3tYNTzgeInZ43RcJX/dNmRCBoVria
         377zMJypOc/4dOlDdgDKfse79uUzFReaQAqMIfiMB42oLCtF1YvUzQtzDhSqQT+wKE3j
         cfCiTdIHTFfWLM43AwlIPKS/1XwIG3tHaBShANJZKf8PLKH30TaNcSkJrEH3GWvWwzaL
         FlRwmWjPyfmh8+BH+TDwBc+zt38Arih+hET+FhdcajnuNlCUGTe8ESETNW3EF3eR4bOG
         ATbiLOqbd9/y3+hffz5zjHxp4w1uqkabbZQjxEZn4viMRfhNVdNfEDrakDhLkEJbYnPI
         ar1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755342030; x=1755946830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T06lT88p/YzbZLXicLV0Iru04vZk4wnjFQ2fKYVU48I=;
        b=ML4GJ5Cj4G+t6GPhNQt4O7BRIF2YPgS1epzXUxB6T0jaVKFu8lzUpDeeM+BVB6YvYh
         hG749dZF24NmLdU1528j7NEHsJEqlzXk/90gZTXMAQ+e2iEG4cVtbo1fpuD42DROilHI
         z0EJL5tzDHxlw7t2uqi+VUy+R00mDZxCcxbwCRotTjbGNofrEtCpNxzSOKD2D2cjxRra
         RUccRO+0yAOg99loPxb7YUkJkAqYJZ47AhYXYOSyNLI53XhHVFA6Mv7vOsrvdox0c3aK
         GPnBRcm6CNzR50FBstyUMfYJdRMsPQ9tG4mJdLQWulnvtqWcQhrhPaPeqmN9Vty0uEvh
         /n9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755342030; x=1755946830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T06lT88p/YzbZLXicLV0Iru04vZk4wnjFQ2fKYVU48I=;
        b=vq/LhD8TYSjTAadINtZTE1+85g03Y1TlUeiLiUaPXUSJvw7L5QcL0Q6wB8o8gxbA3H
         DjlCjXn7wm2Lu+6xxqkAljR+sUSJ9X/yo6eQRYax2VEdk+wWnxIjOX5RnSiQV8dDpuni
         vIXbHRGOxYzuEMAxayV1kxqjXSuT8gi1Km2eRsgYKakQ/YKO8kJZVcMZayBdDSt1Zn5/
         ZgqSw8PtnxfPjMyRCUJva0ShdovTkkCFvDjv8LphlJe41EKriC4KT7Rer+46+5JFu0ot
         DEknCCGHNXFiUHtcI12AG4b6N17fO8RRanI8N/oVA6v30m5YtRwXd8dStBmnLEWtmdww
         dN+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUK9AjmEN4drNIQwkfPr7UNbzpvyMaZEklWxe8HfVJOjcwP6g8IvmwuvD+83Jh86w85hLlpfQ==@lfdr.de
X-Gm-Message-State: AOJu0YwjB2QuuHokv3fVoodlIhjZyhrUdq+fq73iTcC9Uw98If3AzWq1
	p7CxWfNdbA1bHCeI6z38YT+zVgC9uDtuj1KxG/CLK7yvLRlnHYisufHR
X-Google-Smtp-Source: AGHT+IF6hzr8RZGfLeCwSs9jZW1Q4lpU6XcqGHCq50TQGVxXGv/28zGvz849n7mvyV/vV6uGeIGoFw==
X-Received: by 2002:a05:622a:540b:b0:4b0:86b4:2513 with SMTP id d75a77b69052e-4b11e109c04mr84315331cf.26.1755342030080;
        Sat, 16 Aug 2025 04:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfyfBqrqNmy8Q6lwlBdB8Aoibn2u3qQMYlEMc26wFMASQ==
Received: by 2002:ac8:5a56:0:b0:4b0:907c:917b with SMTP id d75a77b69052e-4b109adf39als44384501cf.0.-pod-prod-07-us;
 Sat, 16 Aug 2025 04:00:29 -0700 (PDT)
X-Received: by 2002:a05:622a:578c:b0:4b1:258a:3a11 with SMTP id d75a77b69052e-4b1258a3b97mr36772271cf.58.1755342029256;
        Sat, 16 Aug 2025 04:00:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755342029; cv=none;
        d=google.com; s=arc-20240605;
        b=ip25qCv1l3muQftZmfjo2lynCy9NuqVyI04teo2e9AvUHGi6P1bDU/p3wLiRQviNfW
         2E5NdMGzei5RjuEiwFG1Ze9qNKUxz8qWi3BghvCjYjQdjJxXKgpv8aGslQNZ/0xNYMkS
         xkgvUEbIoHyDRVMTX1UPkPVR2mRsPP4E0cBdPlJp9rpvd3z+IVcfHpfbhIcfom44EOgp
         cTZYHILWJfE9H5BX0d7T5Y/Ie0SSF0+MYcnGC9TtgcngNm8SxLH8/rGooIZPuoqtZcJr
         UY+v5OUj/1aUFZMn/0QO5THnWFnEd7WV8ZNcdqFzYFNprjvJ81COb/zYOuGePqjdlBLy
         P/5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8ia9DU+MGlcZGHa2ZVeJrlLt36DEi2qJrxOkhe9xPqo=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=LuzCHtjdRFMp5D9o6TUez1rVevZZPqjPCST0nbKsaP9SYkseNReBB/bQy9RFTTOWgD
         kZofgUFnIY3Ed+jZPqBWRGImG3PpzLhLs1ueUYKnXirVm33j7IM8ddy9/23qo8lCeKR1
         CwiQbr5qz3Y53wZ8nDS4FNt+AAsMeUrVWPMzKqvt+W4P/19aHuY2Hgu+yJcpeXbmtJRG
         WT9PH84WjgCcsCKqFtFyOV/9fraqCfiLtiWL+ruvH6yzzospR06qhnMduBJeOySVDYxH
         wHgYdBSyObWD8hCmHuA2CNAbp9VDoNSgJwKG+djmhLBMKMrXq7Rs66jhEk21Nt7tUkjS
         e7Kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-4b11dc83781si1228951cf.2.2025.08.16.04.00.29
        for <kasan-dev@googlegroups.com>;
        Sat, 16 Aug 2025 04:00:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 88E571F91;
	Sat, 16 Aug 2025 04:00:20 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id CF0DE3F5A1;
	Sat, 16 Aug 2025 04:00:24 -0700 (PDT)
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
Subject: [PATCH v3 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Sat, 16 Aug 2025 12:00:17 +0100
Message-Id: <20250816110018.4055617-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250816110018.4055617-1-yeoreum.yun@arm.com>
References: <20250816110018.4055617-1-yeoreum.yun@arm.com>
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
Introcude KASAN write only mode based on this feature.

KASAN write only mode restricts KASAN checks operation for write only and
omits the checks for fetch/read operations when accessing memory.
So it might be used not only debugging enviroment but also normal
enviroment to check memory safty.

This features can be controlled with "kasan.write_only" arguments.
When "kasan.write_only=on", KASAN checks write operation only otherwise
KASAN checks all operations.

This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
with other function together.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 Documentation/dev-tools/kasan.rst  |  3 ++
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  6 ++++
 arch/arm64/kernel/cpufeature.c     |  2 +-
 arch/arm64/kernel/mte.c            | 18 ++++++++++
 mm/kasan/hw_tags.c                 | 54 ++++++++++++++++++++++++++++--
 mm/kasan/kasan.h                   |  7 ++++
 7 files changed, 88 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0a1418ab72fd..fe1a1e152275 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
   Asymmetric mode: a bad access is detected synchronously on reads and
   asynchronously on writes.
 
+- ``kasan.write_only=off`` or ``kasan.write_only=on`` controls whether KASAN
+  checks the write (store) accesses only or all accesses (default: ``off``)
+
 - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
   allocations (default: ``on``).
 
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 5213248e081b..f1505c4acb38 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
 #define arch_enable_tag_checks_async()		mte_enable_kernel_async()
 #define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
+#define arch_enable_tag_checks_write_only()	mte_enable_kernel_store_only()
 #define arch_suppress_tag_checks_start()	mte_enable_tco()
 #define arch_suppress_tag_checks_stop()		mte_disable_tco()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 2e98028c1965..0f9b08e8fb8d 100644
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
 
+static inline int mte_enable_kernel_store_only(void)
+{
+	return -EINVAL;
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 9ad065f15f1d..505bd56e21a2 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2920,7 +2920,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 	{
 		.desc = "Store Only MTE Tag Check",
 		.capability = ARM64_MTE_STORE_ONLY,
-		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
+		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
 		.matches = has_cpuid_feature,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
 	},
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e773844889..cd5452eb7486 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -157,6 +157,24 @@ void mte_enable_kernel_asymm(void)
 		mte_enable_kernel_sync();
 	}
 }
+
+int mte_enable_kernel_store_only(void)
+{
+	/*
+	 * If the CPU does not support MTE store only,
+	 * the kernel checks all operations.
+	 */
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
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9a6927394b54..e745187f420a 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
+enum kasan_arg_write_only {
+	KASAN_ARG_WRITE_ONLY_DEFAULT,
+	KASAN_ARG_WRITE_ONLY_OFF,
+	KASAN_ARG_WRITE_ONLY_ON,
+};
+
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
+static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
 
 /*
  * Whether KASAN is enabled at all.
@@ -67,6 +74,8 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
 EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
+static bool kasan_flag_write_only;
+
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
 
@@ -141,6 +150,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 }
 early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
 
+/* kasan.write_only=off/on */
+static int __init early_kasan_flag_write_only(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.write_only", early_kasan_flag_write_only);
+
 static inline const char *kasan_mode_info(void)
 {
 	if (kasan_mode == KASAN_MODE_ASYNC)
@@ -257,15 +283,26 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_write_only) {
+	case KASAN_ARG_WRITE_ONLY_DEFAULT:
+	case KASAN_ARG_WRITE_ONLY_OFF:
+		kasan_flag_write_only = false;
+		break;
+	case KASAN_ARG_WRITE_ONLY_ON:
+		kasan_flag_write_only = true;
+		break;
+	}
+
 	kasan_init_tags();
 
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s\n",
 		kasan_mode_info(),
 		str_on_off(kasan_vmalloc_enabled()),
-		str_on_off(kasan_stack_collection_enabled()));
+		str_on_off(kasan_stack_collection_enabled()),
+		str_on_off(kasan_arg_write_only));
 }
 
 #ifdef CONFIG_KASAN_VMALLOC
@@ -392,6 +429,13 @@ void kasan_enable_hw_tags(void)
 		hw_enable_tag_checks_asymm();
 	else
 		hw_enable_tag_checks_sync();
+
+	if (kasan_arg_mode == KASAN_ARG_WRITE_ONLY_ON &&
+	    hw_enable_tag_checks_write_only()) {
+		kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
+		kasan_flag_write_only = false;
+		pr_warn_once("System doesn't support write-only option. Disable it\n");
+	}
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
@@ -404,4 +448,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
 }
 EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
 
+VISIBLE_IF_KUNIT bool kasan_write_only_enabled(void)
+{
+	return kasan_flag_write_only;
+}
+EXPORT_SYMBOL_IF_KUNIT(kasan_write_only_enabled);
+
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..c1490136c96b 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -428,6 +428,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
 #define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
 #define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
+#define hw_enable_tag_checks_write_only()	arch_enable_tag_checks_write_only()
 #define hw_suppress_tag_checks_start()		arch_suppress_tag_checks_start()
 #define hw_suppress_tag_checks_stop()		arch_suppress_tag_checks_stop()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
@@ -437,11 +438,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
 void kasan_enable_hw_tags(void);
+bool kasan_write_only_enabled(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline void kasan_enable_hw_tags(void) { }
 
+static inline bool kasan_write_only_enabled(void)
+{
+	return false;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250816110018.4055617-2-yeoreum.yun%40arm.com.
