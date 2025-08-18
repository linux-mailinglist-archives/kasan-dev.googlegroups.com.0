Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB2NWRPCQMGQEJOMMDYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BB97B29B3E
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:51:07 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-244582bc5e4sf45425945ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 00:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755503465; cv=pass;
        d=google.com; s=arc-20240605;
        b=PH2OjXLHkasYxulRyDFgOO31ztyK5qRWAHYYOTBcmYYoca8QA2vKpoVZq1XsiSyCXa
         pUZElb00mYogbLQB783d2+cFGOprAkWa2HmK+6FlVzMgqUvVa0JL5D2mbOnHNeYrVE0t
         Lkr8JwckcHgalE+6hlCiQ5JSqc9SYGdHp3+fkCS74KjNgPdT/fopXA0q/JVAhGrPZzVo
         p4QB62UJs2v/Ze0HnRhYdDo0uRgKT2P4KVwBsr/43n9hgXVAARGAlbxLGjxAkc+CEXhI
         Ucs84pWYSL3vjE+N6yQ84qjaUhAP5hjoL6n+MOev3SxXhlhMXgdknkv22tL2X31be3/z
         yeGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mC5gAestTOulav24gT95Bb9d++VAJNX9b4tbkhAm7Ik=;
        fh=ibSamE2uxEkbT0ePSoD4+/410+c2znxg/KNwVR3/u94=;
        b=XNIZiR8UX1lc+FwgT7DQcPfqXgdsihWASmbo/aO4PIHkoU6Ryxop90N1S6y4DeaDIa
         2zazz/cS6idekICpRhPUguwPAC3gPCb50oj0GkbzgG7C9Kofi1iYeKTBRqpEdIkqRvQD
         NknD5povsZ9z//YKsgCbNVZOCgPgrFBsUSuKNIL3zitRRwmtqpy/6VT+NrlySBY36Uo3
         v6oUl2TnemBSy3bU+pm1DBahklub1RoVQFT57ih0fWBvw7CforwY39LlWWmeDhkd1AH8
         vDx8ZEXFAhkwoekhxerImcQhYcJXZTuBggmYJShBJ4z1xu80t1Wph08qVaxODiRfL7PB
         iG1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755503465; x=1756108265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mC5gAestTOulav24gT95Bb9d++VAJNX9b4tbkhAm7Ik=;
        b=v+nZn3/A5ZbcxHhHgkZ0HZtroWKR56KCrY5AjFbHS5DLnyoXPuOdGuEupeLXPQamJx
         HYqLZ19nFkSqKpZQ0oNN4JvNXxv0W2lcJ+7VsT2kjyNWSHh9BYCP4IIPlMt9EuhMEuF9
         OPuYLjDIVW50d80EpW0Mehv1+KPMh/4aGJnHgEWXZ+98ZQoxhSSHlxCsxWYbakzJgGAE
         8Fj/NcUuY46rTIMJqZwSd4Y0Puww/Y7raMOBumysH+c3gC8mAJ01Pd+1qKdP5TpOBlJ5
         VppP/NdCeYfJm2T9QnlrsIP1hqMQezKLJm7ua0cmD+WCCI24KdTCi0V8sTHU8VN/CN3K
         F7Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755503465; x=1756108265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mC5gAestTOulav24gT95Bb9d++VAJNX9b4tbkhAm7Ik=;
        b=vbOfv0TaGetTR/hooznR8Hs25ah/pKFHuVCfRl5oNkWNxVDc2YowTWigr8CwbMFyU5
         SH5RhHGnUyMdiA+vuBN41oEC9up4UoKU/1xZteet2K/m7DyK9AmeSFx2nN82I1N8vBrM
         BIUmX5LL0YV6l8F/yyfYHo+VmMYiQN7CffYj7ZoBJUPVW17wkNFmHj2akmWnuiZxtYj1
         dK397v8FENkN8TGg9NmMfBZdQW55dILXjBeO2zcfPtmz+E+lY+H7+xMSpoXhDncEoBpf
         eklCSoxxDcedqwLRp8c2lKnVwjGiE9LvoADUoVtwlA5CJlZtVccXLVBTStwqfO6aaJ81
         h2dg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlwtZQLdWXw1FhoNBbvC2XDH2wm6vpx+jYbff09yvD/LEop7nSTJxmk4jMCFo+kE2kIsyDyg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5TTKdabbPINXH1mOyfaa3J6ENh+kFPsKwlSTkYbRZNi/mQacX
	gtD2+cMOnVdIuSOQ5QcujltWxnGQLQ5krp+OesylHWB+66slcMoeWEJo
X-Google-Smtp-Source: AGHT+IGU4/oVorOlIExnuDkbpCMKI/Rf9FvJmOchh4Quy/n/978Ud0ap/aeI7UZlC/SB6kNSSWU5NQ==
X-Received: by 2002:a17:902:f612:b0:242:9bc5:319e with SMTP id d9443c01a7336-24478feb6e1mr102974495ad.54.1755503465354;
        Mon, 18 Aug 2025 00:51:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZtCNDUCJk8lwL71In+GsiMLWfZxSEnOjJOj5357j0Ow==
Received: by 2002:a17:903:144e:b0:234:cc1a:5845 with SMTP id
 d9443c01a7336-24457414eb5ls34905465ad.0.-pod-prod-04-us; Mon, 18 Aug 2025
 00:51:04 -0700 (PDT)
X-Received: by 2002:a17:902:fc4e:b0:23f:f074:415e with SMTP id d9443c01a7336-24478e3f823mr93080005ad.14.1755503463976;
        Mon, 18 Aug 2025 00:51:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755503463; cv=none;
        d=google.com; s=arc-20240605;
        b=Pc30sGY+b8tpINqufmMXmrNZWQwcIu8XxZzFfzGPn+v0GDxXR+R0HFSyc4+gEnbnnm
         +x/vNiF6M8W9/q0cH3okUbGPyVAyvAcWSGRcl12/UPRw70SlFSp1we4CNeKlhq+XmImo
         tUPJQbB2qTNYoRG3MDiMe1rnU6bdf4ujCvCIB8kiOWNlmW+WRi83cnDsg+HkxaAV6X71
         W1T4j/LbhYWCctSo/Vw74b278JBNsbUZGhsHJkD73ETcuYRATpN8Un3ptIWWyKqnjWvL
         MUh46ZEaGlXOMadaJBIaK0RsT51Dk/nGMvsjEFEGeapmNA8Mhu9vIC9/tdsJEtUzJOh3
         ssvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wZoCPEA8klgLelB2acKaaIw26FDOCnWuEPdoV2gnhKc=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=DrRFapA/m1WIRQJR5bSkctGlIr3dn0n6PSnJkJ0LD9acCiPRomr++64h75sc9V8Rvu
         xlZdJ+a0f/2cbkWUb1vhOMM/glUBWWvkiEKiYRnCE1RjEqHIEYLDRf0+Om2gPE8aQkIx
         tH4xe0eT7G9i1vGpBcTIs4hZiAqtr0p1rryrnmQeoznjb4gugqcEYyvZ112EYIAxoGMu
         MzjGgJJDjoosldO5j4vaDA1Oj3JXI238d9MrppjNH8F/85IcXuh/iQhOkvKZSk6pVL3C
         hJGHdxBN4kRNtWjRmQICsLvbQ06X8rc7tDpFFVZDym2XDcJc9/GtN2w9xMUlnUvXvyTp
         O4Mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-2446d525defsi3760515ad.6.2025.08.18.00.51.03
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Aug 2025 00:51:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CB0112659;
	Mon, 18 Aug 2025 00:50:54 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 204BD3F58B;
	Mon, 18 Aug 2025 00:50:59 -0700 (PDT)
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
Subject: [PATCH v4 1/2] kasan/hw-tags: introduce kasan.write_only option
Date: Mon, 18 Aug 2025 08:50:50 +0100
Message-Id: <20250818075051.996764-2-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250818075051.996764-1-yeoreum.yun@arm.com>
References: <20250818075051.996764-1-yeoreum.yun@arm.com>
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
index 9a6927394b54..df67b48739b4 100644
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
+	if (kasan_arg_write_only == KASAN_ARG_WRITE_ONLY_ON &&
+	    hw_enable_tag_checks_write_only()) {
+		kasan_arg_write_only == KASAN_ARG_WRITE_ONLY_OFF;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818075051.996764-2-yeoreum.yun%40arm.com.
