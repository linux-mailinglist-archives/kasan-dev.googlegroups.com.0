Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBN6F5WFAMGQEQ6GLJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2373A42185E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:20 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id d12-20020a1c730c000000b0030b4e0ecf5dsf291485wmb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633379000; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRFRrH7WPF9yzZPWZIoM3p/SotDXWdsp0jsRntjEQNzK788ZHwQAU9qkDdtrMPJNRn
         l3c8XpC/Su2v5udIWOu4YqI2GOxa+axbBrilnVauOnKpuha80EsMBK4YV1ozAPfIE0AD
         /2NSsYKaiMpXLQym7xMreWpo89xUY3Mkr8OXdeFj0VRA578IFqqMPMcDZ8uqwPkneXPY
         X1uw8/hoz2/XgtxxOoFfTCdD9b+fR6DEHkYYGbLA1lquxt9+c0R0LFg1o0XvZh4LUjoq
         Ih7LnqBhQnMBVbcmjA/nUNj3X7yvjIKMh/cd94zdLY7FBwCujMGN0MR+4xECNgmAh2u2
         onaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dc7V+4WU4blgWsC8Bd0oTJwWHcZD0d4sVeYaArCmkFA=;
        b=rop70IIlgMHuu1Lm7mHASA7pBbrnao7EMmpkIoH1CxSbrOBfN0XXbe54EKsL+b9nWq
         X3LnZtZV0IxaYTAkO8gcWL8K6zH/OpRkcf7bU3ejgTvsxjBAL7NJIO/pCpCEApK0ms6i
         A01xiyZ/mVgT9CSXWksYBSWWq38JLeB3oqFuhfaYfxcHVMH1WhD4RnGJT6xnoYm3nNc5
         M7b5NJ+Thki9B/xNaYjxVg7yDUqG/tkKI/Xl7t3JTN9tg4XjDWFlHJZyqBYa1hM3MvGL
         RgIspWs8VDC3jy/GP6t/WmuvHzPdH3r5lixQM9swHy4t3DP8FH9OLGjND7mC/UtHA2Fl
         ZhuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dc7V+4WU4blgWsC8Bd0oTJwWHcZD0d4sVeYaArCmkFA=;
        b=PThT6cajjzETVFYwRrCpuHkJa6fryQcjNjqrpXj+BHrHy9q1bV6hi1MeSsKNTl/L1O
         B/1EFlsNL3dl3wPzVTEez4HtIDJouyi1fR8aUEDmQ41wsudKlLbA9xDJNiE8SFac+LhE
         Qja7j1xYdNXCOqs+60fVtv86tPyHoxdVwPf8dbbYNXNJA9d+WMD7caV2vR8Y+KrJNrWT
         +DPyq+9zoxkDj3DKC6mo4ExZg4HIVSj5NIYo2jpPGuGHuPUu/QqVxFQmvrbRxhJRoANP
         sDC2n6GP70QUYL22wNng8NONMWwXxnRisev9WMvwkuWbTK6Qn+PQ/9uDlClrGkYQCpDk
         GGiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dc7V+4WU4blgWsC8Bd0oTJwWHcZD0d4sVeYaArCmkFA=;
        b=tGn3cyZHm83eZKr9/tvjUnXkpRC/DSmHwW0YqAQhzNFo8pGRrxruSYwK87zVMv+oiB
         FxnLgjHxYKKKUTjdbdeCI4MnNHCrjPcYbybNLpWRrKvfSuTKHvvwV+LQqFA05b7bQYdW
         sElNWJL9gNtq/S5Li7JNobjlZkgQsUna7G/jJZcOags/+zNU5raoZbQC/JyhtJSYQT/z
         ZtasWHEU6a3Dk6gP4m0M4uhxRgabXOaThN9Xyj/ceFRi/biQmljF4Q+glLX4IxKiW0gH
         nc6T147Yol0ZAHdlJhVDxLWrJ5eMAAgYRN1VE8pIhZXW+tlcByfxGSmOLgcqeIKzdBCp
         8chQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dObvEeefmwWoKAKHVi2gsPKAHWrXI7BM/EXcuVcp6IHZaMk4g
	10YaB5eHVJJ7dgcr6+au8T8=
X-Google-Smtp-Source: ABdhPJyH2tKrVHm1MGuyUgqrnoR3dHA3qQYpBsJ+gPiqjs52X9lARFD0QgBVwL86u9gU+OBEa7ZgYg==
X-Received: by 2002:adf:f946:: with SMTP id q6mr16693474wrr.437.1633378999894;
        Mon, 04 Oct 2021 13:23:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls268646wra.0.gmail; Mon, 04 Oct
 2021 13:23:19 -0700 (PDT)
X-Received: by 2002:adf:a402:: with SMTP id d2mr16694022wra.266.1633378999090;
        Mon, 04 Oct 2021 13:23:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633378999; cv=none;
        d=google.com; s=arc-20160816;
        b=z90rKI4kyrOpAUJnxQEnruWJri9fAFC2jLWt9wXDJbVSv6UeX0e/UuEUuq2T6NhxJw
         XH687lEJtfCSeuocpTUclyOc6qr0OdrFEbQNbIizPkdDBVK5SdVYd3LqFw3fI2cRd7J0
         f43bbfXujKsO0NmO3b2mwjRoPDKC2jIaPMZSX7buFOWD6bK+DGSvZbDGG4PKpo1R/jTK
         +rzzT/QTJl87NzNR6xMk6i94vUFQp6C2dQQVQF1zvizZxqFxYwe/xCN1khHEKUTyCjCr
         8XR2PhC/x6YN7B8k8kDBR9Dfn7IzkqsaJCHUaluBVXlf+sjfuxpVMnNgrj3w8E4WnDDz
         +Bbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=uKETvstsIU7otGNCWLQwqMCZS2fEN/AusloL76ML5ro=;
        b=Ya0ggI1hOAfmJ/sXWt2lF20FLyvUBtqxrtIJKj3R45vvXU0BCAc5F07VmS1474sy2q
         UWCYXMjzTISMVSPxqarr12cYyGm8eup3wX4JRYCZoYRsVs5T/UcXunLDQVFYy1JpYSdD
         6zTaEJ+1Rr8pzabwOB+aKD76cW8uhHuMpyVCkwMzST0LJUtR3rNVNb9BaLzYn4W0ce/i
         QwpHYJFNE6OBibw2Pvj9Bt3QVF1VProtauYEC2NPZTW2JQb3nmwoIbRyUf21QaQ6e4Sf
         HKqj7skKRMOXitYcTtMFXDQYlSPlH1/mWwDaDRxHqT1gvWJ3lif2L5yF1JLGvcam5aS7
         KQsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s194si430135wme.0.2021.10.04.13.23.18
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 498D9D6E;
	Mon,  4 Oct 2021 13:23:18 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 61FB43F70D;
	Mon,  4 Oct 2021 13:23:16 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v2 4/5] arm64: mte: Add asymmetric mode support
Date: Mon,  4 Oct 2021 21:22:52 +0100
Message-Id: <20211004202253.27857-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211004202253.27857-1-vincenzo.frascino@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

MTE provides an asymmetric mode for detecting tag exceptions. In
particular, when such a mode is present, the CPU triggers a fault
on a tag mismatch during a load operation and asynchronously updates
a register when a tag mismatch is detected during a store operation.

Add support for MTE asymmetric mode.

Note: If the CPU does not support MTE asymmetric mode the kernel falls
back on synchronous mode which is the default for kasan=on.

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 +++++
 arch/arm64/kernel/mte.c            | 33 +++++++++++++++++++++++++++++-
 3 files changed, 38 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index f1745a843414..1b9a1e242612 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,6 +243,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_enable_tagging_asymm()		mte_enable_kernel_asymm()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 22420e1f8c03..478b9bcf69ad 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -130,6 +130,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
+void mte_enable_kernel_asymm(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -161,6 +162,10 @@ static inline void mte_enable_kernel_async(void)
 {
 }
 
+static inline void mte_enable_kernel_asymm(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index e5e801bc5312..b6ad6b861c25 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,7 +26,12 @@
 static DEFINE_PER_CPU_READ_MOSTLY(u64, mte_tcf_preferred);
 
 #ifdef CONFIG_KASAN_HW_TAGS
-/* Whether the MTE asynchronous mode is enabled. */
+/*
+ * The MTE asynchronous and asymmetric mode have the same
+ * behavior for the store operations.
+ *
+ * Whether the MTE asynchronous or asymmetric mode is enabled.
+ */
 DEFINE_STATIC_KEY_FALSE(mte_async_mode);
 EXPORT_SYMBOL_GPL(mte_async_mode);
 #endif
@@ -137,6 +142,32 @@ void mte_enable_kernel_async(void)
 	if (!system_uses_mte_async_mode())
 		static_branch_enable(&mte_async_mode);
 }
+
+void mte_enable_kernel_asymm(void)
+{
+	if (cpus_have_cap(ARM64_MTE_ASYMM)) {
+		__mte_enable_kernel("asymmetric", SCTLR_ELx_TCF_ASYMM);
+
+		/*
+		 * MTE asymm mode behaves as async mode for store
+		 * operations. The mode is set system wide by the
+		 * first PE that executes this function.
+		 *
+		 * Note: If in future KASAN acquires a runtime switching
+		 * mode in between sync and async, this strategy needs
+		 * to be reviewed.
+		 */
+		if (!system_uses_mte_async_mode())
+			static_branch_enable(&mte_async_mode);
+	} else {
+		/*
+		 * If the CPU does not support MTE asymmetric mode the
+		 * kernel falls back on synchronous mode which is the
+		 * default for kasan=on.
+		 */
+		mte_enable_kernel_sync();
+	}
+}
 #endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-5-vincenzo.frascino%40arm.com.
