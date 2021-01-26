Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBK52YCAAMGQEVDYKRHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 323EA303F24
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:46:20 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id y9sf6817337oos.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:46:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668779; cv=pass;
        d=google.com; s=arc-20160816;
        b=KPv7rWbe07T0hOxkp3cDMRfNwUEiqnhEyHwQf427eGszEafQ+r9b7yPDHzCmjrUEdN
         7TpdBTWc+hGhiNZcNLQck30R6QvwsI9hHbNevHkn4STgjqnkuFFoUksOrYY/BR2UrHox
         I9al1xZE3I1d/KglVvVsyaWzwQtIqUh983Ez3kd6FVx2mpLLVOfyqcpo8Y/IMbMBLnPo
         +SQe6lg0aCq7JtFUiBOLeYizK9RUCUzoekzP1hGi64yAMGZkQO4f0N2rp7jvbin6uIZL
         jloxHdQpETsVdH+5NCkxptjgFavaH9nclikkS372Xx+qTh0ggmeLP+21pCXNZoItq1DG
         ArSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DC9Rpvq16xzo/5zyLn3g+wabuaBaigU8QAguazX1o5I=;
        b=OMnhQZ1VaFtSkXPB9W6+LDsUdS0IBl/idlP47pWxuojCYoryRVgoMAK5d4iK18mrKZ
         h4JRkTFmQ/6AIvsH5ISBlMqv6FRAkGnyn4b9GqwTUUQf9etdC79TDyNjfcLh6WBIR77+
         jAakoV3n1xRFFBAKqn1e3fPXlrd1IEgTAcupJeZwuSXZXhZpWEeyZRYR8vKRUvbDGbqK
         kBaXkukKTVwyLw5NscdfCOlq7J+Y+IrQHuCP9RYLnrlB6kp/ZSluB2aeD6ZyaVGHB97v
         EHghsCeQotsoAoM41GflwpcL7TiqDVVrplT3lWr+tUXe1pEmN4Y97DvSckO+LjEu7iZs
         mEDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DC9Rpvq16xzo/5zyLn3g+wabuaBaigU8QAguazX1o5I=;
        b=rPPfNqlbmLbQmtGxEJf++d76OKmPyyJxLXBgd51ptILAkOdzxnlWuuADg3/ZcpOe2h
         iHTFlIH1+EI9tesPvwVScBiNilA46/5nC8GehLOtwgDW4O6yn0fLKXwwDMvOrOUvzbj0
         GAXe6EO4rEwgmGhoouvLrFt60PtoTHBrnOGuzdRN/FeOuflNf+JPjkV7D/hAfdTARsii
         8ucGsnQJn0V4Unv3pBZSDK5vq67HQvpflFmaRgz0J5FRIdlEL6QWFW/lWmhLQTZkmqh3
         G0lM+VPYDrw1BbCk0OuNbwtK31mYoWHzLDbk5ZlWn0V/wrJh788th6ntBJMLqVuQsZzW
         3Wvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DC9Rpvq16xzo/5zyLn3g+wabuaBaigU8QAguazX1o5I=;
        b=fHLw0kvy5kgcklwgLCY3pqGnFkMcHlock4QiUynOD7A3QJLsTGP9K85oKFoBFaOEgN
         aACyx7AJcz/ox6np8FIvT61YP4hJ0aUt943QGFnFgn9sNghlKuLPkpfsbHUjn1sF4QBD
         iE1busfsjwoSi5aI0MlX69W2osTXAbHWN7DUauFsOZW1j3NbNM7yNfRMlKBH/Expma4Y
         LD23J1ErjW6pZofphY3DRmVLoW8HkxBvndyvxQSk0Bqlf9vFtoCIKV4OBR4/9OZhRAUX
         d2ypRVc0fSpAmqvvcpqkpps3kzOJZffOqf3tvXHAadmjel9Uu7XAEqMZOXTrV8iKlp97
         MV1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eQAvdES1rtyl8oS+MFhnWi2kFzceR7/vx+TTMHR2466MBa5bH
	Qybsz6Sz68aIa2eHUS9l3uY=
X-Google-Smtp-Source: ABdhPJxesfUnXQ4KmWploVY7tRFC4RG0BY9GYmIfF14+vWdx+sOm8qdjYDrqt7BACFpat9ledtzjQg==
X-Received: by 2002:a05:6830:1c3d:: with SMTP id f29mr4204177ote.5.1611668779210;
        Tue, 26 Jan 2021 05:46:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls3486210ott.0.gmail; Tue, 26
 Jan 2021 05:46:18 -0800 (PST)
X-Received: by 2002:a9d:3b8:: with SMTP id f53mr3857030otf.344.1611668778849;
        Tue, 26 Jan 2021 05:46:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668778; cv=none;
        d=google.com; s=arc-20160816;
        b=nK4EXGDmiQH+qe3W3AEfiZPL6fRCslsYBKUQaKA5v/H0BisK+HxdjmYbClcf77xn/x
         fD/hgQPvU+0uLmkEUgCbJmMGyebHu8ZFTxBshsgrXfyvYu8/rW+blTXTVd9GQvl5z1l8
         /Yd0jdx/sg5lw8sofSc3rUaXqq0lA/FjAZiN6j75Dly8HHSUYJEzDvPm+SWg710mdK6N
         c36hqtqkWN82Gv7T0XoXLSkHsd6G5eA2oXArjl10yCn25FauqKOjqcD/fbiKdwe/6ks6
         dh+LsI6OJlWVTGSr6goPIJqjs+KuM+M0NGkQ9iWvjegHk5BCtgBHwVGl9nR0A2yS9iQV
         kgsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=gyVtDtDgH5mdykZqagOMclEBwdx69UTG9puaUbhvtxU=;
        b=gQITZcslu1De+EQxNpD+LXgmbvKIYydOupsZs9+TcKkwVa+f8AfndrE8/5jlQ2yvwW
         KgmkbPuzk2Rc8L+IEk7pU+kY/kzLjMuwj1KOF/LvbCPeVZ3dh7FWfULBmDyMh8oerO02
         JivI+JReTXWKBgWkncvOEyPBP+HkjVu8mjdS3e6TOmMoT3feca3GAO+a1+5VISrtUzk4
         n4ZTEfJu33zKrHbr6gtPUh2Clw4Fr/8leuwY7nolmM6zRrZmm8LnnD1YaYxx6T1yJ5Sw
         istXBZwyaR14YKEKqx6cODETakcimVl7xztZsnx4v0E+iEwxP1lDgnJ9iSzsa+7RE5PC
         MK5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a33si1152122ooj.2.2021.01.26.05.46.18
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:46:18 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8CDAA106F;
	Tue, 26 Jan 2021 05:46:18 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C4CAF3F68F;
	Tue, 26 Jan 2021 05:46:16 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v9 1/4] arm64: mte: Add asynchronous mode support
Date: Tue, 26 Jan 2021 13:46:00 +0000
Message-Id: <20210126134603.49759-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134603.49759-1-vincenzo.frascino@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel after the asynchronous tag
check fault has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.
The code that verifies the status of TFSR_EL1 will be added with a
future patch.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cedfc9e97bcc..df96b9c10b81 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,7 +231,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3748d5bb88c0..8ad981069afb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -55,7 +56,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_async(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index c63b3d7a3cd9..92078e1eb627 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,11 +153,23 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
 	isb();
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
+}
+
+void mte_enable_kernel_sync(void)
+{
+	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+}
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134603.49759-2-vincenzo.frascino%40arm.com.
