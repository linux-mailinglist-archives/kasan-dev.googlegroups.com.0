Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7VN6D6QKGQESUVA6WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id A12E42C1556
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:35 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id ba3sf11362106plb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162174; cv=pass;
        d=google.com; s=arc-20160816;
        b=H1fATDGWsf9Jb/4JKvj5E4adrwp+rmp+H0vxOZxCURdkR2iXxTsvaiq+HsuX0Vh4hf
         ck47C1TnaVvlje3MBHvIJ6IODbkw6GNevgqcTnLbQBaELPvzih0QyG8c5PzJA5tJ3eFJ
         X5bwBKsBq+W5zxjRyI+wMsjSY0/DiuD9WRxjzfjpfX11Jueia3se4iwKPxLfNuMvZ5mT
         FM4PoHv45RlqJVOxVtgvppM1ihbVYAxi/gRd/1cudHmRTwkrJaR5unyFncS98Ikm4ZPz
         wQRfrRfsJtml4xVCMiJ1MKom5T6K003Yas82B56f5shnxtDfRLh2yb5WK9QWofnMMMTo
         uOlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0X7o9PITLR8Dh8n9VkJX3syTFHXE8u6BpxIAENsNAMs=;
        b=uc+e15AK4bhZ9ynGJRRAXtnC5BnI+RoGr8i2Z7zpu3V6QWdBnrwa5u891lRm9Qt7MF
         hdVjkZEdtDYnWLCIM64AUIfk8Ev8LW5LSwP/efpF8e7KIvYdABxAIpaeIVJ7lBq5qvJa
         9KpO5fShRotRi5sr+bRBBRs/60QAtsSOlvGXjGu4blxfKLCjqN6JYnCnyhLNddJMa7Hf
         C3XmvBiAzFY1oOlGiwrPoimOHtFeNaMTQsl9C3J8IlNqeGbVQu4OGbGeaupjmeTXEXJc
         RmUYrdAT1aY8+mEClHTOPiQJ1O44OhBGKK0XvwfRx54dXZF4k6/QfHnFlPIttsbwchaF
         tMwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zjw7Bjb0;
       spf=pass (google.com: domain of 3_ba8xwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_Ba8XwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0X7o9PITLR8Dh8n9VkJX3syTFHXE8u6BpxIAENsNAMs=;
        b=fbh7FebX3YYuVouFwdIykQZFd92LyCecS4W2eTb5bjZnimOj3GK1HNCIU/V8rYqkDy
         FjHttwNVNK0eVqbuh5PgF2XLVvZ6TES4OmVxkpXADTVNobOWxfMqpxopGhpPVUvz7Kby
         4H85edOwN67i59TZ3w5W/rUfxR2dhQadL8YzOg8WS3rqr2JigTx6ucb7FPU8uK+7THbw
         8lhK0hv6RfIgMo7rLYIAc+BE2OnNoYomPSF3Hjx4rHRM081/PTxAhu3ZVsp3zgqJLHro
         yfAOuXRMMOY424yz35/ZydxdEdlBb6b1dncAqj+LkicBRdAqoWI3FAztwsy/JQUDUpQE
         w3LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0X7o9PITLR8Dh8n9VkJX3syTFHXE8u6BpxIAENsNAMs=;
        b=O9ZJ87rphlqcnDXXJqibPfELbxgFC+U1M93iX5x4AYzxXzv7/tgNc4YkqSXNZJWn02
         J6UeimkUttPosGkXYcSz54v/XQiUoC1km0HXRRhflP34iehUcn95mMBr9DQjq0AuRT9B
         kGjEiVp+UmJAzGqnhLTn7Jv73gWL4xH30WXpGn+MSvPR/QWLP28NoqR0TQbBi7Te5iu2
         vJfrULZFLlioHVgjAQT96YKeUmmawMX4CJab6mnNZG04fXupLZHJAfu9zuoozM2zw40q
         IIpvTQ7tZ1C+C9EPLI8rZNz9wS11DS8yh7UpLgrag9C3fO5Vg0+Wzxiwx9+KvojlfpzN
         v58w==
X-Gm-Message-State: AOAM533BT5goKPYf0EKWE+4q2zh6QC8YeqHMR6dRsUCxcjZghI9P6Ici
	EdQN7iVr523PMeEUba3sU7s=
X-Google-Smtp-Source: ABdhPJwYV4oObtZXalgOK1dRCRmJwqvbmK7AVWArlj+z//tdnyFt/7WxcGh9NzDUKTJIzvMhdhqk1w==
X-Received: by 2002:aa7:8a97:0:b029:160:c0b:671a with SMTP id a23-20020aa78a970000b02901600c0b671amr948917pfc.16.1606162174397;
        Mon, 23 Nov 2020 12:09:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls4905325pga.5.gmail; Mon, 23 Nov
 2020 12:09:33 -0800 (PST)
X-Received: by 2002:a63:d5b:: with SMTP id 27mr910422pgn.185.1606162173866;
        Mon, 23 Nov 2020 12:09:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162173; cv=none;
        d=google.com; s=arc-20160816;
        b=TwxOfm58tG+LJV7e9RDdpe+8nd7nxANayif8cAK5OIryjZrZg3IgW7DseN332fLB1U
         iAJgs8gqHto3qOz9RRf9aYVG41cqJ17HaSPt8Osg7IhX9lX6lq/w8SXOJWq97zWzImzY
         ftSe9UGYJUQxOivz1wHNxY5ESX5xMP9Rx7jGx5iiqZIvhu/QuB83YMXCenWWCypokoXQ
         DrO/OsDC7xn15t1I991M2sXeE1XpCaTwYXsHCfLNHLXO+ztdM+rufCfR2SQe2M+eKBu5
         DAfmB1ijRn8pe+E4pmd8Gcog4d254FKSIJidKmmH40aD2sMafqvW4G49V3acxEXbd2Q2
         VvbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=rVMBHBVJQeUCZLewjiSRiYOL9IjQshxMwG3NdWet2ZQ=;
        b=zX5o35zU5EtjoZZzcqsqxQlEQDR3/fvD/Pqu0eWoHVrd9t+mC9o0IWKqoa68aCm3Z5
         2uRllAc9OXw131Yd3hZwvmqpWgI+RLnCD8RZP6Qv4EUM+pTIdvmjLq7w1B1AKjx68Yh/
         yAagANce4bVyXdi7+1DlSXZJ9SAf+/P3C8/tNpvmB/oUGnYykN3kuPSyqLLiFdgjZ8Oo
         2hmBF+QVtuylCUCwcEgTD9VeFZy1OFdMixxc4jSIC7DAjVBKrFwLNR6Q7DbPZ7CiaGmT
         F+JLv3EfP/r1RQQSgf/qe9P9SLfI0BQ+chg5hRW90S7xzRxoellgISdl+pXZPTS0LdKd
         8J1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zjw7Bjb0;
       spf=pass (google.com: domain of 3_ba8xwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_Ba8XwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i22si86245pjx.1.2020.11.23.12.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_ba8xwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 198so15489431qkj.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:33 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:40d1:: with SMTP id
 x17mr1213864qvp.21.1606162172985; Mon, 23 Nov 2020 12:09:32 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:52 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <7352b0a0899af65c2785416c8ca6bf3845b66fa1.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 28/42] arm64: kasan: Allow enabling in-kernel MTE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zjw7Bjb0;       spf=pass
 (google.com: domain of 3_ba8xwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_Ba8XwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
feature and requires it to be enabled. MTE supports

This patch adds a new mte_enable_kernel() helper, that enables MTE in
Synchronous mode in EL1 and is intended to be called from KASAN runtime
during initialization.

The Tag Checking operation causes a synchronous data abort as
a consequence of a tag check fault when MTE is configured in
synchronous mode.

As part of this change enable match-all tag for EL1 to allow the
kernel to access user pages without faulting. This is required because
the kernel does not have knowledge of the tags set by the user in a
page.

Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
similar way as TCF0 affects EL0.

MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
enable it as part of this patch as well.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I4d67497268bb7f0c2fc5dcacefa1e273df4af71d
---
 arch/arm64/include/asm/mte-kasan.h |  6 ++++++
 arch/arm64/kernel/mte.c            |  7 +++++++
 arch/arm64/mm/proc.S               | 23 ++++++++++++++++++++---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3a70fb1807fd..71ff6c6786ac 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
+void mte_enable_kernel(void);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
+static inline void mte_enable_kernel(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 86d554ce98b6..7899e165f30a 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -129,6 +129,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return ptr;
 }
 
+void mte_enable_kernel(void)
+{
+	/* Enable MTE Sync Mode for EL1. */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	isb();
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 0eaf16b0442a..0d85e6df42bc 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,15 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
+#else
+#define TCR_KASAN_HW_FLAGS 0
 #endif
 
 /*
@@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x5, MAIR_EL1_SET
 #ifdef CONFIG_ARM64_MTE
+	mte_tcr	.req	x20
+
+	mov	mte_tcr, #0
+
 	/*
 	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
 	 * (ID_AA64PFR1_EL1[11:8] > 1).
@@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* clear any pending tag check faults in TFSR*_EL1 */
 	msr_s	SYS_TFSR_EL1, xzr
 	msr_s	SYS_TFSRE0_EL1, xzr
+
+	/* set the TCR_EL1 bits */
+	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
 1:
 #endif
 	msr	mair_el1, x5
@@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
+#ifdef CONFIG_ARM64_MTE
+	orr	x10, x10, mte_tcr
+	.unreq	mte_tcr
+#endif
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7352b0a0899af65c2785416c8ca6bf3845b66fa1.1606161801.git.andreyknvl%40google.com.
