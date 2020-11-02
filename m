Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRO4QD6QKGQEFWECKDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5FB2A2F0D
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:25 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id a130sf474675wmf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333125; cv=pass;
        d=google.com; s=arc-20160816;
        b=YxptFf/h+AedvfXIOZHDjC36BjLroqa7QlJg+YKWgSvB0KjgdfFhCG9CKHGLNLHi/S
         bKAZh2gpUzRzNVVw/LVRF0s/paVIhzM8zFiigh8wVWXDhH5hi8Xql0jgD28o1ARmkX5V
         i8tCjLRrqlMoRQ28VV2V1u0uGFAlfQgRNfo3O7cqhDTRL2gFA0kgXrAeDf151LgyyBD6
         P9FzCSxHOdGPlvbPdXOEZxd+pUBE2P/6anlF1wcVXbnXUfPDd8gMD4CnDKAEMIIrNct4
         Eb1mb00lNvzsei3QCCDw/6et7qTJMJCds89HTv0E+tv1d0XLBzsSdx/iMRo5ZTJCRnIQ
         Rsww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=E+eIzS1Zka9GBjRGp6T2Hp4UosoNv9wwM+r7xhvDk9I=;
        b=f9n+uoFLx6h2PCfjpCGxKakjvrEzbiVxaZ2/kG+uqexkZC2ECd9kHljR+Ge/tWu8no
         dj5sLHg/YzMW5CAF74fSsGkj/Zgb6sl/gz1h2oUJTu+ziTXp+8rVOsgy7gw7vppuh//2
         L9EEYS77yB0/1WrEljgli7rrnRP6pABZjQpiSHevjnmdQl6wuWQgqBrfcl18nX4shN5M
         5lBSp3WiUgOAm/FBwxIDvoJUPtelaXY4bwC27R+RocoxupVIw4cbrJNdibsetJ4QIiz/
         bMHepnpcWK3u/s7faKXdGiuT7HPiAebQzCIN0nAnY4Kn7pUFrJ6pPk66mBWnNwvT4k/H
         8dJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T32phW7q;
       spf=pass (google.com: domain of 3rc6gxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RC6gXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=E+eIzS1Zka9GBjRGp6T2Hp4UosoNv9wwM+r7xhvDk9I=;
        b=UzkrfVqksq0As6sB9+Njm1fVKQ0gu0Vr4qeF6YXqB63CL1Ul3MHh5Of/uAbEIpZa7t
         Rc/miQvcq22OBsuA5TS8QcRcEvJbWyKxYbNkNZidJ9SVJs+LYBQAXhxogCC7pF0uDUDl
         Pf4QKSxagMY4vnqbMACa2vn47PcbHSJ9/4oy+uwBXOk+SsgFiJWSHnDLUlZxYDd7+WY+
         /FFF30FQFvzicArkCFEhdGsS9vzGBHIm+hCoKslM5YMyePHY6CnKZrFkfwf+GEAq/VNV
         +e06fADwH7LF6KcXpq20+vaHoNN15D2MWVz5Wm02h4j91EuYfY208A6StPRzfNIK7DmG
         nWMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E+eIzS1Zka9GBjRGp6T2Hp4UosoNv9wwM+r7xhvDk9I=;
        b=fZ5MilNfkDU0vRh0O3g4jI3ujt0co6WQEcLezgrszDWtyvHV7mKCcf7aws94UfuGih
         IrpDWqTpK1j7BXelb1YcCoWt1H0fGYsXDmBidO1UKPQ2ALpU5u7Is+lze5fxPeTpPNf5
         5vwuvTIty4joM+5ddI+8J7wuoraEiZJi4JUAa4v5UnytQL0zX0mh9LKFvNdnOmHW8SiT
         Bh29bddjxbchnktwD4+9ojMSFQccd+KqWpAXVK/m7T7xNKfbQ01QGBIOP70ApMqE3fdX
         n49XtkIlLvYdnr6/LYygo68Afp9m2FCXyqnqAm2kDibdcj2NfEmyTbk7CRNZCSnELIvx
         jQSA==
X-Gm-Message-State: AOAM532GANKdSthvtLImElTGMFMyTyfbKa7+sXJqMlnCERPIh2dSjznl
	/2mfVmrEqXG9c4cN2J8ddZE=
X-Google-Smtp-Source: ABdhPJy78AiZYm35t/RpJ69i9PutEjQkOqFV2YT/R8KloxSdaAkEr1GldGTzS0TMkfwSujazHaSP/w==
X-Received: by 2002:a7b:cc94:: with SMTP id p20mr8471920wma.100.1604333125413;
        Mon, 02 Nov 2020 08:05:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f7c4:: with SMTP id a4ls8875424wrq.1.gmail; Mon, 02 Nov
 2020 08:05:24 -0800 (PST)
X-Received: by 2002:adf:f103:: with SMTP id r3mr22734092wro.153.1604333124595;
        Mon, 02 Nov 2020 08:05:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333124; cv=none;
        d=google.com; s=arc-20160816;
        b=IUijk110wFWCRBkHBQqzlbk6npdBnu74oGKo4Q9R/TKbs4/gstV55xm0d3Xz+/wo3n
         JkZZiU5iL68irok9qxa4mkCAC80vVWbGPmVo1v2CYF0qpZOkjQYEQkl+Giqf1PAO2uRp
         vuAU9mTE6ZeWcvbtsdjW4Yf54cZ/gxnkyijARTZUvTpxBw+4gNu1eaI4WuNcE05wWmcZ
         +zICdcHCzAnbUAby+ou8FhO30xdh/3r3Fvu/BlQWlg22zGycKnwswDp8IaqA4j7pdcw3
         0ILGamElRl7RbvFAt6mA49dOgHWt/gQSZAn1nawWpb/GSxjbooyeMykFVfQYPnGW7zGE
         Y9Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d4Yc7AItymQNyKGF4tg/i8f/qZM6X5xLr7PA4bM2pG0=;
        b=OmSGZ7VOHdAbgY5/aFE13PimQnBNH4i5FXw4/dbwV5y51kEohc3Lh/QT7TJIt/fj4B
         qBRwimH3K7TdmDeZ6HIMSZ5SAaiEu8Dg5qqdY/4g3DexSpJcdr0hrz7c0blLSK3PSSTF
         Nf1pm+1cA14uHhcWueDT6R1+LywL9cxQKUX+7eFPnGWU9cFLr382KiDohOnwp7/IvMo7
         4HkVnUZ8r57qX33iTu1jZSHNR4FS5cBeCmeUwHreQofvt1acxA7FpNQNvqDB9lvMKUXW
         RHoYPZ2avnh25VG44swIB4oKtPKZrL4fQZU8TRV1fmqcW6BzQ6Vh2YogSPrp0JhC5Wms
         nyYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T32phW7q;
       spf=pass (google.com: domain of 3rc6gxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RC6gXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m5si307178wmc.0.2020.11.02.08.05.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rc6gxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h8so6625947wrt.9
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:24 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e685:: with SMTP id
 r5mr22556902wrm.340.1604333124197; Mon, 02 Nov 2020 08:05:24 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:04 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <02c3a4f12747cfdd57e75c3dec2c62482e521d38.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 24/41] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T32phW7q;       spf=pass
 (google.com: domain of 3rc6gxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RC6gXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory. Only initialize
it when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I055e0651369b14d3e54cdaa8c48e6329b2e8952d
---
 arch/arm64/include/asm/kasan.h |  8 ++++++--
 arch/arm64/mm/kasan_init.c     | 15 ++++++++++++++-
 2 files changed, 20 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b0dc4abc3589..f7ea70d02cab 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -13,6 +13,12 @@
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,12 +39,10 @@
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (1UL << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
 
-void kasan_init(void);
 void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
-static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b24e43d20667..ffeb80d5aa8d 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -21,6 +21,8 @@
 #include <asm/sections.h>
 #include <asm/tlbflush.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
 /*
@@ -208,7 +210,7 @@ static void __init clear_pgds(unsigned long start,
 		set_pgd(pgd_offset_k(start), __pgd(0));
 }
 
-void __init kasan_init(void)
+static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
@@ -269,6 +271,17 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+}
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
+
+static inline void __init kasan_init_shadow(void) { }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+void __init kasan_init(void)
+{
+	kasan_init_shadow();
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/02c3a4f12747cfdd57e75c3dec2c62482e521d38.1604333009.git.andreyknvl%40google.com.
