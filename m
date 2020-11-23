Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWVN6D6QKGQEFLRWG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E1A2C1548
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:58 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id m12sf6531157lfa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162138; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDuI+Q1iW7KjYFBnUll1L1DCHii3g2Qdcbl291FnwMCBBITuRWrPTER/FSQRihZ9eB
         6MnYXRSZ4M3aDbTH8q/dkIKbSVGbkuTLVMNVFC698r8NsSjvK+beac/kStg5+/fZKx7U
         1U5Jk4DQv1c5s0EdvwDypp87putgPMAP9zgvVhvsDFd28KmG5CR2Q9/aINURBWLPkIQD
         bQhL4dtRa/ZAoil0EPi6oMr2wfDxC84hKu5vrXs5mVpnpnRtVxPubuhdexo6ngNS5r0t
         UhBzdwEJH6BJm2JIaYrkX/QHWAIleNLaeNwKzgRE9ER9w3j5tDNtLZXD/1LsxuAZxMJp
         LeHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vzf2/uhBp388/DL9pqpo4GHa+beAwsWsMLEvaNMT550=;
        b=r6lSAPkUsm0a7S6MH3g/31kJn3xPDKGT/5jpuGZmVyMpkOzx6f53v3kh4miZ43k9zg
         RRBG1NyYmNyTNildP9yvVu3V4Oy3NgIFe4/Qn7IZ0vqRGUS2j56RlAULKfXvylxlwVTX
         UTAAvtD6I5tfdPRZMkSBWsiO1Oq+aPTQ/tkCQrt4B3N0lqPomTKhLR+bMFvRleyn/OFA
         YWq9GszeBU43aRWArVita55sk+uC9Zdv4q3n6PhxspWtYAhxsoE0vMRuEEREhjLJZuch
         SopE2k9CWjuw3U6YYSnJUm8TSum5YHl7OwfQaKZc0yBTauIqVKAtEuBuLShlab1bHY5K
         WHFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WUct1EW0;
       spf=pass (google.com: domain of 32ba8xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32Ba8XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vzf2/uhBp388/DL9pqpo4GHa+beAwsWsMLEvaNMT550=;
        b=GY+F/Oqyrml63EkyPGR77l3dCbgioDpU/1BTXgjfSbqqNC3ayXrH/nMnuMgzmDmplb
         uo3VKjVtds/8ASRwUpMRIg6JEULvFF00s8Oz3T5qrBWV4C0xKWSA8S8BzxNcX2m7CrY2
         xaQIH61TyLTUdycQbi4e4CZMtXxo7OmCflwLpH3qk2TjSOHndtenABrshLM//inp+wmR
         ekf22P57InEPaFB438kVjcPXF81frIzG9OCVAcznBuPdQnuKmUCFnEhaHUqgulZ/xnrC
         pkfoQ5XDuvPABc7zXHX1fAfcGxV6oKLudYuLuhXoOI5yuCAs7wIlV/fq0rZEPY1iC64I
         2wqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vzf2/uhBp388/DL9pqpo4GHa+beAwsWsMLEvaNMT550=;
        b=d/UenMcPy1SofVrqkKDIqaNhMz2927N4gUxE3vNDQ++I3VB/pIgHNMmbIkcgOEd43T
         EICS8pOH9oBonPVjc2Rb2C/NLduOTB+NlNTkWttl2/D2Fb1bMT9QdXjt/4rKd3qFfCFf
         X5IcAhefs/rWr/QGpLpPm3khjwKhbLjD26pqiuKkZgmXfUWOnpCL7URW/uesxWrN+/+l
         pi1AAkmHpymsnqN/EwXMJ/3CKX2aQm5+kNYZpkmhxAp/V/gtI0ANLPCtlq8owWeZ/lQa
         g9MT8Ab3D8WOj2YBGHP5xKdnge09J0lHme73EjZ7hB/+EIqeBF1cOwIBTuQILAVNQOgG
         s+/g==
X-Gm-Message-State: AOAM531MSKAYIWlgHLtvMJ/VF1n1NEXpd4PJ5bJXHMiZfsVrfDgA4htU
	YjIZLlMaEWKyTQd5iZJiwaY=
X-Google-Smtp-Source: ABdhPJxEZzaRgKLt1cSJnS4R5jB6s5ILR3SW6yeulZhN/cXnJBInMA8DNRr1eGjmJnpIrrTK4P7MiA==
X-Received: by 2002:a05:651c:119b:: with SMTP id w27mr401160ljo.189.1606162138377;
        Mon, 23 Nov 2020 12:08:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2ac6:: with SMTP id q189ls2237698ljq.9.gmail; Mon, 23
 Nov 2020 12:08:57 -0800 (PST)
X-Received: by 2002:a2e:bc1e:: with SMTP id b30mr458795ljf.241.1606162137330;
        Mon, 23 Nov 2020 12:08:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162137; cv=none;
        d=google.com; s=arc-20160816;
        b=alIzHCjvS855xgavEelK/FjMZo7FNpMh6UEbt2YxrgEd+55UsjmlSOHBHCfA6aFBKl
         Nr40NP3tqVOSMX10rDjqsW4JuzZLCclHxXhhSnsNzS9qpWK+VhlI91dGbmktkjJXNjWd
         3BansfNjU4xKaLZvB/3qJe0/THgYpD/4DMFNK+rRf0MSUHszzXstVLIRkueA6ychMzha
         EgdPOeObveiKX4HJMJ1tWmsH0+gPiYpAG83r6Fdx0bxvQBbIDOPACbIziixtCCyPZoJn
         B/pPntEwINFtQxnLsvTQO2jhGrSaw6L8QwDPzbCmamnTsK/Urp1Fu08g35sZQJy2eIcT
         mXhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Cs2ewUzarS5QIIwyBJDQZ4khSVYirNCbxYZ99CeZWdo=;
        b=WF6vUhjRf/qTBAhem7HMdUaY3K2PPcKEQ44+OwJBT8jXkrjnnaUMaEd8r/LrxRqSC2
         xiy/Nxwvo+PRBev2oelTYkjR5F93HhIEh5mQAJHeMIYzkvKm2ywDlBMD60ME9xA743+H
         J7d87d8NqeAEvIanzP+OmyIpvm4SEDKqyi/F8SpjLdrye7nQUXlUjqz4gQF8zHKY4PgY
         y2FUQua6M4Om02xoS2edgIwiOBROPDa/cuPsqsmdCkVSaNEDbLt+0d2ii5j1ctU4pupH
         y2LFtdGD0o2WdHzviZARW4+6u8BG+qWXiTnWTBkhasClJ0eGFP3t4DwoNbJr7QwDYnWa
         4GLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WUct1EW0;
       spf=pass (google.com: domain of 32ba8xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32Ba8XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o13si432562lfo.5.2020.11.23.12.08.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 32ba8xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u9so105984wmb.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2cd5:: with SMTP id
 l21mr605185wmc.182.1606162136904; Mon, 23 Nov 2020 12:08:56 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:40 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <29a30ea4e1750450dd1f693d25b7b6cb05913ecf.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 16/42] kasan, arm64: move initialization message
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
 header.i=@google.com header.s=20161025 header.b=WUct1EW0;       spf=pass
 (google.com: domain of 32ba8xwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32Ba8XwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
while the generic mode only requires kasan_init(). Move the
initialization message for tag-based mode into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
doesn't use any printing functions; tag-based mode should use "kasan:"
instead of KBUILD_MODNAME (which stands for file name).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
---
 arch/arm64/include/asm/kasan.h |  9 +++------
 arch/arm64/mm/kasan_init.c     | 13 +++++--------
 mm/kasan/generic.c             |  2 --
 mm/kasan/sw_tags.c             |  4 +++-
 4 files changed, 11 insertions(+), 17 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index f7ea70d02cab..0aaf9044cd6a 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -12,14 +12,10 @@
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
-#ifdef CONFIG_KASAN
-void kasan_init(void);
-#else
-static inline void kasan_init(void) { }
-#endif
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+void kasan_init(void);
+
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
  * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresses,
@@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
+static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 5172799f831f..e35ce04beed1 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
-#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
-
-static inline void __init kasan_init_shadow(void) { }
-
-static inline void __init kasan_init_depth(void) { }
-
-#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 67642acafe92..da3608187c25 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 64540109c461..9445cf4ccdc8 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29a30ea4e1750450dd1f693d25b7b6cb05913ecf.1606161801.git.andreyknvl%40google.com.
