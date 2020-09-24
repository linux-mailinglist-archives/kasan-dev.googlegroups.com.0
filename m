Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3WFWT5QKGQEEOLHUBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9425A277BD2
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:26 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id v5sf280090wrs.17
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987886; cv=pass;
        d=google.com; s=arc-20160816;
        b=NO9jzK7AMBtqOp45J3Jm9Tt9I2S8VPwjfPOWfwPTYhxHPw6i+cH1kC7jt+nwJKWPM0
         tGBI9E+lbKEumR1fcCiuOHa0XuD6qdNVlAJQwYpGKynJAqm/CMkCtOChX+zRcZEnTkdV
         ku2xXts0qWO9hRmH0/e0ShPrNVhuMMh7ZRDFj29P4BS2KGqHOLV3qGrg/r5vOAe3NwMA
         Z0j/khALmlY6ONBd4qQ4BL/49WFtNZi470eWnTVrT8bai2oJLOIiHSp41caBum5ramkj
         QR6VScercWqv9ZUenOuLRLv1bklNtgO/rIANPSweXSm4qKgeiEBWrLw4l3a5Cl5t+0rs
         lthQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XmSQikFQ/dE3QI2RBeAnIoqMUy1aQvlAhlOQQkwyjEk=;
        b=bW/+V+nt+NQiLxRZ01EykD01OSJ4bDCB844nSGFzUWnAqDOOfuVt7NQX546gGFaqB+
         Xc5hTz4+730CqamW2uG/WU4C3tyLOE+LG3BZcD2pNlB4sqgr350u2vKYIUENgWFDday4
         G5CMfY9Y5e/mpl5okowjzbOqqKala/aBz8Hm45TLOBopYHOK2+Jlk4qeovGcSDVWhOLT
         yhIg1Tkrm9IH7Y8s5332e6Wld1JuSNZSc6MqBhlR00MpfUsd0dIMRrBFO1HR6PYtohnR
         m7VBSsPkRrmhdNOk3JWfmcKaEGrbn1gorhl2RBMjqDCI+3uwLFXmLEdLVVqnu8Q2mPPx
         CwDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pjdl2utZ;
       spf=pass (google.com: domain of 37cjtxwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37CJtXwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XmSQikFQ/dE3QI2RBeAnIoqMUy1aQvlAhlOQQkwyjEk=;
        b=GIcQkIb2zRCOC8PZ9lE0i69B4GAJrTUmW66lF7c2+wwp80mJWYQ7F+pK04nHBKt7AL
         u6Wr8a7iiqD0RjPIGw/ETeoYDW2p7VvCmW/VMAHc0XeV5ryQ0h/LskP0oS66PEBIg7UR
         8cFdoQ3xpSv/BTLftNaGn6VbOq2N+iNYy9Gg+XNFjHSQibrAMtXGyPLhnozGV6Dh3PWU
         n7oE9+sv2HurUJRBUiTxYm9iDtjh74ACGMUIjYmlPGoyyBjPJ0bUYHss11AKJRTp60gC
         rKHs50IszUJn8OUR49SMO0EGzNxEURwxiaCth914Chxvxbj5hQYYL0DDnR17GLyhE918
         6itg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XmSQikFQ/dE3QI2RBeAnIoqMUy1aQvlAhlOQQkwyjEk=;
        b=XN/ze5qgI/UHlxuilHIFt/IOLrr6cQMdHWEPsE62zWvvCSZgigEC+4sd7WCIykF+ba
         mF4ssy14FhDS9O+0sqhTcK1+ikUjfFM+0LrsOyLIx5jw7WivuGWa9/R5cDdmF/J7vKP6
         IuVlKVS+FgS/9hMd3FjCZ97GUGtxfMqb6AHASyQfDng7APkbRMs58BgdUvsyImR8sQFO
         GJXXkiySr6U1yKky8ttEcvIfQG/lgMO7zuwc34TL3sGvBYic6YEm5qxwPkQrB9u/yf94
         GsdRRDfLTvTOdIXmETTPEt807n6Vew9hoVLnw+CgsC6ftvNQeAym9wf621M/lh+0PziY
         DqXQ==
X-Gm-Message-State: AOAM530q9PgGbr9BdH4qxa5xuBffLCZn7codN4sQUuKp8q55tW2DIyE+
	LiCyTUCL7DxdnhA8ON9DI24=
X-Google-Smtp-Source: ABdhPJxGsffH6rtrWy/c+ZgJg20J/mukJd55gil/HVO76VvdzgRWQc+IEM0n3k7ychiMQKq6XA+46g==
X-Received: by 2002:a5d:6404:: with SMTP id z4mr1190361wru.423.1600987886302;
        Thu, 24 Sep 2020 15:51:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls1055153wrq.0.gmail; Thu, 24 Sep
 2020 15:51:25 -0700 (PDT)
X-Received: by 2002:adf:c5c3:: with SMTP id v3mr1183869wrg.205.1600987885328;
        Thu, 24 Sep 2020 15:51:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987885; cv=none;
        d=google.com; s=arc-20160816;
        b=j6MkPggCgh5wZyGS0YNOlbQc9d/Yp+ObEYAL72TlU0ig+rmpiBMpEpzMg61gUYsCWj
         f45+55Hr4UA3TdXk5HhVu1Vd+O3BGmARr0xWkOP8aGH+74CNMESASXgl7O/HM9dNcCfb
         1+hLLYxSIZnLbnSdTPWp34dOZXoXEzuEwJ/bghq2YWSB4OqvKFbqs1l9MamkK7CJedvW
         H/b3sdS9Ywg73wbZxMuTmP0VOyAuiYYC9DUiSIyGoviRBS/vDzKivP91efeD1fTDUkBL
         FgqlB+AMOQbvnRMLvsDlZ36LexMv4u64qqtGdLmjpyzd/93H/NDbD9ZGut6L79J/jYET
         n4Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WSKmYtIIRd6kxfe5CKlrOgcFvBqAzMyIV7HUyA4uuco=;
        b=dngj0ySndxRUT+td4mhCP1hw2C80T2uVpnzFp0babfloeNZLegW1NbtypU0IRVaJvx
         Jo5891pW/XReJn1DuSAAQlQnu2LgF6ToMOhgSg3VHIaDtYTwbuTfv5cuZpoDTAXyVwqn
         NvlmB64MHc0yJh+F07F5HpK0VrwRUV8EM7LxiNnlPnYJJg3uFRod3Od13Ccf8QZzqjm9
         vonwexb1jWDv7p2dOAxUyJB6/HviWcEPKyVCuDP7sX2T86SEt7hWBqnnosTuDpBHtAku
         xKzDO2tuONvQI8XScQWDUK6x6cQSMndbTtZjIQ/kehd/C+UWA15+RY5e8ftSig/3DjoZ
         eUiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pjdl2utZ;
       spf=pass (google.com: domain of 37cjtxwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37CJtXwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z11si29509wrp.4.2020.09.24.15.51.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37cjtxwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id b12so388681edw.15
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:25 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:5008:: with SMTP id
 s8mr918984ejj.408.1600987884775; Thu, 24 Sep 2020 15:51:24 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:21 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <dcf9114b08b57bd4b2721936e194f082f52780d0.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 14/39] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pjdl2utZ;       spf=pass
 (google.com: domain of 37cjtxwokcecjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37CJtXwoKCecJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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
index 7291b26ce788..4d35eaf3ec97 100644
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dcf9114b08b57bd4b2721936e194f082f52780d0.1600987622.git.andreyknvl%40google.com.
