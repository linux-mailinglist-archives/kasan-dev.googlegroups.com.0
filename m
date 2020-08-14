Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGMT3P4QKGQE3UUFHYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B4B7244DC1
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:54 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id u144sf3540364wmu.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426073; cv=pass;
        d=google.com; s=arc-20160816;
        b=PlEuDGrrlxcsLQYgX8ZBEmJ4V49WPqY33xELkTg01R4anCvc+S5jIbpy2eG8q9vN6B
         rjZsPd5BpH/qzTNVLPnUHngSlwvGxxIbXjwvag7HFavNZR6gjcHC6axRyhM/hCU3NALJ
         A9vUxqWZP/DNGVfpqQMcunR4doHm/7d0CGbXHLQsdXi4TI0NulL298ft4phWgSFnbWuZ
         tg79i5xCmygH3MADc3b1p9j41gm4wRJsjc6V3CaT2YGB+N4iAa581zoWZIM0egl6gw/V
         Xe+ttCM4H83L+xtxK4Lt8Pp0xBiy/1OJs3tP+GL4j27la5XXYDSSQreBK+5131rT7IQE
         ranA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=D5s/ATXeA/JkZs9YOSH5ycjUXdI7Ooqm68GZCO1tmnk=;
        b=t94HcANLCETpPZzaR47KMO6JQ4g3NpI7Eja1cPsGNH5D9eH95enY7bY4+BbWolnGTe
         TxWM8vZ53C5Ekx4QACLs1ek3VC7N1eL15wIqdMNvBf92ZyPKpzKGpobKP1+atsDIJvs1
         NBqHBaCHcFv72DebrXDSJllTCxufOtIAz7XqDtZ7WdngkbNeQP0gT/4XqjAO5Ju/WC/2
         YEmhzjRbI8jBGveXPXm7wSFUs3P83L5kEUEDeUcFB6oR5wwlw8IeeExDLKnAD3bVjWTS
         bZgm+8WVNoVGoHMJS1VfrieOevJ/AWsA/psP+fBl1OO3dvCU+LbqG8k8XPOdzzc+4onl
         XBwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p38WSimo;
       spf=pass (google.com: domain of 3mmk2xwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMk2XwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D5s/ATXeA/JkZs9YOSH5ycjUXdI7Ooqm68GZCO1tmnk=;
        b=IfW3AqSaepNPTzHHLuhyWbscTbQ2Tx8oN+CHO4yy5SLSbCHAOFcqmxRCjMRnJGpXY/
         cRE24fAGtGYkqA1KZeZdxeMToggwQ5Cgzt4fy3pWQuC3tWIvVZzpE8DYfKmw6Jay1YhK
         JP2qBf9MJQz/f1y92IN7NkHLw5878t/2hgUjY2ie0kKHz+RInyBrqiETHMjMdyskNjvJ
         0ASsZ5B0cQFwjUQZEEebA/FRluNGf3rNpjut7grAtSLXyBC2DlbUusk+Ukf0q9NKVP8z
         edW2HGj8Zgsy9DC+Vz4dE843i8RHsbOLRl3gMLXUhU7prp+fvswEX9P3GljwOsvQ7rxr
         B9Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D5s/ATXeA/JkZs9YOSH5ycjUXdI7Ooqm68GZCO1tmnk=;
        b=dgwJLceyz7rzmO0XxCX0fvWK7iT8oonyRBt4/BwyEkDGac7juuuRo6I8kOe0Kina+h
         D644rPvWrnjn7U5JxTJpZPi6HNlie9g9+KBayIG8sQg9ve92bi47J3E6u+71DZsuN9aJ
         YycHGdKpL5PrC1jTY7ynBWkZdc4bQe67C4nYWwAebF6ULxyaqcAWosNnvt+584vwmnlG
         4PfZwkww76vAJRJHyl9MZlbKm+e+dKHI8xQpmpRP+2b5ggJD9eeBHbLcdmw/OK6MNHAo
         JxB/W1wNuv8pfi+MkpVpgMtssaLb0noN4Kr8BUanOk/oaAEDFLYX1MSAvwYaHFtYNrQ4
         XKfw==
X-Gm-Message-State: AOAM533ElWvmtB51m2KRhy4pKDc6pXK8ZvgeD8wEwOCikb4GU/b1hfOO
	CQ9n9kZ7WuG93/9n3gY1w4Q=
X-Google-Smtp-Source: ABdhPJwPU4AgnPSSDAc4Z73lKx7w5qu3lanlkqK/GNWtFqenJ3rQog1X2hE/60oKQua0pD64OZsDLg==
X-Received: by 2002:adf:fd41:: with SMTP id h1mr3872181wrs.124.1597426073773;
        Fri, 14 Aug 2020 10:27:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a50e:: with SMTP id o14ls4464695wme.3.gmail; Fri, 14 Aug
 2020 10:27:53 -0700 (PDT)
X-Received: by 2002:a1c:7d95:: with SMTP id y143mr3521006wmc.45.1597426073250;
        Fri, 14 Aug 2020 10:27:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426073; cv=none;
        d=google.com; s=arc-20160816;
        b=sLHR+5wEW6BbzoGG0Iy4S3hrdURunVFX2s5pVuUNRmMjGHfBZm0TlnOUtwOGwu9bzi
         XAczS/MopHjX4c2EUzx0Rc0uVyMYLVpAix8obK2DLl+CNXKin+9Y996CBVuQ670Ab/Lc
         uRX387cthR6etbRTvBaQXpFtqmQnqUHSFVx+E98ZAwyJ3x3LVD43/TGLZsKWTFmaYDpr
         IGdEL3drYiH8TZWmlPAFehMf2jIWJkK1pDmJtsm2pi6gVIYnU62k7FGEF9BfsqfDf13s
         0OnHYb37urS6BSob31vf94KQc1Fso4ZH+xdnmNm4tqODVP2aXmK8+iwAGud0wU+H3Mwy
         PLgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gbewbhEM/mrEwI9f62OGQ1mBf+mvC6G7M7H1HOVG3uM=;
        b=feVhh/O8xZ+tt6y8tevB27oAC/lzUfEQGJseBm2PO/WbuF9Ce/gNuhc5RJpe2k9ttW
         Wqd5H0VlTLvIqViAOI5aDt4z5T+GJ7dgy6UqVcYa1Ra2hPZuOKt5GK0rSkhjR5vDLLJs
         oPiO/ChVVk/p1zI+mW7tehDb1bHmrl/wR9fFEq4uggzA4VXEXXvjCb38zt5DTxwg4gsH
         Mu6H8yws9wvNnxxJLrFTWG+PBkOhjqvhpcc6cmI9xQLHmhBwXszp4Ba3DxZSv5TYUAqF
         W/S5UJ+sczoT+HuhtebefQQ+UeKh+PAAW40Lu3AUTW5mcXzRxphXCcJu/sxQpvpsykKY
         F41A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p38WSimo;
       spf=pass (google.com: domain of 3mmk2xwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMk2XwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id j83si922317wmj.0.2020.08.14.10.27.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mmk2xwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l14so3603242wrp.9
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:53 -0700 (PDT)
X-Received: by 2002:a7b:ca4b:: with SMTP id m11mr3338115wml.120.1597426072804;
 Fri, 14 Aug 2020 10:27:52 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:54 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <63a51e69950d6d93714a96d51165cdc332552393.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 12/35] kasan, arm64: only init shadow for software modes
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
 header.i=@google.com header.s=20161025 header.b=p38WSimo;       spf=pass
 (google.com: domain of 3mmk2xwokcqchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3mMk2XwoKCQchukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63a51e69950d6d93714a96d51165cdc332552393.1597425745.git.andreyknvl%40google.com.
