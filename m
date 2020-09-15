Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRG6QT5QKGQEL5LNCXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C0726AF56
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:53 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id f18sf1698695wrv.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204613; cv=pass;
        d=google.com; s=arc-20160816;
        b=JJjChkwsSWYwYSsW9orXbXxXCilVJoczq/vquxDxbbufYzMcQOeFsl4KUqahO4xGJ1
         XHPXMYFo3R1cV6jdnmLn2aPppxQNysMgzbpfMQYOhKszKPbctIT4DZ1slbzuZ1h4B0az
         d//zVuCH8ABclu/Q75PAwDUzKRyQYYrLewoGkVlxLhS/AjUC+m4zkY77MUqyB5yRXOK9
         Iv4yv/h9aoe7Wf74M6OzATmuoUZcuKjz/0Yr/zoDhEllX1lp2UmioV7D0Nm9RL77MMBs
         joFh+MIjBXZz1YVUjfGqLzHrZ090bfmKJ95pDbnIPglavMqE0Ix3SMJ4rCQiYJxD1X1r
         3Izg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Jw5yAOXuK800y3BaIYG3eCtpJhPRpkY0YgOxh8KE4JI=;
        b=fdw9ryvBvCNC76oW28jVmFSd/GgAnUtX0uFvezYoRYQalZhTE6OHaeRQtdS8lcvKmK
         niRnecbXN76/oSEW1rsPaTfCv/UvRjYDZI/a9nW/rPvP7k73A06Y+pqXQkH/HwSxku4H
         eMViYMWKILC58QoCqvmCyyo2NVz6/eXULQ05aUOTUEVY8H6SdIbzaChmSm54KACFFD1Y
         uc8l7hzxvqZOz1ArsA6mZ9MPFZh1PPkomBlRDj6L4hirmZAoE9DNrNQXtC8k40Ey+aUh
         jwi5VhllVAm2C97K4BWURlg+et+f4uuGhaqeSjZaA9xJItIrbXNNqxvWY5YX2ia/XLYZ
         TCYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KwKBifrT;
       spf=pass (google.com: domain of 3rc9hxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RC9hXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jw5yAOXuK800y3BaIYG3eCtpJhPRpkY0YgOxh8KE4JI=;
        b=fkFrmogRZOH2HMrl0LcRjLmCJS/3pmJSR4c7WFyPu95qEPn+WRlTZGVUZ34eDOH7gs
         O2kqif8FsL0S26tRvW2A56bW5DQ17BeIN2wZcOI5er+IMbtZ+QSumbQjOqNDn9Bb0BRj
         /zrg3uBiTNL+zzOFTwv4orV+V+lnp8JV/rjAN9Gayw03Gb0VJCFRHTPcOwQMFW8R0T6M
         u7Sr9WVeWbR/h6WqgdrHjYqtAOEoiqynnvCGkbSWpb63NmrFa9hMxcAUxxdUpj5sWrHb
         H2JovwsJ6cf5APWr5c3Sp0W3SjDL3XBPsWjgZ4rvmxpw8WtXpoTUDNSaa2+1vsdb5ZOq
         /7nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jw5yAOXuK800y3BaIYG3eCtpJhPRpkY0YgOxh8KE4JI=;
        b=UuQhBHkBEu1h6ZFi7WiAMdSNKjD2R5hVR9VnT9KjQacQgLowMeZbqiQluzm8IsAKn3
         cORaxEu6ZXfU7Kr2udDzlhdvhepYvcpDslDx17NNDhnYag3AA91ixpX5PPM7GbyaZkR/
         l9sxnb+WL9w9orI1+5YfalV+HHWxtP28ryOiaOTM5+ggRgWdCYe7vGniT/BWIp7+7vEH
         6tiHceIY/e6kqLL7YBeI9HO1pb7Fr+/WKgyDyHVO1sr4pH6kpsLQ5+Bo7JKFVESIbqMj
         TCKJscC7JsIILNIVdPdk1LAV6CERLjLnkifCrrQWDb+ChE6gIQlNIzdnDtvl/Brh8H32
         sfqw==
X-Gm-Message-State: AOAM530JoZ/Eqc1C/MecdVmU4TLf7/z34l34DYzvP84LWPOzcjKrDb8N
	7H4tScjN2jcMe0fh5ARSVtA=
X-Google-Smtp-Source: ABdhPJwCpZtqqzvDb0qdeOG3pph2X1jx5EzK9OAhV+fEgQjKUDqANAbjyC1ehf0IYZ5w67VqlkEQEA==
X-Received: by 2002:adf:eb04:: with SMTP id s4mr25119647wrn.81.1600204613105;
        Tue, 15 Sep 2020 14:16:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4154:: with SMTP id o81ls104141wma.0.gmail; Tue, 15 Sep
 2020 14:16:52 -0700 (PDT)
X-Received: by 2002:a1c:bbd7:: with SMTP id l206mr1271087wmf.185.1600204612307;
        Tue, 15 Sep 2020 14:16:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204612; cv=none;
        d=google.com; s=arc-20160816;
        b=IwtIw8Y4EzjiMcBB0RqDsFJ1/7qXMVYTurYze7edqNXPKnXNG3FU8vrwfbeDh9xFbc
         lIHV3Kfh+jyJLu2wI9Vt8euCEPxyo9Y5pWrsi0F/41ftEds5rqZho1WO0W9py47DkbWH
         1ZWldozP1FnxrDIrwuUHzR5i44yLyRyovP8Rkv1rS9uG1RFxeRQawgMRDkijhO/MGxri
         SiX3Bcq059jXNaqJqVHchxTvRdeafv3lGw/9yGcYBXDDxWDRSlMthGNd79wMoiBvga6C
         fwAeJdpCxRL3CHc6FDtzVC3hJK5V3N/F4lM7IzPDB8x3CYopyWKOIAKxaJnTd/NtjErl
         /JJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IohLAiQritHYDUsEyFojJvH0Itf5Q6tgZwjJNHAxVZI=;
        b=OaiTqi9mYcJB1NRMhIVxTacYSo7OQ1MPFmz5hli6JAfW+LJefbqAmWd9JGw58Tst1D
         TJYE0bDmpggLw/S/0gr0fPFzEDq57NX1QNPeUisVkjBsy5wfpYAmslN22VsXN3QHp04x
         rWpNHh3w6Q5K6YUg9ZJhAw+odQMH3aLEnW8HQ6oFLr2wVAsTj/rhDk8sZh8wkZ7o++sV
         jj0u0LziOZk7vhDaBetAJuIDMGLiPTBw/x3HnEClqbERS3rJb9tQqpwt3UQwZQDO0SDb
         htVK8YMC6/iRc660nLh2tDckRN4Z7GZxbSqZydfJhCUf5iVFgJrnfO2KyJ3VVQdj/q2R
         xXFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KwKBifrT;
       spf=pass (google.com: domain of 3rc9hxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RC9hXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b1si22788wmj.1.2020.09.15.14.16.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rc9hxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f18so1698653wrv.19
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:52 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:cf01:: with SMTP id
 o1mr23727593wrj.421.1600204612062; Tue, 15 Sep 2020 14:16:52 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:54 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <2d009928ca496df0d7c061749c6a74d9ad36588c.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 12/37] kasan, arm64: only init shadow for software modes
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
 header.i=@google.com header.s=20161025 header.b=KwKBifrT;       spf=pass
 (google.com: domain of 3rc9hxwokcskfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RC9hXwoKCSkFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2d009928ca496df0d7c061749c6a74d9ad36588c.1600204505.git.andreyknvl%40google.com.
