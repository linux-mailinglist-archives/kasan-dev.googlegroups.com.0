Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD7ORT6QKGQEBUFV4EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5819B2A7124
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:45 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id z125sf234087pfc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531984; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbYB5gPE1RyTKxq1jNVa8uJs8GcTeiwTX/PvL9TwwLmNdaPibtzjoTnJBNZyj8tbnG
         ZCMeN2UUsYMRW6VQdgHKI9Ulv6aHETmFN8dnpoHAotiml16qV2Gal0O681f1flEM6QfB
         60MhvpwOLxtZB5HqJMQn3d0J+MWQx21w2PbPZqi8t0ae6GKF5+IoccaAbR7MVJ4tc/m3
         ZvG2KcFuV6tulGJSdaQvM/+vaj5Tb0DGKJthNGmZFSneumWcDbkfnDTKNrooiNfK/Xey
         K0LrF4uYt+/KFpNNsthLmL1qaavI4B4lGbpgrfXkGZgKVIwVpHyXhkVEIxo2yQnwxgWM
         P0YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8oit5ZR+SoALOx864LTlWmKBUXQe35mB6lJuL7g1yi4=;
        b=n7pz9ta8ODGtnG05VdgEvaJgWOxiDvbYhAzXe+CTKgLjDOC+o4xmlIhjOFV88fQBY7
         DZwM++VoQo1A3e08VjRRd3KzbfvbCUFRvwKVXVzTkFTa2YYz8wY4xu6nZkqa/t7RTyDe
         r+XuK7XOdhxVM5Z1w/NMg1xF5I13y+xYgfq3wlrFp8vnMtDO6YISueXdLsXjVxjC8O9d
         RSNqwc5aLSmo6HtJadiFyDIRcKBBMDO+BIk1bo4HvHA9FgSfTIy/1kxOHoSNZG4wdMAE
         7KPwHUZzFXcM1yNHEw/7noxyPG+8T07OK97KViu+G3nu6mq3ajrzH4yLYReEVSzeKT6+
         esAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=im6MoqCK;
       spf=pass (google.com: domain of 3djejxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DjejXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8oit5ZR+SoALOx864LTlWmKBUXQe35mB6lJuL7g1yi4=;
        b=a2q7BfoxVueHjADxynRSDnkN0YOke3lhpmPdtEt2sJ4XAC4Ih01a1t//wkiqCsevTj
         ZkolJSxtCbELkJ/LeSnEAsmgQEVjMKCh56V3tj9FqBoUuSQFwV/jAGz6y4ywNQnoC3oO
         IyU0PFxFI9Jl/WbNbcnZ74izLCyoAvbvmsXTg5ChUx3MrRGTdPWn5Ao/larT8yNK+DWZ
         wGfI6Uc8GyezDntsyu2QY+nMBrfiVMnz1szC8+tiafOcIDwfDdEIC1ZqW2Q0h2Jb4D97
         HRB9+PJJ6P0YPB6UMzyobrEluSGxIwOedn9S6xfKvzkBEPre14HuPzhbdqP9RmZR4IrM
         SsRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8oit5ZR+SoALOx864LTlWmKBUXQe35mB6lJuL7g1yi4=;
        b=F+kBmbROKR0+KOyAg6XHmmRWiJki6wUnYbJVb6997Pv4qBpZ1Tr7aymOsrWB5HPz/1
         bNLQVGpXuJmt+RB9f8bGtyUYZR6grf7VILsPWjuyPxUHtoYV5ICz+1mP5hX8g6IuNFQo
         ywTaJJ3wvMuhs6RO4oRtvbyneBdIdlxlaJuXr1gOd+q3J2Npy6I0fR1aLw7faqApuumU
         xEFS/koqMWYkax2T2BWJ4XD4gwU3TWYftItwZZ8qHFkGCJMsQKy1mv7VLVR1cN+qeZot
         jlKoPyYGPptlKbVIL9lBdzp808AkNAD57WuJ3nMzEO9wI935GCMjjZ3tSer0UvNujPU1
         4OkQ==
X-Gm-Message-State: AOAM531nssY25w8RJOOTQy4UeGNxsOVx46rKV7D0riK1ZJhYkO7N4fJ4
	7zy46NQj3asbxj4Nui06kgE=
X-Google-Smtp-Source: ABdhPJzCSe7rgfEBUWvO5y2Crv+dt7joE1+nXEb1Ysfp7U23P/bGiLhplQP+3KZuj4EetQWj18ZT7g==
X-Received: by 2002:a62:158c:0:b029:152:6669:ac75 with SMTP id 134-20020a62158c0000b02901526669ac75mr310320pfv.5.1604531984062;
        Wed, 04 Nov 2020 15:19:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1669262plr.3.gmail; Wed, 04
 Nov 2020 15:19:43 -0800 (PST)
X-Received: by 2002:a17:90a:10c1:: with SMTP id b1mr261706pje.58.1604531983503;
        Wed, 04 Nov 2020 15:19:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531983; cv=none;
        d=google.com; s=arc-20160816;
        b=CGEF1boEJ9M+sHcUpKJZzcOmWTxbsaQg9ieDdK6z0vGsCLbgKA057Wyi/lM3u+4c3o
         41IpM4KSGj+x/4jhNvehZpdZHdy/LWfDiYxRPCCWvY9Es7+XpMnQlyCq8toKZxvZK16Y
         Y+PldesOeV4WTYeEqRnSTihPbnbHaxOUt9nHWUN5G9mN4FMQ97ZSwOBrgFFU8D2q1eMQ
         vD/1xPeVYsYllW/2Wfyxf8Sj+8tL3zw6MTEpwsmbY2fm8M4y3ayhWI1M0fOQ4XOmoqU5
         D6cWZ0oFU2XvcXPE5ZqPFwBK/gs/5ibt9elqmbCyStaRtE2eEiypxjWrwMHfC38CrEh9
         W1QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d4Yc7AItymQNyKGF4tg/i8f/qZM6X5xLr7PA4bM2pG0=;
        b=AbMlGMHJZkR+kkayv9vaGGM6cYOkjvENypfZY8mDw1QdU9+IPehC5VRJaidxK4ks4h
         0WZieXEvuLOyFU+aZchLndrnR2rsoCv2oCbOoVp0CBi0+HDKQxRQ9iZR0t4XMiyUWDZ1
         ZBuykAmDibXL0d5LI9S+8KUImqwUwocHK8QPQCYi6qx6wFEUTgfRHSAjXLV76l/PP79l
         aZINo4E0Qh9Dq9fhJodxcqAWl6otf9eao83gNyq3x+cHfHWqC4UqA5tLzh+EfTq9fNrd
         27tit0sGAhT8Th8AepdRPzguFRQouR7iRVsWvU0fBXUB/9nNpYuEtqQD1CXlUFplHJMZ
         iePg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=im6MoqCK;
       spf=pass (google.com: domain of 3djejxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DjejXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id z12si265996pjf.3.2020.11.04.15.19.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3djejxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t19so48972qta.21
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:464f:: with SMTP id
 y15mr268562qvv.52.1604531982632; Wed, 04 Nov 2020 15:19:42 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:30 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <82bba01b005a8a658596a77b2413adc16c8dfac5.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 15/43] kasan, arm64: only init shadow for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=im6MoqCK;       spf=pass
 (google.com: domain of 3djejxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DjejXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82bba01b005a8a658596a77b2413adc16c8dfac5.1604531793.git.andreyknvl%40google.com.
