Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7EASP6AKGQEZQWXI7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C3C5128C303
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:48 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id t4sf1258342edv.7
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535548; cv=pass;
        d=google.com; s=arc-20160816;
        b=JQdgWaP68OHvfj9AN/5uPK5D3o4O11WsS4Ui0KHb8PWOEI9ed7mnL+gXuxXtcfxvkN
         Lr9hRdtjGs9X6lL+7+Ur+Abx+FfJWsgOLXvwOF4Z8TP+irowcSA5lPnty5PvSJ03EJJ7
         Yz5qAuDsxngzOLKfXNnPXHN6mkNWs32EVdRR8CNBshqMCYzTW54co7awn3lHHpTMZuWm
         sEjmE17mAtxncyFSjzbnTp3/qr0EZl8M1DuvrjwyZoTZbLB+iFSCMWsGxgMykSgRXxHU
         cDYxpJEcrHTFMwte0bMTNikMZg3p7KXCUcgTVgp77KClVWCghde1NEYju9wOPqJyjky5
         ICMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+QeduN6FoTiHyCbUE7zkkyukTJa6u7GSpyLCTZYFAmQ=;
        b=MtvJRKSLegM4J4ryCSCyQM8I9dUU5bAdiI/Q0PxlcZf5d38xOH9IEMdqK9x0X+Nahi
         xb71lgqdyowRzcXuXrIqIXx6oRSjrr8WIQLcYOFs4yIWfrAzt8y4imw7e8H3nF0Q4Ys7
         bqXjc0RBvRTk14XLUxk7bbO8eQjqf/lxV632LrCNqBlbAg36vkU4R8WQTVPUk6/J7tRV
         06FE9/Zf6HEsgwwK6wHUSL9pCU1eBuVRftmIm57y9johj0jvEHpvzAnEtS6LgsYFPAHX
         eajuiBUQF7mjZSCUg9q0AZa3NI6fItdI6qLoh2EZHYSzCXRgHIWtQjchpa5t0LQvReba
         y8vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uNjzCH5s;
       spf=pass (google.com: domain of 3e8cexwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3e8CEXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+QeduN6FoTiHyCbUE7zkkyukTJa6u7GSpyLCTZYFAmQ=;
        b=TKsTv5iWrsYRRBGStgFmLdmE8c1H0pYPdVJStJRoOAJUDbFmOl4UzI6tsO1a3bcJsq
         Gqj3rCI6dxWB2CZ5rgoz4kU81rHj50BSsSy1WBjVYKJoqMluj/6kw3nJiOab1zPqOfjJ
         roQOBTFa4ka/qW64/5Wt8Wm6vdBtjEep6hfRTXsFXioCi8PEy25De5RjWJTSwWlfjw3f
         0c/oTDexnxTvdIGyDRj64f/P9uLQrEXf4bjcRdjiC73Byma9/87o/KfC9/yBmoN0uJVu
         SMRvdo7K99VQkBc19Qa8U4+Rt0htS7/bLgbOe6l5iDrfo26iGLDRZUoPgKUHUsLJ/TrH
         1SpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+QeduN6FoTiHyCbUE7zkkyukTJa6u7GSpyLCTZYFAmQ=;
        b=E9Ld5py1y3BTcOHpVmaZBSnhEjNf6sJDYLG2Fqz2VN2H9ljg7rw/dagbT3RNDUOb09
         60G8LOcHIb39FtTv/P4d/D9gqcYSyfI1rCmFspd/OkLXOP8R+hi5I3wHvs9X83ekdbYE
         USw08vBkl5RNfAHhzIOTqtN0L0zpJNSpcML/w+JwKZM6g9Y5PQjpVySAkVZ/zALAPnjs
         z6pSbglZ7d+++1VkBIeeF807siVJS0kemUiWplO6Mptnrx2wyEseqTJcUi2istg/c4eb
         VDl9qw6UfrrDY9BoneGJkdVfZD6dt45MMhSExB9MpHlzUd7QDz8hEGkACidhpCvqseda
         9qmg==
X-Gm-Message-State: AOAM533J5OfXh+xTI9CBx1nEolgqo4Rk9Dql/FLl4CQFsTYKyB9u+Ir4
	glKUxFy/M/VaJ+QJeICyDk4=
X-Google-Smtp-Source: ABdhPJwywF59zMFcGF2/SoQIlBKPVO7aIHP4SPuk1Bw8D3frRIOUdypBQ55N9gQnbD8t2mFZPi4j/g==
X-Received: by 2002:a05:6402:7d3:: with SMTP id u19mr16780075edy.65.1602535548566;
        Mon, 12 Oct 2020 13:45:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:2158:: with SMTP id rk24ls2343728ejb.3.gmail; Mon,
 12 Oct 2020 13:45:47 -0700 (PDT)
X-Received: by 2002:a17:907:2079:: with SMTP id qp25mr30655770ejb.347.1602535547865;
        Mon, 12 Oct 2020 13:45:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535547; cv=none;
        d=google.com; s=arc-20160816;
        b=ybN4/7lWMopq1Ll0bC/eUiR+BqHzpRDJKeRD57SztnOFLgwLQUnMgL8yhUj2V9IqUl
         rB4f33EbDsWwsYBuyaMpwYJ8SmUDiKc4zhN+Qfvp4e0oT2phfTvNIUMUDIWYEzhaNfnE
         ocmKslaUk94xDp+SMK0H5W3K8kP1sFGSK/Xf4Oo2HG7IE8eLE08LNrb5OWSyeYjdygcV
         d+fG5ZnMBipgb/1LaElWcQoKVes6FWqHfZ2JjKbWS08ghYPQOpVYo08Ff+96h7GK/J7u
         N8LRnoOoaq7cooSFUcXJNljKtygT9go79yV9iGK7dsHabBRUL95KLXt0UfL8TUSeyXSR
         sYpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tw6DMQkn7MmrZPxZvgni0f9K6FMm37RVzTDthLVuabY=;
        b=WPb6vRabtTHk+HgII/1fD7N7hDQrImrflNX2VQjr/4mMvjenJ7757KzOXtJDTC+4mG
         vI3DQiMfHZUuQqPH04LcOqzL/rBWJ6nVbw7mvB+4+NsSnZUFxuBJI9PO5MvGCEY6xJlq
         4tGpBBr/1yD+WwYJqeLXZ5WnSZCKdbjbpqF6jjYkowFNyCKY2ydjeKsYollsUXPrKAag
         k78ilpIRs/cIOgsFSyGQ2tUWHeUSQQkmQ/zMWVstPpAv0vj/Bhdcz374bcC1qy+L+fl5
         mAam38zy3z5AUMe4TlP7MObicku7rQi+S7DXCGbR2ncPNY7Uxkp6uafM3fnwrDD2F8LS
         mmAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uNjzCH5s;
       spf=pass (google.com: domain of 3e8cexwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3e8CEXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n11si141505edi.1.2020.10.12.13.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e8cexwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id i22so7175072edu.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:7f05:: with SMTP id
 d5mr27995116ejr.362.1602535547465; Mon, 12 Oct 2020 13:45:47 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:29 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <3f1a714d11c03ce1783e835b8c7f93eecedaa7b0.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 23/40] kasan, arm64: only init shadow for software modes
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
 header.i=@google.com header.s=20161025 header.b=uNjzCH5s;       spf=pass
 (google.com: domain of 3e8cexwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3e8CEXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f1a714d11c03ce1783e835b8c7f93eecedaa7b0.1602535397.git.andreyknvl%40google.com.
