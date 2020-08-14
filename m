Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHET3P4QKGQETIDLXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 94F29244DC2
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:57 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id mu14sf6865832pjb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426076; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ut018uXBy+X2mM7Yh1ARO4mnFBipko4a3GbiPrhuE0PmK1fUs37nQF2SSCQiPs2r9O
         UsiXzAYfHj0rJkYz7Q6upY3lZ32nxBEOjSX/0eGMFx3cDzu3v8CbOIDBj7Z6L8wF+AIV
         h+okdXNpWcR3DIHHUfvX+qRPz9Jsoe2eo6IPmmYR9/6wzT20aQM5muoufBBU5BiZ2bz0
         Afdb9gVBUGE0vSDQOr7ZhSTRZbr3Q9FFUiHTMEALGclxKMB3Wu7023mbENR1u+sU5JjE
         Glp1yePyAdeAh9DaMY7KQsVGpVn4lr8FKBO6uzTElnukCJaC3LaKjHXzkgIVAnCPIhkn
         sesw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WB6jz1zjUqirdZdShc2RpVUqa4CubETyGXCj9M4aB5I=;
        b=WdXy+9xMhWW3chpdWk/fXBqUHlvEISXA98E6+WBeiCzgqAymQmAXiPVkfq+9pHOfEN
         RsuQXU6WFw9MGmPkj2wE4IwgwSOvRt3nqeFeQsmYLdzphnAy3eh5Or4vO3D5dFuWBZkP
         EzP9ptcTgmg2ltbCY5zocHOHVUsu5971P5wIj2bDH9exbbLukSvE/l5VO4ZnsM7/vxDL
         OJVn+xAqqb6kP6Ox3SnjJZmh0j2Cr49EGx5gWxwBmQOTps7zN1kgEupXWMPLBNVwIHGf
         lURlCw5q/ZCUZWNRbZzQ9KK1OTr/swLTSv2x0Dr00a2g9NLaZYchkSW3BfD1Cn4UUVh9
         HeOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMtJW6G+;
       spf=pass (google.com: domain of 3msk2xwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3msk2XwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WB6jz1zjUqirdZdShc2RpVUqa4CubETyGXCj9M4aB5I=;
        b=sVmpnBAf9AYqf3piwMfwK1hrHSW2pEtnLOfgeiXs0sDrYKqGlEmjZRzTp6koYtHOJB
         0VXHfQrzsEs5xPVWr+8PNTJvFId6YBNRodBkU8W71M8kcq4WDEyIGGNvZf8peDxN5TVQ
         0e/QAUWcwjwWISq9ovnOwLAgVa3JZPE8cyCARJ3qUfUwIBwuRThKr48DOzEow77V8RKL
         iAnPOyd3UL7p44LjfeiVF/RS5+ZrCfyQzrkm5zRo4HVqf5eLhJC+H0jq5JCFiXfTaBwu
         K3qw29DknYjbO0YJMSDKOPqDiNIGWRq540GV7gv4bsyLQmUCNYRadcthDcuwYhyh9/b7
         gfeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WB6jz1zjUqirdZdShc2RpVUqa4CubETyGXCj9M4aB5I=;
        b=COXkplcf/YuyTkZ0v7oXy0+tIiETlRYBqfAxPhxYHRh5f3YWRheDDyxzIit54ASOae
         7RIRkdhQukxrzTKbd7MZ+W2xuf+9avOZCI1Qra9ToQZjZC9lkuWvw+kvqy/V9RfR0LO4
         3ydfUiJfzSLQhmODgTukO1POjPjiuHXqOarTFubqoi52WoJzxGidp3lB/6YxgShwJlo9
         aAkr9auK1pYkJWuPH79smH4hduY9GFNLlzH3C+WCMBGdeXbpmEHjLvyYolLvfvgaZX8R
         emxdT1tCi7GdSMIqWOF6qxBrr6gt5vikCh8nSzUsw0O9p0pZg3w74SzlU3OKP60tlW7C
         wc8g==
X-Gm-Message-State: AOAM533KsjR+2/zH/FP/KeoRenQgb13lhTHL1EZo2NbmhAEkJ6Vpp4Yu
	sbIvAvkuNyCJb1OslrIoZDU=
X-Google-Smtp-Source: ABdhPJz5RF62B4+0PveIiVUf+FaOgZHhylu74zDD4a9HeiT1wYvGa2yiog5KXFjbYg6S1BNUuFfMvQ==
X-Received: by 2002:aa7:9e45:: with SMTP id z5mr2654384pfq.166.1597426076307;
        Fri, 14 Aug 2020 10:27:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:130a:: with SMTP id h10ls3911158pja.0.canary-gmail;
 Fri, 14 Aug 2020 10:27:55 -0700 (PDT)
X-Received: by 2002:a17:90a:ff85:: with SMTP id hf5mr3039515pjb.79.1597426075858;
        Fri, 14 Aug 2020 10:27:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426075; cv=none;
        d=google.com; s=arc-20160816;
        b=cj1M02DyBD878XeLuFQmeQNNSKhflEfJ+lxuzDnkAfUVj68rnrMf08WuMgRhJ8Jd9Q
         hIubSvpQDZZiMOVRaP3rnzekoikG98CZbmmAHkvkv3L2Ous3uHnDLLy30YK9HhJZmGFF
         zjmUDdrB2IuH5SVyThWt99LtLNfAtQVNNx73oZPAWL7YLx5bxJs6AaqMqN859EYKv1iy
         6d4ZE+AFlV0PSdMNGthY1cFe4gnm+qvY6kXIXaf2JPNTIlLh1abVHoO0G10dtRBs0t0g
         CusXX8F3dQNEG7Sjd3rL1iHjkH086F+lm5NzZz/PDM9+vDT7HrFyWnu39ByNEgTIdwRl
         ghBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=S5YYe9chzXhia6NqEOtjeZEypr/bcyFxBA6eDjcJbWc=;
        b=Myrxe8sCFgIW7G86nMW2RbLj+rQSMKrG1oYDzGLvl4+TpWGxftZD6WtPUQK399bc9b
         jCN2LgTJkuGSReC2txxO9AWq6aobckNjlSHnE3s/1R1Tgr/bJW0tB6bsKb0kxdZf3JGj
         d4O6KgNTgrlvzTfn1Rfn0qkvpzcgz4Ijc6QTEJaVy8nToOm0ykqOYt9k1YNud9r6+lW1
         P1tJUJ4gQeCTL6uXMLlgjwajdT84ty8fJovS9KSIwRAMZa5inTPGDBBjmRqsPEXzGBsl
         be7Jlb06fV6SFgo316I8qMXg6T4NsmwOH3Xpe4JH8KO7ApjRmVBIVYilUup6xakOKJxk
         wsqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMtJW6G+;
       spf=pass (google.com: domain of 3msk2xwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3msk2XwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id ml3si617673pjb.3.2020.08.14.10.27.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3msk2xwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id h185so6473998qke.21
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:55 -0700 (PDT)
X-Received: by 2002:ad4:49a1:: with SMTP id u1mr3592719qvx.245.1597426074976;
 Fri, 14 Aug 2020 10:27:54 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:55 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <35c9e6ff0b5cc69cf97ba7dda143f3ca14af6b5c.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 13/35] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=ZMtJW6G+;       spf=pass
 (google.com: domain of 3msk2xwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3msk2XwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN won't use kasan_depth. Only define and use it
when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/kasan_init.c | 11 ++++++++---
 include/linux/kasan.h      | 14 ++++++++++----
 include/linux/sched.h      |  2 +-
 init/init_task.c           |  2 +-
 mm/kasan/common.c          |  2 ++
 mm/kasan/report.c          |  2 ++
 6 files changed, 24 insertions(+), 9 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 4d35eaf3ec97..b6b9d55bb72e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 }
 
+void __init kasan_init_depth(void)
+{
+	init_task.kasan_depth = 0;
+}
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
 
 static inline void __init kasan_init_shadow(void) { }
 
+static inline void __init kasan_init_depth(void) { }
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
-
-	/* At this point kasan is fully initialized. Enable error messages */
-	init_task.kasan_depth = 0;
+	kasan_init_depth();
 	pr_info("KernelAddressSanitizer initialized\n");
 }
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 18617d5c4cd7..894f4d9163ee 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -52,7 +52,7 @@ static inline void kasan_remove_zero_shadow(void *start,
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
@@ -60,6 +60,15 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline void kasan_enable_current(void) {}
+static inline void kasan_disable_current(void) {}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -110,9 +119,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 692e327d7455..6dca19f2516c 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1194,7 +1194,7 @@ struct task_struct {
 	u64				timer_slack_ns;
 	u64				default_timer_slack_ns;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	unsigned int			kasan_depth;
 #endif
 #ifdef CONFIG_KCSAN
diff --git a/init/init_task.c b/init/init_task.c
index 15089d15010a..13f1cf21412b 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -171,7 +171,7 @@ struct task_struct init_task
 	.numa_group	= NULL,
 	.numa_faults	= NULL,
 #endif
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	.kasan_depth	= 1,
 #endif
 #ifdef CONFIG_KCSAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a2321d35390e..41c7f1105eaa 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -51,6 +51,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -60,6 +61,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ddaf9d14ca81..8463e35b489f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -295,8 +295,10 @@ static void print_shadow_for_address(const void *addr)
 
 static bool report_enabled(void)
 {
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (current->kasan_depth)
 		return false;
+#endif
 	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		return true;
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35c9e6ff0b5cc69cf97ba7dda143f3ca14af6b5c.1597425745.git.andreyknvl%40google.com.
