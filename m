Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ4NY36AKGQEYB3C6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AB3E295FAB
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:36 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id y13sf779948ooq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372775; cv=pass;
        d=google.com; s=arc-20160816;
        b=QU9/gjpKR3CMxVFI4qpnxcn8jaaWy8zXNkCH7Bzt5XpLSMyThlRYUJvNxewAz7yGB7
         fm9RwETsAL74sQMAIvGiUuLEUZhVnsWmI3eoW6osDEIYzc4Q5nmvYdTqNnDbx4nPTMIA
         xiq6lATjd7Gycn/5oaGLhxrL6SaYlZJqf3teZCyfL85D6JhXHzvemJ7R9yAhcMTU7y0a
         6IXeKwv/Xy456N2frbItwdz0sJfka6rIvMfQGV1QJFBgBy2QsJ/IOXRjxhWPEmDGjco+
         sj2SubrrHSIJyOKAuOnyx/Pwgvyz3973ircVrKW5DY0KP88SgV1XRD4wKEIJyLJGhjkL
         MqSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=I6FAQj1Z05feM4SbaQu2OhCl8pCk+64WI0z8JGoSKpo=;
        b=aIbrammhpU04Cjh3284vlHyE5Uw6IjS4xuAUVU9GhhkigizMz+qvlGiOlf0NQJcSax
         5tMAVp8DXXfcb2uVY1Hb+KaklqURn8sOWwqF5cM0GUPNQk5C367vPYRRQ9wlRZ7VXor7
         P0iWX+MVTDxnvV9KRrVSeLmPVmAPWaPe4RuSPp+FfJHk9UXS+xnCOjHuUtIkc1VFB9tH
         EJ5L/FmSkqIRIO1U0UhNnvu5sOV4e9ymZMkyOPfZ/JHMll1saSRa324soat9XcNvX39W
         cE2C0R0PJRaNh+Vbes4uWfVZPRX6kr71utzrXJr0aDWGR5YxXMbIJDtLTZ/PCl+26Zcq
         hV5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyVZvbQw;
       spf=pass (google.com: domain of 35oarxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35oaRXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I6FAQj1Z05feM4SbaQu2OhCl8pCk+64WI0z8JGoSKpo=;
        b=LJveynMFsrZZbGBUK4LDDKFN2uzZzsO3oAhq2eziGVUd+qAdYWa5SINwn/kN0DJcAc
         Q+YD5UR+3K6Kfq3QezvOPxqqry0aCvDw2PK/0qIoeR/6OOs1RXRsJuRKvZsUfXaD7Crl
         safQhDKTxJ/mNtj9urRr8YoCMuoxMEwUZMGyTpyBBC8vfLTqYb4pGsP5MoSGnXq6ecRl
         fr0Cqu0lEWxVT7TbF073Y4077OBxP+a3xFuf2aGM+EsDqtSaruKjfaxVxlh44yUIs9bV
         TwdsGdVlMgAhaI7q9gK8lJkPVo4nSNO+/v1zvZtrrpPeUqMPC9bMItROdLVsYomrtSLi
         Xv5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I6FAQj1Z05feM4SbaQu2OhCl8pCk+64WI0z8JGoSKpo=;
        b=k4B3TskeZ7c/OxHMF20Osl+oxKU+zyFeASEolqX/UTp5dXPqYjUREQUBRvQICRB/kM
         xD2DLLvZbr36/wJSh9XVuyCJrnBlCiFFwuHVc/7P2viwuY02TsYh3dyhSqIMZ2ahM8I+
         VpZD87y4byrm0rFwLIbPcPSho/9k9fVDC/3gXiy1rcJjvXDMXmv9IqfmNiJ1/cJHKbIT
         VbGdU4HuYtD9EQSw26D/xjaeLw6aO4pfQcBLi0BNKkfGclTZ7qLOONHREzLPzLMWotyP
         4W3V6ZnspQQmLkISqtpSfoAhIOVfrrbseRdSoj/jSglVxOu8JM2jOou9bhBQffSGX6eK
         IRCg==
X-Gm-Message-State: AOAM530+PuM3bi1sDxmVwx8HJ+AQxs+DWor0+iTx5QeN05Hap59kjg6A
	+uyrEoWIW7RVyRixEzlJIxo=
X-Google-Smtp-Source: ABdhPJyW6jX8sz9rBNEdBY6y41ZqjB57qfb6cdSr5P86gXNbyDkC/geV4gIRTIbnzR9dveKUu6V9iw==
X-Received: by 2002:aca:b05:: with SMTP id 5mr1589970oil.87.1603372775318;
        Thu, 22 Oct 2020 06:19:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f511:: with SMTP id t17ls381037oih.2.gmail; Thu, 22 Oct
 2020 06:19:35 -0700 (PDT)
X-Received: by 2002:aca:4848:: with SMTP id v69mr1636614oia.25.1603372774910;
        Thu, 22 Oct 2020 06:19:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372774; cv=none;
        d=google.com; s=arc-20160816;
        b=wuGccZnATlQzIutPy7Cfwgd16EXJkbB2lnKsNQ1ZcF5Cn/dg3UPzX7g1Is9Yyq9XY3
         qYBB696wE3PPn4NqMfjEbcaLUCGXLCbPQ7g1gX/1scb0oXOJIfATUWZUCGonPpqCxw+F
         nHzFToQTcJ0DpxmBVDCEt2/55vBoiSRBcBGjqULmPFmo78hWS4eJfAoF1inG2/nqIwUm
         9WSBJD0FF7au0CegR+P5D4SQbLh4VzMQFDmjEyab9+JKTfSA9WdeQzdFHyp7YY4Y9MNT
         nDPwqBjr0ZgggZnX6l0zAenvft0Ci54PTuRurN/PTEwXnE2h4p7JqXVyU+hI0vyHCNFD
         Snpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cQVLrwUdxN7VB2XZ42Engk9gK33XrCOfDjGCi6TbRVk=;
        b=eunxpgWzjQDOipUB7wcjgdTpMKVa562/KjXJwNQ+HafkhuCGV2YzgQuOCc7ex+x0ds
         0yVYXwvztKgbavjBWQ6mu4nWtfyajWfEIghzSEJfatCriPwVrQPqoSGLvXW6uq1q7MNB
         yOctmKdOVn87bu4pAu7KfWiHtW1MSFpEAHE+Mf+35wIiQvTzDbK08rmrzmJ1NWdrhQJN
         ASu9+uQZR0IDLbMCUCen3rL4odag4ILscBqe2N7/vN4wFmQgsIg/BEO+IEI1A22riMhB
         tXK3s4EOldl8kRpMVUVNSCqUd0d7JWzU8pPqEuMgiBZG37VQaV7E5DnxwRpCu+BJX5t4
         W2Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nyVZvbQw;
       spf=pass (google.com: domain of 35oarxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35oaRXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id d22si181274ooj.1.2020.10.22.06.19.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35oarxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id es11so997404qvb.10
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:34 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4ba8:: with SMTP id
 i8mr2332119qvw.59.1603372774241; Thu, 22 Oct 2020 06:19:34 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:56 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nyVZvbQw;       spf=pass
 (google.com: domain of 35oarxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=35oaRXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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

There's a config option CONFIG_KASAN_STACK that has to be enabled for
KASAN to use stack instrumentation and perform validity checks for
stack variables.

There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
---
 arch/arm64/kernel/sleep.S        |  2 +-
 arch/x86/kernel/acpi/wakeup_64.S |  2 +-
 include/linux/kasan.h            | 10 ++++++----
 mm/kasan/common.c                |  2 ++
 4 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
index ba40d57757d6..bdadfa56b40e 100644
--- a/arch/arm64/kernel/sleep.S
+++ b/arch/arm64/kernel/sleep.S
@@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
 	 */
 	bl	cpu_do_resume
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
 	mov	x0, sp
 	bl	kasan_unpoison_task_stack_below
 #endif
diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
index c8daa92f38dc..5d3a0b8fd379 100644
--- a/arch/x86/kernel/acpi/wakeup_64.S
+++ b/arch/x86/kernel/acpi/wakeup_64.S
@@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
 	movq	pt_regs_r14(%rax), %r14
 	movq	pt_regs_r15(%rax), %r15
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
 	/*
 	 * The suspend path may have poisoned some areas deeper in the stack,
 	 * which we now need to unpoison.
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 3f3f541e5d5f..7be9fb9146ac 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -68,8 +68,6 @@ static inline void kasan_disable_current(void) {}
 
 void kasan_unpoison_memory(const void *address, size_t size);
 
-void kasan_unpoison_task_stack(struct task_struct *task);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
@@ -114,8 +112,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
-static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -167,6 +163,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
 
+#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
+void kasan_unpoison_task_stack(struct task_struct *task);
+#else
+static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
+#endif
+
 #ifdef CONFIG_KASAN_GENERIC
 
 void kasan_cache_shrink(struct kmem_cache *cache);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a880e5a547ed..a3e67d49b893 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -58,6 +58,7 @@ void kasan_disable_current(void)
 }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if CONFIG_KASAN_STACK
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
 	void *base = task_stack_page(task);
@@ -84,6 +85,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 
 	kasan_unpoison_memory(base, watermark - base);
 }
+#endif /* CONFIG_KASAN_STACK */
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
 {
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl%40google.com.
