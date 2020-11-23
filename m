Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSFQ6D6QKGQEE2H6CUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A0B52C156D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:06 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 194sf6511798lfm.22
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162506; cv=pass;
        d=google.com; s=arc-20160816;
        b=fHtG5NJqT9gyA7Zjeacx8B6m1eCKJ7ILgb8jBTXIwXTUuu8WDwk8VB1gUBWADWItSm
         /RmdORqOI7f78iFH7CLoRUeIqGQWR4uRkp3WvG6cDDhwyLlMOFO2/bHEtt6IjTZi3/nT
         9ECuCYNfdIss8kJ/fqoBKzrQWn0LhQOBTQ62X4/HXKdwtw+qbDI656biCtiga4pjNbm9
         9WwcwRTGNZMNecJpns8UzXIWO69hXUlkgCIGFml54nlYCApu2fftFOTit4tb5n5P2rDU
         xmwE3NHTIgKDIsba/iueTz92HmDlThUiZ/vYdvEdyX//mLag/84yrHXPH6U+6WUnfqcA
         800Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GikeANYZK/NbeV+Kvd/cfaZz/R1pG8qR+9WGQmw1krc=;
        b=enocXmaY0FyQOUfLgRn6StIqGXBvlp+BdjTMLdfNSU8INCNx7LY0QQeDfcwnFCAHXN
         TjEvJKEujm+7lheXOaIeYJqi4DCsMeCBWT31v8uiUizG6fDL750P9G9zGGvf7fDYk1sa
         eOr8TwJvXDnNpA3BM2WP2HaZ1eFzZi9IkxRZxSOyyYkpX5KR29Ajsr6ZpPX0dR8WhIdR
         D3rcXJAYWdL5RnyQCYgj0HE7SxsrzJgQW0VuISDMCeMZ2Oh8+aEolaOIXYuQZ7aiYu6A
         BQMoWL0owJXmh1wFCgamPA/ZoeHSoKIqMMAbp19cEprbie/2FebpUxB/X8YX+XUHrqIl
         bQyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SgzwKhZ3;
       spf=pass (google.com: domain of 3rxi8xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Rxi8XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GikeANYZK/NbeV+Kvd/cfaZz/R1pG8qR+9WGQmw1krc=;
        b=B2KqTgTI2TEFUXfqaUouD5J1Zj3XnWf+NQ4ZyzndWKLwdZqk7Q83Axdh7r/bCpmFWh
         cAAb48fbAAG/rcatuoUu4VT9ueYTUds+QuxlCs38jBANrgsHEaTYq+WiYshaD+BoKXc3
         z96t1Z4n9Nhtkex1P46QxzwUqAmE8bu94KziDVQrdlQkFBcvWZKcKJIsbV21Sm/eNm5C
         VFhL/yovOPB+XalWXHVMQnk7s87FvqemrtpowMmkGl/2abJna25+E7Zn79UkOddh1g3m
         6E10wZR/SFpC0dAxWnF7ow3LJSfElALgaLQ6JlYjrHPweucK9N91npclDcc9RzEruLUG
         F/2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GikeANYZK/NbeV+Kvd/cfaZz/R1pG8qR+9WGQmw1krc=;
        b=IqKOJGdoaMAqRMJWOzCobiV5VRfJD0nhoTivpxb2HFRB74Q34Rr60Ta0glsip3lDNb
         v2f0j/p82LmhBjog19ZdzWMtsyB3ucVYt4PvC9onnH/G2beEfSTEE7aHUx7sDOC0e1gl
         bnY5hBpHF0eml6hJcTcbC+04Gmc5raIKU+lDf4FvjKU6UKVyle71DIoJpNaufCob6VXm
         HQ09FMz/6qoT5xfBTYOxTgi8VbaflKY0bzx2jk6PDPL9uG+FZqW8VMJ64TyJwR5SeGOR
         4cEQjcaBQP17lLo0qzmJ0xC+fz0mQL1gUufnlVJ/MGFKHgmOhrBeOBMZ7VftX9V/SN30
         ZUoA==
X-Gm-Message-State: AOAM532hUDs4nej5jIHXVRHnY6hLC6Wf5NRth5OpBEvF/FZDmw9Fibf5
	WUC2kXV20MXd1R7w7VmeYV0=
X-Google-Smtp-Source: ABdhPJwilcu3QvLDRwQ+NGvcTcm9DG/gE2A41UwusJVdQtmHasH9zg9wFy2FTsk4SWHBVef6GoV3iw==
X-Received: by 2002:ac2:44ce:: with SMTP id d14mr375674lfm.116.1606162504725;
        Mon, 23 Nov 2020 12:15:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8991:: with SMTP id c17ls863947lji.5.gmail; Mon, 23 Nov
 2020 12:15:03 -0800 (PST)
X-Received: by 2002:a2e:3308:: with SMTP id d8mr431639ljc.183.1606162503728;
        Mon, 23 Nov 2020 12:15:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162503; cv=none;
        d=google.com; s=arc-20160816;
        b=MPfZTwI6qsf0v8zL+XoVZqXhd706124B64eGWF3q0ojb3b/TnnuMJLYqqA0rRcQWL3
         76nTQt9bCj8GIARNfxzvlVGs5mYHo9Q6lKdM6xQvOACcZNvLTOmDOl30uRhNrirC0+5x
         o76FnrGbj3D5FzdWI7YPmZSJnyqHw8UrtfuMto/phC639vZyqMq+5bybb8u8PnBwzUoe
         rD1mXLqwBlA/3AiUixEnxDdqNdjDERZeTWpF1iB9dZk0bgW/4PEqeEtGOYsxZmvo/GZl
         Q/4pOrbjrrOII8SNsJQnm6Xe2C1if1VuluurfvYYCxJ94OaV+A1ZeIbvugHpvBuSRthU
         MY2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+fKBF8tk63anOpwt8A+LLR3Qf9R2P9gh2kXJ7NwYZig=;
        b=WJJE04S3DuclG+bRm9zUUIVcfQDc894dmB2aeDaiFfi8dZrcI0gEc6pgA87Kbdzse4
         kk7ckX39mfX2LICQtW1+Gcq64tSDcg25etV7pdH5X6+YgP8R7jTPSwPVu43HQreVZ6Pc
         o2zzRjQfLgywiu8HxeP+pzzSNnuFK4IiDLp+NJ/BGhuoWYEJj7AtacuNBm+UUIq2QvGE
         2ato/E1ar43VeKrREd9WYHoQXccxz3AwfjLNyU+EoPJbdQTycbpmYCCL00HwHKfMqFZE
         1axEJO1LAv8DTmYWm6cVSAJezN85LxWMM47ighB6evMaMD8XkoKRzcLdSqT7RYSgKHMA
         0fxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SgzwKhZ3;
       spf=pass (google.com: domain of 3rxi8xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Rxi8XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 26si342870lfr.13.2020.11.23.12.15.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rxi8xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n19so319487wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:ce:: with SMTP id
 u14mr639471wmm.150.1606162503128; Mon, 23 Nov 2020 12:15:03 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:34 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <d09dd3f8abb388da397fd11598c5edeaa83fe559.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 04/19] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
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
 header.i=@google.com header.s=20161025 header.b=SgzwKhZ3;       spf=pass
 (google.com: domain of 3rxi8xwokcwwkxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Rxi8XwoKCWwKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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

Note, that CONFIG_KASAN_STACK is an option that is currently always
defined when CONFIG_KASAN is enabled, and therefore has to be tested
with #if instead of #ifdef.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
index 0c89e6fdd29e..f2109bf0c5f9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -76,8 +76,6 @@ static inline void kasan_disable_current(void) {}
 
 void kasan_unpoison_range(const void *address, size_t size);
 
-void kasan_unpoison_task_stack(struct task_struct *task);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
@@ -122,8 +120,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 
-static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -175,6 +171,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
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
index 0a420f1dbc54..7648a2452a01 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -64,6 +64,7 @@ void kasan_unpoison_range(const void *address, size_t size)
 	unpoison_range(address, size);
 }
 
+#if CONFIG_KASAN_STACK
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
 	void *base = task_stack_page(task);
@@ -90,6 +91,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 
 	unpoison_range(base, watermark - base);
 }
+#endif /* CONFIG_KASAN_STACK */
 
 void kasan_alloc_pages(struct page *page, unsigned int order)
 {
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d09dd3f8abb388da397fd11598c5edeaa83fe559.1606162397.git.andreyknvl%40google.com.
