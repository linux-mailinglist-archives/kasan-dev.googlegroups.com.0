Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKMNXT6QKGQEKVGII4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EA402B283B
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:26 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id n12sf6650780qta.9
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306025; cv=pass;
        d=google.com; s=arc-20160816;
        b=q42ZCs3qlgOV2I2ZIo0xiIfdFJ3KA/SoLHAAvUU2qZCLeFumlnaqI7m7dh+gPn+s3T
         U8nxLA+in70orIj8E0qnliWI2brpp+ZbXJPwRQVEymOK/kB4SEZJMBZNi5GqDIRdjYg7
         uBWQMAX7K9fxvEgH1sE73S6vi11nLfD1Q73uwkFn8HYQoPc1OYbsFAdgzdFA221nTH/U
         qmfNKJr+NctaZil0WGUl8KhWgx0xQzEWqraQCPaGVRd+kabrYM26JTkLDN8/+A39Wgfk
         3NYc+os2PDLvA4PBJaW/myKuZWKKwOWStDdKzF9VjGvoNFw9BnPvL4oIZI2dSo7kBSzF
         IZig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7/2dGoFjVLPSaz506icXTL5ku1g4WHGuqLIAP/RSsNY=;
        b=ZGUzFsgVtKAOuDWpd4KGyx4vgpyrhPbcvflxEO+kFmx0t/Z09rflbAIrnza+8ws5DE
         NYfgcc5Kt+UXkhmQAdxj5ZWg3oCND01GGNGLMn8CPdZagdeiCp90jieH2CQ3yiX2thu/
         HAyOXfgvZvPC0ivXKeXjXzQDCIug1+k9h/tLx0Ua7MolaYViRx7BdR5rQfssUWFeC4Tv
         N5lESnvoFFWHZaxhw4D+jdKslVRWHV+hdnhbtbu9n0TJxdf7FxGS2eMxpUoZJ0Q2bNoA
         UuawvrTeOwx67Qdn9e/pLW5Ia1c3b4wbyxxRBnMffVftS+4rK1zr76XsWq0tN1snSmh7
         ktFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r1t8fKl4;
       spf=pass (google.com: domain of 3qaavxwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qAavXwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7/2dGoFjVLPSaz506icXTL5ku1g4WHGuqLIAP/RSsNY=;
        b=GtinY/JmvX7OqmvFFERVYnObSB7W+Nuo1gBU/p/7pcUUhUdM6OTODNgzC5nhSHWky9
         oI2URrgz0Isv5Lx+bPnkHZ/V5LiQAfMRirBmtyTN5qfJZ9e+iXE0kw6ZS64JNhbSme48
         fwLfl1Z1QJRfxMv4QMtzKM9zmKKy4rp38LYV6XfzfkD9Cs8Uj6xFBMYccZZPTO7UTXAI
         NNCXLePG8ucvIIcwu1IsgZmD2cYgy8ueEo3Iyk5NpN/R0JVr3VsMBdrBEmWoOX3l3wdr
         wxaGrokbwCT13EuIG5/oY3vfQyty2vYwtx/2wq0c9gPIxfApT/G9z8IMT5Lt1YDMw0eu
         8vYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7/2dGoFjVLPSaz506icXTL5ku1g4WHGuqLIAP/RSsNY=;
        b=tKHpW0YM7I1S0W1qsaS7L3PnfWIo1Yrb6bThLrE1K6fvWDCmWyN7e0lNlgryTLFid9
         XEztGOXHYAACnd18pAVs+p/KOc9RR+/tXX/1GFYDocldhdaM9KIAGhEBei2sgiDgMgYz
         yDBNaddDPm7Iah/elg2pcF2DOkmig/y9ajfUyqcbcqcmx8mEE66E0wGDd8OmkIW3mbQq
         15Dq2jPBFkxlma3KqGEKMW2cAO4kNSUqtA52yPILkLf1Hq9VUgrqqRkLStm0DdiKRDZp
         O1NZaIdwuKS3NzFpBzlCCJ5E3NXLifH+UzIJF9Yv2LJWgd8WzxNndrTBFkj8z8KGxB8p
         FMNw==
X-Gm-Message-State: AOAM532vjftRf7ryvB5hOLxjDGtzdwfUX/k1SLTNXli0+XJ37VuNmFVW
	E4yKKdE7AYAcj9nbmOIVu3w=
X-Google-Smtp-Source: ABdhPJxYU/Gw9TWS9lsQwvG/e0r3o4RL0zM0nXkBw2gj5GMW6yQTkJ9CfsS23DMcT2MbVq5BunIQhA==
X-Received: by 2002:aed:2aa5:: with SMTP id t34mr4040594qtd.31.1605306025606;
        Fri, 13 Nov 2020 14:20:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e29:: with SMTP id d9ls2687565qtw.10.gmail; Fri, 13 Nov
 2020 14:20:25 -0800 (PST)
X-Received: by 2002:ac8:5ac3:: with SMTP id d3mr4116995qtd.384.1605306025168;
        Fri, 13 Nov 2020 14:20:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306025; cv=none;
        d=google.com; s=arc-20160816;
        b=CZTXF3Jq+AFVpBDVUFwH3CjVtS1np+hoRu9qy7BJk3ZAN9VPSfYAMmAIzrIE6QH9Df
         RixyzOOJAJd+SOOnhAMDHDO49zVdK02CIlkTkMh+bQvLPj6Ux2vJ3cazLLnYGTD0xZvf
         +J3UjAUgm+MTclASnUbH2NMAJcWr8wp6v6QYhvn1/NaoLjJRLyu6LD13ZD/0nZYvH45u
         gKmWOuPh5GG3XZMqEpt5zte5lmB1YsVnxm/j2pkdrFTnNYk6upUCiB1XG70dhNXs+Q9/
         bmzRxx76MmR4SmgxsqYGPhA97L01trdrRQNJ0GKpflsGcM3u/0r3TDjWYsrRBVSWqEGw
         H+tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=u0fQxCBxmUxhMOfySImDDJJwP6bRFOpgmkJnBahaSB0=;
        b=NUfwE7T+3AIjGw6rIuM9WW1Zue5HAUU3noBZHCKqAeEwuI4A3qGtbCzcWch8hdo0op
         kkgQ3UJmzQjAlHtIO4x7fNTc29anpttMlVfKBB5TRT8CNzyWRJmB6Q47XcdAHdSYFlhD
         XqhZ6mwcU4vOO+piHW1orJ+n9YpHN/ibACcuYFLMtay98qHOpRmgbtWR9wRLFAPKgbWq
         qg7U2Lpo6CP5qJ6XmWvxvTKIpvWTsO9vtZZoVPQej2XyRc8rS+SOae4EfQpLk4TB7/6Q
         epIt4P8rKp42M0ZP5ybdvegxtiTOD399eJRuSZ2UAoUhWgpziF6+lUx0g8y2wCT4V/9X
         kpDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r1t8fKl4;
       spf=pass (google.com: domain of 3qaavxwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qAavXwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id r3si645385qtn.0.2020.11.13.14.20.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qaavxwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id w189so7579687qkd.6
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f9c8:: with SMTP id
 j8mr4873782qvo.17.1605306024802; Fri, 13 Nov 2020 14:20:24 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:54 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <d65e2fc1d7fc03b7ced67e401ff1ea9143b3382d.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 04/19] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
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
 header.i=@google.com header.s=20161025 header.b=r1t8fKl4;       spf=pass
 (google.com: domain of 3qaavxwokcxutgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qAavXwoKCXUTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d65e2fc1d7fc03b7ced67e401ff1ea9143b3382d.1605305978.git.andreyknvl%40google.com.
