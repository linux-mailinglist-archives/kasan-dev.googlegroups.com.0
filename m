Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIVAVT6QKGQEAPCDUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B440E2AE2C1
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:46 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id n207sf62165lfa.23
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046306; cv=pass;
        d=google.com; s=arc-20160816;
        b=cGpjkKi6dNvgxKpNpRk4GImvOnVLhOJKm/D9gv9uRwnM/xGnlffjRATWpi1xxNZPaJ
         k3I4e5ZmG8k/qDPR9UVv/NzkaIOyQRObN79PR/GWXB6daJweh9VyGefWXQ1tPCEawscg
         sccWudvsI88RXde8K4nvD6/+cueEGTg0KIEeIwH7skyK5IuF6J55gloW4fGwnLRPUxom
         dSPS93SEFiB6nGX1Twk3xzIpCCeRhCXFBiBwTkyT/ZNj0DVFyB/vwby+szL+Ih1mGVvW
         IvFa3Su31zQjbpQiRY0Pph4+pScwX9kAiMycnm0LeDhBOnaleoFAQAF2uQYuRO51bgd+
         yMrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=P+16jG3Isb4JsSbo/Fq8n7glZXW9ZgUNHbjQvdxzV/4=;
        b=gOSQz2p/0sa6HwiSfJ0omJtXPhu9nRuCSU4l0UxyJjrTnx+b7bD866SVahnjEDGVlH
         MSlfSK5d6LmoHBEVZedTUdEgAbjiwDrsRtUlPmco9YwDPn0MhdmCveHwApCbzfoUbMoj
         bhwiD96cSQ02cPoSFYUaBNBdOi6QLJf9nnQhYK42z0ObYqyTMaznXiLs288c5i3pzCvF
         x4doayOh7r9g/+ulh8YqTVYbc2qjIqUeXONdRSYWMRZF7lJnfh7R//5bH4sKpGP5zCv9
         3LcnLdSbC5ACQ+dOd1SfOR0+AEOVFn1YE1VoDvlutI6mQBKdlJKKt+ZMD9jHrivkEktu
         SHPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iu8mOEF+;
       spf=pass (google.com: domain of 3ibcrxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IBCrXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P+16jG3Isb4JsSbo/Fq8n7glZXW9ZgUNHbjQvdxzV/4=;
        b=NSvNv4SRbkceAdmb79nzmLgITYd5fkNaLPvZ1lx6ggkiNKQjDXcenmbpbnxaI706lT
         fJREsrOnbPt5Us4NpWE2aTM1rZhlUexrwc5zy0hpvymvjCWtaJMc0V1SKxtUdOnfb7Ee
         35maZYTTNGom+PqgpfNnqji5JSxOvRW2wyr5aP7ia2R0VgIy5ivx8+SMgzQKCPtvc+bA
         zbe2zpTSmEr/MH0dZyQAIx8uRSsLom2T6PKjN/PDnRp76Plh88P0uL/ic/QoANqShFE8
         4wFbJP40gFevnWpbbppEbVOQkC2Jbtc0Qa5+1a1RCp1EgGqPy5WUm7BgO14JE+tG+YQu
         MW2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P+16jG3Isb4JsSbo/Fq8n7glZXW9ZgUNHbjQvdxzV/4=;
        b=M3MNR6qgr/LAvwUwhvdM4UgsNN8NiQeK8Jr/fcDqo09se31Kiqp3c2CBdZNm1ywtRO
         g4n9WyQFN9foPYsqLHzDLiBz/t/oXmUxqgN8TV2WGquERK23qp81aJKyKudzTlu926Co
         kq+oZJ6KXxw6kzabMSh4Vk140fuiEJt2PYdlTnvHgLtNZ08Wety9eYBIqyQh7RfA5AXg
         kTsXLHirQa51A45DZ/ZrMvhjULgwCcnX9Nvz9QdPn/KKEIzUnAYYDL4LbZnXVh3IOFS9
         2NbL62HU5KAqKGBPEwrHJK4VGEnlmUOLTZhK5Qa0bGPI1QHGj3S9Eu0uzbMPsTx/5psl
         8JQg==
X-Gm-Message-State: AOAM533c0Squ3jzZIOZ4xMZuE7uMsultYBlBKWp0TXu6XedcfFwtN9eQ
	xUE4BxQXmKslsbOBwLzB5TM=
X-Google-Smtp-Source: ABdhPJzoRtGrR3U75MxGtGd3fEMWBva+pB9lMfP1rFfvr3nrxmYSUlIvjxM7pZ1aawlNNHCPatZ4Ow==
X-Received: by 2002:a05:651c:545:: with SMTP id q5mr5314262ljp.124.1605046306291;
        Tue, 10 Nov 2020 14:11:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e89:: with SMTP id z9ls2398032ljk.11.gmail; Tue, 10 Nov
 2020 14:11:45 -0800 (PST)
X-Received: by 2002:a2e:90cb:: with SMTP id o11mr1133632ljg.465.1605046305164;
        Tue, 10 Nov 2020 14:11:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046305; cv=none;
        d=google.com; s=arc-20160816;
        b=azWV1bXEmaOrujp+rCykIDpmrPci+mJDbW29UFPVGh6Lecz3uoxYDcUuynZz2uF1ow
         E1zwuQPv53pbscwRea9+BYpgoalauVi1OvTM7IVxK0PK9WvjM7WJFcNHWvI+GDG46smx
         DkqhKOOnyV8x7eQuH+UAuiPEcepX9aXFCXGTgD+fR4eul71Wzq54yeVxDoIz0t7/8SOU
         eja3icALtpXVm/vQzVOBsh1PZCKBHeP5MUCE9lij5BzFuRN55y76STpOS7g1+ptt043i
         Ag5ayGDmS03VdDgcM4C1SzBOR1SFC3Y1xxklfBSPA3yiTYEZdjXxR8dmgXLu+VmoIwGL
         awGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LK+ho829pHfUNxMsQpfFeZONsS3mumkNxCYvKzzjGVY=;
        b=QjS3eRq0HLWQ0ra9Yimk4R2nOoPhTE4sEmY/MjG3ub1diikOhAa6m7WNRlJd3LmhFJ
         lGzEAgRhgNL6CWkM2iWLk3kmxwVUqQT71NpXHsf6PqtmryJzEjuZayeu9Y9B8r6ERrU5
         pPgzoF3GuIBiq3959RDRrKvRu/aVBsrjv3wueHVL7BLduaGk7i23hQhSpz5K6EndaMmI
         H8RrY84WAxmjtywR9yEYx6mgCvWARfOlVp0hY/ZVCj+PUaoOumZLD9kitiogUeSM90LG
         HRTnUhwDYMKpLFRlmgNfTFtX/MavAwL86S8T1jtR4JVuDhuZ6p0zFlkL5yxJKzYP5i+Y
         JC9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Iu8mOEF+;
       spf=pass (google.com: domain of 3ibcrxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IBCrXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a1si5499lff.2.2020.11.10.14.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ibcrxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z13so239910wrm.19
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3c84:: with SMTP id
 j126mr226389wma.151.1605046304637; Tue, 10 Nov 2020 14:11:44 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:13 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <91b3defa17748a61d1432929a80890043ca8dcda.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 16/44] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=Iu8mOEF+;       spf=pass
 (google.com: domain of 3ibcrxwokce8reuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IBCrXwoKCe8ReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I6109ea96c8df41ef6d75ad71bf22c1c8fa234a9a
---
 arch/arm64/mm/kasan_init.c | 11 ++++++++---
 include/linux/kasan.h      | 18 +++++++++---------
 include/linux/sched.h      |  2 +-
 init/init_task.c           |  2 +-
 mm/kasan/common.c          |  2 ++
 mm/kasan/report.c          |  2 ++
 6 files changed, 23 insertions(+), 14 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index ffeb80d5aa8d..5172799f831f 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 }
 
+static void __init kasan_init_depth(void)
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
index f6435b9f889c..979d598e1c30 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -51,6 +51,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
+/* Enable reporting bugs after kasan_disable_current() */
+extern void kasan_enable_current(void);
+
+/* Disable reporting bugs for current task */
+extern void kasan_disable_current(void);
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
@@ -61,16 +67,13 @@ static inline void kasan_remove_zero_shadow(void *start,
 					unsigned long size)
 {}
 
+static inline void kasan_enable_current(void) {}
+static inline void kasan_disable_current(void) {}
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN
 
-/* Enable reporting bugs after kasan_disable_current() */
-extern void kasan_enable_current(void);
-
-/* Disable reporting bugs for current task */
-extern void kasan_disable_current(void);
-
 void kasan_unpoison_memory(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -121,9 +124,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 063cd120b459..81b09bd31186 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1197,7 +1197,7 @@ struct task_struct {
 	u64				timer_slack_ns;
 	u64				default_timer_slack_ns;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	unsigned int			kasan_depth;
 #endif
 
diff --git a/init/init_task.c b/init/init_task.c
index a56f0abb63e9..39703b4ef1f1 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -176,7 +176,7 @@ struct task_struct init_task
 	.numa_group	= NULL,
 	.numa_faults	= NULL,
 #endif
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	.kasan_depth	= 1,
 #endif
 #ifdef CONFIG_KCSAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 543e6bf2168f..d0b3ff410b0c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -46,6 +46,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -55,6 +56,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b18d193f7f58..af9138ea54ad 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -292,8 +292,10 @@ static void print_shadow_for_address(const void *addr)
 
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91b3defa17748a61d1432929a80890043ca8dcda.1605046192.git.andreyknvl%40google.com.
