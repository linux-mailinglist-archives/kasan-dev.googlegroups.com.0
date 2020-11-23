Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV5N6D6QKGQEWGBWRCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C46D72C1547
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:55 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id x10sf2155460wrs.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162135; cv=pass;
        d=google.com; s=arc-20160816;
        b=O6t2GG3vquSZv2vJON1Txpkxm59nGx2IkqYLoMaYGMMApjgVSyYu5eEKDQo3kZpHxB
         bOBvOfxRGQU8GiKitUdr/3Rv+xY5ZIVMy7z+XpsHz4oYEkSsjO/wsxpjaJFaooQQBo7w
         2Oq7ZPbSsk4UUkYErygFIEMkUW8ewE2Nkr3pUSjz+hIyYCAwCawwjAFWg67U9Rq08WO2
         hMlMzFLWESgKt7GJiei4bfYBm2F2/nD90YHuwUBj21/UifRl9CWaiariT4B/Sp0/dSK4
         xyskYZrG6jKJ1xQa08enWbhpvdpdvetn4Yx8Nx4NcZVRM1fto6GRhD35Xa1GrwZ18JKI
         genw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fyaSwxWZHW4qWdHtSePl3kK3XWpvKCLhEDYMk7hmraU=;
        b=kbGKjO2LbGNR4jjl/gIqOOb+JwvBdwhi0zQcW5Hle1bgCKuckpez5HNTMuMSffLCoX
         ihqW8izvymV2erJBZahRMoEFQOC04UyaLw5zCduo2mQdB95YSLwMBOzXgZ3eoNu00m7j
         68neyRxNspvnhBMwkn5aGcPeLuebhYPX4w3iWsjygRghT7ipa9qiy3OdLPO+0TejIzjz
         Wi9iu4VS5sA3EsK2lKWLM/dgon/uO6oG4Ca35361BNi1lXp4vigDF+acwacqKU15GP0z
         tEQpyZBH8jTvLcVopqy+s17YwMf28ESizyPieLiRa9gmYpKq0JImDOV8NB62NqesiTjY
         2+iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O7WwYPWk;
       spf=pass (google.com: domain of 31ha8xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=31ha8XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fyaSwxWZHW4qWdHtSePl3kK3XWpvKCLhEDYMk7hmraU=;
        b=fkQLMkJ/rxfjEVEJG1bSAItgycYdn/LmP6ZDsiLTEf9E8FTGxgbQqnfjrgVuXVP7Jc
         9pAeE0kvalHoMGDhN8+AC7BEgXgHmT+HLyguXYLyxo7Ewby/XSq9Whfw5lh5DAJ8DNFq
         83pfbGX2BA6FqVQY3RlMDa/otZZR1o20Qu4JXfzsFSIP77QUqXUWse2OJt4MzuP5dxV6
         CnlNBY/b68d79m2FNdSgxnpzKU37RtPheG4JOgQGdxa2QpQZ1SlonebcQlo5HaOsqfpv
         m6oSD+y1c7aUn4DI7qr5wKeG+GomwY3UETIl6WtgdK9cCpJNBh9O0cOZpCkAegJ4UCSp
         UN0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fyaSwxWZHW4qWdHtSePl3kK3XWpvKCLhEDYMk7hmraU=;
        b=Sq28dbYUePGVVId12dPFc3qQKIYzQ/DbEx3DVfe0m3wpu0VMobvBMAOk2rT7sZfovN
         vp8C17/dEzIOo2k/Ym4tyfM6aXVdzXIzxKo3vGSx7vAilfPx1St+ED8i6vaIQzEM5bsT
         a23zwTEdW5E0VbOKUwXcw5zKbH+lemYImIViRYAniWrOAFzB7c3xoV2u19uenWWyrqIz
         0Q3qClbhgeIhTU9FJAo2+HpOZCknlLkn+eujGZyOBJAr+TJDeHGDNfkLrYdfc0DfVOY9
         6DkQG9XV/QIn4a+rheD1po9y4QaeTUKYPrEKkwQVPlHEBptnjjgTK+5gMK7S6S9hcsgk
         S99A==
X-Gm-Message-State: AOAM533yIxgPepml1hIxWXnrxM6gEQhQFfOW79tZfUPDndwP+C27aiU2
	VWELcqaFd9X4zraUWGOWUWA=
X-Google-Smtp-Source: ABdhPJy2Vrwq0WZAcIVj5wI95wcIeb5pK+a+q57rzxaYm4phdL4tujzHV2/laWiksKgR0SSnXvy6qQ==
X-Received: by 2002:a1c:bc08:: with SMTP id m8mr591759wmf.137.1606162135556;
        Mon, 23 Nov 2020 12:08:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c689:: with SMTP id j9ls8969533wrg.0.gmail; Mon, 23 Nov
 2020 12:08:54 -0800 (PST)
X-Received: by 2002:a5d:6406:: with SMTP id z6mr1410171wru.241.1606162134741;
        Mon, 23 Nov 2020 12:08:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162134; cv=none;
        d=google.com; s=arc-20160816;
        b=V4vvXPsW2ZYkze06Xu9ONV2Lgx78LeELwXYGXF0uDexqBvTo36Cwiu9X/YIIKJzKUD
         Fp2C4th8JWNejxcaTEguIpv85uN3c0FY8G3TeAxCXB2Yf1RjFfTp9aQ0XEABYRQdyaJ2
         dQrtqQMms+UmUgm9kQfvYApjjUVmQHdnsbeunQxY9VZzpcbYlUZnbDV1di8ScCskE0pW
         3mFsApLj6emajD1XVFzKM3RSUS5JYJxTALed8qASSCtR0mEncOjMaj3Wf7hm62TWXA4X
         5Jnamtavv1PwAj1xav6iXQ9LlkatCNT6CKBs0NASMeW+YEOz6lATgWUxC73SDdpVePWm
         4T4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=j0H1kye0JXAlJChaoMRiBPaX4tsiHsBeGw6rmAAJgEQ=;
        b=ZHpp8DE6lpK6FW+LjFQUh/vGf3cN4BO85x6nrZNihHoTHluFnIZHkKQlE5XR0rY5rF
         gQUv+DdMNAvdTq82iJXikEfj2z3kbGCzJZfqmuHL2c5Jg5wmi62x4pu5Njl30leKSSsh
         N78kxOkxFf3WBLWvi4YDxHPEsN46y646LQpL6+3nJRRJufHld5aBRFKwcg1kvye5w8Xz
         Nf9O/ZkfSrNyuB7s2O61xwcxNZOys/CPw+erjckdPjoxOUxXPu+75WM6BrjIq++R7DOa
         q88SvORDuBgVMfzba3/fR4n5ZXBzxsWqQtomfKyCzP3vINlKOcrvvCEChaykG2EblEi2
         nA9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O7WwYPWk;
       spf=pass (google.com: domain of 31ha8xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=31ha8XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id w65si9904wmg.1.2020.11.23.12.08.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 31ha8xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o19so156535wme.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:a752:: with SMTP id
 q79mr630695wme.24.1606162134262; Mon, 23 Nov 2020 12:08:54 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:39 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <e16f15aeda90bc7fb4dfc2e243a14b74cc5c8219.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 15/42] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=O7WwYPWk;       spf=pass
 (google.com: domain of 31ha8xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=31ha8XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
index d237051dca58..58567a672c5c 100644
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
 void kasan_unpoison_range(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -121,9 +124,6 @@ static inline void kasan_unpoison_range(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index e53e2b110128..d440060c9008 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1225,7 +1225,7 @@ struct task_struct {
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
index ae55570b4d32..52fa763d2169 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -47,6 +47,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -56,6 +57,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void kasan_unpoison_range(const void *address, size_t size)
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e16f15aeda90bc7fb4dfc2e243a14b74cc5c8219.1606161801.git.andreyknvl%40google.com.
