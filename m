Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJMCRX6QKGQEUYNFIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C63902A736D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:46 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id h65sf213215oia.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534565; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pep5hY4SLKQ6nqhTiAtatu1RmAFuHGy1dJpirXfK/p90SRNdj1jjrNRFeyjjio1oIZ
         RwVS7omxx5+J6PftZqCZLBTFhhWzkh2+nN6XzgY5nW6a1+sQEPwZmxktkca0CdCONtT+
         z3itqDoqaROGuVWZxCk3VMZD1S5Rhj+zaR0Q3+yN3Fc5/MN3c5af1f6W0zaicPilbty2
         NwkcjnW39r5VUgZrbQ/c2vhjsiLDLigB/tb/69wRumFg5WQWXIqVaIJQPA1t3XfrB2d6
         bLC673fib7tx5nBW//NJlgDQS3R0Ibvtw7T+77FIEwyiOrbsDvjiQ8Bpxdwd2o/UuG5N
         3HyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zdXd8wnqmZ3H6Lbpksn9hKbLTC1Yqmb1OJHvtq6gHc4=;
        b=Wm9WMaR1ABr3v+1ErqHIf+mQdOTnqGu6bXn/o/SeURV4gLLJbLh6cYB5ppU4j8NgYj
         afwyAwApWHhx5RwHdOP39mqYvXddCrKvjqt4J/t1443KgBNjal1d1AjTP7xW03pXIXTF
         71wNoWdbekzAg+lBv7Q1I6+Nh7e64OzvSDMoeX8kpVmxXucYY8txfIojYlEo4to30ETh
         sPmID0yaBPFfvMtU+z0y1sWmDKbDERrBJBGnGhQyB+WCd2u5pLzzqKspyKIK5Ftmxvak
         NranAlCqEtisGiCexscgZnMqNxIJuOkUnqPE1knLSX1sX+I4/8MhJbeu+YacohquoTp3
         Cpbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PRQZtB1d;
       spf=pass (google.com: domain of 3jegjxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3JEGjXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zdXd8wnqmZ3H6Lbpksn9hKbLTC1Yqmb1OJHvtq6gHc4=;
        b=YMW63m5OHOGTT3Dlbidh/C0VfenHXoLae3CILv5O6HIuZqS34h303dIeC/g8k00KUi
         rvzzS/HvsuvhATZJ37Vy88G/gIyfUok2EiSOq4F2yBEv1lfTz2ka5sqDFINac7aszNzN
         kGjK3VNqKDv+z33Tb1qIONJw6C3cUZAzbfNPDgBf0PTSSet8xcTATBHMacW9wf99iERM
         8hGh3FBZrBbYYOVIxTMkdYPUytIFYLeXL+DN3YnqMm7DPuihd99tVlzyOnoABAZ6wr9r
         9wDET1k+uE6Muc22Ui6JqFRO2mUreqPRqe0yIUQWGw0KCs5Pt9iALuF2kq1yYMKdEObK
         tZWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zdXd8wnqmZ3H6Lbpksn9hKbLTC1Yqmb1OJHvtq6gHc4=;
        b=lDqo/N5E17Mlt4qUUu7UYg0nVCLkol4VSAHSxut50k08j4114NssvMDXiIMd0QokfJ
         2Bm/hWkQ1L2Bn2r/43ruMCPmb1aGYeFLy1/4uOCKiu8lkiqUIIEwolhxc+MJSPD5LL4w
         EbUjDDgNYBKnofYlkQzzjNlbI+0KvbKc94t1vRczQed+oZtEB6gvt3SRh5JQsVzD+cFR
         UzUtzPxH3S+IdpzvU4ESdN5PQvfBcHb0mNZlSLCubmMueSLZ5Swr7QpWch9qpR5ADzBH
         mkjiphppPC+UcZBQkFJIW5aPDOBHdGsB0wklMvDr76tjOaMiLCJEShuOvNkaHtf0mfr2
         XJiw==
X-Gm-Message-State: AOAM533lMid1eH4WzR5RtmzfWz+lQAcC2K0rjAdE0SZxu4KrJnQD/LFc
	lFtXF57OfVtwz4kCV5hVC9U=
X-Google-Smtp-Source: ABdhPJwQSDohlNBLOzZfwKKcpNbrBGTtZT25pcpcxXNr1nug85gcpwPYkMT3fNqxDPNuUhYRH/yOew==
X-Received: by 2002:aca:b455:: with SMTP id d82mr172280oif.127.1604534565808;
        Wed, 04 Nov 2020 16:02:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls934078oth.1.gmail; Wed, 04
 Nov 2020 16:02:45 -0800 (PST)
X-Received: by 2002:a9d:6751:: with SMTP id w17mr157575otm.7.1604534565441;
        Wed, 04 Nov 2020 16:02:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534565; cv=none;
        d=google.com; s=arc-20160816;
        b=i3pk0ycLur1UgVJ6pS9inci+Dyph/vVLDW1nDeKITRGePKf69fXCyTC2TcXUnqysO0
         KhWh6GoR3y1u105Zi9Dc5BUzNn/tM6IjGjt5xG7wR4IVpMPvmjgSzStjmAXIj4y1I63F
         fl1tCkptTowguYVVmK3X0tXx+FW2ax06s0sqFkCJfex+DCKCm+YmLipxuHPRVEYwR42o
         nMgqw76qcGAW15aeiLQI/raAngbgsAbaEZmniAZB2e0WEhZkLmJ2pwAyf8Xu4tnqedkI
         s/A1Y3YgCucfQU9Kq0ufJFLwU1l5TtVF+2TC9FrmuonaVytzt1AvXAru7MIp0oNf+olV
         4qgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=75cYXImCPyiWQ9SKzSdNGkBAnxoIkaWvKX26xtnhUe0=;
        b=doo9yFNWzBO8baA3SgG1RaVSQLmFO3Rm++a9AFjsIswtZNRR6UC/cBbCvTOqiuUUFm
         EYJwi1ylZje3Kpq5NPdRcKdbIsn2uRgUj+eOI7LmDk2EBz/zpUu2Mbd3AQtruOoK3c01
         gQSasczWAeq7E+fZxZeLhPweP3CiGd4RPPG2+WfJTuGmxVRE6Nk+IuR3UtNf4ZlWbUwB
         xw9ncAalc/6OUTbRsrBX8XDNeZzYv5pvdq4fLF3q/IjqyVWujkAM3kzvQFORCUclwSLO
         k3k0JQvkI97sOUOtB9m6T4ybySeOpltSd2xZVl4if2M9/BxaZaHhyjFh9C65aw8mJTzl
         iT/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PRQZtB1d;
       spf=pass (google.com: domain of 3jegjxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3JEGjXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id f16si1509otc.0.2020.11.04.16.02.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jegjxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d41so30574qvc.23
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4443:: with SMTP id
 l3mr356156qvt.53.1604534564913; Wed, 04 Nov 2020 16:02:44 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:14 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <16e48c6ca3f6ea0cb80d3555723a723bef85270d.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 04/20] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PRQZtB1d;       spf=pass
 (google.com: domain of 3jegjxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3JEGjXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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
index 42a556c5d67c..2c37a39b76ed 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -74,8 +74,6 @@ static inline void kasan_disable_current(void) {}
 
 void kasan_unpoison_memory(const void *address, size_t size);
 
-void kasan_unpoison_task_stack(struct task_struct *task);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
@@ -120,8 +118,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
-static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -173,6 +169,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/16e48c6ca3f6ea0cb80d3555723a723bef85270d.1604534322.git.andreyknvl%40google.com.
