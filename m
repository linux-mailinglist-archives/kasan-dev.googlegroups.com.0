Return-Path: <kasan-dev+bncBDX4HWEMTEBRBN5EVT6QKGQEWYUY5WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id C168B2AE324
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:40 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id o11sf10361770pgj.21
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046839; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0NjuqeExX29zdxEPtaFmG90xyeK9CRLdY99B5rch4hj8PBF8x2+od7ePc9rrHBIni
         HvIp5akopr/kZt56OPClCgzhECqj+mp+H03BTa/71XSsbPyW5kCLEBDMMtf8orj/KbaT
         +JgyLHsTaPFI+nA7ju8lqqWOI14mKGHs6XXUjs7WhuzF37O7T1LHPGMOxB+P+cWTsWom
         MK87BcD8aHhft0Y4QUlERzvk9HJnma5IEW9Pk5kDNEfXarjjoT2mAfKtznuK8wNfVcXz
         GSAknXq4Ve7qkDIAsK8OcgcEGsMCfWMutQ8v0/77Ba6PyLizzgm7VBXKb2ZMLg8uc6Od
         7/Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oCTFtM3cvAdqtQSb1Z5LsWmtNu3FOVaDx2TbfDtM7jw=;
        b=AxKM+8z0iKYfY8xm0z+m3cRSFbc1bkKE2ab8g1ir8h9aqny0EVrIp9k91ytw2+Wbx+
         YW3ZRqg1wDESmRNMY4uguwFfd3g/9Htqsadkucww5hoLvvbdQ0bzYtwE3lkf73Lz/vIJ
         f9/lOcRK4zBJVoNZdgy2wcKpBSlMgpq0QxWz9WkX2rdrNRBYNeNGaU8kaIsgf6aU6OCc
         L6LU0BWRt/Z9OJdKc/qhOuMPykAqejGPPFgiw7+ZYROvMqX48eZOO4kwdaUUVh25BdLX
         sVcHnmy/PleTmhp9QMfw4IIgVrXiGhljpoemebSHxRBySM2oPPqDUOpE/n3Nm6PYvo49
         a26w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lw7P323O;
       spf=pass (google.com: domain of 3nhkrxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3NhKrXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oCTFtM3cvAdqtQSb1Z5LsWmtNu3FOVaDx2TbfDtM7jw=;
        b=be7EgauFYIGPkUhCbro24hdvz/0PK+4RlxSyx4hTRvXRRlBbInDsm08Skk/0tStf/j
         U+QCXdYeSt/AuXZvtKghA03ekxD3ozHS1YSx53Pz+EU83AKi5TyGri2TSbtSr2ebtkv7
         JsYDB99VjjUsifK7R2P2HLxSQ50LbPM50PVxaE5HDlqmlqQlP1ICf1IlU6mC1RhnDzqx
         HDAXlnKZ+X4ZigFZWK0I5C45sn13Bd4LRwPA0AV3REfO2dStlUvXjhRVUPD5G4eAxxFe
         OQWNu2WONtBnJp6WYUYO4VX9lpQp/M2SVkVtEJlaR0LTijW44ac1CBbQxbTZSQ9yqfDb
         /lEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oCTFtM3cvAdqtQSb1Z5LsWmtNu3FOVaDx2TbfDtM7jw=;
        b=PsrgLSnJiuwiNzrhmPWcW3t7vy5CVi31L9FyJq1zOlw6VN3Qn4CXY+kD6k+HuUR1E4
         0MfWoZLDplMG2RQx03rBhnFFKtpOoRN+maXXONduCJmsEGdK9bnMe87c8Ck3hG/mX3Iq
         C8wnDBzYaFrT5FY2iMNIi0Wl4p/MyudOnUHkukpOgJH1MD0NJi4AfUEf2x1+ndaDdLJm
         OvgZHH9fzX/KXfVvEuVscni+S25vRi6D5CSKh8YlpiuVbAiGjrGrQXJpZocqTcI0GPV7
         NcnkcXTEBW2qmPrebB1oy5/nNbZNh5sQhrU+4jzYieWsDKwuk0+EeFardb6zh++G59uf
         kpiA==
X-Gm-Message-State: AOAM532yPF1gS2LBhjFBZWKq4Jm24+ger4oU4YH4vPAIIC3SV4Cd824z
	AuuvXTazIkw/etchmor3XNU=
X-Google-Smtp-Source: ABdhPJxafbGCnvzE1JG8EQ0QzxN2HfqG1RClkuXc2Emr1dZUp4vELgslG/M/E+5Ppz6UhkTdq2d/Fg==
X-Received: by 2002:a63:f445:: with SMTP id p5mr18562981pgk.293.1605046839521;
        Tue, 10 Nov 2020 14:20:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls5853138plr.3.gmail; Tue, 10
 Nov 2020 14:20:39 -0800 (PST)
X-Received: by 2002:a17:90b:3512:: with SMTP id ls18mr372060pjb.70.1605046838982;
        Tue, 10 Nov 2020 14:20:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046838; cv=none;
        d=google.com; s=arc-20160816;
        b=ldMFI5bW3PmXlGMPDzMCH4UrsBoWQOz1ie++g9HFPcf6RdsKN6bsa5/Frg0xjcPjXX
         AVGAZKMKgTRavoKkqRWakKPFkHxdMPbLeloRi0LGeEw4m3bDIN4CYHcIpbguyxSSCa9g
         uzq1QRmlLgO+Zir5BSZZwQvVkOGwv3bp/dz/MSJbsq9ToXb98PZDaAT4D10HtSUedTe5
         sb4V8E28LO4sgQ5BVK+RyZy70ov+8wbeXxv4NRfJWFedQFhFZJn6qltolzoo036VbRd5
         YInIYKUfz1sGs6OmhqQHgw+rA3NrxRNlqFpkmu+x06ILUbSGQvTUqKudhQ+U+ZuV/XJh
         wJBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tEdtRhABI1InYFpD5ltmIm/evviW/mtmaENcJYt1lmc=;
        b=UQBK4Y2WthznOcZq/lj61fCMy+dwU6lA4Ro1X9YmG3Vt0nlZhn02TfmiSNcMaNZmgO
         HX6D4yeob/79+I4cATjCfTEIb5VE42TnisZWTSh3pHpEKkOsUCOISILzF13H8HGih0Eq
         jMQ6/a/MNT5eAXhKyL82+0rfzVDpZCHsxWYyDOizgewe+QEdAWcym07W/t6C6lylaRrU
         XERBnjwHfIheLCdg0WplmWBabciFzdLLUYV9d+PXrwhKubf3srRYEr7pl7+VnvU/Hm/U
         1vhah7E8dts9s4KqlwgONKVEgyvHqfUva3xx/PZtjmZ8aI92Z6C9Zw2Q6uGdI327wwn3
         VfxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lw7P323O;
       spf=pass (google.com: domain of 3nhkrxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3NhKrXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id m1si3595pls.4.2020.11.10.14.20.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nhkrxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id j5so8487394qtj.11
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:6a7:: with SMTP id
 s7mr22500256qvz.2.1605046838323; Tue, 10 Nov 2020 14:20:38 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:08 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 04/20] kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Lw7P323O;       spf=pass
 (google.com: domain of 3nhkrxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3NhKrXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
index f22bdef82111..b9b9db335d87 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -76,8 +76,6 @@ static inline void kasan_disable_current(void) {}
 
 void kasan_unpoison_memory(const void *address, size_t size);
 
-void kasan_unpoison_task_stack(struct task_struct *task);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
@@ -122,8 +120,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl%40google.com.
