Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR6GTX6AKGQEB7J4MVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D6128E7FB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:55 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id v12sf71138lfo.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708295; cv=pass;
        d=google.com; s=arc-20160816;
        b=k31SAZG0v9nnUm0hq5WShfPkhvMV4S6HRf9pUBVeDkOdcGbgHf2YzW7jZMd8RVg4rL
         AzlDecXqlW6Umkqj1AYWvra5cusTyExPt0OC1vyP/3q3asmfjJMyCle0/HXTbD7D5k3H
         qK+jN3sZ6GXC+yqqQuZgYq9SghP+sboTAepLR+UxknpgTaA2AHuQnjRpG8ddhMLekABF
         Dvobe8MVvsvOPBjcgbAsF0oDtA/CzdNy/Hly1nLkGLLGq/Z8JlXrLHQb5KkPnNFO8/Ti
         QYdUFHYQ4LW3c3mhJPhSrLWWRmxVyI8f8o+aFk6Cd34/VHjMIbIS9uTkY9WDd1dkNRTS
         /idw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VznzWalzYyWtw6EY3Qv1mDb5TvHXj9YMoC65sICSwMo=;
        b=sTuaAsk31+/4Ok+KWfqOpPr8RhMqxfxBto0OcQKf46VQ5IPrrayWeRI3HYd2QrOUVf
         W7Okaeh1BWZHf5MQUAjNOq0o3RcqGFe620MDp2OQMx4hvjBob+/Mi6jefX6L55THbDBE
         6910RpAy59IA1H0YcZPjJ7YRDiWlW9erwGRrPfM6Svg0H/fvhsauOhsrnvx1CmGaRuGK
         0/QEdtc/sj8EtJRaDeNz6YjOVu9HjYC+lEsg0iPbhl0PmBnWt69Of4qgOf/qzZ9PlqXN
         PdhF3hO0OvXcZ2RvbYIOdYepSMw+IPjLkrNda2YbDCeqpbGQLVxNFZmT1p4rs1lyl8lu
         4ZOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uaQGYSwB;
       spf=pass (google.com: domain of 3rmohxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3RmOHXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VznzWalzYyWtw6EY3Qv1mDb5TvHXj9YMoC65sICSwMo=;
        b=kdr+TsXuqZfaYt7ZDw2nurXULevKexIT5eUADBE06r4axuvevNrZjuj3nFsmpkUmJK
         Ef6dSDlbvWAIO2vVUlgTOQqDyBHTLF0jap/EtI5OUp5zKkZ+V2h1reb1aj4un8uSZN8S
         ZxqEjj8y9Cv+3Ox5JRkYKJ/yNTUsoTr2FvKxxB2FxLpqPelPZp5UCSmCCzWkRDqJoFsc
         l1RKBNoEM/9oaAP4OF1wgHOGtA8gn5pDK2J9Hoey9SVEwAQJoQKKcW1cCI8HHdTvG3tF
         VtFevDP6CJvHbSsKnQMuDYEV1uS4Tm43yXdxA+nbHzsUlA7oWU7UMhMqqmj2PI4ZmNnn
         RL7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VznzWalzYyWtw6EY3Qv1mDb5TvHXj9YMoC65sICSwMo=;
        b=rYUd7WhCIraq7HT+co8kZxgwbmE1Y0CI+ueciPjk75WjVV1RynSKSzewY5URcqZ3L1
         6yCJlg0dpzBw4F6c4mjzaLqh5K3BDVfxxsdl04+tzXWJR9NZ/RodVvmvPw8bnBeHGr71
         Zvzl9ZSUylW8MQeZKS/G5/1o5l37bf5fygJ+l3qRrv3UJvPoHhkSZIrQvJqabtO6PqZz
         SIQ/gHfS7lFQ/mwHnwndgnSULbVEo/8Q0WMKvvjEuX03xIziOmJYDvV7zFivEDCNt2eq
         As7Eok6pxlfQsL1x6Vn+y4UAolZEslEZYq4kvI3S4wFEUBVFsf8NWj8fEC1X+9SkcULL
         UVUA==
X-Gm-Message-State: AOAM531hoxrvrMJOI5JFEwUscvqtpvkYLW3OXsSWMKIcSc8Jgi4KGs3B
	YsFGJ7JFmNwBFkOoAD1GXTg=
X-Google-Smtp-Source: ABdhPJytke8Kb6n4ShAunyg77tNY6gtI3Ith3nzX4jez4tQQxnYidPIFQH8XaNrSSgNNGJGIDnXIzQ==
X-Received: by 2002:ac2:424b:: with SMTP id m11mr360552lfl.339.1602708295340;
        Wed, 14 Oct 2020 13:44:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b6d4:: with SMTP id m20ls155881ljo.1.gmail; Wed, 14 Oct
 2020 13:44:54 -0700 (PDT)
X-Received: by 2002:a2e:80c2:: with SMTP id r2mr162541ljg.402.1602708294331;
        Wed, 14 Oct 2020 13:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708294; cv=none;
        d=google.com; s=arc-20160816;
        b=sZFwkKq/Vt+rcJMUzrq6tcdoRyF0ZFNZdgvyX4N1fOAcvwU5py/asWHTODG2ntarii
         hbIUB5C++bKm/tr+Men9GiZmho2ti1nkM74KPAiyLWNhPg2lAxi1IYkAKpCaeiwZerGQ
         8bBZBKT988Qb+VZudJcrhKboo2dXs6GLV+49cJZXgVPb+90M3ekP4wGDgvQ//8n3R6tr
         HiBcTTOEvPlikrGFjp3Pb1crVjoqC3/UBBmbyp8AzFK3DT+psPT+FM+Kmofwx9n+lbVp
         b4HYgziiJbFYqbgHwBZ4YpsBf2899EhciOX/je2W4LI9TEREeVQEyMirPNEtW4JNnmDQ
         qokQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Jb27DzgR4IKP5v5pwQruBqbER0RzES4crWan7oQ9jac=;
        b=KU2OcT+Am3zf1HIMbC0DJYZDa7CEhQ3gRY7Kp7A0gPC0I6yzvhFvHvbfo/u8CVwJrb
         /hhJl3geYnec4Bcoo7xvY/5JWaO9BZ7qij9n2Fny4f+b3a26oQz/ctjdBPPwYraX8HqU
         ZcfMQc33L565vg9UGc8LAQtbmk2fHnytoTQaJ5Mv4y3oqBBIJH98Bffg3i4V63xCy1OZ
         rIGy/+lhb7N67TkxmV1ezGP8WwsA2aqwZijLPHo2r+w9XSLPdTmklVwfCdrBp9+whoSc
         RgOi7vJP+Nbi8ey7PrFsL6DN8fChqSbFbMW/7RbBbR5D0eTe6sVgBdsWbYDrdiHYCqgM
         +RUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uaQGYSwB;
       spf=pass (google.com: domain of 3rmohxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3RmOHXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l28si17124lfp.11.2020.10.14.13.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rmohxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id f2so397571wml.6
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3b8a:: with SMTP id
 i132mr609269wma.178.1602708294026; Wed, 14 Oct 2020 13:44:54 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:32 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <a84636e18c42929492dd05dd5e01128b36196852.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 4/8] kasan: unpoison stack only with CONFIG_KASAN_STACK
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uaQGYSwB;       spf=pass
 (google.com: domain of 3rmohxwokcs0jwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3RmOHXwoKCS0JWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a84636e18c42929492dd05dd5e01128b36196852.1602708025.git.andreyknvl%40google.com.
