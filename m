Return-Path: <kasan-dev+bncBDX4HWEMTEBRBC5P5T6AKGQEM6MATRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA5F29F4FF
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:07 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id m20sf1676437wrb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999627; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJz9nEkFUl+4JYMRyx312Yk3CXuGjDAFA+JiTfwT892wefFZkb8xs59frDVlESW9fr
         pdhZ43490l5ca+/hGU0B4l0Cu3o/yoCwkUsyLGVCnot+6cdxLtS98kWoHHmyaMbR7u8x
         j428LIHfK8v7EO6O4AeN5eRtHjJIGJkqtYKd7GDt0qZGhXwJ/qDat8DJPnKjiyzM8mwG
         SCGgZzLad+D5DKf0jCSdqm/M2N+n6hzanWxq17/vpKto7ob1QGJl65s+Im2fBTtpI3/P
         iUdqynqOMtoVYfKOEPjZrslTToMCxkZhX/0V1Wx/z5IyrHwVQH2sXaW87KNEWstIkltI
         u4+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=I90eDVb0EcaHzesHFmYFLUJWlkLFppWsKeUiUqFVRUU=;
        b=X+neD1kJPfRGyUxKScoBFIYE9nFFk/L83UICnRq2sqBH9fcigOY67Xsuie2ChW5xQp
         y9P3OF/Ec6r+k+/pAFEoUUwmrR7v1vRO8G9SbKbxPclgzRi3Cvcza+W/p0XqnMF5CifN
         lg0JHwbjUU7n0PC60Z64OEd6nrAfxT8RTUxNWTEIhGbesBne4oms0BwCic4tNboS1S0e
         SP0GnxXc6w+6jcLjwv/etmUYwajb0/lqN9ctaxTbHhahS8gR0IwW0o1sNB0w7LgoGKaP
         syBQKLJw+HGb4glppAOKU7e96sbcDCbUY7lEBJTjeuBDUx4TuEL2m09tnZ+gqsBGq0+5
         ON3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JIIuHmSb;
       spf=pass (google.com: domain of 3irebxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iRebXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I90eDVb0EcaHzesHFmYFLUJWlkLFppWsKeUiUqFVRUU=;
        b=KxmaoTBV1TzRecrt7a9s05MKGs5XZBGg273xI9tHcahFu54DI+G1WgfqOghCpvh7ap
         ZGKoIbTIBG4d64qXKuTeMxDCt8/uZ5KnaM6Y/pMdZLYQaGmn2M/QgVPZCv5PQs3ivCOB
         RkPsDmHCE4XHcfuBbVivgwgc61EluIzuUC5AdW4+pVgWD56XcphrLPTy+C52pogpTPA1
         N4ouGmUs+NGoonPum54c2QGalKPilh0j7kS9YfXYgWcT+NAnQjEzRiolVfr7ndco9nRR
         /ytqMUddvj/oPxSHQFU0bG7/m+0IdblEKwRfQUHmRgXp0DwXoTzkNfHvKuEMFHmeYZEr
         xDPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I90eDVb0EcaHzesHFmYFLUJWlkLFppWsKeUiUqFVRUU=;
        b=M+ddJWaqW/mwwqhTIGL4L2iZB9eBsNbKaH6dNe8+0c4IS6AiK4bL1v5ow4/shTP0YV
         4FcFqNu9g6PYy5Dx/H1JSql5npcevh6EE3aLpUEJjdsrnKGjTVeKI0PMSTdnGObFZqhA
         PkCkPrEa1jPKMAE3WwNjgWk9LL5JGE8AeCbYpA4w0iF+8IiRRbQLiuSHHs3cEpIs8csW
         Wl2pMs/wAs9Dun9o5eZu9LlDXsFCBE4+kxHQRBKpSmPJaTmuMsdcdCeK/Lr3x/XLBpkW
         lNFVBHgxMRxdtHwfQr2ax/MX4B90huMmVsDo7A9EbvUb/sc0wREzH3RuY458YmoLJ7N1
         jYFQ==
X-Gm-Message-State: AOAM5306LaRMK9CWFpP/9vS14JBQWaCy+Tau3/Lf5zAs8CR/LlFbtMi/
	2oUTwnjRufRXq2pDzD31+A0=
X-Google-Smtp-Source: ABdhPJyT8KEGwWu/sYw1hfed3FiprPRLJkDNyVDItHUK2xNjFOSoN/den1FKSkH18d5h0GgBuYHkrA==
X-Received: by 2002:adf:a29e:: with SMTP id s30mr6517577wra.29.1603999627247;
        Thu, 29 Oct 2020 12:27:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls459735wma.3.gmail; Thu, 29 Oct
 2020 12:27:06 -0700 (PDT)
X-Received: by 2002:a1c:750b:: with SMTP id o11mr489244wmc.32.1603999626373;
        Thu, 29 Oct 2020 12:27:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999626; cv=none;
        d=google.com; s=arc-20160816;
        b=pky7dHj0KmleJ8J/m9wrMD/sWhv6cgc3awdhoOfrHaDAqmv4jtqMHDzcKATiUPIjTE
         m1iRk8qf47uIuyotridX9QAvRAryGNphZ0ezxUAqzSGfmXs3HsKETHCoqv0LzGNbnZSI
         DHzbzYKS/almskUNsJnEa3rYPlOu84h1/C7ZfgfsNnUv6H1nnky0np7qNRv+nrdn93Pg
         Ze4DZ8uFNly//pwAxYBKDifPJOgf3fo6Dv+mFvg4jzT36TfRX7Lj+wHOkSvAIrVzKiMS
         bZOTmqQJ4QrJfNpU1/jnazDs1tojlU24VGK4LbqHD1Q30Nce2hbBQlaZ0iClRnu2z0W8
         yIPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oI/HbLx6/V9Mgdsl45doZaYB4b1VS6zKA72TKwwbKIw=;
        b=d2A7kq0rVExAMAQ0ULV5q+7cl5eq/jipitFmteLBbjnbNYFoLNsZ+izUEYN8Vq3XUd
         9R1WI7LeZqWYe23gqGqSuCaVqus6WYCTqC5BZ2ReMDpY7W5D+OQyW6PDV+VTzDvb8dVi
         ntGAb7TK4NGKiyv3x7NABHC4EApIWwD6VTx1fiZf0CzkdnwGJU11ItB9TB8Q2LvX0+lF
         olXs6Vf36/MMno+EFgZSk0XcCchOauop4pz1UoSZPx0JksBjD93diejQq/joF4mIF7MJ
         B3T16nmzz7e9nAasY/L01cqZmX3BbM/47wZkvuE0Xl+A6Go1E7zdnqu2nkWz4APnvMhT
         eABg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JIIuHmSb;
       spf=pass (google.com: domain of 3irebxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iRebXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id e5si127747wrj.3.2020.10.29.12.27.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3irebxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c204so304810wmd.5
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:06 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2dc4:: with SMTP id
 t187mr417857wmt.53.1603999625934; Thu, 29 Oct 2020 12:27:05 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:45 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <0a56e9333c945e928c9a20c70451bcf818c4c60d.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 24/40] kasan, arm64: only use kasan_depth for software modes
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
 header.i=@google.com header.s=20161025 header.b=JIIuHmSb;       spf=pass
 (google.com: domain of 3irebxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3iRebXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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
index ffeb80d5aa8d..69c692b58f23 100644
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
index bfb21d5fd279..8d3d3c21340d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -49,6 +49,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
@@ -59,16 +65,13 @@ static inline void kasan_remove_zero_shadow(void *start,
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
@@ -119,9 +122,6 @@ static inline void kasan_unpoison_memory(const void *address, size_t size) {}
 
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a56e9333c945e928c9a20c70451bcf818c4c60d.1603999489.git.andreyknvl%40google.com.
