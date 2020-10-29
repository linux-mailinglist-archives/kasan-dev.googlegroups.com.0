Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4FO5T6AKGQEAOCIRIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A5B1729F4EF
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:41 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id r15sf1655542ljn.16
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999601; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+4ug/Aap/afuorpc1b0WihNcShCyWb6ZNGw9JogwhPaSGI0isYEeYfVlDLGll9050
         55o8yC44LlOMQg1EoSxkvdoh/aCFP90kxU2gLA1imcoHf8hIasFy0fmlfw1C8zjZ9THU
         kcfL1KK7bIXgISYk2ju/RiALtz6EoFUWfox6AdY9tsH041AY+oTVWHUJtv1PXEQGxDs5
         83L4fwVKSA6FUJKHnnlDa2jYMvLiA1ve9wC/N7bItPCWybwhac2ZmlAOvN0fOnpF6Apl
         GO8/7khnJhSqUcc8II6pAGEYWhNhwYL8Rs8daic+OMSiS6peaD2ISIyDjMVJXpPtJRPJ
         Jl/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jWgkxBQ0CrOa1dszw6BKY6FjXedfIQEOAUaxqWNdkXY=;
        b=r1JkrTPKT7z4NNTxOAPfe6aXocTcUiFM1dJzNBhpowFyKNPaNtrZGb6zbE7iIWhBWC
         MnBZylpylJPZx8LcHK2gxRRjOtGhAzUImx+hmy+UfC8VDRlDCBlxbe/ugvOaYNCu1q5R
         MSvNmbJv1p5wlD/wyQhwdd/+ItqaCqvQFASbutJbus5ExSeeDGqFgo/IbCDaFwlm/StO
         24Nb+u0/y02QrFFaV94wVTAuldA9vMKMQjoooAgNFqB1KlStAo/y6hxb92jxlX1NRZKU
         eVSQPtHlq00VUnm0I/PrETfAs8zb2dzdiwP8pufNLin9+1P9VRH90wgdZbEHcOaxER0m
         drxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vLHwj7A5;
       spf=pass (google.com: domain of 3bxebxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bxebXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jWgkxBQ0CrOa1dszw6BKY6FjXedfIQEOAUaxqWNdkXY=;
        b=Ltc0cKmDlqj3Tf6Qwk+YIxMM1mfAgOEpaet6Tux2BRpfQrzC+4jnlwVHRXLE7dRAmT
         UyC9c79/15oM/UZ0YqFZVhGnTbeUZFujgm8uHC6swVyn/Bkaes7mZGh8TZgusVVqLajs
         8fBfnFIYcnWV6GAty4QYcFPM661RycENPlanlIVhkXlITy4N35UxdOHgE2PZwMBCmZsJ
         gwbIIXvPdULI+LOrIwEwEvrrmI5ozttwDOqg/yOYPvdzIzX1xLWkGhLMbXrYldFq0+J+
         yL2b+IOQqNtv4ytNoy4jicPKbx30rpddZluOdpXVgdH9hXjuOdqv/d1A0vBvKgb/RXdj
         38TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jWgkxBQ0CrOa1dszw6BKY6FjXedfIQEOAUaxqWNdkXY=;
        b=RsU+UF/q/grIRL6OShfGCL4cjpjtbro0pvhEo1McSNsDrVW26Ana1EXzPqJW7TJiEi
         BdPqOv1kZyLYw2A+kGZxu86tEgd+4ec0++Ka9hYK4Z0GDMeMv2gB1s/oQAdKNNxKyQla
         /OpS/PLcmP8cD5IwueIUzrCBonhX14Ui37WbTlnBXy1X3HwP4H99mUHuCySOwT+oqWFC
         L+nwwTZfXthAEXNk242ZvwD0IDKdFs+i1nA7/wVc0ynbKB4n/pppLP7GggNxIiF6YEmg
         hyIjjEYNknLZfzW5aJhhflybJtdgwsydNIHU9IDVMgoRe+qEXlLGSbRB650Q+XsdL3aH
         sSPA==
X-Gm-Message-State: AOAM530hSWCktFJyPrzHMTdgAdfJQSYjhFuVhwu0KgC8E1rdULmyXKen
	9/ox1Xc2YSznf8hbQu7h+4Q=
X-Google-Smtp-Source: ABdhPJwaa8R2xfX0BxvxGaIHESsBW2Q4BAZWo545l1dgOVr/8fwljgKtQMkOXESbVZZpCJOTKnk9hw==
X-Received: by 2002:a2e:9052:: with SMTP id n18mr2635065ljg.78.1603999601015;
        Thu, 29 Oct 2020 12:26:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:546b:: with SMTP id e11ls2397459lfn.0.gmail; Thu, 29 Oct
 2020 12:26:39 -0700 (PDT)
X-Received: by 2002:a19:3816:: with SMTP id f22mr1027270lfa.210.1603999599558;
        Thu, 29 Oct 2020 12:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999599; cv=none;
        d=google.com; s=arc-20160816;
        b=VNnu4LsGplxbu5se1Oim7BXDv4pfNkhlg0Yf2ViNYCuoGUOJ1P2wG0UvonaRUdlEd/
         SEVAgUtUZUhmVHc8UQvLo7zBgpzXuPhFwMdY9dBWtuC4QlAY9ZO2WmgPWG3QMIGXjDmb
         bc2FRJctRGJqX1jm7DEKTnz9XzAdTI6zXIqow+nCinj6otWksWJEr89QLtH8ALOfr6v1
         JnzosI+XMdkGlvdAmkRWtWkALxXJ7Wf9E6Cr70K8b2DdMZ+z+izcoAzzbV7n2MhKcWy0
         IvXd7G04bTv4YoSZ/ohjMBfA/F+4Ya3O4MjV6WdHiip/59D+t0drtcp8/kq4X3sR9/jI
         kRuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nboRM2CFBpQGYkXl6uRGVt4iydoGbxyL4XKrxiXLpKY=;
        b=sjReYVUwMbWJo8BwVkNgBijyx7DAc/JszJEgeNwZp6m34+witvpBoX4HdL6KnlQa4I
         1NnxqEvW0sNV0jNu9GCvceXjk+uWRp29my2QDdbmXDEW8aD0/zhnacNMbpB8uBm/rm2S
         R/OF5otO8n8WGtQoWrLmuCo0DnGTjPV30PeXXF1RjlnZJ7rFrxnbfYYCaMlf6MBeExF8
         MRfuLB2UEcNhU62T2d83uVMCJTGyipGVEEj+gRfrTBOkiEU+loGDBlMficeSZORoNaUL
         ZwiKNZjY4T+r0Tpei+otFUgFMwIU8pFBEduvefXjScQIS7SkSELPPekVaE3GcYYLGH5f
         99TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vLHwj7A5;
       spf=pass (google.com: domain of 3bxebxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bxebXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o142si86578lff.6.2020.10.29.12.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bxebxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z62so972424wmb.1
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:39 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:c58f:: with SMTP id
 m15mr7428154wrg.144.1603999599104; Thu, 29 Oct 2020 12:26:39 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:34 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <0130b488568090eb2ad2ffc47955122be754cfbe.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 13/40] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=vLHwj7A5;       spf=pass
 (google.com: domain of 3bxebxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3bxebXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Group shadow-related KASAN function declarations and only define them
for the two existing software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 45 ++++++++++++++++++++++++++++---------------
 1 file changed, 29 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..45345dd5cfd6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -10,9 +10,20 @@ struct vm_struct;
 struct task_struct;
 
 #ifdef CONFIG_KASAN
+#include <asm/kasan.h>
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
-#include <asm/kasan.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
 struct kunit_kasan_expectation {
@@ -35,6 +46,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 		+ KASAN_SHADOW_OFFSET;
 }
 
+int kasan_add_zero_shadow(void *start, unsigned long size);
+void kasan_remove_zero_shadow(void *start, unsigned long size);
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_remove_zero_shadow(void *start,
+					unsigned long size)
+{}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
 
@@ -75,9 +103,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -143,14 +168,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
@@ -158,8 +175,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -174,8 +189,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0130b488568090eb2ad2ffc47955122be754cfbe.1603999489.git.andreyknvl%40google.com.
