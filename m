Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLW6QT5QKGQESC7LHJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AAD326AF4D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:32 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id u8sf3750386ilc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204591; cv=pass;
        d=google.com; s=arc-20160816;
        b=LLVWmivhS8U8ZjsgvbmOD3wE0XsBcH883HzBoldvttcf99tUJI9B26u91WKmrVOx9F
         q+mmsVZR9DO3Q5GTzBMCOkafLgC69As+bEuar7vID1G4LxhfZDexgEkktqZsfp+X52+l
         4UNIDtgLpskTmTa+6vPttRA0aYF+uEDs70Db2pgkYPFVbWFqN/bEWibXkGVP/UhadPKM
         zOVZMVd1dJgt8cHNhnklJ72Z54Sccoqwl7SqnT2JUgRvwzsI8sLze7vP9c6DB55MJlIM
         rm0Bsyd0t3YrY6T6dRdXn+q9jRUMTEVN24PNdDAyExM/uioKvIByEYT620k1w/HpZVfU
         daJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+qcPtMZylJdiXDFBwii+3T5olz0Md6Vy36R2u6JH2DY=;
        b=ci6XkF5AAPvBtXHNLLnkJElPXB/1HXfVIHWVSfvpqOqJ/kBfBoNAMDdjN59yK1ZepL
         jmtMCF+omClyRuc3aEL6cpG9zTJIf7zpWwJ9NBqHkk1wtnga/X3seIIiqtBn5TvDBR+y
         fyVjNUkWmy7CY6ma1GmxRQDc1Rc5ehWoEfJi6BUhtGXFVX7h6meBlztqYaeM2B1XQegm
         Fm24f2jcVMpRk0UIi0Yx5U/4t73GH6WKQKGVvbkpO7LcFc9qCsHy11RbFAOY4C3AOH0L
         tKOidHQuoFSAaduWsyVriX2H6gkTVGrbALPEnMsFSgbJIMS1hxYNkpVf/kS3dpMEYMLO
         skSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hMw9RQ1d;
       spf=pass (google.com: domain of 3ls9hxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3LS9hXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+qcPtMZylJdiXDFBwii+3T5olz0Md6Vy36R2u6JH2DY=;
        b=ccHO1Qus/Kd6xTGeg0gnKC2mH0yudJ6N4cwiCl66/5uMIhk8GnFpNsak2wzz1ZQPTP
         iKTHqThqA79as2Niic+1Gs/E4TrfY8b3fq8GjeZJzsp/HsJNEjj0CUxMhgElXE1c2eZZ
         Cox+ho5NgApoNbD+ekKoGSwBKSWsRlaGVYqR00xT4mM3whsT3Auc5XfnWWqDdbuBZJ31
         HK/i9LWw9Ijbx9pTwgYwNd3ZzslY09ed7fp6gY5tlUqJPkdg85A3JLmXTo5OrEBUxO4b
         f+tdQ6eMY/K3to3u6XpEFSZZ8o7Ek01ss61R6KM/QiC7HQkfhgoUoILdUr19FtWLmrra
         AQ3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qcPtMZylJdiXDFBwii+3T5olz0Md6Vy36R2u6JH2DY=;
        b=TMpKoJeI7byvJd0MOSJvourL54mFxsimO1Kx/KYOVMGSuUyxhALq2IwnD49o2mCYqW
         EzTCCrZ9LhxFcmUXP1Kw76LkU2MS+LmMmPawXdWxZi9NQYxBDo7u3oWT3b4dVNELw1ON
         r1mS9Fju23HCyidyx9ybPO0Z/4Olc12Rah71zBg3qE0Lk9MrHgkn0EnS3k2dGBidUoVL
         MfIJ4raLvxVKDtgD2jPWzXbbHeDWK+3RxBxh7jEe/2GLNXie35Bt4bdFT/0on9mNWg/W
         N3peYM7eiLDsnThTDvCQGdu72KwdY97fT308DUXYdmRGH7r082H1eI43wbsv+imvlyC8
         779Q==
X-Gm-Message-State: AOAM531AAzoF2jXUGPnMgPya6OejKNX3l914z0KBvRTLv1+HFcLsK+Ss
	GNArtqx8RFWKdsNg5G25Gmk=
X-Google-Smtp-Source: ABdhPJzwBRv4e2+8FUFEtIC4O1XiiX8z4Seys7hQxX4+S96b8tnY1o/RwOiDsHvQ0Eyp7Am2a7R2oA==
X-Received: by 2002:a05:6e02:d85:: with SMTP id i5mr17905943ilj.115.1600204591083;
        Tue, 15 Sep 2020 14:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:543:: with SMTP id i3ls23225ils.4.gmail; Tue, 15
 Sep 2020 14:16:30 -0700 (PDT)
X-Received: by 2002:a92:9ec3:: with SMTP id s64mr18047669ilk.294.1600204590638;
        Tue, 15 Sep 2020 14:16:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204590; cv=none;
        d=google.com; s=arc-20160816;
        b=V4VPc4p0OXFXxbDLUl1gKD6H71N5qG/Z5+nA66hu0W2g5wLGrY8ivh93b0u/PqgSby
         gL7AY9MrLBYEN7dR2x6pd9ged6UZ53RlWT0+ixgXKLNtb6aPzICCJe7xpQt6arIoujP2
         S0KIdqj+YSxvz9TaL4+U33SBNmkDl2jaVUlXZqjN4BprJKzQpGBFPxJMx5eiNfSzEJWO
         Gzc7F2m2hlamFk6yp9by8LtPXjBffot4KllYE4F8P76h8OO90O4GFBtV7FiXXob3bPJa
         RXP/dwwUnZDlY4GpAfcd/w7QDbnIzn3GnBldWzcC6e2vXA5kkkl+HI1QoUHO+0pAGNVs
         7iYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CRuZK+9yjNiKO3/D2O90q00ovcGW/0GaRtF/oaFCa6M=;
        b=qVb0Wl+ERsNXKCBmeHIgzMKcg0uExtRLyhii/QcqUtMyO1furp8NSoo0qymKqicJkx
         tFsfvU/Iz0nWvSfn4V6La+cQ+9Gy3wFR34nQXaWhQK9BMI5zmAP/PRTlv7IT3WNJKhj6
         tGo+ECrW77fvAVLTv0jf2f5SaSj0TFfoNMNNfpPwOPWDdXj9kCGbgdA9u5+vPMatJXrY
         +4ZPZUAzZe5dOshrBWdbwjVVGwsYbIVHobOgvJWLLHdNE9idbp9RU9Jlm3jQaQex9SLN
         T+28esSCPNZzro9330h2UP0oUM8hkCqkS9iH0uIFHQSgqpzVeU+h7Zn+zUbUuwjCl2ta
         M0gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hMw9RQ1d;
       spf=pass (google.com: domain of 3ls9hxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3LS9hXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id k18si952924ion.4.2020.09.15.14.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ls9hxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t56so503615qtt.19
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:30 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4527:: with SMTP id
 l7mr20524343qvu.2.1600204589991; Tue, 15 Sep 2020 14:16:29 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:45 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <6ad13f9f94e1a2f84f603e0e374582b89a44a75e.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 03/37] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hMw9RQ1d;       spf=pass
 (google.com: domain of 3ls9hxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3LS9hXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 44 ++++++++++++++++++++++++++-----------------
 1 file changed, 27 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bd5b4965a269..44a9aae44138 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -3,16 +3,24 @@
 #define _LINUX_KASAN_H
 
 #include <linux/types.h>
+#include <asm/kasan.h>
 
 struct kmem_cache;
 struct page;
 struct vm_struct;
 struct task_struct;
 
-#ifdef CONFIG_KASAN
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
 
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
@@ -29,6 +37,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
 
@@ -69,9 +94,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -137,14 +159,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
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
 
@@ -152,8 +166,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -168,8 +180,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ad13f9f94e1a2f84f603e0e374582b89a44a75e.1600204505.git.andreyknvl%40google.com.
