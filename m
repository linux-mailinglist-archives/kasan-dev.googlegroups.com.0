Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBET3P4QKGQEPG3I3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C8A8244DB7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:32 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id z10sf3531311wmi.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426052; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vc0hNuzSXRXstw0NKfpYTGgRqrJNbX3tNTMHnOsN3eyJgS5mldCjPoRTrPr1XxfqKT
         pYzlOnh+eQ28rbrizSH4GrnO3PnDeNXEyA6cPdZs7SkigpDxSU2ZJtsMHUB5fWP26orJ
         tAx5b3WnL3dxLuH7XEgKBqtqZJOzSArhDTrQmARIeVS4HBKPYBReFYOp2qUzaVuXCUhw
         Uye5zuTNdlnRfLHXpbkGWow9jCVCOG1CNjTEDFCcbo/W/kZlL/Lr0XdSvQEM+qkP4IcQ
         hNKEqtxZNPzDIqtkhGiqApgbEw5EDDH3IoCqMWlolyQ73ag6Sb8oZFsgiCalxxLfvzMT
         WSNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nH7qJUcdak5+E0xkSLyAG8Q46nwKO/MZUTiV1vp9XJA=;
        b=1IR3ubZA5HoCND72ecCR7tFspHwCcMm76zoGxqv9d2F4XWkt+04544vY8frOUX7Mn1
         gXpihO6w6lK18AmzTK/SJe2ISLI4WOHq9QzPlTU+lqr+pAq1dBItcp4I5xNzerNoM2Yy
         1DpJ+hQnFk8JYb6RmtW5VcZW3gBdJWp7qWNpmBHY/OvlvHyiVMeZ0lWL3kbGyWwBC2eF
         DGYBR4ZEhZNp/ofayrjo2qdpu42wuIsWQU8Qt1o+cfxopUyBJbSaorv3uIVf+EizkLEU
         w83CnQpaDM/qiGOtiR96HwaiGWajAosbAQIIVrAPeV3mC1vEtk7rDTv15zsa/4GU8iMf
         Y1mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NnWG0R80;
       spf=pass (google.com: domain of 3g8k2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3g8k2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nH7qJUcdak5+E0xkSLyAG8Q46nwKO/MZUTiV1vp9XJA=;
        b=cNZOe28MXSAdf32EziLOuh9a7metRbyR3NQkkiIvbYHIVCXx0kG3cNbh80Ku0Sttsa
         ihXs8rb8HvDqJCXRJ+xaoLshOOiUPsr8jZ7GG5soXV+A1qUr2sTKJZA/GkKGrVRpTmIf
         Fx3+oe7IfvsFclv+BnFCjiWOVotPrXr/4C9kQdc9HkOyopPdhNd5lzz2Rh+rCpkUyXLL
         sW6KIKpqncys7D3/E7+aml4wVb+mOh91a4gNm796Y8BGnkDD+rzKUc/y+tCrp0WorSe3
         ZmUU+ACsHT0P8IyB6RMRYYmOcxNBGpHF//keVkYYVtelkAbpakJEyykprO+c7nQaG+s3
         9hBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nH7qJUcdak5+E0xkSLyAG8Q46nwKO/MZUTiV1vp9XJA=;
        b=uDoJXWIzyi4y7OvfAoRVL6cN23BdFBOGkUYxF/uUVgqme2TQoetjqQiOiGYHKt6h8W
         lZzv4/9OOC9jc+nc+woxbgGR7eNNQakQRYTx3zP85qvEen+8pVUO3uizlVtUkxtuoaUL
         Fodaz5gj+OuzPH0peUxtnG+AdfIgXXTdBq/7rt0r4/FrWmbR1KQhVvXSunMY9rpHU6/V
         aq4ZWVsOHx/G7XfOLqLjwmFinpD8OgIUGMayqjTVCjj4mSu9Dcb8LgIa3ODX7YKyBIMP
         mWTctZ04CEYqBE8+BKKy/1cAz4ymIrVzBaGgkLblxXC5FouNgAHrzriy7I3ZwEWChpja
         m4lw==
X-Gm-Message-State: AOAM533UkbnFkrCOtVWF2Wo0xJqAF9eKZN548/ccPN6tdxyAJIa0M5qk
	+lmkh4vOZHbr2LYqSF9iOIA=
X-Google-Smtp-Source: ABdhPJzJCfcdoJT5g8zWOCJ2EVno+PyOX4LPG64qTo8xcADvABT5fJyzTLy8e+W4yYXapEoJamjZYg==
X-Received: by 2002:a5d:4603:: with SMTP id t3mr3843223wrq.175.1597426052179;
        Fri, 14 Aug 2020 10:27:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e78f:: with SMTP id n15ls709681wrm.1.gmail; Fri, 14 Aug
 2020 10:27:31 -0700 (PDT)
X-Received: by 2002:adf:f8d0:: with SMTP id f16mr3868775wrq.66.1597426051659;
        Fri, 14 Aug 2020 10:27:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426051; cv=none;
        d=google.com; s=arc-20160816;
        b=lZnF2HsO3K8AbIILxojoAey/3AB27JALsFZTCsixTIhaffljudCMuHrvSDtO/MH0S/
         7zsO5EcfM/lyeiNGKkBm9X3f5xUVcCqW98U2ATwXQY55lgniHYJyZa6bmoOX/2h/61TQ
         cXcFVXM5LBlGTBpQhnxd8dM1+nwNRL7F4BUP+ijDqaVsFuiu2xuSHyb4VWcYMvHuVles
         DrrZ8fzr6AsmhcFAT9xALn5cuZHVxHfJewKH7evtraiwgJ/x0nbk4lrhwe4lOkEwnmta
         KHv/NPNQshw5zNyxBHHJN/LXLZl/olDnVcUcb1AcQKgvRyN1cUPmABy4iQA403F23vWi
         PuCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yqDvbJRB7ghhYUJnBffV6Wdevt15gkjdAFpaNJ5xwpI=;
        b=mwPCgYzmwoqKG0+byDQBU5SMAw466BbTTEb/idwVLnMsxTq2mg5Bm29AooFKPXRrhZ
         Oy27kqFBdONG9AQSTbH0jAYrFEP0eypIJnTK/+LcHJOAMmQknVHAnPDpgeO+ocjxDoJK
         kfZFf23jFWESDH2Iphav/yMduLy5vr4OaSFaDf5RrJWflWlelA9g1lxuaIAPvBnNKqBi
         8ZRGK53+RVSv/0p4jKvt/ePATDnnORxBAstPR6K02dyZcdIC5xXsL1Se/nCCEXNs9irK
         dO7fs3FM5F/3WtR8dPPVNyxdkZWBahzGqly4BeEgfGdwok6bYgirQo+EM7hs0fKJI/p1
         ZsOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NnWG0R80;
       spf=pass (google.com: domain of 3g8k2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3g8k2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 64si284267wmb.1.2020.08.14.10.27.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g8k2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id l24so3479270edv.8
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:31 -0700 (PDT)
X-Received: by 2002:a17:906:c7c8:: with SMTP id dc8mr3324691ejb.285.1597426051207;
 Fri, 14 Aug 2020 10:27:31 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:45 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <272b331db9919432cd6467a0bd5ce73ffc46fc97.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 03/35] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=NnWG0R80;       spf=pass
 (google.com: domain of 3g8k2xwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3g8k2XwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/272b331db9919432cd6467a0bd5ce73ffc46fc97.1597425745.git.andreyknvl%40google.com.
