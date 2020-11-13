Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUNXT6QKGQE36IML6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C6F72B285A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:21:00 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id z79sf4573950oia.10
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306059; cv=pass;
        d=google.com; s=arc-20160816;
        b=ga+1widTRbofVidkwyFyWUruyYTpGgQWrdm6OEq0O9YK73V3kXaei/F/jko/ABTgU5
         +imsisZHkl9BrFMjwJ4aKU3szl4GlyJNaxGofxBNGxNA3ogLh+gSMwYydqXHHUMX1Ehr
         xHnk6tP8yLRuOPHZ2Tf/3oezsUeaLHUN5nhmKD97PlN5GjTubTAya823bHpQzYM74qXe
         yM9MSdJZMljYq2liFZ0b4PyCZB15z65lCUtP7Sa9JXotshYGpSYV6xsVSiigZ4PEeOd4
         TE4XGIA0/db4gj2hEwhdV2G4CIhF/7I5MNOm+GFe1YsLkpIelAs4OnBFdXvkBLRs9zgx
         uWfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Lq5vWik+TlH9ckj9DpGjsFAsZO8nb06S+Z0LW09sah4=;
        b=xxJCTOFND56GcNAIp0M7iu+KQlT8RXWlfX3Z/XAEagTGXhg9esLBbwDzZR0MaHRmGM
         M9tgM8HX0EbSLuPalRAr/CvtWw3td974dKDPjJmmzeCcQqzk0oXPGPG88e8I7GOzghDa
         XmZYuh5renwZlQAhpY05wKC70GGPtK8gPssssWWSmpQCcFcZOBjlhTViRV0QEDuYK1CP
         iDQBKz4UsFjCSdJ4jBMosJfBgax6rkaYXUckc3/pMqjToO0JYGWvpe8AjA1+z9UVu5QO
         /T01irRodc3I8uYkiAt45GnXGokotOLtEhlk+XUiqCpqvKURfOVY3Q421OFxHQboHtLD
         g/Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wogiwfd7;
       spf=pass (google.com: domain of 3ygavxwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ygavXwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Lq5vWik+TlH9ckj9DpGjsFAsZO8nb06S+Z0LW09sah4=;
        b=ssGLp2pk5tmPe9DaxtMKmIxUl5lcbelW6CXDokm6b/LHJbcMgHR5SnN+eCnsmFKTNR
         VnaruTMfAGU6HmP0AzRJ6JNaIvXprhevDngCya1tWl5lKw4XAsgfaI6Ugo9DgGsNKlSe
         uVPD5wwcQCvKrtJSB6/goAR4fCYQ/HPbelMdV42EQsLnzLPsTLlPFp17jZcpeQU0qX9a
         B/CjXpntq9qv5eb/HxgSUqMxlLWaKe2c/Q/n0PHaqdq31qT3+9z7rSNU+cKhxGTDqdI6
         zhph8alIGsh01z19fsHu4odvQuvDKpCH6sIvWa/z1xBinCrW6QPfGpX4mwZkuaketOq0
         YhqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lq5vWik+TlH9ckj9DpGjsFAsZO8nb06S+Z0LW09sah4=;
        b=JJ8VVhGzobtQvKxlwnizbRMGy3OngBaR4zouyAqGQbSDfVhlfZcoU+KU7Cpet1dZSG
         xORCiPXDBN251krzugbDJvuMNhR14YX5UALtq+7sghMSZwXmMxgnNVZxk1VpVbJ6tiKh
         9euMRc5FYgXq3zDkB3PgzSNgt6UMGlAaHct7Tqqlbm9yfcq0GEoEdP+Hsf7CvICkUpSD
         D0whvIdkOYIDKzdpFMU/b3an9TY0QgpUebwqfmjeTq2lyNrGAQfbetJY6DP+jQl89szn
         zYPehvOwqxNX2EpBo0XYNl+kz1losU6PsbUn077l8dBZardrdcdBky7EnIBSv16PHHo9
         DVZw==
X-Gm-Message-State: AOAM532JIHrwzoeYZKo/lmTzi3ahNQPlewRUF6FBILiAuMHeQST6bIC4
	X8JofxtHiK6pvG9ehcH8jFw=
X-Google-Smtp-Source: ABdhPJx4oLhFrkm1so/4p95CmzoMWA/jCQAe8yDBJ0U8IDsDoziw/7gKt8CajmK1WFZOp4BR76lgfA==
X-Received: by 2002:a4a:3b83:: with SMTP id s125mr3220396oos.82.1605306059032;
        Fri, 13 Nov 2020 14:20:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:e102:: with SMTP id y2ls1848190oig.4.gmail; Fri, 13 Nov
 2020 14:20:58 -0800 (PST)
X-Received: by 2002:aca:4387:: with SMTP id q129mr3043539oia.108.1605306058724;
        Fri, 13 Nov 2020 14:20:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306058; cv=none;
        d=google.com; s=arc-20160816;
        b=TUbyyN2wStlARG7/SMWrA7pch2MFTpXwZqYQKlFKd9MuKgUFdvRUizH7/U+hS9ncjo
         TVox2/iaIti/gG+p6B9WSJDRnaOwPSgblZQkgLmnlsjToOB/N850P2xdAb9kugn6xUyF
         h2hIInW0HLeJIMb1L8uNZGgLIbhCYp1G+N9/f76XksGEXcTdBJ3+UzaY4CofX6LOL5Ol
         nx5eWawXWEQPihzcAryLvfylhQDzFl2f+plw5eqd01Hr3OGIZ/gmQDlxF1KH74G+qvO/
         xsRuXbde/0Mi0Kn3biMyJNq7IgXNqCD8wYzcPA1sjvVZ2Gvr4o6UcjhLzUqVBpmmZMEN
         A0fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VblPcwxF/Hme6lihpSqzEG9568rY0eTc9RDR6WgTVWw=;
        b=cFjuCihoXgsUzXqFm21FrE0CMnwkFvH35nflfLSbi9shw5xSFhbDEByy4r+lmXyLi2
         zJtknNChtbpcJjnWrADOTYbsnbDq3R94j0z0AJnZJXt5xWFwz399+VO0jmGpf9KFSLCA
         DXDM9juJlfWGP+DPJ6cYLdKNEOeDq3p0JIy35AFrqpa5hW9h08WuCGVsAUtyYFQ9YW+J
         LTWvqb0mEg+ISuhkmfYDWEmefXlXJsxsvEMzfTeazKM1Db9vJhc+JwLskuX97bSxHBz0
         EYC5vtq/svze2OlIdPFNhCqZ+GkmhVDj0m3vi5M/IU9gfovpXWgEB0rGYJRig0+JltxV
         Mm+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wogiwfd7;
       spf=pass (google.com: domain of 3ygavxwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ygavXwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id r6si1433751oth.4.2020.11.13.14.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ygavxwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id 141so7560344qkh.18
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e53:: with SMTP id
 z19mr4596536qve.23.1605306058182; Fri, 13 Nov 2020 14:20:58 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:08 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 18/19] kasan, mm: allow cache merging with no metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wogiwfd7;       spf=pass
 (google.com: domain of 3ygavxwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ygavXwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

The reason cache merging is disabled with KASAN is because KASAN puts its
metadata right after the allocated object. When the merged caches have
slightly different sizes, the metadata ends up in different places, which
KASAN doesn't support.

It might be possible to adjust the metadata allocation algorithm and make
it friendly to the cache merging code. Instead this change takes a simpler
approach and allows merging caches when no metadata is present. Which is
the case for hardware tag-based KASAN with kasan.mode=prod.

Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
---
 include/linux/kasan.h | 21 +++++++++++++++++++--
 mm/kasan/common.c     | 11 +++++++++++
 mm/slab_common.c      |  3 ++-
 3 files changed, 32 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 16cf53eac29b..173a8e81d001 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -81,17 +81,30 @@ struct kasan_cache {
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
-#else
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_enabled(void)
 {
 	return true;
 }
-#endif
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
+slab_flags_t __kasan_never_merge(void);
+static __always_inline slab_flags_t kasan_never_merge(void)
+{
+	if (kasan_enabled())
+		return __kasan_never_merge();
+	return 0;
+}
 
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
@@ -238,6 +251,10 @@ static inline bool kasan_enabled(void)
 {
 	return false;
 }
+static inline slab_flags_t kasan_never_merge(void)
+{
+	return 0;
+}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index cf874243efab..a5a4dcb1254d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -87,6 +87,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
+/*
+ * Only allow cache merging when stack collection is disabled and no metadata
+ * is present.
+ */
+slab_flags_t __kasan_never_merge(void)
+{
+	if (kasan_stack_collection_enabled())
+		return SLAB_KASAN;
+	return 0;
+}
+
 void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 0b5ae1819a8b..075b23ce94ec 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -19,6 +19,7 @@
 #include <linux/seq_file.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 #include <asm/page.h>
@@ -54,7 +55,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
-		SLAB_FAILSLAB | SLAB_KASAN)
+		SLAB_FAILSLAB | kasan_never_merge())
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl%40google.com.
