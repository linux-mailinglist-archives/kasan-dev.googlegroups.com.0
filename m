Return-Path: <kasan-dev+bncBAABB5UB36GQMGQE423Q4PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 97EBB4736E2
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:59 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id e23-20020a196917000000b0041bcbb80798sf8039747lfc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432439; cv=pass;
        d=google.com; s=arc-20160816;
        b=p+RLPB0ItfOGvcgkfKVxJYacddMLmDB/AOQRjdlM5QwIw3u3JndE3P+lUtB/YtY9/+
         7um5tjkX16St0UZbJyh7WuHZXoyXYOLuyfa3Vq0darp5H2LWJ7xlm89Ea35onM4pE+LI
         GrYLPuSCjUomyjN6XPHuxyfygzToJqFTUj/ELQ+W8ER5eTlXvp3bVQCi4d1IcbmCAXg8
         CIQ/tSlcg9VvJOUTYr//02pqCz+mtiucPn8OR3BHe9Gcb6S9qY3ePCW2X26Tipn05xTe
         abXyi71buYBv1fBbUcPP6niCyp+wI572fdRqwdK1pMcFPUrqqNR752LKf4bMh7sg74+b
         kJRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5vS5P7wKy+nZz3jHS5SpvBbmJngvWPO6FEu6tA/BIy8=;
        b=WykdGhsGgreTbd/p3t20HVHjAw6bsWKZAoIW4MiSZaMX4GITw1SXtFZrBj9SDLvyBC
         1IjLnpNiSJxJ8TtZBwD8mfRgM8vpOl57ikkEwyfkSWDn4Bm5eontC6KilwR2QA2SGuTl
         jt/9jP17TdBJEw9xhZFEeo8whjxzC4qd62/pSzdRxZbxtdkxQx2T8555AtDNJl4qX2F8
         PJQNpc2UoSu8HXCUPorxq5OsohT023yPp4/Qrh90+fs9SQ90h/45IeADXNDFg4L9T+wA
         mHtkfXLfnxTj+wkTRamgY2RUgEC7wYkc60u5dQpSbtMpTGHfSbRDzJHWV8BbwQajTwZ8
         tadA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LrcPemYT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5vS5P7wKy+nZz3jHS5SpvBbmJngvWPO6FEu6tA/BIy8=;
        b=pNYYhVNieKDPhYJs8JH8dJytH29MbjWJnYZbQn4LZPl3V2pikkAkJxE3kUc7F6kCVK
         BeweTI3xDyWHLTHc7f2oggmOkvN8iyzvqKF0OxWnJ9RVrNtrkfdR3YkWBXiX2kcXuODC
         /o7zQdv4JMeHqmzHOqbCavoTQ0+Hhw1GxoheRJYIiem7uHWv7bgPpErtPOu+cAHOtgUC
         UEwrRvAMKcCOYiv2qTnYcZX33paqA0+OYogOnCI3m/gJuXBf5eqAIv1WPFYRbwZf+3T1
         /DATdmhm22TuKLW1qaNjSvM0eUiJi9XGUb1zTRbAWj7jZJw4CtMEIx0MHPw/Bl6Uf7zF
         0LIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5vS5P7wKy+nZz3jHS5SpvBbmJngvWPO6FEu6tA/BIy8=;
        b=wcI0/PYE7NOzDIqabcj63wcfidk4QTsbtHHvVXfq4VtcbNS61bwk2TPXNvskCli825
         C0kgUzRln0c7VY6Bkwi6tTcu+xalGrUjlsdzZg+aL3s0AVNPy2vxwXSF0DfM5XzWMyTD
         D7Ud/zK+uqjDPenc7KJaw0xSZN8C1C5B8GoB61nXyA2mtGixdxYA9vx5D7HOXRRpiRW4
         jzMTbeHY4asEHEAIM0gxhzFD5XPAk4tiIQBYEvXU/5PB+0VrWb2d1xLLxibqZWWbCvfp
         /uzEU5nYSEV1Mgq8PI9tlLOgTeYHpUzQlSenHel10HL4G1u2eDP+FgTFJ5fisIjidUcO
         mfQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323VmxMnR00zMKCQnJ62Z26do1nxCWA6U7zgOKaIEPZqu/dShDP
	CDA2H70zQF117L7bdtF7KT4=
X-Google-Smtp-Source: ABdhPJzhijpgNodKdY7lkKA4JY4foIjo7ZFuVPE/h59WvWhpZrCRlq1k3JJqVWJxWy6YEpchZk0SFw==
X-Received: by 2002:a19:c350:: with SMTP id t77mr995625lff.152.1639432439079;
        Mon, 13 Dec 2021 13:53:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1551921lfu.0.gmail; Mon,
 13 Dec 2021 13:53:58 -0800 (PST)
X-Received: by 2002:ac2:4ad0:: with SMTP id m16mr937079lfp.29.1639432438265;
        Mon, 13 Dec 2021 13:53:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432438; cv=none;
        d=google.com; s=arc-20160816;
        b=ozeNzjv2Olr4SBmuUXJYd9LIDkGtot3994w/qRnLUnNA6BdjZg0uza0/gOsrO8Euuu
         lrF2aRIpWjMQEPJGxOpssRnpRYBDYiZwgjQhhF6K2TzHPIh7vsIhTOwQ//jgECsJZ2RB
         XrL5jqbfL3w0Ryndyg6aX0zsN5JHG/OdwuXTVw85hIWwHIJ3N1S7Lod4aZ/F6AptqLKa
         sJgPFYR28Cz1A9uW1mxHiFxTg7vrZLwTEHMLFuOdYJ+bIO1wQ962yNjL1T0SEhP7DCKu
         rCuir9g+EA3K3CEDGhQUZNHfX3TToV/hcC87tz5veG3H2rp302OJhqGXZzjzf0DdLEWV
         Q+vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MjDAtYx0w/hpe8AD4GtlWDQ62MUO/1LFO0D+7L3XaBM=;
        b=xdPr0sUxfcW3LOMqi6N+5qFO+0IA+c0iTGDGijUUuJz1RhXIKSFeTexsZk/4AyKDJ8
         SaHwGx2dfIXAtuGv5/9aADh9xa1hF2fgSlwypbvlcFDqTm8tGevxcRytwHkT7NeDwxbb
         0Wntt60YNPbTsFDL7sGsQ+VpzbrQiW1sX+fmF+mSJnmqUsqNjpdwUS55Z/lkDyvRDbE6
         oLR7AhT9XX0VL8GSVdibEGAbw7J6tdpythN6IIQUkTja5jY+pftayBUFmLapcg9NhtT1
         LxCOx1jcppy9cDCu+QXu41ullSYdPsjptVBmd5Ks0InIigZhLS25yWK6Kxb9qNjhv1oC
         llBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LrcPemYT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id y7si746865ljp.7.2021.12.13.13.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 19/38] kasan: reorder vmalloc hooks
Date: Mon, 13 Dec 2021 22:53:09 +0100
Message-Id: <15eeaed5bb807dba36e36d17a1d549df8e2b752e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LrcPemYT;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Group functions that [de]populate shadow memory for vmalloc.
Group functions that [un]poison memory for vmalloc.

This patch does no functional changes but prepares KASAN code for
adding vmalloc support to HW_TAGS KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 20 +++++++++-----------
 mm/kasan/shadow.c     | 43 ++++++++++++++++++++++---------------------
 2 files changed, 31 insertions(+), 32 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 55f1d4edf6b5..46a63374c86f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -418,34 +418,32 @@ static inline void kasan_init_hw_tags(void) { }
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+void kasan_unpoison_vmalloc(const void *start, unsigned long size);
+void kasan_poison_vmalloc(const void *start, unsigned long size);
 
 #else /* CONFIG_KASAN_VMALLOC */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size) { }
 static inline int kasan_populate_vmalloc(unsigned long start,
 					unsigned long size)
 {
 	return 0;
 }
-
-static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
-{ }
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) {}
+					 unsigned long free_region_end) { }
 
-static inline void kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
+static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{ }
+static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
 #endif /* CONFIG_KASAN_VMALLOC */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index e5c4393eb861..bf7ab62fbfb9 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -345,27 +345,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	return 0;
 }
 
-/*
- * Poison the shadow for a vmalloc region. Called as part of the
- * freeing process at the time the region is freed.
- */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	size = round_up(size, KASAN_GRANULE_SIZE);
-	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
-}
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{
-	if (!is_vmalloc_or_module_addr(start))
-		return;
-
-	kasan_unpoison(start, size, false);
-}
-
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
@@ -496,6 +475,28 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
+
+void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	kasan_unpoison(start, size, false);
+}
+
+/*
+ * Poison the shadow for a vmalloc region. Called as part of the
+ * freeing process at the time the region is freed.
+ */
+void kasan_poison_vmalloc(const void *start, unsigned long size)
+{
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15eeaed5bb807dba36e36d17a1d549df8e2b752e.1639432170.git.andreyknvl%40google.com.
