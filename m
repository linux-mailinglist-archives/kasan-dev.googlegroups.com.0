Return-Path: <kasan-dev+bncBAABBB6BTKGQMGQEYSCQTSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 821264640F6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:03 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id q15-20020adfbb8f000000b00191d3d89d09sf3864077wrg.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310023; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8gjdnubTuij5W4TvzXx7ldXOqAmAkTpgGd4Wj/VAQL949KQnLjX0qdYQpeHyO+BJV
         Q2B+mN5nbpYIoGOh8fl3P+O2etATOdfICW/zJp4IbCyNIm2u3qI6THl/y8OgSrqxFrG3
         /dZZZz+SwnGOIDrJMC9Dqr4fvn1EEvaQpSZvWGAMpjIwqTpaip1dSTddGeqkI0C8zHZV
         C8lCBFrhukNK7JbedWmY1fAvNw7AicwZh97thlQIjB3G9PgVgFbWaGiARgEJ4kDqFawX
         U5YxQl1a+6QMux8hEloc4c1yiYm1yZXbCyns2kWZU3nxPu5mCbTNU4sRUIixO5PB9NbY
         DRVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kVmRKcj6TuTdDT4sSw+o8/UqWFoUs6kb7FBr+z5grbQ=;
        b=QJzojyQX7yHGG+6ADPc9usRejKsX3N97/30aKF7Hki93NdESI4Z3NrmZqJKs8eYXj2
         WjMueazU5KS7mk/FrL6tzVPLRtXWmZOQuIaxo47ggh9H4GEpyn9uvYjqvXXcmcRazQBO
         KGbt2gmINUbWC7rsAPEaG/eMselsd1wpgdq859/ru6JMBS4jX9Be3MFHpOVvuXeK2oXX
         HC3yIQq8l0jUOG5jEYJHQxGHDyZqimJb/bEmJkPO6dnedrmqwL4jQYt5qPQJYyoTH2rJ
         5ePj8cy2aeE9M45c+BBYwK3lHxKDZz7RLKsICdu+Rz0csLUOsR+4q2j8kDO8gMFjIJt/
         cJ6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iJYmQ6wx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVmRKcj6TuTdDT4sSw+o8/UqWFoUs6kb7FBr+z5grbQ=;
        b=GVxVEoPE/dGphGZONVprHD3ECt+VQIzmHa1k/eu1+yHyXVUpbxYbQW6DtjGkYVU0YK
         TaMRBwFBil2nUMAB2cnj5xnOaMAnD0AbytWCMgKMLOWyIj8rBaz/3kDQxZiz5oquP5Lw
         cylI3xiFqXIoktKLdYwxXNG3bDs9chFlQjiasqnyO9OQHAu7ZoM7ILhm5l4kTKGTx0gP
         e497h67Hg/AZJf4Gm9lTCYYPG4JlDeNAZ34fnTdaHX5GN48ExFQ+hZC/5xIrmgZkxY9B
         axgle7sEIAqQBzIaI8dtBBb1Hmx3oO/5WM6tS1ha2wRju3DoOWkuW1wG/UnZF8Vg95Tg
         Y3ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kVmRKcj6TuTdDT4sSw+o8/UqWFoUs6kb7FBr+z5grbQ=;
        b=qBbqJyFM6vTxwNYP668y0fVmi5v2oY2/MrhqeoJn24JN09Ntrd95AknsTMjcX29WEc
         MgblX/cMF08581PopQQ0qH1P+547PGKGuZCX7SJusXYRCjpPgLf0Dq3/E6+H075gTKZC
         KBXe37M7IdsRqZQrrWBPgQUx2DkipGHYNQjCMfs30HudFcaxvcHq5BOuOoVsnI8h5Zs9
         IoA9hMnckB9+2WS0/FuJMiIr/1kMGNtZTBmvCKT8Li6Cug6KkPsFmcX2tJIJltszvSmT
         ZvY5u/6mhnYjqZwEsp19A0XBI8TDd+l+HL6jisYW3Bp9xK6l7mQEaqrYSV6pSzrPltjh
         DJ/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DOtZr79u6f220046SL5KzoEVZQt8MsOWsDCJ1/FI3zllMacU6
	DRofbTCG5M91O8+Fpt5lCaU=
X-Google-Smtp-Source: ABdhPJx+rBZQPsdwuAxDyaDaxrwbe5Y/NXAhIQQgwaMaXO2yleoqfoT4HNeOn0XtEQoaOWQDLIMglA==
X-Received: by 2002:a1c:9851:: with SMTP id a78mr1773725wme.116.1638310023290;
        Tue, 30 Nov 2021 14:07:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls2132291wmb.3.canary-gmail; Tue,
 30 Nov 2021 14:07:02 -0800 (PST)
X-Received: by 2002:a1c:4d0b:: with SMTP id o11mr1804904wmh.68.1638310022685;
        Tue, 30 Nov 2021 14:07:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310022; cv=none;
        d=google.com; s=arc-20160816;
        b=l5WF4HhBHvHJhb3AHPBUxQ1YEPbJon6vL3oSmRXeLV45K9QkeRbVTEJydXreQmQ/5h
         s+m1k32g91cEG075MjG/PvTTinGH++ZjyPsl598yVpH3FCDf2CTGrypZ0ZJh2ay68Mjv
         HdAdEUw6ddRLJlyNIrt3aKJb4hpfxh1UmZ7xv51O/vCizOaWNHbdJ9QHxsBZjxEkmmyi
         ijmtx8rmrDRjsc52csBd40EvTiNEuGs3xyg1O/QM43PgtcorUmkN1ekXHXcmZKA1xzwy
         wzTcXVrCMz8njgdquAq18mkkojXNhYFuTxh3Ee+0RAxxxeaAuobI3+vBH5R1LZDBy8Ar
         yTwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JTNahgB9b8xFEkRfhyeNPJ7ITVoB0ROvdRGcm8t3Kk0=;
        b=cv97am1X6mRAYYK+2JlZHdfTew8YwekmFyL4y2jIdCjkTHa+uaDtDNJlmOql4Z8VC0
         JYQGrP4q+HpqohEo64P+VxNI+8xXAQq+11Xp1TrP7le2ReRo1iVvHMrwmGc8xHsyW4ld
         LF80TaSK11MOL47SGverz2fTYBGvBCocjMW7gXyrZf1BoT53RZQRVjqT2l9FwptCe4/E
         vCtJ3+qKyfVbs+4HgZsyk9ijOZ7GkmcujP9vfYJeQzRHe7iyOPPrUwA2ZoByXSS4X0g8
         vRxiGmBFoIpApZ8kvOcjoP/c8qJ/YnBnGlHPNJZdkdQydOvcEseqZja76WKWVQbifMk6
         FfrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iJYmQ6wx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id o29si801994wms.1.2021.11.30.14.07.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 18/31] kasan: reorder vmalloc hooks
Date: Tue, 30 Nov 2021 23:07:00 +0100
Message-Id: <01fdd2a34c212755b2c9f8b8d729712a7e3a227c.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iJYmQ6wx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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
index 4eec58e6ef82..af2dd67d2c0e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -417,34 +417,32 @@ static inline void kasan_init_hw_tags(void) { }
 
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
index 585c2bf1073b..49a3660e111a 100644
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
 
 int kasan_alloc_module_shadow(void *addr, size_t size)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01fdd2a34c212755b2c9f8b8d729712a7e3a227c.1638308023.git.andreyknvl%40google.com.
