Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPEAZ7DAMGQEUC2KGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0DA0B9941C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 11:56:13 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3ecdd80ea44sf525061f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 02:56:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758707773; cv=pass;
        d=google.com; s=arc-20240605;
        b=lL3L5UIhf8f/ENl+KRk/ghxVfQfaOxHBUHGYV6EVAf3re3H9HqCUUN+q77B40DsIh+
         6zJ2Tps/3FB4dsm6nIeCDZx27LS/NlualuT/BxJlt16NJIRyKqURFszmF4GXYiwXmCDr
         VCWwv3ScUnm0oufpZDmzsXWmqDNKZSGdPnmatFG7fjzvk0dos4yR2N0x3tWdwEzb6DoK
         Y9eF+lpYwumayiK7izk+Z+xLfYlTecUXbLkmU5o+DupXoIGWmvndIl9Xt0QcdRRAkh+X
         x53YjF+UbqSSGbXC2T6TO3EMSKpGmmo0vGRDtP6O7h0G+7rP+hO9Ea6U+Bp/hwTKx+tF
         3dWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=FwkuD39L2zZ8PLVfAiibo3sbJ4gewFDkF4cWrwni5rE=;
        fh=x6t5xpWmC4bEu2TCDWu3XdOkQehSMs5QO6VwO/MF3uc=;
        b=ZcPxQGmzbpW5Ibo4AS81JcEN49+mmiFY1IiDPYuRida4VVfzHozcwpw9tdFaqnoZQD
         hd8b2DuuOhDB46tn3+pq+5CXQNh9LWAunslJjXrS5n5h8ZYImGPT7f0SxihaHr56JsYD
         PtE50gvy2dG6bquzxZordJN5z7jZldfxyVpaoMMf0RtZUJi3bPtrZzEFoPP4Cdo3ZWqn
         TFampGnCqzUWaAjNyxhG93XuoP9ADD/bQ0gauRVcUzYGhlJpapAdkuJnmaNjgZKJYS5L
         8Thw/gPlI4VWNw0s0vvH1EsiIIBLoisz5cAbu1k8e0iE2/M+cHheVfqeAmJeJTDSfSua
         +oZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4jDRqTlt;
       spf=pass (google.com: domain of 3omdtaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OMDTaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758707773; x=1759312573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=FwkuD39L2zZ8PLVfAiibo3sbJ4gewFDkF4cWrwni5rE=;
        b=qoUtk1KmzjkXbcsxlD0yP19alJVZrudK/sC0AOLMjOS0pSc4i2NSEirSDh7vGNnaFv
         b+LcjebsTeqF5m/F7at4lF/YkD6T44lxPjA0o7VfhGEQX/CB1N6PYBjFB6TOJB3gGQPb
         Zq9CBWXmDdwZhbVY+ZdkmCHqC5BP16nER2zuZcuRw37H1RkrPEKDoqA9fFKeS5hcSJGj
         I6YYiIp1rSqmhSAdGvu9SeWPLqtGfqIkMMadluPqNlALHZLduOLu3FL3OfIvDr49ZoqS
         QM8f47UnTFU17whLv9Ck2blVBQJ/E5qFfxS5SxpDe6WdeqyNtnFy0Fy7IHEg5GySb3Pz
         QJyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758707773; x=1759312573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FwkuD39L2zZ8PLVfAiibo3sbJ4gewFDkF4cWrwni5rE=;
        b=vWiy7LeTY4mG0OhHiGkLWZI+DST66u5urwOfTic+ZER7dHZPffeVrWdR17Xrbxdmlz
         2fBLFSKqlhlJXnObfjxeMvX35dAgcIU0uo0VKkmaJVp486yGru08EE1soD0iti+RFiyq
         kFo2VDlM+/pLxrtYLj1jrrZ1JrTSUcv4qRBs3egsJ8ag1KwemyDGBVWyb1G5QS6rhNM8
         3tZQM+030nJU/5x5ahO3zAxBeN+VR2FOXhIr7X3/ZcVpiqlh8QNuAz54FFBBrNYgr8o7
         EKDfWIfLZCQ1WYeG8kD8MBlPw7uxNKzksaSP4Jkkz5igGF2D6ft4HzcwsaeO5Q/wmf+g
         mJ/Q==
X-Forwarded-Encrypted: i=2; AJvYcCWse0i0UA3T/w5281GDcQI450mzMJa6LcgRZB6RJAqYY5dYh8MJmvw/4XZUkY9yRqEV35XyYQ==@lfdr.de
X-Gm-Message-State: AOJu0YyuBEBl2zpWAMDxHUABxMrumnRi5HQyblnuHcTaP5O8+juBPiC1
	UwPoSqzBitU7KvHOAxYB2mk6Ku3sqmLn5Eit+ZA4u2CPr53ic8uT/nkX
X-Google-Smtp-Source: AGHT+IG0miJzsrFuoOl13EF5HtH6s7LK4i+o5jcowW8hVcDuHser8+iyW3hsAdkETPuSUU9tHLrh8Q==
X-Received: by 2002:a5d:5d0e:0:b0:403:36b2:59ea with SMTP id ffacd0b85a97d-40abb57d8a4mr1731479f8f.5.1758707772812;
        Wed, 24 Sep 2025 02:56:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7Yeq/O74615rJnuR7zW6bRbdg5DYPcgqBHOHeIjWB5pA==
Received: by 2002:a05:600c:1c12:b0:468:2a1f:69b4 with SMTP id
 5b1f17b1804b1-46e2862f0eels4368315e9.1.-pod-prod-00-eu; Wed, 24 Sep 2025
 02:56:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzKPjWpsVcSe4+8VqmzeKxmPGLN+azyduUHPrMQqEju+mKFrlbgh6RQuMiw9Ku1/wIdP+tK4GXDUA=@googlegroups.com
X-Received: by 2002:a05:600c:d1:b0:456:942:b162 with SMTP id 5b1f17b1804b1-46e2b543d78mr12561315e9.11.1758707768711;
        Wed, 24 Sep 2025 02:56:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758707768; cv=none;
        d=google.com; s=arc-20240605;
        b=EDEyd+QXTyLJy4a+CbbdptpfiTYIit2JdQzmyfmD3Ks+z7Exev4WrUgPXcHB4G0S3Z
         BijcjcEJbRW9fZRAsiHsk6j0AKZ8r/VRGZtou9NUTk10Bn212HLiyj9svac89rtFXAH4
         2hAkv9FQ2PAksfTkyNML8vEl9B3iTm1mbJkURL3qTPvpU1i0vpERX8tX6DvEKkOEHPb+
         I8cWB9tpQKjS11LHsWrOTTkXLzynMFoTrCBVQ2+QsmQDOyPjkvJW/az+hR1fCWctlirh
         C1bffY7zGe1wYGU190LGI1SUKpNCbnKmLWvZhnI0gqyLrooT2LwDLQvn+FohVjb0Cgpl
         jRSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=QAmycbMkPNpKo2rKRIkxeOAbE/X03s6JAmOKI9ShzKQ=;
        fh=7QRWAPoL/4hXckFO86AUWtL9KXbjpPZYyl83GInLEkw=;
        b=OO2yhsK2UGy+ieotBueh5TCVrudpj68Xby4+WaPLzqPwDcklnO/pwAV1+tUBgcoot6
         nPLsugidNvn5+luvUNE6VKoC6Ikfr//ia/2S2A8PjWIInCVnuS7SJ/DNw0rQ2vrwo0Zz
         x3Rj4FPjDeYcZJF6SwMhgvAxoG56w0TxpnllZKSZRj0GYEkmSAZ4WxIFmKqUi1+Oya2M
         BgPL+qjcnVI9yyplRAkZGCFTVgFx3P5NYYXYUMffHsso9eXJlvpqbUzR59y+pqXTDe/K
         AQUQ7CPPqPbBnw6ahB8F7RPhXHhOXzBa+zRs4M1ue34O5D5+irvcJkxD+KuWWLV4uCtm
         XHug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4jDRqTlt;
       spf=pass (google.com: domain of 3omdtaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OMDTaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e2a996cc4si261895e9.2.2025.09.24.02.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 02:56:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3omdtaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45f2a1660fcso52864595e9.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 02:56:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4nm3mj2CJ9AGOX86mqDQoCp90N7++fEliwE5Sjn0kbjrVYuI2Xt70/JSvUSSGMTwYeAgd5PYrXyU=@googlegroups.com
X-Received: from wmsr5.prod.google.com ([2002:a05:600c:8b05:b0:46e:2897:9c17])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1f12:b0:465:a51d:d4
 with SMTP id 5b1f17b1804b1-46e1d97d858mr54128675e9.6.1758707768216; Wed, 24
 Sep 2025 02:56:08 -0700 (PDT)
Date: Wed, 24 Sep 2025 11:56:04 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.534.gc79095c0ca-goog
Message-ID: <20250924095604.1553144-1-glider@google.com>
Subject: [PATCH v2] mm/memblock: Correct totalram_pages accounting with KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz, 
	rppt@kernel.org, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4jDRqTlt;       spf=pass
 (google.com: domain of 3omdtaaykcvu38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OMDTaAYKCVU38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
for metadata instead of returning them to the early allocator. The callers,
however, would unconditionally increment `totalram_pages`, assuming the
pages were always freed. This resulted in an incorrect calculation of the
total available RAM, causing the kernel to believe it had more memory than
it actually did.

This patch refactors `memblock_free_pages()` to return the number of pages
it successfully frees. If KMSAN stashes the pages, the function now
returns 0; otherwise, it returns the number of pages in the block.

The callers in `memblock.c` have been updated to use this return value,
ensuring that `totalram_pages` is incremented only by the number of pages
actually returned to the allocator. This corrects the total RAM accounting
when KMSAN is active.

Cc: Aleksandr Nogikh <nogikh@google.com>
Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: David Hildenbrand <david@redhat.com>

---                                                                        =
                                                 =E2=94=82
v2:                                                                        =
                                                 =E2=94=82
- Remove extern from the declaration of memblock_free_pages() in           =
                                                 =E2=94=82
  mm/internal.h as suggested by Mike Rapoport.                             =
                                                 =E2=94=82
- Fix formatting in the definition of memblock_free_pages() in             =
                                                 =E2=94=82
  mm/mm_init.c as suggested by Mike Rapoport.                              =
                                                 =E2=94=82
- Refactor memblock_free_late() to improve readability as suggested by     =
                                                 =E2=94=82
  David Hildenbrand.                                                       =
                                                 =E2=94=82
---
 mm/internal.h |  4 ++--
 mm/memblock.c | 21 +++++++++++----------
 mm/mm_init.c  |  9 +++++----
 3 files changed, 18 insertions(+), 16 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 45b725c3dc030..ac841c53653eb 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *z=
one)
 extern int __isolate_free_page(struct page *page, unsigned int order);
 extern void __putback_isolated_page(struct page *page, unsigned int order,
 				    int mt);
-extern void memblock_free_pages(struct page *page, unsigned long pfn,
-					unsigned int order);
+unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
+				  unsigned int order);
 extern void __free_pages_core(struct page *page, unsigned int order,
 		enum meminit_context context);
=20
diff --git a/mm/memblock.c b/mm/memblock.c
index 117d963e677c9..9b23baee7dfe7 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1826,6 +1826,7 @@ void *__init __memblock_alloc_or_panic(phys_addr_t si=
ze, phys_addr_t align,
 void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
 {
 	phys_addr_t cursor, end;
+	unsigned long freed_pages =3D 0;
=20
 	end =3D base + size - 1;
 	memblock_dbg("%s: [%pa-%pa] %pS\n",
@@ -1834,10 +1835,9 @@ void __init memblock_free_late(phys_addr_t base, phy=
s_addr_t size)
 	cursor =3D PFN_UP(base);
 	end =3D PFN_DOWN(base + size);
=20
-	for (; cursor < end; cursor++) {
-		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
-		totalram_pages_inc();
-	}
+	for (; cursor < end; cursor++)
+		freed_pages +=3D memblock_free_pages(pfn_to_page(cursor), cursor, 0);
+	totalram_pages_add(freed_pages);
 }
=20
 /*
@@ -2259,9 +2259,11 @@ static void __init free_unused_memmap(void)
 #endif
 }
=20
-static void __init __free_pages_memory(unsigned long start, unsigned long =
end)
+static unsigned long __init __free_pages_memory(unsigned long start,
+						unsigned long end)
 {
 	int order;
+	unsigned long freed =3D 0;
=20
 	while (start < end) {
 		/*
@@ -2279,14 +2281,15 @@ static void __init __free_pages_memory(unsigned lon=
g start, unsigned long end)
 		while (start + (1UL << order) > end)
 			order--;
=20
-		memblock_free_pages(pfn_to_page(start), start, order);
+		freed +=3D memblock_free_pages(pfn_to_page(start), start, order);
=20
 		start +=3D (1UL << order);
 	}
+	return freed;
 }
=20
 static unsigned long __init __free_memory_core(phys_addr_t start,
-				 phys_addr_t end)
+					       phys_addr_t end)
 {
 	unsigned long start_pfn =3D PFN_UP(start);
 	unsigned long end_pfn =3D PFN_DOWN(end);
@@ -2297,9 +2300,7 @@ static unsigned long __init __free_memory_core(phys_a=
ddr_t start,
 	if (start_pfn >=3D end_pfn)
 		return 0;
=20
-	__free_pages_memory(start_pfn, end_pfn);
-
-	return end_pfn - start_pfn;
+	return __free_pages_memory(start_pfn, end_pfn);
 }
=20
 static void __init memmap_init_reserved_pages(void)
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..9883612768511 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *ta=
blename,
 	return table;
 }
=20
-void __init memblock_free_pages(struct page *page, unsigned long pfn,
-							unsigned int order)
+unsigned long __init memblock_free_pages(struct page *page, unsigned long =
pfn,
+					 unsigned int order)
 {
 	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
 		int nid =3D early_pfn_to_nid(pfn);
=20
 		if (!early_page_initialised(pfn, nid))
-			return;
+			return 0;
 	}
=20
 	if (!kmsan_memblock_free_pages(page, order)) {
 		/* KMSAN will take care of these pages. */
-		return;
+		return 0;
 	}
=20
 	/* pages were reserved and not allocated */
 	clear_page_tag_ref(page);
 	__free_pages_core(page, order, MEMINIT_EARLY);
+	return 1UL << order;
 }
=20
 DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
--=20
2.51.0.534.gc79095c0ca-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250924095604.1553144-1-glider%40google.com.
