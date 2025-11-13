Return-Path: <kasan-dev+bncBCS5D2F7IUIMNQ6UZADBUBHHMZTQW@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA078C54E06
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 01:09:44 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4776079ada3sf1762075e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 16:09:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762992583; cv=pass;
        d=google.com; s=arc-20240605;
        b=GUx2RQJvO1tQZ7bjBJZxUP4AMsY9V/33a8cpCsE2Umg5NMRU2szEGmhR0QaGxM/2rc
         shGQBNusOB6b2lR+TXsLnPJMlZLanGOd4zKFL1B9uo9sJgzvPEZ9T4NMTg7ox7cfQ97u
         ldn4EHjP6yOSEUpPUZ2zsbcakgvXGNz6P0OakPjprwQRtweGknacy1xywJL4jR428Igm
         1P6xkq5AQfgP8ob0afdZ5JnzQ5XdAqMfGcot38Umk4kTVnZ/TwMJ0n/Om+X6OohNMy/w
         mIXB8e/LasGDanmSJkogozCMBpIF7Tlvl68o81q+Ea35yceEFV8iJz/IqYggvFvCtMoN
         2OzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7F5EkObEgjW9Rynz0X7QBxtOY2mP9UpzORKlmI6YRO0=;
        fh=KE+cLJIpvympFGtPJNpCemNsl1WLMHc53c63UsDdyzQ=;
        b=UPSnlmd7iavySmR8dQ6gs9EANWiASt2G3GO0yiWR6NXhHAeIWwr5d3UHTeNHuV8ARs
         I9riNWXjz26F/+KNuvtKfOSBQ9YDKhkC8+7aQu09AOnvUMrqqn+N+lVEdbQ/XdKSj9PT
         N4W+u7g8KdIVq1TU/lyJo3/M1CntzoLva/+lWRs63Tgo9+aXDHoy6D3XlKfpUuyqxki3
         4gbBcn4/VZ5T/06p5fqLTBVTHeUw2dTPcq88enLWF1DjiYh1bRBXhBC2QoYz/pUfG7XN
         Uz8+7g0mq1iAmugp66F7foI5fdpby2toYI4XyPMB/9xEoz7q9IlNDM6T5Ul/vLel/gDC
         gCXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GHmtUzxl;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762992583; x=1763597383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7F5EkObEgjW9Rynz0X7QBxtOY2mP9UpzORKlmI6YRO0=;
        b=V3yC2RqM6MtrrNXTIKGoneDN9B0dIGjmJ5rUYD8tCwaYznj5wh0O/Kdi+7pBbYYTzj
         RJ6MDW4BluuCh9BF/jEIyvG8CAg4jxLOgTMDwhgjzMSJcYpK96+qxIdD6fR/6o/NAlGt
         8gfkXytisSnRlLmboTdgwZUas/mXLZpC8Ha+fDND0TTNEyBcKqkPtWRa/y2+538l5MJy
         SIvmG73LfI5ZrvabOj0yALb/crH7gKIOGGWFS0SEZpPaBPD6eElNR0+W+uVZewJHN5b8
         4ZDJuLWidTmxyRUp28iJRleRKo1pd1sry74p1HIZgEx7cwy/2QOPUQwyG0gP8VZEdetY
         5o0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762992583; x=1763597383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7F5EkObEgjW9Rynz0X7QBxtOY2mP9UpzORKlmI6YRO0=;
        b=d56LGxgd6h3k6VrrKM+Qn8rcopp7pnoewHBNiG7Hv+dNAawHqmatBphgrgF9NHfaUe
         De1ekqNHt6zu61yR9qcrtU2l9gIDprBzp+WaCtU8Qr2TC7kQaDNa0ZTK+hYPzlB5bdMD
         vHmeNUM0IE599u4KdglCTS/CX/Jm0MXB8W4JhgTNEQooe0EDy/owiWHP/acnmeFpCWLD
         g+Km3+aJ8Lj21a4Xr3S0WSQiYR51SgPy2/ZPMkJ06Uuwc+/yVyLt3WdT4hchGOAFXpVu
         hN+4MOjyAXj3FsNxY8bJyk0Vo5YuFIgb4JkQK0XGNHJ70bV4CJVKGeKff26DGBziK5mH
         lUew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWwIl8nlE0E7YEqtZoUTxnkdcULZteNTlJ64DlxjmyYjvOOaHtGbsYg3lsXrFQQXF0WtdDEYg==@lfdr.de
X-Gm-Message-State: AOJu0Yy1W2SEqZU3OuKNl1bD8I9LLTDSId7JILOK0yiAeiqAaxq7WYPh
	FtH+gRvsFgmLblRN7SSdY36Ww/kr5PhvrUyaKc5pxMmyuSczYojbVLt5
X-Google-Smtp-Source: AGHT+IFEKi++fWJs0vJx9t8eodyyJcrWOREv5ja6yERtjpQ0tu21WRIC/TLmxdHzcuv/1k5kIYb50Q==
X-Received: by 2002:a05:600c:630e:b0:477:fcb:2256 with SMTP id 5b1f17b1804b1-47787086fdbmr46070805e9.17.1762992583090;
        Wed, 12 Nov 2025 16:09:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+abBCV984PgVZFGzTG4ng6A2p2A4RLQ+m7ggDplGLm7Dg=="
Received: by 2002:a05:600c:6297:b0:477:4db4:d384 with SMTP id
 5b1f17b1804b1-4778be38ad7ls1713595e9.2.-pod-prod-07-eu; Wed, 12 Nov 2025
 16:09:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVlJ/s4eN2rF1V2nj5+hnZBnhk7E/HEJeiBjG8V0++eRaqqyNlcA1MuOJaVNgc13CLm3AbDE05HzW8=@googlegroups.com
X-Received: by 2002:a05:600c:8b43:b0:46e:6d5f:f68 with SMTP id 5b1f17b1804b1-4778707d44amr44767175e9.12.1762992579828;
        Wed, 12 Nov 2025 16:09:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762992579; cv=none;
        d=google.com; s=arc-20240605;
        b=IgiFM8rffsHAKJaR9c2cA/3GaRLCIjZNBFRapt3YNT4rtASKcEOD4R4JiyIYWhSMHn
         yQO1cdeqMRXsyBq4XxOBhStHY/OmnOgEZF8czHNU2Vl4Xb0BbPhbBZ71MXbaLKUKkkQc
         TeAZMMA2WUXd5HMJzZ97oG7KvKvkr4tWGQTBiKrEoyLey1+fzeOXS8JckzabyvxyXTja
         CK/WbnQFoz0BUVXUYFIBdklVh9Jq7H8mYEbnbr2lXijHklmR6n73EoO1woemnmlh9dRo
         KcWBq6C0D2sXgZ2youLnbI93CRVIlUYOncFiURjc2/CCRXBeGcosVojL97/bvYLHKXIL
         6qvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NtrdOVTvytdbzLtTPBJPfuXb/Jjppd9vDCLKsL+xbiQ=;
        fh=Qb6FU9ExKeUBq1CoaWEHUTrAzO0NqMTMh+praChV8FU=;
        b=IYhSbUPEck53ido/qEomQDsc11yTv9ihA7TOwOViuT51q6byaDYvDeVLMuz+8a4vxH
         0Om3TQ7CuL1BHeNOQJrfpLViBMxO5AmbZ0vqhwFCOOAvxEFsgM25PmLIY537mg2KLYjC
         JGDHU3XewB5ZDs5theHFJIhlBtDWakDJXRIFD/BMwveEBqyZkTXB/mHxAHyIHROz1GHg
         VjqCHQbm6HmZLta9tsFFMuI7BHDMyDasAWNd/TLjutgL9dSmL1nQT6jNmvsM+7tJOXyg
         1Q3oINUhkgqLswj4LfygGSpbNkFZD4oAGzqooVNw+nA3YKZwneoio+x6aXifyzamLN7L
         d7ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GHmtUzxl;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4778c696f98si63125e9.1.2025.11.12.16.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Nov 2025 16:09:39 -0800 (PST)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vJKu7-00000006fPJ-3pLc;
	Thu, 13 Nov 2025 00:09:35 +0000
From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: "Matthew Wilcox (Oracle)" <willy@infradead.org>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	linux-mm@kvack.org,
	David Hildenbrand <david@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: [PATCH v4 15/16] kasan: Remove references to folio in __kasan_mempool_poison_object()
Date: Thu, 13 Nov 2025 00:09:29 +0000
Message-ID: <20251113000932.1589073-16-willy@infradead.org>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251113000932.1589073-1-willy@infradead.org>
References: <20251113000932.1589073-1-willy@infradead.org>
MIME-Version: 1.0
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=GHmtUzxl;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

In preparation for splitting struct slab from struct page and struct
folio, remove mentions of struct folio from this function.  There is a
mild improvement for large kmalloc objects as we will avoid calling
compound_head() for them.  We can discard the comment as using
PageLargeKmalloc() rather than !folio_test_slab() makes it obvious.

Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
Acked-by: David Hildenbrand <david@redhat.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
---
 mm/kasan/common.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 22e5d67ff064..1d27f1bd260b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -517,24 +517,20 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
 
 bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 {
-	struct folio *folio = virt_to_folio(ptr);
+	struct page *page = virt_to_page(ptr);
 	struct slab *slab;
 
-	/*
-	 * This function can be called for large kmalloc allocation that get
-	 * their memory from page_alloc. Thus, the folio might not be a slab.
-	 */
-	if (unlikely(!folio_test_slab(folio))) {
+	if (unlikely(PageLargeKmalloc(page))) {
 		if (check_page_allocation(ptr, ip))
 			return false;
-		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
+		kasan_poison(ptr, page_size(page), KASAN_PAGE_FREE, false);
 		return true;
 	}
 
 	if (is_kfence_address(ptr))
 		return true;
 
-	slab = folio_slab(folio);
+	slab = page_slab(page);
 
 	if (check_slab_allocation(slab->slab_cache, ptr, ip))
 		return false;
-- 
2.47.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251113000932.1589073-16-willy%40infradead.org.
