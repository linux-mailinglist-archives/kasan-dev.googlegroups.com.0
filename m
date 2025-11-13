Return-Path: <kasan-dev+bncBCS5D2F7IUIMJQ6UZADBUBCG2QFZO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 741D5C54E03
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 01:09:42 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5957bd7530asf155782e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 16:09:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762992581; cv=pass;
        d=google.com; s=arc-20240605;
        b=kzis8CHi3bUdR8Ls1pHR8aC0hMjx6yqihZ3iM1lMIwcWGHvz1L5MiQaAMInQMwxTKR
         hXIU3rciZTRw9ITWHvk/HlAodfzz8WLbvz4O0xIXnBHYlaZpjvRq1j6vyQ8a5oJtsEU1
         G7pHgCdWh/lCiwW5p04E9Kw/SBaJ2gZwVn/FHkkAEOw5XV0KHtcj0xeUTZHYM2ORHZ8o
         huT99YQwMXdS0iCHw/n8c/aT//llzhYmq975W21y2cg9t1xgUWVyaIaDPhxPCVpFcpCV
         Ut212KHahcUQwuY71Vl15QwhwXo5zlG35Hpm5y47Rtq9H8uQu777KKt4jGqtob/W9U2T
         hhHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=evcIrJkLhxpFsgBL1AMMPcVn0eVCM2HTKjJforZN2ME=;
        fh=cVBP/GjUL7becXxER2QMvE6ApFPEMXya2VjSmU4nezU=;
        b=jub4GYov+klG6ydYRbQ51kftOEUHgDSCPkkoFP41AO5Rwv01Y7dH4giZg5GDXRhya7
         MifJRGDrRPf/VrbuJHlMSuR06sUZ7eUCcBJhQ4qXCRRpT9E2/dz+TFRp0bfYFdKN3VG6
         wehPYYXrOIsdMzZ+LTtPyZCEKv23bZuWCXvAJZucJv2kwcZ9uiD9XIxYKJs7ZaZanVoC
         fj7mKmKC8D8Xl8u0+VNctlcHrmLUCTqIrz0xS5ykx0wBIy72xUJXPCclaZNV19eGfPTX
         88RxyHz0TD/t/G9jPPpG6620oie1O+DLXABF3uV81GiyNUNxQ1r6TANVv2U86YCsBx1V
         LL0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tzs2MJz6;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762992581; x=1763597381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=evcIrJkLhxpFsgBL1AMMPcVn0eVCM2HTKjJforZN2ME=;
        b=vBCxe7drWMwHwLjGcwq0kA/le8uHv/FwkkoVucss2OoEK0jkvo9XuzXL2abxA91WcQ
         96K6JF1h0K0Vx+J0K9eU4b8TFXYCY7lpVBGVxuLpxfk5stTOfO2ScAATRpx8Pnk8Kn/A
         yKFEC4vAaqDy2ncAZmqiR9AI/QEVL+P9szc37/yUUooGRvKNK+sJQWTO/1eU1+mGNlzU
         G1GHFw7fWAbB8alqFvjqn2kU6RdWqOU8SCPvJ+e4iCxHA/W5+47usDMlEtFvMfto+5fP
         eMMvhM6DtUzJM+1Q62VtvXnmFh9He9sPgtYQXyNQk1AfKg2VtLNBuspgMFNn49LCTD2V
         LO/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762992581; x=1763597381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=evcIrJkLhxpFsgBL1AMMPcVn0eVCM2HTKjJforZN2ME=;
        b=sJ9/oVG6n3SMMFhAhBNgpmCjSkcZuwZnFLt/6oJ5lf8W/AdFqXqni14UzMzM0vKJuE
         dgg4HPtl8L4EWrGzQZyCvX4jRAa09+fLcMOAaI/lbkETLbYsSLTnP/tVIAeLGJg83+wr
         6WjN8TMnbXf1TYX1a4n30rpA+PsgbHN9NPtKIX+OlR8g5Ma5kPC2StvyQZXt1+eaFDFg
         ID3wU3u1moaoH9Xpck/ufzLmhTLhJAkPWNlJ8phBoOM9GvR1UuMbdvf3GlaK11IFHbid
         G6NGdl0Zlm/lIQAYbrAgzUymGDt0U/uGKNwnubPr6xt90gShnX9xppkTvOxPWQdlG6jE
         nTSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWC0yM/fVxGPn+QEHU8or1wnA1sGE2D8CqVdj9MVkwEvFD0bZRPOBDGFZwSgRN/ZPqHIlTDGQ==@lfdr.de
X-Gm-Message-State: AOJu0YzLEQulYVId8zcwYXJUmbM4vwqoSBVcnAq/v58uDdE4LBoz96tu
	MclHzgSBeogKVOvm4oLZKZqreVrpl2q7vDEEDZBgtSf/PwGo9+S0a2CH
X-Google-Smtp-Source: AGHT+IGYVYIIwI153qcL43S/6lM1MwB7MKQ6ttMwLBPG/zplvOVsgI2EvVXAhUItRZm+S+0mTSBXWw==
X-Received: by 2002:a05:6512:2342:b0:595:7fa2:acd with SMTP id 2adb3069b0e04-5957fa20ba6mr187912e87.21.1762992581103;
        Wed, 12 Nov 2025 16:09:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aaGozbm4alPMhrlLn2U/7OpoqaYpvW4sZLeds//pCJQw=="
Received: by 2002:a05:6512:63d8:b0:595:7ee5:3caf with SMTP id
 2adb3069b0e04-5957ee53db1ls105957e87.0.-pod-prod-09-eu; Wed, 12 Nov 2025
 16:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWyasc+XmUHpcforuYnTigIvJukzmC7QuN+/vyPNUFbIFarHZMX8Gtlg7tgaU9VO2bwqcOOZOayRP4=@googlegroups.com
X-Received: by 2002:a05:6512:3b9d:b0:592:eeaa:7b7d with SMTP id 2adb3069b0e04-59576df94d6mr1687578e87.22.1762992577538;
        Wed, 12 Nov 2025 16:09:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762992577; cv=none;
        d=google.com; s=arc-20240605;
        b=a3ITn1697KHbA4K48VNPmZszdQte9AL7i/zLffGf2vY/ZzRqt47hPJfSYgRm3Y9K1R
         mV3EYOQTlS2IYmzXf6V0CSofxDfiQWl4AEt2Ez4MWOr82MKIcOzJxLxvS9RtMN7bOkfA
         SrwM/wkz2zqv84N87pp9fICjrNMrMIl3WkXmHBZke9s63b079UitXDKrQ5fXkOeJkyj8
         BvX5Xlq4EfkY0PJnkxGRnqLczmglGXEhUglytWpm/mNY3d+BaS4diTJ5iIMir77noJp7
         +im138dxylrPeGO9z/kEuCytQNlu7PHRCR5Ret5r5AqJs4SNYz6m+KZ/mUl2BBGU3DQL
         uYRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ph1LM4e+4fMT8OTS6Q8r3xDATqFyFTsTZoy7H8qnSGI=;
        fh=6QUzeHvXtbAFEbrkhmBH4qSTdAA5tW95g+mDol6JkB8=;
        b=dthlH3xcrS1Fl4g6cyp//7EFyAeH1w39dFXOUUC2VGa/lHi/CpbaJ8mNl9CjCXBltg
         y9SrNou2HH3FYNR8piDt83JBciSVwalNG2EXkIm0l2HgMujmqViuMQMQZiXvBzvnMXFN
         oCzxT8KerNlYdvVncETaJ7jRD/RZ0wqSNCicoH6KeOCam7Ex4ikWxoOzR2ZlHAQouKE9
         KwOruR/MINTx7FLkWTtmVMk2WXcGI9qZm/LigZNhKzrya2/DHsJsw6F0d7PP3pcPirY8
         tw1E4kDykP3WhvWWW9sw+DD9buisMGpi7sRqJ6AaIGCQdphnvQ8mBijbVgC3tG4MUzRq
         DoAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tzs2MJz6;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-595803c7a17si4038e87.4.2025.11.12.16.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Nov 2025 16:09:37 -0800 (PST)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vJKu6-00000006fOO-1M6X;
	Thu, 13 Nov 2025 00:09:34 +0000
From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: "Matthew Wilcox (Oracle)" <willy@infradead.org>,
	Christoph Lameter <cl@gentwo.org>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	linux-mm@kvack.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v4 01/16] slab: Reimplement page_slab()
Date: Thu, 13 Nov 2025 00:09:15 +0000
Message-ID: <20251113000932.1589073-2-willy@infradead.org>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251113000932.1589073-1-willy@infradead.org>
References: <20251113000932.1589073-1-willy@infradead.org>
MIME-Version: 1.0
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=tzs2MJz6;
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

In order to separate slabs from folios, we need to convert from any page
in a slab to the slab directly without going through a page to folio
conversion first.

Up to this point, page_slab() has followed the example of other memdesc
converters (page_folio(), page_ptdesc() etc) and just cast the pointer
to the requested type, regardless of whether the pointer is actually a
pointer to the correct type or not.

That changes with this commit; we check that the page actually belongs
to a slab and return NULL if it does not.  Other memdesc converters will
adopt this convention in future.

kfence was the only user of page_slab(), so adjust it to the new way
of working.  It will need to be touched again when we separate slab
from page.

Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com
---
 include/linux/page-flags.h | 14 +-------------
 mm/kfence/core.c           | 14 ++++++++------
 mm/slab.h                  | 28 ++++++++++++++++------------
 3 files changed, 25 insertions(+), 31 deletions(-)

diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index 0091ad1986bf..6d5e44968eab 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -1048,19 +1048,7 @@ PAGE_TYPE_OPS(Table, table, pgtable)
  */
 PAGE_TYPE_OPS(Guard, guard, guard)
 
-FOLIO_TYPE_OPS(slab, slab)
-
-/**
- * PageSlab - Determine if the page belongs to the slab allocator
- * @page: The page to test.
- *
- * Context: Any context.
- * Return: True for slab pages, false for any other kind of page.
- */
-static inline bool PageSlab(const struct page *page)
-{
-	return folio_test_slab(page_folio(page));
-}
+PAGE_TYPE_OPS(Slab, slab, slab)
 
 #ifdef CONFIG_HUGETLB_PAGE
 FOLIO_TYPE_OPS(hugetlb, hugetlb)
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 727c20c94ac5..e62b5516bf48 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -612,14 +612,15 @@ static unsigned long kfence_init_pool(void)
 	 * enters __slab_free() slow-path.
 	 */
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab;
+		struct page *page;
 
 		if (!i || (i % 2))
 			continue;
 
-		slab = page_slab(pfn_to_page(start_pfn + i));
-		__folio_set_slab(slab_folio(slab));
+		page = pfn_to_page(start_pfn + i);
+		__SetPageSlab(page);
 #ifdef CONFIG_MEMCG
+		struct slab *slab = page_slab(page);
 		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
 				 MEMCG_DATA_OBJEXTS;
 #endif
@@ -665,16 +666,17 @@ static unsigned long kfence_init_pool(void)
 
 reset_slab:
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab;
+		struct page *page;
 
 		if (!i || (i % 2))
 			continue;
 
-		slab = page_slab(pfn_to_page(start_pfn + i));
+		page = pfn_to_page(start_pfn + i);
 #ifdef CONFIG_MEMCG
+		struct slab *slab = page_slab(page);
 		slab->obj_exts = 0;
 #endif
-		__folio_clear_slab(slab_folio(slab));
+		__ClearPageSlab(page);
 	}
 
 	return addr;
diff --git a/mm/slab.h b/mm/slab.h
index f7b8df56727d..18cdb8e85273 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -146,20 +146,24 @@ static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(freelist_aba_t)
 	struct slab *:		(struct folio *)s))
 
 /**
- * page_slab - Converts from first struct page to slab.
- * @p: The first (either head of compound or single) page of slab.
+ * page_slab - Converts from struct page to its slab.
+ * @page: A page which may or may not belong to a slab.
  *
- * A temporary wrapper to convert struct page to struct slab in situations where
- * we know the page is the compound head, or single order-0 page.
- *
- * Long-term ideally everything would work with struct slab directly or go
- * through folio to struct slab.
- *
- * Return: The slab which contains this page
+ * Return: The slab which contains this page or NULL if the page does
+ * not belong to a slab.  This includes pages returned from large kmalloc.
  */
-#define page_slab(p)		(_Generic((p),				\
-	const struct page *:	(const struct slab *)(p),		\
-	struct page *:		(struct slab *)(p)))
+static inline struct slab *page_slab(const struct page *page)
+{
+	unsigned long head;
+
+	head = READ_ONCE(page->compound_head);
+	if (head & 1)
+		page = (struct page *)(head - 1);
+	if (data_race(page->page_type >> 24) != PGTY_slab)
+		page = NULL;
+
+	return (struct slab *)page;
+}
 
 /**
  * slab_page - The first struct page allocated for a slab
-- 
2.47.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251113000932.1589073-2-willy%40infradead.org.
