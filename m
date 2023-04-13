Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPP736QQMGQEV54QFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 49D296E0E32
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 15:12:31 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id t191-20020a6381c8000000b00518e776a1a2sf5651681pgd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 06:12:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681391549; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYGhAbnMYwXYXDQxJYKq/KgdP/VbYPYh1nE547V0cVJFECHq0A6YUfdItoiVSyhX//
         sBdQ4E/JlGmGfQAJar5ljEjVJzohyuIb6TDug0tehDUb3dehywvvrdvPVJ14xb8BGOLc
         MaHuP5dX4/DbnxpqSsKmRCMl6tbaGsYJRczI3Y+dW1uCwor3O1VKDe3GxgrdgZSiucCb
         o8GRXixPf4S5TejKFLmyVpC15vM+ZukjZPMTXoMgvqhhvwl3JR6YobFcuLUMgRbp0xwB
         4LoSsQeFjG0NnUR9ADXguVsZMWwRSLK7a3jjy7RpnAqbnC/bUt0F384SOwlDUbBWF1Xe
         BKgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=xvityPH6MSIgWtkq595nY3RUCRkzxBuvm4Jg3RhHZp8=;
        b=JPkesyChncGxPJ3FM7g/flQx4KZYlgVfviDZ6843L09orZwzKAdWmUuvFxnBs+mz3u
         e+uv8PGQEoReknXkKZrePeQAR2/RNEQgU1ZbxoN3Oshg4TaBrB8k/nuu37I7IVy+S81s
         qW3hdI8IqtxDdZF7n7dQu/CzV/eXK41GOhjhvuRK5F9cJ+N5PbiVdEYxiU9B8Dcd4FcI
         hzMd/EA8/Dru5+zsRN6eBf3CJvuzv0cc9fcChu14zRMuKwPAWlBsUhwtEbvXodXjpAmZ
         YuFJjXUFWDZVB6pd48yWLciBXZUhuD+O/o3wSbLJDNlAt9K0sUEknPRgZxX8qdXKyG16
         IFzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eFVXlBPl;
       spf=pass (google.com: domain of 3u_83zaykcciotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3u_83ZAYKCcIotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681391549; x=1683983549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xvityPH6MSIgWtkq595nY3RUCRkzxBuvm4Jg3RhHZp8=;
        b=Qya+q6DtPMxMO6NhkCvAbNRk222QhvPq2jlgPFA4GRbp8ikD740yr2xqE+9UGG6D0x
         V1SKjF1ZJT05XytYuzlClCXsAZcBS/Xzc66MwJlKEBnKVVNCScdgqnHSGlQXF8Q28Y3V
         XuEhKDKnyHDEB5UQTjHFlbzXorTdGkSFLutsDfUscyg0KDhMljjFx66qbQ7+SiKQjTRZ
         wV5y9NaH1eDNEW9QTkpxFKCeF+SPQFsScubKT+4ZEU6g9EyZ1nYWM196EMsRMkgMLsqw
         SlmhZkHKMtUj7kXtKEu3fxI5De3h+kpeIp6g2cmfUNq0XG5RYWJz9b5Qvtls2qkHeBGB
         KTRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681391549; x=1683983549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xvityPH6MSIgWtkq595nY3RUCRkzxBuvm4Jg3RhHZp8=;
        b=dCavGEQA8d8+a0/RplYxglE+SfkZ/2pE+6LvPvZKwLqclZUZkiijHlBxx9QQQBO8Hc
         DjBu43YI1k2SIwsRzePZXISotoXNacWdsgaSV/SuLtLq1vdEbJ03YPSKiw5DQd+oRXAd
         Fc5dnNdSJPr58bcNfF3P9tSMNaFhazXbmYBfhlS0mz1n4wDAGaWRWhzg8rqP64Z6aJjt
         Wa8iUn/R+qA31In7rrVaqsWRqDlY7o5Ygz+CAf9ZBE62QiTloup2J/svir7cjFiq+fiU
         orVDXRrN4YZjuxxUmaI1jOeu0pFkQ9sTsqu+4aT7MDOHM4dP93jZ3vCD4NKttf3AYdsL
         vKcg==
X-Gm-Message-State: AAQBX9c4pQAxaAWcpHar8M/oE2FgZPdCZG74u8DnfzeYT2c0JY/OI237
	FhEcGiOhjEzaNyo+d/VhgT4=
X-Google-Smtp-Source: AKy350ZQBOJgEFPNCthvU4/SDrEf92754RPMEShqkjyxhTh2wPxjCuxANH6RHXNKgueq5ARDK7h5aQ==
X-Received: by 2002:a17:90a:bb8d:b0:246:b617:c730 with SMTP id v13-20020a17090abb8d00b00246b617c730mr1909249pjr.39.1681391549365;
        Thu, 13 Apr 2023 06:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:68d:b0:1a1:a83b:2aa with SMTP id ki13-20020a170903068d00b001a1a83b02aals334234plb.1.-pod-prod-08-us;
 Thu, 13 Apr 2023 06:12:28 -0700 (PDT)
X-Received: by 2002:a17:902:ea03:b0:1a6:6c27:e8b8 with SMTP id s3-20020a170902ea0300b001a66c27e8b8mr2564014plg.59.1681391548238;
        Thu, 13 Apr 2023 06:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681391548; cv=none;
        d=google.com; s=arc-20160816;
        b=X1ti3MBlJlHLdAvkofo3OBZByb8Wjl9n7lDaPhEjeUqQQMxInsuzLoIQzouQcCqxVc
         zuN/iFEHEE5Zmn26TfTxcAjHjRIiA6G/aM9umSbeCX6CdBqQ25i/5scRW8H5O3/px8Bt
         gPGbj+hmq5IXxoGAZc6gyeRbYj0o980rXB1q4pVpE1nTPCfC+65mQxpqWWW7e1cuGx3P
         n05Hb2R+EarfMsyzCpcRhUuGq6OtMDSXaZ/+bl0F7PhA8E38pFLwsREVMysX4MHy43FF
         D+iYBUxqWr8hx04LAzCs+SPsl/XyiZIn0V60jtb+nwqq07nlB7RDlpzQ/n1pcW+/aOxk
         d8PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=akxBw8gEREuaBtxzA9qIYFhL4FrjZkaJp5ikMOEw/lQ=;
        b=ee5zTYDLq5bGbJkpI8zNsATTRq04F9TVBYj706XDlxgiZvkQD1DljMImP2UZen2Cje
         0DezpUsOx/8liU72ALpwgTS0yny/Bd22BYfHtPEG+qhoyWqxMTIe732p4alX5EGyBk4d
         QJ6XaN9gpvrFmrQxdxHIWSJy2XFjk/Yif5vwbczJx9OinoWjViuuETMvNocpjA4QFZX+
         SHEsENKFGTApPSSdZcmOPT4O/usXA4RsStBwuhjWYWDwOz+yUgqqG+qdtF8Tjs1BQKQ8
         5L8hE4VPU1tYrP9BuLt7oF1RgyMt6wVrEKdhSW44Ay1tJR0rzJ+tIKg7/o0ReBRlmxyP
         zzHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eFVXlBPl;
       spf=pass (google.com: domain of 3u_83zaykcciotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3u_83ZAYKCcIotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id o8-20020a655bc8000000b005139eace2e5si86296pgr.4.2023.04.13.06.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 06:12:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3u_83zaykcciotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-54faf2e22afso41179957b3.7
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 06:12:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:eb2b:4d7d:1d7f:9316])
 (user=glider job=sendgmr) by 2002:a81:4319:0:b0:545:62cb:3bcf with SMTP id
 q25-20020a814319000000b0054562cb3bcfmr1362388ywa.2.1681391547580; Thu, 13 Apr
 2023 06:12:27 -0700 (PDT)
Date: Thu, 13 Apr 2023 15:12:20 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230413131223.4135168-1-glider@google.com>
Subject: [PATCH v2 1/4] mm: kmsan: handle alloc failures in kmsan_vmap_pages_range_noflush()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, 
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=eFVXlBPl;       spf=pass
 (google.com: domain of 3u_83zaykcciotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3u_83ZAYKCcIotqlmzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

As reported by Dipanjan Das, when KMSAN is used together with kernel
fault injection (or, generally, even without the latter), calls to
kcalloc() or __vmap_pages_range_noflush() may fail, leaving the
metadata mappings for the virtual mapping in an inconsistent state.
When these metadata mappings are accessed later, the kernel crashes.

To address the problem, we return a non-zero error code from
kmsan_vmap_pages_range_noflush() in the case of any allocation/mapping
failure inside it, and make vmap_pages_range_noflush() return an error
if KMSAN fails to allocate the metadata.

This patch also removes KMSAN_WARN_ON() from vmap_pages_range_noflush(),
as these allocation failures are not fatal anymore.

Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- return 0 from the inline version of kmsan_vmap_pages_range_noflush()
    (spotted by kernel test robot <lkp@intel.com>)
---
 include/linux/kmsan.h | 20 +++++++++++---------
 mm/kmsan/shadow.c     | 27 ++++++++++++++++++---------
 mm/vmalloc.c          |  6 +++++-
 3 files changed, 34 insertions(+), 19 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e38ae3c346184..c7ff3aefc5a13 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -134,11 +134,12 @@ void kmsan_kfree_large(const void *ptr);
  * @page_shift:	page_shift passed to vmap_range_noflush().
  *
  * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
- * vmalloc metadata address range.
+ * vmalloc metadata address range. Returns 0 on success, callers must check
+ * for non-zero return value.
  */
-void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
-				    pgprot_t prot, struct page **pages,
-				    unsigned int page_shift);
+int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
+				   pgprot_t prot, struct page **pages,
+				   unsigned int page_shift);
 
 /**
  * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
@@ -281,12 +282,13 @@ static inline void kmsan_kfree_large(const void *ptr)
 {
 }
 
-static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
-						  unsigned long end,
-						  pgprot_t prot,
-						  struct page **pages,
-						  unsigned int page_shift)
+static inline int kmsan_vmap_pages_range_noflush(unsigned long start,
+						 unsigned long end,
+						 pgprot_t prot,
+						 struct page **pages,
+						 unsigned int page_shift)
 {
+	return 0;
 }
 
 static inline void kmsan_vunmap_range_noflush(unsigned long start,
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index a787c04e9583c..b8bb95eea5e3d 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -216,27 +216,29 @@ void kmsan_free_page(struct page *page, unsigned int order)
 	kmsan_leave_runtime();
 }
 
-void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
-				    pgprot_t prot, struct page **pages,
-				    unsigned int page_shift)
+int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
+				   pgprot_t prot, struct page **pages,
+				   unsigned int page_shift)
 {
 	unsigned long shadow_start, origin_start, shadow_end, origin_end;
 	struct page **s_pages, **o_pages;
-	int nr, mapped;
+	int nr, mapped, err = 0;
 
 	if (!kmsan_enabled)
-		return;
+		return 0;
 
 	shadow_start = vmalloc_meta((void *)start, KMSAN_META_SHADOW);
 	shadow_end = vmalloc_meta((void *)end, KMSAN_META_SHADOW);
 	if (!shadow_start)
-		return;
+		return 0;
 
 	nr = (end - start) / PAGE_SIZE;
 	s_pages = kcalloc(nr, sizeof(*s_pages), GFP_KERNEL);
 	o_pages = kcalloc(nr, sizeof(*o_pages), GFP_KERNEL);
-	if (!s_pages || !o_pages)
+	if (!s_pages || !o_pages) {
+		err = -ENOMEM;
 		goto ret;
+	}
 	for (int i = 0; i < nr; i++) {
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
@@ -249,10 +251,16 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 	kmsan_enter_runtime();
 	mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
 					    s_pages, page_shift);
-	KMSAN_WARN_ON(mapped);
+	if (mapped) {
+		err = mapped;
+		goto ret;
+	}
 	mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
 					    o_pages, page_shift);
-	KMSAN_WARN_ON(mapped);
+	if (mapped) {
+		err = mapped;
+		goto ret;
+	}
 	kmsan_leave_runtime();
 	flush_tlb_kernel_range(shadow_start, shadow_end);
 	flush_tlb_kernel_range(origin_start, origin_end);
@@ -262,6 +270,7 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 ret:
 	kfree(s_pages);
 	kfree(o_pages);
+	return err;
 }
 
 /* Allocate metadata for pages allocated at boot time. */
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a50072066221a..1355d95cce1ca 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -605,7 +605,11 @@ int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 		pgprot_t prot, struct page **pages, unsigned int page_shift)
 {
-	kmsan_vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
+	int ret = kmsan_vmap_pages_range_noflush(addr, end, prot, pages,
+						 page_shift);
+
+	if (ret)
+		return ret;
 	return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
 }
 
-- 
2.40.0.577.gac1e443424-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413131223.4135168-1-glider%40google.com.
