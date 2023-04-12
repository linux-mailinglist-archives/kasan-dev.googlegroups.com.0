Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUML3OQQMGQEIY6WWPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E61A6DF906
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 16:53:07 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id k12-20020a67c28c000000b0042c6ab80f1dsf2588517vsj.14
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 07:53:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681311186; cv=pass;
        d=google.com; s=arc-20160816;
        b=TlLHrGP7AtcPulKH0hAbD1uBPnwM46m8Zt6QJe+mmoWjepKgPolOHK5KQRNHdMQtSQ
         RnxRtZXXa3uY7Z+5TNGfkFDuCmUN3SwiOO34GA3v8CQJ1MBX25XADCNtCGScBbo8mwFD
         4w4btBqI/JDa3DEFtxLu4mopOxf9Kii7pWVcDuT9PZ7JbBg6GwqhvAPCfEAi67+84BXb
         xst3tnzad0/zru9J7TfPNsIrllpB6dMC3WpZs7yts0UhKgu23k4XiP2Fgch/p0ZEmYbK
         ytCZgGTV695bfmDwDshXg5XBIeeG7OOj9sa1McC6l040ZTGC2tpEvgEjsm+WX+3PH3CS
         u/CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=smDoaunM3eiuy+FrWBWOALeQBgDuf4CikwqtajhL5Ss=;
        b=MQl5kd/9yP2LaQtaGCk74emY0vzMIchjHFt7kQF7wgNVPEV+ojx5NFMZo2gj4q23An
         qfndxxfcb9Lqbs3M4Bj/06xhQ3No8K/JpGM5LILY3+7hLqnrDyMsphaSY8ajtJB5YJUA
         fWw3lvUiazirAHdyD60vW7gdaZGW8bBPGOUS4jZdol6cC/x+Kw6ZIeiC7vZTlgWDnbK+
         RnMQtdGX7NjK2IEihKIEkIzTASrt8zCxbZsFBFYmQ9aGpYR1aLaB/8nL0nejbqddbclw
         ddm/Nwv7Vjx8u6h9wUExPNZJ8UxlwGFpEG/Jr0DLmysjyEb/4EZLOJrnyyx7ffkgSZ/I
         +WEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=BGJ19UUT;
       spf=pass (google.com: domain of 30mu2zaykcv8difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=30MU2ZAYKCV8DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681311186; x=1683903186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=smDoaunM3eiuy+FrWBWOALeQBgDuf4CikwqtajhL5Ss=;
        b=GKvM93XLITFDtz+wOLyAQeNOQ3OoX098JwJbAOn3vjfQ346uXpx+ybEe7mEKGkBGXq
         T22wh4lXSbdUvu8TgOfWLfewyqm6kNCmeZu+3awpiEUfp/AkVWdinIz6ndFu6hs8fXI6
         ue4bTAB2IBhoh8Dp249P2Ys81QLn8AiHV70JX1AntK1QTJh+4lb3mL2DSLEZ5V+2YjMq
         p0CRmKxF3fPKlr8jSY+hit54KT/OUBxk7wk1ysM435wcXMs9rehlXTXfwXDxq5rYJYWm
         u+1Bfmw9xFooso0ANGjlcuJ+TvWLeAS1vvMlCxMYjlgt2MQXpRyelyZ3NHZiZBFYkVwL
         4XhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1681311186; x=1683903186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=smDoaunM3eiuy+FrWBWOALeQBgDuf4CikwqtajhL5Ss=;
        b=PMfORqBGJIftGoi2iwMzB/dRf9kSiYe2EFC9RQcVXpdUmfSOV3NMtURkF9iRRA5W9y
         +8HTEMgv9y8Ac5w2Dtae2EGHJbLILFTqsMt00WRvYJMaEvM1BkGVirAZ2ARifAtOYj+z
         XObz8b+g+pMAfsORGVoet4IKUWcQu6Fhi8SiYjE/Qk95uX12zoZHKlznSpyFuF3/YnA5
         +UKAJ0rQbxtA+79qwdGZFFBMs+g5repAZHmcuVMDNIwoLXe3tGUnbXONStU5t6ZxGl2x
         E/bhODVVHId9/zUHuFgst2Lqi3XtJPGiX/VD40bcXU7xt+eu27RxrQFhujPNmh9YrUOy
         GexA==
X-Gm-Message-State: AAQBX9cIRLupxRj9TPGhINuhTi4ijks884tAyw/apjMjLbq1jpQTfCXq
	y8hVM5175ZrGjrqdk3YCACE=
X-Google-Smtp-Source: AKy350Zd3q2Y8GfSe+1FAnLAwSVD1hTVgmUl9bzcgJNPIT/znsnqdJqfUTJbMBmqsGMo/5mq4A/Ziw==
X-Received: by 2002:ab0:5481:0:b0:769:593d:b7ec with SMTP id p1-20020ab05481000000b00769593db7ecmr3949535uaa.2.1681311185645;
        Wed, 12 Apr 2023 07:53:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:f8c5:0:b0:43f:c7ee:63a3 with SMTP id w188-20020a1ff8c5000000b0043fc7ee63a3ls1306959vkh.4.-pod-prod-gmail;
 Wed, 12 Apr 2023 07:53:05 -0700 (PDT)
X-Received: by 2002:a05:6122:2193:b0:43f:e623:952 with SMTP id j19-20020a056122219300b0043fe6230952mr1197795vkd.2.1681311184936;
        Wed, 12 Apr 2023 07:53:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681311184; cv=none;
        d=google.com; s=arc-20160816;
        b=E36OaZDaOJVvFTfabZ1+AO5EHBOwDAy2EPsbjzt8hd7k/nVlLomdK2V/fBV5i+YoG0
         NtYZybNInQvMeuGcami/rzSV17lE3NcHx3nUmXhyh2QkGdKD2NUZdsbFAnFN4bERWaP0
         83YqX9cNTJI+nvyqF9nYtDY213/uaWLpzAKN5sCwkCssQ0/xef8bbf1337r9K80UBrx7
         Grn3P4x4/aoXyjaclj983+D94R/87xod0kJIsmN3SsFQMyfJqGU5/d3LIk6UV1f14BSv
         Y4fow8MByCa2c6JGTNrxExcFNBtPSY6qLLZaSFIQWui/NAWwfDhk9XSQOrdHMK+e3aNz
         9JBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=CwA0wdGrULC2XXBzkQfVWleO9hyls9jS7CAlyZ8lvMo=;
        b=U1maCrFUEnY7d0418KhPPwg81BfLfKMi4TjAT08uK8/fbM/dAkwVrqMDNZ6dQHyRie
         ErWsJJYtBlJYBEMdbryyxaYzvY4/MffiLtX8rns43Jz69MsJcAMkP6yooHxQNNozJbq7
         Xbii1qnoJcmXGjphQhBgjpiFITe6UnvDldVm2RoxOLbRAfRLTvzvrFswcooKWRw+JEpQ
         l8scAeBKsbvbwml8uIfYnsZ9TlTSog2VOh9BA33EzAoFil1cfjLpun3RFtGtDINVhRAv
         1yAgSOMrEBJw9aRlb6yNsy5StGqD1Ut1g+Qi5EalHIH3DgLMf9lqp03H2npOVQu6ACwR
         EmgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=BGJ19UUT;
       spf=pass (google.com: domain of 30mu2zaykcv8difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=30MU2ZAYKCV8DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id j4-20020ac5ccc4000000b0043fa939cd42si939986vkn.0.2023.04.12.07.53.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Apr 2023 07:53:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30mu2zaykcv8difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id c67-20020a254e46000000b00b88f1fd158fso27944853ybb.17
        for <kasan-dev@googlegroups.com>; Wed, 12 Apr 2023 07:53:04 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:901c:7904:40a1:1b6c])
 (user=glider job=sendgmr) by 2002:a25:c905:0:b0:b77:81f:42dc with SMTP id
 z5-20020a25c905000000b00b77081f42dcmr12063363ybf.1.1681311184657; Wed, 12 Apr
 2023 07:53:04 -0700 (PDT)
Date: Wed, 12 Apr 2023 16:52:59 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230412145300.3651840-1-glider@google.com>
Subject: [PATCH 1/2] mm: kmsan: handle alloc failures in kmsan_vmap_pages_range_noflush()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, 
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=BGJ19UUT;       spf=pass
 (google.com: domain of 30mu2zaykcv8difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=30MU2ZAYKCV8DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
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
 include/linux/kmsan.h | 19 ++++++++++---------
 mm/kmsan/shadow.c     | 27 ++++++++++++++++++---------
 mm/vmalloc.c          |  6 +++++-
 3 files changed, 33 insertions(+), 19 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e38ae3c346184..a0769d4aad1c8 100644
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
@@ -281,11 +282,11 @@ static inline void kmsan_kfree_large(const void *ptr)
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
 }
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230412145300.3651840-1-glider%40google.com.
