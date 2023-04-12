Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV4L3OQQMGQE5GDWS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2725F6DF907
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 16:53:12 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id s22-20020a195e16000000b004e9b307b224sf4503620lfb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 07:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681311191; cv=pass;
        d=google.com; s=arc-20160816;
        b=W+vlUIafZv3Q23tj7T8jRio3sQKwqneytke4WHOrNrhE3UDqeOnJUcTjNZ7mAmg9dK
         OBWWrkvKvazfuGC0ng5PrP3K6NPYUoPVWsr6uModvPJT3j5uwd0NWOnkMAbUUasead9v
         J2KmNS3OzBVHd6JtiKC95E2iCu6arvAbkEAGdWU4w/hs7yPSC4ohXI0pBYk5mhYPp63K
         DtKk1e8gEIqn5CVmqDwHy2YaGDUqKIr5Dc+ntJH5rcDa83QvDvHMHOxZf9C9yDNkuSvS
         V12itiQ7hTMWFAtqn/L/Zrs0eKTwtpJOrM9xjZodk67r5l6D6Nxx+gWKUZNHFA6DRBiy
         7xKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TqRRrsySWm/k484Q3fgy6xRdZNMrH2a+f5S1RWSFWgs=;
        b=LkyeGQGD5BgKLZ0DD2453xWMBznERo+wgPF3yAvrl7/b/6BwpMz66AdOLTk9q8FeU2
         mizE+ZoLAkma/XvkayvgCDI9POPCwNBDCzKJS2cKeX7uipQMk+czNcP1v1caN5Co1R7r
         +FkFb1GnFm8Mi2qUtfsiE76VXxkStpbPPv6rQqk5P5SQG1H5Yic+ZGsRVmfDuK3cgqr3
         gocK8MX2BdcENkZDu/MgphCE9XtC+Dha5fqt5p52eRiWbLDRoAvNAz5OwEnLB+mcbdJQ
         3dFJKBeCrte8S1XdpK9gBJhOn0A40EkuGDlgtdQBBJQm/5dIZV9IBnnkslXgRaiqPZw4
         JL5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=utjKfmyg;
       spf=pass (google.com: domain of 31cu2zaykcwqinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31cU2ZAYKCWQINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681311191; x=1683903191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TqRRrsySWm/k484Q3fgy6xRdZNMrH2a+f5S1RWSFWgs=;
        b=c6/22pyTjoR7e+xEuizZoQhnwr1y5JLL5cyiYw0Jxv3ohaeDkpIA2Xa7/9TI1svpXw
         dPPrQ966jdHnZtUMtsxH1Cr7DN859ebd+4QNwoP0cWyS4JdDnB51GPIBiQfTTPVr6TpB
         abO7DPtdXw2+ZqsiXwbtfROIh+K5Bz+bKijvvipDKE8zYTblgijavKAUhD3k8U/VpOKD
         xnSPmAajetXAQ3dFS6LWhTtDdYD5RC7uMGeEOrhT5jVVSvUW2/ZOT2ylnrQROylJrn1A
         P88queqTTQT5V5jy8TkQKEDFtT0FPczl+kuWdxjXIJResLGcVTZn1fulz3AflWzZVvwY
         vHfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1681311191; x=1683903191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TqRRrsySWm/k484Q3fgy6xRdZNMrH2a+f5S1RWSFWgs=;
        b=RkkNU5t2Xzn3QwA8ofoPxq6VJdfElQymN7MntTdWU6s55L0XpvgaMAiGYxbMeFWBVF
         qqWjheEIImLi4d8YTasuF45HLQIk8hDmLUI5LZJKYI47XGuS/TY/f0m3hT4n7b9PXEoq
         Zz07Asfu75pKft7SNsYJbolDd97vv/5oeSVGKhIq/zW5Q5a7LKsuvY5AZsUIQfnrfdDL
         WYIwGCULOhoxytAtNqO7pRmF9vNH65NeU6srEZ5xDxg36jxyQUv7sXPepB1Jm9brrynJ
         eVHchay+KKWgX9rlYzrVciKl92QlY9khB891kltSbJQkMbonE8rj92jf6cDV7CQN/Mfs
         4haw==
X-Gm-Message-State: AAQBX9f3YBLnHOpJwdU7CaLnbeJzbFKibKWl16Tzql4+qnDsKZ+90HkD
	7njRrQx6M/xXjpjBRGwLBck=
X-Google-Smtp-Source: AKy350YhFYuSf+Js4LXrxBLakrzvCc2/zdb7OJm0DMJiLNZDRy661ypXIGHHH3EID88VnL5UvleyHQ==
X-Received: by 2002:a2e:9c91:0:b0:2a7:6bb4:a701 with SMTP id x17-20020a2e9c91000000b002a76bb4a701mr4567089lji.5.1681311191204;
        Wed, 12 Apr 2023 07:53:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4f06:0:b0:4ec:6fe6:9f26 with SMTP id k6-20020ac24f06000000b004ec6fe69f26ls916022lfr.0.-pod-prod-gmail;
 Wed, 12 Apr 2023 07:53:09 -0700 (PDT)
X-Received: by 2002:ac2:5086:0:b0:4df:51a7:a92 with SMTP id f6-20020ac25086000000b004df51a70a92mr3277620lfm.11.1681311189680;
        Wed, 12 Apr 2023 07:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681311189; cv=none;
        d=google.com; s=arc-20160816;
        b=fht4b6hxE0vwWdZg6nhyQ0B15XyeyRnu/9YWEWWnADGMyKlFt/ehccV9dIjKSEjtpT
         McpuHyqkdtT9WKKT0FnZCrs4yXtYhMZAXYdDMj998NIh9ob0qYABQyRymCqv90G8W1RM
         zq71ZYXsqaRRufLi7ODwJH1pP8DR2BNXd0Het3ZCnRtSIWMHB2ItoKd8RBsd188Mooew
         /gG7ZrgQIpCzHORHm9wwqCtKOrfaj9KNJ/cjexNU80FVK9Lk2YMjeb6x2HP9bOCokJYA
         8v0G7MHRSjgz1XOYwAwfqrEhfYytZtj+/x2JtUmoyPFA8njWuHs75aUX5L8k/thgnJ+k
         u7uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GLtuEgzLkzzznhMQcB+RHI4zD53wmkIOG/wGgFhyqPw=;
        b=EY+fFNp1rqV6IP0FNIDdqZb6iL0c31YiH6Kq/u/MMQwUqltMyhRPQOObAsTZ9241fq
         L1Fj8u/FOZNlBiYhbQUTz5X+7N9QlitnhsDf8ralUjrjoW15QB/925qYScj49p7bg9/A
         D5mDP9zGb2BuBFBqGMRX69ELC2pNbYr+00n9N/p7GdYPk6ZrzHLXN4mNeAtv7hv/UDAF
         LxSCrcvPgmKtjGbDdtt3sKxtq0GDchDtm7FPVSe9nRzjZMQkkk09arSesD9duMromlKl
         VCq65QwPkGUGoIALAFcP6oJsrFKRkNaIzL+5dSITSw8jYS9YVJXWIXYZW/nmDkttpmQ0
         fzGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=utjKfmyg;
       spf=pass (google.com: domain of 31cu2zaykcwqinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31cU2ZAYKCWQINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id i3-20020a056512224300b004ec62de2d52si694971lfu.1.2023.04.12.07.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Apr 2023 07:53:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31cu2zaykcwqinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-505149e1a4eso752042a12.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Apr 2023 07:53:09 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:901c:7904:40a1:1b6c])
 (user=glider job=sendgmr) by 2002:a05:6402:550b:b0:4fb:e069:77ac with SMTP id
 fi11-20020a056402550b00b004fbe06977acmr2006910edb.0.1681311189113; Wed, 12
 Apr 2023 07:53:09 -0700 (PDT)
Date: Wed, 12 Apr 2023 16:53:00 +0200
In-Reply-To: <20230412145300.3651840-1-glider@google.com>
Mime-Version: 1.0
References: <20230412145300.3651840-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230412145300.3651840-2-glider@google.com>
Subject: [PATCH 2/2] mm: kmsan: handle alloc failures in kmsan_ioremap_page_range()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, 
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=utjKfmyg;       spf=pass
 (google.com: domain of 31cu2zaykcwqinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31cU2ZAYKCWQINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
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

Similarly to kmsan_vmap_pages_range_noflush(),
kmsan_ioremap_page_range() must also properly handle allocation/mapping
failures. In the case of such, it must clean up the already created
metadata mappings and return an error code, so that the failure can be
propagated to ioremap_page_range().

Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kmsan.h | 18 +++++++--------
 mm/kmsan/hooks.c      | 53 +++++++++++++++++++++++++++++++++++++------
 mm/vmalloc.c          |  4 ++--
 3 files changed, 57 insertions(+), 18 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index a0769d4aad1c8..fa5a4705ea379 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -160,11 +160,12 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
  * @page_shift:	page_shift argument passed to vmap_range_noflush().
  *
  * KMSAN creates new metadata pages for the physical pages mapped into the
- * virtual memory.
+ * virtual memory. Returns 0 on success, callers must check for non-zero return
+ * value.
  */
-void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
-			      phys_addr_t phys_addr, pgprot_t prot,
-			      unsigned int page_shift);
+int kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
+			     phys_addr_t phys_addr, pgprot_t prot,
+			     unsigned int page_shift);
 
 /**
  * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
@@ -295,11 +296,10 @@ static inline void kmsan_vunmap_range_noflush(unsigned long start,
 {
 }
 
-static inline void kmsan_ioremap_page_range(unsigned long start,
-					    unsigned long end,
-					    phys_addr_t phys_addr,
-					    pgprot_t prot,
-					    unsigned int page_shift)
+static inline int kmsan_ioremap_page_range(unsigned long start,
+					   unsigned long end,
+					   phys_addr_t phys_addr, pgprot_t prot,
+					   unsigned int page_shift)
 {
 }
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3807502766a3e..02c17b7cb6ddd 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -148,35 +148,74 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end)
  * into the virtual memory. If those physical pages already had shadow/origin,
  * those are ignored.
  */
-void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
-			      phys_addr_t phys_addr, pgprot_t prot,
-			      unsigned int page_shift)
+int kmsan_ioremap_page_range(unsigned long start, unsigned long end,
+			     phys_addr_t phys_addr, pgprot_t prot,
+			     unsigned int page_shift)
 {
 	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;
 	struct page *shadow, *origin;
 	unsigned long off = 0;
-	int nr;
+	int nr, err = 0, clean = 0, mapped;
 
 	if (!kmsan_enabled || kmsan_in_runtime())
-		return;
+		return 0;
 
 	nr = (end - start) / PAGE_SIZE;
 	kmsan_enter_runtime();
-	for (int i = 0; i < nr; i++, off += PAGE_SIZE) {
+	for (int i = 0; i < nr; i++, off += PAGE_SIZE, clean = i) {
 		shadow = alloc_pages(gfp_mask, 1);
 		origin = alloc_pages(gfp_mask, 1);
-		__vmap_pages_range_noflush(
+		if (!shadow || !origin) {
+			err = -ENOMEM;
+			goto ret;
+		}
+		mapped = __vmap_pages_range_noflush(
 			vmalloc_shadow(start + off),
 			vmalloc_shadow(start + off + PAGE_SIZE), prot, &shadow,
 			PAGE_SHIFT);
+		if (mapped) {
+			err = mapped;
+			goto ret;
+		}
+		shadow = NULL;
 		__vmap_pages_range_noflush(
 			vmalloc_origin(start + off),
 			vmalloc_origin(start + off + PAGE_SIZE), prot, &origin,
 			PAGE_SHIFT);
+		if (mapped) {
+			__vunmap_range_noflush(
+				vmalloc_shadow(start + off),
+				vmalloc_shadow(start + off + PAGE_SIZE));
+			err = mapped;
+			goto ret;
+		}
+		origin = NULL;
+	}
+	/* Page mapping loop finished normally, nothing to clean up. */
+	clean = 0;
+
+ret:
+	if (clean > 0) {
+		/*
+		 * Something went wrong. Clean up shadow/origin pages allocated
+		 * on the last loop iteration, then delete mappings created
+		 * during the previous iterations.
+		 */
+		if (shadow)
+			__free_pages(shadow, 1);
+		if (origin)
+			__free_pages(origin, 1);
+		__vunmap_range_noflush(
+			vmalloc_shadow(start),
+			vmalloc_shadow(start + clean * PAGE_SIZE));
+		__vunmap_range_noflush(
+			vmalloc_origin(start),
+			vmalloc_origin(start + clean * PAGE_SIZE));
 	}
 	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
 	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
 	kmsan_leave_runtime();
+	return err;
 }
 
 void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 1355d95cce1ca..31ff782d368b0 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -313,8 +313,8 @@ int ioremap_page_range(unsigned long addr, unsigned long end,
 				 ioremap_max_page_shift);
 	flush_cache_vmap(addr, end);
 	if (!err)
-		kmsan_ioremap_page_range(addr, end, phys_addr, prot,
-					 ioremap_max_page_shift);
+		err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
+					       ioremap_max_page_shift);
 	return err;
 }
 
-- 
2.40.0.577.gac1e443424-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230412145300.3651840-2-glider%40google.com.
