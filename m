Return-Path: <kasan-dev+bncBDUNBGN3R4KRBCVAV2PAMGQE74DLODI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id C0B476764DB
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:07 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-4fee82718afsf40981377b3.5
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285066; cv=pass;
        d=google.com; s=arc-20160816;
        b=NvLcZK+/5nV3bMT9vIViVcA94V2MnnPyJY3nFNr22T33uxYl9e/q/5dSDXU01lleor
         r1K7/29wnLqx+9QKFjQQzueS+8+O0qpufCw1z0wRmXarN4ILL4nqIP94cjWFUu3W/FjF
         P4zcwITZaMo3KOARc+C/lJJqBmjRpgH18k2J1qJ27rqpHldV6UaS98vliFvLN530yskl
         a6EyGOGIjO0j0e73+saLhEuB5rGW/2K0kj3Ni4OETEi8I8JuoFqIta7WQU4OTu3aifYj
         JXecl0npnaonUmXw6+ZFlHdo1C4gOQP81E4OpQAG8nyPnEO5rLLodcHY+uzkScw+x1Sz
         z5wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tk3wdqmSWOdChyN1youK73LK5gtUZmSfwQVEQTqD3mk=;
        b=jAWBcr3H93WXGtMtWu1NbES79RdsCh9TJHUhh0wSnRZEQe8AzJcGzDHe3gFNnCFo1s
         1LXEqs3slkWIiun3tmGLhk3hTuwHqwQ/aqLw4ZGlv7tlHNZo1RlGHlnXKJrx0snT/+Qv
         TzEk00PITpasrjLLFKgcu4PBx6h06IzrPIOZDwR9hkswy0aJ7+YPU/p49QiyFffk1qz1
         rS4MuES8OphIWSw5pld6x/ddpda2yOq73QRPEAfeoU9qkmOpWH5phfk//t2eDJxxNN1+
         /zraFoZKULnxmYHDafa87fb6QdfxoZmFgejrxG9aHVHA9PlE6yOIcWY4EF3dWzlG+zZb
         ziqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=BhY3pELB;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tk3wdqmSWOdChyN1youK73LK5gtUZmSfwQVEQTqD3mk=;
        b=RYhJNHhgoUF8oN053HrnJSHGEb0OGhlh9HyMF7A50kQIyxSXtw6o9dAFndI2L4w3Rb
         l/C5nUv/9AKeA5gB2/0qa2ihFNP/yvLLHHvHKOqeKZ60m+HpJfE6fm3tpThhCl1A1uSS
         DmCPtJmBwAoBlhykAQbzbBj445zxUilhqwNDA0HcVIYeJcDzJefxxIWf5k8vxptTfN0/
         AuBi3LH5IcO9TC8Z9VDxYl4Jkl05nfvUDfijl4GjLNcnwMtIxhgMNcwb89yW5gxiAckf
         NhnSmXDjuUOa1Y9Hf9lts3p/zt2GjFgE+qV5i29XnAYvdvpXpetvkjGM5hk85ApOz+ic
         lqnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tk3wdqmSWOdChyN1youK73LK5gtUZmSfwQVEQTqD3mk=;
        b=cv+kwnni6UOWb4DVJ+Wxp8cfaMvNb3dArqmPFqNbZk8GgDaDbAVvYP5JSOSmmBC+Wh
         44Z5/yHIXOwGkL4K0qDnsjrln/szFaXLPxsl+LaOCgGomtR9/D4VsfQSuJG6z9tAwOv+
         h/L7cVM4eeAqdUAlUeY8sbU5NfUILaaiYCHrdqhkCeZKqdHafPP0AUCIJytjtfmnLlq0
         +Y4OFJiAUEI92tsnQpUagfjQ4PHXnOXg/GToIrycB3hxv95HWWU9zSYnuy8tu4yKIpig
         66EE1USr5GOgm7TyjTaw27r1ULj/MGN4dUByFVfZm4UP6F/g2WAlVVuGrYPTKRBsfDtB
         i8gQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpxBbV4R3XE9WmvXLife0awGI3QMOLhff4FeNk1pyqRLltbtBaa
	gBRJZ2Vv/l+feyYymW6U7B0=
X-Google-Smtp-Source: AMrXdXuDrn8EwtTWZw3cjgCj/X5trb2b3mZfJm3HkVxyUOpNrJ/9E5lV2JoZfV/P2nIux9H+YaeYqw==
X-Received: by 2002:a81:194e:0:b0:4bd:eb1b:b640 with SMTP id 75-20020a81194e000000b004bdeb1bb640mr2233813ywz.324.1674285066633;
        Fri, 20 Jan 2023 23:11:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:b306:0:b0:500:9587:2b0d with SMTP id r6-20020a81b306000000b0050095872b0dls1828286ywh.7.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:06 -0800 (PST)
X-Received: by 2002:a81:cd6:0:b0:4b2:b15e:265a with SMTP id 205-20020a810cd6000000b004b2b15e265amr12951041ywm.30.1674285066076;
        Fri, 20 Jan 2023 23:11:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285066; cv=none;
        d=google.com; s=arc-20160816;
        b=U1/EYIO4SyLJon33bbb3YwKxoShPH4roVwGhax3Y1dWgrmkW/PDOxCxQRWpNSYqlHe
         gsw8ndvSntrWp2RGN7FicjAMb4Es8AThsNCC9m8CcXpWBRzjT2hKEu1jI85fCqHAXQAO
         1cigQBl86bH3hCV208+DqMjI4yg8DRmhSRPWOYTU+z+d5EHwr1n6XK0KiIDv2JONMIjA
         YwFvmrnJWnw8tZHETFQ83JMCE142brXwRpXrSVsP82Zo2zB1cP8Q7Hq1gt4eofkJ7LwD
         jILwyCowYtc1rTDe9L7su/+dmLHk9dwOpMb5MkKwzyIMIflfEecC+1CVSQfL1+541FMf
         iqJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eBVOWMkt3qqfmS1eY0rzR8noKiZ5EvmTGPqU8LqtGbE=;
        b=PDJHXPBuklsOuHOo1qvlZjfjBrWLqJJhASXKOwH9qyRKzErYl/DlYfi7m+xgZoUoAF
         wYtEnRavvngf8qOcTFJKqAVa3ikwfG1DTMF0ImCFgnIaKkPbVkE62SNc/XWoGdgeBqTp
         y5nbT45fmKNBzgh4g2rHfnrhkQCd1Rt5rUiZhInwjHovWYS5Rmp97HJbdgNTztR+koKo
         PrrVxJPS4Ih/2Y/2X0llm6azJQbewSKdzb3mMZfhi3wV3+kVNEDmSWLMBRDdNEjvjVu0
         Skix4nyjHaPzlxf0e3Izljwy4Kq2DY4wn2qotoruLJ9UQtr6ZGNA+1U7uqJkq7HxYKmF
         Yv6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=BhY3pELB;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id n126-20020a0de484000000b004e0c0549c53si1393445ywe.2.2023.01.20.23.11.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:06 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81l-00DTnB-Jz; Sat, 21 Jan 2023 07:11:02 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 03/10] mm: remove __vfree_deferred
Date: Sat, 21 Jan 2023 08:10:44 +0100
Message-Id: <20230121071051.1143058-4-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=BhY3pELB;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
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

Fold __vfree_deferred into vfree_atomic, and call vfree_atomic early on
from vfree if called from interrupt context so that the extra low-level
helper can be avoided.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 43 +++++++++++++++++--------------------------
 1 file changed, 17 insertions(+), 26 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index b989828b45109a..fafb6227f4428f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2769,20 +2769,6 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	kfree(area);
 }
 
-static inline void __vfree_deferred(const void *addr)
-{
-	/*
-	 * Use raw_cpu_ptr() because this can be called from preemptible
-	 * context. Preemption is absolutely fine here, because the llist_add()
-	 * implementation is lockless, so it works even if we are adding to
-	 * another cpu's list. schedule_work() should be fine with this too.
-	 */
-	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);
-
-	if (llist_add((struct llist_node *)addr, &p->list))
-		schedule_work(&p->wq);
-}
-
 /**
  * vfree_atomic - release memory allocated by vmalloc()
  * @addr:	  memory base address
@@ -2792,13 +2778,19 @@ static inline void __vfree_deferred(const void *addr)
  */
 void vfree_atomic(const void *addr)
 {
-	BUG_ON(in_nmi());
+	struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);
 
+	BUG_ON(in_nmi());
 	kmemleak_free(addr);
 
-	if (!addr)
-		return;
-	__vfree_deferred(addr);
+	/*
+	 * Use raw_cpu_ptr() because this can be called from preemptible
+	 * context. Preemption is absolutely fine here, because the llist_add()
+	 * implementation is lockless, so it works even if we are adding to
+	 * another cpu's list. schedule_work() should be fine with this too.
+	 */
+	if (addr && llist_add((struct llist_node *)addr, &p->list))
+		schedule_work(&p->wq);
 }
 
 /**
@@ -2820,17 +2812,16 @@ void vfree_atomic(const void *addr)
  */
 void vfree(const void *addr)
 {
-	BUG_ON(in_nmi());
+	if (unlikely(in_interrupt())) {
+		vfree_atomic(addr);
+		return;
+	}
 
+	BUG_ON(in_nmi());
 	kmemleak_free(addr);
+	might_sleep();
 
-	might_sleep_if(!in_interrupt());
-
-	if (!addr)
-		return;
-	if (unlikely(in_interrupt()))
-		__vfree_deferred(addr);
-	else
+	if (addr)
 		__vunmap(addr, 1);
 }
 EXPORT_SYMBOL(vfree);
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-4-hch%40lst.de.
