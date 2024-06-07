Return-Path: <kasan-dev+bncBC32535MUICBBZE4ROZQMGQEENGNO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E6A58FFEDE
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2024 11:09:59 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-dfa7843b501sf3198388276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2024 02:09:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717751398; cv=pass;
        d=google.com; s=arc-20160816;
        b=GzItIzbvAzAIRkXo7et5298PxC3hPu3oFzc3O26J4hNMn2N+9/xluOHKTM4TaAecVb
         zioTSXfqYMk65fHKgw7AQiAQue1/EBFikl6wKeen+2X8na8kkSRLYzzNk1T0GJbotH2z
         uuzcw+gQiXce+EwBTQO08matoYrUdnMJS9ypoN/J9M84eis+PehOkAbQ3Rxbk/1mZJDp
         quzBNyBEcyfz0fwc+oc3Clvz2PstgXIxdUFjSNdqvSMIT3mlerJOZ6N2OWvtq7mshrGX
         IxswR+zHZMwrrRg2FziYRicAygzb1ChOwFhKH8HmUKTUzI3gjFIkUdvKKwwRS4SS5x0Y
         EeUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vkesLMaqTzgCDPLoZDBIP1hdFOYk4cRuxow+U41Ka10=;
        fh=k4vu0X+eCsIqqXDBXIcA3ETW9al8DSV57L5CegJoUzQ=;
        b=apilGhN1zEsXmWyEQ+xGLB8Dsmca5vvxxsDQ5PwnlGhHvi+5dnXVD6uoinxMkYoSvC
         cpox5xaTbAEM2os6Y9WtYaJ2ScdHQcSlcTFNLMdAiVuEYj5hQf3AcyZ+BlOXhrF88SJN
         nyN5YUm8GNFwDRhh8mu5H7oRCt/xzY5oUIJx8jMam4npBkmU2cD3oL/nCuO2PC92Z1jc
         A/lLAic9Bt3NezpAPN7CQQvUXB9jMHajzhGQ4LjImeLmMwu0TAlul0OGP0qFK2V8oTiB
         qHHLUzIOU46bCLMiwjJCwz1wIkVBGtculz3VbYUOoHJNKWQMt2L83QE7vxD9zunIQEwJ
         PAJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QD+SPR3S;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717751398; x=1718356198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vkesLMaqTzgCDPLoZDBIP1hdFOYk4cRuxow+U41Ka10=;
        b=ZnfiqlaEbSpdNcT4WZ5Xxgze4zdmQxFFjkjOS3PVMzYHsLXYb+nALlJ8P8XSFRnWHn
         ZIL3290hk6q5iz56Y3ffue5YaEmdiTlBX1X0a3p+fVqcKPDnhIKT+9QvEgKW3q1RjlMp
         OzrmbfEigw0Jg4PVpuk46GOA7HjgSI46R/01LHodvEwcfjyo03CMdVj2d9OVGy3af1oN
         0c7Onl6t271mp91OdpPcUhacVUrYlC2bHMByje2LTU1HQVT1MdlTwM36dfVjxXMmdOfd
         DG6pAW7zSwDLfweEWQhAPZmnhZr6aw/oMoOg87DKV2+yHXj53jVwbRyRzRXmB0zmbsiM
         7s1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717751398; x=1718356198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vkesLMaqTzgCDPLoZDBIP1hdFOYk4cRuxow+U41Ka10=;
        b=F2xI53PjMA3F5e6gUfhmzzvk8A0Q6t/V3YNwGucFc59w+9J1nq4ihwyakOrObOGmp2
         LVvKrpYAiVY79qAXQ9/GU9wYhfOH0KkwBOzLZRYzoFtpdHFuAFHxBSDyCrqIj6QlxVl/
         c3+g4kBZeUR2c0UKPyG3KHVYrZSeMrinyqgi2R/ycawddv4l+ovZqPy3w4LWd352KjJ2
         uGa+t3ff4skD5/5u+SJQFz67yKBFvW5/Sh6Jw632igU8y6lwzGBSHnwNRkB3OoeKUajX
         /OkADEoz2ccBhQnkKval1BuazneijqzVdihVSh0AhgrbHZyU7E7yKejBJ1bqTQ+YDvyu
         DN+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUV8gsewcHjK/NTvHjTMPXZGL+rZw1ocaEQQ/quPo4SEBGlpzIN+NoMlVXNpyCjxYvS6Po6kg1tt3tfGfbUCpVKX9NeeOSO+g==
X-Gm-Message-State: AOJu0YxoMRL7eI2McbPmA3PAw2ra0lXkFOkjTC1YTbW8Cmyny9GcMs5I
	wcoxOoEKBjgqEq4CGkhebRaqbsZLgfRRHEickNAC83R/O6F11Nvc
X-Google-Smtp-Source: AGHT+IF0S7lTBNQatuDo7QNxiZg6odhlqiBbQPNn8nq4oUjBpzL1EnSr8ml4u2s9WmOZWblQNnn0vQ==
X-Received: by 2002:a25:ec0e:0:b0:de4:738b:c2e4 with SMTP id 3f1490d57ef6-dfaf660af90mr1887626276.28.1717751396418;
        Fri, 07 Jun 2024 02:09:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b214:0:b0:dfa:7b7c:c81 with SMTP id 3f1490d57ef6-dfaf162a978ls1585439276.2.-pod-prod-07-us;
 Fri, 07 Jun 2024 02:09:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWH6H82eOANtdaLnYjmrrnNIDHfaxOgqN7ne8v6gOImDIVUqu69A43d4US+EWyH7LxTXbnrhQbdU5guOE6EC53tUJavZ4id682nOw==
X-Received: by 2002:a05:690c:732:b0:624:4154:fcf0 with SMTP id 00721157ae682-62cd56614f6mr17509157b3.35.1717751395486;
        Fri, 07 Jun 2024 02:09:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717751395; cv=none;
        d=google.com; s=arc-20160816;
        b=tbcnCCIVwG+RM4ZNGV2V9WfSxfZGhZ3vPy/hQwyQpiDsVGePPm9RNIyoAvEg8ZPUwR
         if7dyUEr4jlxCZ2VyxtbV+VzRYEzy1c1vjpEQohe5Xez6IPlZC5WogKGv/surbrQdyRA
         fL+f9z1qZgxNoEEvKuo6Truwb1az81PDUZMx3+DCkxcxOr5RTWs5mMuVYnar4awMiUr5
         82mxgYmFZe1X8juLhcLpV8QtdZN58xDqiVxBob5Pjc3BnKUIzYXZVsjiBDN/hbcPVm6L
         MhxLx7F4WV2JXNq4yrFPrXqhLgLfUBy/DaImkn2tp8kkdJ3k7PHSKB9hABCakKo8uumY
         t9mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kiFnKpy9jAQsfmTIBaaW+Ib0u1X/H+DkqsqDykpaDbc=;
        fh=8obm1S+EgOJGM37d32V0lIxEEqS6t/kRT3OFvw5SNhc=;
        b=AMfc+7hibQh8NG/i7T36JJ/4VRPiuETuCsOraXco+CdvI9UmeyqOc/cCY1a83p3l2z
         iPaX2zyGYwUL+oGlYW4iJyepQzjowsJ/Ndk7yOTxOUWvPimn79/6jiKOgxAErr+oCymN
         yV4C77OMGuPMi8xGXlMBUF2rxpS+1l6zyUooB/dpu6nue3TxNG+YQycqHDKPxo3Dpmvy
         XSMy+gS8G3CdhN7o/zT5GkPclHKY0eh+b/YF4lzWUF7g28YaHgjluqPMdIzkgzlYpJr5
         yQYrNL/d9IBtMOLE1Tk3yLggDxSKnltHMUyyaW/VfqvMHQoRRPq5ixk0fdzMGgPwIXo7
         3NOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QD+SPR3S;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-62ccaeb9496si2670267b3.3.2024.06.07.02.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Jun 2024 02:09:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-94-siZVc8J6MdebVKtoCSUwSQ-1; Fri,
 07 Jun 2024 05:09:51 -0400
X-MC-Unique: siZVc8J6MdebVKtoCSUwSQ-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id C59D31C05190;
	Fri,  7 Jun 2024 09:09:50 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.39.194.94])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 44DB337E7;
	Fri,  7 Jun 2024 09:09:46 +0000 (UTC)
From: David Hildenbrand <david@redhat.com>
To: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org,
	linux-hyperv@vger.kernel.org,
	virtualization@lists.linux.dev,
	xen-devel@lists.xenproject.org,
	kasan-dev@googlegroups.com,
	David Hildenbrand <david@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Oscar Salvador <osalvador@suse.de>,
	"K. Y. Srinivasan" <kys@microsoft.com>,
	Haiyang Zhang <haiyangz@microsoft.com>,
	Wei Liu <wei.liu@kernel.org>,
	Dexuan Cui <decui@microsoft.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Juergen Gross <jgross@suse.com>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
Date: Fri,  7 Jun 2024 11:09:36 +0200
Message-ID: <20240607090939.89524-2-david@redhat.com>
In-Reply-To: <20240607090939.89524-1-david@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QD+SPR3S;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

In preparation for further changes, let's teach __free_pages_core()
about the differences of memory hotplug handling.

Move the memory hotplug specific handling from generic_online_page() to
__free_pages_core(), use adjust_managed_page_count() on the memory
hotplug path, and spell out why memory freed via memblock
cannot currently use adjust_managed_page_count().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/internal.h       |  3 ++-
 mm/kmsan/init.c     |  2 +-
 mm/memory_hotplug.c |  9 +--------
 mm/mm_init.c        |  4 ++--
 mm/page_alloc.c     | 17 +++++++++++++++--
 5 files changed, 21 insertions(+), 14 deletions(-)

diff --git a/mm/internal.h b/mm/internal.h
index 12e95fdf61e90..3fdee779205ab 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -604,7 +604,8 @@ extern void __putback_isolated_page(struct page *page, unsigned int order,
 				    int mt);
 extern void memblock_free_pages(struct page *page, unsigned long pfn,
 					unsigned int order);
-extern void __free_pages_core(struct page *page, unsigned int order);
+extern void __free_pages_core(struct page *page, unsigned int order,
+		enum meminit_context);
 
 /*
  * This will have no effect, other than possibly generating a warning, if the
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 3ac3b8921d36f..ca79636f858e5 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -172,7 +172,7 @@ static void do_collection(void)
 		shadow = smallstack_pop(&collect);
 		origin = smallstack_pop(&collect);
 		kmsan_setup_meta(page, shadow, origin, collect.order);
-		__free_pages_core(page, collect.order);
+		__free_pages_core(page, collect.order, MEMINIT_EARLY);
 	}
 }
 
diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
index 171ad975c7cfd..27e3be75edcf7 100644
--- a/mm/memory_hotplug.c
+++ b/mm/memory_hotplug.c
@@ -630,14 +630,7 @@ EXPORT_SYMBOL_GPL(restore_online_page_callback);
 
 void generic_online_page(struct page *page, unsigned int order)
 {
-	/*
-	 * Freeing the page with debug_pagealloc enabled will try to unmap it,
-	 * so we should map it first. This is better than introducing a special
-	 * case in page freeing fast path.
-	 */
-	debug_pagealloc_map_pages(page, 1 << order);
-	__free_pages_core(page, order);
-	totalram_pages_add(1UL << order);
+	__free_pages_core(page, order, MEMINIT_HOTPLUG);
 }
 EXPORT_SYMBOL_GPL(generic_online_page);
 
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 019193b0d8703..feb5b6e8c8875 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1938,7 +1938,7 @@ static void __init deferred_free_range(unsigned long pfn,
 	for (i = 0; i < nr_pages; i++, page++, pfn++) {
 		if (pageblock_aligned(pfn))
 			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
-		__free_pages_core(page, 0);
+		__free_pages_core(page, 0, MEMINIT_EARLY);
 	}
 }
 
@@ -2513,7 +2513,7 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
 		}
 	}
 
-	__free_pages_core(page, order);
+	__free_pages_core(page, order, MEMINIT_EARLY);
 }
 
 DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2224965ada468..e0c8a8354be36 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1214,7 +1214,8 @@ static void __free_pages_ok(struct page *page, unsigned int order,
 	__count_vm_events(PGFREE, 1 << order);
 }
 
-void __free_pages_core(struct page *page, unsigned int order)
+void __free_pages_core(struct page *page, unsigned int order,
+		enum meminit_context context)
 {
 	unsigned int nr_pages = 1 << order;
 	struct page *p = page;
@@ -1234,7 +1235,19 @@ void __free_pages_core(struct page *page, unsigned int order)
 	__ClearPageReserved(p);
 	set_page_count(p, 0);
 
-	atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
+	if (IS_ENABLED(CONFIG_MEMORY_HOTPLUG) &&
+	    unlikely(context == MEMINIT_HOTPLUG)) {
+		/*
+		 * Freeing the page with debug_pagealloc enabled will try to
+		 * unmap it; some archs don't like double-unmappings, so
+		 * map it first.
+		 */
+		debug_pagealloc_map_pages(page, nr_pages);
+		adjust_managed_page_count(page, nr_pages);
+	} else {
+		/* memblock adjusts totalram_pages() ahead of time. */
+		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
+	}
 
 	if (page_contains_unaccepted(page, order)) {
 		if (order == MAX_PAGE_ORDER && __free_unaccepted(page))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240607090939.89524-2-david%40redhat.com.
