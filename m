Return-Path: <kasan-dev+bncBC32535MUICBB3M4ROZQMGQEHDOB3AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7C48FFEE1
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2024 11:10:07 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2c2c5ca75a2sf98644a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2024 02:10:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717751406; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/p1zCqzeQ5Ax2Y5YSzXQcI1H/5K4XmeCS349QFLYEnS+CsX1RCfuYQrPO0WJIsStz
         JrkPeO+qAo8pqpVdZ1L/wnsAXREV0P0a3VrcoFNWbHRfOj5Um2MX1LQM2HjAmA5Q9ZrZ
         U101HeNPcvqy94aDjFElRCRpiMthO2RxKHyJZpdkhEi4LKA2TpKTkj4qJLi3ntkOxtd6
         IFg3JLn2XYckbd04wxnS0xwiwCpWyBvs/fpr+aufhMij77keLVrdLFoajhZBw5qPa8UC
         339i5oO9mnZNHz4xll/8QcC0QkeS57RU4IwB18rS7xg8lfA/GEY0l2yi+gLJCpG4iSwt
         ZYYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0sRan8wqaprG6xhA7DErx2+R1gWrv+FeYvVO0umkG2M=;
        fh=1SO/6pYPh0a7t2bWxRr1TG+O+K7w8mUJe57wGhAF+FM=;
        b=CoIqLQZVnkrQUUY1aw/E2S+0aB/Kpef9NCxRXJoOMJ8YAJalpqnzFs1UcwhflLxiYo
         okF9NmsBxLOFsjjG9Uu3xxEAwLmkvlD+9waazN2F7Y01vM1IBdlxdV/c0jDiSOqrURAH
         kfHsXrzP8E20Bh5BnxPB08lMO4Cza9Ef9xZZ+MhI/a+VMa3uIBqHKEzbEKLY0Y2Rab2K
         enUNKdvm+ZwLCXrS9nKoKJpqQCOUuxIJtSQEXS9vR8kiV2dUH6OCrtrReiWfICnTUBCb
         6t9iv+qNwPZomVyRmcn9n702VCCjgOrlwl7hVuwWj1B3fV0I6PzDkz01bKoXDTGjllnA
         WrZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=btYDeHpJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717751406; x=1718356206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0sRan8wqaprG6xhA7DErx2+R1gWrv+FeYvVO0umkG2M=;
        b=D0EVSkGt3lU1VAFVh+edUXHLJYnTw3y6f/u/kX5YICtVMzzKHMJm/1+Hfeem4qApl8
         BlCSbpJd4dD+5lB01guYK8GpbpaUmcneaUOkcB06SgigO1qnT7HS9rkg9qC7Pjx1nYaS
         3tv9w7FJbDr+/QxIg0aPbJV9aNu6otrn5LvIw2r+zOl3ur7CfTY25MpsYEaWx5bp+E40
         a2lytBOhSGEPttUJVStmZ5gjxlyzdJEQJccxrBuSG8j2RCvu9Jf9j60HUH4cTiKU1gxW
         QrvRt801t4Xsb6Q7J6ZY6w45rpUOsqc003qvrLz31mW7QyU2jLkpm3E+FbL1xGXRnC+D
         UB5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717751406; x=1718356206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0sRan8wqaprG6xhA7DErx2+R1gWrv+FeYvVO0umkG2M=;
        b=bqQ6/skzbG8ILoXH4/awwRBTEUe6y0ogfzFGpau9tic/cZoQr3aO3PaFqBFwdMKRtx
         AAJ9P1xm3p8J3YN2X++xTk178fwJGI5GoQjkKisfx/gJ+UL5hixnoW39aRhyn/pxUnKB
         NCb3+No3M65m6s3PDTKbPMCK/caZ5K5WciqRCjsa5q69fWm2alpDG62k48RSk+UanUTE
         HDAcua+/l1gf80qFjyPpuKaj9E/edAAwEK+YCAgMkVfnQjHyLkJlqQxpImoX8DFrOZQq
         bVzhhSOgwRQ2CvIH+D6WwyQQspAS33dCWHyIemOeDcOMZFb9tKms923yn1kd5pVZ36n2
         as/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjumyc7RJTvI6leyX35QP8oi0jGUDynU02Dkf36g6ORC8k9ga9CJ4VKAmWMRZmaMXfV5NNsEJW6f2EGRtWfPwjk5dkvzQkNg==
X-Gm-Message-State: AOJu0YzP8D6noXOb+izneE289hauk5RIrDsHC5005xm8vhiZqARQlo7Q
	v10a8A597ElO/eG+k7e/MRt/cw8glQ5Dh/S5UH80/o11rW1lHkNG
X-Google-Smtp-Source: AGHT+IHbhd6aOJ5dQDHrArtixW3OCeVIWJ6drpuKPe4BRTxKalaSpMiSaSBpHT1VPJ1vNDBcap80VQ==
X-Received: by 2002:a17:903:32d2:b0:1f5:e635:21e9 with SMTP id d9443c01a7336-1f6d02e48a5mr22331885ad.2.1717751405385;
        Fri, 07 Jun 2024 02:10:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5c5:b0:1f2:f6e6:a0a4 with SMTP id
 d9443c01a7336-1f6cc41f168ls7407445ad.1.-pod-prod-04-us; Fri, 07 Jun 2024
 02:10:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXV+qL5Kg4ZNDUL9ZMKIwoFY4GIbJXgAGLJEMKXZ7OiTiVvSTa2PzsCDtpbRMuVzIEcwBzwIMe+5IIQiiCIA18A9lrrh10Nk1HDLg==
X-Received: by 2002:a17:902:dac3:b0:1f6:30e8:aae5 with SMTP id d9443c01a7336-1f6d02c06damr24592525ad.4.1717751403938;
        Fri, 07 Jun 2024 02:10:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717751403; cv=none;
        d=google.com; s=arc-20160816;
        b=MCMRn3rDtQv4hYSSX/XVoaTh5ZHIRu3sGH6t8SUjh3xc7K/Bz6jdr5be9VNftGTEyc
         NXGa4i5q8313HzEPu6YWwJES88mhKojLOYieQmDavUIUGT0VLCQsbLqqB+oURulGDK+g
         iYuqnD948NDpPkvI9a1EpK9D+7iSP2sdicx/+AEE3B5cYgot0Jl0TG+HnujsjXD3sXin
         msLU95ZTOv8nXzNfdd9/cDiHS7nPWFoF7ZaGKOKiB4/AMfLJo0xSYpG7Ahfsm30gw4Xp
         wZZvZbBFeGB3bIJskagxLO+jkVdkgn0OhyDEccW4XgSXNcwMvMNdLAsTMyrVTioCo8mX
         39OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mc4++sRx3ukGDekZxB1N0n7JzUxaxxhg3TlGVFiWWaQ=;
        fh=8obm1S+EgOJGM37d32V0lIxEEqS6t/kRT3OFvw5SNhc=;
        b=wsjKrAt7Q9CKXc2HSJ7E0Rp3paGR2+z6b1E5f9DZB9e9cYBUo6p3Ml/1c3DJfvdyAH
         +gadV6eeWbpg/BYOjPx+Y+F2cTmQWHBkln6nMhB2SKDefjjZEv1FqgyOKYvu7oW9QIFm
         0duC0aoProJy7GALxy4VJDIo73bdevyyBhC6sPPgdzlPp3Fg8di0AATIDH/IHiGxRtB7
         16NcCR2GQYqDiTsJ2tvd8l3MDuypXjtwhVGaGkml1GT+0EyaOl/2ZRpTOH6hyvderSAQ
         EkfNVeg7PxuK0kndpUT0pIs2yprxRk7Pyhw7Vw81TLe41siAlDgEVB/LI0Dzb31ahFXs
         RLOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=btYDeHpJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f6bd76cae4si1238305ad.6.2024.06.07.02.10.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Jun 2024 02:10:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-606-eUzDhlzTMDqdmYuPAblQDA-1; Fri,
 07 Jun 2024 05:09:56 -0400
X-MC-Unique: eUzDhlzTMDqdmYuPAblQDA-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 964D43C01221;
	Fri,  7 Jun 2024 09:09:55 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.39.194.94])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 30BEC37E5;
	Fri,  7 Jun 2024 09:09:51 +0000 (UTC)
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
Subject: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of !ZONE_DEVICE with PageOffline() instead of PageReserved()
Date: Fri,  7 Jun 2024 11:09:37 +0200
Message-ID: <20240607090939.89524-3-david@redhat.com>
In-Reply-To: <20240607090939.89524-1-david@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=btYDeHpJ;
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

We currently initialize the memmap such that PG_reserved is set and the
refcount of the page is 1. In virtio-mem code, we have to manually clear
that PG_reserved flag to make memory offlining with partially hotplugged
memory blocks possible: has_unmovable_pages() would otherwise bail out on
such pages.

We want to avoid PG_reserved where possible and move to typed pages
instead. Further, we want to further enlighten memory offlining code about
PG_offline: offline pages in an online memory section. One example is
handling managed page count adjustments in a cleaner way during memory
offlining.

So let's initialize the pages with PG_offline instead of PG_reserved.
generic_online_page()->__free_pages_core() will now clear that flag before
handing that memory to the buddy.

Note that the page refcount is still 1 and would forbid offlining of such
memory except when special care is take during GOING_OFFLINE as
currently only implemented by virtio-mem.

With this change, we can now get non-PageReserved() pages in the XEN
balloon list. From what I can tell, that can already happen via
decrease_reservation(), so that should be fine.

HV-balloon should not really observe a change: partial online memory
blocks still cannot get surprise-offlined, because the refcount of these
PageOffline() pages is 1.

Update virtio-mem, HV-balloon and XEN-balloon code to be aware that
hotplugged pages are now PageOffline() instead of PageReserved() before
they are handed over to the buddy.

We'll leave the ZONE_DEVICE case alone for now.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/hv/hv_balloon.c     |  5 ++---
 drivers/virtio/virtio_mem.c | 18 ++++++++++++------
 drivers/xen/balloon.c       |  9 +++++++--
 include/linux/page-flags.h  | 12 +++++-------
 mm/memory_hotplug.c         | 16 ++++++++++------
 mm/mm_init.c                | 10 ++++++++--
 mm/page_alloc.c             | 32 +++++++++++++++++++++++---------
 7 files changed, 67 insertions(+), 35 deletions(-)

diff --git a/drivers/hv/hv_balloon.c b/drivers/hv/hv_balloon.c
index e000fa3b9f978..c1be38edd8361 100644
--- a/drivers/hv/hv_balloon.c
+++ b/drivers/hv/hv_balloon.c
@@ -693,9 +693,8 @@ static void hv_page_online_one(struct hv_hotadd_state *has, struct page *pg)
 		if (!PageOffline(pg))
 			__SetPageOffline(pg);
 		return;
-	}
-	if (PageOffline(pg))
-		__ClearPageOffline(pg);
+	} else if (!PageOffline(pg))
+		return;
 
 	/* This frame is currently backed; online the page. */
 	generic_online_page(pg, 0);
diff --git a/drivers/virtio/virtio_mem.c b/drivers/virtio/virtio_mem.c
index a3857bacc8446..b90df29621c81 100644
--- a/drivers/virtio/virtio_mem.c
+++ b/drivers/virtio/virtio_mem.c
@@ -1146,12 +1146,16 @@ static void virtio_mem_set_fake_offline(unsigned long pfn,
 	for (; nr_pages--; pfn++) {
 		struct page *page = pfn_to_page(pfn);
 
-		__SetPageOffline(page);
-		if (!onlined) {
+		if (!onlined)
+			/*
+			 * Pages that have not been onlined yet were initialized
+			 * to PageOffline(). Remember that we have to route them
+			 * through generic_online_page().
+			 */
 			SetPageDirty(page);
-			/* FIXME: remove after cleanups */
-			ClearPageReserved(page);
-		}
+		else
+			__SetPageOffline(page);
+		VM_WARN_ON_ONCE(!PageOffline(page));
 	}
 	page_offline_end();
 }
@@ -1166,9 +1170,11 @@ static void virtio_mem_clear_fake_offline(unsigned long pfn,
 	for (; nr_pages--; pfn++) {
 		struct page *page = pfn_to_page(pfn);
 
-		__ClearPageOffline(page);
 		if (!onlined)
+			/* generic_online_page() will clear PageOffline(). */
 			ClearPageDirty(page);
+		else
+			__ClearPageOffline(page);
 	}
 }
 
diff --git a/drivers/xen/balloon.c b/drivers/xen/balloon.c
index aaf2514fcfa46..528395133b4f8 100644
--- a/drivers/xen/balloon.c
+++ b/drivers/xen/balloon.c
@@ -146,7 +146,8 @@ static DECLARE_WAIT_QUEUE_HEAD(balloon_wq);
 /* balloon_append: add the given page to the balloon. */
 static void balloon_append(struct page *page)
 {
-	__SetPageOffline(page);
+	if (!PageOffline(page))
+		__SetPageOffline(page);
 
 	/* Lowmem is re-populated first, so highmem pages go at list tail. */
 	if (PageHighMem(page)) {
@@ -412,7 +413,11 @@ static enum bp_state increase_reservation(unsigned long nr_pages)
 
 		xenmem_reservation_va_mapping_update(1, &page, &frame_list[i]);
 
-		/* Relinquish the page back to the allocator. */
+		/*
+		 * Relinquish the page back to the allocator. Note that
+		 * some pages, including ones added via xen_online_page(), might
+		 * not be marked reserved; free_reserved_page() will handle that.
+		 */
 		free_reserved_page(page);
 	}
 
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index f04fea86324d9..e0362ce7fc109 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -30,16 +30,11 @@
  * - Pages falling into physical memory gaps - not IORESOURCE_SYSRAM. Trying
  *   to read/write these pages might end badly. Don't touch!
  * - The zero page(s)
- * - Pages not added to the page allocator when onlining a section because
- *   they were excluded via the online_page_callback() or because they are
- *   PG_hwpoison.
  * - Pages allocated in the context of kexec/kdump (loaded kernel image,
  *   control pages, vmcoreinfo)
  * - MMIO/DMA pages. Some architectures don't allow to ioremap pages that are
  *   not marked PG_reserved (as they might be in use by somebody else who does
  *   not respect the caching strategy).
- * - Pages part of an offline section (struct pages of offline sections should
- *   not be trusted as they will be initialized when first onlined).
  * - MCA pages on ia64
  * - Pages holding CPU notes for POWER Firmware Assisted Dump
  * - Device memory (e.g. PMEM, DAX, HMM)
@@ -1021,6 +1016,10 @@ PAGE_TYPE_OPS(Buddy, buddy, buddy)
  * The content of these pages is effectively stale. Such pages should not
  * be touched (read/write/dump/save) except by their owner.
  *
+ * When a memory block gets onlined, all pages are initialized with a
+ * refcount of 1 and PageOffline(). generic_online_page() will
+ * take care of clearing PageOffline().
+ *
  * If a driver wants to allow to offline unmovable PageOffline() pages without
  * putting them back to the buddy, it can do so via the memory notifier by
  * decrementing the reference count in MEM_GOING_OFFLINE and incrementing the
@@ -1028,8 +1027,7 @@ PAGE_TYPE_OPS(Buddy, buddy, buddy)
  * pages (now with a reference count of zero) are treated like free pages,
  * allowing the containing memory block to get offlined. A driver that
  * relies on this feature is aware that re-onlining the memory block will
- * require to re-set the pages PageOffline() and not giving them to the
- * buddy via online_page_callback_t.
+ * require not giving them to the buddy via generic_online_page().
  *
  * There are drivers that mark a page PageOffline() and expect there won't be
  * any further access to page content. PFN walkers that read content of random
diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
index 27e3be75edcf7..0254059efcbe1 100644
--- a/mm/memory_hotplug.c
+++ b/mm/memory_hotplug.c
@@ -734,7 +734,7 @@ static inline void section_taint_zone_device(unsigned long pfn)
 /*
  * Associate the pfn range with the given zone, initializing the memmaps
  * and resizing the pgdat/zone data to span the added pages. After this
- * call, all affected pages are PG_reserved.
+ * call, all affected pages are PageOffline().
  *
  * All aligned pageblocks are initialized to the specified migratetype
  * (usually MIGRATE_MOVABLE). Besides setting the migratetype, no related
@@ -1100,8 +1100,12 @@ int mhp_init_memmap_on_memory(unsigned long pfn, unsigned long nr_pages,
 
 	move_pfn_range_to_zone(zone, pfn, nr_pages, NULL, MIGRATE_UNMOVABLE);
 
-	for (i = 0; i < nr_pages; i++)
-		SetPageVmemmapSelfHosted(pfn_to_page(pfn + i));
+	for (i = 0; i < nr_pages; i++) {
+		struct page *page = pfn_to_page(pfn + i);
+
+		__ClearPageOffline(page);
+		SetPageVmemmapSelfHosted(page);
+	}
 
 	/*
 	 * It might be that the vmemmap_pages fully span sections. If that is
@@ -1959,9 +1963,9 @@ int __ref offline_pages(unsigned long start_pfn, unsigned long nr_pages,
 	 * Don't allow to offline memory blocks that contain holes.
 	 * Consequently, memory blocks with holes can never get onlined
 	 * via the hotplug path - online_pages() - as hotplugged memory has
-	 * no holes. This way, we e.g., don't have to worry about marking
-	 * memory holes PG_reserved, don't need pfn_valid() checks, and can
-	 * avoid using walk_system_ram_range() later.
+	 * no holes. This way, we don't have to worry about memory holes,
+	 * don't need pfn_valid() checks, and can avoid using
+	 * walk_system_ram_range() later.
 	 */
 	walk_system_ram_range(start_pfn, nr_pages, &system_ram_pages,
 			      count_system_ram_pages_cb);
diff --git a/mm/mm_init.c b/mm/mm_init.c
index feb5b6e8c8875..c066c1c474837 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -892,8 +892,14 @@ void __meminit memmap_init_range(unsigned long size, int nid, unsigned long zone
 
 		page = pfn_to_page(pfn);
 		__init_single_page(page, pfn, zone, nid);
-		if (context == MEMINIT_HOTPLUG)
-			__SetPageReserved(page);
+		if (context == MEMINIT_HOTPLUG) {
+#ifdef CONFIG_ZONE_DEVICE
+			if (zone == ZONE_DEVICE)
+				__SetPageReserved(page);
+			else
+#endif
+				__SetPageOffline(page);
+		}
 
 		/*
 		 * Usually, we want to mark the pageblock MIGRATE_MOVABLE,
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e0c8a8354be36..039bc52cc9091 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1225,18 +1225,23 @@ void __free_pages_core(struct page *page, unsigned int order,
 	 * When initializing the memmap, __init_single_page() sets the refcount
 	 * of all pages to 1 ("allocated"/"not free"). We have to set the
 	 * refcount of all involved pages to 0.
+	 *
+	 * Note that hotplugged memory pages are initialized to PageOffline().
+	 * Pages freed from memblock might be marked as reserved.
 	 */
-	prefetchw(p);
-	for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
-		prefetchw(p + 1);
-		__ClearPageReserved(p);
-		set_page_count(p, 0);
-	}
-	__ClearPageReserved(p);
-	set_page_count(p, 0);
-
 	if (IS_ENABLED(CONFIG_MEMORY_HOTPLUG) &&
 	    unlikely(context == MEMINIT_HOTPLUG)) {
+		prefetchw(p);
+		for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
+			prefetchw(p + 1);
+			VM_WARN_ON_ONCE(PageReserved(p));
+			__ClearPageOffline(p);
+			set_page_count(p, 0);
+		}
+		VM_WARN_ON_ONCE(PageReserved(p));
+		__ClearPageOffline(p);
+		set_page_count(p, 0);
+
 		/*
 		 * Freeing the page with debug_pagealloc enabled will try to
 		 * unmap it; some archs don't like double-unmappings, so
@@ -1245,6 +1250,15 @@ void __free_pages_core(struct page *page, unsigned int order,
 		debug_pagealloc_map_pages(page, nr_pages);
 		adjust_managed_page_count(page, nr_pages);
 	} else {
+		prefetchw(p);
+		for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
+			prefetchw(p + 1);
+			__ClearPageReserved(p);
+			set_page_count(p, 0);
+		}
+		__ClearPageReserved(p);
+		set_page_count(p, 0);
+
 		/* memblock adjusts totalram_pages() ahead of time. */
 		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
 	}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240607090939.89524-3-david%40redhat.com.
