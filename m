Return-Path: <kasan-dev+bncBC32535MUICBB344ROZQMGQEWV7DTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B11A88FFEE2
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2024 11:10:09 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f62e7432c7sf17599145ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2024 02:10:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717751408; cv=pass;
        d=google.com; s=arc-20160816;
        b=slSmHMmRQy0bmrGqdVp2JzL3hdvw7esOlhTLeWM2mAuAnyQqt/ZFORrmF9IuAGA7Jb
         d33I94gwrwq8TY909GGkHYrHftb+vyvsdPljPWgMAZt6WUiNThAD5aLQ1rAe+l7xbNyX
         hFM53FA0IqXK8s5whlDBEToNYu8XAIU2DgQoyjparTUwHrLp/m0HsUgBqJpKZtc+fE6j
         tB8b3fYB+fYG8bBcYz+C3TnXVyrI3SGaeUQ2ejVnpHBwRw2NXTyXbW9DFyBDOTDHuZPy
         lOOchY2OGrCAYqDW+lAYuorldHKKwyCUpKSS5Wcb/BY/0Z7XGHOoOVJwoUZwttoP1phN
         khdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=juZo7ML1YFu4tghoXB67+yNXyBaYmWYAF9c3AGpxN6E=;
        fh=Sjxih73Vmss9DYOC1lW5jns5j4JG1mlko/3r/gtfuec=;
        b=nlRWFJXMnXywYF8jGbTN+0bcNFLiNSusgL6LuRD1kgTePLK9OtjoCC9zeaTX+kxaKg
         mo/bDScbhyssQHMluDPUXG17XUXOBv6MOU2bcCHk8djYuKKPCvYQCBKpVMAJM7r/X7C2
         f8pnGGw4Dt555T0BHsOkXdBZaHZBnsGy6pO5oOLl44o60Fe0OIHm/ze86W763jYyjXh9
         FjKanL84KFlBcGNTyg8oRAUlSTd6rDS/5+satGv9mCBzIRcU6myg0QkRP6vaipBOjpZR
         X3nU9LMlG95vrEHoZiNFi2vARdRREMcFHrPA59igJ6zBvZGkOdcitfgKJjhwwQLOAB7f
         LyYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="EyM1/bpm";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717751408; x=1718356208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=juZo7ML1YFu4tghoXB67+yNXyBaYmWYAF9c3AGpxN6E=;
        b=GeDKy016C1WIQBp8uKgkAlclJFGF1K0heBpuohV0faVCSUe3ySL16WtUGNspXG0f1J
         lxkEjB5Q55putbokROVzwHnpS5zy6UxVrTqnHbgtaXvC1bjqDwkfsUAUlyT2quzjcCNw
         UR475igl8tkQ3jGOp/YtgL5UGn5EtRcqxLO1bp89L+Q1Pyd0TBp/PrYkixJgUcyzVcEw
         0gl9VEt5q5fLXhABGcL7N1Jp+awkIkO+EcyCN9A0s4rAqhZGEYYOxdPVdsaX+x+waRvy
         GGBoS0n9/Fa6ehqVhpzTuTxg4GHheOPt5pdiwYflHpQ/CJp0yyhYKbcpDBPLuEfQn8Yd
         IulA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717751408; x=1718356208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=juZo7ML1YFu4tghoXB67+yNXyBaYmWYAF9c3AGpxN6E=;
        b=Qxq30S8Q/wBca17OjVRf9mgK6ISSssM18kmp1re+inGfeJrEAE25ghSTgulEz1mULZ
         NTFOdApX04VUu8tcXv4q+J+4MnWBv1dfFGvR2jqABDNyFo+h1w3S5vxBzLZsx69TlXZG
         xD7oAUrWv/GMPh4z9QguWTTB8Nrq7timK0+9No4y8adkI5OLvjXSXP+SMwKq9BNRPnVc
         i7MugCgF8Opz5cMO+1QoFxIreMjIDKEuj2h1EjX2dC+DCEnn7zwPnhZfosayY5lB93m8
         U8Wrm2xcBYHm6XHnCj5wF1lpU7QNahGoi8T+Oe2rApNjkGfzLOKapM2SxlQdh+VfQOSg
         gQBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWybVwIqtXXl0424DhiCwxB99b09yuVRn1aYYaK93Kvj1Y85VwPyKnDdWOHK0Ci1imCVsa+ob0A3sKEqsetAXBe9GSFx9VC3A==
X-Gm-Message-State: AOJu0Yzhlkod4jDTPrLuLx0bu6CYzABl8gJ+T+Cb25p3boC0pwCZOMlJ
	wplO3Bju9Aw9ATMjRKrGjoS8Y7tIyFqaG29Z8/FdmQBlEBDt3eEP
X-Google-Smtp-Source: AGHT+IEAgfK2Gi6KEfO7HYSmWqZv/v+vPSOr0I9pY+ka8qOYiWHk1Xuj0AnYXxmgjYVvhSZmSZT35g==
X-Received: by 2002:a17:902:7485:b0:1f6:6ef0:dae9 with SMTP id d9443c01a7336-1f6d0377269mr15343625ad.42.1717751407878;
        Fri, 07 Jun 2024 02:10:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2445:b0:1f6:1501:ac0 with SMTP id
 d9443c01a7336-1f6cc474d97ls7085255ad.2.-pod-prod-04-us; Fri, 07 Jun 2024
 02:10:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuuoUXfwfw5uw5XT9YVjYA6YEeKFmaDRQq/nTubrdq+ZqrppUXlPLPHhoaH4l4+LJ9ViizdkiA0TEh760m8Fgs3yGXclx/acBxJA==
X-Received: by 2002:a17:902:ce8f:b0:1f6:3720:ce56 with SMTP id d9443c01a7336-1f6d02e0cb5mr23914705ad.27.1717751406414;
        Fri, 07 Jun 2024 02:10:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717751406; cv=none;
        d=google.com; s=arc-20160816;
        b=rNUExy2709GxZi/2GpsGGo3mEmkyVl5Gu2Pg/9mR9r/J+KLfxD+x0VLSen7w2P1kSX
         TEY5BCTIacflCzp/VbA7Ye3lHKREXbCi0/PAlK8Tkj2Un3bnw4YjTOJenxwLSnRWCm8H
         plLNG6zYoyYUx05A1RkStVwQA3BEXq7my4BOD+AVz/s89nAXBI+vtoutbk6/yuYgFShh
         jcu4Zos8d04jIEacIncLunhZMY9EQrtoKqwl4UytmkYZZZn54uS+aJdW+CMGwmp4Xd58
         jh4d+Wmzk9c13nz11FlXWXMnWFT+aVNEpqZK2SHSpGNTWH3dB84taY1fIiqARG+0BGcI
         X/8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BkvZtA0DZCTst0gmiY3p4tzfSSSAg0RWHnN+gN89loE=;
        fh=8obm1S+EgOJGM37d32V0lIxEEqS6t/kRT3OFvw5SNhc=;
        b=FhXlpsQ/PWlSrL8hq/DjlcvVW7Y7Sln7yLGZHuAtDZuD9SYqk6jtg7jzdE39bumfV0
         33hhg45TiS49QTJPwpBT4w0+F6Iwy9qtCXTGQaHsgNFeWusr0mLt9IsI8gGT3b6NCvWR
         DdNLG2u3zU3HMKTmVKfs4q4pGwRh62KG0DISkjFGyvyEQHOotkeQBvA183fHMFg0Rlhg
         VaIXrEgyO3M1VVds0TdCqZCNbxBRnw6B6w82zidMtKtN1Bm0PxzVLMVXz5Pv/P9oVy7M
         66AtnQriHHcTUYhoBwQRyu8LSn3Kbv4rXG+Tm9grNWVoAIao+fhz4sVpMiZYW5diovZE
         fzRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="EyM1/bpm";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f6de168163si251585ad.12.2024.06.07.02.10.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Jun 2024 02:10:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-592-yH10sX6lNoa9rUALrYBFDg-1; Fri, 07 Jun 2024 05:10:01 -0400
X-MC-Unique: yH10sX6lNoa9rUALrYBFDg-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 16217811E81;
	Fri,  7 Jun 2024 09:10:00 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.39.194.94])
	by smtp.corp.redhat.com (Postfix) with ESMTP id CF51437E7;
	Fri,  7 Jun 2024 09:09:55 +0000 (UTC)
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
Subject: [PATCH v1 3/3] mm/memory_hotplug: skip adjust_managed_page_count() for PageOffline() pages when offlining
Date: Fri,  7 Jun 2024 11:09:38 +0200
Message-ID: <20240607090939.89524-4-david@redhat.com>
In-Reply-To: <20240607090939.89524-1-david@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="EyM1/bpm";
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

We currently have a hack for virtio-mem in place to handle memory
offlining with PageOffline pages for which we already adjusted the
managed page count.

Let's enlighten memory offlining code so we can get rid of that hack,
and document the situation.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/virtio/virtio_mem.c    | 11 ++---------
 include/linux/memory_hotplug.h |  4 ++--
 include/linux/page-flags.h     |  8 ++++++--
 mm/memory_hotplug.c            |  6 +++---
 mm/page_alloc.c                | 12 ++++++++++--
 5 files changed, 23 insertions(+), 18 deletions(-)

diff --git a/drivers/virtio/virtio_mem.c b/drivers/virtio/virtio_mem.c
index b90df29621c81..b0b8714415783 100644
--- a/drivers/virtio/virtio_mem.c
+++ b/drivers/virtio/virtio_mem.c
@@ -1269,12 +1269,6 @@ static void virtio_mem_fake_offline_going_offline(unsigned long pfn,
 	struct page *page;
 	unsigned long i;
 
-	/*
-	 * Drop our reference to the pages so the memory can get offlined
-	 * and add the unplugged pages to the managed page counters (so
-	 * offlining code can correctly subtract them again).
-	 */
-	adjust_managed_page_count(pfn_to_page(pfn), nr_pages);
 	/* Drop our reference to the pages so the memory can get offlined. */
 	for (i = 0; i < nr_pages; i++) {
 		page = pfn_to_page(pfn + i);
@@ -1293,10 +1287,9 @@ static void virtio_mem_fake_offline_cancel_offline(unsigned long pfn,
 	unsigned long i;
 
 	/*
-	 * Get the reference we dropped when going offline and subtract the
-	 * unplugged pages from the managed page counters.
+	 * Get the reference again that we dropped via page_ref_dec_and_test()
+	 * when going offline.
 	 */
-	adjust_managed_page_count(pfn_to_page(pfn), -nr_pages);
 	for (i = 0; i < nr_pages; i++)
 		page_ref_inc(pfn_to_page(pfn + i));
 }
diff --git a/include/linux/memory_hotplug.h b/include/linux/memory_hotplug.h
index 7a9ff464608d7..ebe876930e782 100644
--- a/include/linux/memory_hotplug.h
+++ b/include/linux/memory_hotplug.h
@@ -175,8 +175,8 @@ extern int mhp_init_memmap_on_memory(unsigned long pfn, unsigned long nr_pages,
 extern void mhp_deinit_memmap_on_memory(unsigned long pfn, unsigned long nr_pages);
 extern int online_pages(unsigned long pfn, unsigned long nr_pages,
 			struct zone *zone, struct memory_group *group);
-extern void __offline_isolated_pages(unsigned long start_pfn,
-				     unsigned long end_pfn);
+extern unsigned long __offline_isolated_pages(unsigned long start_pfn,
+		unsigned long end_pfn);
 
 typedef void (*online_page_callback_t)(struct page *page, unsigned int order);
 
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index e0362ce7fc109..0876aca0833e7 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -1024,11 +1024,15 @@ PAGE_TYPE_OPS(Buddy, buddy, buddy)
  * putting them back to the buddy, it can do so via the memory notifier by
  * decrementing the reference count in MEM_GOING_OFFLINE and incrementing the
  * reference count in MEM_CANCEL_OFFLINE. When offlining, the PageOffline()
- * pages (now with a reference count of zero) are treated like free pages,
- * allowing the containing memory block to get offlined. A driver that
+ * pages (now with a reference count of zero) are treated like free (unmanaged)
+ * pages, allowing the containing memory block to get offlined. A driver that
  * relies on this feature is aware that re-onlining the memory block will
  * require not giving them to the buddy via generic_online_page().
  *
+ * Memory offlining code will not adjust the managed page count for any
+ * PageOffline() pages, treating them like they were never exposed to the
+ * buddy using generic_online_page().
+ *
  * There are drivers that mark a page PageOffline() and expect there won't be
  * any further access to page content. PFN walkers that read content of random
  * pages should check PageOffline() and synchronize with such drivers using
diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
index 0254059efcbe1..965707a02556f 100644
--- a/mm/memory_hotplug.c
+++ b/mm/memory_hotplug.c
@@ -1941,7 +1941,7 @@ int __ref offline_pages(unsigned long start_pfn, unsigned long nr_pages,
 			struct zone *zone, struct memory_group *group)
 {
 	const unsigned long end_pfn = start_pfn + nr_pages;
-	unsigned long pfn, system_ram_pages = 0;
+	unsigned long pfn, managed_pages, system_ram_pages = 0;
 	const int node = zone_to_nid(zone);
 	unsigned long flags;
 	struct memory_notify arg;
@@ -2062,7 +2062,7 @@ int __ref offline_pages(unsigned long start_pfn, unsigned long nr_pages,
 	} while (ret);
 
 	/* Mark all sections offline and remove free pages from the buddy. */
-	__offline_isolated_pages(start_pfn, end_pfn);
+	managed_pages = __offline_isolated_pages(start_pfn, end_pfn);
 	pr_debug("Offlined Pages %ld\n", nr_pages);
 
 	/*
@@ -2078,7 +2078,7 @@ int __ref offline_pages(unsigned long start_pfn, unsigned long nr_pages,
 	zone_pcp_enable(zone);
 
 	/* removal success */
-	adjust_managed_page_count(pfn_to_page(start_pfn), -nr_pages);
+	adjust_managed_page_count(pfn_to_page(start_pfn), -managed_pages);
 	adjust_present_page_count(pfn_to_page(start_pfn), group, -nr_pages);
 
 	/* reinitialise watermarks and update pcp limits */
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 039bc52cc9091..809bc4a816e85 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -6745,14 +6745,19 @@ void zone_pcp_reset(struct zone *zone)
 /*
  * All pages in the range must be in a single zone, must not contain holes,
  * must span full sections, and must be isolated before calling this function.
+ *
+ * Returns the number of managed (non-PageOffline()) pages in the range: the
+ * number of pages for which memory offlining code must adjust managed page
+ * counters using adjust_managed_page_count().
  */
-void __offline_isolated_pages(unsigned long start_pfn, unsigned long end_pfn)
+unsigned long __offline_isolated_pages(unsigned long start_pfn,
+		unsigned long end_pfn)
 {
+	unsigned long already_offline = 0, flags;
 	unsigned long pfn = start_pfn;
 	struct page *page;
 	struct zone *zone;
 	unsigned int order;
-	unsigned long flags;
 
 	offline_mem_sections(pfn, end_pfn);
 	zone = page_zone(pfn_to_page(pfn));
@@ -6774,6 +6779,7 @@ void __offline_isolated_pages(unsigned long start_pfn, unsigned long end_pfn)
 		if (PageOffline(page)) {
 			BUG_ON(page_count(page));
 			BUG_ON(PageBuddy(page));
+			already_offline++;
 			pfn++;
 			continue;
 		}
@@ -6786,6 +6792,8 @@ void __offline_isolated_pages(unsigned long start_pfn, unsigned long end_pfn)
 		pfn += (1 << order);
 	}
 	spin_unlock_irqrestore(&zone->lock, flags);
+
+	return end_pfn - start_pfn - already_offline;
 }
 #endif
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240607090939.89524-4-david%40redhat.com.
