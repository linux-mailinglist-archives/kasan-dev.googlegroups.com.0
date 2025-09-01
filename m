Return-Path: <kasan-dev+bncBC32535MUICBB5HP23CQMGQE2IFT6YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B610B3E8F7
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:12:59 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3f340e9b5c5sf65938415ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:12:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739572; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nbc1fB2vf/nLzGyZn1xAyqRUtXBac3R1dP7TBC9UYr2MHvKeIHQC1gDm6h1pHbDGrm
         l5+EnZpNySAMhkpUZnxaMkkv/h3tHt0j3tyC2NzP13kENrMcgdB6aPy48y/8a22Y1pyU
         cwuCz6HeSAJ3KbUt5szoMCzar8cANltYHqveiL5b6JJl38jhXJajo/OqXFZVxq85Ak/V
         hDVTJdZu/oclnWbNe18D6uIu3IAoJ0IM5RFJKyPeXbUk3Jq51Y6AA9EOAXcU0HZDeHi1
         liG5mmIl4W/PvISK4SUXWW6ZIaAJz8Xm2P0ABquFx0/C+GYZXVutPLTrVc96z5wWt5ZL
         aRKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ch25tK16fFaqwXZOy8vPJVBifaq1VOxb7oeBqXoF2ic=;
        fh=pSiddyz6/Jd8xfQ6qEWmtHIbwVx4D9uxd6mhup+SB5o=;
        b=F+o509Nzy6L+I7Axs+8IChCwyWHGApW7FnAQGVLtdumRKLsW4XDm7DMlw3jFqW5rNQ
         E7N6U9kgTOhqOa4z213Cl81+taBm6ZJGXx9y77MLhUUvLx6jMMnDqeYS4/PMen9HeJXR
         ocez77lWwmZKXR8GsRwtROYCdWXYJiaxYLZIz+3ufRRJaj0g5JqE9+UvDsKAMJMciko4
         GIPDJh9Vksl0QNCPrnByx5Q4Nm/AZy8p4B6af9wj7v5OZKPA6yBqJXZy1S6nc8y16nw3
         5GYqlNeIYewUyUiPrqcM65d1RLqp15LGjSQwFmyMcgsjsM5S6WySAVZRTBiBoX9mJLRQ
         yAVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OXPG/hx5";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739572; x=1757344372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ch25tK16fFaqwXZOy8vPJVBifaq1VOxb7oeBqXoF2ic=;
        b=C/O9oXak/wLCgnT7x0AaGKfdDnqwjdHpsOISUiix0JdECRk4ynim7FbE9f/XOYKR0H
         3DTMNTIQvHEvNT+FkXLOOlC+eF7sqjj76pevEnYbEFCYCeZc7lxyVZ2RtXW5zyFOyDpb
         1QRAj9fmpDuhftc7s8Yp9ewFAGeLAV9xXVkLl+g02y04TtCbAk5rJ6fcbtKPOEEolkKy
         oW4eLNbA9hS6qnqo5fpIJY6QPX3J6+ecpzexoepociYK6KWAMjJ+J/QbJGCO15oPtmn/
         Wv8we5d1z2eV65M51zWRV7TmqupYqIvj17CpJjPhyA0z+UJPVYGi6G87l1gy9FNfCcUH
         1BgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739572; x=1757344372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ch25tK16fFaqwXZOy8vPJVBifaq1VOxb7oeBqXoF2ic=;
        b=v53Fnm2fDM+KHfGqR4uhHqCFz3VvsA3WAvBfr/J7tHh6ifCWeah37rrae3uGzNGo1e
         R0pTTK74Zdm21pq4tkv3efhosk4ta//rlS+jFr2Bm+TWBrAD+X5MM4rtoKZOUvmkB7Qz
         NuMQsO6p10cpu7gXxON7B1U4J8j42LXhX74OEI18Djukzm3WD15KvbheL/ecFd7QhcPL
         GPYsifI9OLPx16sAhkpJS5paQHSuDfE5+zIqj5sCGd1KfL/A2uw/prMCAUb91azmWwc+
         O9PuD/tVLmNhkZwVnFF8Kgm3iGoTg5v/mLyNrASOPmLOM7T85s9XtByyC6schNHBcZH0
         z5zg==
X-Forwarded-Encrypted: i=2; AJvYcCXECR27KYGJWUm3j1h76NRnRVLhKNwnh6J9PESfyHGyRNh/lnaVFY2CyEIf/1TSXbzoy33HaA==@lfdr.de
X-Gm-Message-State: AOJu0YyOC5GCfIXVVj2ewe8fnLzR0kIyo0nC8r2Lzcu07qbZi2Gv8PhN
	Od8D4mtR4t+ho6H2WuuwSTuOqxv3TKAXuZ/f/+VLyR7q+8VKbFxSrdCt
X-Google-Smtp-Source: AGHT+IHOfQP0JY1yA9TJhaLz0xNwf/ZLqkQoQK2NNxsWT/o9/PFJlMQnlrmWBp3uir0iICYoaLXQ4A==
X-Received: by 2002:a05:6e02:1b02:b0:3f0:375:e587 with SMTP id e9e14a558f8ab-3f400286793mr149022275ab.11.1756739572482;
        Mon, 01 Sep 2025 08:12:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfPngWxfvbatcAax9Jc8gcN3Z57ClicdnV177sBtFvtvA==
Received: by 2002:a05:6e02:168d:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3f13aac45dfls54305985ab.2.-pod-prod-02-us; Mon, 01 Sep 2025
 08:12:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuTKJquDSaK1nOxrtMTzdxAX5yH2og4rEBlOuzzea8LSGClI5FRnRSdt4UUCUig/CYf+B8KnVZN9Q=@googlegroups.com
X-Received: by 2002:a05:6602:2b90:b0:881:8d1f:1a7c with SMTP id ca18e2360f4ac-8871f4ad90dmr1301377039f.12.1756739571656;
        Mon, 01 Sep 2025 08:12:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739571; cv=none;
        d=google.com; s=arc-20240605;
        b=RBoeD/Yn8s/pSGw5KUa+HBNjIHJCucPef6wuypHwL7VIRANAbameN1HjJ/tY5ID7Y0
         VUnl8dLfKMkIYcIn0l/FQbbzMtq8kD4Cnasq+qD4gLFYqDOV19oJ4B1xUi1Vr6d5+LPV
         IDXphFCjwCqq+LGJhqmRPvoUh9U7QzoDeJPsLJrbB8hHnu9ejCUah3iFEyqLOSUKnmj8
         SmjM/xIQ01TI6dgk2hHrSLeksPUqBq5EEaAFJJN2dKsrpqIAtvoG3wHdrye3TCPna9L3
         ZRibfCJZlCGMuoLnij4eR3jwqBm/8K+7qjw3WwkSAqmHrce5w5pUclf11s+P9pBUrI9G
         n9Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JVCL+sDJBGR9bgMgmkBKkSxPQW+6L4IAi1OzfCPQ8Uc=;
        fh=89Y1KwDZ1O87mi2PcmD/pzr2HW+qxauoMpE/7fNSPeg=;
        b=c672aQlvEZiQd0j0PnzUqPgZ/mAa9NJpncQrxcEvfyX+d5Y2srdwQQLNfRkcePhLjD
         2mDSVwDXQuEN6KNuinl+J/5RxWJ+UMscgNXkfsB6UhegFv89lD1PW+/9ZRgBSO34jAM8
         enhn28QBmNGl/QJxY/b7hNXkRG3+ahDj7ZUKN424tTWuOjv8uNBf6b6U9g4iBG4H/4MA
         MoSi/94umCv0RZiOQPTTPlMts74Ai0qEh0k1SyziZcUmqwlAzGhXcJXyS0sS4wd3sFGt
         NwAzUGy8dSLxKeG8pxbkJsfPD3P/j+w8GWU9hmPjnnQhftOmC5szmXP6GERzzqoiLN7+
         mXzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OXPG/hx5";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8f054ff5si314626173.1.2025.09.01.08.12.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:12:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-622-R8OgGqqjNtqx4P4_88Q7FA-1; Mon,
 01 Sep 2025 11:12:46 -0400
X-MC-Unique: R8OgGqqjNtqx4P4_88Q7FA-1
X-Mimecast-MFC-AGG-ID: R8OgGqqjNtqx4P4_88Q7FA_1756739562
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AC08F195608B;
	Mon,  1 Sep 2025 15:12:41 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D93CA1800447;
	Mon,  1 Sep 2025 15:12:24 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Doug Gilbert <dgilbert@interlog.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v2 31/37] scsi: sg: drop nth_page() usage within SG entry
Date: Mon,  1 Sep 2025 17:03:52 +0200
Message-ID: <20250901150359.867252-32-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="OXPG/hx5";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

It's no longer required to use nth_page() when iterating pages within a
single SG entry, so let's drop the nth_page() usage.

Reviewed-by: Bart Van Assche <bvanassche@acm.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Martin K. Petersen <martin.petersen@oracle.com>
Cc: Doug Gilbert <dgilbert@interlog.com>
Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/scsi/sg.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/drivers/scsi/sg.c b/drivers/scsi/sg.c
index 3c02a5f7b5f39..4c62c597c7be9 100644
--- a/drivers/scsi/sg.c
+++ b/drivers/scsi/sg.c
@@ -1235,8 +1235,7 @@ sg_vma_fault(struct vm_fault *vmf)
 		len = vma->vm_end - sa;
 		len = (len < length) ? len : length;
 		if (offset < len) {
-			struct page *page = nth_page(rsv_schp->pages[k],
-						     offset >> PAGE_SHIFT);
+			struct page *page = rsv_schp->pages[k] + (offset >> PAGE_SHIFT);
 			get_page(page);	/* increment page count */
 			vmf->page = page;
 			return 0; /* success */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-32-david%40redhat.com.
