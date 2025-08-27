Return-Path: <kasan-dev+bncBC32535MUICBBA4EX3CQMGQELCLCN4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DBD0B38CCB
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:09:09 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b2f7851326sf10112821cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:09:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332548; cv=pass;
        d=google.com; s=arc-20240605;
        b=bQZqiuhlqdcU5Vn33SZkvIAGccQkqm4tsHK4KgvhhUF2UXVT2mqjJZd1DYQE2w52lv
         CK+cw8pCEXpm4M1n/Y7FWk4mg4eZPRnUMQ0UPuMg8pijfFd5COMUnDpuKXkfAuWwvQsC
         Rk0t3hs73cQsmM7mvp7uZygzUet1FkVPJVrscaSylWn8NKsTi1ApP8RdwCC9ZiO6n5Sa
         Vq0acoN6tqB+UQJxGgO2Kb5tPHkoFWZJsJuGniR7wrZvV+DCUiZ5fhWAk7EyHMbMSk+z
         QGIGIyIxaOtkBI6XfAtUv3M60+XWETHiNPg7c1zx/weVzjtHlmSvpFU3k0OF3ukstfmR
         7vbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GbdJ58qxRmSBYeWQDcCld+QjSURGgLChHPa0kuAYEjc=;
        fh=aLVNiWPq7mpPVn3vsDU8/17Db3o3J0mJ5qCUirN5RDQ=;
        b=lcBpwWF5RMi2F6IwEbzjzfBtBA5qbq32/CnXz+CsSDJduGmf858Dx/1KblcvWuXB47
         okScknrqk37YexLBOLv9CQ8WAmL0CG6YeoqROutSI7JeobCUC35lCGqfSKOKzrTXgL2O
         QNVZqbRQu05LHJRMl03R7qcuua4LyiwfR9/kzWrPaBmWGQUUlWjsEsp6KUTlfRU7CkQy
         jRqyZOJhMV+GH6bQDtz3mJCpIfuFw3dm2XG7AOlSidY+iyMUISMbbyxZP9O3K6BD80sG
         8W0FVWqcLtL8KZqLtp3Q5cp090ZiuFUmM9T5Sd+0E/JemcPATmOadPCVVRpG4iPaMu71
         q+qQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BWyfgCAe;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332548; x=1756937348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GbdJ58qxRmSBYeWQDcCld+QjSURGgLChHPa0kuAYEjc=;
        b=wrdnquTaNZbEiXNBdQO8E0602AKJhlTQWjoTSbgZUzJ3O4Ms+o5dnVGuyan7nrCNr7
         c9iJ3IwOIGuKP6gs2rI/xDCBeFJyJFASlBKuC9upC/KTnDv8piQXiqp6f1tmLf6QBFH0
         8mjwcSv1/ZrD9prgXpChewc3Dw9gIQj9Y1ACqP5Iche6CkJaNCF+ZjLP8sP7jM+sRvTX
         J/bgO/G2xCXJyYxq2MFQWTWLfusEXl/s4qqibxPOlJ6QuLdRiCTMAOVGxj3anhrZ+E8e
         d5aZXhmqs2XH9g9dhiJz8BT+YuxrS6qynJzxQGUYnleZel2f8K+xGXCKOQ3wyPg6XuJc
         fA8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332548; x=1756937348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GbdJ58qxRmSBYeWQDcCld+QjSURGgLChHPa0kuAYEjc=;
        b=PxTbBNoi8WGRAZwFnaMVqMTb0+sK3EsxHzErtRtdLgtzHEJa0aTXqH/sd2PryEcs3P
         LOb+CtBbTwazfY6+4eRJico9tNFiNw28JN4Cn83z/LkaJMhxxwHFd6IcJEbKru9HB9ex
         UOYS0W27l91w6giPd8lOZrmjCr6dcOlGWplNBy//ryDiK3CNCXaTOF/vzafwn5LwdvBj
         NIA5aWkYFDiLlY3bhGnfiYd0OTWtr59UvDNBO5EdyHmoCUTcC/cWU/ZLrG3lPoiIq3oX
         WFeasWopt5kjDJtf6GTEt7nMCsXpbpk/2wqhOahUOsMuBCvVmPIxMqIxS9/sYCzjxCLJ
         etPw==
X-Forwarded-Encrypted: i=2; AJvYcCWuJ12xmS6v/6OYLJmVGZsXrHQBXcYccGvId3io12e7occdmQjAA+FQgSV8Qdo2FRy2JH8E/Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy2hgrNx+311dOLrERyUl1z1GMo2us6bOFvoKT1vKvYGQupl1mT
	ZKiljkfWKCOU9HGetfaMgJo/Bvl5zZHhsIrx6e1Qa5cx/7eyOQMWgrpW
X-Google-Smtp-Source: AGHT+IFlyuJQYRd3KETFSCWKMF+Ot6sUVUHwWg1+Y/SFmuKRO+xMpAuRTsRPK064qVUrEZjPEc5S/A==
X-Received: by 2002:ac8:6f12:0:b0:4b0:cb0e:8c0b with SMTP id d75a77b69052e-4b2aaa558f6mr244767831cf.21.1756332548058;
        Wed, 27 Aug 2025 15:09:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+R+/3mb1UWxjQo3Avd2M6tumZ0vuO4JGH0lZZYSg++w==
Received: by 2002:ac8:5741:0:b0:4b0:889b:5698 with SMTP id d75a77b69052e-4b2fe667756ls2258981cf.0.-pod-prod-03-us;
 Wed, 27 Aug 2025 15:09:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcG7RW4Ed5sKTz4KRrfCNdtJ/+HHFBaxo/tna43hT0eDfoGPfYUCOqoVH8cuOG2TYEA+YEoLQeXyk=@googlegroups.com
X-Received: by 2002:ac8:7f54:0:b0:4b2:97be:6cae with SMTP id d75a77b69052e-4b2aaa558ebmr237311541cf.28.1756332547051;
        Wed, 27 Aug 2025 15:09:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332547; cv=none;
        d=google.com; s=arc-20240605;
        b=EjOP6yj+2VW8TXn8St08+jjX55vyDn84Cnv4dMno1egv7AIOi2+6UvA30zFtJUtExy
         it8yYAxcGVYO2339sxHNi3dg4vKLVzL6MGbCGtPT5rUAxG5spZqor2A6qO4yLeKwELvT
         bzW8fNJi4lcA3NX9CuI+HOmwl8ZAS38QoboAYcnZFe0XChnRcKwmWAF240FyiLIcgH54
         op7mOb3b1uHvzP8cZKFx6PgaZlYyL+pZ7oaKJYCAOvIQYeoGbUpgvzgW9aMuUw+CMfvw
         qCRX5QvRol5knS9HREYF73c7R5lUgbEWXfr9URGOnMLrZCA6w4hvkBgkXNP9E5O7Nkui
         sIgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fRSpRx9RRStIQ38BNC0jYyDlyXN9Nb6MMvlgPC7q7iI=;
        fh=y9gITMT4SzIPUAVlasWlbYxlIdPtVmGCyyZZtMXbfSQ=;
        b=F3h0bMO5SQSzbFF2fQ8oglYZbtqbDiyatc4H272vjSj3952euH9opKcwQm+0VTphVp
         Jc0j7Aq6nEJuTXD8jvaTPfo6hu14RQj6isfirvd6JiknttvoT4NCHxkd147CPpYXoWrV
         TY7D6XStGEwg005pU9aETXUMqxbsYk2Jr4bYqUwDsNZiLMwSRh17s8mZMKWxL73pMu/T
         LXSNxSp/5p8XuyutQSAthjwx+AVMTcORzh4cMOEjJzaurTkPF/Pci/TD+Ff9ywMKbaf3
         a5FzeDYiLCsOVGqrFzISau61zPuv9wM6qeyxSw6WJV6BRIJ5fRoFBxQmuoMIGuQoR8M2
         RLbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BWyfgCAe;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8c4f53dsi489071cf.1.2025.08.27.15.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:09:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-125-8rLG3SX1N-GJeE1zdspl2w-1; Wed,
 27 Aug 2025 18:09:03 -0400
X-MC-Unique: 8rLG3SX1N-GJeE1zdspl2w-1
X-Mimecast-MFC-AGG-ID: 8rLG3SX1N-GJeE1zdspl2w_1756332538
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F35E7195608A;
	Wed, 27 Aug 2025 22:08:57 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A36C230001A1;
	Wed, 27 Aug 2025 22:08:41 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Damien Le Moal <dlemoal@kernel.org>,
	Niklas Cassel <cassel@kernel.org>,
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
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v1 24/36] ata: libata-eh: drop nth_page() usage within SG entry
Date: Thu, 28 Aug 2025 00:01:28 +0200
Message-ID: <20250827220141.262669-25-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BWyfgCAe;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

Cc: Damien Le Moal <dlemoal@kernel.org>
Cc: Niklas Cassel <cassel@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 drivers/ata/libata-sff.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
index 7fc407255eb46..1e2a2c33cdc80 100644
--- a/drivers/ata/libata-sff.c
+++ b/drivers/ata/libata-sff.c
@@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
 	offset = qc->cursg->offset + qc->cursg_ofs;
 
 	/* get the current page and offset */
-	page = nth_page(page, (offset >> PAGE_SHIFT));
+	page += offset >> PAGE_SHIFT;
 	offset %= PAGE_SIZE;
 
 	/* don't overrun current sg */
@@ -631,7 +631,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
 		unsigned int split_len = PAGE_SIZE - offset;
 
 		ata_pio_xfer(qc, page, offset, split_len);
-		ata_pio_xfer(qc, nth_page(page, 1), 0, count - split_len);
+		ata_pio_xfer(qc, page + 1, 0, count - split_len);
 	} else {
 		ata_pio_xfer(qc, page, offset, count);
 	}
@@ -751,7 +751,7 @@ static int __atapi_pio_bytes(struct ata_queued_cmd *qc, unsigned int bytes)
 	offset = sg->offset + qc->cursg_ofs;
 
 	/* get the current page and offset */
-	page = nth_page(page, (offset >> PAGE_SHIFT));
+	page += offset >> PAGE_SHIFT;
 	offset %= PAGE_SIZE;
 
 	/* don't overrun current sg */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-25-david%40redhat.com.
