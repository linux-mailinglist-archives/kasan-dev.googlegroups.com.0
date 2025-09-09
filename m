Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBJ6XQDDAMGQEAYSZLZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A494B4FCEA
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:13 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-7296c012f86sf116108056d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424552; cv=pass;
        d=google.com; s=arc-20240605;
        b=jnJmFFTMBnn/P+h7Uhc+V0ftUZQUSGiG0/i8CM1l/U4Mbm72PfvVOQ6ICWOj7t0X+3
         yFXc2JMjDsqiRw5RaawE092V2JzXee1vCnnpDMKLEm2XuGBPJR53IaCM2itco6iCvc+l
         NA2Nv7qI3ObvHGFwgqIHLsQ6gfeusTiR2UvfvrKzacBIhYcgJDp/HDMzWBNMlm7i5QIE
         7ngN/K3zjb1+hdTqWu2c6cDcEJB5NHa4NdvhO2d1TFvQM5LeeAjCqFlf376XTGlQGpbJ
         HPuvRE9pYAgLbSrPIpPW0nqDr39qjLgned3Wm1bqPludU8S6pvr7TpoUP9LwQ7dVkhZe
         S5jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ptzxHdPY6g1mbp2hML2a3QQlzAh1QyG8Huw7afeKdD0=;
        fh=Fi9NWBYeMK3dc5viFRCAgnrl81VxsP5IMJqhgFT4Rag=;
        b=NNBnWguopETXfrL2QR1EX/kawDxV+rsKpjb7jFJ4IUzl1Knm9hxfbM/khlsMBalPrF
         pFjVv6fj2wjgWFAHj9BGX3ybDU7/GWRZT0Q25Ml1JxWr86PVV+QUuZhYq91LkW7QDZo2
         BxU1l5dse7gpra2QG0LhgxerAVC4bvxDRo6pGsG0vi/GLhMJOcj60tFmYX0UJwqya8qf
         WAjg99/L3fnGVlhHqWFWo6Zi8OHPV4NI5wgLj5y2Dt12HnpM7babdE2lNSrO4wxZkgHo
         LdoeoNHyQGmrQREylwnQxnly5529iovlTuNT6XNR/cROD8FqdzFLnfF7t2hs7dgpE4GM
         61eQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nHwsQe9p;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424552; x=1758029352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ptzxHdPY6g1mbp2hML2a3QQlzAh1QyG8Huw7afeKdD0=;
        b=l/ZXCHAfjnNjYXBJoXOxz+X7iD1AbtnXEVoPTVraFhwwJROvu3QOsVcKG36tA5AxYi
         F8vrahIm8CVDylf6dhQ+eAHehMIwGWVTEdDb1qQCIR9lRP8Ljlbu2rJhDvdzSEI7yq6l
         kysMs+JAG+Zu2D2mAu/tF7DJ6tPg+P8kJxDQQShXoU1JXVjjHCpSXMhyx4wCGavT/psG
         R6n/wy0k5UYOCOKP1uKvPVWycphPTXq4OeLOczYVs+vdamsgYYJx55DWsb/YlWdp6hTV
         xuAu3cofWk+PCYdj3p6R/SDpJ1Evf2fLzRdBDgB2p65iaMJd9KpDwzr/0mnL3P6KZxfI
         AkLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424552; x=1758029352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ptzxHdPY6g1mbp2hML2a3QQlzAh1QyG8Huw7afeKdD0=;
        b=akqdoiS83KzgFQ2mvptu497WTdyHzGTGDiV7PXXKq/zz2kRnWdqF3M5iazzz1DQ7L/
         75Z+GiiB/HR9bT5dK/C3FCGHQ1BDYmZZeRIbDzN0mvplX36WNA7BJ1gjd0ZmPIynitcH
         YP4XRwQDBmONK9dHZpIuJsg9Zb0RG0BQn/mQ26GvuqX5WEmAvPx3o7sn05GXO9qYhrd6
         AJ5DKym0ol46KuMojoov3v1vNxuu+kxaZxeEYF3uera7VlJy9fepkmtalQMl839cZF5w
         EpsOohPZfAm1XCrZb20c5VoAgJIGwYyx5VIUAlBw2H4E1m8FUJX8WWY6qsU7mxbI4oND
         j/hA==
X-Forwarded-Encrypted: i=2; AJvYcCW0K2IfwH9lir2u3WWIpEW3sN+b20ddE1jlEPkb4Icb5JbYqrcrPZKJLxIWvFqNpDp+YjWRDA==@lfdr.de
X-Gm-Message-State: AOJu0YwclzFEbgAzlSedW0xQM9FnYeTCgTWgxULTuXUvs36ynv6KFQSA
	plf+IscG5fqLllu6QyTxxnkTNoSv7OhdJ5z04XC1RDOrDDYa9fhYX6v6
X-Google-Smtp-Source: AGHT+IH9hpFkt1B67wR/IClN0zEy8UIrtxYVStKormUcKKdOpyi9BbApfUCvN9AFAgEyAcMkC8u2lg==
X-Received: by 2002:a05:6214:2508:b0:710:9995:cf61 with SMTP id 6a1803df08f44-7391bf4699cmr137963296d6.7.1757424551739;
        Tue, 09 Sep 2025 06:29:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4pTa4o79U27lD3Q6a/wrenBqRoZj5ACyR1VLV5XtpgRA==
Received: by 2002:a05:6214:ac8:b0:709:ad61:71b0 with SMTP id
 6a1803df08f44-72d3c128912ls68364526d6.1.-pod-prod-02-us; Tue, 09 Sep 2025
 06:29:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHx9DVgsk2hwS7CPMFxN3yH8H/GK5vQrfiqemXvLas1fmBF6bBHUCEWg/DtBh7TG3iKhrFOwkrpgA=@googlegroups.com
X-Received: by 2002:a05:6102:5a92:b0:523:f1b1:87b with SMTP id ada2fe7eead31-53d22d29e0cmr4016636137.26.1757424550450;
        Tue, 09 Sep 2025 06:29:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424550; cv=none;
        d=google.com; s=arc-20240605;
        b=SCb0s2PddhhQ/0toF/EsGJgylANCq6PvDcP9AMdu1ktEYCCjMS630ktm1UVXEvD4Fq
         ZsHuQaJa7fLxfeYq6vdfTgEiL1KpP7KKIP4qAAZLfhwVChlx3aWMfo5uzJboz1PCWSFa
         WXTDwmiAHi472fYrdK8rG2SxLE+i7wc3jolWO9Wtt6zyGDPS8ZBGXT5TkLYmo+FQyKRz
         34o+7EwJC84CxrXWPLOFWF8u7bZco1YARlGYT8VENFvdmYe6Od01riVHwnuuZLqJ3PFC
         uk5u6EKeAxr95lyTmVbeNvsVrJdo7wUPjwMXQyp93Jp0WByT0+SrgMv61wJ6gHOLJNjS
         JCIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wthMQG/5mxISW1GKlke+e7Nh6K6PI26zWXKnxv2AL9I=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=OYllLuIgV4N1lAxFBZMYnRdcyUv43eTnH0/sOQ7vzafcR/fbkaHm5qLVFt9PeIN5f7
         74m9cI/0TXYD6pexYhFm6NyDJwzG4TO1/kuUtn1Sg+my407+QrNi3Cl14biQURsrgsjb
         hmOinV3KzKiVdTN/TOH0KFOhBRuHIqNyjk2W1jKEugLb6SlXJ8eNUB3BpeoVk6jOfasX
         rtkevvi4d7Fxp3iNjpxzaHuZOLr/L/pn+9Zu4cvP26ustOykWKdwkYyX4pTRsjmextt3
         uXM116zxuhsFo4TGsVr5tUt6T9O5pkERbRVhlox/9ijiOUkRRWk/dN1PuwtxOo9+mYrN
         uDjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nHwsQe9p;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-52aef469018si1133321137.1.2025.09.09.06.29.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9FDB94411F;
	Tue,  9 Sep 2025 13:29:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A74DAC4CEF4;
	Tue,  9 Sep 2025 13:29:08 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>,
	Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>,
	iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev,
	Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: [PATCH v6 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Tue,  9 Sep 2025 16:27:42 +0300
Message-ID: <0efc4a06258eb1cbedcee642263d8ba24c5e97e6.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nHwsQe9p;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

From: Leon Romanovsky <leonro@nvidia.com>

After introduction of dma_map_phys(), there is no need to convert
from physical address to struct page in order to map page. So let's
use it directly.

Reviewed-by: Keith Busch <kbusch@kernel.org>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 block/blk-mq-dma.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/block/blk-mq-dma.c b/block/blk-mq-dma.c
index ad283017caef2..37e2142be4f7d 100644
--- a/block/blk-mq-dma.c
+++ b/block/blk-mq-dma.c
@@ -87,8 +87,8 @@ static bool blk_dma_map_bus(struct blk_dma_iter *iter, struct phys_vec *vec)
 static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
 		struct blk_dma_iter *iter, struct phys_vec *vec)
 {
-	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
-			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
+	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
+			rq_dma_dir(req), 0);
 	if (dma_mapping_error(dma_dev, iter->addr)) {
 		iter->status = BLK_STS_RESOURCE;
 		return false;
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0efc4a06258eb1cbedcee642263d8ba24c5e97e6.1757423202.git.leonro%40nvidia.com.
