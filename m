Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6OF7DCAMGQEFAQXK7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 06AFCB26E1C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:18 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-244581950a1sf14106045ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194106; cv=pass;
        d=google.com; s=arc-20240605;
        b=OMQm+FNS43xsKrusO813V2CW42A6wRHZ9yvC/ISyIKTWAqpz2/t2WWGi8jcUphWeiX
         FUl/BqIGMQgcy7Y27Y5qyjhuFV6KVxWKEWAhlVBqldpTDCglVfJfCLmSUySXhqTWAtCJ
         bpHD71jGKjS3YoA5M0kaqCCzH+8DPiank/QYG4M6pRE0XRj77yxV+Yko7SE93TlOk1Tv
         t+5BGcijpNX28YQVL4E03cc4pjfOXRrv8lZvyQHszFWHayt6jbDA9rLTkFU3upPJMHOP
         CzmGEc73wiIxGE7b/2BVwPBOCcJWfnAEbMKBQS5C4gU896nwfTSkJogGGrgv45il4SWX
         IomQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=zktg70ciM+IOJAD5TjhsdBCEYdfqO1UwGvJ4ebJxq3k=;
        fh=ZnVEdGS1TnBBNeFFj1yYta+x487cZQ9WKrHHHrdRBs8=;
        b=Ec3Frt8vQq5pxRqWKHgghWTM8l4ge9huDHRr0TpoxVEwHGJiQiVNYQ1XiHJ5E5eoVf
         XSUDLsA3uJCOqbBwtwNGfSbytzb5Jj0vt4czL95W20+DbUA2mnlPpXNWyFaLuO+dwmKP
         w44plIYtCP1WqiYFLDBSVsNR9OP5/Y3ttqUqdwgh9grnoPWARChkG0igjunAZfpQsbFf
         wtK2VFps/zqFgjQDIbSG1t+swxgUp8OUQ66hyNvOt2mKJV1l+45gsVuO+iLYLmgKbBdD
         n3Dzw5BsAoC9Jogal9QEWLgE0JgLuQfD5DNDK+nf1wrfPNdf40jrGKV47O4i1wNlueVg
         R4VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q5y8UPYb;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194106; x=1755798906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zktg70ciM+IOJAD5TjhsdBCEYdfqO1UwGvJ4ebJxq3k=;
        b=PpHf4DfVRGFLkY/6l3NH1f/L47dh2IdG6pMn69gv7IiaN5U9DHYQOea+eBBIhCzfGO
         pcLpUrrAtFPfifQ+xnu9RIShiu4KV3YgdIMnZs/93WV9pgcq2vYBqxFNnhfuxoY5K842
         POJ9P96Xori9twhO/mjePB6uk1g1PQr+lVBU15mNoajG6gMLgisbOoZIG7MkibgqEb4Q
         JGyj4CebioSHcldzK9p2KVGuc5kHp5BosFTE/I8hIvCaO9xneDuhXHnUQopXZOTdrcVw
         T9LfqSha3ccNr/j9ZDC6WhcY+k1O2x/+jIhb53dag1xr0RjPhZiys6Rz8ZqM1p2Q/+wu
         xhOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194106; x=1755798906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zktg70ciM+IOJAD5TjhsdBCEYdfqO1UwGvJ4ebJxq3k=;
        b=PfL+1uwHPHN62YFJy5Ug/gv6wdzBDw48uwdwoW4L/KNRRSxN9nuv2IHwjx2a4SQ05/
         q+sKdUESf2u1osIswej4kS+NFulqa0g/+I+0gDv1eulk/zAbxb4Nry3hJRVzy7ZOinfZ
         9gwt/frZ2PXXZmclG75JeepiB73UxlIYzO1qvy39CgLFlJ7strWWY7Y2oQZAN36WPoHc
         pYv+wzOM10Lg3e8zWCrIaCXPWgYdl6jjFrSWHZvmRC+iDrh6OC64RscmxPxhyCA3+nz1
         zO5Bkt0EsQRUNxUeR708M4ydFjh5RzkdKl9UrQt12+Hq3KYvgEUE4yxNPgC/sR2Vw4wm
         cT+A==
X-Forwarded-Encrypted: i=2; AJvYcCXDpl+nhYgs9bBgRFfNZAorN4wN+k6ihesfpSJWxWVEYC7YhcOyu1nAdTIlI/n2oT9CA5d7KA==@lfdr.de
X-Gm-Message-State: AOJu0YyEIJxHxqTVCqUlOkM1gvJ3cs5cvAHgGbzj/Md1DOGesky/SxOF
	WpPD3WElUjCD4cFilqHnPEe2lpotYqVf8eGg2TXVQb1OdNiDGhVqc09g
X-Google-Smtp-Source: AGHT+IFAQzpFg5vKJvT9tUmEO96rNmC6500HxJ5M3n4dJ6OBIDcHxIqXrk0B6MOGndtE96M6w3tgwg==
X-Received: by 2002:a17:902:ef4c:b0:23f:fa79:15d0 with SMTP id d9443c01a7336-244586d67efmr60212675ad.46.1755194105623;
        Thu, 14 Aug 2025 10:55:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZecy7Dba7m0A0y/g+8PpLKH7x0T5QjzldkM8PyNpuZz2Q==
Received: by 2002:a17:90b:5545:b0:31e:ff9d:533e with SMTP id
 98e67ed59e1d1-323266c0e62ls1383174a91.2.-pod-prod-07-us; Thu, 14 Aug 2025
 10:55:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAKsoxkcIFTb+eqQ5zug8UAG0VwhlGmrKUd74nrUlI6M3SInmz4zfA2MPxjSx8lGNEvgEwf3wk+zQ=@googlegroups.com
X-Received: by 2002:a17:902:ef46:b0:240:5c75:4d47 with SMTP id d9443c01a7336-244582c6a88mr61617805ad.0.1755194103474;
        Thu, 14 Aug 2025 10:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194103; cv=none;
        d=google.com; s=arc-20240605;
        b=Xh32hgZ6ay6XoB+saSqR4gts0PvG4zWRA+NpGHpmgYFTxgJfZdNfw2uT9bMc1fOdpu
         s2gMDD2cLf6fjNPz74z05rDD0wu/Gk+4rbREbKcaEbYxs2KhVMku4H5IyRgnp7JYI6Qb
         51nTWoqOCtI67LVMRttET01M5EDg00Raz4NtC475YuoYNRLI6xwJNsyQaC92GjuQRA4Q
         x04AsSe7Aqyy/bgnP8flxtgGr7+ZEgaWdXR5fccHgOrmBMrRWLsBCq8TBuJqIl4M41BZ
         TKG1Rl2fIVRmMF4l1LNjpEnP8qiUsQ+i0weo8zaHGveRheOoZSrJ+lHN5y3WC8M140u4
         mVUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Py7VOBxcd4HwAc7HHDB+PTMRXMSLHO8b88vcAnVEU6A=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=iXcq2+NaT7qyT3iRFn8+YDKCIFSJRXAAp0Sugrek+0023ppUs9F4VNWd4IRhn+P+1i
         XoGaywbl/LqIgYsenuGzc3gO7frDiKSxhDhtwba1/PZBQ5YxfOUqY0Tbo1mxwX1EiHww
         ZDnkCKH7ZcEU+ApAsJ63wmpHRLbkbEMJu8KEk9QgCsnNAIXZWrkoMQ3FKPF7F4QnG3dp
         ysg+i4AJ/c9fzavGXBAZ7xDekdBZMFHLEg1v+dnPzwCmAIxg3pWkojX2p0aZBYMXAN6Z
         fsRlIH7W9OqDXYv7FPUCqdoq4o+zF89x7gZNR1IYj79ZJxV8Wnl6ZfKR51/vNKG2Olww
         K9Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q5y8UPYb;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-323310d486esi100772a91.2.2025.08.14.10.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id ED6975C71E8;
	Thu, 14 Aug 2025 17:55:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C7099C4CEF6;
	Thu, 14 Aug 2025 17:55:01 +0000 (UTC)
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
Subject: [PATCH v3 10/16] xen: swiotlb: Open code map_resource callback
Date: Thu, 14 Aug 2025 20:54:01 +0300
Message-ID: <be7c97a559d2482c99e41b7714400934251c53cd.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q5y8UPYb;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

General dma_direct_map_resource() is going to be removed
in next patch, so simply open-code it in xen driver.

Reviewed-by: Juergen Gross <jgross@suse.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/xen/swiotlb-xen.c | 21 ++++++++++++++++++++-
 1 file changed, 20 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
index da1a7d3d377c..dd7747a2de87 100644
--- a/drivers/xen/swiotlb-xen.c
+++ b/drivers/xen/swiotlb-xen.c
@@ -392,6 +392,25 @@ xen_swiotlb_sync_sg_for_device(struct device *dev, struct scatterlist *sgl,
 	}
 }
 
+static dma_addr_t xen_swiotlb_direct_map_resource(struct device *dev,
+						  phys_addr_t paddr,
+						  size_t size,
+						  enum dma_data_direction dir,
+						  unsigned long attrs)
+{
+	dma_addr_t dma_addr = paddr;
+
+	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
+		dev_err_once(dev,
+			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
+			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
+		WARN_ON_ONCE(1);
+		return DMA_MAPPING_ERROR;
+	}
+
+	return dma_addr;
+}
+
 /*
  * Return whether the given device DMA address mask can be supported
  * properly.  For example, if your device can only drive the low 24-bits
@@ -426,5 +445,5 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
 	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 	.max_mapping_size = swiotlb_max_mapping_size,
-	.map_resource = dma_direct_map_resource,
+	.map_resource = xen_swiotlb_direct_map_resource,
 };
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/be7c97a559d2482c99e41b7714400934251c53cd.1755193625.git.leon%40kernel.org.
