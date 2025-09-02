Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBJMI3TCQMGQERH3O72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 00386B407B8
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:50:14 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7723d779674sf2535106b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:50:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824613; cv=pass;
        d=google.com; s=arc-20240605;
        b=kjPwP/bM2twsEaxGLwY3sJm0A3s6QZ2B4v4fvumUV/Gd1opyYijIoXnnvrFB2Dfcli
         wV9wUjS5fPUT2Ot4AgriWow+PS3FzN2RvmZ0/KDJLgOL0Pci8/NmWFqRbUhkPv7a+Chp
         Z4vb1r4BFy4nlbxYehV484nCDogjkXLx787gku+zJoX5JpvfSKUYXRjsD9iFBxr6paIr
         YRoC5ZyCx0Xz/8nuWK6c0akwW0iF4eYXe0mpblFTh3VHdjv3aO5huXis9t9wj9QgT1kn
         quxz3SJBTrPZuyE+afRApntgFNaBMvG4lUGoTPg+f/QfgbKQJriEpxH7g8vOMQrGRpWO
         iJsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eRq7QGekUh4omXGuDgk+j5bER8MuEt8bDQEmweQbWcU=;
        fh=gKK8nEg0hmBdFMHTMGPia+36FnvTWppL8gRX9xNC8SA=;
        b=bwERbH6UfnUOVYfbgLoKKxl0LciKiWSCPGD5wLz2/ZoPrf2tQoLGVX8qALehX3MBRO
         wVi2OVot7OZxUFHnK0R49+nui9rmEy9JP50pJG6LwmAkiCPmcgbZSVYJWUzYLK2BrmGC
         oFShcFb+28qkcHz9WOFiN42029ucijglhMiR74CfXHLJ6FTI2suwFMPhH2n1BjnABqMD
         NTkxNy1tGt04c+I2KGxFN08SeHEWg0ABHUrLWgpvmUipDfpz01j4HAEZbqU5PHLwl92b
         dbnYI6oT6qEQEjLMpvHkvHr6+ygvx9Dx/lWfOJIl5WFdvmD0JgZbqmWPwvCKRNT/DJD4
         dAOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XDqouYHc;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824613; x=1757429413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eRq7QGekUh4omXGuDgk+j5bER8MuEt8bDQEmweQbWcU=;
        b=X/I6PcDtrF4M5nFH1lKY8XeTKOz+8TQOMpN9f8+JRCUyAqCKWPXjpgIsIHNHWsQbuJ
         9fU/oCxwLLDZd3FxTp92NI32TMhWwSJLkaUOhZQJc47qPwE5NufSzR3n2KalX+mPQwLO
         0J2jvwHzoKR4xWQbAXN+5dgrMlgTxWeVwJ8TckllH+L0pP1VwE1z+mZ8FVOgLAgs1p1M
         XlYtuu5iDR6gbwMzQRcgdKx47CpmwvAkT/pGE5WfeSsjR7Ayl7EpXYJof4wU1H7xYB6L
         iazhKqrOe4w3UwbE4JsfwTaDvofuXKvB7ruOAbfUnlFBhwwRXyHxY+oZaBXNxvWW/JmK
         ZOVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824613; x=1757429413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eRq7QGekUh4omXGuDgk+j5bER8MuEt8bDQEmweQbWcU=;
        b=XUnc5WTC0TtMDmmhgQRT/MZloFi2chOFaWQtFKkUzk+r51j7UL/lyB8uagWYtgKMK/
         hsP25CDSehbxIsYZiz7qP8hGlJQmn4hpTc22deu+bA4EqWMj+zw0ZbkRRq6FF39fFAiT
         xc9m6Qe4cxdKcyzwZmxN5J+T9uXPaujaA2+lslqnHNeMCkDJFgbQCbwGFRIHg8fp8Rwf
         HSt5Ff5QGlAQx9on8dxoHdCbQaIIDhWU1XzxUPAXpFRfEjDu8zc+49faGj5bKNHAvbDH
         oZrmw1ifnpp3ErN8vOqo00NWSH2i1wfB2U1B1xkHQtXPGUDg+vlNIAEMvSejMDHDI9ee
         Tx8w==
X-Forwarded-Encrypted: i=2; AJvYcCUHGfDyuoFrXx1q46UfF9cSf6A84iZHaEBIiwybnyhcRErYyPlPLCDc0eXKgSxpjVGNXA+MSA==@lfdr.de
X-Gm-Message-State: AOJu0YxSECYzu7NPoMrbEsITxTHFZmAiU5keRVu1Vd1KcwHpxC8dLjn5
	U8MVr7hGRji4NmeBFPDGTcog5aIaQmeYpPjg5Tt4NQYi0Dw+EUSmlSTk
X-Google-Smtp-Source: AGHT+IHPbk4XcWlpPP+qZ9Lujdj+ocTfUxnFvBMHRpbMPENZPA5m+d9CqXuC8GRfYPsTv+xsAHzxAg==
X-Received: by 2002:aa7:888c:0:b0:771:f763:4654 with SMTP id d2e1a72fcca58-7723e30a54dmr17921464b3a.18.1756824613275;
        Tue, 02 Sep 2025 07:50:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/hkmQl62TCxgkDDWmgCUVKuiIn2Ufy0qmvoY/B2ZlGw==
Received: by 2002:a05:6a00:3cc6:b0:772:50c7:d04d with SMTP id
 d2e1a72fcca58-77250c7d27els2909086b3a.1.-pod-prod-04-us; Tue, 02 Sep 2025
 07:50:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8Yl9h2B+lfqXXNiTKsF/ZplRrvKII66VJFgQgNaRR4pYy4oxWJ6cEUiU3xqkDmhqiePCfbCRJMyU=@googlegroups.com
X-Received: by 2002:a05:6a00:2e89:b0:771:ece5:f3fe with SMTP id d2e1a72fcca58-7723e1f4447mr15475601b3a.2.1756824611010;
        Tue, 02 Sep 2025 07:50:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824611; cv=none;
        d=google.com; s=arc-20240605;
        b=D7EhqbCmRIqau0C+/EMZIX53LH7FYuysziZr4/yTjP/F9c0nYKSX87UTuGOz3N4aWC
         CgTe7N8obwv5Z0JNcInIFhJriW1QOjhhyYTQUs0nSFtcdRdBVYLQR0InZLhqKWsvOt+8
         knzj+ka5casQK8cAj5zinsX32tOylbGTkjiMs4DqtkMIQOknSu4xfGtLjor7ZLn27EE5
         ARHiy5GhMtDwsWHQ6+6BptpAuYJKpIc679uc/e2DRRRwNAwvgFGDRlVh+QYnpGRtkZwy
         a3U5k3u8gAvgBVcrlvkmeAa6wAkUcodNj0ETnLx6r87dhzdhOeAIQr9umON5o63EwRrB
         0zrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BsyS7NotPIOQVUQ3M3BiMUXsFzrtiEBx/U47oNkGY1A=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=YSHhGFo2uQ9jDypTJpOWbM58pBou89z35gqFA4zrok5Ljc1swnyiiB0teOpO9H4wHy
         gsDFO3SGqgGo93UUAcQBLenz9egQXDjJZcnBML4FYUIYITTsKrIRNC/X5apMpUPUryQH
         C8y+alr2Fq6ldIHbcEZU+alJ86GPoj7tuhKjJJDg/MT0toZGriMGDssJwosRkeCue8Yy
         42TJUmI7ElgdHaI6Ryd3EwuLzAQXABqITd2vRaQH2N1J38po7e/7F8uHDVWxupRA6UwM
         n/pSAPJEYazzvEl/xmrtdRsCnmlQ15ObLgkMXnHm0Nlzb0QU2u+Ia6s8/Hs3mVbC3JB4
         miMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XDqouYHc;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7723ba80024si270595b3a.2.2025.09.02.07.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:50:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D3F4C41994;
	Tue,  2 Sep 2025 14:50:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF152C4CEED;
	Tue,  2 Sep 2025 14:50:09 +0000 (UTC)
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
Subject: [PATCH v5 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Tue,  2 Sep 2025 17:48:53 +0300
Message-ID: <fedc4cb3d79c81dae7d8b4ef45b5b3373f6a8bad.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XDqouYHc;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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

Block layer maps MMIO memory through dma_map_phys() interface
with help of DMA_ATTR_MMIO attribute. There is a need to unmap
that memory with the appropriate unmap function, something which
wasn't possible before adding new REQ attribute to block layer in
previous patch.

Reviewed-by: Keith Busch <kbusch@kernel.org>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/nvme/host/pci.c | 18 +++++++++++++-----
 1 file changed, 13 insertions(+), 5 deletions(-)

diff --git a/drivers/nvme/host/pci.c b/drivers/nvme/host/pci.c
index 2c6d9506b172..f8ecc0e0f576 100644
--- a/drivers/nvme/host/pci.c
+++ b/drivers/nvme/host/pci.c
@@ -682,11 +682,15 @@ static void nvme_free_prps(struct request *req)
 {
 	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
 	struct nvme_queue *nvmeq = req->mq_hctx->driver_data;
+	unsigned int attrs = 0;
 	unsigned int i;
 
+	if (req->cmd_flags & REQ_MMIO)
+		attrs = DMA_ATTR_MMIO;
+
 	for (i = 0; i < iod->nr_dma_vecs; i++)
-		dma_unmap_page(nvmeq->dev->dev, iod->dma_vecs[i].addr,
-				iod->dma_vecs[i].len, rq_dma_dir(req));
+		dma_unmap_phys(nvmeq->dev->dev, iod->dma_vecs[i].addr,
+				iod->dma_vecs[i].len, rq_dma_dir(req), attrs);
 	mempool_free(iod->dma_vecs, nvmeq->dev->dmavec_mempool);
 }
 
@@ -699,15 +703,19 @@ static void nvme_free_sgls(struct request *req)
 	unsigned int sqe_dma_len = le32_to_cpu(iod->cmd.common.dptr.sgl.length);
 	struct nvme_sgl_desc *sg_list = iod->descriptors[0];
 	enum dma_data_direction dir = rq_dma_dir(req);
+	unsigned int attrs = 0;
+
+	if (req->cmd_flags & REQ_MMIO)
+		attrs = DMA_ATTR_MMIO;
 
 	if (iod->nr_descriptors) {
 		unsigned int nr_entries = sqe_dma_len / sizeof(*sg_list), i;
 
 		for (i = 0; i < nr_entries; i++)
-			dma_unmap_page(dma_dev, le64_to_cpu(sg_list[i].addr),
-				le32_to_cpu(sg_list[i].length), dir);
+			dma_unmap_phys(dma_dev, le64_to_cpu(sg_list[i].addr),
+				le32_to_cpu(sg_list[i].length), dir, attrs);
 	} else {
-		dma_unmap_page(dma_dev, sqe_dma_addr, sqe_dma_len, dir);
+		dma_unmap_phys(dma_dev, sqe_dma_addr, sqe_dma_len, dir, attrs);
 	}
 }
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fedc4cb3d79c81dae7d8b4ef45b5b3373f6a8bad.1756822782.git.leon%40kernel.org.
