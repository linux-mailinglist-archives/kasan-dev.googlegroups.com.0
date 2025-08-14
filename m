Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBB6G7DCAMGQEX22NTYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A0F2CB26E24
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:20 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b109ac42c4sf13007371cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194119; cv=pass;
        d=google.com; s=arc-20240605;
        b=k6o/xb0GsKNjsapr3bh367y4sHkq1agQ6SerykTwre2puk+fEEjAAGTk6vsrMmqd+3
         KqEZeQoTT5N1hKX0VUNuF3AHio5f4qYtToYQ6sPDvTtEZGh7b5eCGwzIQL2gTRLZxWPi
         DreUYkg0Rf3k72l/pENpX8GEXRuVIJPW1o+jAs8fINEzrK9lyd5EObN/M0vZ1qijNplx
         x1sGxvc08TmjaCOfLWbHJyBpp7iJ1aNUcfTSxRHUCtOu980GWvk/trtoz1wmubrjlikl
         OruuJNfk430hO5XreTYcp1iXEJwF62eFicJIydIPggeW7HKFnUx/shTuBTFBHwmH9zaz
         iZzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=oL35v6qJwBDhwJPgNXNJTsXt8UQTrsmViCC8ha++oBQ=;
        fh=Y/MIgbh6HwTg+k9AZzBtgf5hAe74rhgM/t6BH3OjzCM=;
        b=i/NDgqoQFbSNDECxUh5PmvWLLbxkg2mKy7pp0hPYIzca+az5NWnTgfYN2DxVbp8YJy
         jr53r/XIW2vuXJWd4sPVEGdOhaPccxBTY3p6jsKknTsu3SClX/bJFMDWgDo1X8hyVYf0
         /rsghXKn7Wk8JNvZdVZvbeqhlIugIllMFlejGiLD5a4S2RyWjQI1FnC4ELjUDrCXFPF+
         3r+8amkRWj5GFU3KU77ACZST1F71tYaXhjQFoMEyUxGb5JISrxd6fU0s27mZmx7nrXD2
         /VdaF0Q7wsupHb0cBOY6Ntvey21J+UZpuTYFRxqgNBl+RMg2XfAhprtMdFcAiUS4rIPm
         YziA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A2rSNS72;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194119; x=1755798919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oL35v6qJwBDhwJPgNXNJTsXt8UQTrsmViCC8ha++oBQ=;
        b=qCuur2ZJ2673lMbVhNMkEvjuMWYxkxfJFP19uFkL7ZZBhK8E/Qk0AuVDJMGPXE4xci
         eUXuulkxZuko24YMt6V9IRZnsnGH/hLYHebqzRYt6eT1T6BD8hhk+IIhHzdFZ2YCxQUg
         gkM/XCGx+HksU2l75WIgnHvDNZ7xCK0U7cpJXnTlC+VOFZEwrG8JqM5/e8OCB/rADDoL
         GsXpu98dJDFSNfqo4NY4T1LvyAJ13WYrlGwfIRrhxFLiXYSLRz7+FfZebqaLdBc8w85S
         +FJmznAWbCEWOkJLMZCSZroGQQUIwNH9kzANsPHxLaAKnvvBDt2q/dYttUbuvFqbKy9q
         pPww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194119; x=1755798919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oL35v6qJwBDhwJPgNXNJTsXt8UQTrsmViCC8ha++oBQ=;
        b=obisADKRRDwBVRBLWuRJdDJV5HhXMIVjvnoFbIkwZlNJw/DgnyryTTzevZWMGQXH6c
         C699LUCuJz7TpL0qF6ZykRNgkb0gAfrdLZpz5bl9/L5hO3OMn4wtSSdLCyxr99F6M9Bi
         K27JNGv4pC9ZqyWz7x9l7fTxkJsgcikZmcGQIhyCcc0tfX1jn0Sb1xyzNtCr2tJ+xQXU
         Clf6xyFSKGn25RWmvtZ3Is4DgrJkdQ4vQenO7UPdiWTd9B3GbzNEn/B2oFuJ1c2BH3xu
         BVPj+byImkjpCpfazEssTjsxbroAbr52mLlxECis1nCllWVKwANU/YlT7Et9NiUWoI5a
         H6UQ==
X-Forwarded-Encrypted: i=2; AJvYcCX4afr9sXF1R63qlFVQjX/A4YsfPW04AM8vgJN9QabBdc4qBMWRmz0MZkmDJO/IRBr7c+nShQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+4FO8ElOMS5dqTzJkswwPWG7UtwBki8FJ3eD0hL8HJpRhmg6G
	aaFEyiIBqqGcqPOcnBnNUB46XeBYMzTn/rufBVqQrp+5wQz8ItFrBa+G
X-Google-Smtp-Source: AGHT+IGoSPn7ISR3t+vNATB6lAJUuQOEyS7sXeMRpUCXqQJ5B61Y2qaKDxaTJkB2oZlvfP58HlqxGA==
X-Received: by 2002:a05:622a:15cf:b0:4af:23de:fc3b with SMTP id d75a77b69052e-4b10aa628aamr57111241cf.32.1755194119377;
        Thu, 14 Aug 2025 10:55:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZePDOhOls/qzfpsplSKuE9QQqwfBtiOKQwsJMPvOhj5KQ==
Received: by 2002:ac8:7f87:0:b0:4a8:17dc:d1ee with SMTP id d75a77b69052e-4b109ae45d3ls17127791cf.0.-pod-prod-08-us;
 Thu, 14 Aug 2025 10:55:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSHTSbQlaJvjiWqoFkwsGv/EYe8DPNJ3+iwXdaW22J22DPfihwyjOX3kW9Lt2QvZRfeJz77/rqSy4=@googlegroups.com
X-Received: by 2002:a05:620a:8301:b0:7e6:2886:baac with SMTP id af79cd13be357-7e87034f7e5mr469841285a.25.1755194118407;
        Thu, 14 Aug 2025 10:55:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194118; cv=none;
        d=google.com; s=arc-20240605;
        b=CX1dsW8DbbVRpcK9Sj7jD5axmZeOgcyOb9cennpgo96lCttUBpDwT9ctyeQNXvlLYY
         L1x+ZozpKeXjaVffngO0MaQIgPObBhHujnx3FjSxHtpMOrGT17N4WPcZKTmSmgEB7fbs
         2ZUAPGtmOPFz0E7y1QwrEg+56A7AFSQ8nI6aon27UTikRn/LLvjearetAFjmQEHA+Gfa
         m7E7X3FxQ5Jzzfzbi3mKNpE2XTA4eFQZ9xqJhd6J9aOaXjmnOqKcirOedUNniYsARHJt
         ooD6smz6hcmYWjOYKej7Ld+U4fL7U/oFZ8wP2aER0ClEgPo2T8dhyAWMhClGcWc1NZBG
         bR0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o2CfBR34rERHeCycfJu/oeNhZ6WULnoBhGEgp0otVxA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=WiUiDzYU6GZBBXrbJ1iI1Z4TWbrhJVC1OYKTo7fPLouVj/o4j1+dtF1CdoXHDy2PVd
         VuwLdlf7H515rnyJVthuq0jwkMnxIuve/vbFrAnA8UZXikSYYpQcqrUhZAD1H41uAHqH
         l5Ku92cbXamopey/ZHvv7OlEMHkAOOoYtvpvvcems2XXDmo5jH0CullopChmRvLBPfUQ
         XGUynH3VcpZhBKZEWs3nujNqpNUKGoZ8RvhBj2h5ucOVkD//lJDMEF0o9YXAZsxp0z9N
         GQBmZz3V2rvd+EVpqeX0810hiKvFbIRhOQOOIc4mShuALpxLkElaVM2wpOdbl8zbhwvW
         IRtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=A2rSNS72;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87b473722si412085a.7.2025.08.14.10.55.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D46345C723C;
	Thu, 14 Aug 2025 17:55:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4E86C4CEED;
	Thu, 14 Aug 2025 17:55:16 +0000 (UTC)
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
Subject: [PATCH v3 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Thu, 14 Aug 2025 20:54:07 +0300
Message-ID: <16e541279b4b030de54a0a2f1829e601b7923523.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=A2rSNS72;       spf=pass
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

Block layer maps MMIO memory through dma_map_phys() interface
with help of DMA_ATTR_MMIO attribute. There is a need to unmap
that memory with the appropriate unmap function, something which
wasn't possible before adding new REQ attribute to block layer in
previous patch.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/16e541279b4b030de54a0a2f1829e601b7923523.1755193625.git.leon%40kernel.org.
