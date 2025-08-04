Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBLWWYLCAMGQEFCXJNQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F8B5B1A1CC
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:32 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-31ecb3a3d0asf4076192a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311471; cv=pass;
        d=google.com; s=arc-20240605;
        b=W928O2HmeEl+DPgl9n/T4rgGu7/NHbQ8O133LP5aUGKo+dhZcch3nOFyA52MW6fZNT
         GZAEz2VkLxwIxtdfRgXt++vhLmYwUJwRVebnzQP2mqn7DBsHb11S2c11OI7WiqsU3MoX
         R29c37l/hmNbB5QzcKZNoBLbt0y2op8zv9u7G170ewMJxQi6J7VWx0TI5fVNBTCzHpyM
         UgHr9DuOwqcIMxwUq6YjzsH/7OwcbiM/LcrYx1YM2eILczsaTHcElvdf38v2fjOd7uox
         hw4/sRnidB4XC4HRoBW1rPsOSn8f/hek8p6bEdFRswpxLOqubdx1og9W/jK8eigq3rvM
         5KPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JymBnFbChUrD/Nn/LfeNQ2Qchj/Q3VnvfEcy6VFqUdE=;
        fh=zTGqzam0BcVeAEMBESEpi4ui/crRNqmzOQUil0OUSwk=;
        b=kpYznGokiRZSPAvIY2gKThiO+F9M7Eb52o+J8qXAWDqJSMiVrWgfRdFttHW2JnBlS0
         u32uv6sCFVv/laLMIZJY8IxRdHegVZ2V6U9lGhEWgrhIrLCDwCPo0/NZMKw+LO9qZsol
         H/YZWuUSu12yHRY/yA/AQeeeEtpXWDZrpVtDRr9pV3gf0q7m1y4RmzVHExau9WvfYv00
         LRDZJ4aDH8f8mwH7PiwmdWSo59zPvMzdqXWLaPxfqBlc0Fwil+axCDu9rFMNuIfnVhyk
         KrhC6zWrFLrWqYDHXs45X/5lJg8mGPiFSGr5ZxoPolQnpF8juk6yae63Iz50QLEuOKKE
         JCGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QrNeSbr2;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311471; x=1754916271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JymBnFbChUrD/Nn/LfeNQ2Qchj/Q3VnvfEcy6VFqUdE=;
        b=OrtOwDl4cM6uZqG2HYgw0VS441SEZwH/IuWVIq3cXorKkkG3e5waMBwfrOXhdwh8uV
         zVEQaZGXNcq3j0lJifXjQwZet2vM3UvNg6y6eO2/LsNRNkwAw/XvwhCKGln4NZApeq8F
         MjD7IPyJ0oB5jFaGwMSFUSExzgD4ejNtsoCjDmVIEq5Vn+NL8XJ4LZ3jl7rVbcusBagI
         3/fZRbSvKiDu/FGGQbhPPU/MIy8WzuLo6XhovaZ5oToqrpkCaJmVqxnr0W62njFpKb0e
         G7RVbb8gw5tvc8wyss3OGi8u1Oa2FuW8TahiqyzxGdANpNzTLbEm1p9gBA8+wq8HYeq8
         yoNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311471; x=1754916271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JymBnFbChUrD/Nn/LfeNQ2Qchj/Q3VnvfEcy6VFqUdE=;
        b=tySXjxlUvEuD9ij8zem8zveH0RvzX50GD/+MIvIkuNH2o3bhamBWcuM31sNqUVDEAW
         K9IPLMK5CemaSKNpgpBQ6l3u8TRulsXJ+GbkFk4IScJVdHWfglCQK8RvkzcUxVGxftoM
         amqUAVtnWfwsEe7XnpTFu2F9PXRMb5KpYUjIBkXmO97EXTZvfyxIz/yUQYPkcekXu/zH
         IkRiK1aFKeXkiCEfjWq+gQkV3wyU8N5TSvBq+nxzWxQAgI5N89UB7JpoiIaOsnctkRZj
         dFEXkrTeqzdOPKgC8/B4Oz556CPcm6FHevF92lY9OGYYgPRG+G0cJAVyuFeFnai7fGRe
         kTPw==
X-Forwarded-Encrypted: i=2; AJvYcCXv5sVFR5yDirQrPMeahTqLCHv9kv7B3HH7FhRrR2rNnb1Dnqy3K/bv4VTd2o3oIASNr7AMEA==@lfdr.de
X-Gm-Message-State: AOJu0YwIdhOrS7EC6W44pnRRneYaNl3avvl18QB1xvkneRDwjtLC+5SB
	do6LDOWt2zgw7Xkc1Vmo7P44RbtxzwCnazEtpfd71rxiq3OCVHeY19DD
X-Google-Smtp-Source: AGHT+IGhvBMpi8eeRpZXSRJVUJ7TnvWWDOMD2FBXCyqhA0qcrADmvzgnOO4SPn3yUrFaedWBGDSOZw==
X-Received: by 2002:a17:90b:4b4d:b0:31f:a4:8bfe with SMTP id 98e67ed59e1d1-321161de09dmr11703742a91.7.1754311470749;
        Mon, 04 Aug 2025 05:44:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1fZIZAaxHeRL4EXk0L6B7/SOjktjEg6BpYa626S48XQ==
Received: by 2002:a17:90b:1993:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-31f90c4e13els3666849a91.1.-pod-prod-05-us; Mon, 04 Aug 2025
 05:44:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnF5DGK+6fbWMJxCnG7m4NLUUvv/u/Sd4JqXgf8wXK4UBy58SSXtsjGLIsjsLCzsACV6YbuZrz9wQ=@googlegroups.com
X-Received: by 2002:a17:90b:3e8a:b0:321:3715:993 with SMTP id 98e67ed59e1d1-32137150ad5mr5700294a91.14.1754311469376;
        Mon, 04 Aug 2025 05:44:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311469; cv=none;
        d=google.com; s=arc-20240605;
        b=ljaaiBeUCXgMv9nRIGbukhx0yHDrofoVUPQTXfDIZSZZ4zknuq/ln7LXgtmuCUVoQf
         Gi1rhz4bDJYoCkNeyHtN1aRyx9ehnfhoW91LdE3TabZu5ocQgC61AVDepdKPGKnv0SXu
         ASYU7Jeq9H94aTyxH1Z5RsGt6RhPje2dyqSy7kObsdkxj+b1YjH6mvBvBmeSAY0psg20
         RL5KucQjR/tzwl2cB3HbEFysMUM/FaA37krcF29Og4sQ8raJUFwxn5NyU6l5wG2TnUoi
         f0QKjvQ4IiWfNujRAyO+aiyKpKoqIWlZdQdp3froI98Cn9af9D9nvFPuQLBrct2ZqEYu
         Drnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TkPETycZvdzl425XaQeEjwXwnOxHyWl7Qf8kQUNymVE=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=jbURNU9rhpXQEhkc1Z8fB8m4epAL/aXVBQ6vPMX9edkYoSWva9LNdUBPd6Kl4oV+Kq
         +0lPxrjFHaeYcaj4pJemqITyE4evyUXkVqnBi2zuQ+AAmYl9dtfjDt5W7RrPaFlvVKrp
         zuSb2Wl+0dnEHJYazZa+fAlmyG1YxbKT/LVHceKjVc1MSI2RTnEvZyAPPeksh7XTq87d
         tXhAf7ahRVFT17aEPT+FeDWmlCahPecNUgN/izpExi/ZZ8OTPsq38aBUyld+/cr8WD07
         tzaXwE5Nx3QER3TFiEIdAki+HPCEMkCeGCfNU2e5NF27gvGFYzFkamxJo9bfuK/PaYTs
         ov+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QrNeSbr2;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32102a5c9ccsi289343a91.1.2025.08.04.05.44.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 91E81A55869;
	Mon,  4 Aug 2025 12:44:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 16A0CC4CEE7;
	Mon,  4 Aug 2025 12:44:27 +0000 (UTC)
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
Subject: [PATCH v1 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Mon,  4 Aug 2025 15:42:50 +0300
Message-ID: <5b0131f82a3d14acaa85f0d1dd608d2913af84e2.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QrNeSbr2;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
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
that memory with the appropriate unmap function.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/nvme/host/pci.c | 18 +++++++++++++-----
 1 file changed, 13 insertions(+), 5 deletions(-)

diff --git a/drivers/nvme/host/pci.c b/drivers/nvme/host/pci.c
index 071efec25346f..0b624247948c5 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5b0131f82a3d14acaa85f0d1dd608d2913af84e2.1754292567.git.leon%40kernel.org.
