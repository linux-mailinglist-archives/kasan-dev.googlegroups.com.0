Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBHXO63CAMGQEYBX5DJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97B9CB26214
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:56 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-244582c20e7sf8875705ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166495; cv=pass;
        d=google.com; s=arc-20240605;
        b=jLtbchiDBGPAYwV+ouSwKh+daNe+Ui0GbgLY4MGK81HwZaCg/s5Iqi40WB0i+Z6V5g
         70r5AQg2hYG4M0jMOsj3LzndB70aPaaJARZEI+AbCmwheEeiXylYz7UzeI4NsOQCBZFO
         MrESP74UeoZ58cJbjhRGrGzahYov7Rjrmv5zPCu8A1XqIx45oRwoSN+fOMkm0JuoJssy
         eX2O6NbJrhjMa9tdbzkKnRu2BvwyAwgvuY9DCZHFx2S4NBs9DRbh497yR6GUN50DrltY
         ITYmsZg8Dl8KnJc0wUHVVzvP3QEqU8ofaGpejLMpDvnOTug0Ur76zIZ2/rZxsBbRr3EK
         3X/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=En4p1xlX0CQVYj7ESK9bsGL79rZKppySxM8be0YV3ZY=;
        fh=K6neGIseCo0lJFKu/q1N3yRJOlXVO1IIN46zLzcfNhc=;
        b=SV7PvsG+mjJqpYi1jrrTvHL4IcQfgjVrl5P2iBakLhuNuEbjEDqvmfWfYMFkzw/Gmk
         QzVQbAqLuEmFZ7m1TyhgNq/m2gffbCRzs3QOx/QIorchFpjAbrcfkX0E4YetYV46/k0b
         0UEHrg4mae8iv6XCfkFl++rY20zGcj15rnt5IdR+FwcaB3p+HFbzne2ij+WEIWvgBf0g
         uwjdVfW1ENVn/0Trp88dZ6+43YKYQ+rJO9vbu1akosCNAkS2wJBYuEImxi1Ag/Khrm52
         /4/+d7gCg3OEP5lCzCydpG0CQ7Dt+aOs+ak0VfjoimnCxmLyzmCne53lpYc8ZRRrzlZB
         mKPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RwtkFi9v;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166495; x=1755771295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=En4p1xlX0CQVYj7ESK9bsGL79rZKppySxM8be0YV3ZY=;
        b=fFVkPMqMNIIEnGouyFySPxmutU3f92mBcFbxo3ND+BO6uln0vlLauf0v15GFfT4QXi
         teb0ulaqeWel9ZieRpYDGl4gJcFqCJSPxM9dIgf5jWD+8o+cNkYEGF2C6CMF5qiGmDnV
         mIeAvFzyyXryR/vB5XquDVX/C7eus/C/NV/VVmAuEsR8rC74p1Dc15HwKPd6SHFrKxyi
         W/AqBBnkdmbNJR2ewZjubyQE7NkIZY98xrVyp3IowvzZZljRKnTYaaGfXL0Qk1MXXfbN
         rnh5MHJfAld1q8R6R7j/R2ExWCcaA9hzAo64QP1r0I0EHVMvyySm7/qfLagY/UKfcqPY
         uYpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166495; x=1755771295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=En4p1xlX0CQVYj7ESK9bsGL79rZKppySxM8be0YV3ZY=;
        b=dyNlpnMdFTgxCLskgZSjevcBC9H7fkChBE98lkq1Nkvw5pjuJ652+UGu4tIJpHGGNN
         xQIcGZGo8eetsTzLrPb3Qb7xiIJBWGoV4p5YmPd12zJFGOLnTvk/cDSwpt7R7Ra88j2z
         E8HhW1XZZHx9Sh9cBGKj+80cf0H8SAn/HPk3ESTCSnbsDpA9Dz7H3wDQFDf7eIu2Edie
         UpJ7HJ67sUjxT5K/F9MxR1fAYPZHXCfT8DsarK90ia8rDoKKm5hpsOkHL5So1tBzAyKn
         Y/EBvcIEJDpnO8mR+vjAx+AcWIRUPsnqyeQkkLR6Ldiw1qg/8vK+/N5FpnVJ6h+mx8bj
         JP1w==
X-Forwarded-Encrypted: i=2; AJvYcCXjOW2Qto0a8IktMWZYt7AJ6niSoR7U7oHjzMC4bn0663gTqPQRW47eNWiqQA/6K696n5EwmA==@lfdr.de
X-Gm-Message-State: AOJu0YwbFtGDMfBoHedLmWuzoWMDMT3NtMWbIYhTOeBIKaM95OI59HVZ
	hc26S5EFjY13q7BqgP2vyvvHaJe++lFVHVo0lSrojaPwUrwZZGJEtbCb
X-Google-Smtp-Source: AGHT+IHNILvJ6uQCIZM8x+RNKdYGBmPwKPgkwTXgtztXBAM1azbGyZjjTUDGy2a8Cp7mnp0moylajA==
X-Received: by 2002:a17:902:f78d:b0:21f:4649:fd49 with SMTP id d9443c01a7336-244586d8e16mr40590015ad.49.1755166495114;
        Thu, 14 Aug 2025 03:14:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc28O0fgI1w002lrrbH377qjP3bNC+6zS2YGoXM7CIEfw==
Received: by 2002:a17:903:278e:b0:23f:fdbc:de3c with SMTP id
 d9443c01a7336-2445756c53dls6538905ad.1.-pod-prod-07-us; Thu, 14 Aug 2025
 03:14:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrX5VvT1N6mXOdMcXjXKSG4DUnS/q0OeZA5of+mJO1XNfsADdBZq/6TeWl8NEBJNYY0pjEqIsxhMA=@googlegroups.com
X-Received: by 2002:a17:902:ce89:b0:242:d4a4:bba1 with SMTP id d9443c01a7336-2445868b014mr40217215ad.30.1755166493720;
        Thu, 14 Aug 2025 03:14:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166493; cv=none;
        d=google.com; s=arc-20240605;
        b=Y6sR5aH02lcPbNcgxKQHY6JmLivjRuoJDcwKZqe2csSqmMjkTmWOfMfNbd5UFY9n+M
         ezd18R9HJqqByrhQ3oLrzurxDVgnlTwQne2AQYj03QKCZBoIhtkzPactWiia3zFG0qZa
         2hB51j+UzQY+8OkuPE+xLSbvbOw6Z3WvWXLC/S8SwFiuRey2O9FqmpFgl3Qrtp4eS4/0
         OW1VoeqSXvfVg/jWkxJKoniMsor82W1NHkws2OpBtbnJYrSNcB+/IDRDKaG/0QohASxh
         Y5EKlvawlM7RcvwclSNGnJyr8QR0OUwBF+xcBihMu++1Pksa8OqAqHfZ+N3TaZY2Gw16
         E3FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o2CfBR34rERHeCycfJu/oeNhZ6WULnoBhGEgp0otVxA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=A3bRE8qgcJ7n+SEqMdshBY/0S54Hi5F7itNtvlkuHCsg1UFFSOn9Pe/8+XcfW76njV
         OMl/caHAwtN2eeP3FOqZGlwg8Awdtt+doXNHcUE/M5PG+JriATWSknrA3pg3UWdnnrPa
         NM+9+tXNYFVlIiOQ9/5+8r5sz9bKYsV1qMxhKUna6tjQQ4188YfbmxOPlTAgmFWdI6Oo
         GbuYGP6gnGmOeQr0i9Phn/jmchnBjX67ax6ev5/BkUwbrAblL7NDiN3uBVWD7R15qXLb
         D8QDpy8YrSk1hZzJZfi/s6lLO4SWC8fcK0MiJyk/MxjcpG0CaVHLiUY/FghHG4zfWXnp
         Rtlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RwtkFi9v;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-243030b5d21si2265135ad.1.2025.08.14.03.14.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8E68E44BCF;
	Thu, 14 Aug 2025 10:14:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83831C4CEED;
	Thu, 14 Aug 2025 10:14:52 +0000 (UTC)
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
Subject: [PATCH v2 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Thu, 14 Aug 2025 13:13:34 +0300
Message-ID: <a097fc4adf58836287d451db6eb4527c6664f7ff.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RwtkFi9v;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a097fc4adf58836287d451db6eb4527c6664f7ff.1755153054.git.leon%40kernel.org.
