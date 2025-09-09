Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBNWXQDDAMGQEYUUCNDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C614FB4FCF2
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:27 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-61bd4e3145fsf7044452eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424566; cv=pass;
        d=google.com; s=arc-20240605;
        b=IzO9WmN2IheVzbj8PaBEm0uNCPjSE1/0oFMRZ0gK8EpD1Z93N4mL2zHToWNreLNTUX
         s8743584W0Z/ESTsNxCLu7YT3U6GeSDLSjvw+K93K3OP9Bm5LD1iIPfj6MuXFi6SkJNn
         yVDugsxjCujpgeUwIeRKQq4dE/B6RAQ+3XeFI7VkZ65k5jyNywvqzQa8lyRLpxXRHjmY
         221YZDmbL4h3MqppFKj9CkSp2xZYZ/jG54anEgl8OeJpSUWQNMmElt8oa9Rf8CFcclW9
         wjldYZeTuKTZhsa16cB+DQgalIWFuiTPi16Zk03YLzU3K9I+fk3Le2j/Y1UEF33YOucM
         /Cfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qg4iyEljnJ0D2nmtkKv/u6/taINvpxd4lyMqvQigqso=;
        fh=7c1aR8aPMaVZRfoRgrfZfafv0Esh2+Y0fWTy6+deX+A=;
        b=GVlzIHnUM/ygXg9YkoXZc2At2ZeqZJq9gRn8tZ2snD1HIQOJGM/3XJYOJDFeVbrd7s
         3O6gytyLa5vUkWrNscd7YUJSiBA6jubd0FFdGQ4/QwDPtA/k9J/XS/ysdPccJ03rKLbY
         PplG7N/2ZDhI7KwLUY3EF0CwIKAGNLnfWiMDdKiEXzkPhMTtb8gcpLpgJpLhe+tMjXW/
         M3qB8tiBbvTjz1iqy8Fh+9aHp5x2B5JOt3axL1EyuCYzSTqPEIEpfr7X3UFnE8+f1+9B
         +920Jny1TS6ZXw5m9Zo2allIw1Nb7efKt3d8NM4XHISjEI0yBpJ0hXimhiQrAIQoUvF7
         nAjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jsG+qsUJ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424566; x=1758029366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qg4iyEljnJ0D2nmtkKv/u6/taINvpxd4lyMqvQigqso=;
        b=rGxYswPyRdw0uOYcQU5Xw04s948EjpBc6YTeUqjgGbtrVAOuZp+I79impRf75k9WSZ
         8tqmdBqGdARYfFOLFVR5juc66COuoLwY7Pq1ltm7m5RwVg7hpVrZ8Xr4c1JHK1FdEHD9
         zPZD/LRrGEbZrwVsgu2AmUKRrtz5JIOBiASAylVje3rNtBpVHDekLGEEQJG0D3SuTTAE
         vvSsRbmRw6+aTsl38W/CsQ4f7NgkkLTBQ2am3ks4rfSMGHf3xEdduep11dS7Gf/kkJb/
         K3Yx4GC96MukULmLuBsT9qwYef7Lj8BvZ6n3O4MG6qlpFJH7PcLj55cFPBDWJ1sqdY9w
         yqGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424566; x=1758029366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qg4iyEljnJ0D2nmtkKv/u6/taINvpxd4lyMqvQigqso=;
        b=XtksEulgpXnLKxcdQiz4Vceg+mIM2gjWUoD/J1u1rwYMnVAHi4FWU5PcLhyjAbJm+r
         yL8LFJpYmjTO8NiGh2wsAFwB3naQUptCCCDTkvnnsBO8DgZStopcHvqeoHIWQT9Nh/DJ
         Ms3MJDy46ufaxsUeKNm49Z2ZihrnBghGXfrpNLWHJd7EpGiOxYdVgS0elirqpY9tvpJi
         nEnVKPIL5OZXqYwgRZA+rLK2owCN2RwTpf0y0PuG1ysONa21tr56xP48XUohQUA59eNK
         alYCMnxmIdZDB3BM2BZPvjJrPfKIE2UPNYWAas5PI2iikSQcLswp+mMbMRn8dw0iHRbR
         F6Vg==
X-Forwarded-Encrypted: i=2; AJvYcCUili+uMb/4qPZ0cbLu3pnl9b7FmC6EgRjSzCE0O3FZSnqw08av2M8SwLBuZXjDGQN+uXNpqg==@lfdr.de
X-Gm-Message-State: AOJu0Yx93+QjpcTB4U2ZInL6z9ceiJU3qw2UkeDWHe3lzibBxEsJSy7q
	A22dKvbegH7gfBn/NB7nkrxdNtBRAW6OgVxr1xoHhuwie7u0vnOnKM+K
X-Google-Smtp-Source: AGHT+IEuCa2FDCaCg0+FrYvXJChokc19ZXkBRtOFrdybkJDH87fLHFlvgKFLcwIk087EGGh75LOOyw==
X-Received: by 2002:a05:6820:1627:b0:61e:1192:cf89 with SMTP id 006d021491bc7-62178a7f528mr5730327eaf.5.1757424566414;
        Tue, 09 Sep 2025 06:29:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxknljSv8ewJbT3wIvEfCV+5wi5XfjgWSmPtqeqcImfA==
Received: by 2002:a05:6820:4602:b0:61d:f8d4:b321 with SMTP id
 006d021491bc7-6202592fb31ls1336018eaf.1.-pod-prod-01-us; Tue, 09 Sep 2025
 06:29:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhXdh7vTbFKBox3KnK4hTCOE3kWM8/+XiGpSe7DL8BL8481b+rNYwFfNQhuKviFM0Er+cebRT4hIQ=@googlegroups.com
X-Received: by 2002:a05:6830:2b10:b0:745:529e:1d5d with SMTP id 46e09a7af769-74c6fcdf51amr4642909a34.1.1757424562929;
        Tue, 09 Sep 2025 06:29:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424562; cv=none;
        d=google.com; s=arc-20240605;
        b=l1Y4MvR6Vah6cyz41X4MIH18RSxqxDByIriB+OV0Ltk2KZbzA9Nmn5m9pj61XnYljw
         PH3kiJLZBZ/wyYbIB5wE7VVpbGpT002T7ZcNQ65fxvPF9OIMjuKWvQX+YalmUDVrryKG
         EgGNTWGi5Gy3nkQy/TCpNoBvU2JT4742pP4iKzpxaQR/iQb4C/GMDe6/GQz9wHjtVDKv
         VkGTwMV+jVmqD4sApnoV2nqusPaDMFUoF1AjGmga634QvYcwinPzT3kX2rTGpvhvwmht
         zlEaFcz/WoAOQczfwFtopdBmktEedJtTtjEOLxKEouCnKYLTxW/4coCFGdc0EgbqpV3h
         vyHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a5WY4Vqi9EWQquRRNalN/tM7qFg/VUudcPB5gYO/EeU=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=H4R9Q1xDuOa9UcSWa6Hp8aIDMF/1NtTUu2JjwGYxF4NjXGO7LKnXBsjJjUQOcT50j0
         goa8iCx69Faymt+Ys6MVpFWVYoG4+JAPVUSTojVxMbAIAr0iERR2+qKIYpkZlxoIsudk
         KGsHJk4cGGccQzZ5NLX4bftRS1L208Ct7IBIWxgFKbPjmjbXWggQnguv0kYrzmV21iMS
         kPNKeoDdCOjybPp2QcyNDUUYbm33jaViJ3dajksO8FEQiYQgxmgCAwShCafhNFj8/QFm
         aAFQtWw1+X0D6kbxsNsWNo/ELZ4MLmGFPRx4oR8B/R+lJrVNdoj0DHmW9qiFrFkyQAd/
         AccA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jsG+qsUJ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e78fd172fsi121691eaf.1.2025.09.09.06.29.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1B15F6022C;
	Tue,  9 Sep 2025 13:29:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D7C94C4CEF5;
	Tue,  9 Sep 2025 13:29:20 +0000 (UTC)
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
Subject: [PATCH v6 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Tue,  9 Sep 2025 16:27:44 +0300
Message-ID: <be35a070a883286f0e401f6746334d84a7a42612.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jsG+qsUJ;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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
index 2c6d9506b1725..f8ecc0e0f576d 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/be35a070a883286f0e401f6746334d84a7a42612.1757423202.git.leonro%40nvidia.com.
