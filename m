Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBQPNSLCQMGQEMICSZNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F8D7B2CAFA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:39:32 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-709e7485b3esf2702996d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:39:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625154; cv=pass;
        d=google.com; s=arc-20240605;
        b=N1LKhogBEx7z6H/GEuyDUXk2X2boglLyIzJ2aGNbE6eOMTs4svz9QvJL0Gi5F0E2B5
         aNWxeNCK5f2sD0v5/1q6zOzNrmL9cqXZurMyBHpx1pKr24mGqegv0+cn6dLv1HmIZ7DA
         Fm4YtzsE4gUxfYupC8TggHhC1IA8xRH3puuwqy6AFiDvDrsSDGf6V/tk+NkGWdvc2bTt
         kwaFb9jvNafkXUlq5B9F2eY06+YwNvBIhgOB71WgAIriOJkBbD9dU+X9zQoJb0R/Ivhe
         RA70hHcaIWn+7kF62o83ydn4thcG/7nQUklkrmAm+KXm8kVXbIzApCjuDTlkuBG3bEV8
         T4uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=RfXni/KNMkB//PiIjyXZdxCddrDT8mPqO9FIq4GHKAo=;
        fh=dpUwmD6aY0IMa3CuheT/OkaHePdxjmM9L7Sz7gFbTJg=;
        b=d3JaXhR4/BKIJlVZe/9enwah2oycJQkVxaxoNGSbkP6nSfKlmVXdUGzIePpgpBYGYB
         LIqV02jIqyWsM9m7nL2OhgAF70fUStYWPIXZWYw43qV6tY+pypWb+B1JgzEShjG4LJk/
         I9CUFOC/qXNKn6YNuD+EVJ4G/NVvaiy2CftRC9RVFm58cm+3IMdBsUwdR8fpH0tn9CEv
         DYKS4yaxKbRaYkjQrY6i22QzkJ9NpAGoacg7NLoTH80An06g35+Aqu/aMrfjDHXEyAR3
         mvtbGpoWbawTOGyRKWO7w9ZI8tg07WLHVeN7m6ISKvII1aN8BQZxYiTyrP2oAl6qVJvl
         aWFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hP0G8Q00;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625154; x=1756229954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RfXni/KNMkB//PiIjyXZdxCddrDT8mPqO9FIq4GHKAo=;
        b=pIsjJH0wd4xq/A0g9tgbGEYodV2omneALNoTcnsuV4+BdpB0YCDDVXOEfUn7QMjoKv
         X7GenPqipKlkLIG7C9HSEkwnM5fySTbd2BF+Nd+1P5Lw/cmZzQr9kJxX3IAM4y4ar3r+
         /eASzYpz09bBkh7Kocaxz0N93d9dHomnt3wUF2bo9n7ehoUAV/pBztaWqEB2UI8hP+EF
         SGifFm0aBJMlDtw3v21gUuCCSeaHxrjowgcl8AsmDW+PHe0i09XAZcfLHa3UcJGmbjk7
         PjC1XPmATHqC6MGTG/IEUc/UJYQuE/E0izm+gtqI5BEqQkK42nuWdTTknWpRJ9/kGYqz
         rQLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625154; x=1756229954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RfXni/KNMkB//PiIjyXZdxCddrDT8mPqO9FIq4GHKAo=;
        b=X3pl/0RjlzNQZMrZnhqs11TXJmysEuNJy/gp6meuILaiP3E/5tyNvwA/G7X6uXs9/I
         qr/wvbYtoU51g+iDwjmwu6JHnqjZx5Q0EF6stvS1xKj9n/APqu8SSb1YVDtXNmh7xgms
         LLEpYcwTUGuCGzNayFAvCB0yvkPHYqMfyqrdaBdjtylbO9hmWqSbZYgj1LCfPPDnHrYZ
         aOSnEAeIr8IAWYbDtWSeiwhlZk39uuQmbACIzka5ljcQohfv4tPV6bzhEqM9Q42Q3VUN
         DYwtLKxwe2nuBk5lKCBpzj+o7j5/MEP9YWrRCgCUnxWnCONtJwEM4FqXCufBlkUnVWaU
         POyA==
X-Forwarded-Encrypted: i=2; AJvYcCVRpsyRUKpQuwLt81dGT4vXYaZ57ZlylRZQGqdqAEd+G5ttXuGpbl9M9oXqSZF786hUzSE1JA==@lfdr.de
X-Gm-Message-State: AOJu0Yx6zls8PMf9Bfl4lbTXBp9cSShtlXZ337oEWxmlZ5VVuGcixISI
	krTX3Ea6UgnPCd+gD+if9WT9Ze/HuCIVpRCUf51MtCE3ojBWzhQlz2Ss
X-Google-Smtp-Source: AGHT+IECFBs5DVStEs4uhcd0pwotOwmNyjfO9iZ+NzfhK/NjIMacclgNgmaXW/ysVnOUr3puL8ZC3Q==
X-Received: by 2002:ad4:5f8a:0:b0:70d:6bda:889d with SMTP id 6a1803df08f44-70d75e036cbmr2835306d6.6.1755625153987;
        Tue, 19 Aug 2025 10:39:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeZ/ohAgxMj4vBtd7toMBYdjqpXRVcCqA2vZm6SdUN34g==
Received: by 2002:a05:6214:4c86:b0:707:18b0:de30 with SMTP id
 6a1803df08f44-70d75bbafeals483136d6.1.-pod-prod-00-us-canary; Tue, 19 Aug
 2025 10:39:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJRhgHePeHbN1O/2F5sKiNmszW27Ta8H7SA7DmscJ3mHAxNf6WIK7UYgFwki9mPLOBkKgNPIDYwYA=@googlegroups.com
X-Received: by 2002:a05:620a:4096:b0:7e9:fb7d:f32a with SMTP id af79cd13be357-7e9fc7dfdfamr25568685a.22.1755625153119;
        Tue, 19 Aug 2025 10:39:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625153; cv=none;
        d=google.com; s=arc-20240605;
        b=VxBJeS24Z1NWXTgXbMZvjnXnB/Hj7fAES+fUUoeZhjNZvm7oaFYGtszug1hpFzqt7Y
         cN9GcJGmeSnejzaqrFpE60VTLZHV6w5ihAXQhvosUghCSF9T1iDPcv9inBwvbKSTbW6A
         otwcZpUGbRRaXcMMGeiJAZMseA1alskaaJxHKBOoMMtAJQKWxM8EPC5kayTPmlXo1uV6
         DJKf4d3F4TgqNvNejaEKFjeMeFOnSm1jwiKAWcN08UEUyGoGMye+I/gjIpjUpXIK368V
         hgyNej3CwQHv9cvnQ9np3vVfzQ+GYBwR2qPmeA+izm1LxgsjwLGtQXd8yuLXK6iAm6nC
         C/iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o2CfBR34rERHeCycfJu/oeNhZ6WULnoBhGEgp0otVxA=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=JaiKYXyp2UjZrjrA6Gx/7ARMzppbEFQlgPfeg5LpgM/B7GdH1dDet0crXGR1T6Jhvx
         GjRBIhEBIL1ckp9Av9Yo1+8p9Ncc/LH0+lljn/4LTpBWX19B/hUibSRHiO5AXPThOo45
         Fbk3jChUo5hIv3FvkUD38EhWRG2oX9lpl8EzPOHW/BBrvMaErf/j04XjoHfTVSj5sega
         aoHbQqRHomKXgXBhktlSt38ss2okVG15S0zJVg+YhRzUj8/n1bUFwyRdFEIpDQqlCgKF
         cWTMPTWqHr5ix9a7xNDytcRMOXnzfKbD2mwoD17Vtwv+ynNPV1u1PsFVdAjPwteLWIrb
         /3oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hP0G8Q00;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87df99671si40987985a.0.2025.08.19.10.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:39:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5A73A61437;
	Tue, 19 Aug 2025 17:39:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A44ECC113D0;
	Tue, 19 Aug 2025 17:38:59 +0000 (UTC)
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
Subject: [PATCH v4 16/16] nvme-pci: unmap MMIO pages with appropriate interface
Date: Tue, 19 Aug 2025 20:37:00 +0300
Message-ID: <545fffb8c364f36102919a5a1d57137731409f3c.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hP0G8Q00;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/545fffb8c364f36102919a5a1d57137731409f3c.1755624249.git.leon%40kernel.org.
