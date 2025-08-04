Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBKGWYLCAMGQE7VJMX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A6C3B1A1C6
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:26 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e3e979be63sf84871225ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311465; cv=pass;
        d=google.com; s=arc-20240605;
        b=QbSRFsfujBxDSWOyOY76uKs52C1Kpn63al7RdHISg8ZTLg1PI/5nn3rW/SMN3cExpz
         1j7YfVc99vW1zVmz4zvIKmrVJvq1qoS8CG87pDbw+EsX23MriKiAsKt8vqBPsMIjjNuv
         TvQLOUyEX+okNQBDiwRZqox1Lpo2zgsb7MkzJ2bNVPjwPEBU/6Nbw0nDk8x63zNlA8G5
         DwMX7hQeSXNFY8O0GpB/c0qDMAtDqH4aYGlkytSzLK91arj6KAYRbEakhil1y7tKCSws
         15lvV8Xs5chExvHMFJCpOTUs095CWlIP8gss+e6LVEnpM8G41CUP0Fjg68Sq6C7+ApaG
         CVFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HplGduc3CIKqdD1lAcKejSzEiY/Q/kxa9L4EaFSKM68=;
        fh=awR9Rthjevci065gyUZcDzXvbLFfg6K6UcpDEL6mO00=;
        b=dHXk6x0Zc2Nh08lAq90LDUyXR7vyCkucTf/aYZwYbDN+Dz7oWLYuq6pNOClI+sLB1D
         UiHF9DiIkLjoEvopS7u5NFpZJZ/qVWkJt1ZF+AeqbU5AJF1vPjZkrn/2gTEBMKbbFLPP
         Dl2LtuhYKQgf6L/0TLTYWjy73/TkD3AAPKi13+hdN5waFGVM1i9EaBg0UbIpGMDB3Frg
         HDt8CP2N/8ul0eMe5ssZbcrCUpbxN5ZVKr9E4AXIacQhBJ9Cdddf8mCZ7vouYQgJqGmF
         AnT4WYUxC9tp1uhANNYYU3GmyzfeFIjuYwiHk1L1H6TrJwFHpcz/6wfc3n34E8rryX2O
         Nu1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CEWxy3DQ;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311465; x=1754916265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HplGduc3CIKqdD1lAcKejSzEiY/Q/kxa9L4EaFSKM68=;
        b=Duvhh3WEWpHQck5ygFZygGCt6vFj99Bqb13oUtqm0up9tFG9S7KKdTANvPGfYL9hgz
         Mo7YPUZhypEfmVVl5ZvormGsnMNmqCdemHiw+ObuVnEqsTbJVUErocMmKCu1aHqQEuUU
         qeQ+Jtip2LjkkWqa9SgE1j9kpUo5tGvRX6rH+4xSBuoNpgErAEbiIjSTXfY8Orw40cqB
         5r3Fzkz6JF/SZP0u0wU8CRspmPWdRy+VaHpCTAEBDhXkbbFd4sUDSpPPZorccttLzC8Q
         HuzYijkTYTCol7gONbML/Q+5FHPNZBW0YTxBG2diNC5d6lQ2iFVK+4lVTDJAR6mwrkKm
         UpQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311465; x=1754916265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HplGduc3CIKqdD1lAcKejSzEiY/Q/kxa9L4EaFSKM68=;
        b=bmKjGLcFu5P5sgnrwPbU7D1H1Dx+MxFCvpk6/TeppEtOiiRBwKaFHjZv2MMkrFuJ3P
         jTeHwstFovbt2O9BbyrhkKiTBI+8w4CwFAEx/7DaO32cOnm+svyxcd4GTureEaTv6iff
         JIB4JCg9cWsqPCqacG4SRueGqIv9baJvz+/GS7TsjcdkCiXGlG9bXy96BDoaqt7jo9Qc
         ibD9NI2In9x2S4skTIqgBLIFfAXsVSi1RieTxEAHD50DZujOgGpG2h9/yhQqHJvVpwbL
         5IpW0DaU9ctuWAvg+t69qbIUovbJX6yuv1yXpHE+RNLBA2f74wf3p5sjyL8FMPvVDyGm
         82kg==
X-Forwarded-Encrypted: i=2; AJvYcCVfE6j+ppMCoHqnZGnVkH/+uZJiT//a/9c/8QtFNmDbOAYidYkGPHuHO2UYST7vFYL2rU8UVg==@lfdr.de
X-Gm-Message-State: AOJu0YzBUJE3/+bgZjDaa+QBt2Jy1nJpjCneAxfLO1/Xlad71pRsdvyH
	EOzPmTEYrCQfa+OZ6DyttJPZq6sOhVayw5RT0zp7K9zapJb/Kd83cFix
X-Google-Smtp-Source: AGHT+IFXa6evN6RPd9mSqPyc5XzwcIFiakWBAOVw98fT6U4r2Gu0ZuFo+T+vc+KgrhVp4rTSja0/AA==
X-Received: by 2002:a05:6e02:2382:b0:3df:347f:ff3e with SMTP id e9e14a558f8ab-3e416116d8bmr172210455ab.7.1754311465061;
        Mon, 04 Aug 2025 05:44:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeQVj2xkEJ90IwjwXXujZ+RJjMbsV21ZhZ1l1j4I74AVw==
Received: by 2002:a05:6e02:3801:b0:3df:1573:75e4 with SMTP id
 e9e14a558f8ab-3e401c465e6ls42851405ab.2.-pod-prod-08-us; Mon, 04 Aug 2025
 05:44:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7pClNlYk0ZYKof+tJCcp7XXCSBdgzAgxcDP7xABA3kHbqcjRYxm13PePJIeVqPc2hrjJhVrULlTA=@googlegroups.com
X-Received: by 2002:a05:6e02:2706:b0:3e4:1082:a91 with SMTP id e9e14a558f8ab-3e4161099d7mr162367415ab.3.1754311464046;
        Mon, 04 Aug 2025 05:44:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311464; cv=none;
        d=google.com; s=arc-20240605;
        b=PirrC5CfILBMm2ebYAIxwTyxjT/kBuHJPb+VUwiDC2Q9rNTiZgiGAk/b7wFfd/20Bq
         y+w9v/HL6sNfHWRQrip4QfsT54wXUutydTlpGB5QtgVEuok6ltnUPOvyDL2sCwjUWVBA
         ZUVaIB30EqnxdcMyeAv3sVghAEUoV4BXAdkkYABXGPALw3U5bEgQkV5Gxa1V6HnUDAKd
         7tVaSBTyiIe3oUvH9Xq+6ktK+ThV94mRM4S58/f596DxN6BWgVIta8Dohv/wIgU1iN+Q
         bjdfT53p4GY3pSqXvYT0QFrs4U2eoZQShjyKKzhtWpcxJQoItXAWQLQy6jYkxGeGn7kv
         XumQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VKxnKLgBXd3JK+l9/qE4iGFIXvnOntNCGlyh9TtKTfs=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=EHCw3TnGPdPcRBFCXxTkeOnmlxEKUmxYxzv/yf1wFz/jGFayUiI1R+DCkZvM//Zz7h
         IH+4Y4CGqj4smk4z/lIfc/Si+bWEnyvnmhYpvgUXGK7QG5LwuCfDOtSQo/6Zk7WMaD1m
         D2DbnhKtUtuqYXoaDEOnjs09qSvswl69G3G3qOif4oNmYjqwrpgLcgmqPnW9i5VuGq9C
         JlpxSb4iuhKxXC+YXODRKHdosC8fy6IKGeg4gDDCW2uzZgU5ArZMUwMlDwijPlf0Z756
         Qb/9FgO+3p8w0nBN4AKM4q7ZZU2mqPsFr2huAjAoU/Pjf3GkSO2nIci7Ym7c0+0fiIVC
         lgAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CEWxy3DQ;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e402a13343si1718705ab.2.2025.08.04.05.44.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 91E5C5C5F4C;
	Mon,  4 Aug 2025 12:44:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5D115C4CEE7;
	Mon,  4 Aug 2025 12:44:22 +0000 (UTC)
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
Subject: [PATCH v1 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Mon,  4 Aug 2025 15:42:48 +0300
Message-ID: <9b8454a8a24ace186a22242e218e4f4fed103fdd.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CEWxy3DQ;       spf=pass
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

After introduction of dma_map_phys(), there is no need to convert
from physical address to struct page in order to map page. So let's
use it directly.

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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9b8454a8a24ace186a22242e218e4f4fed103fdd.1754292567.git.leon%40kernel.org.
