Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAGG7DCAMGQEPQQZGNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EFFFB26E1F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:18 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-3232669f95esf1190984a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194113; cv=pass;
        d=google.com; s=arc-20240605;
        b=NcgvBbkbwYQKUR3p1X9o2TVCuyOU2RRZoYPXPxsyn5ikWTGN/x/bfu4Ul6yMb1D10a
         szHT60iUyM6adi+0jjqn81DveQ6+Vh8QLWFMcftxAuZNM163zkYG3wn9Qp+jFaINYoyY
         6UlkiPJKgaiHCwx/dARFF+3JaAyvDDYzEM41iVJE66MxNrgsBnCx3Vd6XCYYfZlZCR6s
         7l0Nb2kw+j+xnBBGPv901xWBDmNQZFMlUfkFlcQB2zToYTKAQZnSUQMTaUMCH3LMGak8
         FmVyR0mWys+JuskdSf/K6BhLzJv4E61pjQXsoX9kbkDqocvUjTGu72t+Cc3PUS9ei7BE
         Po0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4Y7Si3mz98B9yu8Zn8dCk9GdGqDf+T92O4kPdpedkyQ=;
        fh=U0nxSGX0Eo7Guf2+4CtV7MKT4KCdj0MgAr9DmTT6LxY=;
        b=B2yEgizZu8TULXiAsspCbBW4TNoA/eiIBZuis6UUtyrc8ECKqhmvLO7NdIx3kMkkKp
         sTjJYV1Nec19LzfHiLdowoN+wMADI+F5SbE/Ns7da/0t78kM04tO8fEAzIqkRd5oz4m7
         xhrXKMLIRljtH9d9WKWoH7o9FnLuAsL/qKBxYDprYFyHtmUTKDJtPp0dtnF8sGTwfEMl
         iMeSJ9ypCK95sIvMBOWWbRMmHxh24JlWuAg1U3bdS7uS2j9aS+6Zn2QvrNTdCT/1+IWI
         FmtaVSGcFZX5HYPRVdJkYzgvdB9/Xf8KSphFTL/CaMuybc9CzyMugWpaxHSyAEffc2h/
         N+UA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M2Mnp3BW;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194113; x=1755798913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4Y7Si3mz98B9yu8Zn8dCk9GdGqDf+T92O4kPdpedkyQ=;
        b=O9Zlo/AC6AhbJGzQmz9xLhivcKtXFg+6ihjGuyYdDVWnXpq6+4iFfIWI1VuJx6TEUh
         NtnSLGRyzm7G9a4LLQBmeaW1YK/1p+b/j0rkhaHFakIQIfCqhJc7KOjZdTwobKWlbwPD
         9tTSnENXSmNdnNRLRGwHBjrpX8axVea+ln1ILqn4B+QMnJISR+BU5nJjycsq/mOKA4aN
         jBoVoRy+9YIVJVnV+gR9hUOyKlatrDyB8z0TmPQ3Po6Jzq16x5DNjxGLHlOTQDb9lEc4
         iOIPpLVKSu0Sh7CKFk/id7vsbCxQ4eeLC2hew4Jv0SW6lxGJz9I/wvdhRcY99BF03cl8
         VwXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194113; x=1755798913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Y7Si3mz98B9yu8Zn8dCk9GdGqDf+T92O4kPdpedkyQ=;
        b=NArXZc32NKVgIR9MyMRbKeT+6VwQ3xYAZWMP8moovTkRHRdkgH5EuwpafS9DdB533T
         Q32f5PNcZI4KDAPgww7asnm0jlbA4v9nXKYMybpgxVz1yIMsX884AE94AZM1ZPm0SACc
         B5PDT1NvK0cTk5a5ZIj+p6/DWG0p2PggmjcDKgfI3yzxOmpT1cMArae5QBOhGzvBvVME
         ZgpvEYERGeIT/s2XlAHkEaubJbAnkRXni3KDm958JcKYth9jkWKbLXKgb6l/XHxF7vwr
         Zv0A0sTeKRSk0vtxxhkbUSkmixL19suLRWCthw2yKZxal7KwCHnwO8iM8z+WofTEG+Sx
         Frlg==
X-Forwarded-Encrypted: i=2; AJvYcCX1GbX2ezcj8XLvKt5HLcyGO6nNFSMi4l2zgt0rmIZm4bFEQDt9vmZJ4APTbDRFVBXW7XJGxg==@lfdr.de
X-Gm-Message-State: AOJu0Yy/VY+U0/SmPluO0L3GJN8tzASvUGwdOyXjKwNtJYGsfi1g+eYa
	yszg3cXaV94HwuSvvJn618vthRi/8ff4H793PrwZZ1qdoLk+yTS6CcdD
X-Google-Smtp-Source: AGHT+IH9uNFEXjg0Xd1DJE0neJGDXnwvZCKvPAVtvcXujWuTQMJlAKNG9HTbl/tVGrRV0maKwMT9gA==
X-Received: by 2002:a17:90b:5346:b0:31e:3bbc:e9e6 with SMTP id 98e67ed59e1d1-3232b2c6158mr4883292a91.19.1755194112909;
        Thu, 14 Aug 2025 10:55:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfG1TdcZCd0L+3Lyf9uHYrQgmo9XASx5pHgONPn7mEEsA==
Received: by 2002:a17:90b:344d:b0:31e:e459:4d57 with SMTP id
 98e67ed59e1d1-32326e1f42bls1136833a91.1.-pod-prod-01-us; Thu, 14 Aug 2025
 10:55:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVB/KgomZkOZSas6hL8ORNoMUMfrCXhPwPEvVLynAN68QT2fU4T2FZ7yDGvrjsxjECmje7/rHzvFDE=@googlegroups.com
X-Received: by 2002:a17:90b:5548:b0:321:abd4:b108 with SMTP id 98e67ed59e1d1-3232b23a067mr5516622a91.12.1755194111389;
        Thu, 14 Aug 2025 10:55:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194111; cv=none;
        d=google.com; s=arc-20240605;
        b=f8tHmGUyp6PK1zeC8CtkPdRajewZ2nAQCtnjOpAJ5FMN10ss/ZfbnyajHI/+vjaZX0
         hlqxZYFk8dmsN794dwbRs09+D2TxP3CMOMzpmPLdnOqupcogH0igjVUamAR2bICFoM6p
         +28pDREODRtLoX9xFBL5c0+PS7v2FGJ1Ow0YPQjkwI2UpeYS7oXBFAu4IPPpYFqmK8Lx
         pvouTY5RKll0UTgc2LMCnX2heot/Ztpx07SPeqrSlZAaLdMtWQGISednNKBYrjhy+0da
         YejBBQkicRsWouiAUwNveoKQZ2xADe0hQkJumvGugZOiBT2udHM0zPQh0mSsG6cUu292
         RK7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CCfmBvMQcZnHpKPeupg0PVl7hYfqXMfZSFQbxGlwy/M=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=ixro3WHcUnol2+DchPuU29hekrlF7hwUjIIzsbyqodJNsTNhB5ROy+ZfT9mRC8jyEQ
         6nWx+kBPtg0LaCQrJoNitGB0lhwuOSnsh/0BzLxOyZ3kWcRJdYC6epVlMS936kV0TFZI
         CkZzPqpEyZNSg2u1FEPNYo0YCSRu6k8s9tR47s2Fz1b0i5zdaoIMOENZjPaFvMElYSQY
         s5Se3lTnQrc109BUf5S0lKDte8sGj5zIDGJFJuZ/17vlFu/O0Ni/UNtOzwbFFD9cBh1S
         ma0EGrDTRyrHGL7FWXIPHH1Rzz926B028OOFE0y5XOxVdONGyjXwa+/o4L0mbubx/+fb
         5azg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M2Mnp3BW;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32329a63f40si81224a91.1.2025.08.14.10.55.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6C823601D8;
	Thu, 14 Aug 2025 17:55:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 765DEC4CEED;
	Thu, 14 Aug 2025 17:55:09 +0000 (UTC)
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
Subject: [PATCH v3 15/16] block-dma: properly take MMIO path
Date: Thu, 14 Aug 2025 20:54:06 +0300
Message-ID: <b82cf88cbe69db93a98bfdfc90f11121abb973cc.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=M2Mnp3BW;       spf=pass
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

Make sure that CPU is not synced and IOMMU is configured to take
MMIO path by providing newly introduced DMA_ATTR_MMIO attribute.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 block/blk-mq-dma.c         | 13 +++++++++++--
 include/linux/blk-mq-dma.h |  6 +++++-
 include/linux/blk_types.h  |  2 ++
 3 files changed, 18 insertions(+), 3 deletions(-)

diff --git a/block/blk-mq-dma.c b/block/blk-mq-dma.c
index 37e2142be4f7..d415088ed9fd 100644
--- a/block/blk-mq-dma.c
+++ b/block/blk-mq-dma.c
@@ -87,8 +87,13 @@ static bool blk_dma_map_bus(struct blk_dma_iter *iter, struct phys_vec *vec)
 static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
 		struct blk_dma_iter *iter, struct phys_vec *vec)
 {
+	unsigned int attrs = 0;
+
+	if (req->cmd_flags & REQ_MMIO)
+		attrs = DMA_ATTR_MMIO;
+
 	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
-			rq_dma_dir(req), 0);
+			rq_dma_dir(req), attrs);
 	if (dma_mapping_error(dma_dev, iter->addr)) {
 		iter->status = BLK_STS_RESOURCE;
 		return false;
@@ -103,14 +108,17 @@ static bool blk_rq_dma_map_iova(struct request *req, struct device *dma_dev,
 {
 	enum dma_data_direction dir = rq_dma_dir(req);
 	unsigned int mapped = 0;
+	unsigned int attrs = 0;
 	int error;
 
 	iter->addr = state->addr;
 	iter->len = dma_iova_size(state);
+	if (req->cmd_flags & REQ_MMIO)
+		attrs = DMA_ATTR_MMIO;
 
 	do {
 		error = dma_iova_link(dma_dev, state, vec->paddr, mapped,
-				vec->len, dir, 0);
+				vec->len, dir, attrs);
 		if (error)
 			break;
 		mapped += vec->len;
@@ -176,6 +184,7 @@ bool blk_rq_dma_map_iter_start(struct request *req, struct device *dma_dev,
 			 * same as non-P2P transfers below and during unmap.
 			 */
 			req->cmd_flags &= ~REQ_P2PDMA;
+			req->cmd_flags |= REQ_MMIO;
 			break;
 		default:
 			iter->status = BLK_STS_INVAL;
diff --git a/include/linux/blk-mq-dma.h b/include/linux/blk-mq-dma.h
index c26a01aeae00..6c55f5e58511 100644
--- a/include/linux/blk-mq-dma.h
+++ b/include/linux/blk-mq-dma.h
@@ -48,12 +48,16 @@ static inline bool blk_rq_dma_map_coalesce(struct dma_iova_state *state)
 static inline bool blk_rq_dma_unmap(struct request *req, struct device *dma_dev,
 		struct dma_iova_state *state, size_t mapped_len)
 {
+	unsigned int attrs = 0;
+
 	if (req->cmd_flags & REQ_P2PDMA)
 		return true;
 
 	if (dma_use_iova(state)) {
+		if (req->cmd_flags & REQ_MMIO)
+			attrs = DMA_ATTR_MMIO;
 		dma_iova_destroy(dma_dev, state, mapped_len, rq_dma_dir(req),
-				 0);
+				 attrs);
 		return true;
 	}
 
diff --git a/include/linux/blk_types.h b/include/linux/blk_types.h
index 09b99d52fd36..283058bcb5b1 100644
--- a/include/linux/blk_types.h
+++ b/include/linux/blk_types.h
@@ -387,6 +387,7 @@ enum req_flag_bits {
 	__REQ_FS_PRIVATE,	/* for file system (submitter) use */
 	__REQ_ATOMIC,		/* for atomic write operations */
 	__REQ_P2PDMA,		/* contains P2P DMA pages */
+	__REQ_MMIO,		/* contains MMIO memory */
 	/*
 	 * Command specific flags, keep last:
 	 */
@@ -420,6 +421,7 @@ enum req_flag_bits {
 #define REQ_FS_PRIVATE	(__force blk_opf_t)(1ULL << __REQ_FS_PRIVATE)
 #define REQ_ATOMIC	(__force blk_opf_t)(1ULL << __REQ_ATOMIC)
 #define REQ_P2PDMA	(__force blk_opf_t)(1ULL << __REQ_P2PDMA)
+#define REQ_MMIO	(__force blk_opf_t)(1ULL << __REQ_MMIO)
 
 #define REQ_NOUNMAP	(__force blk_opf_t)(1ULL << __REQ_NOUNMAP)
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b82cf88cbe69db93a98bfdfc90f11121abb973cc.1755193625.git.leon%40kernel.org.
