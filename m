Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBIMI3TCQMGQEZ7HM6YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 882F1B407B4
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:50:11 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-324e4c3af5fsf5848695a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:50:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824610; cv=pass;
        d=google.com; s=arc-20240605;
        b=FCK2kNbKqN9ALK4Zq/yU4aQ51e3fRMWvPdAWrsJsDYwLLQkI+3JgTFo5qcEPBRtOuT
         QIHmRNf+RkrfAPm2znvOwLSyUpd9Eha5v5UYmgOHOR4lqBwD+sonOURaGPQSrZEQYLXw
         t0/fEpscCGfu5BWVUbXCmGCMnA0erFvK2CTNomhlZqMl0LGVJ9cDjIX2hqs0WoAndhHB
         7FVUpCcR7Vkols8r4cwxPZhA6vjgAjBGLCds3sXx2j1zKQ9tdRjG3cH7+JfnvG3a8gy3
         pxx1CCGsRGTlK78VUd1Aa5/3ud/fL/LCzO62zDlE40sixxrPPfaQqtTM141Vq7LEkOR/
         /lyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VlFlAZauJL4tL1LfKyaUDnUEVILejtM4CtmC+Yeebxw=;
        fh=ohtlqWoRI7iYX1OiClWmbzbbXfD1eZ8IQ3MYy5OBV7g=;
        b=RvHeQ8HtooTYjCqlB0GJyDvvpOgdXIHwb+IJCIirdPKXIyL9D7DgAnUM6A+s6PS3fm
         U+xjIbiz5GWG/2O4eDczpBhybAI7Z0bzLjaYT+QA11Ja3McmGm/A2Db+YqBK//njR7Ph
         P/RhP/mPcB+jZ2OyjBKRLv1IHtxDFZtwJaOl+3aviCBtlCBHUjayVDWC6vgdNKnmlpBV
         HWZdLObD3g2+4wWLqWJQ37Katmc2bS16RgHLhCJRvNAJvF8e9q4Pu9yT/GOFHPsSZCXf
         14kC9SVa9I3grImxkp+w+OVvZFK68vYyWrDKw3YkD/IpwJ5a3g1L5UmJ32jBCpNG4Ww+
         HBug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LKY9fKoZ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824610; x=1757429410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VlFlAZauJL4tL1LfKyaUDnUEVILejtM4CtmC+Yeebxw=;
        b=myuMBMJSA9QK9OjJ8ykUpyL+q503JUQs7OAsQHXYSVtcuW7kT83bMtvumJOx+vLgaW
         +i5Pez+vgg3LHmIZ0zLzEuirUQqeWyn5NyZixMoiiaJzB3cHtgaEbTJ1nlaIXxDrYlfJ
         kJgSJ7dS04yXdrf2g9iEVWG1R429tGVtVGGqKKaWi8Nc9Dk/qqv+DcjsuV9GYLCYBJ5E
         vtzlOMWAe7waBy2HsZ6gKA87rWlYW2D14GQckPMvG2B5tHeLojn7/zCmsl2tFTqmvAl9
         soyKpXwicUMtLN0jxrqo9a7NeAy2Puj70DlD91VtCAqiZCRXJvupMuH3XOHEw2/W0uRw
         WKdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824610; x=1757429410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VlFlAZauJL4tL1LfKyaUDnUEVILejtM4CtmC+Yeebxw=;
        b=wwlPgPOAWstddvW+NQYQC75yfYrIQ/pwgdWO2HU03L4UHyAyIo79HTrIfYgoZzHVA2
         KQj9kNKw4DtgwYqjQekJvWhQZejxBoR5MU1aUz73abnzTLwRBR9dnaxN/v2FL7j/rKCA
         xINkbknvb/k1ijKrYBa7KnGof/4oGyJU3QfD7on19MbvamHR610/rDo7v+R62iYau6U4
         8ksRuoNwaxmoO4ayHxDHyOVFuPe6x3Hzbmp23L/fZsePhtT1b92JQuHWCXN/XDKqV4Ne
         1Nd1gag+k9nWomKO9KGVIRRPJFXjFRnk7EkBvBqHrBNEJYh3jkdT7YcyAMLeGkcB0Cm6
         I56g==
X-Forwarded-Encrypted: i=2; AJvYcCWcUpv3ux3ZCI/xUkNC5KRcT0PT59/iMNfnVmsmVo2+thcNSRhe7wKm20g+tJyoxvsRfSH74A==@lfdr.de
X-Gm-Message-State: AOJu0YxNYItyBnddmi3XQhYsOQMw+8Bcaqh8+TKh7N8SJBJYHkEyKHac
	R2tr8Xyr3ZZY7xbBfg2HkkgIRMw5VIG7HYeXl4oBQ6kRb/aNOAuXTvZq
X-Google-Smtp-Source: AGHT+IGHZIBCj7J18L2y/gtC2tAlaLB266SmW+98e8rHRle/GfYfiTysxeojLJBksHna4Et8odxOjQ==
X-Received: by 2002:a17:90b:5543:b0:325:4c48:af54 with SMTP id 98e67ed59e1d1-3281543cc29mr13481143a91.11.1756824609983;
        Tue, 02 Sep 2025 07:50:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfHRqHFQ4y4DSotxm5q4djinunHNxsm7KIKqHnaQGcuJA==
Received: by 2002:a17:90a:608f:b0:325:3358:2efa with SMTP id
 98e67ed59e1d1-327aacfa50cls5115868a91.2.-pod-prod-05-us; Tue, 02 Sep 2025
 07:50:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHpeD4JdCurEYIsODWgKUN0fU9h5Q2EkrE2dx5cKnQ9KZkn1Fr6mJVuyG5PuX3sj6rdu81NA8+LJQ=@googlegroups.com
X-Received: by 2002:a17:90b:3d46:b0:329:d09b:a3eb with SMTP id 98e67ed59e1d1-329d09ba59amr5073954a91.3.1756824607315;
        Tue, 02 Sep 2025 07:50:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824607; cv=none;
        d=google.com; s=arc-20240605;
        b=QsjRMgn086w8MOYpMA3ItvS+0a87a7k0fSClWKxWEy7nzg8b4GiEOBOjoyAZ209KL6
         tU+KotXcMucAtTJD2Kc0m4N7kbH3FR9DEWBBBRUWp2BVowBLlmugqlPBUhzOpIGie49t
         PgrE5+UY1N0KMlxmoQs+pOn3T+M1X98nkO6yebams0plqCILqrT+LvavJ5MIOtqpdMOG
         c3i0DxBjj/NknZa+tAMFWpaCRbTmwxOM8KO0tmuzj5Ji2dn5hJu2IRjwexYtXhCVOwA0
         iAJyeuZJnDW8dY5jvYKfWZtzi5H47v/fEwGh+9zBmrETkrnjYaNDVy5/zs+PCDYGomDW
         miIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uyX2HSlErhSx4hWPy535LrU8E2hScx2Y8ibgCTwqAm4=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=Rty0Z2K6sgnfSWmYeomQUJyKuFknFf+qqra+ZyOquiHLC4fMBXyJneJ4r1v4/Zr0Uc
         4qmXcotC3TXqUHh90F8dodnxuzvgToYkjpwJBr37fodG6RKstBRs8OcFhjWK7LZkN2oz
         a9W5bLky3s5Rzy4CjSbo8rMxa64HLo1oq97UmZhgyIe1X2n+2O5Q65ELeRt6hdE0xStx
         f1PNonQD4CEk5zLDvHZNxbW4nFE6FR6avW/1SGtf6iLAcxx1G42LyS4jAl+NEHsaTn7k
         OUk02TvLvdzsJqQLUfMC5urKnjNsYBJ/+Pl7lRJ+k843ugBmXtaOoB7eTjPAb4oy97iH
         lMug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LKY9fKoZ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329dca88bebsi119313a91.2.2025.09.02.07.50.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:50:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 63B9B60223;
	Tue,  2 Sep 2025 14:50:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 36EC5C4CEED;
	Tue,  2 Sep 2025 14:50:05 +0000 (UTC)
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
Subject: [PATCH v5 15/16] block-dma: properly take MMIO path
Date: Tue,  2 Sep 2025 17:48:52 +0300
Message-ID: <a640e74c8f407ed46dcc51e0f704e0a128cb4d3b.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LKY9fKoZ;       spf=pass
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

Make sure that CPU is not synced and IOMMU is configured to take
MMIO path by providing newly introduced DMA_ATTR_MMIO attribute.

Reviewed-by: Keith Busch <kbusch@kernel.org>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a640e74c8f407ed46dcc51e0f704e0a128cb4d3b.1756822782.git.leon%40kernel.org.
