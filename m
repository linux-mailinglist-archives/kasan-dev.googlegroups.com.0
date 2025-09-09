Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBK6XQDDAMGQE7PTPOSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C8BF9B4FCEC
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:16 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-72023d1be83sf196553186d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424555; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lo1rRiYaJjIkI6YurrnRikN2MyKGy1qfE37msikcUvcPOgkzNMvCGNo6LBExBHtm9J
         0u2Sw/F1Zi3958GAxJ3vMr5H7G4/zfYJhkK42oOoNtHtCBPjMJaYnrFGvxSdC9W1bc2k
         zxLNlwTq3thIWlltU/5s+pHpSbc5BpjhxJ4imV2P5VPx0cWcnflbR5PxontFo4UVqT9T
         JLb8TcDKPgjWeMjyGGWwYg8LQ2WcYgJIswt55snaNvgbs5oRagbQtGAFVmQ/hERInkec
         +VHEX5PjfbPIZDUk8mR7Pru1HH77g6YS7GEtlngUyOMhgZtiL9lnxU1rXJOasF22X2k7
         1rFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JWwqOUU3z6W38VbLSynZ0Y3X1+QUBlgCZzfFQnVrnSg=;
        fh=RVp0V1eqggziH73U6w2L8dWMDwACkVNc6USSuY/L0go=;
        b=AKWOH5CQWWEwzlyumiZCktGp51bZXAUPyjnfM3QY27PNe75sXlyM8w5gYBr1FUdvId
         OqZLtJKAQLW9Xg+5/tqQBlIszhGMNqn9NRlDsoxDxjFP0L+pYSQKFlyATqKip/R+HpXK
         1QKEbBqIzwwFNyFK3hhqmWg3Q4sib7KpHsq0m8QJHMwS0UsRz2CWW9wPYrvTy5eC6tWk
         nhj2u7YCj5i5WWg8S1kUmbp+WxAkwW3/3KEZaKSZ9hfPNjiU2OJfq+EVx9Ppe9afNBdO
         KawIItK0oJTlkNsxdy8sKFyu/KkMqzMgG/FqOWJEThqwafVEz+lXOKpKu14QdsZN2QTR
         Ixig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tD4Bnfmg;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424555; x=1758029355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JWwqOUU3z6W38VbLSynZ0Y3X1+QUBlgCZzfFQnVrnSg=;
        b=E3IQRbgatFNAI7NV3jCYzz85osw2G7Y0YjtvzxpZmS3tq/fqm3Rz3vEh6bZrsMs/WV
         Hrmt2bfUWMXp5vAP94lNr1qUzCoLIMbNwoykYNuf49g8T6tfw0D3S1+HWrMG8JDj/Sn8
         kloy16Mn1pCaoiqtl0CNznm0fKY2JYV7WT3ugrqVgHfvZULQwG48NCZ1R5Cf9Z13wqih
         vb9yJ2JhgwyQ7U4zKcO3At0nCkX9IxwqnSM+2VAdl/vVrdNmX7saS6/J/w9wzMrpBRGZ
         foDhl1rT8s18nPXXwsWwejd6ReYJNfKcPGdrkTUOH6olzEb8WfQV04JVB3RTarEs+n8o
         2aiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424555; x=1758029355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JWwqOUU3z6W38VbLSynZ0Y3X1+QUBlgCZzfFQnVrnSg=;
        b=c33uApj0byMfSRXv2JDVtW8AVFH8INnqbAkKPWLf8xScRZt8jalHW2nKMHJMeuR6Q9
         GkBiypZqILUUpCyaW3NnPssoTaKdnxTWStvb5Siuw+14fpxcjFKMTA1qCjxfQJQwVzwD
         lxu0wOHbNzNvPIJLLEcPXXJ3bzAAx6zhrFw9ffWMSNPWmYsu3CcP1uzCcIzvQpTSuW0y
         90cUNp61qi2wVEy3mGKva5YX96YOr3AK6QPLqRo5gjHIrlTaM+IZzfW01QGvNf1UOI94
         HwQKyJbDk/vkONUdIhu0sCLpKOIBPYez0VInja0QAZ2JT66IbCSFfHXmPF5PGrvWqauH
         G5mw==
X-Forwarded-Encrypted: i=2; AJvYcCXDCV7w6d4BZhNP/ubfQlWdJAAd3l7H37SKYrrj8TGlgJKPobo+hoZaLWLdYtdG/EPGWL/l1g==@lfdr.de
X-Gm-Message-State: AOJu0Yy/2Wei2L7PiCrobficxJRQZG++ktdmxnprVkZJGyldnR8sOUk4
	iVsbzh3Yt3ZSdRQqdv5KEzOp2/vgjhkcPcmEGn4HJXBkKfnxx6rdj+YT
X-Google-Smtp-Source: AGHT+IFSHjqaKsE81+STHzAO+ToO7Z/xB411uzU0U8fzhb8JBQXI1/vPXpCpSTp3tOf6GrE0XZTO5Q==
X-Received: by 2002:a05:6214:2262:b0:72d:8061:93f9 with SMTP id 6a1803df08f44-7393ec168a2mr92586736d6.37.1757424555432;
        Tue, 09 Sep 2025 06:29:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6a9JF1gm8wzpdUcVTpgp4/NjOA4h1ADCbw99FGpd6A7A==
Received: by 2002:a05:6214:20c6:b0:70f:abbb:a05c with SMTP id
 6a1803df08f44-72d3ac24c47ls77527006d6.1.-pod-prod-04-us; Tue, 09 Sep 2025
 06:29:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCpRkotyIAwlpOCxZT5BMNua8uf6Vrw/Z1Tk9T6tPcA/2lispBAVhbeIH0C3rj6blKEgMNHPyAJgk=@googlegroups.com
X-Received: by 2002:a05:6214:c81:b0:731:48bb:d349 with SMTP id 6a1803df08f44-73944a1876fmr123298346d6.59.1757424554212;
        Tue, 09 Sep 2025 06:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424554; cv=none;
        d=google.com; s=arc-20240605;
        b=LDT8zKpYCPyCpCBVrZ6NH72hNMpq2Nw+eNir+oli0zXtsBrdttKvIaf+afFGtu/V7y
         AS6F4NjW2ZbNZi0k4BIQs1ehuSPzCBc8ScsZ9m2ITcqJLvCtdhZniBqFMcKj1KT2LMCw
         56T9j8F5/GIOLguSePaNc8SDFmp6w1RyZoB6epwqUryS0qQe2ViQWDeng/Sco2csiQs4
         caf5cUbwBdickeqIOvfr57YsfGKPUHtgpN5ehjR5h4Z5PM1CDxeBFTXdNhuj3k/ndZR2
         3Wo4kvt92NJhfbg7Vq9HtIIYKFcg15u3yAGTvr9ggvt9ZsPG1GY9ewg6Skefvv7A2ENp
         cf1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B7WZHRIYheRJ7INKDjrUdN/sfxXGu5MOL2kGZxwrFh0=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=VxXeoWf1q1GCLee//LoNbrJrV5p6wNU+P7iGoQCb3GV+vBT68fyFTBSrrpB/U8Fqum
         lOD7sbZfG0BFGdynu2/lEfYqufEHgjmHRPsZ35mOzriUKXJTjnEi44qtwnLSrJVEhMXQ
         NbzLyLw2/8xmVQS4ulLtUBKLfAsC/vKyiNn03coXrH3IqMzgtpfMy4a95V52PAXzGPQc
         14WiNJ/NC/THdMhX708LsPhQW8bT6sH6AwHk9cg7WxabifRpj5VSUtPIsFVBTFMw6yqr
         wdKXjcThfWCPDiQ734j6C5d49cU/ssa3sQND1dtb2QdwUaddO7Y5n/k3LEuoFWD4q/ah
         dUKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tD4Bnfmg;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7440587e7f0si2576416d6.8.2025.09.09.06.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C541260226;
	Tue,  9 Sep 2025 13:29:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 946BBC4CEF7;
	Tue,  9 Sep 2025 13:29:12 +0000 (UTC)
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
Subject: [PATCH v6 15/16] block-dma: properly take MMIO path
Date: Tue,  9 Sep 2025 16:27:43 +0300
Message-ID: <1d0b07d0f1a5ce7f2b80e3c0aa06c7df56680ed8.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tD4Bnfmg;       spf=pass
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
index 37e2142be4f7d..d415088ed9fd2 100644
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
index c26a01aeae006..6c55f5e585116 100644
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
index 09b99d52fd365..283058bcb5b14 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1d0b07d0f1a5ce7f2b80e3c0aa06c7df56680ed8.1757423202.git.leonro%40nvidia.com.
