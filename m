Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBIXO63CAMGQE3N2W3GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5483FB26217
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:15:00 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88428b350fdsf114820039f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:15:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166499; cv=pass;
        d=google.com; s=arc-20240605;
        b=RT45iE40i1IxTOkHg/9g4TfHjClNj1A11K6yGzYmcFR9L4QTTzKUoTMD2bJ4BdmYTd
         taLizpx2UNi56TDD7GUeoA0lEAbOOUHNvYgJxlY7E49HkWUoCJfMn/A916lV5442cGFd
         vaaW+uDsC4BZSoHl7n7NmrhQMGCM0nxXjpWbvh+1Pbm1V3gKt+mhl8sXcf35Cgyk2emk
         VnSEYGdKQYPRk3JhNT+nI6T0Cd4s+dvk8FNsdYACoPIFG2mayPeQDJ5VvByoLwERaqKH
         /sV+3+b9Ow/cYV8G+OCf8kHTEF0XVcOloxtS6+UZvQsOWYQWNPvx4xF9ZOr0wbrRN+Vm
         ScaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bqfwZGydqq8WRwmF5yIun6mh9EpXkchUTM+cSRnj+fw=;
        fh=8zySj2Jbc6SyfzY2pmtZcYoaesBAAt4Cd9SeV+et50Y=;
        b=TBGf4LfpmZxvs3FI2DsHNIZySUF9uzC/Sq/GSAVyLPKA7qmmHYvCmFwUlrWiUR+zko
         NVsFlaRnojBHh5fkO9gLPBAwbaX71VvGd8GCeLK9P/zFw5A6D0VqUIwCXGIRT2qPUlfO
         3InlOtwdTGsNUtktDVQ+eCDWvYX35TUnHaE7n+cBLs60PPisBs+117I9qJktxvSk4f5I
         +Ze0ASQ3hdV3y2XcbCDNO3/QpV15r+lrXtd210XvKWSr1+b2OyshQZyNZ+26Cr0MqnNS
         H6YE3YEw5dffcyLGailsAUMx3/cSzu3t8Jm+HBYhrZ/+GAiwYg3b9dQ4gMFLSre0q999
         QEPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sgcAjNmQ;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166499; x=1755771299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bqfwZGydqq8WRwmF5yIun6mh9EpXkchUTM+cSRnj+fw=;
        b=iCLVtXs2+eK5jJ5fjQ3cNiMH6ZRJCJOQ30skKRLKX36oDCkyLd+1ESMsw79iiCtTpQ
         rtxaqmm6sZ7jRpsi2uou+ND+jCU78tmlFSYZeUKzvP+zKbKlbuSP0KXSA/l2UjpYxFqt
         29kuxMHs3YUdhmaar6C/GdS4Pik3yyy2STLEZ76aiVnawY/656UCXoy8ibBbxeKRiO0w
         WSn6NXS3aWulE/qcwU9w5yEagyLyWu6hfybCDcZ0YJZAwr2XxmQjwppwNzCAOQzJHrEd
         ZHpccCFPtcjCzNCHrK7tpKkNXb5V6Rnw4ugy8T5Ah3DKuzhjJgeI6F6oEhzGjbvHnL8V
         6C4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166499; x=1755771299;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bqfwZGydqq8WRwmF5yIun6mh9EpXkchUTM+cSRnj+fw=;
        b=NRPU8ey/FEQida/hmOjyrgd38zmFS0/s2OcaWqVsFT5Bigu/UGXSGw3cSHZh4viHom
         S4rx+mWcfxMtFTolyIncKPr27trkMLS5pSEwcNoWUXynKD3ohKguknrKG//9NLfF+tLW
         rIqog4KJMJxkdcATgkWFOJAtZSLL0Je+W8Gycrd6zUPSRFJAFIzBmQCz05wOq6sI8Syn
         PAOQ0M4VXq822T5x7qDRp3MnoiR2iO+KE4K5fpt+l/qi8Mmfxksr+SFFndFy0gDoSGB1
         0gW1SHmsCqBDuq7gYzFRug/v3+z0jteXSQRtS+HIr/0BPJjCh2xa6hSUbU0iWFkFE10+
         q1KA==
X-Forwarded-Encrypted: i=2; AJvYcCVF9bU60BxC3hg0FY2zHqewp+yBZwt8E/Okr5M0MYrlglYHpAsp0vPRW5Wf5MDgfPlsDH9W2w==@lfdr.de
X-Gm-Message-State: AOJu0YylFqvNEkz72raFaX2HSw5IZZuIPW1R5XOMtbSXWgL3gjjqLAfl
	aCPEOIU7QSYsgZwYOWFh6gGTlVThHdAl4d3p0vzpKZl2rVokiy68y2v3
X-Google-Smtp-Source: AGHT+IGZhwhkXL5qO8vj7WTOSBpmDmvFvvD+eieHCA6MdCr66/0sSrZcf2yTajczEpsX89f5zOxZMg==
X-Received: by 2002:a05:6e02:1707:b0:3e5:7150:ebf6 with SMTP id e9e14a558f8ab-3e571cfa677mr32526305ab.11.1755166498974;
        Thu, 14 Aug 2025 03:14:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3s0h7ohgKDQ1ZH+9YKFTQuyDdH3z6sTtHW8FDaLneKw==
Received: by 2002:a05:6e02:9c:b0:3e5:1d8f:5662 with SMTP id
 e9e14a558f8ab-3e56fa811bbls4246065ab.0.-pod-prod-00-us; Thu, 14 Aug 2025
 03:14:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKl8ZD9zYW6B5oyHC3fcCyu+kXzKJU0Nr5BMscVgRzRl+QVVAQ9dWncloBLCYuZcDOti4r3dse1dU=@googlegroups.com
X-Received: by 2002:a05:6e02:2189:b0:3e5:42aa:4c37 with SMTP id e9e14a558f8ab-3e57182aa85mr35511365ab.2.1755166498084;
        Thu, 14 Aug 2025 03:14:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166498; cv=none;
        d=google.com; s=arc-20240605;
        b=Meg0m38HF0MJph90gG7TxBDWA9BIY5/6HpEZgormTkuda8cKpfa6Qhfuo1EQ4NIWK/
         xkXqwZYick4Z/Y5NyeC1i7+9nDQiW6Y6AhayFaeLx4yz0YcCFZ/6pyno1TK38zPw3Inf
         dDxEbbUG4S7pxposQDVhRq67xIjEY+F57e+0ELs6Np0y2K49N6+xovKfDfL7zHsLaXLy
         sl+kj9JArKf2jdj//U99qtsa1DD/1QKrdBUd4x5zdpi5xQLMrK2GQJCn0SctvH3eemJK
         hmoaPYLyLsK+RYtSShSKHMpN32xQwuKT5yeS7sINGOLTFwvYuzcIRlm+sevARkMQZHlT
         tOKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CCfmBvMQcZnHpKPeupg0PVl7hYfqXMfZSFQbxGlwy/M=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=FTGu5soJ317MLsoTaJ7+Mqpkrirjq56ZBG597Lg4neafA+FcYoZaLhLvFfuDtnJajV
         vflKm2E9/FSZaMUW2axG8f4PIOXmm1j9MaBtI9tj48e6hp377dmnHdaYmBWNyPujSqsw
         5t1WsRYkVMXi3tJiIsgw0y8JjSKp9JUUo2GJwgiq3yPBNzi/7GyE9kONPZFGvngrJh60
         2WTlnQq5AM0Mhwf/9HaOOgVu5Hfpf5mtAxT+G2mmc+mC9+rfDEWyI7A4nqZLM3MACSf+
         SjHp/URM+Jo4zBP56gYoE2mXmor99U2s5rnNOhizAV+sdMYXb3chzcBFtFPwgz2YYFnk
         Uf0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sgcAjNmQ;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e5415444aasi5897915ab.2.2025.08.14.03.14.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 6F71EA5685E;
	Thu, 14 Aug 2025 10:14:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E732C4CEED;
	Thu, 14 Aug 2025 10:14:56 +0000 (UTC)
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
Subject: [PATCH v2 15/16] block-dma: properly take MMIO path
Date: Thu, 14 Aug 2025 13:13:33 +0300
Message-ID: <87b7d3a0e3f6be9da49947923d52355ed0835833.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sgcAjNmQ;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87b7d3a0e3f6be9da49947923d52355ed0835833.1755153054.git.leon%40kernel.org.
