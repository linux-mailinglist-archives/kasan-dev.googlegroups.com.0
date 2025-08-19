Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBPHNSLCQMGQEWZHJQCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BA10B2CAF9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:39:32 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-30cce58018esf12077486fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:39:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625149; cv=pass;
        d=google.com; s=arc-20240605;
        b=QxbOzYWYHeAyYJt4G7sAPWj4nKkHscczg0qQ8LYr7smGh1ox4TzLunbJG3QdB6BSWb
         Y7ed/MnQeHM5hhY0kUrSe6cT8NnsvY9Gq4hwwrlpQti8yWtUk5uIzz4CSN9ofdVzE+B+
         Tm9cK91G0nspfgk/BdpSU2Ytn3Q88loMb7+akDFP12312LjsmeW8XlNDM66fd+ajiy3m
         RJxmUi1sWZNTbKOu7E9XJLK2S7aAiCoy0l0CiuBhiSUqafHxZw/H9q4qgbHrDRWJ71dy
         xiNaoDs/BxAtl07yaj2fCA0ycDflhycE1I8mLkXmV52d6F5wyL3vCqW29Zwtjau4Za/4
         PBGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=df0Lgf1NNVxH4hnNGKRaaWa+6YL29hCk089SrFvO/rg=;
        fh=vIvOJU/IBjutZQ7PybWZAgg/qlrLoNKUScYAIczFkZU=;
        b=a17j/yqkTVe60Vn+AFaPMUouRMmn2covAgGSPO1oZ8ZvfVWUlXZ0tcg3XBPJNuqMqO
         YE4/TjUg7VxQTmWSywZWqZAwrv47/CpfJxUrHtCTHjTEP9xQbsf5CB+mh5LePRmDSRqc
         QWPMk+AKEjrLFVWsBcab7A9eigKf25x8QQYjlV8bTde1SVHyCoqRiLpd4OxvifY4LWSY
         LAYoIFwYwYuaGg/FijWaxmQD1sMvd+vrAOYuW6Gch4Au6IcqskXWVaN+tgVzwhVKbvs5
         BBew/wwbRx9M5Hnho6YmXSrm5y38i+dLUQDAlvHyknEyOUy/wHKCzdaSkmMleXDLvJ3z
         J4eg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IyxkIeqE;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625149; x=1756229949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=df0Lgf1NNVxH4hnNGKRaaWa+6YL29hCk089SrFvO/rg=;
        b=FML4W9aV6xmA2VJXz1pH2j+rw90Pd4cn1Qd2Pyb7yy0L5Ad40hjHhwDWiAk6DMBBL6
         FhW3r9ret8pkyZVuqKRgqbs7yAXbQ9eHka4wIB4FNEUfHT/aAmZd5NZ9ngkLe8igH0yI
         qJEc4X1w4pm+QfMHNl8IdhBwQ7DVYqA0iptO/8h7O8GPDppnG1MCEPXTnDi3GNmsHD/P
         WpmeehPAezbaK/PP7KFiW6DDRi5dknoOcOKghA4q5Sdd2QC4+x7cpl3/yfF2wujmuuEs
         jQfARHdYb8UFABgRP/JEAYZKRUCmGC5OclmlP3v6kzMWKkLxxO6cq0FPd7nk4SmnibMk
         9n4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625149; x=1756229949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=df0Lgf1NNVxH4hnNGKRaaWa+6YL29hCk089SrFvO/rg=;
        b=wwJzBWLRQzKSuVP6ar/hx2zi/bwQBZjo4xuiZFmoYxtSTVkEwnsjXbh6Q13I2M5Ms9
         Zl1OrgJA1z8Fs4FT58LLtGXqBuAn4bZX1+pDV0TmleoIEiNRzNA9U052KfXLzrZGIyVV
         xgKk5QkW/Qg0xT5wz3SoeJu6WFasj+vjBhdnkmVUEfdAPXAxHXOpQbgHcJoPOxH2KbFd
         8RcvPQqA49OTzE81arnBJiZaKMqeQE5ODD2NskPTy8cUsZJqJ6RWPj5/I7hS1aE7E05h
         U1U7xvdA+mniag3AbcvY1xFHLmsxwmdHymWW532vNsz5ahMPhsXPxqcTy/8zm0xd/sYP
         hK2g==
X-Forwarded-Encrypted: i=2; AJvYcCWRkmZbng7XBOwm119cBs0I2AJCc0NNMXyxVdq0em5N73uJOtccghmnOWmCMfqUZ1kHUYZOgg==@lfdr.de
X-Gm-Message-State: AOJu0YzCi2DC06fClUPMMaoEzHmHPsUul7P/2xUb7hlWRHpqdVrOOxSE
	WGOIElGATmmwxHkkQoPAxKViCZhiuo01As+Hktscz1bgVApf8I1fdhG2
X-Google-Smtp-Source: AGHT+IFIO8h09VRxCFadROQizXbrzXx4buGaVU0JWHviEW2DD+nRRVjWMpZuBBGJ2x7mnRYGv6soLw==
X-Received: by 2002:a05:6871:440e:b0:30b:904b:c76d with SMTP id 586e51a60fabf-3110c3d07b3mr2984878fac.29.1755625148972;
        Tue, 19 Aug 2025 10:39:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSW52FPOBmaDWNocV155+hpdalv+lvaBJCPsqvF9qz1g==
Received: by 2002:a05:6870:d152:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30cceb68b39ls3634259fac.1.-pod-prod-05-us; Tue, 19 Aug 2025
 10:39:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmJdWdef3ai7Gww/OLElq9WYWMlYiv3meih+lXkqdS4lQmMal8Ux+OJK178soXslvfjBTVm+3Cowo=@googlegroups.com
X-Received: by 2002:a05:6808:1a14:b0:40a:5683:efc7 with SMTP id 5614622812f47-436cdc89debmr2076593b6e.12.1755625148034;
        Tue, 19 Aug 2025 10:39:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625148; cv=none;
        d=google.com; s=arc-20240605;
        b=G5qYfoJavW8kz6Xj6fkyb4b7t7FxiNKOhbdBmYlWM3DQxHwaMAAy54IgFq40k51cNZ
         d7iL6eRANjAZKZFC2zkBZ71EwHqGa97ZovSrbfEkl8jxfeK2HW6/fO9pnx+Ci3JU6cFG
         amDdcRKFuZzg3IJeCiuMeIATMMIQl9FexZFDN8skFLmMnQh3Q6V85Lun27XmUJO31A73
         GFcfJqrCKg5wbNOVNtqP9vqIW+xBnYHZRsME7DNDORU+nMwAgX8R6MLeI9j88SbqL+0H
         KT1fxBl3eoQByccNpQieuF0M0E9n6hb2E9a9BeUvd/COHlK2MVWd6ehAEYBILV4a/jy0
         h0EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CCfmBvMQcZnHpKPeupg0PVl7hYfqXMfZSFQbxGlwy/M=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=YKn/QG8p8KEWxsbUjNy1CYF88WKv6XV/Yh0ivD0R2AqQJ3rGhDyHqoQPoGpTtRx6ro
         cguNlnKsX7x9RwAXYt8+D9CW/WPPW3RcGA8bJbWORfWlFmOorn1tOtta+ioGHDV4gv2S
         vWFDTrFHAET+v9gLo9Z4jbgpjeSLJsjDgBfxDxFpyzl7+sdI0LCbH1HSeGNHfotloNsa
         pb7shDJ/Bdb1zF93M+/GO6qQRdSc6DV54eL1H1pc9fSkBNttOQ6iYoN2X5FkeQEz+7Li
         8OBIsp8kZ4LxZ8yuqND5gus9hxqRwQDkecJ343qSgj4NDGiRTZI2xvHqBbKggozde29N
         rmyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IyxkIeqE;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed235680si402575b6e.4.2025.08.19.10.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5B2BD61426;
	Tue, 19 Aug 2025 17:39:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 79912C4CEF1;
	Tue, 19 Aug 2025 17:38:53 +0000 (UTC)
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
Subject: [PATCH v4 15/16] block-dma: properly take MMIO path
Date: Tue, 19 Aug 2025 20:36:59 +0300
Message-ID: <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IyxkIeqE;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon%40kernel.org.
