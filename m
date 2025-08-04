Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBMWWYLCAMGQE3KOQC4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EBA3EB1A1CE
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:35 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70749d4c689sf65659646d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311475; cv=pass;
        d=google.com; s=arc-20240605;
        b=RGXLqBy6xQlRTRIvVlEb5d9b8ZOnV/R/d+4YLUw3eWCQEk/D4NOLP8BycaccObfkV6
         99FY3cHlkjXSxGsCUoIKiFJth2UdpFSCXqX7Qbyf5UBFVKQb3xvofeaFlWhyGfplEVth
         DNx2ckn3WFBaK6Ms74ZDd2jgPaPrphbQ8DWPgmlh5jcr1Spb+c9Xvn2Aexm0oV93coIG
         IIj+p2IlNQrHWoZKU7hoRuouVtTYlALMH7ppY5D541kqwfhWsBGaMOS6sQIalSDY31AK
         FIp6bljd7w/uWLoNIO2uPcnXz+hYWb4SZS5LTXY9kSw9AJOhkUQXAT26WDu57xi/EmHQ
         UAvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=KzUNhlgJ6zF640F5qaiLBCfUlbJHW122g5ytzGkBCDU=;
        fh=mOFevwlaa9jljWygwo/xKdVrFiCIAZXGMUyYnoebqTA=;
        b=fW0b2vkXOov/AEtZlN2uXnwhrGrMtF4AJQTOR/Hejo7GrkpdLN9Wld+d+ROaqfVEIK
         TlBllCdkyw350DdSkXcbkECF8vEOBDsTKqh0Ikj2l5Vv1D46nb7pVyDpGJPt3ErA+pRL
         s26XzjOwo9l7k9LA9DgakcrStQ7nCoGT3jotN9nls9uPZk+zI0lLvs8tR1vxir8u8PIk
         U6s6HgbJS1VTryxu8X3pV4IN7fu2oyGmyA6jBwNEcvYAnLzgW1xdAnwXrSwNsws2VKZ3
         4DO5Y4gSgV06bOvj3sS6thKC/kIHC1liXycaP8a+ihdtdsblpVPlTHjT+Sx9lwmLtCsH
         bG5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D+O9BFW9;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311475; x=1754916275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KzUNhlgJ6zF640F5qaiLBCfUlbJHW122g5ytzGkBCDU=;
        b=MXWGEH0j/BLY6scnmlAod8aofuQU9SRv+vyVX3Rwx12J2gOLxyByTLdhrtwm6UFwT3
         TaUzz6mvvLmN4+fCQHJXtHY3jqEkKWhXLbcdOYW5RoCJOqvkw5T7APFQoQTxDQRHifVa
         5Zv1x62/QeGxUEoKCC/iOXao7kR2Ik7kPF6votUhWHkfiRNGNPAf9lE8uRvwDCg9EoKp
         lkjSeHPWu/g133heQohFXxj3Xiew12PkvYV4fLNjuKdVdq4VJN/yee2zSofCDN1xRpF4
         Cs/1JN9LVC3gUZEOj1vgzVbV/qVStL4Q0s0TRM1SjnckKw48J4C/Xr/6kjbXUdmF8xWL
         +zNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311475; x=1754916275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KzUNhlgJ6zF640F5qaiLBCfUlbJHW122g5ytzGkBCDU=;
        b=bJiSAuGQdFt30oWj0turUXeogvAW7CDaBVF05M/UnhJl1KJ3gH8MHN6mYpPRzlcLC0
         kI3BYcABggviKtoYGQIFhJJBVKYrLgssnJRZdXEzw9sahLA5xZO3aLQuNTFcrfWM7tR8
         T0Jxn3pkxbW/9CJyWF+udOYBHbdsqOo4PIN2IjFwMJmZq/ms4nv/BvQYCbcO7gtmceP+
         5veMHz/gWLYJE9mkTsfIplecbVTmM3NJC2BtQsYIb1nsZKmuKsd28FwMMx4H385YgS9q
         vNvKbLOuVg7Bc2VsdyRL5HUCBwgeAYDJPGJjbnCXxkiTbfaSDNGC1/FKiOfw8LXKY9Co
         v9sg==
X-Forwarded-Encrypted: i=2; AJvYcCXVZLvgcWsBU7ENbrQNOI4pKSsTRCXfltoJgQuvrDsRIeQUj9CWKAFoN/F2YHdSoFPCvhPMnA==@lfdr.de
X-Gm-Message-State: AOJu0YxtlaKJMgWR5hx6fxkD8ldakiigetMhuOlZoRJq7cDmrldLG23x
	aVUOaKm80dQTCdA847JTH0k2MaPKcPjDyZOpXGENh5aNmArYzxdUaJRD
X-Google-Smtp-Source: AGHT+IGYQbmFue7o1a7gUF/axcwuFtD3GeR0hk5w1S15kABpUrQGgXMsyBI6gRrNlfeBswALu2cy7w==
X-Received: by 2002:a05:6214:e42:b0:707:2220:e077 with SMTP id 6a1803df08f44-70936232b14mr159377846d6.31.1754311474760;
        Mon, 04 Aug 2025 05:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/YJrO25B4D0r/Fx7Ki/kW+KXHZ1NyB9Dbrgk20WSjrg==
Received: by 2002:a05:6214:4c48:b0:709:289d:3157 with SMTP id
 6a1803df08f44-709289d4016ls37003006d6.0.-pod-prod-07-us; Mon, 04 Aug 2025
 05:44:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNy3dr/82qc7TfPkp5X9lzXpWy0k0YYY+YRvWHYXRTDJPmSWW9rClqj79GV1YnhYER+JmvaOWCzbg=@googlegroups.com
X-Received: by 2002:a05:6102:6cc:b0:4f9:6a91:cc96 with SMTP id ada2fe7eead31-4fdc480e755mr3666878137.26.1754311473390;
        Mon, 04 Aug 2025 05:44:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311473; cv=none;
        d=google.com; s=arc-20240605;
        b=lRs+cHuElCT0T+HuqboHQUP1ZeOXDsb5pDhPireFyqXbEbud1NXWVI0iS/A/GLjZo+
         ceLvx3SuaQ6BaG+uDBlfgLVpvV34D/he7obSaPjHbq91o+rm5zYu5bzj6OQUiFEdLAmt
         oDoMigcNzS3QQ75kC5QAafnW5IvhFQkQBjWBLDH+6+XPaYVhII1J5gMVRJ9ydtQQH1gD
         DMVMYWnmuhAdnPxWaOMXmvTqAWYnbOJEOAv7+TqfETTg7vBBCU2hJ0wwH6iLhz9rZG7T
         f80G2tlamDSKfsuknI+o4o8RE1/+/c4rvVgpaDzln0TSFoF3bEGZ8INTzh8rgVy5g8xt
         A6Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rR472IjdMKe4w8RfO8gWCXyzwltO7zaZbCaEciZCZH8=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=dIsdi8TD0/GdEASbVmXhwsYNc0Zwg1Ya0/GFDTG4uU3OKVkSJUV6WAKaFntzKcz5qG
         Sl3WM++BABaA1/Mk3PyqdQzUtgJ7m0jRzw8LphlbVyyO2tvTBkbQLMPfG+pbCuIj4v46
         dczA+PhgeztG9LvBAC+mDfD1CnteE3X4KZvXFVWascSAvKvTu6gHJ40tywuVZve61wsf
         /zBf4M5u4m/h/5uoD5rJxNrOLdTqM+WCSsYLhC6MznXxWt1eLDGbWIZbWuz4Yqy8plRs
         G2fS+0yEfaJbGVbs5x9eZfOJYEy5fQXcWhxUMIe5HpUTr7pVyzszNZX3EK38tPcSNZHt
         OjFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D+O9BFW9;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-88d8f367c2fsi353940241.2.2025.08.04.05.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 10CE7A5586C;
	Mon,  4 Aug 2025 12:44:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DBBA4C4CEE7;
	Mon,  4 Aug 2025 12:44:31 +0000 (UTC)
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
Subject: [PATCH v1 15/16] block-dma: properly take MMIO path
Date: Mon,  4 Aug 2025 15:42:49 +0300
Message-ID: <d9b092cde0f42bc6a8a1cb36ffee3478c46a3599.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D+O9BFW9;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d9b092cde0f42bc6a8a1cb36ffee3478c46a3599.1754292567.git.leon%40kernel.org.
