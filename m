Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBF6XQDDAMGQERQLLPWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B94BB4FCD7
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:57 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32bbe7c5b87sf3991879a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424536; cv=pass;
        d=google.com; s=arc-20240605;
        b=cQoy2QNv325YAo1nvm2qHUXIxxd8kYGBv28kqzOGeL4F3BawCuSYtx8k+0rmK/Oa3V
         60irRbLoaGJo9TAr1v26oRPVHTvb0z2uTY8wDj3SqLDcnaUox9YEqcVj4m0SpVME75QE
         yTQvvc8l4zwdya1V4HFgWQvbtq4sy8GlMCvnufZfl7jPSZaf7y0t2d3OTEZg7p3TRWhD
         X/YExuX38Dv03gnUr8dSuNIamwbw5Oh3SHlzTbrFti+vig1n/jwenB+0g9Xbq3MWUQ5U
         9pBX7ysETCMQnxcgEtnugEChA96VL4vw1QX1Npj+mi9Xibxfb9r2WX8wGYLa91PYX4d9
         NZ2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PBcHYMYmsRTAXd0fOuK0+kfqRhp0UtixFz1luhhsacc=;
        fh=l6zyMgD4f4/zWArpyY2AbkipYfi/4tDRWtFBpusbTic=;
        b=jjw7GCBIeOr+npuEBlRBWoqN4UNBg/EL14vfDr/Djwqxk5xRQpUhXD8MBic0dMRlmL
         CeuUus+UN4TsUwgXlVgSO5yH4z5+uctZD0Hl4EXeuTFtCWekhL0i7SPoJK0cmFszG5NX
         DdzXPDtyS8HKd0s2RvPqCW3Z5wePdiBxWFovdKLmfc2sPsU584aEeK7Cqu7tv3Biup1M
         Saq3BkndeZpW74PHq+EUcUp2oN3acjSeRszHGeaSp7tWRGR0tz3Xq8ZBrMpvvU56URuZ
         /yiqWGiMoSuGK1Jo4yHOaHkfDKaym8jnvWpJAnopmeaplkL6UeRyC7EQCdDhI7fhPgrd
         ICBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mpt2hgsJ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424536; x=1758029336; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PBcHYMYmsRTAXd0fOuK0+kfqRhp0UtixFz1luhhsacc=;
        b=hSiPSs8588jOIFqSXtlegLDJnEtxus9pwyYPtajgEcHd0RBTPMqcJjbMoweqeN9VpQ
         TteHg6dGSLMIVAk8lftU5BIffdz9aRuwNRF86gDaqHJ2unWl/0KLfOImvqPFtEs+BEw1
         ZJCmAE167/544/0ToJxWoVFw6UQoZiN+B9DfzLKsKjBQA2CY6f+UUCWo/VBKIAzgLFOl
         0a4/CNOT8vdienJRCrz88CP4pCCM+2DJFrjwObeKvNhOPAUYExn4HYLAPlKrhr58OqBj
         GwdgyoaUQfSrbrb1cbqsvFQoB1QB0e2Nnm7agIUGC+M29yi9AZYpUlAAg48aXihRyh1O
         wOIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424536; x=1758029336;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PBcHYMYmsRTAXd0fOuK0+kfqRhp0UtixFz1luhhsacc=;
        b=lb2SRcxna2h4cJHo75tMw5sWdstM67i0tWcxwNB3JEB/7zlxjAVg1bL+7Njje+4xDR
         cdEdi5oTc/eBdYX7p8Lr1I6NoSxDD23Y2HuS6iB72EuG9Fkh2XHiuVj1oN2aU589rK0b
         Kuirou91Xl1iyikAhYC9pH0eJJh10mabWEoO/lqKqkxY0H7r347s/yklSvJj03K64xMg
         grK8xrQcAPTnwjYdqSDIhG8I8bBdqVRydZNOIdJQk4Wt21xAxEYykRCYVn4PCXLFPoa1
         K5CU8GsLv1HChPd1q0nwYJ1ENOtA1R2s8sg2sTgRdKhXf98SzbqvR6ye03eFLhZJytYJ
         ZzHg==
X-Forwarded-Encrypted: i=2; AJvYcCVnJYqqqkgEmAqBHf5PNBlk37Awgo0YLx8InRVM23m4MlnSiLnbJu1dKmUc3W0adot35rXTMg==@lfdr.de
X-Gm-Message-State: AOJu0Yx3MJSHNCL7u/zDjjy9hH4Nc/SFWaaJn4SysFV/uoo/kuIOwyg2
	gjvqaAqUlZ9BrlcO+UurRnh5Jzb6dP2jSoVCUEp8tQbOkuVgTW6Wfvdu
X-Google-Smtp-Source: AGHT+IEgkWIIaaC7WPzoQ+1wQBlZidmbFV1y66lBj/u8lD8SkDH+E6LX9UZo9w9N4rwmNGHz7IQb0Q==
X-Received: by 2002:a17:90b:1fc7:b0:321:38a:229a with SMTP id 98e67ed59e1d1-32d43ef084fmr14572611a91.7.1757424536016;
        Tue, 09 Sep 2025 06:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7axVa/CpxDGkkfrtt5Y6q/ypGCN2hvKY9bI+Oan9mypA==
Received: by 2002:a17:90b:1c89:b0:31e:ff9d:533e with SMTP id
 98e67ed59e1d1-32bcaa17939ls5028459a91.2.-pod-prod-07-us; Tue, 09 Sep 2025
 06:28:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVM/BiNF2zlVSVbUU5NzZO7+Mqe64B7fkcYxPcqZ4tmppbRPxGpzseSge3axkve+PQHLj/CBBUVk60=@googlegroups.com
X-Received: by 2002:a17:90b:3e45:b0:32b:df31:3dc2 with SMTP id 98e67ed59e1d1-32d43f653cfmr14218265a91.22.1757424534338;
        Tue, 09 Sep 2025 06:28:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424534; cv=none;
        d=google.com; s=arc-20240605;
        b=Ow2Qox/gcZfW7tQ20TzJTZjx8uIdgH3IKyh/CdGRm2tHfFRVsOebTOQ/wswUNj+dU5
         5PY9BoRufgciZYOvO6xhA3pj1a8o33GCybG6xemZDv1yzPxGHtgatN+Y50dwmiI6VvV+
         MyQC/iFvm8yrh/PpZvXP1WY8A0Bgn0LO0O7dgsSBxifKiezDTrVpd+9WcUkSCBUCydVh
         KAv/Wxh0uE4aYGaDx1udYOFG2yeHSjtsTPzKsm5cmu+Vz4j0+DcMbIP/uLFHIdWHQVG7
         o1EYTsAU05JHSoSaMbwsttiDMg81Dki3DgWD0I3ONmV0UvH2Rk0zKE/MTKdYDu2R3NK1
         CMMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cP4fy7+D7H5hdZTwc3EviaXgpCbdOnzec/g9AJ9Vncs=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=bO4hPi6FOUJo5X2qqxQoRqT8acgmBtq2YDdCb4CrrswywEL/zWbvdLnafVgxlcFIQO
         ytz9Qf0KoAokCendG7ak43O8QksEHB+V5qNI6v7tDgbeEqtNNPbcAPrGStQcAW2WbZqa
         fuglZ3qnujmq0rtw2agHGvJYv9YJzCcWkd4wPlxYldtslopir1zeLEQO1ZE4EWbcW2A1
         S+K38lSkHq546o7qiL28Ppz5h7IZasU1uAVuFAmAZH2lc5XM6umMms9nnugT32OgQUjw
         hJF2ptuT2L8KyyewC1bTzEzgCykJdXxEFnSLcwGgj3y2pHGWC4b1qgnlHHQ8I5x1Q+/M
         zw+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mpt2hgsJ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b4dd94d0esi809464a91.3.2025.09.09.06.28.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 616B6601AB;
	Tue,  9 Sep 2025 13:28:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 849B1C4CEFB;
	Tue,  9 Sep 2025 13:28:51 +0000 (UTC)
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
Subject: [PATCH v6 10/16] xen: swiotlb: Open code map_resource callback
Date: Tue,  9 Sep 2025 16:27:38 +0300
Message-ID: <e9c66a92e818f416875441b6711963f9782dbbeb.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mpt2hgsJ;       spf=pass
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

General dma_direct_map_resource() is going to be removed
in next patch, so simply open-code it in xen driver.

Reviewed-by: Juergen Gross <jgross@suse.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/xen/swiotlb-xen.c | 21 ++++++++++++++++++++-
 1 file changed, 20 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
index da1a7d3d377cf..dd7747a2de879 100644
--- a/drivers/xen/swiotlb-xen.c
+++ b/drivers/xen/swiotlb-xen.c
@@ -392,6 +392,25 @@ xen_swiotlb_sync_sg_for_device(struct device *dev, struct scatterlist *sgl,
 	}
 }
 
+static dma_addr_t xen_swiotlb_direct_map_resource(struct device *dev,
+						  phys_addr_t paddr,
+						  size_t size,
+						  enum dma_data_direction dir,
+						  unsigned long attrs)
+{
+	dma_addr_t dma_addr = paddr;
+
+	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
+		dev_err_once(dev,
+			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
+			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
+		WARN_ON_ONCE(1);
+		return DMA_MAPPING_ERROR;
+	}
+
+	return dma_addr;
+}
+
 /*
  * Return whether the given device DMA address mask can be supported
  * properly.  For example, if your device can only drive the low 24-bits
@@ -426,5 +445,5 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
 	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 	.max_mapping_size = swiotlb_max_mapping_size,
-	.map_resource = dma_direct_map_resource,
+	.map_resource = xen_swiotlb_direct_map_resource,
 };
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e9c66a92e818f416875441b6711963f9782dbbeb.1757423202.git.leonro%40nvidia.com.
