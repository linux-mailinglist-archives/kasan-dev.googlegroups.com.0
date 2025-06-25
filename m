Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB37O57BAMGQEATIJZBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id AC1B5AE8449
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:47 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6fb3654112fsf34295186d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857584; cv=pass;
        d=google.com; s=arc-20240605;
        b=UWRXH2FlKSLjK8eZax1sWqT25DZxDu1EKb51jqdIFxOt7oaS3gzm5w5zhhF1oqF+YV
         WtIRtVSKjzl43RmgyO1jn9Qh6Is3ccomFgY1LwaBBYDJbmJiNM/s+fF//atpT+NnSwpF
         qdhPcWP/f6sm19VwJzMN1MN9BVSdsBCHnglmXQBkniWb5YpQeacMZKk/13t1qTvSPcyH
         fq7AZkdY9hgJtY15Y4J0dkhX+Roq6EcMqbCbDxDxFEI/yuCHHTZR8FR+AnTk0bLbWdbc
         59nQKXRCHAzsU3KZi/uxkMev0a6rYAnVCR9zkzHOxnFUVMLNwBqjvex0/Zsmr9JbjVko
         jiZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PypYbWZeCRhbHQZKS+ZB/YJ7Tur9iuRj1HtVq2z5kos=;
        fh=83ZwCBbBAfNZJ0baKtJ4L2GrgcsKnuyEOwvHCxCgJH4=;
        b=RGygc3M4ndX/mmnoP0uaI4QKS/2rlCUswMpbQNoEMkm7f+hMDbz2M/X3SJfT9hjkbw
         MWfqlaOtodvHX43glTj43IfdQp5R92gxz2ylWsNKPDGR+gpYXI6keWsE5jI9nnU8nnvR
         bf1wc5XZ8IsLNkZ6X5Qo8tY6yLb1R8IjvBKP+xGToJE2RUsmFRbZusUephc0X+4h8Tnb
         C3gT6ZvO+ofFnGz5OUNU7BFEntvTAsg9TYQPuh+dcylWxnYMYUNHmU2gxWT4iXOM1vmp
         AcJhVIfoajyGlnUPnl6go9lYDSCaULJJsHQWmhzrCNXV/qT9BiJmScF0uzGfXfPlLAgK
         KqFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N0G3gV+E;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857584; x=1751462384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PypYbWZeCRhbHQZKS+ZB/YJ7Tur9iuRj1HtVq2z5kos=;
        b=R0eGyKTuJdzw++zwzQa9F0eFO+2HRrqIMYRtPEYz2pwWgqPz55Oym9sCxc3pY8zHXZ
         wX1nVKbc+Yo7S2hfAaIm0LrtJe+PFtdYMofHZJ0nw3Cet8LEqe7F2mChhuwRuAjqvRcL
         Vm5ww8dBJmDGF6X54a5hT6ZrCu/AVt6vyedmLpJQRpZVLDMLRiOzCErA2pQUIFT3FhRN
         QMpQasmM1KmZ8oFCQT6qHqg5qmW3HkLeP0VAyP0n0OhNuMeuEK9lcLdHduZ69r5978ED
         Uj/vGh/Q3x0xbnwkDS6lkQg6b8XvuuksHgX+Manghb3PwV06YMNmInAL6yIa2zCpWVXY
         pfpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857584; x=1751462384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PypYbWZeCRhbHQZKS+ZB/YJ7Tur9iuRj1HtVq2z5kos=;
        b=J3PqVF5ywpIZidA6eRYXOStJSWvG8UKuviePpTuOJ0nHyrUUDBfizBC1FA1dKI469H
         xGqSaztGL2JPWo9ayTx1KRkWojQuB/6JDH+ebqSJqZcu5hUNgPLSo7bEH7gUb55xwz62
         dXUrWi2acMryDF5L5PJlhXL//mtWfuls7gFlg1hLsif/P55FR0MbHpR9le3+otVRqJeQ
         CtJueeFaWB1vjsMjhc3QzmK0b1jF+NpQX/+MxUze+2JzctQ7NnEhOlBPxT3a0lW7qcZe
         er2ctQZoFvHJ2y21jk2p97bK8N+mvdsOiKkNt4/I8/P/XJWWslz2tHHCPaAGS7PQ074Q
         FgnA==
X-Forwarded-Encrypted: i=2; AJvYcCW58i0gAl8FAAHa0XGqBS0+6CpzGQ2PL2hcIPjquCsv+9GaIbTHA2AW+ZKheaOBB/bWTxCc6A==@lfdr.de
X-Gm-Message-State: AOJu0YwRuG/GohHUCLBblVgHeuR+KQuO6OO3JrsCD8CdJBlzmdHUitEx
	FtkXT8Ulzx5+yvCIWOldCbGd9UXZOTeqRbjK6xsPix55A4y3z8k81IDW
X-Google-Smtp-Source: AGHT+IGVtQEH9U09yxzFfyXp4jQsouN9r058sjArCjpEJCxji8uIHgi7iIu1LEiNLiyOGmzf3687jg==
X-Received: by 2002:a05:6214:570a:b0:6fa:bd77:3501 with SMTP id 6a1803df08f44-6fd5ef3bd1emr43038836d6.11.1750857583791;
        Wed, 25 Jun 2025 06:19:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcroZZvdpeD8Ate3OhfwRgxTo7f/PCbWVbrXMjP6EFOYA==
Received: by 2002:a05:6214:2585:b0:6fa:bc23:a7c2 with SMTP id
 6a1803df08f44-6fd0080e3e1ls118716066d6.2.-pod-prod-02-us; Wed, 25 Jun 2025
 06:19:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwrJE56ghP5NPxavxRIEKC+/j+E+jJa26QUivJ/6U7k3s6ACl+7pl0Fn/j00W3jvMvywqHQNqCdBM=@googlegroups.com
X-Received: by 2002:a05:6214:da2:b0:6fb:1c3:f518 with SMTP id 6a1803df08f44-6fd5efa99dfmr37206996d6.44.1750857582820;
        Wed, 25 Jun 2025 06:19:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857582; cv=none;
        d=google.com; s=arc-20240605;
        b=CjFM3LK/sc4t/zzKyM314JI+X8SDVfWTlDTz2KYX75+Wt2MEVfB4BtJNRdsl6f+g2A
         jGC3IpLUrIDIHvM8/lrGEvxHNBkEYMH4WYjurh/uhybjuF4OsaJLsZpobHAqpmEOJT9a
         Lr/2oT1y9HdU7QqmSWje5hfhLYRCq0QXrsQxq9vEZ6b7FVeak4m+QEVl5er2vNA1564c
         EFLsy/3MY0ahG21yP1Pr/dCsROBnUC1cjgAgxv5sXrQbBMVsQiTjE4E2hYlPhqEB3zgk
         mSoskLdy02w/+sx5iX2nConq1rIqTGhfr1vzWZkHOJGYp+dPczvjHvb+bpwyySBPtKeS
         zmVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VaTVD/mLalAtTgGY4GQNF+mAYuMi86gY31K7sa0UK48=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=h7DLMsXMeEccoh2F3bwo6yrazlol14Wy0uYcCchxHawZU9wtLRLj2OOb/EBNvZ5Vre
         5YShC9FK5ldW/OHhvd69qrloKcqyRuLNKgq42fSsokCvNvaHskllFj+Gudu1dcFZvwqI
         f1M1b59m6XbgrHfQBG2lSRNL9R70l5FvoPc2SaN/zcOBwEu/3/W/YD6tj8DrfriAsSuN
         NuZ2juQCWWzvYqf8zvUoBj/3TTjwu/ZjvOGshoSQSdetuefm8UbEu8c6k+Je3T/JGuul
         LyFcNaW8QX9N8W4Af4YqfAJMXaULMMzTFukulP8B16xPAUapLlvJUrCb+gy4vBBPLSPq
         5VVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N0G3gV+E;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd094dfcc0si6254646d6.4.2025.06.25.06.19.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 88376A52615;
	Wed, 25 Jun 2025 13:19:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 54036C4CEEE;
	Wed, 25 Jun 2025 13:19:41 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev,
	virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 7/8] dma-mapping: export new dma_*map_phys() interface
Date: Wed, 25 Jun 2025 16:19:04 +0300
Message-ID: <7013881bb86a37e92ffaf93de6f53701943bf717.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N0G3gV+E;       spf=pass
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

Introduce new DMA mapping functions dma_map_phys() and dma_unmap_phys()
that operate directly on physical addresses instead of page+offset
parameters. This provides a more efficient interface for drivers that
already have physical addresses available.

The new functions are implemented as the primary mapping layer, with
the existing dma_map_page_attrs() and dma_unmap_page_attrs() functions
converted to simple wrappers around the phys-based implementations.

The old page-based API is preserved in mapping.c to ensure that existing
code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
variant for dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 include/linux/dma-mapping.h | 13 +++++++++++++
 kernel/dma/mapping.c        | 25 ++++++++++++++++++++-----
 2 files changed, 33 insertions(+), 5 deletions(-)

diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 55c03e5fe8cb..ba54bbeca861 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -118,6 +118,10 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		unsigned long attrs);
 void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs);
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
 unsigned int dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
 		int nents, enum dma_data_direction dir, unsigned long attrs);
 void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -172,6 +176,15 @@ static inline void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 }
+static inline dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+	return DMA_MAPPING_ERROR;
+}
+static inline void dma_unmap_phys(struct device *dev, dma_addr_t addr,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+}
 static inline unsigned int dma_map_sg_attrs(struct device *dev,
 		struct scatterlist *sg, int nents, enum dma_data_direction dir,
 		unsigned long attrs)
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 74efb6909103..29e8594a725a 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -152,12 +152,12 @@ static inline bool dma_map_direct(struct device *dev,
 	return dma_go_direct(dev, *dev->dma_mask, ops);
 }
 
-dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
-		size_t offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs)
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
-	phys_addr_t phys = page_to_phys(page) + offset;
+	struct page *page = phys_to_page(phys);
+	size_t offset = offset_in_page(page);
 	bool is_pfn_valid = true;
 	dma_addr_t addr;
 
@@ -191,9 +191,17 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 	return addr;
 }
+EXPORT_SYMBOL_GPL(dma_map_phys);
+
+dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
+		size_t offset, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
+{
+	return dma_map_phys(dev, page_to_phys(page) + offset, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_map_page_attrs);
 
-void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
@@ -209,6 +217,13 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
+EXPORT_SYMBOL_GPL(dma_unmap_phys);
+
+void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+		 enum dma_data_direction dir, unsigned long attrs)
+{
+	dma_unmap_phys(dev, addr, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_unmap_page_attrs);
 
 static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7013881bb86a37e92ffaf93de6f53701943bf717.1750854543.git.leon%40kernel.org.
