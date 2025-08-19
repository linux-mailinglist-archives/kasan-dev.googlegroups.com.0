Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBEPNSLCQMGQEGSZMTLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 72E46B2CADF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:27 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88432e5aa43sf644138639f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625106; cv=pass;
        d=google.com; s=arc-20240605;
        b=IjBRV7zN075eb1msVczNS715xQsa0IbeXOOnxvt/W9CQwRS1/cEveS2hNJfChaT2Wu
         RsMPJ0/8gJQQVYtGHsZ7mGqNbVh9tLgl2/ktLeHWlIl4e2huAbuDO+ivgs+8Mh+5ujr2
         FOwxMcFBB5zKvo/pqxllqZAJjq66ebJ8cM95LNHAbw0JosKwjqMI8piikiCzCc3CDQVl
         N5y7+VnC8CPVjFtC1svDP6xsNMPLUG7jp1gLBfsUl7+fw27QnqhhCEgsufgWVuZPUVsW
         9J7+G2XtueMvBoyNrpjrxxH7qW9ilL2WbeQ+8FI35rqTue92EwAXRp4rUqV/slW1Q46M
         hTzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=g/3s1WqNJSv14RYihtrax0Z01K/3VrAcQbhH3SwO2xA=;
        fh=3N6n2ek4dLo+kHpO/W4ZHXargEAFAd5Y1gHnxyzEeCo=;
        b=WfYhdq7tDkc4QPuF0MhSZLamBuOTd7qQWPf0iIZi2qnR5Eg7MP8prvo3NtMCNb85F3
         +StW9o72YzOza3oCoVtZoChlr+jCGBcX5kkqGHbd3mp0+62neoPb25nQ0Tmx7jczv8w8
         2CtqXQbEbW4Kj8nzTFL0SGJ7Ad6crnmXQRydqmQ3EKIoqU5IiNINwNdvbdeTttz8hWx7
         x2J8oe4557sXNzDHMMo3NXhSg5PKxCPBrLd8/W50/tOAyy0cfjp1n9PVdRmHoTUBPrxB
         hS9STbFxKPkstS0wCAkeLo3KKMTeyOZvuD72Yukv56Rg2QSaLstN+9jbkpGj2CO/92q/
         i/tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fqZWHIaP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625106; x=1756229906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=g/3s1WqNJSv14RYihtrax0Z01K/3VrAcQbhH3SwO2xA=;
        b=MFAZrIAnnYTt6f1IcFWfdZUi8EU6uaNW24TAsvMbnlU1PSgOvV7mmPQDPsuI8DTSFz
         L/LaUZa+Cwl3b4+bW7qCNHKzMYMv/f5onkUPv97GtCWA12pyBNboHp1Kc6W3ya5vRdR3
         KtoYMb3VeuYx6fiyyhuV3iaMEGhp46BhpT1cF/55rq0ZliklC4Mojr4FPif63HTiszsT
         Z9yFbKKFUPUeycFrz5NR+NXVyzPNsziez0JAfkzx/2E3JWPoG/CJNOEckmSIQ/at/AXF
         W56SnPndSAc3RXixOM/3Rxu/6qKgbIy+A3R4MAq+etsjeVJxK1F3HwSbYIPjmIkphBuO
         doyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625106; x=1756229906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g/3s1WqNJSv14RYihtrax0Z01K/3VrAcQbhH3SwO2xA=;
        b=g3K+zaOd/7Hy8M+qod74xYpzTH4ic7iXr+c8s+Cw1KewkPi7yYOB8E8fZbvA2YJ1dS
         b+HtRCtljmNo+7GTaBKPhhT+YlF8udWutKuFop/U8OBOhlcqfo1l9ZZxbSg92/LhcyHr
         pAF0k4gnDrtHhlLnIjQvf2IZMWXs+QPuyBJxWyTSuqOn5oDzPHp4LWWW40DyCQjJGu18
         dN9YEkqWDvljTBIu5C4jA3wWRu3LuokyNQ8/eQpPGzAzNEmENG2uo4y862pv/YDn0eIK
         RhcD+z7co3PBQkJL0ju9gC5Df8tq4iViUuaeqbruM5EqfJ970hmFt7N2Sw9jJYiq3VSz
         SZew==
X-Forwarded-Encrypted: i=2; AJvYcCW9rYI2DodP20yOsGd3iQQsJkVKDC5WV8Rv5mKJWTiEjih7zJLSqfEMfWeUV9QjSBfwo8khPQ==@lfdr.de
X-Gm-Message-State: AOJu0YxnitOIR2Crv8s6jIo74OAIDSFBA4VT5N0bpVCdRkVCv6u5P+E/
	H35Q2G6nHZFMWSJaPgP1Tq+qLtrFuJXs2bQL21IoB8BfX8kk/qBSQxCL
X-Google-Smtp-Source: AGHT+IFyh7C53a+//QjEqG23NRrbT3A1+xVPNmLa2iMksEotTZbzXT2lMU78IJ2bP/y4jQOJRq8K5w==
X-Received: by 2002:a05:6e02:17cb:b0:3e5:53da:3c4 with SMTP id e9e14a558f8ab-3e67665c0b8mr48903565ab.17.1755625105911;
        Tue, 19 Aug 2025 10:38:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZegUc7mcm4tOQj0CYky7twcnE9LLy/ZdTxVMRwKnYZzHQ==
Received: by 2002:a05:6e02:17cf:b0:3e5:8140:1e59 with SMTP id
 e9e14a558f8ab-3e58140209als34044915ab.1.-pod-prod-03-us; Tue, 19 Aug 2025
 10:38:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqv4wsTJjxIOihNmiviJGX1DQZ0MKNGYcE1zgFDFl2Og8toLXBeVChDKuUG34DLF8S0qMvYTbiDA8=@googlegroups.com
X-Received: by 2002:a05:6e02:168e:b0:3e5:57f3:abfe with SMTP id e9e14a558f8ab-3e676634c7amr51196575ab.12.1755625104559;
        Tue, 19 Aug 2025 10:38:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625104; cv=none;
        d=google.com; s=arc-20240605;
        b=RuJp2AmRvja1HA6vG+vjxMZAQClA90o4QREqP1tMxsNH27ZSGCVsHsJTGKy+LkniHs
         EV4EIZ10q/BFrwlBXV9/zlPHbQ3g9OsgYdW7NtJyI/8E7TqULi4F4cwc/8YlKyULnCpk
         2/4vsYR47lNW0eLWJoqmXZkrqgiPor3O508bsfnnr8OeVywLjkgE/CUbuRtdIWcRJqqP
         snPqze55+BG39Pxb8+pn0axcmL2V2D78K9EPRFSRUaH/cngksZ/gNAn9idxOITD0LbcC
         6oU5MSMnNp60ObDGEHU5ETyn+5M93dB0NC/ahuvZISnowWq8RSB6NT1W7Z0TaClVt0dd
         jhnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6wpDDK6cIOpZvCaJNMQsaJEJNnsJ8lmKgCJXsKe4wl4=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=UFZwVP9b31XSo/sl0YGvrA+PJW8uPHH0F4PXn4jmCZwIjJIjI6FmA65XvrImwWsOiX
         3ly4cB+1VtkcryCNmRaJsQLlsy4eRHWPBsMhzksNVCLoN83lAwJaU0oe74gnZ4rD6BRO
         AxFUNWgnnc1VJ83HF0K94Mb93C7ftnKBrNW2TD2CAbJazHIIMmu0/5ITP1lJxAF71z6d
         x4Xldpvaka4PxzplnOpeADFbk0+QZp7zEpltT18vZaGdJNQbJv0jcyvUEabx9CJ1Ikn5
         azAUS+NVWd2IUq96t8PGvvVyOOXR9NlvawqvENNE17WUoO/Jg/Z3hBbqDuoGnpHNybsz
         EZXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fqZWHIaP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e785a12si4314205ab.4.2025.08.19.10.38.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id CBE4C45A18;
	Tue, 19 Aug 2025 17:38:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9ADAC4CEF4;
	Tue, 19 Aug 2025 17:38:21 +0000 (UTC)
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
Subject: [PATCH v4 11/16] dma-mapping: export new dma_*map_phys() interface
Date: Tue, 19 Aug 2025 20:36:55 +0300
Message-ID: <bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fqZWHIaP;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

Introduce new DMA mapping functions dma_map_phys() and dma_unmap_phys()
that operate directly on physical addresses instead of page+offset
parameters. This provides a more efficient interface for drivers that
already have physical addresses available.

The new functions are implemented as the primary mapping layer, with
the existing dma_map_page_attrs()/dma_map_resource() and
dma_unmap_page_attrs()/dma_unmap_resource() functions converted to simple
wrappers around the phys-based implementations.

In case dma_map_page_attrs(), the struct page is converted to physical
address with help of page_to_phys() function and dma_map_resource()
provides physical address as is together with addition of DMA_ATTR_MMIO
attribute.

The old page-based API is preserved in mapping.c to ensure that existing
code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
variant for dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c   | 14 --------
 include/linux/dma-direct.h  |  2 --
 include/linux/dma-mapping.h | 13 +++++++
 include/linux/iommu-dma.h   |  4 ---
 include/trace/events/dma.h  |  2 --
 kernel/dma/debug.c          | 43 -----------------------
 kernel/dma/debug.h          | 21 -----------
 kernel/dma/direct.c         | 16 ---------
 kernel/dma/mapping.c        | 69 ++++++++++++++++++++-----------------
 9 files changed, 50 insertions(+), 134 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 6804aaf034a1..7944a3af4545 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1556,20 +1556,6 @@ void iommu_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
 		__iommu_dma_unmap(dev, start, end - start);
 }
 
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	return __iommu_dma_map(dev, phys, size,
-			dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO,
-			dma_get_mask(dev));
-}
-
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	__iommu_dma_unmap(dev, handle, size);
-}
-
 static void __iommu_dma_free(struct device *dev, size_t size, void *cpu_addr)
 {
 	size_t alloc_size = PAGE_ALIGN(size);
diff --git a/include/linux/dma-direct.h b/include/linux/dma-direct.h
index f3bc0bcd7098..c249912456f9 100644
--- a/include/linux/dma-direct.h
+++ b/include/linux/dma-direct.h
@@ -149,7 +149,5 @@ void dma_direct_free_pages(struct device *dev, size_t size,
 		struct page *page, dma_addr_t dma_addr,
 		enum dma_data_direction dir);
 int dma_direct_supported(struct device *dev, u64 mask);
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 
 #endif /* _LINUX_DMA_DIRECT_H */
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index 4254fd9bdf5d..8248ff9363ee 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -138,6 +138,10 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
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
@@ -192,6 +196,15 @@ static inline void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr,
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
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 485bdffed988..a92b3ff9b934 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -42,10 +42,6 @@ size_t iommu_dma_opt_mapping_size(void);
 size_t iommu_dma_max_mapping_size(struct device *dev);
 void iommu_dma_free(struct device *dev, size_t size, void *cpu_addr,
 		dma_addr_t handle, unsigned long attrs);
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 struct sg_table *iommu_dma_alloc_noncontiguous(struct device *dev, size_t size,
 		enum dma_data_direction dir, gfp_t gfp, unsigned long attrs);
 void iommu_dma_free_noncontiguous(struct device *dev, size_t size,
diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index 84416c7d6bfa..5da59fd8121d 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -73,7 +73,6 @@ DEFINE_EVENT(dma_map, name, \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
 DEFINE_MAP_EVENT(dma_map_phys);
-DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
 	TP_PROTO(struct device *dev, dma_addr_t addr, size_t size,
@@ -111,7 +110,6 @@ DEFINE_EVENT(dma_unmap, name, \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
 DEFINE_UNMAP_EVENT(dma_unmap_phys);
-DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
 	TP_PROTO(struct device *dev, void *virt_addr, dma_addr_t dma_addr,
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index da6734e3a4ce..06e31fd216e3 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -38,7 +38,6 @@ enum {
 	dma_debug_single,
 	dma_debug_sg,
 	dma_debug_coherent,
-	dma_debug_resource,
 	dma_debug_phy,
 };
 
@@ -141,7 +140,6 @@ static const char *type2name[] = {
 	[dma_debug_single] = "single",
 	[dma_debug_sg] = "scatter-gather",
 	[dma_debug_coherent] = "coherent",
-	[dma_debug_resource] = "resource",
 	[dma_debug_phy] = "phy",
 };
 
@@ -1448,47 +1446,6 @@ void debug_dma_free_coherent(struct device *dev, size_t size,
 	check_unmap(&ref);
 }
 
-void debug_dma_map_resource(struct device *dev, phys_addr_t addr, size_t size,
-			    int direction, dma_addr_t dma_addr,
-			    unsigned long attrs)
-{
-	struct dma_debug_entry *entry;
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	entry = dma_entry_alloc();
-	if (!entry)
-		return;
-
-	entry->type		= dma_debug_resource;
-	entry->dev		= dev;
-	entry->paddr		= addr;
-	entry->size		= size;
-	entry->dev_addr		= dma_addr;
-	entry->direction	= direction;
-	entry->map_err_type	= MAP_ERR_NOT_CHECKED;
-
-	add_dma_entry(entry, attrs);
-}
-
-void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-			      size_t size, int direction)
-{
-	struct dma_debug_entry ref = {
-		.type           = dma_debug_resource,
-		.dev            = dev,
-		.dev_addr       = dma_addr,
-		.size           = size,
-		.direction      = direction,
-	};
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	check_unmap(&ref);
-}
-
 void debug_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
 				   size_t size, int direction)
 {
diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
index 76adb42bffd5..424b8f912ade 100644
--- a/kernel/dma/debug.h
+++ b/kernel/dma/debug.h
@@ -30,14 +30,6 @@ extern void debug_dma_alloc_coherent(struct device *dev, size_t size,
 extern void debug_dma_free_coherent(struct device *dev, size_t size,
 				    void *virt, dma_addr_t addr);
 
-extern void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-				   size_t size, int direction,
-				   dma_addr_t dma_addr,
-				   unsigned long attrs);
-
-extern void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-				     size_t size, int direction);
-
 extern void debug_dma_sync_single_for_cpu(struct device *dev,
 					  dma_addr_t dma_handle, size_t size,
 					  int direction);
@@ -88,19 +80,6 @@ static inline void debug_dma_free_coherent(struct device *dev, size_t size,
 {
 }
 
-static inline void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-					  size_t size, int direction,
-					  dma_addr_t dma_addr,
-					  unsigned long attrs)
-{
-}
-
-static inline void debug_dma_unmap_resource(struct device *dev,
-					    dma_addr_t dma_addr, size_t size,
-					    int direction)
-{
-}
-
 static inline void debug_dma_sync_single_for_cpu(struct device *dev,
 						 dma_addr_t dma_handle,
 						 size_t size, int direction)
diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
index fa75e3070073..1062caac47e7 100644
--- a/kernel/dma/direct.c
+++ b/kernel/dma/direct.c
@@ -502,22 +502,6 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
 	return ret;
 }
 
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	dma_addr_t dma_addr = paddr;
-
-	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
-		dev_err_once(dev,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		WARN_ON_ONCE(1);
-		return DMA_MAPPING_ERROR;
-	}
-
-	return dma_addr;
-}
-
 int dma_direct_get_sgtable(struct device *dev, struct sg_table *sgt,
 		void *cpu_addr, dma_addr_t dma_addr, size_t size,
 		unsigned long attrs)
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index fdabfdaeff1d..0ca098d2e88d 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -152,12 +152,10 @@ static inline bool dma_map_direct(struct device *dev,
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
 	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
@@ -177,6 +175,9 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 		addr = ops->map_resource(dev, phys, size, dir, attrs);
 	} else {
+		struct page *page = phys_to_page(phys);
+		size_t offset = offset_in_page(phys);
+
 		/*
 		 * The dma_ops API contract for ops->map_page() requires
 		 * kmappable memory, while ops->map_resource() does not.
@@ -191,9 +192,26 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 	return addr;
 }
+EXPORT_SYMBOL_GPL(dma_map_phys);
+
+dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
+		size_t offset, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
+{
+	phys_addr_t phys = page_to_phys(page) + offset;
+
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return DMA_MAPPING_ERROR;
+
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+	    WARN_ON_ONCE(is_zone_device_page(page)))
+		return DMA_MAPPING_ERROR;
+
+	return dma_map_phys(dev, phys, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_map_page_attrs);
 
-void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
@@ -213,6 +231,16 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
+EXPORT_SYMBOL_GPL(dma_unmap_phys);
+
+void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+		 enum dma_data_direction dir, unsigned long attrs)
+{
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return;
+
+	dma_unmap_phys(dev, addr, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_unmap_page_attrs);
 
 static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -338,41 +366,18 @@ EXPORT_SYMBOL(dma_unmap_sg_attrs);
 dma_addr_t dma_map_resource(struct device *dev, phys_addr_t phys_addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-	dma_addr_t addr = DMA_MAPPING_ERROR;
-
-	BUG_ON(!valid_dma_direction(dir));
-
-	if (WARN_ON_ONCE(!dev->dma_mask))
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+	    WARN_ON_ONCE(pfn_valid(PHYS_PFN(phys_addr))))
 		return DMA_MAPPING_ERROR;
 
-	if (dma_map_direct(dev, ops))
-		addr = dma_direct_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (ops->map_resource)
-		addr = ops->map_resource(dev, phys_addr, size, dir, attrs);
-
-	trace_dma_map_resource(dev, phys_addr, addr, size, dir, attrs);
-	debug_dma_map_resource(dev, phys_addr, size, dir, addr, attrs);
-	return addr;
+	return dma_map_phys(dev, phys_addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_map_resource);
 
 void dma_unmap_resource(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-
-	BUG_ON(!valid_dma_direction(dir));
-	if (dma_map_direct(dev, ops))
-		; /* nothing to do: uncached and no swiotlb */
-	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_resource(dev, addr, size, dir, attrs);
-	else if (ops->unmap_resource)
-		ops->unmap_resource(dev, addr, size, dir, attrs);
-	trace_dma_unmap_resource(dev, addr, size, dir, attrs);
-	debug_dma_unmap_resource(dev, addr, size, dir);
+	dma_unmap_phys(dev, addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_unmap_resource);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon%40kernel.org.
