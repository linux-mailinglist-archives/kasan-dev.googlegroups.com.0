Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6GVYLCAMGQE7BMW6YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D894B1A1AC
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:48 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e8e0f10c3cesf5050251276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311416; cv=pass;
        d=google.com; s=arc-20240605;
        b=GT+fljoOTJIztkAVbtOwLyV3fkc/72KPytPnzb9CZW4wa0ZEHhVFR9BxSBbrd0JeTv
         yxKL3VwQu9qxawTGvBFw2hmlgU+dHMPytGdEwvUsaNfr6CpGQXrOUvYsrBjTj16tmV5f
         O2/easv3oNs4HF7BiSPkqWByVc+0sm69SwJIKaQmhJ6QLiukoPWvnbufWo6kIrdy4nv7
         yiiQKeUURx9RDvQE25H/aXgGVFSZ4Xk8AexAGxCBacps+bE+p9RcipG8I1PpVPs8JiLs
         cz8ycLJ/G0hfEZ5nZe0Hlq2NbkjqHhQwzkUzuq/O2IdJ5eZVXHBFgRbzCEV10Xqkv8LG
         0cbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IHrKN5kpuN9r0nXZvA5QwKhdkQ0zH6a8G3k+gv2xZf4=;
        fh=8bCsr8IqZOXbfCbUK2h0c54g+I4lp9hSG+3XDvemfIQ=;
        b=FcJCHnJ6b28ZHDngcgDxjV4lWZ48AJVWITmtaFxN5Emx87I1zirOWq/1mjby/wfxV5
         lsQWhkH9dOqU8K9Yrb2/WCwF9lmURMitC2LIZSJE9jW4kOAIoIYNIKZ3YivgvfxGoEwh
         mMuJtiuOGzeDBxnll7QjpduppbfvHW/wDYs7/V6oaHBvwE3iVMGsttAl8ophFkOnjkXv
         412BYkTwGGmJHdzUlezhGBhaHQIOywV2l4pKSyV/nCqtOc7AOC6pcgJzX8mpD/NUhXmH
         HVl3TYaeFI2r/CeNTCcimLN39sJd2iGTY4iYqbItNhqfLHvNTIa2kAiYngQvc7Q8FJf/
         VAaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WRgsvRlF;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311416; x=1754916216; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IHrKN5kpuN9r0nXZvA5QwKhdkQ0zH6a8G3k+gv2xZf4=;
        b=IA5uWi7O7hzH4jaj+Gwzn3SyEvNDrylkgeznpKB/rwjbM9w3xNU2VcwmT6ZKTDxEWT
         DShg+EHXmoOaQZGZ0AyVEDDzMX/I+Zz/exLkyT7t/yTxsBd63RQCtDWwftO3LqotDE1+
         k1yWux2K2FdzZbRq2gXpy9ZAyEWSR3J35BjQPiI6yquododC0heo/vikB6+KzWV2SP/H
         gIU8a+NK30QcIIbKUW+SvgjKqc4M23guYYHmAt0ggH9GvMdTofGgHtlw4Yua/YAlg+eE
         iIsINd1SWIsvhsbtRcgeZEZHxMGIVtQWd7eA0Bge1Ogg64A7eSk16a15tYw9jWSSGna0
         fRpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311416; x=1754916216;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IHrKN5kpuN9r0nXZvA5QwKhdkQ0zH6a8G3k+gv2xZf4=;
        b=NrAOrZ24QpCgq7iWtI121Q+ySrf/VPIEcnpTXlTo7xh5IDDn1J1xtgHbgKf+gAubDj
         l1xas/+Z5+t6H8K0JM274kPkjguGSj9KK3JicQQc+MjtzfjoAdptSmDMdxVI1Wn8aJ+s
         Ob/hRsDusqmrparHVMMfKkrx4u0fuqRilE1Rbw3oa67J0STseknJPy/bqW7srhCI2lJM
         ZGsNyQZlWfmPvdTy50dNep4XBWcLMroErDMycSH7gMEusAYkCzVGa5R9u65uqTE/PMxM
         jov2JIx6hAZIxym15/Azn/PHFVMeeZnGPES8UJVvXenedaQr0bNKpSsUk/NUM37oEQQR
         77bw==
X-Forwarded-Encrypted: i=2; AJvYcCWcdQ0nYia8dBIwMlvfsyBM/wz7+jUG4U7coJnlMAz2PQKB13hTaVD+ln9iSbRCxq4XP5XIQg==@lfdr.de
X-Gm-Message-State: AOJu0YwoABfopNgOKNE/Ysyr5msQIlg3x4jktntgKK413GrzEMRYhOOp
	mSH+/X9/NdVdbuM43+nwucOG88AKQZvX0QySW7fjMu8rcKoeNlx9WXow
X-Google-Smtp-Source: AGHT+IF2bPDgtBrFZcKGf6ZfST/f6IGfWaf0UNJ07FfkaDCQxK6Em3VYHhJKsiZnsqL2yFDLAKBrvQ==
X-Received: by 2002:a05:6902:f86:b0:e87:b846:33b9 with SMTP id 3f1490d57ef6-e8fee05b41dmr9279246276.21.1754311416608;
        Mon, 04 Aug 2025 05:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdnfV+LDlZICeXqSndZS762sIQyuSb1AX0hBCyTItRFXw==
Received: by 2002:a25:dd41:0:b0:e89:91db:269a with SMTP id 3f1490d57ef6-e8fee87e347ls1118182276.1.-pod-prod-00-us;
 Mon, 04 Aug 2025 05:43:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZdfLx4YQeOVAJZPZHP9G5dxBeIn4gTOcgtFU+fkl/qJ+YSE2rD2faHD7erPtG3ohW1SCXlkRFtfE=@googlegroups.com
X-Received: by 2002:a05:6902:708:b0:e90:1aa:60ed with SMTP id 3f1490d57ef6-e9001aa6559mr4250829276.24.1754311415682;
        Mon, 04 Aug 2025 05:43:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311415; cv=none;
        d=google.com; s=arc-20240605;
        b=iueW1r27kS3VtAJBoEslqIcAIFJWEUps0EsvSWYfbWvfbyTHUxdNKo+OIPuyA3t33b
         TO4GUdgj6glhl/U4laC5yvnEBvKYSAYzuXA68HJ3uaXqn17vmMjKZHdJHOVaCxwK+H3K
         gImCvfBfeqN7N6WXMN3LamSK1ew9LP92f8HEUyIccrreQJwjiiskW+4qV9AgwC9JxQYS
         yL6+6Ua2lO9YTJPjSTyMjghWGPzY8Vbf6DB2l2ZO9iUjxfWPyuvBuZfFWkFp8hhZyV53
         FITpeK8fUkPoLA4UGLfiLondn2ulgdu+/XjLPlp7rZ/Zc+wIgbGeVs7kE2YjIxL5ybyV
         EcWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MLLzwi1yAXsHc08Aygf0gJ2rcKhVnpp9gk2ta6mt2yU=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=g+hG19DuAqgQDrZDF278pFsDCOy/echtsdc+8Bku8BMi/w+tHTbQFAxY+iYbaqOPxI
         jL4qHF74g6zqqDaM4uyMH2PZKTwP1wKeNJIMoAfU4a3kGq/muwnPF5pJWnkxdxihKdyi
         FYX7F6a2cSDjBrhA6DNRxJ5iYPP+O2S8dG4TvACoNZ4NJkDAnlMXIPeOOlYa6+DlKqmk
         QXpNuBM8nGNGD4+/9+9FY2eRha8B9sDKrVgb0ut4/o1Nb86+Dyay5AlO9Xp0IpoUOwbp
         N1fgSt4vWBdojaQsbvd/YRxPiA17eMvZw8D6evB374Bs+V6+1mVl/EphVzD8HgLj4xvs
         Luow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WRgsvRlF;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e901086857dsi36796276.1.2025.08.04.05.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 46869A55826;
	Mon,  4 Aug 2025 12:43:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7673FC4CEE7;
	Mon,  4 Aug 2025 12:43:33 +0000 (UTC)
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
Subject: [PATCH v1 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Mon,  4 Aug 2025 15:42:38 +0300
Message-ID: <7e10dcba2f3108efc6af13bfdbe8f09073835838.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WRgsvRlF;       spf=pass
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

As a preparation for following map_page -> map_phys API conversion,
let's rename trace_dma_*map_page() to be trace_dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 include/trace/events/dma.h | 4 ++--
 kernel/dma/mapping.c       | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index ee90d6f1dcf35..84416c7d6bfaa 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -72,7 +72,7 @@ DEFINE_EVENT(dma_map, name, \
 		 size_t size, enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
-DEFINE_MAP_EVENT(dma_map_page);
+DEFINE_MAP_EVENT(dma_map_phys);
 DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
@@ -110,7 +110,7 @@ DEFINE_EVENT(dma_unmap, name, \
 		 enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
-DEFINE_UNMAP_EVENT(dma_unmap_page);
+DEFINE_UNMAP_EVENT(dma_unmap_phys);
 DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 4c1dfbabb8ae5..fe1f0da6dc507 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -173,7 +173,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
-	trace_dma_map_page(dev, phys, addr, size, dir, attrs);
+	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
 	return addr;
@@ -193,7 +193,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
-	trace_dma_unmap_page(dev, addr, size, dir, attrs);
+	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
 EXPORT_SYMBOL(dma_unmap_page_attrs);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7e10dcba2f3108efc6af13bfdbe8f09073835838.1754292567.git.leon%40kernel.org.
