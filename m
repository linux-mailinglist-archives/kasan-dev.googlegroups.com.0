Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBDGWYLCAMGQEAH2VKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 11407B1A1B8
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:58 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b076528c4asf5985191cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311437; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fmny0VCuO/3m0PuLNi0vGjDwVBxIuXVcgUxFavQYR0R2zYBjPvNeB4bFxj6Ckx9Xog
         MNcWpbFrawPgw1cBrNss23rWo0j7Kv/1lrZ72gY9LZO6DOkYuk0H9KBfDnQXGSeWAccR
         5cuTomiInXheMqim3GUQUkKyRHSeTA6+GK0+W0HSYrpE+qcn4hkbcbRTLRTyZSQB/cY0
         7N+TmOqanPDx7CQaV9vby9oJB7ep3Cj3xPgI50zy1/x2g7DiSRwOz2gn/tphye/CFKGd
         Qxc986R3poOMG1x95/oSBUJazp7IHa0TaXRYgJxIMCQ8dnpZmcGbHKpX0EmNAQ6GelFG
         lwMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VS1xXl/6JkInUoA+4DzPuEj3FzH/0wrm+ZanNLRWE5A=;
        fh=KBNsqsbhYB0WdnxG2dRE/vJK0N+b3bS0mS6kjFyHI2M=;
        b=leMQeh89slwtt1d8VuqWJvz/U2/CxQ2FPudLTl9sYG7z9knFbAbCdj7XKU30n6HqDg
         7TOl2mD5daYrMmBfx1eBvdteZSmL5WqLcaZ5rDVzorsWWPdS13xIFpvJ8F6PogzXE29D
         DkavL0cAM0kxZrHwLQwIXEKLq++q/6VAE3w5AVIYFepKrdj0ipdRLIdWPEKGf8HiO8jw
         wSVlt2t5JDehxFWdKMjjl3KY0+0q03a+ZgSsWw1k64txJwfWWdWAMpSxiVAEJxjzTg50
         vuJAPU3m474gyPNE7PbeHz+vMGVToL0s6bZIR3ZBdVarlhlashnI+JHDapuhcW0tI7aU
         KYPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ihw3Mu90;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311437; x=1754916237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VS1xXl/6JkInUoA+4DzPuEj3FzH/0wrm+ZanNLRWE5A=;
        b=c0IgRs0L48KJLyxhTGQJFWJ1BdYJ9/0UfkSAUSup2o7zqu33cMUqu+4ebJkAiLV0lw
         P1gGt5vlXzEQ70IxZfzHlvOo1X0Rx2JTVyY2B7k4EJkRqJ9yxsSunb6bNFlx1BAsrybU
         KyF39FiQFsd6dh+mkhLj1fVJlvY3oUdld01YTYuiFaGl9a1Xi218W/cZrGZ0h7TAajGp
         5/DpGEU0dTGWW9B5FZ8TaK6JD6CGGuWyvDzrWDao4n4hacoeRyo+lQlJ9x1vgO5wYJob
         rmW2sPtvGD8vuEoFj94l0+6o4qz/hFXM4iPJ0o7ya1XpSSxlxrYUgUudNzpG+gIDNKmT
         clYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311437; x=1754916237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VS1xXl/6JkInUoA+4DzPuEj3FzH/0wrm+ZanNLRWE5A=;
        b=X0M1uK1MFw641dphegqJj9YvpwhJvJwGfTzqZzc76Ox0ybY+vubY1ZYKcOnl73DnOR
         /dz/zcvAJ0cZkGFirvxDj9tTpocOL84jcwZYrVnE/jqYbmhjOMFlM3/jmXRyAqpC7pYG
         sf9Cdkj6Vz83yuVT/B+r2zudVGDCs3J6dSVOrZyHo35LtTxYLetJf9gltp33dN40Wx9u
         AAr5Zyjd4889WE2XVWuxH+MBEAwT+TA/cYm+FHgUj67zm4i59/pdlIWq90ybzXs5ybp5
         rnFq/6tV8jhhx+jYwELlBIsp7rhl2QaYO4mzLejXBageU8Ba+TNsD0TgGAUaEAO0jCEB
         eplg==
X-Forwarded-Encrypted: i=2; AJvYcCWMblhto25Vi7wmaPBbY/gvWSulf8PS2DNtZ4Ertbt5t8Vsk8JbQwrZ094PK0f9tz2KIWDoFA==@lfdr.de
X-Gm-Message-State: AOJu0Ywwua5bqIjtuNtDQXSV76/i5vWEoN5FDWJ4fqnzuI4iA4leRx8h
	toydfNyZGVsGsutmRYC8jDcaXSGABFNSEuQv+Wb4eJclB3TsS198MIdI
X-Google-Smtp-Source: AGHT+IFvZ4Fxs4NjKP+jfnSSh9MbW+2LkKJGjxunEe8EQi8jEa6lhrWDbDTQgDJMZP041d378aRuzQ==
X-Received: by 2002:a05:622a:1b13:b0:4a9:cff3:68a2 with SMTP id d75a77b69052e-4af10d1d57dmr161277211cf.37.1754311436612;
        Mon, 04 Aug 2025 05:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZftYkEFdFdJ2hEfFWGj3YGJMsDt0J3bdtMKWE+/Oh8bRw==
Received: by 2002:ac8:5702:0:b0:4a8:17dc:d1ee with SMTP id d75a77b69052e-4b06d51411cls16230121cf.0.-pod-prod-08-us;
 Mon, 04 Aug 2025 05:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTgr/pMMN7AfveUf9nz4KbF5MLf93m/iNJGw7+mAc+oTWJYFgPNTefNl+p4NXVx6KVhUymeO2BiGA=@googlegroups.com
X-Received: by 2002:a05:622a:17c3:b0:4b0:7ad6:ea9c with SMTP id d75a77b69052e-4b07ad6ecbbmr14040031cf.31.1754311435594;
        Mon, 04 Aug 2025 05:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311435; cv=none;
        d=google.com; s=arc-20240605;
        b=dpyWWIUaGjD7dMNve7upbwCNM6ukJFxWYheOpoZsHs2r0vytWPz4ign+70Bt4SZywJ
         noL39sGEyxfl+AfIczKQEJTmh8r1gY0mUee+bGACb92IyJ8j0XLcTQ5N2TP2ZTuFbhre
         kTCcOPyhFzOLOBbU7qZUsAENBe9rC0hA4qXSSso/odEfDib06csSq9+Ds98hF2kzU5eD
         vstyfDbIn77hiwDKZXnBPt+TXLddhquhCjKcFRSIqIt/y21MNr+6mIt8jsIaMMtl2o8Q
         dwI1MicrSL3ucq8JrkM375D0E5+AQ8c5Q07iZKOyd0SgWuH0f4A/TILuPmRtpdW/cJmn
         DhQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6HioLDHG809Vrmu++exqw36yATpmFSDSvFtTDDJtgR8=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=k9rTxD18Ydf+kcVb+HEW/ooT7fMRsdUVmc522zZa9w0P5u5eXDI01Z4iwyrsOMfIs3
         aOQqxALPBqz3/t/bNVffwyY1JsoNxnWtkxzUlGephMjOa61ne8Ek6UvXan39IiJD3NoO
         v+Zyh1DdCI+uaX86pQnyFNrNBhnSxjX3g0sk7X0ChtvWeUT2MKgFccl5kDKVCLMW+Fus
         m4klVvhtmKTxRIT6Qw4oSmXoCNOPkhnQ3HB/nEGcLWHwguiDhiEzjieYNIAkhyva2y6X
         lfk3xpmxU5sTSl78jBbUICHdEvZS7OJTIrgo4pCDknK2N/kz4jbZwfx/c91v2JXb3qeS
         0nbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ihw3Mu90;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4af1ed86199si1439321cf.4.2025.08.04.05.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 52057A55826;
	Mon,  4 Aug 2025 12:43:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91EBCC4CEF0;
	Mon,  4 Aug 2025 12:43:53 +0000 (UTC)
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
Subject: [PATCH v1 09/16] dma-mapping: handle MMIO flow in dma_map|unmap_page
Date: Mon,  4 Aug 2025 15:42:43 +0300
Message-ID: <152745932ce4200e4baaedcc59ef45c230e47896.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ihw3Mu90;       spf=pass
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

Extend base DMA page API to handle MMIO flow.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 24 ++++++++++++++++++++----
 1 file changed, 20 insertions(+), 4 deletions(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 709405d46b2b4..f5f051737e556 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 	phys_addr_t phys = page_to_phys(page) + offset;
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -166,12 +167,23 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_phys_direct(dev, phys + size))
+	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
 		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (!ops->map_resource)
+			return DMA_MAPPING_ERROR;
+
+		addr = ops->map_resource(dev, phys, size, dir, attrs);
+	} else {
+		/*
+		 * All platforms which implement .map_page() don't support
+		 * non-struct page backed addresses.
+		 */
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	}
+
 	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
@@ -184,14 +196,18 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 
 	BUG_ON(!valid_dma_direction(dir));
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_unmap_phys_direct(dev, addr + size))
+	    (!is_mmio && arch_dma_unmap_phys_direct(dev, addr + size)))
 		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (ops->unmap_resource)
+			ops->unmap_resource(dev, addr, size, dir, attrs);
+	} else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/152745932ce4200e4baaedcc59ef45c230e47896.1754292567.git.leon%40kernel.org.
