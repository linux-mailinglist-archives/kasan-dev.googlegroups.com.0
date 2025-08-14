Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBVWF7DCAMGQES44ELYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A11F4B26E04
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:33 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e56fc142e0sf14315175ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194072; cv=pass;
        d=google.com; s=arc-20240605;
        b=GhmMi32qzB19LpMvdGALhb8zGOpS8uRDbellmf4Z1Ad4Cyv07SO3RC40Yczk/Lq7pt
         PYpp2Q70cFxFU1BRtRtb+nuiI2/uZmGNvsV3TvDxs6oP7DBvTPyCJK8jcAVwgXtedpKt
         sDZfYLJr+JlUMfL2WG2KEUMYM73dEC5VFN6OE9PCpLk5JlbJCv5xU98HtcN8RZK+sO0Y
         N+oFX2E/Qy0ekjbWeN8DNE1hGx1PSdhovmnXtX3rxY836Oc5A4FtfAByIAtw91kv4l5C
         5KXNdkDhH3cYaL+5AVzI2p6L2olqpFQAyC9fHDB/CiogiTUE3p+MLQ8d5ivrY2uGtV81
         hwKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=CUUMPh6SR+CtVHkwtCMDr3aoi2TEZcQ1Ok1RtLSx1lE=;
        fh=IZA2l82UCNvq9UTqthbZ9FWN9IN9D6s9Rljdr5o5Q50=;
        b=kqv1vfOEcMvPpY+4dd80MduqWGfgXDh/aDYo3W572cEfhGItpIPN7o+uDPSWhbunDR
         pSg65JG2m6VjkTi2nkZITl0ZVmq1giYvkVLtTNzuvDtOwaqjoU6TLIPyOGXsMTl9MYXv
         W5y7BG7Uwl8nD/Pr6Bs9N0zD0a3imey9d253ZLYdWHduJDWYA1pS/mK2IoVTrp9e6tLw
         CDhMcEm1xLoZTMejQKG1NeRa9PYPUqm2UFwuercpfT50XgBXBWaBiTkCtPt4O06GseLU
         N1kB1NM/HazgDzY6sJPDmGfZWbqeSAwhPnF9NH2hb/QLgM9cGeJ++9lZ80zsuV7T+vS8
         xX3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EOeexjxP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194072; x=1755798872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CUUMPh6SR+CtVHkwtCMDr3aoi2TEZcQ1Ok1RtLSx1lE=;
        b=H4k8LsBSKOMTQIA0YMqRfwfU8MsuYxPhO6XK1KxHs/Rh7bitsWJu+YLI4K3QHdn3Ob
         tbH2RbAfo6NGv+GpjFgxL5Rm4NHx3K0Bi+4TPG42SWBWwXs1LymV11n6nrR5H5Klpivm
         rWDjfXPc3bxxup5ofnMpgafiFZXznPCONRxPRWmevSRcukRARj32eVS0qPPot1YE+xfu
         bCexTkISPKQee5ZRckeqgwpJ4zytGHp3/IlIDSS0h1o00BHot0njhebgFkVb8WYL4f+D
         I+itwzLOwfkvexAawywhLkOVweOphkBADWBUGmxdPk2UMLsRekzSNcFq6lQNkDBsY5lM
         VkAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194072; x=1755798872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CUUMPh6SR+CtVHkwtCMDr3aoi2TEZcQ1Ok1RtLSx1lE=;
        b=YkuYfncKLMtwMO1D2++1LP6f84ZOBC2lbjrqwQ3ftpxaS/Ix/NSazmTay2k/hNbu/G
         iInxDJgVHi9Cb5liv26+HznNWkmEjpniinux6vS5QifqfGAXt0cJMkTpcrYUQ2steu1O
         G5PhrpusxQwnNhBJXt/BAR4u0QOJkxbU56Eq0hqoaOQqiTzpBa1H49Jen9GWImIWhJ6A
         gVZAaPAAk50YlE1/FFsEfG8i+7CHn5P1yJEZXJjTvolHW7k8aeWjbk/ZqRfev6K4E7lA
         G5UnQnUlfSigeXNJW0Z40LgDiiQjDiPqVtDkeXpjcqpS47YlPlHVWrE8Fr41WAaKBfvl
         YsZg==
X-Forwarded-Encrypted: i=2; AJvYcCXRP8oMl9SBvVy+zG9kTjFfUF9y8khmkCydsRI8xs36tKlwkdfM5svkxxv9C0BLY+0ORV2kXw==@lfdr.de
X-Gm-Message-State: AOJu0YyoDGc4Wq856ujF2TjAvazT2/lFxkvKn41grP6rpKM/ganR+n3g
	d/jK4JU9aCtF0jmwFhy35ZNs8Wa93miMRoCl8/QJcMAtSBbc9SsQtNfv
X-Google-Smtp-Source: AGHT+IHHRC0bl6iNJt5FC7wXuufWiOJfoHmb1sa6Yn6FrXsi3U1s8gtXLWoVYt22RbS+SyYb8daTnQ==
X-Received: by 2002:a05:6e02:180d:b0:3e3:dcfa:eadb with SMTP id e9e14a558f8ab-3e57182a9d6mr63301365ab.1.1755194070535;
        Thu, 14 Aug 2025 10:54:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKvB7YJTh+micNtTy9wZt9xqhvFsBTQ7z1VH2oUfTDbA==
Received: by 2002:a92:cdad:0:b0:3e5:62be:1691 with SMTP id e9e14a558f8ab-3e56fb98671ls6218955ab.1.-pod-prod-00-us;
 Thu, 14 Aug 2025 10:54:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmCUnxrrZg2v5u6VMbr59SPFQwN8UKtJ2nJWe8tPv8pXBtqXuxJ4Lr/n0D8M3+7+rb/yYlt+35IIs=@googlegroups.com
X-Received: by 2002:a05:6e02:461b:b0:3e5:6762:c65e with SMTP id e9e14a558f8ab-3e5718b4d20mr70856815ab.8.1755194069090;
        Thu, 14 Aug 2025 10:54:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194069; cv=none;
        d=google.com; s=arc-20240605;
        b=fOUupnzd7Qkottwh83UrW9BAziOFWU+f8I8VUSTjocBvtKz5Nf4KWkhJelLMuP7VA2
         pyZif0A/66PO5XzQ8neMCGv4gtN6oTrIJkzn/gukiRHYxYQyRMEeoIzPc6XlHMYcu/Rt
         aE9/VPMw9tOu0Zr1kPQThBbB7emltCZT+HrvqsM4iWNvcAyomGkju/sPiKdsZ3VqAN4L
         hic4XYydtqMYaAc3daVRVeAstKJNjEi5B+Mr4SZdImJ9fdyTdTbCHYzscKFKNXAfKNhd
         klOZlkY8py/QT9wco0FCxIy3bcbMNBzJiThmY5TcpGKh9eXlmn3tY1mBCwJi3vVmoSWg
         yqDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AxToNPSfI6WM9a997+Z4VoIL+Khe9+Ojk4pU73w2JVQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=JaOC9d6JmWJ8Wi3ydU4QmCc+mz2ggemb9Q2aeO0FCdQDW3bgLSGlD3TZQalyPCo7uW
         pEPzJW/0BMwI/PqMRQyibRq9VI+T6RRLMtIJgvhXCH66eb0du4J0MnsbdloJdHsdyzYN
         QJlqnz2AftDJFpzc2TXIxEvDZnMFGceMpFMzQCmPqr3kEcrmOvxbfQoOzxAbp9bjK5n1
         bqgvEod53CSWnUE2lAaDRUlEpo23EOyQYC8n7+CHYsHZqr+OmZBprOYF5/Tb1Z66T8y0
         1S6A/tzL3hh95NW9ysUqP/Hnrqa7VF139CquLXu2YJG+j/DKsDa7qPWIhdWdczvsAGGr
         8aWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EOeexjxP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9b6cc7bsi596344173.3.2025.08.14.10.54.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 75DE8601E0;
	Thu, 14 Aug 2025 17:54:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8F8C1C4CEED;
	Thu, 14 Aug 2025 17:54:27 +0000 (UTC)
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
Subject: [PATCH v3 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Thu, 14 Aug 2025 20:53:55 +0300
Message-ID: <d7c9b5bedd4bacd78490799917948192dd537ca7.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EOeexjxP;       spf=pass
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

As a preparation for following map_page -> map_phys API conversion,
let's rename trace_dma_*map_page() to be trace_dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 include/trace/events/dma.h | 4 ++--
 kernel/dma/mapping.c       | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index ee90d6f1dcf3..84416c7d6bfa 100644
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
index 4c1dfbabb8ae..fe1f0da6dc50 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d7c9b5bedd4bacd78490799917948192dd537ca7.1755193625.git.leon%40kernel.org.
