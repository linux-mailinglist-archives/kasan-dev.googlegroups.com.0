Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB7OWQDDAMGQESKE3JSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id AE4DAB4FCC8
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:31 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-406f47faa7csf31848615ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424510; cv=pass;
        d=google.com; s=arc-20240605;
        b=ef3RjEoGgZVmCHwe19ULxqTXfPnxf7UdEI3WByn4pIa65EtHxWMOqCNKF4sh15k69h
         h0RM/9nthyAOyscRJCf5Hfo0gkpxI0Kaq3YcqKuoazUPFDA4uwwqWJY2jWNW6T1WeKAU
         po7sTOfzxhkBCnbC8bsQjMupNYoxjUAkgswF8jzgI1Wq44bydxzsrg/FCf68ZMcedWWi
         gj3rHJb3VKQWZp2AHzdCVBkKk+zLljlSHcmnKxYz7i623ou9KF3OSWsG0tWOo9mpFcBt
         1LdleTmV0qvroOhtWmAFcpNKtZ4SDA+ujqOJ1giudyF7VlzNknd8FwLwZmPtdC0HUhcq
         pvtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Rx64EBCiLhrulwrhBihdLwktRIsXzyefDEKXJjjR6p0=;
        fh=NGFpR6kBdzidsu2bKWQ+CuJtZoFwYfmy/DJVxY8gO9k=;
        b=FpgPWoLhxOWzGEIAapeRE8yqMgiUlOQF4CLcmmaKci07ilkvdBqCVcXiCgAbV/JE26
         gA/kV36ISDRfRbuTvRYwEHWAwXmYi49+l76jfaQtkM8S/3/9CAEGEFuCZkTDyHTB91aS
         fyjBnAep642sA+y0XzaemW9OlR3LyTBmbG+2SkbNIxcxzF3k23mIQnr3J7jZXiiiE+wd
         p4xg8f9VpjmJJlqOM4XgDcc1OPN7ap8yiHcwFZkua+G0R6Rj4dTG1xDMwvNDP3Fq4NJI
         FdBpKtpunFizhllTWZH1BMh6dzUJXMHmKw0L1V0cAbt2qI9WtbvRF1JdJ0qac51kHIbY
         IAqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J1woyVLh;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424510; x=1758029310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Rx64EBCiLhrulwrhBihdLwktRIsXzyefDEKXJjjR6p0=;
        b=KQHKiaoHA9dnP9YwfIYUDF3shvdXCb8fKbvrPpdmTWUVAD1cna6WQwael6LwB/sa74
         pVYqI2EwlaZyXWDxPZCdiwUgCXV45vXpvsGSK7rBh1JMaJBV2wHQOFMnx77KZR8vledm
         VRNpAde3qrxX3j1isr08GMBHA3fYqKXi9nBW4ByiDI50eZzrgcrhjBfc/d+yxuYE9P1K
         6Oxr0qulFe7lE5K7uVAMaQ8LM7PFmFWL333KQZL04drAasqimyfd/p8mF0If+2Jsukeq
         BlEIBCtQVTk9iHN5t3mlYeQZCHKPB9svO+/QgnjUnOAewAW+UiF2djK54L8kpws7REFM
         AXRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424510; x=1758029310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rx64EBCiLhrulwrhBihdLwktRIsXzyefDEKXJjjR6p0=;
        b=vMe+9SAWMcTqCB339gUqnvHwc1pv6pFzcdaQdKXQuIbjLAOT6bNUU9Xq7KNkdXC3Lw
         tv3REKRt8AB64kgTdha2I91uQ32N6yI2sPzbsCnvqNFlaq9ZbTLZ4O8tbIvvktnT8QkA
         b3UDZKOFfoGS6rfMzffBXTLycDLTzV7rCX4GjmV1AIgmTfHMTY7+ME9Cs3ykKdoHIXCh
         wbgV/3dCX1Molim04lQUKE5iaGHfRcyeTYRvh1TvzB6Fk4tVPVq5xhZ6v6fEPPL2fF5/
         7VJlNdAYL+M4i4Uf8ATlDhFoJz5Bk/tD7Wr51tLMd41IzIv5SBLIHNl1adIPjq+51R0d
         n/Pg==
X-Forwarded-Encrypted: i=2; AJvYcCVlIdOld3yzRCfnGeTpue6FlNGHgtmdVrd8j2peO8f0xf6DCwYgPZiOKcDnEUsEZGhq3DiRRg==@lfdr.de
X-Gm-Message-State: AOJu0YzvkJLCHLucp8oobMKqUllUJVo7Esb+iDXAtaRvlVeOOJFAQrWA
	PDAZZgIag/a2lrC0fkLOFkWxMN0lP7dSr3KtejXpCnzEACZdjvDD1ssI
X-Google-Smtp-Source: AGHT+IGDR8pFlh1OBTnL4+/q2Nfo5iynPKxrvqqFWyUAJN6O4rxZIralOryFDWE6WAeK6UnX52XPiA==
X-Received: by 2002:a05:6e02:184c:b0:3f6:55e5:1914 with SMTP id e9e14a558f8ab-3fd94458067mr182145545ab.18.1757424510043;
        Tue, 09 Sep 2025 06:28:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfQ+FBMsoHnl87aUhicST/4ZXAdmCs71aMSPmN/LXnf5w==
Received: by 2002:a05:6e02:4607:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-4012981ea20ls15493995ab.2.-pod-prod-04-us; Tue, 09 Sep 2025
 06:28:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8Dgdg8hrpdyGZhl6/fYP7ipEiudKyEvqb+icnaFNkyHYHEFtp8d2SfaomHVPGVCFCY4DNINoApuY=@googlegroups.com
X-Received: by 2002:a05:6e02:398f:b0:403:c8eb:8782 with SMTP id e9e14a558f8ab-403c8eb88eamr137941415ab.25.1757424508054;
        Tue, 09 Sep 2025 06:28:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424508; cv=none;
        d=google.com; s=arc-20240605;
        b=Gg85TcCu5xeYY1j9u5D7zZH9QtL3KvY+ByzsS6yzACiCAZS2T4VW64OkAQrz2rkkZy
         jq0yG1pJbOSToGvrm1HQjXNjHNddubhnhwfQ2b57e9HtX4tdOJXm6CYAOQIy/pV9Jv+e
         QlbfGyOT/A2D7JxOvNCVts7tkSUF7oRGCacr5aazBhCLBOps+kygWRSnupdJ/2zdBojH
         3SceKYiZ431NlQ5hDqMFVGjIjfwa7reKo1Djr7NZfIZGtYFuVcvGbPZh45Ld7e4KRZVn
         BxZLg8HiajJkaoubSUTOtgLD2e4ZB0ml7h2IhpJM27lpTQ3t5J2/h9g5YtSCYQ1S+6kH
         GjfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vayxyhaMF3JHU73oK2kjzQVv9MzTvy3OtGJfg2sjWUw=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=EGyyCsD0Hv/k/sMi0HUijvmqirx3nYthnWhBpRPtgv01Qo1eh3iqWUCqDcyVlAvJMU
         n1aeWWgWtZYznBSBxzqviIHQ5eZY/BjiV3SOJS/sUsfxmq8eTsXAFwZl4+avvGzOf7/D
         bl1yDlvYPdwhH1p7jOjbVQd7BhEVylTl8EH8G7QROk60kgBzOghe3/AUEt4j4Cz2Pqe3
         CvrfNAIGzCRN6n0e+y8UBRk4IKO7gQlcsG0rN14amt+YdZpSJUWoA9SFpo0jbUEhxqiJ
         BIml5IhrstBYDs0qL2Pq6LUa6u44DUI0zkTfDBfsFZy1RrY84te+79O5zLSH59lO6SLR
         czpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J1woyVLh;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-51021bb2ab8si789842173.4.2025.09.09.06.28.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7FBE744D02;
	Tue,  9 Sep 2025 13:28:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A5E1DC4CEF5;
	Tue,  9 Sep 2025 13:28:26 +0000 (UTC)
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
Subject: [PATCH v6 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Tue,  9 Sep 2025 16:27:32 +0300
Message-ID: <c0c02d7d8bd4a148072d283353ba227516a76682.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J1woyVLh;       spf=pass
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

As a preparation for following map_page -> map_phys API conversion,
let's rename trace_dma_*map_page() to be trace_dma_*map_phys().

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
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
index 0b7e16c69bf18..bd3bb6d59d722 100644
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
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c0c02d7d8bd4a148072d283353ba227516a76682.1757423202.git.leonro%40nvidia.com.
