Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBIGWYLCAMGQEOFADX2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9B8B1A1C2
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:17 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3e3f0287933sf89230825ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311456; cv=pass;
        d=google.com; s=arc-20240605;
        b=WupZCKDgkd19gY3R9n73Jcs3BHD7wOvLahuNvl+4cNqxIsz+xEaXKYMaYGZ5o011Qe
         q40wOAo7ShZpuVN3PuwJI1of3S7BBiJOJAw+n5j/wFMzI5BRaq/2FRIloIZOW8pJztdo
         dH8a9apcAvOMKiPhcESTrS5PeQB9qb5C9EPT7fMnXjRzxKv/xMBvsHN3+yr6QOR2NI2c
         eW4oJSibyIQNczDA+IgaIsw47nKxNoMMsvpqOm3He2Iw0bDRwNCaSmrvxpG+ytEaRRuo
         nb0c28inHVXiKb783vP7J7NB9jTkCF9qjA/OQlnT8d+Q86e5aE1N73O73T+7xH16sUTt
         yvww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZI7m813kQIMMRB3gZTrHuf0mXZq1coL5nPWVr8Vt/yA=;
        fh=nCzhZ7+qz/rit78RSa+FCbIwO8PzAKuuFe02VYuoHUY=;
        b=cXuRDGsh0IottCIURatqEc0agQ2o2RiczXdtGR66m5jEAZNJJpnMAAl7tBDBrqxKtI
         Rcf8dWDDjsn6eLsbD2vCQS3VHuOyTglJsoRbWM0NsrnyBydXMGKBqN6XlQsa6lSEneCZ
         gQD1ezyhAV/ZeoU/0FtBH0w+ofi36UR3V00l9egBiKIZYmOGm/Guz2BTFVAP7/eau0+n
         KjqVdurC8ZVlQtPItJO4gyH6N81sfMM4nbWV+TSmX3FZc7VnfSgJqeWOs93E4+LT28Bj
         EffkY8FFrPnI2FMSfPbTQd3HmfuergpHNaO7H/f/KA5qeaLUkaZAZJlUaq2CfGk6xTTT
         dTUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OtgAnXB9;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311456; x=1754916256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZI7m813kQIMMRB3gZTrHuf0mXZq1coL5nPWVr8Vt/yA=;
        b=UHRfmo8wphSDymguDUiJE9voaK/7AufWIgB+Dq2/c9Jok6OiwMBy+cGyB1JCR3Ox9j
         ciyMcJ2SAIs2FzQccBdX0q0p50UdhciRrS2hQHmR0GLrasouoCbzxmiDkOBHYoRiWtUV
         0/nrXCn12tstcBT0fPofwASDq8889ytA5sj6ASvmiwgjnHAv57t+qio/SEHWcgO/96WK
         XZ7XEccE7a8RqbIa3eIegN8qsnMM+8BrUAeb27y/TJluJl7UVPebZ3Md7qv8m8coe+xN
         3ZbsawloNDC4FftJA0VirxMV6b/a9oV5lmfQgnMuYWSpTkD46kXOSjortmuJHJ/nJSW4
         uOoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311456; x=1754916256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZI7m813kQIMMRB3gZTrHuf0mXZq1coL5nPWVr8Vt/yA=;
        b=d04PSdVVlBhQdCUnOp2vuYXmvcgoPsIZSfVwWsFl9cKfJ+Ywz1lHNTTo/521eEkNW9
         tBiHVTVd8po190zDSKBdyTG9IKH5W8+UHJSiy2sIcUkaQB4Ug2f+pzhVjqPXJfGOxZEP
         s+0tgK8fAYdBXJ5j5nCWX5NUm3nEqMNoV8gAxwuQN7waMHjFZ/wxkZ3fXXS48UxLxBJQ
         TImRR8FE0KQgqe0vYwBYjDnvbj6RtU2ktFegQw/XrKu4nC/T3oSfLIpBJBrtOi6B9qlO
         Iroj05b5Q3fYwsLcLdpUZnW5JKrUNNyp7CCDzqNihTgbJo8K7g3gMHk7XmdEHdncFogI
         ldog==
X-Forwarded-Encrypted: i=2; AJvYcCX3zshgDCqz1NJcUeUUYyc0VWvjmJpQmuG7YSEb10GABcY/IRfgSS29QDkbNL/JaFp9GGnFkA==@lfdr.de
X-Gm-Message-State: AOJu0Yz7Chh1/XPQEh1g9dvUFJQ87yIftQxGhRXZr4EFlk57k/tzYyMv
	l534efu3BDd17/q+M+N+ySw35h20JPn+HzZ6lRKg6/i8/EQ/e5AwVtgG
X-Google-Smtp-Source: AGHT+IEr1VJLGMKLt45309FG02SnAAeuRNccg65DtZlMPIeSicJlr9XRzvLEmeB/sThsSQx+ZvFNEA==
X-Received: by 2002:a05:6e02:2513:b0:3e3:c356:f5a6 with SMTP id e9e14a558f8ab-3e4161c842fmr150736795ab.17.1754311456545;
        Mon, 04 Aug 2025 05:44:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdF+ym7NsotTvydyNQOvY7ZByDXBMRRjYfzVj8PepHCJQ==
Received: by 2002:a05:6e02:5e09:b0:3de:143a:a012 with SMTP id
 e9e14a558f8ab-3e401954b6cls31113275ab.0.-pod-prod-01-us; Mon, 04 Aug 2025
 05:44:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWzufFqNFj0arZyMGJZ4pnpeb427RxJFsCeZT4GzmJesOmY4uyJHA8z/K0GU/tH54iTk7sm2dhTdMs=@googlegroups.com
X-Received: by 2002:a05:6e02:3605:b0:3e2:dc2e:85d8 with SMTP id e9e14a558f8ab-3e4161cb5bcmr176298255ab.19.1754311455499;
        Mon, 04 Aug 2025 05:44:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311455; cv=none;
        d=google.com; s=arc-20240605;
        b=H3dEopErl0FQLGKDSijipKcutE4OxDztYF1H4Lcdu28vATWBxs+X+yKosW0KJA80li
         enO8rVjCRanpt7PKwgHAPOXx3K6N+Y3Uxb/sAl+YQvXIegdPqUtrI77RpocBewXutFxz
         v9fzEZtwA9mRPU3SFexWUoGyJXJtIdPsbs4PgFRNcysY4kTkGw7UVYtkwaYo44Si5IFC
         6WQfIn+2pDcxkT1MAVBcE4msxp+iVH9g04n9XsMlYmTEWdh7jappv1n314frLTNCFyz3
         WlD/pTsZA/td1QSkdYUthgtYHHqJs1y0vbsjrBZJgn8GBETMBJZasxThM/1N5tZ5dfhN
         MOZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=njJVaIqIe6sqKLpFp72s28bWMOkerJgS7/NyUH+svec=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=aKxIq34ICXeroKQBFzs2JZN6jrHoyie7HVc0lzxyhGolygxflBwF2nrpQTa0jrlPeL
         AkBUdEalAD4IsjpTHDC49faslTn3ABBvUwDzL+COJrcY5wC4KHm82Jjw3TDCulcD4oKy
         oVuRP8tChz/e75TBaBv1lFIKSnBp09M1Y34+4fkGmdhm1mjRIc3wR+BHavd0aV4PDLAf
         ZF3j2qDOBVovok5HrYhVoVCHg/30aLbLudrCQr5ZsCyQl8Nx4f5ViKelhLjoCRx5Vix3
         9bEGx7SbNLfRRA1BCJNOmzpSppLXCaMl8rpzcLxVlTXWx9y+Zv0DO+LTyWTwcxi9XA1I
         j6uA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OtgAnXB9;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50a91d58e88si140918173.4.2025.08.04.05.44.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 0920DA55826;
	Mon,  4 Aug 2025 12:44:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 58081C4CEF0;
	Mon,  4 Aug 2025 12:44:13 +0000 (UTC)
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
Subject: [PATCH v1 10/16] xen: swiotlb: Open code map_resource callback
Date: Mon,  4 Aug 2025 15:42:44 +0300
Message-ID: <e69e9510d9024d664133dc788f5186aac414318e.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OtgAnXB9;       spf=pass
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

General dma_direct_map_resource() is going to be removed
in next patch, so simply open-code it in xen driver.

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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e69e9510d9024d664133dc788f5186aac414318e.1754292567.git.leon%40kernel.org.
