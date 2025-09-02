Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB4EH3TCQMGQEMWB7J6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id C0CE6B4078F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:22 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce848d95sf1061133fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824561; cv=pass;
        d=google.com; s=arc-20240605;
        b=KIzS7Fof5utzC1Ka3DpDOXdK49joUWcMF0oSg6U+KDDCXJe33zR3OIdDX3ZiHZTNRw
         cVce6bTyrpJl9QpNS4qO6Zkds9H2G87U5jPAmy2ohsRCaMzuudhfnRLcTKDnKUZaSA4m
         Q7AcnFu0GFKPuzB2gdRTl4CrRV5sqKc2JEF92Azg7ae0fhZEvgs68E+JZ24hLgCSzC1k
         KC5GZzItma5/+qE2Qsv5Bnv85Zerxkb6gXkln91OOK4ellEXPqR5VXump7FLMUqKqQRE
         aoxXeQLX61Ym83ihwltCEA/kTdRo/G/pXBUxNWdcVnbYyl3B6P8lQPw1frAcT1Jt3ZfP
         8IGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=igPCDhcFZpu98eHJz1W7vfcYhatytA6hQMJ10ccvxMs=;
        fh=98V1ZGHawnIwXvhSvhF+Iw+/65W1g2ZTWXb3XWGw3ks=;
        b=ajJOcLGRHh9tWIk2tW3Qvwu5Bqm+a3CGvoiQVxZc4CPywGdvQN1KSv3c81ABd1C+cq
         PDZyham6EeTonUmzMbdVGi+2qwECp+Tf+rWeLf83s1QJYvoLtw6tYbG2W61ucZioqNUz
         a/zGquCOPqFOeHz7VU0Ov2QzMPT9IEmCZ1XJpdp7VPrSadvJCR5S0ixA/uIJbAxIrGly
         /Uq3EnR+9tFdh/LawZoIW4hzfPigWOZrwMgmdzI7ht1eIWevueg0wcAkUA6s2bLD+zV+
         unW48g/K/5SFzBG7ZKn1ZCuApY3s+FMZNOpKBAg2rc1G5N8KPhJj5ghb8D+RWkHAprHE
         EsXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZmeCwVF;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824561; x=1757429361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=igPCDhcFZpu98eHJz1W7vfcYhatytA6hQMJ10ccvxMs=;
        b=FD066YqDn8FBHTIgh7Q2gMDPyaL7kKolu/kRtVJvtQYZadBAXdFNEbDXa0SSDRODGO
         okN8wayJHvSIiWj3rhzaZi+YYOHOyYKQuXb7Oqe6LJjTyEoQ44jdhWwcr249F0XXVYXg
         Bipy3o4BgQXJLujZ5tOn3y1QkIiMw4Kh88evZT1/hAysF8qWIKLstke2KVDAeKNuPRQX
         qbTSlyy5zz3gLeF7UwS20MRXBWW8EIi60BF+fDDx1pl3GrsnuHBumEfz2RPJPSvOAFjq
         Th7xjhe0xag/jjKX5QjU9FqBeaJCs9r5abolXRqF+EuLqLGQmJPWbv1ZLMNw1rLN+HoT
         LEvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824561; x=1757429361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=igPCDhcFZpu98eHJz1W7vfcYhatytA6hQMJ10ccvxMs=;
        b=HsEUkDq4VSqA9+nZZ7mgYDNV4/9TZu7vCYaupTiSeQb95mo+y6qPpoLXUrAnRdDlkO
         RbrN9wQdW1dZsnzyKJmX712CW4LFur+Wnj7vy214XWCyb0Bxw5Jeq/rBPPbA62XKUynu
         h3SSdLjuon1Tw1v51xNwZV82eekg7JXN+PUM/8u15Gu4CXms5wI70W5S1tTFA5utWKo+
         oovh9EgSJvKUoHNTEgHfV/5YIPN4famZde8gQ6qFjYYnwF4Vq61iovu74MZ1oRPos0/A
         MXmqmHqsjLvJc6YA/SDkPQb46tP4QThVfAOXab+yKbEvmqmwRSDF/6K7KIIieEO8k+K7
         5TAQ==
X-Forwarded-Encrypted: i=2; AJvYcCUhXUDyYBEsy28b99o2F3WHkrm7QME1CbzSQ36GN1gluoLn9el0tlHUcMLFE956G5BtXC0o1A==@lfdr.de
X-Gm-Message-State: AOJu0YwT6ydgJBIKvvhd0dbHR/nXOCAw2yDvAd4MBsGhf9MFT8SFiKuz
	+XBBaofcT4JYeH4JOyKVCfRsXeHmV1N6g6+r7LbguaJIzg8tLIukpjyx
X-Google-Smtp-Source: AGHT+IHMP+FQ25lDP57PCQFTZLBWa6aY/PQccst+77719gIGNvHVpjT371wJLmvFTwi5m3qY9gUHBw==
X-Received: by 2002:a05:6871:c7:b0:2df:5323:520b with SMTP id 586e51a60fabf-319630cd16cmr4859818fac.19.1756824561119;
        Tue, 02 Sep 2025 07:49:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcyqToFBL2P51xZsbUuJW6x2aMBLzbNiNbt25uoViZVBw==
Received: by 2002:a05:6870:fba4:b0:315:531e:fdba with SMTP id
 586e51a60fabf-315961bb027ls2570031fac.1.-pod-prod-02-us; Tue, 02 Sep 2025
 07:49:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLt37Keoi4INnghS4388rZ73Jelup8W/O6tH0S4ih3Nlgwx7Qp2oUSRN4gsE3maHj/5OfQE7QD814=@googlegroups.com
X-Received: by 2002:a05:6808:13c5:b0:420:ba87:6c7e with SMTP id 5614622812f47-437f7cae92bmr6289039b6e.5.1756824560134;
        Tue, 02 Sep 2025 07:49:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824560; cv=none;
        d=google.com; s=arc-20240605;
        b=FK6++y7xA0fmkl7/50tpzRCCNbMxJnmqh592EWIXdol5oaPCS0ZmcCkkTx5S+frzdI
         llXUZTO6BQXhG1pG+wQkjx+sqD6BPWpelZ8igI1+fDMIkfHor6tWkHyowLh8QTKBxKid
         h5BxBLrNUsPwrv0ipGtBGLn5rtN3HqUfkdFmHZHfX6CgNvg1my/y90VIjCLWCb4/3qHI
         uDuUmN5JeoQgcYk/pryISTgujjPW1k0F9nQogLa39HcgfzB5MLIivAwGrdmEpbNlTzwl
         jxBAte4HeyYpWwykLgV8ePo0YXBs/C39YC7ZhoJZNjcqZEsrwt0tZRdXbY7xqvZ8YanS
         d4zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7/hlUPkO7h8DBhJNx9gpER7mP0DqTJkgE9FjVOPyX1w=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=BQfMrCQrlLH6MgJrlsJY4/mwJr1opkAWXAj6a2+DXpzzzKuAfmFtqZt9P73rl/J6bM
         luNQmB54P4ScG3pdhIEcfsb4L8P79XUvHSWPoVxtiogZQSgf24E8jDxFsUX0W4Z/7iAE
         KcjA8JLnAOcf4z7Y5PmAIRjChWXDOtytHh2RIhnRA2xau+3ZCJJ3KVD/k3AT1Reb8ful
         aVcWiUKYoofXmuH7VvOvCvnVymYqopGHJGVrAFPiHYx3HuEmpXOfhL9fDzE14gdp8Q5Q
         qB3/pmn3pSeMH0mJ9pIVRG9PxqrpEp2ljPAz0wsggHIz9D8dzfOLk0YcwwBpOTiuWX55
         bCKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZmeCwVF;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437ffe894acsi134848b6e.1.2025.09.02.07.49.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7EA356021C;
	Tue,  2 Sep 2025 14:49:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B2D4C4CEED;
	Tue,  2 Sep 2025 14:49:17 +0000 (UTC)
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
Subject: [PATCH v5 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Tue,  2 Sep 2025 17:48:41 +0300
Message-ID: <7b4656d5f6392486f28f71ad600a95e6690e2f41.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jZmeCwVF;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7b4656d5f6392486f28f71ad600a95e6690e2f41.1756822782.git.leon%40kernel.org.
