Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBGEI3TCQMGQEJL4OMAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47BA5B407B0
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:50:02 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b3476fbe7esf17591401cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:50:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824601; cv=pass;
        d=google.com; s=arc-20240605;
        b=YGmqwRKg1R6/0QVVg9/VgGqaphZGWwmvcgYBBxGvoxuCWWjozL9VJKBeHtWREGxKK8
         JxPsuhlab+DxtlrtRWNkvvb6nIT8odvQ4crPnYuvV6A+UJ/R2mUCRXIqP18CV9047ZsW
         3Eg/NrrQFxd1THBQCADT7e2eceSQHqIGMl4+FRZPz/LL5xHI9f6v+ELpECKAOWR4Lhtl
         MJ1mR3a5gYLJYnr/JTE9Oeuffjyl5W+zVZzW6ZWLA/kC5JL3ZZ8jmnp2c2S2Cr8p25ou
         BqxBBHY+dmopQD4mKTQ7aGNYMtbp+iJ1wM+A+sr2vULCa0dtHE6uBhL/It17oXmARfVL
         Z7nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AqtI3yT0u0tikgYzjf3iNE+UqZd8W9o6T7Y43zeg/KM=;
        fh=hphGXKAcRBQiQreU3/GIT79Tu58LP9AuuY1QUeoa24E=;
        b=GGr1y6umJ0PJXdxNdCak6HpriPocKyN/pu9YCUZZFVn1qS1b1/R74lX0Fko8b5MkLT
         NXJcYnFGQPp8zO+SYxbawLr/D2VTeX4gNdgBetLuxik3oTGxMS8fX0pC4jeEKgEYLZuq
         +eFYk7ebpNl2yU2Vxv7YKfx474ShmfXvsKVg3HN6OfJEQO0gY3mFXzk9Cw3K8Wn/V34R
         po4Uw84WTvLh0hp1rECxC5D3f5bFBUxz9dsXIbaw0pBliG5WOjh5GHgy0lRFVYre0sqH
         x+8xe/Phqf9Hg88oUdrL2vchgEWfBSxtVK43W/a6jME48boAmSAsp9a9xSKfxieeGsvQ
         F4cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eiIBn3T8;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824601; x=1757429401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AqtI3yT0u0tikgYzjf3iNE+UqZd8W9o6T7Y43zeg/KM=;
        b=KOdPzmCqUsvjBuaET5GChzZUuSUD86L0jzMDlW+2/lDwQAnj4d4Ta80t4KtefzD3BA
         KFIDQNuOY+3QVjdookc5bRplbp/ltu2glaqfx8HwYrni4d9F8tJKCW8TSwoRQGnZIp4v
         DKj0b6J5QIJJIfgDbgbfUiNYrmrJ/ZzR7ekkSdxBxx3dTuPmTK1r3/wHaS1mw2MazKh2
         cn1hlchQ9xcOXIzcE7BQH9w9HquNgPZi58jxfnJB5Dd5MCLF3ywqfaxsrbNEIxnxD9u4
         MCqfsqi+oqDyMpkzNhWLwbLnVZB50IuBbff3b4euuMmSOCZ87LmLV9kTSfHSnQ2fq6ad
         FJ4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824601; x=1757429401;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AqtI3yT0u0tikgYzjf3iNE+UqZd8W9o6T7Y43zeg/KM=;
        b=CPxQ+wD0DcpXzAiB+lRbHxXXjZQShEXrT4ZvczhuMU1St6ujWevfeJJTUOd4n/hzp6
         8XTcqO3SuOE5wnK0iap1JbYSUUUmUxxGJtnNRDnFoWF7ebmTrX/rWJ+sSD1R00Vp2cLs
         ltGHyLHxdTyLKKkA1yTRv4gaSa4lwy8/7KUa6IoVVDA3n7PHmc4fpk+IqJcjiN9GRkP5
         zDpO5FO4yOzasz0f3qGOzJAlo6mMAFoihb+PvvwkTY1mUIBP8L4FqyWe+KQUQ1UsJDjA
         4giFzFAM6qD3Z1XRIdsIq8m94kJPC5qRKjhMNOlZo+saAWFh1f+H5uSvOJKCD1L2VJTk
         8BPA==
X-Forwarded-Encrypted: i=2; AJvYcCXw3Ows/c1GcHfsP1xq9mLKwTlshe2KVzXPEe8+TcBqFAOs9/XfeSVn7xH++kzTACSZUExZVg==@lfdr.de
X-Gm-Message-State: AOJu0Yz3UFTdPupYmjahCJAQHeeS9YAix7gU54wVwa7M+wIvYHRTiAQo
	+qo6rN6h01cn0TUuWh/WJr6XadFNpBflX4kSVyCCH1vw3jjvZHitBpxX
X-Google-Smtp-Source: AGHT+IGB8i6NOK4e3CU4rvl0V/u++V/gQanQICv5mzuzydTN95HO1wOfz3gLCYv9+1B4xqCy84zr8g==
X-Received: by 2002:a05:622a:5e1a:b0:4b3:4bbc:77bf with SMTP id d75a77b69052e-4b34bbc8670mr15726361cf.18.1756824600940;
        Tue, 02 Sep 2025 07:50:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfC5MISDwbsCBKsGTLWJ8DXvPA3RZ6Z1uWw4VXg//HD5Q==
Received: by 2002:a05:622a:1a20:b0:4b0:907c:917b with SMTP id
 d75a77b69052e-4b2fe630d6cls91960391cf.0.-pod-prod-07-us; Tue, 02 Sep 2025
 07:49:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlEtjVw82hRHuF5m77kL8RJwKVE4oo+3KdrE9f2v4lFUU7gKIxdhVpRLVObaRxBAiQ1Q3OIIVRdV8=@googlegroups.com
X-Received: by 2002:a05:622a:245:b0:4b3:13bf:63d4 with SMTP id d75a77b69052e-4b31da23a0fmr137422551cf.54.1756824598466;
        Tue, 02 Sep 2025 07:49:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824598; cv=none;
        d=google.com; s=arc-20240605;
        b=UxnwXPXXmdb/E48PVStq7Y9Iqpptvt2uDFKqpsIon59FOMXZoXrpoQKyaXjhACgYRA
         1irbO22rjDXUp98fRHuikR17boRQ7UrfmZxr25wbWLbco2tE93VIiSglUzplsknSiu2w
         J6NkVC2bvO5DtcKl2ruxG5scSQ7mwqimiJaAyjRd2UH7CpO4ERoDKYAdzlGAkEQJfv8r
         FIfJIIUmKIxCAWMcYtlYi+RyH9t5Hte3IwtM45eLh5rMeNkqyZ4J/MavsJlHsqm1JbLy
         lDNCopzKktYJTyZfUgZuUU6uDjbyAfPNu5CRQMErRytAX2j9G/Aa2s+HSyasCSdiT/JV
         OY0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=P+KXvB+QEcDzAMb/9fx1ro7jFsDuULFhvrraHykz/N4=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=KDTaCvetK1k1FXmesYo0h7xt6ts8fKoCzxAF7++2OnUBAePx63M2IRNMnJffQnlRDn
         anEKG9SQzctkcrc514ZBJu1fKuQcKtLlUuPrZ6nllTIpO2OC8WE0+rJYwl9sqHyuq1Jf
         8+RRQ1rW4dEgbQiw4a4Xq7SpuaUJhijDKYXNCZMm8PDJZE+xJgsdpYRCRbv4VukWoDEr
         UAPpBLMnES/gEkld/tloQAbxTRkbkmD9WnIURbsXUELoixTfmjWvTFGm22zqrf5OQViB
         4oLSWs7exPa9QdpZiF+0g0Trf2Wp4o53nh49vFXO6C8z0ORd0+gUoF8L/0Lf5USkBY/+
         WsqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eiIBn3T8;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b346283249si964051cf.3.2025.09.02.07.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E282C6021C;
	Tue,  2 Sep 2025 14:49:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98E4CC4CEED;
	Tue,  2 Sep 2025 14:49:56 +0000 (UTC)
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
Subject: [PATCH v5 10/16] xen: swiotlb: Open code map_resource callback
Date: Tue,  2 Sep 2025 17:48:47 +0300
Message-ID: <7e3225a24df41b483d60d87450b610b399bc15ca.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eiIBn3T8;       spf=pass
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
index da1a7d3d377c..dd7747a2de87 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7e3225a24df41b483d60d87450b610b399bc15ca.1756822782.git.leon%40kernel.org.
