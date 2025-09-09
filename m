Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBBGXQDDAMGQEI5443AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 77EC3B4FCCC
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:38 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-816ae20ff2dsf617559885a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424517; cv=pass;
        d=google.com; s=arc-20240605;
        b=ffBOBvh7sEl+cXuByzXynIKwgYAZbzNIkhMT/0BkBeUMYOowMvmmLLDTIj/0LybR8z
         VVc8gIzGvAwiMdZ1H8SoyLYdD1jdXF5jfmzkE0nKhGs2UiRO6wLu3a3Whm+lyW2W0yW8
         elwZFu5U6BRVOA0/e5ARTI7KBWxQYIIV3EY8FT56qLAdCvnGSBTWlTAfhm4GO0Sg4JjH
         Z4vAB7frnSCIOQhrxCb7McLRvRVnTGM6w0QaQik1Hn8/Pg9pcA9Pk+6tQFfJ+3MSRzL6
         X5iq0tmGZSKiUmjjBEn+UqbdLWO7+hoSwmw8KQvUPjmH1hPVNOc4rQEbejHWLM5OikjG
         zyhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=8hLSXDJq2dY4kNTe2Gj5KmSHVTAh0hMe6KM+LXkjdvw=;
        fh=rD4m7yn3rMP6Z++M7ZWx6Qw5E6fpmjo+MlXt30LvyRI=;
        b=WOI+5s5Iiwcbt//NlFh5NpmXCqe/nEiFms3MK9iHItaidLw0PEsXNqWTr99QjCkXSq
         3tIhuUnZ4yAzk/3yi+X9T6vZ8rIZ9o6hjB6ZGJ9/8I+uS0YXsCbbfsLlU48dg2JMhXyp
         TnodAOPA4QqAY+kKNi7Ty/LT/I3lpmMcWCVjwKV9GMgtE01II4WZgm9B2QfRH8nMYnwX
         RE8ISAgNOhC1JHZIP5znUI5G1bJYnA76MsM+jX00F2hu4Xo9e2A6WB9YCIQPF8Ouvv5K
         QOoKRrePWC6GkuorUj543T48D+fYBKOW/yc3HZmVmbQCEkKX6gckQgl7d6iM0Guqsond
         GxyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wi8yN8n2;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424517; x=1758029317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8hLSXDJq2dY4kNTe2Gj5KmSHVTAh0hMe6KM+LXkjdvw=;
        b=gXxtvw4k6bPlkjJlqINw1lRJdcHIqGFb7sWBjyjHMEsNQ7qcu/sKhRezWGA5Hxitqz
         IMN1PMevmukpWMGxKUXTDhMVLhmiLmzPX7VdOYKxmzvhtBH+L1lY/snLK4MAU3KUv9GJ
         yf+UI6SRXivLOmjiPMBPjDWGGPn94u3fAvOFtf6p5iFmsuuYIdag0M4TQWxfB0yISjhW
         UBED2JksxJIN3kY6LXWkkwalg2KVN93BmPmR2AXA0zOepccht0MJUbemD2pFtFbDjCwv
         yZXXiYnz/G2WSRqAZc8rY7F2XAJ1cdidlUoQ2/5kR/Wi16WxDVkW9KaJP6jL2vN2SxSR
         4D6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424517; x=1758029317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8hLSXDJq2dY4kNTe2Gj5KmSHVTAh0hMe6KM+LXkjdvw=;
        b=qwuiICTsQBkP/FBtMcjn/wjW6zPgtsRWNn59pVVwL3xbVTW42I6TRQDkWJlSHhtG0P
         65DLvlL1+4TyMuRheLOUBrDjyM/9l8xIGL8AKQtgwOQrLFA1QYwGgCLY95ABgjaW7YBa
         XdxQPXTPjDI5K9NHfRHf2f6JXmAadTWgn9Q6ukjFjpAaAR6k2JU7zptkysitAUuhORbm
         g3U4qRowRkOC0VQpf72mjwd6471UKcD3UYpAKqm1cOWA3s6yV60qA10rvIEFVthJuplX
         aIydn6zPj9HCeVI/O8sCfMnhRNQgplcDlkySeb6ivbO+mBIoInkerHoMz51rOrYSHQCp
         eNYw==
X-Forwarded-Encrypted: i=2; AJvYcCUukJu9iQl60G5nDJDttDnwHQDPoFz7HCho2Jd/xkdSoor0hrFrjpzOspL2WU9s+1bd1UBm7w==@lfdr.de
X-Gm-Message-State: AOJu0YwDwafYLHlIyH/XZOgcgqFyS72sKPvJNRDD0dL2UgVgA/dr4OwW
	21dN6i3Hb/PzjX0fOd9Y65C57+CLZqUlYOgQOfMFS+LrWUVXxTOYGKjX
X-Google-Smtp-Source: AGHT+IFMRK/TTvlooP2Mo+cqTfw83Lbb2PzEk5+C2mV3K7E8O5LN+V0n5oFe/YJH9bHAVBDDHKvK0A==
X-Received: by 2002:a05:620a:2b45:b0:815:49ec:9002 with SMTP id af79cd13be357-81549ec9c36mr990887185a.44.1757424517099;
        Tue, 09 Sep 2025 06:28:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZed0lvrMiZkhJHRZNv8wXgCmmff8uQM0WnE5o+bKZJQbg==
Received: by 2002:ac8:58d3:0:b0:4b3:aacd:5c80 with SMTP id d75a77b69052e-4b5ea97519els75008581cf.1.-pod-prod-02-us;
 Tue, 09 Sep 2025 06:28:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmRhrKXjvpY7ndmflLcdC5D5bJWczQwmSKmvcKltVlJ2ceWJhuRGv/+0EQWgjbax90/5j02xmIFvc=@googlegroups.com
X-Received: by 2002:a05:620a:1918:b0:7e9:f820:2b60 with SMTP id af79cd13be357-813c3c83aaamr1064719785a.74.1757424516027;
        Tue, 09 Sep 2025 06:28:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424516; cv=none;
        d=google.com; s=arc-20240605;
        b=fuahRTGYc3ofMk0XCKqeb1kGHcDgTce6J1T2Mzdu8mrk2jtry0ew9mgMAdtlrOYBVs
         e6rxCnFwgsjgoGTddVuzeQXhSPFlDHmLUNq2md+CE8KGAAKtfq3ekJvmVvkqccwEP8YT
         l3iE0yaP7/HjVy+ED+vS7h/oMtZIis4n7SeIYes0EcFI0SWqeLkPz/RPXbKUCpAqKMc9
         VjCAe8tYnNuSNBgthH9uxtj04RHn5pvxvrjQfOutnVbOIxPwftBEch6souRoDKnWysFl
         CXC8aC7kX6xPu6WLhtM3m587UTS/N4srSxk+ZK8wNprIx26bUYns0i+0ViOQMe9UkQPR
         zfGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RXCiWDrz08Ry9Yhr+EUVani0x1mu5TIrqAP93p3Vkfg=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=C+7Da0/zjjzPaoqi2lEluiemvuridE+JHM9H4EJAuaBa3aGi967Hqyjxfkm5iOJCut
         VdahvGtf76ge0trldOsEncJcu7TYJRYK9177Li0Xiyt45rUJuR/E8XDbWwaKRxvMyFn0
         mRVukavZKt/sdeaYzD6iMxzaebvOC8wnfXFnZmuiPhoTw/GSNF1N0pSbc2B4xrSknJqF
         pEM02D1ofy4MTTSy+lz4gOwgc3in+n6ie1QdRWyw+pnqZijakxJtsxa0VB3XFHFUoTgp
         KdfFd/xAtSRk86gxXz1b0rdImsP8RiQ9l6IOflbUGercF4AUa/TxuReL25/7ByYyL1qA
         eWGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wi8yN8n2;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b61bb98403si903541cf.4.2025.09.09.06.28.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9A8146021E;
	Tue,  9 Sep 2025 13:28:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9385AC4CEF4;
	Tue,  9 Sep 2025 13:28:34 +0000 (UTC)
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
Subject: [PATCH v6 06/16] iommu/dma: implement DMA_ATTR_MMIO for iommu_dma_(un)map_phys()
Date: Tue,  9 Sep 2025 16:27:34 +0300
Message-ID: <acc255bee358fec9c7da6b2a5904ee50abcd09f1.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Wi8yN8n2;       spf=pass
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

Make iommu_dma_map_phys() and iommu_dma_unmap_phys() respect
DMA_ATTR_MMIO.

DMA_ATTR_MMIO makes the functions behave the same as
iommu_dma_(un)map_resource():
 - No swiotlb is possible
 - No cache flushing is done (ATTR_MMIO should not be cached memory)
 - prot for iommu_map() has IOMMU_MMIO not IOMMU_CACHE

This is preparation for replacing iommu_dma_map_resource() callers
with iommu_dma_map_phys(DMA_ATTR_MMIO) and removing
iommu_dma_(un)map_resource().

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 15 +++++++++++----
 1 file changed, 11 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index aea119f32f965..6804aaf034a16 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1211,16 +1211,19 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 	 */
 	if (dev_use_swiotlb(dev, size, dir) &&
 	    iova_unaligned(iovad, phys, size)) {
+		if (attrs & DMA_ATTR_MMIO)
+			return DMA_MAPPING_ERROR;
+
 		phys = iommu_dma_map_swiotlb(dev, phys, size, dir, attrs);
 		if (phys == (phys_addr_t)DMA_MAPPING_ERROR)
 			return DMA_MAPPING_ERROR;
 	}
 
-	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+	if (!coherent && !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
 		arch_sync_dma_for_device(phys, size, dir);
 
 	iova = __iommu_dma_map(dev, phys, size, prot, dma_mask);
-	if (iova == DMA_MAPPING_ERROR)
+	if (iova == DMA_MAPPING_ERROR && !(attrs & DMA_ATTR_MMIO))
 		swiotlb_tbl_unmap_single(dev, phys, size, dir, attrs);
 	return iova;
 }
@@ -1228,10 +1231,14 @@ dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	struct iommu_domain *domain = iommu_get_dma_domain(dev);
 	phys_addr_t phys;
 
-	phys = iommu_iova_to_phys(domain, dma_handle);
+	if (attrs & DMA_ATTR_MMIO) {
+		__iommu_dma_unmap(dev, dma_handle, size);
+		return;
+	}
+
+	phys = iommu_iova_to_phys(iommu_get_dma_domain(dev), dma_handle);
 	if (WARN_ON(!phys))
 		return;
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/acc255bee358fec9c7da6b2a5904ee50abcd09f1.1757423202.git.leonro%40nvidia.com.
