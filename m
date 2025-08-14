Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBX6F7DCAMGQEKMKDUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 48A50B26E0B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:41 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-76e2e5fde8fsf1140936b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194080; cv=pass;
        d=google.com; s=arc-20240605;
        b=iFWqCra8ucOvSKbLgd1MiPisVfX3Urry6b401STySfdENz0L6cC14wOKN2JjBpAPtu
         J/6rvYsvfQCX0zLRDdnGD0sO5A8YJk5yuuMvOpyg525XP/UDx7nT2zUj6r1pxElbpd6/
         TXaWadP/q9FWqXMuBGDvxnbvqTFb87GBLsu6n/c7shEEUod2aGMfuzGiBISISnP5ojTH
         6pXVCkxttkU3cwPSk6ITdHCHZK/1xtD+gwXdi497/DlZHYqEOpd+kwdPveYATHi+N7je
         Mqc35qvRgE4QJoyvtMYZ5t097bxZTA99Z232f3UnXcptrLHoVLoCDQQA39omBxklUJPO
         VqXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=d1d99Uk0bs9de2CFzv94pHhHyRDYuyR+giZpfjgXrAc=;
        fh=uyOudV0EZ1IuTZVzgG4AJfyC6MpEgnDJLQ03gwQ7DlA=;
        b=Tqj2nel1Xx2i3vl+hV7y2yXaw9iQT6GPM78x+Oxgj+T2bwMxcGKOTBO6RxrhGx3vVq
         FlEuTjOvCi9hFH/4txZtjej+26Culq4lKnYoFex3R9Eu+geUsNdS7J+W5TOPeOe6xXi6
         Z3rw10Xpkxy70VNUrbdoUqv3eeo0kPpbC2VONbb66e7BDXlHwC9lQbLeGRfffvlJBP47
         RwN4jyHeOvPQ8iB7xqfWCGf4Thbflm2b78V0n1Y1H2cEF6QH23B+/U0YSNJSw0ldnags
         nBkWje8C4MK0KIAbSjUfHXCxDomZT2aTPNwFKDmkqekiG/qEGmBgV18c0Js8IVNaD3qv
         5NXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pIdx8ZwA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194080; x=1755798880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d1d99Uk0bs9de2CFzv94pHhHyRDYuyR+giZpfjgXrAc=;
        b=cGkam4dPbhn7yLoZ/dUWD6bHbprh+lHQyauZjniAqJRI/Q9BbAeDAzNaFXkBjZI2Do
         G2/XQS3bsz6sKHoRCZduqOW+njrixFgUBXC0YTEufpih7Rkwsb9+Jab/hKI2VwxnBX7C
         bHpWygqU3G8e0dTvPZwPbAfOuudUSHrN8s3aWCp+RvDsIW0CnopX+Hp5mwC9AHWCSv/w
         NSBSxyS4G94ZEP/w02pg8xTCRh1M6z5h/EcD1JP81P+31OI0S13JEs9+rsRELt+zS9o2
         0YAFVnp5VAKIVXC3wKqQGHCDKQs/8q1BpgqkAZhMpNilfhVCzVPB+Cp0U5a/wMyDkLxl
         C9MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194080; x=1755798880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d1d99Uk0bs9de2CFzv94pHhHyRDYuyR+giZpfjgXrAc=;
        b=dHcijroYl1XdHEf/z6Ih8Px/t0zrDjdv6RWatAFgjtSF0gMp6n2HIX4oSFlkeljM88
         tp1p0Vq6cs7NJAa1fq4E/1t6kzUdX1UDyZ5e2w5mfGNdwaa/9Jj3wKHsg0eWZBqrmvQM
         KUX/UOO+nImg/2+H4DPv0Dmnn2ZR0/9EcwhDr2qCMdPrRD11SC9YheijaG6Cp017VPf2
         Xmqvh3A2s1cEi3pWrtRBcP449hvou6jK2dFb6MAL2BSUVnVa3haiUeicXOQXzG1tFjI2
         dxR8nyXj06dE1R+cJxpp5Lt8TIsmAY2xXbB+gVAoYcRdNk0PVmyM5EInppHRIobkWetV
         7lDA==
X-Forwarded-Encrypted: i=2; AJvYcCUT8AvVvDYy+f3iGBxvUx8Svgw/WrrCZkNaUWO/MUNpZl7KYpnah9eraPzYap/FIIwGAE3ehw==@lfdr.de
X-Gm-Message-State: AOJu0Yx+/KodMxwvDt87Xvm45aFv7iOfcns8Y0zf94q2/NGX6V1gPMRU
	j4LvWNTabCmCw2kC06cY/4PNQdkqXoAFYHI5F/kLb2MOxEo9pMRTdX5X
X-Google-Smtp-Source: AGHT+IEQV2d4pN4XAKknGelWq6l6zH+QC68HRJq2ZxNyOmcrB1vnlwJ/6gbU7ZeYf+TBs2N6bSgVfg==
X-Received: by 2002:a05:6a00:3e05:b0:76c:3751:dfbe with SMTP id d2e1a72fcca58-76e2fb43301mr6721262b3a.24.1755194079486;
        Thu, 14 Aug 2025 10:54:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc/9X+KWkP9ZOcMRCW3Ux7udeH5MS45FqhdEgXCa8srMA==
Received: by 2002:a05:6a00:1a8b:b0:76e:25f8:1484 with SMTP id
 d2e1a72fcca58-76e2e1d5840ls944062b3a.0.-pod-prod-05-us; Thu, 14 Aug 2025
 10:54:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrPG6cHhuDdlcM/KnfSTEMplz/CIIXpxebArEo/VuomR8q8SWPl1BLez0baRvXsWZS6a9hu0P2ZTM=@googlegroups.com
X-Received: by 2002:a05:6a00:4b50:b0:76b:f260:8610 with SMTP id d2e1a72fcca58-76e2f8e2a4amr5538712b3a.9.1755194077286;
        Thu, 14 Aug 2025 10:54:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194077; cv=none;
        d=google.com; s=arc-20240605;
        b=MqGiv6fdi380Gd6+SJ8Voz1iyrVGQJwEDxLZ1yOPW4Yq3Z5x5DBQKO/PKo7RmtwnM9
         +EcOixDfAAy91zfKSuI11aQBVD8BRGtXNIqOFwcF1Cck2Vwx+NkUFhqb/NYC/qCEii4Y
         GUUz4ZuAHZDsSZH0FjVrk9TB+QvNaJVelsQq5Ef4cC7Pc3+RsQOjTcd/+E37cMmvB3OM
         poFFfDctwDrukCo+W0xjdt8yuu4kK7fHaFHkGyXiV2ynjEyQTquBSYsadgGPSZbTwBU2
         RQMLHKXai2LPmBK9ktNl1aeAHSVXSW6fVi2U7lt9doo3mmEktMw0nM1Fanx4rNF/EHJi
         a9RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KfgzUojTM/DB/MYkk7DA2Hi+SCW1x3wlstgTHhLqb3I=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=J2dLi8K55R+hqacV0T96kRSF6ZX9U1/FEDOFfpDpjto+KO/3+5AkaQaHeli7LwztmO
         ZlAJUWAaxTzWsKlbp+HBNHx3X4rmXQWQj2b7KMm5EtDq3ZYwtcJkQBx9fzMinZMsKtyL
         iOA1+dVza487tt3BlaLMvbnRawYE7/WW10PXbiYik32cudKW2Fej6VrzCfPl/X/9G6nN
         bFIksow4SyO3d9jvbrAbC8ML7G12rqwFci73g3w3bNti4ngrUJsIwYYl3HuuA2LJMnv6
         0kk1kKLDxUeKsWdxp6GeDjfK6ixrCGtDSjzdEqjOjGgmqS81gPA1NqTJJcO8iVI+Gbrr
         IF9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pIdx8ZwA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bccf99c64si1481316b3a.2.2025.08.14.10.54.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 731A16112C;
	Thu, 14 Aug 2025 17:54:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 73FB6C4CEF1;
	Thu, 14 Aug 2025 17:54:35 +0000 (UTC)
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
Subject: [PATCH v3 02/16] iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
Date: Thu, 14 Aug 2025 20:53:53 +0300
Message-ID: <62d9a6c3ca03037631f6d0640ebec5fbac41d547.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pIdx8ZwA;       spf=pass
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

This will replace the hacky use of DMA_ATTR_SKIP_CPU_SYNC to avoid
touching the possibly non-KVA MMIO memory.

Also correct the incorrect caching attribute for the IOMMU, MMIO
memory should not be cachable inside the IOMMU mapping or it can
possibly create system problems. Set IOMMU_MMIO for DMA_ATTR_MMIO.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 18 ++++++++++++++----
 1 file changed, 14 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index ea2ef53bd4fe..e1185ba73e23 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -724,7 +724,12 @@ static int iommu_dma_init_domain(struct iommu_domain *domain, struct device *dev
 static int dma_info_to_prot(enum dma_data_direction dir, bool coherent,
 		     unsigned long attrs)
 {
-	int prot = coherent ? IOMMU_CACHE : 0;
+	int prot;
+
+	if (attrs & DMA_ATTR_MMIO)
+		prot = IOMMU_MMIO;
+	else
+		prot = coherent ? IOMMU_CACHE : 0;
 
 	if (attrs & DMA_ATTR_PRIVILEGED)
 		prot |= IOMMU_PRIV;
@@ -1838,12 +1843,13 @@ static int __dma_iova_link(struct device *dev, dma_addr_t addr,
 		unsigned long attrs)
 {
 	bool coherent = dev_is_dma_coherent(dev);
+	int prot = dma_info_to_prot(dir, coherent, attrs);
 
-	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+	if (!coherent && !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
 		arch_sync_dma_for_device(phys, size, dir);
 
 	return iommu_map_nosync(iommu_get_dma_domain(dev), addr, phys, size,
-			dma_info_to_prot(dir, coherent, attrs), GFP_ATOMIC);
+			prot, GFP_ATOMIC);
 }
 
 static int iommu_dma_iova_bounce_and_link(struct device *dev, dma_addr_t addr,
@@ -1949,9 +1955,13 @@ int dma_iova_link(struct device *dev, struct dma_iova_state *state,
 		return -EIO;
 
 	if (dev_use_swiotlb(dev, size, dir) &&
-	    iova_unaligned(iovad, phys, size))
+	    iova_unaligned(iovad, phys, size)) {
+		if (attrs & DMA_ATTR_MMIO)
+			return -EPERM;
+
 		return iommu_dma_iova_link_swiotlb(dev, state, phys, offset,
 				size, dir, attrs);
+	}
 
 	return __dma_iova_link(dev, state->addr + offset - iova_start_pad,
 			phys - iova_start_pad,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/62d9a6c3ca03037631f6d0640ebec5fbac41d547.1755193625.git.leon%40kernel.org.
