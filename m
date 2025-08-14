Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3OF7DCAMGQEEYVOGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 432D4B26E15
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:17 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b109c7e901sf29987971cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194094; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vef889bdrT8veuCxmQqs1mFW0ZnTAun+GjeX/678v6gVPB8w44FGL1LjtsZ45raCYk
         Isr/g2R2gUnh8NPG3MjOTLtdE6wMto8LcrZZSiol3Uniaj1k0NiPszPEhnAYfw3E8gf9
         NEx+u1qEg9hJGVu3LeoXFIzxFB5yVoY47KTTRQSJMSyipFcoalgUmzT3M0cM5o9e9D1Y
         cDgIERSnyZtfJojxizXUNdfP6FShP/+CssoQPY2fTM1mGEvrYSlYfSpp5MCyRgCf1w5/
         1uu43TCH4h7hqRX/2IWdIfp+QNhrNbddN02/0JDazsor0AD5HeQMxjZScaxsHXPrr9KQ
         DGBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ozpBEayEgBf+aL+L5wF2Yb6qthgeV0VLe3NOMATsHHw=;
        fh=fFhuX9XfgI3LNXPbVibp15N+VsxQIa0laWgXa0Brv3A=;
        b=GE5MCX8Olk+UjaKu7VZggWLo8YP+SSGDtwyzjqqNrigualTQZwKyGTR3yeiJUpZnL6
         6LUpNyDLeXkEVyK/5ET97Fx/UoHLnbkAGM3c75bTgyrNr6zM9k4q4rUQJ47mmsYxK+6R
         Q4dwCKG1PEidlaV1g1XQvPerqPj9qkeMd8gXib7yFp5jkxijSKf6NTapYEgA9LwqzwMC
         40SzvKH3ROixkkNJfLdsV4sFjmIHtzICyNb1fpOQ8gmIThn8oMosk2agZA9qs+cptbnV
         8s9COfbWtdWxJstA23ugJidjL4U0RDnAKi0+GCvtjIHYW+m6R3HKyfiyYkOsC8t3W4qt
         zybQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uzys0fct;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194094; x=1755798894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ozpBEayEgBf+aL+L5wF2Yb6qthgeV0VLe3NOMATsHHw=;
        b=P06mEHesAkHB7OVbUkIwp4pTCowVIPzVRYr5cyssxBhCITB00sk5suPjcaUbw3E9jd
         XdSldpIe1ogrB6H9rvwpIOUzfgHOxbCxYqvRllnZWjwReL0aPDfFmlX8a6Nvxgf0qGiq
         cbySBMdSPNyC8sRLQZxZNaKa23Xs9TNP9Dyhee2ZL/1yFPOQWIb1HSZa5CHgSMS8/+sp
         Jjw/atNTABlfZFagSXxspTnwp5ugRYAEJ1aRGQpIWsS4gDEBtF6L2MwGUgH1a1Z3u7pj
         9K16slPdnqfpjl9XuhQYH7k+dfrvItfWqdEH2a/n6SalYapVQTGDW1jXiunebYHU1lFD
         fJQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194094; x=1755798894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ozpBEayEgBf+aL+L5wF2Yb6qthgeV0VLe3NOMATsHHw=;
        b=Y7lm/5FRjx2qpNSG8RrmzP2PQPMeTueR/YeLYy0NMP9+EEQKRwFl1RFn29tvZAZJTn
         EN94NbJiwVhXQQshJXGArBpC/QjWvFhvX00k6gLsKQUnBmkhJtTe8oaYQivxLGBKNmC6
         5PG5H6nuAZgTxIEMQx9AWWRwFOBH2obkBL0QQlsbSR1KGdsLXZTiL5M44OP84qltJ9Od
         GxHHdsMMyoOiEp2w9XSr4WFYtBSAlh7myqALuQRLC0U7RNI2v1fmiYKdtNUvKNE+XOb6
         QC8yavzF5qaTppS/h6YCGrqOtb18u/LuHuG/Rir7rh6rJrvvUo4nfbSD2yJBMWs2MDIE
         JYOA==
X-Forwarded-Encrypted: i=2; AJvYcCWIfrzxc3nMywAwgO8H89XMGbSEs53WJGESRfydF8ZQqhLGlxnJobB8zD9w+Hap2rIaBW8ipg==@lfdr.de
X-Gm-Message-State: AOJu0YwjFToM3U2PFpcyrjbxwfH59/48D1LaYbik3a73kcWGy5I6Wba/
	5+Zr9Mij7Y0J9fy9/afTagyUPNzNpcsGEoNb7d5IBqJSsBa16xkoECwl
X-Google-Smtp-Source: AGHT+IFuFnqH2r0OxOKj1ZWe9V/P13Ao1Uvdwjf9d4qRvO7OKP/j24uWLGPA2IX+FYEzVhwB1lvU7w==
X-Received: by 2002:ac8:5984:0:b0:4b0:f8ee:9355 with SMTP id d75a77b69052e-4b10aabb577mr49345111cf.30.1755194093900;
        Thu, 14 Aug 2025 10:54:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcE9wz8/wTWaUMpDc0Q4x/GXkL5T5swlv7KGeQ/Hy0g+g==
Received: by 2002:a05:622a:1450:b0:4b0:7bac:ac35 with SMTP id
 d75a77b69052e-4b10a644648ls17369821cf.1.-pod-prod-05-us; Thu, 14 Aug 2025
 10:54:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDkB0nOxbDaybq+sSvzhTjqYukantgs5t8M0rzx1Z9yJ3nZG8SjTAlbeJElTcIDYIftc2yCzvujI8=@googlegroups.com
X-Received: by 2002:a05:622a:134f:b0:4b0:be40:d7 with SMTP id d75a77b69052e-4b10a957463mr56444791cf.11.1755194091696;
        Thu, 14 Aug 2025 10:54:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194091; cv=none;
        d=google.com; s=arc-20240605;
        b=eoUJipN1lmxOqNT5zwMsbjrPVfUGTDKJFBq0aXD4jV7iAsHlCOFJYQoLLBcORNvgnh
         9ERIgj0dPULmaPoiUz/6JK4IdEt8TK0gGci+floDeQg1S6l7zrH8u5hFUdkENRHUor2C
         WGJsb607JP89dz+v1pDSjzLBwmISmiuF/E3morA7kXK5LG1vWKvdC+SFzJxxe86rrjU9
         5ItRAY3/QVGlnSP8/qhjcIIEyQcKSSbB9V29boJMg2qZ9ryYLlDR38YMa9HvFO5LkBQg
         CbWJfcmISGqKuPtwKPKaiYe1IVAn1Uqi68rvFYdRnMDmZITUaDb/OMYg3hVtT8mLhIIH
         sbgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+qkotKjA29uhp00A8rkqHQXkiTzDF9Aqh1SY8eRdGdo=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=WhMd8TyBdcQeYm3wk1ZctQXVgzjZwtYLN5vJ9SbY2SKEP7/dDkCOrUieOMKOTrZ8A8
         o9jfSXvvEjEJvp5Pi91kS/jaY/t1t8fS0koI726M/km11UmE7afHyG+8GQ01mn9ZaDmr
         KxtZW2rtemMU+oali9mfc/1mcSjICArfSZbX1Y4gUKz26FZ6Edvsi+uX86vriyu4oWIg
         VS5W4zgLVSfCFlAYVg0aveQFb+UlX+5ciI76Q4LnLN2SS8TibCNreBOTXvfmtge/irsR
         amwl9H4qI0QsIOQ47LMYgYVRiuh9SXX+7IsCdwafxbxmCUNUVmBH8IbHoUeuYbZ/nmKg
         pAfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uzys0fct;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b119a1f128si46931cf.3.2025.08.14.10.54.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 5A698A56B3C;
	Thu, 14 Aug 2025 17:54:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43E02C4CEED;
	Thu, 14 Aug 2025 17:54:50 +0000 (UTC)
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
Subject: [PATCH v3 06/16] iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
Date: Thu, 14 Aug 2025 20:53:57 +0300
Message-ID: <4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uzys0fct;       spf=pass
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

Combine iommu_dma_*map_phys with iommu_dma_*map_resource interfaces in
order to allow single phys_addr_t flow.

In the following patches, the iommu_dma_map_resource() will be removed
in favour of iommu_dma_map_phys(..., attrs | DMA_ATTR_MMIO) flow.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 15 +++++++++++----
 1 file changed, 11 insertions(+), 4 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index aea119f32f96..6804aaf034a1 100644
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755193625.git.leon%40kernel.org.
