Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBZHN63CAMGQECNMNXQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id B3311B261F2
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:13:57 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b109a92dddsf21644731cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:13:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166436; cv=pass;
        d=google.com; s=arc-20240605;
        b=GBJQQaUYdeF57+MoxI/u0h14N9EMfj1j/jC1XJniAid5EAEa7Bzt+8YHYOaNSydcPE
         2BpUV9nMjy2K2pqWjGM2ynZtZ6sWPlWQ6OISFovbM+m2nCm3Rp715AABGWGQMkl6rX/8
         1M5gCexmW22CCW9wlAIMCO6xNYHMPDazJSoFDLMebPqm5pV69ip2ZFAua6+Zh0tJ+rVd
         Bo/Ew/Nq08aIu2AWIRrfnNJ1bElScV+UV88kK6sGMTLffgzz8IORBpp5x4KPybKYXAMF
         2guAaRY6EKn00AmVyYgdCF4lV0XghS3PjEA14aosyJ06x+rFsW063QvOWDNIMDCJ5OGs
         413Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lxacw5MBEHsOtkZ3lXtMbUhBIyXY3DzZnRxQeZB/Mf4=;
        fh=e7DLZ8f8INIT0XPp2qRCeUUMZuwoA2J/IaDcpeNnkso=;
        b=TV6/33UKTx0pECAza/N41dKcAQolUV+cmKUM97qDFVwOdFG6ORLJNqhvCKiCuxislM
         lwQ3vW+6Ijdh20/pzsvWrbDWgMUYU/qqb7iFf3lXd+j/vi3PYuOkib3Udz1hIC/9m2lK
         /OFdJYKun3E3x3iLTSxBFmuhKI7dTKdKVaFvXULfxM8GEqIDXqv6MZDiSlHEaDRT//I9
         TcI0j8h/surKia+lvjeoAqjXjvT60uXyxuShWFUAbN7iox1qjLe4Z3y74EANzsdwVomU
         dNGF+0XPby/nKrYGhv7BvnA01QQpsKGM/iXpbZz6Elgb7fntPmpTPQuJHYsyMVzPzNcM
         WiLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WhF8V3MQ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166436; x=1755771236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Lxacw5MBEHsOtkZ3lXtMbUhBIyXY3DzZnRxQeZB/Mf4=;
        b=S2iR+fgcCHJSioCc8SEyeKYvrYubMHiGAoF+JJI1vioLHuzvDfV90oQ/zAyMTLX6q9
         qX9pQjY8MVQdxZ8yHlAPwNDlsxNJUtF0CjgA87WAWSaIYX2ALm/+kFSY4lyPc/Z027jf
         CKz4l+if/GvJGz9LTaWATzjLimhSCBZLSm9gkd1UFDuy2MHikfB1JjzqQX9JYHeTMVqg
         3QYasYnk+CTsK6fiejCLc+BFKb6x/ZsCCUN+cEnduuV6AVz7TfLxwxZXwMIG2C/VONCo
         VO9tiZV8X6sTIa7m1qpjzTepmlaVpKZELxGe2JnW+t0Ybk3CzUT2jGqdM11wO5/ZSLkU
         FHZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166436; x=1755771236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lxacw5MBEHsOtkZ3lXtMbUhBIyXY3DzZnRxQeZB/Mf4=;
        b=jCb1RlePqRINrIHDgxqyVw5SgKyZisGwz1cPlkuwej03AevwjnJUd/hJPGEsy8vGX8
         eAd644g2R/HMXiRQQLVZGH4gOMp6r8R2GAb+c68p1AF+aZeM+C6wVoTYuQoYqT78GNZE
         LKH+lNJ/G3WKPZxEu8DDH2L5z9ix4XXB5ySwER+mPq9ajO5JHLZQruWZ0YK7MO58OLgl
         Nynt72vOXBDTj0DsF4tQg5AedmOp75Ac/Mo84BG0PbmnQ0s0C6VCbF0A4qIA8yG54fhT
         k4MYH3HdKR3ro4kJGIhbN9MFufVPHWqVELH62TlAQJOfGVSYDS1pQtVG/0S8pBVa1SyL
         twjQ==
X-Forwarded-Encrypted: i=2; AJvYcCXwZIlIXPPk4WBR7zY+emTyCdJ2tZcRRPCo+Bx/L+5lP8EAdYmPp9cqnVBjdNJJyvVMe/rvUA==@lfdr.de
X-Gm-Message-State: AOJu0YzIQzHO0SGpUcTbgHjL9HHKsTc/sOcUZ7xkL8g4JJG2NCKUyPpw
	+OhJT9DHORsHatbwhIsb/AWTlajMwtxgNcNZy4FlDhkiVxKQuGBaZ3ns
X-Google-Smtp-Source: AGHT+IGiR483Z5llG7BaLiCPMi2G7Fz3G8T5NDE2C/dxkUF1Hdl02VC4Js7VddPRblAGh5zDcd71rw==
X-Received: by 2002:a05:622a:738d:b0:4b0:8338:30ee with SMTP id d75a77b69052e-4b10a920d45mr26857141cf.11.1755166436336;
        Thu, 14 Aug 2025 03:13:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeira0w4UgGNQV/AH2ZiluKB0BBt0s1XsHEF0fg75ZXuA==
Received: by 2002:ac8:594e:0:b0:4b0:64ac:9be9 with SMTP id d75a77b69052e-4b109b9e90bls13028341cf.2.-pod-prod-03-us;
 Thu, 14 Aug 2025 03:13:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVW3W9IAev0H/Iw/YD058gV+VNtprKZb0yQZ4r6tIqXvGKaTwtgclFNyMu94IVdKna/IIyGVJpiTUQ=@googlegroups.com
X-Received: by 2002:a05:620a:5e14:b0:7d4:4a26:4065 with SMTP id af79cd13be357-7e870496376mr289446485a.58.1755166434969;
        Thu, 14 Aug 2025 03:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166434; cv=none;
        d=google.com; s=arc-20240605;
        b=SPlqhR2kM5CSmEdFFpfK4OctwZq4q8EUEvdGssp9AEq+DwbcJz1zBESwWvPO5ZNIj3
         e4iHDiM/sVzlckkg5ajfaeaN4odzApmQJoyLMsQxqgXi0IaAUe54zg4B1sXcqI+4N46b
         llad3tom+ZoYHOVpY/rp6bizPNLU7fHrW3S4t1KgG8u7HhzsGUx4krJ35NlX5gnFEpKW
         D8jZF/VjDn4IpIm2cQCXqSurYCS4O58MAWBdAY843qCN899oVZl+uhAjoi9wDmsnv/Yo
         1k+D9gcjDytAMVf1vkK/AOzSBZq6zE5KQS2owvAR1ZrcX+JUh/bc88CWE1UezqYXN1Ph
         T3/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KfgzUojTM/DB/MYkk7DA2Hi+SCW1x3wlstgTHhLqb3I=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Cys69wHxMk4jBG7w2rI4k/WYgDsMyygwRlqHB3gGWkpSoPc2FSGpX96uuZqqjcFTpm
         PLxg2WASYo5FJUHUR3a5ETJDKhZktQE7rtJCxGgQh84HPCWxKa/1tw7ODFzxfAGJ010B
         H0G9UpXp0CJMBxgsy8EX6ykpyLsoO/mWYPpDpMjzoUmbw+RGOJFIuOStYX4cNW4EE86A
         YOokjoy95nRrKZuqigq/4b5QdjSDiKwcgsOGZ94PPpBB5vg4ECRd3GHpwO5mCea7m0C6
         /QPfBiyxuLXBmwF40U2/HQYLcShTBvElHWp7MkcQRsBMFIbJS2/wYtuaeOCP7tVD9QEy
         5yiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WhF8V3MQ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e858d1f2f6si36321685a.6.2025.08.14.03.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DEC1444F83;
	Thu, 14 Aug 2025 10:13:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 08B60C4CEED;
	Thu, 14 Aug 2025 10:13:53 +0000 (UTC)
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
Subject: [PATCH v2 02/16] iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
Date: Thu, 14 Aug 2025 13:13:20 +0300
Message-ID: <4f39936e5a7319a848b1eebffe928c251e2ec0d6.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WhF8V3MQ;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f39936e5a7319a848b1eebffe928c251e2ec0d6.1755153054.git.leon%40kernel.org.
