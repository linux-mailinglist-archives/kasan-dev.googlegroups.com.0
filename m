Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB2GVYLCAMGQEMC5KAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB5DB1A19E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:22 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e8fd6a31b1csf4624874276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311401; cv=pass;
        d=google.com; s=arc-20240605;
        b=QQKch3M51BIXamxZ2AltPDAik/O5SselX0kvGX6LI2pcFRQRSJuWTiGlSQmKE+wgUu
         7XUmL0rQtChdYd0bShFHMl9qxTXJVvliPicy6sRacKX0Ry/notd8Pi/5afBb86JskKAb
         fmLlTjIO1OfrAv4UDwEnaNB6OgJ2ySe/dIbVFrcYrVyRKraoIjX1kHkcbtOBucwzRMtm
         BbDS0HMkRzJou3VYCYdfmlhBqge/WaP/6B5+42eLdsls/mfdSyBVW3r2tznyB4Ri924s
         XnX6aRToWVSUmuSrEmc2ug3Fj2qWE+9NNHUMQPV2R41Y7KE0qAPL9o22qWkQxx/r9iud
         VoJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GPm0C+jkvmSVR0PXcORsFvg+yCEn5ypMw/ku+SpCN2U=;
        fh=NSGMzqkQ7wUGXAbK9OYcMNfNZ0FU4Ym6KqR+q0d5RIU=;
        b=cQCEXs8b3ZLl5M66NLDKt4aTkMKM9LSfVyreeq5UTQdCD0d6dqvfkH4qNRQXIB8TBl
         lju7Feao+yQTh25xFx2PW65+lkE10dnzqFGRUSvvvQj5DLH9lJKVpnUZIm4CQlFFtKym
         AgD2+IYmPa5OFUNEdI9qLnirT/kASy3vuqbWl+TSVn74McVxWF4uS8KK/jz9Wb+RdEav
         LU/6Rg41njFg0Mb10nYoeeEtr1j7ZgPei0V6nB9Ly0+0lVAjvwoN7schrmlhQPHpPiOu
         Fh/yZnMM+v87BxF2mppG0gPeQFw5WVKfCYV5Qee5WfXP4mZo9lBxHH54r3X00Em6V5kH
         hohg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QrFIfUaO;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311401; x=1754916201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GPm0C+jkvmSVR0PXcORsFvg+yCEn5ypMw/ku+SpCN2U=;
        b=sfaTpWAIGc8zfgrkgBFi8pBVxsvnVI46GxRSA0ZyDO00eaggevX99pEZiza9tLhveo
         u4tvgSc+ouwVQHTEyxiLV5dMnYtxp8fANHMsPnpC31uF7IeN2QfsKEZCButiGFqdtRrB
         AwlMSJ83Y7LLh/ICGiNJJeuDbU1EBG+kL05Pam60d6CqXAJtJbcOIiFjKbQ2DVZxNR/S
         cYqmekpOFJwVHx1+NYsefjtniPzuqI4fk8sTBTM4LE8qnF2WcSVLtyBVgfzhaACWLJGx
         un4DIBdGobEJTBMoG8zGDgIScfjulGhQOPMBgfZuDAQXMj4q54EwHjItfBIA/XAAC2J/
         SPkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311401; x=1754916201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GPm0C+jkvmSVR0PXcORsFvg+yCEn5ypMw/ku+SpCN2U=;
        b=tcea1SDLje/9/a7gpYdPs5qBChcA+LRyaDELxzu1mXDEIWq7mjBOUy+BYQthz0vDnW
         esciwQm5Lq+0L25ZlwNZoLcYQoEBXwWs7AC96NegucLMg7+lWDS4ZqQirdkyahtxGy1f
         /HyFsM8ZL5O0NzKnua4HEClKW+KTdS7iIKi1vC802s+ucU9IhWILKCa2ehXM2jlTa/BV
         Mx0VBxMHxeFhc8fkbCf8T2AaHQBQVZKy4SjrXilaoVoIIT9koB+FTFcN5jK+ezPwRIiz
         z1iMvj/dI24NnL+/M0OgiIi4AZe9WkvU8TqrEAXMMIg9xlpXIdGAPYDmJ+HkPbj/3Btj
         k2Rw==
X-Forwarded-Encrypted: i=2; AJvYcCWqb9rGvPVwnkeMr+emGdF2EJ2MBxfegKaiuEcsDbVAze/ALE1JC8OPItNzvQPbt4qvXhXSlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx4dd/q4SNyvIbzX5z1fQrTAPCIBgK2KJ2DoveEQcsjqT5048E4
	3ovNLhnY70Ug0SDVU8GG/UMqDcQ8yD/cD3Th/BJDDxJL1NhJwPaGqVvr
X-Google-Smtp-Source: AGHT+IGsrJhRKlKTo/P2KNWCclQ+wJi48gfx9oU1Ynfizh0yxcNpVSKTN4cjJ02XogX6TpRYwo3c9g==
X-Received: by 2002:a05:6902:440e:b0:e8d:ed72:5743 with SMTP id 3f1490d57ef6-e8fee281609mr8611616276.28.1754311400945;
        Mon, 04 Aug 2025 05:43:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgkLVT+Cnhg9/Cp+0ImP1R4ruoR3DZBH7i1cpgWjHcIQ==
Received: by 2002:a25:abb1:0:b0:e8f:d133:3717 with SMTP id 3f1490d57ef6-e8fe1eb2f2cls2939192276.1.-pod-prod-04-us;
 Mon, 04 Aug 2025 05:43:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz5v3GYXNc5BkIzGPoiMvEIbjGuo6Hp4+hqaahXN+BLgoWomUOyqbh6FgyTK5efE26mN6nLXFlmSY=@googlegroups.com
X-Received: by 2002:a05:6902:2b8d:b0:e8e:13b8:5c2d with SMTP id 3f1490d57ef6-e8fee206264mr9164607276.21.1754311399189;
        Mon, 04 Aug 2025 05:43:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311399; cv=none;
        d=google.com; s=arc-20240605;
        b=LmNw5WVUcovwqARcSsBxccSySlEm7NTfOBC40tnswcOOqP4sWGOqnAhil1JGSUTHnC
         6wT28E7mORqX3ObBuPfrs8IvGLQVpInZsc6eflCDkhr9gsgyl5AOal+GCJwxuo9Ku5G6
         NSMhlrDBprsqGBSIyrVUWyz/0K8Cua2uv/4NK9+m4vDgoerU1CdKuhw9EpNJ0r6OwV4k
         KZrfZ/bRqlqibCo5a0KNAhZf8za7UzBNA8a9lilJ/C0aFRnXB4vzgefMuk1VjzQpWkMs
         eRXICvaRJYJn4kspmln1iR0T1jRypqtN7T4h9LV4uNllPbW4WE8Di6Ly0k9bDNK+Le5E
         34rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4AS9Yc3IoSR3Vqk1MHpbcTKCwde8JIMHurGCZB+n6Y8=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=BmrVZk2L/A8W4JON14FnsXg+iQCYuglM3nGa8jm9YT84U9SNiTSNCK8JiJutE+Erbk
         aA80NvOiWOsENUoMPBm3WF0iUWug+J5fNmUfeiFMgsn97rR76oBIrjY+g44BGD2MXiOC
         OLKt3JZ6ofq4JrxKy5z1Ai3xWpJZf973YFE1xR9XPJL6uDs2u9Vek80QdB6n2fTXFZ80
         TWDSPfRqHSd7W2eml0iJUAoUw/E+g9pMsXyO6LiA/922d9X4AUMqhL+6VX075Xpk0spE
         5wNVLkugKzRfaPUM0isjyHljTLmapD2g99NBiNAQa4ZEjPxvO9Nsx+HOiNG9KUrKyflj
         tX9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QrFIfUaO;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8fd37f8434si454804276.2.2025.08.04.05.43.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 56FE04423C;
	Mon,  4 Aug 2025 12:43:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4B783C4CEF0;
	Mon,  4 Aug 2025 12:43:17 +0000 (UTC)
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
Subject: [PATCH v1 02/16] iommu/dma: handle MMIO path in dma_iova_link
Date: Mon,  4 Aug 2025 15:42:36 +0300
Message-ID: <52e39cd31d8f30e54a27afac84ea35f45ae4e422.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QrFIfUaO;       spf=pass
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

Make sure that CPU is not synced if MMIO path is taken.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 21 ++++++++++++++++-----
 1 file changed, 16 insertions(+), 5 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index ea2ef53bd4fef..399838c17b705 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1837,13 +1837,20 @@ static int __dma_iova_link(struct device *dev, dma_addr_t addr,
 		phys_addr_t phys, size_t size, enum dma_data_direction dir,
 		unsigned long attrs)
 {
-	bool coherent = dev_is_dma_coherent(dev);
+	int prot;
 
-	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
-		arch_sync_dma_for_device(phys, size, dir);
+	if (attrs & DMA_ATTR_MMIO)
+		prot = dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO;
+	else {
+		bool coherent = dev_is_dma_coherent(dev);
+
+		if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
+			arch_sync_dma_for_device(phys, size, dir);
+		prot = dma_info_to_prot(dir, coherent, attrs);
+	}
 
 	return iommu_map_nosync(iommu_get_dma_domain(dev), addr, phys, size,
-			dma_info_to_prot(dir, coherent, attrs), GFP_ATOMIC);
+			prot, GFP_ATOMIC);
 }
 
 static int iommu_dma_iova_bounce_and_link(struct device *dev, dma_addr_t addr,
@@ -1949,9 +1956,13 @@ int dma_iova_link(struct device *dev, struct dma_iova_state *state,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/52e39cd31d8f30e54a27afac84ea35f45ae4e422.1754292567.git.leon%40kernel.org.
