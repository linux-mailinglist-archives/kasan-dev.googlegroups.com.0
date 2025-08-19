Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBZ7MSLCQMGQEP5UPXEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 96799B2CACA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:45 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-76e395107e2sf4939647b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625064; cv=pass;
        d=google.com; s=arc-20240605;
        b=G0DTgpxkzW8Q97rn3iiaeG/7NiCxxZca2f4eVsUI5tC7yIWo+xWVEZxPj6xWwkI8MH
         Al8ziw4EsiLgG6H3zkaRl0tCofpQmqiEDv+KiWB0UD6+2ZLeY5yItj0R6026JwOoAMyg
         CjJrpvquJcZAnLNLBvQ334mD4cEjheT22o5Vr1/JIMuS/YGqE6Zs7chwaoqMwU5ZXkLY
         TCuNbf6v1GXiKlsG8FwLlIYOpIiOLJF2+q+VvcTGyvWs6ch3uigfuYuwQoyZaQQrcalc
         AkBfgMl3Ai2kT9lP0ogvKMTMR6nKMclYAopRclHG0BvgjFXBpSh0EOWLIPNix2Z0BgLq
         ztag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=oOEK3eQeZuNXqNX3bwEcfrx6R9qMPfnp+LUWDiLL9Xg=;
        fh=inequ5w9W3fvmQYBBmBqbRESb+o7spu77kQF1lyPSFQ=;
        b=NTy55HzsIMz66YQHx1V3yZ3ajbKOg3+pLxW0fMZcVfmC14R8aIVM4E9fDJV5ysubsX
         clPijjyLe49hcpGpo+SOk/yT5sMKPQgq9dGHy/0sr4Xt+wWIa43AbzgmBIB9eVwdUsQY
         uNJSn/+nch/Ps9n2wL/UspWMZBdm6nPuG9Ap47tnoYQwcmle2VmweoSfuFCnQnmUbzot
         nmNJsAF8IWYhcFJ7yXZZ50M8Qgtf6wrpelclQ1GZEPvTFSall1B/oyINalKJf0IDdk+S
         3qTtZHkHcFVzB41/cmVZ3B2VnKx+P0ahrEP4hS0+GAspCzXva7zZW2KPVKs2ck4PHArW
         5lkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcfXQzEM;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625064; x=1756229864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oOEK3eQeZuNXqNX3bwEcfrx6R9qMPfnp+LUWDiLL9Xg=;
        b=YryDYaCN2Iquzq87KwxLwLoxAYskaSNeteVFHnhhUroyzeyB/w2jAXJvMGy33Ww6cD
         rfLhczyqEcwtH8e34pvvU6B9gf0wfRNxt098ddVxE0OE/NPnnRKc1dlzbSqDJR+ztjae
         sTPck3FdXTxprWplHeDopoR4V8d47UveLqYK+ztnbRbPVdBPd9ApnbZhpoq6MK1XtdNH
         iTvKrumVAYmCukf6TCOPfWb9k8zIjYZ3J/Gi+wfi/YsTJ7LeHH5TRx8G8aIrsVMuAvsm
         GpSlzcbIKB4Tev8O5j0XoplAvm7QOpgNExCpwg7wRHNfeB+ypwsF7JM+PNjglWXOWZ9+
         P3DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625064; x=1756229864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oOEK3eQeZuNXqNX3bwEcfrx6R9qMPfnp+LUWDiLL9Xg=;
        b=ZroKq5A0bUTxlzncSggB1xeh5XF7oBR2STrhKv8IvKQWhbbHQZ/1mMHW+4jKVqr1sQ
         guTUDlbTOATRjczywjYYUALssTjzc09NuodkCNrpFM2rYZOFJ2B951EW3M/tQmJ03/v+
         aneRh47l8vSURYekbq/HXeGUHKtWKmWHlNBBCB5P3N/NvtguiEA8lJ2YO6m/yyG7X0Cc
         FtDxZtLcUcBl0qvUkiASXPuGJsF7pA8NEMdAjWrY+gWrtc9ryuNJhP52G3X7MLb3SUqI
         SBSffpFrjZhMckgrYqZmwOmc++u6t8ycv8C2jbk3QJwRbfh3eqxpbLub34a0aig+nmuK
         +mig==
X-Forwarded-Encrypted: i=2; AJvYcCXxMvJ8YtMNQqBajZOPvVmEkaqwMRvJmUxwYrcLHi3EUlpcX3ybV+TzhTk83pQ/zQwziWN09w==@lfdr.de
X-Gm-Message-State: AOJu0YwU5LgFv+dWHHX9HnekM6e8slWMI62MJxndOYlldl1HglN6a7Ve
	Xc/99F74NMqjKh1VH6OwSPUTnXo7UP+qpxiej+jtGW/dm/CgYAoXMmLZ
X-Google-Smtp-Source: AGHT+IF7YD36nK601oriqJiLF6TpawTXmRWxAQU6oELHnSP8hfz+7K5fRA9nzB2L1cS0eqlD4gie4Q==
X-Received: by 2002:a05:6a00:2344:b0:76b:dbe2:40f6 with SMTP id d2e1a72fcca58-76e8dd75628mr48381b3a.23.1755625063804;
        Tue, 19 Aug 2025 10:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZBpg+HaKxgUjzugBva2VjzRrf3MG+q8ES9yjzz/IVeQ==
Received: by 2002:a05:6a00:1c94:b0:736:57a0:c48f with SMTP id
 d2e1a72fcca58-76e2e54bf2fls5100101b3a.2.-pod-prod-09-us; Tue, 19 Aug 2025
 10:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULLJCkiauefeWhWh4+jTeerqqEEoy4zYF1lStLfZyz05VrJqXerAO8f2LiDzG14NcZ9gPnGZG2IXM=@googlegroups.com
X-Received: by 2002:a05:6a00:3c95:b0:73d:fa54:afb9 with SMTP id d2e1a72fcca58-76e8dbec4d1mr70535b3a.7.1755625062297;
        Tue, 19 Aug 2025 10:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625062; cv=none;
        d=google.com; s=arc-20240605;
        b=WikLIjz1QDLnrvMmgESD/gXawzsEApG/YXabh125J1fSL77plQ4PLbWtdEbQcZ4T6k
         dCQU0zzT9EZ1O5iXxvVEQobBPxDBc9xlwhEt3O0OoDY0luZXSCZfCBZL+Ga9jFU/0AzH
         DnT8p5OjJ4hMYzTVSTug1cm/gPgLmvFxBopWHQsasgLTJL5+i9gBqeYTX4qnhh7TJR3H
         RlvnFIamN4wEcPseyjyfTzuS11hc32m4gMA6ne5HX+KSySN+1Ctxa43R0to+0Oj+6slc
         AqohtRqEexYyHcAUPXdcPSh0fLcU1oOUOfjr9R4SQ6ebSO9I9gGTygkmXHmkqvRI5i2+
         iL2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KfgzUojTM/DB/MYkk7DA2Hi+SCW1x3wlstgTHhLqb3I=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=ib7B7XK7vXCpde+Diy1iE6vMoEOpkEeGIRAJmAZoekw9xalinAln23jdrEubHYDioe
         CF1R9ybz+hZUySAbN+Vq2pZoGYuRAbhtQetydTRevLrBkhq2HE0qr23/3IgktE8iQTpY
         aogx37wvVPl7JCm/VvLQEDf7wZ9YHz8gYNVa910slkIC7mUzVlXmnXy7dPN3hP6A3h2O
         kV+912MgM1YASYVokxtoUWl+tt653o38rvqQ3ADdf65hn8hW2CwP4vpZEDCgaszFR1RB
         OIQ8SlCkadtYNuBfznDhmqbNJ7NneBZUnGZNWe4awG6c0IWqulTamlFoUEC6sEwd3UPd
         Zpxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcfXQzEM;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7d1dcf8bsi154150b3a.3.2025.08.19.10.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7C8405C64F0;
	Tue, 19 Aug 2025 17:37:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53FEBC116B1;
	Tue, 19 Aug 2025 17:37:39 +0000 (UTC)
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
Subject: [PATCH v4 02/16] iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
Date: Tue, 19 Aug 2025 20:36:46 +0300
Message-ID: <62d9a6c3ca03037631f6d0640ebec5fbac41d547.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZcfXQzEM;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/62d9a6c3ca03037631f6d0640ebec5fbac41d547.1755624249.git.leon%40kernel.org.
