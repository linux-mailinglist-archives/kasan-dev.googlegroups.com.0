Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBI7NSLCQMGQEIRZCLIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20C94B2CAEA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:45 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-88432d88f64sf1537296839f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625124; cv=pass;
        d=google.com; s=arc-20240605;
        b=lbJMirdHpdRXUyE+pK9VUb/s/GTmdcrvta2lBe1S/UTy4VaZuUWoymgCM3zKje93af
         ILmz43Mb7wuisTJ/I3aA9jRWPUVWob/G7ytcRbnvbE5Jm+qVVTonN9K3mDom43EE9UC+
         MdMnmh6JjU7FsDNDds0tGrjIzFnYZ6TmnHLRSzY+N00FjM21PSedOtzmdkRcO99tlJH7
         9Y6m7W6qwA40O/dhajLLeUyXL8sHDjmZqM62tATA9DzjvesFNuulZTqkidHTOJoRNu62
         B7pVzfGbn4ssLjCxU7j0Ee3XzxVoK9s39PuuL6W11/JQAvAVcLaneYuSRNIsR4OWfj4S
         Yunw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dUA84C6D1AlNZbrL7hO2wBl9OU4KBTu0Ujuzrq7mDyE=;
        fh=rgOCWTsg1ZFkzE8psZ3cadl16CR0KtgMK6FnA9+BWIw=;
        b=Eu9lSkaXQBsk6DxCA2fODPFSh/k3Xa3H528Dw8rPHfYHt2Z8aGFjpHg8GXcayYNKyp
         vl8HZGoVMawPFjAcvroD7uBKlti+XJ81KeZn2QPNQ3h2ud0olM6Xc1SzO97KohKjnoOn
         ybzW1Q0bdTT1zruHtJ01VbkF7JrUMd0O5nrMaOP16N7MHna+ORcYo77zskizpLGwf5Jh
         coupmFTMnLloovlxGygoe8DU5e7WFU8OIWLp+ITs2TsI5fc1+lmurSvk7DLYi+MXPVwH
         Yj7cFtIQq11oNzi/yQa7XaFll5Vy+8aApvo54uycddY4c9do1vQhKoZPEW0h3ErXOOKt
         jbZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mqPmNYet;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625124; x=1756229924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dUA84C6D1AlNZbrL7hO2wBl9OU4KBTu0Ujuzrq7mDyE=;
        b=ZZLcwewV3ux5DGQydxBQ2D6jzMDOrtNjlLdxw3O15AfGCMNNpTynUab0z5BakOStoR
         LJSiiKYRtGR4+BmNeyv8TuZw0iwL+z4i4B9qdYCKQhOhPnm2/VXsIMAsDAQI0/Cak600
         0SAb+FtdQv3IsVnDxlD6PpTe2fMk6Zr8boH1pUfS0lXGachQGqaWWGHWJPMHcOxS8IaY
         rT0blg+16D1U23BmTVbI7TDcONG4MTTyTEj6cgzmp43CewSYCybW81f1z7q9hERk8IuZ
         NBd4NFQ+IgBVhX0wxm/IR512XQmiP1p5R4/umE9rYaJDOx7kPcSQn+N8gmc8vdPpPSYN
         aVyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625124; x=1756229924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dUA84C6D1AlNZbrL7hO2wBl9OU4KBTu0Ujuzrq7mDyE=;
        b=KjGlQ+KPoRyCoP/sXGD1jqMhuu8npWjQR+5vQlu57GsQhalVHiwzLHjusOrZHOrBjC
         8ntkmKynr6gwDbCL1V+2lChDHkJHAzleLCk+BqZNf3SQHbbvBGRmXy/Z/6O5AYYfO9LO
         uiwxa6buJVUbpNWuT7HUZ0uO4Jwr3DKb9/Fey/FXiqutcoC8hyI0llCdTTQMjoQAEPvM
         tynicPf38MOPSx2FF3j8+VJiyebAwvLSOO5Ad4dRWf6W5NM68arFls4YQajFb5poPNC3
         OHIs1CzrbV6zvRCwg674jbc9Pz6x9Gp3rQRhlnT6aiig9iGbGcto5CtBro6dBwbLdYRz
         Nl5Q==
X-Forwarded-Encrypted: i=2; AJvYcCX5vHaYwUwbEt1DAyZ1rlscFCSzmHQEJQwYC2434FEalCaSmvzUXOPh+kyvWObMaJWM6fpxVw==@lfdr.de
X-Gm-Message-State: AOJu0YwSUq3T1rcHdoMA0uh1I/SZnEnmpQjqHib6+bQgTnWwDq5AbqbO
	FOxiwG5nHDcZfDwTveITxAxRS9T4FTxRScyNnKtcWxMXyJC1rLXEyN7U
X-Google-Smtp-Source: AGHT+IFX3p5ViszShQNkeQDtHuKdPc+nwLxFkL/TtiZennPnc7iJNNp4lK3cw0cyG2QZAKp5+WWmzQ==
X-Received: by 2002:a05:6e02:4805:b0:3e6:7937:4fbc with SMTP id e9e14a558f8ab-3e6793750bcmr29656215ab.7.1755625123668;
        Tue, 19 Aug 2025 10:38:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcVge61F3Ob4n2vhVAeqTS4hiILeiORKZ/WCQY4Yity+w==
Received: by 2002:a05:6e02:1a0a:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e56fb53fecls61214265ab.2.-pod-prod-02-us; Tue, 19 Aug 2025
 10:38:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8B9ObvdQDT2La5E9czG9mDK2Zuv87ZdBiAdffqZEVcRAccZIg6/X6DdTduJG/O82EqkUWWFhDeEs=@googlegroups.com
X-Received: by 2002:a05:6602:340f:b0:883:f419:e3a8 with SMTP id ca18e2360f4ac-884718d9eebmr35921039f.7.1755625122601;
        Tue, 19 Aug 2025 10:38:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625122; cv=none;
        d=google.com; s=arc-20240605;
        b=jImImjK8PabkReeh8I0ReEksH6kS1p1k/MDsIUvwG8wEalqt3N/am3vcIl2hC7FWjN
         IQywkzzFXL1nz3gaEbX/aHlarTLYYIQLegcvUBOV6sq9Uamtin7eo68cvNcuFIPWuWFd
         ycvTF6tPPD3/98xsA2nVdV3+BnEbgKzAsVu2uYa+4qwuYy46HoUEB7DlCXt9kxgKo4wn
         QU50m1HA0jaksWwXmIOtz4dO3DWEgcRl9jjY/LuDXH0psyv6ydigrGuKxAHkE42hIsSB
         U8IqUBbG1bCs2t2OiVTq3mhoSz8887qECPKT4X8kPDBerP4C6ZOY06pjL31JiVmcg2l/
         cj9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Py7VOBxcd4HwAc7HHDB+PTMRXMSLHO8b88vcAnVEU6A=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=TCbXt+TkFgEyPqXR3+Jr7w+P3TC2Rtifo8HodrTa+Jwt8uxvPgjZT6S2ZxVtN+/FDw
         z/k+Is2TWmz+V/pjgbIxkX8EjYENnQ3rAvD86mZ5AHu116BlcL5h83Y1HUo2SUN5t1Xr
         Pp+g+hx1mEsEMBIExE444UDeN1oF9UkW+ijbsWvJLg09zgXs/Zcx/OVQiqeNR4zzUQ1g
         zaWSWK2BoODAsKd1zMQDpvgMjNql6VANOTE/c7nerOg6cWiRpbtAF4CURp6yHNYw9GPj
         3AvUSsl7uFN526KBeBxzkqoSb4OZ3dZhXN8B8CES+4Pxbq8Skdlnnglh02rSmIEyC2Dw
         EDOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mqPmNYet;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8843fa20544si32120439f.3.2025.08.19.10.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D42D360209;
	Tue, 19 Aug 2025 17:38:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 55B1EC4CEF4;
	Tue, 19 Aug 2025 17:38:28 +0000 (UTC)
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
Subject: [PATCH v4 10/16] xen: swiotlb: Open code map_resource callback
Date: Tue, 19 Aug 2025 20:36:54 +0300
Message-ID: <babeeb62fcfbafa39f352da1040a5dfa9d2a2719.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mqPmNYet;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/babeeb62fcfbafa39f352da1040a5dfa9d2a2719.1755624249.git.leon%40kernel.org.
