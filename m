Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBL6XQDDAMGQETZIIESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id ED53FB4FCEF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:29:22 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70de52d2870sf38441506d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:29:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424562; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZOdlxS01S8LFRoV/DW/3aZHidrMwrtB2Ch8bX5Z555lbz8dnO/wIgrbFGRBKfXwDni
         TqSByFeSZwLpyOocx+T+1U23qm2OZ+ptQXw/uQqS2GkC+AuGz8SqaeAE6F/yZ2PnwN39
         /9AWbv2ulnQRpGT7AMAsnd0UKz9WtONphV1mdBBSXvSI2O6CAmm2DcXixa2nfoVNddVc
         eLlunhR/pZIb9ltI2AKHoit9+FXJMwrIz/HcH0rQ/6zVkOZ735NQPw/Z0DzM0SCv205O
         MGDBUijEXDNhSv/L7UkLBE8suJdQam8hbRSH0c2g85Pczc+A0YlAKSnm1Hbaznb1lZz8
         eByQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0aX7R/Qh/kFdMA29suACTai3coTF/ZtwXyxAXQ7Wsv0=;
        fh=Tr+EVs7SlwwV5uHpfHyshCsW87M8f3y4Lhdzvo9NFjA=;
        b=UifEGPaLdIt5sWkbLkbPhYJ6+pSqg7IusYkgbqXfxyLWKqYvepvjzdCRRzxb5fc96D
         NUSgpgCHCc3fbxJmYtciIwM/H+hPfeCSRkbigxBTV2c3P1x9fj+JEq88YDkF5yEM4G8+
         KERHpzeEYUmqbUBJ8rIm+cFVg4cg1piq89xbZrrL5JJgj1b0d4h81ywx6+18FHVNUAwy
         BttNOf82qwpCVi0JMMEnn+zkrtP5E60pENYqmx6fHACE/HcEQKKh21S9vUlPhatPBq64
         Zz0a+oFpgwjfStSogF0nN4PE1IvPRII6Yct19A7WMbj/msU7+NzUcOHxC825QDluiGja
         RfHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RO8Swnvn;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424562; x=1758029362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0aX7R/Qh/kFdMA29suACTai3coTF/ZtwXyxAXQ7Wsv0=;
        b=XU28LVwNYZ6Jg8GXGt0UcnOBwGsIARQtR4QttjEYJsvYxfp1CnPXAmu6QS8KHydiN0
         Q0ZsWSKMaUmWMPbN3HBb8o+7s8yLQHQVruuSVcAvGCEN31ZvCYS++Bpj3MV3aGSOzVN3
         BuDXNYa8SAFpl/odVFueKSGP3/uELlpEKi9bZAegWSS1mQ/xSQ35WB8WU48lRv2mbIqs
         NveMcmhCP0rF3PKzZhVa9FfiVakovUROAt7kujmqBQOmrdoZrRs/O6O+Vod8H02hY5pK
         mLy4Di3DlO/Pik9ULgWBlrnGFR2SLD4vMcM6HWzP9sNV5iGuEO5iRPGLijfeRt8qF0Hq
         ja4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424562; x=1758029362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0aX7R/Qh/kFdMA29suACTai3coTF/ZtwXyxAXQ7Wsv0=;
        b=LwY2v/7IJ0AxnBpNziNbiFu7GcoF5LaDXgLtW9rneyyGjrSbkb8SdO+6WeOnL0uB86
         g2WB+WhMLvxIA8aR88lne0QD0DiuKmcNQEuhXPm6f2IoAmI5R3yVRttrLnxcZyTZKREe
         c8XusxhfxvZhwdvo4JD6ZONvhCbW/7ZScj1QqsOAP9mCX93HdEQInrFBdIy7CMCEA8tF
         heufKXTBWZ+5CT2FVrPFf/p3jr53sGbVT44vZxYjLnsznkS8j/Ur5cvHA3aJNUWKfnM7
         bBGYj3m1wEQpUasjOCxOEZGf70d7Ny7D2zsbmiUXrlTMi0Wd8YEBQAzZ6rMle/mkZwIN
         3jTg==
X-Forwarded-Encrypted: i=2; AJvYcCWys2ZSmrbX2+2xEGi1nhzxrbf5q9Ox7iLNmOUjAcYB53wk9C9dma3E+jzIlYMxPeR2p2DceQ==@lfdr.de
X-Gm-Message-State: AOJu0YygyNIwOQUvLVkIyp1CEwmU/NngBNzQXfNcetvjfzGFPsGUHMu2
	WaMUYSe0yPYd5rBZ+JJ+1htpl2CzeFVBKzWMN6aDT52N9NspblIbnuQ5
X-Google-Smtp-Source: AGHT+IFJLu+JZuO+R0HyF1LEVhXfWmyz1k9aPjfNpXEG65pq0GxrjF9eM8n70rOVCk3hXMQFcKViYQ==
X-Received: by 2002:ad4:5f4e:0:b0:70d:fcaf:e76d with SMTP id 6a1803df08f44-73940035b50mr148730806d6.31.1757424560222;
        Tue, 09 Sep 2025 06:29:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd48cb7Cf6CrudUc0Yb9ah4WYAh4ER7JVrn5/mRyufdH6w==
Received: by 2002:a05:6214:ac8:b0:70d:9340:3384 with SMTP id
 6a1803df08f44-72d3c1289bals62974966d6.2.-pod-prod-08-us; Tue, 09 Sep 2025
 06:29:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYR3ccjL4McRBbs3KmjzILOG11V6+IcoqVJlQVqfXyQnmIjea/1XWD2WSpWxoY6ktdPE3n7nGPLW8=@googlegroups.com
X-Received: by 2002:a05:6214:90c:b0:73c:dbed:d2ac with SMTP id 6a1803df08f44-73cdbeddac4mr65528266d6.20.1757424558532;
        Tue, 09 Sep 2025 06:29:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424558; cv=none;
        d=google.com; s=arc-20240605;
        b=O6fZnUrIF5MxXQpjhqmSbN8Yb3Aqi90pe81gvAktnlsOeLLIQ8+nT078X2rN8/+JEh
         tRyyZog1/Xrz0X5yb2v2tXyyADWFqU/PnnzpPHxn7kCgj7sGwmOABKOtA/4yA/PC8u18
         2Ek0s6YQ0jdLbLiK3QtRKPEqKTj3QY8bzIGGuNorPMYK974O+lGJc/GhYIYVBcN2q6tl
         NxrUeBOLtP6Klm7eqiqVgXBJHovipvZatPynGgvGOMp5JnUFxIJO2A8ZfSHkaGIRKYXQ
         OJaQ6oH8gpbG1oMj8ZeO/n9WJEZTLGRSH3XGFuY6taqYfr2QX0k5L8MLiGWavrfhKxMa
         /ezQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6jO1Pi8Tcbmgxlie5tqgLJ/N340a3rHV4szArIgb964=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=UM0PZ7rn7v/a03zjdUVN098NE69y5KzrrSDkqWO4yRnzTkc1W46HRyNkFE7oPPtpxl
         3Wr5gtF5PMsLE3ezMPTYopPprlqZ8jLDH7MYjvn38P4tcoiVN+tR92LhzCarjJ8FqzDA
         S7K/iIso/fvOkPirckMwKf6dsoMEXvlv1rakn5dBeVcyaT4MSLVh5T9mRDneUwUR9WCI
         Hy0TefzREUfaEVRpR6UrxpWKhgJ9Rmj7jfhKbnqHByaVUE/qqx5H94y5T7VlmlDLyY9o
         mtucsONoO9uz4ztJOs/G25f3lRVZp9cFB1PYDb0Yur8+plC+JAWnSycqP/GHV7FDl3Wz
         pfjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RO8Swnvn;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b14464absi8866556d6.4.2025.09.09.06.29.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:29:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C05D3419CF;
	Tue,  9 Sep 2025 13:29:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1F67C4CEF5;
	Tue,  9 Sep 2025 13:29:16 +0000 (UTC)
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
Subject: [PATCH v6 12/16] mm/hmm: migrate to physical address-based DMA mapping API
Date: Tue,  9 Sep 2025 16:27:40 +0300
Message-ID: <d45207f195b8f77d23cc2d571c83197328a86b04.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RO8Swnvn;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

Convert HMM DMA operations from the legacy page-based API to the new
physical address-based dma_map_phys() and dma_unmap_phys() functions.
This demonstrates the preferred approach for new code that should use
physical addresses directly rather than page+offset parameters.

The change replaces dma_map_page() and dma_unmap_page() calls with
dma_map_phys() and dma_unmap_phys() respectively, using the physical
address that was already available in the code. This eliminates the
redundant page-to-physical address conversion and aligns with the
DMA subsystem's move toward physical address-centric interfaces.

This serves as an example of how new code should be written to leverage
the more efficient physical address API, which provides cleaner interfaces
for drivers that already have access to physical addresses.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index d545e24949949..015ab243f0813 100644
--- a/mm/hmm.c
+++ b/mm/hmm.c
@@ -775,8 +775,8 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
 		if (WARN_ON_ONCE(dma_need_unmap(dev) && !dma_addrs))
 			goto error;
 
-		dma_addr = dma_map_page(dev, page, 0, map->dma_entry_size,
-					DMA_BIDIRECTIONAL);
+		dma_addr = dma_map_phys(dev, paddr, map->dma_entry_size,
+					DMA_BIDIRECTIONAL, 0);
 		if (dma_mapping_error(dev, dma_addr))
 			goto error;
 
@@ -819,8 +819,8 @@ bool hmm_dma_unmap_pfn(struct device *dev, struct hmm_dma_map *map, size_t idx)
 		dma_iova_unlink(dev, state, idx * map->dma_entry_size,
 				map->dma_entry_size, DMA_BIDIRECTIONAL, attrs);
 	} else if (dma_need_unmap(dev))
-		dma_unmap_page(dev, dma_addrs[idx], map->dma_entry_size,
-			       DMA_BIDIRECTIONAL);
+		dma_unmap_phys(dev, dma_addrs[idx], map->dma_entry_size,
+			       DMA_BIDIRECTIONAL, 0);
 
 	pfns[idx] &=
 		~(HMM_PFN_DMA_MAPPED | HMM_PFN_P2PDMA | HMM_PFN_P2PDMA_BUS);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d45207f195b8f77d23cc2d571c83197328a86b04.1757423202.git.leonro%40nvidia.com.
