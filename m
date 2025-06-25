Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3HO57BAMGQESZI77IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC985AE8447
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:44 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4a43c1e1e6bsf30778291cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857580; cv=pass;
        d=google.com; s=arc-20240605;
        b=ARlZZj8gc7BC5JaCZBtoHSYgQYJlqKaJKXKChC5wbsgl/B3LMAhvgYlWnnOEBwn7Qj
         pJzCVP98VZz8KPtbv1aZ4nqC8nO2PMXF9acg8N9KU95LDTsbj2L9Ag+isBjQ5ThRoeOt
         d/Qmdt/McQWKhuUv7Gap400Eh9Vxka6VmC6hbD590paE+HZ6kiFZWmo1F+s21cBqMTsc
         kjWl3iN9g6oSqxtO3+6Th6zlx27FSPNcbMBe6prXHzXqyhSlmg7IQVfPYeeU5XR1F9mT
         picaST/VjqYkpvrbOB1IOgSF0vAgJxVMoEH1VlvMhd0b5ramtIOb7bep76WrKe2BRZxT
         qCAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bFyczstP8BvdvxynWDOY7JspSb2reTENlguEYMWydJs=;
        fh=DLmNLtxyefSwFdYR2Z7XeCh0N2dQtvsjRqGs9Eopt8M=;
        b=WOB65FSg1kYS05s9gBAhkfGbaeh+/QdDS2HO2rW7Hg05mNkKIBnhFkgC5VfwIkqi7z
         CsEsaI/9J+SR8BsUY6W4nqXXfWi7kQsClSk5zxs7LMDTAfulTOB8Z7DCO5yD+TghenKu
         elRMSA/YlFTK+VzOG6E2w5pN3FVbOAAgrkVTOT1mgEPZGmvL/cHQ2rK5gDXZVcDKqU7/
         nCDkAaKhgOs6G+U0sqxrfE2PXu09ocYPlhAcgoSk7yaEIxnftI3gWAVEe6J00fGCvYXo
         jpu5jZ8TIhpjG+o3HJl1tmkbs/eKllKRUmSxUaV2L5jyA8s8AfMLBY9fjjQ3SMZSI/F8
         B64Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JmvSEIY+;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857580; x=1751462380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bFyczstP8BvdvxynWDOY7JspSb2reTENlguEYMWydJs=;
        b=IagDA5BeBCn+nNwvWvg27gfMkHHrq+UJyj3K5U/wftmpF3zsiif6pm0tdsvWfDo6XD
         3Lh1izBb2sqzRFOIxchAvlnSseOb4Qut9H5G0Sgh9eVy2ziE1OvM21kUdrwoaaGZHdw2
         xIvHJhCZmaW0PFZ+5joAe8gRMNuyfaq8peb9w5+SwJc3KBGYdN6DAiJV2D8G9MLUUbyd
         dFXfSlB/BMxxweSeF4kT3tvBj9fT6NfAX9bf3u1twC7C7j1iFHnimAiMqY6Hmus4x16+
         i6Ls9SxavcjSG0oLwVZ+u8NXBI1MfAxM68mZp8tehqVQTkIamfyN2ZGzMrLgDBo8iPm2
         k80w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857580; x=1751462380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bFyczstP8BvdvxynWDOY7JspSb2reTENlguEYMWydJs=;
        b=IFs0HBcylSKbdLPN68q0qfpewyYqrXkMVUU3a0NiC+eKGOHyzgA0NcZFTyJGZRyH+F
         2EhdKFp72RpwSsRRzqpHJfNt+hVL3VljWmjPsvuvOiLNiLGbXTkVKwbcESrdFWfgqSmt
         zTp/HO89kBdFpIO5UTS1tOcYQuqPhjh1HDFtO810niW9gDQdUfZdaNS6AfQPKtD2obL2
         GO/OGuRRyvspPL+ytnGGAe811t/tBN7MqqMLkjnqQL0sZr93SltgiF92a54ngk0JLK0S
         vwwR3OQNxpNF4IKNH0g7GwT2TXxYK2pWidlTbzvb3e6vF61AxuKduwpyVNV5V7qi8kaX
         yC0A==
X-Forwarded-Encrypted: i=2; AJvYcCVkLx5asCrOoj8TJ009NzqkixLMxGFbDezvUodSl6VJTOLDcZTdIQ8IYhsWdJu87xS9HlZZAA==@lfdr.de
X-Gm-Message-State: AOJu0YwYnkDAp59u8jF86X0RoH154QsMNu1ycCRlL1fUyczVQaZulvC9
	tJQdNLq6gRm86kuLhwo3sOdRUJAyoDVwe/nlp8GfAv64SWMnwFxFS4uh
X-Google-Smtp-Source: AGHT+IFlsaDgV88Q2SmuWQ3GmeyvqVgpNa05T/m0seFG4VgMPhUYQ7Vo5hz/2apYwOBGSmtSAQxxEA==
X-Received: by 2002:ac8:5a43:0:b0:4a4:2c75:aa5a with SMTP id d75a77b69052e-4a7c07ca810mr50099361cf.30.1750857580264;
        Wed, 25 Jun 2025 06:19:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgYFDAgx2PerqdwuDy104pTCgHtoVrXzDsvaF6Lh93Dw==
Received: by 2002:a05:622a:1887:b0:4a5:a87e:51c1 with SMTP id
 d75a77b69052e-4a771d71474ls100207311cf.1.-pod-prod-03-us; Wed, 25 Jun 2025
 06:19:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMXLCK6uG9b88YPINaBG0clIO5OBx7CsDTEFagZGYHpbqtQn+oJTFIPzKxaE4HElLg3GK25dXugiU=@googlegroups.com
X-Received: by 2002:a05:620a:7003:b0:7d1:2b01:896d with SMTP id af79cd13be357-7d4296d6947mr392584285a.24.1750857579121;
        Wed, 25 Jun 2025 06:19:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857579; cv=none;
        d=google.com; s=arc-20240605;
        b=XxB2Fru1+Hixwc5p9mNn0ReADCNB6S6W72Qz3QkWJzw5b+dhwCisXN/9Bgr3HPSlDC
         hWm3YHTjKz2Rci/daFxrlntL9Pf1Bcj0mcuKrZgJBnzQMUMxmvM2GPss+vR1MryENani
         s+ySYz8r55XmK1OIT6ZAovqGb5isbESVr0YxApTau0pYVnRwvLSsdy7auOF0vlkCWbdR
         SAxJGHvoy1xbZmB/b3s7ESJmfswDbY6CRG4ClMaYXjMatFvaI74Ddf1C6EM29ZmS3q+H
         4X4s/2hiES5QGwiUfsTZSu6rCZ2tTO5juB4ofphuiZj4lLrDqfcBn0ynipEwHLqo+FNs
         NX6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yT6++2TGmOpIUKHGdyhEudX+l9ewF2H6ydYa1C4h+jI=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=exOLqdkuDO5rbT4oZ6bBZWGGapbGbguYK/0iJoxEeff4cgIAsv/VC9qSpaqjByKSPH
         HP/swxiM+cVHvC/zbzja6kvnoI1TrqE3D/saI281nbrY9kxQWFG0Fnb40XDvMvTl/9OL
         GDLX5YhczyobrmmWugT9Vs9azhk4qetHIlZYUO/YEcp/issNRFJsrjD/mUxGii1+wO9C
         iGJiE9miLeWmM51JJdTqeBUqm41vDthANVzxE9DjABesLd79hH/zsV5KyPPEy/+5MpLW
         6kVO2U5r8Nz4MLmLC+5DdSVqBKOhN/KJO0rwBLBiMqocAjJEi3CDbUx4ANPxzmvz61eI
         k4jA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JmvSEIY+;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d3f9a2aa08si16100885a.6.2025.06.25.06.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id BB698A5261A;
	Wed, 25 Jun 2025 13:19:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C193CC4CEEA;
	Wed, 25 Jun 2025 13:19:37 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev,
	virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 6/8] dma-mapping: fail early if physical address is mapped through platform callback
Date: Wed, 25 Jun 2025 16:19:03 +0300
Message-ID: <5fc1f0ca52a85834b3e978c5d6a3171d7dd3c194.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JmvSEIY+;       spf=pass
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

All platforms which implement map_page interface don't support physical
addresses without real struct page. Add condition to check it.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 709405d46b2b..74efb6909103 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 	phys_addr_t phys = page_to_phys(page) + offset;
+	bool is_pfn_valid = true;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -170,8 +171,20 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
-	else
+	else {
+		if (IS_ENABLED(CONFIG_DMA_API_DEBUG))
+			is_pfn_valid = pfn_valid(PHYS_PFN(phys));
+
+		if (unlikely(!is_pfn_valid))
+			return DMA_MAPPING_ERROR;
+
+		/*
+		 * All platforms which implement .map_page() don't support
+		 * non-struct page backed addresses.
+		 */
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	}
+
 	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5fc1f0ca52a85834b3e978c5d6a3171d7dd3c194.1750854543.git.leon%40kernel.org.
