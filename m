Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6PO57BAMGQE4XR6Q7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DAACAE844D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:57 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b3184712fd8sf5164864a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857593; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bu4wEx0rrqbBY2yMh1XDCE+G+ulOEYxwYawljJeTzepFZTcpqUiEK0sre8ijVHihaX
         Wh3BfVqqyKPPLEeeRPU4F4ZImtBa8YbkCJ2MEjnR9PRcVNnmtoX7uU+4D9/6/w3hbA2X
         10gwYGZlgCmGgGAIXQY7v10VGRpnTsOFX9J9uIDA+y3xIC5ob0vGMxygQ61z6Z8867lG
         CRJtInSoigK4YOg0OYo7B7aTXCpTJgmfa0hHqJDJmBDGJiVidiluJVzUHQxQuH2I1nhh
         iFFhVKecb5Ct6dW2cyBuYCfd1i35LHMCRNmSc6N2fNkMPq0g0KPezWJCJ2bSx1FgMrqI
         eAxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=SRDwSEMnPQkpIsv7sXUcx5I90yzyUeD8TS2/Nin6Ar0=;
        fh=WJuZP0rrmqLbsBfuM9/xYkjOpQ6+oHejuXZn/dOYCI4=;
        b=ig7p/bAo6VDtDgwHT/IRneUVCSG3RNDP+Tlv3MTH1wO098x1I2jQBbQkjmKArH/WPB
         D/cJxzZ/T5f04oLhuJC9FhVqPyhEU6igI3vAiit1I3QEt3S9DxshqB8Z9eT0Ak0fqi1N
         H4UXQnwmKgE1k5C/c5vclWB+NwvMNocmdWmaQa02MB4dTa25kA8vDNiqHYeqPGuuD02B
         s2MPZDQC99CEzDHDRqMiFa5DnO9yUElcP8GPx1anScGYW9gqApyBq5U/wQdtqgupUUjJ
         kMHcdlj0BW1fyQK58MxuNKxKJMzYXq9UAg3H5xJA3g6gpsscI1TMjwheyzMC5ihcODSd
         Jr4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GO7zj8pT;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857593; x=1751462393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SRDwSEMnPQkpIsv7sXUcx5I90yzyUeD8TS2/Nin6Ar0=;
        b=WU0AzauGjA4WksDMLiqQXymPPFkqVn3J/kex/Xhg28k+HpjeCXRoMxkpGQZhDGsF/1
         cR39XoL3i3/WdrL73iXYf8Waq6N79vCvCeOUsfkjQj0DOUYCkkR0X8zOkdFuIhel0rWz
         5wzidF58fNFnMDLpTs2RFFnP659XuG75TwoZTk3hutiI2xlvZCBHa2EnzBTDTWoLIZhN
         KwlSobHqul/Yg9dflRqjjeWXk9H69Sq3kFcL5No0Dq/gpGOyFLaCr1gVJQXJuWN+2Bl3
         Uc0PVTI+8pa4LPm1LncVpVjtKC05sMyzRJNaKaY30w604Vu3cxhuVfNE0tlXefyJ0Jpc
         o+6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857593; x=1751462393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SRDwSEMnPQkpIsv7sXUcx5I90yzyUeD8TS2/Nin6Ar0=;
        b=qCQOo+Ehghc2aPD4zzw2XRNp+1UFXeXxd1Hl1g3y+hMYrwc9YoM46VnGJkNV4cRKoj
         4KV342WXMcb1uElugrcH3U93mmW9wlabmtVJ3eWCFNcY3FaAgc/N375F9M5ZnXPeze1S
         Wa89yztVupaR1Ol9wGtktWCuSyeIWNtGzEhpJi0klkpgtEPIOnWf0C1CWBQWKuFw8Wgc
         2ZNGtC6VGwOZISu5Ey7cpbkdo7Nw6LaJlyDcFUYfooUz3eeVeCIdAWUOW2kcuCwoydQ8
         yTPBueWU5CbZ7266L06zqfnPNoUPdhBPGc21grk9jYjBEosi94HSj74DMxshHwl1PLqk
         0OcQ==
X-Forwarded-Encrypted: i=2; AJvYcCXfnnA9kY44zRlXIvwFdcBEnuW1MUABgUmEDvg0Vxvj8ZzzMea8L5wSahDW4M6N+cwGw/NGwg==@lfdr.de
X-Gm-Message-State: AOJu0Ywtl+Dbz5pCRbM/yqmL0p4mCIOYtNuD6jDHZOQxd7KWIvoCNX/u
	8S/LNL04cBHc6GXgnpHtsaoMsmOTLUyGdZ80vYrDNfifbnUHhjnhawSL
X-Google-Smtp-Source: AGHT+IEi9ShwgJ7HabV3fGwj7+Dyqx5L8d3ngZ2HSKoYsVLB1fj/2E1tQm3s6T13Gg9n39V1GJZ4lw==
X-Received: by 2002:a05:6a21:648b:b0:1f5:7280:1cf2 with SMTP id adf61e73a8af0-2207f1d1009mr4575529637.12.1750857593347;
        Wed, 25 Jun 2025 06:19:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZ/Gl8twbBWdHUvfosA5mMArmYNJOU9UbRN89Fy1VxYA==
Received: by 2002:a05:6a00:84a:b0:742:c6df:df1d with SMTP id
 d2e1a72fcca58-748f96c6336ls7765598b3a.2.-pod-prod-05-us; Wed, 25 Jun 2025
 06:19:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxi3gR0PoTOWYnqsSfF+anvjPxYoO96ynZhcNSN7oNHR7OJpimBqMn4g9549ODgqbwNJHDpOqliIQ=@googlegroups.com
X-Received: by 2002:a05:6a00:3e26:b0:748:68dd:ecc8 with SMTP id d2e1a72fcca58-74ad45d4a72mr4665172b3a.22.1750857591859;
        Wed, 25 Jun 2025 06:19:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857591; cv=none;
        d=google.com; s=arc-20240605;
        b=aGpDrneR0WGZubZ88IFwOMzVwGuc1o2QpqlfuiBkOdRp5KHXgWL3YUm74IdAX5Yy5N
         eAwWeP/ogtwebYUj5veCT8Fd+sD21U3RzOBTWm5j3tuHIlPlwugksozY9HjeC6C5ymLc
         3/tB921xm0r9UmcOZ2FdALMjUDdd6cMP1o8CVoPBhP16fPKlVaRKS2GVLoYuL+4ZB6hM
         MLctP50ibLBs4pDHapIDBSqDfjuNcROhtPLkPNSqGFBYcv+JXPZ+1NPwdhrcd06aTU4S
         AyE0IVRGthgSgdeeR1txcxF+tdtudZSqrLd0TMRt+UT380G4RUwWnOA+9ZL+CUOBlcD9
         XsqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EgXAwE7Srq56G8hBoHMWeT/tSpntvUV5q0QgOFWJ/dI=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=XuCviXkzpENxPNBrrB0Ucct6UOx4p2lul0GrsdOEjy+ISsikFJR3wQIvv/63dfrvAz
         ca1Ysdq03JXPff+hrxlDysecLUYd8BSVjlDk4W9H/rgGmtEDanav6NJGNXJFHTwfRqrt
         3QzUe7EHhNuetJ+I9o1UxSbxS8HwfWtNpLdIGJUYzLJcPz4HLqhadRvIeX9Lfh523mAD
         e3/ZWyo09KanDzxBEMc+pcsLqO2GrfzKhm+IOUz2gPSq0mTqGETtPyb8bk49+Rmpqkm6
         67S9pWBn/lTFgKyAADM0oLUuiYUJrmBmRLKECXhO6XqzqPB5BJkeRqSGs102Lekx+wvw
         Rz5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GO7zj8pT;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-749c8816ff0si176852b3a.5.2025.06.25.06.19.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1BCF561785;
	Wed, 25 Jun 2025 13:19:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28477C4CEEA;
	Wed, 25 Jun 2025 13:19:50 +0000 (UTC)
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
Subject: [PATCH 8/8] mm/hmm: migrate to physical address-based DMA mapping API
Date: Wed, 25 Jun 2025 16:19:05 +0300
Message-ID: <8a85f4450905fcb6b17d146cc86c11410d522de4.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GO7zj8pT;       spf=pass
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

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/hmm.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/hmm.c b/mm/hmm.c
index feac86196a65..9354fae3ae06 100644
--- a/mm/hmm.c
+++ b/mm/hmm.c
@@ -779,8 +779,8 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
 		if (WARN_ON_ONCE(dma_need_unmap(dev) && !dma_addrs))
 			goto error;
 
-		dma_addr = dma_map_page(dev, page, 0, map->dma_entry_size,
-					DMA_BIDIRECTIONAL);
+		dma_addr = dma_map_phys(dev, paddr, map->dma_entry_size,
+					DMA_BIDIRECTIONAL, 0);
 		if (dma_mapping_error(dev, dma_addr))
 			goto error;
 
@@ -823,8 +823,8 @@ bool hmm_dma_unmap_pfn(struct device *dev, struct hmm_dma_map *map, size_t idx)
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8a85f4450905fcb6b17d146cc86c11410d522de4.1750854543.git.leon%40kernel.org.
