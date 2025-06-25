Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBWPO57BAMGQE7QRJ7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 68E0EAE843E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:25 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-40668fc07d6sf1185687b6e.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857561; cv=pass;
        d=google.com; s=arc-20240605;
        b=f8FHAsnNqiBbJtsXbb/DXzXyS313NOTC1bHZOiLL98AyCPBBjf9Eg22qyafo1MDEnl
         iuXHtdhZX30XLTID5hVq7MaRMQwvdpmhtM58Vn3UK81gG/lJaRDMDPImmDlNBQty5Phh
         aAcuyvewI32iVwDuSNfXtMHDChp8xB3yejcVA/XxgF2tSd86SNHSo55l1heGGyewSRwa
         O6LJpNYq4RKA/nCLtE1u+1fRh/Y6A3PxGAIGCraz/Wtvjn9zEc5ELLIzdw2PUK7k/uLe
         leVMM1mx64c32b4ALgFwhCwxoJffJcBetKL47GRKfo2zWFcBE/uZXUcU22oZbIbCZeuV
         JIqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=QgfLt8Yk9zJiPq9DK0onhLjht7S9gFrJf9ZGKA7kWyU=;
        fh=VnNZDHRdAW23twMeu/ZtrsH0Bx74F/rzZzaIUZFF9BY=;
        b=VguQG1+r5uW+nziF5ofAX/OcCywkvVoJ/ALaQm0WX16iSI8gdZT8ExEm7s575F2jhG
         h+I8Ki3noob6BedWq1oVdTrDpvB5G2gyybF6by/SIaC0Ptjpw9pZudPB+AdlENNzBae8
         thae5OngMSw90kzUVU/Nq6TRjwZNdSFp5sFsDleSQYkj9pdoq01A6sGdsYuzWEg8cL4y
         g0jmsbWFPd4B8Y4783BN6dJwE6o/Um81HLxoON9VbaT5Ix3nk9NchXzvVFVxs6SPdC7h
         9MTTFYaZ7XqmEnZDfn4AKeyzc5zJ7l4wjt5c4FQLgCHSuckRQxEgwCr/CpXvGrTV+Qhh
         kwAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=achChjnk;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857561; x=1751462361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QgfLt8Yk9zJiPq9DK0onhLjht7S9gFrJf9ZGKA7kWyU=;
        b=m1mgJ7RSvIvay7hEi+TVV9mvE+ka3BT4K8iiUH0ciNyOOHLQ8/2ppyNwi9Ekm0dVOe
         wOLL3yjmoZ4+ZiltWgs4tWTKyG8PWWE/l3nV1XFHv+OHedosx91fRZUB90Z86pbl9gK0
         vtQkhMWeKCYFnmy3aJKPd6xV/gtyPqi15bSY1UMz0meu043ghYTzE2oIX76NKHOEBK40
         wxd43RsBWvdtWWW96gWs5CfZdcBlJY3ddexDUp+PdHVIY3L5bo7cabunUinTpW+HzM67
         V5M3RHOBrQg8SqFmA9gcJJ6diYzDCI9/YSxTTRdw2ACXSx4FM03YT1Rsb3ji8V1cVLW6
         lzyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857561; x=1751462361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QgfLt8Yk9zJiPq9DK0onhLjht7S9gFrJf9ZGKA7kWyU=;
        b=PBAFvmnF+rBvDf3GiOF6ibxIWhK1HJlpAIIP1pjmbmmhiAvpOr0x5tcmTaq0n0HRtg
         auxKf7Eho4r8rJ/ycYE9LP9pdfd4lIKtKSlpVx5PwW5wAtxTOSO+FE0n0ySB4q5Q+TD8
         ZJPEV+q+dfWbj0loFW8JBq4yiLHQxsieZ60Jq0teLn/dYSYYGl8w3k1C4BPqnQPEvE+K
         itTxuAqG7/Db1NruAcNE2VThn0oPxrTNyXxOENSVaBBYdfZk59YLuMvqtAu993WxpcY7
         Am3wEzPMMkcorlKycfn+dcrObpszUDD69AusxXCWuSYku3p6KnVOV9siURklIhRYflas
         eMGA==
X-Forwarded-Encrypted: i=2; AJvYcCWUQXVA+Io61X2qXyLTS+NJ1DVKMHHCr2njGjpEy/TetYz0R+j8Nxl+PcGaC7A+JHpWGQ5bAQ==@lfdr.de
X-Gm-Message-State: AOJu0YyekQpJA8kFsL1dBz5mIsBw0t45h01MikpHx0pUWYIsKNNIJAIM
	0sxsxVj0tgKkzNAgr2IOiclUKdFTMTTMBRwWAoj5ctUaIPtEwJN5lJpX
X-Google-Smtp-Source: AGHT+IGmVorHh0sddinroaVgS05FZfXsTPfdIRDXHtJDSDJ0vCy0++7wEdA2cNjrNf6WmeKZVWdA3g==
X-Received: by 2002:a05:6808:f0e:b0:406:780c:20ab with SMTP id 5614622812f47-40b061e0717mr2253701b6e.6.1750857561394;
        Wed, 25 Jun 2025 06:19:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZft7X67G/F2UbSR+2ryC6FD9VjNTCo7d3oZMShpyNC/NA==
Received: by 2002:a05:6820:4cc3:b0:610:e15b:d696 with SMTP id
 006d021491bc7-6115a7d9140ls2004396eaf.2.-pod-prod-01-us; Wed, 25 Jun 2025
 06:19:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW23M/pLHyoSkKQdpJmys49QennXWX7BPkj4GoFmjaqN3gwmEsU4CtAAboFR0dOt55qzOgojXofqK0=@googlegroups.com
X-Received: by 2002:a05:6808:23c9:b0:406:697f:a62f with SMTP id 5614622812f47-40b0621b7aemr2414707b6e.10.1750857560135;
        Wed, 25 Jun 2025 06:19:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857560; cv=none;
        d=google.com; s=arc-20240605;
        b=EL3KAKbrbytTtO+MNa1DyFJLtkvyiKcbzYlEMeD5lbHX/IXWxg1b5UqZbgNBx2hfd6
         KumNO55PNF+o5+YIELJ6OureGEbfTF9pBqS0KOqu25nNlPN9hxAGFG1eN7G5D7iOIteX
         B4yOhZ3L+puZVZE1rVTFsz3cx+suNavjGYHVnEqmRC/7CXjBlHlCc7LXzy2bCzB3WRUO
         JWaISmH8RS+CMe5hEM56FDgPg/R57JKvE7FlCTU+c+8lw7ReD3Fq+3PSzPVbnaPwI3PU
         tINIbQTJ+L1x5jdBxWJmEEqgieUHjmiRoOZIsa2Dw9K3eKgVniFoJJAn4nb9GBpqbWgj
         2xKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uWE1UOJwglTZP/FXzp20pYnVPWPoHQDtKL7cc7Im+Lw=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=aagLyYM65H0OHBAIxodtgZigy8na/OiAyYmBEnBRLil94i/wffXwjBgCcyNwXjpF7o
         UM4R/10iBdR00ctnSND5nTN9njEWaiM7kHPQg1+6+2FAoI4JKaR0086KniVK/HijOSdJ
         ClQu0cC8J+Pg0qvnWGlBjJlFaZSkwNr6Ggd89g1mbgFZn9dBVS0pzVV7UNMTgx4OAzt7
         xUP7kT3i4AxVejaD/wqlhw2G6hUrSH4qGTfKExfQThb/F7irTfCkm7WGY7KzOvCsx3QC
         X9JI66mb3TArLJsQQcQUtaDm0BkE2XxrjPzEJiQ6f95qz2xzJquqBkdXKYUSk8MLRXpk
         5h3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=achChjnk;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40ac6cfe1e8si671690b6e.3.2025.06.25.06.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4AB7C5C59D5;
	Wed, 25 Jun 2025 13:17:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BC7D6C4CEEA;
	Wed, 25 Jun 2025 13:19:18 +0000 (UTC)
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
Subject: [PATCH 2/8] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Wed, 25 Jun 2025 16:18:59 +0300
Message-ID: <23ef1117e09e3ca8c51ef2700e902f340856b8b0.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=achChjnk;       spf=pass
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

As a preparation for following map_page -> map_phys API conversion,
let's rename trace_dma_*map_page() to be trace_dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 include/trace/events/dma.h | 4 ++--
 kernel/dma/mapping.c       | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index d8ddc27b6a7c..c77d478b6deb 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -71,7 +71,7 @@ DEFINE_EVENT(dma_map, name, \
 		 size_t size, enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
-DEFINE_MAP_EVENT(dma_map_page);
+DEFINE_MAP_EVENT(dma_map_phys);
 DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
@@ -109,7 +109,7 @@ DEFINE_EVENT(dma_unmap, name, \
 		 enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
-DEFINE_UNMAP_EVENT(dma_unmap_page);
+DEFINE_UNMAP_EVENT(dma_unmap_phys);
 DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 4c1dfbabb8ae..fe1f0da6dc50 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -173,7 +173,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
-	trace_dma_map_page(dev, phys, addr, size, dir, attrs);
+	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
 	return addr;
@@ -193,7 +193,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
-	trace_dma_unmap_page(dev, addr, size, dir, attrs);
+	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
 EXPORT_SYMBOL(dma_unmap_page_attrs);
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/23ef1117e09e3ca8c51ef2700e902f340856b8b0.1750854543.git.leon%40kernel.org.
