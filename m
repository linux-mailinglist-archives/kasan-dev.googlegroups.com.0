Return-Path: <kasan-dev+bncBC7OD3FKWUERBGG6X6RAMGQEGZB35XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 77FC16F33DC
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:53 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-545db8dc9a4sf189912eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960152; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZGC1w1DNKusP8RkR9Ujpw9j1ly4o10rhR7IkQxD8BJsNJDUsY/PydnEeD3tDo2VBo
         rRMXsDrFEhVZ+Xu/4/fSAsE5O1noNeVl7xOrmw3YBxbAZD0sKNX5OxCaz0riW6181Duh
         OQssOKHgerFAUdfJwH/8VgEFeM3HpKMoKLxZtvOymYy1WFEw3hUGAbBtZxa1QaApohlv
         sec2ads4bjtw0mhCMt+E51WK6IkrwsEjBcun71EGXqruBUYmUb+MBKgOKChYVFd7mnDR
         mUtllSEWCSE69NICjNFFpIisEC04AOFhIk+V82YObMrIuh2xs4i3eiVJthZazCkKY8ls
         I/4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Uxp+uRU5VgdGuh8Cczcl0xbfxjpp2Z1HkIg+ouAsUfY=;
        b=scqPLi/W6kXopczrI5JQige9X//SgjHNhtSkK9/nVMvayHokRVVvirohzAkVCK8TNF
         mveo8pjUdb2UbyZeoFzrLBCPEiVEOCGYwN12tSqQKhvyir3Tb7dZ2Fqd9fpDQX0zX6wa
         hYbJQWBgLSlaQwKGi3/6gx597zSXpUJfsm022kUpSBiBJKfgzbem0zxPbfN64tK52nsF
         vyUA1XwiW3QlitHiRuZv51a1UHxZsTJi+OEzZhCWLsHkGw9+KyA8mO5porcFkXxxU32N
         hR2q6O0iRtyETRMuDdRl2BTD4BNRhIuVT/IMyYqheBgCpAMmnxvybv14tlvbyyp8Z7rT
         fikg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=hhMiGEI+;
       spf=pass (google.com: domain of 3f-9pzaykcv4oqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F-9PZAYKCV4OQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960152; x=1685552152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Uxp+uRU5VgdGuh8Cczcl0xbfxjpp2Z1HkIg+ouAsUfY=;
        b=bltpvq886Hk4GhUwDXmzVeOcEtWIle2FPl7G5GBBEjhkYniEsAtxg/eZylbYocjnjK
         Rw4kk/yfA2Y/LRqxp1xFtaMjTmKdmbhjrntJzCfWuWQbkHFtrVKXdDEbmA3XzBH+dkP4
         g6j2uxur0d1OPnnvYBHOlIHfVlcpk1vDBAHpiqvgmH8PaYxW057JN7vbVodN/GKa4iOj
         1Od/JnmxBxGHkCeYBkcQccDjhzMbHwhD1xdo/cNTCB7Fw1vsWxxpGf9CUQoqF2Qz/vKK
         w/IR11eU2AH/HoU4M5zdsWbGFJCtQ6Zy2aLD3PxkjAjE24fxgvsIQLlxAOgdLT+ngeFc
         23SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960152; x=1685552152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Uxp+uRU5VgdGuh8Cczcl0xbfxjpp2Z1HkIg+ouAsUfY=;
        b=AmElY+kdc8Tbqi4yJaqgHeI1pZAYSK6ZXuqxVyaC3Oh8S9ZBpJm61ToTekecVEdky1
         gGOREp/PPlKOn4NbGVfL+WO6uWTORkTK0hWBAQ1FkRSYtPmiBnTvtYzUNSgtZyFW7aE7
         xHhtW1oW4vcsFKW7iGGYKCzrzUEluIuAFB4DgM337PRFZlhZGxqemdtrBUqM7RsNpiU8
         ow5xvTo0A1nzNaGpRDm7gaXIzzS3DP51ohawn0baotCA2x5cydEDwX00JVvr5udMuBLF
         MEkS5tKn+XsybYgXfx+57l2nDxiP1k77ohdunkBXxNhuOUxMpWsasW+nQakv8aQHvkHZ
         3v+g==
X-Gm-Message-State: AC+VfDwYU8Hn9VokelxVn27YvGFaxRU0pgYbrVYOPguR98eJ+QlsyeaV
	XQq8GtBsFqHbVzOFCQBI3qQ=
X-Google-Smtp-Source: ACHHUZ5elHkAOWNifkZellCgSQqu1UGjNIouBLutnT5JIuEXB5qPgN4u3DPtWBy4upUsS8c+uq94HQ==
X-Received: by 2002:a05:6870:668f:b0:184:7f61:5486 with SMTP id ge15-20020a056870668f00b001847f615486mr3510917oab.6.1682960152375;
        Mon, 01 May 2023 09:55:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:884:b0:192:7291:2934 with SMTP id
 fx4-20020a056870088400b0019272912934ls404173oab.9.-pod-prod-gmail; Mon, 01
 May 2023 09:55:52 -0700 (PDT)
X-Received: by 2002:a05:6870:8684:b0:17f:cf1f:9d8f with SMTP id p4-20020a056870868400b0017fcf1f9d8fmr6089411oam.8.1682960152008;
        Mon, 01 May 2023 09:55:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960151; cv=none;
        d=google.com; s=arc-20160816;
        b=n33BwYRjPf5Qw5tG2tIg7957Op09qBSwhyrYK2jRaNhNhfLN0Eg5QPbL4UuDYVUSp6
         /oFmJNvqdM6tP3YKo6uflAksE6+d4I/rUIj1SB/Q0C7pFVvtDGM4w18TFYqn09Uahhui
         U1Jxf7tj4W1b0UO8fPD/OmxSPZck7L5mKcPblUKOFyImaGxYnXZNV9IpzuiY/ar3FXxR
         QhU83Qc73tjQfeKUtjkx3+efRODEDqCpDaVBXbfeh8z3iYW1cNkAcdiOxvywmF0Lz4Tf
         tzUF2ckY/Egfjg/1LuRGhX2oJihaW7doCAhSu8KGuHQhmGVg27C0RhHhPF+1ZJodu6Uj
         yc/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LeC1gX4P3RQjW1NYELsxA3PFCP+EdMyYyajg3MbW7ME=;
        b=kp5uV5eT8U5YntBiLgoBvKPG5aFdemXLwjrrr6VgeUhufG6fni0y7T94/0ptm/RqtK
         jsZDuCcVzg68zpQtd2Clhqh4+0fsSKX7OnyRfxLBnkRI+MlsmyjU2X4Ti24VltJhKHi7
         XDvQHIQryEShDq/pUksuEmb6R8zCr+t/IcZq6yDtLVWh31nOYYSUi0ZavGH7LgWwanDU
         f0ZRP5N9sIKtBJMmCqbLaDAnMf27d4VE1Kebo5hJBiSbVYY6joA6LWJlrNpoEHy8fs1t
         tT2yBYDacbBYO+ZUzhe6EOXJoHuheLSJKkXmzp3nwuRLfNtK77E3TlOTNC553BzQ+BwF
         n98g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=hhMiGEI+;
       spf=pass (google.com: domain of 3f-9pzaykcv4oqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F-9PZAYKCV4OQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cr12-20020a056870ebcc00b0019272996894si95974oab.2.2023.05.01.09.55.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f-9pzaykcv4oqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-556011695d1so45700617b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:51 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a0d:ec4c:0:b0:55a:20a3:5ce3 with SMTP id
 r12-20020a0dec4c000000b0055a20a35ce3mr2799132ywn.3.1682960151497; Mon, 01 May
 2023 09:55:51 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:29 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-20-surenb@google.com>
Subject: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid name conflicts
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=hhMiGEI+;       spf=pass
 (google.com: domain of 3f-9pzaykcv4oqnaj7ckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3F-9PZAYKCV4OQNAJ7CKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

After redefining alloc_pages, all uses of that name are being replaced.
Change the conflicting names to prevent preprocessor from replacing them
when it's not intended.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 arch/x86/kernel/amd_gart_64.c | 2 +-
 drivers/iommu/dma-iommu.c     | 2 +-
 drivers/xen/grant-dma-ops.c   | 2 +-
 drivers/xen/swiotlb-xen.c     | 2 +-
 include/linux/dma-map-ops.h   | 2 +-
 kernel/dma/mapping.c          | 4 ++--
 6 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_gart_64.c
index 56a917df410d..842a0ec5eaa9 100644
--- a/arch/x86/kernel/amd_gart_64.c
+++ b/arch/x86/kernel/amd_gart_64.c
@@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops = {
 	.get_sgtable			= dma_common_get_sgtable,
 	.dma_supported			= dma_direct_supported,
 	.get_required_mask		= dma_direct_get_required_mask,
-	.alloc_pages			= dma_direct_alloc_pages,
+	.alloc_pages_op			= dma_direct_alloc_pages,
 	.free_pages			= dma_direct_free_pages,
 };
 
diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 7a9f0b0bddbd..76a9d5ca4eee 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma_ops = {
 	.flags			= DMA_F_PCI_P2PDMA_SUPPORTED,
 	.alloc			= iommu_dma_alloc,
 	.free			= iommu_dma_free,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 	.alloc_noncontiguous	= iommu_dma_alloc_noncontiguous,
 	.free_noncontiguous	= iommu_dma_free_noncontiguous,
diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
index 9784a77fa3c9..6c7d984f164d 100644
--- a/drivers/xen/grant-dma-ops.c
+++ b/drivers/xen/grant-dma-ops.c
@@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct device *dev, u64 mask)
 static const struct dma_map_ops xen_grant_dma_ops = {
 	.alloc = xen_grant_dma_alloc,
 	.free = xen_grant_dma_free,
-	.alloc_pages = xen_grant_dma_alloc_pages,
+	.alloc_pages_op = xen_grant_dma_alloc_pages,
 	.free_pages = xen_grant_dma_free_pages,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
index 67aa74d20162..5ab2616153f0 100644
--- a/drivers/xen/swiotlb-xen.c
+++ b/drivers/xen/swiotlb-xen.c
@@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
 	.dma_supported = xen_swiotlb_dma_supported,
 	.mmap = dma_common_mmap,
 	.get_sgtable = dma_common_get_sgtable,
-	.alloc_pages = dma_common_alloc_pages,
+	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 };
diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
index 31f114f486c4..d741940dcb3b 100644
--- a/include/linux/dma-map-ops.h
+++ b/include/linux/dma-map-ops.h
@@ -27,7 +27,7 @@ struct dma_map_ops {
 			unsigned long attrs);
 	void (*free)(struct device *dev, size_t size, void *vaddr,
 			dma_addr_t dma_handle, unsigned long attrs);
-	struct page *(*alloc_pages)(struct device *dev, size_t size,
+	struct page *(*alloc_pages_op)(struct device *dev, size_t size,
 			dma_addr_t *dma_handle, enum dma_data_direction dir,
 			gfp_t gfp);
 	void (*free_pages)(struct device *dev, size_t size, struct page *vaddr,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 9a4db5cce600..fc42930af14b 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct device *dev, size_t size,
 	size = PAGE_ALIGN(size);
 	if (dma_alloc_direct(dev, ops))
 		return dma_direct_alloc_pages(dev, size, dma_handle, dir, gfp);
-	if (!ops->alloc_pages)
+	if (!ops->alloc_pages_op)
 		return NULL;
-	return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
+	return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp);
 }
 
 struct page *dma_alloc_pages(struct device *dev, size_t size,
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-20-surenb%40google.com.
