Return-Path: <kasan-dev+bncBC7OD3FKWUERB2MV36UQMGQEY2BMPOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 137F97D524D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:47:23 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1c9d42aedc6sf31655975ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:47:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155241; cv=pass;
        d=google.com; s=arc-20160816;
        b=tAZptaLbCyrM/EQCwA9W7pv+wy6BsRl/FocuDtwc+bF4utEYHyt3P1/NLtOSS34A4m
         gUInPzKwpqAWNTfj7Ff1SRLZIYs3fcDfepCeFcpCRH51PUshh92QMhvPAKbnM9/j0vGv
         6G4u2a6ZHYjdLcvfpJsOtV45fqOtxKBr8kg8E/RgH9P4dOQ54go+IQirJaS9dS4VsVAv
         JnIO/6oEYKFLu2mLlmE5vnp+yl7bfrPeAtYUKFbgp8YX1CCrw6FR1sJu/879E9V3+baN
         MLvQHjUVGFg94BeyaKSGyZJvnnriYQ/jPTGjJ/axV2k5bQsKuQMzmrFc5njZS5tnLkg+
         lZkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2gGCAsWlVzSgmqzB66RZU4KzONngTjXhu2CWZCr+lVk=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=qFvxDOPsBJ4yO8lc28sa4IK/+8Bk9QXW3Skfyeba7EfCnY0SZBQWAlRZlpACE0DD6k
         /WrJ6INZKLPvzb/XDNy+Ota6fxkBg3umoHwC3FqkjIlPNFl9oeB62fP1vyEZbpiBAHT2
         pLT+YT9GZonDQkgSSG7z2IY4TAv2hS8Lqj5WFBEh4RcV79w7zTql71oiXprWRIjx5ei9
         ZsG/kM1qZsX1UnWzJIVF2VR+I3Jg/+LjhJWqvtRyctRGJsq4SkBwlhtxDxZzGWWPDT0t
         ZQJTtSLzAVBoCd855gWINmrptDOT/2XvD3K0P/Lu4DU67BERW4M/G+FXc1REa017oD6u
         1pBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bkmN+Ntw;
       spf=pass (google.com: domain of 358o3zqykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=358o3ZQYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155241; x=1698760041; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2gGCAsWlVzSgmqzB66RZU4KzONngTjXhu2CWZCr+lVk=;
        b=fkrgC7GB0rWp2ZeVlH17B3cQpyIOeiuM7C6j7qCifXpoAaTxHVAk9f8dFb5GXs5vSs
         VM3BRx5hYff5Wo4YW8tohNFN+fOZNNC6LFdO/Z7ylTqBdTVuEUld5T+PLyS1nwR7HVlZ
         MqiE/1N+11LNYH0TAfmGODvQ6ofduC4qKajP4I32BzxpNOsNRqcrbdv3y1rdVyz2NHRf
         CqIP0h7cFYGRji0uIBuQ8H5Lm32jD+LFJbC0l+0hgR8C2RWBbBz/T7hQAtmFj/G7JA/I
         1UTl6IZUCQzYRjxpcqAnNTSbNu4NePSKDMpAD8MlYUTvZZj11q8anuQxP7dpS1E5p3lA
         1BYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155241; x=1698760041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2gGCAsWlVzSgmqzB66RZU4KzONngTjXhu2CWZCr+lVk=;
        b=Zuxc/D3ZiI8nfM76qD85VuLVz9zhypSEe2loKkt6NJWwjAmSa7O5PiFbZR0/NaCwwl
         tyj8xzOOf5LkTlHX5/JnqObes9HCi9/hDP4aCNKLPknpO3FmbCXCVWFlEbRAp0RHehUR
         elf0IohFk8AwYP0s7YYSs/j6yba+BX/VzvXKnOt15BcJNuz8LoqhHG8P8wrycfQXMvis
         bvNBh4X0kXWRnA5xqMPBt9hClkPyoXh7EnCV31vEwSQgqp4AY06Pcem6OcFA9ngRWSOa
         C49rhK+etS5ULTpokGEtpDZ4BkL06mFa4+PitJdpdc82jDYq/hW9DR+K4KC5y7jM57QT
         2qpg==
X-Gm-Message-State: AOJu0Yxr3LNuqG0hil8u7Oa7CjFIv5kDztgwtudy12/WPpKnwUsRvSRu
	wvrw3Z/c255m/EvPQEf3cvA=
X-Google-Smtp-Source: AGHT+IGnKQk1cQGqcfyOrI0g5BBWdfWnXy/KtrGaR92dMQ91CgDO6Q1Fiu4kEtnNuStZfGCtoLHycg==
X-Received: by 2002:a17:902:e5d0:b0:1c9:e2ed:66fe with SMTP id u16-20020a170902e5d000b001c9e2ed66femr9860312plf.52.1698155241207;
        Tue, 24 Oct 2023 06:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c0b:b0:277:3fd4:8ff1 with SMTP id
 na11-20020a17090b4c0b00b002773fd48ff1ls1259276pjb.2.-pod-prod-05-us; Tue, 24
 Oct 2023 06:47:20 -0700 (PDT)
X-Received: by 2002:a05:6a20:12c5:b0:17c:cd46:73d with SMTP id v5-20020a056a2012c500b0017ccd46073dmr2929554pzg.20.1698155240241;
        Tue, 24 Oct 2023 06:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155240; cv=none;
        d=google.com; s=arc-20160816;
        b=SDEqQpxrhCikukn5qJGLKqLHnkjoqiCVuslBvUktxKsR8yXJIdYpO3L0zk5av1SvfC
         ymOvEpqEJWpl0U7ENoxAOtBvORThGcUU61qbacWM4Ix2ejA7CrHYjIhpT7/w6vRsZFoi
         eZIKzuSrZwrzUNo1vj3EsUBmFOH0eamr0OYSXCAH7MBY0CJ5wdlOpAsqG08ufTx7b98Y
         B0FuU6EckqLbORl2p3F0rRUtv6JAhzoJv2TxeC89noe2iuNq4PuC2YgG1EVcHZm6H4rF
         ifcZhRsWZR586Su5GoJQFo2/uPHOXq+qpWa0C3YPCCqX1BdIcpTF57HNLwx1K7LSn1w7
         M6Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rU55lfnTUKEjh0uwdJqAIgtITtAkLPiyFECJvQc6NhE=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=qRy4Kq1R2fNcAAF1N8YgeoUCcfTdlg+5VH6akjPil3QrQHlmKjqWRuysO/zN8QIydh
         18oneVgilKXJ6wnovWF78mj5d7upsCGRI6YCF8yls0CIHXARBHJc/bZ691dLWJWLaTeL
         eqJPTKMhxDSTyI0/xywJo0TSOTpVfZGeP1Sx3WEWllW7M4uHxoxAhZ0UrBezXsFGIlOJ
         unVFkS8kiYSBXA9hJr7ZEpRKKMrJz9e4372IXmPoOwy3u+9Acw6CGDGleADpQrspks0H
         HF8cd7fyKd4dNwRLhtDZ4W605HdaMd+AK8xFeP9KN4dx1HaM5KbjAXJK5xwOr8B1+++v
         U9DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bkmN+Ntw;
       spf=pass (google.com: domain of 358o3zqykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=358o3ZQYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id ch6-20020a056a00288600b0068e35848ad4si607462pfb.5.2023.10.24.06.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:47:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 358o3zqykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d9cafa90160so5239268276.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:47:20 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a05:6902:105:b0:da0:3da9:ce08 with SMTP id
 o5-20020a056902010500b00da03da9ce08mr35563ybh.10.1698155239301; Tue, 24 Oct
 2023 06:47:19 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:46:14 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-18-surenb@google.com>
Subject: [PATCH v2 17/39] change alloc_pages name in dma_map_ops to avoid name conflicts
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
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bkmN+Ntw;       spf=pass
 (google.com: domain of 358o3zqykcyw8a7u3rw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=358o3ZQYKCYw8A7u3rw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--surenb.bounces.google.com;
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
index 4b1a88f514c9..28b7b2d10655 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1603,7 +1603,7 @@ static const struct dma_map_ops iommu_dma_ops = {
 	.flags			= DMA_F_PCI_P2PDMA_SUPPORTED,
 	.alloc			= iommu_dma_alloc,
 	.free			= iommu_dma_free,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 	.alloc_noncontiguous	= iommu_dma_alloc_noncontiguous,
 	.free_noncontiguous	= iommu_dma_free_noncontiguous,
diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
index 76f6f26265a3..29257d2639db 100644
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
index 946bd56f0ac5..4f1e3f1fc44e 100644
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
index f2fc203fb8a1..3a8a015fdd2e 100644
--- a/include/linux/dma-map-ops.h
+++ b/include/linux/dma-map-ops.h
@@ -28,7 +28,7 @@ struct dma_map_ops {
 			unsigned long attrs);
 	void (*free)(struct device *dev, size_t size, void *vaddr,
 			dma_addr_t dma_handle, unsigned long attrs);
-	struct page *(*alloc_pages)(struct device *dev, size_t size,
+	struct page *(*alloc_pages_op)(struct device *dev, size_t size,
 			dma_addr_t *dma_handle, enum dma_data_direction dir,
 			gfp_t gfp);
 	void (*free_pages)(struct device *dev, size_t size, struct page *vaddr,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index e323ca48f7f2..58e490e2cfb4 100644
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-18-surenb%40google.com.
