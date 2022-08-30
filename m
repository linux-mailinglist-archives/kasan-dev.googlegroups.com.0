Return-Path: <kasan-dev+bncBC7OD3FKWUERB7ELXKMAMGQEALVAVCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C99F5A6F88
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:49:48 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id h12-20020a4ad28c000000b00448bee68970sf5844290oos.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896188; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXEOmdw1XTcHTfYdFGwwG1CmXjqcBGentLfkNLBw4bEzBv3KZdSUaZqt0uWny3iXsi
         ACN7TovXsoZZ2WUGBTCpDBYHIKpilBDX/TwvjWh+dRY8H8ZrUxZOhRRnrvo80g0UBCuk
         zpRUuTXc8sz7u/5NOZoq/QRcukKW0JPtDQug0eSKpKq7wykk5lmG3L+8ZbCCt1LOodnk
         xgQETBx4kd6TK4M1IOCyF4mmJIvlSrI578Eh6elfhllBn831L5eQk7lcqjC/vnGfjzoj
         dT+DiL2yh+pGUovTy1GkNmWuTxCHSsBx0al8RPJZ6qiYvA4bzAh1m6K9uarntZzx2b0Z
         Thrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N/yGYoVJlc+xXOArsWC4w0B48ocFgpfJc60+CJLnTuc=;
        b=DX388AZNwxuYKdwxwwcyk0ENseMYCEKbY8YQyzOnYEWWQ+Fk9Zh96OELpr7/Qif5Mi
         VKmUoOOgN4yLaYq1IuaIm4TwPXcx1MKexZQrrs8JZFaxrjt4PetApPYFlr1C4rdZecwi
         5hLRKsRyM+QshwdfN0hSXyf0ki2NnpIjSM5bM3O9SxYT1U/bGd1psczl4oM/FGA5dqaE
         xKZSPxqpxm9wWpm9uyGpdupmitzYeItLSe1mearmKhyX9mRGPLJWVb7iWiUbWKEzCe3u
         AD15D6++sH6RNSTs5ICZptN8WWY/GZpp6W3o3Pfbvte4agYzbxl262eijTOTAOCsJKYy
         0N4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eh/OQULF";
       spf=pass (google.com: domain of 3-4uoywykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-4UOYwYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=N/yGYoVJlc+xXOArsWC4w0B48ocFgpfJc60+CJLnTuc=;
        b=Weevg3zYxsOBitjAjK6XmZ7W6YOI52EyZZ5mEaXYEuarEs/OMDYqgW5gH8klM+QZ/j
         ELUzSi9cqsyJgC7mRAbuYy2jEwbEVUg8w3oUALrMayhCcHJkPBdlLbpVRtHhRC63XXMX
         2eKQ791kC9tdoDpJEIoRXHyj8Pv6bQ3VdL/wru8aHIM8Za6SCwZH+NgV6Rwcsw/ateKX
         lDvvv0ijWQotPCjBRwiLkSQOl1Y0768g+IZF6Ytcv92SrtYiNyM7szsmQfN5Skr5H6gi
         aCDukhLT9ksT1xAzV7PcMeEgQUZrTr1f7wvK2NCJfaCQPyIZJZYGY/Fx920qcxuf2aUv
         HGxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=N/yGYoVJlc+xXOArsWC4w0B48ocFgpfJc60+CJLnTuc=;
        b=ZtHbo9xDGgOZf5Hix4oMbsuEHYFZH+MRvCPZj2BUsWW4xILVKHoYrVmq5HNfmqgi5y
         w2j6t9EhseZcM6pIu9ry2tqA0VlVinTrw8Udpg5zqr7YyZ4rWR7sQtsESVcV4Yzi9cPx
         N6cm7REvNRB/CzkGNlnSfd2Jzd2ezGVlLAwaDGFCrBPcN2l6QH8JwprpvPopkBGmhmj2
         2BuP2qWrEUvVg90p7lrrFl3xErVRUtiCuA5AiEP/pubmraAoNEO09j9FOURayN88O36v
         IeUfIU4bsBMPPeXXstNcct+cQCLJLblK3RdY3ysONGuUFcAba/AgYFu29uPeMYPfwAJn
         LF5g==
X-Gm-Message-State: ACgBeo1c7wxCtmrhqtV3xwRhnjVfrR5/a/0z167Drg+CvB+xEa2711V3
	Hyjgi6BJqYLtY86gPj85mYM=
X-Google-Smtp-Source: AA6agR6I6pZUaA21hQQyNue5zD+vZud+TgqZeO1Q0byqEumgnlwZ0T4NhXC5BO71W75GQNdi7KqbHg==
X-Received: by 2002:a05:6870:b61e:b0:11c:d598:e612 with SMTP id cm30-20020a056870b61e00b0011cd598e612mr11060oab.261.1661896188129;
        Tue, 30 Aug 2022 14:49:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:256:b0:345:bc21:cf7a with SMTP id
 m22-20020a056808025600b00345bc21cf7als3575949oie.1.-pod-prod-gmail; Tue, 30
 Aug 2022 14:49:47 -0700 (PDT)
X-Received: by 2002:a05:6808:f01:b0:344:aa11:c161 with SMTP id m1-20020a0568080f0100b00344aa11c161mr28354oiw.150.1661896187745;
        Tue, 30 Aug 2022 14:49:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896187; cv=none;
        d=google.com; s=arc-20160816;
        b=HWINQclXp/X1ykfPbEf8v0hDR2xyrI2yOEMSHL+Bpx51xlSBq5awpCwJRFLS67C61l
         Jk2SbSImVP7R9R5A6wJoQffSam1yPRny1s2JdznJptqFLeKpUEoB3/wOugWK3acnkUi6
         iziVHU8uZ01sam54fUCfqRlSYs8qkA7pMkTM5HDNW6TPM1Ed2e0gfPtROvhv4yy0VNQK
         JtkEyIzoYR6ZNu49G3ifoO5yoO+4hPuJdtAVQNDHvrjkqJpPjFbhwZjHEt/68RWo074L
         Pjwx0C/PNLP5PDSivaru4BvPbjkdF3q1LmLZUws9xry1TRYFr4CExkz2Tj+WnRecXpDv
         j12A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=p8/y/nLBQm6IGi3iJX5wV5NMUkycPfOY4OR1rTeRfxQ=;
        b=h/OCrKUU1c6WN+PplX3Xu5MCLyxJYspy4R5HBtgdHTvGCKtXa2lrqWO6c/8UFApa8L
         2aQfrP72JpBE0CRgsDV6r0i7t8TEXkA7ZovVBkYathnR3vm9qP0pyGsYcmq0T7LCvDHS
         ucoGS8aMombqxZSLjukrF8DhkGTHheNVhorwRaYt09/zm40lcK6/Ce9bNmAVenEsxQ+d
         AGfZfwq6g8c6uzd97VmcwD0Hg9WJ65NPCXlFXBvnxa7AYgGfLIkLKaIuFPFylmI810CY
         iqfrCPxm2Twr+3rtCoLcWoJVl03NWk2x9jhntx9Qofa50RCDjJnpZeQWhJSp4+klAnKR
         PcUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="eh/OQULF";
       spf=pass (google.com: domain of 3-4uoywykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-4UOYwYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id l21-20020a056830055500b006371b439b4esi537910otb.5.2022.08.30.14.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:49:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-4uoywykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id j11-20020a05690212cb00b006454988d225so722911ybu.10
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:49:47 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:4d56:0:b0:69c:3d80:bb51 with SMTP id
 a83-20020a254d56000000b0069c3d80bb51mr6383765ybb.124.1661896187249; Tue, 30
 Aug 2022 14:49:47 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:48:58 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-10-surenb@google.com>
Subject: [RFC PATCH 09/30] change alloc_pages name in dma_map_ops to avoid
 name conflicts
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="eh/OQULF";       spf=pass
 (google.com: domain of 3-4uoywykcwaqspcl9emmejc.amki8q8l-bctemmejcepmsnq.amk@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-4UOYwYKCWAQSPCL9EMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--surenb.bounces.google.com;
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
index 194d54eed537..5e83a387bfef 100644
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
index 17dd683b2fce..58b4878ef930 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1547,7 +1547,7 @@ static const struct dma_map_ops iommu_dma_ops = {
 	.flags			= DMA_F_PCI_P2PDMA_SUPPORTED,
 	.alloc			= iommu_dma_alloc,
 	.free			= iommu_dma_free,
-	.alloc_pages		= dma_common_alloc_pages,
+	.alloc_pages_op		= dma_common_alloc_pages,
 	.free_pages		= dma_common_free_pages,
 	.alloc_noncontiguous	= iommu_dma_alloc_noncontiguous,
 	.free_noncontiguous	= iommu_dma_free_noncontiguous,
diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
index 8973fc1e9ccc..0e26d066036e 100644
--- a/drivers/xen/grant-dma-ops.c
+++ b/drivers/xen/grant-dma-ops.c
@@ -262,7 +262,7 @@ static int xen_grant_dma_supported(struct device *dev, u64 mask)
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
index d678afeb8a13..e8e2d210ba68 100644
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
index 49cbf3e33de7..80a2bfeed8d0 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -552,9 +552,9 @@ static struct page *__dma_alloc_pages(struct device *dev, size_t size,
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-10-surenb%40google.com.
