Return-Path: <kasan-dev+bncBC32535MUICBBLUFX3CQMGQEYRY54FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 18F4AB38D26
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:12:00 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-24680b1905fsf2742895ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332718; cv=pass;
        d=google.com; s=arc-20240605;
        b=H/iMeo6KP0aytFrRt5tYdHvr5vOc20U8q1tbscee+Xl/YWia+kJKW+rodUGgVFGY+m
         MfIuSf7LKmugDPF4UizDZSrfp6d7fTeckuOQDW68/d7sxoE0Fhv1Mqty0t0oCJ7Xrq6b
         kccvgiIR5dLba5rc7rDbfiuZNCErDJl+pIvWvjJ4knT2dnr1yoT18GE2a8yJTu1n1A2N
         Fb2qphDvcL2Q3SUmrJM+apd5QrFyFq2XrITWF5dXXqCdrWz1fKt5/1F91PJaNBFdHC5F
         qZT7q3BwVKS+zmI9d7W7qHR/cTSIRVbCfJwFxNyJ+biS+7PSg0iA+FGLpyG314PMlpsQ
         4j+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PSRkvjcdQRHt2xmVLMCC9iQYv98cHv8hS4PZKWg2Aho=;
        fh=FuBaLwsitQR9OTCQTxA5hVPno12EJwhFvlZXJTL3FlU=;
        b=fO88ySdUo9epUj+JoYZsKpnGPz+OwH78iH4doie0C8Cx+LGM8f0vwW5CzVq8o7W9Fg
         Sc/zieb/B4jPti1LKyYWUY6VGwYH0HsAvzVekVUUJ28ZhiDzY5hh4jHjuRdq2MFsOMZb
         9OXuAIHqqV2Ug6iMIMZjIU1RlQfTrCsZVqtdwabfPLyVIIsVBEI2JE5JGDanYfniEypd
         Aginr9jIpN7b4mTt+1cclfCznPxyKTBBvp+I8hXum+Tqv4csjDjvnnroIpTGUCxYrR9a
         9s71Z0k+oP44/+HYcKP6pF6Wt9Dje3YfQGG1JsT9aBR4JzR/0iCK7BmP4dgRQWHGPBp/
         2GHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=epEMV4gc;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332718; x=1756937518; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PSRkvjcdQRHt2xmVLMCC9iQYv98cHv8hS4PZKWg2Aho=;
        b=UPdQCaNI+CLEJwEfZJVNwfkQCv0e3aU32CU3DxKW51y3WX3zbqKkPqaWmdNNoI+4NX
         rXcMCvdeRTnOK2Ha0VAFXqmXCLXYcAjzobmVn5vgQkyFneBy5EJl6eCZgv//smQQyhwl
         d5DonFqLM3Z+Q4rKdo/+Cuz0BrN0jfynAouj/7GNY3i0piZp5fSDDd3dCfuFeUi9s6NE
         gPCjGm4R10sq6O8V38LgybxTZ3HxL4MJloEdbK9T+FaAv/3ZJhq83u+T8OVK0HDJ6Jh3
         kaNLXM2gv5JcbPvhcpKP3LMSXRTyDbu8O92yolKR/RJOjhlNFBm1SWlXFzPgpmZmV2He
         haMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332718; x=1756937518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PSRkvjcdQRHt2xmVLMCC9iQYv98cHv8hS4PZKWg2Aho=;
        b=kwUbDYNROzLM/RKEitzv29DW8XKOahQoRgqe1b9dm8Dl7+mUZOEA5XnJKk0tgB+XBR
         UuS7PMYfw2Jncz6n0mrovnctF9eUQcVOaJ4Ice8AopdAyz/UMegagxV6ZVy5clMJr0wI
         kM0mlO48TaRFhDlrCLgJsdM6B99u+Fz7KQRPUmlW7BxMXupzeN2PSOjodBCk3CbwbphO
         UhwusaEVic+vBg87tEAdB4CJTf1mqWEwNhTwB+eWf6SNfxJj3okf35nCYdAYkkQMjDba
         SZ/h93Z5vMEIn+AnKduQqPOFTWaGq6dULqd3PzShRnP6RIUHtPy/lvFvVoA7nWHUV0Fd
         sYzw==
X-Forwarded-Encrypted: i=2; AJvYcCUagBxlPBAQQxdEriwI/jSnxFJWgjeMUVeBx54YLkcUwycdQNKYzwO1N1IqIicYSWZ94Oa5xA==@lfdr.de
X-Gm-Message-State: AOJu0YzHKElh3uRrFogE2aF2MBGdH3uk1+0ayHRmGfkW1uK08GOOAvyf
	5AxG1+rz0wWm6rm90sUyWpnj36PmWGLSY0AXfw5yDUz0lopibUmwSbq6
X-Google-Smtp-Source: AGHT+IExmQ6JHESqE5jYCAMLghXgYfMgGBXaL7jRAoYQXoNN1htahNE4MeVWda3nbY4be45ju+vaqA==
X-Received: by 2002:a17:903:234c:b0:246:1c5c:775 with SMTP id d9443c01a7336-2462eddce8dmr261769935ad.1.1756332718371;
        Wed, 27 Aug 2025 15:11:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc6pI3CB4HDJjwqwYHlb+SQ9rn9bqxsV3n3IvwqfNfm7g==
Received: by 2002:a17:902:e852:b0:246:5cd8:f860 with SMTP id
 d9443c01a7336-248d4e3deb3ls1487455ad.1.-pod-prod-09-us; Wed, 27 Aug 2025
 15:11:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVI8Zhkt50ltHPDOjOF9e2AIh+girZ+EX2ObYu+in7qv4X9rgQEIX3bnI70gQDeb0S/l8WxIUTHSjw=@googlegroups.com
X-Received: by 2002:a17:902:fc43:b0:248:d6cc:f89e with SMTP id d9443c01a7336-248d6ccfcafmr3184465ad.5.1756332716496;
        Wed, 27 Aug 2025 15:11:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332716; cv=none;
        d=google.com; s=arc-20240605;
        b=K1mWEqQygwSGwPzeWEERjNGGxRc3Nf+cNBXB7aalVWnpA36acWbcCz2aU0QnFujrNq
         3WNEsf3c2hz5uzo5/qo4ls9z1eFSKQUmFLNL7A2S5mVP7zN60gYf5QSD/xMn3jJ3mV6t
         GoqQbEG4gyWOU7Aam2GsqjMq4AW9DZQLAwSPIYFaa2JZZtGlkV4iOtcIzd0IBzNWJbWH
         LvZXZ9WbWA40hSSHzh3HnvntQRYL79TzufJ99b91XUqbXVVL+kvnaq2lDKkKAOmzb9nC
         HbD0kdXsH1Qy1PueIXY3wd3KQZ9LX0+7EY+n56wlEq+13E3KZHUs7Jwt2k6OAAXP1com
         p1Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oaPdsETQ5qU/BcrWAtBVOePuWmWOKOsgMpANROeM44s=;
        fh=wD1l2eXo4LtWu9Ok5n8eE8oCZzpEPlrADJNGS1oDfag=;
        b=VfKuvhy7YsOZ1W5El15PNJHl+jOlAITrOLS72uFfZkh7SCLBYbu3LGCYMLI6RCc1om
         WHtz7Dkag/3KALpm7roSRYpWC4vEepNPC5G6wR5RNMPQzt6AUxTonBFAH6s6RHGrEwSX
         YRcByCYWcnHC9JKq2aHQ+2f7CgtiVBvJWCP/rZhbIAvcVYodHR7JvO5o+PQnFcvqeWAE
         /U4wdXifmbn3R5nhzkAgItms0mI7OVBERAEGZbtNxeDTgEVfyZisDGOopA1j8T3j3iX7
         xME+b8IwZr5Yq1tY6lnRMxDQfHqqqrL6cA9NSbRR7aJHceXgaZ5BO6uWfPIYvTGG5Nqn
         TQcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=epEMV4gc;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2488bd6255dsi1858795ad.8.2025.08.27.15.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:11:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-658-Snfm6E4cPnqT__aizlDo0A-1; Wed,
 27 Aug 2025 18:11:53 -0400
X-MC-Unique: Snfm6E4cPnqT__aizlDo0A-1
X-Mimecast-MFC-AGG-ID: Snfm6E4cPnqT__aizlDo0A_1756332708
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id EAFA8180034A;
	Wed, 27 Aug 2025 22:11:47 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8D43430001A1;
	Wed, 27 Aug 2025 22:11:32 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 34/36] kfence: drop nth_page() usage
Date: Thu, 28 Aug 2025 00:01:38 +0200
Message-ID: <20250827220141.262669-35-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=epEMV4gc;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

We want to get rid of nth_page(), and kfence init code is the last user.

Unfortunately, we might actually walk a PFN range where the pages are
not contiguous, because we might be allocating an area from memblock
that could span memory sections in problematic kernel configs (SPARSEMEM
without SPARSEMEM_VMEMMAP).

We could check whether the page range is contiguous
using page_range_contiguous() and failing kfence init, or making kfence
incompatible these problemtic kernel configs.

Let's keep it simple and simply use pfn_to_page() by iterating PFNs.

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/kfence/core.c | 12 +++++++-----
 1 file changed, 7 insertions(+), 5 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 0ed3be100963a..727c20c94ac59 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -594,15 +594,14 @@ static void rcu_guarded_free(struct rcu_head *h)
  */
 static unsigned long kfence_init_pool(void)
 {
-	unsigned long addr;
-	struct page *pages;
+	unsigned long addr, start_pfn;
 	int i;
 
 	if (!arch_kfence_init_pool())
 		return (unsigned long)__kfence_pool;
 
 	addr = (unsigned long)__kfence_pool;
-	pages = virt_to_page(__kfence_pool);
+	start_pfn = PHYS_PFN(virt_to_phys(__kfence_pool));
 
 	/*
 	 * Set up object pages: they must have PGTY_slab set to avoid freeing
@@ -613,11 +612,12 @@ static unsigned long kfence_init_pool(void)
 	 * enters __slab_free() slow-path.
 	 */
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
+		struct slab *slab;
 
 		if (!i || (i % 2))
 			continue;
 
+		slab = page_slab(pfn_to_page(start_pfn + i));
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
 		slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
@@ -665,10 +665,12 @@ static unsigned long kfence_init_pool(void)
 
 reset_slab:
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
-		struct slab *slab = page_slab(nth_page(pages, i));
+		struct slab *slab;
 
 		if (!i || (i % 2))
 			continue;
+
+		slab = page_slab(pfn_to_page(start_pfn + i));
 #ifdef CONFIG_MEMCG
 		slab->obj_exts = 0;
 #endif
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-35-david%40redhat.com.
