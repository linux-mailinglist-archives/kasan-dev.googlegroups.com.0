Return-Path: <kasan-dev+bncBC32535MUICBBNHQ23CQMGQE2ZTTEFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45A80B3E916
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:13:59 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-325ce108e45sf4267811a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739638; cv=pass;
        d=google.com; s=arc-20240605;
        b=S9EFjuXV5DvINWm/4y/OdDxYcIPsnfeK2hlxgee3mHxcxNBhUDi/GS1QElyRPcDHJC
         AV+1dc5/HuEcz554NnGKc3jBgpc5r4K2dFtDp7n6nleXkEptkM6bwsJFQgAPd706Nph2
         0exXUcp0y3LeaajnhT70iW8gA2uswnhAdtD/gLG/+JQAlE6diMJZpx/FQvkS+rPtzmki
         M6ZYiXZsTVxOr7fSnOIPBjnNgIOx/E6SUyjOMDMVUetq7XoxNHF0NwOT7XACJdsE/ncb
         nPLHY4OC0YV7Fcz+KihdDtm2bIZzg3k7I3fvL/TkeKEmTC4B7pbazK36WWJFU+Jg16lP
         xtYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=l+gHn14bChvXR/XvNj1ZUbJgqQFTZJBk9fl5ELLA+GU=;
        fh=31khK824I679qsCqeWGZZI1rgAFwfUee1Pfd+Joi7UA=;
        b=YdCSACs1uILzNDjhDHc51ZszqIvfMpV+HuOCacNV+JjmeiHhuugifbFc4NwDzd5AON
         XkezFLZJ7fOivi8y6z/YvRysDmwx1Cit+vz6/ba3GAOHR/T4SvcW6rs792im5WBDoxZY
         EYW4jkRCMRdjfBtQM+FhYzf1rhL1btNqQ8PyrfxQ6FjqMBFW2//8sC22fx7f26o3iaZF
         W+3eqVo+qvPXozHq0MVlZ/oBjnrVMjzfS/u0C/gwrUJDHpTVET7mbUzEVOlqt+sS3wrJ
         8kdMkQ62dVhlvMuG3H0ThwB4HpVMCk+CEODHuP3Z8BQfF7VAFH6VF9oQHXdN4Z6fj2xY
         bt4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SpV6hOyT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739638; x=1757344438; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l+gHn14bChvXR/XvNj1ZUbJgqQFTZJBk9fl5ELLA+GU=;
        b=rjAj9+luRCnwfTlrzww/Q2Kw5Wu7C1wqPDWh1BZUsw3w2P/qAj4xUvCZ8xIf7/jOhg
         SiTInk9pCryglAB8RDSret6Kcli9r0ks4xhoIRKGDwK1FARFFYY7e2BOGFkgWhfDqz5b
         Gj/GkZPVK2+UkRHDAPeNSTNvfyDEC9fvcjUksOB978dleNlxxgO7flXm+Yim56uCwIFR
         Ns50wiD8oNE2xTh5zMgC3CZtf2CPIVixjwqT/mO/jHhhOnxZWMZY6JIScQ6QTFYWjnGh
         T2Z+yClC9wgYy/mYjf0jyocmSNjTMcqyVkfJDcE7fSS/rLgveiPO4zuGd3a4yD6cDxJF
         9HNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739638; x=1757344438;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l+gHn14bChvXR/XvNj1ZUbJgqQFTZJBk9fl5ELLA+GU=;
        b=fhgXyJGvwFShCyPNWXt7pWy2cieXUQUTQd/WwmlHA3BOMYPw5x/mMxGxj+5ODQ5yFT
         OKiMYQX/W6h9FqWm8RIZVHZLj2ZmrQVPqr1tB+ULicSV2ShQsS08xCplciRsYrQ/IrjZ
         eifrI3LmmwNydnPmScJzSU67U1fX2/1fWrDL0r4pYUboW6aUAU81d7sRhRZb2MojAqQu
         lOIoxETkOyVmykk3eainjkImqBDAIcy5rqqRMUftnbO46/6/BH/8h0ogKpjXUR1+DCQq
         NIUiliHMzEkhgF/2DTDH2Mt5X7Qz74VuI7aj6bIVkyiebeUFPshsKJZ97xAGzI2sH43b
         iGjA==
X-Forwarded-Encrypted: i=2; AJvYcCUIbth8swrub+ipob8tiNENZv/2SWYu6s0kyWnA1WqCnDitNrdDmRC+8GPJMnu24JKpXDikFw==@lfdr.de
X-Gm-Message-State: AOJu0YzM/LteVAGJxxmyEeC8qOUdCPIsc341s7fKqjOwa06mUGr7nvG/
	qtlKUZOTIGxUwThq9sTouGhN7mdPgUVesNisgV/YRIKL4VG/Oe2I6SQ0
X-Google-Smtp-Source: AGHT+IEaqUP2pNKEuxLhvNFjhLhUiArjucl/PfGjpEDSJdCt8tbqHSzEsq+CMPy2GsoWCt4Ef+eKKg==
X-Received: by 2002:a17:90b:2790:b0:325:25fb:9128 with SMTP id 98e67ed59e1d1-328156b8379mr12188085a91.9.1756739637098;
        Mon, 01 Sep 2025 08:13:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiVApT+ZpYpvlwflTOQK8lhO8CoBnkUz5fbFmy4EO4Bw==
Received: by 2002:a17:90b:4cce:b0:327:f95c:7f6a with SMTP id
 98e67ed59e1d1-327f95c8155ls1981793a91.2.-pod-prod-00-us; Mon, 01 Sep 2025
 08:13:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvx1sQ+Dueuhk/esDb+2kV/Pn8H84g2G566cKnOFAbZtljG1WD9XGK62BhkNaFEcIZd8VaK1ImL78=@googlegroups.com
X-Received: by 2002:a17:90b:3b4f:b0:327:4bd2:7bbe with SMTP id 98e67ed59e1d1-328154128bemr10888105a91.4.1756739635395;
        Mon, 01 Sep 2025 08:13:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739635; cv=none;
        d=google.com; s=arc-20240605;
        b=V8wyId415MgrEXePl/v6mUjvd85yf6rQXBqY7o2mcNeJaxMPCdkpwqJbvPAfAgWybc
         YDgA9ZGjHcy8h+zOTjvvEboXqgHPFXSF0LAEdANH0sz6dZ+OyWmnyEpQTgRbIsxkaB1l
         WOIwCb3MLIzoTY0eX0k3PFWnZaPigNn7PELRp541A/XKWxv18dN7LRrkCgOhg5Xu+cOV
         t2YTVqiDTp5Dodc/kYEUydmv7ZxJyn1Vms+rF2My9WjYeZ+j7fAY3ckZKrMCjOyLDUR3
         lF9Bf7lTyfBljwp62WZlUT3/5+0msm/Yo7RB1P6ebMYaX5SYzDtp5eiGcbMwIUlG9lnJ
         cSCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jkEShtyZMAsDf/J3X4vsiABth2SEec0fiHHSpv4k9x8=;
        fh=r7P2GQQT9fM/FRf7W7mBd+R3+8OJ65bJmrvO+lRNTZc=;
        b=X6cc2Pula+zmRc5Nk9cn4XMCcgsKGhNHKEMoZ9ACaBDZzKAfY5m911mnRdQXjJZ6NZ
         Xsr85TdKjaKgL4mAHAEWL6P0JeJq1m62lg6utdMMWKTP5tUle/h+oQBmLOaW95T/LNsM
         xHwHjzCK+KGA6x+oNyiHCwKD6gHL+21CU6MGFi2LDHkXyVHJb3k9NWvaY9fDQd9DT+T4
         b1K9xt9s6a9cisOB0QLwdJILgi94PlwxfGXx9NQuFcDXt32hPfGMzQVe4aEKUpfphDZt
         BEQPjxyL8H6F+ArCXoI39wahLA6fGYM4/BGM2qj5O7raLprgYvC9NvlFJlODFgnZCJqf
         vXcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SpV6hOyT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f49394esi659137a91.0.2025.09.01.08.13.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:13:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-1-o2-TD6CtMRuqF-LwyESxUQ-1; Mon,
 01 Sep 2025 11:13:51 -0400
X-MC-Unique: o2-TD6CtMRuqF-LwyESxUQ-1
X-Mimecast-MFC-AGG-ID: o2-TD6CtMRuqF-LwyESxUQ_1756739625
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4DA9F1800561;
	Mon,  1 Sep 2025 15:13:45 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id CF9891800447;
	Mon,  1 Sep 2025 15:13:30 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marco Elver <elver@google.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v2 35/37] kfence: drop nth_page() usage
Date: Mon,  1 Sep 2025 17:03:56 +0200
Message-ID: <20250901150359.867252-36-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SpV6hOyT;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Alexander Potapenko <glider@google.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-36-david%40redhat.com.
