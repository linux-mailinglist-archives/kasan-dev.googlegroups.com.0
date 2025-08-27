Return-Path: <kasan-dev+bncBC32535MUICBBTECX3CQMGQEZ2FZAWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A870B38C62
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:06:06 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-772178f07f8sf163819b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332364; cv=pass;
        d=google.com; s=arc-20240605;
        b=R+PYxKHNgMAuPtupLCVwRdojf1aatATyc4KfN2/3SGwv1a6aQE6NNBH1lMx4C4+rf8
         vGZHlkyPQmlCqMvQ05PLkM6ajjAkVOAotq06IgGN5NdO+4bz7hRxnI5ZeCCh01jUT3w6
         jh7eQWsljzDgBNdYXMaFwkDJmv5n1QOcKbi9mlVYsD2FPuHroDXoIWpA07V3PHCyhlFs
         oCxYzdr857WyQHGa7F9uY7Pa4vUizlSent3unQJAILXp2KEnEIfzmbTypI3kn/Omrocy
         fNvWJ9kXDGmX87BqapwBRC5JdI+SPulv+ZCN+VoPbSH5vqHx90zzyh/IQxxuXxse1An0
         2cGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=K7lyfWi28uaS+uJxd5ZrkEdWVOmAIS9tOwOPVwQyzz0=;
        fh=bXkrzIA9U0TED14Sc5Hujvx1WI4cGQlUvvhwkHD6tc8=;
        b=F4DbawAggXb4a1/Fip7vfgsGma7D6TeMFDpVW9nb5Z9pB1AdTtn1gToTXC9zj6sKXa
         tpHf63k9k+gMgXlp7Z7lKRs8fPzYatBMFMeMnzQFugYpf2IiB9qpLrWNCe7zW3jKPdLq
         YvRKIhJAjQh/MWFS9lUh15+k0vWTxf7pOoM1u5nqn+5ZcRROL6OflOJ2LuPt84Vai/Ap
         ZkDztYpsxDoZBz3cWyLrstTakNrDuyVk6wUkZpbyV2vTAtu0txh0J6nza/YRhySGsClw
         7H/gLgT0RejnUfUBUDbECV1/ZSwgyyfv6fZ9T+Hyfsm7jqanS6pXm5Xe4LfTI7x/456Z
         m1OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QBUlGF4s;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332364; x=1756937164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=K7lyfWi28uaS+uJxd5ZrkEdWVOmAIS9tOwOPVwQyzz0=;
        b=rjtfLeV1/ylFJpMPoR61BMsepFQo/3SCtYPwyQ4FUUtGbAdxdljuAWLYXbTTEXI4q9
         xjcg5KFBvSmMtSHZK04+5GuSvKaJSMuLTRvZDriIQhR4XLZk6f4Kjx4SGRLmhhlZgojt
         gKRcLqrpy6G2coT7iBunOHHu8yl9cclph2sfm22YGG1NUs/gB63cOygRI5kFZG+If6rb
         HriA3MalYfH/E0P9hw+iu9FiLmeuUBwqDECzYkrkUBujFFsw6eO2HSGQaDfZbLzsbdIj
         OlO/3L9i+WspiRge/9IXZHZNSRSg+9wjMhqyiHUd6WBhR/AlhKR1Yu8eefWqFKkxEkQp
         B1Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332364; x=1756937164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K7lyfWi28uaS+uJxd5ZrkEdWVOmAIS9tOwOPVwQyzz0=;
        b=jdCBbrNIz4IU0ndp9eiQn0ITXLWbeAviZkfQCZCKZ2FFR2mKZW0QHrYllPGUbLc7Ii
         gABVDQWO3xjfcU4V/l/dRvb97arJkJqRHxfToBPk3aYkUtPexWfi4uv33UsMdsbW4XCE
         JWV+p8InWNupWxfBby4+dWxywkoXF4vHMiZBbYm5d75Mi2gUkZdIYbAVylHOJG2ZJp9s
         y95DCn3l6RBRAPATn48qUE8+tlzki4D/7cFbv2Crg+Zr4xwEZLHsqBwXBfjS4flxRmCB
         ZsCYis8dY4nFjwsT/njimEEXilT8WGNcg3/GVHpvEOP4txnHklPAAbZKG7g7h26krX6Q
         CMDg==
X-Forwarded-Encrypted: i=2; AJvYcCWaqYr3JLSy3OH7cjBA1U/vBbamnai0dEBuBLNeQzF4rlAyUSnGTwW+ZVsj+h1M3CfbiQsOVw==@lfdr.de
X-Gm-Message-State: AOJu0YyNmgPt/Aa7rTlq+gwSvlkRgTjqdqIeUeNYm/PZxusjgtisnOe3
	bzciR8HqVPIMgcNlRQZRv9wv0sK9uII7VN9RW8VkrtiUT3J+4xvM2lGQ
X-Google-Smtp-Source: AGHT+IF+JBJDCjtpHARQOG6WJ9j/HkR9EtalTkis4k2u3UQTI+0SFLeKCR97hGeJV9MvsMWBuwoV1g==
X-Received: by 2002:a05:6a00:3cc5:b0:748:e289:6bc with SMTP id d2e1a72fcca58-771fc293bd2mr9030799b3a.1.1756332364495;
        Wed, 27 Aug 2025 15:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfD3T7RBndFQFxOzRBFjDxuUQBW6Nqh1ChHCVl4lpx6/g==
Received: by 2002:a05:6a00:1a0f:b0:770:5031:655f with SMTP id
 d2e1a72fcca58-77217acf81dls114601b3a.0.-pod-prod-00-us-canary; Wed, 27 Aug
 2025 15:06:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJwBj57j2Wo2FSVGiWTnuLG+K7TbffP4G30/XKUreWqLhLDjGSTocJpulQYIg7cRrrz0z+bU51PTc=@googlegroups.com
X-Received: by 2002:a05:6a20:2584:b0:243:6f68:a2f6 with SMTP id adf61e73a8af0-2438fad116dmr8986006637.20.1756332363104;
        Wed, 27 Aug 2025 15:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332363; cv=none;
        d=google.com; s=arc-20240605;
        b=OHn2bLEWDCwFV1jmy1OLdTrgz5ZzxccoK3Z3tujWGwajKjHj1QsmR00BJRSrLkfVuB
         QAFlT/pEXavGSJ3T/WDchRPIT+IC4QsLRsoygraiTbTau5oVQKdn9275cTQENharWLGD
         e4umrycpGy8YvDZa9KxgdGKujbXOuQILlshuWqbz7D1tSMa5ScpJIgrHAifKK9li9+pr
         VYxY4BnFQWsO3kaGDH61/jU+Pv5R4Va2Jy5hKPYNxWk2lWYrRtSgjhRIeEntDO7aDIIT
         C13WIyTSyC1t/RwKCj2Y6KyLUyX7ojnqmwmwxvVGl+QZvJgRvG7Z06kevzfimVT1u2Rh
         ZaZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pEIm/KOIpGpHTKl4mPR/fyxdpTiNWERCnfvCZDPI4mo=;
        fh=627QupjP+edwo2KcX5dHXyrwns02iT07WCmCfSZOEjY=;
        b=QpE51DoRw6INA7Gfcix3xC5VKqP8ZMM5FZwiqi4arks7xNR8LnK757yl4bC8B/OYi5
         VPEzBXhydnwMcYiEXdaHsadUOBf4dQYdAEFfE4/yyWp4AqmLcIfApHmjf5sFLLg3Epnn
         cn6gvBImvUCHfxbPkDI2Cxt2gvDpoWrZcBym3WpJcmIMmxt0EgWv54r51x+LFL0VxxL6
         7rZ5PWxAuYpPqsK+j8p0D37mOtRfz1/cKRVTXzzppT6Aj8nmhZWceXcDm3lYAV7MEjeg
         mhakEuyz41+BKK1M6IO4EYvfNCp5kT42EW4n4gPPmCjUN4op39RT1HLZX4mpDW/s4wEv
         Nhsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QBUlGF4s;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b49cb7b1cf8si528837a12.0.2025.08.27.15.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-657-fC3PEug1PNexc7Z1HEH41g-1; Wed,
 27 Aug 2025 18:05:31 -0400
X-MC-Unique: fC3PEug1PNexc7Z1HEH41g-1
X-Mimecast-MFC-AGG-ID: fC3PEug1PNexc7Z1HEH41g_1756332326
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4E647180048E;
	Wed, 27 Aug 2025 22:05:26 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6585F30001A1;
	Wed, 27 Aug 2025 22:05:10 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
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
	x86@kernel.org
Subject: [PATCH v1 11/36] mm: limit folio/compound page sizes in problematic kernel configs
Date: Thu, 28 Aug 2025 00:01:15 +0200
Message-ID: <20250827220141.262669-12-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QBUlGF4s;
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

Let's limit the maximum folio size in problematic kernel config where
the memmap is allocated per memory section (SPARSEMEM without
SPARSEMEM_VMEMMAP) to a single memory section.

Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
but not SPARSEMEM_VMEMMAP: sh.

Fortunately, the biggest hugetlb size sh supports is 64 MiB
(HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
(SECTION_SIZE_BITS == 26), so their use case is not degraded.

As folios and memory sections are naturally aligned to their order-2 size
in memory, consequently a single folio can no longer span multiple memory
sections on these problematic kernel configs.

nth_page() is no longer required when operating within a single compound
page / folio.

Reviewed-by: Zi Yan <ziy@nvidia.com>
Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 77737cbf2216a..2dee79fa2efcf 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct folio *folio)
 	return folio_large_nr_pages(folio);
 }
 
-/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
-#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
-#define MAX_FOLIO_ORDER		PUD_ORDER
-#else
+#if !defined(CONFIG_ARCH_HAS_GIGANTIC_PAGE)
+/*
+ * We don't expect any folios that exceed buddy sizes (and consequently
+ * memory sections).
+ */
 #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
+#elif defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+/*
+ * Only pages within a single memory section are guaranteed to be
+ * contiguous. By limiting folios to a single memory section, all folio
+ * pages are guaranteed to be contiguous.
+ */
+#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
+#else
+/*
+ * There is no real limit on the folio size. We limit them to the maximum we
+ * currently expect (e.g., hugetlb, dax).
+ */
+#define MAX_FOLIO_ORDER		PUD_ORDER
 #endif
 
 #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-12-david%40redhat.com.
