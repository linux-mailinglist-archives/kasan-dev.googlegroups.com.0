Return-Path: <kasan-dev+bncBC32535MUICBB4PYTXCQMGQERTY37TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id CA746B3035B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:15 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-61c0a6d6c54sf2809822eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806834; cv=pass;
        d=google.com; s=arc-20240605;
        b=Goos3h0XL4kXum3gdza44kdPJRFrydu3meNl0H76jdC2P6ROHvnfy/vVvQ0mjXRPLf
         CDBoXFKUGXkgoKA5iFlrOTyfdCEkH1M9jJGELBj4c4xJNy+VULPBL/qxxNTr+m4ImVd/
         C03ol8/pHiblSu9twkSkpErdHM2SiRjr2g0wPPtzvxMJcZ9Q7jGcDSxN7095kvMw+89J
         n/+M/m4uFUVhAeUstozGcBHxnod6KdwiCO7+cxVMbUXQ/OpzRnF93Ey+5KFEFYljyqGJ
         FN09jO1vgzVBpU0W7f412OncrFIgdnhgxdaZEZ7BqHyRbrQwWivEggoBrSgwE+SsILQZ
         Y3CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7lijvQc3ZZbRTI5pHXCBjjKZ8u5dxFoqbfRrbMdUEsU=;
        fh=Wn3BbSS/+RyL95Nrf2JXL5eQ3PqkJqs3B3MrsICSOGc=;
        b=d/mQNxq63jorGSyt4aNWmbUTCDV+2za8Ue5W0K4CdVU4Wqatcnc/fa1iUMx85UW8lG
         uBmAy0rVwZsUzSQDKaQ9PTN/QluspQ7Q3tfe9zsowbO1VEQzfBxWZXyCb1ktshBdVEF6
         RbUyyZLO+mpNBoKs7UOg8jV5NrCO2H8qwTUFWrBKGnyJB6zo5a5/pbP6RrSvBhXvn4CB
         js+qAiWGmoCGFYeW/tyojLVg1GXWAbJR/YkLIhX4eLZc7iStRT9CKJjNaMKj3l3Hr1QJ
         TDiXU9N3zKdu4n4RGwZYXFN2/x2pIRiOYabAeUAhgA1E3Y8GvyxjxdkCKigJUq7PWUbL
         A6nQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=I6549wKT;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806834; x=1756411634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7lijvQc3ZZbRTI5pHXCBjjKZ8u5dxFoqbfRrbMdUEsU=;
        b=HR95Yh7rHiOGJMR02J6uk0bbEQ0Txvwx7JrQhETgYfZLM5z86irEpTFfCLCPY7/ioV
         KLj8SRq9QRsi8XNH3vHsif7yzLjp3E/vQgUrrJYPyhNzAnGyisXcsuiZL5zCw9pn8ydJ
         qRdkBUau6K/PpVb4mwETOOYDJ3OEBj9ZK42j0loVbRalKFWGOMWFmybkIWDPwxtbvW8d
         T+KHxw+/sJYJt6L3DPhuedtlKANslshoVSui4xy1P3so9jdWeqPMdZ3hOA7BDXRdhy+G
         m1BgdN5HJY9WAwtThdHwC3qT2ZloNbZboOGGq7Iz7VZJI5tUoO1mddBQpdaLjp9aGYXu
         Gb5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806834; x=1756411634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7lijvQc3ZZbRTI5pHXCBjjKZ8u5dxFoqbfRrbMdUEsU=;
        b=qTJ4OMkrqY7tYodJtD8aAayYrZT0GNij7weahjFbTpDRccljUsl5ZEH/vT5tWMyGTR
         B9mqk5xwlqwqd7Seu70YsbmPaQE2lHb6YuJZlbtZ2xqjGk5/SXNy2T89Jh8qBbMsjMUR
         rzkHXg7p84vKZi/OdOdW0+0NHXdVJsYLZW44LbbIZpbjbPevjPTavAAIBvCN4I28viHG
         A/HsmCYX9G8nbS2QDTCDGdKMYnbYZbDfoFudkNHFkx1/yc9tMnU0njW8kpsQIKBXYc07
         kHDOp7i+82l+dy5YT2lsif/Pn5lgyOIpES7Qnwfqj/FTLucmEtlJN6L4eLPxAuooVDwL
         A+Iw==
X-Forwarded-Encrypted: i=2; AJvYcCV5bN6ZufLZ3UpbcuvIXZ70QL4goRmukCTczQkHW1hYX4JbzVZPqy8xICYhrTDsQu5f8+UAnQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAWzC12zAFvrhCE3hcR6CXQShzg9bHxDJTVr0MkEwbuHcC7lkF
	uIa1kMMCUQnMv4nDNP4XosM7qqjxrU9qE+ce7jRckQdM9byr4dTQlsRV
X-Google-Smtp-Source: AGHT+IGKadcyVsyrX6IM3H3s3EwFij3QSpmdhIvXMfGFWZPQSrgW3MapDiquTsiRftlg6+G5IQ2x9w==
X-Received: by 2002:a05:6820:812:b0:61b:7d22:d55e with SMTP id 006d021491bc7-61db9ab1364mr304524eaf.2.1755806834062;
        Thu, 21 Aug 2025 13:07:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuyAukUZWN7pQ5QxjliBtGk9M7okQmPQK3wAV90qYyYA==
Received: by 2002:a05:6820:6302:b0:61c:477:c6d5 with SMTP id
 006d021491bc7-61da8ce91c7ls232268eaf.2.-pod-prod-09-us; Thu, 21 Aug 2025
 13:07:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0ot8QpnZ85ibAQzevL71vEDEBF/ibF534u0ECo17LzaB5OmPxNux7YeYksHwGjMvDR6mGhKdZd68=@googlegroups.com
X-Received: by 2002:a05:6830:370b:b0:741:b71b:391c with SMTP id 46e09a7af769-7450099c808mr393550a34.15.1755806833153;
        Thu, 21 Aug 2025 13:07:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806833; cv=none;
        d=google.com; s=arc-20240605;
        b=OQ3EUc5HjprKoH/Q6NA/IWTP9LWZNmKQpfRWrS0ZAZ4kIQ6s4mqY4w9K5kMOy/dWS2
         irojbbAkFrq7WF6D5UjJrbqHEYcT8Vf8cN9wF0aF+39Vn3KJOR7R0TiH8bIMo9TtNfad
         w/1Cb0ByRPO7/aZJbP8wopV6Pu8uTDF+GTd/JXtputCD6DOsLjJiwdlwHXGRJuJGoVsF
         o2ftgqrm6byGR7pUDgLOiGEg8K49g9upHoDNslJPwSk9tfD9G+9sS8O3J+LMwUaJXSyG
         eBK24rQ8pqZHuod1+zBtMLY+6uLFHpJnO8/P1qXnc5mHNfhOx7nSHuqSfRhsjcQPZkKD
         WhVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XmvTcrL5C0dM7rPtm73IEcsYc8PUVzmaMdzwCc2EnvI=;
        fh=3G9+n17WXtBwEJooYYEtL460RCz0ix5eIr0+//xPGUg=;
        b=Bt8+WVX5f5LnTUFkExpnVys+BtLA8aqdbM7MvEFA3oOau7+j1NuKlaysbddM60RXei
         I6N2Gu1eV9yzLdD+3IQJWk8GRBlTB3xXzsIPXP8K5CcQzcIdiwo/THknxfXYXr4Z4kel
         04Wfjmm+9hWxPPCIgGeABT7S43g9O4EWhVSmaL2fRdW86QfACvY7L/X4hoifGi7GSNWZ
         XS778OVnGlF6yfcsLvpP2JYEKsvdKIj8dNIWU0OxTO/l3udbJgI66+dcCOnU+vtKCbcF
         qP27VXqa+CAGGGcWRF/S8qHyKKSUWvFQJd8ukx2XUnSRUthasy2TiEgwN/abYXoujqjM
         Y5VA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=I6549wKT;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61dac6bdcffsi99488eaf.1.2025.08.21.13.07.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-528-kQOw98rZNLitpHtp25LIeg-1; Thu, 21 Aug 2025 16:07:11 -0400
X-MC-Unique: kQOw98rZNLitpHtp25LIeg-1
X-Mimecast-MFC-AGG-ID: kQOw98rZNLitpHtp25LIeg_1755806830
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0cfbafso7804115e9.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0HB3n2jEiUV2M/xumLaL3sbCbjPILwC5uiSnueM72PFyoZsZGKFSR97vA38CRD4U7oYwKPZokyQw=@googlegroups.com
X-Gm-Gg: ASbGncuKHSlyI9Gnhhkd5Aw3NJgN9G9+FpDv5ljuQQppNYXG9z9tupAjj5sDt+Epj2j
	gMFyxhz7OgE8TA+kRAsmTK3YH07192kDxq2fuSfcZGWilFPUz+d1A3+YrULOh0T5y3HcD4KBz0+
	UBSSKv9+cxlfE04n8zux+zQibvs9PQUUu/bbMJQUUXN3WG74OdE0P1Ji3T3cI9K22KDYLs6uslz
	lkvxhGcJD7h3aKUFZbCRJnh0HQ8f86FT4mJmHCTjzqhpbdcwrjaVtk/gObziaPNd3Ovdz0HnjxD
	D7haOk9L7zmn67cbkOmcxk6UDojPYggB31INyTaWtqmVU+EPKtwJ2wS9KJ6yw8GhUL3fL4CfOXc
	G/94gtHIBblmVt1THbqtcMg==
X-Received: by 2002:a05:600c:4506:b0:456:eab:633e with SMTP id 5b1f17b1804b1-45b517c5f34mr3673955e9.17.1755806829538;
        Thu, 21 Aug 2025 13:07:09 -0700 (PDT)
X-Received: by 2002:a05:600c:4506:b0:456:eab:633e with SMTP id 5b1f17b1804b1-45b517c5f34mr3673145e9.17.1755806828996;
        Thu, 21 Aug 2025 13:07:08 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e1852asm8722665e9.25.2025.08.21.13.07.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:08 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexandre Ghiti <alex@ghiti.fr>,
	"David S. Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
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
Subject: [PATCH RFC 01/35] mm: stop making SPARSEMEM_VMEMMAP user-selectable
Date: Thu, 21 Aug 2025 22:06:27 +0200
Message-ID: <20250821200701.1329277-2-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: gZCRV0nHQTmffTOHFqZD33hJZ3DY3VY0bdRmNQKSKAA_1755806830
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=I6549wKT;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

In an ideal world, we wouldn't have to deal with SPARSEMEM without
SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
considered too costly and consequently not supported.

However, if an architecture does support SPARSEMEM with
SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
like we already do for arm64, s390 and x86.

So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
SPARSEMEM_VMEMMAP.

This implies that the option to not use SPARSEMEM_VMEMMAP will now be
gone for loongarch, powerpc, riscv and sparc. All architectures only
enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
be a big downside to using the VMEMMAP (quite the contrary).

This is a preparation for not supporting

(1) folio sizes that exceed a single memory section
(2) CMA allocations of non-contiguous page ranges

in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
want to limit possible impact as much as possible (e.g., gigantic hugetlb
page allocations suddenly fails).

Cc: Huacai Chen <chenhuacai@kernel.org>
Cc: WANG Xuerui <kernel@xen0n.name>
Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Nicholas Piggin <npiggin@gmail.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Paul Walmsley <paul.walmsley@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Albert Ou <aou@eecs.berkeley.edu>
Cc: Alexandre Ghiti <alex@ghiti.fr>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Andreas Larsson <andreas@gaisler.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/Kconfig | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/Kconfig b/mm/Kconfig
index 4108bcd967848..330d0e698ef96 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -439,9 +439,8 @@ config SPARSEMEM_VMEMMAP_ENABLE
 	bool
 
 config SPARSEMEM_VMEMMAP
-	bool "Sparse Memory virtual memmap"
+	def_bool y
 	depends on SPARSEMEM && SPARSEMEM_VMEMMAP_ENABLE
-	default y
 	help
 	  SPARSEMEM_VMEMMAP uses a virtually mapped memmap to optimise
 	  pfn_to_page and page_to_pfn operations.  This is the most
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-2-david%40redhat.com.
