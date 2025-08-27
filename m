Return-Path: <kasan-dev+bncBC32535MUICBBCMBX3CQMGQER44IRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A08B38BFC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:03:03 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e96ffa1b145sf289985276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:03:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332170; cv=pass;
        d=google.com; s=arc-20240605;
        b=AWY+zHR7n3FMkeT4zWMDbYipeMrO7wbdJ88eSD1r56m2NExSS6AAZdLeoqRC5wuVwh
         HAIwh2AlISkraiG5Rv9bxqyGL1q5DAGYEgq4/M0oncUbHszBN7U9++LH2NqMfWp+3KQl
         lZB2rWLbsGPmqGLU1krR6KCM7KZz39IHCd1x/SqwpXYKauIQhzO6Ae6AV48zC7Bsp3Wa
         RkWbc83g0bHfNTUZv8iGhAguoAa2hMiGdSWH9oyC4ZaZpOSZmQU/IHVrmt0lls5dxE/J
         vSfj5WQHdhtAz8pWnFV3lPKH34QKUMTKhIp5tC4IqA65i03ooYkxF/oaHumrdYB+NWCs
         0Cug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=F0JYyPKyiRXa7j6kL9agZ1LShKrIX9jgU2GIm7l3eI8=;
        fh=HiTH7VaJIebUm3E9qm2FBr3JYGXZbkMM4Emmegi/T+0=;
        b=A9yoMZ2RACEWgrkqtgB3tJRbLCJuRCA6Vns+dggeiTHKGh1/1pwtfoxIaXWDgxP+D+
         AyC2FUJ7QnmC5Fsjm0UjIU2+DXBkQ3c20pe/mVfoRetPWQLnperxoAcb1tPvA53zmGn1
         KPt/9MVgehNaltdEV8DME08WpOnpjNgjm3Jo+spH5IeoiwYr+UBYB1efZAPQXzZgspAe
         O11Ay7gmFhhZKS6I1fW+GixwL79FCFqUS95W37jfOMekIryjPaNWd3Z3O7MKEbdXNWVi
         V5mRyi8p0zvGV6g3uUxM3rg/MmILJTDLp3ABg9nVhTTqD3Xl9/eOLN1n8+M04CxUpvdW
         +gLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PDcuiYHw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332170; x=1756936970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=F0JYyPKyiRXa7j6kL9agZ1LShKrIX9jgU2GIm7l3eI8=;
        b=NK6vuw2qzSM/1fFO95bbRy89JaQZhWh10CXyb8FiAxXeOB84jAOQo6iPgVPgf3D8EZ
         0qnOAmo/Qt2Uxvcrs4BijKkZROA5a4Fr8qHoVRWKtVhsNJ1/5bu1UcNoE0La00qtutHC
         QaQHRpJB1oltNULSStNHLNaDcDxC37U6Xk3n/4d0MZKSO3d7Bc9SI1oG3Ap67lFPe1/b
         4Tvb98Y7IhEXNQAjixf+M57JJsNMufMEQL06DPff8b/cON480QXvirnxYdjGvscnmfPh
         c1+YJl7KAknPj9YdxpiHvPn6UmtoWYhntboteLRNOKPOyC/rgtnp/+QR4PJ2VmNL9dtJ
         KfQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332170; x=1756936970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F0JYyPKyiRXa7j6kL9agZ1LShKrIX9jgU2GIm7l3eI8=;
        b=Y8oaXSzlcemklA2k/3iW1snVAr5kYIZoczmKCwEs8oWZXGKNbBWYALmKdPXVATuPXr
         OD2JYNpLSY/7wgVfWeoOBDBdZ2Xnp89v6vvlWjeCgiU5/W+IXL77Bf5uCoRmfUIz121w
         kihFKKjNKiewWwtkaXlv+vp/EzGupieNJA0hB0NnZbyGYrW9q5n1o9xBtEpE/nw740Mx
         Ii1/U/SMLXQgqt+i0Us7VpyuQWV3HkxmQq9xVY1ugrZD3mDQjxR4zD5CPrtDnzDx951A
         0RWXzFcNifOIf8UxnQI15Jra9VVHtn1jAp8E8KOKPWQHJ5vlH1OriKKZSl2t9XrOo1K5
         Ck9A==
X-Forwarded-Encrypted: i=2; AJvYcCU/JuBlaehhu5rHDl065gsfx4jUrcvJ7vl5SL6FtHTNttsEE8QmqhtwwyhxzMFRvbH58STksQ==@lfdr.de
X-Gm-Message-State: AOJu0YybRsk6Bp/NaT58zV+HpQ6dln3P8WLXKcf1Cr0Y4GE7Hb8u2iOd
	nYTeRChh465G1lb1wI1R+qMib70kcP5YfaLt79YHtf7lYsuwavr8qIwY
X-Google-Smtp-Source: AGHT+IEv+TS2gNK9osSE2ocdUYNtY61b41Uj0ZaUwnBnSI9z/gqL86W/UKHEHDmLa+e/Z4lI0Quj+w==
X-Received: by 2002:a05:6902:2d08:b0:e8f:db21:9544 with SMTP id 3f1490d57ef6-e951c23996amr25406745276.20.1756332169839;
        Wed, 27 Aug 2025 15:02:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdq/oz64L707wk7CnAtX/GvDCjJ5QoRjVlWSYnr2yYxAQ==
Received: by 2002:a25:ae84:0:b0:e93:476e:3d94 with SMTP id 3f1490d57ef6-e9700f07e1els155065276.1.-pod-prod-07-us;
 Wed, 27 Aug 2025 15:02:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8xMC1l13wcfW20tG22a9TWFM8gLMSCYbaygrdecjq37B3kldIgjc0NxlPIdqcxF3WB9AProCcQWA=@googlegroups.com
X-Received: by 2002:a05:6902:1103:b0:e95:2ae8:d3f3 with SMTP id 3f1490d57ef6-e952ae8d5e5mr22225377276.35.1756332168283;
        Wed, 27 Aug 2025 15:02:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332168; cv=none;
        d=google.com; s=arc-20240605;
        b=hRfMjnneuoFH6niXOI7R8yI0YCi7dZ+0xaJVkoNwvU4TQ0PaX/aKsb8+yJ6Q9xta93
         USLXVHmehJOpZn2nXwD8biTqVrCwpYSXf7Vry0r3WNNXl39yVz3tqQdT9UD+ayuLKPDw
         26f1svXU1Ex3QwVpYddCXC1AvjD8nrmqhUOev1QaBPgevxosxzBuclx5TiW+PBrwUiWb
         3CTPJrB1qV+2molIUlaeS5T5JV3Nv4TOGz+NGLb82ILAKMOOTDFdZsq83d+h/EQTvYFr
         ZgwHI0H+zivJJtP6xWG1eq59SkMaVkAmlwY1wRVRReQF4QrvH8A9qQpT7SUy4i9tU8Cr
         BRRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sgMQXV8BYAImHmyQ+Wvnc2XZf0WEI6U3t/6BUO8LjHk=;
        fh=sVjVjdn5pTshKMQo9/9KnbJaWpNQgeh41Y49IKEMU3o=;
        b=hlbNofd0kJYBw838snrf9c9JLoSpiE0M5/IXz9MdOIVvzlmW+bwdyCBtzE+jCepIh5
         57PKwYtDPDLfBUdmNTaWS3bifTBqWW+obm8z12DsTr5depZbgSdt4N9hr6EeXgmGYL38
         PKAXYTS1pMGXncJ3UMRh8wuEapDPWOv84KlP7Ky4pbFm2T7ets8f99zVRmE0a6iMgidN
         3FEPnyY81XhpaCvgW6IVgLq8sq7lIqktNRr58kEwIbjkjjqsApvVMJLp5i0TDxukHw1/
         WWXxBb2i7veezbIyakqnKZN57eQsLl0QpgfH0+UxOwooyjarQlJyzPrXfNBdeqgGNSg7
         sTVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PDcuiYHw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96fc73fb40si71480276.0.2025.08.27.15.02.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:02:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-528-yCgqSrvTOiCyp53LlG6ziA-1; Wed,
 27 Aug 2025 18:02:46 -0400
X-MC-Unique: yCgqSrvTOiCyp53LlG6ziA-1
X-Mimecast-MFC-AGG-ID: yCgqSrvTOiCyp53LlG6ziA_1756332161
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6290D195419F;
	Wed, 27 Aug 2025 22:02:39 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id F3A0E30001A1;
	Wed, 27 Aug 2025 22:02:18 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	SeongJae Park <sj@kernel.org>,
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
Subject: [PATCH v1 01/36] mm: stop making SPARSEMEM_VMEMMAP user-selectable
Date: Thu, 28 Aug 2025 00:01:05 +0200
Message-ID: <20250827220141.262669-2-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PDcuiYHw;
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

Acked-by: Zi Yan <ziy@nvidia.com>
Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Acked-by: SeongJae Park <sj@kernel.org>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-2-david%40redhat.com.
