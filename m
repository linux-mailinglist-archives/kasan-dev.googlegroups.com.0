Return-Path: <kasan-dev+bncBC32535MUICBBJHM23CQMGQEJGJM3QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C24B3E833
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:05:12 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70ddb4037b2sf119725066d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:05:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739111; cv=pass;
        d=google.com; s=arc-20240605;
        b=lTwUUAaUBCg/mUXOc0tUqwQXlipwlScZf3Pfkwq6eKw1me2ySxSUcqrUXkQ51j/bst
         0FMIB7eUJTaPpWCFypU33ohGVJ1xD/4Gxxs437fTCAGlObYYRbaRwf4diA4iOdW6zv9W
         VVyyYtfoeunntTnQM8egRSaJSdnbWKKiEhsZptPQi07RTc5/3mXqUtpPgX+g7+ENQHE/
         wf1GrKfFE00Vu2jbQIUj4ZbS+qwYNzFs4MG08Rq1qAGygpvCxgOYQnRp+crpugjufC+R
         +qhPL48igTJGYuii0Nq0maDfr8IBxxSoMqCrtobQU/vWudNEDSZthJAcsNVTcOISSJVK
         Qduw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=CJs4s5f/M3hCIDa2Vn69LkLVPSgv63iRDPkFZXX1WC4=;
        fh=35JPGAaApW/ixYWRWpaB8cDLQ1//KCdTRrPfih71oWs=;
        b=LgIbZ1wxypNVrZzqxWvtQEsnc2ut8QaXRbhfiqmDyzUAIN+FptyQJcnq+Q4D5u2jv+
         tPPX69K6g9R+SubNKuXreuBWMmI2w4Fdd2C9lFjL7j1n68k9JK7J9ysqYTP3qTHFf3n1
         npb5Ig7nw0A+Pn8vJR1p7DfOVRr9O/2HhGMFP1/+GYTat6e0thqx613mgn6Pdk4GiJlv
         X3vQ2wc6ehFxKjH444AfjFQ2RTLDS0q21NNU/BrffQb9LoFnBsDN92FK4GuxZxzgecdv
         lO7o3TD+8/hMJuRj4Hv9N1hkM4lMMqbgI0IKE/+HD3jJD8r46aXjPrsefw+FZawBOr1V
         rZMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gpt7txwl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739111; x=1757343911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CJs4s5f/M3hCIDa2Vn69LkLVPSgv63iRDPkFZXX1WC4=;
        b=uCUAKk4NIp7KK3IZas8ognwJiVUPfLmtZNz7opeADleHS98vYqhWjmnTDtr1uHpDNC
         0LD6bvQT5Kdi5wvbKiqQSSPMbGw65K5xl7ksEaeJe3pw8NmRxjIHQdWXAf1m0UlQ4jBC
         lH2Z21urOZ69WFbnj9uJpGwY0aNPZfaQNO5an6wwC9oxq9craRKBT7TaujhzEqMoIYHY
         KVKgMObda5ZZWonIWnC508enRT9B2JlMp8RbFVJHdDxnjL1ohMvrK9z53O8PvKSoMG2U
         hyfgGF5G9G5ee0ryAWl6h4ShSzYQX2mAjEnGxZKRyAQGN3zMOq/h7Ym2NOf+rWf0AK4D
         DcYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739111; x=1757343911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CJs4s5f/M3hCIDa2Vn69LkLVPSgv63iRDPkFZXX1WC4=;
        b=HYd31k7dycsEOgJ5SJHiOzIB7MTi7tI2P/SuiJpkXmLhMEENdPdUyWtr0w3L0fLgmW
         QZ9rHASGWhWZ7JkDq1+z0F0CRPz53gpvHqWrmQxiuAYLM+OEuLGcVoEWuTWmf2BFydls
         Zis46+Rtq658YpAbXilP8BocUZnXCuPObF0tcZvO3O5mMKpgje3h03m/XEwQMzspmruN
         1gimaUOTN2vO8J8Fz6XLmtagEYw6Ch/QY3gpwfKq03e5GoHxsWebdO9beoSl32pnk/ik
         YxiUHfBLKmZWX79GkZypTk8rai20Skpz9gO05JB0SKVgcJQQCE2fIwP6DlBLlNDMU4Qu
         sEpw==
X-Forwarded-Encrypted: i=2; AJvYcCVtRj94BD5Z/As8vbMI71ratDDyNPMRJOxJMmycpOZwdnosizTuePchY5qhprZLNDYkkVUzzQ==@lfdr.de
X-Gm-Message-State: AOJu0YwfzC2Zd8QP+S0VRKdYfR+Y5TvVrwkgQoB3iQW5dRuGbqebYkbG
	bd57zr9A9kOKtJAk6oRjg+W6Pi5yzO6rcUTdAdqAGOS/7U+kMKArInYk
X-Google-Smtp-Source: AGHT+IEkupYt/rpUqPYWH8cNY1QcviGfPfMBIpsyg1LWRlZHf/83OLlYpVSh2adMa+NwElVa09oo8g==
X-Received: by 2002:a05:6214:cc4:b0:71c:f018:1b21 with SMTP id 6a1803df08f44-71cf0181cd6mr22758316d6.22.1756739109046;
        Mon, 01 Sep 2025 08:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdY6yTdgMiBA4ItpxbWtRxPpWrvF3rtFf8guveO0UX5TQ==
Received: by 2002:a0c:f083:0:10b0:70f:abdc:ed0c with SMTP id
 6a1803df08f44-70fabdcf296ls21305996d6.0.-pod-prod-06-us; Mon, 01 Sep 2025
 08:05:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXU8sjtRUm5afNYX9yeyLKt0spkg6f5Hn38YnW/GdQwqi7A3N3F3ytKJWEdxtS6WYVeulLr/QZ2dl8=@googlegroups.com
X-Received: by 2002:a05:6122:179e:b0:531:2413:ce62 with SMTP id 71dfb90a1353d-544a02a8e35mr1830047e0c.11.1756739105501;
        Mon, 01 Sep 2025 08:05:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739105; cv=none;
        d=google.com; s=arc-20240605;
        b=OQojhvQm4Hh5it9ys0+8q6MYtTsSZ/8W6vR+9/91VepIeOIScQqIj1nfofzKww9dU5
         KCrYeZVGSqO5LkyT2JqdMfqhUP+ATV8/SZtlp858JZynKssCTCM+MYEux7/IczG+C7H3
         sik4Ekmvs6KwSJ30s7/HbcSEMdTol9Y5OsDKoYsOV1ljv5BpcAe0Eu0IDVzKJFNEt1nH
         9T3TopVXlE92xro0B2Vn9c4tPFcosi7GOtugrbuoCIeESdsynxrmpKWxrgM82gJIHkUX
         BpybnVC4+XHJc99bDZvgqZ/XmtJK8PiczeyjRtRB7bwe1WvbO2fbXVw83gtNavJhIuwA
         1nQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OLi4fM0QNdibiBA1k/MTnIMFu1+uGtd+Ar5TgdqnEIc=;
        fh=KXdQ89mIuqeAuqUh0ARjr63vay9N66arKjAOYeWZBL0=;
        b=KsqWr/kvjoUuSETZPtW5YclmPtfmoRANBIxxf24zKLnSuPSGrGJxboHCAhexNtrDnr
         pml1uME8xLINpqLh4cLZWQ5mgvCWV+2HkclQpwQzT4VQot5T2iCEZYVQZ6dhFHpVmnY2
         p/+1dOxfan2w4zDOxWg+80avNv2hzFOnCvI4SL6Kfyx4IJDcW8zVjKgg3XOnIZH4Xe0v
         cgcBJy/jGLJ/0qsVXBlLibrOVGrNxcIC+lbkXYqXDSIjZ/lx7YR8YeEVV7M8NTy6T4G+
         VgZI4hYQpBaGFcp5CzQuzw16tPkzQxpGCB+D0/PTKFQvDTguIMm16yyqfBc2x1IVTWjE
         LmhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gpt7txwl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70fb27334a6si2358906d6.6.2025.09.01.08.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:05:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-596-SnJjvg_JMVyx55RP_RE7oQ-1; Mon,
 01 Sep 2025 11:05:02 -0400
X-MC-Unique: SnJjvg_JMVyx55RP_RE7oQ-1
X-Mimecast-MFC-AGG-ID: SnJjvg_JMVyx55RP_RE7oQ_1756739097
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BEDFD19560B1;
	Mon,  1 Sep 2025 15:04:55 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1702E1800297;
	Mon,  1 Sep 2025 15:04:35 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	SeongJae Park <sj@kernel.org>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
Subject: [PATCH v2 01/37] mm: stop making SPARSEMEM_VMEMMAP user-selectable
Date: Mon,  1 Sep 2025 17:03:22 +0200
Message-ID: <20250901150359.867252-2-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gpt7txwl;
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
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-2-david%40redhat.com.
