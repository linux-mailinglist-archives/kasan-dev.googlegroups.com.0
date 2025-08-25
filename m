Return-Path: <kasan-dev+bncBDZMFEH3WYFBBNNMWLCQMGQEDU35IGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 64505B3480E
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 18:58:31 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e96c3f851dcsf1897107276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 09:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756141110; cv=pass;
        d=google.com; s=arc-20240605;
        b=VQxvltbXP2csAKSJSZpDb5ApElwGefFgmpcgUomcpjSbEK4bszWq5Z2o6wHm5PayQq
         /VvhUwphn0h5CcsRjuzN07Muz/jCR8sx85ZkHaUTPkhcS3t3qORl2LCbbZFudrFgsISd
         hq5fsTToT18YI/MzoFfGqWyI06P0AcLagnDLAO8sFaUS8EHphkAvYxXOkoxL3HGGp9Bi
         osxCGjNbaHL0XhF/SS/utTrUi49HOQIrJv2dm1TfJo1RRt7eVLsZscloSND09jDdoDPo
         2T2/qmgEwnKWclI7EjrN+8PIQRl2p2SkLlFR9roUFDB+eXjNMc1lF2zy3KBOBiDPyxrM
         wUWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pCkQbDYeg+y9AHg1wBwCYNGAVYOI6L0hRcwoNK8/97k=;
        fh=fF+IcTnwOAIEOeid3qG+/p9g9bbK2l9FD86t2u7z6L8=;
        b=O02f3ynLR4chuzeiPDpQU64X0sLppA9UxtoggE1WbRctphukk9Aye8gNSgp/n8PO5e
         CNYHV7sFX2JMlBoMAT2VKh8plHMJPKhM3AXU07yOQoY2Z16lzuqkcvIPxHXQECOlP+0s
         9pMnj/fBJAFw096HgCV7ghUGbmIyvADrCk3OZnp0PTMmt9/oCqyd0WM1eAbnbf6OwPK1
         yRCrOQuVSnpkiIOramXJnAS0rzZpddykmAHDHbXdUjQmCpcXa8R/aP6Rf3V88cBXT6vQ
         T/aS70bSEXw8QBDtnJG03i/1GaWN9/0dwvxeJsvGWlF4ZqfYF6e7g1F0nmbsSRfI87gM
         QOsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K8EPeL9r;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756141110; x=1756745910; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pCkQbDYeg+y9AHg1wBwCYNGAVYOI6L0hRcwoNK8/97k=;
        b=RjRUBLysw33X8HqoMt3nAO22WPOWc8dqhQtV6w1LUafB1idD9LrOvUp0t6/Y+478/r
         t8MfYvdM3q7YHJkYu0wPisBipD6Io0VccNFLIvK2Y4m7tIRLt4+c6bQWOTUN1JNNdtTc
         GSdy/XmooH7Y+5PsAdu7QPvF9DD9+yBtqEv1b99kladTqnPsrOg9nqa1dv7NM6tVoYaA
         CITujpbT8na2/yrbpx0+J7IVtW0ZsjKEcoMa37xgPBxjaZYlyNpsoLY8PZ/ML4RWOphk
         Wo0I0cXwYqJ/+CZbiCjGAyKOXJAUxiRrjoGy5pO5e/OThBaK4+E0EJoRyJj2pumIl4bh
         Th3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756141110; x=1756745910;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pCkQbDYeg+y9AHg1wBwCYNGAVYOI6L0hRcwoNK8/97k=;
        b=O9fhiik9VE0ESzHcZNqxSSU5w+MDEJo5VrAg+Z4cBGYLv6O3sgQzMcEH87UxVGMEQe
         Mg2I8PKKraao7umygnuoMk3lCalqoSvTnDUWUQ0Z4bmwyXmVfQETUOCbwiefoyHOvzly
         R8SjAQzaknKucWXc9Zn7yroMwPXhUXzGRk2PJSl29oSPioZgmqe307T3FrD+zwrUGaoC
         5TCViejcBHzkOu8Pu3QPrLCabgV65+84qpoEb7Z0MdQBsiPJQ8EVPmdt6TDJbFnigKfi
         VC+VuXtrVz4hc/3NICmmeYCF3KYEmC7u+LdWmNdfU73yPDj3hgGPAjRUl+qOVS9OyVny
         8OwA==
X-Forwarded-Encrypted: i=2; AJvYcCVb73w4lxLh3fKYfv22xRH+Ae+tZqT9Xh8AWbuksTRwcmta4R+QnLO/YSpiGD1o4Cy0DGFLgg==@lfdr.de
X-Gm-Message-State: AOJu0Yw+JhsjRbrMU/KgKlfYJniN1yTJaO80Qgtivyfdm3bg/+7dGx/W
	05gIA5kmpFbM3JTqZSNYc9857BmWHl210UI0ki6dYDarCkEtBwNkgNa6
X-Google-Smtp-Source: AGHT+IF5b32CD8GvEVZ687/5oT8hC2NAK3Zvec2+CceAFjMjt5EJoEvn3GQUILOXtXgtgxyVpiU1dw==
X-Received: by 2002:a05:6902:20ca:b0:e95:2422:6d1f with SMTP id 3f1490d57ef6-e9524226facmr10858422276.17.1756141109849;
        Mon, 25 Aug 2025 09:58:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdvAsi4BLLztPQJrcSZ5upPcVTIKY0dmX11212ZmUoNRw==
Received: by 2002:a25:c03:0:b0:e95:3236:dca9 with SMTP id 3f1490d57ef6-e953236de2cls1674322276.1.-pod-prod-09-us;
 Mon, 25 Aug 2025 09:58:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgiHDhpxSw+U+pkW5YBSNQ80w6zt9u4KfFV0t/7gdCOx9oj7hNf+aExeHveNS5r74Krr+adcKasuY=@googlegroups.com
X-Received: by 2002:a05:6902:72a:b0:e95:3406:76d2 with SMTP id 3f1490d57ef6-e953406787dmr8538474276.0.1756141108746;
        Mon, 25 Aug 2025 09:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756141108; cv=none;
        d=google.com; s=arc-20240605;
        b=Fd4ZAf9jFRgJ5b+SjaZDOzOFDtSrulB7ChjpqVqs71kkVnliCf7JSZ9M2hOjuoNZ2+
         /SHN1DZ2b7l2QOoLu8WnlTzWvWTMsEesphs+0S4RKmjhLoqh0pToJXeTXRQoMDifTW+O
         Zj4Ap0JDOpLs8CiO3/GamucQ7cs2xVbc2HEnZafrRlVn5QTO88BgL/3S0Jey+SyK7mFP
         KDXY4Zo4ZmB7qmJccgDwKZ0jqUjaHARXdyIf53Ub7uAl2E/FXFIubVbS4xj2HqqCeGKa
         qWLlGraoYNmbvmnTewsl5CrUi5NADtKF98FS4fdp1xhUclzUfzzJTZZsCSVJKUgzJyYV
         D8sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=r72jr2fb8G7h/yyetD/U7kOQIEeXffCRdNoOrm+lHkk=;
        fh=SnWEHMnw6q5A1i5gHssHZhjXePV2/MD17aPBvTeFLno=;
        b=RyWBd7zsDC67o9G6pJQzP2GZOCj5M5OI/zR1MLnsmWlCoMBINkqLM0ktmBOIgXUnkQ
         7WuWxxGhbK0edAA0XnpP5sdm7+CmiQPalE2tpoy/is/EwBfvbKkQuYkB1N3arRDHxva4
         mHHVZwkbpRK0K4K4psB9NmJo04kRCB9QunGQr8/7OZ688Z3mu+lvz94S7B1X3tYaajoL
         mUzxesLkhdVL7uVcZXvnw3yvKqIq7nY+bNV9y5YjLh32FzvMHWV9wwPRSoPdbXgHqi5a
         g7WlVsQIFsopgWrEScWVERDEb8Jyeq/33W1CE37SiVH4bcx81vTfnX+2r2l/+a5tfZl1
         mN7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K8EPeL9r;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e95314e15d6si294632276.0.2025.08.25.09.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 09:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C4B8D43E7E;
	Mon, 25 Aug 2025 16:58:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AF37AC4CEED;
	Mon, 25 Aug 2025 16:58:13 +0000 (UTC)
Date: Mon, 25 Aug 2025 19:58:10 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Mika =?iso-8859-1?Q?Penttil=E4?= <mpenttil@redhat.com>,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: update kernel-doc for MEMBLOCK_RSRV_NOINIT (was: Re: [PATCH RFC
 10/35] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap())
Message-ID: <aKyWIriZ1bmnIrBW@kernel.org>
References: <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
 <aKx6SlYrj_hiPXBB@kernel.org>
 <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
 <aKyMfvWe8JetkbRL@kernel.org>
 <dbd2ec55-0e7f-407a-a8bd-e1ac83ac2a0a@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dbd2ec55-0e7f-407a-a8bd-e1ac83ac2a0a@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=K8EPeL9r;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Mon, Aug 25, 2025 at 06:23:48PM +0200, David Hildenbrand wrote:
> 
> I don't quite understand the interaction with PG_Reserved and why anybody
> using this function should care.
> 
> So maybe you can rephrase in a way that is easier to digest, and rather
> focuses on what callers of this function are supposed to do vs. have the
> liberty of not doing?

How about
 
diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index b96746376e17..fcda8481de9a 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -40,8 +40,9 @@ extern unsigned long long max_possible_pfn;
  * via a driver, and never indicated in the firmware-provided memory map as
  * system RAM. This corresponds to IORESOURCE_SYSRAM_DRIVER_MANAGED in the
  * kernel resource tree.
- * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages are
- * not initialized (only for reserved regions).
+ * @MEMBLOCK_RSRV_NOINIT: reserved memory region for which struct pages are not
+ * fully initialized. Users of this flag are responsible to properly initialize
+ * struct pages of this region
  * @MEMBLOCK_RSRV_KERN: memory region that is reserved for kernel use,
  * either explictitly with memblock_reserve_kern() or via memblock
  * allocation APIs. All memblock allocations set this flag.
diff --git a/mm/memblock.c b/mm/memblock.c
index 154f1d73b61f..46b411fb3630 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1091,13 +1091,20 @@ int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
 
 /**
  * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
- * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initialized
- * for this region.
+ * MEMBLOCK_RSRV_NOINIT
+ *
  * @base: the base phys addr of the region
  * @size: the size of the region
  *
- * struct pages will not be initialized for reserved memory regions marked with
- * %MEMBLOCK_RSRV_NOINIT.
+ * The struct pages for the reserved regions marked %MEMBLOCK_RSRV_NOINIT will
+ * not be fully initialized to allow the caller optimize their initialization.
+ *
+ * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, setting this flag
+ * completely bypasses the initialization of struct pages for such region.
+ *
+ * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled, struct pages in this
+ * region will be initialized with default values but won't be marked as
+ * reserved.
  *
  * Return: 0 on success, -errno on failure.
  */

> -- 
> Cheers
> 
> David / dhildenb
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKyWIriZ1bmnIrBW%40kernel.org.
