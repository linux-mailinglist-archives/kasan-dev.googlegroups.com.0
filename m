Return-Path: <kasan-dev+bncBC32535MUICBB5MAX3CQMGQEBTF6BUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id EA81CB38BEC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:02:31 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e96dc23e87asf364322276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:02:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332150; cv=pass;
        d=google.com; s=arc-20240605;
        b=hP9DfcO7yPej26+ixPez5TzQRJdnFwJntWEd0eJtk77i8eshFz3ClnarX68hU7Mzo2
         YmAIFNT6I07VGf3LAUKUGVwdcOeiumgD98HSfBzcDpuWxPh6dtw4LVYieZ3eBO0CKiup
         32lZhNDSMwpb+8qDDRZhiVPQNR1KykMeBKlE6lKbQ4C2sz6UElWabYJhTGgk1Sr0dZKI
         VjJcPG25zFUggPAx3X7nTRwKRHfFbv/yLdpJNpctmHxqQHNaKhmBBE0VEbT47RD/udBI
         owK17ys0+rhwpF0cSQbRe1YrlbUb9ELBkXTIQ8s4SBe950VAzWV2fPexL/6Vk0a/nzwI
         V0tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=MtIUg//lT+qXoIDLK+mnSneBYF5gEK1bOWcdoU1EcSY=;
        fh=LrAlDBrcYbtpVU2NQikZoj0HUBXCPDFLB4jVU742R/Q=;
        b=JErxBoKrKW8pr8UbjWox6HAviuVscek2AJ5R45sbUrECDmRhCWoZCoiakFCRD+qvXb
         jrD//GgfqC1S0wzMWGRmo4tyvpB1W2fcqJQhvt9BMzWfhku8qLR0EmL7CHDosM2X+G0q
         +OcGaGpRzVytu05m+n+u+HcMO1rL6qxr6JkLNJ6dPDb0d/7Fen6MynTvy4sjveZiFXFf
         +y9YNo9JiXr/ZSH2N/yKmpDtyXC62NGsQOpLtVcbiLBvsw/FTWB1YzWcI3O27DKLf4gU
         bv8zBebzGXOrPsMzWsaiN3CDQfMg36Hs+VviGHidy9JEUpEN3N1VZKRpArkaMCLCyW8T
         7exA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RVIHKJtP;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332150; x=1756936950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MtIUg//lT+qXoIDLK+mnSneBYF5gEK1bOWcdoU1EcSY=;
        b=Cf7L9YVz4tIbZVLVfOTzBGEXC49W4N/jD6BwpwOGL0rKB4+LzQqamwR6Ur8DJluKvn
         HJRhBN59dtxdHJZvmRdLTa7c389ZCyilSdKybIYZPE4Q/91Z9WDwzz3GfExNESIZgEbP
         i5IfiMmAjQFacalmOa4CB/ECJb9zH3k4ypALgJ/NAEGnkNIP1aSvm69/Q6dUNP42mLST
         jQn4lT/M5NvWyTMwLQS7eIuAcGdhRnp7JHkybiYtC8wWQOkQcIXf+Sogee62ej6IpUtJ
         3GzKXEeExcMVsoB1yL6xsphCFwsbti0E0q5ZynWC2eX2KG9gfO5BReoi7mmlcZtEPSYs
         p/rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332150; x=1756936950;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MtIUg//lT+qXoIDLK+mnSneBYF5gEK1bOWcdoU1EcSY=;
        b=O61RnBQlgDapeUAC3qB5yJGy8kge9zifB7QP57IeSII5OlbRFhfehQjK7l/9AUzBNK
         Si4Cd5NE7yYfrivfVYh4beHHc2ZSA7Q5eTw0lWXh8XZyDe18pfgGJyPbNXOcUtlSyTRh
         VTkp8hT8SBG5YspyxpCnjXsFpyIC2jIsEBY+oR8/3QcSaTcrYP4fs2vdt3PAejWWVuD3
         OvWjylkLlIlUAZsZ9FseBcE0rpv33v5Dk4QhFuqb4EUK8hhxarApEih1NpnuoUjXtSVy
         ItvTh3lH9H1wy1MX4M3xnJQm0gCRNIAzmO1jZ616b+16VFGsJ95NScsBVYzz7rkE3FL9
         c0rw==
X-Forwarded-Encrypted: i=2; AJvYcCXaKbMbbo2ov7aqzEI21jZEOc12nHVMpqU0fnquMvUYMjFQKdEOwHTUKh0eYBAkeTeCD4cS1Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6sxn8HrgAkay4/EGbNE0/Vk1r8Hs6VtQkHKG8Z3+Vhn9GoQrY
	3Va6DceyTUq7NW4+Mz/6bKh/dAusAvhfIKnDIg/P08WQU1JBBtrzEnyo
X-Google-Smtp-Source: AGHT+IGHqooUitKo5Hf8pLcdDtCf4StvBSgy0DuBBdeIhsTYmM40mHDhGtB9y4g3WN9IX/9fnz/qKA==
X-Received: by 2002:a05:6902:6285:b0:e97:258:a12d with SMTP id 3f1490d57ef6-e970258a6eamr289693276.16.1756332150244;
        Wed, 27 Aug 2025 15:02:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf0aTVvo/AZEZx3EHFLCD9j006Wi8EMSBVLS6D3V1shCQ==
Received: by 2002:a25:b1a6:0:b0:e95:3946:b54 with SMTP id 3f1490d57ef6-e9700f4df2fls156499276.2.-pod-prod-04-us;
 Wed, 27 Aug 2025 15:02:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbJEIUxIW6cyuPu5dC+J5WHomZ0z4jX+9rtjFqTPirkCXVUfJAdK+iJWWNQ0bAjr2Ac+K7OWA6oNI=@googlegroups.com
X-Received: by 2002:a05:690c:940a:10b0:71f:f48c:adf5 with SMTP id 00721157ae682-71ff48caeadmr161604037b3.27.1756332148983;
        Wed, 27 Aug 2025 15:02:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332148; cv=none;
        d=google.com; s=arc-20240605;
        b=HBPaSEkMhmuTz6QwtJDPyoiffZbteyKuufdqDzkrLFk8DBH1K3X/yZXUEpn7Mcjn7T
         URQpqX1hUOmfxfwTP6RRCiUv3bxgbtnJJ6FMq3bApqjk4EYuZTf8lh7CBfs5FLrYWniv
         MvMUWlgBkQHr5Ugl9xyylVg+vyM9N3/HuTFxlDgGWqvUFYHYwGBcr/kMuTmh0IuRMdBV
         8rAnaPAM13N1HoZJ8jExG8WxEooK6P1w8Oa7nynb/KTwSxgYNvGKgvV3NC2ozlyb5DCw
         TVpa+akh2mISxLEc6MJF9zxOkc9StlRlil3MW7Xmkh8wSlJ9SmcLZqN4j0pXXUKszbhS
         tTpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=f98zaxrJvycSnAQcu/39hCOw4ptNGiOoTMWM+eDqoaw=;
        fh=cz9Xgd0iYyy9wddevnKV8if1jS3PHdenCWq2eyS3z7w=;
        b=eIfhY1qcoH1e0Cunp5trCTbdjvyXybEHVYEOM6PEEaIVtZwgjUYlneZNzZj2/haR57
         E3Kfwm3QWvNCG2ODOn5p4Pvgw1lzDp6JXMd6MAAlv7DNPYb9CIWfsxMg8wVTzuNrLRNo
         b7wlBqjW6n4wYobJ9l2HluU/o61s2Fz9GmlbTwLiPd714nvr2Vn4Q7OIov9dKXR3ymuq
         fLhFLGsmkul/Hbfr55A+ZEsWfe705JwZFLi7yRjQQHWLkpuCFbVPa2BfhKM4YCtgq7k9
         eedEFGNCTe/2tyTc/zn7R4t2jSXvWWACOcmTLdvi1wrgjC23YB73+fcRZtpA9hghdTnA
         g3dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RVIHKJtP;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5f65871932bsi504724d50.1.2025.08.27.15.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:02:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-652-4tIPN8FiOvyy6eG037Xd4A-1; Wed,
 27 Aug 2025 18:02:26 -0400
X-MC-Unique: 4tIPN8FiOvyy6eG037Xd4A-1
X-Mimecast-MFC-AGG-ID: 4tIPN8FiOvyy6eG037Xd4A_1756332141
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 65CEE19541AC;
	Wed, 27 Aug 2025 22:02:18 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id E90FC30001A5;
	Wed, 27 Aug 2025 22:01:42 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Jens Axboe <axboe@kernel.dk>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Hubbard <jhubbard@nvidia.com>,
	Peter Xu <peterx@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Brendan Jackman <jackmanb@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Zi Yan <ziy@nvidia.com>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@gentwo.org>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	intel-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org,
	linux-mmc@vger.kernel.org,
	linux-arm-kernel@axis.com,
	linux-scsi@vger.kernel.org,
	kvm@vger.kernel.org,
	virtualization@lists.linux.dev,
	linux-mm@kvack.org,
	io-uring@vger.kernel.org,
	iommu@lists.linux.dev,
	kasan-dev@googlegroups.com,
	wireguard@lists.zx2c4.com,
	netdev@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Alexandre Ghiti <alex@ghiti.fr>,
	Alexandru Elisei <alexandru.elisei@arm.com>,
	Alex Dubov <oakad@yahoo.com>,
	Alex Williamson <alex.williamson@redhat.com>,
	Andreas Larsson <andreas@gaisler.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Borislav Petkov <bp@alien8.de>,
	Brett Creeley <brett.creeley@amd.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Damien Le Moal <dlemoal@kernel.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@gmail.com>,
	"David S. Miller" <davem@davemloft.net>,
	Doug Gilbert <dgilbert@interlog.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	Jani Nikula <jani.nikula@linux.intel.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jesper Nilsson <jesper.nilsson@axis.com>,
	Joonas Lahtinen <joonas.lahtinen@linux.intel.com>,
	Kevin Tian <kevin.tian@intel.com>,
	Lars Persson <lars.persson@axis.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Maxim Levitsky <maximlevitsky@gmail.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Niklas Cassel <cassel@kernel.org>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	Rodrigo Vivi <rodrigo.vivi@intel.com>,
	SeongJae Park <sj@kernel.org>,
	Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
	Shuah Khan <shuah@kernel.org>,
	Simona Vetter <simona@ffwll.ch>,
	Sven Schnelle <svens@linux.ibm.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Tvrtko Ursulin <tursulin@ursulin.net>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vasily Gorbik <gor@linux.ibm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yishai Hadas <yishaih@nvidia.com>
Subject: [PATCH v1 00/36] mm: remove nth_page()
Date: Thu, 28 Aug 2025 00:01:04 +0200
Message-ID: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: o_5DjoFKV_AMTvhjGEpxSJjWN5D7Qnc16Ozg3x3GGQ8_1756332141
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RVIHKJtP;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

This is based on mm-unstable.

I will only CC non-MM folks on the cover letter and the respective patch
to not flood too many inboxes (the lists receive all patches).

--

As discussed recently with Linus, nth_page() is just nasty and we would
like to remove it.

To recap, the reason we currently need nth_page() within a folio is because
on some kernel configs (SPARSEMEM without SPARSEMEM_VMEMMAP), the
memmap is allocated per memory section.

While buddy allocations cannot cross memory section boundaries, hugetlb
and dax folios can.

So crossing a memory section means that "page++" could do the wrong thing.
Instead, nth_page() on these problematic configs always goes from
page->pfn, to the go from (++pfn)->page, which is rather nasty.

Likely, many people have no idea when nth_page() is required and when
it might be dropped.

We refer to such problematic PFN ranges and "non-contiguous pages".
If we only deal with "contiguous pages", there is not need for nth_page().

Besides that "obvious" folio case, we might end up using nth_page()
within CMA allocations (again, could span memory sections), and in
one corner case (kfence) when processing memblock allocations (again,
could span memory sections).

So let's handle all that, add sanity checks, and remove nth_page().

Patch #1 -> #5   : stop making SPARSEMEM_VMEMMAP user-selectable + cleanups
Patch #6 -> #13  : disallow folios to have non-contiguous pages
Patch #14 -> #20 : remove nth_page() usage within folios
Patch #21        : disallow CMA allocations of non-contiguous pages
Patch #22 -> #32 : sanity+check + remove nth_page() usage within SG entry
Patch #33        : sanity-check + remove nth_page() usage in
                   unpin_user_page_range_dirty_lock()
Patch #34        : remove nth_page() in kfence
Patch #35        : adjust stale comment regarding nth_page
Patch #36        : mm: remove nth_page()

A lot of this is inspired from the discussion at [1] between Linus, Jason
and me, so cudos to them.

[1] https://lore.kernel.org/all/CAHk-=wiCYfNp4AJLBORU-c7ZyRBUp66W2-Et6cdQ4REx-GyQ_A@mail.gmail.com/T/#u

RFC -> v1:
* "wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel
   config"
 -> Mention that it was never really relevant for the test
* "mm/mm_init: make memmap_init_compound() look more like
   prep_compound_page()"
 -> Mention the setup of page links
* "mm: limit folio/compound page sizes in problematic kernel configs"
 -> Improve comment for PUD handling, mentioning hugetlb and dax
* "mm: simplify folio_page() and folio_page_idx()"
 -> Call variable "n"
* "mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()"
 -> Keep __init_single_page() and refer to the usage of
    memblock_reserved_mark_noinit()
* "fs: hugetlbfs: cleanup folio in adjust_range_hwpoison()"
* "fs: hugetlbfs: remove nth_page() usage within folio in
   adjust_range_hwpoison()"
 -> Separate nth_page() removal from cleanups
 -> Further improve cleanups
* "io_uring/zcrx: remove nth_page() usage within folio"
 -> Keep the io_copy_cache for now and limit to nth_page() removal
* "mm/gup: drop nth_page() usage within folio when recording subpages"
 -> Cleanup record_subpages as bit
* "mm/cma: refuse handing out non-contiguous page ranges"
 -> Replace another instance of "pfn_to_page(pfn)" where we already have
    the page
* "scatterlist: disallow non-contigous page ranges in a single SG entry"
 -> We have to EXPORT the symbol. I thought about moving it to mm_inline.h,
    but I really don't want to include that in include/linux/scatterlist.h
* "ata: libata-eh: drop nth_page() usage within SG entry"
* "mspro_block: drop nth_page() usage within SG entry"
* "memstick: drop nth_page() usage within SG entry"
* "mmc: drop nth_page() usage within SG entry"
 -> Keep PAGE_SHIFT
* "scsi: scsi_lib: drop nth_page() usage within SG entry"
* "scsi: sg: drop nth_page() usage within SG entry"
 -> Split patches, Keep PAGE_SHIFT
* "crypto: remove nth_page() usage within SG entry"
 -> Keep PAGE_SHIFT
* "kfence: drop nth_page() usage"
 -> Keep modifying i and use "start_pfn" only instead

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Jason Gunthorpe <jgg@nvidia.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Mike Rapoport <rppt@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Robin Murphy <robin.murphy@arm.com>
Cc: John Hubbard <jhubbard@nvidia.com>
Cc: Peter Xu <peterx@redhat.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Brendan Jackman <jackmanb@google.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>
Cc: Zi Yan <ziy@nvidia.com>
Cc: Dennis Zhou <dennis@kernel.org>
Cc: Tejun Heo <tj@kernel.org>
Cc: Christoph Lameter <cl@gentwo.org>
Cc: Muchun Song <muchun.song@linux.dev>
Cc: Oscar Salvador <osalvador@suse.de>
Cc: x86@kernel.org
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-mips@vger.kernel.org
Cc: linux-s390@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Cc: linux-ide@vger.kernel.org
Cc: intel-gfx@lists.freedesktop.org
Cc: dri-devel@lists.freedesktop.org
Cc: linux-mmc@vger.kernel.org
Cc: linux-arm-kernel@axis.com
Cc: linux-scsi@vger.kernel.org
Cc: kvm@vger.kernel.org
Cc: virtualization@lists.linux.dev
Cc: linux-mm@kvack.org
Cc: io-uring@vger.kernel.org
Cc: iommu@lists.linux.dev
Cc: kasan-dev@googlegroups.com
Cc: wireguard@lists.zx2c4.com
Cc: netdev@vger.kernel.org
Cc: linux-kselftest@vger.kernel.org
Cc: linux-riscv@lists.infradead.org

David Hildenbrand (36):
  mm: stop making SPARSEMEM_VMEMMAP user-selectable
  arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
  wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu
    kernel config
  mm/page_alloc: reject unreasonable folio/compound page sizes in
    alloc_contig_range_noprof()
  mm/memremap: reject unreasonable folio/compound page sizes in
    memremap_pages()
  mm/hugetlb: check for unreasonable folio sizes when registering hstate
  mm/mm_init: make memmap_init_compound() look more like
    prep_compound_page()
  mm: sanity-check maximum folio size in folio_set_order()
  mm: limit folio/compound page sizes in problematic kernel configs
  mm: simplify folio_page() and folio_page_idx()
  mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
  mm/mm/percpu-km: drop nth_page() usage within single allocation
  fs: hugetlbfs: remove nth_page() usage within folio in
    adjust_range_hwpoison()
  fs: hugetlbfs: cleanup folio in adjust_range_hwpoison()
  mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
  mm/gup: drop nth_page() usage within folio when recording subpages
  io_uring/zcrx: remove nth_page() usage within folio
  mips: mm: convert __flush_dcache_pages() to
    __flush_dcache_folio_pages()
  mm/cma: refuse handing out non-contiguous page ranges
  dma-remap: drop nth_page() in dma_common_contiguous_remap()
  scatterlist: disallow non-contigous page ranges in a single SG entry
  ata: libata-eh: drop nth_page() usage within SG entry
  drm/i915/gem: drop nth_page() usage within SG entry
  mspro_block: drop nth_page() usage within SG entry
  memstick: drop nth_page() usage within SG entry
  mmc: drop nth_page() usage within SG entry
  scsi: scsi_lib: drop nth_page() usage within SG entry
  scsi: sg: drop nth_page() usage within SG entry
  vfio/pci: drop nth_page() usage within SG entry
  crypto: remove nth_page() usage within SG entry
  mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
  kfence: drop nth_page() usage
  block: update comment of "struct bio_vec" regarding nth_page()
  mm: remove nth_page()

 arch/arm64/Kconfig                            |  1 -
 arch/mips/include/asm/cacheflush.h            | 11 +++--
 arch/mips/mm/cache.c                          |  8 ++--
 arch/s390/Kconfig                             |  1 -
 arch/x86/Kconfig                              |  1 -
 crypto/ahash.c                                |  4 +-
 crypto/scompress.c                            |  8 ++--
 drivers/ata/libata-sff.c                      |  6 +--
 drivers/gpu/drm/i915/gem/i915_gem_pages.c     |  2 +-
 drivers/memstick/core/mspro_block.c           |  3 +-
 drivers/memstick/host/jmb38x_ms.c             |  3 +-
 drivers/memstick/host/tifm_ms.c               |  3 +-
 drivers/mmc/host/tifm_sd.c                    |  4 +-
 drivers/mmc/host/usdhi6rol0.c                 |  4 +-
 drivers/scsi/scsi_lib.c                       |  3 +-
 drivers/scsi/sg.c                             |  3 +-
 drivers/vfio/pci/pds/lm.c                     |  3 +-
 drivers/vfio/pci/virtio/migrate.c             |  3 +-
 fs/hugetlbfs/inode.c                          | 33 +++++--------
 include/crypto/scatterwalk.h                  |  4 +-
 include/linux/bvec.h                          |  7 +--
 include/linux/mm.h                            | 48 +++++++++++++++----
 include/linux/page-flags.h                    |  5 +-
 include/linux/scatterlist.h                   |  3 +-
 io_uring/zcrx.c                               |  4 +-
 kernel/dma/remap.c                            |  2 +-
 mm/Kconfig                                    |  3 +-
 mm/cma.c                                      | 39 +++++++++------
 mm/gup.c                                      | 14 ++++--
 mm/hugetlb.c                                  | 22 +++++----
 mm/internal.h                                 |  1 +
 mm/kfence/core.c                              | 12 +++--
 mm/memremap.c                                 |  3 ++
 mm/mm_init.c                                  | 15 +++---
 mm/page_alloc.c                               |  5 +-
 mm/pagewalk.c                                 |  2 +-
 mm/percpu-km.c                                |  2 +-
 mm/util.c                                     | 34 +++++++++++++
 tools/testing/scatterlist/linux/mm.h          |  1 -
 .../selftests/wireguard/qemu/kernel.config    |  1 -
 40 files changed, 202 insertions(+), 129 deletions(-)


base-commit: efa7612003b44c220551fd02466bfbad5180fc83
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-1-david%40redhat.com.
