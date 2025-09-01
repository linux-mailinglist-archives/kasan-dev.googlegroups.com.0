Return-Path: <kasan-dev+bncBC32535MUICBBDPM23CQMGQE3SBMCPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 21D26B3E826
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:04:48 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-80584b42d15sf73514885a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:04:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739086; cv=pass;
        d=google.com; s=arc-20240605;
        b=iXSgRBpWnPX4BZucdYvyg8p3Kf3RGSzDwXZx+frr9u9mxz/OOesPzTXjYyOWi4i7Bd
         O2dGsG6goHfPwj+FuQFDZbI1EYqvca2kABCCCEk5Qk+3zntX89PrNoyVGgEgWvbt/w/Y
         HdhWLrSCOwCWooNckRACE7UvIZvXYVmT+e/UQZUGCIe5qXWSnnjiX9jKrzrwOwAGhWl+
         oz4nElmVcdptFIF6Cczdd/VkPhXtU62wjGt/791pKvqarf+nQzEZAxqV2mPgsd9CRHFd
         u+FBxJLLpdiItlUkyj+GmJvOQoq6v9rFFiagt9yIO4NuSLCXHxttaDV4+Ju3jcK/oJsu
         diBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Glu+WKoEjjmJvO3DN70s5k+/xJSnbNkHobO4mh4sqHg=;
        fh=onyO5i+eJQOvC4JosMeKkuJr+zDJFUc/acMwI3HWEgQ=;
        b=CgDup27lGu87LiFaLeWqhILkz8KkDUAvRtj8VfM8UI7WMBt/3O8MCbxr3F7RPhPVmF
         U1IihcFi2c2g6kEUUN4V2cpSrE+HQ1AlbR2KqFiA22aaeCR+Ckuc1hEcZrZIHumQDLPQ
         W/VIQmAgsQ3vO1VE4Fti1I/Jy3LefCAsJULos6TICotnurWgYeIfPQ3FEwY1G5W7IvIw
         aMd26fUleE/+G/9DWKMnpcDas2aoswmMWgNPMCkIzh48uIE4niyOhgPwDMInQGrre7Ns
         xHaIDlrmRSP8aHuF5uP74OZVRbZMnFZjjQP+ZyxLmBm3D6ehyT2vrJjTEuZ6JdzBd5Yk
         Wy/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BoVbCBlw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739086; x=1757343886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Glu+WKoEjjmJvO3DN70s5k+/xJSnbNkHobO4mh4sqHg=;
        b=kN67zNCi7POz64H6nkzmuqBZzXzFWcdnvedYSRUGOSn6sh/7/9tgTD63eYcMTfRjsa
         uR/r8C84PqVj/aaDKKqjcwGqP1nb/L50uwup7rUQIzDJXJ3b3zvcXQ1PDx08gm6/6NBc
         7AQwVHM3kJLZUot2HnxYIwMxNxAdksUYkHYvdHrS+/4+d/8PNEi1jRAVDF3Mu2+8/hN/
         lb49odrtczn9143hkCcfkmnIiKyW9LHVUxVbgoX2lNwoTz9eFDJY+35A+B6fRB+8I9d8
         uaMwZqzciVScBZNtuRL0epT0fHCWFMdYC3S50QHAN7b6f7utprY3Zs+XrskW1ns9lKhw
         8ktg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739086; x=1757343886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Glu+WKoEjjmJvO3DN70s5k+/xJSnbNkHobO4mh4sqHg=;
        b=QYIGkSBJ60hyhZZN26XYpMFeMqThghEeNvCHfXiprGY46GazDImjik6oJoVHFVTHey
         wwYoyo0d3LhSBxMJw5e181JThwUvIXcKOulynOpnsZNFh6/QCpOj6THPS9zvJhl8bUIh
         deTk7gSgOC2GDKrqM7JUpS06i0BulyvxjPaCoB9Kl+AR+BDS0LDNqINDD8EuHWZUZiBz
         /789jPa9WUoLaLY2LXrB1uDqeDvuvzBSlaaHneGkMcPprdYHdUMsW85bBNHXJKfIFGeV
         k0j0uBV3Z/m8g81tQw0plEW9uXM3TGF9nbUyuNB3nHqmY1UNx6cN4flzXKV7afWrmUas
         +peQ==
X-Forwarded-Encrypted: i=2; AJvYcCV/LEFTsEPsZJ/IUOV9TcQPJ6ROcp9YsxpLqmodKwXkp4aNb1Zi0xNoyd9g5GL0IaP0iJB45w==@lfdr.de
X-Gm-Message-State: AOJu0YzYzVQn4H2HbQZZNcpMIdh+Dut2peASHfFQidZw0WkSHYZ2/wf9
	C0anofWU1QsTvM7ZZmJqm3XByBdiwFjgcVSTTp0Wfm0DT0yTJZ0+NxHj
X-Google-Smtp-Source: AGHT+IH9F5SI96dz1QZxUl8ovVbRtuGAlf8WQIlD3bhbZb7YhfihwCAtixEq8URnG9TXRVwXllG9Ng==
X-Received: by 2002:a05:6214:e8b:b0:716:e723:cb29 with SMTP id 6a1803df08f44-716e723cd42mr70696666d6.25.1756739086177;
        Mon, 01 Sep 2025 08:04:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfOTaa36iSKjdfQb8KUkgDMYyrQdET8p0y9PVk2y/NQPQ==
Received: by 2002:a05:6214:c62:b0:707:56ac:be5f with SMTP id
 6a1803df08f44-710985fdcd8ls25561126d6.0.-pod-prod-05-us; Mon, 01 Sep 2025
 08:04:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXy2VOV0E2+wkuyKJysPx/pzlb+rI+ZHQ9qAEP5eCyzMC8UCqaatVOZUgARk2OtdNSwTYRM59OlBs8=@googlegroups.com
X-Received: by 2002:a05:6102:1613:b0:525:9f17:9e6e with SMTP id ada2fe7eead31-52b1be2a258mr2218412137.23.1756739084970;
        Mon, 01 Sep 2025 08:04:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739084; cv=none;
        d=google.com; s=arc-20240605;
        b=COQgtzMlRXP9s32FHZtOrvo7W1JjY8/SXqu2MKtd05fKa29wzVJW+N91KgSHGc3ggk
         OPjAnE5BL328/hIVdlWrMRvCU7yoLefy5PF8WEkEqEMtNMAVKRQRCvvbZZ2w51S/0zUd
         /kI6aGwG8lFGyJT3t413G4nAOHhYHNGqDq6yVlxOnCjL3lB3dj4VhLAh9QPIukZm2yUi
         FVpe2NVoeeRUbYGKYDrYn/kCmv2HTH1NRDv+Ahgq5J9G2Wcjpl7OUAbo286fqubfU3d6
         8gum6xV4Uim7/9DsTKpvQ414tHXiq3E8h6NJ38GyDlIOaXbLbAX6IyxQV+Ix2ejzW5aj
         eyKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SbnyxtTKWg5jwngdRmLUxKAOmyXBjry9r+xRsqsuR80=;
        fh=ubu1J/jEk2ilozMp3Cxxj36XVw8JqQuNRoyjwBEUwAo=;
        b=aoW7++f+7TwJ7Palxd7AdIPvUcPDdcOK7FvRJtnuDrmpK8FPJlDGHFA+UZCS9TGBy7
         cZ3+o36HwV+1hUcpv9aeCmS9ayKE0lZ3oTxE5Zn6BxNFDvhNNMXtcXiFB+Ok2sMg+b4q
         clD81yZhYHYfuFUtROov6BzvkQ84xAJXw+Hd6mzIG75o8rtp5WgjCkGl/PcOWKEI8fab
         iKrbAMXnZlTCyJ9CFevV57z564oDPhLr4SzcGGuDL+kTgET8QHpZgAffQ2grua+7/VxR
         7KeXNaR2xFW1g9aaSFSbSBb5hrcgJs1Ttt/K9RZV18Pt98Uq6EmgP5IOZhskIU0JkS/y
         6fNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BoVbCBlw;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943b821ea3si307173241.1.2025.09.01.08.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:04:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-625-CtF_kTYGNmmX59oM8MuI7w-1; Mon,
 01 Sep 2025 11:04:43 -0400
X-MC-Unique: CtF_kTYGNmmX59oM8MuI7w-1
X-Mimecast-MFC-AGG-ID: CtF_kTYGNmmX59oM8MuI7w_1756739078
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 85A49180048E;
	Mon,  1 Sep 2025 15:04:35 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C99171800447;
	Mon,  1 Sep 2025 15:04:00 +0000 (UTC)
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
	Wei Yang <richard.weiyang@gmail.com>,
	Will Deacon <will@kernel.org>,
	Yishai Hadas <yishaih@nvidia.com>
Subject: [PATCH v2 00/37] mm: remove nth_page()
Date: Mon,  1 Sep 2025 17:03:21 +0200
Message-ID: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: YcBvn_2Ngag1WCoA_1WgyS0l3exX1LdcW5TvqR8M3zo_1756739078
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BoVbCBlw;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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
Patch #22        : disallow CMA allocations of non-contiguous pages
Patch #23 -> #33 : sanity+check + remove nth_page() usage within SG entry
Patch #34        : sanity-check + remove nth_page() usage in
                   unpin_user_page_range_dirty_lock()
Patch #35        : remove nth_page() in kfence
Patch #36        : adjust stale comment regarding nth_page
Patch #37        : mm: remove nth_page()

A lot of this is inspired from the discussion at [1] between Linus, Jason
and me, so cudos to them.

[1] https://lore.kernel.org/all/CAHk-=wiCYfNp4AJLBORU-c7ZyRBUp66W2-Et6cdQ4REx-GyQ_A@mail.gmail.com/T/#u

v1 -> v2:
* "fs: hugetlbfs: cleanup folio in adjust_range_hwpoison()"
 -> Add comment for loop and remove comment of function regarding
    copy_page_to_iter().
* Various smaller patch description tweaks I am not going to list for my
  sanity
* "mips: mm: convert __flush_dcache_pages() to
  __flush_dcache_folio_pages()"
 -> Fix flush_dcache_page()
 -> Drop "extern"
* "mm/gup: remove record_subpages()"
 -> Added
* "mm/hugetlb: check for unreasonable folio sizes when registering hstate"
 -> Refine comment
* "mm/cma: refuse handing out non-contiguous page ranges"
 -> Add comment above loop
* "mm/page_alloc: reject unreasonable folio/compound page sizes in
   alloc_contig_range_noprof()"
 -> Added comment above check
* "mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()"
 -> Refined comment

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

David Hildenbrand (37):
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
  mm/gup: remove record_subpages()
  io_uring/zcrx: remove nth_page() usage within folio
  mips: mm: convert __flush_dcache_pages() to
    __flush_dcache_folio_pages()
  mm/cma: refuse handing out non-contiguous page ranges
  dma-remap: drop nth_page() in dma_common_contiguous_remap()
  scatterlist: disallow non-contigous page ranges in a single SG entry
  ata: libata-sff: drop nth_page() usage within SG entry
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
 fs/hugetlbfs/inode.c                          | 36 +++++---------
 include/crypto/scatterwalk.h                  |  4 +-
 include/linux/bvec.h                          |  7 +--
 include/linux/mm.h                            | 48 +++++++++++++++----
 include/linux/page-flags.h                    |  5 +-
 include/linux/scatterlist.h                   |  3 +-
 io_uring/zcrx.c                               |  4 +-
 kernel/dma/remap.c                            |  2 +-
 mm/Kconfig                                    |  3 +-
 mm/cma.c                                      | 39 +++++++++------
 mm/gup.c                                      | 36 +++++++-------
 mm/hugetlb.c                                  | 22 +++++----
 mm/internal.h                                 |  1 +
 mm/kfence/core.c                              | 12 +++--
 mm/memremap.c                                 |  3 ++
 mm/mm_init.c                                  | 15 +++---
 mm/page_alloc.c                               | 10 +++-
 mm/pagewalk.c                                 |  2 +-
 mm/percpu-km.c                                |  2 +-
 mm/util.c                                     | 36 ++++++++++++++
 tools/testing/scatterlist/linux/mm.h          |  1 -
 .../selftests/wireguard/qemu/kernel.config    |  1 -
 40 files changed, 217 insertions(+), 146 deletions(-)


base-commit: b73c6f2b5712809f5f386780ac46d1d78c31b2e6
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-1-david%40redhat.com.
