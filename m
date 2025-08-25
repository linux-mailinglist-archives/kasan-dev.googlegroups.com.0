Return-Path: <kasan-dev+bncBDZMFEH3WYFBBXPUWHCQMGQEOJYSYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 013F3B344D7
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 16:59:44 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e931cac8a57sf7525932276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 07:59:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756133983; cv=pass;
        d=google.com; s=arc-20240605;
        b=XyAvjjNNB/JerUW92+TbRAYXNZElB0sHuG50zo0n/kTcQaaW2Wz9XYIH1WvEhqvbcS
         QMlOJzUdImDmBCLHA1SJh3C5fmO85lXRhk/5btzgXHyENjnAneNeNBCxDLlj19adpxnN
         79WggCcBXlqsCLU+x8Au1/mGN7Gb3X5COMJnkCEnOQRxT9rArUjT6pcAi+rS9S8+LmCY
         U+8IgyPaUrASlFZP1GjSoeX005fsj7R6/E2mDuWXkRK6i2XkELFqetDUrFMu6A+bM1XK
         rxmB5oGMho99x9lLjIj6wCefzof1SVC2mYlO/Palfz/9uxpsUGmDi0A2TxlPYXLUSmwp
         WTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=YerfOMLhRKiM5HTF9FLQwhOtvQn67EFMboYGedbjy5g=;
        fh=qiZzN2QKiX0up1yPVvOWXI/suymxKobbxxsZ1s2kXXc=;
        b=Mtbp3F/MG7n5kYUyWQv+d7J4Budu+yv9odCi/AuZEp8YAUuQoNTZ7rCGCrhmKlCj5D
         vmHhHNrHfmNlaZ3DuzQaQjrgFDLLWqXrw1kBKi2jA7A+20O1Wjvu0ehbKAgyXvGC4Ib1
         a75iykI6AGNgE+LU8YgjJFGm3jkVPcUalnTYPBQIu8Cw/lSIE8LhnJHnxguzI7iF+zua
         SM/GrnZbgNKW5QchXlH7qJIRGc2mpMfvEyjMdaOhMd7Dk1qFz8HTwHLZ4/NwMMwLIA7+
         yWVi7gqS92JFTWFUTXRrTnN3sxL1sGbv3/Ayfn3gzAX18+0oBbfXdcrl/M1huUxRAEZn
         fZDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Jn0AZo3p;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756133983; x=1756738783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YerfOMLhRKiM5HTF9FLQwhOtvQn67EFMboYGedbjy5g=;
        b=WeODekS5bRDW71RpxvSAlnXUyqAM9e9JFbH+2ffGTpm2cX0mKdOWrFBSUnH+wEhqQ8
         eJb2n5I9fa7pzib1h0xcWv6Uip9pifk/BRIM6buG1zoFAiMt3STE2fdkB7ud1fbjZIW6
         seKBxwLEdqJU6+aaL95bo91SGMf+uk9UkFREVch/ql62hlZxm4ZAgCKk3IubCU8IJWRZ
         r7VwmbhY0BVPhhIHj5iZVjF1pB8/1sJpRFC63cdXBCisTZk84KmyV5SCCa4s8aMKIZ1l
         8mAqt1p06qcQR8AXdqK5epBkN6CEYarLbk64HHwbbT/v25QETairWox1iH4cOyvvNUo6
         9AdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756133983; x=1756738783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YerfOMLhRKiM5HTF9FLQwhOtvQn67EFMboYGedbjy5g=;
        b=vBQpj0qWEihQQEOLG8MnrAZ0eIiuLVn7n8yL4B+Juj7aWrXlHgkijU62ZO/3IEFN83
         Hjb5ldyOXhZqLAJ7hsMcNYYHq+G2HWkEbXvzIQ+7wvPkKi64y6+swCAoeWc8YB0rKciJ
         R2BMd1AXxhx0JWOQ/hdMnEW35T3tGy8KxX2qHLTsX7C84PAKcdy5l3mnvZ44XmQo7U0U
         e33OCQRKk6zpCRBY0DfmndLFt+n1z5pIky7R4FtbGm0SJqGm6H98JLD7r4EgynZbyXEe
         GMPFOBxVcCLz0nTlOf6HWl2aXpPgWAnKZtWFCKVCx1J3RVSm/E7nGsPZunQYABRqW2Vr
         tfgg==
X-Forwarded-Encrypted: i=2; AJvYcCW18h0jCYJMpXVQxAIl3MdcH5FJp9ICcLJf9nTnDDlhp+r9h+gSDDnLimddU6Aslp6ADiKLyg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5ifw2J0tz0dBIZjPuXj0mjxPzHX1CmUeuvtIjgwb2Ga+KlVvM
	A64oTjQWedF49zcI/t1hKttKx7skN/tVVzVZV/U7E6MJKxcYkA9uC5M4
X-Google-Smtp-Source: AGHT+IGuWccV5vd07OG3P3mLZdrWWNnBn4tPHV3ukJo96IPJ6qea6RT6ZNzGkSQm4GRqaY915wmcaQ==
X-Received: by 2002:a05:6902:6b13:b0:e94:e1e5:377c with SMTP id 3f1490d57ef6-e951c2da504mr12519692276.50.1756133981554;
        Mon, 25 Aug 2025 07:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeqQkxwj0OMmwjakPghbuyPbsVOXsUt77ueGWhEjVIO4A==
Received: by 2002:a05:6902:680b:b0:e93:476e:3d94 with SMTP id
 3f1490d57ef6-e952d2e489dls1486773276.1.-pod-prod-07-us; Mon, 25 Aug 2025
 07:59:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6HQSRsI9OqpvhpVAEl5vHYWYkxIQ5yut8ps9+9oKeaE1oPY5cueaqTsmUB+xakkRpaQxnOGv41sE=@googlegroups.com
X-Received: by 2002:a05:690c:6a83:b0:71b:f83a:afa0 with SMTP id 00721157ae682-71fdc306895mr149951367b3.22.1756133980514;
        Mon, 25 Aug 2025 07:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756133980; cv=none;
        d=google.com; s=arc-20240605;
        b=KrlNIk8DUBJl3B6KeFP5XkPSPHrjUNBLocoE87dPaXtEq1UL4Q/CniKOVwOQFEF6tx
         E2LSjcJ0lv6Z/iPYkuQ/8a549whQuXPsmbLjiCUFcjYTR6FF0h/YU8XWfyxbw01YA3j8
         GZ8FGQiOiqt4a3B/QrxmUReeFaSAytm69Wklg0bd3p16INzhrdCyFSdi12V8UFbzaGbt
         HyWd+BrwpYNpxt/sMiRrZQ7R6l6Btgyqx+Y6pynTKMZR0P98HSgVhPCQy+59z5lPox/b
         X53iIyIJwzrjTgnkalPDetyXx8sw1Il2TSZdLac0tXwtlNSVL0gOTdna2I8Rv115dhKy
         nSXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qkD+sthOFrkZQBgyD/Brdao7sTCKGDTnrvrWEf6+780=;
        fh=SnWEHMnw6q5A1i5gHssHZhjXePV2/MD17aPBvTeFLno=;
        b=cvgT47bxCbaWkoCFQuHfAwMa1mDG0DVOz6VTWOzhyg17+BcrKu9D6LowVx7gdSkN2C
         gm64t7rZqSHz6Jpxbnu4dUOa71CwQ6sFFnUFsKhaE1C2sFq3UE91MuyEmvE2+gaoBJyB
         snVWEAkjE7ZVnZhfDDIxrwBrrmaP8xCfJmoq5hn6qSOYrAOEO2TyhkdL6dX+NlqnkO3i
         ujpzQIlD6V/beJDSFBIN+HLuvkwNeb7wk9qgxb/smAtcJSgXmAlApUIkepNPwj1e5Yml
         YV0/FIVp/oKCVpSa3JqLlgL0ZJAPfS7zpLQQdRVUtdxkXNKklzJ9qJTY3PzTNOuEUDon
         2EwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Jn0AZo3p;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5f65871932bsi264093d50.1.2025.08.25.07.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 07:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EDFB95C5988;
	Mon, 25 Aug 2025 14:59:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6B3D6C4CEED;
	Mon, 25 Aug 2025 14:59:26 +0000 (UTC)
Date: Mon, 25 Aug 2025 17:59:22 +0300
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
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
Message-ID: <aKx6SlYrj_hiPXBB@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Jn0AZo3p;       spf=pass
 (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Mon, Aug 25, 2025 at 04:38:03PM +0200, David Hildenbrand wrote:
> On 25.08.25 16:32, Mike Rapoport wrote:
> > On Mon, Aug 25, 2025 at 02:48:58PM +0200, David Hildenbrand wrote:
> > > On 23.08.25 10:59, Mike Rapoport wrote:
> > > > On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
> > > > > On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
> > > > > >=20
> > > > > > On 8/21/25 23:06, David Hildenbrand wrote:
> > > > > >=20
> > > > > > > All pages were already initialized and set to PageReserved() =
with a
> > > > > > > refcount of 1 by MM init code.
> > > > > >=20
> > > > > > Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT,=
 where MM is supposed not to
> > > > > > initialize struct pages?
> > > > >=20
> > > > > Excellent point, I did not know about that one.
> > > > >=20
> > > > > Spotting that we don't do the same for the head page made me assu=
me that
> > > > > it's just a misuse of __init_single_page().
> > > > >=20
> > > > > But the nasty thing is that we use memblock_reserved_mark_noinit(=
) to only
> > > > > mark the tail pages ...
> > > >=20
> > > > And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INI=
T is
> > > > disabled struct pages are initialized regardless of
> > > > memblock_reserved_mark_noinit().
> > > >=20
> > > > I think this patch should go in before your updates:
> > >=20
> > > Shouldn't we fix this in memblock code?
> > >=20
> > > Hacking around that in the memblock_reserved_mark_noinit() user sound=
 wrong
> > > -- and nothing in the doc of memblock_reserved_mark_noinit() spells t=
hat
> > > behavior out.
> >=20
> > We can surely update the docs, but unfortunately I don't see how to avo=
id
> > hacking around it in hugetlb.
> > Since it's used to optimise HVO even further to the point hugetlb open
> > codes memmap initialization, I think it's fair that it should deal with=
 all
> > possible configurations.
>=20
> Remind me, why can't we support memblock_reserved_mark_noinit() when
> CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled?

When CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled we initialize the entire
memmap early (setup_arch()->free_area_init()), and we may have a bunch of
memblock_reserved_mark_noinit() afterwards
=20
> --=20
> Cheers
>=20
> David / dhildenb
>=20

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Kx6SlYrj_hiPXBB%40kernel.org.
