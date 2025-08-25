Return-Path: <kasan-dev+bncBDZMFEH3WYFBBC7IWHCQMGQETZ3M46Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0981AB343F0
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 16:33:11 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-7ea01ed5d7csf487172285a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 07:33:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756132389; cv=pass;
        d=google.com; s=arc-20240605;
        b=JuMog8p/QgIdgjdwj3hUtzQUnzZSQ/9ytWl0pBMty0VDtiJXi82t1miD0vRDq3/YkW
         9QzltjVmC3l/JWTt4tP0cpXeh+ntTQ9x+RPP699M//y1kL+MQ5aP5K26BIdfncEdyn06
         pBqI5/6a4dQEx4hhdur/mFrpJ4nkL9muPqf1Jv74LzZ40QGXnE5UV/NobcJbiC5HOCKs
         VAnqeCZat4XwTR4hFOFfQ7teQQOf1s9fPpe6b07Etz6YJQv7TH5hAx4lIG51Arin5wau
         vl/NVmX0ivndYzl2ZAyW/4+1K4ISI8v3mrv1G7g63/4Rlalap/Q292pzEzMOJs2Ogyuh
         Zc2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zg6tVr8NBfWdX/9Rrjf13rhCK6kdzQ/NnFnA0dub4/A=;
        fh=AN5S7Kvt5LqD248IJv+A+ktRVsbnjQfKu4q+iUZxZ/4=;
        b=JUDS9AFkqPPhfLuWRTEoHLzzb+Hmo5R5tk2K3bccsw91m08uNrzt5WNUPFvzY5TH45
         fjbP72eMwNWA4lEWAmJs7E8qBVe8orWnHpYZiytg0XrXSoVXEm2NJD7HIYyh37Z8kS7m
         nuEvcTRdgPr8u9m7phQP45BSdy1QOt8tDI5mF8eYVGDdexOIiY5fRX/bhYtNkxSz3LgM
         oBoRSgeDxB2kgiQIiJm5akQxaejcb3aJubgkIjp3GWL/JX17H9tixDMII+mX/yC6x3Y6
         xWeVb2hjG+xc9ozidELWVuykh57nn/vh7fY4VpoDH4YLYijXUPYCW5d+bpMtWvijhNkk
         KuzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n7YZsnMU;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756132389; x=1756737189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Zg6tVr8NBfWdX/9Rrjf13rhCK6kdzQ/NnFnA0dub4/A=;
        b=QWfhx6Zupj/qTgmFvkLT2DajqL2syf+7fXpVoZRRIoM4fbpLnNnYD45bmy1W7d8+Yj
         wuiqXoN18/p82JXHWIZVjad7a5WZxbNvWOCuYCQ7LGWI+neBqR/ANDe8nlOvY6FjwJ36
         WmROivTBsjEKZvt1Re8ciPJYNesVSHGTo+mxk9m/ObHXRcLqx0lVqe39jo0w/Rk7+QT3
         udzT9bIa11A6lfL0h9gsj9xQ4xDl+brBUu0NWaEGwIfEGCYTGpzQEZmlJrJi992s6mW3
         rxUj0TC63EwfCPJ1dfBSuxuOxJm6UrWgIwSatEL1aPatajywcDepfjdlItpQnUug/QJp
         E95A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756132389; x=1756737189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Zg6tVr8NBfWdX/9Rrjf13rhCK6kdzQ/NnFnA0dub4/A=;
        b=S1uB0JrjGTiu6s8hsJPrAUX/aS2K34lt0rLYRZ2wdsfCcl9kksEjGQmxmmu6l6BCcr
         esc/19fq6SP4HlvXqolrRtbVSseUk7k19YEQdXZEc6+GJ6E/a34VZl5RdMv+X7zEMuk6
         yiczokNr0kIQ3dWiDcRfE4Ba8gkITnOxacrWqje5nxU+oudcGJcJn9cDsSIua0JCaIVr
         Gnbmq0To9EZUCEJS5ZUYl1A/oNSz9SEHJLGpbvBtoy5wbEy0oMnIbr7+lmk8+2vxON0V
         9bjxlNKXsKMCi4fZfOrofuvSyNNMrlwwMJavWTM5bb+ozljnKJN/zocxlM6xtme4nFiH
         kvhg==
X-Forwarded-Encrypted: i=2; AJvYcCVEXPqQg0uYDjRwpSRnOebayWPSFMI7sqfsJ5KxVnBIe9f+pKe9E5OX+yE1n4TT1oOSV+DHHQ==@lfdr.de
X-Gm-Message-State: AOJu0YzW/aeAYhbtz6vxcdZiyxYzVUv0CcUxMJO70OWTCejqcd4cUiyO
	fCi/RDvIcD/YjgBnzAGMzulbv/tPXZ4tjJM8bEqT0As4kUB+PRE0kua+
X-Google-Smtp-Source: AGHT+IG7iCjjT46oqMG/WQtoYQYdAXw4NJIQ1oafM1t5sU2FNSYPOziLqzu3hKcNNt7UqZkIPWHhBQ==
X-Received: by 2002:a05:620a:1a84:b0:7e6:969e:c54 with SMTP id af79cd13be357-7ea1106947fmr1592809185a.63.1756132363466;
        Mon, 25 Aug 2025 07:32:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehA+DhbihQ0ydB/sYKuPGskUhJv93Mrd2c+1+IHJ0vww==
Received: by 2002:a05:6214:2128:b0:70b:acc1:ba4f with SMTP id
 6a1803df08f44-70dad7b822fls30421756d6.1.-pod-prod-08-us; Mon, 25 Aug 2025
 07:32:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULem4ag7gCSp4WRdImvCYz1dldeAxbM/Vop41UZeg6nbVea+XH39xPI9Zaf/2si2zqTopoHAqPgDw=@googlegroups.com
X-Received: by 2002:a05:6122:658c:b0:542:6263:5f2a with SMTP id 71dfb90a1353d-542626361f4mr515444e0c.10.1756132362261;
        Mon, 25 Aug 2025 07:32:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756132362; cv=none;
        d=google.com; s=arc-20240605;
        b=a/w0P45aWSpqnnDK9WWO2N2+5aWnfVgpE9u+bZ6e0kZ5xmD46+gPvNZga8dOE6bwwj
         Ar4YApliXzVWpkOsYmtgJ82e3SfJ7mm2fxGu+pC7rmse+bScjWecQJILjYXvzOyeaSEk
         07UMvAj2YbvWAYJxYC6eX3tu15INUGZleGih1eLozK7LLeAuRNACpbkT93ZIYqDjidRH
         3BW4a0AqEDZWLTtjFLwZlnvdrqUw4t7RLQm+UDoSXcKtJozz/QcGzvk2/ELoegJGzgXa
         j+JTEJvE2Wki46KlZfeyvGFzDwIze0uKGcT3pS/AcEnFmZxiOracng4+U83lt+P/UFzP
         wrAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=7q3aZRioWrrwo6BulP8o1mtOMyDOIQxT+3ZS1iXQjig=;
        fh=SnWEHMnw6q5A1i5gHssHZhjXePV2/MD17aPBvTeFLno=;
        b=ahSv5TilZp8EJrLjI0tZEpe65hG6sL0rICDUUfpFXWrncWctnVk9zviIDBsKig/hNr
         GSFwEKh5zzHt1/V+pKzLyd3BGMwQgRS3cvtu11snsCd5jSBnmujjjTeoRroChydNcn0V
         DHdmjYnXty3ICvH6IhH9q5IWs1y2k0w9BDfk71dg5et3IhKCnABmVKEhZcL+ZkGbJKee
         dalwD2vowpLDyFFA1X7EK16wHBNEyIT+DZnVORTFj12LTzMVpsc3B+lOCYtjZ849em+c
         a+D9dSx9dvMiJHv0hXNz110q5nQHzMnpf3UhSDsOGHKReDSgV4FcC3sLuYlA61A+CFxa
         WRlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n7YZsnMU;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5423a81a165si52881e0c.3.2025.08.25.07.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 07:32:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 07341407BB;
	Mon, 25 Aug 2025 14:32:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28395C4CEED;
	Mon, 25 Aug 2025 14:32:23 +0000 (UTC)
Date: Mon, 25 Aug 2025 17:32:20 +0300
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
Message-ID: <aKxz9HLQTflFNYEu@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n7YZsnMU;       spf=pass
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

On Mon, Aug 25, 2025 at 02:48:58PM +0200, David Hildenbrand wrote:
> On 23.08.25 10:59, Mike Rapoport wrote:
> > On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
> > > On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
> > > >=20
> > > > On 8/21/25 23:06, David Hildenbrand wrote:
> > > >=20
> > > > > All pages were already initialized and set to PageReserved() with=
 a
> > > > > refcount of 1 by MM init code.
> > > >=20
> > > > Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, whe=
re MM is supposed not to
> > > > initialize struct pages?
> > >=20
> > > Excellent point, I did not know about that one.
> > >=20
> > > Spotting that we don't do the same for the head page made me assume t=
hat
> > > it's just a misuse of __init_single_page().
> > >=20
> > > But the nasty thing is that we use memblock_reserved_mark_noinit() to=
 only
> > > mark the tail pages ...
> >=20
> > And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INIT is
> > disabled struct pages are initialized regardless of
> > memblock_reserved_mark_noinit().
> >=20
> > I think this patch should go in before your updates:
>=20
> Shouldn't we fix this in memblock code?
>=20
> Hacking around that in the memblock_reserved_mark_noinit() user sound wro=
ng
> -- and nothing in the doc of memblock_reserved_mark_noinit() spells that
> behavior out.

We can surely update the docs, but unfortunately I don't see how to avoid
hacking around it in hugetlb.=20
Since it's used to optimise HVO even further to the point hugetlb open
codes memmap initialization, I think it's fair that it should deal with all
possible configurations.
=20
> --=20
> Cheers
>=20
> David / dhildenb
>=20
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
Kxz9HLQTflFNYEu%40kernel.org.
