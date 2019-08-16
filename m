Return-Path: <kasan-dev+bncBDV37XP3XYDRBBOG3PVAKGQELBPXGKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DD75E90671
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 19:08:21 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y3sf3772972edm.21
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 10:08:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565975301; cv=pass;
        d=google.com; s=arc-20160816;
        b=dvfrs++AmMrH9BqcvaMWvWyL+9c+eU10ToO8R80N1r6HG83lE6S55QoVe5etQpjm5f
         evV/YxEFWoNcwxjQjduPmE0DBc8xFMyhNcRQRNImw2UBVqQoBPJPPh+EEyWYiy462gWn
         qXln78UWmLmIIlgo5Kr9FiArXkRMXvjjMwXE9FDsE4WD6fzqSNit7WwTr0oFj4SrIc7l
         fCnV5ZaxQmmxc3Vl29BHNB0sRo2A2Z68EfGF0AIhWjRYL8+bokcEq7QtdUBoVWOxvSnB
         p82mUuu8LS4hDz4RTFng7sy18mRONK/DZg77fZlLSOEKzbaw6NMx6q4fS6PaJxxdjQMs
         8Ybg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=mSkQ2WOBcXMRof8XC3vPUzRgWXlWcZ6E3/QHxjOvBwk=;
        b=oF+oJEMzZ2t2xxziuqRhcyCPbV9Yipt5k38urVRJrHdOmyLr+qX4Ky7VAlY+WblNvi
         doS6KbFzZFr8hZ8mooQiP/FifzmQBsUUgeB5EfuSWnbEXKX49RRPVqVRh8nZJBH1oZeB
         3TtjpkwMoHhZmVSHY/86MbfYikyJ+vzQYIa9SKEi9VlecRsIYmTbaOYI/Oo7CXxFcFMv
         iZP8gFJRAEH2ZAdlcITunGcwvL8ZYPTWcWCVChA+29dXmytO1uUii5ag21x2CpFbSQO5
         5TVvYOATeITm77ElXPRjbKl/XdIWcG73BeBRvv1VlTX1EkhPRA+3hZXoTnyTBl3zzXT5
         /qNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mSkQ2WOBcXMRof8XC3vPUzRgWXlWcZ6E3/QHxjOvBwk=;
        b=ZWpjGWuRtt+PacoQzAoQnlR8tz+BM/yIkq+9EZ425G/dFNETFMcHfscXlsyfNg2x29
         5D4RAaITGP6/jm5GT4g1X+gPvVzH+9RMWVqXHd6GPEYxZABFBf3wrExWvjyYBHUJPH6n
         xGsdAgem+KMATu5NEJYPrqapL1PNz2u7+/0ZKsd66FIJiWIGOHbVaeeRaVp15DbSMOl6
         2tUizL4h0gthjbLHNLQaoZFw+NAPDRh1HHB3tONZduw930GXYeYmn5ndUr31NF7OL3dl
         dUIpNZ3txqvktpm38bxDPI1O/pz3NZPFGwZbfMbkiNOBXSqilEPdigZhFeUa3XCsiVd2
         ECXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mSkQ2WOBcXMRof8XC3vPUzRgWXlWcZ6E3/QHxjOvBwk=;
        b=ZfDVMyrG2uGMazDfd6JtVOAitYmReWcjWlCR8DiMTZdt4JCt1tCgUvq6O949bMJz2e
         WAsyYWDmfDEYxaqXzQlTh6jAhW+bnnyp9o3EQMn0Zs/h836KubfsTL/T4IAJJ5eu0/3o
         KWkPCtL/3xAiEu0NtLf4R0tvxL+BcEtHPgV9nPcQKG2V5euJECSY3YukcF8XvDVY31aA
         QWg9dn7jnNSQDQcpfEe9zuMk7lU8ow2nWY43i35q7UUlF7K5hevRBXaZACWKyoSuc4aD
         8RfX4AQfH10ZKJJ3JR2UAe48R2x6PHdoURo9xq2FcYcBiesiX64pGxR0amRpfqLXu/87
         aTwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUNzXrA/9s7SJmmqKTejcSZ9vz+hr2/tu5M1wWssmxrMT4pQApZ
	1fQAaTDSUetpQ2/ZRKVvwMg=
X-Google-Smtp-Source: APXvYqxa6//n7aOHLYc6P8ZXfnu8UObvBY2JhHvAj/RRMT2baC1sOUvKcDgdIK19HXVAmqmJef/bCQ==
X-Received: by 2002:a17:906:4706:: with SMTP id y6mr10197624ejq.191.1565975301541;
        Fri, 16 Aug 2019 10:08:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:8052:: with SMTP id x18ls238451ejw.10.gmail; Fri, 16
 Aug 2019 10:08:20 -0700 (PDT)
X-Received: by 2002:a17:906:4882:: with SMTP id v2mr10358467ejq.100.1565975300811;
        Fri, 16 Aug 2019 10:08:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565975300; cv=none;
        d=google.com; s=arc-20160816;
        b=xI6ENs+S5Iz5ogwlQXAI8grQWiibQtHjjnduSfvZ+MrBue/XKk+L1wgcIvcda36vSC
         3jximYEO4o19AAC4qnWKxqBVMUoJiFTFcrg/ZnKhCVnrC/388GOjHxK+krKeWdGo/yTY
         iVBsbyIFprn2WP21rJM8fvgNi1vf+WXTbHcm2gVHet9mnE+KhLwJ2HzXzKBxriCYD0Kc
         PmAWUNreydiX9GkC63YW0zawmb20m6Klxiu5EI7FxZVZpsx0b+zVHmo5TYmjo6/kN/sv
         /WuyR99wNVVCFSuTUEJfxsEcSrBLJjPt3EklgqaSFqdfYeuFcltyzUYe54P3z5qrs3Zt
         CU/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=iQP6cTOXD2gZPjecCX7PieaZTobOpg7FNKc3tId4y28=;
        b=nihDmi/PdNAAuYH715egwcHaTeR2yGe7exdnfkwTP4+qTBPY3u/M49NS8GQDvoelqV
         r9Nnf3/79oJ8wyzJXfKQS4+9IlwVji6RscxlLr0iDcJxPkedR7OZXk1z9slXNtzsF6NV
         59InIL9ozCO6cDx9S6+z99ijsNbSxoY6lPUW8lXIo19ixnIwKdqI58t4NpfBXnDsniqM
         WX/D3WlynVInGkwHikTbc6aE/1eIF0TQAEng3fbGQlbSWQMU4vTqV0gusOCF8Su4Xf5v
         YEj5Lzl5Q7vDxmTOhawD/3iRzez8sPShmLTFS0RUAceJIhaCQ3kesFkyImltkYw40WCD
         r2RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m29si297422edb.3.2019.08.16.10.08.20
        for <kasan-dev@googlegroups.com>;
        Fri, 16 Aug 2019 10:08:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 074A928;
	Fri, 16 Aug 2019 10:08:20 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 700803F694;
	Fri, 16 Aug 2019 10:08:18 -0700 (PDT)
Date: Fri, 16 Aug 2019 18:08:13 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Christophe Leroy <christophe.leroy@c-s.fr>
Cc: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
	glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
	dvyukov@google.com, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190816170813.GA7417@lakrids.cambridge.arm.com>
References: <20190815001636.12235-1-dja@axtens.net>
 <20190815001636.12235-2-dja@axtens.net>
 <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi Christophe,

On Fri, Aug 16, 2019 at 09:47:00AM +0200, Christophe Leroy wrote:
> Le 15/08/2019 =C3=A0 02:16, Daniel Axtens a =C3=A9crit=C2=A0:
> > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > memory to back the mappings.
> >=20
> > Most mappings in vmalloc space are small, requiring less than a full
> > page of shadow space. Allocating a full shadow page per mapping would
> > therefore be wasteful. Furthermore, to ensure that different mappings
> > use different shadow pages, mappings would have to be aligned to
> > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> >=20
> > Instead, share backing space across multiple mappings. Allocate
> > a backing page the first time a mapping in vmalloc space uses a
> > particular page of the shadow region. Keep this page around
> > regardless of whether the mapping is later freed - in the mean time
> > the page could have become shared by another vmalloc mapping.
> >=20
> > This can in theory lead to unbounded memory growth, but the vmalloc
> > allocator is pretty good at reusing addresses, so the practical memory
> > usage grows at first but then stays fairly stable.
>=20
> I guess people having gigabytes of memory don't mind, but I'm concerned
> about tiny targets with very little amount of memory. I have boards with =
as
> little as 32Mbytes of RAM. The shadow region for the linear space already
> takes one eighth of the RAM. I'd rather avoid keeping unused shadow pages
> busy.

I think this depends on how much shadow would be in constant use vs what
would get left unused. If the amount in constant use is sufficiently
large (or the residue is sufficiently small), then it may not be
worthwhile to support KASAN_VMALLOC on such small systems.

> Each page of shadow memory represent 8 pages of real memory. Could we use
> page_ref to count how many pieces of a shadow page are used so that we ca=
n
> free it when the ref count decreases to 0.
>=20
> > This requires architecture support to actually use: arches must stop
> > mapping the read-only zero page over portion of the shadow region that
> > covers the vmalloc space and instead leave it unmapped.
>=20
> Why 'must' ? Couldn't we switch back and forth from the zero page to real
> page on demand ?
>
> If the zero page is not mapped for unused vmalloc space, bad memory acces=
ses
> will Oops on the shadow memory access instead of Oopsing on the real bad
> access, making it more difficult to locate and identify the issue.

I agree this isn't nice, though FWIW this can already happen today for
bad addresses that fall outside of the usual kernel address space. We
could make the !KASAN_INLINE checks resilient to this by using
probe_kernel_read() to check the shadow, and treating unmapped shadow as
poison.

It's also worth noting that flipping back and forth isn't generally safe
unless going via an invalid table entry, so there'd still be windows
where a bad access might not have shadow mapped.

We'd need to reuse the common p4d/pud/pmd/pte tables for unallocated
regions, or the tables alone would consume significant amounts of memory
(e..g ~32GiB for arm64 defconfig), and thus we'd need to be able to
switch all levels between pgd and pte, which is much more complicated.

I strongly suspect that the additional complexity will outweigh the
benefit.

[...]

> > +#ifdef CONFIG_KASAN_VMALLOC
> > +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> > +				      void *unused)
> > +{
> > +	unsigned long page;
> > +	pte_t pte;
> > +
> > +	if (likely(!pte_none(*ptep)))
> > +		return 0;
>=20
> Prior to this, the zero shadow area should be mapped, and the test should
> be:
>=20
> if (likely(pte_pfn(*ptep) !=3D PHYS_PFN(__pa(kasan_early_shadow_page))))
> 	return 0;

As above, this would need a more comprehensive redesign, so I don't
think it's worth going into that level of nit here. :)

If we do try to use common shadow for unallocate VA ranges, it probably
makes sense to have a common poison page that we can use, so that we can
report vmalloc-out-of-bounfds.

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20190816170813.GA7417%40lakrids.cambridge.arm.com.
