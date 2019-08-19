Return-Path: <kasan-dev+bncBDV37XP3XYDRBPXN5HVAKGQE3A4XUOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A8DA92119
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 12:15:27 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id e20sf420575ljk.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 03:15:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566209726; cv=pass;
        d=google.com; s=arc-20160816;
        b=BMWpLFDASIpY7F+jiyUJ2b+Qxs//lzte1hFwXuJRKyb7qW05jAj8ckBiovlBDAYxtW
         yDb2Wrt0ZWlOU8M4jc9QXh/WZM+v4igapWxfp4K5DphCpHe3MJAb3PUxWB5TixCoh030
         YXjgp6KNv3Pwasj5zewiy3hkuZKS3QnzQCKniQ2UcYZxDYLXNczIbhWHo7f1kBZuUZUl
         RnlZg7cJVrePPosRREBSoVWQz5n3UlC9Exh1AhYhjUKCyfoxhP2xR8iwJkw6xOcM5slR
         XI4giqb7BzvAHvA5lVdK/Ni3ZwYXj+lFLXeqL9KEOTnMw9W8wG5UbjVbEpW2t7A6WOfI
         vT5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RQI9KV0/I9Q+FTGDZ1MPDJ0iZiMmB2i2t/FkuR6LOT8=;
        b=mLQDuKa7EWLYFCATmo8tRswaxnazGT0spuhQlMKt5SpJ3fX+WBL6KYkn/Tb4jG+fiP
         824w2kPajGwAEIoOmqCH7aF5LlcErMkmciZ2u9Qq9YLwvTSvNVZSlpI/FbOvJRB9iuSW
         4PJnYBdevc2TXJEE/Zyt6NiOdUqUatgocPOS27UxULDHStP2HFedUbDJm7PJIQ3wI0s0
         RLMdezF442C1/2t9lB34ZIjvdoJpeHJEeBHc9m5Y+hYEv9tGASRF2k8oYaAVphoARdPN
         Y0too+AnhOymIIWfsLpq8SU+x7SuwkB5EHN22CNeznb40zVe/L40IG4L9GO2k8oHrIed
         BUjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RQI9KV0/I9Q+FTGDZ1MPDJ0iZiMmB2i2t/FkuR6LOT8=;
        b=OrfNo12C9RZkoia12izhboi9DSFcu+/q2JpseN8i+fA7sihENUFdwKz5V/vlgAEUnM
         1aY1cqGWmrG5UATArbIAwnMr+1Rs28iSnO/zeimc9EAdHnpjAb4pnpi3QjkWUhlmmzDM
         aHMdUDsKmMkjVRMafVv2mCNEV9nCdZykupiMTicm/T9ySa9fMXHU8MOwvWwtvwhklieF
         4z15YJmIoXK4AkFQWROmH7UehJ9PBi0rHW6dh1Na6bVdTOQIoUT1dZwiuZ5Fv3Xjx+eR
         L2GhktdX4ZSgL63PnncU3dLvMr4u9/hXMk7n25/2crePweceZy/iFEBjglm9hk/yFq+L
         OIdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RQI9KV0/I9Q+FTGDZ1MPDJ0iZiMmB2i2t/FkuR6LOT8=;
        b=jojFUIVyILDAS1Y72+V/RA9Ez4m5jF+a1yvQ8X2aDEkAPQtWCLCdi2hP9sFV1IiwgJ
         FlTSrGLQAUhn81SZAVFEOnxMHMnY6d+NQ3eoYhrBi2NoFEDwSC1iLnQp+GMjQG3mToRl
         wJ4UP/hE1H/RmtE9Z22DznLZEsvR3FlT2z9VduwIxJZyhqdhYOV+P8MH/0OM3n8q9/Rc
         rxUjdG8DxTb+isWlDvT19dY0x2ryu2pmcO1OcuAZByVYIYeAcKcOU4SrxiG+hWAOOn2t
         p6mZTB54j9PLGgEdPtiA8IRj4/UJLxXMT7DLPvbFe3HjOyZ0nstPpcYu1Xo8bGH0zVd9
         Iz6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWazFHzqWY+Xx+cXvxQw9anfENhLSNLZliv9zdgOHm++hiaSDA2
	4AWXRSchZd4v7goy0wTmnt4=
X-Google-Smtp-Source: APXvYqzo0qfI+zLPo5pG3H3lhTMmeLQ7Zdt2uptg7y9iy2jbF2j7kqnQhBkc/AjMdGIhGpAhD6Xvtw==
X-Received: by 2002:ac2:4157:: with SMTP id c23mr11516779lfi.173.1566209726710;
        Mon, 19 Aug 2019 03:15:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5213:: with SMTP id a19ls1293994lfl.8.gmail; Mon, 19 Aug
 2019 03:15:26 -0700 (PDT)
X-Received: by 2002:a19:4a50:: with SMTP id x77mr11290060lfa.91.1566209726091;
        Mon, 19 Aug 2019 03:15:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566209726; cv=none;
        d=google.com; s=arc-20160816;
        b=sM3vWrBTrKjJcCvvwDRXLaVZ0iIImnG9eJzSJOo5/jVlRmsq8fbkCF4Pnf6uSP2qlu
         45kkftSanA6YhLMBdyZyKjz7Lx7zX8L1URUH9K005MyxYxpDMmwmwokoKr6OtmHmsCO8
         NW/2MkQnVH/oUexQxF2BnBvPG/1s9kD6b5K4Lh/J1h8to52uSceobbnPVkxHJ3ZJ0+JT
         ea30lIOSc+f/1RgKmWco2nzs2hbBMxLggjLmSGsm01urCDHD+jBh9XxaAmX41Kj5Qj4n
         kGb78/cdX6E4CquVgHfDf8lDc4/7jBbrcsN8ZnWh9AymKDiYKkQqIvdGNlxPnxomqm8A
         UXNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=QwBHYCGmcIOOc937HJv6T9b0F34SmX/IMtI3Uo5CqJc=;
        b=Vi68Y60ri9i8I2+iAWi2i/5Xx0RVArBb4uwzR3ztpc4MHbowfusQFpaCgVPltG/wq3
         myi8HbPVz9KsXA2ox4x1JiPz6m4eiX6GQNQEu4mEGA6eeErvJpiOcVorBU+ULXRh/dgc
         Pen3mVbm/akXSPAAcfiZIF2WC+jRA6z5HhgIDvQTiLAJVAW/8uPlQjD6YsX/e2RdbqAe
         Ifnl46htW9KUvDmLeza00ERbpZaUbZmlFaMfKwgyDOjrHJXw9SvjMNeA1+ZTg9PvlzUS
         FQ0pia86nbtHCs5mNZr6vOITM/rlSTMGKkNY0e8vKU73jQ+qTyJ6OkLE/7XgQx2nhQnf
         B0Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s14si754690ljg.4.2019.08.19.03.15.25
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 03:15:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 52B92344;
	Mon, 19 Aug 2019 03:15:24 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B14723F706;
	Mon, 19 Aug 2019 03:15:22 -0700 (PDT)
Date: Mon, 19 Aug 2019 11:15:18 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Andy Lutomirski <luto@kernel.org>
Cc: Christophe Leroy <christophe.leroy@c-s.fr>,
	Daniel Axtens <dja@axtens.net>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, X86 ML <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
	Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190819101517.GA7482@lakrids.cambridge.arm.com>
References: <20190815001636.12235-1-dja@axtens.net>
 <20190815001636.12235-2-dja@axtens.net>
 <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr>
 <20190816170813.GA7417@lakrids.cambridge.arm.com>
 <CALCETrUn4FNjvRoJW77DNi5vdwO+EURUC_46tysjPQD0MM3THQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CALCETrUn4FNjvRoJW77DNi5vdwO+EURUC_46tysjPQD0MM3THQ@mail.gmail.com>
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

On Fri, Aug 16, 2019 at 10:41:00AM -0700, Andy Lutomirski wrote:
> On Fri, Aug 16, 2019 at 10:08 AM Mark Rutland <mark.rutland@arm.com> wrot=
e:
> >
> > Hi Christophe,
> >
> > On Fri, Aug 16, 2019 at 09:47:00AM +0200, Christophe Leroy wrote:
> > > Le 15/08/2019 =C3=A0 02:16, Daniel Axtens a =C3=A9crit :
> > > > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > > > memory to back the mappings.
> > > >
> > > > Most mappings in vmalloc space are small, requiring less than a ful=
l
> > > > page of shadow space. Allocating a full shadow page per mapping wou=
ld
> > > > therefore be wasteful. Furthermore, to ensure that different mappin=
gs
> > > > use different shadow pages, mappings would have to be aligned to
> > > > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> > > >
> > > > Instead, share backing space across multiple mappings. Allocate
> > > > a backing page the first time a mapping in vmalloc space uses a
> > > > particular page of the shadow region. Keep this page around
> > > > regardless of whether the mapping is later freed - in the mean time
> > > > the page could have become shared by another vmalloc mapping.
> > > >
> > > > This can in theory lead to unbounded memory growth, but the vmalloc
> > > > allocator is pretty good at reusing addresses, so the practical mem=
ory
> > > > usage grows at first but then stays fairly stable.
> > >
> > > I guess people having gigabytes of memory don't mind, but I'm concern=
ed
> > > about tiny targets with very little amount of memory. I have boards w=
ith as
> > > little as 32Mbytes of RAM. The shadow region for the linear space alr=
eady
> > > takes one eighth of the RAM. I'd rather avoid keeping unused shadow p=
ages
> > > busy.
> >
> > I think this depends on how much shadow would be in constant use vs wha=
t
> > would get left unused. If the amount in constant use is sufficiently
> > large (or the residue is sufficiently small), then it may not be
> > worthwhile to support KASAN_VMALLOC on such small systems.
> >
> > > Each page of shadow memory represent 8 pages of real memory. Could we=
 use
> > > page_ref to count how many pieces of a shadow page are used so that w=
e can
> > > free it when the ref count decreases to 0.
> > >
> > > > This requires architecture support to actually use: arches must sto=
p
> > > > mapping the read-only zero page over portion of the shadow region t=
hat
> > > > covers the vmalloc space and instead leave it unmapped.
> > >
> > > Why 'must' ? Couldn't we switch back and forth from the zero page to =
real
> > > page on demand ?
> > >
> > > If the zero page is not mapped for unused vmalloc space, bad memory a=
ccesses
> > > will Oops on the shadow memory access instead of Oopsing on the real =
bad
> > > access, making it more difficult to locate and identify the issue.
> >
> > I agree this isn't nice, though FWIW this can already happen today for
> > bad addresses that fall outside of the usual kernel address space. We
> > could make the !KASAN_INLINE checks resilient to this by using
> > probe_kernel_read() to check the shadow, and treating unmapped shadow a=
s
> > poison.
>=20
> Could we instead modify the page fault handlers to detect this case
> and print a useful message?

In general we can't know if a bad access was a KASAN shadow lookup (e.g.
since the shadow of NULL falls outside of the shadow region), but we
could always print a message using kasan_shadow_to_mem() for any
unhandled fault to suggeest what the "real" address might have been.

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20190819101517.GA7482%40lakrids.cambridge.arm.com.
