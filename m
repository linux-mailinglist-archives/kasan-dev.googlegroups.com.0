Return-Path: <kasan-dev+bncBDAZZCVNSYPBBDH46WAAMGQEL3NHH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id C6CE5310E74
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:19:09 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id h16sf5749131qta.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:19:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612545549; cv=pass;
        d=google.com; s=arc-20160816;
        b=u94gtYMpLJL9nRMKrEHYEDJ2ohb56aSljoGhKhb9GKZziicFKP32M+XQ2C4FvdJTSt
         nn0Zg/t9Nmmqg5sZYMedC5mtWJZDTREfw/QL9GUycIgZB9Y7qp2SKldv4c/8b50e0bJS
         NP2QCsXu8Ll8TpI6BPdxMkTInyV0INDPzDIA8Xvmn7nY0ahNe1ozFq635TXuqnUZIoN0
         +AtDWLl0uvqmJj1NrJfKhP0WsVgbthkZ0tCkURWQsTsXqnlw9HGBEB2w65A/h4xHPnx7
         7nYuw4yJQoc/+gqU9gpQpScWB/h6/9R7qOcE7MZWnXFmZJYkQOEhrdZYSR6taf/l4DyI
         8cKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fvA5PonsR/mBR10rj4LS/yF8orb45bbBkZDpll7DJC8=;
        b=HRlPpp8oYJZQd57mrjILYT1uGc/HEG/WlX9dEKIZrpK8GnESuthTSJRrILBRgkmp+t
         0TonJxV86qNp1fJzjbPSyIYS04T6bWYiC36fEsmyEKHOUGpkBqJKeRzcEQF0pDH5Cbwn
         v02/vjicViWh1xlFdILNa21fmmcVysh+OLhY398FXD5LedHDoqMu4ajnxCmbtBQPmvWN
         Kbf3U8qaCgTaWq+t2v8OFMqdsQzHAj/g2PQIdqQqMPkcHt9JO3IH89T6NU/WjYgGoknv
         2wbnXpQpAuywbf9zhWZODc+1WGtXMI740G29xRRCTqm+phFWwz9R70ky6UqP7fz+AMuz
         7/+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fynDnKT1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fvA5PonsR/mBR10rj4LS/yF8orb45bbBkZDpll7DJC8=;
        b=i7GQxk1K01MM37jMBMGTtfYTGLfN0dzdgNDL8qz96AqstAefiEL9jLPvwibD1n3Fv3
         3TdKlXY942hPWpKBSS0xgJSCQhnqaB2QNFB2R3GIAIViGIiyqNb2Mzsx7Wtl/piuBI3a
         5iSyXZ4DMnzHDZTnwtCuhJ3kgbFdSxzv20vhnMm5aMhXbfT7s/z7KTfDmsnUzSAuCIBe
         VFKrxYPs8l+cwb18aO2SORV6CqK+Zm8RFz9GZl6aik7iP97NqAjxuWen81Q3+O1jb87V
         cEXd6UR1Lvyjky8EnpbSeC9Ilxb5S2Xz68NmcH7tsdmulLNmFnyTRlYnQfCEC0DvWGlB
         VHLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fvA5PonsR/mBR10rj4LS/yF8orb45bbBkZDpll7DJC8=;
        b=hJSVSnUYZyFui1qYbsXlwCQMvsfhAjgP3amPn1dh8ri4knR6SUGZ7+KvYmmrkic0BU
         Ef2s+8PDoUQzrLNm0NIn1Kl8ys0F3CVaQ1NTSmWf6iEyrvErpjCFk4DtWEsxkE0D7PVB
         4GjgqRSqufVHSuUeHUPzl4W2+klKoz6ow6tesBB5lZS2tqtxb2vc9txXZ5tLotdNYCDd
         13aNbroaQd9hk5vmqT9SeeOKSJUpDcLxFkxH6sJjjf1zmCjFTOpuMrpbGaBUq5cT2ErB
         1IOuDF+o36K3DEiIOJDnH2nN0h1IDDdqQ8oZo+8uME4U2RPm6PyVxav8QF3jZQjguR3A
         hqLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aOTqwruoPYGLDWvnStMSVDMVBUreeswx/s/lMyDoEsknObvcT
	q6H3IzU+gvD628O5ZM55lmM=
X-Google-Smtp-Source: ABdhPJw7sRyyd5W4gqzokxJ1WY4KgIdCxqkbr5coGg1c0qfvk6XmjKZDAhmmF4ZoISR15NiawgIu0Q==
X-Received: by 2002:a37:7cc5:: with SMTP id x188mr5225325qkc.130.1612545548897;
        Fri, 05 Feb 2021 09:19:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:e88:: with SMTP id 130ls5246643qko.0.gmail; Fri, 05 Feb
 2021 09:19:08 -0800 (PST)
X-Received: by 2002:a37:944:: with SMTP id 65mr5092208qkj.235.1612545548156;
        Fri, 05 Feb 2021 09:19:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612545548; cv=none;
        d=google.com; s=arc-20160816;
        b=sTY1WCSOrD2feW52zuRhFjOBMJ6uYYRhQa71VdMDVaCjnbYeYnxOozO6OsebDQFAMg
         juLY//b401SNVVL2+fwTLsgksrmJ0FtS8mRH/0jcyJppxnI3HqPAsNM9LMb5rTL97D72
         0R/zVLTK4fEm+eKpyDkWuLr/8Nb71gb4i+LgUGq+7G79LRsZcZqC6SmeRz4gXgN44wqU
         ERFpn+jouIsNGApkdVNrQi54CZZSx3O4FxblhCIIPGNKg/fbCS5hzGMBiYsp9VkECwGt
         UAetfElnAsaMzwVgnyujR8aAInzqAWJkUBkJMER+ob9dpuBQl+UnFu+/unLw8CqLx5IT
         bz6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fBwM4ghHidDqj23b6IHM0PNDSAl74cInai3Ju/xQihY=;
        b=S/yrjKEOOQOIARfLn95B/wZs7YGiRSIKxlJjixdvHYCSmIuWCzwxb9DUVg56p4NAVG
         duAL/xb3Hwq/u/cKXSZVFRpDg/N06AUNu6mLKYV9IOPpiYq988Fb7NfPnSN9MXXQ8ptE
         7sbg0+GymJZRp4vjbp4aOJxYxDrZHxxlYyhV89s9KEC5ETzGwITfY8Vmiql3e8IM9yO/
         odMABtxJaDEskIjeh0I4tfl607Z8vSezxdb8DEsuY9R5AY20OS+A9Uo3VwBzmyA3qamI
         6HRLYhR6FEhOPPgy8rSIaPLFwlbz/+4OQDxNAGBS5QoBqTY+xsqD8XuiVIdHLiaXGcBZ
         ZQ7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fynDnKT1;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h123si469304qkf.6.2021.02.05.09.19.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:19:08 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E0B5C64F2A;
	Fri,  5 Feb 2021 17:19:02 +0000 (UTC)
Date: Fri, 5 Feb 2021 17:18:59 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@google.com, ardb@kernel.org,
	aryabinin@virtuozzo.com, broonie@kernel.org,
	catalin.marinas@arm.com, dan.j.williams@intel.com,
	dvyukov@google.com, glider@google.com, gustavoars@kernel.org,
	kasan-dev@googlegroups.com, lecopzer.chen@mediatek.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org,
	linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org,
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for
 CONFIG_KASAN_VMALLOC
Message-ID: <20210205171859.GE22665@willie-the-truck>
References: <20210204150100.GE20815@willie-the-truck>
 <20210204163721.91295-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210204163721.91295-1-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fynDnKT1;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Feb 05, 2021 at 12:37:21AM +0800, Lecopzer Chen wrote:
>=20
> > On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > > >
> > > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > > the VMALLOC_START between VMALLOC_END.
> > > > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > > > should keep these area populated.
> > > > >
> > > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > > ---
> > > > > =C2=A0arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > > =C2=A01 file changed, 18 insertions(+), 5 deletions(-)
> > > > >
> > > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_ini=
t.c
> > > > > index d8e66c78440e..39b218a64279 100644
> > > > > --- a/arch/arm64/mm/kasan_init.c
> > > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > > =C2=A0{
> > > > > =C2=A0 u64 kimg_shadow_start, kimg_shadow_end;
> > > > > =C2=A0 u64 mod_shadow_start, mod_shadow_end;
> > > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > > =C2=A0 phys_addr_t pa_start, pa_end;
> > > > > =C2=A0 u64 i;
> > > > >
> > > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > > =C2=A0 mod_shadow_start =3D (u64)kasan_mem_to_shadow((void *)MODU=
LES_VADDR);
> > > > > =C2=A0 mod_shadow_end =3D (u64)kasan_mem_to_shadow((void *)MODULE=
S_END);
> > > > >
> > > > > + vmalloc_shadow_start =3D (u64)kasan_mem_to_shadow((void *)VMALL=
OC_START);
> > > > > + vmalloc_shadow_end =3D (u64)kasan_mem_to_shadow((void *)VMALLOC=
_END);
> > > > > +
> > > > > =C2=A0 /*
> > > > > =C2=A0 =C2=A0* We are going to perform proper setup of shadow mem=
ory.
> > > > > =C2=A0 =C2=A0* At first we should unmap early shadow (clear_pgds(=
) call below).
> > > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > > > >
> > > > > =C2=A0 kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PA=
GE_END),
> > > > > =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(void *)mod_shadow_start);
> > > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > > - =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(void *)KASAN_SHADOW_END);
> > > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > > >
> > > > Do we really need yet another CONFIG option for KASAN? What's the u=
se-case
> > > > for *not* enabling this if you're already enabling one of the KASAN
> > > > backends?
> > >
> > > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmal=
loc va).
> >
> > The shadow is allocated dynamically though, isn't it?
>=20
> Yes, but It's still a cost.
>=20
> > > There should be someone can enable KASAN_GENERIC but can't use VMALLO=
C
> > > due to memory issue.
> >
> > That doesn't sound particularly realistic to me. The reason I'm pushing=
 here
> > is because I would _really_ like to move to VMAP stack unconditionally,=
 and
> > that would effectively force KASAN_VMALLOC to be set if KASAN is in use=
.
> >
> > So unless there's a really good reason not to do that, please can we ma=
ke
> > this unconditional for arm64? Pretty please?
>=20
> I think it's fine since we have a good reason.
> Also if someone have memory issue in KASAN_VMALLOC,
> they can use SW_TAG, right?
>=20
> However the SW_TAG/HW_TAG is not supported VMALLOC yet.
> So the code would be like
>=20
> 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))

Just make this CONFIG_KASAN_VMALLOC, since that depends on KASAN_GENERIC.

> 		/* explain the relationship between=20
> 		 * KASAN_GENERIC and KASAN_VMALLOC in arm64
> 		 * XXX: because we want VMAP stack....
> 		 */

I don't understand the relation with SW_TAGS. The VMAP_STACK dependency is:

	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

which doesn't mention SW_TAGS at all. So that seems to imply that SW_TAGS
and VMAP_STACK are mutually exclusive :(

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210205171859.GE22665%40willie-the-truck.
