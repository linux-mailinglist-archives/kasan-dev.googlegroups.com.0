Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBM6SQXZAKGQE25OOXUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 81953157D6C
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 15:31:20 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id s205sf2267954vka.17
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 06:31:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581345076; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiSdM9P3A0oT23i6UgJh8PjCPwmdkGrTa4sCiZlRnQZZUmpwT0b+0DFChoDldLPUUf
         rU09sM+L33OfY1OnuRpU/aDmb+VhzzReRR9ZFuTDin+FGtUcLY1TftKQD4mqLekfhvCG
         iATxJVgEib5b+5VNg1J+NpTntg3ipEh/flIz+3dy0DFMJkKOeRGhe/bVnST8WAcXC5I/
         aUkS+276OlLZ7ezKvEt+sxjly55cAkQN+AvFnhh/hrsnb8BOeO9NkBQtkkBW/zVCKE4F
         RuLB07CnlnDrOvuIIjcgn7BpMOZgeUFEgO0liE+xVNJ09JXAFx0utWnrF40VBicIKfnz
         LC1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=FFN4lSlBdjiBIkfJpYaIdZTzZyLmI+DEkH1Y7afS05M=;
        b=UNGnBZnUt29loSYpNAE5xMgOKvtmgbvUVQxn1xU59HHpwtpXIoDSgM0A1UMy3XfMDO
         FAJHXbLOkQkqu/Zp5DIakh/S/lsq74gjsKUfUaRK900oMoIXTuy55JlJ7VU4oJOi0a0f
         RdYRdKaGC4IF6vGmghnq2tQX+pfZeb3t6F/10JjsN2j6ahJn24rkMIlTy0pnd7k+WPD2
         mo5HlJ/QJF9wmNoW0jmiFSdywrDNwdxOa5A94T+XhJ/dxzTYW7xZZg38JlqnNKHo94oe
         dCj0/ruL5F1e6AkgQaBjbKB7idCIMwr7IFpTz0bT0Np3g97KUkFDF1MRs2VTaXd/Qfm1
         g8kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="XXf5//gt";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FFN4lSlBdjiBIkfJpYaIdZTzZyLmI+DEkH1Y7afS05M=;
        b=fga6UVls/CsUb5q8a5jO9KrA0jGTeBuUjZdN+/SsSO9oV3jE1VAy/3s7DzuIB3oBYB
         TjxQmxnfC3yurjHAvgqh3iKrAlrn7mb3ljoNbo4Gc0B/6WIlWaLG7QajUzNo4pIdzOMN
         La1PEKL3DUdCotE0aGFgiHdiD6tmNDh+8b5BG3tNP9pnoIO00Akr355OFlAcLbusb3+B
         jIHacjdx4LwZYyL0ce6KNtiNkVWQY2lRo0dTOGu4q9zwxza/l8Aieyt2N0njjXwepKzb
         cZTQPM1oeydEg7R6MM4JEikZCUC5HpGbThZeTErGeOfFas0gQfEVyasesrbbjmJI45Pc
         gbvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FFN4lSlBdjiBIkfJpYaIdZTzZyLmI+DEkH1Y7afS05M=;
        b=Jq07tE8Jt71iPRpbPIs5pNAxXxBqqSO+4YpIs+t41Dc1oGaxAXNB3OggIAzWbBTo5T
         B8wYF/I+aYVGrrSdh8N9sl1SIhZ7ULviTGO9eLcFtrRvHnDG6G1JaApBhbk3xanQo50I
         J/LDR+gaWTKQB3ARDhI2R75kErprT3Cn+xarpHwDqCM7rrCAQ2MMRoN8P8Iw2h97eZTO
         J0BV9/bU1PsJQZUGWz7oSunsh+QQdGGZNIqd0M2akymp4+Fo0F1b5IVdGslXLY46zUHQ
         9KKs3KNng7hs35JKvHwNdw7cW1uFTjtAMojppVV2DZMjmDl07YS9+o8Tp9rBu467sK5z
         AyDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXBAgzs/LeU4OB9SFwOCBfxLC3bUS+BfVF1AFIg3zpxJkOOafxB
	U859ZTWrBNe7K/qWus3OHEk=
X-Google-Smtp-Source: APXvYqxhRQbsZIQ1Uk0LIteUPrrtCNINCBI9jESoZDbQwbd+TkFEy4ipCcPXjzgICAHnVfhUjgUosQ==
X-Received: by 2002:ab0:6558:: with SMTP id x24mr771950uap.130.1581345075969;
        Mon, 10 Feb 2020 06:31:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:804:: with SMTP id g4ls755702vsb.11.gmail; Mon, 10
 Feb 2020 06:31:15 -0800 (PST)
X-Received: by 2002:a67:f6c8:: with SMTP id v8mr6809948vso.147.1581345075503;
        Mon, 10 Feb 2020 06:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581345075; cv=none;
        d=google.com; s=arc-20160816;
        b=codI0ft5pf8ZuYNctKc8dmA/f34Q/WMqlT8do10SVbmz1PvnlThuoWjbGKic9imwSz
         vtQ4ZafdbRTlTVmSChwsVdOo4sZwNMkIG4vVLMmaOG5QeDa66K+oXxeuqrwKHZE6R1Fc
         VQacfpXDgfRfPxou8ixZuUnaYaAhVv1okukrOncEeoo+0PrS5HCgOT+ciTUJkXmZvSjk
         MFbVnIGtsbqYsShjFK28dRbv3zDhHULVzIaVKwvCmsmFgyEd2I6ez7aTC3zflLCulP2w
         2GHI1cnWTyPfExtS3T8n2MdsMbJZM3D8wjfzIa7gBdMzq1aYoDKgKP3DI81VAFt3ATi3
         vjAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=qcAgZw/ui3CLohL6PVMtRlohm+XOB+CMbaeiCefL8Tw=;
        b=u2nqR+XOaoLp/JUr8h3ZKNH/FL8JDltUH5wfmxYHNgwWipwn3HNUxPInYwt/SHawIN
         a+xM/fTR23B2VGfp09EgaOLjpVmDDiopdH2VuQnKjFTv5TgYOOrUQELZpHbYpJWvftU4
         lZvjEWTH8H7qTUJXiw8aDAFcycHYftmosZESLodz1dwIpOYfw9EhTuUKc7RVI2vp3ZgY
         VTZ1t//uhSBxs7gdnsITs5GOcM0fn5oRaJC50mAgMAJvukPWr0B8E68N+XWdy83WXdPl
         8Coog61i/LAlst0fU39cHXCbi2H5xlq5ybB0edEKL3rlPc+85hOdUUmSEujHlIqAzs2P
         rh3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="XXf5//gt";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id o19si19211vka.4.2020.02.10.06.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 06:31:15 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b7so6652784qkl.7
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 06:31:15 -0800 (PST)
X-Received: by 2002:a37:270b:: with SMTP id n11mr1631942qkn.26.1581345074983;
        Mon, 10 Feb 2020 06:31:14 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id r12sm200397qkm.94.2020.02.10.06.31.13
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 06:31:14 -0800 (PST)
Message-ID: <1581345072.7365.30.camel@lca.pw>
Subject: Re: [PATCH] mm: fix a data race in put_page()
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>, David
 Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
 ira.weiny@intel.com, Dan Williams <dan.j.williams@intel.com>, Linux Memory
 Management List <linux-mm@kvack.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 09:31:12 -0500
In-Reply-To: <CANpmjNN=SNr=HJMLrQUno2F1L4PmQL19JfvVjngKee77tN2q-Q@mail.gmail.com>
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
	 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
	 <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
	 <1581341769.7365.25.camel@lca.pw>
	 <CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF+GZqqxvpC8Ui4iN8New@mail.gmail.com>
	 <1581342954.7365.27.camel@lca.pw>
	 <CANpmjNN=SNr=HJMLrQUno2F1L4PmQL19JfvVjngKee77tN2q-Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="XXf5//gt";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, 2020-02-10 at 15:12 +0100, Marco Elver wrote:
> On Mon, 10 Feb 2020 at 14:55, Qian Cai <cai@lca.pw> wrote:
> >=20
> > On Mon, 2020-02-10 at 14:38 +0100, Marco Elver wrote:
> > > On Mon, 10 Feb 2020 at 14:36, Qian Cai <cai@lca.pw> wrote:
> > > >=20
> > > > On Mon, 2020-02-10 at 13:58 +0100, Marco Elver wrote:
> > > > > On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
> > > > > >=20
> > > > > >=20
> > > > > >=20
> > > > > > > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> w=
rote:
> > > > > > >=20
> > > > > > > Here is an alternative:
> > > > > > >=20
> > > > > > > Let's say KCSAN gives you this:
> > > > > > >   /* ... Assert that the bits set in mask are not written
> > > > > > > concurrently; they may still be read concurrently.
> > > > > > >     The access that immediately follows is assumed to access =
those
> > > > > > > bits and safe w.r.t. data races.
> > > > > > >=20
> > > > > > >     For example, this may be used when certain bits of @flags=
 may
> > > > > > > only be modified when holding the appropriate lock,
> > > > > > >     but other bits may still be modified locklessly.
> > > > > > >   ...
> > > > > > >  */
> > > > > > >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> > > > > > >=20
> > > > > > > Then we can write page_zonenum as follows:
> > > > > > >=20
> > > > > > > static inline enum zone_type page_zonenum(const struct page *=
page)
> > > > > > > {
> > > > > > > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONE=
S_PGSHIFT);
> > > > > > >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > > > > > > }
> > > > > > >=20
> > > > > > > This will accomplish the following:
> > > > > > > 1. The current code is not touched, and we do not have to ver=
ify that
> > > > > > > the change is correct without KCSAN.
> > > > > > > 2. We're not introducing a bunch of special macros to read bi=
ts in various ways.
> > > > > > > 3. KCSAN will assume that the access is safe, and no data rac=
e report
> > > > > > > is generated.
> > > > > > > 4. If somebody modifies ZONES bits concurrently, KCSAN will t=
ell you
> > > > > > > about the race.
> > > > > > > 5. We're documenting the code.
> > > > > > >=20
> > > > > > > Anything I missed?
> > > > > >=20
> > > > > > I don=E2=80=99t know. Having to write the same line twice does =
not feel me any better than data_race() with commenting occasionally.
> > > > >=20
> > > > > Point 4 above: While data_race() will ignore cause KCSAN to not r=
eport
> > > > > the data race, now you might be missing a real bug: if somebody
> > > > > concurrently modifies the bits accessed, you want to know about i=
t!
> > > > > Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but =
just
> > > > > remember that if you decide to silence it with data_race(), you n=
eed
> > > > > to be sure there are no concurrent writers to those bits.
> > > >=20
> > > > Right, in this case, there is no concurrent writers to those bits, =
so I'll add a
> > > > comment should be sufficient. However, I'll keep ASSERT_EXCLUSIVE_B=
ITS() in mind
> > > > for other places.
> > >=20
> > > Right now there are no concurrent writers to those bits. But somebody
> > > might introduce a bug that will write them, even though they shouldn'=
t
> > > have. With ASSERT_EXCLUSIVE_BITS() you can catch that. Once I have th=
e
> > > patches for this out, I would consider adding it here for this reason=
.
> >=20
> > Surely, we could add many of those to catch theoretical issues. I can t=
hink of
> > more like ASSERT_HARMLESS_COUNTERS() because the worry about one day so=
meone
> > might change the code to use counters from printing out information to =
making
> > important MM heuristic decisions. Then, we might end up with those too =
many
> > macros situation again. The list goes on, ASSERT_COMPARE_ZERO_NOLOOP(),
> > ASSERT_SINGLE_BIT() etc.
>=20
> I'm sorry, but the above don't assert any quantifiable properties in the =
code.
>=20
> What we want is to be able to catch bugs that violate the *current*
> properties of the code *today*. A very real property of the code
> *today* is that nobody should modify zonenum without taking a lock. If
> you mark the access here, there is no tool that can help you. I'm
> trying to change that.
>=20
> The fact that we have bits that can be modified locklessly and some
> that can't is an inconvenience, but can be solved.
>=20
> Makes sense?

OK, go ahead adding it if you really feel like. I'd hope this is not the
Pandora's box where people will eventually find more way to assert quantifi=
able
properties in the code only to address theoretical issues...


>=20
> Thanks,
> -- Marco
>=20
> > On the other hand, maybe to take a more pragmatic approach that if ther=
e are
> > strong evidences that developers could easily make mistakes in a certai=
n place,
> > then we could add a new macro, so the next time Joe developer wants to =
a new
> > macro, he/she has to provide the same strong justifications?
> >=20
> > >=20
> > > > >=20
> > > > > There is no way to automatically infer all over the kernel which =
bits
> > > > > we care about, and the most reliable is to be explicit about it. =
I
> > > > > don't see a problem with it per se.
> > > > >=20
> > > > > Thanks,
> > > > > -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1581345072.7365.30.camel%40lca.pw.
