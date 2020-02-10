Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBS5YQXZAKGQE4YD4AUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 179C5157C3F
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 14:36:13 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id b8sf4959605qvw.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 05:36:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581341772; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0zelgGcm6C7wgFcoZUJQ7KSEtqHqbCOVL9SFEp2tpTLMPInwd/kE6xJqHHa7Pq6kV
         mu+1b3DfrsvrrF27e6wzuwvUx9iFpRbSP8xJh8yvsPiGJE8F+PNKjPd+gpLcJmLqPqcV
         cdSvFsO9bYRDM2KWHF9HPpVLPYwKkZLCcMp/45mSf2e9mY5N9ChZ5dXQ5QMscbRGqmcI
         i8MG0gvvlV9C9T2h4Fe2JEJh1u77ksMVQfgsGhM47Kt57+fmJBHw8q9jOEKZxPfnEM7b
         idIDn/TATtHgzQe/7HhH9KKrL8o7fH3qwXLH84QiTKYPlj9gQ3xtvdiJ/AJprVVRuKNq
         PGSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=mwNLJzfy0BasVxkPRleZBogjCrZqTVCfz4scaZcHRHc=;
        b=ajjLHjdXSuP2XpXFjgb6wU/ex6njxfGPJZRbksssp8O5qCS6PHu1zQE7HUqY1qEaQ3
         RK2zlj9HehygeoCZ3rtxypZLBnyr59SkWr4KXycbWClri/NNunLGH4dLylQgm7r/qTgD
         CLY81SoZjWzRww93/4SASO4FYkK08YPkWXvXb5D+fUlQlXloCgM6d8l1hKjrXBWtMyk1
         hEiI+BTPac48afq1FktAqhYMYIDSp2JQSbRDZyYlsZKBpQuCuVl1JIe2iqjGFYX6PSIz
         kMjQslDdDsYFO+glveZKSmmlee+7OF12lgRr+AkkbUvWQdLz41HKz9PTdf0UTBkm44ZY
         /RPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hOLmFJuX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mwNLJzfy0BasVxkPRleZBogjCrZqTVCfz4scaZcHRHc=;
        b=FZ+s0xEjAQMaod4pwFROT7F9iMd8jusG+t9Cbvd1z/NOIw+8VaZCXRCSKpmlL/Ia/n
         sIfygmllIUT1n4XKDXjFe5krI82QG2KtB44Tzi9pOCFObXSPkSHNlO9mnc3FYacAXNt2
         Znd2eKy8XBJTEMga5gAI0Kn2t7THSOggvtR7Lkkv0A4E8kNe5iGKtHLmu27dWuPimINt
         sqXDlbTUVP/j4oQHqDPnvCyydiUbNeOr8Ukf70+Py7KaHcibOb7KHcAyLZ3HWxI554FM
         6Ic+GkIY6q5ProzG60fHUfPwx214gIAMtLF+Lyn6ewSp1CYyou9vVXZTQdxi3ohY5Htn
         2sRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mwNLJzfy0BasVxkPRleZBogjCrZqTVCfz4scaZcHRHc=;
        b=nhYkVZ4+9o5T/c1hL9Dkcl+Jksu7BlcLJlwom5f/0ATmvOIHi/T6AJjqzkqBMHWrrm
         IcZOkApTFOgIf2CGIdJ9A4UUhtWF6oZ1Bt9ATuU2iGF7zRl3n7I1FGtHbo3cKixv4qsl
         ++KraADNNQPpCV0hGN0zDi+Rd7zW5pPAwvgtASkd2rmMaqB+OQl56aOxcSgU9nRwZnpu
         lsIA3ci4WIbOlL8oEgIOgDUySnx/YFR4g81SbZ/C6EqKNUNUPhCBk8QkYpNlGZjVqYNa
         VK/zV0oP44TFpW82AzqnYmho6NdZWmZs7JQX+ksCcD+GEoNFNMMW/Ca0kL/qlcyvYAYb
         UTiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFu3nRzEduBNONyvOV4qKgu0Ho0WJkZUTxTLoKIWNpAPEqDI9n
	fGzs8gEdEl+6hk1ilXagNkI=
X-Google-Smtp-Source: APXvYqysFeBau7j2TAE1UlUUuc2aS+DCf53BITKImiFDl1uEKQQZ8yjPsRbIiq6tAl4LA/QplTJHvg==
X-Received: by 2002:a05:6214:1090:: with SMTP id o16mr10037484qvr.105.1581341772006;
        Mon, 10 Feb 2020 05:36:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1650:: with SMTP id f16ls1671570qvw.0.gmail; Mon,
 10 Feb 2020 05:36:11 -0800 (PST)
X-Received: by 2002:a0c:fec3:: with SMTP id z3mr9654961qvs.111.1581341771661;
        Mon, 10 Feb 2020 05:36:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581341771; cv=none;
        d=google.com; s=arc-20160816;
        b=pRPGndljEtJyZiIbF8y7ckWCuD5NJyr95H6h9wkdRG+SFYos+OfOh7DuIZFGlMS5Y5
         6391PhPg0nlB0TkR9KZ1K8n0j+ZTYJOjDAJ4+jtkx5RpCzgATZF1I+iceFqKNZArY7+t
         bmxHCwE9SRBaA8Cj9s4nPEUw4m0nqOj/VtqTAnumLZy/ROv8SS+wg9FnGMt6qDJf6F0/
         WFowlO3NOSfoTkqyyQEmlbDsJqvzsJvi3XeKcGQit/pDoUAi4mnDqyDj8kuDqQmKlxyB
         0L0pCrVbiAOKhuVri0UbVJBlWVFss2+lWyW62/h2SAcRfU6KYjeDYcCN8BbNTyGrhfeM
         0zrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=K7xCPnfPDVaR+RixreW4kHYksD72YNNnHkzPeZTukvc=;
        b=erk/AW+nmE1USe8mUCvXwzq70zjV5yAdr9LtrpDp5cJAaHSrPWttgHcHYJwwMTJRCf
         7A+nn4wAZcCzVWxnXuBXISG4uWIvdiPlbBujwlsVQ/TBuf0nwX6Usxsc8i0/EOQISifi
         sFZxtHyShfKN6VISSoluUIT8+scVWESG36HOEiDRGnwVbZklGXr4UH6OgqTHyYCoiLAi
         9UCeeINL41qVw66BbuD0uI/2YbSMRoNj1JEORLmD9ll3aFf95Y264+goDoCy5z1WilyP
         OClVZnwq3FAvGAqoQKrZeuNutnLsP+6mAOu6afPa2K+i2o5GK3eshfJQEZ5hN2sHpS7X
         rquw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=hOLmFJuX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id b25si10960qkl.7.2020.02.10.05.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:36:11 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id v25so5088629qto.7
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 05:36:11 -0800 (PST)
X-Received: by 2002:ac8:163c:: with SMTP id p57mr10090991qtj.106.1581341771026;
        Mon, 10 Feb 2020 05:36:11 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id 205sm144034qkd.61.2020.02.10.05.36.09
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:36:10 -0800 (PST)
Message-ID: <1581341769.7365.25.camel@lca.pw>
Subject: Re: [PATCH] mm: fix a data race in put_page()
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>, David
 Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
 ira.weiny@intel.com, Dan Williams <dan.j.williams@intel.com>, Linux Memory
 Management List <linux-mm@kvack.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 08:36:09 -0500
In-Reply-To: <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
	 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
	 <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=hOLmFJuX;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as
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

On Mon, 2020-02-10 at 13:58 +0100, Marco Elver wrote:
> On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
> >=20
> >=20
> >=20
> > > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wrote:
> > >=20
> > > Here is an alternative:
> > >=20
> > > Let's say KCSAN gives you this:
> > >   /* ... Assert that the bits set in mask are not written
> > > concurrently; they may still be read concurrently.
> > >     The access that immediately follows is assumed to access those
> > > bits and safe w.r.t. data races.
> > >=20
> > >     For example, this may be used when certain bits of @flags may
> > > only be modified when holding the appropriate lock,
> > >     but other bits may still be modified locklessly.
> > >   ...
> > >  */
> > >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> > >=20
> > > Then we can write page_zonenum as follows:
> > >=20
> > > static inline enum zone_type page_zonenum(const struct page *page)
> > > {
> > > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIF=
T);
> > >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > > }
> > >=20
> > > This will accomplish the following:
> > > 1. The current code is not touched, and we do not have to verify that
> > > the change is correct without KCSAN.
> > > 2. We're not introducing a bunch of special macros to read bits in va=
rious ways.
> > > 3. KCSAN will assume that the access is safe, and no data race report
> > > is generated.
> > > 4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
> > > about the race.
> > > 5. We're documenting the code.
> > >=20
> > > Anything I missed?
> >=20
> > I don=E2=80=99t know. Having to write the same line twice does not feel=
 me any better than data_race() with commenting occasionally.
>=20
> Point 4 above: While data_race() will ignore cause KCSAN to not report
> the data race, now you might be missing a real bug: if somebody
> concurrently modifies the bits accessed, you want to know about it!
> Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but just
> remember that if you decide to silence it with data_race(), you need
> to be sure there are no concurrent writers to those bits.

Right, in this case, there is no concurrent writers to those bits, so I'll =
add a
comment should be sufficient. However, I'll keep ASSERT_EXCLUSIVE_BITS() in=
 mind
for other places.

>=20
> There is no way to automatically infer all over the kernel which bits
> we care about, and the most reliable is to be explicit about it. I
> don't see a problem with it per se.
>=20
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1581341769.7365.25.camel%40lca.pw.
