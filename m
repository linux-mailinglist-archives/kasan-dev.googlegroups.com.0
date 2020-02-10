Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRUVQTZAKGQEFW22MLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C93E2157011
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 08:48:23 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id v3sf4496673qvm.2
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 23:48:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581320902; cv=pass;
        d=google.com; s=arc-20160816;
        b=VB9s8/c0k+T7HQLCny1qXwHqC01CpGqnFSNi2MNTgI7Dz6TxdO/1pvrBGxUfu/fpQV
         r2W6fyUWPEz34Nk05YoWngAIhHzLvY3v3KbqnIr3EqEg5vGgGiVKnI8bI+jedqWQkuAR
         39si384hvqjV8au5gFQYIj9A8TK1l8TfFfxR188uE92MKTzqryHEoV3Vpjs1j7gdzZ2F
         kY6Mdi6nuDORUZpFoWfB8mCMBiI0e+l9Ho/AyH93s02NAIibZsmBZUtjJIwRNHOzg2lc
         ZtScjSJMXLI8uduqnutZcrKIQl+05BbXSeyTpRej3xomgOzDFlzAVYl80Dvd/DiW/iny
         oOTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qGzZkZOr92vuOesTjhQbvlHoTEsR9lvQyT6WMIRexew=;
        b=XBoOH6i7Fko6cOiHXeQEKKEFMVgN59/u8mlckU+j/qWtyIn+1VeYB5yN6j5EN2YnLB
         NBlv4vKjokwhbV3dJj6zJnVx8cM7aC2Oaf23Gvy6tHjFrV3SITVC7wzsuF5+ZErOR3PQ
         /LcTW3HIUek9LB4vXt305nL9xeTR0jsdFLSqo/dCwIAL4YQ0Njjr1q1PeoihZMnkYy2f
         T+XqkZKmExMwywODqYDFWOy9aP4fLNBYJ8ohdPAmiVUbqGe/EaIY3JmxoHzCKK3bMptb
         Nj7U2HZ1H8p9GQR+gJtsAgMEGJV14sDFnpzSzfC+2br3BRLNqmjyKvYNuftCY2aGJvMO
         CUOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BXDgZ3uI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qGzZkZOr92vuOesTjhQbvlHoTEsR9lvQyT6WMIRexew=;
        b=hbwnVhgG6baDxziriwwIzFhGLm0r2t+Ilqj6TA5ZbxdarGWTh7464anROgSWXGUbeL
         DSv2IowNw4PpGTS3Y41kFWpKkVQ5fhM1jAXKmDXj6e1Vyuzob6zZyQKdfh3uzdtM59Yu
         KPC+BEcyEZR+9EhB2L/AL9G5kvE7GIuDKpfr/cVxqp1nCdswkPrnQ0cUTg4/ZqOJwUDQ
         DNkkDfbD+WMGCtTpM00Wd5fFKcqAnIgoBNSpBYz/f6mewsmeDmKl7lnnM7MgkA44QXSe
         03zcB+g+P6q0iaElNnCFDoTBxfPOZANwLDmHRAUY43FvHrKZ3K9rD9I41UivsyKwJG/t
         By1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qGzZkZOr92vuOesTjhQbvlHoTEsR9lvQyT6WMIRexew=;
        b=qLQk1gr6NQ+1xiJr3W2/ukNG1Rq8h7OV1rH4oK3EqIGG1vJYYYpecPZhR4jgCot6lq
         EQXlCnOVx5GRDYX3NKiwTCJiUxHaSYMxIwoo+nKaYFhWBK/ClgJakKjZfGa9pFgUVM7b
         +GIb/rarBz+vpsL3girIYvOdUIAEtkH58aUDDAtYh0fqSdBAecl3lH2jyRpYe5W1pHV/
         VSXbVgLdxWzsx+AoJZLHIP8Kz4TQ/614eTBZPn/VQ/4rK93ijHtGBJFjQUyjK4K74rrs
         ny+qrK5KCkviH1Rj7K4Vg7qUhnOES2gskXwJtmcpKzkUYhHb3c0FQmF/q+T8+HrDl/Hy
         HMeg==
X-Gm-Message-State: APjAAAWTHxRtYXPLCoALkhLeWupoaEWEslpIUPAVASANdBcYuULjThO9
	wsiiLJQeGozAnM5GAkUZM44=
X-Google-Smtp-Source: APXvYqx1r9fFgfHWlrsIDTS+yXBRp9/fXfCrHysiQ+e5j32jLtkcQpkXlbFnzNBHCfO8ci+sFxZh6Q==
X-Received: by 2002:a05:6214:1433:: with SMTP id o19mr7505405qvx.87.1581320902567;
        Sun, 09 Feb 2020 23:48:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1818:: with SMTP id q24ls2313815qtj.0.gmail; Sun, 09 Feb
 2020 23:48:22 -0800 (PST)
X-Received: by 2002:ac8:33f4:: with SMTP id d49mr9020374qtb.145.1581320902203;
        Sun, 09 Feb 2020 23:48:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581320902; cv=none;
        d=google.com; s=arc-20160816;
        b=NHNnCI/oZYJV2PgEYWZgP3JpIV8eFxJZW5IPDHQSO9A/a3j4STDJmEUmztmZEQeMK9
         hlE/64NgFGNGnHwx5Q5mQSUplvDteJAdM+6xtwvN5MnMChl+78roOHQT7nLprT9eXxo3
         IPnyZA+q1mIezU69Y0E6Suaj2/sFUf5Gnh9rj3vvyMVMHVKEbsNJNEYSVJpDmXZftFri
         fvP+AdqbipxeeVb+y95DDuaJUoPPApxjIsp/Q5ysds9ytUQIq2DZiAnT6+GXwGpcH1rR
         IW/hGmZRdF0ALyMJQvIqbaOxJ9KEBr/PgXYetyY7GBM3unwFs89F6KBPBG/krEW6BpQu
         nAcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=az0xrMz0KQMndBSBLSGsJUmYrXwbi8MgNFXptPawpwg=;
        b=vlReOGVQW9OQQGnHKW75gw1+eAu3bwMbmxqP38Xv8Iht2UaydeE+lAm5sxeBhT0AHC
         2TH6WNlIbI9GUuXfd9n9KleT/ubmNKjlsce8DgD8Xx3vQCFHow0MkFXOL8YhPO7bF9ds
         6AfA8gzDR5hldheeJE3XPqbd0ygpKC5OmkPMWe0kh83u9D7dJcTvyqgYLpDGP0bhoDVW
         fkiJ276bmANLF4hTrJfGKCA9Kym8fEVUL4bqFp68qoCH7JM0FRRfpy2UtKPArMP467ud
         HKr7rL/YVeOwyG+gVzIGhbW25vFZAmU760uEW4zoswV1Epx3NJZ17STIVc6er7J8/TAm
         f0yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BXDgZ3uI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id o21si252933qtb.3.2020.02.09.23.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 23:48:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id c16so8364537oic.3
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 23:48:22 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr61094oiz.155.1581320901440;
 Sun, 09 Feb 2020 23:48:21 -0800 (PST)
MIME-Version: 1.0
References: <5402183a-2372-b442-84d3-c28fb59fa7af@nvidia.com>
 <8602A57D-B420-489C-89CC-23D096014C47@lca.pw> <1a179bea-fd71-7b53-34c5-895986c24931@nvidia.com>
In-Reply-To: <1a179bea-fd71-7b53-34c5-895986c24931@nvidia.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 08:48:10 +0100
Message-ID: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
Subject: Re: [PATCH] mm: fix a data race in put_page()
To: John Hubbard <jhubbard@nvidia.com>
Cc: Qian Cai <cai@lca.pw>, Jan Kara <jack@suse.cz>, David Hildenbrand <david@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, ira.weiny@intel.com, 
	Dan Williams <dan.j.williams@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BXDgZ3uI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 9 Feb 2020 at 08:15, John Hubbard <jhubbard@nvidia.com> wrote:
>
> On 2/8/20 7:10 PM, Qian Cai wrote:
> >
> >
> >> On Feb 8, 2020, at 8:44 PM, John Hubbard <jhubbard@nvidia.com> wrote:
> >>
> >> So it looks like we're probably stuck with having to annotate the code=
. Given
> >> that, there is a balance between how many macros, and how much comment=
ing. For
> >> example, if there is a single macro (data_race, for example), then we'=
ll need to
> >> add comments for the various cases, explaining which data_race situati=
on is
> >> happening.
> >
> > On the other hand, it is perfect fine of not commenting on each data_ra=
ce() that most of times, people could run git blame to learn more details. =
Actually, no maintainers from various of subsystems asked for commenting so=
 far.
> >
>
> Well, maybe I'm looking at this wrong. I was thinking that one should att=
empt to
> understand the code on the screen, and that's generally best--but here, m=
aybe
> "data_race" is just something that means "tool cruft", really. So mentall=
y we
> would move toward visually filtering out the data_race "key word".

One thing to note is that 'data_race()' points out concurrency, and
that somebody has deemed that the code won't break even with data
races. Somebody trying to understand or modify the code should ensure
this will still be the case. So, 'data_race()' isn't just tool cruft.
It's documentation for something that really isn't obvious from the
code alone.

Whenever we see a READ_ONCE or other marked access it is obvious to
the reader that there are concurrent accesses happening.  I'd argue
that for intentional data races, we should convey similar information,
to avoid breaking the code (of course KCSAN would tell you, but only
after the change was done). Even moreso, since changes to code
involving 'data_race()' will need re-verification that the data races
are still safe.

> I really don't like it but at least there is a significant benefit from t=
he tool
> that probably makes it worth the visual noise.
>
> Blue sky thoughts for The Far Future: It would be nice if the tools got a=
 lot
> better--maybe in the direction of C language extensions, even if only use=
d in
> this project at first.

Still thinking about this.  What we want to convey is that, while
there are races on the particular variable, nobody should be modifying
the bits here. Adding a READ_ONCE (or data_race()) would miss a
harmful race where somebody modifies these bits, so in principle I
agree. However, I think the tool can't automatically tell (even if we
had compiler extensions to give us the bits accessed) which bits we
care about, because we might have something like:

int foo_bar =3D READ_ONCE(flags) >> FOO_BAR_SHIFT;  // need the
READ_ONCE because of FOO bits
.. (foo_bar & FOO_MASK) ..  // FOO bits can be modified concurrently
.. (foo_bar & BAR_MASK) ..  // nobody should modify BAR bits
concurrently though !

What we want is to assert that nobody touches a particular set of
bits. KCSAN has recently gotten ASSERT_EXCLUSIVE_{WRITER,ACCESS}
macros which help assert properties of concurrent code, where bugs
won't manifest as data races. Along those lines, I can see the value
in doing an exclusivity check on a bitmask of a variable.

I don't know how much a READ_BITS macro could help, since it's
probably less ergonomic to have to say something like:
  READ_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT) >> ZONES_PGSHIFT.

Here is an alternative:

Let's say KCSAN gives you this:
   /* ... Assert that the bits set in mask are not written
concurrently; they may still be read concurrently.
     The access that immediately follows is assumed to access those
bits and safe w.r.t. data races.

     For example, this may be used when certain bits of @flags may
only be modified when holding the appropriate lock,
     but other bits may still be modified locklessly.
   ...
  */
   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....

Then we can write page_zonenum as follows:

static inline enum zone_type page_zonenum(const struct page *page)
 {
+       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
 }

This will accomplish the following:
1. The current code is not touched, and we do not have to verify that
the change is correct without KCSAN.
2. We're not introducing a bunch of special macros to read bits in various =
ways.
3. KCSAN will assume that the access is safe, and no data race report
is generated.
4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
about the race.
5. We're documenting the code.

Anything I missed?

Thanks,
-- Marco





> thanks,
> --
> John Hubbard
> NVIDIA
>
> >>
> >> That's still true, but to a lesser extent if more macros are added. In=
 this case,
> >> I suspect that READ_BITS() makes the commenting easier and shorter. So=
 I'd tentatively
> >> lead towards adding it, but what do others on the list think?
> >
> > Even read bits could be dangerous from data races and confusing at best=
, so I am not really sure what the value of introducing this new macro. Peo=
ple who like to understand it correctly still need to read the commit logs.
> >
> > This flags->zonenum is such a special case that I don=E2=80=99t really =
see it regularly for the last few weeks digging KCSAN reports, so even if i=
t is worth adding READ_BITS(), there are more equally important macros need=
 to be added together to be useful initially. For example, HARMLESS_COUNTER=
S(), READ_SINGLE_BIT(), READ_IMMUTATABLE_BITS() etc which Linus said exactl=
y wanted to avoid.
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNaHAnKCMLb%2BNjs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg%40mail.gmai=
l.com.
