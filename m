Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6MLQ3ZAKGQENBN7ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BCE74157FD5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 17:34:02 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id 203sf5551588pfx.5
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 08:34:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581352441; cv=pass;
        d=google.com; s=arc-20160816;
        b=WXcwrWMReO9/7G6Qgdx8AOMibtEC1wfI4+wTNF5SRI9MRXlBXy0oMJjbgaUOIhUFhQ
         9VVP4FAT0wQIwzzZXfKPjLGdsEFSG7IcEkWx1G3N2gr/hgfWcj+P7zSYf6BHcohidstS
         2Rgq/XQLqlP6l/J+Z7bpnR/ClLFk4d0xBr4uZtELrAzM3au7e3cx3FWouzIn8pApqoVv
         J1M2c3vBpB/8CqZObbhZXvz5m1v9B42FivEZKUJI6y3KHoCIHtlSJYzQdvMi8OL7s4dp
         Nvbxv1oOK7FJKogR3kg8Bn+DgxEUKtNpWnJgkWd1lyX/JmJ/mtbU9sZ+YUjV4lov2QYT
         5E/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=60zPRQaON+qptSPLr1hp/asQ14qSTwHYv95AkgpWHiI=;
        b=NMmGN5d4WA4JzqxB+bxPaQUzBRygo6gtYYaH68G8fuR1SvyzJOvnXAjqKDuoYfcU/d
         rkG6ljg51i3jagUcsbrLH5wDftenkTttFHQn2/+P9AXmdeDbv0+pmmcBbA/lAZwfO/b3
         /6z9UovpJur5os6ZpAS3vYh6uD3BwXQd1lOB8w9vQt0V+tYeGfBFty9dmsF/U/kLcfGt
         qkRQ1+Ro1ByZDt9Dfeb/+g47p5rcmkaD/jScyro6JLX/geqnQf8Y8J0BchP+FnigZ0l1
         F5OMtHkTnWSLbpPjhcyvOCfA9CAkNAsDXK/2i33LRDIH3140q4+aWChSroeqUFpfGN6X
         T0XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HmUZAl2b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=60zPRQaON+qptSPLr1hp/asQ14qSTwHYv95AkgpWHiI=;
        b=ENv02tyl5WzKiiawCRd00RMzfrM8PReJ1VnQz6b5zbngVHctlDtEVeU3o6OlEr2ZrL
         gy/rqDIlrFJGK+qC3RisGhvMIbLfsQjtJjYK2DaISJx0VlHPwg/y70Lb5MzDFSPam0+4
         QZuc4nbkynd9t7xEGxNdm9STx+DH+CzW1SEU9zpmNH9/L8Tdc8qu2JT7boPOoIbSv/gc
         FQiVzeuyv4i5ISMkyX8xD9gdZIE6kZbbn0batL2tlD+AzS6VMsAzB0RCF1XOER1PYQ+a
         5l8SZg/yL/TvLTd8PJI7xSl7OP26mpbxntoNzcxLiW452ZlpJwHB/nIVzMNtjWwrbnXi
         Mvng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=60zPRQaON+qptSPLr1hp/asQ14qSTwHYv95AkgpWHiI=;
        b=QSOQtQ2Tkb1WwFHY5utWrgjDqrc+grid9NeMh/yUbAGuK4EU569Sy7eX+p44whpPqk
         L0Mym9DdnLd4LTKrR0yD7+cuq91SSxxW21reDbjzvD/0xhCA+BpyPHsmgTmRAr9iJNjj
         Gn+7HK/T4+K+zYJNO1AnPtM0CqwUNRJlRyqmbgUhdIPgArACy5hk0RXWT0GUdGte1SZh
         XJj09xnQccQ0WJUWm/ZB7WbZn/f3MSrfEVmQ7hRIgSbbqdbPNIoBUfHzYcRHhGzbPg4E
         zo8sxKesJ9/j74EMbh93xpoAId8AOlMZs/usk6dg6h9efjs7qfo7MwQQ7xJi03GUDIDx
         3ljg==
X-Gm-Message-State: APjAAAWL02azGjN5MkZn+15kKJOw+6ac/RBWfmpt7CKcpVbD9rlFC79t
	eW5GXw5IJRUvo+++UeLDaWE=
X-Google-Smtp-Source: APXvYqxk01ftqW82UwTZw8IKu/f6ALiObJRxApO6CZs1S1kO6xynlComrfzyVgA2IjE+nURu1CPj3A==
X-Received: by 2002:a17:90b:1256:: with SMTP id gx22mr2738585pjb.94.1581352441133;
        Mon, 10 Feb 2020 08:34:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab86:: with SMTP id f6ls4058180plr.10.gmail; Mon, 10
 Feb 2020 08:34:00 -0800 (PST)
X-Received: by 2002:a17:90a:9f04:: with SMTP id n4mr2734557pjp.76.1581352440594;
        Mon, 10 Feb 2020 08:34:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581352440; cv=none;
        d=google.com; s=arc-20160816;
        b=TYPYIpDxW+Bt3AjDy6QkBiPsdabcO56PsYjouOq4vKz1o4gjWsgG7D3A2uUOJo1aat
         tQ76pUMyTDBtivwLQKWMmOCcRsET5IJzNODCW8MWftsb8VIqYSfsmJc7RdEUGOCzj2E8
         aHenZ//nCXcu1ikj642nnWWvedSmUns0Jqd6FL3lQCoXgiCam3FfSn53cX+8xtTDIRcQ
         X022fHINW+Gwc+Ra8IDPWVzCMCjRf+me65P9oVZpO7nKurOMZKs9hUe3v3isnXTgQYut
         tz+YwvN5peyYnwriV5yH44juap0k55nDoxzq79/SAAbZwm0Pc+iOybWmmf5MsZIrQTLW
         vljQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wf+AhbPiSiYAxsrHR8SQ2ICmgdSGnvtwAFNxR7pXl/o=;
        b=BKfBiBx9Odo9m07mEalzC9mu/nIVQlAr3+V+KGhWXs4ZR0GUl7wJ//TlDvB7dFAC1Z
         T/V0Qz9ASOSQHKTCJU8j7EbdPaarSclLkTrKjuq1M8WzTzOKMPYP9BElns1LnTYIwbnu
         l1HJSF+1mZ+1W1p5wmZXz/sTFpLXy6dRm7/CdZc/B/2mClUrlJ0Ggu2fc/O9yHuQ2WUx
         sXhhcrUbIpQ/i1c0agmyGnlPcsR27MCecAbcL/3Yq7ObuAU1xmr9sX9ZyL5Lu3YsjIcw
         kYo1f6iZHb6QmQAj7Baz2TM8qkPcOYpH6gfnmYfLr97FKPhaj1ktd1F2lVFgdRRQP6WD
         5BIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HmUZAl2b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id j123si27181pfd.5.2020.02.10.08.34.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 08:34:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id 66so6921952otd.9
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 08:34:00 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr1781390otq.17.1581352439599;
 Mon, 10 Feb 2020 08:33:59 -0800 (PST)
MIME-Version: 1.0
References: <5402183a-2372-b442-84d3-c28fb59fa7af@nvidia.com>
 <8602A57D-B420-489C-89CC-23D096014C47@lca.pw> <1a179bea-fd71-7b53-34c5-895986c24931@nvidia.com>
 <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com> <1581351789.7365.32.camel@lca.pw>
In-Reply-To: <1581351789.7365.32.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 17:33:48 +0100
Message-ID: <CANpmjNPzH6rCQT+Pe_atpm8D68Tt9ChMg276jECxOyNzTUS=NA@mail.gmail.com>
Subject: Re: [PATCH] mm: fix a data race in put_page()
To: Qian Cai <cai@lca.pw>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>, 
	David Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, ira.weiny@intel.com, 
	Dan Williams <dan.j.williams@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HmUZAl2b;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Mon, 10 Feb 2020 at 17:23, Qian Cai <cai@lca.pw> wrote:
>
> On Mon, 2020-02-10 at 08:48 +0100, Marco Elver wrote:
> > On Sun, 9 Feb 2020 at 08:15, John Hubbard <jhubbard@nvidia.com> wrote:
> > >
> > > On 2/8/20 7:10 PM, Qian Cai wrote:
> > > >
> > > >
> > > > > On Feb 8, 2020, at 8:44 PM, John Hubbard <jhubbard@nvidia.com> wr=
ote:
> > > > >
> > > > > So it looks like we're probably stuck with having to annotate the=
 code. Given
> > > > > that, there is a balance between how many macros, and how much co=
mmenting. For
> > > > > example, if there is a single macro (data_race, for example), the=
n we'll need to
> > > > > add comments for the various cases, explaining which data_race si=
tuation is
> > > > > happening.
> > > >
> > > > On the other hand, it is perfect fine of not commenting on each dat=
a_race() that most of times, people could run git blame to learn more detai=
ls. Actually, no maintainers from various of subsystems asked for commentin=
g so far.
> > > >
> > >
> > > Well, maybe I'm looking at this wrong. I was thinking that one should=
 attempt to
> > > understand the code on the screen, and that's generally best--but her=
e, maybe
> > > "data_race" is just something that means "tool cruft", really. So men=
tally we
> > > would move toward visually filtering out the data_race "key word".
> >
> > One thing to note is that 'data_race()' points out concurrency, and
> > that somebody has deemed that the code won't break even with data
> > races. Somebody trying to understand or modify the code should ensure
> > this will still be the case. So, 'data_race()' isn't just tool cruft.
> > It's documentation for something that really isn't obvious from the
> > code alone.
> >
> > Whenever we see a READ_ONCE or other marked access it is obvious to
> > the reader that there are concurrent accesses happening.  I'd argue
> > that for intentional data races, we should convey similar information,
> > to avoid breaking the code (of course KCSAN would tell you, but only
> > after the change was done). Even moreso, since changes to code
> > involving 'data_race()' will need re-verification that the data races
> > are still safe.
> >
> > > I really don't like it but at least there is a significant benefit fr=
om the tool
> > > that probably makes it worth the visual noise.
> > >
> > > Blue sky thoughts for The Far Future: It would be nice if the tools g=
ot a lot
> > > better--maybe in the direction of C language extensions, even if only=
 used in
> > > this project at first.
> >
> > Still thinking about this.  What we want to convey is that, while
> > there are races on the particular variable, nobody should be modifying
> > the bits here. Adding a READ_ONCE (or data_race()) would miss a
> > harmful race where somebody modifies these bits, so in principle I
> > agree. However, I think the tool can't automatically tell (even if we
> > had compiler extensions to give us the bits accessed) which bits we
> > care about, because we might have something like:
> >
> > int foo_bar =3D READ_ONCE(flags) >> FOO_BAR_SHIFT;  // need the
> > READ_ONCE because of FOO bits
> > .. (foo_bar & FOO_MASK) ..  // FOO bits can be modified concurrently
> > .. (foo_bar & BAR_MASK) ..  // nobody should modify BAR bits
> > concurrently though !
> >
> > What we want is to assert that nobody touches a particular set of
> > bits. KCSAN has recently gotten ASSERT_EXCLUSIVE_{WRITER,ACCESS}
> > macros which help assert properties of concurrent code, where bugs
> > won't manifest as data races. Along those lines, I can see the value
> > in doing an exclusivity check on a bitmask of a variable.
> >
> > I don't know how much a READ_BITS macro could help, since it's
> > probably less ergonomic to have to say something like:
> >   READ_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT) >> ZONES_PGSHIFT.
> >
> > Here is an alternative:
> >
> > Let's say KCSAN gives you this:
> >    /* ... Assert that the bits set in mask are not written
> > concurrently; they may still be read concurrently.
> >      The access that immediately follows is assumed to access those
> > bits and safe w.r.t. data races.
> >
> >      For example, this may be used when certain bits of @flags may
> > only be modified when holding the appropriate lock,
> >      but other bits may still be modified locklessly.
> >    ...
> >   */
> >    #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> >
> > Then we can write page_zonenum as follows:
> >
> > static inline enum zone_type page_zonenum(const struct page *page)
> >  {
> > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT)=
;
> >         return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> >  }
>
> Actually, it seems still need to write if I understand correctly,
>
> ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
> return data_race((page->flags >> ZONES_PGSHIFT) & ZONES_MASK);

No, I designed it so you won't need 'data_race()' if you don't want
to. I'll send the patches shortly.

> On the other hand, if you really worry about this thing could go wrong, i=
t might
> be better of using READ_ONCE() at the first place where it will be more f=
uture-
> proof with the trade-off it might generate less efficient code optimizati=
on?

The READ_ONCE() I'd still advocate for, but KCSAN won't complain if
the pattern is as written above.

> Alternatively, is there a way to write this as this?
>
> return ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);

It's an ASSERT, without KCSAN it should do nothing, so this is wrong.
Also, this won't work because you're no longer returning the same
value. I thought about this for READ_BITS, but you'd need (I wrote
this earlier in the thread that it likely won't be suitable):

   READ_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT) >> ZONES_PGSHIFT

to get the equivalent result (notice this will result in a redundant
shift). Because we have all kinds of permutations and variants of how
to extract the same bits out of some flags, it's cleaner to have one
'ASSERT_EXCLUSIVE_BITS' and just give it the bits you care about.

Thanks,
-- Marco

> Kind of ugly but it probably cleaner.
>
> >
> > This will accomplish the following:
> > 1. The current code is not touched, and we do not have to verify that
> > the change is correct without KCSAN.
> > 2. We're not introducing a bunch of special macros to read bits in vari=
ous ways.
> > 3. KCSAN will assume that the access is safe, and no data race report
> > is generated.
> > 4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
> > about the race.
> > 5. We're documenting the code.
> >
> > Anything I missed?
> >
> > Thanks,
> > -- Marco
> >
> >
> >
> >
> >
> > > thanks,
> > > --
> > > John Hubbard
> > > NVIDIA
> > >
> > > > >
> > > > > That's still true, but to a lesser extent if more macros are adde=
d. In this case,
> > > > > I suspect that READ_BITS() makes the commenting easier and shorte=
r. So I'd tentatively
> > > > > lead towards adding it, but what do others on the list think?
> > > >
> > > > Even read bits could be dangerous from data races and confusing at =
best, so I am not really sure what the value of introducing this new macro.=
 People who like to understand it correctly still need to read the commit l=
ogs.
> > > >
> > > > This flags->zonenum is such a special case that I don=E2=80=99t rea=
lly see it regularly for the last few weeks digging KCSAN reports, so even =
if it is worth adding READ_BITS(), there are more equally important macros =
need to be added together to be useful initially. For example, HARMLESS_COU=
NTERS(), READ_SINGLE_BIT(), READ_IMMUTATABLE_BITS() etc which Linus said ex=
actly wanted to avoid.
> > > >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPzH6rCQT%2BPe_atpm8D68Tt9ChMg276jECxOyNzTUS%3DNA%40mail.gm=
ail.com.
