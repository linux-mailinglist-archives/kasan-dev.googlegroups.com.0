Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXOJQXZAKGQEPYHLVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D5CEE157D1D
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 15:12:46 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id l62sf4713568ioa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 06:12:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581343965; cv=pass;
        d=google.com; s=arc-20160816;
        b=W15ayDBJs6YjfTQ8qv7EWtgIOwHByAA601wdyqi8jhGDWd4GyQyUoKKTIC/ILQtJee
         hrm0NRGTPfcstSWPqPVAF8mq21foXoN8XZppA99ywrgr/Qxs+OA4vDFYlikLE0KJ+v2V
         FqKIo6KBEQCNI8jMmTFO6HZL5NbXfuAUYJr6xSizkZLD0lATIqoD++rUHFlG3O+Xi+6P
         PkdW7xldFr0ThT/DMb+HkqbKL5GWjiWbUfd6KqH1La63gf3nSMEWPT/wnKbJ/1/dSyPI
         dA5F2r/2iqDVxTH+ut2tRu/l9nJ6xlYzcLNvip/rUNCvzt8aJXkQNVKbJFvd2DCpwASW
         NPWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wx7ZgrwruZ4ZLUfk0O4smRMKFexAzHhmwZmmy+Nph8s=;
        b=zdv6gPwis3WnDyrFcYEz9FnlKIz4Rsez2hZ9jHHyLa+cObDXK9CUhsAqqWQucenICD
         XJrShf6rQ1WfBcMfze1IYnwJDGrrv8kD7lRRhsx0vSftst0VDLkKCvLQc+7/oa/Gj93Q
         9FTPY+5gp2HJB+HujbqdvfwiGcbbNvohjC/2Xv7t3j3kmsF3Ioasgbu7XRHcwGR5Ebi2
         krZjmvaya240n4D93nnmVUd+Bj9R/W6jMpQSO0JRu1zjmehYmsg30jR5pM56lXjFygQL
         IazUeJdXNIIjO8T760YvWhajOrq98+CBEyqM+KthYPyLRLdOtLNr6kZiLAaestj1guKa
         L6dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s8AaOmsF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Wx7ZgrwruZ4ZLUfk0O4smRMKFexAzHhmwZmmy+Nph8s=;
        b=GJJDOVh2DnGsOTu/zApenodNycwqPfQLwrjKhLyNs5PR+GjTnLWCoCJCDXravfMZvG
         Qrx1EgVAW9xRZan52YuepPZmRv0wY1mCwvPvu07QThyuzu1HYsk8dLDL7JbW/y/BQRUW
         o0USWwOylkmgqvXzEhxWie2up/unQHvIKOjv/e1CLkbIFAYbhumWXZ014UD6JNDReVrJ
         NpfMFW3iQhCpBTObej4bS8SJDitILG7e0NJmIPotVkUGWjsFhnnxQT9yvsMX7yFjyrBd
         pfbQJLN0owdPLUxaRhwXAJHx4H/5KaUuKgGu8jWiWFcxH2fXbTZemzN1+BGvWowG1oF2
         G7DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wx7ZgrwruZ4ZLUfk0O4smRMKFexAzHhmwZmmy+Nph8s=;
        b=opxPX+oON0ZY1ZjJ/xxV2IsuG6R/iIGI7opUzdUf6U9TXlaWTELK1r1jyOLUehxfvj
         k2GTg2EZ+Qy28sUdany2qkcIu8eglciPxApyjhXzU6CCofpcjE2itAKBNC0VbwCBWp1W
         cVIkxxM/UWzT389HXrY3Fpff/CW1QQl5QCRk6Mw/jbrYDVFfrEK3j64C8Jd5z67AWjWq
         L50H9irtjWmUoR3iTvCFZu2lHNZGgoCvrWtpx15mqZMzCegmBIEs0buUoiPTBqKzir7D
         1q/+s5IDS5TVTzRzSCIyCrJCjWFDObllfVmtkoUmxYFisxgqrgZumOJZfD98obCJ4xCA
         VPbw==
X-Gm-Message-State: APjAAAWdunVtk6qF7i04Va5A3uYmv1rQE1qnm3uIm12IInoeB/Pn8aTd
	/q5t6Tty2SFZ1uXmBPnVvs0=
X-Google-Smtp-Source: APXvYqxY/F12mB0uxPck/38cHxRU8l6cV9NvPpb0ZNuUZ8JzqxFMWTxzSyNzOHHKKgZ5pI0vzoKUnw==
X-Received: by 2002:a02:c6d5:: with SMTP id r21mr10082212jan.129.1581343965414;
        Mon, 10 Feb 2020 06:12:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:5f17:: with SMTP id t23ls1359624iob.10.gmail; Mon, 10
 Feb 2020 06:12:44 -0800 (PST)
X-Received: by 2002:a6b:3845:: with SMTP id f66mr10059574ioa.102.1581343964709;
        Mon, 10 Feb 2020 06:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581343964; cv=none;
        d=google.com; s=arc-20160816;
        b=Xoke3ulmdgMBnP1Ii4kigg2VWdUX0pEavh0UH+mPTZzEKknXQy2q8AxeP7JknFRS5l
         YdW6Xolhmq/o3fXOtBdjLpUgJA6FzrN6SG262OPHg6QmD3zPFvAE8wDMXv8y+9oblQvD
         P9JO6I2QoUoZ1kjAgqmtTDoKeIcz9ErIpY4OzGJC4zn72J02d0bjFIplwhorp4syM6jD
         /b5drdmTyNBOd+4sdItr5Q8qcV58aP50pAa+mVu7+CeSPZcldGUNZgFIBRguuz0ndMVi
         meXjHP3WmAAf2L+YKIP5lxEwCkmZbL0aDE0303xl6DJrDG81dviRQHiup+DDx2nmEeeN
         jWRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ST/uAoLQf5dHHFUuf0J7KbsthQeZglVfBV4jHCEUrUk=;
        b=IA4rRH8Np+FwAvNtJyiKMpAAtTe6KcMeBQn97FSjBPoEaExQ3z1wOfpt9yUDo0aKoT
         L/pW/p5gzx5cKRWTOGT6jqmGlkNzXF45sJTUeNjC+p3khJ/60Bjkh9rnWqbbOmcD8OT5
         KVr+YH7b9IzWJnnKO5fFyXVikUZ49rp6J/f1Hc+CChb4PLNGI5PgAnR4xDzurJS1C4R5
         8VBLnlhKL5+Dxe0tlkSr6qBRTOA0vRtaH8lnzLmxPDFkubvOqHb/hGtA/xgGScPGEL6p
         iYz4stSbDWk3Wmt4nwcMtGxD+Mlp9FNqPzvhuVxK8mBUcpHxRnT7A9GQPevftXRu+nal
         Ctxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s8AaOmsF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id b16si21768ion.0.2020.02.10.06.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 06:12:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id z2so9285184oih.6
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 06:12:44 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr884734oiz.155.1581343963985;
 Mon, 10 Feb 2020 06:12:43 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw> <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
 <1581341769.7365.25.camel@lca.pw> <CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF+GZqqxvpC8Ui4iN8New@mail.gmail.com>
 <1581342954.7365.27.camel@lca.pw>
In-Reply-To: <1581342954.7365.27.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 15:12:32 +0100
Message-ID: <CANpmjNN=SNr=HJMLrQUno2F1L4PmQL19JfvVjngKee77tN2q-Q@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=s8AaOmsF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 10 Feb 2020 at 14:55, Qian Cai <cai@lca.pw> wrote:
>
> On Mon, 2020-02-10 at 14:38 +0100, Marco Elver wrote:
> > On Mon, 10 Feb 2020 at 14:36, Qian Cai <cai@lca.pw> wrote:
> > >
> > > On Mon, 2020-02-10 at 13:58 +0100, Marco Elver wrote:
> > > > On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
> > > > >
> > > > >
> > > > >
> > > > > > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wro=
te:
> > > > > >
> > > > > > Here is an alternative:
> > > > > >
> > > > > > Let's say KCSAN gives you this:
> > > > > >   /* ... Assert that the bits set in mask are not written
> > > > > > concurrently; they may still be read concurrently.
> > > > > >     The access that immediately follows is assumed to access th=
ose
> > > > > > bits and safe w.r.t. data races.
> > > > > >
> > > > > >     For example, this may be used when certain bits of @flags m=
ay
> > > > > > only be modified when holding the appropriate lock,
> > > > > >     but other bits may still be modified locklessly.
> > > > > >   ...
> > > > > >  */
> > > > > >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> > > > > >
> > > > > > Then we can write page_zonenum as follows:
> > > > > >
> > > > > > static inline enum zone_type page_zonenum(const struct page *pa=
ge)
> > > > > > {
> > > > > > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_=
PGSHIFT);
> > > > > >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > > > > > }
> > > > > >
> > > > > > This will accomplish the following:
> > > > > > 1. The current code is not touched, and we do not have to verif=
y that
> > > > > > the change is correct without KCSAN.
> > > > > > 2. We're not introducing a bunch of special macros to read bits=
 in various ways.
> > > > > > 3. KCSAN will assume that the access is safe, and no data race =
report
> > > > > > is generated.
> > > > > > 4. If somebody modifies ZONES bits concurrently, KCSAN will tel=
l you
> > > > > > about the race.
> > > > > > 5. We're documenting the code.
> > > > > >
> > > > > > Anything I missed?
> > > > >
> > > > > I don=E2=80=99t know. Having to write the same line twice does no=
t feel me any better than data_race() with commenting occasionally.
> > > >
> > > > Point 4 above: While data_race() will ignore cause KCSAN to not rep=
ort
> > > > the data race, now you might be missing a real bug: if somebody
> > > > concurrently modifies the bits accessed, you want to know about it!
> > > > Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but ju=
st
> > > > remember that if you decide to silence it with data_race(), you nee=
d
> > > > to be sure there are no concurrent writers to those bits.
> > >
> > > Right, in this case, there is no concurrent writers to those bits, so=
 I'll add a
> > > comment should be sufficient. However, I'll keep ASSERT_EXCLUSIVE_BIT=
S() in mind
> > > for other places.
> >
> > Right now there are no concurrent writers to those bits. But somebody
> > might introduce a bug that will write them, even though they shouldn't
> > have. With ASSERT_EXCLUSIVE_BITS() you can catch that. Once I have the
> > patches for this out, I would consider adding it here for this reason.
>
> Surely, we could add many of those to catch theoretical issues. I can thi=
nk of
> more like ASSERT_HARMLESS_COUNTERS() because the worry about one day some=
one
> might change the code to use counters from printing out information to ma=
king
> important MM heuristic decisions. Then, we might end up with those too ma=
ny
> macros situation again. The list goes on, ASSERT_COMPARE_ZERO_NOLOOP(),
> ASSERT_SINGLE_BIT() etc.

I'm sorry, but the above don't assert any quantifiable properties in the co=
de.

What we want is to be able to catch bugs that violate the *current*
properties of the code *today*. A very real property of the code
*today* is that nobody should modify zonenum without taking a lock. If
you mark the access here, there is no tool that can help you. I'm
trying to change that.

The fact that we have bits that can be modified locklessly and some
that can't is an inconvenience, but can be solved.

Makes sense?

Thanks,
-- Marco

> On the other hand, maybe to take a more pragmatic approach that if there =
are
> strong evidences that developers could easily make mistakes in a certain =
place,
> then we could add a new macro, so the next time Joe developer wants to a =
new
> macro, he/she has to provide the same strong justifications?
>
> >
> > > >
> > > > There is no way to automatically infer all over the kernel which bi=
ts
> > > > we care about, and the most reliable is to be explicit about it. I
> > > > don't see a problem with it per se.
> > > >
> > > > Thanks,
> > > > -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN%3DSNr%3DHJMLrQUno2F1L4PmQL19JfvVjngKee77tN2q-Q%40mail.gm=
ail.com.
