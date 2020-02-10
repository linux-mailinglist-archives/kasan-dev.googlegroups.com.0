Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB3WBQXZAKGQE7ZPP3PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E2D23157CD8
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 14:55:59 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id z19sf5275989pfn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 05:55:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581342958; cv=pass;
        d=google.com; s=arc-20160816;
        b=BidgKfi1LDAyaQTIQNpUBEf8B16pcIcxXSvXyGLXqe2kfw3TMjqR2+kY6e+81wrk/H
         zJMdTVPApHASc2t5uVWMhP1+0KeBctTu9rBm9/2uwUj1rZW6M6FxCoSxy71StlGstIuX
         BCtjJtSRZeewJ0ScPvgY9i2UfCRIkAppn7Um/yLFK+1xuYcihJQFbyOXWdzDYn9HjkN+
         WLUfmNsn2v2YdUdjUo11HVwO7DAoOAQ9RTsJ4wWrV8FtvDZ3P0OmMsuk3TNJj0eOWz5e
         wLEgoH6jIcDU/+quRpMHqryvm2DuH09Q6R3P1n26fEgfQCDPq/dOqYxq+0BVkbm6l175
         NeAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=XquCIMSVzF+8Jw1hfu4RjdG2kyOSnBYqCUGkJfk4BYw=;
        b=F15/5eFoXEDHYEe3qCW+/WYkdZzvWd0K+JKB1mGbl1JqCW8k3HDnNTX6eQF+RYn07H
         m0l560WSQ7OMimn13+iCVEHOWxU/Uviz4U0XvnEDRpUSZfvSt/i9ClA3wKP2Tvyxs302
         n517IMQPKu+c74c3xAziwlJHTAak23MKQ1YClsD7Bz5TOn/XMCkTHmU36M3pKjvqA/xC
         OFFsbitFGfBnGT9R77yD3nhWZTTblvUcwfO1lwxrlw/mjLys//9Ua6lbu76mlOWeiR1S
         RS5aYKaqWa6T+/P86nBC4UBxZWhgu23CeiQ2dzdsl06NHDGF40O2N1U98Ws4mcJ+8KZE
         53Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=StiymXhX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XquCIMSVzF+8Jw1hfu4RjdG2kyOSnBYqCUGkJfk4BYw=;
        b=Fd/kf+rpB7eGxqrRfJdp48o4vBn47epqZ9YeKJOuI3kvvLGctJ6b/twAPzDhwKl4d/
         N1pi7VpXqCsviz+H5VH90yiPPymyAIt6ENJjbB1tX/FajbdPOWMvuWGDoktZeiy3fym6
         Bap+dkF6ToZOqU/00zfgpppB0VJXZE8L6yMVKKVr/BN7FSY9PgcOP8dnWYZnC2YAC+ea
         YweAEpmnU6glbCCmW3WIMjnlHeoS5iME5NrCL95a2m5SznyukvjzBHe8EzKg3+q4iJMO
         qrPgeMqwW5LdmHxdG4dyYPpdbHw/Yxz5pW2HbjNZ35WLn5DmDxvOcNJHSe8tlVfJyjeX
         9j1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XquCIMSVzF+8Jw1hfu4RjdG2kyOSnBYqCUGkJfk4BYw=;
        b=aGnK+f9m4+UVy1lSfyiCa32ZhrR5VROV+zDdbV/UNYin7I3oOMEXR0vpq2jCaEkJSq
         s0xPI5LXuoZ1wflI9fkvTnqyx/apK0JYEJGX+IMvk8WYGNzIxkcVNyYhvr+Iu3ZTGuWx
         1l3CV/Fkrpx3sXIJRzYZGdAPn2FKvZvAA+bRTpAVt+VlXccCkNuzRu18TJW6lG4i2W98
         Hq0LUOlACoRFvBLp+wtlnY6aWQEfoCQFGnnaZNK/Um1ZWI8W0jyKyRfIX2Jil2qbG2jK
         mByKgtwQVASGhMExgr8SEP8ZVWYHnlKZVpSxOnx1klPsHNAtqjEopK+m4fCl+Ua++BWr
         gvbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW16WN5BIdXGNxhUuz5OpE5/0/2eRoxD5RfhLL5bliEokHm8EAW
	vBez4MuJccchqJCBK4u8f38=
X-Google-Smtp-Source: APXvYqzfxVkBMw6ysJ1DI7YwlcBfkBIerF5k9UgjFrANgoSoSJQDGR4HUDpd5aKHNy+KuJyUNq6dGA==
X-Received: by 2002:a17:902:343:: with SMTP id 61mr13156612pld.332.1581342958297;
        Mon, 10 Feb 2020 05:55:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6644:: with SMTP id f4ls10423090pjm.2.gmail; Mon, 10
 Feb 2020 05:55:57 -0800 (PST)
X-Received: by 2002:a17:90a:154b:: with SMTP id y11mr1941130pja.78.1581342957891;
        Mon, 10 Feb 2020 05:55:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581342957; cv=none;
        d=google.com; s=arc-20160816;
        b=kWo4fLSlFtsiWlq+2o8rjZQ8SDuKqhb7yVofgJurQdf+eJxB/I6IMP3DsSvo37ClOC
         9wC39RB7uUPfHKY6uAj/9a/o1Qs9SMs+rd4ZYFqa1xYLYxdpBqgxKmtSGMFBgO9F0GON
         kWp+rSLbSdClqJcZxYIuAoOXZhwnLO1lu33ZmJsWM7us5Lc+f0a6e4geWdrCNALXkSHq
         uqLf2XX2XSfQkNdC0WdoOWnrXZOLlMToR0atQcqSzymeLsQK6DJUDmMhgxRCsCOXNml3
         IyJzqWjMC69WtO5XcF/5NQiDNqys1ljQHH2SOHrylhVpHKXl1CwTvo1JvnF58clC0q6a
         8WUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=uvc+HCAjGfX6aDuiEDkX1stZqSNz9kTlsYc/8zRaw1M=;
        b=f/+lpdclhJHxUZz902TlbQNli2wg8wnpGT9cbGNOAvFyeleSFCYsrREkmONDSG+yle
         Qry7Sn0DfndFMam5AN/Zjdd2Es3uVzlvADkyejxUH4M11Bnsy2/SP6GsQs75h37NlrRX
         zDf/fqkZWdJl1kZmlQEd6xG1WGbeM3A7QwQtfAiRUivUqvgq9TSm6u8+caCKKD99Dskk
         vldiHN1O/EL8uj2DOTtzx9c1Vav01UdhvRU7OqpW+TFzdJnufzn3drB/HZEJfUUBgwOV
         0SSCvwFk0lxNKTaju9BtwRuIYNHLHDMjRjkeZ+fhd0Nbi4IMke92xmSvzzXdKAXGlJ+x
         qmOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=StiymXhX;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id j123si11278pfd.5.2020.02.10.05.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:55:57 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w47so5151469qtk.4
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 05:55:57 -0800 (PST)
X-Received: by 2002:aed:3eee:: with SMTP id o43mr10143047qtf.33.1581342956768;
        Mon, 10 Feb 2020 05:55:56 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id a24sm157600qkl.82.2020.02.10.05.55.55
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:55:56 -0800 (PST)
Message-ID: <1581342954.7365.27.camel@lca.pw>
Subject: Re: [PATCH] mm: fix a data race in put_page()
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>, David
 Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>,
 ira.weiny@intel.com, Dan Williams <dan.j.williams@intel.com>, Linux Memory
 Management List <linux-mm@kvack.org>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 08:55:54 -0500
In-Reply-To: <CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF+GZqqxvpC8Ui4iN8New@mail.gmail.com>
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
	 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
	 <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
	 <1581341769.7365.25.camel@lca.pw>
	 <CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF+GZqqxvpC8Ui4iN8New@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=StiymXhX;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
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

On Mon, 2020-02-10 at 14:38 +0100, Marco Elver wrote:
> On Mon, 10 Feb 2020 at 14:36, Qian Cai <cai@lca.pw> wrote:
> >=20
> > On Mon, 2020-02-10 at 13:58 +0100, Marco Elver wrote:
> > > On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
> > > >=20
> > > >=20
> > > >=20
> > > > > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wrote=
:
> > > > >=20
> > > > > Here is an alternative:
> > > > >=20
> > > > > Let's say KCSAN gives you this:
> > > > >   /* ... Assert that the bits set in mask are not written
> > > > > concurrently; they may still be read concurrently.
> > > > >     The access that immediately follows is assumed to access thos=
e
> > > > > bits and safe w.r.t. data races.
> > > > >=20
> > > > >     For example, this may be used when certain bits of @flags may
> > > > > only be modified when holding the appropriate lock,
> > > > >     but other bits may still be modified locklessly.
> > > > >   ...
> > > > >  */
> > > > >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> > > > >=20
> > > > > Then we can write page_zonenum as follows:
> > > > >=20
> > > > > static inline enum zone_type page_zonenum(const struct page *page=
)
> > > > > {
> > > > > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PG=
SHIFT);
> > > > >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > > > > }
> > > > >=20
> > > > > This will accomplish the following:
> > > > > 1. The current code is not touched, and we do not have to verify =
that
> > > > > the change is correct without KCSAN.
> > > > > 2. We're not introducing a bunch of special macros to read bits i=
n various ways.
> > > > > 3. KCSAN will assume that the access is safe, and no data race re=
port
> > > > > is generated.
> > > > > 4. If somebody modifies ZONES bits concurrently, KCSAN will tell =
you
> > > > > about the race.
> > > > > 5. We're documenting the code.
> > > > >=20
> > > > > Anything I missed?
> > > >=20
> > > > I don=E2=80=99t know. Having to write the same line twice does not =
feel me any better than data_race() with commenting occasionally.
> > >=20
> > > Point 4 above: While data_race() will ignore cause KCSAN to not repor=
t
> > > the data race, now you might be missing a real bug: if somebody
> > > concurrently modifies the bits accessed, you want to know about it!
> > > Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but just
> > > remember that if you decide to silence it with data_race(), you need
> > > to be sure there are no concurrent writers to those bits.
> >=20
> > Right, in this case, there is no concurrent writers to those bits, so I=
'll add a
> > comment should be sufficient. However, I'll keep ASSERT_EXCLUSIVE_BITS(=
) in mind
> > for other places.
>=20
> Right now there are no concurrent writers to those bits. But somebody
> might introduce a bug that will write them, even though they shouldn't
> have. With ASSERT_EXCLUSIVE_BITS() you can catch that. Once I have the
> patches for this out, I would consider adding it here for this reason.

Surely, we could add many of those to catch theoretical issues. I can think=
 of
more like ASSERT_HARMLESS_COUNTERS() because the worry about one day someon=
e
might change the code to use counters from printing out information to maki=
ng
important MM heuristic decisions. Then, we might end up with those too many
macros situation again. The list goes on, ASSERT_COMPARE_ZERO_NOLOOP(),
ASSERT_SINGLE_BIT() etc.

On the other hand, maybe to take a more pragmatic approach that if there ar=
e
strong evidences that developers could easily make mistakes in a certain pl=
ace,
then we could add a new macro, so the next time Joe developer wants to a ne=
w
macro, he/she has to provide the same strong justifications?

>=20
> > >=20
> > > There is no way to automatically infer all over the kernel which bits
> > > we care about, and the most reliable is to be explicit about it. I
> > > don't see a problem with it per se.
> > >=20
> > > Thanks,
> > > -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1581342954.7365.27.camel%40lca.pw.
