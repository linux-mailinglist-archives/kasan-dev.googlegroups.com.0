Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX5ZQXZAKGQEL47MFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 228BC157C82
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 14:38:42 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id x141sf5152494ywg.5
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 05:38:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581341921; cv=pass;
        d=google.com; s=arc-20160816;
        b=RcQlOQnP9ifFbqmkTbuyE8e57D3gKUw4iniTeqQ0EcujRGS7WQAHHorVp9p7Lwbz8d
         U80LjOf7qbqXDScwqGEpFc/5uI0aKNp/RU517cxL8tQG7pyNydckmvNGqOLAzYiA5Emz
         9VvEYj48JH6iGyu4dd44d1FgRl+XNqLs89e7SYr1W3cg6HmLrUJLUiBiR+nuxiD+um8J
         Uhh95CHbhmAD4RyklyxPXTJQwjV4rWLq4PMvB2vwFG+9Ryq3MRXHpG36+HzNlqEf8OHE
         m8GoShmkAOD5khd0SfMtDeFEvcDI+FXAXBRxEvYOh6zzcgPa4ukwql9ygpd0DLgCtS5v
         Wxmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mNZllIX7km44fCykPNW7WjuYkRmqmQppnp5IaN+oIFE=;
        b=L9pRGYqXiFAcETW7pXT41FwNxKIAZZSfeha3em+ZLUBJJSx0bo4uLRU/3PJPF/hMi6
         g3F4LkQgUTOhj8O6WnAy4/pKXcWnKKxTdMsTSTW0uExdfBepotkdX0a+o8MxiN5IIp4P
         c5ko8PdDh7JYn2VdYU9tI2R5jFCtwOPEPntc0HRp3WNfbEgQiQDn2uhAls/2tp8HQOjP
         5+E9puxJJ4CV+LJ4ZPJSqJgua+pLDSzxcOlJx3zbpTNuB2f9CHhkbNAb7nlillC/K8KO
         afpao7w+xSh8L4X+iR+x0vzHekykI3FXt9L/+0kH9AZdmandiAcxuIP053EGCDWNd+3w
         KU3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k+lzJ4Ld;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mNZllIX7km44fCykPNW7WjuYkRmqmQppnp5IaN+oIFE=;
        b=gOIeZaFH9MuIgw/+i9LI4avnTeWjS9r4Ch6CvIElQ6bQPoBFOWjCpKN9fy5WE34vP/
         jkyv/Vwb4iWDW6TqH+8ln8yf0HspMKZ4hu72HeowUS4rWK30gvlkc/8ZuDQTASV6F1sB
         mo4MGhFC0oY+fKUoqh027Ke586r+OcHq6aoI7RsDaZpricMGkSdilIoooisZiC4y0OCB
         sclPck5mbEvS7RXltZjze+HaDtk83RApRdJM/ktldFS+QoYuWqhFALGCa8wgxzEQ2uaT
         +w4jmV011kIZRfh3YEsRX1fCo3Sbu76a7pQSz89pTu7zfHuGBQgO8RLGHWEdUBp4tG12
         9iow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mNZllIX7km44fCykPNW7WjuYkRmqmQppnp5IaN+oIFE=;
        b=V3p1ak1CLNUnEF6LR/dhHKhCoGd5J+36wHxKD2Rd7sp6VpB75MsBgKAaweRFNkXqV8
         nFk33cWbZ1dZHTwmmGVjnyF6NitNEiDnTHG2UUiH1zboxNc8wEZ+FSM/mOPh0iaw4jDe
         bDV2skn+g9b6ifsdjP4m+BSdx8j3OGhFj0LaJ6e5NrN+1YYa/exojkP3hliGjna6kyI/
         Z8k/DaYQCMCBi9Fqpau7xWjTmFe+6ue87vMi3MCoUnCd13lf/XM444L8uIzNNAdbyIPB
         GpPotc1I4EA3UpnYRQBRHcW1Dg2qBdslFBgKLL4DGV2d82XL+78Ywk9Q3EeNhSJxVhms
         DbKg==
X-Gm-Message-State: APjAAAXDE9fVfh03nqrGnjWeeAYL+4Yy1SsWhReacj1tqSWoxF5lsGJa
	ldsDyBcOJlGCj1rHPeyv7s0=
X-Google-Smtp-Source: APXvYqx6o19Ydp/VgztHmeWbzap6H+nR0f72qbi+NNtYqGsNUJWGmI4zyHYD8DGNizgLGWMbll9Cjw==
X-Received: by 2002:a0d:e815:: with SMTP id r21mr1036728ywe.473.1581341919762;
        Mon, 10 Feb 2020 05:38:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca8c:: with SMTP id a134ls1597330ybg.0.gmail; Mon, 10
 Feb 2020 05:38:39 -0800 (PST)
X-Received: by 2002:a25:e6d3:: with SMTP id d202mr1354624ybh.418.1581341919445;
        Mon, 10 Feb 2020 05:38:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581341919; cv=none;
        d=google.com; s=arc-20160816;
        b=s6K+CkRpkHU1aPNy2U+TgVAvZZLvLuEvW8gYJn9YvD141xBA6olPex0DBNJ76G1Ag8
         31mRHxD2ng33LjbC+KNtaAlU3uRVCa0fFWrrm2fTNKrniJLORliqzlhsgiv4o01O8nko
         xBXqB5EJZ+38WPOAI3rwxsH/omGtOZ2ylKlm0vIcVBVLrj3cGp1cLN3PBLyv2H2ul9IC
         P1yWyk3pU4N9jNOhiCcWG3EV2WXEFuTDos+rCwGwhQEeDnyGrcWpootIE2hjzOF8sgla
         k4ZavHVf2S5wv7861XByXp/YvpzbLiNOZJcM3HnhJq53COQNeS/9qbBmdNJTFXdwFxk4
         0auQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=n4VkksM4yOFdYfQnXs70fdXcOaBAA6a7KVukuRv0B/0=;
        b=O4GrcofQTQmH8NOr2SaDiapd8B3W+KOKVGH5lyh8safdETBRzq9QK+spZK4rrx+Qpt
         J63u6jnRjzB7HYD5635wusdeqIiWaRz57uzqSlK8oM76fiWhxT4KAsXzAEg56uI4w71t
         PyTLsH3U2v3CFNKp1tCLVnsTeu2S9b11ozklEaA0zO5scbHITOta3BRgaypjfK1IoRaB
         TmZbzH7Ikf9/2HuPm3PBRtAYLNwHTNYJ8HyPic5RWildTT4TfySrE3lJidoLYwTbPm8G
         NPJGkmqQ/5vSbBt5n/zr3nzhU6NF9CNy4mapvHNf/UtEeXUlr9KzId8IDZb/1gb16Fxw
         doTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k+lzJ4Ld;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q5si25329ybg.4.2020.02.10.05.38.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 05:38:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id b18so9214103oie.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 05:38:39 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr788817oiz.155.1581341918727;
 Mon, 10 Feb 2020 05:38:38 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw> <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
 <1581341769.7365.25.camel@lca.pw>
In-Reply-To: <1581341769.7365.25.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 14:38:27 +0100
Message-ID: <CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF+GZqqxvpC8Ui4iN8New@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=k+lzJ4Ld;       spf=pass
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

On Mon, 10 Feb 2020 at 14:36, Qian Cai <cai@lca.pw> wrote:
>
> On Mon, 2020-02-10 at 13:58 +0100, Marco Elver wrote:
> > On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
> > >
> > >
> > >
> > > > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wrote:
> > > >
> > > > Here is an alternative:
> > > >
> > > > Let's say KCSAN gives you this:
> > > >   /* ... Assert that the bits set in mask are not written
> > > > concurrently; they may still be read concurrently.
> > > >     The access that immediately follows is assumed to access those
> > > > bits and safe w.r.t. data races.
> > > >
> > > >     For example, this may be used when certain bits of @flags may
> > > > only be modified when holding the appropriate lock,
> > > >     but other bits may still be modified locklessly.
> > > >   ...
> > > >  */
> > > >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> > > >
> > > > Then we can write page_zonenum as follows:
> > > >
> > > > static inline enum zone_type page_zonenum(const struct page *page)
> > > > {
> > > > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSH=
IFT);
> > > >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > > > }
> > > >
> > > > This will accomplish the following:
> > > > 1. The current code is not touched, and we do not have to verify th=
at
> > > > the change is correct without KCSAN.
> > > > 2. We're not introducing a bunch of special macros to read bits in =
various ways.
> > > > 3. KCSAN will assume that the access is safe, and no data race repo=
rt
> > > > is generated.
> > > > 4. If somebody modifies ZONES bits concurrently, KCSAN will tell yo=
u
> > > > about the race.
> > > > 5. We're documenting the code.
> > > >
> > > > Anything I missed?
> > >
> > > I don=E2=80=99t know. Having to write the same line twice does not fe=
el me any better than data_race() with commenting occasionally.
> >
> > Point 4 above: While data_race() will ignore cause KCSAN to not report
> > the data race, now you might be missing a real bug: if somebody
> > concurrently modifies the bits accessed, you want to know about it!
> > Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but just
> > remember that if you decide to silence it with data_race(), you need
> > to be sure there are no concurrent writers to those bits.
>
> Right, in this case, there is no concurrent writers to those bits, so I'l=
l add a
> comment should be sufficient. However, I'll keep ASSERT_EXCLUSIVE_BITS() =
in mind
> for other places.

Right now there are no concurrent writers to those bits. But somebody
might introduce a bug that will write them, even though they shouldn't
have. With ASSERT_EXCLUSIVE_BITS() you can catch that. Once I have the
patches for this out, I would consider adding it here for this reason.

> >
> > There is no way to automatically infer all over the kernel which bits
> > we care about, and the most reliable is to be explicit about it. I
> > don't see a problem with it per se.
> >
> > Thanks,
> > -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPdwuMpJvwdVj6zm6G5rXzjvkF%2BGZqqxvpC8Ui4iN8New%40mail.gmai=
l.com.
