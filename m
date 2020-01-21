Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAGGTTYQKGQED5F7C6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B3411441C6
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:12:49 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id y24sf1628045oto.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579623168; cv=pass;
        d=google.com; s=arc-20160816;
        b=rSfBRF56vF9T7BRaLOU3cCg4aVRoGHsWAl6kIOawVZlzfyTR8jpSAikAz41ojDGRKt
         o8f4rtuVKwSb8mUGerujlaPf1TO9VHWTBIgG0mNKH4MAJS/WlgZL8v+wZYKseFIjaHeV
         x33AcBH1WfOyUs0FPf9FUBY6Qzk4MrTCVEjZWWxPaip3WvfUeODqbdNjXUbwkgd0te3Y
         hr5Ocipf/kLYRl+SZjBhGPxUmZu5JNXuw3Q6lAzfjSgh9RgoGQKCZbc3sMHZqmw+KDeL
         O5iweu0ZGZikWXxuPVr5j5Vofit+uDb20eAz3ifR/bY5GKp6JUge8tOSdiL5E/Qkcok5
         jCeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d6k2ByTEP/uZxnaZ+U7UslOyzPwxvP4ke4AzANePhjQ=;
        b=d3UnznwEXuSKPMEdLu0bic2U+DNpynOX4/+btsljG5vLSmAGUAlJf55yhfAw5rhN/C
         9Gnf7jd5McWlxoEYaNnbJCxfTpr5Q1v5X0HBLFvi0Ey+EGAArQPWkeCXNPcZJusGMoMq
         IEb4v5/UJNVmmFyrXsN2E7GWAPvcpkPsXSs96yNu3O0HJBCtqgagjh/BDGfa4zs9HJkJ
         Kwe9iOIZ8ugFmZ5nNqvpnDa5vQOGGBJxcv5LnI9FB4h5zpXS+fMEOFOl8CKl/8m+CcQK
         mduvWcrjj2aI6TPLuWpEESZGSdLNLSe6ERBmrirE9wG89FLY9CJO65O8FrV4D/DXmw6R
         dWJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Fk/VjSwG";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d6k2ByTEP/uZxnaZ+U7UslOyzPwxvP4ke4AzANePhjQ=;
        b=kVnjtKurJCA6edI7DEfNNdfTXVNU+QmW07XDK68oypWVpyRA3i9oq0Llvd5Hdal4lO
         ULhMUpTrBDFqKTJFruXDFb5M/UkNR2uz3DZkDdQj8zaLfzA92OWAMGiKbtdX9lAwGisv
         DgTdUsKSdrL5lPOoQdn9bLrepDXVGLbXJWxpp3BwsDRWRxfOLKhNgUswKCrfYbALPSCL
         KaEysg2D+4i5UikY6dm1395yNAU4c5uBXBlMfWWkd0/4DQvavoSet2ltHqdc9vHW96T0
         mvsi1skLLQbU10OUOhwTF22Uc6EbdCaMNUD1/xJC0d88v7FbniYUwQh6AlEwUnkxuLMs
         v+oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d6k2ByTEP/uZxnaZ+U7UslOyzPwxvP4ke4AzANePhjQ=;
        b=G87rhrHUfYRkZ7X6ItIT/Cugd9HR0fyhqFAkvOI/RLlKmuZyKAIhstAx/6OwAdmDcH
         P3vPU6fU+MMHcbeVJizXlWHWIS5I0ANqoE5+yFbM1grojBi86sXYKQrIdCxTs9aOKjoj
         zO+FkS0ZNGDZ2fF1/lSVa2DYD2XV/fps2Djc+nSTBe3YdZhlkNkSVujBNydHfyRyjFtS
         5yj9K+85sbxKZW9d/aLdm8NJtHUxxfeSJGiAsFYzoDkZo9W1PP6U4bqA+vcC9EiR0+W2
         R/FHsxVDdq5xWUjt+Bn+92jLMpd3098E7xJk+A5YFczU3SUvmAJGF8GaIg4FEl1tNANf
         9akA==
X-Gm-Message-State: APjAAAU5kLzbp3IBxNRoal+GYUlyU9iBP1CK7e1adGTPiw/0UTjoAS7m
	NYe8MzFjVgTyj2cp0Sx1uhM=
X-Google-Smtp-Source: APXvYqxq24jyyYp1Vzm8gjkbNHDKwQJe4Ok21nB5bTqlfPVyg1wZrSWSKKIoFrG3zgAExLcqouQ4pg==
X-Received: by 2002:aca:1b01:: with SMTP id b1mr3378681oib.6.1579623168235;
        Tue, 21 Jan 2020 08:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf95:: with SMTP id f143ls6394483oig.7.gmail; Tue, 21
 Jan 2020 08:12:47 -0800 (PST)
X-Received: by 2002:aca:110a:: with SMTP id 10mr3567733oir.130.1579623167860;
        Tue, 21 Jan 2020 08:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579623167; cv=none;
        d=google.com; s=arc-20160816;
        b=sKImZ2KDsShRCMWhPLAIhvpp9AebnHwwREmHWDwiv6dE43plgJWHpqE72szadw4Iqm
         CCfI8jSDXxZ4gXgumbHbh8UNzn3ULldJU0fJX0glML9ToefopKWi9zX9EunyyLqD9TNH
         HUeo5nHQJmGvEDhapz5EvWMSxZyPEU0ArX4sHXgXMzRO3iKqgmvxcGX9MygzNy15k/Nk
         QMP2OalgVVxVpvrfpVpyyp52ZgsH9ryt8rMI+RQAbb9AyNQbqeM9QkEhD65FQFxmXIsT
         cl9rPN2sr7Kmax0qTdckucV9bIzczNGEwK5JcGCsRXWlUij0nV2TiBZVI4bReaNG0O+4
         BjIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t0oGkq5Pa6BFHnIeKryyeGImhC+iJMmb3104WkR55ys=;
        b=Gm9aCY0kAqdz/iXSMWeY5xeBRGFYgwylPaO813/kSNJ/grhfG/+GX9u7WBrydFa17u
         l0m8K4AZCyThPQecBPxa+wmsRnY6vVln2P131uoKUaHkP/xVn2oND2zzqzI3h4f7Oa/8
         YgAWkba/9OzPQPFX+OlQasogPL+64GoohktQ7Cf+/b1Kt+lrNe19ZlcIiJeCwJjtYRgB
         U8jLlpBK6V+tssxZWR7NLbANnauhGMZRvAG+MTSVb8cy9aGpBJiddTSPw8mgXh1UtNiC
         sTAOYBc5l1YZzgbiNhXbzEo0csl2KczdsIY6dVNXAaewLLi8PPoL8V/1IckKAVahhVcy
         dFMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Fk/VjSwG";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id a12si1825774otq.5.2020.01.21.08.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:12:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id k4so3076327oik.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:12:47 -0800 (PST)
X-Received: by 2002:aca:b183:: with SMTP id a125mr3673714oif.83.1579623167224;
 Tue, 21 Jan 2020 08:12:47 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
 <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
 <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
 <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com>
 <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com>
 <CANpmjNOUTed6FT8X0bUSc1tGBh3jrEJ0DRpQwBfoPF5ah8Wrhw@mail.gmail.com> <CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM+G4X-hMgpBsXMA@mail.gmail.com>
In-Reply-To: <CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM+G4X-hMgpBsXMA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jan 2020 17:12:35 +0100
Message-ID: <CANpmjNMe4a8O9ztaVCVym36au9jaaCooUorYnFd0egUQSfn7gQ@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Fk/VjSwG";       spf=pass
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

On Mon, 20 Jan 2020 at 20:03, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Mon, Jan 20, 2020 at 4:11 PM Marco Elver <elver@google.com> wrote:
> > On Mon, 20 Jan 2020 at 15:40, Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Mon, Jan 20, 2020 at 3:23 PM Marco Elver <elver@google.com> wrote:
> > > > On Fri, 17 Jan 2020 at 14:14, Marco Elver <elver@google.com> wrote:
> > > > > On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
> > >
> > > > > > If you can't find any, I would prefer having the simpler interface
> > > > > > with just one set of annotations.
> > > > >
> > > > > That's fair enough. I'll prepare a v2 series that first introduces the
> > > > > new header, and then applies it to the locations that seem obvious
> > > > > candidates for having both checks.
> > > >
> > > > I've sent a new patch series which introduces instrumented.h:
> > > >    http://lkml.kernel.org/r/20200120141927.114373-1-elver@google.com
> > >
> > > Looks good to me, feel free to add
> > >
> > > Acked-by: Arnd Bergmann <arnd@arndb.de>
> > >
> > > if you are merging this through your own tree or someone else's,
> > > or let me know if I should put it into the asm-generic git tree.
> >
> > Thank you!  It seems there is still some debate around the user-copy
> > instrumentation.
> >
> > The main question we have right now is if we should add pre/post hooks
> > for them. Although in the version above I added KCSAN checks after the
> > user-copies, it seems maybe we want it before. I personally don't have
> > a strong preference, and wanted to err on the side of being more
> > conservative.
> >
> > If I send a v2, and it now turns out we do all the instrumentation
> > before the user-copies for KASAN and KCSAN, then we have a bunch of
> > empty hooks. However, for KMSAN we need the post-hook, at least for
> > copy_from_user. Do you mind a bunch of empty functions to provide
> > pre/post hooks for user-copies? Could the post-hooks be generally
> > useful for something else?
>
> I'd prefer not to add any empty hooks, let's do that once they
> are actually used.

I hope I found a solution to the various constraints:
http://lkml.kernel.org/r/20200121160512.70887-1-elver@google.com

I removed your Acks from the patches that were changed in v2. Please
have another look.

Re tree: Once people are happy with the patches, since this depends on
KCSAN it'll probably have to go through Paul's -rcu tree, since KCSAN
is not yet in mainline (currently only in -rcu, -tip, and -next).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMe4a8O9ztaVCVym36au9jaaCooUorYnFd0egUQSfn7gQ%40mail.gmail.com.
