Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHGIQGAAMGQEL2J2ZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id C26BC2F64A7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 16:32:45 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id c83sf5039017qkg.15
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 07:32:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610638364; cv=pass;
        d=google.com; s=arc-20160816;
        b=b+ng1yyIeQDi/XHliYJwoTSLI5lcJWW5FmJolU78OdE3I3ReesrOZS6DehktCN+K+Z
         Nwv0LQCZOog+4k4Utr4iI0PdIsGzh3ATY5PV7/j9Qw8A977TOYi5xc7P+0jmV3duLwuP
         KCmeAN8M32SfcZKYXH3jhEFy3jPWpWI+OSCalZne3Fxw/PJt1IaXOQRfcR7dZmgEG4Yc
         Uf2In5QW/gne8r8B7HG7C1RbUsOMq5E9+KZrgWaXcylweO1yUe8/Gx2KG5a1ZZfUAq+y
         iH2bitaYV4KorRIT6hEuCeM3jy9jNbEjiVYySKEjeZyMw09IC+m5YMDaAQBFxubOHWbn
         DjjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=m3qjEvPzXktpTipOWq8tvnImYf9/q2q+UWkskBweuSA=;
        b=UvkbK2NUUnxBHHg9PPx61NSEoDc+H5Zr5A5y9Dcw+VO65qZgY20vlO9I1Ta1OWIjOp
         0iTTOKiRn6anZyYgJzSH3revuhPKPpIkT7uUh12kuvKnhBjbfQHXQgOFzOoVQqMVuUyf
         EokSdeXyDoROP9VMVq1iy5vfmOhd6vPjbzdRPKXqFMOfi1+Vzr8ZjBqE5zpB0/EiPWq/
         536s0ZCCToy91QHdexOgYegqpDShsQNI9UN80yTsFCYYtiVjqTvcD+K4pM0RovDS4cfB
         haKXzEEcEhjOtmVVTNkWCUjF11BaBPjNGak0RSfrrqTJCTRXRiU/AYMme2R1G0+FDqRJ
         qCzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F+h+U5OX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m3qjEvPzXktpTipOWq8tvnImYf9/q2q+UWkskBweuSA=;
        b=bBFHvyGoWEkwFVJ+h8AOZCdlT4Jx3lEYyl+ZWQcaZ+A0RDjYm7qkFdurlBGJNRGrI6
         8Fpo0UeWbTHW0deioZou3TgjaP+o7PqBzQFxUBCLM/AFnWL/jpaFgOJfu/M9PpYO9xje
         aj3JjSLkHywUc7pg9H0dy0/6s4Prca4eOaU+/1WbdqcAsNbgWAdDwznLVt5p9Q1GiI9J
         z6IatKhNOp9dm41TMYYWlo7JKSGmhTuBNzwT6yjq64o/nELTYQtcYYuH1oOgZ2bG/wci
         w4/3ptSIb3ZjZ5UJ+NscdUGcbNhshQXUKwxm1dr0CkAO3HlcmBWYsaKJqxehoWIwHLIh
         rd4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m3qjEvPzXktpTipOWq8tvnImYf9/q2q+UWkskBweuSA=;
        b=Miaa2Kpi8tcCMZBivXRbRaCoFu8O29QgGntP6Z/Re7DZEn1EaWvecLV9o27e0NcfDA
         +4a9lQvUCPte6kHF/h/TmSBBApbgtgLXVKKO4iP+nYlp0r3hBcTOZmFf9LGE0wsOUc6i
         gqoD7fz14WUZMcYMQ5j1OeeDKFAh9gqJyG0OEEfyuoTZpr0epmU9zfAl9ntObrrtQWZf
         RGcTpfg2SM8YN7VQSeYXFogUhyv3Kuuh61ZmXuq81OJIb0I+HrJvQV7x8hnpFfxPWs/f
         fGnw1xBSdjZi6yDvAGtZ83zeD9Se38GMnDtEMGEh260thxE+UUMmdo7OG/iLQ0AJrEVo
         K6Jg==
X-Gm-Message-State: AOAM533HyBtF19qTTJBm5owVPY/nLRq1jn6d4FuziKSqoczfBW8x9zqJ
	w69QxG7K1U4TtNWhKVs/br8=
X-Google-Smtp-Source: ABdhPJwClT6IbltQhZci7ck9GHcpfoTI/EO8M/metK4PqyvSOTtmXmeX9/g5QV42HqIE687bDmxltA==
X-Received: by 2002:ac8:bc8:: with SMTP id p8mr7417778qti.135.1610638364760;
        Thu, 14 Jan 2021 07:32:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9a4f:: with SMTP id c76ls2932405qke.8.gmail; Thu, 14 Jan
 2021 07:32:44 -0800 (PST)
X-Received: by 2002:a37:a57:: with SMTP id 84mr7752732qkk.218.1610638364309;
        Thu, 14 Jan 2021 07:32:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610638364; cv=none;
        d=google.com; s=arc-20160816;
        b=w11k7DqhuBFiPLwc0t1qb2tHPjlV0CTsfpnlD8mXZAK+gdNSxg75OQCI5Tcgyz5SuM
         dbMEG+fAeSwoHWJElnBEX/XGUkgmW3pxvzwYZ8u1zGrk4mdOoqBNh3I3Y6RHHfRryHO2
         Mk7EOOok63F9d3T8goMCIwkAcxgIavVh7DSQOQDOf+5rTjUIVtcEo/tmez629AkMIBm0
         TT1s9rQEucOQIITCHTnZBXCQ+BLMvoNnftKIsk9qFkL4lUYwX8cuR1Sfzoy/RnbFTWGl
         V7HHwwv4K3TeWFw+MXt5zerBenj6KNiIF5+FvduVPkYJLdXPcmYGkpWMxvIIafgiJTSC
         Hxlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hhCmnieS6x/7jX7jC0A67czRT8RpEOexXMJwHSjcG8w=;
        b=LrIjpHuj9a76AsEkNxktxrNDHdBqrbL34UJjDA9aruo5iUW7uvrxKP/R5OgCRVR89R
         wur2lK0V5YRXxtBZceCAhOPqF7kHiMfIhKkj+W6Qyt+enYqa14Xvo4V98fH/QPwoHvap
         nUUThpOi1aHD1yq9Nu6cgJ1S6Nnyten4L4lwI1zFP59QVTx0IUema6Pc78Xt4zcKmuLl
         i9tdSSDtMKONT0FncBMsmJD60afDPuvu3ejDQ468w9uGD+ESOR0R+P1QaE2N5HJpKh/N
         BqMBsH8wcW+8APFFzS+L9nf56IxJRqDkMSfPyvnFQ1EOTilly98aNUkLCnjvY7sS6fnZ
         XqHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F+h+U5OX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id y56si369487qtb.4.2021.01.14.07.32.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 07:32:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id i7so4006289pgc.8
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 07:32:44 -0800 (PST)
X-Received: by 2002:a65:430b:: with SMTP id j11mr7862747pgq.130.1610638363793;
 Thu, 14 Jan 2021 07:32:43 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <654bdeedde54e9e8d5d6250469966b0bdf288010.1610554432.git.andreyknvl@google.com>
 <CANpmjNPOtohFy800icx1LU_hzuQZNMQqqTBUSDXZ_9wWO_vHWw@mail.gmail.com>
In-Reply-To: <CANpmjNPOtohFy800icx1LU_hzuQZNMQqqTBUSDXZ_9wWO_vHWw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jan 2021 16:32:32 +0100
Message-ID: <CAAeHK+yXQN2QWUEATrdpAuEC=s1+VSZ1JzxxJbEuhpXv3nCtAQ@mail.gmail.com>
Subject: Re: [PATCH v2 14/14] kasan: don't run tests when KASAN is not enabled
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=F+h+U5OX;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Jan 13, 2021 at 5:39 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
> > corrupting kernel memory.
> >
> > Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  lib/test_kasan.c | 3 +++
> >  1 file changed, 3 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index d9f9a93922d5..0c8279d9907e 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -47,6 +47,9 @@ static bool multishot;
> >   */
> >  static int kasan_test_init(struct kunit *test)
> >  {
> > +       if (!kasan_enabled())
> > +               return -1;
>
> This should WARN_ON() or pr_err(). Otherwise it's impossible to say
> why the test couldn't initialize.

Will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByXQN2QWUEATrdpAuEC%3Ds1%2BVSZ1JzxxJbEuhpXv3nCtAQ%40mail.gmail.com.
