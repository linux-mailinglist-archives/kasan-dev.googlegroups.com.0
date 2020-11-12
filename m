Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO6LWX6QKGQEM3J7H4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 512622B0A4A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 17:41:33 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id d4sf4114893pgi.16
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 08:41:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605199292; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYKpn8XvogT+M5fAZYkeSgneb/C5t0/njogFdbmpBAj8CDnMvz3iD1R3thpXmbYVeB
         0B+El+nVo1y//d2S1DlikHjoEo3W7/jtwDF/JLj5djuCVSXAy4U5JRgMqTWfmSlQrnn+
         KQPUTpdDD9vx+qKtwTAtgQK7gDwWaLenk8jcHeLN8Qu/NmZmETZPq6KcSGwwaUng7Sqk
         0CgIApj2XHl2qpejS9cHNLT81TaRdHr/kWKBh4MYn4p9rWQbDp0Fi7UlMiFLpIk6E3z5
         kzNJ16vvgMGyMkQsNG+ZQrwyBvqNc7ywZVW+b7lEB0V1UbyGKGfjbK1dCILHRif7QB7h
         KSIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xx5ZSeCPjekLxzRKnyk9kBK19K9ub/tjsKaPLVfwse8=;
        b=i99Z7ve8LkTeTH1OYqcATUKcf3kkiE/wgPCoIvbbKa1HbvCVeF1TyWppXxDs9BNK45
         K9qTsa0LQPtfrIXOSDJv4WSv5j/8CIzKxDT6Dj3yaHustolnVJQQIE8OErp4D7KVOkvm
         XM9zIJ9So0ztPc7ypYEwPSDiUGGTLrF8Dv1VbZ9xk09PYhWj79OxaRA5E9QD1rnpJbas
         ajZosuAmyeSB7X1rE8Qyb5n4EwNu/lvPFEuPBjF8jo3O6snxQzM4Lcnm5A5cX7WQGyIV
         UO5cZtfhTA2nkeQHtJBnjRfvPBOFgo0OL00ATXbfphT19yFO29Juk60y62IIM1Fm41rd
         +deA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lX8a8Eka;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xx5ZSeCPjekLxzRKnyk9kBK19K9ub/tjsKaPLVfwse8=;
        b=Yba5ihAX+tLsT5LjRgJ0mPaCD35SCWUK2K5nIwxbKUifO9ec+i2/j7QqV/ZtOVVylB
         85k9viecS8QnocRKHFeuBqSCc7nPIrKsil0/RxrJ7YT/NqHpN7r0bFBlPmM7iQY9BZbT
         42pd4OfKTvChEr5bvdiZFDxYkR2TCTBvwGukdj3tZgzXKRAFNP/8f2Ul6o2Xc/j9kHGT
         +rYwDuKayoPP4dG9Yz5qZFvgUiYTVsYiWPXenuBhfSsbsXI3i6SVU8aCESNrXOsCwpYG
         JGxdS6DYd4/tI7CWvMOEXplfvYMUcYlcvZPbNRYGDE0vWV2mFxf+lRT8vqet5saS59Vr
         TK0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xx5ZSeCPjekLxzRKnyk9kBK19K9ub/tjsKaPLVfwse8=;
        b=XoVQHELQ5whUgC9W4GrMM0lJdRtF7XC+npr7N1yEitZ7I0FFNRqVBVaekDO1AekxSl
         OBTLpJrpjDjWKvXM1RP5SxtqP1slfoDkZYwc4eMIM01D8fnQS41EB0eKQwK5Oo6CPqGk
         vp/pMwSbXsUv0vOno/CDTgw+VbpzaUzMFzCwMmFuDxFUrVU4PU1Y0hUFha049DiTrX9d
         gr+41m9dfKaTd7dJwuclCIgz+8K9d7cnQy9JuBOAefgH6ftzYHTCdO1IAL7/4vT/uN7I
         L/EVHa9lh74be7a+PS9JdVbrEVUQ/TsrlD1gb7+ROHsWFFTUS3bWlKXLMXU3q9RJ/5E9
         M74w==
X-Gm-Message-State: AOAM533qU322Fm9vRwPoR68vqCofpg+9KS6qEMujCegXJaaXjfSu01A6
	hm27l6Mvq4kAvFoFeTOSzRs=
X-Google-Smtp-Source: ABdhPJyLw/6Y/vjcHPq1nIJZqRxCbv3dhkXq8UhnhjVGsNhAWv6HaQjSqCwE3VRJGvb3jXxqdjr5Jw==
X-Received: by 2002:a17:902:a705:b029:d6:e486:ef6 with SMTP id w5-20020a170902a705b02900d6e4860ef6mr253042plq.0.1605199291823;
        Thu, 12 Nov 2020 08:41:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd8d:: with SMTP id q13ls1705432pls.0.gmail; Thu, 12
 Nov 2020 08:41:31 -0800 (PST)
X-Received: by 2002:a17:902:d386:b029:d7:c6c4:b128 with SMTP id e6-20020a170902d386b02900d7c6c4b128mr245037pld.70.1605199291316;
        Thu, 12 Nov 2020 08:41:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605199291; cv=none;
        d=google.com; s=arc-20160816;
        b=lvxn90ygNyw2K/PM0QQtZf/WGPPeQ9eJgB5KVVLkh8YHfNsK1UbGrkJO8aTFZw8FXa
         TVq37yWXT5BrifIDBsMv2PCapDd3tVByWvAZ2gVeWoadDXhs5KZBnK1kSBbWFUpCadK3
         SS24GeVazuyXeJq2Dy4SRdBvyy4Yem5al31VJYekRxncfNVmxL0SbMFvoYTKnuY9nqfk
         po9xUJaAB8NZtqAE/2E+O+WC4OlMEls2A7HiqjBbe57NdGjJ7LjEo9k+NhJ7m3ku+u+6
         iesnFcOD5oZBsTVrvAgZCHin89kmmUysrN8ioOrDftDlRrK7zY5Mu6yzWKB8m3pkf0/v
         +U2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=k1nxBPerHo0opWxBOg1iC4tCjytAR1tnAmyGb9xHH/M=;
        b=0xUiTGOeJXO/x6b7Djk/WkBMR5a/VZcEydiwDu+1PLVDwbECjC7SDQOiW/6Ygl3aTi
         iAmb94H1mR5ofmNqIJq7F+9cqTTuDZH+V6QaUTvGW2GMexytpF0P/ozsVthxXHS7L+nU
         8FBi4d1qAjb+tDa11bVSptNRZkQfS/ff/JOJl87M+Y6cF+ADfXD4ICsWcBOYulwjdy8W
         x1r0H6Ys/7BNZOEITQtA+lPxLh7a7hB4Mmnp8wshw4jRot0I6cosO394+Z9Wq0CrGkMk
         FO+QTCXBTBrnutMq7twrOZOuFkUlAQ11FS5JIHXJH12yYObKKBCIiL7dc927YU++wRSF
         cnnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lX8a8Eka;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id o24si256943pjt.3.2020.11.12.08.41.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 08:41:31 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 7so4426423qtp.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 08:41:31 -0800 (PST)
X-Received: by 2002:a05:622a:291:: with SMTP id z17mr18923qtw.180.1605199290292;
 Thu, 12 Nov 2020 08:41:30 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
 <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com> <CANpmjNMaDkKBtWF8y22rhc6bFNN0CrXgfGNKXBLPvz3c2wd7rA@mail.gmail.com>
In-Reply-To: <CANpmjNMaDkKBtWF8y22rhc6bFNN0CrXgfGNKXBLPvz3c2wd7rA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 17:41:18 +0100
Message-ID: <CAG_fn=VS7afjd4mXHvc+FcK=cnQC=SjEOJL6phkFLSWxP8+uaw@mail.gmail.com>
Subject: Re: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context switch
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lX8a8Eka;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Nov 12, 2020 at 5:09 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 12 Nov 2020 at 16:59, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.co=
m> wrote:
> > >
> > > From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > >
> > > This test is specific to MTE and verifies that the GCR_EL1 register
> > > is context switched correctly.
> > >
> > > It spawn 1024 processes and each process spawns 5 threads. Each threa=
d
> >
> > Nit: "spawns"
> >
> >
> > > +       srand(time(NULL) ^ (pid << 16) ^ (tid << 16));
> > > +
> > > +       prctl_tag_mask =3D rand() % 0xffff;
> >
> > Nit: if you want values between 0 and 0xffff you probably want to use
> > bitwise AND.
>
> Another question would be, is the max here meant to be 0xffff or
> 0xffff-1. Because, as-is now, it's 0xffff-1. Only one of them has a
> trivial conversion to bitwise AND ( x % 2^n =3D=3D x & (2^n - 1) ).

Yes, that is basically what I meant, assuming that Vincenzo wanted the
max to be 0xffff

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVS7afjd4mXHvc%2BFcK%3DcnQC%3DSjEOJL6phkFLSWxP8%2Buaw%40m=
ail.gmail.com.
