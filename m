Return-Path: <kasan-dev+bncBCMIZB7QWENRBLVSZHXAKGQEIX2ZVQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A666E100093
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 09:41:20 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id m16sf15740804ilh.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 00:41:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574066479; cv=pass;
        d=google.com; s=arc-20160816;
        b=XA8BROfmYcQ+grQaqzGAFjQ63sTG1sX4pr5bF8/P26TD4DUz7zkMB8wxsX9rwFLnNP
         Ka6IFW+JVAga67BGrhyekyygo9QzENI/A4nJ90KnSD3lQ6mGQ4EDDSnhXdqLjzqtkA7t
         Guna2E8d3yCTOClw8S9nZ0HK/FRTF6VLkKYaDt3qvzE47je7lVSwR44F/wIKv76aN3DF
         D5EcjE7Q7J0PKTynCC2NRoOqbGWsmEmNB/Gupmyl5cKhln2vBnwKfQCkABiuQSfJWmk+
         zf+QSLTKNZ8CO3DOKraKWW6LyOLEBoGwAt2MDLyk6tE51do9esb2tpOHNjXdXvJqpZxp
         OV3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OWWbTtvsvnpcR/MxM10xoKrduFqfZbUvQXg48eQZZek=;
        b=fKs0lfJymbmzYue7MEzuzJVT4q2CXqwXGteQf2jES/2a81SjD7+Gg2G1Cwqc9lrNb6
         ujSfHyNXnelVKDjXvza3HXFEXOdQ8vkKgfjQSuPqGEWSReEK7AFwPbRJqE6Ow3P09Jxx
         L+yQqzq7BAJouUnZlUn5A1SxfuMQRgk4CDPELzLWpNrh41aZGdOzDJuEJ+rYDQeI9qmb
         GW8BjMwOrirnyamOU1QMRrMkGRlmS65B/dDJ4hPD/9OXfnkx07nZPzq+PqFci4kL4yqq
         6u1frO83eMSi+RHjX/yp60Uht5y1RAdlL98US2bEKJXDF2+Qvg4pfoEVT7riNW8ZBHIc
         H37g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IC7OCAsa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OWWbTtvsvnpcR/MxM10xoKrduFqfZbUvQXg48eQZZek=;
        b=jRZ23T7ga16Pr6gKPCjDaar0X+0p9tUxQuZekBvXswT45LRIZPcBipMmLh+kXIvfIS
         4TuBNIjDLzK25iIjR9Qwaw+h9E+qoCjLxFyRkJuqKUUmKVSIMJM6PS1hjeHMZui1hxvX
         UF3tR6XBdiSEzzyqL1payDqbp4LkasIME0vHrMjHIvnWzhA/vp2t62LCu0tnh8Mpdmy1
         xcErCOWxm92xl9Rr5wy0857WqX0VtrGh03peByHBsRIXb5A2/rDM9xv3pBRvrsT3aCtB
         yCwIg8OneeItgLIQEJ8lX/mPpVtNWs/ZwV+CCQ9/Jd25NrEMZtwzqW8U1rY8l+lkrsmj
         AcvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OWWbTtvsvnpcR/MxM10xoKrduFqfZbUvQXg48eQZZek=;
        b=EWHSzBdlmubO4qwHJNhdDHi6q8ppndJlqom0eewq0s7bM7YD43j7fgXuFdJFGCAsRq
         EoGcRM5Z0GhZXTIX0Ylp+UzeiEju64TlHPAiztK5TajdNZg9KXTNe6WDa8R8unrvzwc6
         PsZSc6gLN0W5KbizCQPvrfxibf6HdsEgYJubDvAq5uGY3L9Oj9MpndCGApbvM7EDWouT
         V5YTzcQnV1VF8XChhIkhtJ80yKbyCc60ujIekCoKMr5Cp6zpVbFuvSWd9N/6h3YXO9si
         4mFY/KTNQsTglUj/YgiSr4du116vBGL65dlbmtiMXIs8KfbrT2ljBg8tzdfCp6foFEJA
         9EsQ==
X-Gm-Message-State: APjAAAXgVB/J7HN+Qe76QTfTKjgga7KZxy8CGLB2UCeGFPzOOEKvQ9I2
	eZ2/V33LOrNXc6815m4ztZg=
X-Google-Smtp-Source: APXvYqwz08fQIz4MT8lGYeZebvZdiRKhZeBDYJnTQ0fELh1FftN9BjNvy2gaOYOfhxtg3ZncFFSFew==
X-Received: by 2002:a5d:81cf:: with SMTP id t15mr12351779iol.288.1574066479092;
        Mon, 18 Nov 2019 00:41:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7004:: with SMTP id l4ls2500446ioc.12.gmail; Mon, 18 Nov
 2019 00:41:18 -0800 (PST)
X-Received: by 2002:a6b:8d09:: with SMTP id p9mr12684698iod.227.1574066478756;
        Mon, 18 Nov 2019 00:41:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574066478; cv=none;
        d=google.com; s=arc-20160816;
        b=sqiNmqWr8sT29V+ztkmruiHgBWy1OefUxmkhm3vyyW0kjzkEtyrxhWmV/MWS+Jl6+K
         XuMjhi6FUkb4k+4juOUdNevKifvq9uUNJKagUxmeGzTI6iCdqB0dQO6hrRHZi/f4Xf+w
         +s9otgMDYTDlEgLrf+U+tQ3T9sESB3G2HuTT/QdY+KNjgmXM/IV50WDiZRHu1XtUG6aJ
         9b5SNsvTkMvql08o9ZqNJn7pSxnaFDUwhr0pMbpM8tHlQtlbioJGQXNaP582Nq9xe0KK
         iZNC9glVjPgQoEqnSDdCZcyTzpQnbZoehubDXQcrMNwfN9ojf53Fp+I/v5ydcH+h1C2w
         +EgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ps8MPX8AyfJLLBwWKE68qZjw9L/Pg8PHKG4fAaJeaII=;
        b=dwmH0zkbG/h7mE40VlVPBQwwnylI7qDqAc4XsgkZ6ypeQ4DKA7vhAM8dtxksfh+6LX
         W0DZCz0NycGIVaYzak1JcGxpVG2ICzLYLIYYgawhDyg9j9VrCYi/yIF0IupIo45laj30
         KfGZjLE8pBMI0kWozHgOU81QOFTOsS1P/RT70GUe0n1A6tINp53EqyK+5qk6eiKwZ+Ka
         RE0Wr6UdmYR+qXHn1B0kbupFzDubYSKBPE1nMk7xIdlTm3lvQWoXs22t/321NHoLwhvA
         akFpWchL2p7ZrDdYYmY4S6b8IXRy2cmFJJhKKFevrqKKGTwCObqfZ6h+4Od7VKs0L0Un
         B+iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IC7OCAsa;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id 75si724543ilw.3.2019.11.18.00.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 00:41:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id i17so19352097qtq.1
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 00:41:18 -0800 (PST)
X-Received: by 2002:aed:24af:: with SMTP id t44mr25451220qtc.57.1574066477833;
 Mon, 18 Nov 2019 00:41:17 -0800 (PST)
MIME-Version: 1.0
References: <20191028024101.26655-1-nickhu@andestech.com> <20191028024101.26655-2-nickhu@andestech.com>
 <alpine.DEB.2.21.9999.1911162055490.21209@viisi.sifive.com>
In-Reply-To: <alpine.DEB.2.21.9999.1911162055490.21209@viisi.sifive.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 09:41:06 +0100
Message-ID: <CACT4Y+Zv8VDQwiCW=8_qKb1Kja+bopBAtgBjhevM3ZpgMpXmUA@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] kasan: No KASAN's memmove check if archs don't
 have it.
To: Paul Walmsley <paul.walmsley@sifive.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Nick Hu <nickhu@andestech.com>, Jonathan Corbet <corbet@lwn.net>, palmer@sifive.com, 
	aou@eecs.berkeley.edu, Thomas Gleixner <tglx@linutronix.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, alankao@andestech.com, Anup.Patel@wdc.com, 
	atish.patra@wdc.com, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-riscv@lists.infradead.org, Linux-MM <linux-mm@kvack.org>, green.hu@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IC7OCAsa;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sun, Nov 17, 2019 at 5:58 AM Paul Walmsley <paul.walmsley@sifive.com> wrote:
>
> Hello Andrey, Alexander, Dmitry,
>
> On Mon, 28 Oct 2019, Nick Hu wrote:
>
> > If archs don't have memmove then the C implementation from lib/string.c is used,
> > and then it's instrumented by compiler. So there is no need to add KASAN's
> > memmove to manual checks.
> >
> > Signed-off-by: Nick Hu <nickhu@andestech.com>
>
> If you're happy with this revision of this patch, could you please ack it
> so we can merge it as part of the RISC-V KASAN patch set?
>
> Or if you'd prefer to take this patch yourself, please let me know.

Hi Paul,

Acked-by: Dmitry Vyukov <dvyukov@google.com>

We don't have separate tree for kasan. Merging this via RISC-V tree
should be fine.

Thanks

> -
>
> > ---
> >  mm/kasan/common.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..897f9520bab3 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
> >       return __memset(addr, c, len);
> >  }
> >
> > +#ifdef __HAVE_ARCH_MEMMOVE
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
> >
> >       return __memmove(dest, src, len);
> >  }
> > +#endif
> >
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> > --
> > 2.17.0
> >
> >
> > _______________________________________________
> > linux-riscv mailing list
> > linux-riscv@lists.infradead.org
> > http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
>
>
> - Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZv8VDQwiCW%3D8_qKb1Kja%2BbopBAtgBjhevM3ZpgMpXmUA%40mail.gmail.com.
