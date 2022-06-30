Return-Path: <kasan-dev+bncBC6OLHHDVUOBB25M6WKQMGQESDDOVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id AFFF95613A2
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 09:53:16 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf2931607ljj.19
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 00:53:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656575596; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZY4/PCUguDW7yfsGzep58cdIJpNjehcw80uVzzJpTVBY2XIiigfSem6PapXHcRRGxx
         ELjPonDgFhsaX9xNfsLVWh0oHuxmfRdHPxs9XiHo0H1GlS04NuCbL5Uvig1pKTsku5Al
         Ra8ou1f2Uh0ZYjtGM56kzvjJn1741XWmqiHJg9sCGlT7h9vCr2vi8odq9OHI+AggZ1m1
         Dx5HkTMEX1k+pfLdJdVJmsCc+ShUGROXDeoZnE3py0QDmn0QNLF5KmU/fEg/qhb3SD1l
         jkM/ZVFTebVtHkVF5xiymSmq5b2FUTatkixQfVNi5I8WTxi2qdVtQbOkfWAvxvylDGMd
         7ejQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JVMr4dfLtVaAGgzfmMym17dVfLDHKuxAW/XulyhP9yg=;
        b=u4NljNNT8YXuGPUvo0nK/RP2qhXc6hw8Igk+YK+wM5OrvXkFBRMIDcsiMC6ABE7bV5
         tkF4ldplzZZZzuSajQ9yOHSFuv6I2M8QC4ya3VxSYL6rUXPMoTsy+TiQKxq7kOrh5lF3
         4GHNMUwOg8Dslt5lt8NvMPGeGF8rXOFZV1b9q3kemvfG6e0ijq3Pnmd9zV+iN33VxhIq
         fYbK26gqPkmJCH7OqAQ6PsSeoqvQo2GnZVP9t/QUniSnpY/XK4WzQ4q1xtIyp27hjiks
         GKVFhPOaSekSD3TDq2T1kO3Vlk+9iVZeUPO/PHOqHigvNJR+3LhE/lsyaIXRNsdCPU26
         gfzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iL+4gYKE;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JVMr4dfLtVaAGgzfmMym17dVfLDHKuxAW/XulyhP9yg=;
        b=gqZ5NUbC2IDd8ou0KCP4qYG1L2poX8gXXgqN4asNxY3DSvUtgTc3zPWqO1ta5mN6qu
         HL5bZGXzfkBb4tRpJfLPd3nMX8pCNhac042RcQpQd4RN8UaLviN+YOngmt6zHi8Of31s
         2QXVciec8g+O1fhAPkJVeA4IfQSG9cvfSuda0it1gd2Fw9/M0JgIqRAZ/WLJiZ9utfx0
         OqT8Tp4S4t8uiHnNT2qXA16VemdzGzguvb9MdF+dqtpMgBLwkF6i1mLHspyH70lzG/AP
         qpbHldO49FWLVNN283WAqcu9tsfidv2z+PybcJiVOvCuHFvaHIhbxVLpWw4enjHlY3J6
         stMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JVMr4dfLtVaAGgzfmMym17dVfLDHKuxAW/XulyhP9yg=;
        b=rb87KV52PKZISQrsFpfQ6TDak2si8UdgdvePehlXrb8ZE3H1qHtEpr6DzGd19CAwDn
         a/svHXZ6olPHeDqa6Gwy0TW6i3f2vV0OeRkrCDXNY+vbITO5+iBLQkSJVw6r2HmNfbRq
         MKXvqeDRXxaVZ5ORNr+YUCRbKHXHN/SCo4ka8aheH9P+xq8VJnecZ/AZJi/q7/MnUNin
         tJSOrSiMDjuuH07IoyJBQs9xbE/bZhXJh4fX9m4Sxc0/3FXVs3T2vYTPA7o8d9nHgnRV
         6Axu0wiAK0Gr6TQYQ9xli7v5ovshbKLlf/HHIDGR37iPc4/shOBoU9ePGvsIHqGU0MJb
         WysQ==
X-Gm-Message-State: AJIora8S5Twje/H2Vyt4mKgbJQn56filC9lwU6rIrRstfyHkmLjkbvTr
	FxpV/ncQUoa4D5YcGOkeTS0=
X-Google-Smtp-Source: AGRyM1t7UffNusuj+1/aEt8DAASSHhgCM2kaE1jPswGjlrRDvLx3D8cB8gZMd5ZquavSx2bVd8pagw==
X-Received: by 2002:a2e:8552:0:b0:25a:99bd:5f9e with SMTP id u18-20020a2e8552000000b0025a99bd5f9emr4322793ljj.519.1656575595858;
        Thu, 30 Jun 2022 00:53:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238e:b0:481:2fa:2826 with SMTP id
 c14-20020a056512238e00b0048102fa2826ls131445lfv.0.gmail; Thu, 30 Jun 2022
 00:53:14 -0700 (PDT)
X-Received: by 2002:a05:6512:25a3:b0:481:25b8:51b5 with SMTP id bf35-20020a05651225a300b0048125b851b5mr4890448lfb.472.1656575594389;
        Thu, 30 Jun 2022 00:53:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656575594; cv=none;
        d=google.com; s=arc-20160816;
        b=pXHbThp7edyjbovWe5TP/AkVvCH6Z8gVHrJMmYSZlVSH5lhk5SAt0ZviHOG8vTlx+r
         hvxRuwKXSV1JiE0DMrq7vqLnPup3uYLRCSXvLh4miaM38WOG7xaUEPEYbRM5KYyb9xpc
         yo/PxGALaQMk41alYsioyinEMqbEMF1h2SO2gquIJQEWMY1eMDOFheMmRuV3EJnyF/gg
         ktqjn55g4aGcUYJzhncFtylBA6CDXOdCSckun+yxA+fCiVivu1ly/St3H+AXfwzesMUZ
         GHlclKCaTSTiL9qUkFOWbVO3NKuc3L/O56HCtzCcG/KqVGsZENqIJsOv6lG90PjdUCEE
         VIrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k2a71x297ZADJzEPxttWEizkIknOexDX93mkmWqB2RE=;
        b=NFmb/mbJh1/bMUCGCNRqoI56CKI5D/AtTl6dmYC2jdW4gJSxZiUBPyAh/wgVIfTpSH
         z+4ubqBt06uCmYPRwYadLrwdnOZZ+ZzQI54HcdQBz6hKTIgMeqT1fDnDMTcKWh/SFGHH
         xJHhPgxODGqF6JO94KrdJGIQpvfXYNQBZqxhuNl/9y1f+ysa1dXH7EwT/b9UMwtYWJ9e
         ojZ+1pIgYCvdCUpzqxDGxyIkvAeSa6QykwzolsASUxmHIzrMgqeK0l+9hcwfLeuoZPxK
         Et1TVaAtbMQtt1a26SwD3k3RMpM+EFA68MbTK2XKBg7jL+Atzpbk0W/HwXDX4rCrpAIQ
         GPSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iL+4gYKE;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id bp20-20020a056512159400b0047f8c989147si749473lfb.3.2022.06.30.00.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 00:53:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id k7so1490978wrc.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 00:53:14 -0700 (PDT)
X-Received: by 2002:a05:6000:1ac8:b0:21b:9239:8f28 with SMTP id
 i8-20020a0560001ac800b0021b92398f28mr7092801wry.517.1656575593964; Thu, 30
 Jun 2022 00:53:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220527185600.1236769-1-davidgow@google.com> <20220527185600.1236769-2-davidgow@google.com>
 <de38a6b852d31cbe123d033965dbd9b662d29a76.camel@sipsolutions.net>
In-Reply-To: <de38a6b852d31cbe123d033965dbd9b662d29a76.camel@sipsolutions.net>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 15:53:02 +0800
Message-ID: <CABVgOSkNqTAeJa=Z4pNYO=ati0qVsLe2uGUfn7yO_D2QfAzHyA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um <linux-um@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iL+4gYKE;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Sat, May 28, 2022 at 4:14 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Fri, 2022-05-27 at 11:56 -0700, David Gow wrote:
> >
> > This is v2 of the KASAN/UML port. It should be ready to go.
>
> Nice, thanks a lot! :)
>

Thanks for looking at this: I've finally had the time to go through
this in detail again, and have sent out v3:
https://lore.kernel.org/lkml/20220630074757.2739000-2-davidgow@google.com/

> > It does benefit significantly from the following patches:
> > - Bugfix for memory corruption, needed for KASAN_STACK support:
> > https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>
> Btw, oddly enough, I don't seem to actually see this (tried gcc 10.3 and
> 11.3 so far) - is there anything you know about compiler versions
> related to this perhaps? Or clang only?
>
> The kasan_stack_oob test passes though, and generally 45 tests pass and
> 10 are skipped.
>

Given this patch has already been accepted, I dropped this comment
from v3.  As you note, the issue didn't reproduce totally
consistently.

> > +# Kernel config options are not included in USER_CFLAGS, but the
> > option for KASAN
> > +# should be included if the KASAN config option was set.
> > +ifdef CONFIG_KASAN
> > +     USER_CFLAGS+=-DCONFIG_KASAN=y
> > +endif
> >
>
> I'm not sure that's (still?) necessary - you don't #ifdef on it anywhere
> in the user code; perhaps the original intent had been to #ifdef
> kasan_map_memory()?
>

I've got rid of this for v3, thanks.

> > +++ b/arch/um/os-Linux/user_syms.c
> > @@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
> >  #ifndef __x86_64__
> >  extern void *memcpy(void *, const void *, size_t);
> >  EXPORT_SYMBOL(memcpy);
> > -#endif
> > -
> >  EXPORT_SYMBOL(memmove);
> >  EXPORT_SYMBOL(memset);
> > +#endif
> > +
> >  EXPORT_SYMBOL(printf);
> >
> >  /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
> > diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
> > index ba5789c35809..f778e37494ba 100644
> > --- a/arch/x86/um/Makefile
> > +++ b/arch/x86/um/Makefile
> > @@ -28,7 +28,8 @@ else
> >
> >  obj-y += syscalls_64.o vdso/
> >
> > -subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
> > +subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
> > +     ../lib/memmove_64.o ../lib/memset_64.o
>
> I wonder if we should make these two changes contingent on KASAN too, I
> seem to remember that we had some patches from Anton flying around at
> some point to use glibc string routines, since they can be even more
> optimised (we're in user space, after all).
>
> But I suppose for now this doesn't really matter, and even if we did use
> them, they'd come from libasan anyway?

I had a quick look into this, and think it's probably best left as-is.
I think it's better to have the same implementation of these
functions, regardless of whether KASAN is enabled. And given that we
need the explicit, separate instrumented and uninstrumented versions,
we'd need some way of having one copy which came from libasan and one
which was totally uninstrumented.

But if the performance difference is really significant, we could
always revisit it.


>
> Anyway, looks good to me, not sure the little not above about the user
> cflags matters.
>
> Reviewed-by: Johannes Berg <johannes@sipsolutions.net>
>

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkNqTAeJa%3DZ4pNYO%3Dati0qVsLe2uGUfn7yO_D2QfAzHyA%40mail.gmail.com.
