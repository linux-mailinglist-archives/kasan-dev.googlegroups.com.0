Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6WURODQMGQET6UOZ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 034BA3BBC0E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:18:20 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id r4-20020a4ab5040000b02902446eb55473sf8376144ooo.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483898; cv=pass;
        d=google.com; s=arc-20160816;
        b=bUSlbS71AM5297v1dIBrRghZUCK+KPTK05KheIpljLX9QsaOkSaUFEFmMU9NsBMrLR
         cFXd/jbrFG8Wl3jy9/BegEqT0PbpsPUg2UMQ/jlCoJ90RzVpp/pK0T+ciaVgzMRC3RkL
         fZBa0iKvrYd//Jhtw0EC0nfzHCbUsCyNp0z61PYsCfQMdeU+0XsXcOLZaztHCoZ4tJSl
         WG8VjYkEAbaJwNULxmTLE8MdgifnsU8stGcwvKQxJgO0h+1sqdaZcHvazP1A3+lH/2LD
         TXxTkmkhYUdvJ37eA0IxaFc6ugYbb1zcxOv09fciro0Zq4JW0qVth00UuoXm3Wn5tSfz
         B64g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0Mp/naLSVuLb7Tp8BaHq6D2Dq5G8I3zrh5AICWoADaM=;
        b=wNVNzfZfetl1tezxbPBTWvOJsgdwtTeVco4zrcdCAj8wY/SMF3KVz792huzaKEFNtQ
         pfS8NEROjVV0zlZ0yZrhtVukmUfq31Ss6v1/IWhZWYtbcUeIeQetpkMOYH4N+TMO509X
         52BGHXGtBXM4gHA9r4WWUI3sg+e1q6AqQVH5Qcv1kT7QrL4H7CNsnY2pMlwv6GPLnXBR
         oSF4wV1tRiG7Y8Ll0A4VI5W5qsIPuZ1+kfbfy/JXA5hO/z4KNVMERFCehPuc8JAXitqq
         Wkx1FpPJsC2egdS2XMYKVtUeUyaWno/cC0WqE2/z3f38Nx6NW0L4hXNCNfVhF46XRJKa
         uWVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cHNJERRy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Mp/naLSVuLb7Tp8BaHq6D2Dq5G8I3zrh5AICWoADaM=;
        b=h8jxYLN0t8RdIgThvSIFRoLblI8ekELwzOtZDuJIuaejHM/j8BOtAl/9z+yqYDUZzL
         sDIGE6kGlAllX3oc7JwwDsA088Hlm1wVwRI7C2uGmBEWuu15jImnISe+R4XyZfcpqnib
         gE4hHye9GmKKzYUGmPSRqwLn486ojmFeH2Vsvm9N5o7KwSOeitRfSfcBYSfhexSYgxZN
         4QStoM44oRHLxGeeF9TQWXi2p+UVY3/gB+TYnrvn99iV4lxek1NOKzCnqRNM5yNJshTG
         rWLKub9BG6S3dnJUNdCPgTGkL2P1SH9B9YTXvtlrg9Pr0/aGDM/NO4SB8yXJz6GWbW5e
         fkTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0Mp/naLSVuLb7Tp8BaHq6D2Dq5G8I3zrh5AICWoADaM=;
        b=tgAyjbrgjVSQufHjcSCtUn80oCx4DBtjuOJJFW5dkuAlLf2NAD+NrX8KnkBmZ8Qjve
         msouhG5v6yI+GUnzzYZTzEHc+UFdfHSmnPqRkq6Y5CHxrfA+rKWF2Y04TdLJPM0nJEFV
         BEBzNO8/xIPS4yHLvVI1MzxyN5j0KZxQ49vrbnJ7196/MdNqJZFpZRtnIjexsE9X0Oii
         WVJBDadQM9xigEg9RfuPG5YsOPzlOYrIsUGmDeFH+sTs+ZtzYd27nJ1LmJr9lQSt0wEL
         NsXgMK4nynl8t61RlJAa4w7pEaRMIp9PHiv2hAS7JSDkuWDJOFy3O3n6NR0nPnmce/Fo
         +ZWA==
X-Gm-Message-State: AOAM531+6FZhAbFPF7yazuVdE/y73QoqKl8wfRjLCUWWUr6jdqS2iUf5
	NCXc8YccRAsaa3wTmNi1yWw=
X-Google-Smtp-Source: ABdhPJyAxjF0iDmJifTjPsVNpkI/WaOl5FmgvSba4y1EcfhUqgZfDxPZLSylyuReMMAr2eSMnKgBvw==
X-Received: by 2002:a9d:74d5:: with SMTP id a21mr328272otl.175.1625483898872;
        Mon, 05 Jul 2021 04:18:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls6823811oib.6.gmail; Mon, 05 Jul
 2021 04:18:18 -0700 (PDT)
X-Received: by 2002:aca:f491:: with SMTP id s139mr3867896oih.128.1625483898529;
        Mon, 05 Jul 2021 04:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483898; cv=none;
        d=google.com; s=arc-20160816;
        b=HKN1NJZn6NEdc3CRP1Fwt+lbXv+8a9jfU3+0nIB20ME5zhH/yQ96vpT9x5mIt66ngl
         muw0lnTNctqhYlPDi4QAtKG4ytaBLbD5ycRxx1VpCD+nvMMix2ev1nLKIaIo1XCcVH/B
         H1ilSTQ15tnDwmQuQ/Za3H5L10D0AZzOGTcslnHgssmOgYzTILnWHkibsZkp6B7lFSoH
         quD+D2OCgo2ALxqN/MNjYpMHIcr8F0kG9Ic7cr2/WIhpTBhi8T9L/NFfrk/GqKC8fBae
         cxIDz8MWOQTsxCWmGIVyVF85SIFfHvJB8Tq9TJX4tLHeDeUoiRMhYduTnVvMvcYcc5se
         0kqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vQCc966SXUWmxUzITD8j4jyP6srsgCllnc0jbweek7I=;
        b=yWultUpVtQYNcTTHB9RfKdP5GHCnGXEqHdqdB1LyFOsGhqJPi7ZHdKOFAlnyooWLL7
         eij1F39KFvFYKCnNnPNlDoJ8yb4BqlaSx+mChk26KvCGGetC/NmZ9h+NupnXxCxBrq9X
         BnS7rDMAKPsZFQv63z/47WUF5zk8hITAlGrUDx4Ne1pRL+mtwnd3HUM3wivxZ/75dgq/
         VVNBej+EwU7dcxDK8Hz+GJQXIvL2eHnTAEs4yy7x/h9mkrTECvfM3VOVhqkZvjGezmJ2
         y812+t9hR8QGpSqqu+6Q38nbiJpe85QueYo7mT6zvLRBs1EkD1ueGYWboygkdvdC23Js
         70tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cHNJERRy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id b195si818888oii.5.2021.07.05.04.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:18:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id b2so20398851oiy.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 04:18:18 -0700 (PDT)
X-Received: by 2002:a05:6808:2d9:: with SMTP id a25mr9673299oid.70.1625483898064;
 Mon, 05 Jul 2021 04:18:18 -0700 (PDT)
MIME-Version: 1.0
References: <20210705103229.8505-1-yee.lee@mediatek.com> <20210705103229.8505-3-yee.lee@mediatek.com>
 <CA+fCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A@mail.gmail.com>
In-Reply-To: <CA+fCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Jul 2021 13:18:06 +0200
Message-ID: <CANpmjNNXbszUL4M+-swi7k28h=zuY-KTfw+6W90hk2mgxr8hRQ@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: yee.lee@mediatek.com, LKML <linux-kernel@vger.kernel.org>, 
	nicholas.tang@mediatek.com, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, 
	chinwen.chang@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cHNJERRy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as
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

On Mon, 5 Jul 2021 at 13:12, Andrey Konovalov <andreyknvl@gmail.com> wrote:
[...]
> > +       /*
> > +        * Explicitly initialize the memory with the precise object size to
> > +        * avoid overwriting the SLAB redzone. This disables initialization in
> > +        * the arch code and may thus lead to performance penalty. The penalty
> > +        * is accepted since SLAB redzones aren't enabled in production builds.
> > +        */
> > +       if (__slub_debug_enabled() &&
>
> What happened to slub_debug_enabled_unlikely()? Was it renamed? Why? I
> didn't receive patch #1 of v6 (nor of v5).

Somebody had the same idea with the helper:
https://lkml.kernel.org/r/YOKsC75kJfCZwySD@elver.google.com
and Matthew didn't like the _unlikely() prefix.

Which meant we should just move the existing helper introduced in the
merge window.

Patch 1/2: https://lkml.kernel.org/r/20210705103229.8505-2-yee.lee@mediatek.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNXbszUL4M%2B-swi7k28h%3DzuY-KTfw%2B6W90hk2mgxr8hRQ%40mail.gmail.com.
