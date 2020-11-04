Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2EART6QKGQEO3VVDSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A9392A6DCB
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:26:33 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id n5sf9138281oov.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:26:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604517992; cv=pass;
        d=google.com; s=arc-20160816;
        b=qbRaMpY7h/mvh9lMfzVpcAv492zPEUGqQ0IcEtkItvm7EW1SIC0Fff9li6Djl28xUC
         qgJm8I70evsAo5DJw2Goh75ZjPdRpJ1wGTkcNt8k/IiziZ/R+Ua+fZmif2mL6EGjCKB3
         4qJK+KGtjBIK7hoy9wV+X5FdiyYm5XvFFqFY7EsXkDmZ6NwXqEC0MvT3ZIbB73hODeFH
         Th3anS8CkDvRlGp0L3fSso+y1BZXwjyZfdQtq+npv2VE/liPpaKkubAl7stE2YC+AFpj
         05eE+NaOdsPiFVbUGLzMK3JQIH09TmMYuQpiAgVde3q1V3TI66ipyoQvosVr132F0+iH
         rv0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XB9YZgmIgmPw9gpsD3fkxXiqeK2hjXSx5okMuBO9MC4=;
        b=XFym5AQAUPqF3wauCyKlewFgJMoGORYc5k6ZisToQaa9ZFb7mMXNqkdAmn3nB9cOqW
         zI4/20zGumXIEcfAigSE6GV22lRT0+stgSahYOgLFueg8ILsM8eS0Fm6SM+cEmt2yrXC
         15mM0GSfcOpkO0YQs8WxWxNL5u0131E1XkeLz4zwos354alRQu8BlUksH3qsq+Fd0CTD
         7OP41I4P5+F2pYymIPQMZZLF9cKsc8g6sAUSp9SjOZAE/4867VuzGbTSBeYhiwHPt3+t
         u7X7MeAvRZ1lFVN15qV9YAzj60kub7PIPaPhaozyfZEuPZOcnYg+Ag6GjwkSaqIjiMq5
         nb7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QaU/Brb9";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XB9YZgmIgmPw9gpsD3fkxXiqeK2hjXSx5okMuBO9MC4=;
        b=a8/vLaCbDxJfUkSjE+M2Zuh0gp+sRSlxZiiHHAjmPBHJmZqwnPmBZdWIdKnwaQtCSy
         82wiPx6xsZT4XhdAp+BwkL3fsPeShYyOsUN6xOMiVAAwA3cQ7tFjIHkjaq3BhhP5i6Ha
         wj1a46ZNqtC3DV6nGfUBaFYdscUzvwrceeDwQGh3heX2ZzCHD+0RBwl/23nSfoLy468R
         ZYoKdQE0yK3QGq2GEKK3hh41vAKxCsCMeEoKYvP7mJFmi0rjz6n4QK5RkJ+UelvxF+lj
         qXEtgCefnpJBnhK4o5FgneWcVe4CYUNJO8GmvejRtUG5NXhPP6rRQldKgqi6Bhc5uYOw
         xw+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XB9YZgmIgmPw9gpsD3fkxXiqeK2hjXSx5okMuBO9MC4=;
        b=dkjK2TA9Fq00ziJ20AeHuGD1WtjdCw9q5yTShHGiSgM0+1Cu0uxCr15wCdBljgd8vo
         5yAwt81RkARlW6GkXrqQvYiQekDeoIEmTdmH5plsOhN03BFsmXBpQoESIjP5J7R4LXLW
         q2a1TQ1dppFfdlyLYFTY2cKh/MjLvk0G42Zs+Larwu+CjnZKN4FXqME2PvVb2xnjMiIm
         PHGnDp4QCcnoYgcQYzdLJ5T0WSXqlFzhJK0yzxsE2U63zTXJKraDzaQkfFeKoXFPBJMC
         q6aBhx1ayojlBl0biZYNL8sqOwqFpSp6lnO1wVV8+46XFL92e5Ao/O/4e9wU7NBzr/b7
         SbVw==
X-Gm-Message-State: AOAM531bsIVrPfVU2IqNc09vroH/KkBgZxmjhEJRcGz2iZ63xLaWayb5
	nWPlF8KaSQI+b/YRndBTC4g=
X-Google-Smtp-Source: ABdhPJy4R0ZDjBNSBUHD4KQuZN4W2GTkDs3rVQrwe6SaA646hK+v8/efp1fW8YZ38Q3mvtzCDlmCRg==
X-Received: by 2002:a9d:4703:: with SMTP id a3mr20445957otf.179.1604517992530;
        Wed, 04 Nov 2020 11:26:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1a04:: with SMTP id a4ls846313oia.6.gmail; Wed, 04 Nov
 2020 11:26:32 -0800 (PST)
X-Received: by 2002:aca:5886:: with SMTP id m128mr3507569oib.29.1604517992195;
        Wed, 04 Nov 2020 11:26:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604517992; cv=none;
        d=google.com; s=arc-20160816;
        b=efKlbrKh4HibbFWZZzNTDaOvZRzVlhXpsTouEHcEJrepo/Igp11QJXQepPIa6pVN86
         fKGbWgU5II/E9hvETpgCWiiUE3r2HC1bSFwhyDaX3jLDHDqr7W4eY8l9yQW2oZVHW/KB
         J2zC5nShf7+UCoDfTK+9nSerJutJYrvmoprYVGeah5pmiv+KcWCn0YFzROgkKHwhA32l
         miDkUoaEel1WAI1PAoBY/xR4Nqo7ROlLcqwujT1XHtZ5etCFww0svbbuBmyAzsAhCE+1
         es/ivbJpAy+qk8xWTY4FGsWxu1IZ2pc/mal6gIX9B4LUDI2cqbDpt5pOn0238DrwReY6
         6ZFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FEU9I/sSHhuQeVi3XIRAFCC61r4m2vgIPksqGF6T7cY=;
        b=jUXeA8TEo0maAuj11Zfhn4gCjGaHIzbWrQiba5n2ivABTfUSm5tCVW529DIH4QYzh3
         vQwxX1wLEZ+jA7ccfrcTNsg9jb4yvBAvK5dAPqXtt86rKY0BmTM1xNMEBOJEceBXOlCX
         S46Kfzf46PeevGs6AqsMAiu4NlZzErpwb5/mBBDatrV+IAM+pIXCb/NhNekVO6BXwyaJ
         d34doxfbk7hXnfl8m7Qvme1cXgwFkPqQD0VQuD13I96RjDswZfQME4hZkeBKBWTNjfAt
         n6JCzSp2v3ZNcIgVpYihLX7L2RuES6gJiJicxRjJk7ZtBvONchtkNyRaMgYcPy3flEVw
         49Ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QaU/Brb9";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id i23si333179otk.5.2020.11.04.11.26.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:26:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id g11so4250123pll.13
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 11:26:32 -0800 (PST)
X-Received: by 2002:a17:902:d90d:b029:d6:ecf9:c1dd with SMTP id
 c13-20020a170902d90db02900d6ecf9c1ddmr3858971plz.13.1604517991448; Wed, 04
 Nov 2020 11:26:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com> <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
 <your-ad-here.call-01604517929-ext-5900@work.hours>
In-Reply-To: <your-ad-here.call-01604517929-ext-5900@work.hours>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 20:26:20 +0100
Message-ID: <CAAeHK+wD_TgqYvqvp6fiQ_558CpvQyt67uahxLDYkp2hr_QUZw@mail.gmail.com>
Subject: Re: [PATCH v7 13/41] s390/kasan: include asm/page.h from asm/kasan.h
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="QaU/Brb9";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
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

On Wed, Nov 4, 2020 at 8:25 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
>
> On Mon, Nov 02, 2020 at 05:03:53PM +0100, Andrey Konovalov wrote:
> > asm/kasan.h relies on pgd_t type that is defined in asm/page.h. Include
> > asm/page.h from asm/kasan.h.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> > Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
> > ---
> >  arch/s390/include/asm/kasan.h | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
> > index e9bf486de136..a0ea4158858b 100644
> > --- a/arch/s390/include/asm/kasan.h
> > +++ b/arch/s390/include/asm/kasan.h
> > @@ -2,6 +2,8 @@
> >  #ifndef __ASM_KASAN_H
> >  #define __ASM_KASAN_H
> >
> > +#include <asm/page.h>
>
> Could you please include
> #include <asm/pgtable.h>
>
> instead? This file is also using _REGION1_SHIFT which is defined there.
> And I have some s390 kasan changes pending, which include
> asm/pgtable.h as well, so this would make merging simpler. Thank you.
>
> With that changed
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>

No problem, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwD_TgqYvqvp6fiQ_558CpvQyt67uahxLDYkp2hr_QUZw%40mail.gmail.com.
