Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6HS7LXAKGQEAJLZLGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB34210B4ED
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 18:59:22 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id v23sf1001179pfn.18
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 09:59:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574877561; cv=pass;
        d=google.com; s=arc-20160816;
        b=O11XLAiZqMuRgBMnCoUNW/AN8b/1C5CTiMQNTdK2c4BPyuKiYN76JxjuoDzCJsCO6v
         gZufTi2oTONIBxBSqRCfqD30TwpBATMuRzPPp7UAUEYzxUgdQ7KN5j1+m2sFGMrirP+Z
         tzL5eE+VzfoJHrB7zs9j9lLKuIGsn1S6Hc7L/55l2Ay8CY+3iJDR5cWH4z/SFkwJwqaL
         WqGhwnvduPZh7QPnF31fYqn35Job5oJknKw7zkCpn6ZS5+OIAuxCecPUpZTdTNYha0DS
         vLSk7ZgMfjTD0fr05EVyl8tDJsyPtLSkgEtmz2wZz2ZIsHKD8poBSm+Ub9W4BV+2lwbG
         lSZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VW15Yy4pnlr1Ujc8WEetDWKDHMY0IG5nr0jJQeGqZ4Y=;
        b=TpZxrLpdPIWNqm24qOUcEYJ+t+AYxlgIf1R5RijtRu10z5Mk3Ohru07v7v6ovkuzVI
         ofcIL4H1PVuWxVXJqlfziSiC+Zs1AleOev+uPGPb1ZdFALo/DzWczSvxZ9Ffxfx/7ijJ
         xuGArNOAJ6khDSknYgjsnjvmTkg8E1b8up+XCHanCdu1mnBZe+LMGljy+lZB9OAz3OaN
         GLK4/7EERlYS/oBulIl6SFNcq5XqWKKEPhQ/0zofxZe6+Z6jO32lyrb0ic+tgkfLPhZA
         MvfKTERAAyPqxVjJN9fYgjLOAnS1HnHkrBVsbOIZ2zT7eSKkBe+I8EbIoAKMB4tQRzEl
         hQlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J6979edA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VW15Yy4pnlr1Ujc8WEetDWKDHMY0IG5nr0jJQeGqZ4Y=;
        b=N2PB5CYgZCoeaR47VfKE3wCPoKNHC3OwF/6MuoADbFOS6+805L3jrb32fJpN76YjuP
         GdKOKDDlenmEs/IVzYSCSodztxNb401BURJVFg/bjjvnX8CvX73LCLPuhgMePG6pHWZ2
         2gyBY8EXN3+V1R0s4Knr0z03GIPEFevEfZAD3Tmbiqs+APiQ6naJJmD3eCtUYuq4IPBs
         /HSMslnYd1pLSjTviTLknU59plIrIJUGe3WoUWUa9a4H6lvY5mLo7k8DOLwhSjuTfVlE
         DY1c+vNiokj+YN9sD1W2leJVeWxDNDVOXlQQFmbGnIn2FnZ8MLpDAI+O3mQ8g9OLs1Yn
         J8SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VW15Yy4pnlr1Ujc8WEetDWKDHMY0IG5nr0jJQeGqZ4Y=;
        b=dinKUhjP64QtDmLvib67NEKnwR6/ohEEnbWyTGVChkPQ4aO38jQLO8ZgdPuHNTijmH
         Bqm37pIyJAjgo29cXHKPEkFughZSGaFbMbgdN9oOsgh78xbalRP3txA79LMRrDdXsetI
         dEu2l1dUmv5SLM9iqsSarBx+TrW4hNAc/IDBHjdkBIh/XifC65lmNJqsiLIeuXAs21h1
         2Kljy1reGVyR9Mim00Gb1rBxQaxiuQna6Pp6wirao/vhAQpDrM3lMZBmW6QqAt6sSzpA
         ez0JmrWovuuobcv86AfuUsZZI9JrEm6QCXHk4SrFRa6E0h+v/NRWZaPBYpdNvMc5iNby
         rmag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWwB97N8GMNW8b/nYc07sU44NVNTm1ruvgFcQax0OqXY8b55Hf1
	2L+eIHOYikvoyQweJ0E/hJU=
X-Google-Smtp-Source: APXvYqzK993ch1mFgHS/IPsYieg9D9Mg/RUu+HXsYeM4u9/I+K9VJC7hE6GjZHKAUH+Qtvl+0MYLjw==
X-Received: by 2002:a17:902:bd87:: with SMTP id q7mr5157104pls.187.1574877560838;
        Wed, 27 Nov 2019 09:59:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7785:: with SMTP id s127ls5994277pfc.4.gmail; Wed, 27
 Nov 2019 09:59:20 -0800 (PST)
X-Received: by 2002:a63:2949:: with SMTP id p70mr6527306pgp.191.1574877560363;
        Wed, 27 Nov 2019 09:59:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574877560; cv=none;
        d=google.com; s=arc-20160816;
        b=bvCC2Gogfrs4EKli1Ileh/PdRZbWcgLLby+H7igkSDVqPt/LCajPUgsgP9jPeKsimZ
         bwLgQoQWR77V6lPSUbnwW5dlUZmnz2PuD5RgakCxStlmmYVbRuSMxsM2Xg3ipyLYzB+U
         rHpqVAjLx8TkyQmmZe6cz+QYSHLkU4Uuj2sAxt/ZMwCWITksEAMZGgOepa65pjcrDd0a
         mFrHRvbumIDRYiBsWRTgO/AOscG/QnBXjIxc7Aw4Ij1FI1Fi9kykOwUQYqpPLIEWUb8C
         1kRXDH9n/LBLtlxylSEeDDUNXkXFCWV19C7ks2dNP1x+ptsr7lzwpWLsQjOTRmBPv6fq
         P+Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ezl2J7x0qEbob3yE0P5wX3Ui+Wbk0cG2BwPkP3kEj5Y=;
        b=yZG7JkwxFti1kYzn7sMko1Vf2hAU+63qeVfHJmbmP7caZpQk1wHfVKBJnMb1HH83SQ
         K3YogZs8l/V0Lcw7UXErFP48J/rQprrUDdIXY0X/vCpkZBRV7AlVSwxSRWWlZN5kBNul
         +mYCPRhwpsgFD72ye7IISQPhLQuOuLlSZKEsZwcDsfXcArswHaeTsDpApeTCLzdjcsdw
         7IVsreyEJdNg29UqHpxV5uO5eAXLwjbNvkbmMNvnAqf85zcaDKazQHrHJaRGbFRwwhCP
         X9jFkW+79btpHx8nFXZ9kKpzN68a+G8f5bpMnqMSElsN7RV3QG5eJybC2JJEH+tweOzf
         RDvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=J6979edA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id r12si204386pjd.1.2019.11.27.09.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 09:59:20 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id s8so10365246pji.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 09:59:20 -0800 (PST)
X-Received: by 2002:a17:90b:3109:: with SMTP id gc9mr2956841pjb.30.1574877560087;
        Wed, 27 Nov 2019 09:59:20 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id e8sm17373921pga.17.2019.11.27.09.59.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Nov 2019 09:59:19 -0800 (PST)
Date: Wed, 27 Nov 2019 09:59:18 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kernel-hardening@lists.openwall.com,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
Message-ID: <201911270952.D66CD15AEC@keescook>
References: <20191121181519.28637-1-keescook@chromium.org>
 <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
 <201911262134.ED9E60965@keescook>
 <CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com>
 <CACT4Y+aFiwxT6SO-ABx695Yg3=Zam5saqCo4+FembPwKSV8cug@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aFiwxT6SO-ABx695Yg3=Zam5saqCo4+FembPwKSV8cug@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=J6979edA;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Nov 27, 2019 at 10:34:24AM +0100, Dmitry Vyukov wrote:
> On Wed, Nov 27, 2019 at 7:54 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Nov 27, 2019 at 6:42 AM Kees Cook <keescook@chromium.org> wrote:
> > >
> > > On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> > > > On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> > > > >
> > > > > v2:
> > > > >     - clarify Kconfig help text (aryabinin)
> > > > >     - add reviewed-by
> > > > >     - aim series at akpm, which seems to be where ubsan goes through?
> > > > > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> > > > >
> > > > > This splits out the bounds checker so it can be individually used. This
> > > > > is expected to be enabled in Android and hopefully for syzbot. Includes
> > > > > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> > > > >
> > > > > -Kees
> > > >
> > > > +syzkaller mailing list
> > > >
> > > > This is great!
> > >
> > > BTW, can I consider this your Acked-by for these patches? :)
> > >
> > > > I wanted to enable UBSAN on syzbot for a long time. And it's
> > > > _probably_ not lots of work. But it was stuck on somebody actually
> > > > dedicating some time specifically for it.
> > >
> > > Do you have a general mechanism to test that syzkaller will actually
> > > pick up the kernel log splat of a new check?
> >
> > Yes. That's one of the most important and critical parts of syzkaller :)
> > The tests for different types of bugs are here:
> > https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
> >
> > But have 3 for UBSAN, but they may be old and it would be useful to
> > have 1 example crash per bug type:
> >
> > syzkaller$ grep UBSAN pkg/report/testdata/linux/report/*
> > pkg/report/testdata/linux/report/40:TITLE: UBSAN: Undefined behaviour
> > in drivers/usb/core/devio.c:LINE
> > pkg/report/testdata/linux/report/40:[    4.556972] UBSAN: Undefined
> > behaviour in drivers/usb/core/devio.c:1517:25
> > pkg/report/testdata/linux/report/41:TITLE: UBSAN: Undefined behaviour
> > in ./arch/x86/include/asm/atomic.h:LINE
> > pkg/report/testdata/linux/report/41:[    3.805453] UBSAN: Undefined
> > behaviour in ./arch/x86/include/asm/atomic.h:156:2
> > pkg/report/testdata/linux/report/42:TITLE: UBSAN: Undefined behaviour
> > in kernel/time/hrtimer.c:LINE
> > pkg/report/testdata/linux/report/42:[   50.583499] UBSAN: Undefined
> > behaviour in kernel/time/hrtimer.c:310:16
> >
> > One of them is incomplete and is parsed as "corrupted kernel output"
> > (won't be reported):
> > https://github.com/google/syzkaller/blob/master/pkg/report/testdata/linux/report/42
> >
> > Also I see that report parsing just takes the first line, which
> > includes file name, which is suboptimal (too long, can't report 2 bugs
> > in the same file). We seem to converge on "bug-type in function-name"
> > format.
> > The thing about bug titles is that it's harder to change them later.
> > If syzbot already reported 100 bugs and we change titles, it will
> > start re-reporting the old one after new names and the old ones will
> > look stale, yet they still relevant, just detected under different
> > name.
> > So we also need to get this part right before enabling.

It Sounds like instead of "UBSAN: Undefined behaviour in $file", UBSAN
should report something like "UBSAN: $behavior in $file"?

e.g.
40: UBSAN: bad shift in drivers/usb/core/devio.c:1517:25"
41: UBSAN: signed integer overflow in ./arch/x86/include/asm/atomic.h:156:2

I'll add one for the bounds checker.

How are these reports used? (And is there a way to check a live kernel
crash? i.e. to tell syzkaller "echo ARRAY_BOUNDS >/.../lkdtm..." and
generate a report?

> > > I noticed a few things
> > > about the ubsan handlers: they don't use any of the common "warn"
> > > infrastructure (neither does kasan from what I can see), and was missing
> > > a check for panic_on_warn (kasan has this, but does it incorrectly).
> >
> > Yes, panic_on_warn we also need.
> >
> > I will look at the patches again for Acked-by.
> 
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> for the series.

Thanks!

> 
> I see you extended the test module, do you have samples of all UBSAN
> report types that are triggered by these functions? Is so, please add
> them to:
> https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report

Okay, cool.

> with whatever titles they are detected now. Improving titles will then
> be the next step, but much simpler with a good collection of tests.
> 
> Will you send the panic_on_want patch as well?

Yes; I wanted to make sure it was needed first (which you've confirmed
now). I'll likely not send it until next week.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911270952.D66CD15AEC%40keescook.
