Return-Path: <kasan-dev+bncBCMIZB7QWENRBHELQ3YQKGQEDOFGGJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 98AE0140735
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 10:59:57 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id e1sf15670655qto.5
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 01:59:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579255196; cv=pass;
        d=google.com; s=arc-20160816;
        b=syGWTIc+lDv8/jEgt82In4OSwa/6PIbUKM+8vspIP7fDiyf3iUpySeFS55pAa3Rxvq
         fgnwyOeOGZzOLbeT7jdYScjSGCrQlTHllEnXvFphI5R+4jPNCqLIMNbE6QovXRzixNxN
         tcVqjwYNzCJLsWmEo5n+nw5p84pxeU+sr8lhEuDco/u5TTehbjfVqvCG0y5caMSOfbti
         zbJw6veWLziy8M8U1T6uKSQoeaQmgI9JnjZ+bgJi9YqTJhs4+RL87rxAUE+8/U74XqCA
         XgGkRqkVlUBPpl9BeJyJJWCxsl6ljfRqCF5Yd6geuhxX6acCAuu207p1tohBxHcgWm80
         +sRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oBAFXKxtRdfZpFcr1Q7A+xQf9zp4Uq2LGHVVyHYe+LQ=;
        b=mx2BovZONTP+Alc2qKBlmysnEABp5WKN/6CJLTgwIqxG+uoMQ3T04fwKsV0bf3yA4S
         KrHMvCIjWUprHGZk119syp72OHh2nmHRuA7yQHJBP8QYpFj1h9xiNd/7Nh4Oz6xkTVf3
         A1nm00dC1yCAcqN4DIqb+hqheOl5+EvKCR1UAkiblrRX49/TrOGGslqtpb3Yx2W9xKtM
         kILTZoKaWnSjewYwcrx5pfwH5VGEuoqllzq6h1VDBa4VXW7RLGa7grNor3L5xuCm73cG
         ZVn4MOU3cNSYu3NO6CJNQycAwkjZygYkWQ+jgQsV4xMOBOddf2xptW9ThOLhz25IR0mv
         Xe4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFb8Zxd4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBAFXKxtRdfZpFcr1Q7A+xQf9zp4Uq2LGHVVyHYe+LQ=;
        b=kOJsDwRKPke8n9x0fheQ2Hk9ShisLM2AkY8QrNVsYBTMSnMCiWtRazjOd6ZmhjLaWc
         2x5rcWNDg8+z9j6TEVqK86ZsfL35FS5Xdriz85/CFM3ieHPHHgNMfxCIcqphwqkN13Oo
         PCFueDnpxzfj/kntbiQ5fLE1NJTTMq2hwdUh66ESqXlqvq+R3E+KuYOBP/o5ePrMS2HC
         obmIwk4KZYP1JGYRmcrmm2n30qr5UVV4IfCi4yzpGUsxmVAtGP/WD+lLVaqN+rVP4MQL
         sziYROgDpXkARPBmtTmjeEZJ+fmKVSTYa3GmG916hM+42QmcOMCzEHa/7ST2G2FmDrRE
         PpfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oBAFXKxtRdfZpFcr1Q7A+xQf9zp4Uq2LGHVVyHYe+LQ=;
        b=n0/LTG7bvAdDFmFnvFHXA9Umu4bfws7OnIhGtIsSfncF8yxllvJaWZeXDrbTNo2AHB
         UgjhhoGkQq3bbMG7VBrxly4u1LfrWdy7Lsm6eTyWVvaPVN6IhpocEiQytqSraR8pFESF
         sZ2jvR1kgZGy4xxOha/jsGw2hcgWL43t1Kmox1RUtuA7QXPfUHWGwLgh9VCEOaYW5IrK
         4JaNyS2LD+tcbf4yKAkU3n+JW9pIpqBu/qOqT5q1geihs7wXw8AxAmM/K5ibVa3hTOO8
         jqjtXWFcVmDVtWzDwiQMf/ypa/tZUyOEajFywabtjGNjGKOUDwbFFL5Xc3xbikbBMq0D
         PInA==
X-Gm-Message-State: APjAAAXPN5VytWvdBQG/78oyuIcPr4EKEq7yLxcbqJijd1AatDR8yuaP
	Eas3IM9UC6ono12RSpzfR5A=
X-Google-Smtp-Source: APXvYqxqXqzSotihECs+qfCa6ccGM6wG54loo7t5AZLSqXmK302NiPpp/jG8WCHvvibuA1K5YxkLww==
X-Received: by 2002:ac8:43c1:: with SMTP id w1mr6542645qtn.156.1579255196575;
        Fri, 17 Jan 2020 01:59:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:58a1:: with SMTP id ea1ls4706809qvb.15.gmail; Fri, 17
 Jan 2020 01:59:56 -0800 (PST)
X-Received: by 2002:a0c:8e08:: with SMTP id v8mr7027904qvb.4.1579255196221;
        Fri, 17 Jan 2020 01:59:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579255196; cv=none;
        d=google.com; s=arc-20160816;
        b=Az3VJnLBgpqubfHYYh5GuiY623XuQqqCsakNMIn1artaW4dLp0U3r6kPTC9FW1tymQ
         2b5g2UoGb/20yfG6hJEcCYfDQQUhUPLQMUJzObX4bR+zKOrVIShvQoF0MBQ9YATnzY7S
         VV9cj+bQEf5HgjuzFwCNL7VKwocPnu3ReO3s76p5rwfatPo4kvoAiAQMkojldkw2/cZR
         Y4TyN1CsIsd8IS77TqfN8f8UzCLdXmnoa9xOAgdUqAD/X1if2C8auA+tmn+/3ef54j1i
         8NP7cyv3tr9fuVjWt5HT8Gz9Noy+QSVs2g+gVDfqfy0iqyuRnfxHTI+Wfqwc9QSTEMdj
         dVug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jC/gslMBQjozVdraFcTbF5iK/wO0zoAIUa/gx2s21AI=;
        b=PXUP2AdBi1UZ1QD/cIsmJyX6TyN6czFFyMwQfs9PdsqVQM1qgt4JNnxSnx9ZcU3nHA
         QskzVwKlmYZc6W0IHbEcQHA0HCBfsFmBWRQhQgBNrnKsf7h7E4Dt+7r5545y+UiS7gOd
         SBNv4rCHfrTOaN8QBpTqYh/Gpcngjg0fFCnA7BkBy1lccNVTypAL82PEpZ404ltaboPh
         reYtvkArfd5wE3Z344Hw9NqOJCGqoj8IxgahX6hz9Gj5e4N3vVjfIzj30JIFWliRm/q2
         YFztauMcYfn0EiuhnjVvib2rec+0RwdxDv7GqFxlt3CIsolCFIqxOgiuOpligKQ/6mFd
         kiAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFb8Zxd4;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i53si1174406qte.2.2020.01.17.01.59.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 01:59:56 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id r14so22070267qke.13
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 01:59:56 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr37899734qkk.8.1579255195666;
 Fri, 17 Jan 2020 01:59:55 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
 <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net> <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com>
In-Reply-To: <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 10:59:44 +0100
Message-ID: <CACT4Y+atPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF=+Uu5hw@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Richard Weinberger <richard@nod.at>, 
	Jeff Dike <jdike@addtoit.com>, Brendan Higgins <brendanhiggins@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, David Gow <davidgow@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dFb8Zxd4;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Jan 16, 2020 at 10:39 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> On Thu, Jan 16, 2020 at 1:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Jan 16, 2020 at 10:20 AM Johannes Berg
> > <johannes@sipsolutions.net> wrote:
> > >
> > > On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> > > >
> > > > Looking at this problem and at the number of KASAN_SANITIZE := n in
> > > > Makefiles (some of which are pretty sad, e.g. ignoring string.c,
> > > > kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
> > > > initialize KASAN too late. I think we need to do roughly what we do in
> > > > user-space asan (because it is user-space asan!). Constructors run
> > > > before main and it's really good, we need to initialize KASAN from
> > > > these constructors. Or if that's not enough in all cases, also add own
> > > > constructor/.preinit array entry to initialize as early as possible.
> > >
>
> I am not too happy with the number of KASAN_SANITIZE := n's either.
> This sounds like a good idea. Let me look into it; I am not familiar
> with constructors or .preint array.
>
> > > We even control the linker in this case, so we can put something into
> > > the .preinit array *first*.
> >
> > Even better! If we can reliably put something before constructors, we
> > don't even need lazy init in constructors.
> >
> > > > All we need to do is to call mmap syscall, there is really no
> > > > dependencies on anything kernel-related.
> > >
> > > OK. I wasn't really familiar with those details.
> > >
> > > > This should resolve the problem with constructors (after they
> > > > initialize KASAN, they can proceed to do anything they need) and it
> > > > should get rid of most KASAN_SANITIZE (in particular, all of
> > > > lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> > > > (in case it does not work now). The only tiny bit we should not
> > > > instrument is the path from constructor up to mmap call.
>
> This sounds like a great solution. I am getting this KASAN report:
> "BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x2a5/0x2c7",
> which is probably because of this stack instrumentation problem you
> point out.

[reposting to the list]

If that part of the code I mentioned is instrumented, manifestation
would be different -- stack instrumentation will try to access shadow,
shadow is not mapped yet, so it would crash on the shadow access.

What you are seeing looks like, well, a kernel bug where it does a bad
stack access. Maybe it's KASAN actually _working_? :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BatPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF%3D%2BUu5hw%40mail.gmail.com.
