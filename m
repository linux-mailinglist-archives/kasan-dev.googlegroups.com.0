Return-Path: <kasan-dev+bncBCMIZB7QWENRB2OH3T6AKGQENTHKI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E7FD2996D8
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 20:30:51 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id m3sf3106175pjg.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 12:30:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603740650; cv=pass;
        d=google.com; s=arc-20160816;
        b=sk+qq3Fcczoc7SMmFbrg2mzdce9rmDx/GHU88qcCivf5NxpMtHt3gc0ZJnblZ3PRuy
         TTV0ttOM3xtInMTRBmBYzPJ7AVCFtE5VrEof7tcNegvhXW3SgqHAN1yGed3JFS/9pfwy
         FD0d+pQ4LoWK6gWKT4cSEYqxRNkDOJF9uB4Tbz/QDUAdD3P37Z1V3OMoSieveEoNqMua
         fEysl1H0zyHlGer/n/GSU4FRezbjko2kdLDc5KPZ8Iwxe2oNYyMoqndDMYqBZ7a5XnBQ
         8HjxNtmprB1hqw0D5WrOBxvYGp0MzHpVRSVJWvTKhszO+wSa4aQHchyaVYpwZwmPGwvj
         mHhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OJjIqnZRfIvapn7MjXIunHKUygQmkDdKQxVTUDrHdTo=;
        b=hlE001bNaIYVl0csYsIeIDHEwsA0Tr/8q78Qoue3y4gt4CLFjJWSpeIKNAHE0Kv9z3
         BOQO0ysNYQuEM87/nr08UBHRXAklD0nLat/Bg6pGN+VroA0GK+hc8jPqeOPodvpM82I+
         L0Vrr2uXsuQNtofRTEHOINDZLuZKXY0a9kjLuv2clIG6TRV9npejmFR3Rj26G/nW67VN
         UDFxByYAffx6DQmj0nM/EI2kVd4LbF6r3YsoNs65G5zNx/Ys6Fc2IWc5AK+kXqgstDze
         uuzFvMXtXJnG0CKeJTcWT+2+A59KGSfDx97WRazMG1hQ328KrelQdLSXrB2qdMpiG70P
         M+qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cpHNSoq1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OJjIqnZRfIvapn7MjXIunHKUygQmkDdKQxVTUDrHdTo=;
        b=nbWa5BeGHfjDqmlO4GSAuWNmaBkhU0Ts8WS3PtGF5JTXOK9zPyApr3RLL+OrcPdemB
         89T+UHEUYc0QK9JZNDzRaeQ/VbbJxM1CorYHxZF9enM6uxk5ne0hi6Eyk3suv9Vyj8lA
         15aoRPlBanHBEAWqfcilgdJU9uGF9xOTZ8EFfVt0ijLHV15DFzodhUkkZ163hmb9BsQA
         yJqNAF5E7OtVH8h/6z8jXr94rO2WJM2h0SwO7cqmh2Vc/XLMdU7Ch8KkCECbPVJmNml9
         ojnsn4/QFPN/n/mE9+8OWpsIL2V2Gcy75H9dEP0m+uPfxqWrMNuPRcZsI85iFKQsu7n4
         N6/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OJjIqnZRfIvapn7MjXIunHKUygQmkDdKQxVTUDrHdTo=;
        b=iQCRQaJPAGpvflccgiZdyjBirqr5ppiRG2it0jm4SLF2SCRfpJamaa5B09esLa6ESu
         UxO49u8aZzxCo1hXN5kAn5ouKAsvj1KM+Ue+1DWfUTQx3aOH/gOolqO+RGmb9JggTFFR
         gCKC03rIJyDPAehtL5QBZ0j5YMSqozdURGMUh/kO5QcuqEwbxUsZ4nCY+wpgXj6gpJs7
         0K98MNOA1Yt1mtRHA2ZNDmJH+K/BygKb26lyQiWsfBbAb3V7v0OHWzbjuEvUh//bsmjQ
         PEaedBG/d5BY00SeKyLFzCdZ1tsl8GCBPEr/OBv5U9UVoaCsrQyB7ERu0aiCj3oEm+MC
         RluA==
X-Gm-Message-State: AOAM532mKFqR942fxWeKNTj/urLlzThgjGkSVkCnYINL9DRvAGT9Mhh6
	lHUMhwx9MAPPaNEVXWxvE8k=
X-Google-Smtp-Source: ABdhPJyPBil5WauRG6qxSYR00jJW5psfbxOpYlSIP+OXMabeyn69RfvjBAImv2+2wo2edY+nxT+Z1A==
X-Received: by 2002:a17:90a:e884:: with SMTP id h4mr22419736pjy.126.1603740650101;
        Mon, 26 Oct 2020 12:30:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:ec1:: with SMTP id gz1ls5020157pjb.3.gmail; Mon, 26
 Oct 2020 12:30:49 -0700 (PDT)
X-Received: by 2002:a17:902:724b:b029:d5:a5e2:51c4 with SMTP id c11-20020a170902724bb02900d5a5e251c4mr11757707pll.80.1603740649503;
        Mon, 26 Oct 2020 12:30:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603740649; cv=none;
        d=google.com; s=arc-20160816;
        b=FdGLSdqXMqIJc1oJNeCLBYrJfcnMHxHja+uffY9lPe9h2I6zxthFzmhIj1gL9VckKw
         E8qeGa9wvXsSZKM8q2100EZLqMhjq4Q7+Jk9i6aR8QkUwHKUkL8G3wfIw+eONLMKfoxb
         fLUjmjptJyW8L5dHsEc4dzfO7xro29n+irZESVxc3wYzHe8zmoMA6oUB0fL4OZ+98b++
         ER243wg6GvlQdKLah2BQUfK1RNPcwaeeGIJyUhG6vQwxkQ7suh4i17sEimSz5XEPnxni
         qA5+tPxAKJMllQ3++Ug+qLibobAr0C8s9IklT9TmC8ub9rQMalNWCTDIcRqlXuGXLAbF
         xyKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IISXfAubKBZn4Oqp91nhXoi1ToEex8TlLdus0KejKY8=;
        b=wng5dHg6iwxDxrB7EBi+ngHYWveEXn4k5TBFsmdx4jpn3OXM55sCuBQNBRD2NUocBH
         peROHBKtCOazYuKK4o0G/UPVNP5u+JqwBgYpbU8gqa9VgcJw81gp88qnTqEdY20tvewh
         uWxYX60qyaLDV7+l7baLdS8PSlqo0LNS4zHEPdM22/KJLLBDgihopZQu9XBAzMpxZNqj
         j14kUuCJE1plKSf+zzynMrGwzJX215Z59lHdUUC+EyGSoPMqxpmu+PNJsHVjPfDINxYH
         8+V2MGqyktd/tgTnkrrUhiTclJIGa2FZnA3hPFCvtTaJONFpgfKmrUHyVRqbjt0qXfbw
         VMxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cpHNSoq1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id z15si600733plo.4.2020.10.26.12.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 12:30:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id m65so7600392qte.11
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 12:30:49 -0700 (PDT)
X-Received: by 2002:ac8:57c1:: with SMTP id w1mr17362440qta.290.1603740648301;
 Mon, 26 Oct 2020 12:30:48 -0700 (PDT)
MIME-Version: 1.0
References: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com>
 <CACT4Y+aGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg@mail.gmail.com> <CAG4AFWZvWRMYR-7+zv7RS-Khd25+AEgdyX4O86utTbTZ7QD3yA@mail.gmail.com>
In-Reply-To: <CAG4AFWZvWRMYR-7+zv7RS-Khd25+AEgdyX4O86utTbTZ7QD3yA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Oct 2020 20:30:36 +0100
Message-ID: <CACT4Y+Ya30AEFs-p-3p=oWePkVxd+GvBAi44u-8ZKCuH+Zz6zQ@mail.gmail.com>
Subject: Re: How to change the quarantine size in Kasan?
To: Jidong Xiao <jidong.xiao@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cpHNSoq1;       spf=pass
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

On Mon, Oct 26, 2020 at 8:26 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
>
> On Mon, Oct 26, 2020 at 12:19 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Oct 26, 2020 at 5:30 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
> > >
> > > Hi,
> > >
> > > In asan, we can use the quarantine_size_mb parameter to change the quarantine size. Like this:
> > >
> > > ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
> > >
> > > I wonder how to change this quarantine size in KASAN? Do I need to change the kernel code in somewhere (mm/kasan/quarantine.c?) and recompile the kernel?
> >
> > Hi Jidong,
> >
> > Yes.
> >
> > > Like I saw in mm/kasan/quarantine.c,
> > >
> > > #define QUARANTINE_PERCPU_SIZE (1 << 20)
> > >
> > > Does this mean for each CPU 2^20=1MB is reserved for the quarantine region?
> >
> > Yes.
> >
> > You may change QUARANTINE_PERCPU_SIZE and/or QUARANTINE_FRACTION:
> >
> > #define QUARANTINE_FRACTION 32
>
> Hi, Dmitry,
>
> Thank you!
>
> In ASAN, the quarantine_size_mb doesn't seem to be relevant to
> specific CPUs, why in kernel, this quarantine size is defined for each
> CPU?
>
> Also, what does QUARANTINE_FRACTION mean? if I want to specify 128MB
> memory as the quarantine region, suppose I have 4 CPUs, shall I do
> this:
>
> #define QUARANTINE_PERCPU_SIZE (1 << 25) (i.e., 32MB for each CPU).

QUARANTINE_PERCPU_SIZE is just a local cache for performance.
Generally you just leave it at 1MB.

Re QUARANTINE_FRACTION: see the comment on top. That's what generally
defines quarantine size.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYa30AEFs-p-3p%3DoWePkVxd%2BGvBAi44u-8ZKCuH%2BZz6zQ%40mail.gmail.com.
