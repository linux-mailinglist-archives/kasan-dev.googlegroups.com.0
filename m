Return-Path: <kasan-dev+bncBCMIZB7QWENRBJ7AQ32AKGQE5WSV3JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F5291976A6
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 10:39:05 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id r16sf12462090pls.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 01:39:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585557544; cv=pass;
        d=google.com; s=arc-20160816;
        b=GggsJbd/qi2nS8bLTTzvOLoKo9QaI31CUZ6NDGPMQowen4tckcAh7LP9LJhR4CW98D
         V6akQ8JuF9Vy2yiXcWd15wXkPSfFOaVJzr843M47CYO8f60S+IXCJhLCdSLVUJGjI9FY
         H7lI8axXE8ULB/K0uWzd8M6fsZhsflcIWP9FhFaDBWFgxdCQWD3MpKLm1ceYQ+Y6ipuq
         R63Hm/u7WHQJEWniiVt91TCUEfTrekORtNzDhJn1K/j9LeAX/2nMF7vao2l6OfEBh3Um
         iLz3lF9zwDUZWXbEC4kiTxn13K4T8nQyVFcbX7sGmQ1MywPkyVRSQ7NKtUG5DJttvDx2
         /5yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4pwUxptriZORaNpcV/2ySqqs/27aMN8zVeD9zAvebks=;
        b=ZlOo8BsD84x+/34aAmgFR+5IU0ji4kTBlVC9T47bcZJOUKhXsMis2Tt8w2sJTFMKBi
         F1k56bKFIXop2mpfvALHXaKbRLAgNutAwG68OgDNgVyi9cli0CGYDveDm4PJNkH+IGmk
         NfI+Ri5jWy4kBew+b0Q+fi+zf69ZLV40/2iZd3iV6hHXNYc3RYi/4zKCUk0ccFSfpD/k
         vm+6jKNX0XcMmRwwgzKRxqpWOWG2nsSMNcu3j8bTNdMqJ6TtL3x4ZH8icDpZhKX4ja/r
         4MGdt3QA3cfWWClStzmgNzC4/E63zFAcW7T91hKOwKPMOXwtkRCCzvsZkF0KULcPAkt8
         ruyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLmWxuLq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pwUxptriZORaNpcV/2ySqqs/27aMN8zVeD9zAvebks=;
        b=ZogmPilHOjwaWdlY2h7C8+HCWZAlZZyVbYGaea/PhFAy11x5UHTiZxp0/6HnZ4m5Eh
         kjzBQhgHIwSFgvrJswfInSbFersX5iMIxXurzKLhNj4BQA3Cjf6o4CZj67ycAoFPECfB
         EOy7CVMqLzA8EJ3omi7n0oNLlx3Vw9Krvw4K3X4Gx8iZPJfQM46gsfCmClsQeM5mX+5N
         tDtQnTtrFcqXE37Irc+guQhRjbzLIIPisZW9ru+vJTvUx+6K8xUFADxQW8D1NfRGHMLz
         B97bQ2BGoj/X71sk1GPBeoiUYUFhTveogKS5u8KNqm9Kc2D+pKBDBthUgvYPWZuKrt1b
         L+kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pwUxptriZORaNpcV/2ySqqs/27aMN8zVeD9zAvebks=;
        b=HRVAAftKwwoJ2v3a0M+47guVmpn/W1hUlz4LlbHT0etL1m7HfYuBNIBqE/cf//DQdL
         YeWrrfXXrVF9RtTZnV6VtL+fLRusSsx6volVNPLP2yUogUMPliZQk3xs3hFLY1g9Gaqs
         RrtKHwLxOoZhlCKG6aKPN4N01seexbIIT5tG3UmDbygvHwjq3gFW37g2/pFB1fOaeUTG
         it8CU62KqFiHzmsrt4Fqsrz5gyxIQwdJ6iaoLsGDOHpcPlZfAJS057FKosTUPIUXV9cJ
         hJ8lqxZgPMnByvNr4B8ThFnK8Sm6dhvrp3jPqBe3ssr1w1SEDfFOuA4ucLNPjnCPjaIH
         aPYw==
X-Gm-Message-State: ANhLgQ3rlXJ3q5CI8EQ+1y6k0pm12uIL/s6Z2R+MsTe+kvcNT9gCtKB4
	8Cy0e5UdmGSFvNOnFeYJTOg=
X-Google-Smtp-Source: ADFU+vvlVY5EyV8REfDbJRJfsq8a56uCck8REcOO6W1adEMCkJAMiZxR5Zw2piFz3jhz0lsGWrH4uA==
X-Received: by 2002:a63:79c2:: with SMTP id u185mr11528348pgc.139.1585557544056;
        Mon, 30 Mar 2020 01:39:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a9c1:: with SMTP id b1ls12090950plr.11.gmail; Mon,
 30 Mar 2020 01:39:03 -0700 (PDT)
X-Received: by 2002:a17:90a:21ac:: with SMTP id q41mr14948014pjc.41.1585557543518;
        Mon, 30 Mar 2020 01:39:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585557543; cv=none;
        d=google.com; s=arc-20160816;
        b=DtO2LU6PBOg8BfuVSM6x77e3NJXADAAd4Rg4BN/yjP3aIHjyOUlAD5MuXRxG8Tk5cS
         PDBvaleZ+h6NfNXNfIazoVYO324QgBlXvbDY5vphlXUQPNuRCyB1LLMxbBZsFT63bhSa
         A9OwsaXo+roWdHaNgPhpHaPPaEhlQLnEpBCYu9xCqV4DFheOJ9fMjkOTl/AbwBbV5h1z
         b6tzHYrZIFvnC58sZcW4vg7Hhs8+v4Oxc1yqqG8iQj1YTNBDJXLOGLZTW+9CMy4TjuRe
         3kr3/urZalAhoyISxo1GBGLwYQ4kgZJG2aJWAVBapBXF7aY6uif4Lb5w0UfQRfqwd3zY
         BlgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4xCc6G1fjYHS6JfynXvIUwvrt/yvbN0xlTjIkaNy98k=;
        b=NW0iXPUWIbI38pk6ZCOrD9xJ0PAUwQuE48ADzqy+SB+phf0nWPOqhTlczl+oGiD9o6
         s5fF16SrKk2SPXQ/1T3+ibc8uZ41R4O2ydnRPGkK3UGbGh/YFWtBRwIGmi7D/uGs9ULE
         N8cC2MLNdets3Qn4cKNoJGIWVkKwC/3Vkdd7SfiOKbK7J826cJ4MNqZnQcWmPmnaf1d9
         /XFOfgAhQyVtlTdo4Z7Z2CLBWhw68BBOedveLJYgfuRWXw1nlqRu13+jxUGnF4yMujJL
         COSycqITOwzNWTQdp5YJPQibpma/T0nbO2DQpAIzOUigb0zjNqleoTsQvJQ5hOVyfZJx
         fKNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wLmWxuLq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id 19si887737pgb.2.2020.03.30.01.39.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Mar 2020 01:39:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id q188so18063206qke.8
        for <kasan-dev@googlegroups.com>; Mon, 30 Mar 2020 01:39:03 -0700 (PDT)
X-Received: by 2002:a37:bc47:: with SMTP id m68mr10748443qkf.8.1585557542372;
 Mon, 30 Mar 2020 01:39:02 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com> <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
In-Reply-To: <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 10:38:50 +0200
Message-ID: <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wLmWxuLq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Mar 30, 2020 at 9:44 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
> >
> > > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
> > > confused the values - because I see, on userspace, the following:
> >
> > Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000.
>
> Right, ok.
>
> > Then I would expect 0x1000 0000 0000 to work, but you say it doesn't...
>
> So it just occurred to me - as I was mentioning this whole thing to
> Richard - that there's probably somewhere some check about whether some
> space is userspace or not.
>
> I'm beginning to think that we shouldn't just map this outside of the
> kernel memory system, but properly treat it as part of the memory that's
> inside. And also use KASAN_VMALLOC.
>
> We can probably still have it at 0x7fff8000, just need to make sure we
> actually map it? I tried with vm_area_add_early() but it didn't really
> work once you have vmalloc() stuff...

But we do mmap it, no? See kasan_init() -> kasan_map_memory() -> mmap.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYhwJK%2BF7Y7NaNpAwwWR-yZMfNevNp_gcBoZ%2BuMJRgsSA%40mail.gmail.com.
