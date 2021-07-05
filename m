Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBEVRODQMGQEB5GENFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7695E3BB9C3
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 11:01:58 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id u8-20020a6345480000b0290227a64be361sf13171981pgk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 02:01:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625475717; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lh/lQPtlb3o9XwI84EWQamcc3NwVIrkip3UfBoMYIamm8YpmWDZAf1Dn8lOCSPcCOX
         30cBqW2IZ8e7Tn8rGS60w0PTKNz6bYiZjH4u8g5/EMboqucZHjkn5kPhEnnnqqEYa/QS
         gwZyJMceION7Fd31hPft3TK5ZbU8JtwzBNdcjIopfTkqYJEgNnKA2HsKE4YQJMc2oC5S
         3BOxvbY2dVjQbQEY5jjKMsP9I+t8AOa5IKvp51Ypj6QBLEMkEvrjgKoBlvJktqmDoLmt
         eGaTaBfmG1Gi2krtHcBH2XHstvFksVEmfWmuuJ54p/kus22F5738v6P6iY/pfdT2vdMW
         BDTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZuxgvmVsp+8rz7S9QdqYQSayCnmzMvMBbZHOKZWlxz4=;
        b=BsxSHnqKymbsIKPPzhRrA7DU+IKGa9NGJlIgOunIqW/ULhCCr4y1OjKwkQZ9AeDiws
         A8voIMUD2BAwP662vAi8cAhGT3VjRFY4npiyP0Q0xedqlPD3ex1+KodayFPAcm3n2sL8
         10c/K/9eEupE9xJmWSB8UE2in058pJ1noQWUfxXVVqXCQZhGZZSd9SWULPbthDJNCLfV
         w186yRMeT4iO/+NVd/9hO6Pp6Bjar57P7B5vMBXIWYpJ084CFZdBHCOZNj8uX5cQuqT/
         R/dkmwmD/UG82cKS8lHu3hGUg4KiUeCl8p4WDDBrt30yjusyJuIfG8m4pjtmcFUxWoVz
         EXcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EScxNMFd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZuxgvmVsp+8rz7S9QdqYQSayCnmzMvMBbZHOKZWlxz4=;
        b=mCaPCJ//tO8HKWo1WhoEtrIgDP71WjuNNVH5igvhrw9IXnarZkmTifXBvOWO0HoKHp
         6Lpplj2ezgYRtXhgc3oY3FnEOyCCWW/FLGqT+wqv9AnGUgQCjeNmwFiuBUNci+HG4ThL
         GKCdCy0i1/l4HLmmfrGwB4Y1q6deLBJmJH9ACPfoKDd0rk6P0YN4jDEzKV4Ze3xrKgNp
         rirBqYUMtO5tAbIZsxTeoYpq7ZLD/cX3bZyaLGWVIvajjyYGU+aJ856VR07moOB7IUjI
         j+fRHjaGvIOyjryEj8kNgGOXGGmKbR96B3ZWGs9jIX1cXzeG/HW+UlDFgDVqMRTIL7Ur
         jpkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZuxgvmVsp+8rz7S9QdqYQSayCnmzMvMBbZHOKZWlxz4=;
        b=SRz1fCycrpdgvqp8m3p5H9rheDhfVadbN56X9n1hw25bbQ1DBq9p/bYRZI5Loi4DtP
         NqbfKrOEnIAtDq8OZeTkSrjejrvWzMn1DZVxVTAd7PReOh3JxgeDQFr6qMqmnWlBegl0
         wdwoMygJu7WC6QTf5cBdX8XISdps8LDwRPmKnL47ON2fuz6oCRPLwF21hkZSFXQ++jMB
         TYRXNBSbR5Pjk2y893Y2bMniEFLG3btN9+YW2PDx55nhuD8j6OKeBMKXJD0mSV/Ao5J7
         suFdsC+2O1YzGKf4p8MvyB0wm9Dv7K15mG3xW/riYGfB5FQV/8Jnvbp7Jq54J6fSjKcW
         7BOg==
X-Gm-Message-State: AOAM533k20SoJBSjMzXJJgiqb3474Dk6m2h4Ok7AuStPB8GeVLCQlLha
	g6P2fCHHvO39CuM3n9IgIj8=
X-Google-Smtp-Source: ABdhPJw1kwdP+RMmS20AQIfZeMCSlRr29ZlGWf3kVEyBNW910mt9svhJaQ826bcDFwxxeBHxVWMqmA==
X-Received: by 2002:a17:90a:ee8e:: with SMTP id i14mr14115530pjz.29.1625475717002;
        Mon, 05 Jul 2021 02:01:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d505:: with SMTP id b5ls5661600plg.0.gmail; Mon, 05
 Jul 2021 02:01:56 -0700 (PDT)
X-Received: by 2002:a17:90a:9282:: with SMTP id n2mr14473280pjo.92.1625475716041;
        Mon, 05 Jul 2021 02:01:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625475716; cv=none;
        d=google.com; s=arc-20160816;
        b=w+llWldS17QKyK+0tDVSEZhk4Dj7OM/EFZQdwalfnAJHuXfvV2zZBmg6llx1e88o+Y
         Te+doMgTTH+nhjgvJD6lUvW5cQaJ5Mfs5tMd9qcWHyfKYv84UlIweLBEcJsnIaRSW4Py
         iII9PSOwva2PwRrzjEzDd4z12aRTiKXgEX43j1Oy806rVx4F3SAber56uOLyO4bKBh3n
         8pJqYo070E7jWdWbrZ2hK41QkH9RVzMqxMUgvTmZuRB8dKziCarcMq5oU0bgaP6aXkwp
         2d7WxEGtE/M8x5xsAuQ6+JvNSYinYBLxbwImtGRtzxj8fl8zyVYn67zxp0KRM2136yQo
         jnqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pi5VhRb63QYKLkBHNkU2ZBerPCcgeUsVkfNp8aUI108=;
        b=tW2FNyDXFBwDRTU7PTXxpvXfwKIiRRcmf59Gced2gpzWdDgToOavPUqieQlU/gKJwJ
         LV31ZxRPIpk1yavAb40cyCV3QSPi3JuasphJkrDKOQ2KxZmASGdrZYI6u9hRAwGBr2ca
         3tp/EvFWgU9doEoxG7JnsbnZCFvd35LwjizpbVWgnt935P7pJIql0yDC44Ujlywv0eyx
         m5Do0lWnmC3bEKArDB5NJlOJhZM2Y/efRUhVvFUagA4yq8E5C2Q9yCL4O/0jiVcCYqEF
         595/G+Mv3KFf0QeuYSe60m86i+JFtciVktMzd7wfq7Di6Kl8v5FPsCVwOKwPCnWql1ms
         4UgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EScxNMFd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id q7si1396381pgf.3.2021.07.05.02.01.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 02:01:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 59-20020a9d0ac10000b0290462f0ab0800so17616903otq.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 02:01:56 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr10450183oti.251.1625475715433;
 Mon, 05 Jul 2021 02:01:55 -0700 (PDT)
MIME-Version: 1.0
References: <20210705072716.2125074-1-elver@google.com> <CAHp75VeRosmsAdCD7W7o9upb+G-de-rwhjCnPtTra2FToEmytg@mail.gmail.com>
In-Reply-To: <CAHp75VeRosmsAdCD7W7o9upb+G-de-rwhjCnPtTra2FToEmytg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Jul 2021 11:01:44 +0200
Message-ID: <CANpmjNMZTe1Vs6Xx9bC9+azeRWJc7JvT-G4O7aQAq--wAp7f=g@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix build by including kernel.h
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, pcc@google.com, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EScxNMFd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Mon, 5 Jul 2021 at 10:50, Andy Shevchenko <andy.shevchenko@gmail.com> wrote:
> On Mon, Jul 5, 2021 at 10:28 AM Marco Elver <elver@google.com> wrote:
> > The <linux/kasan.h> header relies on _RET_IP_ being defined, and had
> > been receiving that definition via inclusion of bug.h which includes
> > kernel.h. However, since f39650de687e that is no longer the case and get
> > the following build error when building CONFIG_KASAN_HW_TAGS on arm64:
> >
> >   In file included from arch/arm64/mm/kasan_init.c:10:
> >   ./include/linux/kasan.h: In function 'kasan_slab_free':
> >   ./include/linux/kasan.h:230:39: error: '_RET_IP_' undeclared (first use in this function)
> >     230 |   return __kasan_slab_free(s, object, _RET_IP_, init);
> >
> > Fix it by including kernel.h from kasan.h.
>
> ...which I would like to avoid in the long term, but for now it's
> probably the best quick fix, otherwise it will require the real split
> of _RET_IP or at least rethinking its location.
>
> Reviewed-by: Andy Shevchenko <andy.shevchenko@gmail.org>
> Thanks!

Thanks!

> > Fixes: f39650de687e ("kernel.h: split out panic and oops helpers")
>
> P.S. I have tested the initial patch against full build of x86_64, and
> it was long time available for different CIs/build bots, none
> complained so far.

It only manifests on arm64 when using CONFIG_KASAN_HW_TAGS mode
(requires Arm64 MTE extensions). The other 2 modes include
<linux/pgtable.h> in kasan.h, and that seems to include kernel.h
somewhere. The HW_TAGS mode, however, doesn't receive -next testing by
a CI system AFAIK, so this was missed because it's not yet used by
many (I'd expect that to change when CPUs with MTE are more
widespread).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZTe1Vs6Xx9bC9%2BazeRWJc7JvT-G4O7aQAq--wAp7f%3Dg%40mail.gmail.com.
