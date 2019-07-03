Return-Path: <kasan-dev+bncBCAKHU6U2ENBBCMH6HUAKGQE5CXODVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C1E25DDD8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 07:56:25 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id o13sf864813edt.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 22:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562133385; cv=pass;
        d=google.com; s=arc-20160816;
        b=G52UD95qKILlo1WK5xwGcG2XmEgkj0X2n3jeSg/Kk/1kETFFhP/kAiLCPFy4B+S92i
         2ztiJzFPP6jOxyLztGzlTMzn73IYW+bJurCSXFjCCTxLOddx+yKNU6opQMRbetExKvbI
         GWGQphXsGffp9K9CN71uFyFs2zTX9DdA3WcNRJIRMUTRFvyxPbKjQv6VVdkZf2B1Poqv
         Rv5bYGFLPIROkfpSTPfSXb61bKgWa2vPu3aAkz0Pf6k7UJ0yPY4cQTxFHxgeNBxkkzcd
         lUh8R9IW8RGjnG06QeLP/Oo7YPgX5GY4oPYsEsIO7xZDgI3x8oMNm5anACjpFJqc58k5
         blZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=s917hZy2cIPXXy32WT+ox8gOSg3VYHvHKNPXTZo15TM=;
        b=rAwYZLzfah7KxPSycvViXHN9athyLAkKog/pON34QCv6VcGhn0hmE4ffzEM3Io70gE
         KlQQHIYu49kI7mYUDOf03RBplEE9Z6fi2RbSnNRT6Ak2fcbvLZ5Z5fx8vaVqcwpjglrS
         9eZltTSFf9Zd2+HHsyKgvFSTZN2cgDiJgh9O3QQI5+Mjku83vLp/H82ITP383sv5axWk
         7AulCKRes71bj3s4xs4qHD7BMIBIheZzqL93E2A0uP68A1bxme9Oo1N75b5EuEOk5CnK
         EZJgcjgK9w0Fc9lNwdRtEPl1YMKkIRlyot6RDTbqS7vmVairBSGnq4EC1n140XB71NZZ
         8YaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=F5cjRuWe;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s917hZy2cIPXXy32WT+ox8gOSg3VYHvHKNPXTZo15TM=;
        b=X4XHD7o9LtluI3dv/LOOI7gMQ7bbR9VLE2UIBxdbNNFH2aUtyUpU52P9KtC8ixahMA
         mGZZBk5phz5G0TluJk53xDBO1hqxQ9YnnO7coEcie/xQauPzfbzXrwKgo2ofNKlmPEXX
         /oCgi5GGADHAwOjERni9eyVhVJYLePY3X2S90DSEWbsnxjW3UnamesxRG7t0iqxL68v0
         M2p+DFPIwo8SemxnnYfOqy264c5GU/Gbyl6h8AZMovQ/KtYdSv8uBtr4FIyNDyPubsZG
         8ey5ORhze0GaRGrHHvHCIsn/XAf6nqG1T78OY5jtHbJQjEojgG/MPSccB+4q3Pxq/T1c
         zbFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s917hZy2cIPXXy32WT+ox8gOSg3VYHvHKNPXTZo15TM=;
        b=oW78i4D7XAjCXNPeP6q5gU/WAmbaDF27juAtLvh1RLYsW1DcFHpCOXf6AUDhv1WYxu
         5SZORzM6OsJ84Har5Xv0B6n2wG2ZqYrDODn9KG4eZzjfVXleWql5E+SzB02P4E+NKrxg
         BmmCRqjIBBZuw6D3xrTsPRcZp+4HtcXWQxwKkQ9Cjjmfo1SeD/qXwfpBhWuzA2eO7mAO
         6NSsWmZJiWNaM40KjdmxPSxkhCzFez0D71RRQhZQlbkjXuKiDanyXTL6jXQrv9ep3PvQ
         uWkvF0sHmEO7YeX8SI1I3bY37NL8Wv92vVpRfRA4wPy3F/2rNAjTtaw7MAQ5tXc8dUbk
         +k6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s917hZy2cIPXXy32WT+ox8gOSg3VYHvHKNPXTZo15TM=;
        b=NPK45TdO0SYkDXgGG8ZN3EGzFoVZCVYDg69yXxVnqzTAkIrzNUgVh9AE2NTlrE6Z6k
         Yuf972i74rRN09F13n/04EbbVGxcR/x4a9+24jX59foh85UzUAC3oRJ2rpz/AXvhVgVt
         a/izJpkMkdQTO6zJRAPIXKVxA9oUEQrAjdlKFtsQiwfnjZl1Zp2kgHhSyImtLu1TzIXX
         VDqmc6Ug3foZREcgUkmqpdhWnHo6TRxHlPxk4z7F61w1bOPri+ykDemE1IR5EZhnKuk7
         JTtqt7bhYa+3aMrZqIxBPehrQWzUGft2r19j6xYNJoug8W0osTIhviu/KNeMDQnepBwG
         NDzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUxr8Ip299gHhA69SBxK7uOvJ7jqxYKWSYsRFnVme/dccMbZAqt
	Mnlk3zREKXnV4KK49m6wqDE=
X-Google-Smtp-Source: APXvYqzKxUGbcdOXEDFDPCXBNUmEUNHhXaqGt/52P+17yyjPjzIQduDxpwumhVBOnCbPfyG972/YzQ==
X-Received: by 2002:a50:91e5:: with SMTP id h34mr39596251eda.72.1562133385217;
        Tue, 02 Jul 2019 22:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:61c5:: with SMTP id t5ls240365ejl.11.gmail; Tue, 02
 Jul 2019 22:56:24 -0700 (PDT)
X-Received: by 2002:a17:906:c446:: with SMTP id ck6mr32470023ejb.190.1562133384669;
        Tue, 02 Jul 2019 22:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562133384; cv=none;
        d=google.com; s=arc-20160816;
        b=UmBxPKcGxs9IVPsTRrFADs/PVhAp6sPEqIbIlRbSz2P6aEbitTXpT0dJE//3YFussJ
         rp7eQ9aiX/0WqmQIz+e41A9uYgoCRJSpoeIh3H7RazWt1xUjwc0Rv6EY4ppZdbkKiueR
         tpKMaK8jvs0sHm7BQiMGbTvkXj9/ohQRYaQop2rhHnVHcoCVuMhT2e5pAptdEhVeUBUC
         d3tm7VDNzCdP0QS3MtuL3hDs4GGzI+p0Lwc6WriENBFhF6cvowrQ8y5Ip/2dIaMlz3K7
         tsrQN4lA4peKeVN60vO//acvaJodUuAhkAvaz8YY5hQMAs5KgsNgzpznNCzUyJ1dzSJE
         PAow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gm5H7tN+Ijb/5KQ50vxsS2nANpdDxCRQ2rQV8UzdOzc=;
        b=zBd113l9Y0Vydzfug08UtnzxoSUM2e2lj7tzvVkMT6GNV9EEfKXqIAxLUErQUUrjJ1
         vHPnNCl+IlTXERngrxd3mXaM7CL6hJ9vYNXdjeEiXfUKLX4UICzBEVKWS4sTrlCYK1T2
         eNchhjLiiCBncgVqNe4TSNArap5AZ13MvSKTP/dlymcp6cHkw2hayTUAXkvpzL5vgz1I
         VVLnD+rDexK4FIoneZC+5WCM59iYTZMl1hAZpV2rn1WfkoHSAQdZe/3dOfOrTwqVQWdm
         F4v0zZjEUPSAy2xBKXAMQS4kj/YEeyl60eV2KdeSeRqB8hxo/sWWAP47Ut2e9AOAobV9
         fpZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=F5cjRuWe;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id k51si83096edd.0.2019.07.02.22.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 22:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id p24so823565lfo.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 22:56:24 -0700 (PDT)
X-Received: by 2002:a19:c7ca:: with SMTP id x193mr2790383lff.151.1562133383879;
 Tue, 02 Jul 2019 22:56:23 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
From: Anatol Pomozov <anatol.pomozov@gmail.com>
Date: Tue, 2 Jul 2019 22:56:12 -0700
Message-ID: <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anatol.pomozov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=F5cjRuWe;       spf=pass
 (google.com: domain of anatol.pomozov@gmail.com designates
 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hello

On Tue, Jul 2, 2019 at 10:15 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jul 3, 2019 at 7:01 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> >
> > Hi
> >
> > I am working on getting KernelThreadSanitizer into better shape.
> > Trying to make it more stable and to report racy accesses a bit more
> > accurately.
> >
> > The issue with Linux kernel is that it has a plenty of synchronization
> > primitives. And KTSAN needs to take care of them.
> >
> > One such interesting primitive is semaphore
> > (kernel/locking/semaphore.c). I am not sure what is the use-case for
> > semaphores and why other primitives do not work instead. I checked
> > some examples (e.g. console case -
> > console_trylock/down_console_sem/up_console_sem) and it looks like a
> > typical mutex to me.
> >
> > So I tried to add KTSAN interceptors to semaphore implementation and
> > found that down() and up() for semaphores can be called by different
> > threads. It confuses KTSAN that expects mutex ownership.
> >
> > So now I wonder what would be the best way for KTSAN to handle semaphores.
>
> Yes, that is the official meaning of a semaphore -- it can be "locked"
> and "unlocked" in different threads, it does not have a notion of
> ownership and critical sections, only the counter. The counter for a
> non-binary semaphore can also go above 1, i.e. can be "locked" several
> times.
>
> For such primitive I think we should just add release annotation in up
> and acquire in down.
> But how did it work before? Did we already have these annotations? Or
> it's a new primitive? Or it is used rarely enough that we never
> noticed? Or maybe it is already indirectly annotated via the
> implementation primitives (e.g. atomics)?

Semaphores has never been annotated with KTSAN. I guess they are rare
and problems never been noticed. Currently ~30 of semaphore uses in
the whole Linux tree.

And btw semaphores do not use atomics. It is a non-atomic counter
guared by a spinlock.

>
> We now need tighter synchronization on KTSAN as +Marco will start
> actively working on KTSAN soon too. Need to avoid duplicated work and
> stepping on each other. I think we planned the following as first
> steps: rebasing to HEAD, rebasing fixes for benign races, fixing any
> new benign races during boot/ssh.

That's great to hear.

I've already rebased KTSAN to current Torvald's HEAD and fixed some
issues that crashed KTSAN. Now KTSAN works more stable for me. Will
share the tree once I clean it up.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMFOmWrBT8z8ngZOFDR2d4ssPB5%3Dt-hTwump6tF%2B%3D7A4YhvBA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
