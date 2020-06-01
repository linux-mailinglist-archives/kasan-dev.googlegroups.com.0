Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS7O2P3AKGQEUX6276Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DCF31EA419
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 14:40:45 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id t13sf7560304plo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jun 2020 05:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591015243; cv=pass;
        d=google.com; s=arc-20160816;
        b=FIa9LVFtFyACQipEVnSLpMdPZcBXKiAMtDf6RObM9uJ1LXGSZo0hAgvdQQ3fT08aeZ
         2rpdcDkxc7xQt+75Yg6GnbRLWn47GQ9FpCJck7ZaeDgv3cWu01d4EkYI83Jd8bFy43q/
         yxzBJzaHFejTFU6oZv1Q76RlQCAmI189YuNOUUZRVl5Q8bjECkmE0f5gYQCxhTTWWesS
         Tr8yvP+bDKEjrtjCeDslfNmSlPIGYsO+5pAos9Tsu+7/7npVK81jlH7txvUCZ1knVBM0
         kjxdFNBzqtdVt3jOEvcXk7Fum4LPQfFSRzsepfzmIA+a0PaE5PZoUweZqkkkbORIC83I
         0eXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TgwCu5fmkQtxHhxyIhAMQIkMzxv8zcU2NH6cf1VtKhk=;
        b=mqSKAJzwgbiSBwUYJ1+zsbr4Tq/snSlx43CGAsJwl8YhrnfPakceKB90LqMlbMZexP
         Slef49YeJr1Qm1PMMl8CWzks9uksVa++T/oLC0h0bWbEnckKjmahPRBT7qMFdH2GfEMi
         7uS7wWW5nChYL09eLhURA5MN8tetLw+X0UPJIJQFZF2Ils/4bV/x39C96HgRG9X0QiAR
         riCIwJnLWkETcTVFqEhVoQT/kYSb9MgiKljiUiFtMAPMxWUO2MYJAC+zdgsafWTNOiSh
         iIFqHKs8TRynuwWNggWVFLL3or4eYiHWqK+Y524mlI306cL+biTRqNTWKaZIFddtviIn
         ZEGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RZbZjQG6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgwCu5fmkQtxHhxyIhAMQIkMzxv8zcU2NH6cf1VtKhk=;
        b=qC6Mc5wbwOa1TMNhMistJFR98Ee424YbThaf9YD+ix9qrLG7XVYznimZGwI+z+In+O
         J5cyTvp40kcS+70sbO+V25K+ePPvkbaTvb3HFUmk/VjAgM1lFJ/VQT2dxb0z4o/WfWsw
         MROgcsbhTtNt0S8yPv4st4DEpdvFkIFU2r4tS7r9MZHe0OnINTb1wh8VTB79zSRc5BKO
         5g+bjPgsJwMoekuIDGK3pJuOjAbSd3EA0cIpL+T4NYKqWIFhQxnjeFb57JEi8Xe2Y244
         lk6mFMLRDgMcu/du5I3UdVdfBw3BPRUdlmX5Etbk2aBQE4yVSarp3y/h2IC7RO7ytX/u
         Lf5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TgwCu5fmkQtxHhxyIhAMQIkMzxv8zcU2NH6cf1VtKhk=;
        b=EBIxjh7zA1Hy43Fv8ozF/QcGxudsnw0b6rupBbY9cMYigyHjFR4fhA61mxCVsXn/Jn
         6KHjckDgPHnnXgoxP9YhoSP+Rdo1pdn4qtZ58gMneMTI0WFzXTTPNM5pW3zZXU5GAAZe
         8qLGQPNqRAPwCsbU/OJ9zkdjWKaXu3U351FUta8oTHa1u0Zwga32y2OlKaA/WbUpn3mb
         /17rHyIx3uwzKACUiw1KzgdbD88S+9FUKo52uscPKxFaRv34dIv65sfmHQ8jKzYkmaho
         JQmayHBtHpXEQjMWlp3GVkbEADifujSwh9b6OBB8piKVKn+qYGVslYIeIIj60g1sUH78
         Gmeg==
X-Gm-Message-State: AOAM530JZMdFsj9tdNskbXbNxRzraYqfoMubVEEWa1PpuW7vAydzdfKA
	QisaShkuaq6/X4aIibzAlJ4=
X-Google-Smtp-Source: ABdhPJxsrSUyBB3RMC70wVN2tY/InZDTgXr8OuC7M3hBpp9UEsod46Sl9l49V85vW230BXZrib0xcw==
X-Received: by 2002:a65:6715:: with SMTP id u21mr19825929pgf.365.1591015243750;
        Mon, 01 Jun 2020 05:40:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls6718492pjb.2.canary-gmail;
 Mon, 01 Jun 2020 05:40:43 -0700 (PDT)
X-Received: by 2002:a17:902:6902:: with SMTP id j2mr20381773plk.2.1591015243309;
        Mon, 01 Jun 2020 05:40:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591015243; cv=none;
        d=google.com; s=arc-20160816;
        b=l1yc+J6eWAd4FQ0KSK9SmV3BeAFOmifITH4j3BEoJK2PTiEpTHGNHWWswKXWf1f9Mr
         ZfZlZ6Rm65pRPMwfbrv9buh7Sf/ets6as7QEzlUyvcOdITYrt123/OkU4Walvuwch8w6
         lMeMdMS4HLc2a830yg9TMqOWSDjIgcECYSwnYldfAZ6Va6/OV7DbsvaX/9+tksDmZk1n
         SwyXRT6r8gndyESCRXgDR/LS7WwI+UzftzrEaDTYUGqv7h5L4Mbh9klbBy02OV2QWYLA
         87Ke8QuP9tNtf+cbv//VAl8U1obNoKZYr4TTcReIb/bSSKWTIFQgHJ4naRyEJqKsrS1P
         oIKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/xqANHaGznl5Aocto0IQ3gq922jkx9zcNPs6wxjCx7c=;
        b=xs32kCmvIlt1qcvt/akoV/lp/by2zeT3MqKjLEcuZeqoWdplRX9j7Pt2x3Ix9W9x3M
         b9I41Vq6D3cYqqwaI+n6Ur5VU3AgTFZh6XETXrOBnhxfiY8xn7a7xrvUp+oxA6SwKDce
         C6QzPn1P7Q4m2RmFyIhAtxXhlciYZNF8Tf9PLZmKsdrWOkSO7fK67cUozXSAaO/FalKW
         8HwtSll5leUbxCvGs30slOKtYLelnS6OQYZUvFSCu0Q2R1J7b5PW8sv1HP2HN80fRI6y
         16EtWU3sFP7nhMt2kLY5avBU3wVlak1YjMW0VsYemYZp2BO12qBEIy/ID+2xpUwNXS09
         lpkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RZbZjQG6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc43.google.com (mail-oo1-xc43.google.com. [2607:f8b0:4864:20::c43])
        by gmr-mx.google.com with ESMTPS id l22si1126526pgt.3.2020.06.01.05.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Jun 2020 05:40:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) client-ip=2607:f8b0:4864:20::c43;
Received: by mail-oo1-xc43.google.com with SMTP id h7so1366510ooc.9
        for <kasan-dev@googlegroups.com>; Mon, 01 Jun 2020 05:40:43 -0700 (PDT)
X-Received: by 2002:a4a:b54b:: with SMTP id s11mr11444003ooo.14.1591015242422;
 Mon, 01 Jun 2020 05:40:42 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d2474c05a6c938fe@google.com> <CACT4Y+ajjB8RmG3_H_9r-kaRAZ05ejW02-Py47o7wkkBjwup3Q@mail.gmail.com>
 <87o8q6n38p.fsf@nanos.tec.linutronix.de> <20200529160711.GC706460@hirez.programming.kicks-ass.net>
 <20200529171104.GD706518@hirez.programming.kicks-ass.net> <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YB=J0+w7+SHBC3KpKOzxh1Xaarj1cXOPOLKPKQwAW6nQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Jun 2020 14:40:31 +0200
Message-ID: <CANpmjNP7mKDaXE1=5k+uPK15TDAX+PsV03F=iOR77Pnczkueyg@mail.gmail.com>
Subject: Re: PANIC: double fault in fixup_bad_iret
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "the arch/x86 maintainers" <x86@kernel.org>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RZbZjQG6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as
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

On Sun, 31 May 2020 at 11:32, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, May 29, 2020 at 7:11 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > > Like with KCSAN, we should blanket kill KASAN/UBSAN and friends (at the
> > > very least in arch/x86/) until they get that function attribute stuff
> > > sorted.
> >
> > Something like so.
> >
> > ---
> > diff --git a/arch/x86/Makefile b/arch/x86/Makefile
> > index 00e378de8bc0..a90d32b87d7e 100644
> > --- a/arch/x86/Makefile
> > +++ b/arch/x86/Makefile
> > @@ -1,6 +1,14 @@
> >  # SPDX-License-Identifier: GPL-2.0
> >  # Unified Makefile for i386 and x86_64
> >
> > +#
> > +# Until such a time that __no_kasan and __no_ubsan work as expected (and are
> > +# made part of noinstr), don't sanitize anything.
> > +#
> > +KASAN_SANITIZE := n
> > +UBSAN_SANITIZE := n
> > +KCOV_INSTRUMENT := n
> > +
> >  # select defconfig based on actual architecture
> >  ifeq ($(ARCH),x86)
> >    ifeq ($(shell uname -m),x86_64)
>
> +kasan-dev
> +Marco, please send a fix for this

I think Peter wanted to send a patch to add __no_kcsan to noinstr:
https://lkml.kernel.org/r/20200529170755.GN706495@hirez.programming.kicks-ass.net

In the same patch we can add __no_sanitize_address to noinstr. But:

- We're missing a definition for __no_sanitize_undefined and
__no_sanitize_coverage.

- Could optionally add __no_{kasan,ubsan,kcov}, to be consistent with
__no_kcsan, although I'd just keep __no_sanitize for the unambiguous
names (__no_kcsan is special because __no_sanitize_thread and TSAN
instrumentation is just an implementation detail of KCSAN, which !=
KTSAN).

- We still need the above blanket no-instrument for x86 because of
GCC. We could guard it with "ifdef CONFIG_CC_IS_GCC".

Not sure what the best strategy is to minimize patch conflicts. For
now I could send just the patches to add missing definitions. If you'd
like me to send all patches (including modifying 'noinstr'), let me
know.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP7mKDaXE1%3D5k%2BuPK15TDAX%2BPsV03F%3DiOR77Pnczkueyg%40mail.gmail.com.
