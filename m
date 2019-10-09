Return-Path: <kasan-dev+bncBCMIZB7QWENRBPFA63WAKGQEEIK5A5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1FBD08AC
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2019 09:46:06 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id f8sf984184plj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2019 00:46:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570607165; cv=pass;
        d=google.com; s=arc-20160816;
        b=xZM009zbt7M1923qCRfzYx+JO8Q9/k6YIS63dSHyf4cN6k2BglL7kl/FrzCxLp9c8i
         yVpGDMAAEtDdPDJCvlTiTm98yNc6y7MRckPnkYdzWun2EulGYyqZ3aXeMqLXgeZvSQqa
         enoucmPA2WX6YORleY0KL12bG9eSvqF5sxGem6RK+If21YXsy8Unv0BNXg+43NWt3mI7
         q6q2irnk2trW1az1OwjZx19y/Dh3OJpY2UUanRbFtnOP6MmyHPaInhb65cPjSOHVwqE4
         zK10TQDpeGkY4NYREPEyctgABU4JTG3yrW+7ITq0DHb+psY/YTBJZWx0PiQRGylJ1W1U
         9gWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qJAuGt1rDwXq4DF6x3wFSuKgxmIq1Z25wrOOaxiPgGo=;
        b=KS4ntALo/yuuQ+oP1OW7iowDimGREuGFJUjiCJ/210bcz+5cYzRgbwt1qJ0PYVd8rZ
         PeVgs8jJaMnbtV8hgXjbNC71VSV+Vc8N8Am+1mH1OsnEWgrAU8Lnb4DmN4W0a0wPqmXQ
         1tXOrQJ43H4d6P10twnB7lM4g+6P1ZCsy/byNcFe32Tx/+aYDWkhzbdXDVpLRF+cX80T
         Zvf6RIivzCXCJaIEwex1XA9598xCkJBto5V0UAW3uWr+VpOXvOqWEgoTDcmJyisVyck/
         Po49Nl+K+tQ790EGS05lOH2zSE4BumvjZOImLXvXsdLiE3BM6tr3oMcwboq/J6/xIhYn
         974w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJbDYOXG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJAuGt1rDwXq4DF6x3wFSuKgxmIq1Z25wrOOaxiPgGo=;
        b=nsxXZfIod9sczOH0J65L3bUATrZMYtRx/B3rzGSfV7H0cj8KAzUFze1NT92xSg3BuV
         pFDBeHXEI5h8ehABt7BnIN4x9YikSXiDwIL4qnKhcrnykgmbd9CwrMQZribOHpm+4nxf
         t+zE+LQpAg7X5dWW9GkcloL7zzSftCWxEIURWdkQlcpdWbyH/nqEUEy0W9lcXkfV3GMB
         7AACGQaD8474JlAycjzqpuTizy+4n16LQRTQRMgvCsSU6hQGjIwBLttCd9wS9vM3pC54
         RhY6kTp4ZOCUk4OcHehB9Skj5kz0JN1J93cxWbnnArJxFA0LihBQqpGB7QkHN7QkTs0z
         vXoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJAuGt1rDwXq4DF6x3wFSuKgxmIq1Z25wrOOaxiPgGo=;
        b=bxS8FrPFhfRYiISWLGvEUiH8eu2sFNx9an4MmJI+15pTZD7gEcBYZLfW31S9Xhdpbz
         nyWYLiDwr2Xild37ZT3Y5tyLlRqI82ULQ+hplKrYzgmWSIuTJfLqi6NsH+VoUWHvz+Ql
         yo6sq2kLyyvkO8Ttr/DBA12/A0QE57c2SPseulgQa/yWEA+htXCyF5kJhNIJDJgBbIgH
         0u1R/55OcsWEBRnBbiTTMRFkL6koqschIm/i0cHeQ2idzqcJ7i2dzWURpjNOnxbfnQFX
         Mu3XUDxLun2t7rtALy47+E6sqoDnvrIMjw12XVjKXq04IJCSp+I/0bTNFUXbodvBtuFT
         d5FQ==
X-Gm-Message-State: APjAAAWwcpLiawWFl5wI2xd4AlDBNz6ZV8MBZBnT70AEa9tBWKO2AH6N
	oiIXIiGaD2TYT5J8Zcp1LgQ=
X-Google-Smtp-Source: APXvYqxNLNjwFzJoDBCSelM982PZAGSKqt02kbT/9erY0E6aRHm9npXIX4evZZLbuI1M1OXRlQWPIw==
X-Received: by 2002:a63:9149:: with SMTP id l70mr2911181pge.354.1570607164877;
        Wed, 09 Oct 2019 00:46:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c086:: with SMTP id o6ls481132pjs.4.canary-gmail;
 Wed, 09 Oct 2019 00:46:04 -0700 (PDT)
X-Received: by 2002:a17:902:9f81:: with SMTP id g1mr1906221plq.82.1570607164095;
        Wed, 09 Oct 2019 00:46:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570607164; cv=none;
        d=google.com; s=arc-20160816;
        b=m83P6f+7+J/4a41l6zxTAg5F0sDuLehXoFhum6e+cXca3sFQHAuPfybBskPVpPoC5j
         ztNlMEpPgu3Eesxs/8RY1Wdalbq9BY/PChu+czOzKew50qdcT5+XIe5D6Zdn7wLvsCXA
         UdJmPNbP2tjmVlUocSpbqXWK8z26k4CuJvpbYlgKIoQa86Ay9JHsbjOo3uLenIPF3Wkt
         WHQgDEYemvqz+leci5vFzZnSOONspAKDCQaaAztJI0Rf51Gf52YwBMZnMXskPiKganqu
         0RZU4jS8ZKKsWPeecCxJlVn5YJaWgY/brWRFH8TCW29TBIswpDAot+CC0XRxww6x3xTL
         Z6YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sxXKt3AG8Tk8Yu+PG3kbL4A+1NeXOKutWUO/KuZh7Ek=;
        b=ciFKtfSe8tYTbBrBNJ9KOIB0Ljo/h0z1FKPRy690cdDnCVmSVHxXRpoWJsHCXlPVjo
         7fVu3a/ZeXbyewBLvKikeyAEKgyo21oRMEeZbVK3OZsRsN3sk8EHk5jIqD4pI6HUKRi8
         0EXdJt6ICM550GuXcRsB7+c8c2WpwgAMJK555DxpOQLzwcgkjwVZr1MXdjYP0rP/gVfs
         mbVdozSVAaUr2ufprT4+DRkysLN7iFimr9G/aBafncVjRw03mp7UwHRfPOe5LK+z33hV
         lY4xqhevySjYKw9ctN0zqRn2ul8LIADCbxfdfuyv2RNjrkSGjYvZK2dx5+Cn+1eZRiI6
         IDvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nJbDYOXG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id d5si136554pls.5.2019.10.09.00.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2019 00:46:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id y144so1325198qkb.7
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2019 00:46:04 -0700 (PDT)
X-Received: by 2002:a37:4a87:: with SMTP id x129mr2264716qka.43.1570607163183;
 Wed, 09 Oct 2019 00:46:03 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck> <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
 <CACT4Y+bdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q@mail.gmail.com>
In-Reply-To: <CACT4Y+bdPKQDGag1rZG6mCj2EKwEsgWdMuHZq_um2KuWOrog6Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Oct 2019 09:45:50 +0200
Message-ID: <CACT4Y+Z+rX_cvDLwkzCvmudR6brCNM-8yA+hx9V6nXe159tf6A@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Eric Dumazet <eric.dumazet@gmail.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>, 
	Anatol Pomazau <anatol@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nJbDYOXG;       spf=pass
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

On Sat, Oct 5, 2019 at 6:16 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Oct 5, 2019 at 2:58 AM Eric Dumazet <eric.dumazet@gmail.com> wrote:
> > > This one is tricky. What I think we need to avoid is an onslaught of
> > > patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> > > code being modified. My worry is that Joe Developer is eager to get their
> > > first patch into the kernel, so runs this tool and starts spamming
> > > maintainers with these things to the point that they start ignoring KCSAN
> > > reports altogether because of the time they take up.
> > >
> > > I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> > > to have a comment describing the racy access, a bit like we do for memory
> > > barriers. Another possibility would be to use atomic_t more widely if
> > > there is genuine concurrency involved.
> > >
> >
> > About READ_ONCE() and WRITE_ONCE(), we will probably need
> >
> > ADD_ONCE(var, value)  for arches that can implement the RMW in a single instruction.
> >
> > WRITE_ONCE(var, var + value) does not look pretty, and increases register pressure.
>
> FWIW modern compilers can handle this if we tell them what we are trying to do:
>
> void foo(int *p, int x)
> {
>     x += __atomic_load_n(p, __ATOMIC_RELAXED);
>     __atomic_store_n(p, x, __ATOMIC_RELAXED);
> }
>
> $ clang test.c -c -O2 && objdump -d test.o
>
> 0000000000000000 <foo>:
>    0: 01 37                add    %esi,(%rdi)
>    2: c3                    retq
>
> We can have syntactic sugar on top of this of course.

An interesting precedent come up in another KCSAN bug report. Namely,
it may be reasonable for a compiler to use different optimization
heuristics for concurrent and non-concurrent code. Consider there are
some legal code transformations, but it's unclear if they are
profitable or not. It may be the case that for non-concurrent code the
expectation is that it's a profitable transformation, but for
concurrent code it is not. So that may be another reason to
communicate to compiler what we want to do, rather than trying to
trick and play against each other. I've added the concrete example
here:
https://github.com/google/ktsan/wiki/READ_ONCE-and-WRITE_ONCE#it-may-improve-performance

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2BrX_cvDLwkzCvmudR6brCNM-8yA%2Bhx9V6nXe159tf6A%40mail.gmail.com.
