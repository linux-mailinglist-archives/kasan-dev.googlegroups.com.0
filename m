Return-Path: <kasan-dev+bncBD4LX4523YGBBUMR2SGQMGQEQRX3WCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F1B9F471618
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 21:23:46 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id l75-20020a25254e000000b005f763be2fecsf22959606ybl.7
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 12:23:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639254225; cv=pass;
        d=google.com; s=arc-20160816;
        b=F8zS83f031TmAxRfoPhm+8oRxwAhvPV+Sj71/5ghjS97cUxiYIcCybxHpWD/bH+RAH
         7oCqTk2rV26mX4TDHQ75Fh9piPBeNQcMxdkUJyI/lNtzhxYzsuiT0XRzMRQJleNwQcRJ
         UzvBwCqPiSLqw3G9p7md/D4lJ9+lxAirbtDT8QX943kDfLQ9Og6U2+kRDhr5A8A4VkRN
         rQFBV1ZfEtOSulbdVtRtQBFn6/RJKD6iMRFor5IfUqXozd++AqjhgGjLbswJgqPJQRoQ
         c93BJ+sNGRJyA22bvo80FI5p/pGoKLbUOX/d3MP8jcz9ShlmJv2pBXH6aTWquUtul2UC
         dVDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eqp/GdDCI1Wf0F+R8NcewR2o82CHRHJvyaJczDsFUks=;
        b=mp7L4Av/+vBLsKcoRcKS3xtVl/1EbhKo6i0mhi74+oC3L+a+zUGFaLAg8ttYJ5IuXB
         xSzxFXCFPw3ctdQawQeAq+CCk2KfnRaZUDvMm9APZ5j/Krpl70UINH2H9ubGz13B2VyV
         0IMJhLfQS5bcDlPq9Z6dzV5MMp6sYs3aR4QTU9nsD3W8YEmclyzxpZj/JZa5xnQe3hFv
         PayG3vlVDmhBiyjotdHpq0ap/q8o8tTfTGRdMt4NzhCqSH9uVc2FAFWAuSPl3jHikZqY
         H2ZEDzroUnw0BUCGZtCQupggKqgV+Vp6RSIc+ndMH0pOXaV47VTgtwLfhTkzqVhKqVn1
         kwiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eqp/GdDCI1Wf0F+R8NcewR2o82CHRHJvyaJczDsFUks=;
        b=STaugOdPPP8cnbeZPBVPqmchUrHizVvdyEHjuO6MzG78xwj79nfHaWfzHsv2ByZ5V6
         aXYbbUzogcvesvdj9g7L6EDNILNbcLbAF8P+DXaPaI9DVyQfbijgFPsS1e6REBk220hN
         Lkp1pqbsmjofjKzh7Mupugtb4hAer6Go5etzqmvl9X1/C1EO8hhj5qPzglzmT26e4SfZ
         eXd1UX5OpxE9TzMo2yZXlXsAzJs+yIbW3ububNFnHkazIPkDCuoiRjaHpv5wM7lTcB4m
         wqzh5esANaWF9wTSx4mz4U6OjmbIft1YEl+lhvYIgoQ2mi8xPsn2UKHoHxBjxbecdRrh
         GGsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eqp/GdDCI1Wf0F+R8NcewR2o82CHRHJvyaJczDsFUks=;
        b=rjEF6tBAy1A4E+bfGYR4ObTpg+BXOIAgFrAyJkuwPlU8qEZAqhtqZwcjpTPIoR9yYR
         UUDwUA+nBOePsPUxzB6Xs2HYJlp8snSPtP7g87bR0z1LOodt0P60Y2aWsJdEoQbPu2jP
         LieBZ8CzoqzwaM+5lwu1rT+a/tua4M8qAFHKyBSsQYUwEj58Q4xBkOkLo+ckOvkBv9Ic
         r/AZlpRqJQ5uB3aCFVyadXAFUWLzdkOpmHZbMOgSE12P2Co6H2bUr4n+hSaYJJdskBR3
         n7JVa60cLApDvg0sE0ewYioiwnx46AnzlZOPgf2OPkR9E1WXYZZlfeLNQzAEz7MmI6R8
         SyAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HvUn9b1NhvVbgZTjO8L6PBIub5JZ1GdHAcfT20u86g6yKCV13
	P05Qzw6XFdTHvqGlaUXZ6EI=
X-Google-Smtp-Source: ABdhPJyRtNraRHR6zggNhzdQji4rzWrjeR8CNXavUf2bVelKuFwozlDQ8NktzoRvHza7twaPNzFLmA==
X-Received: by 2002:a25:d013:: with SMTP id h19mr23609577ybg.428.1639254225743;
        Sat, 11 Dec 2021 12:23:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:25d0:: with SMTP id l199ls11877ybl.6.gmail; Sat, 11 Dec
 2021 12:23:45 -0800 (PST)
X-Received: by 2002:a25:417:: with SMTP id 23mr21639869ybe.319.1639254225201;
        Sat, 11 Dec 2021 12:23:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639254225; cv=none;
        d=google.com; s=arc-20160816;
        b=utLNd0U25ERxsc8PvhtFDuIOnlqCPoIBfCgyrlDv6EYj9J/6tpJKWLCzBZ8YlEjRRG
         mZuPupfNZvXAjtXcgrEbbTTbF0aXEEFVzbSB4KrjlfW8BMxyaSYkMDbH8MeFB23n+3lX
         gPJFlV0FmX2GbnuVjyhBY0Bd/QyEmr1IggFE8MnWihkjh3xRCpyiCTxSWAMczsnjKIPi
         o2omv/DAAGudUOmtMzKJtGBRKQo8bzZRoSuCybISXPthk3uL7Q/ZEYhQI+ZktNY0DvPO
         7l4JVTaH4kbXDFPAvbWbuDQSArarlYlpEzHnJq1Nb0gbyfE5jzgUUyBxSKOMgKWHVlub
         23mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=q/CHgMbz3rmaI1XOd60/Xa3nMws7oX2r2YRVNx2dN8U=;
        b=cIHL60I0d9wVGHboYCFHH6Q4nIwgjXM53Kn99iNdvXVyPzCAbXFdtf/Ida4SZHIO9q
         V6sx6DKWu4vJXjJ2HGnOOS0e+5lhf5g5cqIqu9Yf5MFVfEazPCMI/RebQN36sarzEmXT
         KwxMJw+PV/zFs+Yboetv9hM21t8hkTvBfBkv9QOoNsMEtmqjI4n6Vof6d6WIuuVsZQqc
         aWvb9X+qyu3xxnIrYWAN3+ASjk90LALEC3PE4yzBcxLEgVO/6jNi9DmwRQBaaepZGiJB
         sUuqY3nqNgFjGBtkaFHlinwhqS9mUxes9zV86FOMZDzlFK0RhVtcQKeHpAGlpVd1olHa
         jZBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id w6si385657ybt.0.2021.12.11.12.23.44
        for <kasan-dev@googlegroups.com>;
        Sat, 11 Dec 2021 12:23:45 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 1BBKKThb015069;
	Sat, 11 Dec 2021 14:20:29 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 1BBKKRTs015068;
	Sat, 11 Dec 2021 14:20:27 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Sat, 11 Dec 2021 14:20:26 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: David Laight <David.Laight@ACULAB.COM>
Cc: "'Jann Horn'" <jannh@google.com>, Marco Elver <elver@google.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Alexander Potapenko <glider@google.com>,
        Kees Cook <keescook@chromium.org>,
        Thomas Gleixner <tglx@linutronix.de>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Elena Reshetova <elena.reshetova@intel.com>,
        Mark Rutland <mark.rutland@arm.com>,
        Peter Collingbourne <pcc@google.com>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "llvm@lists.linux.dev" <llvm@lists.linux.dev>,
        "linux-toolchains@vger.kernel.org" <linux-toolchains@vger.kernel.org>
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <20211211202026.GB614@gate.crashing.org>
References: <YbHTKUjEejZCLyhX@elver.google.com> <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com> <d35ca52c81e7408ba94210c6dbc30368@AcuMS.aculab.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d35ca52c81e7408ba94210c6dbc30368@AcuMS.aculab.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Sat, Dec 11, 2021 at 05:01:07PM +0000, David Laight wrote:
> From: Jann Horn
> > void bar(char *p);
> > void foo() {
> >   char arr[512];
> >   bar(arr);
> > }

> >         call    memset@PLT

> There is plenty of userspace code that allocates large arrays on stack
> (I bet some get into MB sizes) that are correctly bound-checked but
> the expense of initialising them will be horrid.

Yes, you need ulimit -s much more often now than when the default limit
was introduced (in 1995 apparently); back then it was comparable to main
memory size, now it is a fraction of a thousandth of it.  But because of
the same you do not need to increase the stack size for pretty much
anything in distros now :-)

> So you end up with horrid, complex, more likely to be buggy, code
> that tries to allocate things that are 'just big enough' rather
> than just a sanity check on a large buffer.

Yes.  The only problem is this will touch memory that is cold in cache
still (because the stack grows down and arrays are addressed in the
positive direction).  This is a pretty minimal effect of course.

> Typical examples are char path[MAXPATH].
> You know the path will almost certainly be < 100 bytes.
> MAXPATH is overkill - but can be tested for.
> But you don't want path[] initialised.
> So you cane to pick a shorter length - and then it all goes 'TITSUP'
> when the actual path is a bit longer than you allowed for.

If you do this, you probably want to warn for any non-tail functions
that have such a stack allocation, because over-allocating there is
pretty bad.  Or maybe you want to warn whenever you omit the
initialisation even :-)


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211211202026.GB614%40gate.crashing.org.
