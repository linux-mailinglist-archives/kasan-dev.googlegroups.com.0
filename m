Return-Path: <kasan-dev+bncBCMIZB7QWENRBHGBRDZQKGQEZA7AZWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D52F17B9D4
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 11:06:22 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id i127sf1139907pfb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 02:06:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583489180; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjUPDK1rieVFmCVYWhUmTUYlYQ/1gMFHRK0ia6+lN+u8YUFFpbL4S8eY4j7TLUFpDL
         CoVxdLCJThhDNLmZCfI04jK++23Ca3r2nDpACQG7Tozo9Gx747r+zqdf6fg+Oc9i0D70
         GoMaGkIalXywbqFCGk8MwvNf0HLqkQSoRokw29iddgTjjJKctxGpP6sdd+iu7ohEPU62
         trZywPeJxt1k/SWF5jRMarsZkK+DFRqHStAd3z2Uaz3z4FjeHiy450RaEGWaEgcjZqkn
         pHjxUOBGs0iMHFTTHGpoUfMX+Dr18kKJYC2J/Zdge/nClBWKDC0RrRex+Kc1ywopjXeA
         n0RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E7ERG3NUR6Uhz0hZhm2muOV5TQRkjOUsUe7Zrl94hnw=;
        b=x0Iq80IAUl9zniRRr15eP+agJxOLTpH5Pkn+ZFMJb28Bi4GiFNnI04Eb2OE+s5RHgt
         UDrUhfvlf7wp8u5v0lrhqgLKMd3hxa7b+7E41sNvKw1YLwbw5MF3XbQNm2RrMqClDyvK
         lAORi4aA2G2ClY/y7VyGJe0zhFeOqyMIj2Cf9bbCmMLQgJderiobT0k8mlbFFPtSYR6j
         dlXvqbaHjOp0vi79TODcx63CzYDJ0Q1M/uKTlVKkn+wzuADvLgzS/KZAfUgt1cJxfqk5
         x+rB0dnaLYmMO5WMY6AwsUqcQo2N/SUaRFYxDKpYwHQQ5gcrFlZOsC7w3CyjvmF4CLVr
         0lIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ghUQE/kI";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7ERG3NUR6Uhz0hZhm2muOV5TQRkjOUsUe7Zrl94hnw=;
        b=Z9yCSx27YIHdGoZdZXLmczSAN7KOmtcFtQLVDuhJpf0NTcxTM5CIOd9Xgm4264oTFt
         Dh3G1aUTGFqZfUdgcoL3nubbLJ/FdT54CYkuI+fUTQ6UtkFY/uVeDZF6fN42ar54DBlM
         //Xp2wqgxM7QTjOw9h9Sk9uSsi7+R73L+Vv3wZR+oulrsA+fKRuXtTGfxwV62Yi/EOlI
         X7QqeyPEHGO+X+KEPPu00+wxLeywNAVflDEMJ7nWSD/pdSiCi0wolWD7q6GVXB6gOrpV
         P8NlPsbcwUNSL9ehLKO8MxASWx0GuVDZ47pTaeRqG7+ON8HU/5XV8HWJYlhrRh/bYay+
         A1oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E7ERG3NUR6Uhz0hZhm2muOV5TQRkjOUsUe7Zrl94hnw=;
        b=A3eO6UIM2NPhzBKvHmUMHoun4RU/oJYJPvhWq4FdUsQEC9vJtE6J2aQHNiPjpp2IT/
         1dUEP1wWAeCjTADQAjIeTQTa4m4Fap1RRPxbaBRdLf7oKR5vJ962UQgAA7fv3KX66ZZV
         SxmUcK/6Tl/rACi/UOrodLfI+m64kjN2X+MHeBkM7sQtqRoOT5rjfJdhIDtWUuGfxggM
         StPRpwySy2TnGbVW0WZ9xr+TZd4d/fkUP/M5NeSSi4pl8nvfjb9QdZo8Kt25IGVL/d25
         U3DHn1i27B9/Da9dBQTAoY2VgUkTdDeLEzHNNpoYaUK3TxYmUZGSDn0a9DYNsJ6WLCvO
         rXjg==
X-Gm-Message-State: ANhLgQ2q4Be/rjDjfNSIsoqFl3NY++swT0zbjsZ2bUxkCh8ymmWDjYH3
	d7heVOez/GsGpcYHpcKxhTQ=
X-Google-Smtp-Source: ADFU+vsz0d25ek7N5dh6GncB+dwj2LzggNvA0Mv3N/GmBsUSNOTHgaYTzw8aMhZpOMZt2CllxZwg1A==
X-Received: by 2002:a63:4502:: with SMTP id s2mr2582517pga.391.1583489180836;
        Fri, 06 Mar 2020 02:06:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b415:: with SMTP id x21ls828267plr.0.gmail; Fri, 06
 Mar 2020 02:06:20 -0800 (PST)
X-Received: by 2002:a17:902:7b8d:: with SMTP id w13mr2384393pll.78.1583489180319;
        Fri, 06 Mar 2020 02:06:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583489180; cv=none;
        d=google.com; s=arc-20160816;
        b=lBBYZVsx01rVVK52JKFxQnZiR0e17h9TCAvCmZo/XpPJY5enuXPNaf4mE3bSCRITYo
         4aepSycQtroI196QUAH4YzBctFxrs4k8l+zi+PhXHm5l5NU3VkPlGeCn8C739dRA134j
         ig7S8o7TyqJrl6lInV09ye8b1ocjebiUhg10ku+T1Ym62DUU7FVzVRwsD3Zx/ZxC5WOU
         jHLxAOI0EeC+kgxAX/va6OpIdZpXlLfjk4bQ2NIlpfzWUk+6KqU4UZEXZb3VEafIhIjM
         zGfABvD+NBzpXXsaTDrx0xEaMptNOZAufGLRQSOI7qL+Mi+/5GoIm7MItqLe7t/iWcPj
         Garw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1TPmJcv3nSQpoNiFGvvOWqOkqIas2fqVCp+FPrWfKZg=;
        b=CiExbEuYpnvN1zztcbdRTo4fTJIqxKC3JmFYsaZjQV+h9B9o87NVb1ETL3CIsZqO/x
         FBt4XeZzweDf7EyO8QJnMy2N/psrTgGjlxbb6/v7kKAKmJNOwZCaCb4vBdCyYDPDwJfD
         Fo8f6XUl+BgZLKt3D2XXy0wbLaoZIrWyjNg3HkSWay8H3Q1is9V6J3ThycZ5PZMjTqoi
         eOBqkOg+BX7l9SvwwC9hasCcagylWOZuP0BjmHwusuwg2G15AuCtXjtqM0tcaFxiFnid
         YBm3WDlit2ifykRQ0JPqOj+2WgbLPdeI+GIpCoxZrtf2Z65VjvNUjXnOrVCPa0HmhBuF
         AlKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ghUQE/kI";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id c13si98358pfi.3.2020.03.06.02.06.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 02:06:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id d22so1323735qtn.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 02:06:20 -0800 (PST)
X-Received: by 2002:ac8:3778:: with SMTP id p53mr2147174qtb.158.1583489179154;
 Fri, 06 Mar 2020 02:06:19 -0800 (PST)
MIME-Version: 1.0
References: <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net> <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
 <20200305184727.GA3348@worktop.programming.kicks-ass.net> <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
 <20200305202854.GD3348@worktop.programming.kicks-ass.net> <CACT4Y+Z=qy9MjhqOMNr2kYLwHy=gRXo0yqHBWBZpX2foRJBpMA@mail.gmail.com>
 <20200306095127.GE3348@worktop.programming.kicks-ass.net>
In-Reply-To: <20200306095127.GE3348@worktop.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Mar 2020 11:06:07 +0100
Message-ID: <CACT4Y+a_yu3u2ce=NgOqgOfNAPiZbUb0JzZauW7snm7ZCmDedw@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ghUQE/kI";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, Mar 6, 2020 at 10:51 AM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Mar 06, 2020 at 06:34:49AM +0100, Dmitry Vyukov wrote:
>
> > Say, consider, poke_int3_handler
> > gets inlines in LTO build, and compiler says: you know what, I am just
> > going to silently ignore your no_sanitize attribute to give you fun of
> > re-debugging the issue you think you fixed ;)
>
> *groan*, can't LTO still mess things up when combining translation units
> build with different sanitize flags?

It shouldn't. Why? It can preserve and respect the attributes/flags.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba_yu3u2ce%3DNgOqgOfNAPiZbUb0JzZauW7snm7ZCmDedw%40mail.gmail.com.
