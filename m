Return-Path: <kasan-dev+bncBC7OBJGL2MHBB66JZ6GQMGQEYYED3DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF30470ED8
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 00:38:36 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id a10-20020a05620a066a00b0046742e40049sf11834277qkh.14
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 15:38:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639179515; cv=pass;
        d=google.com; s=arc-20160816;
        b=nGBf7BBXAoX4eP+A4t7ao1FSKf15rcovdfRPJJJmEnMuSRQ593Ap7bkvNJ+Qn80J5l
         /kyQLPI86630d+jhBNo1A15Db9Q/j5+2PiPD5Yz5q/VgBCJB1/tFp94oRarKS8lFawpw
         d2NlFEJxdtvSNZ3ZgK2srWCadB3Hu7IqKnDgJ0VNrU8x2L6YofVfUoct6ePG7U83tONI
         E5cSLYny3BnQu7OHMIAz7h2R3Ug4X9t8qjqDnLD/wtClTb8PARfQJ6rTaYph/YaAGilF
         OeCd8nQpdR2g3c3VaC/fJKPavG8epqUcZSsvK+oCP2JiAV1m4OuExhagh+faj3sxGiNX
         yhng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qj2HYKs7DgiDeVqFH3Ym6/HVhJXQgr6xaj0KAiXsYw0=;
        b=jdEl73MEc3pENRzavd1L8mpTZJV+vBed1kJ1fGLg3WRlPezPF8VR4j1dKl8z+rkGV9
         amzDiLXOcLY7S3TUSHLH7EkPQuVPPGMgfdk6fpUhV4uI28AIWHz08ozY+7DPBObgdzNV
         b4w8oZatpehYLK+oyP//P0HZAXrPHgFKvOhqZsz9Y9jnTKhsPrlCh+ljvSWeMT09jlZi
         Z6WJm+IFhlyaGo9vkGLtBqW7+tzJecaaCTmqur3BOu5fTzNHciso4XhBRjJ8HoydI51H
         VYyN0KQ4QK+GA59Yr1Zq/llKCTMvFyT9Yci2ns7XILLWKOz1VoXwoHJkM1b6lxMu+unc
         F9KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=heFroTLF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qj2HYKs7DgiDeVqFH3Ym6/HVhJXQgr6xaj0KAiXsYw0=;
        b=EBwy3a/tmGoQ2S52aCCFvQxgVhX6grekB3OpViMjdY7cuGjSU99krx1X6ku6mIdsLa
         cZ4U5CeMyA/Lwqvv/AU1tqVCGlEHmaro40Vwe3l56brSTlY3CQnVLGiXgdhAA/rfhOtW
         5hV11bZn7wzXNOWZo4KdKfsKu8yabeyZ4YFTrEtjbxFa0Q2foAGFXykWwUHr/kmVuvlH
         gFznuC9lK2wRx2CSnk6lB/OR9HmmpPOVYGpi6U6EnzgXaQ133YmCzf9eeKJdjvw/oLXa
         KWDjFwIJbu1z6vGvZ+OYjzJiL2JsjTtIpCs6j7aye2gX8iPfiCJXyYySpzlu/JHNTEA+
         iNag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qj2HYKs7DgiDeVqFH3Ym6/HVhJXQgr6xaj0KAiXsYw0=;
        b=cREz3D2ls5gs4l5n6EXu5+9Y8KYuOlSjXrY2T/P5Z3kE3kReNiufpH6NYKFzLcrbVF
         nna/fsP33qDEYaFVbCXcd/r0BIT/DC782v55eWUezZ5oaebemdyd0+5ZX8BNrt4138zS
         QnAa0DLyUMCs5zzOmku1meASGobSw7AWBoJ14KFdz2Z8kMVXchfydsN8Ersc5B7d7gIo
         jn/CtO38/zeU9xUJRyaxqknec77N14krf0IqFYUe8DWIDU1J/1Fir2/0AZO2RmOaTzC+
         uwpbq6pa/NVLd83/2Xp1wEvRjv8AFCxv8IaZpHOP9b+rBuOibplIAIrkO7Uv2iVjoyBD
         bxBg==
X-Gm-Message-State: AOAM532YAnPILbOWKlwPNO5sTv8YyRvM0TtuHWHAq/6iivuK41SV5jIr
	qDYGHf+zpAmz3CvsZ2xMfH8=
X-Google-Smtp-Source: ABdhPJzL4Z8i07w4ViLbCV/MmHoY7Pr+8fGRYPsmkr3x0Gc6Dm25qe6yn248UAgihxsj1dQn82tPvw==
X-Received: by 2002:a05:6214:509a:: with SMTP id kk26mr29866126qvb.43.1639179515165;
        Fri, 10 Dec 2021 15:38:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f2c1:: with SMTP id c1ls5731404qvm.10.gmail; Fri, 10 Dec
 2021 15:38:34 -0800 (PST)
X-Received: by 2002:ad4:594a:: with SMTP id eo10mr29198163qvb.75.1639179514732;
        Fri, 10 Dec 2021 15:38:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639179514; cv=none;
        d=google.com; s=arc-20160816;
        b=xyhgFF1KEtaQ/jcQb3Wj+ve9/qP26K5gi4vmyn5vRAQkFBPwiHNWWkWf6VpQnisXJA
         D7VI15eky0ofNCotCdNz0JzABkwY7MR/scRwZFJu9k8bUnCrKogD14qRUrLygO4mb5Tz
         q7k38q25NS0t9U3dI3vqHK5WlgkbPNWzBVveBQZtbR0lRx1yDuyrT4HqZnQaiu/qmg4c
         YSqcr4Q3a/BxJYA0oyd/d6FKzbxEvo+HdASub14W7T9UnG7phwyjZB/5+zLQgO0VYrFd
         AJMvkI8hX/YP0kosQVnFc2jyuqRrgaKhh9M3Bp76BQdkvXxqu70jWPZOxp6oGklUB6kN
         ihkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9BvpYczibr3fHvAclIbse6LgViarAvvHO4nOus9478w=;
        b=rxg9wzgr2kKacvb0kCHvHlEin8dx7cZ+fe+ng+uAUdzoevojQCkqEHxGjT0n+YS7d9
         2opZi8C5KsjgwnElyUgGTHQSKCnlwA3PYb9PYZx4QrOFVsGr/suRsYEF5F+FgpJPf37t
         im8T8C3BU3MYEUVVm82vo1yyrEqDAr6zenJJwfexRIRVKVydke+gRZGFrvWVqfh3x+Os
         HswhGkcjSVonT+RWggw4NIGDIPY20pt/r54lY4EE8rl5H1BtJVfZFyOeKnNrXDRcT4BH
         VMa68hGrGXvz3ecuZ6+BS1wxNMIeJkm063II4ERkXdMhcZBQmSBKEWPZe4OyyQ4D7guD
         IsdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=heFroTLF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id d14si278969qkn.4.2021.12.10.15.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Dec 2021 15:38:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id o4so15345759oia.10
        for <kasan-dev@googlegroups.com>; Fri, 10 Dec 2021 15:38:34 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr15416460oie.134.1639179514326;
 Fri, 10 Dec 2021 15:38:34 -0800 (PST)
MIME-Version: 1.0
References: <20211115085630.1756817-1-elver@google.com> <YZJw69RdPES7gHBM@smile.fi.intel.com>
 <CANpmjNMcxQ1YrvsbO-+=5vmW6rwhChjgB20FUMKvHQ9HXNwcAg@mail.gmail.com>
 <YZJ01V8fZBlWz4VW@smile.fi.intel.com> <20211210183520.5cb1c4d4@gandalf.local.home>
In-Reply-To: <20211210183520.5cb1c4d4@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 11 Dec 2021 00:38:22 +0100
Message-ID: <CANpmjNMda2Gu48wOTQAb0pGHK7-EFPngbr-0r2RnJmM7J9mcMw@mail.gmail.com>
Subject: Re: [PATCH] panic: use error_report_end tracepoint on warnings
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Petr Mladek <pmladek@suse.com>, Luis Chamberlain <mcgrof@kernel.org>, Wei Liu <wei.liu@kernel.org>, 
	Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, John Ogness <john.ogness@linutronix.de>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Alexander Popov <alex.popov@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=heFroTLF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Sat, 11 Dec 2021 at 00:35, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Mon, 15 Nov 2021 16:55:17 +0200
> Andy Shevchenko <andriy.shevchenko@linux.intel.com> wrote:
>
> > > > >       ERROR_DETECTOR_KFENCE,
> > > > > -     ERROR_DETECTOR_KASAN
> > > > > +     ERROR_DETECTOR_KASAN,
> > > > > +     ERROR_DETECTOR_WARN
> > > >
> > > > ...which exactly shows my point (given many times somewhere else) why comma
> > > > is good to have when we are not sure the item is a terminator one in the enum
> > > > or array of elements.
> > >
> > > So you want me to add a comma?
> >
> > Yes. And you see exactly why I'm asking for that.
> >
> > > (I'm not participating in bikeshedding here, just tell me what to do.)
> >
> > Done!
>
> Is there going to be another patch set? Or did I miss it?

Andrew was kind enough to fix it up for me. :-)
It's already in -mm:
  https://www.spinics.net/lists/mm-commits/msg161488.html
  https://www.spinics.net/lists/mm-commits/msg161487.html

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMda2Gu48wOTQAb0pGHK7-EFPngbr-0r2RnJmM7J9mcMw%40mail.gmail.com.
