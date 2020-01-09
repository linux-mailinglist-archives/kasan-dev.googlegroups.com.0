Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55Z3XYAKGQEVB3ZCXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0458135EDA
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 18:03:53 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id g20sf3968562pgb.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 09:03:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578589432; cv=pass;
        d=google.com; s=arc-20160816;
        b=WiFSA/J0ig3DieEGfxeLMEdCMz9/IwC6tfanYk3TAeiM50J9K5u8Dnv5lkGjZZBrSn
         n0/CDfkqYEC0MeshQzSdUh+eKToXLwRjAGa62g3rZWZ9Rfo7qRr/xwkFjFLtCx/q6j1m
         zTHsDBbBfNOEAJPZhJkw9SpJ+Rpz46ZSKNL1P39cCv5bJE2VgPc9509UJlCeLSV7dJXp
         j18Y6mjeW3nG2+sgI3rQAEDs290XwdnL08WNsxaWc+IZVyQaphWqLygPU3AOI3FbxIU9
         TqaPUS1kyzcYB27qgf0GEq7do7W/m3GD1AHrbC5bFa11V7L7qDkOkoD8dwcN1wThvJnB
         V9Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1hG1zqts3Ms8I281yYck9ABf5bePp5jZaH5TOwU7gAU=;
        b=SM8FfDAcTK9hyly+edMJ3D9QSIaQ+7bZfCAYuRNe4J4vda56eN6KK+nhxNSJef3Iuu
         rRgUd3KUWtKc/KSp7XbwWT5HoszTvzm1Zzbx5dYGxym1Bmzjy7lgBaxs8JgO1HXA8fWC
         KX3E6HHmsW7i6iFOV5gpTAOjVeDs72+RCiBY8VvZ7yMaUnPsJd9dFRp7Qhvau8ixmHaa
         v2zcXnBKikxHdNEDJfEvFES1sBP8rQ/1PKRZN3ZoWbWPsr+bNzsM40e98z3RIc2oQHOu
         zxVw0Cq+h2BHHBSg0af7MZiJKMRer27drm1v5RlKal79G7RreS/z3oYA4bZKfAFpyCkW
         a9DQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZJ6DV7q4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1hG1zqts3Ms8I281yYck9ABf5bePp5jZaH5TOwU7gAU=;
        b=jemm8v7Mq0U3PpcQihVBwkYS84o2TF8r562D5LFeOh4d3NgHobp95bARCNyUjLExRD
         uWJk7e6qtY9c3Fd4Nt+iClppqUoMuHxksV6RqwZ0rmiAiOff9nvr8fdjsVjqWbF0bMh0
         38i6+Gew1rol9p/FZhToaQRhTCBHPBYA0OabvorSOKEBpAzk7+X/MZY8dg8yauSvYR/M
         R4N4SFD8oMZYP//bqSo0UiXgXnLmKGL4kH6ol25q1nFpreGKE33bzkgfLBICfn3xGn+J
         T8AYceJF44VQPZme/+I1W1tzGmy2aOCXMbkS8g0CaHTkR8ndbdtQguxJ7jF1R2zsR+kA
         voog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1hG1zqts3Ms8I281yYck9ABf5bePp5jZaH5TOwU7gAU=;
        b=lGEGjk4iTZNEKIwv6RJY2Oo+YA5jD/j82poDiWcOnF8MHBdLPHGuLP4v+sEiAKWZdj
         YqJsFuiTmHcfNkXqOeZ4S9zPJSk/WKAxSrONvns95YgBJTPxlHQ+prgdD8xqXWCdZSpr
         PiOAmeRWVmzl0RzZx5rTdVjYGs79mQwvPahd3RS5Sv9niuU4yyU9YHFvcH20ccAdNYYC
         G4988iPTRz8aX2T2wp8+V24d+iH1W00AYi5Y5L67p/287iGfxgQYvZRZnh5lS9rXFCbN
         c9MSx1TOWGzUHeeSZA5yRODDoRkHOoLDTSd9jEZmrZeuxzTR1QZbc8ZSlvQautz8cL/y
         W+iQ==
X-Gm-Message-State: APjAAAUx83YxcmqBD7sYYIYwWBDjMBeFXKX4qjul3AC/CYucGP4Pcrda
	rpymDwn9A4ofQvJ0OiprtQE=
X-Google-Smtp-Source: APXvYqwXmFiWhglLEY7Y5o8RTSU24GwkW1kGEA5nI58Dx3KOjDgKWMy0NIHBYzvZ9MF4otMfc40RnQ==
X-Received: by 2002:a17:902:ff12:: with SMTP id f18mr1178629plj.256.1578589432079;
        Thu, 09 Jan 2020 09:03:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2703:: with SMTP id n3ls725095pgn.5.gmail; Thu, 09 Jan
 2020 09:03:51 -0800 (PST)
X-Received: by 2002:aa7:80c5:: with SMTP id a5mr12380872pfn.53.1578589431548;
        Thu, 09 Jan 2020 09:03:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578589431; cv=none;
        d=google.com; s=arc-20160816;
        b=JGkGjbldWyjLk5Ax3tPVBe7WoRGeYmHB1xk7+yLG3NzbSqLDsPKxbBGHIk1Qy5JNiO
         I1OTBIgD3qqrXtqlXeOWm7BBwMPndJ9FNqMzXDl5XDi/SCW0dO3PlCsRREVfcwl+jEAr
         AGiaR205jyhHKSeAvMvN0/QlcG+YD/2AIMKngeMzM7wYeKYB+pYfCI6lsaOeXIBgnmth
         ZnfmznLERzrIxv/BRflSaFrZgSIttDRRKzek/QuMxTfo8kUjYcSXJbow+Eu7bMLFji63
         M+KqoxG8hywixbDmkKpK92bJEorZ3LEnN4A7tZQTTcH+JBm/N5fqLq1h5pzLEqBUWO44
         hCnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bMx6vW+NjpB+ZzfdSbqjjcW3Neq3wFHEeHMe7FuFhBA=;
        b=r+lFru6P6J4L4rPoqDJqayEc7YNkHwaYzVagXBEO7X225tYPyo+1Rc1hG1vvXFH5xW
         l93Z67UlmYFr4YgPjYWFpSCHA9u82g6AIMTqxle2FnGz4TJvTK36VzGlSH5TvL2tP/J5
         /Z0EiIStNGxuU+IO9AvpKR64usGGqdJHCAMLJIwHpUmBxwANe2FZXYZuHQwmNmWpudff
         SYEiFl7xv1u4PqFmlU/a3B+OaIN4YvvrQ3PEw07SIHjvHv42qcvWlG3uj8xXElx95zE9
         v1+ko7dkJp3j6Ys419zVSDNlbd2SWEKMkqGDq8SDBVd4KHTN77tzZdJ1io3RWr9vJt4d
         /u7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZJ6DV7q4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id d12si107698pjv.0.2020.01.09.09.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 09:03:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a67so6478032oib.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 09:03:51 -0800 (PST)
X-Received: by 2002:aca:d4c1:: with SMTP id l184mr4065405oig.172.1578589430440;
 Thu, 09 Jan 2020 09:03:50 -0800 (PST)
MIME-Version: 1.0
References: <20200109152322.104466-1-elver@google.com> <20200109162739.GS13449@paulmck-ThinkPad-P72>
In-Reply-To: <20200109162739.GS13449@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 18:03:39 +0100
Message-ID: <CANpmjNOR4oT+yuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg@mail.gmail.com>
Subject: Re: [PATCH -rcu 0/2] kcsan: Improvements to reporting
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZJ6DV7q4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 9 Jan 2020 at 17:27, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Jan 09, 2020 at 04:23:20PM +0100, Marco Elver wrote:
> > Improvements to KCSAN data race reporting:
> > 1. Show if access is marked (*_ONCE, atomic, etc.).
> > 2. Rate limit reporting to avoid spamming console.
> >
> > Marco Elver (2):
> >   kcsan: Show full access type in report
> >   kcsan: Rate-limit reporting per data races
>
> Queued and pushed, thank you!  I edited the commit logs a bit, so could
> you please check to make sure that I didn't mess anything up?

Looks good to me, thank you.

> At some point, boot-time-allocated per-CPU arrays might be needed to
> avoid contention on large systems, but one step at a time.  ;-)

I certainly hope the rate of fixing/avoiding data races will not be
eclipsed by the rate at which new ones are introduced. :-)

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> >  kernel/kcsan/core.c   |  15 +++--
> >  kernel/kcsan/kcsan.h  |   2 +-
> >  kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
> >  lib/Kconfig.kcsan     |  10 +++
> >  4 files changed, 148 insertions(+), 32 deletions(-)
> >
> > --
> > 2.25.0.rc1.283.g88dfdc4193-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109162739.GS13449%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOR4oT%2ByuGsjajMjWduKjQOGg9Ybd97L2jwY2ZJN8hgqg%40mail.gmail.com.
