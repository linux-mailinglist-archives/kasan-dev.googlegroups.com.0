Return-Path: <kasan-dev+bncBDGIV3UHVAGBBM5DZ2EAMGQEJITWJOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE633E8CB3
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 11:00:36 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id cm18-20020a0564020c92b02903bc7f21d540sf882216edb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 02:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628672436; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9K9USsqMAMr4et03Kbem21NWXWmhMEJe9l1yzlLfAIXZIEzLhd/BHCrkzXUZ4RqXD
         8sp9skG9CLMt1mtOhRQRKwCjluaCrkEUs9VG6mPWz9OvIFteJXHpOjGjRBbVGSf1mexx
         4Ku5ruhuS0xIGl0M9t08fqNaQ4v/tVf5BXdN1iBOsaFZXqs86qDZv6ThEw79i4oGHLQD
         R3f9gtPcwPJsTF2U812yGND4+TbL1obi05darA558bFn1gld+9lkeO5TSOdppk862t7x
         AxB96I2PRgIOoqUnLCxg/1z+btCT13CrUetBqQtfySUD2YjFwt3wRYZtJkj9+16FioeJ
         Vx0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pj6i/agmehoK2tN4PU++kCPBH9CDfDR08SJkwsgEw/c=;
        b=vXjA9MvD7rBehdl9r2XF4zQSJ5CzrfMd82YDHdq2Uvv2eG7UnYFB0PPmD26sp1W9f/
         +pz6ha+Qnq3M5ZkTGXbPnUQDSfhP8nI0j7r2Gm5IWIQVxxa/BKFBlelN271NW3QHKrIo
         LB2sQUGO/5ci9jM0D34PNyu++O4xLGwwz0xwW1K/wj9tMPlzPhIVf4ukLd9FvsEYg9+X
         O6VLuoXNNlD6rBDT4lbaGaBOMvGa6ap3HFX/z4juLDkt0sdCEej5iwWTtGjh2A4SPVOq
         HsYS/d0f2onaw106FaY7l6V2/mHaMuM0//eKx5rvH3ZwddLrHs7suFKOkFi75/NGwjvT
         cO1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=u6BMEXBN;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=ZIrd3wXt;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pj6i/agmehoK2tN4PU++kCPBH9CDfDR08SJkwsgEw/c=;
        b=MuUHKKKXE8vFhj3rAdRnZuV04kFx60As7u4FuDDHiqT3ZcvGenShrb9ISjklcQsNn9
         ylAzRbv1crlXy3AfduEIp5oTyWAbdTYSUsjrKv35iD4XUyj+tMwIlFCeReoCRK+KSNDK
         VZYnea3W3o/okNlVhTy5XDtIGHdrSBkKRXAlEldY6XR1uBRssiz4M0VbOKZ/oY4wvQRs
         AffY/Q39niuzepc4EGHam3TQa6m9CILgLo6BZbDEcVppEWz2SNs9+2YC/sisRmir7XOI
         i56Tu5YXttxlke/RE7EFn4FP/LyqTYhe0fsWzRN5eRz+5Wr5NUwkAaimVR5GgyC3ODAT
         O3VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pj6i/agmehoK2tN4PU++kCPBH9CDfDR08SJkwsgEw/c=;
        b=KI2JBLnrNs4MIL/JWbUWZbjg9pBTwEfZ653KxzWvHDiEdO4TMcGEPz8Q//MwF4/g6q
         fCM7fYxE45Wibjc5NDVw2BL7Sk3+UEzcVvWFj3/qHHhTWC4VUsPv0mBVyGCsJ/+Hp9Ej
         9cu1+OpdHAa8EjKXNWZ2k+Xg4lqU0ufO2/1YYp7gBLzgqzaEqZwIyHQniZeninXZtEzx
         ioAiqeXQQwokc3Ct8IdlW9drfVnl6XjP2hXpuMK+QxoLSANJTTYYx29nghaDc+CB3a39
         z6tK1Danwn6KF5ihevDC0LkGL5Q3R3b06XxHOYV7kdbOCK8KHgA8DbHFwDFdJ6fnqLzU
         M/wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uOJDxJdLMzcVzkbGSJTpQhAUH96QqXtD8UOeWy/34Kdu5ctWr
	8uBS/Ix8BdINzQH1CLG1Sh8=
X-Google-Smtp-Source: ABdhPJxD5bqyUQ3sWkmUuSWxb7yDe5OwsGPXSrA0vfuU1h/9rsXa6SqLfnmNE0IpgT9RcVTCT8pDfg==
X-Received: by 2002:a17:907:9602:: with SMTP id gb2mr2664690ejc.354.1628672435929;
        Wed, 11 Aug 2021 02:00:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:d96b:: with SMTP id rp11ls716985ejb.0.gmail; Wed, 11
 Aug 2021 02:00:35 -0700 (PDT)
X-Received: by 2002:a17:906:1f8b:: with SMTP id t11mr2632244ejr.131.1628672435067;
        Wed, 11 Aug 2021 02:00:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628672435; cv=none;
        d=google.com; s=arc-20160816;
        b=KMemap0hhsVR79Ba6Uo4hVW8FJf2KTK7zpVhx+AEpwW9kPSQyma6tkmPLPezODWfgD
         chU4o0CtszC0PryopyG25NXXCnX18+HdGJJB3kMM77gHK+m3hAPgfhsdA6xME5I5Sua+
         bjxknnAywhkpMT/GnMcUYGa7K4UiD2u9ithz8o3j362xLhxeOVJnRqGYm6JY+uSczkE6
         4GtCa7xBAoIt9y7QpgC+xFgig3vlCMzHu+tSsBeRb7BdrEb+NZ7N8BnRa9+WeQ5sB3Nn
         2bAHxsOrEa9P9es55qDqetxfa2y93rsmUPj7KI9pkr/dFRiAV4+P9hbQ37OZdpbYFWbN
         qMmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=6NUQ3TyOknPB3iraV2OgTTMR9Er1TbuGJXWQNUYkDqU=;
        b=TnsUSgYNB4pTyGZaMPCMM5OOoYQbWzVqqyaOMlt2d3tyrA2RiMfUmNz4wTwZ/ngS2n
         EYtTTHGo//6nX1BNEwkZnNT3ieD+fTagrs5VBp4hpZCBF9Qr7RYTFn23GQ2oUJ4FKjJi
         in78KZ8awnjCo/J5t9uzQqTpsub9POdTYnpj+uClg9GC7kUDYEjeTSjd+GznvzHz00SM
         1iQSZuAatNoPM+vKGcpUOIV1dECK/1BFUm643IqCbRG11e73oD4VUAOtZCwX7xImB75T
         Vs6xg+rBaX2XhcIHm75s+aMRFY0OJMJmYzMAQvWLoqj+dRC6GPmzhuqHi1f2vur34n28
         1qnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=u6BMEXBN;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=ZIrd3wXt;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id s18si1147578ejo.1.2021.08.11.02.00.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Aug 2021 02:00:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Wed, 11 Aug 2021 11:00:33 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Clark Williams <williams@redhat.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
Message-ID: <20210811090033.wijh4v37wlnny3ox@linutronix.de>
References: <20210809155909.333073de@theseus.lan>
 <20210810095032.epdhivjifjlmbhp5@linutronix.de>
 <87sfzhox15.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <87sfzhox15.ffs@tglx>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=u6BMEXBN;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=ZIrd3wXt;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2021-08-10 22:38:30 [+0200], Thomas Gleixner wrote:
> On Tue, Aug 10 2021 at 11:50, Sebastian Andrzej Siewior wrote:
> > On 2021-08-09 15:59:09 [-0500], Clark Williams wrote:
> >> Saw the following splat on 5.14-rc4-rt5 with:
> > =E2=80=A6
> >> Change kcov_remote_lock from regular spinlock_t to raw_spinlock_t so t=
hat
> >> we don't get "sleeping function called from invalid context" on PREEMP=
T_RT kernel.
> >
> > I'm not entirely happy with that:
> > - kcov_remote_start() decouples spin_lock_irq() and does local_irq_save=
()
> >   + spin_lock() which shouldn't be done as per
> >       Documentation/locking/locktypes.rst
> >   I would prefer to see the local_irq_save() replaced by
> >   local_lock_irqsave() so we get a context on what is going on.
>=20
> Which does not make it raw unless we create a raw_local_lock.

But why raw? I was thinking about local_lock_irqsave() instead of
local_irq_save() and keeping the spinlock_t.

> > - kcov_remote_reset() has a kfree() with that irq-off lock acquired.
>=20
> That free needs to move out obviously
>=20
> > - kcov_remote_add() has a kmalloc() and is invoked with that irq-off
> >   lock acquired.
>=20
> So does the kmalloc.
>=20
> > - kcov_remote_area_put() uses INIT_LIST_HEAD() for no reason (just
> >   happen to notice).
> >
> > - kcov_remote_stop() does local_irq_save() + spin_lock(&kcov->lock);.
> >   This should also create a splat.
> >
> > - With lock kcov_remote_lock acquired there is a possible
> >   hash_for_each_safe() and list_for_each() iteration. I don't know what
> >   the limits are here but with a raw_spinlock_t it will contribute to
> >   the maximal latency.=20
>=20
> And that matters because? kcov has a massive overhead and with that
> enabled you care as much about latencies as you do when running with
> lockdep enabled.

I wasn't aware of that. However, with that local_irq_save() ->
local_lock_irqsave() swap and that first C code from
Documentation/dev-tools/kcov.rst I don't see any spike in cyclictest's
results. Maybe I'm not using it right=E2=80=A6

> Thanks,
>=20
>         tglx

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210811090033.wijh4v37wlnny3ox%40linutronix.de.
