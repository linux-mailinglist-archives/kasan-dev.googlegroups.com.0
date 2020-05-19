Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBWEWSH3AKGQENHU6IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BC0501DA338
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 23:10:48 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id x11sf136312wmc.9
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 14:10:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589922648; cv=pass;
        d=google.com; s=arc-20160816;
        b=OySDAC3wjFn60wg8gY4r2tS63CxdtmXQtLeNQ3AbmAhZzbHPBT/8zTLknSZcrO8OZ5
         QgREv8a8wwLXIH5DtVRBg0JkTBE0e1yTKLeJKfjCmySiS3b8G/qkzXoi/TKgJ+WJT+UP
         tfc+Rj0r/I5Sk69OpFkBywrnl2IhGK1CGy99ZMzxD3RwGgcZM4mvud64KOJQHNBqbmln
         0GQIrARjSE7wZww/D17xHCps/2iFKWuMc0eV5KYAtE1q/oMlRIdJLaxKHtWjOfLbgjsO
         Y1a2NTad9zqcV4FZSU4P/FuVLtPWRUqhHkU9ayYID+jEu4sn6dsumYUkcSFnCh5FE9PC
         rjBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=whpjDcNXB3oZisuM/qQwYruXR1fYxROskEWECsju4ro=;
        b=wgSi3TJ1smVM/jrUkSIs9CPXAik2+7fIuFCPPPVbiauKaka8eWLCOllbSLRN0R/koi
         XqI+dq6sQf+5LM+hVWLWdLBN++E7MquXfpr6TNcTXNvHJIUMTENzsFhnmAMr13LPoIg/
         0+JxV++BTwzELdIlAuHwRz+DMBoVjgMW+Yy6ZP8xWk/RoWC8oBN2bgEJyxyokJ6meMU5
         RRlTXJW4fH1DDbMaCwkOhhaytGQV4ozg+KkMv5TcIajdBaiUoyjPWjqZMS5if03qWpM0
         NpSG71mxUE7OTlZVIo/4wlW/iRUSs5XM6m2rqpvuWYq8Ipb2v+LKCMHZ1DBjWK0hiqZr
         N+HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ljbBHdns;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whpjDcNXB3oZisuM/qQwYruXR1fYxROskEWECsju4ro=;
        b=LMsPiE1CBaT5yr0Y+rlJZwjXKU/cIFYg2G0E/7QKyG5noE/OZSaXQuWWMK9TzE1D2X
         SbwsIZD2HP5MdudLnMFo51IF14ISn5KubTS7VtKBzRSdfL/+aHwJbUCVD2TMe5CTAmqx
         kjvw4P9KQ5i6pjHO+n0ouDHHqJLHF1MQpsYbY5uztqGhdfxeGJ6JWwm229UELsh+umhK
         WxHnFN4/TqECEaM9GcV0wMz3RfrW5rJK+jQP8Lso5mzAKFzV8zkoqqNmz+m3NmGk+Tzx
         VWqg/BeiQ3CCFvZkGUmZ0LgGGGjPu+cAPaWwdtLQ1FHofsMXnKRfXefxhAgjekDJbCpZ
         Nu+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=whpjDcNXB3oZisuM/qQwYruXR1fYxROskEWECsju4ro=;
        b=PzC4oUPIYO7jNBR+OP3w/lb+3kHUj21qvLqNad1lsWUA2xyJF8VtTp4iq2sVzOTQum
         rT9DxdutMGrBOUplZ6fAvq1GdqdJVMmj+7Yo0aV+KdQe6hAS+iaY6g2mTylUGFdRbmFw
         yUUhpDQh0VINqc5G8Iw45PxL830NUn2pTiuMUxTuOOELSeyi5Mt/o6nORhpKTzILDNb9
         9Ximwtbyw+BVg/AQdpP3W2RC50T4Rw5Xl2KrDCjEKZmLYNo6GIQRByrD/iMYTNvEfslr
         rx4FL6Iu/DzGl56ObjAg0Nl3na/cmD3t9LVudrXLvmExwStEl1dDQ2rmoRrXa+dIFUHB
         8K3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BgQ1LOfzBuXMsgl9elbFrmdLqHDCRfy6oWmne1FuwUuMl8fGy
	dBtYILzQ6Ld5T7N0eIPmnFY=
X-Google-Smtp-Source: ABdhPJxPwQ4XApi1hbcXbTQP7whufsLNncWpWu5Ns6cN0hnE9ifCObsJf+jFztj2X7gieQZE1uMO+g==
X-Received: by 2002:adf:ed82:: with SMTP id c2mr832925wro.255.1589922648496;
        Tue, 19 May 2020 14:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a544:: with SMTP id o65ls381543wme.2.canary-gmail; Tue,
 19 May 2020 14:10:48 -0700 (PDT)
X-Received: by 2002:a05:600c:231a:: with SMTP id 26mr1363574wmo.59.1589922647961;
        Tue, 19 May 2020 14:10:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589922647; cv=none;
        d=google.com; s=arc-20160816;
        b=fVAvV/Oopbs3hAU/LUogPBq96dk0SmzZ8uP/AZnMXdTz1N/leokJDCMC7IY88tAydZ
         epgS9Mw+Pd9IGi0bvEjjAjdFRPyZ/8Hjy1N6aP0OXV64UPuWYEKYshszQJjkgk8HB+OA
         BMispXT4fV4lpmEJkBza6MMzJLyPykdfQp4B4C4qrIQdUdjLHjrPPlxX92Fu8pFLCyYs
         t9aMMTfv34S0MVDuy3XRPPNnROI7ItHTuTadLwbduYSd8Nq2T/8KigXxrkizIhAYu50+
         G6+X8cpr8fpn7aNHCZH/i+yCtk7lk7JjGkdM6pa4tkh/fYkiGiSlILDWw05yEJyrNvye
         R1HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AbC5vCRnUHjH33LjSKWOgN9hGAne5JahHYoJjapwL0Q=;
        b=YPemU4tlWmM+AIf7haWU4RQt3Hz34SvmwsGYHJrJMxo8enulho/AbWywDNiqwOfbSO
         2gsWsKvTJhDnrfj84u/pKnQez38pOu2y3G0iSy3ziE/mvDpKC6CsHKh9G+Vw4J5XJK/5
         tv1XFx6iyZqYF9EchdeuJhkeRuiK56mlX3dX6af7O11U6+XVR2XFoyf4p8kAkdWT0b5N
         8302ATPcA30xbnHi4VZKRjh8FiDkPd4GEKQ0T4isZAz7tWD95EVXDBhYL1q0FmxywAFr
         u6y8mmc2WA/DtY8/u5kBeyK1h4TyyUgk2vQROhuwEzaPNyaB8lrn4TfrBay5HYSC+WDd
         7p8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ljbBHdns;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-ej1-x644.google.com (mail-ej1-x644.google.com. [2a00:1450:4864:20::644])
        by gmr-mx.google.com with ESMTPS id q16si59188wrc.0.2020.05.19.14.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 14:10:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::644 as permitted sender) client-ip=2a00:1450:4864:20::644;
Received: by mail-ej1-x644.google.com with SMTP id j21so704106ejy.1
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 14:10:47 -0700 (PDT)
X-Received: by 2002:a17:906:f198:: with SMTP id gs24mr977304ejb.547.1589922647505;
 Tue, 19 May 2020 14:10:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200512183839.2373-1-elver@google.com> <20200512190910.GM2957@hirez.programming.kicks-ass.net>
In-Reply-To: <20200512190910.GM2957@hirez.programming.kicks-ass.net>
From: Qian Cai <cai@lca.pw>
Date: Tue, 19 May 2020 17:10:36 -0400
Message-ID: <CAG=TAF5S+n_W4KM9F8QuCisyV+s6_QA_gO70y6ckt=V7SS2BXw@mail.gmail.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ljbBHdns;       spf=pass
 (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::644 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Tue, May 12, 2020 at 3:09 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, May 12, 2020 at 08:38:39PM +0200, Marco Elver wrote:
> > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > index 741c93c62ecf..e902ca5de811 100644
> > --- a/include/linux/compiler.h
> > +++ b/include/linux/compiler.h
> > @@ -224,13 +224,16 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> >   * atomicity or dependency ordering guarantees. Note that this may result
> >   * in tears!
> >   */
> > -#define __READ_ONCE(x)       (*(const volatile __unqual_scalar_typeof(x) *)&(x))
> > +#define __READ_ONCE(x)                                                       \
> > +({                                                                   \
> > +     kcsan_check_atomic_read(&(x), sizeof(x));                       \
> > +     data_race((*(const volatile __unqual_scalar_typeof(x) *)&(x))); \
> > +})
>
> NAK
>
> This will actively insert instrumentation into __READ_ONCE() and I need
> it to not have any.

Any way to move this forward? Due to linux-next commit 6bcc8f459fe7
(locking/atomics: Flip fallbacks and instrumentation), it triggers a
lots of KCSAN warnings due to atomic ops are no longer marked. For
example,

[  197.318288][ T1041] write to 0xffff9302764ccc78 of 8 bytes by task
1048 on cpu 47:
[  197.353119][ T1041]  down_read_trylock+0x9e/0x1e0
atomic_long_set(&sem->owner, val);
__rwsem_set_reader_owned at kernel/locking/rwsem.c:205
(inlined by) rwsem_set_reader_owned at kernel/locking/rwsem.c:213
(inlined by) __down_read_trylock at kernel/locking/rwsem.c:1373
(inlined by) down_read_trylock at kernel/locking/rwsem.c:1517
[  197.374641][ T1041]  page_lock_anon_vma_read+0x19d/0x3c0
[  197.398894][ T1041]  rmap_walk_anon+0x30e/0x620

[  197.924695][ T1041] read to 0xffff9302764ccc78 of 8 bytes by task
1041 on cpu 43:
[  197.959501][ T1041]  up_read+0xb8/0x41a
arch_atomic64_read at arch/x86/include/asm/atomic64_64.h:22
(inlined by) atomic64_read at include/asm-generic/atomic-instrumented.h:838
(inlined by) atomic_long_read at include/asm-generic/atomic-long.h:29
(inlined by) rwsem_clear_reader_owned at kernel/locking/rwsem.c:242
(inlined by) __up_read at kernel/locking/rwsem.c:1433
(inlined by) up_read at kernel/locking/rwsem.c:1574
[  197.977728][ T1041]  rmap_walk_anon+0x2f2/0x620
[  197.999055][ T1041]  rmap_walk+0xb5/0xe0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG%3DTAF5S%2Bn_W4KM9F8QuCisyV%2Bs6_QA_gO70y6ckt%3DV7SS2BXw%40mail.gmail.com.
