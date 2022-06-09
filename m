Return-Path: <kasan-dev+bncBCMIZB7QWENRBGGKQ6KQMGQESIEDYVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 29EA1544B92
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:18:33 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id be12-20020a05600c1e8c00b0039c506b52a4sf565534wmb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:18:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777112; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ly/tjbRf8c6dI2RO+BonFfRTgqFVnHOpAwIP/HHAlLA7XIJJYWoeO2CR/q6N45HvWG
         Ia0695/8xkJPOENBXeh0I06LTYZ1zrtyGnAIfwwMoNRDa9PoueQT0D0V9LSpiA/L0fs0
         FaRXBpwYx6YNV9EEfPW42xrOHLHzmZld9bkgPnWwa/wQByddF5ISBUY0v99K738InmoP
         /rE3UX/TM26zr1D4iBI7SqcoSCefmAzKWhrqCjlWJTUWbidZ0KCk+1utZ8WFxjzuqC6j
         2heg9fsvs1tigmBt6/qaTLyTIdJ4WBc5b/BMAiglxD6/j8Fs2RRfDDB51zIJY/7Cg/Kd
         i/sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zxdK5fKw0h9lKN5DjcBTvUjnA1w4Nb3m6viIWapnMZg=;
        b=Nhqthk5H8zNY/Qlppg12H3gWBAbHloo/QuRbgiu0SGXijdroiv7/nAoQO0HOebxPZS
         Q5XlRMJptA20qzOFJxQKpSRN2aYMIUcUfx12v+B/txzzMz3VLziwkfcdLXGQV3Ra4UVm
         VskVH9UpxJNygQrvPmtNtl7Zim5ibKkaGjcDiEuTaaCn1WqTjDwS4bZpm43N9Ae/8FFW
         N8jqsdPau4JskUqOPvx6CEutlNN/UrmxPgSgwvwj4OEeTXMuzXrGbJgpU3ccD/4c38DS
         HZztjKygwg7Rc19D+447Aj0BGkq+od/fZFw8a1Qb3OUkteM/e9bH6MD97L5HeMhQF8Kz
         Zr1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SnGVLIFV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zxdK5fKw0h9lKN5DjcBTvUjnA1w4Nb3m6viIWapnMZg=;
        b=mzAV/1NZJo6tvWAFNCzNN0MwuM8Z18XvXPEzCGCaihcmJYykrTjQhAtlHJb+7lZAfo
         +puiyoMH0NvLhbOF7lLbMihmSIGH4oEUnwfuMDuGcSYvz8nC4qGPqlsmnXqH0KqV9Xan
         Uy7kcIDDae64OWhZPrbnByDdB1wHqaoPqzChD6HusiWfcttcJA2u6DNuwb7wPuFDyzvX
         iKLSc+0/QdvV79CtDT9WeDR6QdeCa5/+L05tHPWon02OVXY3EGYoqWZ+EFJ/DEBCgPOe
         A5HVJZnlaXYhacJjLlOXfC0P+UbbbmjJ8G5jrbAub+AocD9ZGBAKYlPAIB/hAZxIu1Ni
         5bjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zxdK5fKw0h9lKN5DjcBTvUjnA1w4Nb3m6viIWapnMZg=;
        b=e0pFZcNle6orZb5snSFKMjDdjNwPs5uT553WWiZq/vF0mGnh7twh0HfhbwgmInszVW
         HTX6Bw+o31CTvXwcXT4w6qjuG0b6IyNF6oc5WzAKP6TbQfPwKTO/6yqFLs5Vhink8e6V
         yQjFGS1LOXGdV5t3CIExlTxgT5SNJRQq9i1cpzc4SAY8oUFxorFzxW46sRtjvK/4rTJQ
         PsMutid27KIqi71FYSn8+1MFPZnnRvYLy8ZBVOaOgHaaLNxqB0jzmgDf5OCkHV/XFAli
         aJBXZ7rPWx+9yh54WzzRYtbxDCVcWa3VduFau7KU1lZGJhIrMV26nLDrURBEbImOd4vT
         OFvg==
X-Gm-Message-State: AOAM533o3VJM2kdMWIlPN/XKaZgyscga751IHB1ovFfy8/QZi4bDbnbY
	MdJCs5wB2tB0gcNfu/xF2gQ=
X-Google-Smtp-Source: ABdhPJxGmEfctwM2+RvKKUKeGSvxQlQBR9hNd8vcsfTqtu+UDeZFxvlCvOI5lxUS2Gc+oHRiFwdkXg==
X-Received: by 2002:a05:600c:3386:b0:39c:5b81:af9e with SMTP id o6-20020a05600c338600b0039c5b81af9emr3075722wmp.2.1654777112776;
        Thu, 09 Jun 2022 05:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls1205340wrf.2.gmail;
 Thu, 09 Jun 2022 05:18:31 -0700 (PDT)
X-Received: by 2002:adf:e2c9:0:b0:20c:dbc2:a411 with SMTP id d9-20020adfe2c9000000b0020cdbc2a411mr37749388wrj.391.1654777111592;
        Thu, 09 Jun 2022 05:18:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777111; cv=none;
        d=google.com; s=arc-20160816;
        b=P+iT+ErTcdndaZhdEYUHYEbItPVCfZn/GsQr+V1e6NUxnJYtd/GDk7liuK/YCOINIE
         YGDftBNVzEVE2ojf5h9nOFYoV/laknFAHIpETwc6iQevzSWa2WomsbQ33RT3S1Acxa6o
         pR1WcwpCVJbKy2+k1AssGu2ZJ5kjrf9IiiiNndoF4FO3CuwigMHPtmscFprwKZejLB1o
         E63M1jadsQOBSZH4k5jXHg2CmBdMgAYNX/l7gdvHyNX04ottX3BMFkD+VvbUKVtD58qh
         5asBMbEpseqH83vLRUcjVEzL54A5rwIQcJC8jJgPVwqq0gBAYwtEu7vFhRkm8N0LanAA
         7Bbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qCB93MU2lyB4bbkAlS32u/raZUY6pI3+1JJtxGQYwOs=;
        b=VzBvAzgETaIgJsxz+scrij3ZwFZIRUaqsqjiXUiEKA4oeWCOEqtJdAmzpRg4Wci0He
         Vm8mDcqXgiAhlwR0OrLKDC1gqipWWomY+KUrlb2iLBqWHDcTt5+LiaZ64SiOGdZMS0p6
         htojrMFWKcfqI/FJqyLxUVDcogxoeGn8Y7B6d8mTrXzJTyncEx9YzzMHD9+4RrFcCkgq
         ykNyf1sa2kPf/Yf/qll5o/sUenox0Q2hZ5wEwzJW0kXabWDa9vwW+WzHKcL3pRyS89Dc
         gxgSuWa4P4FIraR1WopNOpOh1cpXebu2QyVXkUMWGAJZZzxz6TGwsQy/D2EhUeoApc2B
         H59Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SnGVLIFV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b0039c4aeeff11si105942wmq.3.2022.06.09.05.18.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:18:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id a29so9189268lfk.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:18:31 -0700 (PDT)
X-Received: by 2002:a05:6512:3f13:b0:464:f55f:7806 with SMTP id
 y19-20020a0565123f1300b00464f55f7806mr25244406lfa.598.1654777110811; Thu, 09
 Jun 2022 05:18:30 -0700 (PDT)
MIME-Version: 1.0
References: <2a82eae7-a256-f70c-fd82-4e510750906e@samsung.com>
 <Ymjy3rHRenba7r7R@alley> <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de> <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de> <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de> <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de> <YqHgdECTYFNJgdGc@zx2c4.com>
In-Reply-To: <YqHgdECTYFNJgdGc@zx2c4.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jun 2022 14:18:19 +0200
Message-ID: <CACT4Y+ajfVUkqAjAin73ftqAz=HmLX=p=S=HRV1qe-8_y36J+A@mail.gmail.com>
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for per-console locking
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: John Ogness <john.ogness@linutronix.de>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Petr Mladek <pmladek@suse.com>, 
	Sergey Senozhatsky <senozhatsky@chromium.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>, "Theodore Ts'o" <tytso@mit.edu>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SnGVLIFV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
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

On Thu, 9 Jun 2022 at 13:59, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> Hi John,
>
> On Thu, Jun 09, 2022 at 01:25:15PM +0206, John Ogness wrote:
> > (Added RANDOM NUMBER DRIVER and KFENCE people.)
>
> Thanks.
>
> > I am guessing you have CONFIG_PROVE_RAW_LOCK_NESTING enabled?
> >
> > We are seeing a spinlock (base_crng.lock) taken while holding a
> > raw_spinlock (meta->lock).
> >
> > kfence_guarded_alloc()
> >   raw_spin_trylock_irqsave(&meta->lock, flags)
> >     prandom_u32_max()
> >       prandom_u32()
> >         get_random_u32()
> >           get_random_bytes()
> >             _get_random_bytes()
> >               crng_make_state()
> >                 spin_lock_irqsave(&base_crng.lock, flags);
> >
> > I expect it is allowed to create kthreads via kthread_run() in
> > early_initcalls.
>
> AFAIK, CONFIG_PROVE_RAW_LOCK_NESTING is useful for teasing out cases
> where RT's raw spinlocks will nest wrong with RT's sleeping spinlocks.
> But nobody who wants an RT kernel will be using KFENCE. So this seems
> like a non-issue? Maybe just add a `depends on !KFENCE` to
> PROVE_RAW_LOCK_NESTING?

Don't know if there are other good solutions (of similar simplicity).
But fwiw this is not about the target production environment. Real
production uses of RT kernels will probably not enable LOCKDEP,
PROVE_RAW_LOCK_NESTING and other debugging configs.
This is about detecting as many bugs as possible in testing
environments. And testing environments can well have both LOCKDEP and
KFENCE enabled. Any such limitation will require doubling the number
of tested configurations.

Btw, should this new CONFIG_PROVE_RAW_LOCK_NESTING be generally
enabled on testing systems? We don't have it enabled on syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BajfVUkqAjAin73ftqAz%3DHmLX%3Dp%3DS%3DHRV1qe-8_y36J%2BA%40mail.gmail.com.
