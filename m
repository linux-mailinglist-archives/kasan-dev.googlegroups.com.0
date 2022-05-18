Return-Path: <kasan-dev+bncBCMIZB7QWENRB4HKSKKAMGQECZECSHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF0BA52B534
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:59:29 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id x36-20020a056512132400b0044b07b24746sf803112lfu.8
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 01:59:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652864369; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYF0opZO6bebbuQ9GZTmhATA9MiICJrnn+xQG02livHzPxmexH3D7rmQ6OTJTBz5On
         o8oatvATjkaXiPKfG6A6MB3c4eGOxV6E5uXX0OxYiEbjX1e56nzcS2ARfo3U3gEJZUuy
         PEdXy8C2d6EqMW7rmEf7lpxElDdIGTsEmnTPeA3le6a8sytBHsLCmxdgTvWtb/PVFtOH
         fgvpy9/nM5nE3psFLCphItyY+F0enRe8BK+tII5SWu7mTyWqmXgEg1ssxa3GjjANmOS7
         d2e1L1c9Km4n64VdZmL7a22HN/y7nqGWEc3hS2MT25h3z0Pk78H/Vu9sUaNNNFt47ap9
         lowQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XQzDe+7hi2OUSbsqsztQAqRHth0i7wGOmwF9v+jRMYY=;
        b=MJ+v1UXrRG60lYS5oEs5eKZ/StKklfVW4F7whg7vEJ76qH1tIe0+FdOZaBpZiQ8/Zx
         OBpeEIXxazpGZqGodv0MFZj5l+FZ9fPvc++/zUGtR+1SNzPub/2mJjUo+Te7kto5WBjG
         WXNIVCRKB6Z7KEAECsHsdxDh18/XRHfsasSOJEHpnj6xYUmAQtVvN9ws4ADld+80BKCY
         K2tbGVbAdc4+BzyYukYDc+O7kzB3Uj2zILUIVidVSlSwd54DlvMx4Ay0MfxlJ1PgfjKp
         P04SwPTbpwovoRvVJgRbm2OvGSsloWMd73e18e7K3neeIQpZcBUm9aVn+KyeEUfVA5ue
         QJJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lYs8a06s;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XQzDe+7hi2OUSbsqsztQAqRHth0i7wGOmwF9v+jRMYY=;
        b=bvn/4ad8yKxthkn34n73Q2KBDH1PYgNSSnJCuuvotMEHPtusDMaacmUZ5trBe/9kR0
         dshHRFhhTT9dHSGP291KoHWulF2IHUP0XA5+Ic7myoZyrwlYeMznmBbWYkGi/eDvBMii
         28ZG4or+ZU3iVBDCxrAt8yftSlxKeHqHYA6A3w1vvI4xwoqtlr/ZnBvUna4AkeXfozG7
         ON5U8n948dki/PCII24nsoVURcm2dsDCd4cf9EM+b7SXUCsycatxYcxYjREhBxG2jgy8
         bH2MN1PW35whD4et2e3quk9QkPHfuAbdC1pVvwqT3tn2cZtau5hIc7SaloNn6oOSpfsC
         KCkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XQzDe+7hi2OUSbsqsztQAqRHth0i7wGOmwF9v+jRMYY=;
        b=WV6o4nkwwkvqB0i8ZUiqkjNHj+l8iuOjSbo86oSHFuwpJcEWH85uUVvjZ82so/su0b
         QHaF3QYNgdgIjqYAsVbMzAd98k7+t0p/9ntlW+gCaI5IUYJKphuQB36gtHL5AYkWdhE7
         VuJx/fCcvfbynDGL9Kx9VvoSmizCH+PSlNitbdAI3UN0L1/yWgT1GKrJKzFbhJoCQ6fd
         pK2RhBMfTd1rz1Wr6dTqGyumyMKIh8Up0FqY90i1xCjl7MYreB9RHPhmCzEdMds7aZ/m
         TowLUdArHuvlA6n47TL0oKUZBpUu0NqfX4HXtfStpc3WP9KgbAlwZzZJmpT0e0RaxVzG
         hCmw==
X-Gm-Message-State: AOAM532eNucG4n+yg6n18RQAksD7p0+/2jog/OUCtunosIF5s4a8EpiK
	+xasqv+SapuYhG12bHhm0eM=
X-Google-Smtp-Source: ABdhPJwzuVw4HUOvl4ITMYA48CYszlvAjjY/aPzDy5vd5rzHr9+3OqGELlJJuCYW/bbur7xSN7t56g==
X-Received: by 2002:a05:6512:33cb:b0:477:aa55:5f3e with SMTP id d11-20020a05651233cb00b00477aa555f3emr4259012lfg.488.1652864369177;
        Wed, 18 May 2022 01:59:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9256:0:b0:253:c4cb:1c2 with SMTP id v22-20020a2e9256000000b00253c4cb01c2ls468142ljg.7.gmail;
 Wed, 18 May 2022 01:59:28 -0700 (PDT)
X-Received: by 2002:a2e:b8cc:0:b0:24f:501b:af80 with SMTP id s12-20020a2eb8cc000000b0024f501baf80mr16540948ljp.328.1652864367998;
        Wed, 18 May 2022 01:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652864367; cv=none;
        d=google.com; s=arc-20160816;
        b=sBEF7bxTQwdZ8so/Fxnfldhe78YOYP8XOHJ6bpeJlb5r2iJcrIhYL+wNxkqXC0MQJs
         NabrTptGTwCFZ0dQL+ZhBYo/xcKv4qbzuIYAY3wM143KmMxD4T/0K9y6Bm5fNPEH0IOI
         X3Vt8Iyg5jL3INWA7Ka+mWlx4ip7a36xifKUOUKhMdRk4CrnbZ9d1cE5bpU5tVZPsaxz
         rFop1IJWKBkS6WVyT7/kIeEG/QoBbw049cEmSUsRTrE2TZY8iOdsbkCi7y8jQ5I4+ZaX
         0SSgw/V+wANHeJ66ZFcWVcyn0yiVCZ22rvloGudZVYivhTtKUO6HU1Vs0BMfDDMghb8Y
         +sWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1y20d2CkjJ3jV4BDulmfhtq8qKaxqCZFrmrXAIB+XD0=;
        b=K9mBiPnCRMOp4y3ZhHJoLrttHljvH84FcRkDBIJnchSjp/olZsCORRnVE9BGN4DqT7
         sPx+6Kc6IS1NM3d4mp7uJm1vvp3WRbLaUbwuEUoH77FizxRezUzrIUhN55AhE2/3SQ90
         l925jWNzkqE8/1mQUvQQTg9p0TOzxubCHkO0c9wmtcsVMYYdmsFFaE+ck/I7HG7/pANJ
         kyEm97vNnZUeHYv7oAzXCwE511hhkUERCyC/pgZXsUmKpzLYNhX3agjRF/JaxNiRfOUu
         nSYQd02mfv+2ttTNCpT0bTXS/Euau94UTnAc2Sq+5RIo1vA03q/+DGjr0y/LhTE/KhZC
         Qxag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lYs8a06s;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id o7-20020ac25e27000000b0047193d0273asi70388lfg.8.2022.05.18.01.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 01:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id e4so1166915ljb.13
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 01:59:27 -0700 (PDT)
X-Received: by 2002:a2e:8603:0:b0:250:cf53:7f46 with SMTP id
 a3-20020a2e8603000000b00250cf537f46mr16307079lji.47.1652864366092; Wed, 18
 May 2022 01:59:26 -0700 (PDT)
MIME-Version: 1.0
References: <20220517210532.1506591-1-liu3101@purdue.edu> <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
In-Reply-To: <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 10:59:14 +0200
Message-ID: <CACT4Y+bAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
To: Congyu Liu <liu3101@purdue.edu>
Cc: andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lYs8a06s;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22d
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

On Wed, 18 May 2022 at 10:56, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, 17 May 2022 at 23:05, Congyu Liu <liu3101@purdue.edu> wrote:
> >
> > Some code runs in interrupts cannot be blocked by `in_task()` check.
> > In some unfortunate interleavings, such interrupt is raised during
> > serializing trace data and the incoming nested trace functionn could
> > lead to loss of previous trace data. For instance, in
> > `__sanitizer_cov_trace_pc`, if such interrupt is raised between
> > `area[pos] = ip;` and `WRITE_ONCE(area[0], pos);`, then trace data in
> > `area[pos]` could be replaced.
> >
> > The fix is done by adding a flag indicating if the trace buffer is being
> > updated. No modification to trace buffer is allowed when the flag is set.
>
> Hi Congyu,
>
> What is that interrupt code? What interrupts PCs do you see in the trace.
> I would assume such early interrupt code should be in asm and/or not
> instrumented. The presence of instrumented traced interrupt code is
> problematic for other reasons (add random stray coverage to the
> trace). So if we make it not traced, it would resolve both problems at
> once and without the fast path overhead that this change adds.

Also thinking if reordering `area[pos] = ip;` and `WRITE_ONCE(area[0], pos);`
will resolve the problem without adding fast path overhead.
However, not instrumenting early interrupt code still looks more preferable.


 > Signed-off-by: Congyu Liu <liu3101@purdue.edu>
> > ---
> >  include/linux/sched.h |  3 +++
> >  kernel/kcov.c         | 16 ++++++++++++++++
> >  2 files changed, 19 insertions(+)
> >
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index a8911b1f35aa..d06cedd9595f 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -1408,6 +1408,9 @@ struct task_struct {
> >
> >         /* Collect coverage from softirq context: */
> >         unsigned int                    kcov_softirq;
> > +
> > +       /* Flag of if KCOV area is being written: */
> > +       bool                            kcov_writing;
> >  #endif
> >
> >  #ifdef CONFIG_MEMCG
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index b3732b210593..a595a8ad5d8a 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
> >          */
> >         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> >                 return false;
> > +       if (READ_ONCE(t->kcov_writing))
> > +               return false;
> >         mode = READ_ONCE(t->kcov_mode);
> >         /*
> >          * There is some code that runs in interrupts but for which
> > @@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
> >                 return;
> >
> >         area = t->kcov_area;
> > +
> > +       /* Prevent race from unblocked interrupt. */
> > +       WRITE_ONCE(t->kcov_writing, true);
> > +       barrier();
> > +
> >         /* The first 64-bit word is the number of subsequent PCs. */
> >         pos = READ_ONCE(area[0]) + 1;
> >         if (likely(pos < t->kcov_size)) {
> >                 area[pos] = ip;
> >                 WRITE_ONCE(area[0], pos);
> >         }
> > +       barrier();
> > +       WRITE_ONCE(t->kcov_writing, false);
> >  }
> >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> >
> > @@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >         area = (u64 *)t->kcov_area;
> >         max_pos = t->kcov_size * sizeof(unsigned long);
> >
> > +       /* Prevent race from unblocked interrupt. */
> > +       WRITE_ONCE(t->kcov_writing, true);
> > +       barrier();
> > +
> >         count = READ_ONCE(area[0]);
> >
> >         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
> > @@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >                 area[start_index + 3] = ip;
> >                 WRITE_ONCE(area[0], count + 1);
> >         }
> > +       barrier();
> > +       WRITE_ONCE(t->kcov_writing, false);
> >  }
> >
> >  void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> > @@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
> >         t->kcov_size = size;
> >         t->kcov_area = area;
> >         t->kcov_sequence = sequence;
> > +       t->kcov_writing = false;
> >         /* See comment in check_kcov_mode(). */
> >         barrier();
> >         WRITE_ONCE(t->kcov_mode, mode);
> > --
> > 2.34.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA%40mail.gmail.com.
