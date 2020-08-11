Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF4CZH4QKGQEYMUWYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D38A24168A
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 08:56:24 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id c1sf5493659ioh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 23:56:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597128983; cv=pass;
        d=google.com; s=arc-20160816;
        b=I5Oz90FlhAW0w95sxhbBmzSZeDTslK4lzW8pF1YwzH1ZwPjvdanMul0pKq4fqgnAQF
         k3JTzkK6mW7HVI/Jg5h3HdD98H8SRa02fR+4yxUbGfvILe/1daC3/OwSpPRK7Iz0mKoG
         nGPRPQsgBYPwByXG5DHlhKJCsWjnTsw3nIz8js6ErSE1vgH74LHfjUSuFaTp8UCrlCXn
         7JRv3nGKRpjkzNdCOUF1+3QIyfe8poIWf7TBNkCyvKlJuDkwA1hoN2VPQdIuCI3O7Nej
         NTG3fH6/tJK60EnpIpAT+G3qbBCfnhjVyT1XvFk1mpHZJQmnmY9m6WVr3KNRwKZcNHUA
         7bkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tA6M7/g8qD4pHA9FwFmpMrIsGC45/RshQH1PmAgszHw=;
        b=AM59kQvmU2My0CIrGd78Fg6CNqdXmUqPqHpbqXvdlHDbZiIZ3UAOWcd9oOlKAuR7of
         xjUn8qmHMGd4bPd7r3yJrfRDyTs5MusmTc7775dSpPRvCiK9waKtmNEOsuc9dAcHSgXz
         5UbRj3LfqbnFzBKNhQo4hIStlD1UGMr12+M1OiguA2TughetaPEozGMG36jlqJHM1JVq
         rRg+uCNHM1ynIZ5TZu2mU1lrdJmhtoE/7ehtbQW7JV6tR2iOBbdqzFt2VGdE0ov/SiYu
         OuCCnXM04NvqsuRS4W4ej5l/f6RyvW/IsxaRH1U2XYvnMEV6Y3yLXDUvGGPgVF2Y4bWt
         g/Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uA2yZ3mD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tA6M7/g8qD4pHA9FwFmpMrIsGC45/RshQH1PmAgszHw=;
        b=TkW6MJxbtkEGs8VmA6ch0OZFZKKHyaLebqgn3cWhwm3cwUdEoDVkClCuxeSFGgQS1u
         MA9zqmPlq7oLyrbqGT2Iexnag3nx3GXaeWtqwqlAMc9uF+f9P1SfutDdDhCbuKU4yw4m
         id7RfOWumaoOJZzvwN22sQfVoT4SN2UgRsCNLsrQohk1SKBOl0YfyIhaS8xgsY2TxVLd
         7TxKxSrtjlN12PUtNlOPacFQ4NZFDfJ/xbgmZtM7ei4MB70yl3d08XSarIiUKV16+v4W
         7SL28wrM3cxQnvL8A3R5X+ueuCtsGw3LGdSdeA/+nfku+siN/Oo5gKG6KOuU5hNlVnGd
         HHbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tA6M7/g8qD4pHA9FwFmpMrIsGC45/RshQH1PmAgszHw=;
        b=ACh7X5XlLOXJdSuIJVJwsRkX2HQQmTy3I0uXfDuoyJn8byJ8AhPU1di8KIkwSP+g8d
         4dCsG/CmO0nDsD53GW30vPe0r2FMF/6mQF7NtKrq7X1SOBPXikMZuzNCyFDPfu/9Qh1X
         3bMz4xofMQHHU6of2a17BtVZOgN06RzNBrbabPVZEXeNiiFpmR8jobD6oe+wbcNyC5F7
         b2vJBlE6iWFVpzaKJRVZ8bnv7cre0kg5m+WyVCdL675dukS+omLRtbP2M7Xaf7l0j4Ed
         Xjo0quz++2XmRSJfwSHuJNo4ibg29Y8uvvNO+dXukZb1FwnABftntJMu/2mDc+A6dt94
         Syiw==
X-Gm-Message-State: AOAM532VBxtlixZAaEK+irFQWnI2jeAJk7MjhZF9RICwTjh02FtwuWPL
	g6uZ0DuLVDGYtn/qYqTUD98=
X-Google-Smtp-Source: ABdhPJwOuh4OfSyIFZtza4Et/hdHe4f1jAGnwdB5NoD+H1nOt6UTU4/sf9MK+CsgGAhpyV4xwiMdyw==
X-Received: by 2002:a6b:e009:: with SMTP id z9mr21041601iog.124.1597128983308;
        Mon, 10 Aug 2020 23:56:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2286:: with SMTP id d6ls3304750iod.5.gmail; Mon, 10
 Aug 2020 23:56:23 -0700 (PDT)
X-Received: by 2002:a6b:ba89:: with SMTP id k131mr20795366iof.133.1597128982962;
        Mon, 10 Aug 2020 23:56:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597128982; cv=none;
        d=google.com; s=arc-20160816;
        b=lCxXll85cOHTvaNOsSH5KWy0ei48PBNFiyADrWJ9S8OhUVZyFQT0644s9wPoBJLtJp
         /E9SIRh1Txq4SknRujjF0V/+sIleoIBaBYz6e5JkjTwtMwefRXKHBleAXrmYyWTkmaez
         EBgQ13bx5xIqY9Ka4gAcLxTy1BISmqnRisL9UMdLvZVuHjBsi6WPGsPB+TLAm/UXUEsM
         JqejhSJjB+Xa2+T5zooUTfcSqL2rSymqXtn1ShjvMJ6ajiaTJ93Kp44Nmym8rgQs1CPT
         1L/YTu2Dd0pkeHB3UExHoklI0+Gfwy1eyOfH0AgnEn+Yg2rPqjztQJT/AgmAwEcp2tGN
         Cshg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qBONm3JGSIredide1r1f2aq4pO6yJwD51o3qC+jyQL4=;
        b=CuY5d9hfnetQFTt7TytfK3YfiuJXkb/kZq7PJPxEmPr0Y992x47SKfN/srr6Gkkgl/
         OyawAUfgUT/+dHynfZSO3U5ek04omA4DvAEdPwduW8ZcUWLbWY1Km/7W9ZKvbMUddw9Q
         xpoeRsWxsfyYcMG8kjxC0CMgVV9ly22GdVR0eA/DjgzpRf8yMGwmb6RKi+10xLiDGpLI
         zjxeVfWzjLPf7EA4ANzlzCjqz8ziGO7W+XrqDHYGjUYU6CoyPrxQ/S6GGD0LXFJn7+4J
         VDiWqglaGfHChYStn0OrjD81v4Df0wyUUaNIqPdx4JnCVfdUtkPWH/BIsGCRFpV1X0x1
         bHNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uA2yZ3mD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id z6si1197262ioj.0.2020.08.10.23.56.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 23:56:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id h22so9287836otq.11
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 23:56:22 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr3989495otc.233.1597128982279;
 Mon, 10 Aug 2020 23:56:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200807090031.3506555-1-elver@google.com> <87pn7yxnjc.fsf@nanos>
In-Reply-To: <87pn7yxnjc.fsf@nanos>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Aug 2020 08:56:10 +0200
Message-ID: <CANpmjNPz8vZLGWUzO_8xxtxdXC7cODUL1zVyZf-rBKDBd9LOpA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
To: Thomas Gleixner <tglx@linutronix.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uA2yZ3mD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Mon, 10 Aug 2020 at 22:18, Thomas Gleixner <tglx@linutronix.de> wrote:
> Marco Elver <elver@google.com> writes:
> > Since KCSAN instrumentation is everywhere, we need to treat the hooks
> > NMI-like for interrupt tracing. In order to present an as 'normal' as
> > possible context to the code called by KCSAN when reporting errors, we
> > need to update the IRQ-tracing state.
> >
> > Tested: Several runs through kcsan-test with different configuration
> > (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> > original config that caught the problem (without CONFIG_PARAVIRT=y,
> > which appears to cause IRQ state tracking inconsistencies even when
> > KCSAN remains off, see Link).
> >
> > Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> > Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Patch Note: This patch applies to latest mainline. While current
> > mainline suffers from the above problem, the configs required to hit the
> > issue are likely not enabled too often (of course with PROVE_LOCKING on;
> > we hit it on syzbot though). It'll probably be wise to queue this as
> > normal on -rcu, just in case something is still off, given the
> > non-trivial nature of the issue. (If it should instead go to mainline
> > right now as a fix, I'd like some more test time on syzbot.)
>
> I'd rather stick it into mainline before -rc1.
>
> Reviewed-by: Thomas Gleixner <tglx@linutronix.de>

Thank you, sounds good.

FWIW I let it run on syzkaller over night once more, rebased against
Sunday's mainline, and found no DEBUG_LOCKDEP issues. (It still found
the known issue in irqentry_exit(), but is not specific to KCSAN:
https://lore.kernel.org/lkml/000000000000e3068105ac405407@google.com/)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPz8vZLGWUzO_8xxtxdXC7cODUL1zVyZf-rBKDBd9LOpA%40mail.gmail.com.
