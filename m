Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5O25D4QKGQEYL7E25Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6665245D62
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 09:10:46 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id x20sf9441527plm.15
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 00:10:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597648245; cv=pass;
        d=google.com; s=arc-20160816;
        b=WzlannpE/NSS4MJnLZ4WRq50Y2n/d7ljSryQ9/D+U2Fg1radHt3w3B85RVVpxA02n/
         rZhiatkUbZSf+RhoVKQy+fGkwt4BaDu5ENQYt+vwqc1oRDawoij92WISt5HQkQDquMrB
         8ZQgHTqLZqhpOvZi9Jyv8CEls78CKmiCDia/9Mlss7Jns9p3PykPze9Ot3SE1N6E0Svl
         rJVtxNl+QP2k6KQY/+ZUt6FrmiAn+nrirSAK8AWtHOi8laVH3MX+QIahf2A/j93isVig
         FbN2FglpiC5q5bxTN1SDL04C7ECqMje3Ddwf8JPGyg/d7y98aGRtX3S5oX1iBb1sZp78
         DQ4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+SKYLnIn+jztDLt2Ua+MfPHDmvLzVnIcZcCBS+gtJ5U=;
        b=ltmx5fIO4X0bmHFkatDiGlob0AGhaug7pqzmxSdO2wFcBKSk3XalcOSnicr2uPz4BS
         Z31Px0fxoyQF4W1Zz4x82NAQrweYReoTKe/zSVdAJmGFWYclY6j8n7h8z56A2cb7F7za
         LBXO4p042VcEULzDU+jfJLC86dAv3loLq3uwS/Ii2cD8RBl1iFzBzGmgRjoVAIQ6fgOf
         4lW4mUoHjpyFvvrowcxV13y3vcjPp0fmU6Gr73XVGQJiXWOV7UwctZ12nPrAAtltRpFP
         Q7g7gLRPFdt1IVFqy9CbiWxamd4IAfdE+9Qjo+lrq+iuEBjhfE8MsI3/6ttTfAqE1a2E
         /bKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OhMuhXoT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+SKYLnIn+jztDLt2Ua+MfPHDmvLzVnIcZcCBS+gtJ5U=;
        b=Gj1VcCVgtkgTfD80JqW/LjFW2o+eIk/P9SFxCWYjfuXVJEatiSZG5FuxKVMwOLNZQx
         FVdAmHjZdZy5sl0Ddqk+0AEiWSjxZt60ZHfg0NtxEDG+hy37Ach8+lnrPHmf5dFLYmT/
         NrLVW/SLqJEMv7YmyI2tTUNzweHeNYz/9XWFCqupKqeOO88eMLBhucEBpB766jY23u9u
         vajwOqY3kZ/6eMXD3Fs3eSqf2TWZb0lneTlBNU7UOYpkQ77a2ahMxsHi6R6hJIp61Omh
         987gyiRAhmaUEEvX5N7K7xjNko0lMJN7xeJ2h+mWflkgIL64Ceq9Hn3YC23BHSXZ4Ftz
         ByMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+SKYLnIn+jztDLt2Ua+MfPHDmvLzVnIcZcCBS+gtJ5U=;
        b=Ax1suwBbb5Zbj7+xewgfHY/YrhUm8P1gzKRuEdG3RnS9A9IaMdZlMUAKF7q3lF+qyE
         UjBj//f/mR0iOWHSAZIiryoDemE/mkAzEnKKypjCFWWA7T+4dFXcRPgCmHjQGgN4aWxX
         THzV60F2NMBUbIsCBzANCn14rNVdH6yCTU2J54wQWDsYTTkkANhAdTpGzLVsxHoOlEUk
         itNgzleoQlul9zqarZy0OJRb2iS9PjXebpkx/gdkCg0cOvT95VFyOoBj5MJaUgn/+/Ec
         nvTDp+yPoX7/EJAv0hJnGEjVrv6Q++Bo4joSBYDIaYy/YPA7YzAu7Cb36LQhXdHa7JHr
         L/KA==
X-Gm-Message-State: AOAM532kYmxQ3X1nV9BVDBO+B7Sou9tFe0EhYaEAV8wx1mmwAw7dwyfn
	GXFqB0tRAThmVWW9B4hEGT8=
X-Google-Smtp-Source: ABdhPJxEFqJnb50V7r0jJ+6lET02kxlqAAlMtzDLAUwazxFNQnC01d8N9H07sNH9inLnQFuuIsiUOA==
X-Received: by 2002:a63:130a:: with SMTP id i10mr9386071pgl.322.1597648245139;
        Mon, 17 Aug 2020 00:10:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7593:: with SMTP id q141ls5492072pfc.0.gmail; Mon, 17
 Aug 2020 00:10:44 -0700 (PDT)
X-Received: by 2002:a65:6287:: with SMTP id f7mr9325645pgv.307.1597648244648;
        Mon, 17 Aug 2020 00:10:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597648244; cv=none;
        d=google.com; s=arc-20160816;
        b=s9bts5zR4SkzWPOUGFjaFY7Qq5FvYNJtbK2U+w4drVxW/Ld13vQOZ5Pz0D6Xq6HsbI
         8/WvRPNCk+I8GflsPtTiTUNUYKFLQqlKEYtMG0sRJUVaVvzO+tS3zLsfxTUwndXX1y35
         gpQHqseBOI/PFwZW1vdH8QHzm5EStw71ZE/jXmSVWmhdZWBJIcR9dah3qmqG4TKx9UMD
         OqHo3TjeLJvcnWgMB93uS2athjUJRoxA4tGHuCHwbKyXVTK6M0iNQgBFbBqXcH21vLpA
         fNf1pmQu9eDz8KR+3qo82tWyHVxYlGfg7ANp/BucsXpoT34ifHFbN9NkGEqiv7lmS6Sp
         NVFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yjoi260yivvP8E6VWrtmP+N5ypeCnjjZyP0aQQnqe/M=;
        b=d6pkQFy4OqEEWbLgk0yBoLQMEInVZ7BAZOXSehhUSznbTElzZ6RQRtT5YKO9hPLLNq
         c7aVjy15G6hZMbQ+uPmRVP2VtZ2Yh27yuln0LH7HesXLaNah2UAojkIyg/H1BASSYpEE
         jUnoc6TsHiPRcKJw4d1L7mIMurpoyaMUt3UgxZmWNL/6JREcG76KDoQN7QEPFK612dio
         Fn4zWp8lGRwxx36qYd7VXgLdw9sZye3sImzZ4efSnhN4ExmRVnozFtU0zT/+818B9fl1
         2kBGkf7sXpzw/Emc6egYhgixoHytNLIfUnv9+8S1N8uZY3OG1O9T7uZqUJJ76wINk3Ge
         LTnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OhMuhXoT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id h41si1309103pje.0.2020.08.17.00.10.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 00:10:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id n128so10137766oif.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 00:10:44 -0700 (PDT)
X-Received: by 2002:aca:aa8c:: with SMTP id t134mr8082078oie.121.1597648243722;
 Mon, 17 Aug 2020 00:10:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200807090031.3506555-1-elver@google.com> <87pn7yxnjc.fsf@nanos> <CANpmjNPz8vZLGWUzO_8xxtxdXC7cODUL1zVyZf-rBKDBd9LOpA@mail.gmail.com>
In-Reply-To: <CANpmjNPz8vZLGWUzO_8xxtxdXC7cODUL1zVyZf-rBKDBd9LOpA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Aug 2020 09:10:32 +0200
Message-ID: <CANpmjNM7kyBLpvcL7wqAUpMnQhPv8zc=aCnE2eQO248b9-2CNQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=OhMuhXoT;       spf=pass
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

On Tue, 11 Aug 2020 at 08:56, Marco Elver <elver@google.com> wrote:
> On Mon, 10 Aug 2020 at 22:18, Thomas Gleixner <tglx@linutronix.de> wrote:
> > Marco Elver <elver@google.com> writes:
> > > Since KCSAN instrumentation is everywhere, we need to treat the hooks
> > > NMI-like for interrupt tracing. In order to present an as 'normal' as
> > > possible context to the code called by KCSAN when reporting errors, we
> > > need to update the IRQ-tracing state.
> > >
> > > Tested: Several runs through kcsan-test with different configuration
> > > (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> > > original config that caught the problem (without CONFIG_PARAVIRT=y,
> > > which appears to cause IRQ state tracking inconsistencies even when
> > > KCSAN remains off, see Link).
> > >
> > > Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> > > Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> > > Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> > > Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > Patch Note: This patch applies to latest mainline. While current
> > > mainline suffers from the above problem, the configs required to hit the
> > > issue are likely not enabled too often (of course with PROVE_LOCKING on;
> > > we hit it on syzbot though). It'll probably be wise to queue this as
> > > normal on -rcu, just in case something is still off, given the
> > > non-trivial nature of the issue. (If it should instead go to mainline
> > > right now as a fix, I'd like some more test time on syzbot.)
> >
> > I'd rather stick it into mainline before -rc1.
> >
> > Reviewed-by: Thomas Gleixner <tglx@linutronix.de>
>
> Thank you, sounds good.
>
> FWIW I let it run on syzkaller over night once more, rebased against
> Sunday's mainline, and found no DEBUG_LOCKDEP issues. (It still found
> the known issue in irqentry_exit(), but is not specific to KCSAN:
> https://lore.kernel.org/lkml/000000000000e3068105ac405407@google.com/)

I lost track of what's happening with the IRQ state tracking patches.
Do we still need this?

Or would Peter's new approach (to make raw->non-raw work) supersede this patch?
    https://lkml.kernel.org/r/20200811201755.GI35926@hirez.programming.kicks-ass.net

Which would appear to be the nicer solution.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM7kyBLpvcL7wqAUpMnQhPv8zc%3DaCnE2eQO248b9-2CNQ%40mail.gmail.com.
