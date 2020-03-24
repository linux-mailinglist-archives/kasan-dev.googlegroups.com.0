Return-Path: <kasan-dev+bncBDK3TPOVRULBBKEN5HZQKGQEG5BLG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FCB11917E3
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 18:43:05 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id o2sf3233584lja.17
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 10:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585071784; cv=pass;
        d=google.com; s=arc-20160816;
        b=xSo3+4bfzro646Law5OBurgWJySLMW0EZpa1utyihNYot544mylv4pgbccSjUknotO
         7mMIYQFntTh8cpyEbhzidEyo2eXGudUJijVGkIbrdJJCENLH7IvLJeWh2JUWM3uVJH0b
         keBWRvINRIeDsrbLlVM09Cwtn9iIvmUCki9lGaILIy6WogLaZ62chbHFc2a4sAz1zd40
         DPPc01fBpuBE/fbTjLwmVvCHuf+xnMNGk3Eq9ZxNTNDxabIFbfKZ2gxEf0lmzG2m1Twq
         HY3iOJzstUyYwtHLrblEwqiPBx+9SzLoZFnTrxkj7AkVOBMRhEyRW9j9i40jB9RpxnVy
         xGXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7qX4BFZcqDPAyZtK+IW+a16OjEzK840FtUel9i773JA=;
        b=nCxgEu6J+2AHroA+0CuJZBA7HqEFGmk5FZEJaFbQVFhi8bUEGXyW8xCch3VzbN4g0x
         DNXXMZKH//kUh16bDsagGIOEaVX2K7imfU+puddUV1wYLjfhKHTV93Wm3ysLAH5mhF5A
         ky/Q1CivfsPAuaJWRrEtbO4bq+htdG/nOFbOirZQHoDgYFLBdWRUsU5tZg1g+0fLs/fl
         uS/+m+tW/XjQ2WW8cCbdGNQbkEZu/3Lqq3SkSaDNtrE02wAJW5+H9BO+beUsBXqlpV5/
         YJXA6PL948ZlQAdV7YdDwZyIBPVKptBrIYY/DjDk+sUcomijP0Jvmeho7XUL7pYgz+Ns
         eIrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KrRtb/WC";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7qX4BFZcqDPAyZtK+IW+a16OjEzK840FtUel9i773JA=;
        b=TJi+n8eW/wem2c/uIcohejEiFhjeLpxhsRG4Tat1H7G4I9/fm1i1bFM1596y8PsVmP
         GshXnWMWkOuZvtxbYrfQzpcL+W6xxc8DyylhxiW6yggAKG+JNdTVPsHF52TeeZyJRv5N
         nQcMiB9zDTkcdLEBvXBO9aIE6ByupQ/rYX4pxttPEgzScWumTJpxJJpJ+8ZzhFvDi5+A
         Ki+0RY6LS9/K938BbCxrGvjwYzimbC61xD/ieugXHTKn4B+ygBIYdJci/2bWObc+H2DM
         RZOwryrGjo9mG9gXJOI+1AvsW70VjXYjgGWulU8hZQfh+FCQsYInCWSE3bOLa4qPBOBQ
         tOYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7qX4BFZcqDPAyZtK+IW+a16OjEzK840FtUel9i773JA=;
        b=nBnyHXfjoyhokZHMF07hdJicvRFuVMScjL0PVEtWtmgI7pnqIh8C69khYjWVkCin4s
         SGFje+sbJP6aR8UALRFlSRzpSqneeIiX6p+sY6WlcJRBCF4HiS0UiN1E9BSy/zUQIhBP
         zPNd2qyUaStVU9Yb1ZmljVx9Sg4S7qydMStytIZWm+EMoy8fdGdcWoU4uWAd5eSd8Qx7
         Rbj63g3RmMNpKDPjjKRHpkffICqQw1AalHkuaD/W8g2zP0Q8ynKDkmt1FEzJkNkdJLXO
         jHSqjLVyDgUndcwekvlaAUzxKubSrsQRcWTfkmDI5sk3pSY4eFBDuSg4H6LIIq7R0tAB
         rEBQ==
X-Gm-Message-State: ANhLgQ3fPhT1Qz1/UUvGXL88GOqtVfZWDmlThRkgWlxpi6L2FCkfi0iN
	64nOWskaaXPOzkEdfklP8/s=
X-Google-Smtp-Source: ADFU+vui8jxBWgoF3nDUl4biZAaXeskGXiUehnn+CQq45dRyWFZsUH+Ub705+UpoONMS2gu/PxRPdg==
X-Received: by 2002:a2e:6a12:: with SMTP id f18mr1240214ljc.51.1585071784576;
        Tue, 24 Mar 2020 10:43:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7017:: with SMTP id l23ls1426808ljc.9.gmail; Tue, 24 Mar
 2020 10:43:04 -0700 (PDT)
X-Received: by 2002:a2e:b1c5:: with SMTP id e5mr11442770lja.111.1585071783953;
        Tue, 24 Mar 2020 10:43:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585071783; cv=none;
        d=google.com; s=arc-20160816;
        b=T6e/U3ckn8x+JLsR5mSE9QP4GqQbE6e1NWagNjmzxw1rJCoskH4eJaCnFG5Fwe7nIK
         kWuyJi8xXvYPBRz3sXfgIuR08sCnCTveK/g/0uK57mFR/CYz4NRUHKAZ2/h69vavMDFS
         4h+YmEgl2HSQk0lnn7yI2FXea/5xSK394Y18Vi8MOGigtDcIy9iAyZElnymidZynhDuA
         lqCHlHJZB4sNlOfCnFEdMXIHyXuvKRGXRd5IalwSerhm1XugZg1HCboVVKZ9wDQYJvIA
         MXH3BXPx3sNB/liV5yAIgyW9pBeecWWRnuOiGq8RsFoIdaTrAv4xa3bojB+5G7XVXpuL
         KMJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LbJGyxS21FEV88+GhI3Kztu2LQlp+tbZk/mv+EeL9vg=;
        b=XuJeKOZ29+mHbybYXloPUF69LhaXbkVcggUucKqXdD7CzLOa9TEuWrhSZYb8Qq1Cff
         W5lSGRnEfe7bSPtRIEumk34Pu3qb7qSAAWpTEbURlVc99i593tJdtgJFNm/5Df41bO3q
         ko0ZjSi0PX0CBXRQ+jOLZv5ixAdtkdDHbmv128EHio6aGtFSMmdyk+p8baUoew9uAANf
         6wCBYmnBbdEwKb0YqDx39Wqrql3GwAEoq4U7fTIVctESip459JQ4YO4TYw+3zPfEjGkH
         lYf4wbzCs8cbQJ67DGmQxdWlB9+GiO29dXCzRFt2ol9x9K7lLa95J8tSxz7onukFihLR
         WVPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="KrRtb/WC";
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id d12si1087369lfi.2.2020.03.24.10.43.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 10:43:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id s1so22612922wrv.5
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 10:43:03 -0700 (PDT)
X-Received: by 2002:a5d:4ac8:: with SMTP id y8mr37687404wrs.272.1585071783098;
 Tue, 24 Mar 2020 10:43:03 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
 <20200319164227.87419-2-trishalfonso@google.com> <alpine.LRH.2.21.2003241635230.30637@localhost>
In-Reply-To: <alpine.LRH.2.21.2003241635230.30637@localhost>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 10:42:51 -0700
Message-ID: <CAKFsvULUx3qi_kMGJx69ndzCgq=m2xf4XWrYRYBCViud0P7qqA@mail.gmail.com>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
To: Alan Maguire <alan.maguire@oracle.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="KrRtb/WC";       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Tue, Mar 24, 2020 at 9:40 AM Alan Maguire <alan.maguire@oracle.com> wrote:
>
>
> On Thu, 19 Mar 2020, Patricia Alfonso wrote:
>
> > In order to integrate debugging tools like KASAN into the KUnit
> > framework, add KUnit struct to the current task to keep track of the
> > current KUnit test.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > ---
> >  include/linux/sched.h | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index 04278493bf15..1fbfa0634776 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -1180,6 +1180,10 @@ struct task_struct {
> >       unsigned int                    kasan_depth;
> >  #endif
> >
> > +#if IS_BUILTIN(CONFIG_KUNIT)
>
> This patch set looks great! You might have noticed I
> refreshed the kunit resources stuff to incorporate
> feedback from Brendan, but I don't think any API changes
> were made that should have consequences for your code
> (I'm building with your patches on top to make sure).
> I'd suggest promoting from RFC to v3 on the next round
> unless anyone objects.
>
> As Dmitry suggested, the above could likely be changed to be
> "#ifdef CONFIG_KUNIT" as kunit can be built as a
> module also. More on this in patch 2..
>
I suppose this could be changed so that this can be used in possible
future scenarios, but for now, since built-in things can't rely on
modules, the KASAN integration relies on KUnit being built-in.

> > +     struct kunit                    *kunit_test;
> > +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> > +
> >  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
> >       /* Index of current stored address in ret_stack: */
> >       int                             curr_ret_stack;
> > --
> > 2.25.1.696.g5e7596f4ac-goog
> >
> >

-- 
Best,
Patricia

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULUx3qi_kMGJx69ndzCgq%3Dm2xf4XWrYRYBCViud0P7qqA%40mail.gmail.com.
