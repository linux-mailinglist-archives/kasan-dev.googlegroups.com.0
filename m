Return-Path: <kasan-dev+bncBAABBXPX4H6AKGQEACNHZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2882329C94D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 20:58:23 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id l13sf1270451oot.13
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 12:58:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603828702; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rqo8wsz31RRsAhy0YU2dfy+PUr4sG8MO7yx8Ao2KvSE4scb638s5jcp15xQM1S3DdG
         dVV+P4L6A7K9ZCxwXUjtB266kq5GYOZNoKT022L6YomG2fIQD1AgQKb1lukLfun5Koko
         xiFpQv1o5Zay0T5fi2OCqMIYxvuJP2+/DLDzSJlWRExPSgH181/ghvhpy3Nz7ETs2fPT
         t3BG0l9evYJ7YtSXH2zNM+mJTmRllNJr8THn4nD7pt9FBOfTdpgGHsWNQizgtxTM0hCT
         l9w4aV4R8e1AEM0K4fqMn4yKkJCMmOHL9cP3kMMHZdqdV/1rFmaMXSIifCa/n24SLPC7
         dBRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=aoY/FhG1b49HW9cqtou3P2h+X/qc8zlt5a54sRjhSdQ=;
        b=UFpwwdVO/yhk2KUb6S16Inb02/KtuNb6QLnbSeuMN3CRpweVhxBtgeFqATTwXeFMKC
         OE2u0s5m0CXVaOUH5/Lo8TZC2UydUQQkguR4JbHpyqZ6IeWrtIzk6Qkcxh7WagFP+/P7
         UxL3Y9Q51xcvG5+m02PdW66CMW+zrndmrnwG2kpE/Tty5M7EXVFbqSx5z9XqaOpQYJ4g
         9nt8YoZSejbq7L7olTrPpqTYw4b/u1rj8QlG0IM8F9ZylidKUM9OvbiPsqNw6dWL25dX
         s+Oo84XlzF6ONHO4F/dQTRkN3C16AvxzuPKWVq5fO0Z6s9JrxbEEB/NdCYZIxKq4mLPI
         +4zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XYoLeftk;
       spf=pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aoY/FhG1b49HW9cqtou3P2h+X/qc8zlt5a54sRjhSdQ=;
        b=X4KA9Hz4UFKFXeO4aT+fS5pjwdxPgogie9CyxnhpGwap0gXU08LT6S1b8Rd6Sq8eOv
         70aOrzP6aENrxcskjbtZEoNuexzfWdFYEjaAbMCQEMutBA29OAjbAOPGsQelcoFuA9wW
         2xyaUbNO7byuJzUBeOwDo1VL+P8+Wc0MCFXeiNpQxeOgEzvcUP1B+jC7CY0JDttOaSoI
         Pvcfyb2DDsfdteTZQoqgsGlH6Jrjw/DbobCQZtbBnOB0fsQoEFJ90QToJk02sIrVsZGr
         b+/apVb3kvTvwGRcfw9v39FjiCmCVMkSB8F0mPgNUPhDv/bTOYuJaUfedY1UqgtI9Cg6
         Ytiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aoY/FhG1b49HW9cqtou3P2h+X/qc8zlt5a54sRjhSdQ=;
        b=b/fBeIveaRJNJlpYZ35vr2fFNoG3ynKPrYDu50Xrh88svtsJopZqb1WvlUXNBBs8G5
         B3DnSHWV223H/Ym5gi2awjU/UHnvLWgURLrPzTYxtrMAlu4XcpdWlmTRWVsdss8dy59C
         1rWwt+lTuquqWZD1ucjGrAk5zLMgs7dCyMEDNAnkdPw7F2D0afk0Tr+2zG8I4yLEXfx6
         x7VbYeQMvXfp8M5lr1IlK1pMXRPJJGiEiQjJhQK75mWfnracgRUH9J2+g6on7qc8FDD8
         wiGb2jRv7RsVL+X8vn/6sZENllFxr9+qpRzSi53yBoQ197sa8kleeWOtKa5VkyLlY0D1
         a+xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O0SR6/s60dH41YZaQbClmOzZtVs83vvQYcVgO+f76n3uq0d7f
	RupOuqJ6E6crBz6TWwwaFgA=
X-Google-Smtp-Source: ABdhPJwoKQA/R920GVGCkITGXA7qJcRwREnRepo7eOUhUoot3uVcETS1UkI7Z7V5leuQK3vPpyylKw==
X-Received: by 2002:a4a:b308:: with SMTP id m8mr3147081ooo.7.1603828701851;
        Tue, 27 Oct 2020 12:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6949:: with SMTP id p9ls668832oto.6.gmail; Tue, 27 Oct
 2020 12:58:21 -0700 (PDT)
X-Received: by 2002:a05:6830:232d:: with SMTP id q13mr2709717otg.324.1603828701498;
        Tue, 27 Oct 2020 12:58:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603828701; cv=none;
        d=google.com; s=arc-20160816;
        b=ffC0/j5HmB+Q5jgzrGnwOWDxmulnsdFwOuU4RvdLNdpHq2Ce5i9d/mCK9hRNHsUfj4
         yuN6BkuEEVRiwiO6RbkHSt8VOTdcyVK57/oKRn8fWhnB2boWkogy7mF0bGKuxHPrbm5y
         6WRE5Zdrd/NbuVwGg2qsj+BVOwYDVPDmpO368sjWCrgY3xb9O3omM8TSs/Me+lIXPVvV
         cA6TOrWz8nAT5Gwif1lc40QwBKDjqxOGCDMeGRmCWQaUr/pbakBTj7/T7c7jCwq2D5ZI
         X4dPXIP5UxZRBqZ2uasaNcI/ASj0IP9Kq8YOouQru+gGTf7lPief1EE3umdaRe/CCua5
         n/RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=0k/++cMaZ9FKSZ6IwzvFWTPrC5B7eg0R2fhDGlHYPbg=;
        b=URzhULO5oaVJmx221EzukC2VVHXlstCsMr2xIEJzKpGuZP5Pd2VN5jOyKdSqndoQ/9
         heIVnvh1LRBxOpMFttHVA3bn1Fzrsxr1bVIkTORvmIDGoGnIdXvY3GLmvJfOw0j0uBZX
         1ECKvup+7y4wYvCcKaWHYF+VFmTN5RAandy+hP6h9x1pp0g7D02PMXr1M6/UE2EuEOvN
         TsQKDmL1+UsBumGiu9oN7drMHsvkMqDPAgWJkJdpmsLDnPYLrxrlWUvZkVOazN+vXGvi
         JnscPt41DXx+QfRGkB3K7pcVg5tSaz7AJdgIH9TKdM9MnfI01zcneqpPLOUX9y1sImgh
         CVDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XYoLeftk;
       spf=pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r6si417285oth.4.2020.10.27.12.58.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Oct 2020 12:58:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 662902074B;
	Tue, 27 Oct 2020 19:58:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 04BF4352285C; Tue, 27 Oct 2020 12:58:20 -0700 (PDT)
Date: Tue, 27 Oct 2020 12:58:19 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Andrii Nakryiko <andriin@fb.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Recording allocation location for blocks of memory?
Message-ID: <20201027195819.GZ3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201027175810.GA26121@paulmck-ThinkPad-P72>
 <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=XYoLeftk;       spf=pass
 (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Oct 27, 2020 at 07:40:19PM +0100, Dmitry Vyukov wrote:
> On Tue, Oct 27, 2020 at 6:58 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello!
> >
> > I have vague memories of some facility some time some where that recorded
> > who allocated a given block of memory, but am not seeing anything that
> > does this at present.  The problem is rare enough and the situation
> > sufficiently performance-sensitive that things like ftrace need not apply,
> > and the BPF guys suggest that BPF might not be the best tool for this job.
> >
> > The problem I am trying to solve is that a generic function that detects
> > reference count underflow that was passed to call_rcu(), and there are
> > a lot of places where the underlying problem might lie, and pretty much
> > no information.  One thing that could help is something that identifies
> > which use case the underflow corresponds to.
> >
> > So, is there something out there (including old patches) that, given a
> > pointer to allocated memory, gives some information about who allocated
> > it?  Or should I risk further inflaming the MM guys by creating one?  ;-)
> 
> Hi Paul,
> 
> KASAN can do this. However (1) it has non-trivial overhead on its own
> (but why would you want to debug something without KASAN anyway :))
> (2) there is no support for doing just stack collection without the
> rest of KASAN (they are integrated at the moment) (3) there is no
> public interface function that does what you want, though, it should
> be easy to add it. The code is around here:
> https://github.com/torvalds/linux/blob/master/mm/kasan/report.c#L111-L128
> 
> Since KASAN already bears all overheads of stack collection/storing I
> was thinking that lots of other debugging tools could indeed piggy
> back on that and print much more informative errors message when
> enabled with KASAN.
> 
> Since recently KASAN also memorizes up to 2 "other" stacks per
> objects. This is currently used to memorize call_rcu stacks, since
> they are frequently more useful than actual free stacks for
> rcu-managed objects.
> That mechanism could also memorize last refcount stacks, however I
> afraid that they will evict everything else, since we have only 2
> slots, and frequently there are lots of refcount operations.

I am guessing that KASAN's overhead make it a no-go in this case
(in production), but am checking.  But this might change if we can
reproduce in a more controlled setting.

Huh.  I bet that I could do something with the information accessed by
print_tracking() in the slub allocator.  This of course means that I am
betting that we could run with CONFIG_SLUB_DEBUG=y.  Thoughts?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027195819.GZ3249%40paulmck-ThinkPad-P72.
