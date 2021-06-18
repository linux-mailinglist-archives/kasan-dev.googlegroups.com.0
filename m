Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA4GWKDAMGQEDJHHHVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 745543AC9D1
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 13:27:00 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id i8-20020a2e80880000b0290161f7012dd7sf3383493ljg.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 04:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624015620; cv=pass;
        d=google.com; s=arc-20160816;
        b=yUukUWH+pTaXocgllHtliWn7jpq0IPC1kNc3tGG+B9lhWwU6cs3Ryz1Ujpi3hl+qND
         zGokgPX8Ya6EphlDGZi99ufbzzD2kAi2REJjJKKbO/UNOSku8iG7N7WPJWhCA7u6vWHG
         sncxP2DEdBCuNXYIWFW3fQtvuCjvkIT1pq8eyonbo84VGH+HFYSD/lXQMk5K8hlh1XRZ
         Un97w5LfBzPqdVN2DvgfdpVAAh/OxHSTebbMeu2sB4eccKZSs6bRxMMdE5uKmkhZpuwJ
         lMlNiYuufphKduxxk/UCJV7bmulQnj1McpW9d2GM+Pqgn6xH5DvTEODkT3dO797RH7jJ
         sboQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Vl1GFZGXfRb3tRnZ/zTt9uUHR2RmV0OIKUE6LxaKDzg=;
        b=neQC6DQRNK4xlbBho09rgFbCb70yRITJxqo5x0RoSbewi6B/X3Gr43fl0I4TsYjemQ
         WknJYHz6k8fyVfMXVYLvkFz+PZtlGIUkcOEtYThmTGLZ0nxUnRleigSUEIOkjUeJ9+gO
         9cQmsGNINF/rGzkrIyegPphEwEA7UXj+Cl/M41ypD9Z9YnuvSuAN8RlNUKffMeW+Ftwt
         iuzcTMf9HwHAJTzqUjkWd2tz/zIUq8Nswn5Ydla0peZEVDAxnPv4jEaNZGDMn5gMXRqz
         hiDisYAZn2C8uNrFACKG/JL35CXEsotOEOcqvhcy/IiveKHV0MPgAlxr7Qo97yJEfB9j
         XZtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KnMwd1AT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Vl1GFZGXfRb3tRnZ/zTt9uUHR2RmV0OIKUE6LxaKDzg=;
        b=EUoTXeNDg0QWIhwEMQqly3rMwwBIQscaWowvoF9lxNZ5BRMgR50eqvLhK2li5YJnFB
         CeoJ3J0zy3ZFfJ56Q3E0TutIoGr0kJ9cSeqTVnXFkwn1e+PJ2C5O1yMf0VNc0cY1TlDS
         Zd8HuOoxD5NAkCdOoqKjQGaR1itC1JbeOE1tgn2Z2qKYA06yv7L2lPsgjEhzHBMxRCTB
         +I1aO/k657B99k6mDnxM3fCdjlrsdc7mS0Q4L2AePwg/q8rMZV73N40o6z6Sy5b6T519
         VJv32oAQ+TPZToJwX+fz0P05c8xoyqCtBh07eoq23Z75zWjwnn46DPhQfGk44VoM+RbF
         t9Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vl1GFZGXfRb3tRnZ/zTt9uUHR2RmV0OIKUE6LxaKDzg=;
        b=tPF8A3lKrUDVNIkUOhJ11xCekT5fferh+8ncFaJot2PONIiTcqq7mbDi/ymqfn3sUi
         O3tFhop1TYm8SOOZUwxdTAHbpdDj5NeCSExbYyYMq6uP4zMTwUf/vSuySOHth+VOrw5G
         o7JA5rOFamRcYbdEtlI0GbicxLyxGYekNkPWBCI5mHRggQsWYvpH0YB0Jo53a9WBO1Up
         8mP8hk7MJc7D5KFZz3wSPd12vxMbaxWK3MOLmvRxf6384Ve9guyEoUIzFwcyF6jVugo1
         fARy52eB23aQhdA14qjBppxU5jT94g90Pg1i66PiidMoyJ8sCW9YcmCRPw/a9iWoNZk8
         EiWw==
X-Gm-Message-State: AOAM530fmbo+AuGyjOsSBlFyvx3kXCtXyQMzJSrUu4MKpNCbkeAZhDsv
	PNIPkUpjhrzNRJx8jPBYqM4=
X-Google-Smtp-Source: ABdhPJwHhvRs+brHGTu0qr0aZ+w4ooxuYNpuQVDx7K78aMcFDoEq9nEA586hdAFCo0PL1fyxQpo5Dg==
X-Received: by 2002:a05:6512:3b2a:: with SMTP id f42mr2796609lfv.425.1624015620064;
        Fri, 18 Jun 2021 04:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b99:: with SMTP id g25ls2567278lfv.2.gmail; Fri,
 18 Jun 2021 04:26:58 -0700 (PDT)
X-Received: by 2002:a05:6512:11cd:: with SMTP id h13mr2857987lfr.162.1624015618890;
        Fri, 18 Jun 2021 04:26:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624015618; cv=none;
        d=google.com; s=arc-20160816;
        b=nSBv0pSM6ybBbOXlK05/POBfalK2UjB3tG+6z/5vZE3genVGmCJHYBqTrspUIZFfzl
         bl2rFUVM7nA9kZTrHdx8aMjo0Pbu9CsWKAm38YjvPaTfXioUiE1Xz/EudZzN1/vI7m2T
         PTm66gv9ZNqF2CfLLzsURIzh/6iGfN6SftNM+pi85X2acFChvwkMfEz67fpm+jz28xHV
         cfJpJWt8/nWe5jtTwu+lKHlTNUH5BeIK5+f7c599/izm+7GZMJ41HCu0LvMio0id8UWI
         k3RuwFX94UIYHLdMZt0VeWrZlLDWPe68SjoNq0CRm8566EqjLBNBP2qtjVlap8CceI6A
         uIiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FoipwiSu6RMmejDEuQLuWgfq8PcsSlF81vDlDxsZQGA=;
        b=nSoy2tdHKgW2eXszk/bJQk5T/bbE/0m6FU56rgZOTlvP/g7TnKlllYB8StWWrR4Zx9
         VY/apfkYEbIWV2qOTfzU59s3yDRR6+cTyXycG2o+0i+TQ1G826ilKa8IiUSGtPF7MxGc
         +ruM0mxFxmbLo1hxuxB6hjxbhpprshvrFL4ZlveaYL9KZAnV5yNecZrQbR7WkbenTxJf
         jOzNQvHSg3TsbCxw3nTZ2hDa59Jk1FNd3HlU6skC1xvl0IgaBHLrFTnzA3ftuP06cP+0
         7vkkL9eJnbaRMngWU2OJ6PfXU+izFB1oYb24L+eiXHYVeU8yuy4ztTkbX89xH01yB3Y9
         0sZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KnMwd1AT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id i12si274856lfc.10.2021.06.18.04.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jun 2021 04:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id o39-20020a05600c5127b02901d23584fd9bso5670508wms.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Jun 2021 04:26:58 -0700 (PDT)
X-Received: by 2002:a1c:4d0d:: with SMTP id o13mr11083791wmh.59.1624015618201;
        Fri, 18 Jun 2021 04:26:58 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:f927:d21d:7ac:d122])
        by smtp.gmail.com with ESMTPSA id k16sm7381882wmr.42.2021.06.18.04.26.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jun 2021 04:26:57 -0700 (PDT)
Date: Fri, 18 Jun 2021 13:26:52 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
Message-ID: <YMyC/Dy7XoxTeIWb@elver.google.com>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KnMwd1AT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Fri, Jun 18, 2021 at 09:58AM +0200, Daniel Bristot de Oliveira wrote:
> On 6/17/21 1:20 PM, Marco Elver wrote:
> > [+Daniel, just FYI. We had a discussion about "functional coverage"
> > and fuzzing, and I've just seen your wonderful work on RV. If you have
> > thought about fuzzing with RV and how coverage of the model impacts
> > test generation, I'd be curious to hear.]
> 
> One aspect of RV is that we verify the actual execution of the system instead of
> a complete model of the system, so we depend of the testing to cover all the
> aspects of the system <-> model.
> 
> There is a natural relation with testing/fuzzing & friends with RV.
> 
> > Looks like there is ongoing work on specifying models and running them
> > along with the kernel: https://lwn.net/Articles/857862/
> > 
> > Those models that are run alongside the kernel would have their own
> > coverage, and since there's a mapping between real code and model, a
> > fuzzer trying to reach new code in one or the other will ultimately
> > improve coverage for both.
> 
> Perfect!
> 
> > Just wanted to document this here, because it seems quite relevant.
> > I'm guessing that "functional coverage" would indeed be a side-effect
> > of a good RV model?
> 
> So, let me see if I understood the terms. Functional coverage is a way to check
> if all the desired aspects of a code/system/subsystem/functionality were covered
> by a set of tests?

Yes, unlike code/structural coverage (which is what we have today via
KCOV) functional coverage checks if some interesting states were reached
(e.g. was buffer full/empty, did we observe transition a->b etc.).

Functional coverage is common in hardware verification, but of course
software verification would benefit just as much -- just haven't seen it
used much in practice yet.
[ Example for HW verification: https://www.chipverify.com/systemverilog/systemverilog-functional-coverage ]

It still requires some creativity from the designer/developer to come up
with suitable functional coverage. State explosion is a problem, too,
and naturally it is impractical to capture all possible states ... after
all, functional coverage is meant to direct the test generator/fuzzer
into more interesting states -- we're not doing model checking after all.

> If that is correct, we could use RV to:
> 
>  - create an explicit model of the states we want to cover.
>  - check if all the desired states were visited during testing.
> 
> ?

Yes, pretty much. On one hand there could be an interface to query if
all states were covered, but I think this isn't useful out-of-the box.
Instead, I was thinking we can simply get KCOV to help us out: my
hypothesis is that most of this would happen automatically if dot2k's
generated code has distinct code paths per transition.

If KCOV covers the RV model (since it's executable kernel C code), then
having distinct code paths for "state transitions" will effectively give
us functional coverage indirectly through code coverage (via KCOV) of
the RV model.

From what I can tell this doesn't quite happen today, because
automaton::function is a lookup table as an array. Could this just
become a generated function with a switch statement? Because then I
think we'd pretty much have all the ingredients we need.

Then:

1. Create RV models for states of interests not covered by normal code
   coverage of code under test.

2. Enable KCOV for everything.

3. KCOV's coverage of the RV model will tell us if we reached the
   desired "functional coverage" (and can be used by e.g. syzbot to
   generate better tests without any additional changes because it
   already talks to KCOV).

Thoughts?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMyC/Dy7XoxTeIWb%40elver.google.com.
