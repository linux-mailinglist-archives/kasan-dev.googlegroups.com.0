Return-Path: <kasan-dev+bncBCJZRXGY5YJBB4EYTKCQMGQEULEDIRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B5F238B426
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 18:21:05 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id z14-20020ac8710e0000b029020e9ce69225sf1991343qto.7
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 09:21:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621527664; cv=pass;
        d=google.com; s=arc-20160816;
        b=hkDx53vljJwYMNPrcXLEeDWibUWew8QFc9uLKTvtXyjW6nn6WEqCCQaQD+Iuy3it7L
         uIpFcQL1B2eQ163ZH0twUZIh0UhQbWbwch4AoGWrAcbxZgYeUag2ORMMP4o86wLHjeeO
         8kKD0aARFAf7Chqv+KktAeAS4zjS/S8jieMsxwJQH/pvuhfuSu3K4j+9dmfbXuQeMwJE
         qqXiowVbW2/LXH8WVEIQ+lSSI/Oic/m/Ric0XXGMJFjQNLHmRAULs2ikQ0iB0MsPlVz5
         m7GLkp/Tfu2Pm3RsM15aGzHzIcHdjIK3MDPqbAxmcCsh6gzmiQkFlYbLrhyElj/dx4iB
         i5cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=EgdHuUWD5kLua04GFfl0aTehDfPhZFI4aLXL6qloz+Q=;
        b=O+drD5a0qchjUTTmWY5Dd90aGk2xL+Nvvfw4s/39fAOC8ESPAYZhJWvitQVZeg90no
         OLALA5umzs3t/THOgw2fGF8wi3jhafFv9T+5J1hxkVdSkR0980JbGPpxs0Zc4UJdci2r
         2r3evVQPVmpWpPeo+lHMPdpGWGZQ5YgqYtNypPCm7VltRvLY1fNnUzVNWA24ieLB3s9j
         Mjc4zK2d1U3uzap8qPTmQFoI/AfnbUmMyaj4+D3p51LDRDPz6IfMNYeFnsH4FjC/UczA
         ge11sCZbaPpZlVRxlSjNxTRY1fsTz70LU+hPjcP0BhNjjZAy2G0MTYraugQM4uTTwCG9
         Tz1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r4HAri4T;
       spf=pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EgdHuUWD5kLua04GFfl0aTehDfPhZFI4aLXL6qloz+Q=;
        b=eYHgKnOmZiXLB8sGLRJQ6XNq2dH4Z/UbZPNNovEBuHaRGoFWcWc13mR76BxZmFatm5
         RfolaUBqi76rkJwKUI+riG+u/VkOMXzEP4g5Yd388ndvzsIO+YzcLAZIBvEKU9omOtYb
         hI55tu70zFvRy8kbe/hgarnuqEhotRieZbywh/VAgeUSz5hoiI25/735AiL/vydPFNpb
         GgVQbg/kA8u9apYCKkqMGcZwfja47u4GkaCWPsZM19WOmdTG9IF5Ze8SoDaMOhILJbnh
         UvgkOduq/lyPTzDHhQjvo2VjqzRgZc54YRojmuTOdjr3A0eszKnHLOUa8uj68+neu17w
         z64A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EgdHuUWD5kLua04GFfl0aTehDfPhZFI4aLXL6qloz+Q=;
        b=LQ+mr9Fhg5ZgGruQ5gEg2JFyYGAqCvrAUOUQkrZ+cImT5aeG4W5jw+j9VlSVILvxmn
         VRY9Iu/7P1uh/iTFuBhDcf75xmehLpmw6th6CcUk88v+O54N8r/LL+RxKAf3lPHGvPT0
         0/o5uK2uSJmXCE381YFTGALC9LGG8zOtjUZ6EGMgbuUy1a0QnK/8c+myqpFu54G+rWSE
         wlSslLB0/xUw5Rlwvvi2U1CtvvZ4nzm6nnAWCLeQ/Y9Pm/7UpIYN9k+N4wvLgSC6En/I
         YMrUtbArJ8LuEak5nvGdzz57BvcWywPEK/UuW7m9MyWFRw+ygn2c8trLnj/RdkvKShM8
         GREQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530J8ObEkMNVh3x15O+iqi57VuDGH7ktDr6uYORkwgxS1euQm8bH
	vt5HuBWBiHj5aWsoTpoGPH0=
X-Google-Smtp-Source: ABdhPJyaYH2FVYq2rrpyXF+/RhiLfAFLR+24wjPdSw9zZWm7ono49rWgaRb3qHIq7HxYOW5D+ZRCqw==
X-Received: by 2002:ad4:5045:: with SMTP id m5mr6622270qvq.14.1621527664330;
        Thu, 20 May 2021 09:21:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5f44:: with SMTP id t65ls2015892qkb.0.gmail; Thu, 20 May
 2021 09:21:03 -0700 (PDT)
X-Received: by 2002:a05:620a:21c5:: with SMTP id h5mr5783747qka.395.1621527663864;
        Thu, 20 May 2021 09:21:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621527663; cv=none;
        d=google.com; s=arc-20160816;
        b=mdWcZYLe8gjtmtpa/yCI4/x6Xl+EFKtoc9pXoNiNJc15UqGViYazIt21mlbIRPg7nS
         cikCOGQGYJlGafEkjvxDe44jCsXHCehfIZ3l8cHDq6WVyumKwWkHzAp7mtAWKnFXKsks
         NXgJ3VlJAZr3sAxYB55Fg54qfE49IR0Vq1PZjZ7C//+k/CRGG2C/F86m9fwZWPVZXxJc
         CIu3FbWnlcG3GG2oFYPfIVuyDTbYIAR/74X+fEro+ODgm6+nu6ewNv+rAd/Nt7ef91Xt
         OgaFi+j9rwlN3HS4e7uKWxva/pYkqg0V7jysokwb7ZLddM6yxNSUi6IggiWeYul8hZYs
         d6sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ov/G5SPNp5+sKDgUY0QjqzKQRdGNs6bXWYfLlbqX3T0=;
        b=neBu/psOlq6kFHl1JEc1rOHsANsRqMBuexTh4p5LE2VxD+WsL8tFF7Dls7RGVbYRfy
         idjeWMnBDJDTbPoQ8aIC9uSsfO54nhMuLTfHODxO46clq0FKtFhK/D8T6tX1VV248nJ4
         m4ojfOqw59qN+P0I76Ha5ppv9RIUI/JLfyBuvdLDy08nrhFmbBDTtiSaRrpD9YfEKGvu
         7VLpcRp/Nzq7gUPdjTG2aoYRoy4Rsbcih8eX+/rm0FMgF3W+aAFsHImGLSIPKdt9iuvZ
         lpB2wtW2jmbCzMX8p2kPKJBuCiOc8dNp7ok8VAIHukgknrNQP/GV98tF9U1gMBsCpjuY
         9mKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r4HAri4T;
       spf=pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 8si227385qtp.5.2021.05.20.09.21.03
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 May 2021 09:21:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D8334611BD;
	Thu, 20 May 2021 16:21:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 874845C00D8; Thu, 20 May 2021 09:21:02 -0700 (PDT)
Date: Thu, 20 May 2021 09:21:02 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <20210520162102.GL4441@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CACT4Y+bNeErg4L5Tn=asK6ZNr+V6bnwwuD+Pg26x=pMO+pRXXw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bNeErg4L5Tn=asK6ZNr+V6bnwwuD+Pg26x=pMO+pRXXw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=r4HAri4T;       spf=pass
 (google.com: domain of srs0=jzu2=kp=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jzU2=KP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, May 20, 2021 at 06:46:35AM +0200, Dmitry Vyukov wrote:
> On Wed, May 19, 2021 at 10:24 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
> > > > On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > [...]
> > > > > > All the above sound like "functional coverage" to me, and could be
> > > > > > implemented on top of a well-thought-out functional coverage API.
> > > > > > Functional coverage is common in the hardware verification space to
> > > > > > drive simulation and model checking; for example, functional coverage
> > > > > > could be "buffer is full" vs just structural (code) coverage which
> > > > > > cannot capture complex state properties like that easily.
> > > > > >
> > > > > > Similarly, you could then say things like "number of held locks" or
> > > > > > even alluding to your example (5) above, "observed race on address
> > > > > > range". In the end, with decent functional coverage abstractions,
> > > > > > anything should hopefully be possible.
> > > > >
> > > > > Those were in fact the lines along which I was thinking.
> > > > >
> > > > > > I've been wondering if this could be something useful for the Linux
> > > > > > kernel, but my guess has always been that it'd not be too-well
> > > > > > received because people don't like to see strange annotations in their
> > > > > > code. But maybe I'm wrong.
> > > > >
> > > > > I agree that it is much easier to get people to use a tool that does not
> > > > > require annotations.  In fact, it is best if it requires nothing at all
> > > > > from them...
> > > >
> > > > While I'd like to see something like that, because it'd be beneficial
> > > > to see properties of the code written down to document its behaviour
> > > > better and at the same time machine checkable, like you say, if it
> > > > requires additional effort, it's a difficult sell. (Although the same
> > > > is true for all other efforts to improve reliability that require a
> > > > departure from the "way it used to be done", be it data_race(), or
> > > > even efforts introducing whole new programming languages to the
> > > > kernel.)
> > >
> > > Fair point!  But what exactly did you have in mind?
> >
> > Good question, I'll try to be more concrete -- most of it are
> > half-baked ideas and questions ;-), but if any of it makes sense, I
> > should maybe write a doc to summarize.
> >
> > What I had in mind is a system to write properties for both functional
> > coverage, but also checking more general properties of the kernel. The
> > latter I'm not sure about how useful. But all this isn't really used
> > for anything other than in debug builds.
> >
> > Assume we start with macros such as "ASSERT_COVER(...)" (for
> > functional coverage) and "ASSERT(...)" (just plain-old assertions).
> > The former is a way to document potentially interesting states (useful
> > for fuzzers to reach them), and the latter just a way to just specify
> > properties of the system (useful for finding the actual bugs).
> > Implementation-wise the latter is trivial, the former requires some
> > thought on how to expose that information to fuzzers and how to use
> > (as Dmitry suggested it's not trivial). I'd also imagine we can have
> > module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
> > state, and also add support for some subset of temporal properties
> > like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
> > suggested below.
> >
> > I guess maybe I'd have to take a step back and just ask why we have no
> > way to write plain and simple assertions that are removed in non-debug
> > builds? Some subsystems seem to roll their own, which a 'git grep
> > "#define ASSERT"' tells me.
> >
> > Is there a fundamental reason why we shouldn't have them, perhaps
> > there was some past discussion? Today we have things like
> > lockdep_assert_held(), but nothing to even write a simple assert
> > otherwise. If I had to guess why something like ASSERT is bad, it is
> > because it gives people a way to check for unexpected conditions, but
> > if those checks disappear in non-debug builds, the kernel might be
> > unstable. Therefore every possible state must be handled and we must
> > always be able to recover. The argument in favor is, if the ASSERT()s
> > are proven invariants or conditions where we'd recover either way, and
> > are only there to catch accidental regressions during testing; and in
> > non-debug builds we don't suffer the performance overheads.
> 
> There are some (see below) and I am sure there are precedents in other
> subsystems as well.
> What's the rationale behind not having a common debug assert/config...
> maybe because nobody cared enough. The current approach is poorly
> suited for CIs/generic testing but fine for human-oriented workflows
> for testing a single subsystem only.
> 
> $ grep DEBUG_VM mm/*.c
> mm/debug.c:#ifdef CONFIG_DEBUG_VM
> mm/debug.c:#endif /* CONFIG_DEBUG_VM */
> mm/filemap.c: if (!IS_ENABLED(CONFIG_DEBUG_VM) && unlikely(page_mapped(page))) {
> mm/huge_memory.c: if (IS_ENABLED(CONFIG_DEBUG_VM) && mapcount) {
> mm/interval_tree.c:#ifdef CONFIG_DEBUG_VM_RB
> mm/interval_tree.c:#ifdef CONFIG_DEBUG_VM_RB
> mm/ksm.c:#ifdef CONFIG_DEBUG_VM
> mm/ksm.c:#if defined (CONFIG_DEBUG_VM) && defined(CONFIG_NUMA)
> mm/memcontrol.c:#ifdef CONFIG_DEBUG_VM
> mm/memcontrol.c:#ifdef CONFIG_DEBUG_VM
> mm/mmap.c:#ifdef CONFIG_DEBUG_VM_RB
> mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
> mm/page_alloc.c: if (!IS_ENABLED(CONFIG_DEBUG_VM)) {
> mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
> mm/page_alloc.c: * With DEBUG_VM enabled, order-0 pages are checked
> immediately when being freed
> mm/page_alloc.c: * With DEBUG_VM disabled, order-0 pages being freed
> are checked only when
> mm/page_alloc.c:#endif /* CONFIG_DEBUG_VM */
> mm/page_alloc.c:#ifdef CONFIG_DEBUG_VM
> mm/page_alloc.c: * With DEBUG_VM enabled, order-0 pages are checked
> for expected state when
> mm/page_alloc.c: * With DEBUG_VM disabled, free order-0 pages are
> checked for expected state
> mm/page_alloc.c:#endif /* CONFIG_DEBUG_VM */
> mm/slab_common.c:#ifdef CONFIG_DEBUG_VM
> mm/vmacache.c:#ifdef CONFIG_DEBUG_VM_VMACACHE
> mm/vmstat.c:#ifdef CONFIG_DEBUG_VM_VMACACHE

One possible work-around would be to create a CONFIG_DEBUG Kconfig
option that selected all of these subsystem-specific CONFIG_DEBUG_*
Kconfig options.  But I would not necessarily expect that the resulting
kernel would be stable.

Here are RCU's:

CONFIG_DEBUG_OBJECTS_RCU_HEAD, which checks for things like double
call_rcu()s.  It depends on CONFIG_DEBUG_OBJECTS.

CONFIG_PROVE_RCU, which is equivalent to CONFIG_PROVE_LOCKING.

CONFIG_PROVE_RCU_LIST, which enables additional lockdep checking for
RCU-protected linked lists, and which is supposed to be retired after a
conversion process is completed, and one that I had completely forgotten
about.

CONFIG_RCU_TRACE, which enables additional RCU event tracing.  Not sure
that this is particularly relevant.

CONFIG_RCU_EQS_DEBUG, which provides additional idle-entry checks that
have proven valuable for hardware bringup.

CONFIG_RCU_STRICT_GRACE_PERIOD, which shortens RCU grace periods, to
the detriment of system performance.

It is not clear to me that blanket-enabling of these guys would be all
that helpful.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210520162102.GL4441%40paulmck-ThinkPad-P17-Gen-1.
