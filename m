Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJP6VOCAMGQEZHZQ5SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 898B436EFA0
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 20:47:02 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id c24-20020a5d9a980000b029040db7d17e09sf3022445iom.22
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 11:47:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619722021; cv=pass;
        d=google.com; s=arc-20160816;
        b=HU4bvFRaoNppJAd84wz1NgzEMJ9Ien/vNGpVv2aiTPUZiOubnKFyD/iiDtw/2+cMC5
         Sfe4VnEwg8gfRnN4jlTcqGhB4xQm6Dwa0JlgQXjZb5WE16UgrsE0r6RNPQh0PW5O5WoL
         r32V8w6Ly6fFpRmTi7JLNm8k4axMWTbrTYjqY8Ym/JfYfeDb5xf7nqyMXa7Rx4gGwr0Y
         8BtwXbUnZxNVX+spQ42TY8/ZtPso1svdKD0oqlRd0PnfPkL1Wrf4Hql0Uz03Kkn4s8mr
         DhTsknwEiI51vNYeSfsUXw6ZqmhKzxVQXWGKMClcUUkS68IWaVXCBymONBzLfC5oNM/y
         Ddyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pvlu5dfRJ1wq0ZnuaZebOYao5/9WNQzyYGeMzhOGBUQ=;
        b=NG2P7U7PAyj7HfHdtyzH9rp0bzHsBNC2XKpJ1UWjv+aBOwzmAhpO44Gn1VuDoGxopt
         xeG6N5K+OCJFJgLRco3peidVLveF5DxNhTFxNqyU37yff+I3VWrNXRRgCdpdd/VJa1QM
         yjNJJPLpjm8HK1kiEnFqUxbOUJeDSOqn5vs17E1Ftpi7/WyawfKJtqvdy009JEdHj/MN
         146zg8ULTD8G9F5iWcJprYgcyzOXCk0FYYTGsPdxch5t8CmRvOxcaGtsLdDnoVYJsM0h
         W90o+DuZRNiXVwG1sEtDXb+K8GH9OsCywM5jc5KyQQRzSVcjoFOqgKWVe+32Ih16ULzM
         quQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YheD8PJ4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pvlu5dfRJ1wq0ZnuaZebOYao5/9WNQzyYGeMzhOGBUQ=;
        b=RIH8TQmw1CzpaMIR7F5tM+cHQfFhK3Ui07TGaSJjRKZumlyUUVZrqtmwCsxlmIKneb
         BlcMYVz42tx3Gj9s/NPd2idlOgOcOy2A/ilw+yJNcCM5/Jc0JgJyyBMpkiHctvdmskI/
         hxjIsk7dmY4IG9X3kx6YlafkrKfXMn/SmNk8zOZY1PBugJWq0EaKw7etqBh3ZUIE2Fvo
         EpB/r75rffWZQPKJjLkZkG/K6wTC0D8SAOHhGKE3/mhHMR6ZAs7Ef7lWJj0nCJk4lqd0
         BwTaLbc6i4zrm8SBJwWNn93483bWiEPdMHYsT+oq7z8sT4MGnDYn+y9go7QsajrOJ0UB
         CK7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pvlu5dfRJ1wq0ZnuaZebOYao5/9WNQzyYGeMzhOGBUQ=;
        b=eFqYuPbU8G26SQuvVEnIy2aJ+161D2TAsZ07a7po0RehhqP8Y2FyMyxKfBsFQG1lLK
         noSPoCAIvdOwM0k9q7OS1ueGzsYfjA79ClN+T7nuL0E7XoXc5LFRc6ptyKujnnUuGgzW
         dENpRMYRB+H9jrtNbMZwyOm3TMB4EPWoJtfeTptjjVrDOSdhexm1pIs2N6WZfJvi/kMj
         eqhL5cn6zl1K8/JUipdaIMGAJxTZjoQcIuQ7v9b/vmlfJZFvMVZ/qJKrDPnXgyFFZtop
         ehPfiWyNODt39lRtWa0kFB5gASyLcnXu3XacPrpen7xb/F1+TY9wmjjs1EbQaHxTsIPY
         huHQ==
X-Gm-Message-State: AOAM532hfCqzWmUUJSjGFuut15erxZVAkxpW6Vce/FEGpPJoYKDHiMVo
	floJQ73/zWizxIR0Gx6IxOk=
X-Google-Smtp-Source: ABdhPJzwmtjo4U4v/sz3cYHsPoiBXJz5u1wlpnGnUeFxOuRw/YpY2W4BSB8z8/w/isAfnsgkgQ88SQ==
X-Received: by 2002:a92:bf11:: with SMTP id z17mr936740ilh.146.1619722021318;
        Thu, 29 Apr 2021 11:47:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:107:: with SMTP id s7ls584412iot.2.gmail; Thu, 29
 Apr 2021 11:47:00 -0700 (PDT)
X-Received: by 2002:a6b:d20e:: with SMTP id q14mr479274iob.200.1619722020876;
        Thu, 29 Apr 2021 11:47:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619722020; cv=none;
        d=google.com; s=arc-20160816;
        b=L4nK6sjKEJgNTq4Pdz/NXZ95nVieM9LtsjEFUfz8d/25xuwmMxlXq1xfD/EoACsLgB
         DxX7N3zM49vo6Lqw00I9zt9klUMYRNGBDHpab4so5hXLYSx0c32f6e54hqrC6ZlV8q2P
         wynXchaQWPhbRVi67wKXG48babgfJmtvthEh4merPEJ25Z8TdztyWiV9ysgK1ku9kpmL
         TtvGMCvzisucywElmeA3POZz1OBcndcNOe+rWujbZHgLX39DzunGUvhpxkcRFWP8ymmS
         +rNVPu9yte1d+mgFI8Uj/0I7t4TjYFEucB527mFVL+JwRm3gW0quPBSo8jkRop7HbU8S
         Sbyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8+UJwrU2MphE2H9pVBe4Va+3pVl8MrgEBW+di5Ar9x8=;
        b=mfkiSbanOClpLV7QwCUuBmJI0Z4Y5KBtuK+WCDwHI8UqK7JRIEGdd/jd0ITWd62GBp
         Xjuz69XISXYgGOYHeMxTMWjB7d4OZFA8t00kMPbrT4T78aVdxYPLtniPKxiqKu81p9qW
         /5rAnffTCPPPulZUsQwdAqEoNIUeB5SAmFR0Gi/sW77aaY3AxqQxYw5AQveRhtAp5wUa
         TCxGb6tE7sEnx7MBxuACYXMtk1aPd6F6tLNptwz/HByMSXfH7P720YZ2kPQThIwa1KK6
         n8cTLUaPifZHFxVwyOSc+bpAw6RH/PQiN3+wI4mfEg7+yO4dSuOeGH6abSK64vM675iS
         1yqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YheD8PJ4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id d10si327317ioi.0.2021.04.29.11.47.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Apr 2021 11:47:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id c12-20020a4ae24c0000b02901bad05f40e4so14912875oot.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Apr 2021 11:47:00 -0700 (PDT)
X-Received: by 2002:a4a:96e3:: with SMTP id t32mr1153302ooi.14.1619722020332;
 Thu, 29 Apr 2021 11:47:00 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
In-Reply-To: <m11rat9f85.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Apr 2021 20:46:48 +0200
Message-ID: <CANpmjNNeH7+7H3y-5BCNGx+Yo11HG-F3M5TLqCAXd11Up5PTWA@mail.gmail.com>
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Florian Weimer <fweimer@redhat.com>, "David S. Miller" <davem@davemloft.net>, 
	Arnd Bergmann <arnd@arndb.de>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux@vger.kernel.org, 
	linux-arch <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-api@vger.kernel.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YheD8PJ4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as
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

On Thu, 29 Apr 2021 at 19:24, Eric W. Biederman <ebiederm@xmission.com> wrote:
[...]
> > Granted, nobody seems to have noticed because I don't even know if these
> > fields have use on sparc64. But I don't yet see this as justification to
> > leave things as-is...
> >
> > The collateral damage of this, and the acute problem that I'm having is
> > defining si_perf in a sort-of readable and portable way in siginfo_t
> > definitions that live outside the kernel, where sparc64 does not yet
> > have broken si_addr_lsb. And the same difficulty applies to the kernel
> > if we want to unbreak sparc64, while not wanting to move si_perf for
> > other architectures.
> >
> > There are 2 options I see to solve this:
> >
> > 1. Make things simple again. We could just revert the change moving
> >    si_addr_lsb into the union, and sadly accept we'll have to live with
> >    that legacy "design" mistake. (si_perf stays in the union, but will
> >    unfortunately change its offset for all architectures... this one-off
> >    move might be ok because it's new.)
> >
> > 2. Add special cases to retain si_addr_lsb in the union on architectures
> >    that do not have __ARCH_SI_TRAPNO (the majority). I have added a
> >    draft patch that would do this below (with some refactoring so that
> >    it remains sort-of readable), as an experiment to see how complicated
> >    this gets.
> >
> > Which option do you prefer? Are there better options?
>
> Personally the most important thing to have is a single definition
> shared by all architectures so that we consolidate testing.
>
> A little piece of me cries a little whenever I see how badly we
> implemented the POSIX design.  As specified by POSIX the fields can be
> place in siginfo such that 32bit and 64bit share a common definition.
> Unfortunately we did not addpadding after si_addr on 32bit to
> accommodate a 64bit si_addr.

I think it's even worse than that, see the fun I had with siginfo last
week: https://lkml.kernel.org/r/20210422191823.79012-1-elver@google.com
... because of the 3 initial ints and no padding after them, we can't
portably add __u64 fields to siginfo, and are forever forced to have
subtly different behaviour between 32-bit and 64-bit architectures.
:-/

> I find it unfortunate that we are adding yet another definition that
> requires translation between 32bit and 64bit, but I am glad
> that at least the translation is not architecture specific.  That common
> definition is what has allowed this potential issue to be caught
> and that makes me very happy to see.
>
> Let's go with Option 3.
>
> Confirm BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR are not
> in use on any architecture that defines __ARCH_SI_TRAPNO, and then fixup
> the userspace definitions of these fields.
>
> To the kernel I would add some BUILD_BUG_ON's to whatever the best
> maintained architecture (sparc64?) that implements __ARCH_SI_TRAPNO just
> to confirm we don't create future regressions by accident.
>
> I did a quick search and the architectures that define __ARCH_SI_TRAPNO
> are sparc, mips, and alpha.  All have 64bit implementations.  A further
> quick search shows that none of those architectures have faults that
> use BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR, nor do
> they appear to use mm/memory-failure.c
>
> So it doesn't look like we have an ABI regression to fix.

That sounds fine to me -- my guess was that they're not used on these
architectures, but I just couldn't make that call.

I have patches adding compile-time asserts for sparc64, arm, arm64
ready to go. I'll send them after some more testing.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNeH7%2B7H3y-5BCNGx%2BYo11HG-F3M5TLqCAXd11Up5PTWA%40mail.gmail.com.
