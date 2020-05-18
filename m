Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYU4RP3AKGQEWPY4KFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 733D61D8369
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 20:05:23 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id w14sf1026932ljw.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 11:05:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589825123; cv=pass;
        d=google.com; s=arc-20160816;
        b=dGHhvErYHJStzL9joGT0XGFnwuMomRaMubZTYChwTn0WZHzLBEp/9Vciz7xqqAWpvQ
         pO/sMlzLvX02nJYoxyBac2r+AMz5+TFwxtV/kIdepWUmEGruA8gdp7sBM5XQz+TxFnW2
         eQjacM6rD8u9d9d3JXj9U+V+fitYuPJY7qC87mtDtJKByxIh+TQl2xkJGdf9shnywfpo
         mdAmVLGebs62a6QhwJrIhR/4G2lPgL7gNvKsbP9gVjBPUbRbU9dbbNZGcX2sPr9QJVcP
         CoB5v99W3zdPwWlaLTDD2WFX43Ng7c/mWU5DN7eDkDBXKw2S3IUxUoJBw6N5gzGuwJVJ
         bDqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ChKsD4a6DS6RNDkiGizI08PnMPAexN2ahfPkupaIItc=;
        b=ouVmoe0ktg9q7iF1946z+f6NTlelVBPbjxNOeyZO8F7D+B/jsIj6qM2GyzFHZu7KZD
         UB0OytBSmw5loor6aVSolpAq8GCRlsZtNVYIQjwHlHYWUIIGH2XS/Gzm4PilyIq7MkIW
         K5EV2KxouiYHZ0Gk5LNki3JaGEEcMsAQ8nxgZY11ZVMel90/TXhuUhtM5Zvqux2It/TR
         9t2F3HfI0U4OJAI0hhqvM7XtAXvIsu3wOT8RATxo3TVmBrEXgfNcsaWlO0wGMGhvvdha
         HsfL0W0k6kTgTsIqEFU88K23UmUCWY0nI2GpD9mMtWUKKwQcVMn/A+ZxYFc3MDInT1ES
         WwOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z3ybWwqd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ChKsD4a6DS6RNDkiGizI08PnMPAexN2ahfPkupaIItc=;
        b=jWyJW9HRE2A0R7oywJjikW6GE5s1ZXOtCMRLTvFb4Qhk9ZYWiRqvJIIkcJbRKv8ePz
         lo/JVCRmv2lO8tEuY5RcDVhxlXLEm5f3DxyK98t174nUE9KprEB3mqs/ejdRVAVrynRK
         se37V+dEmkRGGD23O9eKGU1Jyg9Rjc+/l7n3/n78/GZvNoJhhUEAu5J+guJb0miwO65p
         UM+iTgrObDzufgVijK/cdjJPN3dfjIKQF282wo/KUDyqjnGcDUArI/LFW3q8o0VNQHQb
         8pgaH/9xl95ut9h9ggOb8V8LzbaK0X2bXIJlyl+SZ6kMD7ovSFu2mGsLcZbZ914wZUKh
         WzFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ChKsD4a6DS6RNDkiGizI08PnMPAexN2ahfPkupaIItc=;
        b=OA1xAl1jbbaMJJoIYD6CRlwudvXQiqYGH/jOx1BMBiT6gdyB4Rtq2CE3WBumlAN4Jm
         r9UEbmJmUhe5uVb/3GDL2WSr+NFAbnNCO8RpSnSBhQBMD/Ze4evdkJvhPTQjpPH5yKyF
         kXjGf+i8HtRmdP0JK4MQ8eOwaU9Yr6mF6Rx98iSC4Zi2kxcDCJUxpVpP3ROJuxXcBbbU
         bvSnvKqfsfvv/80HKZMQXveKed7Mb5UwR4/U56bAVgsYJ2amgsBYlORbYJ5yCrn1wGej
         d/w7JoI6qfsWtBoE5dEkHT2vqIjaIkd/Zcir8CujdFmehEXNtrfT56FOY4yBvl/ZCJ5k
         Xfew==
X-Gm-Message-State: AOAM5310SoCkNiXsiG8wmr3FWm6gIHq7E2Gqy8kXamIOB7WFfh91Qcy6
	lp/zgsACNGPVRR9s/l2EcgM=
X-Google-Smtp-Source: ABdhPJzP52TKS6TBS/8fkKFOqdVcAq9lq/ngVroUe4QsYVtM/kF4ygUBcL5g3yuq2LWaeUD5hA2tgQ==
X-Received: by 2002:a2e:b4e3:: with SMTP id s3mr10976016ljm.11.1589825122908;
        Mon, 18 May 2020 11:05:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5de8:: with SMTP id z8ls1577045lfq.4.gmail; Mon, 18 May
 2020 11:05:22 -0700 (PDT)
X-Received: by 2002:a19:c04:: with SMTP id 4mr12535688lfm.17.1589825122181;
        Mon, 18 May 2020 11:05:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589825122; cv=none;
        d=google.com; s=arc-20160816;
        b=1G2FfVOOyeLpXM1l7mn8WbHSxOzZEieFlSJ3jdcPTFtyjFj0AzH9ThgJ3jsidzQpfK
         +3T9oJ3FvD/mapvaDODTHfepldAo2gWdXTgcaJ5i64sSx02RJswddQ3l3WrpyYp8ncZv
         E9lTP1T9rUzmjC7wWU0uOHeJDlA2W3kv7WveARTpzAoz9Fu6r4nB8aKd3UAls0/W2CS3
         dI6x+r9bjEfD2DRrRKKHUm7MldlC4T80WUORVg2zIx7LfFBmzPwcdfBVWYw8uTNYHh94
         gI+KldABdW3ltYF5UCF/Sw6C08W/7OKqAIclAnK/IDa1w0A5XeSXbGmyk1oAJUFKK4jx
         ZkcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=A1Of05sXfKMuAB6KElfJxv+kaM0ti5HUQFDuIZAc/hE=;
        b=lEDBInGQvHHJ9+gMK2MXBTpq1gYopFgCG/N8kZTVn5Il48ngdJ9wxYcHuKSdR+jelU
         kel1bEiw6EjXBGwZSvqkVAMn7BdAI2NnLcWK+zwxAZEgRMSYpDirGdYQUaIl6V8XEK/P
         2t9qhXSrS4q8nDuU28IcoC0lRPzvGo7upTIh0LFVj2z4EKhE8bpW8nLO/A7Uan0eegqg
         mxGlPT2OQvTPfXotUlkuxsTIIFVxFUmouHSU28gbxAc6zn4ocg44Dqg6V9gESLMGsFtd
         X7rWRADrdXvpongkq1wk9guuC6MXjjRJ7uznxePOY8zl130KO0dIPzRom6lhIhHQcMYo
         couQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z3ybWwqd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id u25si791715ljg.1.2020.05.18.11.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 11:05:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id h4so423168wmb.4
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 11:05:22 -0700 (PDT)
X-Received: by 2002:a1c:7410:: with SMTP id p16mr627463wmc.134.1589825121166;
        Mon, 18 May 2020 11:05:21 -0700 (PDT)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id l11sm457783wmf.28.2020.05.18.11.05.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 May 2020 11:05:19 -0700 (PDT)
Date: Mon, 18 May 2020 20:05:13 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Kan Liang <kan.liang@linux.intel.com>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel test robot <rong.a.chen@intel.com>,
	Peter Zijlstra <peterz@infradead.org>,
	LKML <linux-kernel@vger.kernel.org>, LKP <lkp@lists.01.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [rcu] 2f08469563: BUG:kernel_reboot-without-warning_in_boot_stage
Message-ID: <20200518180513.GA114619@google.com>
References: <20200517011732.GE24705@shao2-debian>
 <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
 <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
 <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z3ybWwqd;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Mon, 18 May 2020, 'Nick Desaulniers' via kasan-dev wrote:

> On Mon, May 18, 2020 at 7:34 AM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
> > >
> > > [+Cc clang-built-linux FYI]
> > >
> > > On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > > > Greeting,
> > > > > >
> > > > > > FYI, we noticed the following commit (built with clang-11):
> > > > > >
> > > > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > > > >
> > > > > > in testcase: boot
> > > > > >
> > > > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > > > >
> > > > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > > > >
> > > > > >
> > > > > >
> > > > > >
> > > > > > If you fix the issue, kindly add following tag
> > > > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > > > >
> > > > > >
> > > > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > > > BUG: kernel reboot-without-warning in boot stage
> > > > >
> > > > > I am having some difficulty believing that this commit is at fault given
> > > > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > > > for his thoughts.  Especially given that I have never built with clang-11.
> > > > >
> > > > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > > > rcu_init().  Might clang-11 have objections to early use of this macro?
> > > >
> > > > The macro is a noop without KCSAN. I think the bisection went wrong.
> > > >
> > > > I am able to reproduce a reboot-without-warning when building with
> > > > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > > > (good), and found this:
> > > > - Since v5.6, first bad commit is
> > > > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > > > 'perf-urgent-2020-04-12' of
> > > > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > > > - The actual commit that introduced the problem is
> > > > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > > > Ice Lake server uncore support) -- reverting it fixes the problem.
> >
> > Some more clues:
> >
> > 1. I should have noticed that this uses CONFIG_KASAN=y.
> 
> Thanks for the report, testing, and bisection.  I don't see any
> smoking gun in the code.
> https://godbolt.org/z/qbK26r

My guess is data layout and maybe some interaction with KASAN. I also
played around with leaving icx_mmio_uncores empty, meaning none of the
data it refers to end up in the data section (presumably because
optimized out), which resulted in making the bug disappear as well.

> >
> > 2. Something about function icx_uncore_mmio_init(). Making it a noop
> > also makes the issue go away.
> >
> > 3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
> > from icx_mmio_uncores also presents the issue. So this seems to be
> > something about how/where icx_mmio_uncores is allocated.
> 
> Can you share the disassembly of icx_uncore_mmio_init() in the given
> configuration?

ffffffff8102c097 <icx_uncore_mmio_init>:
ffffffff8102c097:	e8 b4 52 bd 01       	callq  ffffffff82c01350 <__fentry__>
ffffffff8102c09c:	48 c7 c7 e0 55 c3 83 	mov    $0xffffffff83c355e0,%rdi
ffffffff8102c0a3:	e8 69 9a 3b 00       	callq  ffffffff813e5b11 <__asan_store8>
ffffffff8102c0a8:	48 c7 05 2d 95 c0 02 	movq   $0xffffffff83c388e0,0x2c0952d(%rip)        # ffffffff83c355e0 <uncore_mmio_uncores>
ffffffff8102c0af:	e0 88 c3 83 
ffffffff8102c0b3:	c3                   	retq   

The problem still happens if we add a __no_sanitize_address (or even
KASAN_SANITIZE := n) here. I think this function is a red herring: you
can make this function be empty, but as long as icx_mmio_uncores and its
dependencies are added to the data section somewhere, does the bug
appear.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518180513.GA114619%40google.com.
