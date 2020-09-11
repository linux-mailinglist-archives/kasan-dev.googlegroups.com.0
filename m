Return-Path: <kasan-dev+bncBCMIZB7QWENRBKHO5X5AKGQE7CPNEVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A4E266007
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 15:10:01 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id u18sf8937449ybu.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 06:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599829800; cv=pass;
        d=google.com; s=arc-20160816;
        b=W50Fc82M09HsTzWMW9Jo/6KrckNBPbiINnP6lEWup0xzf0+GvoG5FzpE+zq5dhF7IB
         /e2pOxXCplI1+AUKBxEnpcKBVIUckByqtQV0w55jfhntBNZN+Z8q5acbPh5u9+KrIDX5
         +3dPXOA0VqAMNNNTAurGFrtVwOB+l38w/BxlMqfJHMTN5goK+gB/uyDAZvd90KBqxx/I
         GOhGNyVCfhKXVqRXZOGJmF9FDCDyfB9cOt8HT7JwCcUV9ESF2a1LEQ4dCH7rzXFapQYV
         NYDZ39kkVjfpK7Of8TAKePlsBR8/mptEbbkO3waNlrxP1oU79ypeL4TpHMI5pfB/XOhv
         PiPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NWGOrMyWIOxxp4Cg8Gw/f2RPRv+qfTb5uIDLsMWTpzA=;
        b=MUrGB8KJLNXmI9iBfwC1Kozv8LVqqCSInNw3DHndZev6HtIpIWxqN+FgsMWH3PkmX/
         H4lxGyWlgbm1YlLGbtmBxqQYmGu2DOzDS1Z41uqsiq/W1juzc4Wx+jzLccj9djV0m2x+
         U51KtctHM/peLuPDbDzCBsx9V06A/QaQ/VkviVx9a0wyOkY+USdJmOxUv9Hy1t7T0ZWX
         RrdIJWmJHpjEvkLcbR+S0AVDkGQyeABeA2By9ytitDIGT+R8nIvWQLlvH91N5jDLXWH1
         yYdFU4XUGlOkrw0M3LiQC8eZNmAIzyFbI8LuIbjHn5R+o1jC9DR+QHP7YJkb95707TjE
         34zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oMdmCnlt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NWGOrMyWIOxxp4Cg8Gw/f2RPRv+qfTb5uIDLsMWTpzA=;
        b=sH8Dvoyfqg2M/kWeT7KNdMd55ZN6TPKs2mDqhF2+9gOr/vBWg/hrwZ2oTv/CZLSZlW
         GqYx6JQPC2bfpvH3SQMXuWv5M4mdE3kkgkV9+OXXFl1OXYhFwPDm2RuMwfYIH0nhpZKi
         S/DbdnCGivgSj2UeDFFuOdF6g7jX9FcmYy2HhL6Jn0f37nVU0RQhMrto1mXPLW55qDQI
         r60ZH5NibZHWcc1iR/6lzsqd/I7qWrySC5OaWQqHR6lhEM4oWdPSgBJ36cga7hjh/5jm
         jHeetZO2K6KwcoLAPOqkLz7Nr+rOkZxbPLh9R/tLatzwVDxpsTSdN9L9lbIR4OYPeYpT
         BPSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NWGOrMyWIOxxp4Cg8Gw/f2RPRv+qfTb5uIDLsMWTpzA=;
        b=Z/O4+UAqvEI99YZh+Rrvy6d+0ye6WVWjYXm4nJ8AtHfDFl35XG8NUEB465l4mz7jmF
         m404/bTAb74jQqTtH5z1OE26Un75UVTY8bNiGiU2HYpSTeuApn8DBdDMraFLp13i6fSo
         fiYjLdVdRB8HSkE7lzD6ccb1ndGHENS6RMsbbJD/c7awmH6sn2ItvKb62vXnWPBxNgRT
         oxAFmTYcf0I9MquwJJsfZaGkaUdHyVh0Yi2LynPZzz2yPbE3Gxi7eBxollUzLTXQ3Ue3
         pkQ9xQUX64u3OBlisIKxy9kLenmixcF5DXYD3mtwtgEIkfXGLlK9K/vKprfsOvpmHmn/
         ijVw==
X-Gm-Message-State: AOAM5339VDUAg1BIe1RHstOMkIbQnrRDsRUlfCaltEmXqusmSWUUPXG2
	P9Wcf1lrHUFxHu9mkw7eGxg=
X-Google-Smtp-Source: ABdhPJyQJTXgeJRJQy2vma2MXqsXclT+/IvH+QrBnxFkcG2JfdxszTZmz5wAl1TbRTXCBsrgtSG1aA==
X-Received: by 2002:a25:a125:: with SMTP id z34mr2275759ybh.390.1599829800631;
        Fri, 11 Sep 2020 06:10:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c550:: with SMTP id v77ls930737ybe.8.gmail; Fri, 11 Sep
 2020 06:10:00 -0700 (PDT)
X-Received: by 2002:a25:6b4e:: with SMTP id o14mr2281843ybm.23.1599829800184;
        Fri, 11 Sep 2020 06:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599829800; cv=none;
        d=google.com; s=arc-20160816;
        b=ycf/zC0LQscZSGq2wecz7LyOD+wayE47aD68KM8My9Y41trTByPqOzUlk7jPQ/2JIb
         fkxPyH22tLSQ7w/oMEyfxb+1wfYOzi2oqJ+WD4reG+tn3dZ9YcsHzL5vTTKVlQecMjOf
         Qu/5mG9WbQCqMPU6wWXI+5ERHIAwsZbxWXHfDYCWeYBEC1joI8TUFRNqNKODtLLtKJnO
         uAAZvhZBUET8gIS9kQ1uDxYiEMets4xEjL5dmZHEHIaB6hdsTxHJ6oVv0WVqUhTMGUEL
         mnV81qCmfGhkMbQ9BoqL5Q2TLTkr/BBFNRvspgEVAioKATXzp4uNGSm1ambGdyRC8T3k
         Y0iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cdR3w46F1Dqn8ODmMx+KwCNXsWHRoDripL6i3lIvacY=;
        b=bApNDwfdRb8JsXTBP99vMXFGZETscrat3OwcIQh5Or6jWN9+S5U1yA1i0pBb2TIGv3
         UcgfnUcJ6qV+lfmyC2AwciBrHIiva2V6KGh/VekcJogs+rwwpduTarBaGw33E969xays
         +UkoARDIAiRKaMcqoTkcRW0m041xzjN4DAseZUplIPTIdDoj7sq1dkEOWTRvyAzdSJE4
         VmK7rJOa3OV2XRLSJ6AJN/U1mxTZmZt2pkzLO13s2p4ZEpuSMspGzQw0c9kqp3CvDaA/
         Ng+mFs9DGGOjlN91u8ks3lGOwJvrGUGlvWDAHkMtoUadvDT2uwmvGb1zpnn/2XuuxiQa
         GxlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oMdmCnlt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id v129si111918ybe.2.2020.09.11.06.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 06:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id e7so7734818qtj.11
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 06:10:00 -0700 (PDT)
X-Received: by 2002:ac8:4658:: with SMTP id f24mr1770470qto.158.1599829799395;
 Fri, 11 Sep 2020 06:09:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com> <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
 <20200908155631.GC61807@elver.google.com> <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
 <CANpmjNO7XwhefA+NKszVkNqj8a60QY45n-=EUtGns+ysNYV9mQ@mail.gmail.com>
In-Reply-To: <CANpmjNO7XwhefA+NKszVkNqj8a60QY45n-=EUtGns+ysNYV9mQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 15:09:48 +0200
Message-ID: <CACT4Y+YSQDjEh6+XMXiHvMaKAT8bA=JkC8xY3AXfcSk+f9yR+g@mail.gmail.com>
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Dave Hansen <dave.hansen@intel.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oMdmCnlt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Fri, Sep 11, 2020 at 2:03 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 11 Sep 2020 at 09:36, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Tue, Sep 8, 2020 at 5:56 PM Marco Elver <elver@google.com> wrote:
> > > On Tue, Sep 08, 2020 at 05:36PM +0200, Vlastimil Babka wrote:
> [...]
> > > > Hmm did you observe that with this limit, a long-running system would eventually
> > > > converge to KFENCE memory pool being filled with long-aged objects, so there
> > > > would be no space to sample new ones?
> > >
> > > Sure, that's a possibility. But remember that we're not trying to
> > > deterministically detect bugs on 1 system (if you wanted that, you
> > > should use KASAN), but a fleet of machines! The non-determinism of which
> > > allocations will end up in KFENCE, will ensure we won't end up with a
> > > fleet of machines of identical allocations. That's exactly what we're
> > > after. Even if we eventually exhaust the pool, you'll still detect bugs
> > > if there are any.
> > >
> > > If you are overly worried, either the sample interval or number of
> > > available objects needs to be tweaked to be larger. The default of 255
> > > is quite conservative, and even using something larger on a modern
> > > system is hardly noticeable. Choosing a sample interval & number of
> > > objects should also factor in how many machines you plan to deploy this
> > > on. Monitoring /sys/kernel/debug/kfence/stats can help you here.
> >
> > Hi Marco,
> >
> > I reviewed patches and they look good to me (minus some local comments
> > that I've left).
>
> Thank you.
>
> > The main question/concern I have is what Vlastimil mentioned re
> > long-aged objects.
> > Is the default sample interval values reasonable for typical
> > workloads? Do we have any guidelines on choosing the sample interval?
> > Should it depend on workload/use pattern?
>
> As I hinted at before, the sample interval & number of objects needs
> to depend on:
> - number of machines,
> - workload,
> - acceptable overhead (performance, memory).
>
> However, workload can vary greatly, and something more dynamic may be
> needed. We do have the option to monitor
> /sys/kernel/debug/kfence/stats and even change the sample interval at
> runtime, e.g. from a user space tool that checks the currently used
> objects, and as the pool is closer to exhausted, starts increasing
> /sys/module/kfence/parameters/sample_interval.
>
> Of course, if we figure out the best dynamic policy, we can add this
> policy into the kernel. But I don't think it makes sense to hard-code
> such a policy right now.
>
> > By "reasonable" I mean if the pool will last long enough to still
> > sample something after hours/days? Have you tried any experiments with
> > some workload (both short-lived processes and long-lived
> > processes/namespaces) capturing state of the pool? It can make sense
> > to do to better understand dynamics. I suspect that the rate may need
> > to be orders of magnitude lower.
>
> Yes, the current default sample interval is a lower bound, and is also
> a reasonable default for testing. I expect real deployments to use
> much higher sample intervals (lower rate).
>
> So here's some data (with CONFIG_KFENCE_NUM_OBJECTS=1000, so that
> allocated KFENCE objects isn't artificially capped):
>
> -- With a mostly vanilla config + KFENCE (sample interval 100 ms),
> after ~40 min uptime (only boot, then idle) I see ~60 KFENCE objects
> (total allocations >600). Those aren't always the same objects, with
> roughly ~2 allocations/frees per second.
>
> -- Then running sysbench I/O benchmark, KFENCE objects allocated peak
> at 82. During the benchmark, allocations/frees per second are closer
> to 10-15. After the benchmark, the KFENCE objects allocated remain at
> 82, and allocations/frees per second fall back to ~2.
>
> -- For the same system, changing the sample interval to 1 ms (echo 1 >
> /sys/module/kfence/parameters/sample_interval), and re-running the
> benchmark gives me: KFENCE objects allocated peak at exactly 500, with
> ~500 allocations/frees per second. After that, allocated KFENCE
> objects dropped a little to 496, and allocations/frees per second fell
> back to ~2.
>
> -- The long-lived objects are due to caches, and just running 'echo 1
> > /proc/sys/vm/drop_caches' reduced allocated KFENCE objects back to
> 45.

Interesting. What type of caches is this? If there is some type of
cache that caches particularly lots of sampled objects, we could
potentially change the cache to release sampled objects eagerly.

> > Also I am wondering about the boot process (both kernel and init).
> > It's both inherently almost the same for the whole population of
> > machines and inherently produces persistent objects. Should we lower
> > the rate for the first minute of uptime? Or maybe make it proportional
> > to uptime?
>
> It should depend on current usage, which is dependent on the workload.
> I don't think uptime helps much, as seen above. If we imagine a user
> space tool that tweaks this for us, we can initialize KFENCE with a
> very large sample interval, and once booted, this user space
> tool/script adjusts /sys/module/kfence/parameters/sample_interval.
>
> At the very least, I think I'll just make
> /sys/module/kfence/parameters/sample_interval root-writable
> unconditionally, so that we can experiment with such a tool.
>
> Lowering the rate for the first minute of uptime might also be an
> option, although if we do that, we can also just move kfence_init() to
> the end of start_kernel(). IMHO, I think it still makes sense to
> sample normally during boot, because who knows how those allocations
> are used with different workloads once the kernel is live. With a
> sample interval of 1000 ms (which is closer to what we probably want
> in production), I see no more than 20 KFENCE objects allocated after
> boot. I think we can live with that.
>
> > I feel it's quite an important aspect. We can have this awesome idea
> > and implementation, but radically lower its utility by using bad
> > sampling value (which will have silent "failure mode" -- no bugs
> > detected).
>
> As a first step, I think monitoring the entire fleet here is key here
> (collect /sys/kernel/debug/kfence/stats). Essentially, as long as
> allocations/frees per second remains >0, we're probably fine, even if
> we always run at max. KFENCE objects allocated.
>
> An improvement over allocations/frees per second >0 would be
> dynamically tweaking sample_interval based on how close we get to max
> KFENCE objects allocated.
>
> Yet another option is to skip KFENCE allocations based on the memcache
> name, e.g. for those caches dedicated to long-lived allocations.
>
> > But to make it clear: all of this does not conflict with the merge of
> > the first version. Just having tunable sampling interval is good
> > enough. We will get the ultimate understanding only when we start
> > using it widely anyway.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYSQDjEh6%2BXMXiHvMaKAT8bA%3DJkC8xY3AXfcSk%2Bf9yR%2Bg%40mail.gmail.com.
