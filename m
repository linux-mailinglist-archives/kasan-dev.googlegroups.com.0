Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBOP5X5AKGQEUTLCA5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D53D265F2C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 14:03:18 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id j125sf2769843vsc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 05:03:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599825797; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQR+g5FHT0920i4RKqz9rmt8FOJM6cIfDD9f8IGiFs8IOBKfiiU23GdUEQ83ucXy74
         bH20hvIE4XkXj6tE/0PsoGkXnamxAOuacLn7OpySJvSNJbQ4sIetQmUMyXTf8UmKdHcV
         wP0Pb8/u9iSIwgG9B9ULLmVnSOjf3MtE7fB5RPQgHoc19rBG8ftCyd7+PhuX2iz3gOFS
         DEMVy4Tnf9fo52G0Us46rO7+dgDDB2lzle2jtyGpGEpdQqmB3XzOx7bK2SN28cpYX0fy
         kjI9zSvl60/pcGd3i6S9LLc5ucuVgMREkybyi3ggS8V4eEwn1TWokKTDrn5698QClSvK
         +vIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TBZGLujYrEuWnkHUFPf+/5vk5BGxTsaz5h2BwE1VaMs=;
        b=NXMpM0bpmL3JaqUs0b5NufZZGXcPPPU/yzApLkkUmwRALMfto+vXsLWBQi3B3ZDdlj
         0/DPD34Lg+X5EvrUfDvq91AA8wZ6UzgAh8ohSnN2Joj8/jT6nbBCuzgCs6wKDieJL6S0
         YePoZvIqH9y4XgDKBH6DnpJOHKOsBnptX5wphw3azdKgmQfyokWrV2bQhb/SEyaCe7GB
         N0u4uNtuCm7qoxs4vMomVRbaI36oQRxRhkxIQAJ1A3PcRrgXA+PM+k5YbUlFC2HDqiXl
         KMSJvYTtujZs7ZzxmBdC9n4qnZjVjUV6ScLMuZNOU+nKW+cyTzOS5LaU2RXbw0auRffk
         TtfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a620psJv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TBZGLujYrEuWnkHUFPf+/5vk5BGxTsaz5h2BwE1VaMs=;
        b=ezNgc5swWsTrXyBJz9J47jogazBR4gZt8+A1kr5Tk6mDaQSLIX+KPcIbKvKqh0G2uK
         Qo3qtXqqCqePrtuJwH+YUL6GmHwG8AgrQ8QCWOpt8Ghxy59PRSXxNzXlNAXb4tE2eFVf
         ivx3kfx0z9rKM2sRKK6LH96sqaxDS6lQUN6FE+9u9FGdNanLFxiSj7lpvI+Qrx03KAvU
         D6gvSxkW6uF66diaO/CpJDywtAoOTqtl/5I+qnAcRgsWxgLwyfi54e3Iq6WYHJe/jeWD
         CWaHk7BoP5GZVMVFOc3xLpibdjM5tfBNixDfSI16IO/WJqZ+OT7Yk5eWGTdViLOnnKLe
         GeKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TBZGLujYrEuWnkHUFPf+/5vk5BGxTsaz5h2BwE1VaMs=;
        b=Ho18tb9QTnwb/OOXP7LoGQhn+xDPX6TU0XfwjcGiXbs3+Sm2aHhV/HDMLUGlUH5XoB
         Ti4XnjnW4lkcIM6XVW6ZSd3h8GIfJBg9RQtGxzN+zxwrh5zpNhf96eToqJlvN1l66gOQ
         Juvxc4erS4XyixHTkMgL/pQCQZve2yiAeQIr6CAnpdpfA4tEXpQjJwZ5V5aHY2+E2l3z
         wrYZfh1dSRef+k+HTVUxtl4h5LmSSO0xRApZpjYH60aWUVc0bIs9INtsQlxRkuLA67/J
         XvhwoMNhO2SGTHCy8/T/HP4bs0X6rg7ohj52cBx1kV0E689GUggpdp2WH0KBH3BB9bEG
         1wfQ==
X-Gm-Message-State: AOAM533Twmp9AjdjiDnGp82G6EhcYNiVfybnHN6NLqjvA9IN/pJ+8YW/
	XdjP4HEpD1nz+PpMryn1+qI=
X-Google-Smtp-Source: ABdhPJzRr6XfuWsKosktcCV6ZMUqrSowbW0NYrEoueoDs1BbTmYEjgAuFXgyQRPwGy4uMVdJVCwk/A==
X-Received: by 2002:ab0:4e25:: with SMTP id g37mr659506uah.106.1599825797583;
        Fri, 11 Sep 2020 05:03:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:bfcb:: with SMTP id p194ls83297vkf.8.gmail; Fri, 11 Sep
 2020 05:03:17 -0700 (PDT)
X-Received: by 2002:a1f:a4ce:: with SMTP id n197mr581525vke.25.1599825797043;
        Fri, 11 Sep 2020 05:03:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599825797; cv=none;
        d=google.com; s=arc-20160816;
        b=RHOUSR9rEjVPCxjxgTffOj1CxYHnanmS3OnWOeGhFMJZblq9ya5TIvJ5yZVOxjhaMd
         w92nqBQkVX/CyTt2kFmKkJjFygaHaygfMCvzsVt10zfKCqBj2xP1w2PkRlA59faBVd5Y
         a5flusGrL5Xz8AduNyKMT7IIZwi1hMwETZsxt2TtfLwx95evrxjCK0aiUfK36ROvrKHe
         JTTe9QMeETFVSsZ5dAtx1+6ns7BUx7++N48SOq/LxPbtRdphr7UOh9tt/+dMFktPIyRC
         N+oz43AtXaJoMSTbI9kbOSA6unRhi7LeobH8+PEHj2fmHcfddGF41oIUmMMlPYUeaIzm
         RN9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hZRenMhRkxQrqJ0KxaG3JuIL2Afy5FWfAugoFYemeVE=;
        b=G1Hok6WvQ5GIu46nFNyqPoF93+pXoOBcwNt9dIJCwpL6Ds1e7oREiGwfaoQu/A6oXg
         KJjuwY0w+ummxOjcxhKrSNoTb7tn0wkitw/ZyBWq/fd28H+DleeACEJNGMkfKqhaZpH6
         mmZDAdcfhpaY9W4kIIbt54HZh8FwyxMONITAHV3TPYWPD6srvtYe/zvKmIIV/T0nawim
         7INP7kxw0yviUKqVHeKE2NEeVU3EOaCCyFLNYwtcHBvShAqsDCUkx7f6/a6CifwJudNj
         xyQ97N1/sbM37FaQpeGb0Pn2FOSwIjiSBgTRL6/qODBMLzTPMKgOZuEoi1nIQijs/7Db
         hWxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a620psJv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id t1si149013vsk.2.2020.09.11.05.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 05:03:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id x69so9179419oia.8
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 05:03:17 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr1079246oib.121.1599825796209;
 Fri, 11 Sep 2020 05:03:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com> <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
 <20200908155631.GC61807@elver.google.com> <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 14:03:04 +0200
Message-ID: <CANpmjNO7XwhefA+NKszVkNqj8a60QY45n-=EUtGns+ysNYV9mQ@mail.gmail.com>
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Dmitry Vyukov <dvyukov@google.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a620psJv;       spf=pass
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

On Fri, 11 Sep 2020 at 09:36, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, Sep 8, 2020 at 5:56 PM Marco Elver <elver@google.com> wrote:
> > On Tue, Sep 08, 2020 at 05:36PM +0200, Vlastimil Babka wrote:
[...]
> > > Hmm did you observe that with this limit, a long-running system would eventually
> > > converge to KFENCE memory pool being filled with long-aged objects, so there
> > > would be no space to sample new ones?
> >
> > Sure, that's a possibility. But remember that we're not trying to
> > deterministically detect bugs on 1 system (if you wanted that, you
> > should use KASAN), but a fleet of machines! The non-determinism of which
> > allocations will end up in KFENCE, will ensure we won't end up with a
> > fleet of machines of identical allocations. That's exactly what we're
> > after. Even if we eventually exhaust the pool, you'll still detect bugs
> > if there are any.
> >
> > If you are overly worried, either the sample interval or number of
> > available objects needs to be tweaked to be larger. The default of 255
> > is quite conservative, and even using something larger on a modern
> > system is hardly noticeable. Choosing a sample interval & number of
> > objects should also factor in how many machines you plan to deploy this
> > on. Monitoring /sys/kernel/debug/kfence/stats can help you here.
>
> Hi Marco,
>
> I reviewed patches and they look good to me (minus some local comments
> that I've left).

Thank you.

> The main question/concern I have is what Vlastimil mentioned re
> long-aged objects.
> Is the default sample interval values reasonable for typical
> workloads? Do we have any guidelines on choosing the sample interval?
> Should it depend on workload/use pattern?

As I hinted at before, the sample interval & number of objects needs
to depend on:
- number of machines,
- workload,
- acceptable overhead (performance, memory).

However, workload can vary greatly, and something more dynamic may be
needed. We do have the option to monitor
/sys/kernel/debug/kfence/stats and even change the sample interval at
runtime, e.g. from a user space tool that checks the currently used
objects, and as the pool is closer to exhausted, starts increasing
/sys/module/kfence/parameters/sample_interval.

Of course, if we figure out the best dynamic policy, we can add this
policy into the kernel. But I don't think it makes sense to hard-code
such a policy right now.

> By "reasonable" I mean if the pool will last long enough to still
> sample something after hours/days? Have you tried any experiments with
> some workload (both short-lived processes and long-lived
> processes/namespaces) capturing state of the pool? It can make sense
> to do to better understand dynamics. I suspect that the rate may need
> to be orders of magnitude lower.

Yes, the current default sample interval is a lower bound, and is also
a reasonable default for testing. I expect real deployments to use
much higher sample intervals (lower rate).

So here's some data (with CONFIG_KFENCE_NUM_OBJECTS=1000, so that
allocated KFENCE objects isn't artificially capped):

-- With a mostly vanilla config + KFENCE (sample interval 100 ms),
after ~40 min uptime (only boot, then idle) I see ~60 KFENCE objects
(total allocations >600). Those aren't always the same objects, with
roughly ~2 allocations/frees per second.

-- Then running sysbench I/O benchmark, KFENCE objects allocated peak
at 82. During the benchmark, allocations/frees per second are closer
to 10-15. After the benchmark, the KFENCE objects allocated remain at
82, and allocations/frees per second fall back to ~2.

-- For the same system, changing the sample interval to 1 ms (echo 1 >
/sys/module/kfence/parameters/sample_interval), and re-running the
benchmark gives me: KFENCE objects allocated peak at exactly 500, with
~500 allocations/frees per second. After that, allocated KFENCE
objects dropped a little to 496, and allocations/frees per second fell
back to ~2.

-- The long-lived objects are due to caches, and just running 'echo 1
> /proc/sys/vm/drop_caches' reduced allocated KFENCE objects back to
45.

> Also I am wondering about the boot process (both kernel and init).
> It's both inherently almost the same for the whole population of
> machines and inherently produces persistent objects. Should we lower
> the rate for the first minute of uptime? Or maybe make it proportional
> to uptime?

It should depend on current usage, which is dependent on the workload.
I don't think uptime helps much, as seen above. If we imagine a user
space tool that tweaks this for us, we can initialize KFENCE with a
very large sample interval, and once booted, this user space
tool/script adjusts /sys/module/kfence/parameters/sample_interval.

At the very least, I think I'll just make
/sys/module/kfence/parameters/sample_interval root-writable
unconditionally, so that we can experiment with such a tool.

Lowering the rate for the first minute of uptime might also be an
option, although if we do that, we can also just move kfence_init() to
the end of start_kernel(). IMHO, I think it still makes sense to
sample normally during boot, because who knows how those allocations
are used with different workloads once the kernel is live. With a
sample interval of 1000 ms (which is closer to what we probably want
in production), I see no more than 20 KFENCE objects allocated after
boot. I think we can live with that.

> I feel it's quite an important aspect. We can have this awesome idea
> and implementation, but radically lower its utility by using bad
> sampling value (which will have silent "failure mode" -- no bugs
> detected).

As a first step, I think monitoring the entire fleet here is key here
(collect /sys/kernel/debug/kfence/stats). Essentially, as long as
allocations/frees per second remains >0, we're probably fine, even if
we always run at max. KFENCE objects allocated.

An improvement over allocations/frees per second >0 would be
dynamically tweaking sample_interval based on how close we get to max
KFENCE objects allocated.

Yet another option is to skip KFENCE allocations based on the memcache
name, e.g. for those caches dedicated to long-lived allocations.

> But to make it clear: all of this does not conflict with the merge of
> the first version. Just having tunable sampling interval is good
> enough. We will get the ultimate understanding only when we start
> using it widely anyway.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO7XwhefA%2BNKszVkNqj8a60QY45n-%3DEUtGns%2BysNYV9mQ%40mail.gmail.com.
