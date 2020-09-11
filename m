Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRHZ5X5AKGQE5DB7XOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F015E266054
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 15:33:57 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id a6sf8994161ybr.4
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 06:33:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599831237; cv=pass;
        d=google.com; s=arc-20160816;
        b=xq1ahVGS2OqlkUa8Bt/j3BWjYOuxaGe1lcK/clkP3/iGxZUiSJ6kHT8KpKDJSYC0JQ
         jc4kQdHGO+rtKfN/M/Vo4FvDL8EnjGevFX+vzPSQN8GBWISkVylWH2Y1cD+Z2hzJLGnn
         yHnSaDOPSbto/pi3BvOvDS9ck+ouilXnzryUEc5PLS3MGq0NPgkwiAelWUmXs9quMmbz
         jY+LVUkXXj/1VN6j69IWLNzM9p+F7AZcW+8qpV5XQAt4/zgVn4WzEmLd4HqC5zc9Qh3R
         pj0T9V8+r8bhsFX1fBVcLsqTFLwdzpCQzyXOOjCYTS/SY3wjxcsj5wHpWja+sSCT8WU8
         hG/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KGP30NR9K+YXQ5evOKnNtkS67w/JxQWQXWqDMpTm7Hw=;
        b=GvDclv/QjSYC6iMx2TMSWcVH3ZTsrBZnLkH3GhDSRiZSPRYdiTMgs10rjhRech4ioX
         M9QU4JBBJ14SA9UCWD8SPsnWcLobbuSh3dea3qktuJ6qJ9GWE/DonBBis/6rOgXnlH+2
         hJdzIMBnmrlrCPqAQ2+f55c7D6AQegR6nsvZP0kI5mNzeHcOrsHAMPzE++v+gXp5DKdS
         w15GqvRIsWU6YtQWKy5KvbSXC168qe/u7EdPUVskj6Q/fzgcKWQyspz19Zq2YMuSL5d2
         vkLP8yajqpfoQ3l6TDbg5fWMK1xSJQV0dMNfZ8GNw3tnU/MqU6CWw2reMxxfRjThEVnB
         kTkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cL1oEi6G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KGP30NR9K+YXQ5evOKnNtkS67w/JxQWQXWqDMpTm7Hw=;
        b=GTCu5ssMGhgxWPpyj/pIuwsxwCGQQSNnsDsfOPKOm5zNEmz7UcVkyMJvt9WdSsHVE4
         Dglj5pG1lLWk1FYTaegCm3PweRLwD9644Rydq7EPbcPanKiFSseD5TS8FIG1t0fTy5vL
         IUvxIr72nwCQqXEAQxgbc9Qvh+ZkiOjPHNLXNGQ3uLronTFgQLaV3K/12MQfgKvYfhWs
         uWMb8/cCrmbr5Y+8oSfLCR5VzKdLw0LpJw12lL3mxbZCcH45LsEAJQZGD2GPxizt+75N
         hpl9TgmuO8hN1oSQhQJXF46aHe2UDZXr/lgW2DM2mmgwZkKZvzMg+5qzqpRBd9MOpJTT
         4Tng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KGP30NR9K+YXQ5evOKnNtkS67w/JxQWQXWqDMpTm7Hw=;
        b=KbuprUiewfZIF59IDFBgr+9ndltkiOPaiwfoUdVyC4GrRrgB0zyP6zBK+XzOwkOmew
         +sz7SoEVUvyL10ntYnS596VtQXpfu6eTW7ewQqpK5U17xaOrdnjUrKbI9zq71OIHXW+Q
         kqwTMNmrdi+ExsSlWKVh8PxpPP0j+XZHii5hKb/36PcHyEhCq1N9KE0W789Y0jYxe2rv
         W7ZbrTo8aR9qKWGoYcdQNWSbYMoq2m2C9Fc7hyDn9AFbHTj05SuRUjrUP7znb52OqEGV
         SWV5RsazvNTSBrCNJ2DW687Sofi+nQrfGWtG5Z/TfD9Vk58ybjIiiiHqz6eeh+VPI1ms
         1iSg==
X-Gm-Message-State: AOAM532oO2QzGfejwzIi4KXlrPR0khedJwxAHsnI9MXClextv/WerlAY
	5Zo7SgaPKl4vsjEqhm9FKRs=
X-Google-Smtp-Source: ABdhPJxnjHbryNP2OtXpZgmaQs+WAl2sbAe/P3M+NGgWwrzRe72fqihnO298+EI4mygJRQNJSOaISQ==
X-Received: by 2002:a25:4608:: with SMTP id t8mr2574203yba.164.1599831236896;
        Fri, 11 Sep 2020 06:33:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:68c4:: with SMTP id d187ls976992ybc.1.gmail; Fri, 11 Sep
 2020 06:33:56 -0700 (PDT)
X-Received: by 2002:a25:d4ce:: with SMTP id m197mr2537732ybf.224.1599831236411;
        Fri, 11 Sep 2020 06:33:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599831236; cv=none;
        d=google.com; s=arc-20160816;
        b=wkewOJ5XXNHss1LzkYB5Hu1TukScLxmcmpwn6uJCbtovZv5nZsm/o+tDd13nww1Ide
         J4hWKAZQSBsExXFMpTspbJ+bp704VOevNkvH4cH0FPW7r3IG3oqRlmHKOkBkqAZF17tZ
         SGGvFao2PbGoo6wIs1KHB+t9THyNAGRj2fmsfFf2e2zfeNeZRTVQjwn+wYEZZ9BJB9SJ
         Z+iyIjF41sWgVzNV0toWL2VUe4MAzBt3hXmJOievUWL/UJt/rk88Tl7GpJ6u5U+SXuor
         3cw+M8fWiyv4+AVecwqWZNnWmldzQm6xiXuvLJLw2esZqbHGgDflZKGR/Fjnj7Fvj09T
         GftA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TpsoM88cyk0U9ujavsoiNiP/xNpunXVnqQMw3rUrW70=;
        b=MDmZvnCDGwSYusZMjz5hE0WPHjlnDrPNOw+L+VhV5QGUbfhzYPqvCrbNoqjQOpKTQJ
         z1FpDKc6cZdO5MMymHSMsUfttKlIuBIdKKOhdLnjk8CAnRSdOXbcyIy2yeTCtAkRnnHX
         S2izDcyXzrGtuQDeruUk1W/IMfKaasaBuiCSsHB2hoqCBX4TflnRMY5YipHfgFvCOqQw
         xKQM+Ddzp6crFIKPPGk1CUSoYqdgbBzanCeYy6db3vG2/eFxcotahZz9C7oAmE02UrJb
         CIz0dH6StAfidr+lF67dXj9pTM/AyAgJqoRXyy/IO1RVYF8bdI67wOBfXKIAMTpymyrF
         HZbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cL1oEi6G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id x125si135264ybg.1.2020.09.11.06.33.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 06:33:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id m7so8015527oie.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 06:33:56 -0700 (PDT)
X-Received: by 2002:aca:54d1:: with SMTP id i200mr1268021oib.172.1599831235876;
 Fri, 11 Sep 2020 06:33:55 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com> <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
 <20200908155631.GC61807@elver.google.com> <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
 <CANpmjNO7XwhefA+NKszVkNqj8a60QY45n-=EUtGns+ysNYV9mQ@mail.gmail.com> <CACT4Y+YSQDjEh6+XMXiHvMaKAT8bA=JkC8xY3AXfcSk+f9yR+g@mail.gmail.com>
In-Reply-To: <CACT4Y+YSQDjEh6+XMXiHvMaKAT8bA=JkC8xY3AXfcSk+f9yR+g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 15:33:44 +0200
Message-ID: <CANpmjNNWOVi317bF_E=QdcSSd5x6Dfk=+nECA9VnZSLGMKigYQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=cL1oEi6G;       spf=pass
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

On Fri, 11 Sep 2020 at 15:10, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Fri, Sep 11, 2020 at 2:03 PM Marco Elver <elver@google.com> wrote:
> > On Fri, 11 Sep 2020 at 09:36, Dmitry Vyukov <dvyukov@google.com> wrote:
[...]
> > > By "reasonable" I mean if the pool will last long enough to still
> > > sample something after hours/days? Have you tried any experiments with
> > > some workload (both short-lived processes and long-lived
> > > processes/namespaces) capturing state of the pool? It can make sense
> > > to do to better understand dynamics. I suspect that the rate may need
> > > to be orders of magnitude lower.
> >
> > Yes, the current default sample interval is a lower bound, and is also
> > a reasonable default for testing. I expect real deployments to use
> > much higher sample intervals (lower rate).
> >
> > So here's some data (with CONFIG_KFENCE_NUM_OBJECTS=1000, so that
> > allocated KFENCE objects isn't artificially capped):
> >
> > -- With a mostly vanilla config + KFENCE (sample interval 100 ms),
> > after ~40 min uptime (only boot, then idle) I see ~60 KFENCE objects
> > (total allocations >600). Those aren't always the same objects, with
> > roughly ~2 allocations/frees per second.
> >
> > -- Then running sysbench I/O benchmark, KFENCE objects allocated peak
> > at 82. During the benchmark, allocations/frees per second are closer
> > to 10-15. After the benchmark, the KFENCE objects allocated remain at
> > 82, and allocations/frees per second fall back to ~2.
> >
> > -- For the same system, changing the sample interval to 1 ms (echo 1 >
> > /sys/module/kfence/parameters/sample_interval), and re-running the
> > benchmark gives me: KFENCE objects allocated peak at exactly 500, with
> > ~500 allocations/frees per second. After that, allocated KFENCE
> > objects dropped a little to 496, and allocations/frees per second fell
> > back to ~2.
> >
> > -- The long-lived objects are due to caches, and just running 'echo 1
> > > /proc/sys/vm/drop_caches' reduced allocated KFENCE objects back to
> > 45.
>
> Interesting. What type of caches is this? If there is some type of
> cache that caches particularly lots of sampled objects, we could
> potentially change the cache to release sampled objects eagerly.

The 2 major users of KFENCE objects for that workload are
'buffer_head' and 'bio-0'.

If we want to deal with those, I guess there are 2 options:

1. More complex, but more precise: make the users of them check
is_kfence_address() and release their buffers earlier.

2. Simpler, generic solution: make KFENCE stop return allocations for
non-kmalloc_caches memcaches after more than ~90% of the pool is
exhausted. This assumes that creators of long-lived objects usually
set up their own memcaches.

I'm currently inclined to go for (2).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNWOVi317bF_E%3DQdcSSd5x6Dfk%3D%2BnECA9VnZSLGMKigYQ%40mail.gmail.com.
