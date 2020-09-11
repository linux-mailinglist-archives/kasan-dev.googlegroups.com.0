Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GN535AKGQE6LKOR2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1518126643E
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 18:34:06 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id e6sf7029546qtg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:34:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599842045; cv=pass;
        d=google.com; s=arc-20160816;
        b=YkNJkOtNHdR/PbuzMlK7XqJPiMz7G5LsAvTbYkaHsUyWCStPkbFdODmkupULFIErz2
         5o2Vyr9x8vRYUavuGGC8LoxQShHaDiUFzlJuEoT2OixR3IrI/XkWxbQWKHnoJjPK3NsR
         cWzEp/1QptZSk8gkgyzJkaaSObzyQieFX2Gcw4T1nv8zIVr86+wHgtXJQlDXtsNQOgpO
         pnbc2NyYXcclOnLU9jZPaA+dsQdBmFAQQDJopcDpQmNpjAcqgplsB7vhL3JqiDkDke0v
         6uE+dhKHdzo8gVsrfiN1TNk5OL4ygTNwUYmqvqFY480HI8793cGImjfCOXPql1gTpZVO
         7P4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lcXwrYGOstRrXJ9hkfolbQSGEGrl4+aFL891avskIYg=;
        b=cGel7XoVqzZSox70QkvlEvhqTUMx2TRPDPH+p6pejF5oDg+lPX2IH9DK0OXy40bzAy
         Z3czGJZGMy9seamtfo2J0eBBI0D86SGnQ2ZppTtnEt/d3zEMxJ8qwHvH16ohKb1WuQ3T
         GTRwDoYvPCnAP8eBBQETz4yTRzhzcIhW7P1kt+9alYfP1r/A722nu5omvLaEdketAYhg
         L7D4UqBijeU9nYzyLS3vjpLLT6cqGRmWoS+GkDvKvNQby5TgfxPQNStKEmOTMRyOEeMM
         w82LQG4cXGyrggcdK2vhSRJ1q/2SjjgmnejJMqk6/El7mo4TYC8jt45Z1Sb5TqwBsXtG
         VwMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gPyGKwnG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lcXwrYGOstRrXJ9hkfolbQSGEGrl4+aFL891avskIYg=;
        b=YgdPfzcJNN4CaPgM3ApH3wu4Crmol5mpl/73M4SVPNsYj7DK3RsVux9thFPPQl3jjB
         lUBLqNk6HTbpQYdQPhfimE/yoN4Nk2pkI8uOpCdl134ZZ0a9mzXwCMXdq+xbPgQuJJie
         oErtiCBu5n4w2Ys3mJZ4UiXW/6y+lZzyYduua9hg3R/ws+GUIYrlY1LzTTLG7dq76Cq7
         lbZGhtEiTgwNBivOJXuwH1/Bx1q0NlTRw6TyLJlu6BtaI69Yx8UlBIG7aYpWt2k79cG3
         qU5YbNMjSRl8vVex0iB08oS21u0cvy9D4xpsKQ0m3aVTSfMyrhR1s1YbKTklDB1hXbbm
         MiIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lcXwrYGOstRrXJ9hkfolbQSGEGrl4+aFL891avskIYg=;
        b=iVM5ErSFftITUb4oM1DYHYxJq1Q27oHq4h2CdzHBk5AsAQjFgDbDiBgy28x0wafRU4
         riBa26P6KIF2dZaTQfk2sPBiYsl1GA5uFJQMrX7YSg3xZOqGBUySMJfOEaD9gG4fw2yV
         IbRvnmg7M96uzpxbfkiz0GYKPg/DAp6UdVdsTTPOxNEVaxP69p6z5BswIWJr9LDS8JQl
         VmLGV8o/NpcpK6uAwxx0PGWXuEre3pJyKtrlfxsyDg/PVVclvuUMLDkCSnjf6SxTi9ep
         5aXbklygEZL8D93A8KzkMVKtnXutwdUI49rMeQvSLOfJHl6fetKZOqllvAziQGt610dV
         hynQ==
X-Gm-Message-State: AOAM531APQ8RIvJ3dQB9URWOY1TmtXWz2g5gXmgtDmfMiB2cv7J3YugA
	Y890cPQ+TpURvspdOe2FH88=
X-Google-Smtp-Source: ABdhPJwhG3NnZnhotmQFzfdyO+f+C3UCk2QQkxks4DOApXIsmfhZ4z4186eTBmFl1jRIQFmy2fjRzw==
X-Received: by 2002:a05:620a:221:: with SMTP id u1mr2346610qkm.373.1599842045043;
        Fri, 11 Sep 2020 09:34:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:146b:: with SMTP id j11ls1297748qkl.0.gmail; Fri,
 11 Sep 2020 09:34:04 -0700 (PDT)
X-Received: by 2002:a37:4c4:: with SMTP id 187mr2362753qke.40.1599842044418;
        Fri, 11 Sep 2020 09:34:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599842044; cv=none;
        d=google.com; s=arc-20160816;
        b=StjmW2o6qjrPcWeWbJnQp+8y4NkJ2LBcr44gJPW0Jo9kL7giCiM5U285jORq2YbSXt
         y7cGJJddiO8s0ARDkOUO816WpBZQ9sGXDbCyCHPUK8ahpbXpHye71COEvHYSSGK5Wak5
         pVpP/b2j+CezcpqHMlMOR8V8kpw9NJ3RcmspoAWafdCpddJhg53RbVYWortUnzRnP3Mb
         75/ccGY+XogC4XPC6cl02g727YLvBxB2HHvoONBDai4s3MI5DRhiaolNvSwDwvp3Svdv
         jRQi7LZdYSVpVxCrNcjx/MzDGNvdqO9EDiGebfAn9y5zShLyTOfmEaC7CdbK5pOut74+
         GkuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LXuI1+2niHV1f/itEDtLBlt+egT8GEGRmfKrWMZ85Ng=;
        b=KlGSst+aM+ptK+HxYGVQmXY84wpUCQmmS+xtPVrHZE+qRjlHP+wLkBZmoqVFXjaKtI
         ihfKBdzjG8mYqirIZbQ9MAsChNg5DXHHVBtJt5fdzTeqPy1vJCKKFCLf/q4F2kbIJbdH
         CBxE+VJ1tX9N85wz1RkUrjqCfnS/E8kiZzkBtmR5ti3WmEVZOgUdY+E6jvuEmqcHpPfr
         pStLDa/QI7/VxzqH86i40GNHQov51qgnoSOsl7367Ez9L9hLuB8bBqSTEAXxNQSptfjD
         ySGnq50LqbxZQCOVHdxb8yzCDk3U2sU0b5/T30MOGTUokGv6XN9aMAtKzRtEaB8dmVWH
         EFuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gPyGKwnG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q5si156804qkc.2.2020.09.11.09.34.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 09:34:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id d189so9971533oig.12
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 09:34:04 -0700 (PDT)
X-Received: by 2002:aca:54d1:: with SMTP id i200mr1720432oib.172.1599842043737;
 Fri, 11 Sep 2020 09:34:03 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com> <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
 <20200908155631.GC61807@elver.google.com> <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
 <CANpmjNO7XwhefA+NKszVkNqj8a60QY45n-=EUtGns+ysNYV9mQ@mail.gmail.com>
 <CACT4Y+YSQDjEh6+XMXiHvMaKAT8bA=JkC8xY3AXfcSk+f9yR+g@mail.gmail.com> <CANpmjNNWOVi317bF_E=QdcSSd5x6Dfk=+nECA9VnZSLGMKigYQ@mail.gmail.com>
In-Reply-To: <CANpmjNNWOVi317bF_E=QdcSSd5x6Dfk=+nECA9VnZSLGMKigYQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 18:33:52 +0200
Message-ID: <CANpmjNN_OPCvWPnb62nu+B94t7P54utAH6BGaRYuYuuCfygzig@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=gPyGKwnG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Fri, 11 Sep 2020 at 15:33, Marco Elver <elver@google.com> wrote:
> On Fri, 11 Sep 2020 at 15:10, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Fri, Sep 11, 2020 at 2:03 PM Marco Elver <elver@google.com> wrote:
> > > On Fri, 11 Sep 2020 at 09:36, Dmitry Vyukov <dvyukov@google.com> wrote:
> [...]
> > > > By "reasonable" I mean if the pool will last long enough to still
> > > > sample something after hours/days? Have you tried any experiments with
> > > > some workload (both short-lived processes and long-lived
> > > > processes/namespaces) capturing state of the pool? It can make sense
> > > > to do to better understand dynamics. I suspect that the rate may need
> > > > to be orders of magnitude lower.
> > >
> > > Yes, the current default sample interval is a lower bound, and is also
> > > a reasonable default for testing. I expect real deployments to use
> > > much higher sample intervals (lower rate).
> > >
> > > So here's some data (with CONFIG_KFENCE_NUM_OBJECTS=1000, so that
> > > allocated KFENCE objects isn't artificially capped):
> > >
> > > -- With a mostly vanilla config + KFENCE (sample interval 100 ms),
> > > after ~40 min uptime (only boot, then idle) I see ~60 KFENCE objects
> > > (total allocations >600). Those aren't always the same objects, with
> > > roughly ~2 allocations/frees per second.
> > >
> > > -- Then running sysbench I/O benchmark, KFENCE objects allocated peak
> > > at 82. During the benchmark, allocations/frees per second are closer
> > > to 10-15. After the benchmark, the KFENCE objects allocated remain at
> > > 82, and allocations/frees per second fall back to ~2.
> > >
> > > -- For the same system, changing the sample interval to 1 ms (echo 1 >
> > > /sys/module/kfence/parameters/sample_interval), and re-running the
> > > benchmark gives me: KFENCE objects allocated peak at exactly 500, with
> > > ~500 allocations/frees per second. After that, allocated KFENCE
> > > objects dropped a little to 496, and allocations/frees per second fell
> > > back to ~2.
> > >
> > > -- The long-lived objects are due to caches, and just running 'echo 1
> > > > /proc/sys/vm/drop_caches' reduced allocated KFENCE objects back to
> > > 45.
> >
> > Interesting. What type of caches is this? If there is some type of
> > cache that caches particularly lots of sampled objects, we could
> > potentially change the cache to release sampled objects eagerly.
>
> The 2 major users of KFENCE objects for that workload are
> 'buffer_head' and 'bio-0'.
>
> If we want to deal with those, I guess there are 2 options:
>
> 1. More complex, but more precise: make the users of them check
> is_kfence_address() and release their buffers earlier.
>
> 2. Simpler, generic solution: make KFENCE stop return allocations for
> non-kmalloc_caches memcaches after more than ~90% of the pool is
> exhausted. This assumes that creators of long-lived objects usually
> set up their own memcaches.
>
> I'm currently inclined to go for (2).

Ok, after some offline chat, we determined that (2) would be premature
and we can't really say if kmalloc should have precedence if we reach
some usage threshold. So for now, let's just leave as-is and start
with the recommendation to monitor and adjust based on usage, fleet
size, etc.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN_OPCvWPnb62nu%2BB94t7P54utAH6BGaRYuYuuCfygzig%40mail.gmail.com.
