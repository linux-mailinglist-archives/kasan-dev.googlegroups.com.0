Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGCSL5QKGQEQX63KOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C8C926FBEC
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 13:59:29 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id p13sf5250022ybe.4
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 04:59:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600430368; cv=pass;
        d=google.com; s=arc-20160816;
        b=CX/cXU99XjIazhnKSBBqaqEh8pTS5YKU87n5j2at+IU4NKnKYsigDr+xEhVzmlAqz6
         g+LAZHIi/QUCRTCJcN4jRCeypUkpozpxl9JGPn/THtw225yH4iqtiladircY9FkGJ0ui
         yluNcC5RiuyPN5uQWBDvcKhgycmfMWRsDddTwZaWMpiE7TuY3xMoUHHvJnHWD3DSpixx
         NApimTCcXvTa6rf+XBdtKYMpmRHLB9NVXlk8joszz1I7g90S2zQZrMjynjSbXtoMj7g6
         1779cixxzrzNkpbFj+g1GgfmMVFY9KvrKQQWbF/aMHpwImskqdOiyte3N/EjRAJms1BT
         RSmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UEb3XCk6gt5o4UyJqRtj5hmPr4fYwwU7/OwOB4dHafE=;
        b=zsTMsapi83dwJIIgz8IoF37Ss7G3T+4Vvzy6bsSWOfrWpLDJF5vQGfyMgsF4R2ah+I
         Ef/ghe6UACMRPUBGu574m/G87G+3oUQeDoKpX+USdOb2eRCfBRfOFvUlO+z7ZGC7knqr
         E9t8p/cgMZ+iJCX8sMEqsQmD1gt2VYO3tOYA2FEjN8I9gvw9hhn6KJohklJKPcAhHsUD
         paJUL4UlbrVFr7Osw5tq0GC+TI+Fv3d4DWtXFal1aY+ABP6iPoNoBYe2w2josYklQl9+
         mT3eFu0nq4EYPB8ZZgK4AhKONJQwIxnTsFICyEFIGwH5pRDH/Hp5cKnxNLiE3o7rk/lQ
         bM0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DFPRb7Y9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UEb3XCk6gt5o4UyJqRtj5hmPr4fYwwU7/OwOB4dHafE=;
        b=J2pCfHL+mspMlyqIKFNk/0fOenrofL3CUjsUOl3J9OyavsaNRdplQAiRMnRfIUCyUE
         +NDNZpk8140nMROHTKupK70JnQkXkjZDBo4H6eOtrbxScMr7S6IxWwvnl6EnkD6yvsXm
         jwNui2ujCEpPZctfSpJrSC3PMweSRazNzNnHTeGmOikRf0x7J4nBKaBE+OqyUhBDHGlh
         VqjwXEZ2A+AjqZieNc9UTLfcATZ4ZxVuBCe1IAT+n7XtZ+K8pYgujB+oMKR/NUziNp9V
         AVInna1k41FeV00/pdnm2ycLNT+ot8SHBiycnXSyVqalHb/VfKqM56yrsf9pVQVvpntM
         FOjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UEb3XCk6gt5o4UyJqRtj5hmPr4fYwwU7/OwOB4dHafE=;
        b=FAHmIMla91fbH9k/rP3+RSjuJPoTyZo+HZe3cioYKcVMaqTrq7dFTwwDfigH4TiApA
         iiPrvI2DQrnMQJV38d06zaKWSwiINDF3tfxdZXgU6hVA0FV+u6iYc8cffNNBwd6CYHEW
         wzZHvK0nHfgIEKoGsjgOvAtxVLef4RpMKnuc8IuyyOJzcwJbuZw5VBpDlTUQRfBoCkx7
         P15ryv/eAhNTrx2M7loaD6ELcwxHms2u1yBZlex5Bj/CZOA/ejl4jVuk/q9wMTde7uTa
         g6Es+ZBGbvH8lR58aE0Fplh+kOWQpkCnsMJ1zNcWkoGnp4OTVCMcn7mbD+rV33QNQidN
         Kifw==
X-Gm-Message-State: AOAM533avlbCTInYUUU2jmsyxqAxxbITcS/P5jj4Teo8fV+c6m+jzpCv
	Y1LobI5/Ag6ficszuB5L3nE=
X-Google-Smtp-Source: ABdhPJxpHnzQAqDdtl5nfHvsqbcvIT+DoSho0BKEwjKYg9eLCrxtik8eMk7IcTopcIToWxIzDTS8dQ==
X-Received: by 2002:a25:6883:: with SMTP id d125mr1826375ybc.105.1600430368201;
        Fri, 18 Sep 2020 04:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5755:: with SMTP id l82ls2320919ybb.5.gmail; Fri, 18 Sep
 2020 04:59:27 -0700 (PDT)
X-Received: by 2002:a25:6644:: with SMTP id z4mr18446966ybm.347.1600430367725;
        Fri, 18 Sep 2020 04:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600430367; cv=none;
        d=google.com; s=arc-20160816;
        b=L6eyF1562hHcYjhv33UKD6JOMweCnXcUaQO/WxgIkzByH+Fjo+d4oEgg4f7XQarjwN
         xlEeeJtJmJsUe6Gzyqk20wjigzjBj6SRy6xhKW0bz68BmYBKBRdVNd26ApIFKekVUZ2Y
         +KPhj4PE3DX5uNTrltq0IVwKf9sTIGCalrwZYy4DR30vhuz78/SgjqIzRUJG2qdUiBkK
         3R4ok0k8E6AdTOx86MS69mnbU6XYBC3WuYNbac5/nx3wj3Age4y6EPL+Caohf7RrJLNw
         FdkYuRyrTuQ7H0SQQGgtRB+ufcXRBIgxnLsFmZaEM0MSYBVn7xto0sWqTYnc5bnz6NE9
         Y8RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p0D5X7Y+m7ttT/u5XV6+XFjpJPYZ+5nXOo1ENk9Sr6U=;
        b=PA85IkM0BkS2GF5bvJ+5BRbzOS1hYPPeFR4T6uVWET06xw3wPjzot8AMnlb6rC4gdl
         rbkvc0V45sm8cvaHbaZfkq7eB2JWbj0m8CPS8H1MmCfbAXIrhNLzbhziZo2X53JhY1qT
         suGtBu6OBCumJORcTcf6t96NXmvjt36yGiRSuUhVfz8JitLFTZf2oXIQkWXcJ3DmCUO/
         rvgt3d+QBSh9SeO6vy7tO20hFu7GXQK7ZfYzEM9tyWogPyIaNQHWHhwWe+A/l5KjPtNR
         WKOX6s9v7l0bXyq/o4CoJiLedpt0JREc/42btvUysvKfELC9WWPvNgQFdM063Sg60QNr
         1Ycw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DFPRb7Y9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id s69si170159ybc.4.2020.09.18.04.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 04:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id c13so6671716oiy.6
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 04:59:27 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr9503239oib.121.1600430367017;
 Fri, 18 Sep 2020 04:59:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com> <115e74b249417340b5c411f286768dbdb916fd12.camel@redhat.com>
In-Reply-To: <115e74b249417340b5c411f286768dbdb916fd12.camel@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 13:59:15 +0200
Message-ID: <CANpmjNMkjuW_qU+G77UUzgqGx+e2RswfhYuWTFMq2da2NwqSdA@mail.gmail.com>
Subject: Re: [PATCH v2 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Qian Cai <cai@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DFPRb7Y9;       spf=pass
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

On Fri, 18 Sep 2020 at 13:17, Qian Cai <cai@redhat.com> wrote:
>
> On Tue, 2020-09-15 at 15:20 +0200, Marco Elver wrote:
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.  This
> > series enables KFENCE for the x86 and arm64 architectures, and adds
> > KFENCE hooks to the SLAB and SLUB allocators.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
> >
> > KFENCE objects each reside on a dedicated page, at either the left or
> > right page boundaries. The pages to the left and right of the object
> > page are "guard pages", whose attributes are changed to a protected
> > state, and cause page faults on any attempted access to them. Such page
> > faults are then intercepted by KFENCE, which handles the fault
> > gracefully by reporting a memory access error.
> >
> > Guarded allocations are set up based on a sample interval (can be set
> > via kfence.sample_interval). After expiration of the sample interval,
> > the next allocation through the main allocator (SLAB or SLUB) returns a
> > guarded allocation from the KFENCE object pool. At this point, the timer
> > is reset, and the next allocation is set up after the expiration of the
> > interval.
> >
> > To enable/disable a KFENCE allocation through the main allocator's
> > fast-path without overhead, KFENCE relies on static branches via the
> > static keys infrastructure. The static branch is toggled to redirect the
> > allocation to KFENCE.
> >
> > The KFENCE memory pool is of fixed size, and if the pool is exhausted no
> > further KFENCE allocations occur. The default config is conservative
> > with only 255 objects, resulting in a pool size of 2 MiB (with 4 KiB
> > pages).
> >
> > We have verified by running synthetic benchmarks (sysbench I/O,
> > hackbench) that a kernel with KFENCE is performance-neutral compared to
> > a non-KFENCE baseline kernel.
> >
> > KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
> > properties. The name "KFENCE" is a homage to the Electric Fence Malloc
> > Debugger [2].
> >
> > For more details, see Documentation/dev-tools/kfence.rst added in the
> > series -- also viewable here:
>
> Does anybody else grow tried of all those different *imperfect* versions of in-
> kernel memory safety error detectors? KASAN-generic, KFENCE, KASAN-tag-based
> etc. Then, we have old things like page_poison, SLUB debugging, debug_pagealloc
> etc which are pretty much inefficient to detect bugs those days compared to
> KASAN. Can't we work towards having a single implementation and clean up all
> those mess?

If you have suggestions on how to get a zero-overhead, precise
("perfect") memory safety error detector without new hardware
extensions, we're open to suggestions -- many people over many years
have researched this problems, and while we're making progress for C
(and C++), the fact remains that what you're asking is likely
impossible. This might be useful background:
https://arxiv.org/pdf/1802.09517.pdf

The fact remains that requirements and environments vary across
applications and usecases. Maybe for one usecase (debugging, test env)
normal KASAN is just fine. But that doesn't work for production, where
we want to have max performance.

MTE will get us closer (no silicon yet, and ARM64 only for now), but
depending on implementation might come with small overheads, although
quite acceptable for most environments with increasing processing
power modern CPUs deliver.

Yet for other environments, where even a small performance regression
is unacceptable, and where it's infeasible to capture in tests what
the workloads execute, KFENCE is a very attractive option.

There have also been discussions on using Rust in the kernel [1], but
this is just not feasible for core kernel code in the near future
(even then, you'll still need dynamic error detection tools for all
the unsafe bits, of which there are many in an OS kernel).
[1] https://lwn.net/Articles/829858/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMkjuW_qU%2BG77UUzgqGx%2Be2RswfhYuWTFMq2da2NwqSdA%40mail.gmail.com.
