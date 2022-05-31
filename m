Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTXO26KAMGQE7L6PYIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 521B8538F73
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 13:09:04 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id y12-20020a4a86cc000000b00324cb8287a4sf7141088ooh.19
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 04:09:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653995343; cv=pass;
        d=google.com; s=arc-20160816;
        b=f8WArppzQ4WKX75DbX6G/TDnO4b97RChaenS2NYVwkUtxY6OlepwLVPdMo5H1CKlft
         CbkbbnBcsZ9bg5V4RFzrxfhGZsYKvDBEVz/2rrYsQeMdPNQKi4YnXfFg4+GE/LxOfNVw
         OtKV8U6LGdxL5MdTXzMxcx+3TKU1CQkBBmEvwvcdXUUSJ63wiLR0du2tNdkVRse+VSHk
         M16Vvq21E4dfD6L9x8LG3Qo44x+ctcM0Q/PeDWAaH3SuHZCJKDGgLEqrpFOi3wK0Qh6O
         +xcpTlXtW9pdlsVQkOSdwnCsZRCCk1DsW/JOnWL8KdOHrTVJxfLTU8x/iLGRUEyOA8Q9
         DNZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gWx5+a/rYt65yU1v+Xhj/k23ixwhATz60Rl47bFs1XQ=;
        b=Sbsp990Em/yGebuMpnOlXLomGG59sZboGN0oW/VivhWdiTKBDrbVtRMQu4uvGK6D6e
         COKK9+3YmhNYMfQ0jPkNIySzAzt/Lr8RS0/jrU8602CKCyQHdT15pAb3cNXsyQ2qY1Z6
         qnzwQ2JTvHUJ7pciEzXGNXOLtGodLyWiG6x8CGa6qzhOH/6XpFrRe1U4TC33OPorc6BZ
         9IofPELBFMtbAGk47uoz5op0ju18O/8nyYVcmqEQs8O0YUAaGN+DmJBa4r6ZmMfW+4Mx
         Dwqf8hQtxtqDKZQ/e6wK3W9EBfLMPK450HTaeMgpIpL+51XiZ2gkvZJbuJWaO1rhMmcs
         U3hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WH6nv9XG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gWx5+a/rYt65yU1v+Xhj/k23ixwhATz60Rl47bFs1XQ=;
        b=B4b6b/KTI1+WRRxWb+J0dSoXR18Op25rv30z+CE2iSmbi5t5JUQsOA01wIF/7aYosZ
         MicIDFM01AvwXkjy+Zs90aEQPeFOkdlp5ujR2ETRmezn667eR31dbM9WhiKxepMJJx+N
         sfJAI8GE1z30DXtH/eqL62RzqIqnFSJ1+X6aBm5ZN6iAU+k101fSzCU94L3ZmbXja58x
         rf8AE4BleZpQmOSy9YGMUEwiTqCqmicOVq818p54HHDkKfkbB+q1u/YS9MpqG5VXRTDQ
         jjAl6Fk+LS4A40bOV3uTLfk8pU3xEhs7KiPb68Ut3/FMfrLRdHPigJzMHEy3U21+bDUn
         MthQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gWx5+a/rYt65yU1v+Xhj/k23ixwhATz60Rl47bFs1XQ=;
        b=LwQCqjeiNM35HGzyafKuMxF0AzRh+oMc2565d6irOe3CyEM7NtE290ViIZ0/8kG1OE
         rWbdYiQoLb5xRUDpZt441CaiVqSdxrNDP7FDErRSMX5AHJtQg1/koEhF7IFhMouvThAc
         wcUEpfRRH6mH9sEuuiQCYVref9shOWX0zNnO6oOdY3SAvhC/ukFq5PDtV/rdb8dHkcQy
         CF6Mnba+/U1UedhiTZEWc7CkC6wQBOjLOhI/y1IuTkZsD2unDZIYVYQzyxDXLsVlqKoX
         d4nucIhA9SU42P3EpXcAoVykrUWyVflks01vAQliWcSCHQBvh8AZnWORByJi30yHSfVh
         /krg==
X-Gm-Message-State: AOAM533dQ2+nS0ZGShqy0ZbrdtyW04bgxHpYiB9E/z9uquIKRGvJa38T
	16Os2pOeZytR8/CXb7tIGJo=
X-Google-Smtp-Source: ABdhPJwWQQzd0R29Ce0a85OT9YlcMomjHbdpO6fPg+uWtksM5bUEfgPSCUBV+pTu7hh8rRjDoBggLg==
X-Received: by 2002:a05:6830:4391:b0:60b:4149:babe with SMTP id s17-20020a056830439100b0060b4149babemr9272415otv.248.1653995342796;
        Tue, 31 May 2022 04:09:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a9a4:b0:f2:dc5c:8024 with SMTP id
 ep36-20020a056870a9a400b000f2dc5c8024ls5373151oab.0.gmail; Tue, 31 May 2022
 04:09:02 -0700 (PDT)
X-Received: by 2002:a05:6870:960d:b0:f1:28b4:41ff with SMTP id d13-20020a056870960d00b000f128b441ffmr13147672oaq.51.1653995342347;
        Tue, 31 May 2022 04:09:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653995342; cv=none;
        d=google.com; s=arc-20160816;
        b=tW18cVYEzxvmn0buRS5V70XU0cdrLaArzfcnfUvFkScPOCTwc8H2Qzkk44EPVTcO3Y
         mLTYfTI5cJfUtYS9lX3nfgrf6pXcjUGxAMNbClId5llhw0K8x19OH+GI8OXhcLL8bKrJ
         HBanXnZtEWEqiB/zQnAC/H4V8PHkC9WQ8Y9L2LfR/ydEbCxLvgA7Yw5Ht8p/w2808uzf
         joLeSyUGVpEvDufyI8JYuJDcopR4Z2yn5L4/AZrso9dyLC3/vccc+PuFuHtKCocEi5ZE
         UgBvwA0xqgJYv/cQSXtf10/XHqsWAOx9tPJeqLnBfOg6JMjwFiiVXXDhkZigGJuv3oSC
         Cd9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=89pC4XAY/z7UFh8pChBVS1ZQvKsoUeUASgbw5YbK0vc=;
        b=s//yf/UgI5sDNsgcJ6kL9zW/yZTwrJ8QC9ghWHmbxwGT3/IgSWe/VVZSmEXwIUALtO
         UoZgRJlSnIKj2MJOTXPEquevDAgwJejhM03hrTFE1n4bDtOJnGQb5py6JhXfXCuJTg/P
         Jn5bUf9nsFBkPVh37/x/JKYteKuIA3M1JM3fJq8tfIQHV7CJgGJsi2n+C+yiqf58pSAU
         /zo5q3Qek+WOg7fVdBOs609g90c/MbhxqiHZdFxC4j6KeSZG+FSu/I61RriO1fjMwiLT
         GMx47/r0BiilYz2foG7rI6jD2K1EqGKm//S3c8dgsxB6+bUg4y3oRBwR0SxIOTX5xrJJ
         GQuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WH6nv9XG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id x10-20020a056808144a00b003222fdff9aesi928066oiv.0.2022.05.31.04.09.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 May 2022 04:09:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id a64so13010484ybg.11
        for <kasan-dev@googlegroups.com>; Tue, 31 May 2022 04:09:02 -0700 (PDT)
X-Received: by 2002:a25:4585:0:b0:65d:49fc:7949 with SMTP id
 s127-20020a254585000000b0065d49fc7949mr1914785yba.307.1653995341430; Tue, 31
 May 2022 04:09:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-13-glider@google.com>
 <YmlOrxYCbAnVrV7r@elver.google.com>
In-Reply-To: <YmlOrxYCbAnVrV7r@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 May 2022 13:08:25 +0200
Message-ID: <CAG_fn=XvG5atw4qEOKRB0ZmBf5uMutFEV1zVVv6fUTtV_2+bBw@mail.gmail.com>
Subject: Re: [PATCH v3 12/46] kmsan: add KMSAN runtime core
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WH6nv9XG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Apr 27, 2022 at 4:10 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Apr 26, 2022 at 06:42PM +0200, Alexander Potapenko wrote:
> > For each memory location KernelMemorySanitizer maintains two types of
> > metadata:
> > 1. The so-called shadow of that location - =D0=B0 byte:byte mapping des=
cribing
> >    whether or not individual bits of memory are initialized (shadow is =
0)
> >    or not (shadow is 1).
> > 2. The origins of that location - =D0=B0 4-byte:4-byte mapping containi=
ng
> >    4-byte IDs of the stack traces where uninitialized values were
> >    created.
> >
> > Each struct page now contains pointers to two struct pages holding
> > KMSAN metadata (shadow and origins) for the original struct page.
> > Utility routines in mm/kmsan/core.c and mm/kmsan/shadow.c handle the
> > metadata creation, addressing, copying and checking.
> > mm/kmsan/report.c performs error reporting in the cases an uninitialize=
d
> > value is used in a way that leads to undefined behavior.
> >
> > KMSAN compiler instrumentation is responsible for tracking the metadata
> > along with the kernel memory. mm/kmsan/instrumentation.c provides the
> > implementation for instrumentation hooks that are called from files
> > compiled with -fsanitize=3Dkernel-memory.
> >
> > To aid parameter passing (also done at instrumentation level), each
> > task_struct now contains a struct kmsan_task_state used to track the
> > metadata of function parameters and return values for that task.
> >
> > Finally, this patch provides CONFIG_KMSAN that enables KMSAN, and
> > declares CFLAGS_KMSAN, which are applied to files compiled with KMSAN.
> > The KMSAN_SANITIZE:=3Dn Makefile directive can be used to completely
> > disable KMSAN instrumentation for certain files.
> >
> > Similarly, KMSAN_ENABLE_CHECKS:=3Dn disables KMSAN checks and makes new=
ly
> > created stack memory initialized.
> >
> > Users can also use functions from include/linux/kmsan-checks.h to mark
> > certain memory regions as uninitialized or initialized (this is called
> > "poisoning" and "unpoisoning") or check that a particular region is
> > initialized.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v2:
> >  -- as requested by Greg K-H, moved hooks for different subsystems to r=
espective patches,
> >     rewrote the patch description;
> >  -- addressed comments by Dmitry Vyukov;
> >  -- added a note about KMSAN being not intended for production use.
> >  -- fix case of unaligned dst in kmsan_internal_memmove_metadata()
> >
> > v3:
> >  -- print build IDs in reports where applicable
> >  -- drop redundant filter_irq_stacks(), unpoison the local passed to __=
stack_depot_save()
> >  -- remove a stray BUG()
> >
> > Link: https://linux-review.googlesource.com/id/I9b71bfe3425466c97159f9d=
e0062e5e8e4fec866
> > ---
> >  Makefile                     |   1 +
> >  include/linux/kmsan-checks.h |  64 +++++
> >  include/linux/kmsan.h        |  47 ++++
> >  include/linux/mm_types.h     |  12 +
> >  include/linux/sched.h        |   5 +
> >  lib/Kconfig.debug            |   1 +
> >  lib/Kconfig.kmsan            |  23 ++
> >  mm/Makefile                  |   1 +
> >  mm/kmsan/Makefile            |  18 ++
> >  mm/kmsan/core.c              | 458 +++++++++++++++++++++++++++++++++++
> >  mm/kmsan/hooks.c             |  66 +++++
> >  mm/kmsan/instrumentation.c   | 267 ++++++++++++++++++++
> >  mm/kmsan/kmsan.h             | 183 ++++++++++++++
> >  mm/kmsan/report.c            | 211 ++++++++++++++++
> >  mm/kmsan/shadow.c            | 186 ++++++++++++++
> >  scripts/Makefile.kmsan       |   1 +
> >  scripts/Makefile.lib         |   9 +
> >  17 files changed, 1553 insertions(+)
> >  create mode 100644 include/linux/kmsan-checks.h
> >  create mode 100644 include/linux/kmsan.h
> >  create mode 100644 lib/Kconfig.kmsan
> >  create mode 100644 mm/kmsan/Makefile
> >  create mode 100644 mm/kmsan/core.c
> >  create mode 100644 mm/kmsan/hooks.c
> >  create mode 100644 mm/kmsan/instrumentation.c
> >  create mode 100644 mm/kmsan/kmsan.h
> >  create mode 100644 mm/kmsan/report.c
> >  create mode 100644 mm/kmsan/shadow.c
> >  create mode 100644 scripts/Makefile.kmsan
> >
> > diff --git a/Makefile b/Makefile
> > index c3ec1ea423797..d3c7dcd9f0fea 100644
> > --- a/Makefile
> > +++ b/Makefile
> > @@ -1009,6 +1009,7 @@ include-y                       :=3D scripts/Make=
file.extrawarn
> >  include-$(CONFIG_DEBUG_INFO) +=3D scripts/Makefile.debug
> >  include-$(CONFIG_KASAN)              +=3D scripts/Makefile.kasan
> >  include-$(CONFIG_KCSAN)              +=3D scripts/Makefile.kcsan
> > +include-$(CONFIG_KMSAN)              +=3D scripts/Makefile.kmsan
> >  include-$(CONFIG_UBSAN)              +=3D scripts/Makefile.ubsan
> >  include-$(CONFIG_KCOV)               +=3D scripts/Makefile.kcov
> >  include-$(CONFIG_GCC_PLUGINS)        +=3D scripts/Makefile.gcc-plugins
> > diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.=
h
> > new file mode 100644
> > index 0000000000000..a6522a0c28df9
> > --- /dev/null
> > +++ b/include/linux/kmsan-checks.h
> > @@ -0,0 +1,64 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * KMSAN checks to be used for one-off annotations in subsystems.
> > + *
> > + * Copyright (C) 2017-2022 Google LLC
> > + * Author: Alexander Potapenko <glider@google.com>
> > + *
> > + */
> > +
> > +#ifndef _LINUX_KMSAN_CHECKS_H
> > +#define _LINUX_KMSAN_CHECKS_H
> > +
> > +#include <linux/types.h>
> > +
> > +#ifdef CONFIG_KMSAN
> > +
> > +/**
> > + * kmsan_poison_memory() - Mark the memory range as uninitialized.
> > + * @address: address to start with.
> > + * @size:    size of buffer to poison.
> > + * @flags:   GFP flags for allocations done by this function.
> > + *
> > + * Until other data is written to this range, KMSAN will treat it as
> > + * uninitialized. Error reports for this memory will reference the cal=
l site of
> > + * kmsan_poison_memory() as origin.
> > + */
> > +void kmsan_poison_memory(const void *address, size_t size, gfp_t flags=
);
> > +
> > +/**
> > + * kmsan_unpoison_memory() -  Mark the memory range as initialized.
> > + * @address: address to start with.
> > + * @size:    size of buffer to unpoison.
> > + *
> > + * Until other data is written to this range, KMSAN will treat it as
> > + * initialized.
> > + */
> > +void kmsan_unpoison_memory(const void *address, size_t size);
> > +
> > +/**
> > + * kmsan_check_memory() - Check the memory range for being initialized=
.
> > + * @address: address to start with.
> > + * @size:    size of buffer to check.
> > + *
> > + * If any piece of the given range is marked as uninitialized, KMSAN w=
ill report
> > + * an error.
> > + */
> > +void kmsan_check_memory(const void *address, size_t size);
> > +
> > +#else
> > +
> > +static inline void kmsan_poison_memory(const void *address, size_t siz=
e,
> > +                                    gfp_t flags)
> > +{
> > +}
> > +static inline void kmsan_unpoison_memory(const void *address, size_t s=
ize)
> > +{
> > +}
> > +static inline void kmsan_check_memory(const void *address, size_t size=
)
> > +{
> > +}
> > +
> > +#endif
> > +
> > +#endif /* _LINUX_KMSAN_CHECKS_H */
> > diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> > new file mode 100644
> > index 0000000000000..4e35f43eceaa9
> > --- /dev/null
> > +++ b/include/linux/kmsan.h
> > @@ -0,0 +1,47 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * KMSAN API for subsystems.
> > + *
> > + * Copyright (C) 2017-2022 Google LLC
> > + * Author: Alexander Potapenko <glider@google.com>
> > + *
> > + */
> > +#ifndef _LINUX_KMSAN_H
> > +#define _LINUX_KMSAN_H
> > +
> > +#include <linux/gfp.h>
> > +#include <linux/kmsan-checks.h>
> > +#include <linux/stackdepot.h>
> > +#include <linux/types.h>
> > +#include <linux/vmalloc.h>
> > +
> > +struct page;
> > +
> > +#ifdef CONFIG_KMSAN
> > +
> > +/* These constants are defined in the MSan LLVM instrumentation pass. =
*/
> > +#define KMSAN_RETVAL_SIZE 800
> > +#define KMSAN_PARAM_SIZE 800
> > +
> > +struct kmsan_context_state {
> > +     char param_tls[KMSAN_PARAM_SIZE];
> > +     char retval_tls[KMSAN_RETVAL_SIZE];
> > +     char va_arg_tls[KMSAN_PARAM_SIZE];
> > +     char va_arg_origin_tls[KMSAN_PARAM_SIZE];
> > +     u64 va_arg_overflow_size_tls;
> > +     char param_origin_tls[KMSAN_PARAM_SIZE];
> > +     depot_stack_handle_t retval_origin_tls;
> > +};
> > +
> > +#undef KMSAN_PARAM_SIZE
> > +#undef KMSAN_RETVAL_SIZE
> > +
> > +struct kmsan_ctx {
> > +     struct kmsan_context_state cstate;
> > +     int kmsan_in_runtime;
> > +     bool allow_reporting;
> > +};
> > +
> > +#endif
> > +
> > +#endif /* _LINUX_KMSAN_H */
> > diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> > index 8834e38c06a4f..85c97a2145f7e 100644
> > --- a/include/linux/mm_types.h
> > +++ b/include/linux/mm_types.h
> > @@ -218,6 +218,18 @@ struct page {
> >                                          not kmapped, ie. highmem) */
> >  #endif /* WANT_PAGE_VIRTUAL */
> >
> > +#ifdef CONFIG_KMSAN
> > +     /*
> > +      * KMSAN metadata for this page:
> > +      *  - shadow page: every bit indicates whether the corresponding
> > +      *    bit of the original page is initialized (0) or not (1);
> > +      *  - origin page: every 4 bytes contain an id of the stack trace
> > +      *    where the uninitialized value was created.
> > +      */
> > +     struct page *kmsan_shadow;
> > +     struct page *kmsan_origin;
> > +#endif
> > +
> >  #ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
> >       int _last_cpupid;
> >  #endif
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index a8911b1f35aad..9e53624cd73ac 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -14,6 +14,7 @@
> >  #include <linux/pid.h>
> >  #include <linux/sem.h>
> >  #include <linux/shm.h>
> > +#include <linux/kmsan.h>
> >  #include <linux/mutex.h>
> >  #include <linux/plist.h>
> >  #include <linux/hrtimer.h>
> > @@ -1352,6 +1353,10 @@ struct task_struct {
> >  #endif
> >  #endif
> >
> > +#ifdef CONFIG_KMSAN
> > +     struct kmsan_ctx                kmsan_ctx;
> > +#endif
> > +
> >  #if IS_ENABLED(CONFIG_KUNIT)
> >       struct kunit                    *kunit_test;
> >  #endif
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 075cd25363ac3..b81670878acae 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -996,6 +996,7 @@ config DEBUG_STACKOVERFLOW
> >
> >  source "lib/Kconfig.kasan"
> >  source "lib/Kconfig.kfence"
> > +source "lib/Kconfig.kmsan"
> >
> >  endmenu # "Memory Debugging"
> >
> > diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> > new file mode 100644
> > index 0000000000000..199f79d031f94
> > --- /dev/null
> > +++ b/lib/Kconfig.kmsan
> > @@ -0,0 +1,23 @@
>
> Missing SPDX-License-Identifier.
Will do in v4, thanks!

> > +config KMSAN
> > +     bool "KMSAN: detector of uninitialized values use"
> > +     depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> > +     depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> > +     depends on CC_IS_CLANG && CLANG_VERSION >=3D 140000
>
> Shouldn't the "CC_IS_CLANG && CLANG_VERSION ..." check be a "depends on"
> in HAVE_KMSAN_COMPILER? That way all the compiler-related checks are
> confined to HAVE_KMSAN_COMPILER.
Good point, thanks!
I also think I can drop the excessive CC_IS_CLANG in the definition of
HAVE_KMSAN_COMPILER.

> I guess, it might also be worth mentioning why the version check is
> required at all (something about older compilers supporting
> fsanitize=3Dkernel-memory, but not having all features we need).
Done.

> > index 0000000000000..a80dde1de7048
> > --- /dev/null
> > +++ b/mm/kmsan/Makefile
> > @@ -0,0 +1,18 @@
>
> Makefile needs a SPDX-License-Identifier.
Done.


> > +     shadow_dst =3D kmsan_get_metadata(dst, KMSAN_META_SHADOW);
> > +     if (!shadow_dst)
> > +             return;
> > +     KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(dst, n));
> > +
> > +     shadow_src =3D kmsan_get_metadata(src, KMSAN_META_SHADOW);
> > +     if (!shadow_src) {
> > +             /*
> > +              * |src| is untracked: zero out destination shadow, ignor=
e the
>
> Probably doesn't matter too much, but for consistency elsewhere - @src?
Fixed here and in other places where |var| is used.

> > +                      * If |src| isn't aligned on KMSAN_ORIGIN_SIZE, d=
on't
> > +                      * look at the first |src % KMSAN_ORIGIN_SIZE| by=
tes
> > +                      * of the first shadow slot.
> > +                      */
E.g. here

> > +                     /*
> > +                      * If |src + n| isn't aligned on
> > +                      * KMSAN_ORIGIN_SIZE, don't look at the last
> > +                      * |(src + n) % KMSAN_ORIGIN_SIZE| bytes of the
> > +                      * last shadow slot.
> > +                      */
and here.



> > +
> > +extern bool kmsan_enabled;
> > +extern int panic_on_kmsan;
> > +
> > +/*
> > + * KMSAN performs a lot of consistency checks that are currently enabl=
ed by
> > + * default. BUG_ON is normally discouraged in the kernel, unless used =
for
> > + * debugging, but KMSAN itself is a debugging tool, so it makes little=
 sense to
> > + * recover if something goes wrong.
> > + */
> > +#define KMSAN_WARN_ON(cond)                                           =
         \
> > +     ({                                                               =
      \
> > +             const bool __cond =3D WARN_ON(cond);                     =
        \
> > +             if (unlikely(__cond)) {                                  =
      \
> > +                     WRITE_ONCE(kmsan_enabled, false);                =
      \
> > +                     if (panic_on_kmsan) {                            =
      \
> > +                             /* Can't call panic() here because */    =
      \
> > +                             /* of uaccess checks.*/                  =
      \
>
> space after '.'
Done; also reformatted the macro to use tabs instead of spaces.


> > +void kmsan_report(depot_stack_handle_t origin, void *address, int size=
,
> > +               int off_first, int off_last, const void *user_addr,
> > +               enum kmsan_bug_reason reason)
> > +{
> > +     unsigned long stack_entries[KMSAN_STACK_DEPTH];
> > +     int num_stack_entries, skipnr;
> > +     char *bug_type =3D NULL;
> > +     unsigned long flags, ua_flags;
> > +     bool is_uaf;
> > +
> > +     if (!kmsan_enabled)
> > +             return;
> > +     if (!current->kmsan_ctx.allow_reporting)
> > +             return;
> > +     if (!origin)
> > +             return;
> > +
> > +     current->kmsan_ctx.allow_reporting =3D false;
> > +     ua_flags =3D user_access_save();
> > +     spin_lock_irqsave(&kmsan_report_lock, flags);
>
> I think this might want to be a raw_spin_lock, since the reporting can
> be called from any context, including from within other raw_spin_lock'd
> critical sections (practically this will only matter in RT kernels).
(Marco elaborated off-list that lockdep will complain if a spin_lock
critical section is nested inside raw_spin_lock)
Thanks, done.

> Also, do you have to do lockdep_off/on() (like kernel/kcsan/report.c
> does, see comment there)?

I don't see lockdep reports from within mm/kmsan/report.c
However there's one boot-time report that I am struggling to comprehend:

DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
WARNING: CPU: 0 PID: 0 at kernel/locking/lockdep.c:5481 check_flags+0x63/0x=
180
...
 <TASK>
 lock_acquire+0x85/0x1c0 kernel/locking/lockdep.c:5638
 __raw_spin_lock_irqsave ./include/linux/spinlock_api_smp.h:110
 _raw_spin_lock_irqsave+0x129/0x220 kernel/locking/spinlock.c:162
 __stack_depot_save+0x1b1/0x4b0 lib/stackdepot.c:417
 stack_depot_save+0x13/0x20 lib/stackdepot.c:471
 __msan_poison_alloca+0x100/0x1a0 mm/kmsan/instrumentation.c:228
 _raw_spin_unlock_irqrestore ??:?
 arch_local_save_flags ./arch/x86/include/asm/irqflags.h:70
 arch_irqs_disabled ./arch/x86/include/asm/irqflags.h:130
 __raw_spin_unlock_irqrestore ./include/linux/spinlock_api_smp.h:151
 _raw_spin_unlock_irqrestore+0xc6/0x190 kernel/locking/spinlock.c:194
 tty_register_ldisc+0x15e/0x1c0 drivers/tty/tty_ldisc.c:68
 n_tty_init+0x2f/0x32 drivers/tty/n_tty.c:2418
 console_init+0x20/0x10d kernel/printk/printk.c:3220
 start_kernel+0x6f0/0xd23 init/main.c:1071
 x86_64_start_reservations+0x2a/0x2c arch/x86/kernel/head64.c:546
 x86_64_start_kernel+0xf5/0xfa arch/x86/kernel/head64.c:527
 secondary_startup_64_no_verify+0xc4/0xcb ??:?
 </TASK>

Perhaps we need to disable lockdep in stackdepot as well?

> > + */
> > +static int kmsan_phys_addr_valid(unsigned long addr)
>
> int -> bool ? (it already deviates from the original by using IS_ENABLED
> instead of #ifdef)

Makes sense.

> > + * Taken from arch/x86/mm/physaddr.c to avoid using an instrumented ve=
rsion.
> > + */
> > +static bool kmsan_virt_addr_valid(void *addr)
> > +{
> > +     unsigned long x =3D (unsigned long)addr;
> > +     unsigned long y =3D x - __START_KERNEL_map;
> > +
> > +     /* use the carry flag to determine if x was < __START_KERNEL_map =
*/
> > +     if (unlikely(x > y)) {
> > +             x =3D y + phys_base;
> > +
> > +             if (y >=3D KERNEL_IMAGE_SIZE)
> > +                     return false;
> > +     } else {
> > +             x =3D y + (__START_KERNEL_map - PAGE_OFFSET);
> > +
> > +             /* carry flag will be set if starting x was >=3D PAGE_OFF=
SET */
> > +             if ((x > y) || !kmsan_phys_addr_valid(x))
> > +                     return false;
> > +     }
> > +
> > +     return pfn_valid(x >> PAGE_SHIFT);
> > +}
>
> These seem quite x86-specific - to ease eventual porting to other
> architectures, it would make sense to introduce <asm/kmsan.h> which will
> have these 2 functions (and if there's anything else arch-specific like
> this, moving to <asm/kmsan.h> would help eventual ports).

Good idea, will do!
This part will probably need to go into "x86: kmsan: enable KMSAN
builds for x86"


> > +     if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
> > +             pad =3D addr % KMSAN_ORIGIN_SIZE;
> > +             addr -=3D pad;
> > +     }
> > +     address =3D (void *)addr;
> > +     if (kmsan_internal_is_vmalloc_addr(address) ||
> > +         kmsan_internal_is_module_addr(address))
> > +             return (void *)vmalloc_meta(address, is_origin);
> > +
> > +     page =3D virt_to_page_or_null(address);
> > +     if (!page)
> > +             return NULL;
> > +     if (!page_has_metadata(page))
> > +             return NULL;
> > +     off =3D addr % PAGE_SIZE;
> > +
> > +     ret =3D (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page))=
 + off;
>
> Just return this and avoid 'ret'?
Good catch. There was some debugging code in the middle, but now we
don't need ret.

>
> > +     return ret;
> > +}
> > diff --git a/scripts/Makefile.kmsan b/scripts/Makefile.kmsan
> > new file mode 100644
> > index 0000000000000..9793591f9855c
> > --- /dev/null
> > +++ b/scripts/Makefile.kmsan
> > @@ -0,0 +1 @@
>
> Makefile.kmsan needs SPDX-License-Identifier.
Done.





--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise
erhalten haben sollten, leiten Sie diese bitte nicht an jemand anderes
weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich
bitte wissen, dass die E-Mail an die falsche Person gesendet wurde.


This e-mail is confidential. If you received this communication by
mistake, please don't forward it to anyone else, please erase all
copies and attachments, and please let me know that it has gone to the
wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXvG5atw4qEOKRB0ZmBf5uMutFEV1zVVv6fUTtV_2%2BbBw%40mail.gm=
ail.com.
