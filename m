Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWBTTWQKGQERM5YHLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2874D9310
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 15:53:11 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 6sf17698595pgi.10
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 06:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571233990; cv=pass;
        d=google.com; s=arc-20160816;
        b=hktT+WOtmAsl761IxbZDFuMNqDY0OFD/3CpCR1rd3uF3cBQHlbStdcehxWrgVCQflQ
         ncbFLHHSVKJcNRfT7F4ODkKQF1wSCtsQyj/LC12urHrHoUVEyv/LBdX7pUzu7fu80xsH
         V/UMKorIdfttttebc4BIm3DRXUB3edOivxB0YleoOrw2/HuFNPwP9PDz30Vls8/nbAwU
         OZ8DJTIRnsY0JS/sR2ud+WjZ9zg2lW1L9gIWOh3rog/xny6zm57c9gibFASaC6nDClct
         NNKlBoaF5Tkgn0sjxux9WdIbM4inDJ7m6FQHiaZe17SktH2BLorcJOmq3LiRoanIAgDM
         /8BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GKkcXq6f8zGWuzHao/wEgSlibaZrEh6/LypUjS7IpMs=;
        b=a7rSixHNkvYQ7HGm3irAn0+AQEJiJekgHlQ6TakQ0i6CVa9OF0TOv1Dj1Xc9JAeBgr
         ZXOfkfK3gKG106sCqmaVgz/pE0YVRAWflxUgi+OAAzyI2LMDF+QAar/OdpGKPx+nNRAT
         3iNkt5P8OTPCYQYFkBe/ZJPw/rjWUm7EzfFQq/UXObRDdQWC6baL+iuxnG9gF+sWlA6f
         yaCkiXsU7SKJLH3rW1TKt3xGZiQhhiZjbLGGSvwjg9U4EBJqH2CpT6Se0qrLHSt4lw1I
         EyMHu6x1GKgjOJmr+wX9Y4AW0ZUgdZuE7iUgnshNoi5rZFYziQAgK32bpjG7dHoCL7DQ
         Yjig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C9UK7bh+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKkcXq6f8zGWuzHao/wEgSlibaZrEh6/LypUjS7IpMs=;
        b=Wd6Hf+GeW5yTo+BLcUmVJPPdRpQvuKQBjXq+fHHUgOe/9ZfW1PM0ZuC/p7KAeqBGeO
         LXjkfoUsvDR/UpCu4+M4txryWp5EKtkDkeIEyEmMaC2DJG17ZJ2fooT9OPnvUAqi24sg
         s530pru47mf2EMIhmhSSwGvYX/YlN6m8vppKJB2vnOnQrg0/IufB21W/AFvXLRVo/cMl
         somKCOdpJD9XoEKNTHrLA1o3SLfyyEQ8Xcu9z9PhL9zKvmzz3WG5F03m9FBp/88p4ceZ
         RUOGdPvH16cGwseBiot5dSXB8ptZA/SmDAuYBTNAe/9Bb7XoiEzTWfkRjw6CqSL3PyBL
         8njg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKkcXq6f8zGWuzHao/wEgSlibaZrEh6/LypUjS7IpMs=;
        b=ffaV4Z6ruxiTF8VijEnW9m8hkMw8Bnv3uN3xnSZm2xEXWmaH/AJjkveek2yL9OWydN
         wkBYTOJp7ebMwEH18LKjfH/U5LXXWE+4/lXIlO0aIgtf/Blp0hUB36nruG9Vd2InC6GW
         MtDAchrHZ6tdJ3hCk1ovMLGp7SBXmLPb5IQnQYo6UmfXczGfMgxdHy+M9WcZXR0T0s18
         378oa2FGIO1Fy/KIAFS++N1a1FDPKULvK5w7bP2iUY5183KusnkVM9lfnMKFJ8JQ3JFl
         KJ4HB5SWPYjnqtPXSJGW6HOdn4zAWtTSRnfKT09xl/lU0r/eWfU23TPmgTiRyUh82yKG
         z3qg==
X-Gm-Message-State: APjAAAWEQcfcPHhgFbb3NLwBoSZfeuWYGHE2G2OiE/0GGmG0BKfC2HwT
	ar2h4KRrV/Ra1d4mDj6FPc0=
X-Google-Smtp-Source: APXvYqweh0OUPeAp+E5LqayqT0Od/Ixx6DiqcyO4ORzYZRS71B5qpKsOtp7h3aL1IEP6LCBss4DdMQ==
X-Received: by 2002:a17:90a:bd8e:: with SMTP id z14mr5067225pjr.40.1571233990295;
        Wed, 16 Oct 2019 06:53:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:8849:: with SMTP id l70ls3222085pgd.13.gmail; Wed, 16
 Oct 2019 06:53:09 -0700 (PDT)
X-Received: by 2002:a17:902:d691:: with SMTP id v17mr40004565ply.340.1571233989139;
        Wed, 16 Oct 2019 06:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571233989; cv=none;
        d=google.com; s=arc-20160816;
        b=wBSzK/nWl6Gy0kOCTJE2i+ugpLnbQYMviO2aUREiu2nolLljPtjf0qYO4Yh6Ebk6/N
         FxcPiJeaWFU7muivXe4BNLSQ6Wzx+fUGa6k0XltYnHCsI/V9clzKHzAXOEX1CXlCUWve
         EA+qrAne/2DWwTO/Z2+97N7eOyGSRq7K5NLL9iHb130jKeYhMCW5aAzDBZFwerOPMfhr
         SAw6zFDbCzG9o6Q0MwB8CddKYED41JQOizoCqHR+QM/lkPgh1GBYRNzQ3ywhJjvgPZO4
         UloZbzyvzqO0OLeLAUQ3PPWuH2Yx/UT3vvINfGv4gB/SHT4nzPSXitcW0gDax+s/fvnc
         G7CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pXaUYTlHBDwej+JruJ2WTRxguQOYJLFuT4MqoWM48a4=;
        b=tze5TZBV5T1opqLGASi5qcqjMzRgvGPnNaDAr1hfuPif3e2cDZZepzLxYnpyI+FB+E
         CZk78Zz3tclzQgVH0qonkR2hnoAoZl8MI13cpVXiWaCen/SsWLrMnYospEkMjo+dEojV
         AY65w1WfmBMBrITVo9m1xmY9BY9fZD8mzRo+52jramyOKx02BAEHDLEjyedcO8MwlP03
         Ves0OEnC7GS3ZPc0kjXSF/jyg+wq8hg8phZPPHtAPTyQwfXLaayNqigVSq5Tc80Vcml+
         iyJZ0cOuJfv2kSfjcfWW/Lv7gE2dXHkc0AkR+Uq4nBXLEnUeL5Ffi8XDtPxwo+exnox0
         XvEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C9UK7bh+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id b64si723878pfg.0.2019.10.16.06.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 06:53:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id g13so20183501otp.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 06:53:09 -0700 (PDT)
X-Received: by 2002:a9d:724e:: with SMTP id a14mr34578027otk.23.1571233986798;
 Wed, 16 Oct 2019 06:53:06 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-2-elver@google.com>
 <CAAeHK+wO226yFsWw97wET_CY3aCiqX30JBYLtBspO5PbSV9FAA@mail.gmail.com>
In-Reply-To: <CAAeHK+wO226yFsWw97wET_CY3aCiqX30JBYLtBspO5PbSV9FAA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 15:52:53 +0200
Message-ID: <CANpmjNOcE=myHAC4xYOdssMUvJP2=1BeXmQ62O_tRQ-5cbiKMA@mail.gmail.com>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Andrey Konovalov <andreyknvl@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andy Lutomirski <luto@kernel.org>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Daniel Axtens <dja@axtens.net>, Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C9UK7bh+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

> > diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> > new file mode 100644
> > index 000000000000..5b46cc5593c3
> > --- /dev/null
> > +++ b/Documentation/dev-tools/kcsan.rst
> > @@ -0,0 +1,202 @@
> > +The Kernel Concurrency Sanitizer (KCSAN)
> > +========================================
> > +
> > +Overview
> > +--------
> > +
> > +*Kernel Concurrency Sanitizer (KCSAN)* is a dynamic data-race detector for
> > +kernel space. KCSAN is a sampling watchpoint-based data-race detector -- this
> > +is unlike Kernel Thread Sanitizer (KTSAN), which is a happens-before data-race
> > +detector. Key priorities in KCSAN's design are lack of false positives,
> > +scalability, and simplicity. More details can be found in `Implementation
> > +Details`_.
> > +
> > +KCSAN uses compile-time instrumentation to instrument memory accesses. KCSAN is
> > +supported in both GCC and Clang. With GCC it requires version 7.3.0 or later.
> > +With Clang it requires version 7.0.0 or later.
> > +
> > +Usage
> > +-----
> > +
> > +To enable KCSAN configure kernel with::
> > +
> > +    CONFIG_KCSAN = y
> > +
> > +KCSAN provides several other configuration options to customize behaviour (see
> > +their respective help text for more info).
> > +
> > +debugfs
> > +~~~~~~~
> > +
> > +* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
> > +
> > +* KCSAN can be turned on or off by writing ``on`` or ``off`` to
> > +  ``/sys/kernel/debug/kcsan``.
> > +
> > +* Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
> > +  ``some_func_name`` to the report filter list, which (by default) blacklists
> > +  reporting data-races where either one of the top stackframes are a function
> > +  in the list.
> > +
> > +* Writing either ``blacklist`` or ``whitelist`` to ``/sys/kernel/debug/kcsan``
> > +  changes the report filtering behaviour. For example, the blacklist feature
> > +  can be used to silence frequently occurring data-races; the whitelist feature
> > +  can help with reproduction and testing of fixes.
> > +
> > +Error reports
> > +~~~~~~~~~~~~~
> > +
> > +A typical data-race report looks like this::
> > +
> > +    ==================================================================
> > +    BUG: KCSAN: data-race in generic_permission / kernfs_refresh_inode
> > +
> > +    write to 0xffff8fee4c40700c of 4 bytes by task 175 on cpu 4:
> > +     kernfs_refresh_inode+0x70/0x170
> > +     kernfs_iop_permission+0x4f/0x90
> > +     inode_permission+0x190/0x200
> > +     link_path_walk.part.0+0x503/0x8e0
> > +     path_lookupat.isra.0+0x69/0x4d0
> > +     filename_lookup+0x136/0x280
> > +     user_path_at_empty+0x47/0x60
> > +     vfs_statx+0x9b/0x130
> > +     __do_sys_newlstat+0x50/0xb0
> > +     __x64_sys_newlstat+0x37/0x50
> > +     do_syscall_64+0x85/0x260
> > +     entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > +
> > +    read to 0xffff8fee4c40700c of 4 bytes by task 166 on cpu 6:
> > +     generic_permission+0x5b/0x2a0
> > +     kernfs_iop_permission+0x66/0x90
> > +     inode_permission+0x190/0x200
> > +     link_path_walk.part.0+0x503/0x8e0
> > +     path_lookupat.isra.0+0x69/0x4d0
> > +     filename_lookup+0x136/0x280
> > +     user_path_at_empty+0x47/0x60
> > +     do_faccessat+0x11a/0x390
> > +     __x64_sys_access+0x3c/0x50
> > +     do_syscall_64+0x85/0x260
> > +     entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > +
> > +    Reported by Kernel Concurrency Sanitizer on:
> > +    CPU: 6 PID: 166 Comm: systemd-journal Not tainted 5.3.0-rc7+ #1
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +The header of the report provides a short summary of the functions involved in
> > +the race. It is followed by the access types and stack traces of the 2 threads
> > +involved in the data-race.
> > +
> > +The other less common type of data-race report looks like this::
> > +
> > +    ==================================================================
> > +    BUG: KCSAN: racing read in e1000_clean_rx_irq+0x551/0xb10
>
> Do we want to have a different bug title here? Can we also report this
> as a data-race to simplify report parsing rules?

Changed to just "data-race in" as well.

> > +
> > +    race at unknown origin, with read to 0xffff933db8a2ae6c of 1 bytes by interrupt on cpu 0:
> > +     e1000_clean_rx_irq+0x551/0xb10
> > +     e1000_clean+0x533/0xda0
> > +     net_rx_action+0x329/0x900
> > +     __do_softirq+0xdb/0x2db
> > +     irq_exit+0x9b/0xa0
> > +     do_IRQ+0x9c/0xf0
> > +     ret_from_intr+0x0/0x18
> > +     default_idle+0x3f/0x220
> > +     arch_cpu_idle+0x21/0x30
> > +     do_idle+0x1df/0x230
> > +     cpu_startup_entry+0x14/0x20
> > +     rest_init+0xc5/0xcb
> > +     arch_call_rest_init+0x13/0x2b
> > +     start_kernel+0x6db/0x700
> > +
> > +    Reported by Kernel Concurrency Sanitizer on:
> > +    CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.3.0-rc7+ #2
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +This report is generated where it was not possible to determine the other
> > +racing thread, but a race was inferred due to the data-value of the watched
> > +memory location having changed. These can occur either due to missing
> > +instrumentation or e.g. DMA accesses.
> > +
> > +Data-Races
> > +----------
> > +
> > +Informally, two operations *conflict* if they access the same memory location,
> > +and at least one of them is a write operation. In an execution, two memory
> > +operations from different threads form a **data-race** if they *conflict*, at
> > +least one of them is a *plain access* (non-atomic), and they are *unordered* in
> > +the "happens-before" order according to the `LKMM
> > +<../../tools/memory-model/Documentation/explanation.txt>`_.
> > +
> > +Relationship with the Linux Kernel Memory Model (LKMM)
> > +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > +
> > +The LKMM defines the propagation and ordering rules of various memory
> > +operations, which gives developers the ability to reason about concurrent code.
> > +Ultimately this allows to determine the possible executions of concurrent code,
> > +and if that code is free from data-races.
> > +
> > +KCSAN is aware of *atomic* accesses (``READ_ONCE``, ``WRITE_ONCE``,
> > +``atomic_*``, etc.), but is oblivious of any ordering guarantees. In other
> > +words, KCSAN assumes that as long as a plain access is not observed to race
> > +with another conflicting access, memory operations are correctly ordered.
> > +
> > +This means that KCSAN will not report *potential* data-races due to missing
> > +memory ordering. If, however, missing memory ordering (that is observable with
> > +a particular compiler and architecture) leads to an observable data-race (e.g.
> > +entering a critical section erroneously), KCSAN would report the resulting
> > +data-race.
> > +
> > +Implementation Details
> > +----------------------
> > +
> > +The general approach is inspired by `DataCollider
> > +<http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf>`_.
> > +Unlike DataCollider, KCSAN does not use hardware watchpoints, but instead
> > +relies on compiler instrumentation. Watchpoints are implemented using an
> > +efficient encoding that stores access type, size, and address in a long; the
> > +benefits of using "soft watchpoints" are portability and greater flexibility in
> > +limiting which accesses trigger a watchpoint.
> > +
> > +More specifically, KCSAN requires instrumenting plain (unmarked, non-atomic)
> > +memory operations; for each instrumented plain access:
> > +
> > +1. Check if a matching watchpoint exists; if yes, and at least one access is a
> > +   write, then we encountered a racing access.
> > +
> > +2. Periodically, if no matching watchpoint exists, set up a watchpoint and
> > +   stall some delay.
> > +
> > +3. Also check the data value before the delay, and re-check the data value
> > +   after delay; if the values mismatch, we infer a race of unknown origin.
> > +
> > +To detect data-races between plain and atomic memory operations, KCSAN also
> > +annotates atomic accesses, but only to check if a watchpoint exists
> > +(``kcsan_check_atomic(..)``); i.e.  KCSAN never sets up a watchpoint on atomic
> > +accesses.
> > +
> > +Key Properties
> > +~~~~~~~~~~~~~~
> > +
> > +1. **Performance Overhead:** KCSAN's runtime is minimal, and does not require
> > +   locking shared state for each access. This results in significantly better
> > +   performance in comparison with KTSAN.
> > +
> > +2. **Memory Overhead:** No shadow memory is required. The current
> > +   implementation uses a small array of longs to encode watchpoint information,
> > +   which is negligible.
> > +
> > +3. **Memory Ordering:** KCSAN is *not* aware of the LKMM's ordering rules. This
> > +   may result in missed data-races (false negatives), compared to a
> > +   happens-before data-race detector such as KTSAN.
> > +
> > +4. **Accuracy:** Imprecise, since it uses a sampling strategy.
> > +
> > +5. **Annotation Overheads:** Minimal annotation is required outside the KCSAN
> > +   runtime. With a happens-before data-race detector, any omission leads to
> > +   false positives, which is especially important in the context of the kernel
> > +   which includes numerous custom synchronization mechanisms. With KCSAN, as a
> > +   result, maintenance overheads are minimal as the kernel evolves.
> > +
> > +6. **Detects Racy Writes from Devices:** Due to checking data values upon
> > +   setting up watchpoints, racy writes from devices can also be detected.
>
> This part compares KCSAN with KTSAN, do we need it here? I think it
> might be better to move this to the cover letter as a rationale as to
> why we went with the watchpoint based approach, instead of the
> happens-before one.

Removed mentions of KTSAN where it doesn't add very much.

These are properties of the design that, if not summarized here, would
be lost and we'd have to look at the code. This is also for the
benefit of developers using KCSAN to detect races, highlighting the
pros and cons in the inherent design they should be aware of. I prefer
keeping this information here, as otherwise it will get lost and we
will have no central place to refer to.

> Some performance numbers comparing KCSAN with a non instrumented
> kernel would be more useful here.

I've added a sentence with some empirical data.

Changes queued for v2.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcE%3DmyHAC4xYOdssMUvJP2%3D1BeXmQ62O_tRQ-5cbiKMA%40mail.gmail.com.
