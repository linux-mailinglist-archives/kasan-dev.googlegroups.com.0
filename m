Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEVVYSLAMGQEXPIU2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1B91575C8B
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 09:43:15 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id 11-20020a056e0216cb00b002dc7bfe6ad0sf2381407ilx.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 00:43:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657870994; cv=pass;
        d=google.com; s=arc-20160816;
        b=nFWdO/I5T2NbSsx9NcsEuMG54723OyTakCqB9hUOn9C09NkSCRj2hGqj+ldCRz7Y0I
         dfZlvtSEs0+KiSncH7CQ5hO3O3G2AzXj/O7KCP/63R+sU2R5Ig78MlfhujhJW1NqLz8I
         NQL3ho9DhAPwZWu1qwunL8PvwSfHIJIhbHohJwe7kXn0MW6GleAegaHEUo+VBupfBXjR
         9tCzJ55DPy+RrgFLAil7gaR0Ga+RlqfD+lVRvwMRzmPTcZ/axwoOk6cSHCUM2J6Cg10W
         T7N7syN85UwiyaG85xgiAK5RRWkXGXCfS/fEwCtCpGvebOFERUAiBjE2lawnRBLnQpKb
         Feqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SbrFQ/mJObo2AlNegWmrkuD6GEDrksHy5vm9jLyijXM=;
        b=IHlnMAZKKEThNUPXFiQ4ONgJVbW4aoR/V8+0HTeQdij00C8Qq2004+9UdMugNaagWG
         rDhPkS2Fl5boV2MpnzuMfQQABF4JfqcqfbBaRAEcIVwviexC6MoK356tSWeBR5F9b7wD
         T8K+JM99deyil032FkJt5SHiT6WuwyTGNukebw1oQnUTCt2++1v8j6GnlXAAq6SWbjF6
         FTt8MbPiqMwTTRrv29BZ3N6N2C10DHjRo03r3t53oTAsD7TeafvmgZpEo+l3r8/aawAT
         boYNcN/RrIlIwBWXVGM71ziibqmOnihKUYnTAH2rPMySBZFshw3gBWev31Ey6zaNRDGw
         e5rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ke0eisTS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SbrFQ/mJObo2AlNegWmrkuD6GEDrksHy5vm9jLyijXM=;
        b=Su6fqkDGvF2C+tXhuVl0KGpRyxzHu0cZLqdKgbS3FxpnNWhIwV+4zv6U1QkZE8Sf5J
         JO2nBHbGrK4lZuAUluc2LLSzsDpsP83/2q/q5/WYluYWhuZH+jJ9amxKXqq+zeYxYqTe
         m4uJ34VdAnsvzStUvCsu4nMRJKg4nEcf9tO0vvt6+3nowK1jiXCh/Kmvak8f7/cS/t4U
         NFOxbxKx2p7R7zNKS3CSOcFSec3NC2OK0Ivc59phPGFUnxTiXSacLEB6ReqgdfF+9Zge
         JyQiJmURasoQ2iJu+ubzePT+faJS2ooIzz3LhbQNsaaWwiNOnmbnx82YNNWs8yr68U9b
         AxvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SbrFQ/mJObo2AlNegWmrkuD6GEDrksHy5vm9jLyijXM=;
        b=Kw6Ov5UPCO7FyN3Ilcp+pw4FfvbFELmK69hLxJqkYplSsv9QHMmUy19qDZICjBkvfk
         NJ9mLQwiYbFg2eiEUpg0no1BNaCIq1+TsRkyPS2NmSwBUEiEYVdRWwvBzq00tt9h8XTn
         ervRVAtsDEOMRSMZXb8isbLRgm+B7fxrS7NjSuwYyGMWzES+5hT0n0yHZiUmQb4aHZjj
         bId0C+FGFOdzYzFY5vu3TUim5I3gwYYpYjh7JFOhMGABp/2QDrR8Lq/yc7Zs5s8Mp/zd
         U4yU2BxtHpVNzvOy/mkg10T+TfpTuCS9pxdlEUJRRr+EjHqWmCHQOfXEhQMa8iYe9NAa
         vLwQ==
X-Gm-Message-State: AJIora+5x4h4EltJfEoLV2Ri8oQ/uSGZzezXYGMeMtbOw9lvVVhU7mti
	FydD+jOXn62kGCAhodkZ/Bo=
X-Google-Smtp-Source: AGRyM1uHj5XAEGvT/XANztBZILiQu2xI0cDoDUmc+uYrn3DjkQvJ4AtsJdNS4AvgZJCW6DMYVX3YqA==
X-Received: by 2002:a05:6e02:17c9:b0:2dc:9b70:56dc with SMTP id z9-20020a056e0217c900b002dc9b7056dcmr6534181ilu.66.1657870994525;
        Fri, 15 Jul 2022 00:43:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:214f:b0:332:109e:3b77 with SMTP id
 z15-20020a056638214f00b00332109e3b77ls252045jaj.2.-pod-prod-gmail; Fri, 15
 Jul 2022 00:43:14 -0700 (PDT)
X-Received: by 2002:a05:6638:411f:b0:33f:8c3d:c4d9 with SMTP id ay31-20020a056638411f00b0033f8c3dc4d9mr5360651jab.259.1657870994016;
        Fri, 15 Jul 2022 00:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657870994; cv=none;
        d=google.com; s=arc-20160816;
        b=uxp0yi0fg/XawEYTXqHXjCe9RtTxKGN7uHi8wzeFILaVHj/Scxv4jm/6BQuAF87m/s
         li+Ek+LEDGAfAAeuDonRZ3I5FYYTzxkqCI49+wnEsnJ/s+DocffLAQkr/p9VNdeOTv0j
         RcW4Zzyn34kyUd9L3dToqhB63eaaLxQkwZecuXlz9uFm9/1pyK29k++8c3dPjlex7fnG
         WXh2OOCybK/V/325sdOdIAzFimyaIF1JHo5bOtD9oB4VBzrH2ZfDvpVTadei7zAU4d7P
         BmymQDULMhC9eDxeHU2+ioNi1OSpXNSERTez/sddNgy+sxMQIIprOU8tBi4WjMxzZAAk
         OFJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wow5GwZUq1ephtzdcsWQKNRsHibDh8Of4LJkNVIGZKs=;
        b=k4FFzb9qDYOtiaaq3MbFsJ57xrv+DhrlEh8QURfWa4PthTiku2+0pBjG6RaiMbG8Wl
         JsyhDNXKVobmMYXrVwhUQ9nPqm0mq/dh8JVVQFrse7s/XckCk0NRcDmPDAK2S7T/TENu
         34R67TxiMNFK1aRZu8iSJw1PCiZaP7APkv3rY+KO3dFplCklIOgFe22joBHbpOdLhGe9
         oBCwNxTETc5xonj7X4dR8QRys0SJIof9NsYc5aVxllsGIADOImR4jkgRLRE2Ox3dpc6i
         XdYls08GPZIyQDSfgb3tnm/bqGRFyfvlILQz8ljL39OkRGnowyinv+SKnHOrdqbinAVB
         B3Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ke0eisTS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id m11-20020a056e02158b00b002dad0373761si172933ilu.0.2022.07.15.00.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 00:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id i14so7225724yba.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 00:43:13 -0700 (PDT)
X-Received: by 2002:a25:d78c:0:b0:66f:5acb:d3bf with SMTP id
 o134-20020a25d78c000000b0066f5acbd3bfmr12396195ybg.307.1657870993486; Fri, 15
 Jul 2022 00:43:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-7-glider@google.com>
 <CANpmjNN=XO=6rpV-KS2xq=3fiV1L3wCL1DFwLes-CJsi=6ZmcQ@mail.gmail.com>
In-Reply-To: <CANpmjNN=XO=6rpV-KS2xq=3fiV1L3wCL1DFwLes-CJsi=6ZmcQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jul 2022 09:42:37 +0200
Message-ID: <CAG_fn=X5w5F1rwHuQqQ9GRYT4MiNGQLh71FRN16Wy3rGJLX_AA@mail.gmail.com>
Subject: Re: [PATCH v4 06/45] kmsan: add ReST documentation
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
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
 header.i=@google.com header.s=20210112 header.b=Ke0eisTS;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
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

> To be consistent with other tools, I think we have settled on "The
> Kernel <...> Sanitizer (K?SAN)", see
> Documentation/dev-tools/k[ac]san.rst. So this will be "The Kernel
> Memory Sanitizer (KMSAN)".

Done (will appear in v5).


> -> "The third stack trace ..."
> (Because it looks like there's also another stack trace in the middle
> and "lower" is ambiguous)

Done

>
> > +where this variable was created.
> > +
> > +The upper stack shows where the uninit value was used - in
>
> -> "The first stack trace shows where the uninit value was used (in
> ``test_uninit_kmsan_check_memory()``)."
Done

> > +KMSAN and Clang
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> The KASAN documentation has a section on "Support" which lists
> architectures and compilers supported. I'd try to mirror (or improve
> on) that.

Renamed this section to "Support", added a line about supported
architectures (x86_64)

>
> > +In order for KMSAN to work the kernel must be built with Clang, which =
so far is
> > +the only compiler that has KMSAN support. The kernel instrumentation p=
ass is
> > +based on the userspace `MemorySanitizer tool`_.
> > +
> > +How to build
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> I'd call it "Usage", like in the KASAN and KCSAN documentation.
Done

>
> > +In order to build a kernel with KMSAN you will need a fresh Clang (14.=
0.0+).
> > +Please refer to `LLVM documentation`_ for the instructions on how to b=
uild Clang.
> > +
> > +Now configure and build the kernel with CONFIG_KMSAN enabled.
>
> I would move build/usage instructions right after introduction as
> that's most likely what users of KMSAN will want to know about first.

Done

> > +How KMSAN works
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > +
> > +KMSAN shadow memory
> > +-------------------
> > +
> > +KMSAN associates a metadata byte (also called shadow byte) with every =
byte of
> > +kernel memory. A bit in the shadow byte is set iff the corresponding b=
it of the
> > +kernel memory byte is uninitialized. Marking the memory uninitialized =
(i.e.
> > +setting its shadow bytes to ``0xff``) is called poisoning, marking it
> > +initialized (setting the shadow bytes to ``0x00``) is called unpoisoni=
ng.
> > +
> > +When a new variable is allocated on the stack, it is poisoned by defau=
lt by
> > +instrumentation code inserted by the compiler (unless it is a stack va=
riable
> > +that is immediately initialized). Any new heap allocation done without
> > +``__GFP_ZERO`` is also poisoned.
> > +
> > +Compiler instrumentation also tracks the shadow values with the help f=
rom the
> > +runtime library in ``mm/kmsan/``.
>
> This sentence might still be confusing. I think it should highlight
> that runtime and compiler go together, but depending on the scope of
> the value, the compiler invokes the runtime to persist the shadow.

Changed to:
"""
Compiler instrumentation also tracks the shadow values as they are used alo=
ng
the code. When needed, instrumentation code invokes the runtime library in
``mm/kmsan/`` to persist shadow values.
"""

> > +
> > +
>
> There are 2 blank lines here, which is inconsistent with the rest of
> the document.

Fixed

> > +Origin tracking
> > +---------------
> > +
> > +Every four bytes of kernel memory also have a so-called origin assigne=
d to
>
> Is "assigned" or "mapped" more appropriate here?

I think initially this was more about origin values that exist in SSA
as well as memory, so not all of them were "mapped".
On the other hand, we're talking about bytes in the memory, so "mapped" is =
fine.

> > +them. This origin describes the point in program execution at which th=
e
> > +uninitialized value was created. Every origin is associated with eithe=
r the
> > +full allocation stack (for heap-allocated memory), or the function con=
taining
> > +the uninitialized variable (for locals).
> > +
> > +When an uninitialized variable is allocated on stack or heap, a new or=
igin
> > +value is created, and that variable's origin is filled with that value=
.
> > +When a value is read from memory, its origin is also read and kept tog=
ether
> > +with the shadow. For every instruction that takes one or more values t=
he origin
>
> s/values the origin/values, the origin/
Done, thanks!


> > +
> > +If ``a`` is initialized and ``b`` is not, the shadow of the result wou=
ld be
> > +0xffff0000, and the origin of the result would be the origin of ``b``.
> > +``ret.s[0]`` would have the same origin, but it will be never used, be=
cause
>
> s/be never/never be/
Done

> > +Passing uninitialized values to functions
> > +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > +
> > +KMSAN instrumentation pass has an option, ``-fsanitize-memory-param-re=
tval``,
>
> "KMSAN instrumentation pass" -> "Clang's instrumentation support" ?
> Because it seems wrong to say that KMSAN has the instrumentation pass.
How about "Clang's MSan instrumentation pass"?

> > +
> > +Sometimes the pointers passed into inline assembly do not point to val=
id memory.
> > +In such cases they are ignored at runtime.
> > +
> > +Disabling the instrumentation
> > +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>
> It would be useful to move this section somewhere to the beginning,
> closer to usage and the example, as this is information that a user of
> KMSAN might want to know (but they might not want to know much about
> how KMSAN works).

I restructured the TOC as follows:

=3D=3D The Kernel Memory Sanitizer (KMSAN)
=3D=3D Usage
--- Building the kernel
--- Example report
--- Disabling the instrumentation
=3D=3D Support
=3D=3D How KMSAN works
--- KMSAN shadow memory
--- Origin tracking
~~~~ Origin chaining
--- Clang instrumentation API
~~~~ Shadow manipulation
~~~~ Handling locals
~~~~ Access to per-task data
~~~~ Passing uninitialized values to functions
~~~~ String functions
~~~~ Error reporting
~~~~ Inline assembly instrumentation
--- Runtime library
~~~~ Per-task KMSAN state
~~~~ KMSAN contexts
~~~~ Metadata allocation
=3D=3D References


> > +Another function attribute supported by KMSAN is ``__no_sanitize_memor=
y``.
> > +Applying this attribute to a function will result in KMSAN not instrum=
enting it,
> > +which can be helpful if we do not want the compiler to mess up some lo=
w-level
>
> s/mess up/interfere with/
Done

> > +code (e.g. that marked with ``noinstr``).
>
> maybe "... (e.g. that marked with ``noinstr``, which implicitly adds
> ``__no_sanitize_memory``)."

Done

> otherwise people might think that it's necessary to add
> __no_sanitize_memory explicitly to noinstr.

Good point!

> > +    ...
> > +    struct kmsan_context kmsan;
> > +    ...
> > +  }
> > +
> > +
>
> 1 blank line instead of 2?
Done

> > +This means that in general for two contiguous memory pages their shado=
w/origin
> > +pages may not be contiguous. So, if a memory access crosses the bounda=
ry
>
> s/So, /Consequently, /
Done


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX5w5F1rwHuQqQ9GRYT4MiNGQLh71FRN16Wy3rGJLX_AA%40mail.gmai=
l.com.
