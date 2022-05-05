Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYND2CJQMGQETOQBLYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 43EA351C6B1
	for <lists+kasan-dev@lfdr.de>; Thu,  5 May 2022 20:05:23 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id eo13-20020ad4594d000000b004466661ece9sf3838206qvb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 May 2022 11:05:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651773922; cv=pass;
        d=google.com; s=arc-20160816;
        b=CBCKb4qGsi9hQT7zt5BcyWty5Y82o99nVr+zVDPIpzpWKiwR2/9lvQ1YzoocGjnQAt
         QNpvtQ0Qa7pPOpzg93M0Ijum/1yNwX/N0cIDk4UJriLbrily9Iq8Xruity1LTeRTnCV5
         EVumBhtvYKWpTPQxmMVIFNeIUq2oUv95YYLaauWlXCOBHhkohBSYHeZ7apsxlBEK778Z
         ezxUFdbmVQeqYKwEKq2uIa35r+bkD0tuov9zgM9QFPE+RHXuGK4IiLJSy/halqGRo5M6
         APlrEHzAjyT4xMTxzixErM2xQNaePpiZ9Nh4KpOWBRi3THfvbxtUOWv8ip+ecmY503aD
         Sh7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U78xsbKuKnB2lJOyUMCrapCK/YSyGsXSlRllVN6kg4E=;
        b=WONAFWs5hTo35cXpJ7K6LWUtXrbnsgSZCnKASq0PTEyldOq73x5o4umVM/1krUBpwq
         XvDA5Pzs5NWa7pPyDdhMqmI/GghrocRXQf6PmqzCQzaFBEoaoEoJc7dgXWo7XLzBBXpx
         cUpbi5tCinZH+QNREh+TO67eN7r3V6JKG4HnYYjihGYi/hmqIRBeeQrFzu0dF8no/cJT
         T6BWSVOuQ9BkwvDj7pLXQelOcPV2Wgc2CV2IUm+bLwEx31yQsUOB0kkT59Dm9plq04V9
         QBfQ1YDjYfEXxIlnxvr0zlsBG4xwr/6zkg/AF8rknjktNYhnk2WWORS+pwEMFjkLtZKa
         6CaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ndgpe6IF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U78xsbKuKnB2lJOyUMCrapCK/YSyGsXSlRllVN6kg4E=;
        b=qeVU/Dtv/HVxFuGacZ7RS90vKRQaF7ksknHC1+7V2dIDbnmN1ojL7YbX2Fp69GugQe
         6YV0KZ8brzo4E0VkHNrwlEbizVlufPtzf0KFRxHyW6a+n4bP9mtJgSxYrm+EF422GN0g
         WRgx5RrKj5NmfDi3ilsD1qlXp8SWolQ4aNZhl0/jk37glYDsM1qDd6mmO7dvfwZdN6RY
         rr11CrcBlUWcJDD/9JEVsAk96r5QhuVXCbmJ0t6py5swkD/mj5pNTTpyQSSMAWOE+iwQ
         zI9xBcxb7+thWw8hqsIy0sDj2IFiKcGOkys1nupHaCXQ+T5dHfzm50anuXA3foj3lQ0I
         UoTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U78xsbKuKnB2lJOyUMCrapCK/YSyGsXSlRllVN6kg4E=;
        b=440BTpW9wKEDOWZeFzCmV3naIBnrYhovVsUOrocWdHUpkrcmRaVpRNUax1J0SCmR+k
         ZP89o1KPsAa6ik/bcWezU7f8z5yznHYOXuXlXqiggdX6cKf9SHyMVDFLoScYV47zNu/4
         J9PMG3b9KetdH2K7trC7zFIYgwXFbRevfbVaYEvowj661pQ7hZGvg/iNu8Lf+zJ9Kf9H
         hP8CFQvNZE1EPl6K2oS2A72rHGlyIC9Ve7AuvgyDsMWt2PPQk1ykJqPskKTCf+nna2Wk
         p4m4mI9A1ALAJEpWb/BdnsybmM1VuUSNaS/1Lz5cUIlWztMkrrsYIRIusmTwuYD6Vn/b
         PcOA==
X-Gm-Message-State: AOAM5324W18ru0JqT+SERkSMjdw1IM6M2hW7ajSm3L7sGlPxtx+XBLxW
	3ysIL0S7oW8W5sNOISW29BY=
X-Google-Smtp-Source: ABdhPJz+ldgvP3F6Adr6Nd6h4sUV70qLKoeTsn7gRgpJvU4cPDp65YZgSRu89JQpzr8Vn22cERHxTA==
X-Received: by 2002:a37:a890:0:b0:69f:be02:9fbe with SMTP id r138-20020a37a890000000b0069fbe029fbemr20141732qke.314.1651773922020;
        Thu, 05 May 2022 11:05:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4107:b0:45a:af61:b125 with SMTP id
 kc7-20020a056214410700b0045aaf61b125ls2570513qvb.10.gmail; Thu, 05 May 2022
 11:05:21 -0700 (PDT)
X-Received: by 2002:a05:6214:1cc5:b0:443:6a15:5894 with SMTP id g5-20020a0562141cc500b004436a155894mr23007015qvd.59.1651773921575;
        Thu, 05 May 2022 11:05:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651773921; cv=none;
        d=google.com; s=arc-20160816;
        b=zYHv+813WNjYEdF4PuLBLWcZFiunf/U9/qvKvR4Mrzsn82Bflm573idY49oCzPLFB7
         a3Sia70iELeU79dg51zR2CGjx6QdqErG9AIRX4EzMAt0ByfBnG7DtTKL5xEnYmUqiMKJ
         +25JcHpa3rVH4KrQcwT+VIOMRFd0VPgOavWtrkDw9YKcHnSZFPiI1m72xWiotIxD3zRs
         vs4UGbBd5SFuTdBET8iCZXAxdZKeM2SnbzCXQgjbk2UdgubPLjWOsacgCdbinbOcgVc8
         ui8rRIuGK4TKcgfo6z315w4uOHzJIV+zedFM7UrQ4CX9XM6ybuZyrDVCXhqqLD57Eue4
         chlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lfs9ILt8sxsLN7d0CVj7IGkIjZk0ddULlJ98hbLjdl0=;
        b=tzcCBIwu/fYVZ1eOarV3JrZNhTcXs/Z68ngqVnbJkqiJkctcdJeGKFejGQpGC0QQ31
         2HTqrSW6RWMbY/rCJNDVkYKGgtmhAZJKbq1KH3DU0X2hOMIxVuL1KUWeD9FKT/zIdtvS
         TojKM+24zthyOp5JMXwc/QK3REJ0xWHAI9h2LxzhOP2q8pRJaIuSeQ5cTCljLfgEk6Qj
         AEDqGPDlEompSgE22uVW67UfxQXvuywOM2bPgVQC6vC+PMrOn/HjTdxkf/DNAS0DrdxE
         iczN4UlD9XDSIHEK7dqmCJ9izMQ7SFAj4F1nukmZPuQkvjVewEZ+JR+fcydnq0lpGNpC
         1j2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ndgpe6IF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id t21-20020ac86a15000000b002eb870d94ffsi132830qtr.2.2022.05.05.11.05.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 May 2022 11:05:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id w187so9001261ybe.2
        for <kasan-dev@googlegroups.com>; Thu, 05 May 2022 11:05:21 -0700 (PDT)
X-Received: by 2002:a25:aa62:0:b0:648:590f:5a53 with SMTP id
 s89-20020a25aa62000000b00648590f5a53mr23847856ybi.5.1651773921071; Thu, 05
 May 2022 11:05:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx>
In-Reply-To: <87y1zjlhmj.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 May 2022 20:04:44 +0200
Message-ID: <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ndgpe6IF;       spf=pass
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

On Tue, May 3, 2022 at 12:00 AM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> Alexander,

First of all, thanks a lot for the comments, those are greatly appreciated!
I tried to revert this patch and the previous one ("kmsan:
instrumentation.h: add instrumentation_begin_with_regs()") and
reimplement unpoisoning pt_regs without breaking into
instrumentation_begin(), see below.

> >
> > Regarding the regs, you are right. It should be enough to unpoison the
> > regs at idtentry prologue instead.
> > I tried that initially, but IIRC it required patching each of the
> > DEFINE_IDTENTRY_XXX macros, which already use instrumentation_begin().
>
> Exactly 4 instances :)
>

Not really, I had to add a call to `kmsan_unpoison_memory(regs,
sizeof(*regs));` to the following places in
arch/x86/include/asm/idtentry.h:
- DEFINE_IDTENTRY()
- DEFINE_IDTENTRY_ERRORCODE()
- DEFINE_IDTENTRY_RAW()
- DEFINE_IDTENTRY_RAW_ERRORCODE()
- DEFINE_IDTENTRY_IRQ()
- DEFINE_IDTENTRY_SYSVEC()
- DEFINE_IDTENTRY_SYSVEC_SIMPLE()
- DEFINE_IDTENTRY_DF()

, but even that wasn't enough. For some reason I also had to unpoison
pt_regs directly in
DEFINE_IDTENTRY_SYSVEC(sysvec_apic_timer_interrupt) and
DEFINE_IDTENTRY_IRQ(common_interrupt).
In the latter case, this could have been caused by
asm_common_interrupt being entered from irq_entries_start(), but I am
not sure what is so special about sysvec_apic_timer_interrupt().

Ideally, it would be great to find that single point where pt_regs are
set up before being passed to all IDT entries.
I used to do that by inserting calls to kmsan_unpoison_memory right
into arch/x86/entry/entry_64.S
(https://github.com/google/kmsan/commit/3b0583f45f74f3a09f4c7e0e0588169cef9=
18026),
but that required storing/restoring all GP registers. Maybe there's a
better way?


>
> then
>
>      instrumentation_begin();
>      foo(fargs...);
>      bar(bargs...);
>      instrumentation_end();
>
> is a source of potential false positives because the state is not
> guaranteed to be correct, neither for foo() nor for bar(), even if you
> wipe the state in instrumentation_begin(), right?

Yes, this is right.

> This approximation approach smells fishy and it's inevitably going to be
> a constant source of 'add yet another kmsan annotation/fixup' patches,
> which I'm not interested in at all.
>
> As this needs compiler support anyway, then why not doing the obvious:
>
> #define noinstr                                 \
>         .... __kmsan_conditional
>
> #define instrumentation_begin()                 \
>         ..... __kmsan_cond_begin
>
> #define instrumentation_end()                   \
>         __kmsan_cond_end .......
>
> and let the compiler stick whatever is required into that code section
> between instrumentation_begin() and instrumentation_end()?

We define noinstr as
__attribute__((disable_sanitizer_instrumentation))
(https://llvm.org/docs/LangRef.html#:~:text=3Ddisable_sanitizer_instrumenta=
tion),
which means no instrumentation will be applied to the annotated
function.
Changing that behavior by adding subregions that can be instrumented
sounds questionable.
C also doesn't have good syntactic means to define these subregions -
perhaps some __xxx_begin()/__xxx_end() intrinsics would work, but they
would require both compile-time and run-time validation.

Fortunately, I don't think we need to insert extra instrumentation
into instrumentation_begin()/instrumentation_end() regions.

What I have in mind is adding a bool flag to kmsan_context_state, that
the instrumentation sets to true before the function call.
When entering an instrumented function, KMSAN would check that flag
and set it to false, so that the context state can be only used once.
If a function is called from another instrumented function, the
context state is properly set up, and there is nothing to worry about.
If it is called from non-instrumented code (either noinstr or the
skipped files that have KMSAN_SANITIZE:=3Dn), KMSAN would detect that
and wipe the context state before use.

By the way, I've noticed that at least for now (with pt_regs
unpoisoning performed in IDT entries) the problem with false positives
in noinstr code is entirely gone, so maybe we don't even have to
bother.

> Yes, it's more work on the tooling side, but the tooling side is mostly
> a one time effort while chasing the false positives is a long term
> nightmare.

Well said.

> Thanks,
>
>         tglx



--=20
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
kasan-dev/CAG_fn%3DXxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8%3D01jw%40mail.gm=
ail.com.
