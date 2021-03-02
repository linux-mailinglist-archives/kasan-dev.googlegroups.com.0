Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3GH7CAQMGQEW5T3EGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E840B329CCE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 12:39:30 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id n196sf5437909vkn.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 03:39:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614685165; cv=pass;
        d=google.com; s=arc-20160816;
        b=KDlKsdyIFKuzpM1OPv5wmRmRFg/Fp454ba01yDT8tpGFeH6JnwK1bn4suUX8slm3XY
         hvAZTvOcEI2jLx3l0gZ1pcajo2ThTxDpkZZd2d/BQgj70+DTbGbx4citbwjwV5yFB87r
         6522PJVBIFFdn7IoAfYSId9EkELGeQW1Za7nD4T++zBY3TNdG+6ehccO4ep60ESers0b
         mID42k9ckrWUcCLUhml7AyyXN/ETIzVMAc3iL3xExJJ1WgefskGFDi+MmXuBilsizMRg
         +mO9SMMlyBRfowfA6AfE0wyjSDrjnB7H9+Xq2LPHksqzVT7tFOFEmCYnjRUeVEopX94m
         wZIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+uWmlD0Im6ASpFhx7V6wdaRGiX7LiW0Ti1g4IlhG9Qs=;
        b=SxH09/HuFQPu6PhqsViIyuIQx+sh4inQRxqL3ofwsLrZCMtYimp8S6TwQmW7oCUcIq
         G+x9ZPnYn9JCIpg2ih6I6QQNvzn5EpSdLMqW7ldqOwuDd9kDpL1SM5wlCOfRbwUKZuyV
         PuDkbHpbCD231cSESLtHUDq74S2TAWGNaGqrzDwhtr4uryL9gDWwtH5hhgvgybQO0xWI
         FkO035oKuiD/RLR0hBkwAXETNTnJOa8LGHEcUCArAFzjZTvBoWATr1pZj9KvcQ7js/DG
         umpwIafcMf+yH2q0MgR1ml3SB2x841zZ2cL062evw6SkYyFZGbnYnXjkMwTr+U9vUhCH
         JnTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBhA66Cx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+uWmlD0Im6ASpFhx7V6wdaRGiX7LiW0Ti1g4IlhG9Qs=;
        b=nUkUOMqXNimjP8wh1SJUk+aSLG//7Tbq1CC4qWhimXkalQmqBpVY9a2NjBVmHOzD1m
         KsxDE3Ho1ILw4kJVmqXNVUU794pLYWMxsQFq0Dx/CJwvvM8h4DRh32gj5QmyojvlbSqM
         m7pUguMQcdtuw2CZk2eWRHhrCTxWtxehyHCU8g3UFbbMgrCsx68nMwmaNbk5836IIPT/
         s6O/xRvzXU52Jk+iYu/XB/ARN1zskZ7KXZvoZPUcxxZOGp4CRouWy4UtP5Lztv4/mHNi
         9ulFnssU8ElAoELo9gc1BjZYL1D2Ov+MHR97w/NYOfApPPmZymf1bQZ72kR3uRCpUqUZ
         rumw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+uWmlD0Im6ASpFhx7V6wdaRGiX7LiW0Ti1g4IlhG9Qs=;
        b=MAGsYlj3QNJiX7bHKvYaDEzo9+VMDUUSJDct+7SpI7mnJHsANxgq+jBf3meJUW3c7v
         95zQBPlBmDLyiohtfEozcVurFN8AMvhvptjirtibuaYy9Cum58mVX1bkCnUdZexx7VVH
         LzNApDN4civ93Or60PKXGFdPmbyW4AVu8RR0tS7YIjWCB4YMfH/ZU4PtzO9Low6c8ZXz
         mxfV6L/Oa+TiIEmGSVeZdk6FRZM5DFywn0C7hyxb2aQ39257ogFiJx0dLcefyiqohYXJ
         ilmOcHCqkBJB8wVB1Boe5BOcklNy7CHGFllvDgcrGLBxPJLO3lJsZzqaXFmTyPcYj/lE
         qRmA==
X-Gm-Message-State: AOAM531UEng1TzQAACHDmV5aG7G9a0K8pIWd+nUNRGyQvuom7ger2fdp
	vel8pSDSdQGXats0SKhKUG4=
X-Google-Smtp-Source: ABdhPJxHS/m2Vmj4w+LuTxrrheVT4X9xdMlVcH0SmOADRFlVvdxQaSgAVNrmF7st33bfyOsv9v8kKA==
X-Received: by 2002:a67:7f42:: with SMTP id a63mr1666616vsd.43.1614685164865;
        Tue, 02 Mar 2021 03:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cc66:: with SMTP id w6ls399651vkm.10.gmail; Tue, 02 Mar
 2021 03:39:24 -0800 (PST)
X-Received: by 2002:a1f:7846:: with SMTP id t67mr1440837vkc.21.1614685164338;
        Tue, 02 Mar 2021 03:39:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614685164; cv=none;
        d=google.com; s=arc-20160816;
        b=Gwp/wlGcZzyvwq/hIfbka2zvrVibNnXyVYrtqfLxKjY/kFViw2eCjoTTPj1ZmtnB0p
         mOSxIn3jIqibpFXFaAF6gENC+Ol5+jiwxQlgfKAcuo+kigFDrpAejsbEXQuCVzx6yakF
         GWcyfkbld1nGPAzq6+w6j95MxruDYWZ8EbI2ROoTIWjqxRFECYROedVW4lHlM2doZPu+
         7YymzvRdilTz1Ez6vBbnYsB7QCbBDLX+7WTPgG2onDm/6SJeERefVaIJ6CcowZlqoixo
         U6ZpHtusUfLnxH28mC9NocsAURn04hcVXv2j+nEVcmRqeiLziq8s0GQhON4A84UFpwxd
         I00w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Awszz/knFkSmYzdRRUyEmKjIRZ+f0H/e4tpJCA3RU4E=;
        b=Ine6XfNFlO6o6dWmbc+tQmmRjoLkAf3tOaFbTRWw3WmoGp1g6ztRBuNmt8TY3DZnLD
         9ml0MNIEhBh8CZ2slXnyRt/EN4EqZbp6IV3K/KekalYUNfDWaMuFL69lP1bcAbmAZGzB
         3TfrnQHSY6dfT61x3oJnFgpqhPmxJ4CaOF6e8zz2cL2KUdsnP/9dE1zk7XBL/VIM5dKX
         RnRYacQsCOCK197BgESr54NAEdzRz7wN4Izk1XM5YMVrBvNj3m8JRFa5dFknED4XW1Jl
         PbD1/nm3hWf226b0FcnHCMhqifrhj3uDNs6uxKwjtlewlZkz28Y/1a8445Y5RZqbl5Z8
         bpbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBhA66Cx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d23si27431vsq.1.2021.03.02.03.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 03:39:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id d9so19615178ote.12
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 03:39:24 -0800 (PST)
X-Received: by 2002:a9d:644a:: with SMTP id m10mr17823761otl.233.1614685163647;
 Tue, 02 Mar 2021 03:39:23 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
In-Reply-To: <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 12:39:12 +0100
Message-ID: <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iBhA66Cx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Tue, 2 Mar 2021 at 12:21, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
[...]
> >> Booting with 'no_hash_pointers" I get the following. Does it helps ?
> >>
> >> [   16.837198] ==================================================================
> >> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x54/0x23c
> >> [   16.848521]
> >> [   16.857158] Invalid read at 0xdf98800a:
> >> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
> >> [   16.865731]  kunit_try_run_case+0x5c/0xd0
> >> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
> >> [   16.875199]  kthread+0x15c/0x174
> >> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
> >> [   16.882847]
> >> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> >> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> >> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
> >> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
> >> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
> >> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000000
> >> [   16.918153] DAR: df98800a DSISR: 20000000
> >> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 00000008 c084b32b c016eb38
> >> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> >> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
> >> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
> >> [   16.947292] Call Trace:
> >> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x23c (unreliable)
> >
> > The "(unreliable)" might be a clue that it's related to ppc32 stack
> > unwinding. Any ppc expert know what this is about?
> >
> >> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
> >> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapter+0x24/0x30
> >> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
> >> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
> >> [   16.981896] Instruction dump:
> >> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 907f0028 90ff001c
> >> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 812a4b98 3d40c02f
> >> [   17.000711] ==================================================================
> >> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/kfence_test.c:636
> >> [   17.008223]     Expected report_matches(&expect) to be true, but is false
> >> [   17.023243]     not ok 21 - test_invalid_access
> >
> > On a fault in test_invalid_access, KFENCE prints the stack trace based
> > on the information in pt_regs. So we do not think there's anything we
> > can do to improve stack printing pe-se.
>
> stack printing, probably not. Would be good anyway to mark the last level [unreliable] as the ppc does.

We use stack_trace_save_regs() + stack_trace_print().

> IIUC, on ppc the address in the stack frame of the caller is written by the caller. In most tests,
> there is some function call being done before the fault, for instance
> test_kmalloc_aligned_oob_read() does a call to kunit_do_assertion which populates the address of the
> call in the stack. However this is fragile.

Interesting, this might explain it.

> This works for function calls because in order to call a subfunction, a function has to set up a
> stack frame in order to same the value in the Link Register, which contains the address of the
> function's parent and that will be clobbered by the sub-function call.
>
> However, it cannot be done by exceptions, because exceptions can happen in a function that has no
> stack frame (because that function has no need to call a subfunction and doesn't need to same
> anything on the stack). If the exception handler was writting the caller's address in the stack
> frame, it would in fact write it in the parent's frame, leading to a mess.
>
> But in fact the information is in pt_regs, it is in regs->nip so KFENCE should be able to use that
> instead of the stack.

Perhaps stack_trace_save_regs() needs fixing for ppc32? Although that
seems to use arch_stack_walk().

> > What's confusing is that it's only this test, and none of the others.
> > Given that, it might be code-gen related, which results in some subtle
> > issue with stack unwinding. There are a few things to try, if you feel
> > like it:
> >
> > -- Change the unwinder, if it's possible for ppc32.
>
> I don't think it is possible.
>
> >
> > -- Add code to test_invalid_access(), to get the compiler to emit
> > different code. E.g. add a bunch (unnecessary) function calls, or add
> > barriers, etc.
>
> The following does the trick
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 4acf4251ee04..22550676cd1f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -631,8 +631,11 @@ static void test_invalid_access(struct kunit *test)
>                 .addr = &__kfence_pool[10],
>                 .is_write = false,
>         };
> +       char *buf;
>
> +       buf = test_alloc(test, 4, GFP_KERNEL, ALLOCATE_RIGHT);
>         READ_ONCE(__kfence_pool[10]);
> +       test_free(buf);
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>   }
>
>
> But as I said above, this is fragile. If for some reason one day test_alloc() gets inlined, it may
> not work anymore.

Yeah, obviously that's hack, but interesting nevertheless.

Based on what you say above, however, it seems that
stack_trace_save_regs()/arch_stack_walk() don't exactly do what they
should? Can they be fixed for ppc32?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYEmLtQEu5G%3DzJLUzOBaGoqNKwLyipDCxvytdKDKb7mg%40mail.gmail.com.
