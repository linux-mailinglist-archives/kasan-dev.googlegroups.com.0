Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEW7CAQMGQEE4YCR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id E7CA032988E
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 10:54:01 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id m22sf1624052vsr.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 01:54:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614678841; cv=pass;
        d=google.com; s=arc-20160816;
        b=qclPDPS4SKQA9sh2kTGlSM7/kdfylbyUk2albYHhB9D7veOdtbXUSFDU7m8XwmXZ1o
         w2kcdfFy7QvEskpv9CMd9g9PQ7mgkM7nQzSXJHkQeZ4jULE/JznFcMogqgBnmkc5RoZU
         21di8bSzrN69gc1mT88RJq4AhEfGTbe6d4OMKU6X8dMFaKRDnqhqwzvNq/D6dSLd/gjS
         EZm1ZWfLJPBThglCXoFAEK4FZPpyzETDE7eudt7DOa2onghjVkpkWpCAXJee8SIVEHBk
         GOeVMvj62GBUo6UQ7ZmmIe3bBoWNjRMOkEdbc36OmuXL3Kph31dgx/GbP8Vd9c4prgS9
         6Hcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B/5US83YhUaa4RSv81DJ5WC5mL14456pmv9ikKlPZw8=;
        b=a90Nyhkmc1SUqQMrTFNudmiAeN6UhOAq8gktAvI7tzjWeSXEdGeU+k3/OEmQz5wHnD
         4PbqCtHi2OEuZ1tqOgtfv26u+jOUk/9/TqkE4J7yyuDpHqijCmm0rr6bQdfftj6O6R84
         oFVT6vmkNet1YOw0V0FM/kLrBSA+2AYvOWcsDgPEx2+0XXSDRwWfp4ZjfAvXMmfaTgx0
         I3CExCIZyamUJd7w/ZhG6X3PmQ6VznfId+zvCH1gc6E8Uqh44byC5fQuVu7BYvj2Oh4I
         crsWdmMUN6rewyVux+0Xf6l5tVie50P2ZFvOPXVr5MXicRldy66zCiUvlh+RzlGx3hSt
         14/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cfWyjvjn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=B/5US83YhUaa4RSv81DJ5WC5mL14456pmv9ikKlPZw8=;
        b=UERnjyWg0FMQmqhfDysoJsFV/aqWA28pwYljMLls2ml2V18gnBpCCwLHMilGwUFORD
         EeZFYmGoEyZjnFLL4mhJ6YskIVzj3eKsQ4Eza+vnGM99tJxGVt8M9Od4OrJVOSdMNAIX
         r9r35N6pDt++JsqttwFtCQslUCV988rpCqEkR7f/heDH7ODo3htKbInECPQoYa+q8XvL
         fb5tQFYslBcFCRx+bQx55e2FF3eDoKCxYxVCvYx+RtphGDl97f3Vmqam0FobCld7alfO
         TwUbTwoab9UO8WrseaQLQrdqfntSzIKD1kC5SK+M1qbUJxFFKrTqxllv7iozjjPfk11b
         K1bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B/5US83YhUaa4RSv81DJ5WC5mL14456pmv9ikKlPZw8=;
        b=ECdcreg8ZFxRLSICrpydu/4LMDP2Ol3MKMX58O4GnYDWfRkAO0KThMxlkxvkpiK28M
         axxTAJkUTi3BZyOJRXMRcKRgXKvYQ5WeafCegYbydK0M63FXkzk7WiI0GMk7J7gtgCy0
         KeaDOu0N8+c2ELq39giVb87nsmxiX7sSEwXJM8CApBTirShDgKHAo/pmWNzs4V+76Ibv
         R8BDdnXC9nX3ggMSjhU7XkvEGUTUvLaRWEIY6EqUwuTf1pHpljq33QLN/LvlKDFzp03A
         YzWx4r5TDWjR4WbP6nH3ERxvgxlBlst/uxOAvECjYkcDMlIEJSBdkjdJeD6Ol/yD0e1C
         LT+Q==
X-Gm-Message-State: AOAM5335H+Fpx5DKgZRwXMU7AVn7vloyfdCfPEiYkSnS1x+BaLYOlAcr
	sHZd0mRQny51Ep2MPBwcrTM=
X-Google-Smtp-Source: ABdhPJx9rmtlS9wbq/DEr0R2whJ1IElydXuZGYZu+BlfczySw7AfR1iJn0YWCToatKxTxwpsF2vihQ==
X-Received: by 2002:ab0:3c91:: with SMTP id a17mr12420908uax.9.1614678840867;
        Tue, 02 Mar 2021 01:54:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:61c5:: with SMTP id m5ls1458850uan.4.gmail; Tue, 02 Mar
 2021 01:54:00 -0800 (PST)
X-Received: by 2002:ab0:54da:: with SMTP id q26mr4090371uaa.126.1614678840326;
        Tue, 02 Mar 2021 01:54:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614678840; cv=none;
        d=google.com; s=arc-20160816;
        b=LFCu1dTeLeoa/j0r/eVU2kwtjvRNtbifXYIrAKMY2LD5TUidM50+iAxODFHC7oJRVV
         DI/tIu6+Nn3dgL8ot+5mpfH60AQLixVexHWs15sXw5eBBpeWvRL2AuqzL4K1bP0bGM8t
         j+wFh4ItOzYzKGuMEvoHBvEQjqgDyJq72lTeZ6ERVOmZmjVIRnpQ+U3Mkqhb77ercn1A
         +FSQMX3PK8ZoyaLNVdWBeJR3ylcC4RIFfbgZrX3daE/AfF6gz43to/sg/7UFA/ZiHXIh
         z4kZATLIWzvpISQnjJsfjtY25KifI76fe/lYUgqrpnrayEQMVPPnjXvIimFqZpepBaRs
         yvfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tvKwxmRwJCtoKJ49eALPKngOjwRbk6LF76WWu5CWfIo=;
        b=UdLivsMoz6W3XjpONXd/aW6Oct1x0qgIXyH6KzacxmlWO6uSRH8DB8tGX511Fn8KmW
         FH623rWleUxBFPinyEc/EVbf8sdV3aV7e4cyMmkY2Y0kv3y89qRp5f4Y1MiAQfDc2MND
         +/MfOK63dmKkArhN3bpgVvEs/oPWEwJswvnW7UdET3ZYvibNtOnAL/L34dJG9wvOj0r1
         y28dP6xFnbXPXDefDT30UlmLOm09rA1ieBfbTJC+XGKYHCXOp/8WzvEwh4VLcusHSVJh
         NHh+05pXuNtSdi7mg0DLuonBdTW5G24WTMWH87r0EdctrQvOqFyapsZAcJ4YnNOlFQb4
         fssA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cfWyjvjn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id n3si927908uad.0.2021.03.02.01.54.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 01:54:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id z126so21363369oiz.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 01:54:00 -0800 (PST)
X-Received: by 2002:aca:d515:: with SMTP id m21mr2637776oig.172.1614678839617;
 Tue, 02 Mar 2021 01:53:59 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
In-Reply-To: <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 10:53:48 +0100
Message-ID: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cfWyjvjn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Tue, 2 Mar 2021 at 10:27, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
> Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit :
> >> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0+=
0x54/0x23c
> >> [   14.998426]
> >> [   15.007061] Invalid read at 0x(ptrval):
> >> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
> >> [   15.015633]  kunit_try_run_case+0x5c/0xd0
> >> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
> >> [   15.025099]  kthread+0x15c/0x174
> >> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
> >> [   15.032747]
> >> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> >> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> >> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfe=
nce/kfence_test.c:636
> >> [   15.053324]     Expected report_matches(&expect) to be true, but is=
 false
> >> [   15.068359]     not ok 21 - test_invalid_access
> >
> > The test expects the function name to be test_invalid_access, i. e.
> > the first line should be "BUG: KFENCE: invalid read in
> > test_invalid_access".
> > The error reporting function unwinds the stack, skips a couple of
> > "uninteresting" frames
> > (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L=
43)
> > and uses the first "interesting" one frame to print the report header
> > (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L=
226).
> >
> > It's strange that test_invalid_access is missing altogether from the
> > stack trace - is that expected?
> > Can you try printing the whole stacktrace without skipping any frames
> > to see if that function is there?
> >
>
> Booting with 'no_hash_pointers" I get the following. Does it helps ?
>
> [   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x5=
4/0x23c
> [   16.848521]
> [   16.857158] Invalid read at 0xdf98800a:
> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
> [   16.865731]  kunit_try_run_case+0x5c/0xd0
> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
> [   16.875199]  kthread+0x15c/0x174
> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
> [   16.882847]
> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 000000=
00
> [   16.918153] DAR: df98800a DSISR: 20000000
> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 000000=
08 c084b32b c016eb38
> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
> [   16.947292] Call Trace:
> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x23c=
 (unreliable)

The "(unreliable)" might be a clue that it's related to ppc32 stack
unwinding. Any ppc expert know what this is about?

> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapter+0=
x24/0x30
> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
> [   16.981896] Instruction dump:
> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 907f=
0028 90ff001c
> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 81=
2a4b98 3d40c02f
> [   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfence=
/kfence_test.c:636
> [   17.008223]     Expected report_matches(&expect) to be true, but is fa=
lse
> [   17.023243]     not ok 21 - test_invalid_access

On a fault in test_invalid_access, KFENCE prints the stack trace based
on the information in pt_regs. So we do not think there's anything we
can do to improve stack printing pe-se.

What's confusing is that it's only this test, and none of the others.
Given that, it might be code-gen related, which results in some subtle
issue with stack unwinding. There are a few things to try, if you feel
like it:

-- Change the unwinder, if it's possible for ppc32.

-- Add code to test_invalid_access(), to get the compiler to emit
different code. E.g. add a bunch (unnecessary) function calls, or add
barriers, etc.

-- Play with compiler options. We already pass
-fno-optimize-sibling-calls for kfence_test.o to avoid tail-call
optimizations that'd hide stack trace entries. But perhaps there's
something ppc-specific we missed?

Well, the good thing is that KFENCE detects the bad access just fine.
Since, according to the test, everything works from KFENCE's side, I'd
be happy to give my Ack:

  Acked-by: Marco Elver <elver@google.com>

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPGj4C2rr2FbSD%2BFC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q%40mail.gmai=
l.com.
