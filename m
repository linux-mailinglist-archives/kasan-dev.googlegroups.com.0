Return-Path: <kasan-dev+bncBCR5PSMFZYORBHGI7CAQMGQEOFVDUGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BE8E5329CE6
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 12:40:13 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id v184sf16534906qkd.22
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 03:40:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614685213; cv=pass;
        d=google.com; s=arc-20160816;
        b=u74eg9ybwP39jjPkaqQ8PGQRBqpnuH5QxsrqnpVpooEGF5x+h728Za0OVbsGbp3UuQ
         c5LvJcheB9OZWLK9mBdPeyrmLHQTQZTRPYrsBRUx7bI7eTvwrh1W2o3b6n+Vyo7a+JXt
         b4nssfsykn5XSo0SwTLqUf2KnuFL1LHZJj3aet/VbmXv4ZzzjYA+AlO1zF4U4twcrmFw
         Kd9CotcS0wq/d2Lh70gqrLaIjl7q4Tc497/I09GvJ28j93ud8RMyXqE5rx5TXPEZCByb
         G2JtPLUlcds6/Huk4mX4YBLKfwFhv3Oe4OD3H9YqStU8IUmgmXeAMJSPcB6vPcKaQMMK
         kcug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=p8j8+SixEXjhUfSuSfNtjaJAVujc6b3nuQkkZ1X+UGw=;
        b=IIUrBigNRpv+TZkrOR1HYWVfiJ+K533PefNzY5+vZEw689Pp63docLbZjATavsKIQi
         dmDjzAE5plafOPkccjz0ZcpoulSUcHCM092HkWFL6sm2cTxthdvrYRARNVmT0jK1oa0Q
         fY/ReYqybr/tgzx3rn6stsDv4+vQ0+wPSj2aQmPT02ZM8dWvF+rf/mtqOe9cjsbRcv9S
         7dPBNW8f4mwyXvw197X0BHZD55SrE6R5krsgbksazlhu+2VCz0KquBytCeheYLtpY2yo
         +VfBPv0jZZOx/8CvoRHQ9sv7FrGNUe3909TiBUjej28WVetPZJ3szg+xysncgEOGNEFT
         4Mjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="gz/h8ua+";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p8j8+SixEXjhUfSuSfNtjaJAVujc6b3nuQkkZ1X+UGw=;
        b=VWphd+3JK9ftHr/ixgT54riEKtDTo6V5sPMrYKUOuL+8dbT5/12gZ3EwuiWc0EQgwG
         JFgI0JXCgnAlzKwz4ovBt1ZiDabBTTpEjZSfGxznm0tPJtQBgvnFQ6OagHNOIsVrit0J
         wlS8tF9USBinLJB4/m4xo5W1vqfE2/jsnk+SmtVo+y8Gd0zl5juQzJDEUmUOGECjeuUQ
         kbfomTuZLkFVhHROTcWELUvs7xvm1s15qsS39Y81tuTc1QQvfkoZ//I9h2wjVp2x2nIm
         MX4YzKBkAtgfQ33jh3Dbi9Fgv4fPc4uVl8YPyGt2hv569Nl/EdY3U+l7yPF/2ZOhBpFa
         5LIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=p8j8+SixEXjhUfSuSfNtjaJAVujc6b3nuQkkZ1X+UGw=;
        b=TWeh4IeoekLSTkALvAwt0YkJUi3LuHxak2+Q2/McODpD9XZwOM9E7GpCtCGCABzxD1
         J1wVZAU3cnoUypAmRXVP2FMces9Gh4kWumvWc/ZDTLkouL3KqLSeD4lznwc0dE91yMz+
         rtUVghUQfBRpcVbwcKOiAdyOaodySFY41YJJaUY6/txXuxMy5L+aFLrXnDvCeWyFi9wn
         N9k+kjY+kqfqHM2IkrN1OmMLje0E0J0LJ/UmcGT2YST3Kz6aLP5p9ESHFEEeuyp6xQ2e
         hPlyRRtZexhzWyPipFUZOgJDcpasdPEjmRuqfkM9/QM5PZylX0ty8Y9qq0hFsg6lo0Jw
         8kqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DRpuhrkE5tmwWQDIfpLf6tidLkBr3JvIul9dNF6QRzwFwjzJy
	wjhKZXHn8mk7lEWd+fWf8tA=
X-Google-Smtp-Source: ABdhPJx/btnQ2wSW9BybJaN4M2ZenHB4r3XzSrTFDyIpo4ppJPFeQRu/uZh7o4LPg4pifroxBJ/XGw==
X-Received: by 2002:ad4:5614:: with SMTP id ca20mr10700741qvb.37.1614685212757;
        Tue, 02 Mar 2021 03:40:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:d2:: with SMTP id p18ls7684142qtw.3.gmail; Tue, 02
 Mar 2021 03:40:12 -0800 (PST)
X-Received: by 2002:ac8:4e95:: with SMTP id 21mr8184888qtp.177.1614685212299;
        Tue, 02 Mar 2021 03:40:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614685212; cv=none;
        d=google.com; s=arc-20160816;
        b=rBHUcwVJqVfmqLtgOHdQNiveZT37DSe0hnPC+Ve5/Z0F1gDsbyeV3DMzTHWeXfXJO1
         e6cCoqodx0lARdtcQCm88mGaDdMdTkYr8XgKGmhXLPAulxQPsVeJ2/oKejcrWvpndBAc
         RYnR34OoisB53h/sqjiLpQiJc2kCUsK8uUv8aZj+Nu0JTdImCnh4rG9PiplOjgjvpZZG
         k65Or9B4UvPMOfs1PSZwMunULH8CvcRZF91jaB4mzkXAYvMh7vPN24JeMI9Un+Ox2DiJ
         QS5rA1vaW+RdRXlX/nBE+eT/V9Y7jMGNrgta6CllyIO2oHpFynzgu7gLCN0e4MMBislD
         m0VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=qnXEMb74LFjJdDFTchm+rFQQSCK63cIEqJKvUj+9GG8=;
        b=CrRxZNzUJ7DxJP27Dlm5jfytmKQh8QpMwekwlONMrS9aIVmk3NCvbLoQcRlKaiYIBe
         6KdTLd9qTwbSGpWaMmKatYFcQyxhWot0L7qTYdsjBpCkiMrSk/TH6xt9xCJy+1T84XPu
         IUe7rtb8rFfldnUXdKUwKDIqKaQINiZQSgOwEQQ+qGhdmG4ZMZvWGFjAHlf9JhRWL7fJ
         g0Gax14TPualEp2E+HA+Oo+JB5UC4iFcc0LEQEScVpPjB8Fknqs3RdJjfFNwoEEU9iBr
         eIFqvNwdjIfnUvPKPzc+y6l8ZoOM+1rMCofRRLey9jTvpWZPTI5VpHxRYX5MJMhStC5u
         pZFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="gz/h8ua+";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [2401:3900:2:1::2])
        by gmr-mx.google.com with ESMTPS id j10si753938qko.3.2021.03.02.03.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Mar 2021 03:40:11 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as permitted sender) client-ip=2401:3900:2:1::2;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4DqZtX1LwJz9sVt;
	Tue,  2 Mar 2021 22:40:04 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Marco Elver
 <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt
 <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Dmitry
 Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
In-Reply-To: <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
Date: Tue, 02 Mar 2021 22:40:03 +1100
Message-ID: <87h7ltss18.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="gz/h8ua+";       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2401:3900:2:1::2 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:
> Le 02/03/2021 =C3=A0 10:53, Marco Elver a =C3=A9crit=C2=A0:
>> On Tue, 2 Mar 2021 at 10:27, Christophe Leroy
>> <christophe.leroy@csgroup.eu> wrote:
>>> Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit :
>>>>> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0=
+0x54/0x23c
>>>>> [   14.998426]
>>>>> [   15.007061] Invalid read at 0x(ptrval):
>>>>> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
>>>>> [   15.015633]  kunit_try_run_case+0x5c/0xd0
>>>>> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
>>>>> [   15.025099]  kthread+0x15c/0x174
>>>>> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
>>>>> [   15.032747]
>>>>> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>>>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>>>>> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kf=
ence/kfence_test.c:636
>>>>> [   15.053324]     Expected report_matches(&expect) to be true, but i=
s false
>>>>> [   15.068359]     not ok 21 - test_invalid_access
>>>>
>>>> The test expects the function name to be test_invalid_access, i. e.
>>>> the first line should be "BUG: KFENCE: invalid read in
>>>> test_invalid_access".
>>>> The error reporting function unwinds the stack, skips a couple of
>>>> "uninteresting" frames
>>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#=
L43)
>>>> and uses the first "interesting" one frame to print the report header
>>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#=
L226).
>>>>
>>>> It's strange that test_invalid_access is missing altogether from the
>>>> stack trace - is that expected?
>>>> Can you try printing the whole stacktrace without skipping any frames
>>>> to see if that function is there?
>>>>
>>>
>>> Booting with 'no_hash_pointers" I get the following. Does it helps ?
>>>
>>> [   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0=
x54/0x23c
>>> [   16.848521]
>>> [   16.857158] Invalid read at 0xdf98800a:
>>> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
>>> [   16.865731]  kunit_try_run_case+0x5c/0xd0
>>> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
>>> [   16.875199]  kthread+0x15c/0x174
>>> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
>>> [   16.882847]
>>> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>>> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
>>> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
>>> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
>>> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 0000=
0000
>>> [   16.918153] DAR: df98800a DSISR: 20000000
>>> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 0000=
0008 c084b32b c016eb38
>>> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
>>> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
>>> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
>>> [   16.947292] Call Trace:
>>> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x2=
3c (unreliable)
>>=20
>> The "(unreliable)" might be a clue that it's related to ppc32 stack
>> unwinding. Any ppc expert know what this is about?
>>=20
>>> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
>>> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapter=
+0x24/0x30
>>> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
>>> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
>>> [   16.981896] Instruction dump:
>>> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 90=
7f0028 90ff001c
>>> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 =
812a4b98 3d40c02f
>>> [   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfen=
ce/kfence_test.c:636
>>> [   17.008223]     Expected report_matches(&expect) to be true, but is =
false
>>> [   17.023243]     not ok 21 - test_invalid_access
>>=20
>> On a fault in test_invalid_access, KFENCE prints the stack trace based
>> on the information in pt_regs. So we do not think there's anything we
>> can do to improve stack printing pe-se.
>
> stack printing, probably not. Would be good anyway to mark the last level=
 [unreliable] as the ppc does.
>
> IIUC, on ppc the address in the stack frame of the caller is written by t=
he caller. In most tests,=20
> there is some function call being done before the fault, for instance=20
> test_kmalloc_aligned_oob_read() does a call to kunit_do_assertion which p=
opulates the address of the=20
> call in the stack. However this is fragile.
>
> This works for function calls because in order to call a subfunction, a f=
unction has to set up a=20
> stack frame in order to same the value in the Link Register, which contai=
ns the address of the=20
> function's parent and that will be clobbered by the sub-function call.
>
> However, it cannot be done by exceptions, because exceptions can happen i=
n a function that has no=20
> stack frame (because that function has no need to call a subfunction and =
doesn't need to same=20
> anything on the stack). If the exception handler was writting the caller'=
s address in the stack=20
> frame, it would in fact write it in the parent's frame, leading to a mess=
.
>
> But in fact the information is in pt_regs, it is in regs->nip so KFENCE s=
hould be able to use that=20
> instead of the stack.
>
>>=20
>> What's confusing is that it's only this test, and none of the others.
>> Given that, it might be code-gen related, which results in some subtle
>> issue with stack unwinding. There are a few things to try, if you feel
>> like it:
>>=20
>> -- Change the unwinder, if it's possible for ppc32.
>
> I don't think it is possible.

I think this actually is the solution.

It seems the good architectures have all added support for
arch_stack_walk(), and we have not.

Looking at some of the implementations of arch_stack_walk() it seems
it's expected that the first entry emitted includes the PC (or NIP on
ppc).

For us stack_trace_save() calls save_stack_trace() which only emits
entries from the stack, which doesn't necessarily include the function
NIP is pointing to.

So I think it's probably on us to update to that new API. Or at least
update our save_stack_trace() to fabricate an entry using the NIP, as it
seems that's what callers expect.

cheers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87h7ltss18.fsf%40mpe.ellerman.id.au.
