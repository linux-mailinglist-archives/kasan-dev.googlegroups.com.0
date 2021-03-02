Return-Path: <kasan-dev+bncBDLKPY4HVQKBBI577CAQMGQEXSOFAIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D8D329BFC
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 12:21:08 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id d11sf3459695lfe.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 03:21:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614684067; cv=pass;
        d=google.com; s=arc-20160816;
        b=WgCEHVK8n2YUI7N/oattjARcxsM14ZNla2zldPEKtUaO73N70xSiGUrDp12ZjnpvDj
         8/BpjIk9EcFeQfAsH1mPIz4SzKM5fm5kU5SOioCnG9v1pMIshnMpOQTHBBit50hT65GM
         3+Xh3yWb+78dgkHINorB87rB3xh9x/39DgiImnNibqS+4OkZFF3ebM1RzpStNrW3VCjf
         9ezNhsj9HSlVMKxoFScrPbjYWE1I+JshLW/bsG1qAaicSZnMnpnumWSawpGbj3urO5R7
         VVmUpE3J3djrGZZgvla9u01htklHPNasgC4vyrrsg69UnmjF4ShXvTz5vpKQD9BeHoZI
         Q6jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=DUaNXOW/12lCMGvRKw437FDnB8zSs5JR9UrD56z0KPo=;
        b=QgwSr2dydvU9BO4JMYMQVbLjTmAj4vx709fyhQhi5DzWk+Hd8ITN9e2p9m/NDvoqrE
         Jt+1X0MNu8yyuof/AQgalaOcX36UtGm72esC7/9fsB6CwP1qYC7Lx7geF9pS+LKcQlSk
         20+G5760Wlkb1IjnXLja6FvUPL1ZH3OpsS2idWD0NPsRUQQb1sXjhJ+X62dnTmv5inA4
         yyfS1T6qglVucSvh9JetPZ1tm3JWM/cdeeuYbwGQWpd/BaBMAnv5q7xedldFvwJe9k6A
         C5nEPSdRmBHZk5LCkSrecZAFGKwFJePHphuO8vkzRzqWRfzJEjLU9FGk6ZdaYyx77g9l
         tPeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DUaNXOW/12lCMGvRKw437FDnB8zSs5JR9UrD56z0KPo=;
        b=WfVGYeDvNW8gulG9arXuFuUWJMGe+OKjJhqPEWABgg7t07g2Rad7sVW84EJp1KvajZ
         M5+GPosh1VweiGlPsqBKn2tDpfO9Y21rRwgp+n6H/JEEArfv3zyX2NbGBezZyueObO48
         wOvbG7RXUBXB8hnZmWCWiSIkpjQBiwiL/kmBQfHW7GZDdNyDm9OFZBzJrk9SplQ082+D
         rHwAS2iC8DZoeRROlFweAdl8sdOqeqZ4WeRLuAtXgIO2p1FecDF0rbiJB8GPBootSOIo
         ifqbd/itFID72xMFFqJ38+idWyR1XbsQefSLVcEBiiNRNYX0E9/pPsP33CxW+J1Cwx2E
         vRFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DUaNXOW/12lCMGvRKw437FDnB8zSs5JR9UrD56z0KPo=;
        b=HGyi7ZQeGVySMLjoDD/pGkPp/Z8TEz0hMrIlD0VbFcQTZ9IUqC4f4zR53btYnZdh4f
         +j0gaIUHf2IaGb1r3ewe+0V2nvuFbMKzOlCiTrr9T9WO8a+qU1BsTWlsLWchNkFmUsfx
         n/pkbYwv7Cp3hp6a+O4+MBEH3bqjVvkzaaIlBJ36Fz19YEESlLChcn1V31MZkj6LMgLk
         8pRzN+vmkylPIosvFyNbR0p1Xsk7RlbzjVyqAIvcxqMzlW/hzT8b3SV/WSdFIO4BZQPX
         7bEagnzNoBv/vlqkwPlZHOMCUHOJ2M7gUZaeMjTCTk+mF9cUUZTBCPQQmJmWXz5crihR
         u2lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300fDN3Fqc1zr5Ccrq4GE5wI1UwVksIGiNL2Fs9iUrArqa/W+d4
	VRkD51q1Fc4mVylTILgLTlQ=
X-Google-Smtp-Source: ABdhPJwTrADylO7L6s0CuXIABRH0Mb3LxZgvKp1zidaJqAxG0fDPXddyPaNQafT5w3vfSfyMzS57wA==
X-Received: by 2002:a2e:8592:: with SMTP id b18mr11815169lji.155.1614684067678;
        Tue, 02 Mar 2021 03:21:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls7822839lfu.3.gmail; Tue,
 02 Mar 2021 03:21:06 -0800 (PST)
X-Received: by 2002:a05:6512:118f:: with SMTP id g15mr12141621lfr.274.1614684066595;
        Tue, 02 Mar 2021 03:21:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614684066; cv=none;
        d=google.com; s=arc-20160816;
        b=UTpG3zIkZ+RfRKJAFHPfpGSIcGLhzjdb/cIS59mikPXWUbecukce7ZjAKbTuoCb1Tl
         P3QxUnISEF4oMeUmOCWMGVWjw05j9ut8pFr7eF93ecJK86r1crN3aamE7AU/Y4HkK1Um
         tlX54R3a87v7a8ssUvxKr+wX3hXIEv2Msajjg/Y+F0ngKp3oqOJfOxtshcdqwb99lAZA
         7ImVG7GjOpvmYPHK0SRCThi9WblVF4gI6nbEtd/PvQFdVNh38hHuambDhT+109JezfVJ
         3r7oW4J8T11Ld0oE+2/RM+OArhGI70vbatgjGuT8o7lCEy2MDVic4660YJQifhufJuaw
         o94Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=iAZbZTBOhxmyK40BbJ5kDVGUB5mUOjHevkX8+P7gYHE=;
        b=XtG0DIFULMsHkyP4HpKNs+GgKnmNQvVY/FsSlVyXJG4TmndMQRVaW78BR/7/XDbIhB
         KjgKXyoE092bkBpKcidIct/ZWMoHkWOmiWcze/MxUJy40o6oVbWVUv3tLVEfglXnAE7n
         ftN9Cb6ittNTw4cIkBX0HtnWgbt32fYytgQTziYzwfLbDAVKHa9CYyHpGMnfH9SjpQRd
         u5pDyvBfODqTtkYkm3QgRQU6FKLCyWUGIOTegQHZvO1yfWD8eGVFSALB2kt1PrGY1lQd
         VjXxxjMd2+GEqNQYZZuYmWopQ1RW63l0hhF6XbEzSjy9W8MhMYMzhOAI9hpDUwi6s5Bs
         uxGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id k21si852927lji.3.2021.03.02.03.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Mar 2021 03:21:06 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DqZSc4Rq1z9v0XH;
	Tue,  2 Mar 2021 12:21:04 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 43cCyl6SrVuX; Tue,  2 Mar 2021 12:21:04 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DqZSc2SqKz9v0XG;
	Tue,  2 Mar 2021 12:21:04 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 928738B7AF;
	Tue,  2 Mar 2021 12:21:05 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id YFKLrjJMMdVn; Tue,  2 Mar 2021 12:21:05 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id DACDB8B75F;
	Tue,  2 Mar 2021 12:21:04 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
Date: Tue, 2 Mar 2021 12:21:02 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 02/03/2021 =C3=A0 10:53, Marco Elver a =C3=A9crit=C2=A0:
> On Tue, 2 Mar 2021 at 10:27, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>> Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit :
>>>> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0+=
0x54/0x23c
>>>> [   14.998426]
>>>> [   15.007061] Invalid read at 0x(ptrval):
>>>> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
>>>> [   15.015633]  kunit_try_run_case+0x5c/0xd0
>>>> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
>>>> [   15.025099]  kthread+0x15c/0x174
>>>> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
>>>> [   15.032747]
>>>> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>>>> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfe=
nce/kfence_test.c:636
>>>> [   15.053324]     Expected report_matches(&expect) to be true, but is=
 false
>>>> [   15.068359]     not ok 21 - test_invalid_access
>>>
>>> The test expects the function name to be test_invalid_access, i. e.
>>> the first line should be "BUG: KFENCE: invalid read in
>>> test_invalid_access".
>>> The error reporting function unwinds the stack, skips a couple of
>>> "uninteresting" frames
>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L=
43)
>>> and uses the first "interesting" one frame to print the report header
>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L=
226).
>>>
>>> It's strange that test_invalid_access is missing altogether from the
>>> stack trace - is that expected?
>>> Can you try printing the whole stacktrace without skipping any frames
>>> to see if that function is there?
>>>
>>
>> Booting with 'no_hash_pointers" I get the following. Does it helps ?
>>
>> [   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x=
54/0x23c
>> [   16.848521]
>> [   16.857158] Invalid read at 0xdf98800a:
>> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
>> [   16.865731]  kunit_try_run_case+0x5c/0xd0
>> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
>> [   16.875199]  kthread+0x15c/0x174
>> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
>> [   16.882847]
>> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
>> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
>> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
>> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000=
000
>> [   16.918153] DAR: df98800a DSISR: 20000000
>> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 00000=
008 c084b32b c016eb38
>> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
>> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
>> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
>> [   16.947292] Call Trace:
>> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x23=
c (unreliable)
>=20
> The "(unreliable)" might be a clue that it's related to ppc32 stack
> unwinding. Any ppc expert know what this is about?
>=20
>> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
>> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapter+=
0x24/0x30
>> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
>> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
>> [   16.981896] Instruction dump:
>> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 907=
f0028 90ff001c
>> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 8=
12a4b98 3d40c02f
>> [   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfenc=
e/kfence_test.c:636
>> [   17.008223]     Expected report_matches(&expect) to be true, but is f=
alse
>> [   17.023243]     not ok 21 - test_invalid_access
>=20
> On a fault in test_invalid_access, KFENCE prints the stack trace based
> on the information in pt_regs. So we do not think there's anything we
> can do to improve stack printing pe-se.

stack printing, probably not. Would be good anyway to mark the last level [=
unreliable] as the ppc does.

IIUC, on ppc the address in the stack frame of the caller is written by the=
 caller. In most tests,=20
there is some function call being done before the fault, for instance=20
test_kmalloc_aligned_oob_read() does a call to kunit_do_assertion which pop=
ulates the address of the=20
call in the stack. However this is fragile.

This works for function calls because in order to call a subfunction, a fun=
ction has to set up a=20
stack frame in order to same the value in the Link Register, which contains=
 the address of the=20
function's parent and that will be clobbered by the sub-function call.

However, it cannot be done by exceptions, because exceptions can happen in =
a function that has no=20
stack frame (because that function has no need to call a subfunction and do=
esn't need to same=20
anything on the stack). If the exception handler was writting the caller's =
address in the stack=20
frame, it would in fact write it in the parent's frame, leading to a mess.

But in fact the information is in pt_regs, it is in regs->nip so KFENCE sho=
uld be able to use that=20
instead of the stack.

>=20
> What's confusing is that it's only this test, and none of the others.
> Given that, it might be code-gen related, which results in some subtle
> issue with stack unwinding. There are a few things to try, if you feel
> like it:
>=20
> -- Change the unwinder, if it's possible for ppc32.

I don't think it is possible.

>=20
> -- Add code to test_invalid_access(), to get the compiler to emit
> different code. E.g. add a bunch (unnecessary) function calls, or add
> barriers, etc.

The following does the trick

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 4acf4251ee04..22550676cd1f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -631,8 +631,11 @@ static void test_invalid_access(struct kunit *test)
  		.addr =3D &__kfence_pool[10],
  		.is_write =3D false,
  	};
+	char *buf;

+	buf =3D test_alloc(test, 4, GFP_KERNEL, ALLOCATE_RIGHT);
  	READ_ONCE(__kfence_pool[10]);
+	test_free(buf);
  	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
  }


But as I said above, this is fragile. If for some reason one day test_alloc=
() gets inlined, it may=20
not work anymore.


>=20
> -- Play with compiler options. We already pass
> -fno-optimize-sibling-calls for kfence_test.o to avoid tail-call
> optimizations that'd hide stack trace entries. But perhaps there's
> something ppc-specific we missed?
>=20
> Well, the good thing is that KFENCE detects the bad access just fine.
> Since, according to the test, everything works from KFENCE's side, I'd
> be happy to give my Ack:
>=20
>    Acked-by: Marco Elver <elver@google.com>
>=20

Thanks
Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/08a96c5d-4ae7-03b4-208f-956226dee6bb%40csgroup.eu.
