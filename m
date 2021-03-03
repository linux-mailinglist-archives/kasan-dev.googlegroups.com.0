Return-Path: <kasan-dev+bncBDLKPY4HVQKBBA6X7WAQMGQEUVLG5GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C75C32B6F6
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:57:08 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id o8sf8944561ljp.15
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:57:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614769027; cv=pass;
        d=google.com; s=arc-20160816;
        b=kf/QqhFimQKKvqJ4vzHh/MjIweFx6P26TvDPu5jzimtsXPkoRfZex0Fy+vLezianfL
         h3dHm6Mykp/UgzgkfUGmZKEJ9+ILERdHWzhzoq1hhuCUvyQ7vYuQUE43h/CWwJWMVNIS
         jdnYvKAvpAAPeGvNeAHBD1s3UsWr1aPEv9c5CNIjPTiueqbbmFVIpMn0NM1mM44FJULx
         CCtpqSpRV3u8s3xikzuAJhVL8qWYKUIr/cptzhPZoCbHOrbEiHn4OB+hYMJ23/pQiUlU
         ZXvtNbhtc8DYT/GF0n8f+X7rTrp1LTHUCY1PdaQv95HE2TTB/ati67HJz4/gDQACrKBs
         OKAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=iYwfxbbsFLZ1dW+nZP6njRe8ROkB/UkJb1gEMVQpJ8g=;
        b=hkpy1X88jnr4moLJVbj1M7hzfT9+naeNwiHAkYCOU3cc0w08YYrOQqoNkRfiddaZ8l
         N+50xljP17zVyXTyI0AlCf3+53lKwG8IzBO32mHZydI/bd+eMIJu5XPIK035KyOPTdP5
         9RZ2arFCJkCXHYu91gk8ccJNU5Ns43f+6dGlk9+/hfeY3XUHu37pWzRdJ+nTSqfSenw8
         4hxlEo7DeSqIqVzWqBHP7Z9NUDmD9uGAxYquNyYIZyJ50f/EDxdj1QYsghAw5FLZKqjw
         dXJngkWmK0RvPXrBgsVtWERiFKvXI6sSDGEZbNWXDWeQRjx7OLTFxM/oMucLvsa8QmG2
         ugYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYwfxbbsFLZ1dW+nZP6njRe8ROkB/UkJb1gEMVQpJ8g=;
        b=l1TL18oBYIMsRXvnJZnpJh+MymdShF3T5KmmoM2mxbOAH18NyTES3GXMHDGrijKoqh
         vptl271mNLlfq4UDq9ES1Rt+UsiRkCa53Ffy30jZSpdgP/Sax4D+6ISmctBacSTHfEgz
         PEEL6dh3nVoUc29rZsLPabIwxFseShAz7Q00Sf2hM11+Kjb62VHVpDnqtUHcqmdEaswa
         G1TodxfeUh0+eKdUY/RbweY11q++w7g4Sd9/TZtBGBpB2bLI5vocphg7QKMyuPfqvn8E
         scm0zb1czAGqNq7DE30Q27Q3LK73lC5Mf1M1zKreVHytqSW2gM0EJ8X51MqjelByPknX
         VbUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYwfxbbsFLZ1dW+nZP6njRe8ROkB/UkJb1gEMVQpJ8g=;
        b=oAQmw49uXXI3dTCOZrOJCPWe+sH5QzL8p22aGbVwUjqHSCGG9qGpcEmFZ/IP7VjgoW
         z3LIkfGv1k5YA5FO885HjPiFeCEzMNWnzGkgjcP0qFirARajXSACbaXC+HCPDCds7Gdb
         yGZNdkh2NqFV5x22epZPhU0+3CTZ7XvKFh5XGrQUtdMCLPNvozqMxCsM6mp+jBARvPwS
         KUqCCWK4rXH/gMhGg5ZEMCVHFhbG8Ae3842wHtHw5o4iErPDZf1kaZyqXhlCxO1hDQVs
         7x73Wa4jvl9LihUBF64sEHc1wRBHAtVJxFcFI6jW6fATHl6P47y1Cnif30oAq/dtjZmD
         xeMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RLg+Fewr2z00KA/mqN8G9/076gLI6X0R24i73JmA0x2YteGUv
	lViMwPH8k0IL3ZxJxBZ7Ffc=
X-Google-Smtp-Source: ABdhPJzSIAOQWEpx87mseU6HKrzVv3KktLtfuFasxoYW18CrazbPyUCa3QRDIiaqtIWrkCAN97j1mQ==
X-Received: by 2002:a2e:9196:: with SMTP id f22mr14669674ljg.419.1614769027857;
        Wed, 03 Mar 2021 02:57:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls806166lff.1.gmail; Wed, 03
 Mar 2021 02:57:07 -0800 (PST)
X-Received: by 2002:a05:6512:374c:: with SMTP id a12mr15228680lfs.34.1614769026998;
        Wed, 03 Mar 2021 02:57:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614769026; cv=none;
        d=google.com; s=arc-20160816;
        b=DBbT9FbGjkDK9bY19WcH72VFLZhzSS4pahFWqv4Md9fmE9VpXA32l2sbAKLo+KY7pd
         348Xh363cZ8ALx15pLJ9KcuwP1xbwAfLzWVvWvwpo7+QN38WQsSg5w88kLaivuevg7bN
         /MXNowWK8IFsRi0p22EauN0O7//2avVCECNZaBfGV1wiiL/FGRoBc0dxZD0lGQKALCX9
         upzgyOxExGVdJ4iKIz/dFCMT8+UT4oXqwRKqzebzIsh81wCXNfarsR0zvTqmJBx7wO6j
         i5qych2563QCYbVKvGq64jBKE7U2YuDe0VQiwwBqdYMJ6cd/GYTV/DiBPI9mj74gTq+J
         B5/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=o7aQtXiiJ8o6fNVi+KozjPhwFIFicqWpxZt3TLUuW28=;
        b=WlTGb9GQMlhZTC0HYWdKZt8pY6tTXRpA8hFpbdjncdv9bazCpbqCfuPM75ttI29Bfl
         PzTLnGGs9LBJYl7XU9kG+e7ra47/Dr+a2v+89PyID/AOR5zQPq8fpFxxtXiaUIFEB1r8
         WNXBh+5gcRkDx0s2gGyeKro/VMj91Zfm4X6cBqE2iZAhga5YiINSpgrdnKkeOr8GxjUq
         3otejASdR6DtG413JxC0imZcorwrmwJH1ZVSgG+7IW8CdfqBQmlCxs1qeE4i1Kz9laWr
         94qJGzq3dwSOVMEiNn/9TBSAAf7jKJxIGJJ8N5cwNRDJwP57781rz9+sY26L24h5gM1T
         mJBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id m17si1002480lfg.0.2021.03.03.02.57.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:57:06 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Dr9tR6h0Xz9tygN;
	Wed,  3 Mar 2021 11:57:03 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id i-a1Nz-ZudRo; Wed,  3 Mar 2021 11:57:03 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Dr9tR5VLxz9tyZS;
	Wed,  3 Mar 2021 11:57:03 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 9A0638B7CD;
	Wed,  3 Mar 2021 11:56:50 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 9UicWIe8FC3n; Wed,  3 Mar 2021 11:56:47 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3B6948B7D8;
	Wed,  3 Mar 2021 11:56:30 +0100 (CET)
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
 <3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu>
 <CANpmjNMKEObjf=WyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <b66d0bbd-d587-cf1c-11df-daafeaf70552@csgroup.eu>
Date: Wed, 3 Mar 2021 11:56:28 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNMKEObjf=WyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA@mail.gmail.com>
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



Le 03/03/2021 =C3=A0 11:39, Marco Elver a =C3=A9crit=C2=A0:
> On Wed, 3 Mar 2021 at 11:32, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>>
>>
>> Le 02/03/2021 =C3=A0 10:53, Marco Elver a =C3=A9crit :
>>> On Tue, 2 Mar 2021 at 10:27, Christophe Leroy
>>> <christophe.leroy@csgroup.eu> wrote:
>>>> Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit :
>>>>>> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.=
0+0x54/0x23c
>>>>>> [   14.998426]
>>>>>> [   15.007061] Invalid read at 0x(ptrval):
>>>>>> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
>>>>>> [   15.015633]  kunit_try_run_case+0x5c/0xd0
>>>>>> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
>>>>>> [   15.025099]  kthread+0x15c/0x174
>>>>>> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
>>>>>> [   15.032747]
>>>>>> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>>>>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>>>>>> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>>> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/k=
fence/kfence_test.c:636
>>>>>> [   15.053324]     Expected report_matches(&expect) to be true, but =
is false
>>>>>> [   15.068359]     not ok 21 - test_invalid_access
>>>>>
>>>>> The test expects the function name to be test_invalid_access, i. e.
>>>>> the first line should be "BUG: KFENCE: invalid read in
>>>>> test_invalid_access".
>>>>> The error reporting function unwinds the stack, skips a couple of
>>>>> "uninteresting" frames
>>>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c=
#L43)
>>>>> and uses the first "interesting" one frame to print the report header
>>>>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c=
#L226).
>>>>>
>>>>> It's strange that test_invalid_access is missing altogether from the
>>>>> stack trace - is that expected?
>>>>> Can you try printing the whole stacktrace without skipping any frames
>>>>> to see if that function is there?
>>>>>
>>>>
>>>> Booting with 'no_hash_pointers" I get the following. Does it helps ?
>>>>
>>>> [   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+=
0x54/0x23c
>>>> [   16.848521]
>>>> [   16.857158] Invalid read at 0xdf98800a:
>>>> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
>>>> [   16.865731]  kunit_try_run_case+0x5c/0xd0
>>>> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
>>>> [   16.875199]  kthread+0x15c/0x174
>>>> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
>>>> [   16.882847]
>>>> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
>>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
>>>> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
>>>> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
>>>> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
>>>> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 000=
00000
>>>> [   16.918153] DAR: df98800a DSISR: 20000000
>>>> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 000=
00008 c084b32b c016eb38
>>>> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
>>>> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
>>>> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
>>>> [   16.947292] Call Trace:
>>>> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x=
23c (unreliable)
>>>
>>> The "(unreliable)" might be a clue that it's related to ppc32 stack
>>> unwinding. Any ppc expert know what this is about?
>>>
>>>> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
>>>> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapte=
r+0x24/0x30
>>>> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
>>>> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
>>>> [   16.981896] Instruction dump:
>>>> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 9=
07f0028 90ff001c
>>>> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0=
 812a4b98 3d40c02f
>>>> [   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfe=
nce/kfence_test.c:636
>>>> [   17.008223]     Expected report_matches(&expect) to be true, but is=
 false
>>>> [   17.023243]     not ok 21 - test_invalid_access
>>>
>>> On a fault in test_invalid_access, KFENCE prints the stack trace based
>>> on the information in pt_regs. So we do not think there's anything we
>>> can do to improve stack printing pe-se.
>>>
>>> What's confusing is that it's only this test, and none of the others.
>>> Given that, it might be code-gen related, which results in some subtle
>>> issue with stack unwinding. There are a few things to try, if you feel
>>> like it:
>>>
>>> -- Change the unwinder, if it's possible for ppc32.
>>>
>>> -- Add code to test_invalid_access(), to get the compiler to emit
>>> different code. E.g. add a bunch (unnecessary) function calls, or add
>>> barriers, etc.
>>>
>>> -- Play with compiler options. We already pass
>>> -fno-optimize-sibling-calls for kfence_test.o to avoid tail-call
>>> optimizations that'd hide stack trace entries. But perhaps there's
>>> something ppc-specific we missed?
>>>
>>> Well, the good thing is that KFENCE detects the bad access just fine.
>>> Since, according to the test, everything works from KFENCE's side, I'd
>>> be happy to give my Ack:
>>>
>>>     Acked-by: Marco Elver <elver@google.com>
>>>
>>
>> Thanks.
>>
>> For you information, I've got a pile of warnings from mm/kfence/report.o=
 . Is that expected ?
>>
>>     CC      mm/kfence/report.o
>> In file included from ./include/linux/printk.h:7,
>>                    from ./include/linux/kernel.h:16,
>>                    from mm/kfence/report.c:10:
>> mm/kfence/report.c: In function 'kfence_report_error':
>> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argume=
nt of type 'signed size_t',
>> but argument 6 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>>       5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>>         |                  ^~~~~~
>> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_S=
OH'
>>      11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>>         |                  ^~~~~~~~
>> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>>     343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>>         |         ^~~~~~~~
>> mm/kfence/report.c:207:3: note: in expansion of macro 'pr_err'
>>     207 |   pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n=
",
>>         |   ^~~~~~
>> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argume=
nt of type 'signed size_t',
>> but argument 4 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>>       5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>>         |                  ^~~~~~
>> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_S=
OH'
>>      11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>>         |                  ^~~~~~~~
>> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>>     343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>>         |         ^~~~~~~~
>> mm/kfence/report.c:216:3: note: in expansion of macro 'pr_err'
>>     216 |   pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
>>         |   ^~~~~~
>> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argume=
nt of type 'signed size_t',
>> but argument 2 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>>       5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>>         |                  ^~~~~~
>> ./include/linux/kern_levels.h:24:19: note: in expansion of macro 'KERN_S=
OH'
>>      24 | #define KERN_CONT KERN_SOH "c"
>>         |                   ^~~~~~~~
>> ./include/linux/printk.h:385:9: note: in expansion of macro 'KERN_CONT'
>>     385 |  printk(KERN_CONT fmt, ##__VA_ARGS__)
>>         |         ^~~~~~~~~
>> mm/kfence/report.c:223:3: note: in expansion of macro 'pr_cont'
>>     223 |   pr_cont(" (in kfence-#%zd):\n", object_index);
>>         |   ^~~~~~~
>> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argume=
nt of type 'signed size_t',
>> but argument 3 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>>       5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>>         |                  ^~~~~~
>> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_S=
OH'
>>      11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>>         |                  ^~~~~~~~
>> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>>     343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>>         |         ^~~~~~~~
>> mm/kfence/report.c:233:3: note: in expansion of macro 'pr_err'
>>     233 |   pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)a=
ddress,
>>         |   ^~~~~~
>>
>> Christophe
>=20
> No this is not expected. Is 'signed size_t' !=3D 'long int' on ppc32?
>=20

No, it is an 'int' not a 'long int', see arch/powerpc/include/uapi/asm/posi=
x_types.h

#ifdef __powerpc64__
typedef unsigned long	__kernel_old_dev_t;
#define __kernel_old_dev_t __kernel_old_dev_t
#else
typedef unsigned int	__kernel_size_t;
typedef int		__kernel_ssize_t;
typedef long		__kernel_ptrdiff_t;
#define __kernel_size_t __kernel_size_t


What is probably specific to powerpc is that ptrdiff_t is not same as ssize=
_t unlike in=20
include/uapi/asm-generic/posix_types.h :


/*
  * Most 32 bit architectures use "unsigned int" size_t,
  * and all 64 bit architectures use "unsigned long" size_t.
  */
#ifndef __kernel_size_t
#if __BITS_PER_LONG !=3D 64
typedef unsigned int	__kernel_size_t;
typedef int		__kernel_ssize_t;
typedef int		__kernel_ptrdiff_t;
#else
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t	__kernel_ssize_t;
typedef __kernel_long_t	__kernel_ptrdiff_t;
#endif
#endif



I have no warning on ppc64.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b66d0bbd-d587-cf1c-11df-daafeaf70552%40csgroup.eu.
