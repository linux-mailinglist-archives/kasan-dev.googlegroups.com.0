Return-Path: <kasan-dev+bncBDLKPY4HVQKBBO6J7WAQMGQEDPV522I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C063032B691
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:28:11 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id p8sf2737912wmq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:28:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767291; cv=pass;
        d=google.com; s=arc-20160816;
        b=E18lqD49CBaitOZ2PzxU9dtTDHO5YMbYZmqYpDJclTSbflqjl9lnfIyrfR5yRH15bV
         KulfP19Okjf+brGCXahWYUD0hY3BJiXC3CthfKbrbEMJix47pr4C4lXAmHmktqBnp0Hw
         AN0oJ4jJxqoaXfGBT8y2nyt2ulcu3HZjB/18zeFvH3EWRYZjlmiiMb66d/Zz8KzKleis
         ay45/vWLJjDLkOqZPtMPOoX8ZbqjQtTqtzWxOfJeZWnMVTFmJlLV2rtEIVcuGxGHbq9v
         BDSJhQ1xiiQLl7wTnD1lbE/qiU+c6lpcGDmn9i71+iQh/R9idjuxLlWti2LXxuX6iYgm
         hZbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=uBE8D2dWzuB2J+Ksd7GZ0hduZ7Zke70VkWMp4YIskOc=;
        b=eqIkH5vOpigAQ2gKh/ks1lkL0wJLk59tpVl5iY6BBNOIwBrsF7+DsJTteflFULyfXe
         lpxHIiN24uKx/dOvgtTmRcKxpDyQ1IbuV2ggZY5N0OHLtEGmzJs7fSFAZnQ+0INQZvAV
         f1NxbMl+tvcVcPynH642HbQ51gahTIXPH3RGI47QkJ9HIApTVnxE5vJLK42xAqZM45wE
         SChZ/t2rtwLfN+wj/3YZQ5edmRaFB8eFeSPG5Yge7RolEhrBVbM0L/yhmz4MEktBtJ5w
         WWuHlmmGnf7HP4D6L12b1t5RM0o2mDt6on8suYonkBWeXp9Y9/uoZPwHUw42RH17ytDA
         muiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uBE8D2dWzuB2J+Ksd7GZ0hduZ7Zke70VkWMp4YIskOc=;
        b=iGntMivDT2aoHzoSN7LwAT4GIO+OEQupkk9LvnYSounOVNEQ5rATd10XJlIoOQwAMi
         h6Dy9emty0uKvYDtmiL24/47RRKWjJYg+lTqhgTbMQNNIJlsIUpWd72hx3JmGzBIQTMM
         wawVDnB+IiHgeJAFBTn7ntSjElem9UJjAlKdadXBp+sNWprVFXhPgVPNZuoBSbV7JDFk
         93pjPxGwKLpsn7mcoz3c/KpFvmYY1fi4dS/Co9RRtTD8/HcJM1uwo6uBn3IZLBfBFSdM
         ZXiCwZhEUuTGzz5q6oY8zj6raixEftt8yT/9UdhibpV1w9yer7VMtR3OR5BVcUqjyVck
         tsNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uBE8D2dWzuB2J+Ksd7GZ0hduZ7Zke70VkWMp4YIskOc=;
        b=Zm+Ok5djgAutxQoHpGRoVFOnzWPmPe29cPS4jSy84LkMq3wcU0jG6pP+jICAmmymxo
         aDP7iUQH8bxRVIgCB13suNvYCuNX90/SkztRDoB4egPWtZEPm1AolUcxq655B1xOFR/m
         veHBq5cglH7tMzgX3GEDxBzs/zIee0wbeYTRNQtJyDF3Z5CFHz6Sc/sbWPp8/vuaK4T8
         S87hqDYvoNUqaSk/ySHQRkNF4sN4s6okexEA1Qbq7yctW4rQOcEnpTepTyNm7HCwMEmi
         km2vo2EPeDmQPQpdBQy4CKhWvrZvKele4Uj36xolpHE6wGXupowd/uOQpz3neVvXgd8z
         KDwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uoAcQoNLAC/tWZsN6O2WZb5WOZTr7ckJb6hGgk1R20ODycNYE
	uk393SMC9VaqqEZfr1+b3uU=
X-Google-Smtp-Source: ABdhPJyYLTXGufYNEorBbnItMYuq3WcYtdslfcFyMYcRMzUjjbWfFki4KpktU62xIc+YDD0Pr7ASEA==
X-Received: by 2002:a05:600c:2f08:: with SMTP id r8mr8497087wmn.95.1614767291475;
        Wed, 03 Mar 2021 02:28:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c2:: with SMTP id u2ls938341wmm.3.canary-gmail;
 Wed, 03 Mar 2021 02:28:10 -0800 (PST)
X-Received: by 2002:a05:600c:608:: with SMTP id o8mr8675858wmm.42.1614767290618;
        Wed, 03 Mar 2021 02:28:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767290; cv=none;
        d=google.com; s=arc-20160816;
        b=V+yzB3uhZDxhPnB2L6BYmg31eIRKp45LTGiNCwJO9J1cVk5HWji+xU+7SyExFxzZNL
         jTJ/Nb/HUoGcbkRsnyFsqonzHpbNyPMgEmB2+mYf+3Gg4aOKuyH7AItZRjoiMc5o1o0r
         GV5BKgJWOmhGAVyxU543cdZqRxqg3sYvnynTw1hT0aF08nGya6B+vcIQ6+vj78wm28/E
         yylu8RUkwb1SFAKtfgX7vdDVGDbXS3cgp1gyVzE/RTlbZEWWDrqSiPZAcMHKjLVYFPjq
         CTEl8Rs5cku8+2l9UfWArv8l9sQ3wVvodwLyaPrjInDTFZLStSaT7JI3ILJajOL3jE4T
         NcSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=efgoKDbYTpVNaU6H9ixjPBOXSZQlmDMgS455/HIiakQ=;
        b=qbNp88ZWBUG7JFaHm7fym7sX2oiUYR000V4FulxXjaZQdpFXAitygra1k4mnxpA2wj
         ub6xwmVC2p6V7Was49PrSy/06945aXhMtGstL47MH09kkHHyzFiq8fGwMhndcDQCrsWt
         Rp/6FdYVUZpal431Lui3RnxXkHvOxOA2yZqQwCLsqMfj8/vodVfHDXqRZ7WinUQd2Vja
         sURD0taGG6eM0LMeZfI/UzRRUChLFIbVwH+Ds4pk+xrD2SV5nEExQy+SmunrL2sGxbYM
         eBRiCwQNtipK9j7s3hgmOkjLeP/WH5gtLyVrlI6vreoaRSEDd+cVhR6zEYA+2iuAVc4B
         DXFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id h16si545412wrx.2.2021.03.03.02.28.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:28:10 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Dr9F41pSLz9tygt;
	Wed,  3 Mar 2021 11:28:08 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id FbkezhdaHit1; Wed,  3 Mar 2021 11:28:08 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Dr9F403Lxz9tygd;
	Wed,  3 Mar 2021 11:28:08 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 23E278B7D0;
	Wed,  3 Mar 2021 11:28:09 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id UzqfpylKXQEC; Wed,  3 Mar 2021 11:28:09 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 074028B7D1;
	Wed,  3 Mar 2021 11:28:06 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Michael Ellerman <mpe@ellerman.id.au>, Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Dmitry Vyukov <dvyukov@google.com>,
 LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <87h7ltss18.fsf@mpe.ellerman.id.au>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <f911a6ad-2f7a-7173-7e51-2afc25d127a2@csgroup.eu>
Date: Wed, 3 Mar 2021 11:28:02 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <87h7ltss18.fsf@mpe.ellerman.id.au>
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



Le 02/03/2021 =C3=A0 12:40, Michael Ellerman a =C3=A9crit=C2=A0:
> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>> Le 02/03/2021 =C3=A0 10:53, Marco Elver a =C3=A9crit=C2=A0:
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
>>
>> stack printing, probably not. Would be good anyway to mark the last leve=
l [unreliable] as the ppc does.
>>
>> IIUC, on ppc the address in the stack frame of the caller is written by =
the caller. In most tests,
>> there is some function call being done before the fault, for instance
>> test_kmalloc_aligned_oob_read() does a call to kunit_do_assertion which =
populates the address of the
>> call in the stack. However this is fragile.
>>
>> This works for function calls because in order to call a subfunction, a =
function has to set up a
>> stack frame in order to same the value in the Link Register, which conta=
ins the address of the
>> function's parent and that will be clobbered by the sub-function call.
>>
>> However, it cannot be done by exceptions, because exceptions can happen =
in a function that has no
>> stack frame (because that function has no need to call a subfunction and=
 doesn't need to same
>> anything on the stack). If the exception handler was writting the caller=
's address in the stack
>> frame, it would in fact write it in the parent's frame, leading to a mes=
s.
>>
>> But in fact the information is in pt_regs, it is in regs->nip so KFENCE =
should be able to use that
>> instead of the stack.
>>
>>>
>>> What's confusing is that it's only this test, and none of the others.
>>> Given that, it might be code-gen related, which results in some subtle
>>> issue with stack unwinding. There are a few things to try, if you feel
>>> like it:
>>>
>>> -- Change the unwinder, if it's possible for ppc32.
>>
>> I don't think it is possible.
>=20
> I think this actually is the solution.
>=20
> It seems the good architectures have all added support for
> arch_stack_walk(), and we have not.
>=20
> Looking at some of the implementations of arch_stack_walk() it seems
> it's expected that the first entry emitted includes the PC (or NIP on
> ppc).

I don't see a direct link between arch_stack_walk() and that expectation. L=
ooks like those=20
architectures where already doing this before being converted to arch_stack=
_walk().

>=20
> For us stack_trace_save() calls save_stack_trace() which only emits
> entries from the stack, which doesn't necessarily include the function
> NIP is pointing to.

Yes, as the name save_stack says, it emits the entries from the stack. I th=
ink it is correct.

>=20
> So I think it's probably on us to update to that new API. Or at least
> update our save_stack_trace() to fabricate an entry using the NIP, as it
> seems that's what callers expect.

As mentionned above, that doesn't seem to be directly linked to the new API=
. That new API only is an=20
intermediate step anyway, the consumers like KFENCE still use the old API w=
hich is serviced by the=20
generic code now.

For me it looks odd to present a stack trace where entry[0] is not from the=
 stack and where entry[1]=20
is unreliable (possibly non existing) because we don't know if we are comin=
g from a frameless=20
function or not and even if the function as a frame we don't know if it sav=
ed LR in the parent's=20
frame or not.

I would deeply prefer if KFENCE could avoid making assumptions on entry[0] =
of the stack trace.

What about the following change to KFENCE ?

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index ab83d5a59bb1..c2fef4eeb192 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -171,12 +171,15 @@ void kfence_report_error(unsigned long address, bool =
is_write, struct pt_regs *r
  	const ptrdiff_t object_index =3D meta ? meta - kfence_metadata : -1;
  	int num_stack_entries;
  	int skipnr =3D 0;
+	void *ip;

  	if (regs) {
  		num_stack_entries =3D stack_trace_save_regs(regs, stack_entries, KFENCE=
_STACK_DEPTH, 0);
+		ip =3D (void *)instruction_pointer(regs);
  	} else {
  		num_stack_entries =3D stack_trace_save(stack_entries, KFENCE_STACK_DEPT=
H, 1);
  		skipnr =3D get_stack_skipnr(stack_entries, num_stack_entries, &type);
+		ip =3D (void *)stack_entries[skipnr];
  	}

  	/* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
@@ -202,8 +205,7 @@ void kfence_report_error(unsigned long address, bool is=
_write, struct pt_regs *r
  	case KFENCE_ERROR_OOB: {
  		const bool left_of_object =3D address < meta->addr;

-		pr_err("BUG: KFENCE: out-of-bounds %s in %pS\n\n", get_access_type(is_wr=
ite),
-		       (void *)stack_entries[skipnr]);
+		pr_err("BUG: KFENCE: out-of-bounds %s in %pS\n\n", get_access_type(is_wr=
ite), ip);
  		pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n",
  		       get_access_type(is_write), (void *)address,
  		       left_of_object ? meta->addr - address : address - meta->addr,
@@ -211,25 +213,23 @@ void kfence_report_error(unsigned long address, bool =
is_write, struct pt_regs *r
  		break;
  	}
  	case KFENCE_ERROR_UAF:
-		pr_err("BUG: KFENCE: use-after-free %s in %pS\n\n", get_access_type(is_w=
rite),
-		       (void *)stack_entries[skipnr]);
+		pr_err("BUG: KFENCE: use-after-free %s in %pS\n\n", get_access_type(is_w=
rite), ip);
  		pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
  		       get_access_type(is_write), (void *)address, object_index);
  		break;
  	case KFENCE_ERROR_CORRUPTION:
-		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entrie=
s[skipnr]);
+		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", ip);
  		pr_err("Corrupted memory at 0x%p ", (void *)address);
  		print_diff_canary(address, 16, meta);
  		pr_cont(" (in kfence-#%zd):\n", object_index);
  		break;
  	case KFENCE_ERROR_INVALID:
-		pr_err("BUG: KFENCE: invalid %s in %pS\n\n", get_access_type(is_write),
-		       (void *)stack_entries[skipnr]);
+		pr_err("BUG: KFENCE: invalid %s in %pS\n\n", get_access_type(is_write), =
ip);
  		pr_err("Invalid %s at 0x%p:\n", get_access_type(is_write),
  		       (void *)address);
  		break;
  	case KFENCE_ERROR_INVALID_FREE:
-		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[ski=
pnr]);
+		pr_err("BUG: KFENCE: invalid free in %pS\n\n", ip);
  		pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)address,
  		       object_index);
  		break;
---

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f911a6ad-2f7a-7173-7e51-2afc25d127a2%40csgroup.eu.
