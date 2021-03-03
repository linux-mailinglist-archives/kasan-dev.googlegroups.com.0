Return-Path: <kasan-dev+bncBDLKPY4HVQKBBSGO7WAQMGQEDAXQDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 603E032B6B8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:39:05 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id d15sf3773697ljl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:39:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767945; cv=pass;
        d=google.com; s=arc-20160816;
        b=asbbo4FEPirWKWNj0VPJaQOk9v1ruVkcrrJ00HEKkauwnx5VTKMb20l4fFyEzhSmVc
         E1HsMmt+LtcfyIKP9nK3P/0cbLD/7T06D1RLYvJbc3o3lTkWapNsOzJb6sPS5gGQLvor
         l/pfFLYok62eetWIHa92q65dnKmjLFOPXAx8wMlr7pdMicyHRP9vrpPF7N44m2b+YQw/
         3CRKS1Z4BBtyF5iCZTj+8hYWzq7uNQrlFl2JKE1dJ1e6uwls6PxEYlQ4j+mqZL1En1GC
         JMEduv9OjxymhaUQQMVXMcHE4lpdUtexqbADG0dZpqhfZVB2Yo5uEybSxtcY4AKsHHPE
         sVnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=KRcFKIEOn0JlmkxDS5GB6nhAbI0YRln0B090T1cpaig=;
        b=Vidu7JZH7UJPEwCDHnQOfDxCl6429+0R2S5yYjRtAT3nnDSDKv0sO5Q/UsekZt2oZn
         0a0AUcg7rwIjlkmkVzYirpa17gISAmE6YXA8Su2E2Rh9PF14IRSCAcB/dLCsQT2fBKfL
         Bzki1UWtGNw659ZiDJLgn9THe2X9sx9je4nyXCMl2O7PzdbJTMliU/GwPlulmcrxiDjq
         F2uyF1PrGG7qdPwnensx9Fqcl4ml4zKnSvCNeC+JXwf72XD2ygCoIClZ2/qWfnRRwh1O
         D8OHAe7GmicoA0m1/rbw4Mzbqs/ZRwaDDevrRk2j+6p1xmX+yQ7yxACYe8Xj6ZmhseNP
         mCqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KRcFKIEOn0JlmkxDS5GB6nhAbI0YRln0B090T1cpaig=;
        b=fojlhcTqHXIJrSnFkX7gzbybwZHICKANJSQIv/OSL5hgFYK4TAFg5xtDTk6TmmvcES
         dA7PwGKdbDYkykoyo4mG1vbZ3URHP97kwKuNYwjLk+bM3+HGK6UHMMGNF6js6GN3Mwi2
         htwZnBXjbbBumRzVHFa3juv2uAyR5+EUmh9CnGvDyvHdh1x6PVtYkA/7DHv+IYz831L8
         YEZy4t8AyBYGqztukCZgkhfReiNgYAZOl/h4zjCqBpDQNslxdRQQ9ZF6VbnzMSZJv9HP
         EvnRmfm+J6Vz5Sb7TuJtV8Yzrf2qeO2AL3pSOioqnW1lWBiGe/A0NZKVrcvnB+doOQ48
         AtGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KRcFKIEOn0JlmkxDS5GB6nhAbI0YRln0B090T1cpaig=;
        b=SwX0lSppLDR/Q+8m9HvaosMRm/8JVRmRY1GWOuXS55sdVvFgHmAEgSzmMgfbkKWTNT
         /qlpkROlsdMOLaLtTtVNgxLC7MvBXoXBTnwjvmVLXxMQdrSsjCyEijd4efA2vKjJILIF
         5p//STLxpSd4sQ1AcLk8A1lRRcK1biOhx3DncUuJmNiytyPPZLYZ0CLmbm/AD/MarYPH
         gHKj6aYDfChhhP1FfaqiPVjbU3ioU1GUGiWOPQ7atAd/3HiW3jfAecIc2/RkltbglQtE
         /0jP6V+ripTra32zBt3p+V7vWz8brSjRypAPSAlhDpY+mHC5Q4qBmWv3DD2lgZsoBRer
         B/xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uAN0/can73J4oDGIPmWf5PUEMvjO3LT6tsncYl3sBUQqnLC4R
	2ToFN0sYRUd/j/k/5ljlO8Y=
X-Google-Smtp-Source: ABdhPJyuouKB4Kq3yLb5UX4E0WqckLwsvJny73gYX12keRHba7+wO1SafYNPvURa1qpu9bcVCV/Kpg==
X-Received: by 2002:a2e:a481:: with SMTP id h1mr5391771lji.143.1614767944977;
        Wed, 03 Mar 2021 02:39:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls361863lji.6.gmail; Wed, 03 Mar
 2021 02:39:04 -0800 (PST)
X-Received: by 2002:a2e:a60a:: with SMTP id v10mr5315057ljp.267.1614767943967;
        Wed, 03 Mar 2021 02:39:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767943; cv=none;
        d=google.com; s=arc-20160816;
        b=jnC4iiXtSeo7B88oMS5WsLdMtGyB+ZKfcDtVuBKjWbPJtgcxa87e9a7PysZvcU0gBF
         2ioPElupjeWebYR3jteK3iJJBJRhrkR04ow36Ee2o4PbXPlpUm0WTA08E5dKXJ9Eb/j3
         DyaYAf3jMJheONlJiHmLi0bxiQ6Gvr1WFJX2n0/jTtb8pl3+4xlqOa/85QGbTSuFNxyG
         XwCcqB/HsE4FS7SIH7/aVB7IxMoYh+DNle6hqOC+cRL5UhMiDyOgpvF/zSrgR68btSEB
         29wdsuFP8XRLz16rcEb4WooBP5fBHA9phBOCmuzUTc0O2PpX5PCyN6AHEaLxBoB0U7bt
         zUHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=o+ylr9XL8n+TGVs6WvDl6HvarnKoHfXmSWvo39IO93w=;
        b=vq6jeFlL4jl4wQSAJpTjXxAo3kBCds5+oH61dkBQootIuTmN0rB7k+r181AEP90eq+
         +mxNYtQ+K7FS3RZDOg/LZWWFwJzNXOIBoohGiTg+96h9hpI0otTjSGumxyanL8GnwuAm
         jzzBzaJ3dJmlaU4XlgOeZjGIoW5zqfHvPGU5Hi/3v+YJa7Tc1HgeIKJrEDc+yBPNhvso
         8T6ZAHDkhtMW2FAvx3SewveItupQFIaGJFydcPEI7bcuscb/wdeYOUsRBtgNMYv6zk+r
         vwR4eJSjd6ZMs6L8We+gIMvBKWifn3zghhJfLANaaEqyMw47HWbeyCsDyFIQ0611/Bql
         iROg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z2si884705ljm.0.2021.03.03.02.39.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:39:03 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Dr9Td42QDz9tygN;
	Wed,  3 Mar 2021 11:39:01 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id f_Vl0gODMLXr; Wed,  3 Mar 2021 11:39:01 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Dr9Td2Nq5z9tygT;
	Wed,  3 Mar 2021 11:39:01 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0397B8B7D0;
	Wed,  3 Mar 2021 11:39:02 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id iHEA4-6VBwMi; Wed,  3 Mar 2021 11:39:01 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 36CFD8B7C3;
	Wed,  3 Mar 2021 11:39:00 +0100 (CET)
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
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
Date: Wed, 3 Mar 2021 11:38:58 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
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



Le 02/03/2021 =C3=A0 12:39, Marco Elver a =C3=A9crit=C2=A0:
> On Tue, 2 Mar 2021 at 12:21, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
> [...]
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
>=20
> We use stack_trace_save_regs() + stack_trace_print().
>=20
>> IIUC, on ppc the address in the stack frame of the caller is written by =
the caller. In most tests,
>> there is some function call being done before the fault, for instance
>> test_kmalloc_aligned_oob_read() does a call to kunit_do_assertion which =
populates the address of the
>> call in the stack. However this is fragile.
>=20
> Interesting, this might explain it.
>=20
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
>=20
> Perhaps stack_trace_save_regs() needs fixing for ppc32? Although that
> seems to use arch_stack_walk().
>=20
>>> What's confusing is that it's only this test, and none of the others.
>>> Given that, it might be code-gen related, which results in some subtle
>>> issue with stack unwinding. There are a few things to try, if you feel
>>> like it:
>>>
>>> -- Change the unwinder, if it's possible for ppc32.
>>
>> I don't think it is possible.
>>
>>>
>>> -- Add code to test_invalid_access(), to get the compiler to emit
>>> different code. E.g. add a bunch (unnecessary) function calls, or add
>>> barriers, etc.
>>
>> The following does the trick
>>
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index 4acf4251ee04..22550676cd1f 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -631,8 +631,11 @@ static void test_invalid_access(struct kunit *test)
>>                  .addr =3D &__kfence_pool[10],
>>                  .is_write =3D false,
>>          };
>> +       char *buf;
>>
>> +       buf =3D test_alloc(test, 4, GFP_KERNEL, ALLOCATE_RIGHT);
>>          READ_ONCE(__kfence_pool[10]);
>> +       test_free(buf);
>>          KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>>    }
>>
>>
>> But as I said above, this is fragile. If for some reason one day test_al=
loc() gets inlined, it may
>> not work anymore.
>=20
> Yeah, obviously that's hack, but interesting nevertheless.
>=20
> Based on what you say above, however, it seems that
> stack_trace_save_regs()/arch_stack_walk() don't exactly do what they
> should? Can they be fixed for ppc32?

Can we really consider they don't do what they should ?

I have the feeling that excepting entry[0] of the stack trace to match the =
instruction pointer is=20
not a valid expectation. That's probably correct on architectures that alwa=
ys have a stack frame for=20
any function, but for powerpc who can have frameless functions, we can't ex=
pect that I think.

I have proposed a change to KFENCE in another response to this mail thread,=
 could it be the solution ?

Thanks
Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ad61cb3a-2b4a-3754-5761-832a1dd0c34e%40csgroup.eu.
