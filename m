Return-Path: <kasan-dev+bncBDLKPY4HVQKBBIWL7WAQMGQEUGANTIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B05C432B699
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:32:03 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id t8sf8922937lji.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:32:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767523; cv=pass;
        d=google.com; s=arc-20160816;
        b=KV+B4Ja+IrcnvdFB1OBMwRTa0F2Kjdw4LQw5mKRvCCUt5xJVARNtCvkfOVYCu2jeIZ
         c+bcr6lt4B7rzOJK0JDHqkx/o0uMGjSD+91RMmW470jGfFVZT1a/OOv39ZimbHcsdNkY
         vOEipe2HVIUFwZxYVVj7PH/u+H11/TyB0cSS3wR5YwqcA3TTpfejORFIZQpCoa4alqj/
         fG6dABZfxhUH3kGvkO4+lJdQ7hnDxjN6ObaVqRLqYwlOr30KHgaeQu5yVyDtQoiqrXhp
         PF/y06443IeAGTDB8LHHxe95LJapzDcnVoQRABGIqdgN+fcNPMN6EZxMCrzFGaKBO0tY
         wpsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Ct8AanK6/Uc09/cNotOQcaiibd4YG6uaiUUuRR9JWpM=;
        b=nBgixfyY4RAYYkazUTFF2aqOR01dQQQbs5WR7Nm7ntZyGgrmNnuX/u1TBy4dLa4zO5
         i9wxnrrWsnyIYCYAOy26nZr6+NRoQXAWOtOOMV6RXazH5iP9781DMg3JMc7ntbYZni9L
         3jdBO+cG1hcZQGbhLF4qph9L9UAMPsmtfMI1eVXvnBDfnD5miA29SAwSHqE3ratTOVl0
         iUNZKO7q57ueO+9qnMHXsCFZ5QK8eaNtuA5UVAjmNLUhIYDwoEV0soUA8+0Hh0b6JlU4
         t7Vj6enjEq34NUwY/KgLeJNRZmwX30/z9UuziLx0DDSwxqt697X7MB/OVRRw16F1Asf3
         r+8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ct8AanK6/Uc09/cNotOQcaiibd4YG6uaiUUuRR9JWpM=;
        b=pz+qId7jb0/vlbpuw/LaKfDvetUKkQhMdi12gjZydtqVGOBaIeT4i+dR5DrcMdVbrB
         GMP+/s4mK6tqRKPATNSj+IqQoSNB8AvventcJjtsR49CGCg+hbB16DbyMvdtqc1OwoOY
         /LsSgqbhp0th8mTJ3n2jC0WhjzuQZsx2NrEuklAf0IlFKOzb4B7dQ8n5m4l2rJ5QmDmV
         OKzkEsbGbmjKnkKoM7t/YA6lRB8qHVo9vxHv9EQ/lUm8DFGLkjtVwD3ZcVDP7Fc6IZ2I
         uO5hUmeL3m85Uz0oGYV98WpU3rXLzgMxRFb/DDRs3UD1JeGEZlq1wUn9AdsdceKxpGCI
         CEFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ct8AanK6/Uc09/cNotOQcaiibd4YG6uaiUUuRR9JWpM=;
        b=E0vUe4hNQlYrIwDG78v2RiakOdoUdDfjb3Xs21FW2vqzaexL4/TQ+chKG1GmA7YVDM
         icE9+CmcY3I57bfaHSNiUz6ZR+EwJm/b0B4q8ZBgOfhTHnhJR7Cx9+KZeRMowkRtcBtN
         4eTTjAmljmJvCXO5n6tKcC1DSD6eXXJ7hICXEuqiBToQIVgAyGg0UL/WUQXg9djsXH3t
         TA21OjuQ+MQAEP1dH47hCMWm7bAvJyrjoFFVuY0KDnjyHqNf0QIyUhec1iwySaiDO4MH
         10R4YnKIWqibU4di+3iSkp+1a+AJv/FSkysiowCVMLtBdoU66eaYpE1FGYeGnW02DdZY
         yFuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M8tU941W7G1jIhaoKOCWR6Uqx0qxTBTovLOVsbouiIbDnVbp4
	SjqV75m6dnZzHJELz1Ems/I=
X-Google-Smtp-Source: ABdhPJwc5GvwGVFnFV9NGw7X916JMgGKW6Vjvtp8WnCRRM9YCIITG0WiKQGwV9nSEvkeYTlQbd+FAQ==
X-Received: by 2002:a05:6512:33c9:: with SMTP id d9mr14185748lfg.630.1614767523141;
        Wed, 03 Mar 2021 02:32:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b603:: with SMTP id r3ls358294ljn.5.gmail; Wed, 03 Mar
 2021 02:32:02 -0800 (PST)
X-Received: by 2002:a2e:8508:: with SMTP id j8mr9843989lji.270.1614767522020;
        Wed, 03 Mar 2021 02:32:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767522; cv=none;
        d=google.com; s=arc-20160816;
        b=VQnA776U1+3tqBf4b2tEOAGPTDg2Z23FXK9NCPYdTL9mPKyyQ2ULSnykY5wfRYAq+P
         Ui9icBD8xf+eIho8783V2nbHfifFPwtfwb/oqAItH9FGphcjBKy6FckTD8RVtWUHXv84
         72vjMYaYfuJKjz9zDblVkKXe19sQRSYDHfa0FqMsHX7gHXInjAD3LksKu4GC4oPwdOFU
         4ebRr/LnEFotJTc/+QMCv64fS9yQBxX9VRa5vm27El+3I4C9p6pCiymxYya8BKIftUme
         dtKKQkUaMAgvjQRd1121MppZOBe7w5fkzpIHotpokNeBllVPTL8CPDDKNuKOT/CpccPY
         LOpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=1Pp7SYWy8ZYkYPV9VOW1GQr1xifYd/Yvk8xHNmx4Ww8=;
        b=gLqVsy+U+Q2HiZNeDZvOUpI1Tx6LF8G8gF2XIWUN4384p/St0RYfZNI6zF7Sn1T2Pv
         TiGZ8GGy/+cXCVBOowgQnMdUYOZ42+j9Caiz7zfF4YRNb7I7AHvd1U5o0JJ78SavQNY1
         XSwYltNuUYwGg/umMf+JGqOpAbE28nXVIbkB8HfhY0AXyzv4ENVURu4u+4F43cikkN4R
         d1o64qmwpTAeYQKfC6mp9tfuIN9QT/1b1XJwLepZQUhgWKQvJRU8vJJnQs3bK9TlCjEz
         lkEcu4Xz9bP96OsucHrznhKwOGI+LMAd8KiLXuIuwl8JT26KUm1lBL92qw/Quqxp94n9
         /cYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id q26si1165365ljj.4.2021.03.03.02.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:32:01 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Dr9KW1qJQz9tygX;
	Wed,  3 Mar 2021 11:31:59 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 0QULnvIuV7Xg; Wed,  3 Mar 2021 11:31:59 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Dr9KW0l9sz9tygT;
	Wed,  3 Mar 2021 11:31:59 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C19B08B7CD;
	Wed,  3 Mar 2021 11:32:00 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id jz1xUYx8uX1J; Wed,  3 Mar 2021 11:32:00 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 04AC38B7C3;
	Wed,  3 Mar 2021 11:31:59 +0100 (CET)
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
Message-ID: <3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu>
Date: Wed, 3 Mar 2021 11:31:55 +0100
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
>=20
> What's confusing is that it's only this test, and none of the others.
> Given that, it might be code-gen related, which results in some subtle
> issue with stack unwinding. There are a few things to try, if you feel
> like it:
>=20
> -- Change the unwinder, if it's possible for ppc32.
>=20
> -- Add code to test_invalid_access(), to get the compiler to emit
> different code. E.g. add a bunch (unnecessary) function calls, or add
> barriers, etc.
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

Thanks.

For you information, I've got a pile of warnings from mm/kfence/report.o . =
Is that expected ?

   CC      mm/kfence/report.o
In file included from ./include/linux/printk.h:7,
                  from ./include/linux/kernel.h:16,
                  from mm/kfence/report.c:10:
mm/kfence/report.c: In function 'kfence_report_error':
./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argument =
of type 'signed size_t',=20
but argument 6 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:207:3: note: in expansion of macro 'pr_err'
   207 |   pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n",
       |   ^~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argument =
of type 'signed size_t',=20
but argument 4 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:216:3: note: in expansion of macro 'pr_err'
   216 |   pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
       |   ^~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argument =
of type 'signed size_t',=20
but argument 2 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:24:19: note: in expansion of macro 'KERN_SOH'
    24 | #define KERN_CONT KERN_SOH "c"
       |                   ^~~~~~~~
./include/linux/printk.h:385:9: note: in expansion of macro 'KERN_CONT'
   385 |  printk(KERN_CONT fmt, ##__VA_ARGS__)
       |         ^~~~~~~~~
mm/kfence/report.c:223:3: note: in expansion of macro 'pr_cont'
   223 |   pr_cont(" (in kfence-#%zd):\n", object_index);
       |   ^~~~~~~
./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argument =
of type 'signed size_t',=20
but argument 3 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
     5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
       |                  ^~~~~~
./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SOH'
    11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
       |                  ^~~~~~~~
./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
   343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
       |         ^~~~~~~~
mm/kfence/report.c:233:3: note: in expansion of macro 'pr_err'
   233 |   pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)addre=
ss,
       |   ^~~~~~

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3abbe4c9-16ad-c168-a90f-087978ccd8f7%40csgroup.eu.
