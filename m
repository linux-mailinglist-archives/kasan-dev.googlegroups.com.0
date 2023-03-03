Return-Path: <kasan-dev+bncBC7PZX4C3UKBBSUCRCQAMGQE3KLRCCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BD9FA6A993D
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:16:43 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id z6-20020a05600c220600b003e222c9c5f4sf984958wml.4
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677853003; cv=pass;
        d=google.com; s=arc-20160816;
        b=aIDYvIBnUIlN8biRf8rnCOv2pLCpz+OHpDC2rh0gWToC0uxpPbpKfq+Db2j/8WtIgF
         NQtLmIL8EBbrwdpkTAt9u12AI3esXlkGQF+2/ZTsNvbcQ6wvSbYGMHFIz8b57JDwI1y+
         74VyYxodZ5aAC1OpGY1ToUBaDZxrvBxxcO8Poc/h7q6l9vl82BSNaiXPalt4gkuz8g4P
         H1R0dsqRgqKtx/shzSyeqHItilVGaCuMiqavdyso56gxdPVyNjM2B4SlBi++PbVtVRbV
         EyPsstRel3NoWgdwJVvIN1IXEUpj6+9XHUJLvm/6AC33cbMrQNsx/OD1aJoMIF0Uxzc8
         Rnaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=HGKl74g2rvWv1pKgI6jHRVb9yV42GOxSRqKL7a07P9Q=;
        b=t0W7NJExb8KHks3l3ISnwRQhVFy/HZUzHxu2PdujbEpvLzllYDcavQBP1Oxsgy61z8
         aDcL1bLTP0K4LmmY7t3TyGq9w00rpU0DvlP0t5lmNX0044hUi7g+vYr1KzeY1ZqPrbzh
         qXf4OG/Dqz2wJJyBC7p48bFf+j/SIIi5t6K4GJAOoHu/dvmQwwT8MSnv6szltfj2/wg2
         8crAIj5KPEItGQtH51r8zXTwj9eNydPq0nxusnaxH9VKC3cP/sBRLLC/6lD+1vtFd14l
         SL07l5Xxgd741dql0EjdabRw5avtggsDFA1fkHnxhl8Q3W6Z9sjVCLOAwfvA0Gz1nRRQ
         D1AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677853003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HGKl74g2rvWv1pKgI6jHRVb9yV42GOxSRqKL7a07P9Q=;
        b=gzgUUSlzD+RiFIV8rx2Q9M1KcIOgz918QimU6SXd9dZiRqZ0dWo9Z4O3142LOPi03B
         yzyZzkip5jrwI+lyM95JCJwYa6G2p2Y/x0evcjYnyQUcgQ5XY1w+4QJ/VRh4foMlO/cI
         gxWD2EqSX6RtyTMmOqh70MWZBWYEi3/LpgQrBDqStRG4id1y+SmPyc/lTsrPkcEcRZou
         CtO4I8pOGeXGxp4WMyL3bhlrBzzOjAvGpRvw12Z+G9uD3WGHcjOfIPFwBDk48pO6CfmM
         T1N5xmodchkVKtxspsJmGfuqYU1oqnF3RZlzCXS/LvBQEUeiiWX7scsLvCD1TxFknIXl
         bIGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677853003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HGKl74g2rvWv1pKgI6jHRVb9yV42GOxSRqKL7a07P9Q=;
        b=pQs6fBibUeAjRS8w8Z7Szjq5igiO62QpiB4Q3GWYXVnWBQgLVO+vxhI88bhWzu89Cd
         yFhl0aPCSXAio7QFrJxwTx0QRXP9lOb2AcBL0rjzpo4kJw+DSfNsCxrejalPd+np4hTV
         RTHYzDmTxbNgWzf2azPxaFn/Nx1dEg/4ab6aLKC4FBSLZNkMT+Jh0L1oRJQG+eeXnGtn
         1M3Ab0S9Bntbr8Ky1RqxmlRVohmPo4N4RtQEFfodKy5l4Khsfk7A3RQrHIt60u36+LEA
         kWWYxsoKjseNXOKC6vPz+BVF+Tt8xvmNwK3x5WNYhB8xpH3SHKXjBqzKZgOtRjhK8dPv
         4j9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVT7SSUyA4brlQequlU847RfPX22D1hdNQ2jeX6V1u8QdAe3Day
	vWzrMYkNvq6S08/8KCX+gmU=
X-Google-Smtp-Source: AK7set9kTxSoPff+3cSKNbtK+MVQMW+7QhSMuWWLYequpFudUgmjK0boLyylbFzikoRzrHNS9BPzcw==
X-Received: by 2002:a7b:c2a2:0:b0:3eb:5a1e:d524 with SMTP id c2-20020a7bc2a2000000b003eb5a1ed524mr458602wmk.3.1677853003075;
        Fri, 03 Mar 2023 06:16:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca4:b0:3e2:165f:33d0 with SMTP id
 k36-20020a05600c1ca400b003e2165f33d0ls1612158wms.2.-pod-control-gmail; Fri,
 03 Mar 2023 06:16:41 -0800 (PST)
X-Received: by 2002:a05:600c:3506:b0:3dc:405b:99bf with SMTP id h6-20020a05600c350600b003dc405b99bfmr1883668wmq.15.1677853001528;
        Fri, 03 Mar 2023 06:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677853001; cv=none;
        d=google.com; s=arc-20160816;
        b=O/iQq5toW36/b1jyV0+4cGMQE1R+w8wngENIm9Js8ymRhQFYbyCtwCSkdBpxqEkYHC
         jeq2gXhsviICJi9gaNWzFN7DaXxdI/DYGr8o115DivjCKCNHes80UHPsqSNAv1tQJfxC
         8nUExBr8a3o2PBvNFKuOHq5HENa5j2WgVQEOFUv+Nv9WtIzo0X4mQVtIpC8X2mB7eCYt
         hg2z/aODOP+9d9bYIk47uYW47RgLT9B5Uli6s/lEb2N2x5EKkuQy1uqYobIL9Y3QON0S
         HU75q5ey9h/7KIbBeJgOjtIsfSL/zfVZMonwhCKUE58Std3ATt2m4/MBRyJqJbgs8O3p
         A03A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=qJ/igPCBTkjRhHgrNDDSIAX3lFUMXN8YIwEws64deHM=;
        b=ZQUQsk9uJiDShMu+hT1vT6dkAQhltnW3ix8/kqqig2PluEgky4RWQTsdInjEXrOdiz
         TCDiB0TyCPfIr3yFpaeA12U+deLrJqOqT42RVElKLPjZ+cywp4CO5XSVofPp2sRwkBOY
         rQsYYLJ42CcZFNG8KDsKkbIAcfcHqu2rOFKRClLXCUp5SWYmwYJjK8crR69z8JumnyYq
         hEzAaalANNq5gW8zyVErErA48UJeXIe/ulqjbelR9Oga9nuuFabkpfkO9c94Xh8AWmzF
         kEFZvDWqV/wANbKP18EnTRaEd/NCjoMrpGJTs67he/q+WW6eFVNcEG4jRdn364Jtwdu5
         z3GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay10.mail.gandi.net (relay10.mail.gandi.net. [217.70.178.230])
        by gmr-mx.google.com with ESMTPS id n37-20020a05600c502500b003e1eddc40cfsi374534wmr.3.2023.03.03.06.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 03 Mar 2023 06:16:41 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.230 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.230;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id 8BEF5240011;
	Fri,  3 Mar 2023 14:16:38 +0000 (UTC)
Message-ID: <6b2934bb-ff40-fd85-f305-d6ea8eb2b200@ghiti.fr>
Date: Fri, 3 Mar 2023 15:16:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: RISC-V Linux kernel not booting up with KASAN enabled
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Chathura Rajapaksha <chathura.abeyrathne.lk@gmail.com>,
 linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
References: <CAD7mqryyz0PGHotBxvME7Ff4V0zLS+OcL8=9z4TakaKagPBdLw@mail.gmail.com>
 <789371c4-47fd-3de5-d6c0-bb36b2864796@ghiti.fr>
 <CAD7mqrzv-jr_o2U3Kz7vTgcsOYPKgwHW-L=ARAucAPPJgs4HCw@mail.gmail.com>
 <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com>
 <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr>
 <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.230 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

On 3/3/23 06:44, Dmitry Vyukov wrote:
> On Thu, 2 Mar 2023 at 21:11, Alexandre Ghiti <alex@ghiti.fr> wrote:
>> +cc Dmitry and kasan-dev, in case they know about this but I did not
>> find anything related
> Hard to say anything w/o commit/symbolized report.
> If it's stack unwinder and it's supposed to be precise, then it may be
> a bug in the unwinder where it reads a wrong location and is imprecise
> (not the frame pointer).
> If it's supposed to be imprecise, then it should use READ_ONCE_NOCHECK
> to read random stack locations.


Please correct me if I say something obviously wrong.

The config used to generate this trace does not set=20
CONFIG_FRAME_POINTER: we were then in an imprecise stack unwinding mode.=20
When set, the backtrace disappears: so IIUC, the issue lies in the stack=20
unwinding function that reads the stack randomly and KASAN does not like=20
that. So as you suggested, I used READ_ONCE_NOCHECK when reading the=20
stack and the backtrace also disappears. So the following patch would be=20
the fix for this, is that correct?


diff --git a/arch/riscv/kernel/stacktrace.c b/arch/riscv/kernel/stacktrace.=
c
index f9a5a7c90ff0..64a9c093aef9 100644
--- a/arch/riscv/kernel/stacktrace.c
+++ b/arch/riscv/kernel/stacktrace.c
@@ -101,7 +101,7 @@ void notrace walk_stackframe(struct task_struct *task,
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 while (!kstack_end(ksp)) {
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 if (__kernel_text_address(pc) && unlikely(!fn(arg, pc)))
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 pc =3D (*ksp++) - 0x4;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 pc =3D READ_ONCE_NOCHECK(*ksp++) - 0x4;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 =C2=A0}

Thanks for your quick answer,

Alex


>
>> On 3/2/23 19:01, Chathura Rajapaksha wrote:
>>> Hi Alex/All,
>>>
>>> Kernel is booting now but I get the following KASAN failure in the
>>> bootup itself.
>>> I didn't see this bug was reported before anywhere.
>>>
>>> [    0.000000] Memory: 63436K/129024K available (20385K kernel code,
>>> 7120K rwdata, 4096K rodata, 2138K init, 476K bss, 65588K reserved, 0K
>>> cma-reserved)
>>> [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [    0.000000] BUG: KASAN: stack-out-of-bounds in walk_stackframe+0x1b2=
/0x1e2
>>> [    0.000000] Read of size 8 at addr ffffffff81e07c40 by task swapper/=
0
>>> [    0.000000]
>>> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
>>> 6.2.0-gae3419fbac84-dirty #7
>>> [    0.000000] Hardware name: riscv-virtio,qemu (DT)
>>> [    0.000000] Call Trace:
>>> [    0.000000] [<ffffffff8000ab9e>] walk_stackframe+0x0/0x1e2
>>> [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
>>> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
>>> [    0.000000] [<ffffffff813d86e0>] dump_stack_lvl+0x22/0x36
>>> [    0.000000] [<ffffffff813bd17a>] print_report+0x198/0x4a8
>>> [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
>>> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
>>> [    0.000000] [<ffffffff8023bd52>] kasan_report+0x9a/0xc8
>>> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
>>> [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
>>> [    0.000000] [<ffffffff80108748>] stack_trace_save+0x88/0xa6
>>> [    0.000000] [<ffffffff801086bc>] filter_irq_stacks+0x8a/0x8e
>>> [    0.000000] [<ffffffff800b65e2>] devkmsg_read+0x3f8/0x3fc
>>> [    0.000000] [<ffffffff8023b2de>] kasan_save_stack+0x2c/0x56
>>> [    0.000000] [<ffffffff80108744>] stack_trace_save+0x84/0xa6
>>> [    0.000000] [<ffffffff8023b31a>] kasan_set_track+0x12/0x20
>>> [    0.000000] [<ffffffff8023b8f6>] __kasan_slab_alloc+0x58/0x5e
>>> [    0.000000] [<ffffffff8023aeae>] __kmem_cache_create+0x21e/0x39a
>>> [    0.000000] [<ffffffff8141623e>] create_boot_cache+0x70/0x9c
>>> [    0.000000] [<ffffffff8141b5f6>] kmem_cache_init+0x6c/0x11e
>>> [    0.000000] [<ffffffff8140125a>] mm_init+0xd8/0xfe
>>> [    0.000000] [<ffffffff8140145c>] start_kernel+0x190/0x3ca
>>> [    0.000000]
>>> [    0.000000] The buggy address belongs to stack of task swapper/0
>>> [    0.000000]  and is located at offset 0 in frame:
>>> [    0.000000]  stack_trace_save+0x0/0xa6
>>> [    0.000000]
>>> [    0.000000] This frame has 1 object:
>>> [    0.000000]  [32, 56) 'c'
>>> [    0.000000]
>>> [    0.000000] The buggy address belongs to the physical page:
>>> [    0.000000] page:(____ptrval____) refcount:1 mapcount:0
>>> mapping:0000000000000000 index:0x0 pfn:0x82007
>>> [    0.000000] flags: 0x1000(reserved|zone=3D0)
>>> [    0.000000] raw: 0000000000001000 ff60000007ca5090 ff60000007ca5090
>>> 0000000000000000
>>> [    0.000000] raw: 0000000000000000 0000000000000000 00000001ffffffff
>>> [    0.000000] page dumped because: kasan: bad access detected
>>> [    0.000000]
>>> [    0.000000] Memory state around the buggy address:
>>> [    0.000000]  ffffffff81e07b00: 00 00 00 00 00 00 00 00 00 00 00 00
>>> 00 00 00 00
>>> [    0.000000]  ffffffff81e07b80: 00 00 00 00 00 00 00 00 00 00 00 00
>>> 00 00 00 00
>>> [    0.000000] >ffffffff81e07c00: 00 00 00 00 00 00 00 00 f1 f1 f1 f1
>>> 00 00 00 f3
>>> [    0.000000]                                            ^
>>> [    0.000000]  ffffffff81e07c80: f3 f3 f3 f3 00 00 00 00 00 00 00 00
>>> 00 00 00 00
>>> [    0.000000]  ffffffff81e07d00: 00 00 00 00 00 00 00 00 00 00 00 00
>>> 00 00 00 00
>>> [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> I was able to reproduce the exact same trace, I'll debug that tomorrow,
>> I hope it is a real bug :)
>>
>> Thanks for the report Chatura,
>>
>> Alex
>>
>>
>>> Best,
>>> Chath
>>>
>>> On Thu, Mar 2, 2023 at 11:25=E2=80=AFAM Chathura Rajapaksha
>>> <chathura.abeyrathne.lk@gmail.com> wrote:
>>>> Hi Alex,
>>>>
>>>> Thank you very much, kernel booted up with the patches you mentioned.
>>>> Bootup was pretty slow compared to before though (on a dev board).
>>>> I guess that is kind of expected with KASAN enabled.
>>>> Thanks again.
>>>>
>>>> Regards,
>>>> Chath
>>>>
>>>> On Thu, Mar 2, 2023 at 2:50=E2=80=AFAM Alexandre Ghiti <alex@ghiti.fr>=
 wrote:
>>>>> Hi Chatura,
>>>>>
>>>>> On 3/2/23 04:13, Chathura Rajapaksha wrote:
>>>>>> Hi All,
>>>>>>
>>>>>> I observed that RISC-V Linux hangs when I enable KASAN.
>>>>>> Without KASAN it works fine with QEMU.
>>>>>> I am using the commit ae3419fbac845b4d3f3a9fae4cc80c68d82cdf6e
>>>>>>
>>>>>> When KASAN is enabled, QEMU hangs after OpenSBI prints.
>>>>>>
>>>>>> I noticed a similar issue was reported before in
>>>>>> https://lore.kernel.org/lkml/CACT4Y+ZmuOpyf_0vHTT4t3wkmJuW8Ezvcg7v6y=
DVd8YOViS=3DGA@mail.gmail.com/t/
>>>>>> But I believe I have the patch mentioned in that thread.
>>>>> I proposed a series that will be included in 6.3 regarding KASAN issu=
es
>>>>> here: https://patchwork.kernel.org/project/linux-riscv/list/?series=
=3D718458
>>>>>
>>>>> Can you give it a try and tell me if it works better?
>>>>>
>>>>> Thanks,
>>>>>
>>>>> Alex
>>>>>
>>>>>
>>>>>> My kernel config:
>>>>>> https://drive.google.com/file/d/1j9nU7f9MxCc_i-UHUCTvo7o6nDrcUz0w/vi=
ew?usp=3Dsharing
>>>>>>
>>>>>> Best regards,
>>>>>> Chath
>>>>>>
>>>>>> _______________________________________________
>>>>>> linux-riscv mailing list
>>>>>> linux-riscv@lists.infradead.org
>>>>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6b2934bb-ff40-fd85-f305-d6ea8eb2b200%40ghiti.fr.
