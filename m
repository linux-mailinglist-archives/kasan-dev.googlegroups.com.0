Return-Path: <kasan-dev+bncBDLKPY4HVQKBB6X766AQMGQEGP6RTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A0712329794
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 10:06:02 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id jo6sf6077229ejb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 01:06:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614675962; cv=pass;
        d=google.com; s=arc-20160816;
        b=AYuLoJdg1ajCRS7uctXZDpnUoCb42cA/qUkhE5UpsH03U8BXsR1HFQZOHIrX/pOOER
         XCX+XGZZOt+4ZNrmNiaEfEjvwrODhAZhxoC5RKl8X2UUULJW46N17LmFOPEqaf0CsMZ3
         jxZMyIL2qNBb/SfiFop3wtUZCMeKqI4cbjijHKoL4FIH6mldijmdCQo3cQVEY8/UEnXx
         ora+Aqbuz5I10AB5xbqBlE4UEjB09grlxH9LquzpbmQIpZTovuMRQQ4nZJHKRtmKyP3K
         FEe8FD11gurvDLeISwI9nNnjCvFfWT3jf54iKGUptSJwiFDNhuqlWdLOZVGrKwnPwCCq
         2YzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=1pONNOskKoumB9k0VTJ3Kxoa/T/j230tngQPytnQHn8=;
        b=R2j5CypAIC1YLCKsMNNQP40cALljnippZcaBZjGV53IEKtxyV5MrG9iUYQzkmXvaFp
         isqgexQDjaKmvlNpg1q72/MQAS4tZMqw9/7lTQxqxiIk9FcQiDorhZmnTJM1Yd38kHc5
         9S4LrKKX5bxIiY/t6dY3bk3W/3YrNUPSv/ivCTiJZr6CRWsZnSIW8Ik53tHaA1P/bbrO
         83Hl7RdO4hMgSsPj/ybcHUXOP9qRKzE9xNuyoRcZCR9EuRffmUJ7t8xasBzVCygS9Wuc
         e9bsrxNr87RoEShq4rhKN35IZRmysAHJOye1Sl+kuFlO9Nb0KZ2jsk4Zemy76PZnfGXk
         9I/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1pONNOskKoumB9k0VTJ3Kxoa/T/j230tngQPytnQHn8=;
        b=BcrqbMsqyGQ1UvWAKv7bgUQLsJ701jjtb5jgQ/NbDpajIEMTmkkGFtOV2IK0/lJ5IM
         wH/Flxtv/ZCin2s8BRrsRehmV2KtTWIcDgQSlOkAWFFFFKoymx4XEq98qNAR2WYLSz3Z
         bFMP8u1h4Yim7pi/X6lI907DnE62ARHqF4iaEptoCT53PsrH/EK2cxgaZoaBg/dEAIBT
         rc5uGLP9pLf4Gqc5Vr8FLpgtdAxtgchzkgbO0vEcvD23E1z+4/95lJldKbW8p4FKUrZc
         6IqVH+WV9XSoc/qZe2Eq2cohBHRoSMiU54gDix8eLUuZxdUzgqzZ5k8LXc87tyZfL9tK
         IQIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1pONNOskKoumB9k0VTJ3Kxoa/T/j230tngQPytnQHn8=;
        b=Yz5W0+yaNR2ONUwGFfF3Mq25p7x97zlIbuDH8BMT4UnrdH4TvDr7ZR3Czy/2N7KYvx
         CdmTWdaf0Eu6a8bzmhPc9Nd+tFeG0o054GkCposJnjB6QsCQ1Uijqg+9TyKwGmejlkIw
         7JNoK651a3YsouidhrjfvZoV5ISS4obu41pF0lYvua26p3TSWQXLsNtTdqPTaFY0vf2p
         SzckJ7EIxlM0eAbY+LLx4bkqJ+k+MUbW3ThhmnanSEL7cl1w0BYgNUFPY35a1jtANLyo
         25opf+dymlgZIwQsGWMgWeJO565II1VJoTcG6Wrkatp4v6YpMLVQEL+L7nQeHc7W4EF6
         wbJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dp/sl+wZaTDY4jfrbOQyhc2g8aDs+0TRiGjEit1ZCv8k1jBZb
	zturkS5wr7ax7ZfL7BoasaU=
X-Google-Smtp-Source: ABdhPJx4rYRokbTIrA2SJtTCXwubuvgwQZTPRaHnMHzfguxwpP0LDwN7M1q4EMg7wV7uFZyUja2hjQ==
X-Received: by 2002:a17:906:5453:: with SMTP id d19mr19422365ejp.150.1614675962293;
        Tue, 02 Mar 2021 01:06:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bca:: with SMTP id y10ls224520ejg.0.gmail; Tue, 02
 Mar 2021 01:06:01 -0800 (PST)
X-Received: by 2002:a17:906:a016:: with SMTP id p22mr19651659ejy.456.1614675961370;
        Tue, 02 Mar 2021 01:06:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614675961; cv=none;
        d=google.com; s=arc-20160816;
        b=Up7cHppeC4xDtgaHfDuFWUZl3+OUxc7pZvNh8937E5SjqxGTLdCY5zwbW91N8Pq5JU
         ylw3tLH3fVaOAcr+NnTXhY2gsKsR/9tvFx1srGAaZls1NRzkNEkTIddxolNDe6i5vrLI
         fFdY2ZW0iiVdXqi5tAUDIDA9EBEZF58n2/n1HBY38ltZ4rnpU0zDlmxZEhJRwhFJOXJO
         /OvcSYPFWlfGrBVz3iAOZChJeFmQKwbMaL2OHph85XBbVZbHADmKtNQTTiCX9I4/WH6m
         o5AJl2ho7krbtuGJwBezlRxKLnNfeQIXUHgQimmTBxE+z5ghEnVEnjcRbu8Sf/lgrBR7
         VS5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=c+uMjQ3nZboCyr3Z/XJPRCUarinbjxuRFSEkC2qodVg=;
        b=LJEznCG5KkYueh6vmPOET900usqmNBH+900y6NZwQPZ9eKkLUNGAxKfbvD+k4d/c1u
         DOGJ9rgva9e1hysN3AQtjQ1MPdWxEOyj6cRdkSKN87TRnuI/dwtfxA4IjzjD/OAPP7V+
         HB9+fzgSvsUloqYzwZ2/QuVb+Noym3XtUrBZl2tAQtt0/Lm2uCECQM//ds7SUyrNOEY8
         VN2H+hSZuE6hsRDzjiwY8ft+H/MQ/eIEkjzR7Xl+MaQnwYlkHjCzq5P2gyBzGu3CPySB
         imPOZ37DE18dfHNq/8qWUEolu0e6M30rpbihixsKp0BOnGZugrv16j/EsJGzfRWi4/Rc
         u1eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id w12si943929edj.2.2021.03.02.01.06.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Mar 2021 01:06:01 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DqWSl5JjMz9tyZ5;
	Tue,  2 Mar 2021 10:05:59 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 89Yk5czapt5P; Tue,  2 Mar 2021 10:05:59 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DqWSl30J1z9tyZ9;
	Tue,  2 Mar 2021 10:05:59 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 782B38B7AF;
	Tue,  2 Mar 2021 10:06:00 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 3oTUi2wpAK48; Tue,  2 Mar 2021 10:06:00 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 68D518B75F;
	Tue,  2 Mar 2021 10:05:58 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
Date: Tue, 2 Mar 2021 10:05:41 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
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



Le 02/03/2021 =C3=A0 09:58, Marco Elver a =C3=A9crit=C2=A0:
> On Tue, 2 Mar 2021 at 09:37, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>> Add architecture specific implementation details for KFENCE and enable
>> KFENCE for the ppc32 architecture. In particular, this implements the
>> required interface in <asm/kfence.h>.
>=20
> Nice!
>=20
>> KFENCE requires that attributes for pages from its memory pool can
>> individually be set. Therefore, force the Read/Write linear map to be
>> mapped at page granularity.
>>
>> Unit tests succeed on all tests but one:
>>
>>          [   15.053324]     # test_invalid_access: EXPECTATION FAILED at=
 mm/kfence/kfence_test.c:636
>>          [   15.053324]     Expected report_matches(&expect) to be true,=
 but is false
>>          [   15.068359]     not ok 21 - test_invalid_access
>=20
> This is strange, given all the other tests passed. Do you mind sharing
> the full test log?
>=20

[    0.000000] Linux version 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty=
=20
(root@localhost.localdomain) (powerpc64-linux-gcc (GCC) 10.1.0, GNU ld (GNU=
 Binutils) 2.34) #4674=20
PREEMPT Tue Mar 2 08:18:49 UTC 2021
[    0.000000] Using CMPCPRO machine description
[    0.000000] Found legacy serial port 0 for /soc8321@b0000000/serial@4500
[    0.000000]   mem=3Db0004500, taddr=3Db0004500, irq=3D0, clk=3D133333334=
, speed=3D0
[    0.000000] Found legacy serial port 1 for /soc8321@b0000000/serial@4600
[    0.000000]   mem=3Db0004600, taddr=3Db0004600, irq=3D0, clk=3D133333334=
, speed=3D0
[    0.000000] ioremap() called early from find_legacy_serial_ports+0x3e4/0=
x4d8. Use early_ioremap()=20
instead
[    0.000000] printk: bootconsole [udbg0] enabled
[    0.000000] -----------------------------------------------------
[    0.000000] phys_mem_size     =3D 0x20000000
[    0.000000] dcache_bsize      =3D 0x20
[    0.000000] icache_bsize      =3D 0x20
[    0.000000] cpu_features      =3D 0x0000000001000140
[    0.000000]   possible        =3D 0x00000000277ce140
[    0.000000]   always          =3D 0x0000000001000000
[    0.000000] cpu_user_features =3D 0x84000000 0x00000000
[    0.000000] mmu_features      =3D 0x00210000
[    0.000000] Hash_size         =3D 0x0
[    0.000000] -----------------------------------------------------
[    0.000000] Top of RAM: 0x20000000, Total RAM: 0x20000000
[    0.000000] Memory hole size: 0MB
[    0.000000] Zone ranges:
[    0.000000]   Normal   [mem 0x0000000000000000-0x000000001fffffff]
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000000000000-0x000000001fffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x000000001ffff=
fff]
[    0.000000] On node 0 totalpages: 131072
[    0.000000]   Normal zone: 1024 pages used for memmap
[    0.000000]   Normal zone: 0 pages reserved
[    0.000000]   Normal zone: 131072 pages, LIFO batch:31
[    0.000000] pcpu-alloc: s0 r0 d32768 u32768 alloc=3D1*32768
[    0.000000] pcpu-alloc: [0] 0
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 13004=
8
[    0.000000] Kernel command line: ip=3D192.168.0.3:192.168.0.1::255.0.0.0=
:vgoippro:eth0:off=20
console=3DttyS0,115200
[    0.000000] Dentry cache hash table entries: 65536 (order: 6, 262144 byt=
es, linear)
[    0.000000] Inode-cache hash table entries: 32768 (order: 5, 131072 byte=
s, linear)
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 503516K/524288K available (7532K kernel code, 2236K =
rwdata, 1328K rodata,=20
1500K init, 931K bss, 20772K reserved, 0K cma-reserved)
[    0.000000] Kernel virtual memory layout:
[    0.000000]   * 0xff7ff000..0xfffff000  : fixmap
[    0.000000]   * 0xff7fd000..0xff7ff000  : early ioremap
[    0.000000]   * 0xe1000000..0xff7fd000  : vmalloc & ioremap
[    0.000000] SLUB: HWalign=3D32, Order=3D0-3, MinObjects=3D0, CPUs=3D1, N=
odes=3D1
[    0.000000] rcu: Preemptible hierarchical RCU implementation.
[    0.000000] rcu: 	RCU event tracing is enabled.
[    0.000000] 	Trampoline variant of Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 1=
0 jiffies.
[    0.000000] NR_IRQS: 512, nr_irqs: 512, preallocated irqs: 16
[    0.000000] IPIC (128 IRQ sources) at (ptrval)
[    0.000000] kfence: initialized - using 2097152 bytes for 255 objects at=
 0x(ptrval)-0x(ptrval)
...
[    4.472455]     # Subtest: kfence
[    4.472490]     1..25
[    4.476069]     # test_out_of_bounds_read: test_alloc: size=3D32, gfp=3D=
cc0, policy=3Dleft, cache=3D0
[    4.946420] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    4.953667] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0=
x90/0x228
[    4.953667]
[    4.962657] Out-of-bounds read at 0x(ptrval) (1B left of kfence-#23):
[    4.969109]  test_out_of_bounds_read+0x90/0x228
[    4.973663]  kunit_try_run_case+0x5c/0xd0
[    4.977712]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    4.983128]  kthread+0x15c/0x174
[    4.986387]  ret_from_kernel_thread+0x14/0x1c
[    4.990774]
[    4.992274] kfence-#23 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 91:
[    5.000997]  test_alloc+0x10c/0x384
[    5.004508]  test_out_of_bounds_read+0x90/0x228
[    5.009057]  kunit_try_run_case+0x5c/0xd0
[    5.013093]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.018505]  kthread+0x15c/0x174
[    5.021758]  ret_from_kernel_thread+0x14/0x1c
[    5.026139]
[    5.027641] CPU: 0 PID: 91 Comm: kunit_try_catch Not tainted=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    5.037729] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.045220]     # test_out_of_bounds_read: test_alloc: size=3D32, gfp=3D=
cc0, policy=3Dright, cache=3D0
[    5.146454] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.153698] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0=
x14c/0x228
[    5.153698]
[    5.162770] Out-of-bounds read at 0x(ptrval) (32B right of kfence-#24):
[    5.169395]  test_out_of_bounds_read+0x14c/0x228
[    5.174037]  kunit_try_run_case+0x5c/0xd0
[    5.178085]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.183501]  kthread+0x15c/0x174
[    5.186758]  ret_from_kernel_thread+0x14/0x1c
[    5.191145]
[    5.192645] kfence-#24 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 91:
[    5.201366]  test_alloc+0x10c/0x384
[    5.204878]  test_out_of_bounds_read+0x14c/0x228
[    5.209514]  kunit_try_run_case+0x5c/0xd0
[    5.213552]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.218965]  kthread+0x15c/0x174
[    5.222219]  ret_from_kernel_thread+0x14/0x1c
[    5.226600]
[    5.228103] CPU: 0 PID: 91 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    5.239575] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.247126]     ok 1 - test_out_of_bounds_read
[    5.247534]     # test_out_of_bounds_read-memcache: setup_test_cache: si=
ze=3D32, ctor=3D0x0
[    5.260310]     # test_out_of_bounds_read-memcache: test_alloc: size=3D3=
2, gfp=3Dcc0, policy=3Dleft,=20
cache=3D1
[    5.356422] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.363670] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0=
x90/0x228
[    5.363670]
[    5.372661] Out-of-bounds read at 0x(ptrval) (1B left of kfence-#25):
[    5.379115]  test_out_of_bounds_read+0x90/0x228
[    5.383671]  kunit_try_run_case+0x5c/0xd0
[    5.387720]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.393138]  kthread+0x15c/0x174
[    5.396398]  ret_from_kernel_thread+0x14/0x1c
[    5.400786]
[    5.402287] kfence-#25 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 92:
[    5.410490]  test_alloc+0xfc/0x384
[    5.413918]  test_out_of_bounds_read+0x90/0x228
[    5.418470]  kunit_try_run_case+0x5c/0xd0
[    5.422511]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.427926]  kthread+0x15c/0x174
[    5.431180]  ret_from_kernel_thread+0x14/0x1c
[    5.435563]
[    5.437067] CPU: 0 PID: 92 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    5.448539] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.456076]     # test_out_of_bounds_read-memcache: test_alloc: size=3D3=
2, gfp=3Dcc0, policy=3Dright,=20
cache=3D1
[    5.556454] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.563701] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0=
x14c/0x228
[    5.563701]
[    5.572774] Out-of-bounds read at 0x(ptrval) (32B right of kfence-#26):
[    5.579400]  test_out_of_bounds_read+0x14c/0x228
[    5.584042]  kunit_try_run_case+0x5c/0xd0
[    5.588091]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.593509]  kthread+0x15c/0x174
[    5.596768]  ret_from_kernel_thread+0x14/0x1c
[    5.601155]
[    5.602656] kfence-#26 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 92:
[    5.610861]  test_alloc+0xfc/0x384
[    5.614288]  test_out_of_bounds_read+0x14c/0x228
[    5.618927]  kunit_try_run_case+0x5c/0xd0
[    5.622966]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.628382]  kthread+0x15c/0x174
[    5.631637]  ret_from_kernel_thread+0x14/0x1c
[    5.636019]
[    5.637522] CPU: 0 PID: 92 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    5.648993] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.656810]     ok 2 - test_out_of_bounds_read-memcache
[    5.657178]     # test_out_of_bounds_write: test_alloc: size=3D32, gfp=
=3Dcc0, policy=3Dleft, cache=3D0
[    5.766441] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.773686] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write=
+0x78/0x164
[    5.773686]
[    5.782848] Out-of-bounds write at 0x(ptrval) (1B left of kfence-#27):
[    5.789387]  test_out_of_bounds_write+0x78/0x164
[    5.794029]  kunit_try_run_case+0x5c/0xd0
[    5.798078]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.803494]  kthread+0x15c/0x174
[    5.806753]  ret_from_kernel_thread+0x14/0x1c
[    5.811138]
[    5.812638] kfence-#27 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 93:
[    5.821357]  test_alloc+0x10c/0x384
[    5.824868]  test_out_of_bounds_write+0x78/0x164
[    5.829503]  kunit_try_run_case+0x5c/0xd0
[    5.833538]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    5.838949]  kthread+0x15c/0x174
[    5.842202]  ret_from_kernel_thread+0x14/0x1c
[    5.846580]
[    5.848083] CPU: 0 PID: 93 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    5.859554] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.867115]     ok 3 - test_out_of_bounds_write
[    5.867476]     # test_out_of_bounds_write-memcache: setup_test_cache: s=
ize=3D32, ctor=3D0x0
[    5.880408]     # test_out_of_bounds_write-memcache: test_alloc: size=3D=
32, gfp=3Dcc0, policy=3Dleft,=20
cache=3D1
[    5.976421] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.983669] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write=
+0x78/0x164
[    5.983669]
[    5.992834] Out-of-bounds write at 0x(ptrval) (1B left of kfence-#28):
[    5.999374]  test_out_of_bounds_write+0x78/0x164
[    6.004016]  kunit_try_run_case+0x5c/0xd0
[    6.008065]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.013481]  kthread+0x15c/0x174
[    6.016741]  ret_from_kernel_thread+0x14/0x1c
[    6.021128]
[    6.022631] kfence-#28 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 94:
[    6.030835]  test_alloc+0xfc/0x384
[    6.034263]  test_out_of_bounds_write+0x78/0x164
[    6.038903]  kunit_try_run_case+0x5c/0xd0
[    6.042944]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.048359]  kthread+0x15c/0x174
[    6.051615]  ret_from_kernel_thread+0x14/0x1c
[    6.055998]
[    6.057501] CPU: 0 PID: 94 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    6.068973] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.076743]     ok 4 - test_out_of_bounds_write-memcache
[    6.077110]     # test_use_after_free_read: test_alloc: size=3D32, gfp=
=3Dcc0, policy=3Dany, cache=3D0
[    6.186527] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.193773] BUG: KFENCE: use-after-free read in test_use_after_free_read=
+0xa0/0x158
[    6.193773]
[    6.202934] Use-after-free read at 0x(ptrval) (in kfence-#29):
[    6.208777]  test_use_after_free_read+0xa0/0x158
[    6.213417]  kunit_try_run_case+0x5c/0xd0
[    6.217466]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.222882]  kthread+0x15c/0x174
[    6.226140]  ret_from_kernel_thread+0x14/0x1c
[    6.230526]
[    6.232026] kfence-#29 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 95:
[    6.240746]  test_alloc+0x10c/0x384
[    6.244257]  test_use_after_free_read+0x7c/0x158
[    6.248892]  kunit_try_run_case+0x5c/0xd0
[    6.252927]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.258337]  kthread+0x15c/0x174
[    6.261590]  ret_from_kernel_thread+0x14/0x1c
[    6.265969]
[    6.265969] freed by task 95:
[    6.270467]  test_use_after_free_read+0xa0/0x158
[    6.275108]  kunit_try_run_case+0x5c/0xd0
[    6.279141]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.284551]  kthread+0x15c/0x174
[    6.287802]  ret_from_kernel_thread+0x14/0x1c
[    6.292180]
[    6.293682] CPU: 0 PID: 95 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    6.305153] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.312658]     ok 5 - test_use_after_free_read
[    6.313020]     # test_use_after_free_read-memcache: setup_test_cache: s=
ize=3D32, ctor=3D0x0
[    6.325976]     # test_use_after_free_read-memcache: test_alloc: size=3D=
32, gfp=3Dcc0, policy=3Dany,=20
cache=3D1
[    6.416496] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.423743] BUG: KFENCE: use-after-free read in test_use_after_free_read=
+0x98/0x158
[    6.423743]
[    6.432908] Use-after-free read at 0x(ptrval) (in kfence-#30):
[    6.438752]  test_use_after_free_read+0x98/0x158
[    6.443395]  kunit_try_run_case+0x5c/0xd0
[    6.447445]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.452863]  kthread+0x15c/0x174
[    6.456124]  ret_from_kernel_thread+0x14/0x1c
[    6.460511]
[    6.462014] kfence-#30 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 96:
[    6.470219]  test_alloc+0xfc/0x384
[    6.473646]  test_use_after_free_read+0x7c/0x158
[    6.478286]  kunit_try_run_case+0x5c/0xd0
[    6.482327]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.487742]  kthread+0x15c/0x174
[    6.490998]  ret_from_kernel_thread+0x14/0x1c
[    6.495381]
[    6.495381] freed by task 96:
[    6.499849]  test_use_after_free_read+0x98/0x158
[    6.504490]  kunit_try_run_case+0x5c/0xd0
[    6.508530]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.513945]  kthread+0x15c/0x174
[    6.517201]  ret_from_kernel_thread+0x14/0x1c
[    6.521583]
[    6.523086] CPU: 0 PID: 96 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    6.534558] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.542222]     ok 6 - test_use_after_free_read-memcache
[    6.542587]     # test_double_free: test_alloc: size=3D32, gfp=3Dcc0, po=
licy=3Dany, cache=3D0
[    6.646612] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.653855] BUG: KFENCE: invalid free in test_double_free+0xc0/0x170
[    6.653855]
[    6.661704] Invalid free of 0x(ptrval) (in kfence-#31):
[    6.666940]  test_double_free+0xc0/0x170
[    6.670889]  kunit_try_run_case+0x5c/0xd0
[    6.674928]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.680341]  kthread+0x15c/0x174
[    6.683596]  ret_from_kernel_thread+0x14/0x1c
[    6.687977]
[    6.689478] kfence-#31 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 97:
[    6.698196]  test_alloc+0x10c/0x384
[    6.701706]  test_double_free+0x7c/0x170
[    6.705649]  kunit_try_run_case+0x5c/0xd0
[    6.709685]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.715096]  kthread+0x15c/0x174
[    6.718347]  ret_from_kernel_thread+0x14/0x1c
[    6.722725]
[    6.722725] freed by task 97:
[    6.727222]  test_double_free+0xa0/0x170
[    6.731169]  kunit_try_run_case+0x5c/0xd0
[    6.735203]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.740615]  kthread+0x15c/0x174
[    6.743865]  ret_from_kernel_thread+0x14/0x1c
[    6.748243]
[    6.749746] CPU: 0 PID: 97 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    6.761217] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.768683]     ok 7 - test_double_free
[    6.769043]     # test_double_free-memcache: setup_test_cache: size=3D32=
, ctor=3D0x0
[    6.780589]     # test_double_free-memcache: test_alloc: size=3D32, gfp=
=3Dcc0, policy=3Dany, cache=3D1
[    6.876516] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.883761] BUG: KFENCE: invalid free in test_double_free+0xb4/0x170
[    6.883761]
[    6.891612] Invalid free of 0x(ptrval) (in kfence-#32):
[    6.896854]  test_double_free+0xb4/0x170
[    6.900807]  kunit_try_run_case+0x5c/0xd0
[    6.904857]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.910277]  kthread+0x15c/0x174
[    6.913540]  ret_from_kernel_thread+0x14/0x1c
[    6.917930]
[    6.919432] kfence-#32 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 98:
[    6.927637]  test_alloc+0xfc/0x384
[    6.931067]  test_double_free+0x7c/0x170
[    6.935015]  kunit_try_run_case+0x5c/0xd0
[    6.939057]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.944473]  kthread+0x15c/0x174
[    6.947728]  ret_from_kernel_thread+0x14/0x1c
[    6.952113]
[    6.952113] freed by task 98:
[    6.956579]  test_double_free+0x98/0x170
[    6.960528]  kunit_try_run_case+0x5c/0xd0
[    6.964570]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    6.969985]  kthread+0x15c/0x174
[    6.973242]  ret_from_kernel_thread+0x14/0x1c
[    6.977626]
[    6.979130] CPU: 0 PID: 98 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    6.990602] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    6.998260]     ok 8 - test_double_free-memcache
[    6.998626]     # test_invalid_addr_free: test_alloc: size=3D32, gfp=3Dc=
c0, policy=3Dany, cache=3D0
[    7.106546] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.113790] BUG: KFENCE: invalid free in test_invalid_addr_free+0xa4/0x1=
78
[    7.113790]
[    7.122159] Invalid free of 0x(ptrval) (in kfence-#33):
[    7.127397]  test_invalid_addr_free+0xa4/0x178
[    7.131867]  kunit_try_run_case+0x5c/0xd0
[    7.135907]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.141323]  kthread+0x15c/0x174
[    7.144576]  ret_from_kernel_thread+0x14/0x1c
[    7.148959]
[    7.150460] kfence-#33 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 99:
[    7.159179]  test_alloc+0x10c/0x384
[    7.162692]  test_invalid_addr_free+0x78/0x178
[    7.167157]  kunit_try_run_case+0x5c/0xd0
[    7.171195]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.176608]  kthread+0x15c/0x174
[    7.179862]  ret_from_kernel_thread+0x14/0x1c
[    7.184245]
[    7.185748] CPU: 0 PID: 99 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    7.197220] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.204816]     ok 9 - test_invalid_addr_free
[    7.205177]     # test_invalid_addr_free-memcache: setup_test_cache: siz=
e=3D32, ctor=3D0x0
[    7.217849]     # test_invalid_addr_free-memcache: test_alloc: size=3D32=
, gfp=3Dcc0, policy=3Dany, cache=3D1
[    7.306455] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.313701] BUG: KFENCE: invalid free in test_invalid_addr_free+0x98/0x1=
78
[    7.313701]
[    7.322070] Invalid free of 0x(ptrval) (in kfence-#34):
[    7.327310]  test_invalid_addr_free+0x98/0x178
[    7.331781]  kunit_try_run_case+0x5c/0xd0
[    7.335832]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.341252]  kthread+0x15c/0x174
[    7.344514]  ret_from_kernel_thread+0x14/0x1c
[    7.348903]
[    7.350405] kfence-#34 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 100:
[    7.358695]  test_alloc+0xfc/0x384
[    7.362125]  test_invalid_addr_free+0x78/0x178
[    7.366591]  kunit_try_run_case+0x5c/0xd0
[    7.370631]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.376047]  kthread+0x15c/0x174
[    7.379303]  ret_from_kernel_thread+0x14/0x1c
[    7.383687]
[    7.385191] CPU: 0 PID: 100 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    7.396751] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.404531]     ok 10 - test_invalid_addr_free-memcache
[    7.404897]     # test_corruption: test_alloc: size=3D32, gfp=3Dcc0, pol=
icy=3Dleft, cache=3D0
[    7.506510] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.513754] BUG: KFENCE: memory corruption in test_corruption+0xac/0x20c
[    7.513754]
[    7.521951] Corrupted memory at 0x(ptrval) [ ! . . . . . . . . . . . . .=
 . . ] (in kfence-#35):
[    7.530760]  test_corruption+0xac/0x20c
[    7.534624]  kunit_try_run_case+0x5c/0xd0
[    7.538664]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.544080]  kthread+0x15c/0x174
[    7.547335]  ret_from_kernel_thread+0x14/0x1c
[    7.551719]
[    7.553219] kfence-#35 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 101:
[    7.562027]  test_alloc+0x10c/0x384
[    7.565540]  test_corruption+0x7c/0x20c
[    7.569399]  kunit_try_run_case+0x5c/0xd0
[    7.573437]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    7.578850]  kthread+0x15c/0x174
[    7.582104]  ret_from_kernel_thread+0x14/0x1c
[    7.586485]
[    7.587988] CPU: 0 PID: 101 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    7.599545] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.606994]     # test_corruption: test_alloc: size=3D32, gfp=3Dcc0, pol=
icy=3Dright, cache=3D0
[    7.976603] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    7.983846] BUG: KFENCE: memory corruption in test_corruption+0x168/0x20=
c
[    7.983846]
[    7.992128] Corrupted memory at 0x(ptrval) [ ! ] (in kfence-#38):
[    7.998258]  test_corruption+0x168/0x20c
[    8.002208]  kunit_try_run_case+0x5c/0xd0
[    8.006247]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.011661]  kthread+0x15c/0x174
[    8.014915]  ret_from_kernel_thread+0x14/0x1c
[    8.019297]
[    8.020797] kfence-#38 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 101:
[    8.029603]  test_alloc+0x10c/0x384
[    8.033114]  test_corruption+0x138/0x20c
[    8.037057]  kunit_try_run_case+0x5c/0xd0
[    8.041092]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.046503]  kthread+0x15c/0x174
[    8.049752]  ret_from_kernel_thread+0x14/0x1c
[    8.054131]
[    8.055633] CPU: 0 PID: 101 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    8.067190] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    8.074671]     ok 11 - test_corruption
[    8.075043]     # test_corruption-memcache: setup_test_cache: size=3D32,=
 ctor=3D0x0
[    8.086586]     # test_corruption-memcache: test_alloc: size=3D32, gfp=
=3Dcc0, policy=3Dleft, cache=3D1
[    8.436449] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    8.443694] BUG: KFENCE: memory corruption in test_corruption+0xa4/0x20c
[    8.443694]
[    8.451888] Corrupted memory at 0x(ptrval) [ ! . . . . . . . . . . . . .=
 . . ] (in kfence-#41):
[    8.460709]  test_corruption+0xa4/0x20c
[    8.464573]  kunit_try_run_case+0x5c/0xd0
[    8.468622]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.474039]  kthread+0x15c/0x174
[    8.477298]  ret_from_kernel_thread+0x14/0x1c
[    8.481685]
[    8.483187] kfence-#41 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 102:
[    8.491476]  test_alloc+0xfc/0x384
[    8.494904]  test_corruption+0x7c/0x20c
[    8.498763]  kunit_try_run_case+0x5c/0xd0
[    8.502801]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.508215]  kthread+0x15c/0x174
[    8.511468]  ret_from_kernel_thread+0x14/0x1c
[    8.515849]
[    8.517352] CPU: 0 PID: 102 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    8.528910] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    8.536421]     # test_corruption-memcache: test_alloc: size=3D32, gfp=
=3Dcc0, policy=3Dright, cache=3D1
[    8.646543] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    8.653786] BUG: KFENCE: memory corruption in test_corruption+0x160/0x20=
c
[    8.653786]
[    8.662066] Corrupted memory at 0x(ptrval) [ ! ] (in kfence-#42):
[    8.668201]  test_corruption+0x160/0x20c
[    8.672151]  kunit_try_run_case+0x5c/0xd0
[    8.676199]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.681615]  kthread+0x15c/0x174
[    8.684872]  ret_from_kernel_thread+0x14/0x1c
[    8.689259]
[    8.690760] kfence-#42 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 102:
[    8.699050]  test_alloc+0xfc/0x384
[    8.702477]  test_corruption+0x138/0x20c
[    8.706422]  kunit_try_run_case+0x5c/0xd0
[    8.710461]  kunit_generic_run_threadfn_adapter+0x24/0x30
[    8.715875]  kthread+0x15c/0x174
[    8.719130]  ret_from_kernel_thread+0x14/0x1c
[    8.723511]
[    8.725014] CPU: 0 PID: 102 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[    8.736572] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    8.744274]     ok 12 - test_corruption-memcache
[    8.744642]     # test_free_bulk: test_alloc: size=3D108, gfp=3Dcc0, pol=
icy=3Dright, cache=3D0
[    8.846447]     # test_free_bulk: test_alloc: size=3D108, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    8.854317]     # test_free_bulk: test_alloc: size=3D108, gfp=3Dcc0, pol=
icy=3Dleft, cache=3D0
[    8.976407]     # test_free_bulk: test_alloc: size=3D108, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    8.984275]     # test_free_bulk: test_alloc: size=3D108, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    8.992322]     # test_free_bulk: test_alloc: size=3D279, gfp=3Dcc0, pol=
icy=3Dright, cache=3D0
[    9.496452]     # test_free_bulk: test_alloc: size=3D279, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    9.504323]     # test_free_bulk: test_alloc: size=3D279, gfp=3Dcc0, pol=
icy=3Dleft, cache=3D0
[    9.626404]     # test_free_bulk: test_alloc: size=3D279, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    9.634272]     # test_free_bulk: test_alloc: size=3D279, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    9.642331]     # test_free_bulk: test_alloc: size=3D168, gfp=3Dcc0, pol=
icy=3Dright, cache=3D0
[    9.886438]     # test_free_bulk: test_alloc: size=3D168, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[    9.894309]     # test_free_bulk: test_alloc: size=3D168, gfp=3Dcc0, pol=
icy=3Dleft, cache=3D0
[   10.146407]     # test_free_bulk: test_alloc: size=3D168, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[   10.154277]     # test_free_bulk: test_alloc: size=3D168, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[   10.162329]     # test_free_bulk: test_alloc: size=3D95, gfp=3Dcc0, poli=
cy=3Dright, cache=3D0
[   10.406442]     # test_free_bulk: test_alloc: size=3D95, gfp=3Dcc0, poli=
cy=3Dnone, cache=3D0
[   10.414225]     # test_free_bulk: test_alloc: size=3D95, gfp=3Dcc0, poli=
cy=3Dleft, cache=3D0
[   10.796405]     # test_free_bulk: test_alloc: size=3D95, gfp=3Dcc0, poli=
cy=3Dnone, cache=3D0
[   10.804189]     # test_free_bulk: test_alloc: size=3D95, gfp=3Dcc0, poli=
cy=3Dnone, cache=3D0
[   10.812156]     # test_free_bulk: test_alloc: size=3D214, gfp=3Dcc0, pol=
icy=3Dright, cache=3D0
[   11.056442]     # test_free_bulk: test_alloc: size=3D214, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[   11.064312]     # test_free_bulk: test_alloc: size=3D214, gfp=3Dcc0, pol=
icy=3Dleft, cache=3D0
[   11.186407]     # test_free_bulk: test_alloc: size=3D214, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[   11.194276]     # test_free_bulk: test_alloc: size=3D214, gfp=3Dcc0, pol=
icy=3Dnone, cache=3D0
[   11.202357]     ok 13 - test_free_bulk
[   11.202730]     # test_free_bulk-memcache: setup_test_cache: size=3D264,=
 ctor=3D0x0
[   11.214213]     # test_free_bulk-memcache: test_alloc: size=3D264, gfp=
=3Dcc0, policy=3Dright, cache=3D1
[   11.316443]     # test_free_bulk-memcache: test_alloc: size=3D264, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   11.325092]     # test_free_bulk-memcache: test_alloc: size=3D264, gfp=
=3Dcc0, policy=3Dleft, cache=3D1
[   11.706404]     # test_free_bulk-memcache: test_alloc: size=3D264, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   11.715052]     # test_free_bulk-memcache: test_alloc: size=3D264, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   11.724042]     # test_free_bulk-memcache: setup_test_cache: size=3D58, =
ctor=3Dctor_set_x
[   11.732296]     # test_free_bulk-memcache: test_alloc: size=3D58, gfp=3D=
cc0, policy=3Dright, cache=3D1
[   12.486442]     # test_free_bulk-memcache: test_alloc: size=3D58, gfp=3D=
cc0, policy=3Dnone, cache=3D1
[   12.495083]     # test_free_bulk-memcache: test_alloc: size=3D58, gfp=3D=
cc0, policy=3Dleft, cache=3D1
[   12.616406]     # test_free_bulk-memcache: test_alloc: size=3D58, gfp=3D=
cc0, policy=3Dnone, cache=3D1
[   12.624967]     # test_free_bulk-memcache: test_alloc: size=3D58, gfp=3D=
cc0, policy=3Dnone, cache=3D1
[   12.633885]     # test_free_bulk-memcache: setup_test_cache: size=3D260,=
 ctor=3D0x0
[   12.641609]     # test_free_bulk-memcache: test_alloc: size=3D260, gfp=
=3Dcc0, policy=3Dright, cache=3D1
[   12.746443]     # test_free_bulk-memcache: test_alloc: size=3D260, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   12.755091]     # test_free_bulk-memcache: test_alloc: size=3D260, gfp=
=3Dcc0, policy=3Dleft, cache=3D1
[   13.136401]     # test_free_bulk-memcache: test_alloc: size=3D260, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.145052]     # test_free_bulk-memcache: test_alloc: size=3D260, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.154042]     # test_free_bulk-memcache: setup_test_cache: size=3D155,=
 ctor=3Dctor_set_x
[   13.162383]     # test_free_bulk-memcache: test_alloc: size=3D155, gfp=
=3Dcc0, policy=3Dright, cache=3D1
[   13.526458]     # test_free_bulk-memcache: test_alloc: size=3D155, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.535107]     # test_free_bulk-memcache: test_alloc: size=3D155, gfp=
=3Dcc0, policy=3Dleft, cache=3D1
[   13.786404]     # test_free_bulk-memcache: test_alloc: size=3D155, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.795051]     # test_free_bulk-memcache: test_alloc: size=3D155, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.804047]     # test_free_bulk-memcache: setup_test_cache: size=3D173,=
 ctor=3D0x0
[   13.811768]     # test_free_bulk-memcache: test_alloc: size=3D173, gfp=
=3Dcc0, policy=3Dright, cache=3D1
[   13.916446]     # test_free_bulk-memcache: test_alloc: size=3D173, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   13.925094]     # test_free_bulk-memcache: test_alloc: size=3D173, gfp=
=3Dcc0, policy=3Dleft, cache=3D1
[   14.046408]     # test_free_bulk-memcache: test_alloc: size=3D173, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   14.055057]     # test_free_bulk-memcache: test_alloc: size=3D173, gfp=
=3Dcc0, policy=3Dnone, cache=3D1
[   14.064085]     ok 14 - test_free_bulk-memcache
[   14.064468]     ok 15 - test_init_on_free
[   14.069584]     ok 16 - test_init_on_free-memcache
[   14.073956]     # test_kmalloc_aligned_oob_read: test_alloc: size=3D73, =
gfp=3Dcc0, policy=3Dright, cache=3D0
[   14.176456] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   14.183702] BUG: KFENCE: out-of-bounds read in test_kmalloc_aligned_oob_=
read+0x60/0x200
[   14.183702]
[   14.193213] Out-of-bounds read at 0x(ptrval) (81B right of kfence-#84):
[   14.199839]  test_kmalloc_aligned_oob_read+0x60/0x200
[   14.204914]  kunit_try_run_case+0x5c/0xd0
[   14.208964]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   14.214380]  kthread+0x15c/0x174
[   14.217640]  ret_from_kernel_thread+0x14/0x1c
[   14.222026]
[   14.223527] kfence-#84 [0x(ptrval)-0x(ptrval), size=3D73, cache=3Dkmallo=
c-96] allocated by task 107:
[   14.232335]  test_alloc+0x10c/0x384
[   14.235847]  test_kmalloc_aligned_oob_read+0x60/0x200
[   14.240916]  kunit_try_run_case+0x5c/0xd0
[   14.244953]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   14.250365]  kthread+0x15c/0x174
[   14.253617]  ret_from_kernel_thread+0x14/0x1c
[   14.257998]
[   14.259501] CPU: 0 PID: 107 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   14.271058] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   14.278626]     ok 17 - test_kmalloc_aligned_oob_read
[   14.278987]     # test_kmalloc_aligned_oob_write: test_alloc: size=3D73,=
 gfp=3Dcc0, policy=3Dright, cache=3D0
[   14.646606] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   14.653849] BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_w=
rite+0x104/0x1b0
[   14.653849]
[   14.663430] Corrupted memory at 0x(ptrval) [ ! . . . . . . ] (in kfence-=
#87):
[   14.670630]  test_kmalloc_aligned_oob_write+0x104/0x1b0
[   14.675880]  kunit_try_run_case+0x5c/0xd0
[   14.679921]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   14.685337]  kthread+0x15c/0x174
[   14.688592]  ret_from_kernel_thread+0x14/0x1c
[   14.692975]
[   14.694477] kfence-#87 [0x(ptrval)-0x(ptrval), size=3D73, cache=3Dkmallo=
c-96] allocated by task 108:
[   14.703285]  test_alloc+0x10c/0x384
[   14.706800]  test_kmalloc_aligned_oob_write+0x58/0x1b0
[   14.711959]  kunit_try_run_case+0x5c/0xd0
[   14.715997]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   14.721411]  kthread+0x15c/0x174
[   14.724666]  ret_from_kernel_thread+0x14/0x1c
[   14.729047]
[   14.730551] CPU: 0 PID: 108 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   14.742108] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   14.749627]     ok 18 - test_kmalloc_aligned_oob_write
[   14.749989]     # test_shrink_memcache: setup_test_cache: size=3D32, cto=
r=3D0x0
[   14.762405]     # test_shrink_memcache: test_alloc: size=3D32, gfp=3Dcc0=
, policy=3Dany, cache=3D1
[   14.856686]     ok 19 - test_shrink_memcache
[   14.857052]     # test_memcache_ctor: setup_test_cache: size=3D32, ctor=
=3Dctor_set_x
[   14.869060]     # test_memcache_ctor: test_alloc: size=3D32, gfp=3Dcc0, =
policy=3Dany, cache=3D1
[   14.986723]     ok 20 - test_memcache_ctor
[   14.987102] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x54/=
0x23c
[   14.998426]
[   15.007061] Invalid read at 0x(ptrval):
[   15.010906]  finish_task_switch.isra.0+0x54/0x23c
[   15.015633]  kunit_try_run_case+0x5c/0xd0
[   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   15.025099]  kthread+0x15c/0x174
[   15.028359]  ret_from_kernel_thread+0x14/0x1c
[   15.032747]
[   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/k=
fence_test.c:636
[   15.053324]     Expected report_matches(&expect) to be true, but is fals=
e
[   15.068359]     not ok 21 - test_invalid_access
[   15.068722]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Dcc0, poli=
cy=3Dany, cache=3D0
[   15.156430]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.286387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.416379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.546385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.676382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.806388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   15.936382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.066420]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.196384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.326379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.456381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.586400]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.716382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.846389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   16.976382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.106388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.236380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.366395]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.496385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.626383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.756398]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   17.886386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.016387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.146383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.276385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.406388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.536389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.666387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.796386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   18.926381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.056383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.186384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.316388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.446382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.576387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.706386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.836379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   19.966387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.096387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.226387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.356381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.486386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.616380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.746387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   20.876379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.006383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.136389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.266385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.396385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.526382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.656387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.786385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   21.916385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.046381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.176381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.306401]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.436383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.566381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.696411]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.826388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   22.956383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.086387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.216405]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.346379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.476381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.606387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.736385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.866383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   23.996386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.126390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.256386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.386382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.516388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.646385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.776381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   24.906385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.036379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.166381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.296391]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.426385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.556380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.686385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.816387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   25.946382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.076379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.206384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.336389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.466383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.596385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.726379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.856389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   26.986384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.116383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.246381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.376387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.506395]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.636381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.766386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   27.896381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.026387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.156386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.286393]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.416388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.546385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.676380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.806384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   28.936387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.066390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.196384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.326416]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.456388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.586383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.716385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.846402]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   29.976396]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.106385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.236379]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.366395]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.496386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.626387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.756380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   30.886386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.016381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.146383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.276388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.406386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.536383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.666388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.796384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   31.926384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.056391]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.186382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.316385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.446391]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.576385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.706381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.836388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   32.966388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.096378]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.226386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.356383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.486389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.616386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.746383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   33.876385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.006383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.136389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.266384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.396385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.526382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.656385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.786383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   34.916383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.046390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.176387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.306386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.436385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.566382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.696386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.826383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   35.956415]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.086386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.216382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.346378]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.476404]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.606382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.736386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.866381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   36.996388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.126390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.256395]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.386388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.516386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.646382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.776385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   37.906385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.036389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.166382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.296389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.426387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.556388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.686388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.816386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   38.946381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.076382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.206387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.336386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.466382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.596392]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.726382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.856390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   39.986389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.116382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.246382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.376381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.506387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.636388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.766387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   40.896381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.026390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.156384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.286380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.416384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.546383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.676388]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.806386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   41.936381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.066390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.196389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.326386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.456390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.586414]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.716380]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.846386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   42.976381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.106404]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.236385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.366387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.496382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.626385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.756378]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   43.886387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.016390]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.146385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.276389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.406382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.536384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.666391]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.796382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   44.926387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.056381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.186384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.316389]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.446382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.576385]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.706382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.836387]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   45.966383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.096383]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.226382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.356382]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.486384]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.616391]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.746386]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   46.876381]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   47.006399]     # test_gfpzero: test_alloc: size=3D4096, gfp=3Ddc0, poli=
cy=3Dany, cache=3D0
[   47.136923]     ok 22 - test_gfpzero
[   47.137299]     # test_memcache_typesafe_by_rcu: setup_test_cache: size=
=3D32, ctor=3D0x0
[   47.148950]     # test_memcache_typesafe_by_rcu: test_alloc: size=3D32, =
gfp=3Dcc0, policy=3Dany, cache=3D1
[   47.296422] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   47.303670] BUG: KFENCE: use-after-free read in test_memcache_typesafe_b=
y_rcu+0x210/0x34c
[   47.303670]
[   47.313354] Use-after-free read at 0x(ptrval) (in kfence-#91):
[   47.319199]  test_memcache_typesafe_by_rcu+0x210/0x34c
[   47.324363]  kunit_try_run_case+0x5c/0xd0
[   47.328412]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   47.333830]  kthread+0x15c/0x174
[   47.337090]  ret_from_kernel_thread+0x14/0x1c
[   47.341476]
[   47.342979] kfence-#91 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dtest] =
allocated by task 113:
[   47.351269]  test_alloc+0xfc/0x384
[   47.354696]  test_memcache_typesafe_by_rcu+0x100/0x34c
[   47.359855]  kunit_try_run_case+0x5c/0xd0
[   47.363896]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   47.369311]  kthread+0x15c/0x174
[   47.372568]  ret_from_kernel_thread+0x14/0x1c
[   47.376951]
[   47.376951] freed by task 0:
[   47.381401]  rcu_core+0x1c8/0x900
[   47.384741]  __do_softirq+0x13c/0x374
[   47.388431]  irq_exit+0x9c/0xf8
[   47.391599]  ret_from_except+0x0/0x14
[   47.395289]  default_idle_call+0x5c/0x10c
[   47.399326]  do_idle+0x8c/0x118
[   47.402495]  cpu_startup_entry+0x14/0x1c
[   47.406441]  start_kernel+0x4e4/0x530
[   47.410123]  0x37d0
[   47.412239]
[   47.413742] CPU: 0 PID: 113 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   47.425300] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   47.432931]     ok 23 - test_memcache_typesafe_by_rcu
[   47.433487]     # test_krealloc: test_alloc: size=3D32, gfp=3Dcc0, polic=
y=3Dany, cache=3D0
[   47.556587] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   47.563835] BUG: KFENCE: use-after-free read in test_krealloc+0x3dc/0x57=
8
[   47.563835]
[   47.572130] Use-after-free read at 0x(ptrval) (in kfence-#93):
[   47.577973]  test_krealloc+0x3dc/0x578
[   47.581751]  kunit_try_run_case+0x5c/0xd0
[   47.585800]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   47.591218]  kthread+0x15c/0x174
[   47.594476]  ret_from_kernel_thread+0x14/0x1c
[   47.598863]
[   47.600364] kfence-#93 [0x(ptrval)-0x(ptrval), size=3D32, cache=3Dkmallo=
c-32] allocated by task 114:
[   47.609170]  test_alloc+0x10c/0x384
[   47.612684]  test_krealloc+0x4c/0x578
[   47.616369]  kunit_try_run_case+0x5c/0xd0
[   47.620411]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   47.625825]  kthread+0x15c/0x174
[   47.629078]  ret_from_kernel_thread+0x14/0x1c
[   47.633460]
[   47.633460] freed by task 114:
[   47.638066]  krealloc+0xc4/0x124
[   47.641327]  test_krealloc+0x170/0x578
[   47.645103]  kunit_try_run_case+0x5c/0xd0
[   47.649140]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   47.654554]  kthread+0x15c/0x174
[   47.657808]  ret_from_kernel_thread+0x14/0x1c
[   47.662188]
[   47.663691] CPU: 0 PID: 114 Comm: kunit_try_catch Tainted: G    B=20
5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
[   47.675248] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   47.682686]     ok 24 - test_krealloc
[   47.683045]     # test_memcache_alloc_bulk: setup_test_cache: size=3D32,=
 ctor=3D0x0
[   47.786755]     ok 25 - test_memcache_alloc_bulk
[   47.786799] not ok 1 - kfence

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b9dc8d35-a3b0-261a-b1a4-5f4d33406095%40csgroup.eu.
