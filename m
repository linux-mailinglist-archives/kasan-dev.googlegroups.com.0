Return-Path: <kasan-dev+bncBCXLBLOA7IGBBN7TZXXQKGQEG3PZHDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BC911E2F6
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 12:44:55 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id i9sf2487500wru.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 03:44:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576237495; cv=pass;
        d=google.com; s=arc-20160816;
        b=dTevQJBOSZzq3XLzkGQnnUdJBysdjQSc5r3LUTVEuZxr2bpflERCII/+hiH2SWzUKB
         fo4Ynju2LFVJyIxvCBO8fF6F6LKwzn2DwUo+JyMrAa0nmMRnTQELMbZoCybPUdfgCIAu
         ll3fj/mIxkgYdQy28UnbFGiqxgXpEn5pWdPhl/kpUD8nEnTCa6iEZSbKFtM9PyVNkbUz
         UZm15fLEZsD0Wsu0DcDkIU1ra7UQBocxNLmWUiQBeTVLxfApRvdJYMuvbopWEje499Y7
         bfHLIidVydSUC2LRVUcRhRN+R7aXBKxlOGhwJJ0d4w79qyp3S4U02vHdC2gKcAwGfANX
         lHaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=CrebHBzOIXE7Hncv8WgpGBnN4Dhe8rXuef3RCejzZhY=;
        b=pOKqCjFpnn1Jy+cb7x7VwpeFGSfPS38zQiVCvKJ4zcGFtrIvoaNHU3dVUSAYaxSSNK
         UNtA5qPme3IndxRUNmS8wwCrzkoApDBZMfv2Zyf4SOIbnHKRvfBfvR3/n+Pjkg7WhP1m
         FIpgXGfzMuzh4JWK5UidH4AfSjPfUsRI5N3ZP8DQkkpWYsq2dPoKzQqzM+0w6Gvt5966
         XkzJQLbZYwPYOoAjEYqYgkDlF1+ITqTkkcseDvdIXfB47IWtPm7HoTqJaf8j5W4mXDoh
         rimDgzJSP0ujlK1e4oody3AKwdKHiTL+1FLMadTz1z/7oh6Grh9AcXzEgKJyCkpoUINQ
         bwtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=m4cjFtGL;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CrebHBzOIXE7Hncv8WgpGBnN4Dhe8rXuef3RCejzZhY=;
        b=CwGhiCEt+XNVzz+kaZCYDNfLC2MHFfpExqN2DiwlknAX6YTFYOIeSmsJYV3Uf3Dz0M
         YWyAPY+qjjYeqlAV3JvZg87ijInmosgS0QEon4rB9Q2sS8wNjMOoRQlJTiZ6hLQDzxYI
         6MyjFrUvhk2kF5yxehJcMrFAFdMi/FeZ6pixy9m2sg13P9SfEuUZNW9HVu8qbiDaSlnc
         3eVuUCZ8wOAyuNHf67Ks8WUJoQoVw6KWl/Sx3/EPtY3gWVb8qhEKTrOavlnufZVKeIY2
         Xd9srsXW2DXrjcUAcK63TQVIKJboPef3CzwTLRZaldYkRXaj3AX1PrfRbsLWpe/QFIOg
         d+xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CrebHBzOIXE7Hncv8WgpGBnN4Dhe8rXuef3RCejzZhY=;
        b=YyVagUNvrBJZojnaTnOs0yPntQa47XPQPVk09drQuZ4gejLvost0pKx8o5k5QvRgU4
         j8nNJMjZO1Rl98uIVc/S7qQYHM+YQZvR5t7gZS6hKpoMGUViyJLZ8QiagIaTM6aL9KBU
         snWOcKoRDSux/q5Pf6eq0eZQEuI+nt7n6JIcc1nF2MKwLxtWGYNCBGSxOEr2CKg7IAIY
         QnQcW+HHfY+OXntLqaFKnGfz4c493doBdkTPryK6MP+eywuBpcPvFBoGL8YiYddTKG9Z
         fpbFHEoW3R/QGAgSvGsd5E1euln3d/U0jOX8bHufMCQ5CSD/b8esWrOxg4x7Q+qggjqQ
         pdUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWCub7qXXKvQwldp7I0jxOl1oLNpUdQW3UkwCJBwlu9HDy9HI22
	CWtDhGaP5CU+tGo+wXCRjAc=
X-Google-Smtp-Source: APXvYqw0ScS3v1aoDb0r1ZsKe2PxmdryNZm8ybsiWOsAfLZteebO6k8jZ2Z9K10xTtnGbRaWEhPtqQ==
X-Received: by 2002:a1c:80d4:: with SMTP id b203mr12695022wmd.102.1576237495304;
        Fri, 13 Dec 2019 03:44:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb4c:: with SMTP id u12ls3704606wrn.6.gmail; Fri, 13 Dec
 2019 03:44:54 -0800 (PST)
X-Received: by 2002:a5d:6b03:: with SMTP id v3mr12347239wrw.289.1576237494783;
        Fri, 13 Dec 2019 03:44:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576237494; cv=none;
        d=google.com; s=arc-20160816;
        b=N9j4MxthmW55PDHSMDJ1iS9zDlFNGklnvMwcr7NdlEVj62k0G18TytvQ0Zg44tx+V8
         4itj7f3UmJjt57tWsQOT9HkUvWGago8DgV0FMp/SlLOGdaz9JqJ39+oOHyUsSyE7q3Nj
         Lr4ehCeeO0XLORAzzDlnKixTiq6RXMTVLLfEX+NbJ6UczeHk6jcFmjfX8sWIPWmKc6Yr
         r7pNS/sBR7xTdG5qmCv+w5k8WTGIsnk47265JocmyZhBOoqfcxM0SfCKk5Grad0VF7sW
         R3ACN8vpFKbUeDHURRBJrFfWQd0hvqks2tRdrkvASAgZwKDIxWNuU1o/uKwfKMoBAO7j
         ZRgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=GXcNSiIRiKyDXyT92jW4k31tmkd7NQbvaQCCa3tyddM=;
        b=SqH3WiryySajlKDNDW8/Ywm3WO3aC6A5xvv+gserKgHXN5JtU8NGLm2yFMdpiH2Lc0
         RSTaTMoNhSkx/XPrOo8MtzQ3mubqmwKQj8OskIZXIr+4SdIFKOke9R0hr+7wFQPZfSS+
         9/z9NHEH94a1ngjGsuZfIwDFXG+xOCSTyJn79VmLeoVOVnDd/bqJj4GALTAaQLds7go0
         2801nyKz254P4js1RWRpExh/sT/nSrGNo8QK66rwaKR2aOkhXuRqSpYdO92HT4hCsfs8
         4yMgxs8RMMqjv49YBMIXknnITgfZkEZ4aWrqCJvVF0UesaL/sm/AdY6OtYbymFuXdPWn
         hVeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=m4cjFtGL;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y13si323851wrs.0.2019.12.13.03.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Dec 2019 03:44:54 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47Z83T0PBLz9vBJw;
	Fri, 13 Dec 2019 12:44:53 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 5SpWWOJ66fyK; Fri, 13 Dec 2019 12:44:52 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47Z83S6KYcz9vBJv;
	Fri, 13 Dec 2019 12:44:52 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 240FD8B8B1;
	Fri, 13 Dec 2019 12:44:54 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id sa1BVUFoOkYZ; Fri, 13 Dec 2019 12:44:54 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B2A7C8B8AE;
	Fri, 13 Dec 2019 12:44:53 +0100 (CET)
Subject: Re: [PATCH 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-5-dja@axtens.net>
 <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr>
 <878snkdauf.fsf@dja-thinkpad.axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <464a8b50-0d4c-b1ea-485b-851f7cd7643b@c-s.fr>
Date: Fri, 13 Dec 2019 12:44:53 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <878snkdauf.fsf@dja-thinkpad.axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=m4cjFtGL;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 10/12/2019 =C3=A0 06:10, Daniel Axtens a =C3=A9crit=C2=A0:
> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>=20
>> Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
>>> KASAN support on powerpc64 is interesting:
>>>
>>>    - We want to be able to support inline instrumentation so as to be
>>>      able to catch global and stack issues.
>>>
>>>    - We run a lot of code at boot in real mode. This includes stuff lik=
e
>>>      printk(), so it's not feasible to just disable instrumentation
>>>      around it.
>>
>> Have you definitely given up the idea of doing a standard implementation
>> of KASAN like other 64 bits arches have done ?
>>
>> Isn't it possible to setup an early 1:1 mapping and go in virtual mode
>> earlier ? What is so different between book3s64 and book3e64 ?
>> On book3e64, we've been able to setup KASAN before printing anything
>> (except when using EARLY_DEBUG). Isn't it feasible on book3s64 too ?
>=20
> So I got this pretty wrong when trying to explain it. The problem isn't
> that we run the code in boot as I said, it's that a bunch of the KVM
> code runs in real mode.

Ok.

Does it mean we would be able to implement it the standard way when=20
CONFIG_KVM is not selected ?

>=20
>>>    - disabled reporting when we're checking the stack for exception
>>>      frames. The behaviour isn't wrong, just incompatible with KASAN.
>>
>> Does this applies to / impacts PPC32 at all ?
>=20
> It should. I found that when doing stack walks, the code would touch
> memory that KASAN hadn't unpoisioned. I'm a bit surprised you haven't
> seen it arise, tbh.

How do you trigger that ?

I've tried to provoke some faults with LKDTM that provoke BUG dumps, but=20
it doesn't trip.
I also performed task state listing via sysrq, and I don't get anything=20
wrong either.

>=20
>>>    - Dropped old module stuff in favour of KASAN_VMALLOC.
>>
>> You said in the cover that this is done to avoid having to split modules
>> out of VMALLOC area. Would it be an issue to perform that split ?
>> I can understand it is not easy on 32 bits because vmalloc space is
>> rather small, but on 64 bits don't we have enough virtual space to
>> confortably split modules out of vmalloc ? The 64 bits already splits
>> ioremap away from vmalloc whereas 32 bits have them merged too.
>=20
> I could have done this. Maybe I should have done this. But now I have
> done vmalloc space support.

So you force the use of KASAN_VMALLOC ? Doesn't it have a performance=20
impact ?


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/464a8b50-0d4c-b1ea-485b-851f7cd7643b%40c-s.fr.
