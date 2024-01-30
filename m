Return-Path: <kasan-dev+bncBAABBV7Q4OWQMGQE64XQHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA7A584261D
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 14:23:36 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2051ab02477sf5633485fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 05:23:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706621015; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0AaMfgAGnJ9JsoAYGZ4sa8JnddNB6OPgDx5IMHUwTCjejt8ybDgJ5/jaYY0MJn8C7
         y7DU1LBg2o2GauFgOdfQtzLast+1lognVuDRY642JPWeH6/bcjnYhWRdIwcpN1vY800l
         S8ddqJGdsUot9s6yckf/dC3vLIgRCAEIwax2JuAp09DDuF4BDWKsraVZG0qSYayuzHu1
         B9Qoo8SzkT3tBP8ugEpf68EyfN2iHEgjl5yEJMWY1BbtqR6hzmPHiDRBjNyudXRrVv3r
         a+48NTC7iXg4b1QFJk2o1KaSNiygiSelWm6b6y8d6Vnu2NajppTTlxHwPU4ioEv37SCl
         mccQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=VuhdV3pxJ2ggzP6JKzbEcF2++mixaA6xRsrBoM9ARyU=;
        fh=7MNXGxtYTwfI8ffyG5AOOQraFXIKbO9yC4nGnB6I72I=;
        b=FHf9q8swHLpdYZ7lJEgzw3GkRQk/9K+9FvQSW+7/lID2OGHlatWScBItpWqKLFNP5d
         IyA3NS74uceVC9wko7kCq6iksYAR5WJkr1ctCN7OPU7/XrDAf2aLxQ2kr4uJeM3bDQw0
         J+DbdqFCZKyVIp6AAGG+ik3X/le71H05vHQNuF0j9r+zeeqlEpCOVgy6hhjpc3AuJMzN
         8NMAc+xXQUoGIqbPybeXZ1L0G+vq+obh6mk5sXXnR25MMh6Jdu147wT7XgjIqUEXKFkc
         SYywXK5ZzCigCr2XdXthf2s8CZt5U59+x2rg3Ir6E7MelQK9jRUpogU9L3ZNjm65IFjV
         /LSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706621015; x=1707225815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VuhdV3pxJ2ggzP6JKzbEcF2++mixaA6xRsrBoM9ARyU=;
        b=vs5/rgnN6VoL3ZGItxWYXr/bJExrFl0J6ZDGpJmzsxzxpyxLGTqfqSns0qtODvs1/Z
         VCe0L9DqDVWJLhjgunAR291XlCgt6MMpZjZDLZZFiAhMR4RwbIOewY/o2jHBQOdQhFqp
         pps+MtE9J1Gzl2iCKHPpXsBik5HyJeBJktH5g/GOwBWa3NQZnDaXonG7IXVu2DVLePDF
         tWxyzLRsLibKhaabxMBKY5myYBs2DivwiLyaDrrQ8w0A2+3XJfWmjGCIyXCKnLcbXeAe
         g60cMFLj5Nq5ZjMsBl7Zakn7m+DA0fJOsndgDTkQZWxADi+fvI6Vrrk7Orgp6h4k0XVI
         ywng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706621015; x=1707225815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=VuhdV3pxJ2ggzP6JKzbEcF2++mixaA6xRsrBoM9ARyU=;
        b=htyZxkxibiWQUlnHM+L7AJCrqPlQVPBPZ0Wq3TSEjj2n7DVt6hgMgCVgkMQRKJ29yP
         8Iw5CzkmyhtoWMfa9xFHKMNf16DuRKMSjuGMp2A7WvvjvS/RpT+F9MF8LH9EjgulhPeD
         W16wR0Sa6/6nuBi1TPq505076lPfAW6TOKl6ORjWEQ7T1/lbzhWG96mcr1bNymRPoaJb
         2FQhhX7P7lrlBa2LM51PiTDy5B+/jC2rcA1ZiL9Fiv4Q6U3RStsPchTL+jkpflDw8CGc
         toov5iwyIZwyAqVXn4wjwhh5Dpc2MMj+s4+4U6hz1qXQrS8zrMtW8I0VR+zWCo+1gCd0
         xiwQ==
X-Gm-Message-State: AOJu0YwzusWkRsSlIhkTOtSKfk/HHxSRY068w0WvjMWWHXyvgVTKjnbo
	zB16kcZ5/QyHOjpS5WZlnliXPUdYZ6buS6x5uiHpe9a7xgJsM6Oc
X-Google-Smtp-Source: AGHT+IHepsCiM/zKu9I9ylPSwXpNLm+wIHcFLzuHIuAE/hslnHrBSlH+hfN/cBhM1/sz2FRgMRwtww==
X-Received: by 2002:a05:6871:7985:b0:218:73ae:3f30 with SMTP id pb5-20020a056871798500b0021873ae3f30mr4304860oac.0.1706621015683;
        Tue, 30 Jan 2024 05:23:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:7b03:b0:218:44c2:c8d with SMTP id
 pf3-20020a0568717b0300b0021844c20c8dls1816153oac.0.-pod-prod-08-us; Tue, 30
 Jan 2024 05:23:35 -0800 (PST)
X-Received: by 2002:a05:6358:6a47:b0:176:cf6d:20a6 with SMTP id c7-20020a0563586a4700b00176cf6d20a6mr5269859rwh.19.1706621014990;
        Tue, 30 Jan 2024 05:23:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706621014; cv=none;
        d=google.com; s=arc-20160816;
        b=waQuFdh4Ec1wfw88Bxoc0aRBGXiW0Uit0OXlAwOncFrXdZUad5I498poct1ccK9I1s
         oBZlBfTaX1cfQe4S93gOGt7ap5reB8oCFvAu9EzxolRApBnYzbZTBU5vpYEMSn3sMPaY
         OvBQ6Lgd1snCSJmzfHlQKHod8w5zKkoCQErnjwDKUdrNlgSUjdHAVGCAKr7NJQs9L8+A
         vYSdJGIYHq+sTNGKUOAZAfzYeK3B3ecvdBcPCgncqK97XanuPWCMdt7xWHLQtz9CPTsl
         hlPspserB8jFrRo41ZVLWMidzLPOtp3Y48OfFwcjesP27eueB9dQEIWuyL5YTHPVF7rO
         M5SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=aTwYhJSbGAYcPyErFmbNrPBq4uVa0blYqv4qIpWzJb4=;
        fh=7MNXGxtYTwfI8ffyG5AOOQraFXIKbO9yC4nGnB6I72I=;
        b=slbWxwSauAE4DG5L45Z+N2cuzrPgWP0uECMrzrdj4VUPNIZ9z5rz1QrgOXIdikrdyc
         GMz9QKXicHg3eBjmpsY5tZzFDEDJQHgavEy35bt6HHg7p8IUPLYw35o7cwxr/snqPYVr
         czPgo8y4JxPvlud/CXk9YUvNKlJVKsPgi/KyHneZFiHi0Z1sMHCbIPZSCzWqmoUqbA/r
         SjH/sCvZ+1uV5hpPsy3kHDZ+ieRz7r4nCWG+/DWGeOnA+o9VLXggkW+oWFzo616M6iR9
         hlTLAkeQpilFWKav5JQ4A0HL8ojhMrbhRVkgEsar86vAiklbwMyOVZR6azwhd+YCSQNB
         RriA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCUD0vUJX/68II6BQMPAH2XfSOwlK94VFUEJ9LQdZLRvwTRURmxeqzEP59COQBLY4ORMgZ10omcLjE+TQp1JMyluahnjgw0uDuKWyw==
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id d3-20020a633603000000b005cfbe30ed15si860889pga.0.2024.01.30.05.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 05:23:34 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4TPQm8519Qz29knY;
	Tue, 30 Jan 2024 21:21:12 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 574B81A016B;
	Tue, 30 Jan 2024 21:23:02 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 21:23:00 +0800
Message-ID: <f10848f1-36d5-c954-2b55-d9cdaf5262bf@huawei.com>
Date: Tue, 30 Jan 2024 21:22:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v10 2/6] arm64: add support for machine check error safe
To: Mark Rutland <mark.rutland@arm.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	James Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
 Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Aneesh Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>, <linuxppc-dev@lists.ozlabs.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-3-tongtiangen@huawei.com>
 <ZbflpQV7aVry0qPz@FVFF77S0Q05N>
 <eb78caf9-ac03-1030-4e32-b614e73c0f62@huawei.com>
 <Zbj0heg7eFukm_5Z@FVFF77S0Q05N>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Zbj0heg7eFukm_5Z@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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



=E5=9C=A8 2024/1/30 21:07, Mark Rutland =E5=86=99=E9=81=93:
> On Tue, Jan 30, 2024 at 06:57:24PM +0800, Tong Tiangen wrote:
>> =E5=9C=A8 2024/1/30 1:51, Mark Rutland =E5=86=99=E9=81=93:
>>> On Mon, Jan 29, 2024 at 09:46:48PM +0800, Tong Tiangen wrote:
>=20
>>>> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
>>>> index 55f6455a8284..312932dc100b 100644
>>>> --- a/arch/arm64/mm/fault.c
>>>> +++ b/arch/arm64/mm/fault.c
>>>> @@ -730,6 +730,31 @@ static int do_bad(unsigned long far, unsigned lon=
g esr, struct pt_regs *regs)
>>>>    	return 1; /* "fault" */
>>>>    }
>>>> +static bool arm64_do_kernel_sea(unsigned long addr, unsigned int esr,
>>>> +				     struct pt_regs *regs, int sig, int code)
>>>> +{
>>>> +	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
>>>> +		return false;
>>>> +
>>>> +	if (user_mode(regs))
>>>> +		return false;
>>>
>>> This function is called "arm64_do_kernel_sea"; surely the caller should=
 *never*
>>> call this for a SEA taken from user mode?
>>
>> In do_sea(), the processing logic is as follows:
>>    do_sea()
>>    {
>>      [...]
>>      if (user_mode(regs) && apei_claim_sea(regs) =3D=3D 0) {
>>         return 0;
>>      }
>>      [...]
>>      //[1]
>>      if (!arm64_do_kernel_sea()) {
>>         arm64_notify_die();
>>      }
>>    }
>>
>> [1] user_mode() is still possible to go here,If user_mode() goes here,
>>   it indicates that the impact caused by the memory error cannot be
>>   processed correctly by apei_claim_sea().
>>
>>
>> In this case, only arm64_notify_die() can be used, This also maintains
>> the original logic of user_mode()'s processing.
>=20
> My point is that either:
>=20
> (a) The name means that this should *only* be called for SEAs from a kern=
el
>      context, and the caller should be responsible for ensuring that.
>=20
> (b) The name is misleading, and the 'kernel' part should be removed from =
the
>      name.
>=20
> I prefer (a), and if you head down that route it's clear that you can get=
 rid
> of a bunch of redundant logic and remove the need for do_kernel_sea(), an=
yway,
> e.g.
>=20
> | static int do_sea(unsigned long far, unsigned long esr, struct pt_regs =
*regs)
> | {
> |         const struct fault_info *inf =3D esr_to_fault_info(esr);
> |         bool claimed =3D apei_claim_sea(regs) =3D=3D 0;
> |         unsigned long siaddr;
> |
> |         if (claimed) {
> |                 if (user_mode(regs)) {
> |                         /*
> |                          * APEI claimed this as a firmware-first notifi=
cation.
> |                          * Some processing deferred to task_work before=
 ret_to_user().
> |                          */
> |                         return 0;
> |                 } else {
> |                         /*
> |                          * TODO: explain why this is correct.
> |                          */
> |                         if ((current->flags & PF_KTHREAD) &&
> |                             fixup_exception_mc(regs))
> |                                 return 0;
> |                 }
> |         }

This code seems to be a bit more concise and avoids misleading function=20
names, which I'll use in the next version:=EF=BC=89

> |
> |         if (esr & ESR_ELx_FnV) {
> |                 siaddr =3D 0;
> |         } else {
> |                 /*
> |                  * The architecture specifies that the tag bits of FAR_=
EL1 are
> |                  * UNKNOWN for synchronous external aborts. Mask them o=
ut now
> |                  * so that userspace doesn't see them.
> |                  */
> |                 siaddr  =3D untagged_addr(far);
> |         }
> |         arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, =
esr);
> |
> |         return 0;
> | }
>=20
>>>> +
>>>> +	if (apei_claim_sea(regs) < 0)
>>>> +		return false;
>>>> +
>>>> +	if (!fixup_exception_mc(regs))
>>>> +		return false;
>>>> +
>>>> +	if (current->flags & PF_KTHREAD)
>>>> +		return true;
>>>
>>> I think this needs a comment; why do we allow kthreads to go on, yet ki=
ll user
>>> threads? What about helper threads (e.g. for io_uring)?
>>
>> If a memroy error occurs in the kernel thread, the problem is more
>> serious than that of the user thread. As a result, related kernel
>> functions, such as khugepaged, cannot run properly. kernel panic should
>> be a better choice at this time.
>>
>> Therefore, the processing scope of this framework is limited to the user
>> thread.
>=20
> That's reasonable, but needs to be explained in a comment.
>=20
> Also, as above, I think you haven't conisderd helper threads (e.g. io_uri=
ng),
> which don't have PF_KTHREAD set but do have PF_USER_WORKER set. I suspect=
 those
> need the same treatment as kthreads.

Okay, I'm going to investigate PF_USER_WORKER.

>=20
>>>> +	set_thread_esr(0, esr);
>>>
>>> Why do we set the ESR to 0?
>>
>> The purpose is to reuse the logic of arm64_notify_die() and set the
>> following parameters before sending signals to users:
>>    current->thread.fault_address =3D 0;
>>    current->thread.fault_code =3D err;
>=20
> Ok, but there's no need to open-code that.
>=20
> As per my above example, please continue to use the existing call to
> arm64_notify_die() rather than open-coding bits of it.

OK.

Many thanks.
Tong.
>=20
> Mark.
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f10848f1-36d5-c954-2b55-d9cdaf5262bf%40huawei.com.
