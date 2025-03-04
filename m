Return-Path: <kasan-dev+bncBAABB4MTTS7AMGQE7XH557Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 72B5AA4E04C
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 15:10:58 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2c15042a9c2sf8167140fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 06:10:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741097457; cv=pass;
        d=google.com; s=arc-20240605;
        b=fZVkGsQd6GP8R7khGdCy72SqD13+CUTrDfs2kZ7ACx/9uTs/GnKZteBWlg+n0hJGIP
         JCa+T/Q8rwKA3021ecMUsxj0LMUYeLXJYbqKSTYmQgKmD04m5DMXOWNiEIqJLbujFCaj
         N2Eiz0tht8xFksIwOweygRw2UamhYP5SACPcnh/hzK2TqnmHn4DPjumQZTeG35O1MjMQ
         Ywy8KSQQ8AFEkrcD1/r1U/XWKW/JySZtV4nPGjMofqHO8AWrFOtXs2KpQRgsy/jtJ7o5
         K7WfXP15T5+4v12X4BJT6QRthIJvDvAw1TUnSbNkX0ZNMrFvoscZKrpO2+BXf5i/cEFE
         OyDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=9RNT60lOEVn23sm7eLCCz0ubKQVQG6l14nBb8sMgcTw=;
        fh=L9Ojcv4fFNZ0jJ1Ie2DwuXIkluPkdhnKqg0tk7IHJ9Q=;
        b=Y3sOQWrxxDIMVP5D9weOPhRq8drIS1Tkkr/jOjhBjT2cBqdJPYC/npCsrtStX3eteG
         t6Az5Kh/JKYe81HU4iFCshx6dY6/HM8Uh3DahHnbKBuyIK8G/VFkIG+G5Fz8aG47x3WX
         RQBN+togo/lQc8aZsgurhlIRve55RneyVOVHJvG5OmpiZC3bcRPcL/THTbbsQZCZmP/I
         utiHiboKrztcWlrshAlFShAKtkwm+CEgDITebGnZnnkm/Cl2yBWRiiSFmnjjcZB3fvMP
         rqwcApCbqjK+J/Yoo8+gc81eXneQ3JuVIg/2B3416quSBfki9wGvVVOZT6nB13dmNaly
         QkLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741097457; x=1741702257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9RNT60lOEVn23sm7eLCCz0ubKQVQG6l14nBb8sMgcTw=;
        b=vRbhRNq6kgEn/qxxTtqoaNOlrVfoTOP7KngeR2qhwZejUtqeKI7bzGXuJxo47aoOvh
         EtwsUkgDMfeIlDk4ngkmBt0fc1K2Vngf51555+sN1yP23byQHTTazXYqGjAWs+JlNHoT
         8ppSDFGG/2JKKdamQV6R1qbVxLEYYQ1CqciqGkIJUl5JaO2NX+ZRi9++XCi61HDl/zDR
         bHWzxUcIFbBWUGulURxqrf378R0AD2XcK8aC3EmsoQS3xCX6rwG6qHq7wqC0JCZafe9K
         9SyEtn9QkrqEUVf0CB56S92BuZt/DCgMJzG5ICHcoG50gsnuzehOOeAF9skLJ5GGU4vS
         64TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741097457; x=1741702257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9RNT60lOEVn23sm7eLCCz0ubKQVQG6l14nBb8sMgcTw=;
        b=ShaRy2cIF3W9iRu70tn7o2GTNcCo8XkjM9jRSmUICTQvAg0+8bJ48fksFFM79ZKK20
         3/qjEhhfwiY6sODXQ9u+4FILiqXk3tH/3Bj3b5hf6pilnOYv6RdqznBPnSRhSPqGRvmO
         01r5JlOcpiVPURloaKzcIljATLaiczTmswKaExYT6eVFF2889kjfc2GHCqjXvZaNNkoY
         e29jwdDT9tk57ZaXDvgi6D+Bn3VhIiOgDWSXig7VXLfEoOPhAcfj0LxcNOItmorBXLU7
         uSEh95KKCzt7bopfBBcKlFUAwt2F9nBciPnMG6K/FiU/IgJa7LlQZnrV9cWnLX6fKL2G
         fxjw==
X-Forwarded-Encrypted: i=2; AJvYcCXBi1T6Rrmg1DWHZwsu2wB76hhRxxCeRuYCLIL+BURrcRe2FGxAWv1MnmwfiY9ShWbH2RBG7A==@lfdr.de
X-Gm-Message-State: AOJu0YxvPzeanrddSqxHLv/RbUU6kSw+WHRTqP8Le/vv50Db/tA4nfM/
	aLPrKTGf6O8E+G2ByMgRS6JjDRkJj3kDT72r1MPfXSaH+nLR4IQ4
X-Google-Smtp-Source: AGHT+IGCIHjAkcv7uphFQt3zBJ97XTzrmlWhWZ32u/frnuHGXjlwT1p6udb7ObscvN28+amBhPqsIA==
X-Received: by 2002:a05:6871:a68e:b0:2bc:70af:1d62 with SMTP id 586e51a60fabf-2c178786c20mr11246152fac.26.1741097457143;
        Tue, 04 Mar 2025 06:10:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFwlQPREzuOclz2+NBImBANeiXngOrrll5AJMPVk50f5A==
Received: by 2002:a05:6870:ab0a:b0:2c1:3777:bee8 with SMTP id
 586e51a60fabf-2c15410ace4ls214932fac.0.-pod-prod-03-us; Tue, 04 Mar 2025
 06:10:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2/yQkiDEU3OcYyxdmWW2PY5vYAInUJFqM8+c7NfNoNy78H41lRvPPKLmaMAVMkOoiamMJAdYwKt8=@googlegroups.com
X-Received: by 2002:a05:6830:2b11:b0:727:2f0c:916f with SMTP id 46e09a7af769-728b8286b08mr12289111a34.12.1741097455929;
        Tue, 04 Mar 2025 06:10:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741097455; cv=none;
        d=google.com; s=arc-20240605;
        b=el4UiiIKozS+j7qoGcZK2+uFxNAZLNCh0cRFG1s2w3nFfxTkN0TZhf02Xwsb6K67zZ
         SS+A8PvzwEHsUU/IlHv52TROryRy5PhkUMVtNPdgfuL3akwWkejLIukCyi2nCyxnyTV9
         YihsPK5GbcW5kjpg3e5u1IDJ66+xECVBVxb0kjojAaZnPqANGqGTdzjXYCcuxzOHGn2i
         JJnISqpXEyJqZbj9B0HefWLRlqEIfvA9DJGiI6KqBoSK70JWz29mJI35Mj09VH+fJnge
         2Xex/bBtdVuDzV2KP/K2QQDtXjs1e/SxpLba9NCEEra2fBEGB0Fc5sqsM+BJCTTV20xp
         Z4og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=Cz7IA69OFA9tHcBAPSVOCjGmnTTL7mvde1OZORF4svs=;
        fh=RzQbsIRJIGcsOahvYzttPrzbIb6n8kVsMKDOWJddbjk=;
        b=Mgoo/rDFk3rz06wyQphyQ1JW0nzIlZQfkSVgt3xnBhphJqVQgANrloe+Q9lRNof3Qa
         FkIPxPQE5YKaie+6g8zsG2BO8KTHGV76WF9do0vieCHjE7K/t+SbJrmKEnU1zJsS/Lbu
         d3ab7ibrPFyHfrr3eiQjv1JIReK61UvPF9ncPdJ16i3CGYx4G4n/KQJsplOC6itJzlAq
         ys1E5hw+iZFll2HanNXoEnEtvO2wynCq1Z5NXP+fpEG0i8kytPMj5V5LibdIiYNEsEX2
         zIZfzXrSQvEJAYn8+lAR3mOnYeJBM1EIU29jzoS8k6d7W51wv1EetAApw2qCf0h1bj8Z
         LQFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-728afcffbb3si564734a34.2.2025.03.04.06.10.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Mar 2025 06:10:55 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.163.17])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4Z6ctR2c3Gz1ltZw;
	Tue,  4 Mar 2025 22:06:39 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id B226C1A0188;
	Tue,  4 Mar 2025 22:10:50 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Tue, 4 Mar 2025 22:10:48 +0800
Message-ID: <2c1fa758-c292-aefb-f6e2-cab41f592568@huawei.com>
Date: Tue, 4 Mar 2025 22:10:47 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Will Deacon <will@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, James Morse <james.morse@arm.com>, Robin Murphy
	<robin.murphy@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Aneesh
 Kumar K.V <aneesh.kumar@kernel.org>, "Naveen N. Rao"
	<naveen.n.rao@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, <x86@kernel.org>, "H. Peter Anvin"
	<hpa@zytor.com>, Madhavan Srinivasan <maddy@linux.ibm.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <wangkefeng.wang@huawei.com>, Guohanjun
	<guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com> <Z6zWSXzKctkpyH7-@arm.com>
 <69955002-c3b1-459d-9b42-8d07475c3fd3@huawei.com> <Z698SFVqHjpGeGC0@arm.com>
 <e1d2affb-5c6b-00b5-8209-34bbca36f96b@huawei.com> <Z7NN5Pa-c5PtIbcF@arm.com>
 <3b181285-2ff3-b77a-867b-725f38ea86d3@huawei.com> <Z7TisqB5qCIF5nYI@arm.com>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Z7TisqB5qCIF5nYI@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as
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

Hi,Catalin:

Kindly ping ...

Thanks.:)

=E5=9C=A8 2025/2/19 3:42, Catalin Marinas =E5=86=99=E9=81=93:
> On Tue, Feb 18, 2025 at 07:51:10PM +0800, Tong Tiangen wrote:
>>>>>> =E5=9C=A8 2025/2/13 1:11, Catalin Marinas =E5=86=99=E9=81=93:
>>>>>>> On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
>>>>>>>> Currently, many scenarios that can tolerate memory errors when cop=
ying page
>>>>>>>> have been supported in the kernel[1~5], all of which are implement=
ed by
>>>>>>>> copy_mc_[user]_highpage(). arm64 should also support this mechanis=
m.
>>>>>>>>
>>>>>>>> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
>>>>>>>> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE a=
nd
>>>>>>>> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>>>>>>>>
>>>>>>>> Add new helper copy_mc_page() which provide a page copy implementa=
tion with
>>>>>>>> hardware memory error safe. The code logic of copy_mc_page() is th=
e same as
>>>>>>>> copy_page(), the main difference is that the ldp insn of copy_mc_p=
age()
>>>>>>>> contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefor=
e, the
>>>>>>>> main logic is extracted to copy_page_template.S. In addition, the =
fixup of
>>>>>>>> MOPS insn is not considered at present.
>>>>>>>
>>>>>>> Could we not add the exception table entry permanently but ignore t=
he
>>>>>>> exception table entry if it's not on the do_sea() path? That would =
save
>>>>>>> some code duplication.
> [...]
>> So we need another way to distinguish the different processing of the
>> same exception type on SEA and non-SEA path.
>=20
> Distinguishing whether the fault is SEA or non-SEA is already done by
> the exception handling you are adding. What we don't have though is
> information about whether the caller invoked copy_highpage() or
> copy_mc_highpage(). That's where the code duplication comes in handy.
>=20
> It's a shame we need to duplicate identical functions just to have
> different addresses to look up in the exception table. We are also short
> of caller saved registers to track this information (e.g. an extra
> argument to those functions that the exception handler interprets).
>=20
> I need to think a bit more, we could in theory get the arm64 memcpy_mc()
> to return an error code depending on what type of fault it got (e.g.
> -EHWPOISON for SEA, -EFAULT for non-SEA). copy_mc_highpage() would
> interpret this one and panic if -EFAULT. But we lose some fault details
> we normally get on a faulty access like some of the registers.
>=20
> Well, maybe the simples is still to keep the function duplication. I'll
> have another look at the series tomorrow.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
c1fa758-c292-aefb-f6e2-cab41f592568%40huawei.com.
