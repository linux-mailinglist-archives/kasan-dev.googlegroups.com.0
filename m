Return-Path: <kasan-dev+bncBAABBDXZ4OWQMGQEFVP6OVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8528184264C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 14:41:36 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-6e119f68b24sf2362053a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 05:41:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706622095; cv=pass;
        d=google.com; s=arc-20160816;
        b=m49xaNAqtM408YXW29wT9XfiNgeLCyedslutTtjfQVl7LvhkyQ54GZ9V7DjvtmENzA
         vrzhphETztnJe8n4pZ1kvOIM/Xol+BjHMp20rh1L5Mc8sFCfpwBJfG55HOboSYOAMx/a
         D1BEaI+8sOxur+wOgrTMvcTO5YEYaVrJjxVm7WVlvU3jpeC7C78XmdpQq7HKINoR+cKE
         B480tE80xfzicHHSLuKY1KOnbsZvSs4qx5PMXoYUILC5xdn7OGGjl7ZiVVu95DvWD+PW
         JI5HngKtBgr2LKVk5ncMLs0C9fYiSYjWFNVWZaNZikotkyvbivFdNkzgrBk+KZEaK4Hl
         PXBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Qk+9bcRenKPO6LQK7UWaV7dvmiL6rPPMgLaFNk/aw44=;
        fh=W6nDGqgZMHf9Qb0quhSO5kLmCGCNKja483HmLv8Br1o=;
        b=X8oDxAn8JtV1rEEYTcojc1es65pE6PZ5tMzCHO+a2+sLVTmZJMK77WtHmlBMy0/Aez
         f/4306JDp9bHlWHr6EQzzMKcACq8XPkjXvpATouSfcYAsSROzYnhNfEN6LjlAfcC/1fI
         P7jeoly9gAy9DvJ51lE0CZHzmoqwMsbn89t0AvOzctFW582PBTNiZ+pcrpLijHYfvsdE
         KMPmVUvQXMOLHkItyoehOIIt9LwtTlm3vfBGJvI4Uc8orVQ4dqJ4IZX+Uap1zgvP3xYs
         lsIglD2Qy3nfsQ105PpaMRrZfW3Yld9B5t3rSraPilSpRkWhpXE1p2MpyWcBr3Cw3vjL
         swtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706622095; x=1707226895; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qk+9bcRenKPO6LQK7UWaV7dvmiL6rPPMgLaFNk/aw44=;
        b=I1JaxT+zfOXMhGWxAiWe5jcPlwp//1i1Ti2FBH+LD3I/xAigIzql22McH2fvjFWXV2
         z7O9XsAu5OuPLARVLvkRiJ8F27PaYC2I50X4T3E6/rZ+3LKIIqEs4/c9e06n3OzkR8EW
         6mZqi0H4N7oMInrQQyI1aah+omnx98rhOV4GVRiWoDQ3BN7cnoOfTpSZqfLm73A0iP1o
         9l9b9UiWveWmSY+BukdlLBIzDliOs93NblfnOi9HYzYc6dC02PsXbNAC04TLISfMKxPg
         dRtzC332FBhS2T0ZKFKyvK1uTxXyqS2oEgijQ6HFV6tabOgVxhCcnNSqrtzg/GkG/AIs
         /YKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706622095; x=1707226895;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Qk+9bcRenKPO6LQK7UWaV7dvmiL6rPPMgLaFNk/aw44=;
        b=cybTyGz9PgrTdQouOF9r0Asobzz8lbRnqdfBa2gzW6UDS9X0NfKZbJp/MA/MfNr+s2
         SSTip6NKrOfiBU9TaCRWpHw4QP8RnaAg0bRIcapFTntQ+tlcC7p5Ap54265cw3pvQvqP
         4Q+q+KDJ+HY/SLwp7AdEJ22c49aZIvv0uWk0EeWwbcaR14Py1ehd7kLKp0ae0t3sBQpK
         yHf7BfO1k1X0e6r0H/lUyekzgxj7Eh+qxDeffj99qu/rVjd15vR2Bg7YGhNfQmgQpEmi
         oVPJQqrHawdAKRO8am9VAVI+qIYgtbrEKe0GmvENg02oKXciC8hRXdj7zFhok9KwYRNS
         MKLg==
X-Gm-Message-State: AOJu0YzWOW9qZp7jCKGyDA+5lhMgUNz1mivP2mhCIkFIkUZVefKcSfOj
	NWoJvVBTeaC+yaZZAW3L4LtsBPXbZRbWJhIdnPFnzHtvRl/f5uCR
X-Google-Smtp-Source: AGHT+IGV8abuudt34qwF5/K+JNEbmzZisOdnFRPdlK5qlEV+iPmM+jocaGQYdHsufDGZDdQYlOtXKg==
X-Received: by 2002:a9d:6c56:0:b0:6db:ffa6:6c4d with SMTP id g22-20020a9d6c56000000b006dbffa66c4dmr6464131otq.24.1706622094858;
        Tue, 30 Jan 2024 05:41:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:aa0d:0:b0:598:dc0d:33b6 with SMTP id x13-20020a4aaa0d000000b00598dc0d33b6ls1149272oom.2.-pod-prod-03-us;
 Tue, 30 Jan 2024 05:41:34 -0800 (PST)
X-Received: by 2002:a05:6870:82a2:b0:217:e97d:88c1 with SMTP id q34-20020a05687082a200b00217e97d88c1mr5070814oae.55.1706622094214;
        Tue, 30 Jan 2024 05:41:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706622094; cv=none;
        d=google.com; s=arc-20160816;
        b=0iOz55+8eZ+pQJN7ZIx/uEfE7/cFYW/7HsBOyJWwssWb2XflZ0feuCesYfqrgX2YA7
         CWthS3a/28taunIwS88lGI+CBUJXjv2x8ZqaaRGLaH3AMvq6bERV9aeNCQqmLDuhtna+
         s9Oj8uvuwP+T4Vsbws1Jg6/xB196zXtjeTpwAd4IwvdqJMaY4e83NwO515pWo+wYBF9d
         fBnSEHHrcQXsJclyQ8zkSfESRJbXvVxs1LqYomAmkz3pvaH86hIDxo80tUVj+YEa5bYR
         SewavnVJtEVnVNZv0FRrA7kOh4TJtt2AhydtT66N/6BeJb+ndFD1EYy4GVXM+xIn7TLo
         GbGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id;
        bh=5s+/rA66jkcBc5RVqpNWURjYoBpzfZPwaFzayiRRQRI=;
        fh=W6nDGqgZMHf9Qb0quhSO5kLmCGCNKja483HmLv8Br1o=;
        b=uuoS3tEJNoGCaubvA9ZeNN7dR9jVSzWkfm4hNpWZ8pW8nMsd0onkT3AzYr7paP2iA6
         nXsnFYUFJ9ywG6IUOpio9fNoDs0EZAOo2G9hJFFZkO+48vImdCqF3PeUzQiDwLi0hynE
         h08XYApc9G30y6GIx1gufuV2lO8nHc7TJGCjxSSPWFd0/U0OazFiUsRaZba2k6sRoyg2
         W3QrStsnYWNhlqWCJQfLN4FLyJaJMH9umjg/eUeB0G7ba8KulhjN8EYTlaZMb67nnKMv
         FakKPYoQhRM4ADCWTDSX2g3EU9bslJuO++DBNtPzQ8bOOciMNtY/i9pLSoDq5uI8eqSS
         H+KQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCXygKwm9meFuKhzTfJAZWwiY9W6Uv0LHqNwbOP1W9PgbuNxXvZKvb2CIVmr4X0ePNbIFkSo5o+ro4V+BEk1DVuwpPy2YxgvnryN9Q==
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id nx19-20020a056870be9300b00214d44ae5a1si1392423oab.5.2024.01.30.05.41.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jan 2024 05:41:34 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4TPRBS0vRFzJpQM;
	Tue, 30 Jan 2024 21:40:32 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 8B07B1400FF;
	Tue, 30 Jan 2024 21:41:31 +0800 (CST)
Received: from [10.174.179.234] (10.174.179.234) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Tue, 30 Jan 2024 21:41:29 +0800
Message-ID: <d8cb8cec-5530-c0e7-3bd3-bcd47e9bf4e1@huawei.com>
Date: Tue, 30 Jan 2024 21:41:28 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.8.0
Subject: Re: [PATCH v10 3/6] arm64: add uaccess to machine check safe
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
 <20240129134652.4004931-4-tongtiangen@huawei.com>
 <ZbfjvD1_yKK6IVVY@FVFF77S0Q05N>
 <23795738-b86e-7709-bc2b-5abba2e77b68@huawei.com>
 <ZbjlFXVC_ZPYbKhR@FVFF77S0Q05N>
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZbjlFXVC_ZPYbKhR@FVFF77S0Q05N>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.179.234]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as
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



=E5=9C=A8 2024/1/30 20:01, Mark Rutland =E5=86=99=E9=81=93:
> On Tue, Jan 30, 2024 at 07:14:35PM +0800, Tong Tiangen wrote:
>> =E5=9C=A8 2024/1/30 1:43, Mark Rutland =E5=86=99=E9=81=93:
>>> On Mon, Jan 29, 2024 at 09:46:49PM +0800, Tong Tiangen wrote:
>>> Further, this change will also silently fixup unexpected kernel faults =
if we
>>> pass bad kernel pointers to copy_{to,from}_user, which will hide real b=
ugs.
>>
>> I think this is better than the panic kernel, because the real bugs
>> belongs to the user process. Even if the wrong pointer is
>> transferred, the page corresponding to the wrong pointer has a memroy
>> error.
>=20
> I think you have misunderstood my point; I'm talking about the case of a =
bad
> kernel pointer *without* a memory error.
>=20
> For example, consider some buggy code such as:
>=20
> 	void __user *uptr =3D some_valid_user_pointer;
> 	void *kptr =3D NULL; // or any other bad pointer
>=20
> 	ret =3D copy_to_user(uptr, kptr, size);
> 	if (ret)
> 		return -EFAULT;
>=20
> Before this patch, when copy_to_user() attempted to load from NULL it wou=
ld
> fault, there would be no fixup handler for the LDR, and the kernel would =
die(),
> reporting the bad kernel access.
>=20
> After this patch (which adds fixup handlers to all the LDR*s in
> copy_to_user()), the fault (which is *not* a memory error) would be handl=
ed by
> the fixup handler, and copy_to_user() would return an error without *any*
> indication of the horrible kernel bug.
>=20
> This will hide kernel bugs, which will make those harder to identify and =
fix,
> and will also potentially make it easier to exploit the kernel: if the us=
er
> somehow gains control of the kernel pointer, they can rely on the fixup h=
andler
> returning an error, and can scan through memory rather than dying as soon=
 as
> they pas a bad pointer.

I should understand what you mean. I'll think about this and reply.

Many thanks.
Tong.

>=20
>> In addition, the panic information contains necessary information
>> for users to check.
>=20
> There is no panic() in the case I am describing.
>=20
>>> So NAK to this change as-is; likewise for the addition of USER() to oth=
er ldr*
>>> macros in copy_from_user.S and the addition of USER() str* macros in
>>> copy_to_user.S.
>>>
>>> If we want to handle memory errors on some kaccesses, we need a new EX_=
TYPE_*
>>> separate from the usual EX_TYPE_KACESS_ERR_ZERO that means "handle memo=
ry
>>> errors, but treat other faults as fatal". That should come with a ratio=
nale and
>>> explanation of why it's actually useful.
>>
>> This makes sense. Add kaccess types that can be processed properly.
>>
>>>
>>> [...]
>>>
>>>> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
>>>> index 478e639f8680..28ec35e3d210 100644
>>>> --- a/arch/arm64/mm/extable.c
>>>> +++ b/arch/arm64/mm/extable.c
>>>> @@ -85,10 +85,10 @@ bool fixup_exception_mc(struct pt_regs *regs)
>>>>    	if (!ex)
>>>>    		return false;
>>>> -	/*
>>>> -	 * This is not complete, More Machine check safe extable type can
>>>> -	 * be processed here.
>>>> -	 */
>>>> +	switch (ex->type) {
>>>> +	case EX_TYPE_UACCESS_ERR_ZERO:
>>>> +		return ex_handler_uaccess_err_zero(ex, regs);
>>>> +	}
>>>
>>> Please fold this part into the prior patch, and start ogf with *only* h=
andling
>>> errors on accesses already marked with EX_TYPE_UACCESS_ERR_ZERO. I thin=
k that
>>> change would be relatively uncontroversial, and it would be much easier=
 to
>>> build atop that.
>>
>> OK, the two patches will be merged in the next release.
>=20
> Thanks.
>=20
> Mark.
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d8cb8cec-5530-c0e7-3bd3-bcd47e9bf4e1%40huawei.com.
