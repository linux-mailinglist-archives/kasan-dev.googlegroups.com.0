Return-Path: <kasan-dev+bncBDXZ5J7IUEIBBBG7TPDQMGQEG5XAL4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69714BC6D67
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 01:11:11 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4e0fcbf8eb0sf11537071cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 16:11:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759965061; cv=pass;
        d=google.com; s=arc-20240605;
        b=gmpRAGdikjRxd5zoQ/dUccJekeeXcBDz9T6ryHy0w5TnDPN0s6QPxE7OrZ3vtS4ktJ
         zhwGZ0v36ZWEoTg8YVvHNhKDNVbXEqaODB25FuZ6BFpR6BVUl4/+VWPhaMLx6EfmSmGr
         uc/7eMmNR8bN04+cgk8cim+vTm61HJ35EmFQG978Zl+WX+t7F9EI3FCu5CzGwrIcJn8A
         ffvoUMfJw4/qmNDv2LsfzYChWe4Ju3ieZwV760GfsJ6APstwZ+aMuaIdcVdQDiSVFl4u
         kB4lH82upEF/E7yVvbbmrfdHLMci5lgxerg6o+3wpZcaEgIcOipKe0z3P5eeprSQf7h1
         RQcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:content-language:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=HY6N5etquYmgymEM4zP6sCJaXmtk6fkPRKm8unmafpo=;
        fh=+4s9kKjui0j9jEJUd56KSw22Sy7emy+13NrrngLLNQs=;
        b=DUz/uZzBjAt7rHSTgcVYxXyQh0gesDohscD9Uf15NvAoDC71TSwz71isMn2oUEMgLW
         KaWLkpSCwaA6ppiF0PhjCkzo9nNcGS3JyUBwy9OAxTy/a37GFkhzUtsYbjXNNfIaFX4M
         enGzS4VqqzMn53vfbRZF+MF/r8QfOlqBKUVS/GMpfkqaDFEkPZ5/wxYaMTsIat5O9nIT
         YfLkx1AM9LXjXTv20s3lEhTU21zVa2RRdPhhUD8ACxZjQVDU5k5sFoh42sEdRV1KKR9W
         0ZHSsdgdHBcKpKVbOHiiFiWZVpVBYoRdyWlkhmI8POf4yTzvsaLcwkqNm/nRJigxT3D2
         EMow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.41 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759965061; x=1760569861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:content-language:references:cc:to:from:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HY6N5etquYmgymEM4zP6sCJaXmtk6fkPRKm8unmafpo=;
        b=xh2+qgoEBx4OE5CyRVOsYw6oxqSVYc/7kMzMUj1Xor/iuzUMNWca94UW6hbYLalE/9
         xoeMtFxl81ovHxoMW7kw6b7zQN/iGMXK9poQxN01wQPUKOFYXOjs5Q5m5iRRdQWYRYQX
         DfTY2glmjEuaHXBG3T80ERtnobSpZ3U4/Z6HWYelb8R2JNtYhgL/K8Xyvfhjz/xZDXHN
         54a9cwgBn1Drnv1OVvP4ZZJqa4gxh9+FlkvGr288uyF4INmmhOPp07qMHfcmCQ9KBVkp
         Jk1UDewRDbKOjvIAnoIAkHrfrBeBoyKXC8GEJXRNkOT2KdlLf4e7gIgOwkQVn+5XKPCE
         nW4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759965061; x=1760569861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HY6N5etquYmgymEM4zP6sCJaXmtk6fkPRKm8unmafpo=;
        b=DjbDRTYjD5JLkN049XGQ1YkyIS7xmKoFQ0d+Z+ghyPmgCTtXxj4SVLThFA0WjUkDln
         8a9jaG48RpHMAZXaply68in0JcudoJEB8xFqMycYJPmX2lRBwBHRZ3Tvr7B9jJouSoHA
         56VN2Dmxg+0OzHH8FRhg/np/tS9jaqv/mTpQy0B63sw5edjlzHvGXNTkNMqF0y81RGkt
         wseeG31u/BCPJ+NRTiy8kXquj/kUDZnGSpwgRWVfBob7qXpmsORzz2FrzzUFxCsbTDuH
         JcA1NDeoIAy2W8lQ6T/AcmfuvDkF1JWnqXO6HIWILvnLy5ICuZCIKvRy4hRJu36Q4M4g
         Nr4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrphDEO0VjAGf1E0mi56ZYIQLA8M5mcKc5yIUiiwH7OHHhXLvu6Alj5BLTOmv1oSsWGsWOpQ==@lfdr.de
X-Gm-Message-State: AOJu0YylyD+lm4fL9VyCQBd7Xvw3aBIJ4THjeTWXwjBqva8hnd8n5YRh
	XTxgrruR/RA8myGYdf9iJNGl2ZEXOu7P+kev5AMGofbPhPjE+ozn5WqS
X-Google-Smtp-Source: AGHT+IFZS/Qvqp1YlD5Mm4M0ZFTF8UfEt4PywMvPy2s3IFDHIiTdWqFHtSFCxCv7qST0JhmRf+6emA==
X-Received: by 2002:a05:622a:1a9c:b0:4b3:4a3a:48b8 with SMTP id d75a77b69052e-4e6ead75612mr86553901cf.73.1759965061151;
        Wed, 08 Oct 2025 16:11:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5wG0NEtSO7+DytoXyPlb966O7P3j8DOdWmQnu60ZoHnA=="
Received: by 2002:a05:622a:8c16:b0:4d6:c3a2:e1bc with SMTP id
 d75a77b69052e-4e6f8b84d87ls9017741cf.1.-pod-prod-09-us; Wed, 08 Oct 2025
 16:11:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVKan9M2rmTfLI18H8ciduLpc/Csm7q6JfKDHH2+B97/osXlmEzHrSoc4V/T+HR1yL4HoXz5o3sR4=@googlegroups.com
X-Received: by 2002:a05:620a:28ce:b0:864:1d18:498b with SMTP id af79cd13be357-883538452bamr949887685a.23.1759965060211;
        Wed, 08 Oct 2025 16:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759965060; cv=none;
        d=google.com; s=arc-20240605;
        b=CrK1/IbcZ19WQ+cUXPGR3vMlrtfJ6a/TaCyL2lcAysBSZIj21IEJqYST6iaYK6BpgI
         5qPIRP0sCkY/9TYS9FOpLcjW1picqokhnHsUrscZOHukQ19EByFlcDm1mZopGbgyXjGX
         8Anal1cjQ/mfTdqpJhsYp+XEp5hFlAT/bn7IjPTsqXmzX8GRPHfTrfNTSNAS7B7IyA2R
         yZG+yAxr4AdkENNvKX3pVCOBCHWtUd72sO4/IcJTmWYtsELKECJo9Gc8SKnUHPSs/DyN
         oOj+4nZ2XTOJuAEQmMi3FVeEIX1vG3bjr1r5KTTzV6BeFRCW6qz1qf9E2sVEE0ayzqrf
         1AoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id;
        bh=+f6ArVeWZd2reFq0nlx9DebYmTrmGwR2XKW8kYdyUtM=;
        fh=AwB0/cu/+B+J+NGnar1A7fe3M+cvWSf7aHGu3MIsG/U=;
        b=NxnMdiUCF+M1n033884+P+BUfpv/mesIpquP24pArHlyAXF6yqgoGwp9J4T3ZQqUIt
         QMs7CRR8PN9obBJoRHA45nUXk9EqCNCJErFBSh6jzGTY37cPvZJCX8jV5LkLM2MtvA7B
         K/WrUyIHYA8puTW2anrgXbDezcr28Wv91jVKUhxNu3aTr1lqIlAXuYFZz1XEr2ZNWiky
         jjzo3qKuj7dY7cnhj3iIYE0oObABeRI8zjimC+VC/TWablETxVVd9EMXYPzAMumGbp8M
         jwPpocKKDOP3FMQZQupdeZ6HE/mk+lCkSHIJG65eeHK5nusEM4ioXyteulO6SegsxSsS
         vngw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.41 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com. [209.85.216.41])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-884c6f6d16csi3329985a.5.2025.10.08.16.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 16:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.216.41 as permitted sender) client-ip=209.85.216.41;
Received: by mail-pj1-f41.google.com with SMTP id 98e67ed59e1d1-3352a28d28eso48753a91.3
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 16:11:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUytHYeOjNbxHrCp4pXrXRZQ9NhbIzqufZAOL//KP7f9DbNl85WSOqL2/WKcIV295dY5HRfh64JuIk=@googlegroups.com
X-Gm-Gg: ASbGncsetMe/m6GJO4b1iRXod5zNHRkiLDzIrJ4d8a4+K2hZBoH5gAP62GQur+BLGJ9
	82Bb0i8Htew5A8pK1zVoarf6u1aL34a66kudYBoCTsB+lnMh228TvL5aaIMP8hoG6d1i9geKRkn
	d05p0rwpFESOsvDsDSB60I1dkpszD+qA0x8u9cf74F1gY2okBtPnDlUVRUjOj2mi5TZp7WtnuvQ
	qMt6tpWKqJLJx/i57U111fmsfI3Rte4bgQnNetRJPYyCn0vxM01na7WSSH0yBdfOUHrvcmjuwxj
	+WIsU0n+QNdAn1pGQb20e2zYCEZksPmEn+gbS7BbVamDB56EJIedzd8ci6NAHzAAmPVEGSc826a
	Vox8L6YSa1n72TjFj2D+8K/WWRJXsWMApPd7qgH+u4/NrJhhbLafU1XpPxVz4FRL0WpjVLYpcR9
	c01DllAifuAavcC1Q4XA0V8+KiCWQrzofhZ3R3Lw1yUg==
X-Received: by 2002:a17:90b:3889:b0:32b:dfd7:e42c with SMTP id 98e67ed59e1d1-33b5139575bmr3708891a91.5.1759965058889;
        Wed, 08 Oct 2025 16:10:58 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b510ff99dsm4801947a91.6.2025.10.08.16.10.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 16:10:58 -0700 (PDT)
Message-ID: <2b8e3ca5-1645-489c-9d7f-dd13e5fc43ed@kzalloc.com>
Date: Thu, 9 Oct 2025 08:10:53 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when
 KASAN_GENERIC is active
From: Yunseong Kim <ysk@kzalloc.com>
To: Catalin Marinas <catalin.marinas@arm.com>,
 James Morse <james.morse@arm.com>, Will Deacon <will@kernel.org>,
 Yeoreum Yun <yeoreum.yun@arm.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marc Zyngier <maz@kernel.org>,
 Mark Brown <broonie@kernel.org>, Oliver Upton <oliver.upton@linux.dev>,
 Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20251008210425.125021-3-ysk@kzalloc.com>
 <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
 <d0fc7dd9-d921-4d82-9b70-bedca7056961@kzalloc.com>
Content-Language: en-US
Organization: kzalloc
In-Reply-To: <d0fc7dd9-d921-4d82-9b70-bedca7056961@kzalloc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.216.41 as permitted
 sender) smtp.mailfrom=yskelg@gmail.com
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

To summarize my situation, I thought the boot panic issue might be due
to incompatibility between MTE and KASAN Generic, so I sent this patch.

However, it seems that the problem is related to the call path involving
ZERO page. Also, I am curious how it works correctly in other machine.

On 10/9/25 7:28 AM, Yunseong Kim wrote:
> Hi Andrey,
>=20
> On 10/9/25 6:36 AM, Andrey Konovalov wrote:
>> On Wed, Oct 8, 2025 at 11:13=E2=80=AFPM Yunseong Kim <ysk@kzalloc.com> w=
rote:
>>> [...]
>> I do not understand this. Why is Generic KASAN incompatible with MTE?
>=20
> My board wouldn't boot on the debian debug kernel, so I enabled
> earlycon=3Dpl011,0x40d0000 and checked via the UART console.
>=20
>> Running Generic KASAN in the kernel while having MTE enabled (and e.g.
>> used in userspace) seems like a valid combination.
>=20
> Then it must be caused by something else. Thank you for letting me know.
>=20
> It seems to be occurring in the call path as follows:
>=20
> cpu_enable_mte()
>  -> try_page_mte_tagging(ZERO_PAGE(0))
>    -> VM_WARN_ON_ONCE(folio_test_hugetlb(page_folio(page)));
>=20
>  https://elixir.bootlin.com/linux/v6.17/source/arch/arm64/include/asm/mte=
.h#L83

 -> page_folio(ZERO_PAGE(0))
  -> (struct folio *)_compound_head(ZERO_PAGE(0))

 https://elixir.bootlin.com/linux/v6.17/source/include/linux/page-flags.h#L=
307

>> The crash log above looks like a NULL-ptr-deref. On which line of code
>> does it happen?
>=20
> Decoded stack trace here:
>=20
> [    0.000000] Unable to handle kernel paging request at virtual address =
dfff800000000005
> [    0.000000] KASAN: null-ptr-deref in range [0x0000000000000028-0x00000=
0000000002f]
> [    0.000000] Mem abort info:
> [    0.000000]   ESR =3D 0x0000000096000005
> [    0.000000]   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
> [    0.000000]   SET =3D 0, FnV =3D 0
> [    0.000000]   EA =3D 0, S1PTW =3D 0
> [    0.000000]   FSC =3D 0x05: level 1 translation fault
> [    0.000000] Data abort info:
> [    0.000000]   ISV =3D 0, ISS =3D 0x00000005, ISS2 =3D 0x00000000
> [    0.000000]   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
> [    0.000000]   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0
> [    0.000000] [dfff800000000005] address between user and kernel address=
 ranges
> [    0.000000] Internal error: Oops: 0000000096000005 [#1]  SMP
> [    0.000000] Modules linked in:
> [    0.000000] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.17+unrele=
ased-debug-arm64 #1 PREEMPTLAZY  Debian 6.17-1~exp1
> [    0.000000] pstate: 800000c9 (Nzcv daIF -PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
> [    0.000000] pc : cpu_enable_mte (debian/build/build_arm64_none_debug-a=
rm64/include/linux/page-flags.h:1065 (discriminator 1) debian/build/build_a=
rm64_none_debug-arm64/arch/arm64/include/asm/mte.h:83 (discriminator 1) deb=
ian/build/build_arm64_none_debug-arm64/arch/arm64/kernel/cpufeature.c:2419 =
(discriminator 1))
> [    0.000000] lr : cpu_enable_mte (debian/build/build_arm64_none_debug-a=
rm64/include/linux/page-flags.h:1065 (discriminator 1) debian/build/build_a=
rm64_none_debug-arm64/arch/arm64/include/asm/mte.h:83 (discriminator 1) deb=
ian/build/build_arm64_none_debug-arm64/arch/arm64/kernel/cpufeature.c:2419 =
(discriminator 1))
> [    0.000000] sp : ffff800084f67d80
> [    0.000000] x29: ffff800084f67d80 x28: 0000000000000043 x27: 000000000=
0000001
> [    0.000000] x26: 0000000000000001 x25: ffff800084204008 x24: ffff80008=
4203da8
> [    0.000000] x23: ffff800084204000 x22: ffff800084203000 x21: ffff80008=
65a8000
> [    0.000000] x20: fffffffffffffffe x19: fffffdffddaa6a00 x18: 000000000=
0000011
> [    0.000000] x17: 0000000000000000 x16: 0000000000000000 x15: 000000000=
0000000
> [    0.000000] x14: 0000000000000000 x13: 0000000000000001 x12: ffff70001=
0a04829
> [    0.000000] x11: 1ffff00010a04828 x10: ffff700010a04828 x9 : dfff80000=
0000000
> [    0.000000] x8 : ffff800085024143 x7 : 0000000000000001 x6 : ffff70001=
0a04828
> [    0.000000] x5 : ffff800084f9d200 x4 : 0000000000000000 x3 : ffff80008=
00794ac
> [    0.000000] x2 : 0000000000000005 x1 : dfff800000000000 x0 : 000000000=
000002e
> [    0.000000] Call trace:
> [    0.000000]  cpu_enable_mte (debian/build/build_arm64_none_debug-arm64=
/=E2=88=9A (discriminator 1) debian/build/build_arm64_none_debug-arm64/arch=
/arm64/include/asm/mte.h:83 (discriminator 1) debian/build/build_arm64_none=
_debug-arm64/arch/arm64/kernel/cpufeature.c:2419 (discriminator 1)) (P)
> [    0.000000]  enable_cpu_capabilities (debian/build/build_arm64_none_de=
bug-arm64/arch/arm64/kernel/cpufeature.c:3561 (discriminator 2))
> [    0.000000]  setup_boot_cpu_features (debian/build/build_arm64_none_de=
bug-arm64/arch/arm64/kernel/cpufeature.c:3888 debian/build/build_arm64_none=
_debug-arm64/arch/arm64/kernel/cpufeature.c:3906)
> [    0.000000]  smp_prepare_boot_cpu (debian/build/build_arm64_none_debug=
-arm64/arch/arm64/kernel/smp.c:466)
> [    0.000000]  start_kernel (debian/build/build_arm64_none_debug-arm64/i=
nit/main.c:929)
> [    0.000000]  __primary_switched (debian/build/build_arm64_none_debug-a=
rm64/arch/arm64/kernel/head.S:247)
> [    0.000000] Code: 9100c280 d2d00001 f2fbffe1 d343fc02 (38e16841)
> All code
> =3D=3D=3D=3D=3D=3D=3D=3D
>    0:	9100c280 	add	x0, x20, #0x30
>    4:	d2d00001 	mov	x1, #0x800000000000        	// #140737488355328
>    8:	f2fbffe1 	movk	x1, #0xdfff, lsl #48
>    c:	d343fc02 	lsr	x2, x0, #3
>   10:*	38e16841 	ldrsb	w1, [x2, x1]		<-- trapping instruction
>=20
> Code starting with the faulting instruction
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>    0:	38e16841 	ldrsb	w1, [x2, x1]
> [    0.000000] ---[ end trace 0000000000000000 ]---
> [    0.000000] Kernel panic - not syncing: Attempted to kill the idle tas=
k!
> [    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the=
 idle task! ]---
>=20
>=20
> If there are any other points you'd like me to check or directions, pleas=
e
> let me know.
>=20
> Thank you!
>=20
> Yunseong

Best regards,
Yunseong

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
b8e3ca5-1645-489c-9d7f-dd13e5fc43ed%40kzalloc.com.
