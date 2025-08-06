Return-Path: <kasan-dev+bncBCSL7B6LWYHBBFV3ZXCAMGQEG4KPP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D019B1C703
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 15:50:15 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3b8d62a680bsf574416f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 06:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754488215; cv=pass;
        d=google.com; s=arc-20240605;
        b=h8cGP/Rb7WC0Yvoi01KhhRy+SNRIwgSs3gzlO5YrPVLr6ZDCYe6MnK7JbnLcv7LCkD
         ZzNFMkuJJ7hXiDr/dpSRRkuHi+84/hXvA3qLtZ9A7+1QBDUrvTklyyo6rhffPLhMPK6g
         QrYLeVudo9aqkpvwwahx5cDoiXumRyuFxB15YJdPa4R7jj2fsMnaQysphrfoxAblXfmS
         MkvxpGeNcPPotZklJUMF/K+/6RaTbzLpi0Ly5AqrtwwXEUAhGOjqUk2H4Sg70xeyGAFT
         QOGFk+fUXOtGc71V2XyjC9KqEL7B1VfrYGo2jJd+CqDiNTcUPPjqVWpKdxAcuak1xbal
         xCMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=yDfAbjfQeHSQwCrvWwLeikvZyG0kW4P9KMKB2XfyR30=;
        fh=axX6y7uuHe2t1a0pnfz4n3AZP5aEdjf5AAJrmqOnEF8=;
        b=J//txI4pbplh+HFtMEVp3Wd6HsWeaZe0ouFnGAauwQjbNqQOh2RJmvcC8plevj0jir
         HqehBi2wAi4C/GJJCnm15Lwrga0EUpRVeLb87MtE1sIPn0cHJDXuifz2QADcByKzh41T
         1W5H9yg0u0MNNL29HY/y3Dyn0nSGmzqdupsjKXwXa/f3kvI0Utj5X3H32Qf5rK42UmGI
         CFPJ1Sk0m7TU68owIOlO9qyQiqYTw9v0dBRvh2U7FzJBPzSQTpNjvObadDzCrWaGY5cs
         lDaBO+HnwLo8dX+JbDAb4UcydqmoX/sHgauab5i6B1rydfdxno1+mbxYw8Emot1QQ+py
         cb/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qj1UwzGJ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754488215; x=1755093015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yDfAbjfQeHSQwCrvWwLeikvZyG0kW4P9KMKB2XfyR30=;
        b=YSZ3n8sqdrYZJTFj6QQDNFlvTRR097mKehqm23JjilpujYJ+FQfKyfS9ZKTa8d+QWr
         dWli84UjRXQZCTDeoJgItXpGmmael1+xjCBCmNrvIrNJMgASkAa0GzWcFFoSGaxWzqtt
         ea6HWycIRMH8oNFDFpBJOng8jfGX0xaeDPgU5CvtHAwoWTINOyFL7/DOrysIt3OQhp+j
         lu6oj/VegmM/uKDklEXWWyF72wvBL7QjeghpFPfokj8F3mOJYgkzg/sCLJxC3JY8Oh05
         nBNX6mPB8E+Es81aPwf2nT/5y9XzX8qiHRrjk2UqA++2rywDEoO2uyj1h9vbyvq/098i
         YU/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754488215; x=1755093015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=yDfAbjfQeHSQwCrvWwLeikvZyG0kW4P9KMKB2XfyR30=;
        b=EYWdaAl77fgOB1/lGww22jfy9bAfulvQ+rMowiSSTg5p5bF4JvRv+CHtDKPL8lJB0w
         WDsMtjxhG7Fn3ipf4zdZ95yP/iamY1x9g6ssB0P31Nq4tWcQn9Uz8k7OzLtWN8CArXvQ
         Fr9Zn6M1XebDXKPByOy+JbFlNHYSDlywMjWEroRjEbKWGrI97p+cOkSapBHnzFbdXtyr
         HJBHqE0GaSCCMhvXO5LhmeXu0uIdvz5BMnIfappFgiBNE0ruSEC9l1s7BmRUOAuIYPjn
         nCBk4RW1Ryd5AcK5hU4Pi5o8mFikiYbx/APMwefBwSLL39obKf9XTfGaslLJqTnyzYz7
         cdfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754488215; x=1755093015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yDfAbjfQeHSQwCrvWwLeikvZyG0kW4P9KMKB2XfyR30=;
        b=TQsj+HIPlgUrSnmEvOz5IuKgxMdJwx23a9rQ7Bp9o2meG+EZhvPlko6jMk25SnUsEG
         +jTAMAsO/ETGsvf3m6t2nA6Z0UYr6zEwndJ3bLMS5PsBYaR+NmVH/bhEEskVYEPytib/
         0DgwlYGb/hPqt5SEIYPvg0LHwGqUNlqU2brYGVjc3h5bjyZWwGfMI9rKLHrJHHtDUvfm
         N0or5hNQLRxtL5eFk7JN6oee7HqJ4lDMvnyrWM0b1DKNW9wlpQb53pPhmOgfFxoLv2dy
         mlB+Tt45Q2chVqzIyNFOKN96AHaAlZnOGiKWTac/dl+V/GilWqf9Q3N2WPXTw/1elh3O
         14HQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlMx2v8n/HvXmS67lMRztGmw8K1gDudO0rUYsi4fWHA+ehT34W0ve8SIpAyrVJdpocRXM3rg==@lfdr.de
X-Gm-Message-State: AOJu0YyVdHKtJov7G83UCtuBHbK8wQZsvnq0niN+Zxn1swScjZXLHU0h
	tHPG/vTzZEnQFpnhxQbYWOudznAzcfCZcxX8pd9BtmEozGSOObrrClgS
X-Google-Smtp-Source: AGHT+IE+7WY8xwnzMm8bNDUhyLY24wN56Fvh8k/Oj8z1JC5tTRIV6INeTWj4/i83mI5oIU3eQgAzvg==
X-Received: by 2002:a05:6000:2385:b0:3b6:d0d:79c1 with SMTP id ffacd0b85a97d-3b8f4316685mr2335137f8f.10.1754488214623;
        Wed, 06 Aug 2025 06:50:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcS/YZYE449ppLc/q1nXbSBbOXOrOm7ywXkgBMyAjyuyw==
Received: by 2002:a05:600c:5246:b0:459:d904:8de9 with SMTP id
 5b1f17b1804b1-459e65b6f5cls3486355e9.1.-pod-prod-00-eu; Wed, 06 Aug 2025
 06:50:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoaz6tpdVrmibC5EtH83JBTnzicDMqW3p9VqQL9Kv9acJCgkXz5IRBaYORLdnPtSUV1qkW/uQy+uE=@googlegroups.com
X-Received: by 2002:a05:600c:2d92:b0:458:6f13:aa4a with SMTP id 5b1f17b1804b1-459e70bcee5mr18411805e9.6.1754488211313;
        Wed, 06 Aug 2025 06:50:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754488211; cv=none;
        d=google.com; s=arc-20240605;
        b=i9iAc/Q3+KowafRqrwAtwhh+DeOahfK7Ll5V+GewG+WyJEMK3YcvoucOzG+f91erSL
         TAWkC/CrwtH2ljeWKGD97rD2UbxfM1EHvOkEmFp0nMIiEIOk0y0ITPCpFsD+BQuw3E2H
         99LVYbgXqKjYOVlQdfy/rFfErrwyvfgf3O4rMMMgnr8HSA5JxQ2qL1IZDNoUObG7Hubc
         WWOBiCtBiwL/5jwBiJoby7m7Zz1xf61YdcDENx5WRWZgasYXCesOhtsFydNij7JapVuU
         ySpc3ii6NT3swICY27TO5T58QB1l5ETpbEdUbeFywNjkYMzpWmWGbCAUoLMs3BJn6rLE
         m32w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=pDOCIZR6gSwH1CTXkpwwYCK6HLPl+F0ICSkVzqPXsh0=;
        fh=BgSFvsb33+dCGKjXNoSmpd37/+4aC56dGJQBhepxYkc=;
        b=DqnoXI/s761b26Oq7al6qy+eesvYPX0WgR80PguApJvdYPPPnJTtz5VWGWXTtawqba
         b4qcA6viTUxLc4gWJ1XWsxTDs9QcY0pqk9f0UGDsYCQt1d2isSwpvTozd4KuqhWBvRHg
         c1/1ZYb17xeqHtSSGKyDBmVSOmBLdl8rIqfs18yH7kb9AUAwzuGRHQdaZTXkLGGVrDtj
         49r1wjqSwNVA6D1ghg7BB9aeYaUOGaDbRiXtSTk7XCESMp85wOM8ze72lgY3T2WNx/dQ
         uG6fk0zxR8oom9Qu/nkLnlssnLYRJu2TaVwM9PMlLOKdMaEopbQUKuW/7zSouRV587C8
         U6Sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Qj1UwzGJ;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458bfb31d49si1196655e9.1.2025.08.06.06.50.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 06:50:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-332468a0955so7034251fa.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 06:50:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUdsEbvLtp1x+lkV/tmyUPuWY983w5hI8hvvfXMLOoi7uvEqvKBK3Wr7EZSrAoJ9s3Daisr8PDLQ8=@googlegroups.com
X-Gm-Gg: ASbGncuBWaFi0m6V3IGq81h31j5qkd9f1nG3O0oJEkLuEiGY+nMU0FFgzQAI3JQ5jdc
	I8yWbg9qCHvd1n9W8aQQcjacNUHUd/pCM9g42zoDRQYt2c2+tKVWoKurdhwa/HuBkjj2NWuQmI3
	lRwb8A4Cl8UL+ZGFS4yD5IF5PZEX/aKrNQGvUqHm7uHau3duuvCbXvIiizpvYjTs/oSsy0J0e2G
	tsyMJP9qVxahiqUIsqriYjbDnGCukFsBEaqilxctkFVX6zpP2Z0qABlbn+mj7muYU8DSECUSnBf
	0Ip1VtVvIbZyvfaOEZo6aCouli+7xT9YZMTXBkt4kBUTj+FQyn4C8DspH1lmvOrTd4LZ7jC0dVs
	ipwTqH0WJV1kM+L5+q0eF2GfyA/e2Wee1jdmhQx1X4SYmHZ+Pbg==
X-Received: by 2002:a05:6512:3b1f:b0:550:ecdf:a7f9 with SMTP id 2adb3069b0e04-55caf35fc1amr414988e87.10.1754488210277;
        Wed, 06 Aug 2025 06:50:10 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88cabbd8sm2356761e87.149.2025.08.06.06.50.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 06:50:09 -0700 (PDT)
Message-ID: <ece4aab9-a195-47c9-b370-c84f5dcc0098@gmail.com>
Date: Wed, 6 Aug 2025 15:49:22 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 6/9] kasan/um: select ARCH_DEFER_KASAN and call
 kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com,
 agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com,
 glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-7-snovitoll@gmail.com>
 <60895f3d-abe2-4fc3-afc3-176a188f06d4@gmail.com>
 <CACzwLxhs+Rt9-q6tKi3Kvu7HpZ2VgZAc4XEXZ4MEB60UbFjDKg@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CACzwLxhs+Rt9-q6tKi3Kvu7HpZ2VgZAc4XEXZ4MEB60UbFjDKg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Qj1UwzGJ;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 8/6/25 6:35 AM, Sabyrzhan Tasbolatov wrote:
> On Tue, Aug 5, 2025 at 10:19=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:
>>
>>
>>
>> On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
>>>
>>> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
>>> index 9083bfdb773..8d14c8fc2cd 100644
>>> --- a/arch/um/Kconfig
>>> +++ b/arch/um/Kconfig
>>> @@ -5,6 +5,7 @@ menu "UML-specific options"
>>>  config UML
>>>       bool
>>>       default y
>>> +     select ARCH_DEFER_KASAN
>>
>> select ARCH_DEFER_KASAN if STATIC_LINK
>=20
> As pointed out in commit 5b301409e8bc("UML: add support for KASAN
> under x86_64"),
>=20
> : Also note that, while UML supports both KASAN in inline mode
> (CONFIG_KASAN_INLINE)
> : and static linking (CONFIG_STATIC_LINK), it does not support both at
> the same time.
>=20
> I've tested that for UML,
> ARCH_DEFER_KASAN works if STATIC_LINK && KASAN_OUTLINE
> ARCH_DEFER_KASAN works if KASAN_INLINE && !STATIC_LINK
>=20
> ARCH_DEFER_KASAN if STATIC_LINK, and KASAN_INLINE=3Dy by default from def=
config
> crashes with SEGFAULT here (I didn't understand what it is, I think
> the main() constructors
> is not prepared in UML):
>=20
>  =E2=96=BA 0       0x609d6f87 strlen+43
>    1       0x60a20db0 _dl_new_object+48
>    2       0x60a24627 _dl_non_dynamic_init+103
>    3       0x60a25f9a __libc_init_first+42
>    4       0x609eb6b2 __libc_start_main_impl+2434
>    5       0x6004a025 _start+37
>=20

No surprise here, kasan_arch_is_ready() or ARCH_DEFER_KASAN doesn't work wi=
th KASAN_INLINE=3Dy
This configuration combination (STATIC_LINK + KASAN_INLINE) wasn't possible=
 before:

#ifndef kasan_arch_is_ready
static inline bool kasan_arch_is_ready(void)   { return true; }
#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
#error kasan_arch_is_ready only works in KASAN generic outline mode!
#endif



> Since this is the case only for UML, AFAIU, I don't think we want to chan=
ge
> conditions in lib/Kconfig.kasan. Shall I leave UML Kconfig as it is? e.g.
>=20
> select ARCH_DEFER_KASAN
>=20

No, this should have if STATIC_LINK

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
ce4aab9-a195-47c9-b370-c84f5dcc0098%40gmail.com.
