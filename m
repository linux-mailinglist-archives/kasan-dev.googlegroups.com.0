Return-Path: <kasan-dev+bncBCSL7B6LWYHBB7VT5TCQMGQEX7Z33MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B96BB45FBC
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 19:12:32 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-336cd3a26a1sf14334691fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 10:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757092351; cv=pass;
        d=google.com; s=arc-20240605;
        b=ffgwwpAdePIbF63W27owEtBq4udWfuOov5HD0cy6MitWt2wBV3L6gxxH+8ZafknG3j
         n0VlgG4MxMd4zZwCcivc2wrBYjYsjQrXw5cGhlX1lc2y5a8p14pVjSJHiI7TPfeEbDmd
         ZCFtaViD2j76OQ1X0Jy83Shubr1OLKc1Z8CZsOjkcQ6aVTAZlFD8mZX+xTY1f4WPP5Bu
         Ar1n/Yk9JOUu8+hMKHnGsQqJ9WZTJGO1FscYZlxaS/cjTUMvZDuzKEm3HRwHLp9REUwz
         cx51WSb1qzfcgiIFNbvewkiXFZgEpZJvAiIRyQEoamlBg/BORjcMcIMaFjLtuAYKYw+P
         Tf/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=MRptzl6PMecgZCG2ivXYOswJhofuS9jxV/sgQ07SG94=;
        fh=PSR1jMLruwyZZGgX9eRQPlIJs6qB+Yh3jv+LpC4VGqk=;
        b=I2wx1c4kHQRdB7YTq2iDQRXmyVd0DgOoIDEHOO+9cR8f6Oojjm/mRWLlsURBiQeeI3
         Kj4AIxo+7Bz4dMx3qn6HzhKGoX/s52wo+EpXFsQlW1XdEFxrpACNB4aVttjUELEMBjko
         FOtgRiGAn2SsbXj6cz4H+WXjCxQpCcDwa9KmS9CHM8Ub3lNYEV8KEWxgxAl1noClUPr5
         VXKdqE/Mu2ycetsZT+kE5qwgBRlCAax1Mg5Qf4w6ACSdOefG1DT00pA+RuW+Lwrf/jdx
         dWmsYD7W+2uxWJMI4i8VQKgFeDSnnrnWUS/5cr2GMn28Yn2z+oo1M6EI9xUHDl+lEAV8
         C6pA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dwn7d2xH;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757092351; x=1757697151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MRptzl6PMecgZCG2ivXYOswJhofuS9jxV/sgQ07SG94=;
        b=Ce1oMbtXH4N+FS7iLEZYEcJ18CDWuUzlqsXASjhmxLk+gk0WU2cR1UD1gPqix16AD4
         m1OvEtOTgLo2IE+iW8Jem3pHLkdHzmMUnUPePkkdCA81KVwRev5vbahS7jcj3ticYSAC
         /GqvnV7632kUBFKUw7pxpyYsHyFb5HDCBENGg3A0HPIJFDn7saeecPD6Y8njncl9M8dT
         qTBdf76KavnyiLOpI140n4eCBZqzeGhx63t4e8YAfErGB4zsvPLS3x2hmGl6Ei0jLbSv
         mpqqBHWHl4aiDqLtaW6UFpweicI2Oti88D6mA9h10vr75X9ZHfYKbmuSw+s/Tchjkiq0
         uDng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757092351; x=1757697151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=MRptzl6PMecgZCG2ivXYOswJhofuS9jxV/sgQ07SG94=;
        b=iBbw+4Nbx4GHFKqnXrdrKdCvDbJKb67FH/TWMeHCR3SbQqvmop5tVeQQSCxMqLgMvQ
         k6PHGyXXMNqScPuL/yo1eKaobLx9qH8GY5fcxDn4u/dBAntQAL9g8dS7MJq7UsOk7KAp
         c9uEWCA9Ga7dAeKwMfu0rdTlsxLSQwKQbnT66RqtY4OjEJzhmHaqgGQb4NddUFdoab9n
         ymb2jvkifIwYRHak4xR7UHH2fJ4KKf1KcqQZbny/n2oYM09p10LX5RylqPEjkG+8Bc0L
         UGPyux10JJE6djPgAMzUjoe1Wri/x38sdBMmiIms+U7RwRxYV0WjlpxYpOBCaLgQGSwu
         SaYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757092351; x=1757697151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MRptzl6PMecgZCG2ivXYOswJhofuS9jxV/sgQ07SG94=;
        b=oWVgzpX+Wk5swwDQW3piarFxF1Myn8PvDGQCPTa9nvHWAevBLj1P3UFC5HuaE0r+vc
         DxbCS6yNkBSo6uK0qIEZ/M7sr8A7nT8SM4Xg6IqIr7CkrXUmhdLo3S9BwN+6lhg7Rc0V
         7vJtX0NNKAVeigUd46HLzlWRyPX20z/QdD0eecygFM2HfYqUvlc1unIhh1sVK1xYF8XF
         EKe63XcePArATfFrY6iC8jXbAq3xFYC8277+t+f1b3+mhl7/C35IUYcJYy+x6tIxFpta
         gNyRbRbQv4IMSaV0x0MQ0Pk6T2B05/KgWUZiX0hilb3/mSq9mXUP3l+qqAXxThIQYkg9
         4r4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKQ1SCA+fFGdukbnLNi3VhTn5pR3phyDM0PtIEHH7AlfTqLKZIN32DDHWTx1GJgSAESZYiiw==@lfdr.de
X-Gm-Message-State: AOJu0YzRGrxVCC/rAhu7TamofvMna3oBERgOw/lTZWGoZOGzKKn/+0Q5
	V2md34MQ9FI1CB8HcPrk8qevf37B3hNX7HuNpz83O0nb7YhynTQ7cVMX
X-Google-Smtp-Source: AGHT+IFAvEWMy/R8F9VygqtkAZTmsLcUQcRAkEQVF43sONTXmTgA5CgK5SwJwImfsUINR6S2YLYNCw==
X-Received: by 2002:a05:651c:b06:b0:32a:6eea:5c35 with SMTP id 38308e7fff4ca-336caa56fdcmr55324511fa.15.1757092351260;
        Fri, 05 Sep 2025 10:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdgLVQXBkCrSwqE4zs59Dx0h7xSAoQWk3aSdaW0knk2ew==
Received: by 2002:a2e:b5af:0:b0:336:de7e:6efe with SMTP id 38308e7fff4ca-338d4268a24ls2573061fa.2.-pod-prod-08-eu;
 Fri, 05 Sep 2025 10:12:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXED2XuzgumfagAV8kh4iNEhfSQ0cJS+4CL2Jzt+rAQunZh4vizGfgPUl/nw+IQZ3TmVBS0yf3VeQs=@googlegroups.com
X-Received: by 2002:a05:651c:1079:b0:32a:6aa0:2173 with SMTP id 38308e7fff4ca-336caf70ec1mr51873571fa.20.1757092348084;
        Fri, 05 Sep 2025 10:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757092348; cv=none;
        d=google.com; s=arc-20240605;
        b=ZhJjjjDGYFf4zMhOYk/76XWsuhNqr/5Gxn5LvWxdeaAZb/j6lSWtpxNae3u+aMK8AM
         8TxSuP6xMA19XTJoFQul58sB79MkvJLUxJQvm4E5Rr2ONdAN5mFkHmX9ncn9q7VkP7QI
         Jp5ngJ/aeKVTnJ3IB73fnFj97xAHWsw1/fEGmI8G+DQQykH+J+K4OGN/r61qalvrJO7k
         VPDM5XxhidjJW1Ban9Y87kleAnfqzZSxodwn+MsnEFfNyTJOPiRZWBZQNVeizD1RKFqL
         hf/bjhN79mF2qUjuv9XtBTd8YC0sFzz0vkohKHcSkTw7E8WItljgnU0plQK2QVw7G+a4
         jRog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=YRexvvNjPPJfK1uT0OSGvRNA7ydx0We94Cj4HRzyUo8=;
        fh=ECSwwQy9oZHuZM1SgS9ssdJoXn6oa+kTcH+kh2dSqTw=;
        b=XL/92D/HPxFQku4EJk5Zk1Sd4cyr+vMuegwTBm1yy/6YcR575ESGSJBhO6WaAZ26HK
         J31Z6yI1r46CFtYFysj+QXbaxzflnQG2CrGHnPkTZ6VikA6XnVfiaGQVGkhHcUwcotSg
         0GKEi+ZJybsa6VEDxQI37b/FkDisFOlXjwJ2bs33TxWHBxhoafcoogT/W9Rexp1NAfJC
         EhL4skHXu3nLewTgRjHJjG13tcTeccapTVD2jhLbk68zj95li2KPVw5bes0Lpr+4JOPt
         y6PX0yYNAg0TV1Bo59KJ+K5k4xxbUMzvqpegSX9nuYb8MMdeVaj57q+7+T189b3DxcWG
         rZzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dwn7d2xH;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4faaadbsi1789831fa.5.2025.09.05.10.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 10:12:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-3cd299b1833so363077f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 10:12:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYKiP3VwCUEXzrs/DbXzuQbiIAS/bhFlNH3MzeyaN/9y+PlR2xFsHBCM+rMKnfDmYJcPIggABqamI=@googlegroups.com
X-Gm-Gg: ASbGncsmhwaU0i7olfCLfNjF1DRjt3cLEV6pRd6HkyzOAstsl512qfSBcBgFKV0oN/R
	cKLqcbpqNW66Ikk1zVriv/p42TaYNdo3KXz4sbi/5k9B2Y3XKUv3XYucJS11FJZBn6lZgPZHzd4
	16TDqrn7FLqtCI8eJlfrVK2d0TQqOm5XveUD3z0eXohYHIClh0ZUHDB+Td6RJcGmuztSUnTM36Z
	45J7DOGm2CYHbvcABiewiekSz8iDs8wQddQ14FmQi502TtK6yHewdXDDKtMas+0tiHyBuGRUkXN
	db9Cz2TPqseXS5F23IUbrAqy92yq+Hm7oheUGf33jhSx5rORWSceN1fyJtZDkdgSQXDpKbFtM6F
	0gBumZPeQDZ5gRMbABj00EA2tjEprLuYi2pHnknka5/2M5TJguNe0ocdRaIs4VKJIKuHisTO3m9
	esrA9vgDUC/Tw532A=
X-Received: by 2002:a05:600c:8b10:b0:45d:d0a9:18b3 with SMTP id 5b1f17b1804b1-45dd0a91aecmr33464465e9.4.1757092346974;
        Fri, 05 Sep 2025 10:12:26 -0700 (PDT)
Received: from [10.213.233.28] (109-92-217-44.dynamic.isp.telekom.rs. [109.92.217.44])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e8ab14esm369577925e9.21.2025.09.05.10.12.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 10:12:26 -0700 (PDT)
Message-ID: <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
Date: Fri, 5 Sep 2025 19:12:01 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
To: Andrey Konovalov <andreyknvl@gmail.com>, Baoquan He <bhe@redhat.com>,
 snovitoll@gmail.com
Cc: glider@google.com, dvyukov@google.com, elver@google.com,
 linux-mm@kvack.org, vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com,
 christophe.leroy@csgroup.eu
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dwn7d2xH;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::433
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

On 9/4/25 4:58 PM, Andrey Konovalov wrote:
> On Thu, Sep 4, 2025 at 10:11=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
>>
>>> If so, would it help if we make the kasan.vmalloc command-line
>>> parameter work with the non-HW_TAGS modes (and make it do the same
>>> thing as disabling CONFIG_KASAN_VMALLOC)?
>>>
>>> What I don't like about introducing kasan=3Doff for non-HW_TAGS modes i=
s
>>> that this parameter does not actually disable KASAN. It just
>>> suppresses KASAN code for mapping proper shadow memory. But the
>>> compiler-added instrumentation is still executing (and I suspect this
>>> might break the inline instrumentation mode).
>>
>> I may not follow your saying it doesn't disable KASAN. In this patchset,
>> not only do I disable the code for mapping shadow memory, but also I
>> skip any KASAN checking. Please see change of check_region_inline() in
>> mm/kasan/generic.c and kasan_check_range() in mm/kasan/sw_tags.c. It
>> will skip any KASAN checking when accessing memory.
>>
>> Yeah, the compiler added instrumentation will be called, but the if
>> (!kasan_enabled()) checking will decide if going further into KASAN code
>> or just return directly.
>=20
> This all is true for the outline instrumentation mode.
>=20
> However, with the inline instrumentation, check_region_inline() is not
> called (in many cases, at least) and instead the compiler embeds the
> instructions to calculate the shadow memory address and check its
> value directly (this is why we have CONFIG_KASAN_SHADOW_OFFSET, whose
> value has to be known at compile time).
>=20
>> I tried inline mode on x86_64 and arm64, it
>> works well when one reviewer said inline mode could cost much more
>> memory, I don't see any breakage w or w/o kasan=3Doff when this patchset
>> applied..
>=20
> This is interesting. I guess what happens is that we still have the
> early shadow memory mapped so the shadow memory accesses inserted by
> the inline instrumentation do not crash.
>=20
> But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
> CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect this
> should causes crashes, as the early shadow is mapped as read-only and
> the inline stack instrumentation will try writing into it (or do the
> writes into the early shadow somehow get ignored?..).
>=20

It's not read-only, otherwise we would crash very early before full shadow
setup and won't be able to boot at all. So writes still happen, and shadow
checked, but reports are disabled.

So the patchset should work, but it's a little bit odd feature. With kasan=
=3Doff we still
pay x2-x3 performance penalty of compiler instrumentation and get nothing i=
n return.
So the usecase for this is if you don't want to compile and manage addition=
al kernel binary
(with CONFIG_KASAN=3Dn) and don't care about performance at all.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
5a2eb31-3636-44d4-b2c9-3a24646499a4%40gmail.com.
