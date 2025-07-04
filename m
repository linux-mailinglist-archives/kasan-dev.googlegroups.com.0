Return-Path: <kasan-dev+bncBCSL7B6LWYHBBAFFT7BQMGQEIVEFFVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id DABD5AF93B3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 15:09:33 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3a4eec544c6sf475816f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 06:09:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751634562; cv=pass;
        d=google.com; s=arc-20240605;
        b=FNEmu9BztkhVzf5Mw4Bbsei3kpxxD0WvTaTIaR2TufuxTtgbBju0V8XHkCY7EtvSP9
         8u5ZCaSPP3V0axMa6rv4RyN92KAPYfWuxerwCjq1rIeJ6eoTxpHK3q1imUisX5DxmG1g
         XTDdsLMrV+UXRsOQVxYpIqmOG1HF9qK6/kzoADxl2lnckCMy6s0KpElx/MMc/4Cdsc0p
         wt7uXDI2piGZNfcSx0j+n3vXq0yKEpYB2sLc6/MXgWsx1jkx8bamLhgP7O2J0ppPUQR8
         DZsT+ro/8Pwpk/AQo1EH6P6aGigMUgeMYOumQg49t8xce154CAhIyb9Qdnxk/LRN+PrX
         LF9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=g5GQlOA36DhQ5WT2RAssIgFMVojgbnuFl+uHgMmTGIU=;
        fh=QdsCgn9Hs97fQdFvgzWKEDes/GOgTfPYoNP4YAEL1Hs=;
        b=eV1ymkwpnht3VfO4WzvPJHIw3M5B5XXiYB5eThSALuz1um0n/g5LwL1x8lg6NfV9Ma
         ISWUR717ZeT8Pa3zoGBBF+sgntu/FFfhyjvsO6ik5mh+gaB8zwo7EKmRl3bM5hPPZvfd
         qbwLhQeekkxvMhQTz3AC1jjJhoylIYEINOABrqpvKMSqaG2xtX/g+vmCw3cskuYihunc
         kSvo8exBBBn4z/Ay9xsEEgQPpZGKlu1yt1D8fud1RdGBwh/llQ5O1dMEIH0+3UD+92Eq
         /EAz+JTX6NET2yqqBOz3rc1X0q0eUVEez/EZLglu+iQEyuN2Q24kgdy0LTTBpKIi9blq
         QT8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gmP+f62X;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751634562; x=1752239362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g5GQlOA36DhQ5WT2RAssIgFMVojgbnuFl+uHgMmTGIU=;
        b=tfXl7asok4dZ14BB46fc47Vd7Rz8QlEuGdXYJHTpq58OToDxzpcIsRMwOPkkN8v9Cd
         sLrZF+g0KV6R5h4Hr78Tj1qwZ2XXkqInCYqLJPwzyKTUIx2ma6RG7SNLKIa3bl5Jn28F
         FkaR8kFe1mcudONN2q1xvc6ICB3zJTun0shRWupSZ1hEut4F1wxSOGFUsizblWVtLkUt
         sCu8Ts2xpqcjX8L/PEDTtVPE8VLXpev7epzy0ZR9HYwQi62AyMAf8fuXb+7G9xX81kwV
         u3RubeBF4I5avNv7VKS49ELmrF7+62Vfl656UTfyvMGAQE+ErHUugli6CzZCQzKkJ5PF
         YjmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751634562; x=1752239362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=g5GQlOA36DhQ5WT2RAssIgFMVojgbnuFl+uHgMmTGIU=;
        b=KEMCOtKWi4Q4RgUXCT83gwxf+kn93JdJoJOo0zmmYkweYzYdXx6dAk0aVvzqz2b2PO
         yQW8petr6sMa8s1Y3/6Wp6xwoG8S3ILKZsnWiSyjjoRnsTQUN0WZOk2HMz2WX2N38Tll
         Coj136/SgmsZXnNc7O9pBxeqmeYjs6JMR0JYn0ManegjQF+BpcsqzzQC8o/DN/XrzloO
         AVAOhjHCg9EYgiwJPZNPsRGx2VtfYewO4McuoIfJw1eMxjewPP3xVVk2bcAkrlcbLyi8
         nUe97jBhD+hUCAFN96OV74A5Xp8FNw1bSkw+1l39WaZKlkbJL8fKnqFdlfj6LS/km9CR
         XzRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751634562; x=1752239362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g5GQlOA36DhQ5WT2RAssIgFMVojgbnuFl+uHgMmTGIU=;
        b=O92ZdaoIetCux2Vtqsf+fdLSpyp+54kAqTWTaRZLecJQHLCDh9LtMQvHb7FvHUjyMa
         JYZHK8yUh2fvtQQW9R/vtk0OpcbCZXL37wxmHrZOtqFFlJC+BYnDmuDeTdU/l2XxjVVg
         sx5PSgIPXACMhiubWMxtStxxu6qNtE9lWfrxkUDpGm7lPaH3bPAzcIkP2Um+1YSbl1EI
         u4Cawr2xHvEG5rcSQBg+CeJ6eSvvNmzW34Z8tsArpz8lyeTHJGofEkJfhuvFud/OeFQN
         EJ+SfenDaR74Y0T3Jd80RkHhbZvzHRbmrpMb0vXN27drzZZzOLAyZs1Nnt3s26yWnyMn
         E0RQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmJ0elgmLFJhsQBzhlIV+un+c3VkVVjxLjLqT7/n+qa5/iyyyCHRZ0bxBtA7GCqYOLmpz+MQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx46WNoiAr3/ypgyd1pmQ31B5i8vZ/eMsmer72ObvkoUI6oVp+0
	LqJco7zfUY3W0HQgYzBT6HnXSj88oCcpQuZiybs3stvnRG0jF/jcR62f
X-Google-Smtp-Source: AGHT+IFr9WH6t7fl8ltCSy3rbpOniMe233hPjNsc0oXjho660iM+LGn+ORTmSNocttqzFyeYxlKqdw==
X-Received: by 2002:a05:6000:1acb:b0:3a4:ea40:4d3f with SMTP id ffacd0b85a97d-3b4964fc498mr2290231f8f.53.1751634561822;
        Fri, 04 Jul 2025 06:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwXWxF8DfR+vzb+4p56WyTaIWu4FuaUsAAZNaITR+txQ==
Received: by 2002:a05:6000:420d:b0:3a3:76d8:67a0 with SMTP id
 ffacd0b85a97d-3b4975a4db0ls269902f8f.1.-pod-prod-03-eu; Fri, 04 Jul 2025
 06:09:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMZtujgsGodK6eXqO+405ZyZlUIO2ranBsamhc0ojBHYx3/Qm4eBZidZbKR1hSQfcLB3uarpxp01I=@googlegroups.com
X-Received: by 2002:a05:6000:2f83:b0:3a4:e387:c0bb with SMTP id ffacd0b85a97d-3b4964fc7dcmr1974372f8f.59.1751634556131;
        Fri, 04 Jul 2025 06:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751634556; cv=none;
        d=google.com; s=arc-20240605;
        b=Bxc9YvV2XiLxFbE5YlAY+vnzJWBGWl8wEZV0fJPLx8oOlSwrJZWSQt4Jvba/4gg+4V
         lgLXA3fUg0N2+8VY+r/eKGHGifcbccuGl9MvgzrGooRgSvdQqTunUWK749FmaQH4WwzM
         V4/JlkFPk/2exF5cajdPJE8ift0eD0Cq/GswLdQ3U9gQPqWglEjB/vKu9k/lcP/JF3Re
         GOZAszrSgQkjoBfS/iB/da1Ab6bg7sy3V1zJ+ugtAL2uIpNbXEj9ZH3cAlqtYufFpmSg
         +9f1tmKlFXHrLHJKIutuc3k78iCYFc8p5SUmS3suVVVjf6rA576E/0CuTJaGOjlWQCIG
         SUbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=bPT/Yn9IyO9lNhZMkeKSyj5/KPjAxsknNyMSqLYzrPY=;
        fh=9ZOyoGtPreezdDA0r/gyllKIrjc9DLB4KasbgSwGdyQ=;
        b=kmCEiHaTmvbVye+dMygLWNM+y/9Slbzx+YC/tgRp2+HkKpT5hs3AoiFvMeEmw6TDXe
         kX15jIzHnnaDGHiZqt5OVtsTlENL+LOBCqXZozjoUFIagFxNKMVFN9XVUzqAK82k9h5/
         +N2QLow117hZyggcWXV5nHHK+nW3kOfmjIWhnx33+Q/VERNq2Dsw8dc0rQzofc/oHJex
         doamc/LU8gy/fm4swiOF72fj1IFd4ZmtqO77QYSvo6FNoOy6CZaXneUtgaN4hOmkSPfZ
         WuAqfLlyMypO8bq9AwS/e9OpnLipu8qCK5tJkGH5zuNXrNzZaVvalPA7kx63Gqzyu7x2
         2AxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gmP+f62X;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454b3b1ed4esi360635e9.2.2025.07.04.06.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 06:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-553d27801b4so38516e87.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 06:09:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0XJganJ+oQOuNRy/mCpzKO3RITtDY4unlkp2zzSueE63b57zq0xM53T2z/QYKhS8XCQYqEzujsHA=@googlegroups.com
X-Gm-Gg: ASbGnctBJZy+0cTpFpF6fQBFNDuLjyXAEquQo45C7jIYO8lgI+qKzmadcffKCFUmlE1
	meBVR/E3yCOat5jV0oE9TFICiKYFiGqcSHJCDTifFRcWGhiiGa3UfO32DuW6Cw8bja+EYJCeJPV
	R00aBrmlYdRcpJTRVt6MUZNPitwQF9gdR/nWBjxbU/Dow0PWAHgHdpelGUPdE3DnysLyryRH3a7
	D6IxR9t3YG1BZ/G05HvIw3TPg9Ippy/gTpldE59QWhUz4SMb26FnnLZvW1Wvqtcufblz8Jfuhye
	uV/seenUSRFJNnbZhZRbjWavuNX8ssQjA6USlmNkXRpoYKTrwjFsA7/1L99KNV8WpHFosZwkUH0
	+GLE=
X-Received: by 2002:a05:6512:2247:b0:549:8c32:78ea with SMTP id 2adb3069b0e04-556f3db2bb9mr271494e87.7.1751634554993;
        Fri, 04 Jul 2025 06:09:14 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-556383bb14bsm246405e87.16.2025.07.04.06.09.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 06:09:13 -0700 (PDT)
Message-ID: <b32229f0-0702-4047-9e71-e3d6ed85f0bf@gmail.com>
Date: Fri, 4 Jul 2025 15:07:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible
 deadlock
To: Andrey Konovalov <andreyknvl@gmail.com>, Yeoreum Yun <yeoreum.yun@arm.com>
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org, bigeasy@linutronix.de, clrkwllms@kernel.org,
 rostedt@goodmis.org, byungchul@sk.com, max.byungchul.park@gmail.com,
 ysk@kzalloc.com, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
 <aGbSCG2B6464Lfz7@e129823.arm.com>
 <CA+fCnZfq570HfXpS1LLUVm0sHXW+rpkSOMLVzafZ2q_ogha47g@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CA+fCnZfq570HfXpS1LLUVm0sHXW+rpkSOMLVzafZ2q_ogha47g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gmP+f62X;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12d
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



On 7/3/25 9:05 PM, Andrey Konovalov wrote:
> On Thu, Jul 3, 2025 at 8:55=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> =
wrote:
>>
>> Hi Andrey,
>>
>>>>
>>>> find_vm_area() couldn't be called in atomic_context.
>>>> If find_vm_area() is called to reports vm area information,
>>>> kasan can trigger deadlock like:
>>>>
>>>> CPU0                                CPU1
>>>> vmalloc();
>>>>  alloc_vmap_area();
>>>>   spin_lock(&vn->busy.lock)
>>>>                                     spin_lock_bh(&some_lock);
>>>>    <interrupt occurs>
>>>>    <in softirq>
>>>>    spin_lock(&some_lock);
>>>>                                     <access invalid address>
>>>>                                     kasan_report();
>>>>                                      print_report();
>>>>                                       print_address_description();
>>>>                                        kasan_find_vm_area();
>>>>                                         find_vm_area();
>>>>                                          spin_lock(&vn->busy.lock) // =
deadlock!
>>>>
>>>> To prevent possible deadlock while kasan reports, remove kasan_find_vm=
_area().
>>>
>>> Can we keep it for when we are in_task()?
>>
>> We couldn't do. since when kasan_find_vm_area() is called,
>> the report_lock is grabbed with irq disabled.
>>
>> Please check discuss with Andrey Ryabinin:
>>   https://lore.kernel.org/all/4599f645-f79c-4cce-b686-494428bb9e2a@gmail=
.com/
>=20
> That was about checking for !in_interrupt(), but I believe checking
> for in_task() is different? But I'm not an expert on these checks.

The problem is that CPU1 grabs '&vn->busy.lock' after the '&some_lock'. Thi=
s could
happen both in task and in irq contexts, so the in_task() guard just won't =
change anything.



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
32229f0-0702-4047-9e71-e3d6ed85f0bf%40gmail.com.
