Return-Path: <kasan-dev+bncBCPILY4NUAFBBIO4WK6QMGQES5V66HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 00C00A32843
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 15:20:30 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2fa1c093f12sf17956520a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 06:20:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739370018; cv=pass;
        d=google.com; s=arc-20240605;
        b=BYuyocwm1aqGM4esnciimrYQEX3dc8QRaw7dz20/Lk1fHCLZ9tAD5YM5OKmmkMBshv
         h2pUi3Gkw/NjyywqRaOX48Tc7zw0842VuqMb0FnpwWExIUk8948Sws/Tp4iNNzBGILOy
         wppd9hEV0ZFknTf5mhBFw3Js7PDzMYZuyyrFSTvMuZxf2wcStk9RBbiqbeRAuDcYLVMB
         bBIu0ykCary2ZeSzmidaEqZKwa3Wtp66hGaY7kz51mBQvYcSnILeKrQFi2TkIwMmA3gt
         GCtQuwvCr9M7FLhyi7wvqoQ1PvLCkLRyJ2LUMYWAjUof1AI0tb1Xs6me/Wio/JWa3Nmk
         GiLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=pKygWF/geQwl2MjFInBf2oSc8nfdEU5SVemjt2BbQpU=;
        fh=Wfs3cnLgj7GXfFasHy9kUrSOqoihEy/HibPY7dACEOE=;
        b=krU5LWt1A1BBUviE9RsLCcJ26UP7yZrWHy9XmXi93MEaBeCQ+j8aDr8ybR4sUDH8e7
         47HQUfamjMt787+LqOoqr84xRVSVRfSutNJTpSXjJnB0JkjodinpBvYEMxelyz/jwGyo
         4t0ARlLk1FuueJPWjOuJJs8dqJD7i7p5g2pTjIWDapo6xZAgyoLcAeNUPy+K/E2ImIhM
         0EMi9igLe8EdlnumJLLCGD32yRyLTdYhMVGNWrrBtr3y+GZmdfk00CyLdarDD+sEuaMF
         I8CBeYoTzyYNeuaXbEhSXJFTAxhg+hdKMf9eUa7rSm1F0dq2UMkuUKpXy09lpNDmhBGF
         Qn5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=d9YK4XsQ;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739370018; x=1739974818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pKygWF/geQwl2MjFInBf2oSc8nfdEU5SVemjt2BbQpU=;
        b=MMo7smoOkcAqUdRJzWBN/7+X4Kst5jeWC/mvQXHTgx9rhHJGY057BynpkMUsw2c3jV
         wohiD8JM4UX/QFpwG3iscREXt1txygmU0UkooL1sT0u0Pve+LGuxrxthqCeSOzGQbRhg
         zXj0YPQ72fWErl+eclohDzmACfljtOJCpEXTzKDp00aoI28izYDDU3z7bbgp3QAq6TEp
         UrvaTg4Y03X5tvaWb0ZBk+nZGmRjZUZzWhObqtjfEMbjS+qmUu0IydMcx7TS/H3ki3o8
         deX74jgYTet0d5bQ7LUYOKaWalf59e+wu2dFoQUVTyjczn4Q97mH4oC4kJQ2N3+kIANJ
         zjAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739370018; x=1739974818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pKygWF/geQwl2MjFInBf2oSc8nfdEU5SVemjt2BbQpU=;
        b=l55YQ8EvFjnvvXNeILgdzAJ5KgzGu+GI1M8FYwSkd3Su0++VGUX99zvlxSpnOcxFsC
         JatAAX1IzgF47WGcRvIH6syoqPmUbSSQFbdUfdWz3MG8zBj8kufYC11idfoNrgpjMXx8
         Ii9JDbDUFkgPq/eexROC1WFb3rJLkZIIbKA0rnkVCcZ/5mP8yaMU8e+Jy+Oiyn6K3Jio
         XfrImn6SsHVDnek8ARKS2LOoOKzDS+Rv4iL1YA+chUFUFLnM0tRS6TcdEtpWrjH85Xwa
         0uHnt82xPGM2wm1KaZW9kRuMqPtK/0+7Rn24y4FujaiLPhPBIuvNGTr2jZ+XOQK+IwtU
         g31g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWh55ZUS47wj5D27UwxFrutfM3eYGcyOlnc/X4jJSMDupS08sxqAEa7C24ZE8mOWqGy8oN7GA==@lfdr.de
X-Gm-Message-State: AOJu0Yy24YkcFm60gui7/4m6DKknlq7wzbO/GgXEtDxDg+jXdYofiBvv
	a0qkRFg/Jq9SqYdd7jTflhTu27nXM+d3zRHgYaSMrobpxR8Ld8we
X-Google-Smtp-Source: AGHT+IH21KRJ5gJFm1ZYPRl/80kzp2dmxxaeoz1/Ioi1F2quDlHiVGe3HZ6ENErVFMPY6qn6nfIdVQ==
X-Received: by 2002:a17:90b:2743:b0:2fa:17dd:6afa with SMTP id 98e67ed59e1d1-2fbf5c0f614mr5925332a91.17.1739370018249;
        Wed, 12 Feb 2025 06:20:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3503:b0:2e7:8a36:a9b7 with SMTP id
 98e67ed59e1d1-2fa228f2df3ls268963a91.1.-pod-prod-03-us; Wed, 12 Feb 2025
 06:20:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUa1CxkzC7RQaM+Wo1iKRM0mKembEbvuA1p4nI3y25qCX7FSf3FqYxk/Pq6CFssb0t3jH8Atr1MoEE=@googlegroups.com
X-Received: by 2002:a17:90b:540f:b0:2fa:2252:f438 with SMTP id 98e67ed59e1d1-2fbf5c711f3mr5251447a91.30.1739370016858;
        Wed, 12 Feb 2025 06:20:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739370016; cv=none;
        d=google.com; s=arc-20240605;
        b=M9u3kznK5d+1ewVxivv/E7cG0Xq0wsbEHztWkQi89mkabumTkZKEsdoIiCIM+7oTiR
         8QAirHKTia4iTr3T5r+uZCXXLS4YJWKme06+lfLwA8Lp6tVcyMJkdNNzr+x/TPIfM+R9
         3UjrEGJlXBL/Sny8OuMm4ExX9kj1wGTgOemisNSvvHp66dIpRyRjrb1Oh9Er/qEsWG8o
         Vpn9A5y7OoUTz6zg98HhP7n7AC4HzDGpQgr1Dot38Y5UFoic2NhzI4Kh4A3alDLSB+8i
         k2hbwwy2ARkLR5OXY8kFpQKHPE01WG6hIHC01V+uSLXOISF2Z/vf8y6P8dIMK8yE4/QD
         nMnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:dkim-signature;
        bh=UaytPCHhKVjGWAsx5bfcp4r8jWAvoXQuesD8NM57z/o=;
        fh=0jzeDJVOBIIFbNBbPF4nIlR6MJx8xeJi8l6SqfS4zgU=;
        b=NNT5wLNd23S1LWuPCjFvvlA4ulDRJ/uRNn7uHT6GGopY9MA+ohqpRaeJ1za7Q6JR8d
         qHzz2VzqyiXaxXMmU9xuGZq4iXPqDyTE1SoMUKfGfQapdi0KV0Z4ftPV5hyxFz6shigA
         M5fjcJx8Mb7Gk/GsdSFY3k/mGCJ/DF4NrRBW7xrRY9bI664d0RyCaVVUgrlvnBLvDA2L
         5xik7XSQt5uqH3vRYQY40/91G+Trhej8XPMUsAM+Wz+byvel7PWTV27FJIuoZOeVmutZ
         f0Tfp9JmJZAz4s+9SjuwcYQ0qqD09BoookSjHK9qL63Cy3HFnyeljTmfwHSg3VlW+XLS
         qCDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=d9YK4XsQ;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fbf9947ddfsi72078a91.3.2025.02.12.06.20.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 06:20:16 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-oo1-f69.google.com (mail-oo1-f69.google.com
 [209.85.161.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-550-pl9SJ8ZmPPm7r9zJUQF5xg-1; Wed, 12 Feb 2025 09:20:14 -0500
X-MC-Unique: pl9SJ8ZmPPm7r9zJUQF5xg-1
X-Mimecast-MFC-AGG-ID: pl9SJ8ZmPPm7r9zJUQF5xg
Received: by mail-oo1-f69.google.com with SMTP id 006d021491bc7-5f7fd71ded3so6229802eaf.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 06:20:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGsKeL7rwULyPFqSDhXLv7yreGI5iv8vlR5dIFABBS9Ex0Sm471iRd2iEJPId37uXMdjQ1cwT3bFU=@googlegroups.com
X-Gm-Gg: ASbGncvXranqoGgL1+//CJjSV/R9Unlamw5veZipFc7FuxBINXrsgD/lEI99jy62hoo
	1H/fIeW+QtRqz3iCYNdgF5YQ7a828cuqakeLd8eYc8/nZCONEOBCl/kxtDzuHJQjirRRqaZd0FN
	irLNHgWKjLPAU4KUmYG/3fuGlvZph/TqMoPaaSok4VQ33fIqzEx1y7bOyeDhtAvaM4WsVMKK/DS
	SrmpPNjKEG5tbXZKH3pm2Q5fBFCWajpV850kZG1sEGFaMsRccxzOgzz3AS3OXoxw3G2uKYIY4/o
	1UHHAbWrqWZDHHxUzDKxDzWqcJHz/J00QEQHp7b/IszsL4li
X-Received: by 2002:a05:6830:2585:b0:723:31c3:c511 with SMTP id 46e09a7af769-726f1a4c68cmr2366737a34.0.1739370013753;
        Wed, 12 Feb 2025 06:20:13 -0800 (PST)
X-Received: by 2002:a05:6830:2585:b0:723:31c3:c511 with SMTP id 46e09a7af769-726f1a4c68cmr2366713a34.0.1739370013361;
        Wed, 12 Feb 2025 06:20:13 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 46e09a7af769-726fd014926sm62615a34.32.2025.02.12.06.20.11
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 06:20:12 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <73dd903e-d670-4e97-8df5-cc861a6015ec@redhat.com>
Date: Wed, 12 Feb 2025 09:20:10 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 3/3] locking/lockdep: Disable KASAN instrumentation of
 lockdep.c
To: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will.deacon@arm.com>, linux-kernel@vger.kernel.org,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
References: <20250210042612.978247-1-longman@redhat.com>
 <20250210042612.978247-4-longman@redhat.com> <Z6w4UlCQa_g1OHlN@Mac.home>
 <CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.com>
In-Reply-To: <CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: U5TxX1zT4q-80fEPc7NvdVIoMuv6-Wo6yHCkufSIx44_1739370014
X-Mimecast-Originator: redhat.com
Content-Type: multipart/alternative;
 boundary="------------NA1qsaaFt71wJQPAnCAK3lma"
Content-Language: en-US
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=d9YK4XsQ;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

This is a multi-part message in MIME format.
--------------NA1qsaaFt71wJQPAnCAK3lma
Content-Type: text/plain; charset="UTF-8"; format=flowed


On 2/12/25 6:30 AM, Marco Elver wrote:
> On Wed, 12 Feb 2025 at 06:57, Boqun Feng<boqun.feng@gmail.com> wrote:
>> [Cc KASAN]
>>
>> A Reviewed-by or Acked-by from KASAN would be nice, thanks!
>>
>> Regards,
>> Boqun
>>
>> On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
>>> Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
>>> Each of them can significantly slow down the speed of a debug kernel.
>>> Enabling KASAN instrumentation of the LOCKDEP code will further slow
>>> thing down.
>>>
>>> Since LOCKDEP is a high overhead debugging tool, it will never get
>>> enabled in a production kernel. The LOCKDEP code is also pretty mature
>>> and is unlikely to get major changes. There is also a possibility of
>>> recursion similar to KCSAN.
>>>
>>> To evaluate the performance impact of disabling KASAN instrumentation
>>> of lockdep.c, the time to do a parallel build of the Linux defconfig
>>> kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
>>> and an arm64 system were used as test beds. Two sets of non-RT and RT
>>> kernels with similar configurations except mainly CONFIG_PREEMPT_RT
>>> were used for evaulation.
>>>
>>> For the Skylake system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 0m47.642s             4m19.811s
>>>    Debug kernel                        2m11.108s (x2.8)     38m20.467s (x8.9)
>>>    Debug kernel (patched)      1m49.602s (x2.3)     31m28.501s (x7.3)
>>>    Debug kernel
>>>    (patched + mitigations=off)         1m30.988s (x1.9)     26m41.993s (x6.2)
>>>
>>>    RT kernel (baseline)                0m54.871s             7m15.340s
>>>    RT debug kernel             6m07.151s (x6.7)    135m47.428s (x18.7)
>>>    RT debug kernel (patched)   3m42.434s (x4.1)     74m51.636s (x10.3)
>>>    RT debug kernel
>>>    (patched + mitigations=off)         2m40.383s (x2.9)     57m54.369s (x8.0)
>>>
>>> For the Zen 2 system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 1m42.806s            39m48.714s
>>>    Debug kernel                        4m04.524s (x2.4)    125m35.904s (x3.2)
>>>    Debug kernel (patched)      3m56.241s (x2.3)    127m22.378s (x3.2)
>>>    Debug kernel
>>>    (patched + mitigations=off)         2m38.157s (x1.5)     92m35.680s (x2.3)
>>>
>>>    RT kernel (baseline)                 1m51.500s           14m56.322s
>>>    RT debug kernel             16m04.962s (x8.7)   244m36.463s (x16.4)
>>>    RT debug kernel (patched)    9m09.073s (x4.9)   129m28.439s (x8.7)
>>>    RT debug kernel
>>>    (patched + mitigations=off)          3m31.662s (x1.9)    51m01.391s (x3.4)
>>>
>>> For the arm64 system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 1m56.844s             8m47.150s
>>>    Debug kernel                        3m54.774s (x2.0)     92m30.098s (x10.5)
>>>    Debug kernel (patched)      3m32.429s (x1.8)     77m40.779s (x8.8)
>>>
>>>    RT kernel (baseline)                 4m01.641s           18m16.777s
>>>    RT debug kernel             19m32.977s (x4.9)   304m23.965s (x16.7)
>>>    RT debug kernel (patched)   16m28.354s (x4.1)   234m18.149s (x12.8)
>>>
>>> Turning the mitigations off doesn't seems to have any noticeable impact
>>> on the performance of the arm64 system. So the mitigation=off entries
>>> aren't included.
>>>
>>> For the x86 CPUs, cpu mitigations has a much bigger impact on
>>> performance, especially the RT debug kernel. The SRSO mitigation in
>>> Zen 2 has an especially big impact on the debug kernel. It is also the
>>> majority of the slowdown with mitigations on. It is because the patched
>>> ret instruction slows down function returns. A lot of helper functions
>>> that are normally compiled out or inlined may become real function
>>> calls in the debug kernel. The KASAN instrumentation inserts a lot
>>> of __asan_loadX*() and __kasan_check_read() function calls to memory
>>> access portion of the code. The lockdep's __lock_acquire() function,
>>> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
>>> added with KASAN instrumentation. Of course, the actual numbers may vary
>>> depending on the compiler used and the exact version of the lockdep code.
> For completeness-sake, we'd also have to compare with
> CONFIG_KASAN_INLINE=y, which gets rid of the __asan_ calls (not the
> explicit __kasan_ checks). But I leave it up to you - I'm aware it
> results in slow-downs, too. ;-)
I see. I don't realize that there is such an Kconfig option. Will try it 
out to see how it works out.
>
>>> With the newly added rtmutex and lockdep lock events, the relevant
>>> event counts for the test runs with the Skylake system were:
>>>
>>>    Event type          Debug kernel    RT debug kernel
>>>    ----------          ------------    ---------------
>>>    lockdep_acquire     1,968,663,277   5,425,313,953
>>>    rtlock_slowlock          -            401,701,156
>>>    rtmutex_slowlock         -                139,672
>>>
>>> The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
>>> non-RT debug kernel with the same workload. Since the __lock_acquire()
>>> function is a big hitter in term of performance slowdown, this makes
>>> the RT debug kernel much slower than the non-RT one. The average lock
>>> nesting depth is likely to be higher in the RT debug kernel too leading
>>> to longer execution time in the __lock_acquire() function.
>>>
>>> As the small advantage of enabling KASAN instrumentation to catch
>>> potential memory access error in the lockdep debugging tool is probably
>>> not worth the drawback of further slowing down a debug kernel, disable
>>> KASAN instrumentation in the lockdep code to allow the debug kernels
>>> to regain some performance back, especially for the RT debug kernels.
> It's not about catching a bug in the lockdep code, but rather guard
> against bugs in code that allocated the storage for some
> synchronization object. Since lockdep state is embedded in each
> synchronization object, lockdep checking code may be passed a
> reference to garbage data, e.g. on use-after-free (or even
> out-of-bounds if there's an array of sync objects). In that case, all
> bets are off and lockdep may produce random false reports. Sure the
> system is already in a bad state at that point, but it's going to make
> debugging much harder.
With CONFIG_LOCKDEP on, the lock_acquire() function is usually the first 
call before the lock is acquired. So it is likely the one that reports 
these memory bug. However, the lock itself will eventually be accessed. 
KASAN instrumentation there should be able to catch the same problem.
>
> Our approach has always been to ensure that as soon as there's an
> error state detected it's reported as soon as we can, before it
> results in random failure as execution continues (e.g. bad lock
> reports).
>
> To guard against that, I would propose adding carefully placed
> kasan_check_byte() in lockdep code.

OK, will look into that.

Thanks,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/73dd903e-d670-4e97-8df5-cc861a6015ec%40redhat.com.

--------------NA1qsaaFt71wJQPAnCAK3lma
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body>
    <p><br>
    </p>
    <div class=3D"moz-cite-prefix">On 2/12/25 6:30 AM, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.=
com">
      <pre wrap=3D"" class=3D"moz-quote-pre">On Wed, 12 Feb 2025 at 06:57, =
Boqun Feng <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:boqun.feng@gma=
il.com">&lt;boqun.feng@gmail.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre wrap=3D"" class=3D"moz-quote-pre">
[Cc KASAN]

A Reviewed-by or Acked-by from KASAN would be nice, thanks!

Regards,
Boqun

On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
</pre>
        <blockquote type=3D"cite">
          <pre wrap=3D"" class=3D"moz-quote-pre">Both KASAN and LOCKDEP are=
 commonly enabled in building a debug kernel.
Each of them can significantly slow down the speed of a debug kernel.
Enabling KASAN instrumentation of the LOCKDEP code will further slow
thing down.

Since LOCKDEP is a high overhead debugging tool, it will never get
enabled in a production kernel. The LOCKDEP code is also pretty mature
and is unlikely to get major changes. There is also a possibility of
recursion similar to KCSAN.

To evaluate the performance impact of disabling KASAN instrumentation
of lockdep.c, the time to do a parallel build of the Linux defconfig
kernel was used as the benchmark. Two x86-64 systems (Skylake &amp; Zen 2)
and an arm64 system were used as test beds. Two sets of non-RT and RT
kernels with similar configurations except mainly CONFIG_PREEMPT_RT
were used for evaulation.

For the Skylake system:

  Kernel                      Run time            Sys time
  ------                      --------            --------
  Non-debug kernel (baseline) 0m47.642s             4m19.811s
  Debug kernel                        2m11.108s (x2.8)     38m20.467s (x8.9=
)
  Debug kernel (patched)      1m49.602s (x2.3)     31m28.501s (x7.3)
  Debug kernel
  (patched + mitigations=3Doff)         1m30.988s (x1.9)     26m41.993s (x6=
.2)

  RT kernel (baseline)                0m54.871s             7m15.340s
  RT debug kernel             6m07.151s (x6.7)    135m47.428s (x18.7)
  RT debug kernel (patched)   3m42.434s (x4.1)     74m51.636s (x10.3)
  RT debug kernel
  (patched + mitigations=3Doff)         2m40.383s (x2.9)     57m54.369s (x8=
.0)

For the Zen 2 system:

  Kernel                      Run time            Sys time
  ------                      --------            --------
  Non-debug kernel (baseline) 1m42.806s            39m48.714s
  Debug kernel                        4m04.524s (x2.4)    125m35.904s (x3.2=
)
  Debug kernel (patched)      3m56.241s (x2.3)    127m22.378s (x3.2)
  Debug kernel
  (patched + mitigations=3Doff)         2m38.157s (x1.5)     92m35.680s (x2=
.3)

  RT kernel (baseline)                 1m51.500s           14m56.322s
  RT debug kernel             16m04.962s (x8.7)   244m36.463s (x16.4)
  RT debug kernel (patched)    9m09.073s (x4.9)   129m28.439s (x8.7)
  RT debug kernel
  (patched + mitigations=3Doff)          3m31.662s (x1.9)    51m01.391s (x3=
.4)

For the arm64 system:

  Kernel                      Run time            Sys time
  ------                      --------            --------
  Non-debug kernel (baseline) 1m56.844s             8m47.150s
  Debug kernel                        3m54.774s (x2.0)     92m30.098s (x10.=
5)
  Debug kernel (patched)      3m32.429s (x1.8)     77m40.779s (x8.8)

  RT kernel (baseline)                 4m01.641s           18m16.777s
  RT debug kernel             19m32.977s (x4.9)   304m23.965s (x16.7)
  RT debug kernel (patched)   16m28.354s (x4.1)   234m18.149s (x12.8)

Turning the mitigations off doesn't seems to have any noticeable impact
on the performance of the arm64 system. So the mitigation=3Doff entries
aren't included.

For the x86 CPUs, cpu mitigations has a much bigger impact on
performance, especially the RT debug kernel. The SRSO mitigation in
Zen 2 has an especially big impact on the debug kernel. It is also the
majority of the slowdown with mitigations on. It is because the patched
ret instruction slows down function returns. A lot of helper functions
that are normally compiled out or inlined may become real function
calls in the debug kernel. The KASAN instrumentation inserts a lot
of __asan_loadX*() and __kasan_check_read() function calls to memory
access portion of the code. The lockdep's __lock_acquire() function,
for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
added with KASAN instrumentation. Of course, the actual numbers may vary
depending on the compiler used and the exact version of the lockdep code.
</pre>
        </blockquote>
      </blockquote>
      <pre wrap=3D"" class=3D"moz-quote-pre">
For completeness-sake, we'd also have to compare with
CONFIG_KASAN_INLINE=3Dy, which gets rid of the __asan_ calls (not the
explicit __kasan_ checks). But I leave it up to you - I'm aware it
results in slow-downs, too. ;-)</pre>
    </blockquote>
    I see. I don't realize that there is such an Kconfig option. Will
    try it out to see how it works out.<br>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.=
com">
      <pre wrap=3D"" class=3D"moz-quote-pre">

</pre>
      <blockquote type=3D"cite">
        <blockquote type=3D"cite">
          <pre wrap=3D"" class=3D"moz-quote-pre">With the newly added rtmut=
ex and lockdep lock events, the relevant
event counts for the test runs with the Skylake system were:

  Event type          Debug kernel    RT debug kernel
  ----------          ------------    ---------------
  lockdep_acquire     1,968,663,277   5,425,313,953
  rtlock_slowlock          -            401,701,156
  rtmutex_slowlock         -                139,672

The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
non-RT debug kernel with the same workload. Since the __lock_acquire()
function is a big hitter in term of performance slowdown, this makes
the RT debug kernel much slower than the non-RT one. The average lock
nesting depth is likely to be higher in the RT debug kernel too leading
to longer execution time in the __lock_acquire() function.

As the small advantage of enabling KASAN instrumentation to catch
potential memory access error in the lockdep debugging tool is probably
not worth the drawback of further slowing down a debug kernel, disable
KASAN instrumentation in the lockdep code to allow the debug kernels
to regain some performance back, especially for the RT debug kernels.
</pre>
        </blockquote>
      </blockquote>
      <pre wrap=3D"" class=3D"moz-quote-pre">
It's not about catching a bug in the lockdep code, but rather guard
against bugs in code that allocated the storage for some
synchronization object. Since lockdep state is embedded in each
synchronization object, lockdep checking code may be passed a
reference to garbage data, e.g. on use-after-free (or even
out-of-bounds if there's an array of sync objects). In that case, all
bets are off and lockdep may produce random false reports. Sure the
system is already in a bad state at that point, but it's going to make
debugging much harder.</pre>
    </blockquote>
    With CONFIG_LOCKDEP on, the lock_acquire() function is usually the
    first call before the lock is acquired. So it is likely the one that
    reports these memory bug. However, the lock itself will eventually
    be accessed. KASAN instrumentation there should be able to catch the
    same problem. <br>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.=
com">
      <pre wrap=3D"" class=3D"moz-quote-pre">

Our approach has always been to ensure that as soon as there's an
error state detected it's reported as soon as we can, before it
results in random failure as execution continues (e.g. bad lock
reports).

To guard against that, I would propose adding carefully placed
kasan_check_byte() in lockdep code.</pre>
    </blockquote>
    <p>OK, will look into that.</p>
    <p>Thanks,<br>
      Longman<span style=3D"white-space: pre-wrap">
</span></p>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/73dd903e-d670-4e97-8df5-cc861a6015ec%40redhat.com?utm_medium=3Dem=
ail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/73dd90=
3e-d670-4e97-8df5-cc861a6015ec%40redhat.com</a>.<br />

--------------NA1qsaaFt71wJQPAnCAK3lma--

