Return-Path: <kasan-dev+bncBCPILY4NUAFBBPNBXG6QMGQE6HXIV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C7D8A34F01
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:06:23 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d190258f86sf6242145ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739477182; cv=pass;
        d=google.com; s=arc-20240605;
        b=cPVYAEIdYS1Pt/YJYmZjWJXKWtFsUDLymi6YlmHVOjtlDoyEfgMhMEqhRnuQSOgy/t
         VyK/CCay4Q3Ll6HbyC7sdCnKuRWTOFZC+4y/jCnDgqHygZxBR8U7bpyJcW3mMBkDxk+a
         ZGMw7ugbcugRpwHldbnnxbI1Ijs55XuBehyRzR57dPX4FMa416lN4j0cM6dmMvNk+f5h
         JqJmABZzERnMqxNxDeDCyBr6+UyqlM+Sr2l5/nN2ChAvFfIP02/ixLVQeabbf/WwBFW5
         u1+1SUUY48lhxZOPf/MNqeutnl4XjweoOJ8WgOZlInzTf1b5Cw8FeN7IUwIqK5boAJBo
         7EqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=daR2nLPt7nnccdGxGqq/vRZyW8ROtp9keNYJe7j+b1Y=;
        fh=0+60W1LuQ4sE8xGhKuJq113S6BSkRUZoPH4OZJKerkU=;
        b=ROA6vNp6fFlG2xW+2MyrzqQdZRx6di15WH8SFNWQXTjpc7H8DwQ78lRyEgRsoc9sjO
         9dMIqAkcpvJ7Viieds+yqNgvhxBG3O/g6czbykIz80e43aqQkBGAjyM6VQHIySL3zRaE
         mGSOAM8bsY61N0XVw57NiHPTK8pCe7vg8urxzAZRK3NRgE0FIqgNTx2bQv5RBERAdzov
         ga8STx9wRNTP4EpbAPgRKWfSnxV9ednzaYSDBzOgaWn7ncGKW/FZWuH8WG/z0d3p7umn
         6KQ08/lRODrfhme30O/pDR3Ny4APqYSlPwVGqD+2VTcb0D3UwLbXDwfUQ9VLWrtbq+iW
         6tPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FNXxpDi+;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739477182; x=1740081982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=daR2nLPt7nnccdGxGqq/vRZyW8ROtp9keNYJe7j+b1Y=;
        b=ia3TnUuq9UP9sZY6+9eo1KcIGCAJ/jzG/DcGXFo7jNufZBw6JaSWpeGFRJTmZ9OtNj
         FaTbErdVoG5crV48lM4wzDhjZHgI80dd4F8Etpwjp0nXMkjsqAe7UiGU3A5wbg/7W3MK
         4HTnrafStmife4a94n9vNY0B8bYGJZedK1QrZ+1X0Li79jhtKSlqkUzzs24uS0W7Mymr
         NosGsiW2t3sjDEv9VLTZmZ/JDzAcrjV/wjymAltu9w0nearx/rgEC/UsRiyxZt/kT6h2
         7JodsQMu1qo14aoTJOXOoI0rzBX8GZIvQY34l0JyjbuU0d2vTNT/R9apFX2ZJVVWF0ZG
         wz5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739477182; x=1740081982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=daR2nLPt7nnccdGxGqq/vRZyW8ROtp9keNYJe7j+b1Y=;
        b=CzU6bvCEvJLGGaLFQSLWvhWnoIv5HvFvli0D9sLqeNPcR27p+I7IyTjEEXlHBcZAea
         f1R+Rq6Eo3P3vMIwJqW7YAtFmWL4Gq+vPx5rf+/ZMsFC7s3vzKf2rAgs2wLQxGST8IDF
         uKfGoUygqcOTNdEFlb/yuYJaYtLmRjLWXqea/h4Rfj9nOPrPO10jKAKHlF8jYlGzreuc
         7MF3g/WMFspSG1yAOfUk7gAqyPqMVf/9NVXInS7W1jBxFdirJ2tcney6l/M4xuI//5D8
         XM50OQMu37nkMfCRqtuT7RHDVimNyYmHf9cdfujIwnn0QYWBpUEvoxySSDx4wZ4dx+e0
         /HAQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUs+fZph3/31djr3hJ7DgVqydshI/TFci1wDWFmfRSY5x3+A4jLJc56n7Jhk02FF6m9GX5Z8Q==@lfdr.de
X-Gm-Message-State: AOJu0YxFtupnPi9sYUW0/+b5DP6T6BsawZ6ebmSnb9vLxokynI97fpjF
	AWznaH3Lc7D6NBgt7NMrcpOKt3yfF4vAeLzdyHZJtQWlCyXtUaGg
X-Google-Smtp-Source: AGHT+IEQXXAy/tBxNr4xSiW3DY+Xcn5/tqDKCw07iTrm3fq79il9RreynW7L+/5BBQRvX9v8PMKdMQ==
X-Received: by 2002:a05:6e02:1aa1:b0:3cf:ba90:6ad9 with SMTP id e9e14a558f8ab-3d18d05b3b3mr28552165ab.9.1739477182106;
        Thu, 13 Feb 2025 12:06:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE92Fnv2ug9rS2qRvoZOFNFICymXZuiiJ3mVJGv88C+Ew==
Received: by 2002:a92:cecc:0:b0:3d1:54c3:2ef5 with SMTP id e9e14a558f8ab-3d18c247915ls4486645ab.0.-pod-prod-00-us;
 Thu, 13 Feb 2025 12:06:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUmZaC9mZIlwGRDQgJ51LcS/p/dN3mG6YIre8Ve3S58QF11SaN7SVrRGJGy50jLM4gPoAROO9DwUrQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1205:b0:3d1:84ad:165e with SMTP id e9e14a558f8ab-3d18cd0864emr29535725ab.7.1739477181229;
        Thu, 13 Feb 2025 12:06:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739477181; cv=none;
        d=google.com; s=arc-20240605;
        b=SJJuFpZCSqj6OMEFP/uTFtTG9aFXbcgDalrOZ49W4uMtmJfu1BFjNeV8hYnZJ2VQ7x
         kv1yLTzU2junRjaVmBdbOPuALB7zI7iNPCfp+vxItV3mXAWXGRrs44XWxXLmmD1FB+e5
         UAafJbAbqt/N/jqwRmSNfJMtXsgLBPVYhPY7UgAP1YpwMXSJyPVZ9UFBf1gOUyjbAezY
         i279K4pTK6cTbaINgNgQD8GDf0ucnnmEUi4z9ObscQZ0zF9hOhUcAixbpxZHJ7zaTyLO
         qtc+L8pSCm4GrQa4y558WJnDbysL85Wm7UrwpzMpXQf1Rh+5EKiJYmXgPZx9mAqXVBUD
         A9hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=cs7CBbdif2NtPjYqaugNyMN77mXyI18t95wiVnROh6Y=;
        fh=wGKML0ClTCMXDWs3gLYDHD6JSbRDtn6Ni4aaccMuGks=;
        b=UOKDKI2loSRRHMIokV2QLGbEf57HDtct5W53CDL/EXPk/cRgvG9FLZsV/Po9Gp71am
         tFTcEL40oGYor3oYR+h+xUQqnoh0JTfVX5EqzZVxia0F49W6fM1C7fOElgySkDYERb+d
         ihG3YBoOP5EbG7c4SWcC58iTs+iN2tmST29MGZI3Nj9zGtTXYyLaUaX3As2FkAASDV6f
         L+LEteP13XjJMnXrxgnB81VTWTCHYFIri3//5ww657RZorE+iDkqSG/I/sV1zLZd3Sw0
         TLr5oBRhXHYgacUqgA6TOTvMJD3GkG3IPXjoHWhMnrhueA+f9Muoep7528WEvixCMj8b
         PFQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FNXxpDi+;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ed28285eb4si86763173.5.2025.02.13.12.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:06:21 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qk1-f198.google.com (mail-qk1-f198.google.com
 [209.85.222.198]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-515-Vo5NOXPyPB2Det70koEy8g-1; Thu, 13 Feb 2025 15:06:19 -0500
X-MC-Unique: Vo5NOXPyPB2Det70koEy8g-1
X-Mimecast-MFC-AGG-ID: Vo5NOXPyPB2Det70koEy8g
Received: by mail-qk1-f198.google.com with SMTP id af79cd13be357-7c05f4f174cso216784185a.0
        for <kasan-dev@googlegroups.com>; Thu, 13 Feb 2025 12:06:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV39n8BvfMaXSNODFhhP4ToLBg64Nm/zEJzBGV4PoGwvOL0bH7OFckmnFv2YxjNQogcQFVOgn69c4Q=@googlegroups.com
X-Gm-Gg: ASbGnctbUIjtYNVeFF7rxR7aJOGdK6aAQf+nQq4MDtRdHVRsTdA7OsahB54n/NSt10u
	qF8isu1dVOdzC3y4hklsbBdL6WZhdlvfety0KGQDQh/hMi63m7o71kjmQcTe0Bnf3dF+tFnhvOz
	63NTde9RB0qIhqtCfcxnyx1mE+Lf57X9isYcjIojdooeI5fzHSpkczRVVJzl40EsJPw5trGwBf9
	2MtwDDi6SGwPFHKda0Ts5KUxTGVwKqOOxeNliloVb4ntoue3a18KCGYLKy01xJMxc0rrWm0MObO
	0n3F57X+50Bu1u2GLCgYmHKwiGjX3TTarGjXG5VJqf/ztuVj
X-Received: by 2002:a05:620a:2493:b0:7b6:d5b2:e58 with SMTP id af79cd13be357-7c07a9c2860mr709728885a.18.1739477178373;
        Thu, 13 Feb 2025 12:06:18 -0800 (PST)
X-Received: by 2002:a05:620a:2493:b0:7b6:d5b2:e58 with SMTP id af79cd13be357-7c07a9c2860mr709724785a.18.1739477178033;
        Thu, 13 Feb 2025 12:06:18 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7c07c5f3730sm129390585a.20.2025.02.13.12.06.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Feb 2025 12:06:17 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <45f90875-d4b0-4cea-b857-752bc93fd48b@redhat.com>
Date: Thu, 13 Feb 2025 15:06:16 -0500
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
 <a6993bbd-ec8a-40e1-9ef2-74f920642188@redhat.com>
In-Reply-To: <a6993bbd-ec8a-40e1-9ef2-74f920642188@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: N-tQebkohtTyUlu-m7u8O-cqDa-zk5nCZ1hIS7kdTbk_1739477178
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FNXxpDi+;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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

On 2/12/25 11:57 AM, Waiman Long wrote:
> On 2/12/25 6:30 AM, Marco Elver wrote:
>> On Wed, 12 Feb 2025 at 06:57, Boqun Feng <boqun.feng@gmail.com> wrote:
>>> [Cc KASAN]
>>>
>>> A Reviewed-by or Acked-by from KASAN would be nice, thanks!
>>>
>>> Regards,
>>> Boqun
>>>
>>> On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
>>>> Both KASAN and LOCKDEP are commonly enabled in building a debug=20
>>>> kernel.
>>>> Each of them can significantly slow down the speed of a debug kernel.
>>>> Enabling KASAN instrumentation of the LOCKDEP code will further slow
>>>> thing down.
>>>>
>>>> Since LOCKDEP is a high overhead debugging tool, it will never get
>>>> enabled in a production kernel. The LOCKDEP code is also pretty mature
>>>> and is unlikely to get major changes. There is also a possibility of
>>>> recursion similar to KCSAN.
>>>>
>>>> To evaluate the performance impact of disabling KASAN instrumentation
>>>> of lockdep.c, the time to do a parallel build of the Linux defconfig
>>>> kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
>>>> and an arm64 system were used as test beds. Two sets of non-RT and RT
>>>> kernels with similar configurations except mainly CONFIG_PREEMPT_RT
>>>> were used for evaulation.
>>>>
>>>> For the Skylake system:
>>>>
>>>> =C2=A0=C2=A0 Kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Run time=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Sys time
>>>> =C2=A0=C2=A0 ------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------
>>>> =C2=A0=C2=A0 Non-debug kernel (baseline) 0m47.642s 4m19.811s
>>>> =C2=A0=C2=A0 Debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 2m11.108s (x2.8) 38m20.467s=20
>>>> (x8.9)
>>>> =C2=A0=C2=A0 Debug kernel (patched)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1m49=
.602s (x2.3) 31m28.501s (x7.3)
>>>> =C2=A0=C2=A0 Debug kernel
>>>> =C2=A0=C2=A0 (patched + mitigations=3Doff)=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 1m30.988s (x1.9) 26m41.993s=20
>>>> (x6.2)
>>>>
>>>> =C2=A0=C2=A0 RT kernel (baseline)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0m54.871s 7m15.340s
>>>> =C2=A0=C2=A0 RT debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 6m07.151s (x6.7) 135m47.428s (x18.7)
>>>> =C2=A0=C2=A0 RT debug kernel (patched)=C2=A0=C2=A0 3m42.434s (x4.1) 74=
m51.636s (x10.3)
>>>> =C2=A0=C2=A0 RT debug kernel
>>>> =C2=A0=C2=A0 (patched + mitigations=3Doff)=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 2m40.383s (x2.9) 57m54.369s=20
>>>> (x8.0)
>>>>
>>>> For the Zen 2 system:
>>>>
>>>> =C2=A0=C2=A0 Kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Run time=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Sys time
>>>> =C2=A0=C2=A0 ------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------
>>>> =C2=A0=C2=A0 Non-debug kernel (baseline) 1m42.806s 39m48.714s
>>>> =C2=A0=C2=A0 Debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 4m04.524s (x2.4) 125m35.904s=20
>>>> (x3.2)
>>>> =C2=A0=C2=A0 Debug kernel (patched)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 3m56=
.241s (x2.3) 127m22.378s (x3.2)
>>>> =C2=A0=C2=A0 Debug kernel
>>>> =C2=A0=C2=A0 (patched + mitigations=3Doff)=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 2m38.157s (x1.5) 92m35.680s=20
>>>> (x2.3)
>>>>
>>>> =C2=A0=C2=A0 RT kernel (baseline)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1m51.500s 14m5=
6.322s
>>>> =C2=A0=C2=A0 RT debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 16m04.962s (x8.7) 244m36.463s (x16.4)
>>>> =C2=A0=C2=A0 RT debug kernel (patched)=C2=A0=C2=A0=C2=A0 9m09.073s (x4=
.9) 129m28.439s (x8.7)
>>>> =C2=A0=C2=A0 RT debug kernel
>>>> =C2=A0=C2=A0 (patched + mitigations=3Doff)=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 3m31.662s (x1.9) 51m01.391s=20
>>>> (x3.4)
>>>>
>>>> For the arm64 system:
>>>>
>>>> =C2=A0=C2=A0 Kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Run time=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 Sys time
>>>> =C2=A0=C2=A0 ------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 --------
>>>> =C2=A0=C2=A0 Non-debug kernel (baseline) 1m56.844s 8m47.150s
>>>> =C2=A0=C2=A0 Debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 3m54.774s (x2.0) 92m30.098s=20
>>>> (x10.5)
>>>> =C2=A0=C2=A0 Debug kernel (patched)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 3m32=
.429s (x1.8) 77m40.779s (x8.8)
>>>>
>>>> =C2=A0=C2=A0 RT kernel (baseline)=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 4m01.641s 18m1=
6.777s
>>>> =C2=A0=C2=A0 RT debug kernel=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 19m32.977s (x4.9) 304m23.965s (x16.7)
>>>> =C2=A0=C2=A0 RT debug kernel (patched)=C2=A0=C2=A0 16m28.354s (x4.1) 2=
34m18.149s (x12.8)
>>>>
>>>> Turning the mitigations off doesn't seems to have any noticeable=20
>>>> impact
>>>> on the performance of the arm64 system. So the mitigation=3Doff entrie=
s
>>>> aren't included.
>>>>
>>>> For the x86 CPUs, cpu mitigations has a much bigger impact on
>>>> performance, especially the RT debug kernel. The SRSO mitigation in
>>>> Zen 2 has an especially big impact on the debug kernel. It is also the
>>>> majority of the slowdown with mitigations on. It is because the=20
>>>> patched
>>>> ret instruction slows down function returns. A lot of helper functions
>>>> that are normally compiled out or inlined may become real function
>>>> calls in the debug kernel. The KASAN instrumentation inserts a lot
>>>> of __asan_loadX*() and __kasan_check_read() function calls to memory
>>>> access portion of the code. The lockdep's __lock_acquire() function,
>>>> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
>>>> added with KASAN instrumentation. Of course, the actual numbers may=20
>>>> vary
>>>> depending on the compiler used and the exact version of the lockdep=20
>>>> code.
>> For completeness-sake, we'd also have to compare with
>> CONFIG_KASAN_INLINE=3Dy, which gets rid of the __asan_ calls (not the
>> explicit __kasan_ checks). But I leave it up to you - I'm aware it
>> results in slow-downs, too. ;-)

That is not correct. Setting CONFIG_KASAN_INLINE=3Dy does have an effect=20
in lockdep.c to reduce the number of __asan_* calls. I have posted the=20
v4 series with the updated test results. I have also added a new patch=20
to KASAN checking in lock_acquire().

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
5f90875-d4b0-4cea-b857-752bc93fd48b%40redhat.com.
