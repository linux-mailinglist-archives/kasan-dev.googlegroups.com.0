Return-Path: <kasan-dev+bncBDL5ZOFA3MARBZUXR6XAMGQE75MPU7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 115EB84D12D
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 19:28:56 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-363ca646a1dsf7463855ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 10:28:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707330534; cv=pass;
        d=google.com; s=arc-20160816;
        b=HEnGEZM2PVSMGN3l4SkIBfMfiWl1gJg0s316po8muqzEWmDd+MsG+35x/QBcfua9Af
         Sq9IQ3fbRF2VsCVzjk6UudXcn1Noxt3RN8cIkKyAgge4+JTpbhN81QgpeGJVUmRBNOA5
         GEpBf6Ik7WLxtzIGZ9MYHR5nsXzxOyDpn2f26bInEhdpaPWhiYiGxiY+OWUh24POxr7b
         y5wzD5kXutbkrg2BN439B47TqX4h29h6lEw9jTKWKJ4yLkg7O7PMc64iH9DlJ9gPIrp+
         HOs5xp6zYNjVPnW9/zRPtXWL6BY5sKOsTLj6QnSuckzESs10K9SMBP7SyIu9O3xI9Aay
         zVRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=mvkuL2mjHcLuu5mtgFEQmyPzm+rvoHGTovWW4aEhu/8=;
        fh=I/Eul9SbpBXDVqWdup9nvFfg3YQUofWxVIF2PomVEVc=;
        b=ry6cTDXVbBFScKxQnuI44wA1xxQ27sunxHkr9DyIsjcV1OLOudc21xBKII4Vx9C4rf
         NnA+hUyfGb59LRT1fChVG/L8dOfMlBu5NTIy590PXPLljHvUck4TKa71oz6kwMNR6CjG
         cChlcJzWyYF2ElreEyez9wdcbTJGHFBk8TEaDrdjRamqtOulV4n0ba4SDjwY//FkOCCb
         2zOywlUKTH6+QGpYyh7FqohWxmyzOd9xKRx9vIQWgFUKF+R4yXWOPrPC1NBmM8AFbsyb
         BIqYL7BISX1B6iaNGiOFWdr6LUPnnoLZ8KtFJC3BtkmC4ddDEfvCcYDdj4Nu3ewg5c+B
         6hIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kILtloZU;
       spf=pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707330534; x=1707935334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mvkuL2mjHcLuu5mtgFEQmyPzm+rvoHGTovWW4aEhu/8=;
        b=jdkn184YbZ5dAvXvPOcqnRDARmvnIG2sqL/quXNCeniUQ0fFZviCa6XakFAxy94Uo3
         0JXLuKIzuWLO40nzT0ibK5L0fKYTVqZbXw5QkVnwVpJRYKTOsqEe8BgOdji5scm9gSmV
         qCxiEsU56Pck2e8CIV6mLXr1/4pv2AvgxQuRlOZql0SD6KiiV1huhwTgeELZEjCIAfEU
         Otc5uDTChxMr0IJZpKYlLoKb+oOz7zWjp9xYwr2HL2/0/z43znwiD84GpFK1e5GUQsuf
         45EbmXfhtvO2zdjfyYGkOhQNOT7SOrgCupPUju4cCmlYBjPNSVHV7xpSBnqoTELXsRWf
         omtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707330534; x=1707935334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mvkuL2mjHcLuu5mtgFEQmyPzm+rvoHGTovWW4aEhu/8=;
        b=r/6J/edrfAdP9nHMCsguB97MH6mjFT/FkQdAoGBNCBra5t4UcEK4dSdOg4VvmWvaeU
         QGBUZgZ3vnHveK+MQoFpjn25fz/kTmXm4bP9MgcrihT2o/hbJNaOEomDQpTX0S15ZlVy
         ffYj4sEYas3nNYw70LimDGjx/ylewyklvVpf/B1dNHFKNJYm6pssP3UaHrb+Gnf5yE5c
         kHtkYBZ/lwkJDM97XnrQgV+++1jGQc35D2PvcqtmA6iT+OPbO6GIWSmeKkUXriqyAv7n
         XiNuw7WMaIGZYRZ6cOlANT9158U6HsLHmBa82GRdKPTtIscO5yxnKheszHItOY3zVLlX
         vAUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwFaqjzdaouHDZgdAMw+CSAKvK+hjZCN0pe9DBrJRlHX4k/K/LN
	2o9LDBL7sLHKA1Wy8wOersR/CotxWAWXn4N+axedBZRf6MHtg+b8
X-Google-Smtp-Source: AGHT+IEM+jb34pUX+tedc9+pLdm/YVflPGuCM/pcu3UYb749fpC1fR+EH3KUan4E4IX8bZznNr0joA==
X-Received: by 2002:a92:2902:0:b0:363:d9eb:c2e5 with SMTP id l2-20020a922902000000b00363d9ebc2e5mr3895453ilg.26.1707330534657;
        Wed, 07 Feb 2024 10:28:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:388e:b0:363:93da:bf4c with SMTP id
 cn14-20020a056e02388e00b0036393dabf4cls568387ilb.0.-pod-prod-05-us; Wed, 07
 Feb 2024 10:28:54 -0800 (PST)
X-Received: by 2002:a05:6e02:1a29:b0:363:7985:eee3 with SMTP id g9-20020a056e021a2900b003637985eee3mr9504103ile.24.1707330533857;
        Wed, 07 Feb 2024 10:28:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707330533; cv=none;
        d=google.com; s=arc-20160816;
        b=fny65XZVua5jI/mwVDT3L4B1mkuP87z4xA9AFjOF2wRYJqKi196c7r424Szk2LHAfX
         JI9Q9IbogvN2cCbJJuIqveBPAdrBB5w+RZw6IOsvNHVZYRShfyZjGlkZcVOWEK4e0iR8
         M9mofhl893+i8xpKzbSIqbpbDJFAxr8YaZZApGiZKrhDeGmwDOTZ/4jOfma9yffOVZU6
         dWnunz5IPR6pwJA0gc7prqySUPoi7EL5ErCyCkR/esa7vZXLviRdZkmhrjGnYKmUQuVo
         pOjM84bH3ZRX7a5BTjSoAXdpWcbiZ/AGsMEAxC+OsAmLEIVv4sPH3eao4/c7LYgXnNuG
         ahKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=Yrjbd9eh7nQRdI5moAWl4HlkZlnPco8JLeYxt+xAa/Q=;
        fh=I/Eul9SbpBXDVqWdup9nvFfg3YQUofWxVIF2PomVEVc=;
        b=W325z4ih6Edg8IuMG8l/mf9qJgzfaRboKi727YeRTfjT5GfiLPrR+r8/M799HdnGaz
         dTsA/Mwm+1mD4XlqbrxdPXOx7dPLGIa9EmQlliGUHOxHpRvdMNylGbe4xQWW8xo4yQ3y
         qvB2k1U1Ec4ahIAROAsW9F8/FzHT2BoGQF6cVGG1qih8J8cdlnBQQNe95GYp5xmDvs4P
         U92EuAHL8gI1Mi/+/hsNZlJqNl/HDfpSIvBo0XA5wHlNAkrETKEg/euu7nzyfSnSV1nJ
         D0q5j/mlFwDx07XWoGA0/Ca2falSAgkAliQv/U+Mge7uLFoMMlwlSS/oNwt4PomrqXa0
         Nijw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kILtloZU;
       spf=pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCWaIRGi1WZV6U0uBrLjj9AcO069y6x7hwfDiqNarxb+uA0KrWzk+mB9fdH5gZQx0Qn1nHWmUkAqDkPo4BY/K4hGC4oJ5LznQs+ePQ==
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id y64-20020a636443000000b005dc13d8277dsi228695pgb.2.2024.02.07.10.28.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 10:28:53 -0800 (PST)
Received-SPF: pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id DC45ECE1AD2;
	Wed,  7 Feb 2024 18:28:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C2DDAC433F1;
	Wed,  7 Feb 2024 18:28:48 +0000 (UTC)
Message-ID: <44dece0f-5dde-4bbd-a713-cb7db2654ba1@kernel.org>
Date: Wed, 7 Feb 2024 19:28:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: KFENCE: included in x86 defconfig?
Content-Language: en-GB, fr-BE
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>,
 linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>,
 the arch/x86 maintainers <x86@kernel.org>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
From: Matthieu Baerts <matttbe@kernel.org>
Autocrypt: addr=matttbe@kernel.org; keydata=
 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
 lzVbFe7fduHbABmYz9cefQpO7wDE/Q==
Organization: NGI0 Core
In-Reply-To: <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matttbe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kILtloZU;       spf=pass
 (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=matttbe@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Marco,

Thank you for your reply!

On 07/02/2024 19:05, Marco Elver wrote:
> [Cc'ing a bunch more people to get input]
> 
> Hi Matt,
> 
> On Wed, 7 Feb 2024 at 17:16, Matthieu Baerts <matttbe@kernel.org> wrote:
> [...]
>> When talking to Jakub about the kernel config used by the new CI for the
>> net tree [1], Jakub suggested [2] to check if KFENCE could not be
>> enabled by default for x86 architecture.
>>
>> As KFENCE maintainers, what do you think about that? Do you see some
>> blocking points? Do you plan to add it in x86_64_defconfig?
> 
> We have no concrete plans to add it to x86 defconfig. I don't think
> there'd be anything wrong with that from a technical point of view,
> but I think defconfig should remain relatively minimal.
> 
> I guess different groups of people will disagree here: as kernel
> maintainers, it'd be a good thing because we get more coverage and
> higher probability of catching memory-safety bugs; as a user, I think
> having defconfig enable KFENCE seems unintuitive.

Thank you for having shared your point of view. I agree with you, the
x86_64_defconfig is probably not the right place.

> I think this would belong into some "hardening" config - while KFENCE
> is not a mitigation (due to sampling) it has the performance
> characteristics of unintrusive hardening techniques, so I think it
> would be a good fit. I think that'd be
> "kernel/configs/hardening.config".
> 
> Preferences?
I didn't think about the hardening kconfig. It seems to make sense!

I will wait for people from the Linux Hardening ML to comment if that's
OK :)

Cheers,
Matt
-- 
Sponsored by the NGI0 Core fund.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44dece0f-5dde-4bbd-a713-cb7db2654ba1%40kernel.org.
