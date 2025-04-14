Return-Path: <kasan-dev+bncBC7M5BFO7YCRBRW76W7QMGQEMX66QYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1922AA88D04
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 22:28:07 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3d5a9e7dd5asf46838175ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 13:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744662471; cv=pass;
        d=google.com; s=arc-20240605;
        b=VN7h2zAP7t80rwEuZQRL9voYU8dzqp6NA0lEU0qR7TDUZebnnbbUzUQwmP2nKWHdEm
         AqpMTrvwhRH2W3s5x2/TdD8wXBFti0teDf/8ULWiQRLW2ym1kChFY+Ryb7bh19X1MTz9
         FbTqTVz8gNh+tCBvCbUOFj3LlvQyjpjg9FiaXzOoLmaojp9JBQW8vrCcKCl278lyLUK9
         k1tKYkPREfAVYy+BKiaPvOcS1YIaEx2qRIoZ5TA1eRkyjxaVgMTqXbV5VtfDAdM9GGbv
         lWm+XNn5xX88IIIPgixHWWJ+Gpxr1kMZjOXSHkYQQCjl9mqxu6PYcRxMZXWKizNxycxp
         b1Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=jCE2Kb04wxIqfOq7AeNL+4DLfLZH7NzaHjsp2VbIVNQ=;
        fh=l45awMaDya0s/cWhclTdrVJCkzXcOg2IIahAxYhnAwk=;
        b=bksWYVBM5D8Hp7ZTWj/k8b8XuEFWflvr49n/tUhpe6OhT6aIPOI4Gv0rayltwkta52
         G3QItO1lLar6hnIhzTS89h26VezibwNCsnArV6K5wRXLLxX0aMOlgICD7l4fSUCE4RZt
         dTGSOyIhQCXnxzqH646pfCSYHKtAzLBprVxaELSSlu56bv2uh1sQy1tnTQ1YUSoS6ps4
         wQN5HYBpRCT4PAf8fkOcfixeB4aBR42tZaiI+ESgYz58KFwBJJyRDnq/iefyk86sJhFx
         y2RllmxutbwQ23vuC31kI824DP/1MJpkF0cXsJo2Dj58YF89YDWQ3PlbhDut+cIT7dvt
         swzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XnObJ+3j;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744662471; x=1745267271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jCE2Kb04wxIqfOq7AeNL+4DLfLZH7NzaHjsp2VbIVNQ=;
        b=mm/id44x5BT0UzWgDCo2bykf2VoEU3Uk8FVHhlWZ1aVaypUdWnPKmgEeOUNBnauy6A
         9T+o3/Q9v2bf8k+98Qge0ZhKmGbeB8MC8oiEuK2jmB39S74D0VMyhR4ZpP4ObnSdtMOn
         tD+ACx+PB5FKKywKfHQuAu/xNxoq1Yx+sSV7yqFThRONJzGQiLb6FRGzu3pElgigqie9
         YGNutbL3f24ZZGLRtbtveSqrmfXdXPSlHEDi6pP0N4wQv/7yzxytYTLL5Zq4fKCCR2Ah
         NuOo1I76ad863Wp3Q1SCZ6tWQ4pVNtun72lJgn48sPXklxHhZieBWxeDRMkOPyTLZkKo
         C6qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744662471; x=1745267271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jCE2Kb04wxIqfOq7AeNL+4DLfLZH7NzaHjsp2VbIVNQ=;
        b=IIWFZJlsBge4vD10DDbL/AnKOyWYR6k+umLHAzX86rbPZXa9XiK+pGFV2+Sdpym4FS
         vMwxr8aztFlbEFnOI/p0VjOhUOJfIDedukOMMpLg4urlDFSzKeWy3Gq0aw14UOGZDBex
         +uOyqDIxcKSEmYgRs8GyyZGtWxPuZhIKhaj5oQnVQ/9zuaWJT9TUph8cU5WIRRhmySVI
         AJPa6gfKPm/AOnsVgeAtCm2A37yt2X58crOtPnGf2L44mUyk6ToEnSZ4lQ29BL0UDkHl
         YeyngFoj6H4XhzazPalLYXMSOOQShmkIIt1dInlw+B+DQWsTQQz8yJ0Tqg832l7HwCYF
         tpJA==
X-Forwarded-Encrypted: i=2; AJvYcCVi6FoFbN7o1q1uFClxsoJKbJfV7u3EYDX3EH1GhRQoEgdk9oMMG45kVMikX/SW0NtLwIJt2A==@lfdr.de
X-Gm-Message-State: AOJu0YzcbHAzNYFmZtqBjp8pdZ0YPgJhZDCDeXMPh7ov82Ej+rVEsOOa
	0IPm6j3u51GHEP+NZ2J4dt5kFvwrbgFugpH8vLtnfoMgk8Vl6Ohf
X-Google-Smtp-Source: AGHT+IEERZR9BOPD7E6Q9//vqvo3EYqT6eDjCy8Sh5bwR0bKXtTwBclERd3/cwTqTJbbmHQslpA/UQ==
X-Received: by 2002:a05:6e02:3805:b0:3d1:97dc:2f93 with SMTP id e9e14a558f8ab-3d7ec27ae46mr146393695ab.20.1744662470738;
        Mon, 14 Apr 2025 13:27:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ3ghmjX2fYYFMCuIIbR/yi8jdTpnL7du3EemH1Bu7irw==
Received: by 2002:a05:6e02:3b06:b0:3d5:812a:ea06 with SMTP id
 e9e14a558f8ab-3d7e3c6c0fels13364145ab.0.-pod-prod-09-us; Mon, 14 Apr 2025
 13:27:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuSjCPXH4hP467uBD+zgY1SkYlueqyYI9YwBtAqfpGAJuxdPP4ogLjSnMZj1ICn/12Z5ho2SgRg0k=@googlegroups.com
X-Received: by 2002:a05:6602:3a0a:b0:85e:1879:c708 with SMTP id ca18e2360f4ac-8617cb46601mr1472887839f.1.1744662469174;
        Mon, 14 Apr 2025 13:27:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744662469; cv=none;
        d=google.com; s=arc-20240605;
        b=fsy4q9AkiRABicGpAf/Ah2oqEFWHrIjluJSRBK4dnvBdgTZ0b96Q52oqSR8T+yuEQh
         uLUFgPEFwYkC4DVJo+YLR4nDarycjok7j5MpDymUQXc/tbr1eKQpRSIWkWo9vwyq1wUA
         TjaFnpOSuulLiCA8tFUnblVAMEEnUDBXiQn/jqWt7GrR7Ex0xm76r1TgmpLSm5pHpKXX
         n1FaOWO7dqhzu53JklpMkLMshDHBzcnxj5PtwgDhoOvsnUtFQgOBY+kRNtop9VDXXosk
         IOjpAmz22s6B1MzyecqKmXGaedyFYq7Aw9YKSOy1MMZvPgGi1ATekoI2fViF1vtTaY6E
         hGHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=FpFBwiHdEgQDg0IQrpqMzAFITSNp5w8uPN/sxeBVsiE=;
        fh=AlyP+c7yy4omfv0Ua0hKSkK3UODMBQV5Xx7fewN+484=;
        b=j984ReNyFnSo+42zAks2phde8SR5IlXHahol9E+xTwm1c899mpMr1roYjlUVlCRYOb
         SodjE+qDwBAqeWZS1BNEmpeH8ogXxUeCUNCzCgG7U2qUmQvITto+XQjeZnIhbDh1v8N4
         oCiaxytVn5XoElzZTTYsDLJkJv/fRDShhqAe4X9h4spxewitPvZRLS5Bqcvywyntog1W
         wmpG6+LQDItN3GW2l652lT7hwCieNeWWkG1XCmqiDr6f9AymtBZYThU4JvslFbyYmyGw
         YZnwPOuOCfydzZXCBfBjt2w9loFYHkQZrXa5SaIjOfJIdDzFjH3C+FDbqpWOKj6IXbtY
         XPsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XnObJ+3j;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-861650858ccsi49813039f.0.2025.04.14.13.27.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 13:27:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-22403cbb47fso50782405ad.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 13:27:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCAbrShy5Xv9t/WZzZlsfPTXPthWfBZkLsi7NmRTrLvO8itOZa7wc6fMGbTXaWPE4QSLB2/FJS5QE=@googlegroups.com
X-Gm-Gg: ASbGncs4ELV7D6s/3FIknqNImdCYXgTK9M8u4SKyx4bYRC6Z6FrZ5JKr5sYH6/KRAG+
	dJeSHeNceS6jiDf6J9dA0rxRkKpHEBRaY3C/TLRKek1By7Y3n/vHbPGP642CnFTQAqbMFlUxZkD
	IqRFeEPYdU1nv+W3e72wDCusZxrEIQlM3NXNByBTLlxTN42e0LgSVSM+CqECiVjQ5VGwtuZi0TI
	/qKPeeoINfRi7TfFUOZIotlFi2aus4O1QRFI2yhM0Zz1OLGikCLOwHIesvKO4O2XgVjdS58nxK8
	mqhH2/Dw/k5/x8WGNCwnUE4qA4XEREBw54+2vA/zWXEHHM1qvqCjxeDuTScQ178VQU/RYkSt1Sr
	l443R9T5CuVb7yg==
X-Received: by 2002:a17:903:1b08:b0:21f:85af:4bbf with SMTP id d9443c01a7336-22bea4b70d6mr191325105ad.20.1744662468302;
        Mon, 14 Apr 2025 13:27:48 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:da43:aeff:fecc:bfd5? ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-22ac7c95cbasm103251495ad.133.2025.04.14.13.27.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 13:27:47 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <f87758bc-8298-4135-9410-34c2afa1850a@roeck-us.net>
Date: Mon, 14 Apr 2025 13:27:46 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC PATCH] x86/Kconfig: Fix allyesconfig
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20250414011345.2602656-1-linux@roeck-us.net>
 <CAHk-=wir+NJgwwrmRzj_giQYBuXBh=NRhhnPEqMmOM-phANVNg@mail.gmail.com>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <CAHk-=wir+NJgwwrmRzj_giQYBuXBh=NRhhnPEqMmOM-phANVNg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XnObJ+3j;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::62e as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

On 4/14/25 12:59, Linus Torvalds wrote:
> On Sun, 13 Apr 2025 at 18:13, Guenter Roeck <linux@roeck-us.net> wrote:
>>
>> Solve the test build problem by selectively disabling CONFIG_KASAN for
>> 'allyesconfig' build tests of 64-bit X86 builds.
> 
> I think we might as well just disable KASAN for COMPILE_TEST entirely
> - not artificially limit it to just x86-64.
> 
> Apparently it was effectively disabled anyway due to that SLUB_TINY
> interaction, so while it would be nice to have bigger build coverage,
> clearly we haven't had it before, and it causes problems.
> 

sgtm. I'll wait another day or two to give others time to provide feedback
and then send v2.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f87758bc-8298-4135-9410-34c2afa1850a%40roeck-us.net.
