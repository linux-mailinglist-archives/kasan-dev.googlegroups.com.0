Return-Path: <kasan-dev+bncBCSL7B6LWYHBBXFL2PCAMGQENVNN2KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B98B1B1DBD6
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 18:35:43 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-459dbbf43c0sf11668375e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 09:35:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754584543; cv=pass;
        d=google.com; s=arc-20240605;
        b=lxur+9BDZVVhB7BW+0XMcEB5cUiFp6YjX1oUY4MXgIfrQWPJwTZOZWCJq0lrQJrJIQ
         S2dGjzciv9JNGCOm10wyExp/dJ74JnbG4vj5nMzScbkSlcrxDQj0oG02ZAnn8dD8oak7
         XATSTrvpMTdnlccX/mb9MXcQ0JmK9v6hrXZsWoSjFncY+mvNd27eCZXEqHOy4Q2c06L1
         B2yW7c2VoA2fRKc86mzmtFMGZyBgyFPRP0kIzWiQ4vpIVRyJykcANXKlz1iiU4Yv1DQJ
         OxiI9r1HaWRZBARlqDgfJy+Mb4DrEww/PukQTVh8/H3cGVfUL8sPSEnx5QzC/6QiS3oC
         H+dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=tYkXq77jEYfCWr6G1/ZzlnuX36ll1hJEWzu9JscNb1k=;
        fh=WlgI7wp7j5w8E8C75qNknZGjzHNYsX6GpYXkByAEDuk=;
        b=h2Y8AJrslGa3INbNq2L6BgiA+TDmeeH4dDAvb18TWfOGJTAEbo7ixySU7aMVI3cVZk
         frYSsXcvLCqUh9v3DD49wCdiErDEb8JeRuR3iQyF9LbJuLcrAoZnDibrzWzO5wMnErQz
         EcK0HqYiDlwD0qaD0DyPAfiYY5A1NLwdUlgptfX2H7Ee3a3sRTl+qpRzEVR5CmAmQJ3C
         VzhorkIa/pAS66J6Z/4um85QV/xb2SStsDPdaEcJQrt8252dY8ZrAvzZruG+3AQn5re9
         01+9Tkm5R65udP7VNTUIHj6lAg79ZlYSG7Ej+YAS9aJ35+XGwiwH1cb07D7EEZV88Ni6
         JWLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Rg5iRNGO;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754584543; x=1755189343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tYkXq77jEYfCWr6G1/ZzlnuX36ll1hJEWzu9JscNb1k=;
        b=w5xXLj7tLPMTNSU41dAtj5v7PScddZiVk8AD3NmIlAD2acT1atr2VpQeEH6WMXzTEb
         YGp0RWxmwIcBgjQAJ3OgoZptX5dvap7KBQsOWZ4BqKmFk39WXfgf9nxwJ9aa0hxnWrNi
         qPyvIRQq060U9/fV6iBW6T2Zt8GAGoVQ83yCtkETbUxfEJpjMHPhoqXUZMHvv+gVaOFK
         2+soae3CUN7nG77X6dQVfI2taAr8J/2yoo/jKkMHNYcNDJHT3hCtap35aG3CuLEGGMIJ
         qadNB2wI1pqUIKlNks7FJIGEIln7dsSuXMMSCscE0ogNYXF/zyCT8s08dEvBJ55Olxmh
         guKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754584543; x=1755189343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tYkXq77jEYfCWr6G1/ZzlnuX36ll1hJEWzu9JscNb1k=;
        b=gD9uKtKJcoWEUrvPPXMkBL2Cos9JiKOj0961IKRnwnYrDNf4N+Sx9HZn+xKUbwMo8/
         GeSRkbSIBdZrvAwSZHJiUB/rur2MK5ZIJ58kwfzxOv0MIzdytRtgf4QIUMozrGIcBxFz
         LNksB7PpWA/Z3OyRSBCBkZYDupShgj4lG7kYyLdPZYssRsuGLFN94HE4ArbsC6gSGsgn
         qYMmKoy3bk0hsAzSTX1gi1Lvs18K6J7ms0uzvvBMWL308JNmeon5UsNIV4T2K4wiVAVa
         y1oLcKIoi/5ZN2MxElpL9rmVoTKTh14I71djO5s2u5fwNgxxT4BQ/8nA/Ak1mvOZXcBp
         V6gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754584543; x=1755189343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tYkXq77jEYfCWr6G1/ZzlnuX36ll1hJEWzu9JscNb1k=;
        b=BL6CqhUeG9HBHk/9t/P3NnKv2z5RSwF+HZHb6m0AOwk26cr9wSnqUOuze+IIYYz48Y
         b3b/Ar3fWaHEmK2fjv9cMKtBHWMGXpB0RO6hHy+pMc0LeanqI0LniU5+X9PVRMHIvhf+
         FXPDiYHg9Jp9+6aYGsOl/mBjaCyavLinF1pnYY0VKdyLLzOV4zKP+TYwvnymMcHK9MJ6
         2YnHxwd/V1UxxxSrDMgzlLNRlooFHOnrjhppbntGz7v6p+Jdlui9tXQWknD5LTtJT+UD
         CCPN5RlLM1PyxPGvS9zM2zMrbRUX3o2fA0G8QXvu/25LsiUVlJKPyuMZMsWD/xaHn6QW
         1BeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUSyumXG5UGk9cQ6dYD/6gWTTrgHUqKfa9KKb8PUtnP2zgXx8vDivZMW18GZxlEoWJChTbFug==@lfdr.de
X-Gm-Message-State: AOJu0YyyVJi98XhgYqDGjbk8RWmQBTgZ42a+FvdFbbYYgt7pr+ENPN/i
	+Dk5yX91man2Voak3Ng3021lwVT7+iUfAolAO+nmZtfVxfUoPRPyOZ0o
X-Google-Smtp-Source: AGHT+IEXwJCc5N9tg6WrzIPGBNu9cynEjrJniULIU0Y+T+VjDJyGhDZ1446wM5Oeaz6y68gko1M2vA==
X-Received: by 2002:a05:600c:6205:b0:439:4b23:9e8e with SMTP id 5b1f17b1804b1-459ede887cfmr51434075e9.3.1754584542817;
        Thu, 07 Aug 2025 09:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZffZPnePmYErMEVYVTrOEiOm2sZXd4rlScD6Gn4QfigwA==
Received: by 2002:a05:6000:290d:b0:3b7:88cf:e1bd with SMTP id
 ffacd0b85a97d-3b8f9238b42ls404424f8f.0.-pod-prod-00-eu; Thu, 07 Aug 2025
 09:35:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLTuiK4QMeEcak9XRxN248BMyuzdGSgwAOk7TZ6UL1p9jk7pQec38LoH9wlhz2tJUwZnIdXVfCJuk=@googlegroups.com
X-Received: by 2002:a05:6000:2207:b0:3b7:9703:d99f with SMTP id ffacd0b85a97d-3b8f97e76bemr3784510f8f.27.1754584538131;
        Thu, 07 Aug 2025 09:35:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754584538; cv=none;
        d=google.com; s=arc-20240605;
        b=cqx6NccToVC1hFP+1chkyNrCYf0r5uEggvkoCcWmXYamM9tdf3Pp9xnlTHyzSm/Mef
         4uRnz3/isMM8mwuHd7M9WPLOQsbjFi/vGEpKUN/aiNkdy7rbyYx8TcEQzxG2QAAfXiC4
         vaD31qQBbQKrmwMVk/DQjmjtI53cbQvHPH+JSJpy5QmAHvk1bVyEdBVSfBL55zv8oFQp
         MWJ7n7+3mR2eu7DUtCeJPseNsrgyDq1VQPP3q9nlWfxn0x3Hj0j5t+iKsrQiiNvqG8xO
         gBegOnr5SJNtPCXx+yWpAwf0HeCrsx3f893IhF3PK6JObfLk/8t7Une8BIraXUk6ePUI
         fbvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=HtJ7SukZttuLpvU2sM4wbLSaHHmB2xRR25bbI/ADQkc=;
        fh=D7zJ81zf3oEKkXJAIwy10gnpwrtxRgS2tJdbH/qnnhE=;
        b=iSgOmAcCwHfeIJqrrDoKyQhcNyFLnyHwsWVh2kgf+2qJLEGgQqkXCJKN1XEXSGej48
         /lKF886pKLE3fPtRdJJMPTjt7uXzjCTNVbma7aa/NR3RdNV+sYqxR354dA0dejOkJr4t
         asTGLxQnj4rf7v/QN/9RZQagZTlsQDntqqjuKzfmWb01Yjfsf7ubBNKp+wyjgPpBSfmQ
         kmjFKtF24SEpxFEPjXAmTAT4RDBiJa6NmAfY6eres/y9j7iNFL2HsLLHLF1F/huNyki9
         ipcdUVpCJTBPvZaSAsAtCJHTlaJnfXoGAT1gUhLpriLk1/ry0eCbH024vPJbEcwyn6xZ
         0/HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Rg5iRNGO;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c339ca7si415970f8f.0.2025.08.07.09.35.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 09:35:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-55ba2644bdaso245743e87.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 09:35:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzYD9BnKBOkaY97cqbtosiUlbNy0vGDValEWKRzNvb0qEPYcYVAjCJwg6ZRLwdtWy2PLSe970ppTg=@googlegroups.com
X-Gm-Gg: ASbGncvowu6aHCmaBeNwZWzgr/l0miCQiz+aWTzPDP4JzVJDo3rgjwqbefxj22+M521
	RXgw0e5dXA2+NQaauxv+AOXAIlqauf8rhhi8M6kWA81jc9sgAWhw4VDzig9EsEMMz7lsvTSjK/R
	QEMbLMzuevquyT2oZ2NOfYi1NEGoAvtAatV0x/xaU6jdkOUTW2Hzim2b13/a78p+vNBKqeyNrok
	3OtjKM96PHdYIGtwyjuPtc4OB+iVNqUmtK+NgX0eG5d0WlELN0dCRd2fizPDY0pNDr4bDrLS+b0
	lKo6qfzg7UCv2jtMV/TRZiKFG4Q+JqzBIAfU5KAfLUVOINwooF0YIRMxxRb4Lt1WEtVmjpSHrnA
	MQ8Hl0LJH8EFEJGAxr3Cqhoibi8vN0fNIQ+LiGEo=
X-Received: by 2002:a05:6512:3b28:b0:55b:8e2e:8ce4 with SMTP id 2adb3069b0e04-55caf317e7bmr927137e87.5.1754584537230;
        Thu, 07 Aug 2025 09:35:37 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b8898bd4asm2706906e87.11.2025.08.07.09.35.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 09:35:36 -0700 (PDT)
Message-ID: <69b4f07d-b83d-4ead-b3f1-1e42b2dca9c2@gmail.com>
Date: Thu, 7 Aug 2025 18:34:47 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>, linux-mm@kvack.org
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kexec@lists.infradead.org
References: <20250805062333.121553-1-bhe@redhat.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Rg5iRNGO;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135
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



On 8/5/25 8:23 AM, Baoquan He wrote:
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=on|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built. 
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.
> 

Ideally this problem should be solved by having kdump kernel with different
config. Because if we want only reliably collect crash dumps, than we probably
don't want other debug features, e.g. like VM_BUG_ON() crashing our kdump kernel.



> So this patchset moves the kasan=on|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> kasan.
> 
> Test:
> =====
> I only took test on x86_64 for generic mode, and on arm64 for
> generic, sw_tags and hw_tags mode. All of them works well.
> 
> However when I tested sw_tags on a HPE apollo arm64 machine, it always
> breaks kernel with a KASAN bug. Even w/o this patchset applied, the bug 
> can always be seen too.
> 
> "BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8"
> 
> I haven't got root cause of the bug, will report the bug later in
> another thread.
> ====
> 
> Baoquan He (4):
>   mm/kasan: add conditional checks in functions to return directly if
>     kasan is disabled
>   mm/kasan: move kasan= code to common place
>   mm/kasan: don't initialize kasan if it's disabled
>   mm/kasan: make kasan=on|off take effect for all three modes
> 
>  arch/arm/mm/kasan_init.c               |  6 +++++
>  arch/arm64/mm/kasan_init.c             |  7 ++++++
>  arch/loongarch/mm/kasan_init.c         |  5 ++++
>  arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
>  arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
>  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
>  arch/riscv/mm/kasan_init.c             |  6 +++++
>  arch/um/kernel/mem.c                   |  6 +++++
>  arch/x86/mm/kasan_init_64.c            |  6 +++++
>  arch/xtensa/mm/kasan_init.c            |  6 +++++
>  include/linux/kasan-enabled.h          | 11 ++------
>  mm/kasan/common.c                      | 27 ++++++++++++++++++++
>  mm/kasan/generic.c                     | 20 +++++++++++++--
>  mm/kasan/hw_tags.c                     | 35 ++------------------------
>  mm/kasan/init.c                        |  6 +++++
>  mm/kasan/quarantine.c                  |  3 +++
>  mm/kasan/shadow.c                      | 23 ++++++++++++++++-
>  mm/kasan/sw_tags.c                     |  9 +++++++
>  18 files changed, 150 insertions(+), 46 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/69b4f07d-b83d-4ead-b3f1-1e42b2dca9c2%40gmail.com.
