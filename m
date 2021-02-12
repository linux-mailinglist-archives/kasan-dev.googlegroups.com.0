Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4OJTGAQMGQE52JMUBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 09D18319D4C
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:22:27 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id c186sf7100912pfa.23
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 03:22:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613128945; cv=pass;
        d=google.com; s=arc-20160816;
        b=vKG+EHc/JkkfsqCtMUnfsxNmxaR2hm9QvV1PqqkbeUTvM8H894cfGNFeteCZew5UHk
         HZIdSQ6Igrn0rPUL0IPYZ8UDqvvHh1IUtbC5pjrDHk7jkHCWDkjs73LdwFS+M3/7wnmj
         rTQrwT8pe0FX+nuc5FAs0jWJPFQOUFRpShdy3N/YEFSr4OPlRxDRKt1RSmrDJORxclNG
         Kf/LdWHUyRNmjYMYn/n3mHjRCvPmwmYi8NrG0DBmrxlkbksyNSDrqrkbup45sXXnRk00
         Z5SSVWQF4g3Owf5+FVWnuYVubhWLXIu2pZMg/SnGCpqIuDXALBzOX7khPyGjEqKl0kSd
         eWNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=iVtG0qBFQ07KhMNs+9o2BxVPJ/1acl4HTKU2Ds9M6ME=;
        b=pxCoQNZVvZ6ay78dCNLMaB8UZtyP8rpljUr0G37TAKzkKFVg7F4TuWuakVZaEWk6z/
         6UVr6msd3aotB1C+VswToAqJRf+Z2TiKXr+amC2s9NCEC4GZQSTxVjgzFqOiBdZQ15kR
         UftiHloMhsGOE/jhBDNe6nbgRO7HGURnNkNi+12okfSL9gMbzyzFTaZqIr0wt3B423Zi
         mu+FYYnjS0a8yFuH2I63awHkHcaMesCYGbrVziv3qn8IQ/ED+kOcfxHZjbUq3M38ih+D
         V3LEySJkXtJMxqjkU6IOyGxH3mI0rFXVm6ukCq6TRLHoypmwEB/FDLFLWypVRBNm0b//
         RGRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iVtG0qBFQ07KhMNs+9o2BxVPJ/1acl4HTKU2Ds9M6ME=;
        b=FZTlgC2bICj5CUliJaKzoS63HijRNZFjJw9bq/ddUnRaonqhwFF/GSQN/NxwocwVVD
         4Kgh0tYV6vR4D3ROUY8reAlb05yqq/uDS0ytnbUwm9mXd1So3AGJ1m6HJK4d2jYioXBt
         kuFmgJ1TOLtc0eB6CPvXNbVZea4ZknDC3YxsCt2R9yGDbY27xlfHUNcFlGxKLcfA2M6x
         OhN8YUrInvemhHsqcjLU2L0AiuvrwODznUq+aNzKec/NSOla2vw22f9IPL+FrfEJszPg
         NGm/OMtxvaBnfxOyVBszd58MChUcQ6vxDx8EZXs46AaqIdhbHuVRvH1jrwmH36Jdm9gX
         dgyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iVtG0qBFQ07KhMNs+9o2BxVPJ/1acl4HTKU2Ds9M6ME=;
        b=bj4yzfDBGtBUb1cw/oe2Kz4zp1OQMPsXaIpp5ZnN9X9K13amtWgwrjY4VWKg73yFa8
         QpdCg8XfT6JYIhaK6GEE/3co/N/EM+y0h1lyI+rjGqaBeqdtyl42UecedPXBvSjGotOe
         wKpoy6+5q3qXQRTJDtMwV1kDQhM+FLiSVd/SlGDPUUAUm5K9vC+Fiz2sDR46bpiFo9/Q
         dTRxtaNuA/J8N30ghQFPtylDP80IJ7/e6nZ2Nv/VlO51bxk++JycU2hKcmFS9WBATbs9
         QbxejS+nR2hfV4pI53Keh3FOye35Y0jDam+c8Scdt9MqGs0UyG5KqviWeQx8wLL/xxVn
         YxNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eqSn/GZwbAe+sYOSr9UBA4zOY+KTomaZRHYKGiZSOelsuC6rf
	kZ5ujU5xoHnyDgLF+viH4Cg=
X-Google-Smtp-Source: ABdhPJxm8wA2zPKB7t7ZX5BzPHMRIpc/C6gpvZ0TgLzBMi3YkpQnOpJsFmgWv57JwxFQ/3RaLCC80w==
X-Received: by 2002:a17:902:cecc:b029:e1:268e:2286 with SMTP id d12-20020a170902ceccb02900e1268e2286mr2605632plg.62.1613128945577;
        Fri, 12 Feb 2021 03:22:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2ca:: with SMTP id b10ls2323603pft.10.gmail; Fri,
 12 Feb 2021 03:22:25 -0800 (PST)
X-Received: by 2002:a62:ce87:0:b029:1e5:b858:2e5 with SMTP id y129-20020a62ce870000b02901e5b85802e5mr2678047pfg.64.1613128944981;
        Fri, 12 Feb 2021 03:22:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613128944; cv=none;
        d=google.com; s=arc-20160816;
        b=q1RqIoYTJt9KYSFsfXOHsFSs0EHbMPEUm2soN9cmh52HTHHszbYNc+8p3M4WxijG6z
         u2WsntTsVgsRwXMXnImjkA/nsqWS2nRzAdaNue0kS7JFbvjFHKi7NRnPLP08fYYS55w4
         uaO3heNQuwZ6RSEbNYwug6we2bQIAVk6Lqz8GW7M1W3tNC/lxIO/XcxxqiIRwztJG/1U
         r3md39aVHIkZqTmEZOVkr6tVmDsDrG3HGKopQYUO6zfy7pzJHnSFR1M19mN+m1yw68KO
         +BgEpdT06hYrx9FyBP2ioaLxUsZ+qUYISbjEZ/z0TIoHqSLbuwh/qjGu48TVg9UjVVlB
         GJfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=czJheoqsNLhsD4HOS97/zX87AdR86V9PHxoM/bcdus0=;
        b=notYPsSS8MwIxo7z0xwwFAGBZbkJLbQoNP98guPONp0aTcytY4CfGncuUS/fH9vkNu
         JtBh/XQ1RrybocsMAW0Bh4u7qukFs1pA+gcQsSvJP8dClOmET/vqC3EcVj6mEuJxn3GH
         0DsRNFcUOGTDe9TjFh1+tbtF4LjWLLkTdrScaN4K0pcBl2ocEJjl/JTWRkS5kajb46zg
         oBAdy8PlQce02K4+PRnpmjniQa3P6fZHXzl0N3QH/I5MQY/YLl0o0cAmptT7I9VuXRWE
         5oxrkk+ccFl8xGmV0Pqt76oaziT63OSn7oXz27bRvfy72vcjm08k8kfGd6eJ13VSz/nV
         cSbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p10si460462plq.0.2021.02.12.03.22.24
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Feb 2021 03:22:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4061B11B3;
	Fri, 12 Feb 2021 03:22:24 -0800 (PST)
Received: from [10.37.8.13] (unknown [10.37.8.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A3CFB3F719;
	Fri, 12 Feb 2021 03:22:21 -0800 (PST)
Subject: Re: [PATCH v13 2/7] kasan: Add KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-3-vincenzo.frascino@arm.com>
 <CAAeHK+zefPsq6pzO-bTz-xOXQrNkwuCS8i9L7EXLxH=SkKAgJw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <913e2b39-9cd4-5310-df27-999c65b8d76d@arm.com>
Date: Fri, 12 Feb 2021 11:26:27 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zefPsq6pzO-bTz-xOXQrNkwuCS8i9L7EXLxH=SkKAgJw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 2/11/21 5:50 PM, Andrey Konovalov wrote:
> Let's default to KASAN_ARG_MODE_DEFAULT like for other args:
> 
> if (!arg)
>   return -EINVAL;
> 
> kasan_init_hw_tags_cpu()/kasan_init_hw_tags() already handle
> KASAN_ARG_MODE_DEFAULT properly.

Ok, no problem, I will take care of it in the next version.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/913e2b39-9cd4-5310-df27-999c65b8d76d%40arm.com.
