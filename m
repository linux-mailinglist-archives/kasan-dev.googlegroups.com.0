Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBFPP4D7QKGQEEQVTLFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E80522EF0D0
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 11:44:38 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id m20sf5249573vkk.16
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 02:44:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610102678; cv=pass;
        d=google.com; s=arc-20160816;
        b=MxH8Ez0au7HxrVxi2I27vGHunn9Z0CBNRDq6AGR7C5AKNlPuiuiDKuPkqnOgxwDblP
         pyJXCniSjhqC8QmGdMspOBpjEN4q3y9jQRTykVQpreclyxJTRJ+UbtPlDeYakW+0Php9
         g7D8ljo0TJIb953T/TJC8hZCcLyl4/WRMctkK2nqu4KMdzOOmqf/dY7ubnbj0i2jJLHR
         Th+wv7dAwLuAY1h+nD9ggttsrfRUX226BVhzN8rh9d7IK7Htq5eR1/EQ+ZIskt0fZGfo
         3OpzlN0yAfp7aZHumcMPpuSAngJXdCNbqrm3Er9I4krSHC3/qou68AL441sm926qwDag
         +ZYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=HH0xm5xV+aupjJPsEcDl0lMcsu8sTVQPyyzdk/s6InY=;
        b=jpnJGG3zUhlCMquasDEeN+1rR5XY4nxi5UWr+aJw1YaKWW/pdpLF3TprdPAFdt6+zb
         zN9TY6cPbUISkYI+G12XAL5a/0bLTczZBIUCHRH/PkkqqtXPaR8cvcCXcHjiLzqtzm11
         ud3yqovECgtroJ8ZOsfenBbD8hQ6aODMO+x3Slt0Cn6BJR6aEhE4eXKg96bFc19f0iJH
         2p+3qt9q7DFEN1oUAqyFT0+arkjLSZ4EInEshvZ+YOJTZkqy4+A833ZkU1IXy3Osb5gN
         SDZsuIw83Xqli5Bun9lqA81G+YYvFY2pF5Il8XXfCtd6EPqfBvzrI7YxBsg9zbTIun4M
         ojzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HH0xm5xV+aupjJPsEcDl0lMcsu8sTVQPyyzdk/s6InY=;
        b=sN6ExzVMBT8UHfxt5bRRyWkKGx3NtJhXsb2kcnpAxdUo324WgWRpUa2VCeMoSAGLNQ
         1FYBajZOp7+TQVasG1/4+Q5gTXJZMMXx7Omx2ox8m/MFDrPH16O6nNR82KAfaYLKuQbJ
         /YjJoPE49kMmrDDrgV5ved4d6sTkYysGi8VKoF2MHWfbq+Kh13Bg6T/1ls7PcUY3stBO
         XRUnTy3iVn7ZAcZckJWft7dRhmr6Db46Vlz0Z8GFUdKaAyE0sHWIZZtHSk/VC6asCFzr
         JtvuPMKMNoQJ1Lpc62o9IK8KAwZwHSA43KpvEvDG2MqrJaO/JqtipSu29XtVjqxzB0Fn
         RsYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HH0xm5xV+aupjJPsEcDl0lMcsu8sTVQPyyzdk/s6InY=;
        b=RYmwANlcF5aru7+OQ/vH3IiMfCEpwJ/Hdy7u+SH9h1d6M4cCMKB5eOculHAl8cHwsc
         dv40h84sb5zZQHRD95LVadk4NUo0qLYZHiuNMV/M8aAOLB/92YJsHJZWAGwQeV+Fx5jq
         a5YE95L5x93VE2x749vIT+kGjkx1U54wAwWf/bCEjyCQ0Svb83za8nfycsxldkFmsrlv
         1CQ1IMIsmc6+Md9LdVQyor3AzPrgEr5SLQtyrit3JwDwnGN59/NVRC235OK/qrWYCSY4
         elnv7Wx4i2t0Q/ZyBQoxSDxJuBEYNb2ZM+xomIMJQA96sU4jAP4bwBnEzRZxDoC8RETd
         nLeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zuOzDA/bdm6SKvOkeRhRF5u8KsqG5N+LH62UzJ4V6YpkZQTim
	xsSO6A9PAUM9DT9zap1EjcU=
X-Google-Smtp-Source: ABdhPJxuZMAuc5CZRheSSLk+3YqMC93aRsMvo5xhVY9ontv7bTIU3dcDYKGFwl1Q0T5DpH+IJl/Awg==
X-Received: by 2002:a1f:b4c9:: with SMTP id d192mr5169669vkf.13.1610102677890;
        Fri, 08 Jan 2021 02:44:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3153:: with SMTP id n19ls900327uab.11.gmail; Fri, 08 Jan
 2021 02:44:37 -0800 (PST)
X-Received: by 2002:ab0:7593:: with SMTP id q19mr2315271uap.50.1610102677341;
        Fri, 08 Jan 2021 02:44:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610102677; cv=none;
        d=google.com; s=arc-20160816;
        b=yZLcDeRL9vROhZZ8CthrFRHIGBHxlGU4Ru2wmd2s5lfDSoqd0NPmg3oIoIu5gUC2Y7
         PKY1ZEvYq/rbFiWdqCmYoYaczjXEoB+RSb9R7Ou7CshYlgC4ZVk5R4xVtMjGNmmy0Hs9
         MQ8MkznZpTvvqIEfgUhqr635hrJyvrfuOK8KaGemc7t4vyR4ztGuvvjsV2Yv0rANGJQw
         zh2HHTjlnQtN9f8CXSgLGd94Q/WiDmG3pJpsQj760Puc61YgwF692Itc224uJfUmPAJk
         u3o4Wlun41tiDTMQdj7br/Pjbs0+WT6v87b6WGrKq6B+IwPTI8nAXljmKBjg41S5+EeW
         0TNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=X1FDf5j21tdljsRi308Uq/n3PaLsYxGNFiOeaRg6KEo=;
        b=Eb9LC3AxZjKtwRWAW9ll5Y1Q+xRQGI1X0eID2GfiShLraoV6IVokQ+kigliKhFMjU6
         KvOI+sgjrqHARj4APW3hBlHp3BQ/xqoJIAKDjQpx2YeCdyr81yEcrf6f+Y4d6NCdIwkR
         tVwoLaeYjOdW9l2/1bL0Nsf3XdsS7Iu30mD62hgbgVpOvRlPywrsFYTJgfL00oRZjOPh
         nfIh/nf0kXoNRM7CZNciSjKsDW35GzkK+3gwg4LV9ALJ7fOdPwzI6ZB+B29XWAOeIAp6
         WFT45UF33DypaCNqZO9GFlPgvHCN5Di9ulOjv15qpCfQbwlEkgVh9EezqUrJ4R6RB0QS
         P7IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g3si175593vkl.1.2021.01.08.02.44.37
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Jan 2021 02:44:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7E267D6E;
	Fri,  8 Jan 2021 02:44:36 -0800 (PST)
Received: from [10.37.8.22] (unknown [10.37.8.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4F5D03F70D;
	Fri,  8 Jan 2021 02:44:34 -0800 (PST)
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
 <20210106115519.32222-3-vincenzo.frascino@arm.com>
 <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
 <c4f04127-a682-d809-1dad-5ee1f51d3e0a@arm.com>
 <CAAeHK+xBrCX1Ly0RU-=ySEU8SsyyRkMdOYrN52ONc4DeRJA5eg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c3efaa8d-cb3a-0c2a-457e-bfba60551d80@arm.com>
Date: Fri, 8 Jan 2021 10:48:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xBrCX1Ly0RU-=ySEU8SsyyRkMdOYrN52ONc4DeRJA5eg@mail.gmail.com>
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

Hi Andrey,

On 1/7/21 7:18 PM, Andrey Konovalov wrote:
>> Boolean arguments are generally bad for legibility, hence I tend to avoid them.
>> In this case exposing the constants does not seem a big issue especially because
>> the only user of this code is "KASAN_HW_TAGS" and definitely improves its
>> legibility hence I would prefer to keep it as is.
>
> I don't like that this spills KASAN internals to the arm64 code.

Could you please elaborate a bit more on this?

If I understand it correctly these enumerations I exposed are the direct
representation of a kernel command line parameter which, according to me, should
not be considered an internal interface.
Seems that in general the kernel subsystems expose the interface for the
architectures to consume which is the same design pattern I followed in this case.

> Let's add another enum with two values and pass it as an argument then.
> Something like:
> 
> enum mte_mode {
>   ARM_MTE_SYNC,
>   ARM_MTE_ASYNC
> }

I had something similar at the beginning of the development but I ended up in a
situation in which the generic kasan code had to know about "enum mte_mode",
hence I preferred to keep kasan agnostic to the hw implementation details.

What do you think?

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3efaa8d-cb3a-0c2a-457e-bfba60551d80%40arm.com.
