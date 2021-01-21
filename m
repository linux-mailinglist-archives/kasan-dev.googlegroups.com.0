Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXHYU2AAMGQEZG3XSEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C2B42FF21F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:39:42 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id 98sf1567482pla.12
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:39:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250780; cv=pass;
        d=google.com; s=arc-20160816;
        b=DdBVsvW9hkIM4Bk9SArQJh8prqbqC0+dVf/Y8giNt2LG3gw6GYL47Gp0ez8h9aBSDK
         kzOPG8xMo5AQRoFFZVxi3CU68Q/SyW/1gMRgk1I6dRnCqm6AXAIVljyjPB2ZfKWu4ekS
         BL7kde8KxZ9ObLIVTYCcqufKyIdfu3RGGGuoYjYtuZzbFJYuTndY583Ejq2iXqu8owBr
         soxIaS4uMTgGUXuhPwxp+lUkqvqZTGk39+2o9g0/2zK4Nk/g0s+8n72mRoP4wkRc3VeW
         pV+uVi7ipfRk8FvUdCjP++dZ3Y2eKdkGjD/x5N25mINrSVf21Zfa07MeOUiOQLaQV9vR
         sZgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=I3pBejtHsiCKUN9YCtmVH4JN7nypwTC2L5JYVHb+NiE=;
        b=iPsABjwf/+QZNkovpC2Pb8NCC5cs+TKlOGfVMk49XjqJqXeBXZEkyb6/GWuf2NPvhP
         1iSfiuVHQt8LmjhFmNAA7qU4mkGD7IrV6fNl6SqiXqKj1pS5DEM9CzhgA8OooFlrtt3Z
         NLjnOXyg5DtLoX6yAwZEqm0jHGEKuNgPY6/abUn6JUgdRD8e1hrjimJ2ytPjTKqYE/rF
         bn1q/1IpE/jWrP1OHpXeOne5q3PhAZ7VdnImzvMgQv9I27I8kpEOtfmG4lDgFReVW5zD
         SA0el4O87LnxNIqHlQhu0f1xLb1uCslkMxk8ESw6CsAUX5lmoqoWPRwxedsOIU32IlQ0
         cqUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I3pBejtHsiCKUN9YCtmVH4JN7nypwTC2L5JYVHb+NiE=;
        b=Fjs7+wAo4LSn3xCDJqzpfoBqRLEHFBxecEWF3nOTtQ63P+TuTuLSicWvyOQ2/uZKJE
         g37O8DuTc6tQXITmHOBZMGspYKPOmKSiYXEoL0IKxqgQ71Nf/Q+dtfa9acn/m7tseUOo
         dHLTZP1WkjgUMtD9Ib/Yz+87QI/d+b3LP28WsY+VhrP/1i8S+8Um8NXzv8X+NSacXWlI
         yo8EoJDClfSRSz3hav7gVK7fkjFu91Nw2Dc2IIXx0l0S4CvR2BtCvvyiOkXrj8kUDB/K
         rNEL46gUJczML8yNnYMtwnmsVPSscdBNjS/62/okctowrv8x9/XWKotARxl8g0wM++iB
         2Bfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I3pBejtHsiCKUN9YCtmVH4JN7nypwTC2L5JYVHb+NiE=;
        b=IAaKQC2O0q3DPb1wg93GwWeFVuFbi5bszHXzBjpQ1mrIehX4d7KwJadMCEiYJDmaqv
         KINfPe2dp3ztc5vVevjYEWfUy2Dc8lrwMgM4ZEOpoQPsvIxzm5uGOVKk4AOKZcIwfXvG
         H38aF0bobSKiWmuwkBcL6pbjA8hyXKs7M37QnsoT9BbxW+GfZgtpzordSnD0TK1YOLGV
         Svniu0b8ONiDXa4FE8aVqJQK8uAIzMlSWiLexCNW6Wk97KSd5DA+lVnDK5ycMa0MS5k0
         j2I4awmwOLSTgxE5RT25Snmm/fsiiYCMXbQRq5IhJsSAP5w2Q2VAPE9yL7RQuRTknePM
         n6WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301yXtIrGJUp4naNV7luL3t3npVJggHs4pSZ5V9w10T6cM7PrAn
	ZwqKpMWF2YFhMZG8Kj9MQFA=
X-Google-Smtp-Source: ABdhPJxzPp69sggNNMKJto0fBKQ3sLGeazDA+JhG2dUE8fJxRQrtORlRv9+aF/EtFbRowSOLO9L6BQ==
X-Received: by 2002:a17:902:9f87:b029:de:9e09:ee94 with SMTP id g7-20020a1709029f87b02900de9e09ee94mr350606plq.29.1611250780671;
        Thu, 21 Jan 2021 09:39:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a416:: with SMTP id p22ls1447685plq.3.gmail; Thu, 21
 Jan 2021 09:39:40 -0800 (PST)
X-Received: by 2002:a17:902:9a03:b029:dc:31af:8dc2 with SMTP id v3-20020a1709029a03b02900dc31af8dc2mr350795plp.39.1611250780144;
        Thu, 21 Jan 2021 09:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250780; cv=none;
        d=google.com; s=arc-20160816;
        b=hE60Yh47tQ5fBl3FONfrph4xdOZuMe7jmI+NPdZMDmIFFazbgIeRX0seBVTh1sIuie
         sBuLO8bMykUAR+LR62l5L99rsEEjsSzqVM2IantPg6Wg7fc0JFMUhx0yMQl6qtHlh5jl
         Wt0bUODrR0paNvaIDg4FwKnD0Xoarcajp0bT4xTX/QTyb/d8IlfQF5YVil5kvmwEk6a7
         6CIdfpysxshnEAUa2nJHo5M0/koFOa5RiBBbMO/U0D6iobLfaOo9xGPWgM89M/iaezzk
         oaENafEqSj4PGar7zp9gciQ6D5kwgyg0IMs56stFdoswL7eD9kJ8WLy5BPYp9YWBLy+S
         OHzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=cZPn62k8df2eHGReTbH7zvYPQOjcSDKaknVRFGtfOko=;
        b=ELN1PRZIV7T62HAjF0r5ykvqD0MCrN0G0fu2CMdb8Hg81zwJzya1pVOtzyYEnRo9w6
         AHFLpg7pMYt2cBD5Liy35aLhsgXhq1Xomk0/Q37X9Q4Rz4cZUgS0itytZHIgILuZXGW9
         O4AYEfnb/fR69klFPYyiWPcqm2xw+mcdCnddS91bVVivZeRqAc+DnNeu8mqivcb3MUuV
         DI0DZmdaJebhCrIo3t0wIgaksbH1Vzqacm3m0qrTgwc9osTa1quA79kwaDl4YOiLDfO6
         YACT5qoU6vSbZcd9mS9v8rnRskWIN9k5r5c4MlZRg3L0WswJJTRYeTn/fyfREtPjqJkM
         qCdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l192si333338pfd.6.2021.01.21.09.39.40
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 09:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5982611B3;
	Thu, 21 Jan 2021 09:39:39 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6869F3F66E;
	Thu, 21 Jan 2021 09:39:37 -0800 (PST)
Subject: Re: [PATCH v2 1/2] arm64: Fix kernel address detection of
 __is_lm_address()
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Alexander Potapenko <glider@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
 <20210121131956.23246-2-vincenzo.frascino@arm.com>
 <20210121151206.GI48431@C02TD0UTHF1T.local>
 <95727b4c-4578-6eb5-b518-208482e8ba62@arm.com>
 <20210121154938.GJ48431@C02TD0UTHF1T.local>
 <5a389787-4f6a-7577-22fc-f5594409e1ae@arm.com>
Message-ID: <ecbc7651-82c4-6518-d4a9-dbdbdf833b5b@arm.com>
Date: Thu, 21 Jan 2021 17:43:27 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <5a389787-4f6a-7577-22fc-f5594409e1ae@arm.com>
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


On 1/21/21 4:02 PM, Vincenzo Frascino wrote:
>> I think it'd be worth checking, if we're going to use this in common
>> code.
>>
> Ok, I will run some tests and let you know.
> 

I checked on x86_64 and ppc64 (they both have KASAN implementation):

I added the following:

printk("%s: %d\n", __func__, virt_addr_valid(0));

in x86_64: sounds/last.c
in pp64: arch/powerpc/kernel/setup-common.c

and in both the cases the output is 0 (false) when the same in arm64 is 1
(true). Therefore I think we should proceed with the change.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ecbc7651-82c4-6518-d4a9-dbdbdf833b5b%40arm.com.
