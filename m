Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBO6YSCAAMGQEUTDVH2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 59E3F2F9247
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Jan 2021 13:23:25 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id c17sf13461787qvv.9
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Jan 2021 04:23:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610886204; cv=pass;
        d=google.com; s=arc-20160816;
        b=WzmloAiSgSohBoQ+Ek73ONJrwZKMeRCYc6FfA4hUBrvA8TtLB5m/yuwd5A/Lx9VUAi
         tbQZyaqn6t4/Xv/vqSyKiJhbDGNrpE/MfOPoFiP3gmpNpcj6457comP1yAFuKCSFQytw
         FOzWcZt4LsvcXrhEBl438YoXTymEY0+eSLEB07K91IETHiRmPW5wQ4Jv+ck0ek7Fw8GM
         qw8ROQtywFhUMNQCFFRMwFpqImQmS6XvihJgnmpHiuBENceI0eWjW6pVsjtmeKIn1Eqq
         sEQaeUdG+qGos9b6KruKCM2yu8mi9pkFLgnP6QHaatiOTnPMjKo330p5pDtU+YORs+MX
         ckSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:from
         :subject:sender:dkim-signature;
        bh=yDP6XwsmIDh6T+JGPGjdoCddqGWJqTR8OCicrlZE5Ag=;
        b=PS8trwOBVua40hPHQLCLRNZqi6bJnSN4yFR6uo/XA9ONIwRwLncDN3MeSJYYfJqXeO
         cWerK2w/BHyEgmtNiWBmsy5eq3Pu8WcGv8s8HCpplc0vCEbhPpK8LUouezcbtkhj08HF
         omz9leW1Kk6Fr/D2F/zRjZsx57WsskwSwqU20s8wABEvVvh7pmYsktwx0R8h+vLplmxC
         3sib3bI0MQBz1J4owJ0ARuK4S/J6V4Yb2kynhBWfh7rd0Izh2zEPSdMN4v1CWDYEpztX
         gnUmHo0lt8E1GSP7/yXYo7rP/cglKrNH0FFjk1t4SvEjrAH8krVilxzmhH4IkoNzAvEm
         iMpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yDP6XwsmIDh6T+JGPGjdoCddqGWJqTR8OCicrlZE5Ag=;
        b=lJ/9wH3RbIBvkfdA3fHsv4qGjhp2lMKiCENSpR1ScrDKghpy9LaYW4aSzgIziDSBI6
         bZ9pGlEIgMWd3utGzzEHmczSyqIlWRbbtutlQZKcvCXkS7Fgz1hBfkhg5TAr80C6uC72
         LGyX5VF5pkUPrBUye6IJK0de6ECgdZ8oezElP3UEJVjQBpxPTZQ8i82xPNs7JAqAX5FE
         bn/FgeRnxOdkM21ZWsYRA3jG16qNoQVSnn1D471cmWBMwlIJ1a3AKDlPmmmWY2KLAGat
         O0e7bZUQkBOQ3PlqCH1QKOgfqIQGU5QzIo1rYJVxZImgp5CoYVS9Ge9mXiwEIRpTJq+g
         QJAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yDP6XwsmIDh6T+JGPGjdoCddqGWJqTR8OCicrlZE5Ag=;
        b=pR0IN6NAlbr1fhix9qhwVKREWHPOsbr07HZTMlrO8EnwIOrI+suaMDNIRxRffB3afE
         P58GYQJ2md30SNeIUxAvApdT8rJc0WS+iuqMM5jl+Y2Ehrpl6nUcHHFOo7bkTR6kPPx8
         Cy3fRJE71667diDNX37GCsJuJ8D/ye+rF/6+iuubUmNwKbJY8PRchXqPK9WkS6qs00eL
         MNRAorPoHV5RPAWRxJQSNApM1DQdm2U39jetzhRBeX1R1BkiKKFw5ZB+77WAkia5TprK
         YWNAC1yeAdcLnu2e8zTMxQFyB7phyXdCyHEbC55btYTdriw8MqBoNK3Fcm+L8oZfeYBG
         0LsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dAkDSQNGpPFervfyTAGLybMV/A9MpmAHnSKjAm0Z4WzZt+WTQ
	eWzNjH8m/uUHchaa5waE+nc=
X-Google-Smtp-Source: ABdhPJwwih/ju5neUbbbK15qXE/8pYz3wsuDGdwrAf8vCYfbhVPDfAI2KNORUm+tuauQapdJuufuyw==
X-Received: by 2002:ac8:d4e:: with SMTP id r14mr905011qti.7.1610886204100;
        Sun, 17 Jan 2021 04:23:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:498e:: with SMTP id t14ls2941691qvx.0.gmail; Sun, 17 Jan
 2021 04:23:23 -0800 (PST)
X-Received: by 2002:a0c:8c87:: with SMTP id p7mr19730665qvb.46.1610886203644;
        Sun, 17 Jan 2021 04:23:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610886203; cv=none;
        d=google.com; s=arc-20160816;
        b=dr59VNOOoJSkTeDdAc+IWfgtzc28SvAlFGxXyxM6LbS3HLDb0mrGsWBEfUCSvpWxQk
         p2OsAFkMhUe11ZPvYTb5L7Gl0+OaxK5kE9BAJV0rptM3wUNtf94tp/Ejvi6KYb2gZrp8
         WMZdCHVCswLoTepp6Ts2loL3B398qtPRGzOjKqxgDhrL5Q2SsvxKlaJUnm2771RTBUhP
         m3RCsjvrJE81cECl3gCUS1EQS69eHbJJMKOWbI5XNqelCpCnAKYnU4+Jz6kYjOzf3+Hw
         91+Y3U47RQMlD54zVIoOuTV/jOqN00evL4Sj1f7Fof5LH7tSMufQkNLeUCAbLJdK9fxM
         v5fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=Xj10ZymXkiCdqoENnxuXlIVmsUI8Vx6V0fa54FN0zQU=;
        b=DjXY55ZqN8HZ3vuDU1s+azh9WZ3UpQ8UFsYK5fkmFwyMSvWKlWpvbmoGtX1+PQvvBH
         hfVooKFI3vv9SCggoLA1qFWtOXZsOGxGnuMt5vIHhcRrL4yYEeVEouB6OxLvIBD0J445
         gojUJcHzExINijttpoDYOvHXL3NWFQJ0ZauycpOrjA0Hw+9A5GR9UmHWjfTsEFPYxdWv
         7tNccvnHInIcED3ZauSgKhZjYVUDR2wngqEZaLGuaAloAhai7wqNerLCRIGhOjEH5uTC
         KeDNX1exMhSLppTtVjCYFIh5x6AkaFwHb2/9JNR+RpnpwKOMmkOog5xGhL1c6eyD+nVX
         ooXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q66si880668qkd.3.2021.01.17.04.23.23
        for <kasan-dev@googlegroups.com>;
        Sun, 17 Jan 2021 04:23:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DABEC1FB;
	Sun, 17 Jan 2021 04:23:22 -0800 (PST)
Received: from [10.37.8.4] (unknown [10.37.8.4])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C10153F719;
	Sun, 17 Jan 2021 04:23:20 -0800 (PST)
Subject: Re: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Catalin Marinas <catalin.marinas@arm.com>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-5-vincenzo.frascino@arm.com>
 <20210115154520.GD44111@C02TD0UTHF1T.local>
 <4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03@arm.com>
Message-ID: <0c1b9a6b-0326-a24f-6418-23a0723adecf@arm.com>
Date: Sun, 17 Jan 2021 12:27:08 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03@arm.com>
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

Hi Mark,

On 1/16/21 2:22 PM, Vincenzo Frascino wrote:
>> Is there any chance that this can be used for the last bytes of the
>> virtual address space? This might need to change to `_addr == _end` if
>> that is possible, otherwise it'll terminate early in that case.
>>
> Theoretically it is a possibility. I will change the condition and add a note
> for that.
> 

I was thinking to the end of the virtual address space scenario and I forgot
that if I use a condition like `_addr == _end` the tagging operation overflows
to the first granule of the next allocation. This disrupts tagging accesses for
that memory area hence I think that `_addr < _end` is the way to go.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c1b9a6b-0326-a24f-6418-23a0723adecf%40arm.com.
