Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBUOLRGAQMGQEAQ5Y7YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E94C314D30
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 11:37:06 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id z24sf5114307uao.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 02:37:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612867025; cv=pass;
        d=google.com; s=arc-20160816;
        b=XFrDp7zCo+p8y0EbmoO6ZQnNct70gVIX3UlYIaU6d+HNAo10tjJElnvNg76Jy87N1p
         ceNu2Tt4/9Lab5w9L8XW4JQtCMSdkDCv0brWHS1homPhjjxnBhdeugnRmdVRO0dkR/Io
         h8PXDmN9St1E/luAMtmwZEemCOfNSOsfeSrsAj7EMn1naU0NFCScZ379v2K8/yhJeSV9
         vK7w85huvFWcejWqyrS5ZvxMhglFSVE/ZVIfhM4lXPhRBRFu66H2w/fsYcl3KPGSsIx0
         Y4dMI3PjhrDGRZMgcgaIjrAYca198TSVuJpZfCNp1wSltL/V9mBGvSWhYgxuBrcK9fZi
         uNdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=cRgEqvFuUboSRKzLeHNilvVeHXAUUB7/YS/rUmroXww=;
        b=NOSEY2AIKAAiMXK70yMLypydy7TaCfgzT8/PQ+KuqpGslcWqYE2uF7US4ww1Suxsuy
         dFI3BRvwOvQT5ncBAyBVtuZHU72hyIVQIysHrOOdokqKlKFQwOJtG+rwUa/3gMmLOBjr
         zs+mJCdDj6CHCgAZNZgF8z7JadWpdSBII1m4V6Tgbj/Na8k2ZVH53PQJiLfb7MDKAy7z
         2QgTMnPROzDSfKNqmNoump+efnpHaiq4lv/ujKeAyfgAqzxIUToWmMc4ED3ukR8D7UAD
         Usr24DHWCwEeogSI8lmmATRye/ihs99FInEZsQ9yDeKAYJ6yCeo8BpM6DivqByOThOKd
         1T3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cRgEqvFuUboSRKzLeHNilvVeHXAUUB7/YS/rUmroXww=;
        b=CJjI0o0DDqnZkAsaDOCO3RvfR5qdrMkT1ZIjZVj5eInGYVDBOEp7akTh6CJKp10opY
         aff4RiaoKmPIaZdCTk7ND5n01klO/k95rSTua8fkTqtoBanhkklmi59JPwCy1JZpJN6G
         yNk0UKlC45j3F6UCVctpTMkwhhWm20Z3QzulYs9UhbJAlr/a8qdX9In5yYxJbKJ3DW2M
         uLeZpvOPVYrfgeSTcWm7YjiF58Ogqfxm1Fv/0OwktXrAuRt1yJaTOS2UoVPg6T5MwvEv
         wjA6uxctz3EfVYjgR9uzArpe1DiHakq7w73SAHgODQZ9MgT0ZoK1usmVeGDlDvm7hmnj
         TNoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cRgEqvFuUboSRKzLeHNilvVeHXAUUB7/YS/rUmroXww=;
        b=Nep24eNZxMmFrqLlqgFn2G87ZA+of6iuUklzCtao6ddOtBAYlKIM4SbXLZyAF2sP3x
         f1YIgwJVn+uFqEovVywqtaWxTl7UGMJ3NXnqIiYDjygqA+lY/SF5T/RxOVsCdpyKOenn
         asmBSQ7kHsPagDYcRuMRaa4VtEF9Xjc+VL3WuHQrnPayLG+3tWofOHPpE7zjxbWCoyfP
         2dLQ1XsAi862PNeZP3R4bkKtsKuXLLQyixkVfNT8nbVqvny1eEWR6V+Sq03z5+EsLdaD
         CY1Ko0vGkIeIpSG4deLb+ApLr8CnnfiOmRWqtdrUdHJdxhkeIBTC8/UdfXh2DuIsmfNZ
         1qwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KP+I42SbZPgmx2wtldiiyZsqjHwgw51IuKTpjEiz0shRZj1mE
	5s1Zf2EqKTMc6oZ8wUrOLQU=
X-Google-Smtp-Source: ABdhPJzPVBZt9XHD0/2zFVrcTLKg337Y8qLGi/loHq3NuMCSNmvQXM6j/2FYaOyqGIA0gxT+4whGRw==
X-Received: by 2002:a67:c89b:: with SMTP id v27mr13636502vsk.5.1612867025280;
        Tue, 09 Feb 2021 02:37:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:30a3:: with SMTP id y3ls687203vsd.5.gmail; Tue, 09
 Feb 2021 02:37:04 -0800 (PST)
X-Received: by 2002:a67:581:: with SMTP id 123mr13021039vsf.14.1612867024930;
        Tue, 09 Feb 2021 02:37:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612867024; cv=none;
        d=google.com; s=arc-20160816;
        b=M/vjh8mNtreJu1Fy19n1soydF5a/FKZqyTs7/ZUGuFGhHVjzS6O8UEECpWdRfYxPOX
         7uPZtf5Gt+zAK3PSmtGDLwRZaVBQmI3UQZXa9A14uhvx8e5YiWC0PDqSv5CO7GRynZfw
         r6xDIE95GcYT87RIjlYri6/Ula4qO/Tnnt/WOTbF3hBqf6ftxDqUQinOmw5fjc77V8B8
         QL0+0u3typR08Uwb7sw9A0zDORnpSRgQqefr6EGVkwENGiULJncU/thsVawGeAn0t8CJ
         VUgs6DwmsISJbSHVYaz9zOgiS0dRQ4hbMzK7BfR8jyb6wqqbXp0dQEwJY0thNRYTXovl
         w3yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=g/ciLjAoLhTjofAlu8/9h5ap6y2B3jWluWi3QaAsC7A=;
        b=H3lZhQk3bzPJkPlPQ1nzCo3ygU0KxzwcENUMYqLiBvKwSsmArTg9UQpQjoakyOAyh/
         pLdAcMUQh/8hOMzwbN7Kv1YSrhpaPjEUCc/k0mHi8+9IOCd2Uv4iULnW81KK0KyPQHA9
         IhG5whg/QD8J1SIK5UJaM7VLzibvwYphx5YqaKLHoliKe9O0PDKpbOpZM03TejkbmlPR
         FQzebNQvwz92WJWcDfkHtcMfPfGf8KsNsXUyedRrtgtnqZEsHzPvZB3vvg8d8IrvWHEI
         AF1LzolURn22In0+t+8EqjOpom0eiHB6K1N9iR1SgDc150jxI9FvoNIiU7Ofz4LduZRX
         CPAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f203si458903vke.0.2021.02.09.02.37.04
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 02:37:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 060BF101E;
	Tue,  9 Feb 2021 02:37:04 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1FE4D3F73B;
	Tue,  9 Feb 2021 02:37:00 -0800 (PST)
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
To: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
 <20210208185635.GA13187@e121166-lin.cambridge.arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a6ac58ef-f437-8a77-d288-c4de3316692f@arm.com>
Date: Tue, 9 Feb 2021 10:41:03 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210208185635.GA13187@e121166-lin.cambridge.arm.com>
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

Hi Lorenzo,

thank you for your review.

On 2/8/21 6:56 PM, Lorenzo Pieralisi wrote:
>>  u64 gcr_kernel_excl __ro_after_init;
>>  
>> +static u64 mte_suspend_tfsr_el1;
> IIUC you need this per-CPU (core loses context on suspend-to-RAM but also
> CPUidle, S2R is single threaded but CPUidle runs on every core idle
> thread).
> 
> Unless you sync/report it on enter/exit (please note: I am not familiar
> with MTE so it is just a, perhaps silly, suggestion to avoid
> saving/restoring it).
> 

I thought about making it per cpu, but I concluded that since it is an
asynchronous tag fault it wasn't necessary.

But thinking at it from the statistical point of view what you are saying is
completely right, because we might end up in scenario in which we report the
fault on multiple cores when it happens on one or in a scenario in which we do
not report the potential fault at all.

I am going to update my code accordingly in the next version.

Thanks!

> Lorenzo
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6ac58ef-f437-8a77-d288-c4de3316692f%40arm.com.
