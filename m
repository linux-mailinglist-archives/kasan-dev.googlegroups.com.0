Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBU4V2GAAMGQEPVI2FMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31312308BD8
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:50:12 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id l1sf4376456oib.10
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:50:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611942611; cv=pass;
        d=google.com; s=arc-20160816;
        b=WGYnDLLr7D51kIj8SXMpxwGOUhLYfKgu/isL/i+jN26nRgIdWWl+DP6cAtsdpWk5/a
         P7bgn/OXBJ0FKqFfvYQbxne6arfDMWw4hTdfTyNvex2uxJywIk4S/g19biYCQCiJGF5R
         6HPl800EhStmI9NAdqgvurSiC2k510hdJZsxzkRtEiDXsmIWXJ8h03b5F1HnHhP7fjZo
         i5a0Xkxxbz8kgd8XH7zBULNU5hVfvMPHYAQgdYfvmKvliEFR3poPHjKtvyJO6mgOLRgs
         fVUDfybIQFnjnLwJ0dc0BeZ5RVxsOkr0XMgUN8DPWh3MVxpKIr0wFepJkPgY74r/12aA
         Uk5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=y8ETEoEE2fGkZKEoELvcaT7OIOjBToN1wdeklbAJQrU=;
        b=t2IoKDSqjfXmUOEgMsZrqKc7gq+HZHbfh/4t3219Igu59+ODMvdyrNqgphtX+C0DRu
         jH/5Ub3Elh9bY7jlNbVi92QSfTZbEcYOvSTEOmu6KbYRfx9dh+3yKv2ZR7ttcwf0NJ3Y
         z8b05x6q5rE2nzAGGAPpqg+pqmMcWwEunz4UBZ9P5mLA2+VLq8a6BoajxJ4IyR9HZWdc
         8eGxCxWn+ITTY3OEeL0kcIK2Nyx+txx4GwK/9fVRW7DjC9WZ/daKKpzJ3s3WE5FX+9R1
         vWEUXXcU1j6i2jmm5BcZKSScQ5sqIPnyerN612mEs1YwZGU1rjzrdbmuX06c4BTlQAw/
         GqRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y8ETEoEE2fGkZKEoELvcaT7OIOjBToN1wdeklbAJQrU=;
        b=V1nRYU+JjGxkNymf4K1GqE0vTg06eGPdNihGmILDNK703ysjFrUV+R295UxiYdmFni
         aJ8FiloLENcGaz5PJ63WbzH/NIExugLMQF40pdQmsK7qiZU3xzjK5FkMX3Ebo6HTK/Pf
         G8Usxk6q0C8imU4pWa6ZcxCr6I+PNxj0ajGX8iEgg3vHYt5BkJJjBoC/IQpOlH2Xw0JA
         /lQz2KLfBExQ1WJiDSIDVgYjuwtXR9cxIFM0hFpc2SGkWh5wa7U7P0DVYCuwCyM3hJlD
         mZYKWMdziW4JrLkfRm3oUB6CS4+r+etcgZUHFmli5Xf3gM6mJ1KEA+hHqeCx7Bc1th6w
         avtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y8ETEoEE2fGkZKEoELvcaT7OIOjBToN1wdeklbAJQrU=;
        b=N5NLlbCOfJIm2Fcp+Xd5DYrY0sBXh9vhHJsM0xGYd91QvcV2YePt2YKxW6yrWZOrVo
         eQKfNUlvltoQUY3EiLdFqWo3D7pKaZE8RcGluAuUejlO/AqKd9QxP50mT71qGenSWvYz
         3CPmWOigfn+YMrL1fnj/tQDgokE006bWIssC4xAOStdObNtJiRDxU6W0NPad5NrTwyzd
         5RTKG68Ov2gYY86zmevsbz8Q0AVBSpDEsi9faIWhqU1e/uTqPfxXoRYM2+ZX0yVKR3/y
         byoG1E15GPMk177DHJe/wKmOmUaCOMF7gwCmk/68S1AhrbBMQQDqeIf7Z8GEZ+Be3UCA
         M7RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qxhSHBNNsC1sIi2scvVyLphpE+0pja9YfVPh1czhdz8llLDrz
	9FBAF2/arTFAY9dEP8u6RlY=
X-Google-Smtp-Source: ABdhPJzH2ONuqcIq78dgSiZo/+ZOpQFHiIvuOJHY0njSnSl3RZDs56vUDTTYudhX0wyVrFU+szfWlg==
X-Received: by 2002:aca:5d04:: with SMTP id r4mr3306299oib.43.1611942611148;
        Fri, 29 Jan 2021 09:50:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:3cb:: with SMTP id s11ls606467ooj.5.gmail; Fri, 29
 Jan 2021 09:50:10 -0800 (PST)
X-Received: by 2002:a4a:844c:: with SMTP id m12mr3815352oog.30.1611942610757;
        Fri, 29 Jan 2021 09:50:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611942610; cv=none;
        d=google.com; s=arc-20160816;
        b=ZVbBVKrjHAFvF424gq8kz+VdHidiGl5PoTzF2fdL/DvV9LJf3GI9xyJ1P70eUenSTm
         LhkGDz1QLmO5D5+8yZqXbTBzvAWzih7C225Np6d/Ja7F/FbZbP4CAWZ3mC5fi2FRfM7h
         qR4d9YaNZA8qk2+U2PqhY/7JAZuqlJMIB1bIqGM3ZnzqwZkQk5xfXNqcXaHqB0J2CXQP
         wlTXlV94irGLB7m47PnaDLVkwLklSyfkMNxyw7/bai9sXk9SxgqXrxto6tpaTen9VbAr
         rwLmmH5Go470At3XrOjeTMVNZ5UWuSycZ6MwuxDpqxYNl2u+3eQqKTip+ZQPAf2voP56
         qn1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=lHkYhPdDozg2gxEH5uD5iEII7/PfWn08wvd9ivNBV/w=;
        b=EX1k7S4QFnP9/am6lA6a72tyWTc+nCfRSXjs9pHQqlz3B4PmvakRWMAvI2i0j21hn2
         inMBPIr+OYxQM1nRwQpC7TuK/Y34M/xES8V0ttN5i4elnrQ7LLKZHVUxMmbGE4vu6mSh
         JzMedapJ/uKiJemE6N+l0+Fdhzl/asDqzey+oL0N9uWzaagUFzTQHZeLihcQizZUWDUF
         PgmvhFUVkw9svugRA0OWXa+5qwz5kWS02K1Jwtj5hdBUZHmQ5L1Tk/kCmKBOglah793J
         oNoHvs5UVy1XfjZHsyOV3mYotSjSo0rVicv06LJ3y5KsjR2GRx1I+UCht3En1QU0BPg2
         tjxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m7si596749otq.5.2021.01.29.09.50.10
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 09:50:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 444D513A1;
	Fri, 29 Jan 2021 09:50:09 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 22A583F885;
	Fri, 29 Jan 2021 09:50:06 -0800 (PST)
Subject: Re: [PATCH v9 0/4] arm64: ARMv8.5-A: MTE: Add async mode support
To: Will Deacon <will@kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <CAAeHK+xTWrdJ2as6kBLX+z64iu3e6JEGppOkN-i_jsH74c6xoA@mail.gmail.com>
 <20210127221939.GA848@willie-the-truck>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9d619e7c-ab49-987c-2087-f44a47551d7f@arm.com>
Date: Fri, 29 Jan 2021 17:54:02 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210127221939.GA848@willie-the-truck>
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

Hi Will,

On 1/27/21 10:19 PM, Will Deacon wrote:
>> Andrew, could you pick this up into mm? The whole series will need to
>> go through mm due to dependencies on the patches that are already
>> there.
> Please can you check that it doesn't conflict with the arm64 for-next/core
> branch first?

I just merged for-next/core and has of today there are no conflicts.

I notice though that with the introduction of:

ceca664b9581 ("kasan: use error_report_end tracepoint")

the interface of end_report() is changed hence my patches do not build anymore.

I will send v10 shortly.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d619e7c-ab49-987c-2087-f44a47551d7f%40arm.com.
