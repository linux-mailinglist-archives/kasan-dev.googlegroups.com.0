Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCVUT35AKGQE35JNKAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 16DC6254454
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:33:32 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id b10sf270993vsm.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:33:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598528011; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4gWiIpPbAMq2lIcrNftVX9g9tM8zjt2903ViMQKmgmKzvXYtdkHfhHZOYF0e5Hbr1
         NyTpgoLVmRU+FbxiGnc0rRbdr06Ahll6VvYvakp+9+a0Vip9nWKT3KtPbitRfJIipFL4
         u+X+ssJkcRf5mvKSk2VxK6UkZEVf+3NGbe2KBHmIZabF/8Fc05v4qKplGvKyxjs1UR3p
         h5uSFLdjwYbjvbaItooslkPFOFgMhtPcXxB9yjbmuxZWD40YNiEdCY2ZbL6Uyyr61Aai
         c2VACLmCEe3mC5ylt2xuuWYPadcA2c1ZC8uU1tGYTaW7zEluzUQlvhaZSB0EnmaiSOHT
         6VZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=WwMi3EEd0HF0eq6UbXPqXh7/d7EBkmIYB379nnY4pXk=;
        b=A2Imif1DO930FzcvXRWhqdO95ohO9a7642U98VCOKO7qeBQUPqkZkkyUJkQruS3SY2
         IvDGEkh/cOm15AyeyUhMSYyUm12tEwj7Dj4XAeGHeIWN/1hIUZ6w6O4ZeYceUkFeODam
         jX7RJ6X/gdi8rQBz936Rss4UOqpyPkfA8gKkHT7+Z1+D+5KeKjZGeeSnoJmn2RQzIown
         a91W+N0Cu19np4CQZgk+AA2egcguWN+4K9HWSo7GTTMu2mruYnvozFkA1kVfCX+Xg2G5
         y8B7yE2DwDTrKtVjtM+CGQUgHox4ESsYnPRWdXV7/kQ8JtPOsqMin/sXoxkWLKGgL/5f
         gjCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WwMi3EEd0HF0eq6UbXPqXh7/d7EBkmIYB379nnY4pXk=;
        b=RukrAgIedeThppGRo84ywRSE0Jx/XgfOgTGF85Ya0CqqpnCubVhcjC+ETtEJ7efDU7
         aPIcgFX5+8TnhPSiZeVQj4XPTCxHh7hzSa/oc4iUmQoU42H11btTCTbWJzYd/TVaV7dk
         DGx/ug1LpfqBpZUW8wBs9Q4itFFaJlOipes239TAtZ/NZ5sGV2UURdXysLTLP4yyVpn3
         umC10hkowYkV5Vi34r/KlgRGeZm8EH2ck+Xe0FASodn7ktwL4tl72g7/3/eBA6apoI7k
         OzaSI4a7Opa1DXlIMSiE+EYamWMqytsw8o5JamyaEbe6qzai4a/2kU6BLkvPoKmmRVsL
         Yk+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WwMi3EEd0HF0eq6UbXPqXh7/d7EBkmIYB379nnY4pXk=;
        b=Ckz6+MEcx46fI9drV3wtDYYmnlAnZAJWiACPiNv9rG3Wlx5mxe2XWVN/VMYx++xInc
         F+4WQWVt58SXCy8cYdnOQpTkMK3D1UiVBc4D8qGcE1phbLwnejYfmVOPRAmrw9sTQabq
         u9mbpm4RFIgnoqDNnHXDd9CCwQ5DUjB6KO5165NnNqynJVyZg/y0eurVHP9e6azgVdj7
         asxAVDXESiC1tdQHbXDv5Bvf+4FOcNHtlgKL2zYwQhYOflrAPuDTz8lk38mXtSpJ51gn
         8dUfUAYKFvfSyn/IwxNLF7+98FmEgwVfbd66VOOe5IkiRsJu/+OeIhmLFhNJf3CbkmzS
         J4ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532auHy5wzv8ngUY/9bPZL2a/GSY+aD2wBe8Q5Mm//+pd3JFdJVe
	C3ymt8aiEgoIy5DtjB23Gwc=
X-Google-Smtp-Source: ABdhPJx3uH0f9aALwwHqPXOGsi+ASAnqkjxszKSs+CUpIH0mGsg4Xh45JnuzT0KCwpykaMp5/1NSMg==
X-Received: by 2002:ab0:77c1:: with SMTP id y1mr9609884uar.120.1598528010999;
        Thu, 27 Aug 2020 04:33:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:24c1:: with SMTP id k184ls223696vsk.3.gmail; Thu, 27 Aug
 2020 04:33:30 -0700 (PDT)
X-Received: by 2002:a67:2903:: with SMTP id p3mr678532vsp.18.1598528010769;
        Thu, 27 Aug 2020 04:33:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598528010; cv=none;
        d=google.com; s=arc-20160816;
        b=sRSc2qkmOE5qCODI9FWVUn611+yZLg5p3Ltzr6ryePW2s+70N5mCDwzdchbLZjBmvC
         b0fCU1mCsMwtUW3MDjySd8+26Pg0heXuddz5HIHq8HlGewJ2m5cJd98+r5hpDdWEiic0
         fkGhbUiLSdCBYC/Z4uPQMKz+VEpOLSgXvR5elDwhekkgi3WJv6PDwxy+3+MX2jHnGxaq
         /WiwnbYrIpd4KPngIgd6cuiiV6CjxIKQ4XQKam9ijd16YqJGpJjo7YAtW126hy4MSYGT
         gPmzKiuy32/dtSqn54+K0bR56zfF+euRP4WxCP1eZ0nh2tLblHPOptjtCaeuNoh1VSOU
         +JEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=uw+w3GNyyv6ofnCFZGDCSu/ounA7lJCQKoxLSTs67rE=;
        b=ytmtMN8nbzxFup9U+O8mU0aaJRnp/rJ3IqKFYnmnNqiPSSWoFmpjTwOyXp4tUt4/8f
         iV1+qPbrasReqhoMjy60o8OwweXMMR4t2I9xrcgHY5r3ReEXkPsV00lpzRJmhYCuAueH
         rGppj82ZX8+xJ+3KAnivT8TO3scm1xX7zgOjchfPOJ8ryZo3is2TxlYyOqkNMsyOsmLC
         tYIgLvjn4sP73T7J0KybMGaOerjs8RupY2y7ujiPViHQkQ0hO8hw13klA5w+fvNcCEqO
         gJRyy28BhFWtzR2qie2C/TdbMf1V0OcpWSXFEKiXRylUjYcZMAUqCHY5cGRiRieuN/0W
         CGTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y3si122198vke.2.2020.08.27.04.33.30
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:33:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 38EF91045;
	Thu, 27 Aug 2020 04:33:30 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 21F033F68F;
	Thu, 27 Aug 2020 04:33:28 -0700 (PDT)
Subject: Re: [PATCH 31/35] kasan, arm64: implement HW_TAGS runtime
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1597425745.git.andreyknvl@google.com>
 <4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl@google.com>
 <20200827104517.GH29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <567f90b6-fa25-6ef3-73b8-45462cc7ceb2@arm.com>
Date: Thu, 27 Aug 2020 12:35:41 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827104517.GH29264@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

On 8/27/20 11:45 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:13PM +0200, Andrey Konovalov wrote:
>> diff --git a/mm/kasan/mte.c b/mm/kasan/mte.c
>> new file mode 100644
>> index 000000000000..43b7d74161e5
>> --- /dev/null
>> +++ b/mm/kasan/mte.c
> 
> Since this is an arm64-specific kasan backend, I wonder whether it makes
> more sense to keep it under arch/arm64 (mte-kasan.c).
>

Yes I agree, I had a similar comment in patch 25. I think we should implement
the mte backend entirely in arch code because other architectures might want to
enable the feature (e.g. Sparc ADI).

>> diff --git a/mm/kasan/report_mte.c b/mm/kasan/report_mte.c
>> new file mode 100644
>> index 000000000000..dbbf3aaa8798
>> --- /dev/null
>> +++ b/mm/kasan/report_mte.c
> 
> Same for this one.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/567f90b6-fa25-6ef3-73b8-45462cc7ceb2%40arm.com.
