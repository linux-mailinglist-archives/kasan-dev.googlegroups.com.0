Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIPC62FAMGQEPIMV67I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B03F5423FF7
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 16:22:25 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id d13-20020adf9b8d000000b00160a94c235asf2192001wrc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 07:22:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633530145; cv=pass;
        d=google.com; s=arc-20160816;
        b=ykGaQyQwzn7UfH3O+uyQi+ow5LBI+DM1P5TBMUvcA0BXNd3Xq5LaT00gXfV5wMQVtm
         aOlED7xLngcH9DZWsyEkAhAyN+dHF5jOt0nxpCnfjo62H4s3JZgiREsX1b/VOho/NZk7
         MsagfhFu5kAaKc2yrycXgKVyo9dsVjPmI9vd7VlOWy+bC6Cv+TGKSXcya7AdNUObZY3C
         C7diMIbEtMGKRvIP60iZE1nY096c1SfdKw71VbdnGNhiLFqLBeGu4QzhrLUEY3IhmH8o
         4rsKCJ7H8Qa+aImXBYl5xSzF7Y4+hRaiQd+vuZJJHsWMrnaJG17Mguw3oadwLoyEBTmK
         mVaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=4JHOgSdSU98pfUc2GH2iuVNullEcI3twctA5X+48dk0=;
        b=SzCGfGqoQ5JNZN8W5V+EohHIDMMhlucJcrgyNN+jZ9pH2qvhfEWWOq8p7jHCrh5hEZ
         eQmSMzDvjQCuGy4GkYKG1h0SWd7/srH+d04ktQ6lbd5/7uoN0oRZB4DDzHowXo/xjHnK
         D9Qbl9znvRwXom2mPsXFzc6gmolDZB4sbsAJPCZ95oEQIJwTNc6SGj4XU6MiH3a27qz7
         uPQroB6ngVoO64m2B1Fl6ODfND9qVSo5gyPr5Q+oZCHTdXb8qcAzFmPVS7nT4vvGTXWu
         Lytki+LCEu1eF5U5SaqYz/66aStS22LSf2fUnMmi8kdEGt6PhOGwokNPqxy7OCQbthY0
         vfng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4JHOgSdSU98pfUc2GH2iuVNullEcI3twctA5X+48dk0=;
        b=QFa8u8KUNQY5ldEgpRw92N4PJWWntbE6f8BQ6gGfhQ/9jbkxfTZCdteFH+O4+wvBWT
         alTrypEKAOUEN1bMQeBxJQNKTxBMLTAkGnXs0z+WLTFakMkBla733nOQrE6NEDLUk7fQ
         sBg1wKfysJ/QGjSiHlT/gPIelOSdsRaug/wZfhuM1q2GeT9x3V6+xDJLWXn0xGTuFoy2
         31+MiL7t5vql86i1QZ1nnTiAfaHSeY2VOJRwfTIbKNYEC510Xz0MhsJVdsGBV1UnETkw
         fyx0XelgAzMOUxXOKyRb+MikqbheVSiuaJ+bCZOpj3IW8/mVljoRosc3uBLhQN+/xNu2
         kWYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4JHOgSdSU98pfUc2GH2iuVNullEcI3twctA5X+48dk0=;
        b=0T4Nkn/4XDfMCNFVTcBQCkYZLiZ36rhnwaO0U+R+IDQhojtEzTEH6BLG6cW4WH2WHY
         WTY80o8kWlpCEUc7aijmjHO8xIp0ZfKNpQs3qmSXKR9ZDTc4QL2Dqo1Sml3HtvnUH86A
         LqT8s1d/CRZv89gaNfQ0si35Kz+BCukGbv6eaONyIoBwREGfM8xY17EPsv/rR85RlKzD
         7JkB+L8l27C/jn9zy0FsADkdeYamBtq0I7m75wrPlzHt7Kys36NhLG/exPyYGV6+NrWl
         bVVYu63LIoz3/mtZkx23zhnqHfZld6qYuOAaWA/UzXoFmuVhZIQc2H20aWNG3jdQhktx
         oEEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XtEPfM2YfEXHoOyuDpMmyh41IMx2yPTz89JAQCKLwFgQ/i84t
	yLyotB8ZU6+aApg4kUyTATw=
X-Google-Smtp-Source: ABdhPJwnliOzxKESy8QdBevixNLvTbVtrjXaZ2w/wAPtERFV7GzfQREZCLym4ROLugtfb5b5C+JF6A==
X-Received: by 2002:adf:a549:: with SMTP id j9mr21635879wrb.123.1633530145500;
        Wed, 06 Oct 2021 07:22:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c3:: with SMTP id g3ls112440wmk.0.gmail; Wed, 06 Oct
 2021 07:22:24 -0700 (PDT)
X-Received: by 2002:a05:600c:a08:: with SMTP id z8mr10352368wmp.52.1633530144803;
        Wed, 06 Oct 2021 07:22:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633530144; cv=none;
        d=google.com; s=arc-20160816;
        b=bMcqN3GcxLIyV5JmvUypKD59OSvbpTN+SDODw1OlvHi53OLJzpbELJ0Cpeo8fjHznb
         hvDiasWx+j0t3Qi65HrFx04EEohIv9xhM0KxX6oWcrEIA79bYx5OCmTINoYrp0pYJr3R
         /mHHCvfM0S090c2+t3udcDGP19XpxOj8QJ530V4M6s34puu6/xLTB+ehAxmHwxzSbvxW
         ynL7o/7gmS1DvtPi7On1I07d8nc1R3AWPbUS/SBwjNywBvhsBvyn66VwriwcwufxFf3w
         I64mSvAfhc0Anc7GnpoUfDGLktT/agayW67Naue3/7YElGO0xCBEtGkCn3eH/CYofeYQ
         XOBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=SX6/ryuExCiavJ8H2Um8T0jzBtM+GE41+BXw3u2KU+Y=;
        b=YJRm3mweswGKMCI3/GrS+cNaOdPQ+JeKVK2vzJA5nfKkLYhSfdiYtqK9C3KzrJo4qf
         auWi00mOUI9iStyQ0K2nPWjQI/tzzeQjV8/peBsmUGqSo18LZUhNjKAqwPEP0+L5LgVL
         PAGl9rx0BOQJc6/i67Jie4cm4QnN2UNfSzFauSOTnrPYDd+bCWC1u5Ci4hAzuxkte5z4
         iLull3gLxmJ6ULfjo7sO1O3xMQlV4PB0C0RD4dGNsCVzUUZiZtmUicmgHeoOPlUacVNl
         WnTrv9jqHsxVPvs6DiKaCZ/3jZoThrBjmcqRYXD0kHoFy7y4sl4XcJVpFAp4tto2k7tZ
         gdtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j20si428631wmq.2.2021.10.06.07.22.24
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 07:22:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 18B136D;
	Wed,  6 Oct 2021 07:22:24 -0700 (PDT)
Received: from [10.57.43.152] (unknown [10.57.43.152])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 012703F66F;
	Wed,  6 Oct 2021 07:22:20 -0700 (PDT)
Subject: Re: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
To: Marco Elver <elver@google.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211004202253.27857-6-vincenzo.frascino@arm.com>
 <YV2J8/i7C/FYf4F1@elver.google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <53a2d27a-57f7-a5c8-d8d0-17c78d95decd@arm.com>
Date: Wed, 6 Oct 2021 16:22:38 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <YV2J8/i7C/FYf4F1@elver.google.com>
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



On 10/6/21 1:35 PM, Marco Elver wrote:
>> +static inline bool kasan_sync_fault_possible(void)
>> +{
>> +	return !kasan_flag_async | kasan_flag_asymm;
>>  }
> Is the choice of bit-wise OR a typo? Because this should probably have
> been logical OR. In this case, functionally it shouldn't matter, but is
> unusual style.

Good catch!

This is clearly a typo and a copy-paste of a typo ;)

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53a2d27a-57f7-a5c8-d8d0-17c78d95decd%40arm.com.
