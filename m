Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBEVASWAQMGQELSDRAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id F0F65318EE7
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:41:07 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id bg8sf4316067pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:41:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613058066; cv=pass;
        d=google.com; s=arc-20160816;
        b=TLHRSnYdeFkJ2qdSfOme4+dpwmXjMSMGeWReSljuA8O2kGG49CvxnEM+EOIRr/plSj
         jS9tJvGNtlgj9Wv7xj//AnmPAaSZ7j8sWDH7pko3QW+gBds7eyZ/6QhtOfNxYgL3XG33
         wG6BRvyKVovR0cymHkZ57B7DJeCYxPxdquutjPNNdOX+EpVCFs6UezQqVyJWKtt4iC7a
         qUG26PQI41RR71uiQhPpWotL50c/KFBd/Q3s7bKpPw1HT995UV21ADcbzy6Wy8HlAqQg
         MA8IT2vdlj6gXwTj3/NPplVm60qgkzgsJGgqks0+KMrtw/OqUHGWBiwXdQ3AefEn8xPg
         ix+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QlGBgDbAQJOj804eVU9QVsY54ZKi7bXqdnuKZkWfXXM=;
        b=xnuu6+6DHjCCbnz4cM+rGDS6JJD4gP1TK3McaKvDi4x+ePkY4fHNiLM7NrUCInqBuC
         02KU9ZuqncRfj0dH4tqWl+fN0epGjaWdU1p+pXMr1yQdY1FZqee0R/2M65mJv6Gt80uT
         IzJiKyb0/dvWKvkSzlbBVIw/kqsx0X/3ZY/OJHyYKNLamhBtugTZSJcjZyrIgv+lhgIT
         YjwidiZHR4Tl4seOpeHYHQcm/L2AIXjoXpIfWwEHnbGARs6phlcA3+/eoiQMbOexDI2K
         J8Fi2vuUkpsYFman3MZKxI1Yb6IUtwNG9V5eqU3Jtoh305MTjIo3JaQ/QWwarLtHlILd
         n3YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QlGBgDbAQJOj804eVU9QVsY54ZKi7bXqdnuKZkWfXXM=;
        b=NL36oZwgN2hY+mktre3dTaKuOfYB8fKgkcaUEuCENbBx8/DniehIu5HphYHAg36vJJ
         f7rEjBC3caPnglO3bEG21jL4C0Byu3qkD4A307mhtHZXyu8Z7ZeIPim80UQHHryJMWOb
         +eiEklizd1Tay7yTbr9XE6UyLcttTlWt1VxyZUOg/WEvU8872uoVGEm5KhDlt1zY2yLK
         +IC2J0kO5sv/CTWa6X8EN/NcITW+yFIWRRFQfjbBrepMW1JWcM5X9W5blde/Iy287PbZ
         Ds00WjDRGUxNm/GTCJy5AbMkYCXqGETiwUw2SiX7+VoGS+cTOR4tUattYzXrTdDLeS1h
         e4bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QlGBgDbAQJOj804eVU9QVsY54ZKi7bXqdnuKZkWfXXM=;
        b=jW1DiO31nwrpfiubJEM/WyhTAUBL6Ia//USnTaBdgCg0WRpq+OgweQInTx/AMT7VRE
         6sriV225c8ATfs721YCwDbinCuEI8+jlGqanfwhSG4Ssv+L/eaq1tAnciflavQhtMaHT
         yW+shNTDcUB/XDCxr8JNsIx9tuDud9m/6yFm1xcQ+ugWh5ms48Nbzm7msZS8WT4Q3ZO0
         BMkaU6LXf11fvGHs0pdJJCYC8SDLAKt+h/TppG5eCbzNNgl10lQKjpD0gG1E1nrqwyQo
         ZYr+FLYUNdoOG4MP0VDfAFwpiq9GpPZkryFQwOk1jQqjmjW2ZSQHXVz0cpRiwmGxHcaa
         U+YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Gzol60JudYgoEDtItnHcplR/dPT8AApLZl2gfyQB8UV6nRRKS
	u+WNTsOvoZy4Yom54Li32kI=
X-Google-Smtp-Source: ABdhPJxZNgvtwxGcSyyOCSUmcZ0+csBVsySRxovamabLxt8cx4r6WTXEEKJpt+DJNKi4ydeAOO0skw==
X-Received: by 2002:a62:528c:0:b029:19e:4a39:d9ea with SMTP id g134-20020a62528c0000b029019e4a39d9eamr8424192pfb.20.1613058066736;
        Thu, 11 Feb 2021 07:41:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a15:: with SMTP id m21ls2230392pfa.11.gmail; Thu, 11
 Feb 2021 07:41:06 -0800 (PST)
X-Received: by 2002:a63:5a05:: with SMTP id o5mr1853969pgb.452.1613058066087;
        Thu, 11 Feb 2021 07:41:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613058066; cv=none;
        d=google.com; s=arc-20160816;
        b=lZKcVLTG0n9dW+c9L7ar1LCvF4FUNoOcMqlPSlXrLsEJlwnS+li71SZV73nzirPzSx
         Zis+UJvCtyS5XnIbqWwM1JFKWAirX/ERp2twp95qGKs82hPkJeYo0a+KAP5HFUr6TZvY
         /jHR0qWf9Y12OQTUScKLsc93wGvav95xKBIPpjxaYYFH3pEaVgrx9MwDWZVbo93yJb9+
         BhTIg8JZhLywK9M9OjFmX/95KTuNWDJSt57P56x5/IxSzBxKaWJGvEGzajpOsLyEeZ63
         OMJroTnf6Q9nxbgjXDy3du8QARCwymQAUXCWIpZmcUcXMi5+Y3i2Ko95h65HCD+jq6oe
         eVRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nCFNVl/0DYQzXQGe9udKOCBzb9RTZsL64lUHDycVya4=;
        b=G6xF6fzbmmBTQTRFb64Vm0qB8UWrFOeL5PNBFw2dsaBIZCLvr+JyDj86KGNFfrP1LX
         DjTKZGwgnWdk5Iz84bvzwp/RcY/YHGiI9z1WtwO4GDafkPIZwtVnp3O/GQVqey6vt/YE
         E3VM2eltuWhLU5ee4I/DZYPn3gbk6qsJoYr+kOusPyosStUIFxfcV5TI+Miw6mjYrHpz
         1CHwLv9Rgvxl2d+vKRfzPD2bF+qH0bCRa+Ag0nD+c/ImHfI2PbIkX8XhvQi4/i6Fyvfw
         CP9oWf2H5E6HTEmci7PJGxY9yu4hcd3GWVafiX5Hl4QmlNMNK/0BFpjxYRCg2NXceII4
         CSeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i23si282353pjl.3.2021.02.11.07.41.05
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:41:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7191B113E;
	Thu, 11 Feb 2021 07:41:05 -0800 (PST)
Received: from [10.37.8.13] (unknown [10.37.8.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8A2023F73D;
	Thu, 11 Feb 2021 07:41:02 -0800 (PST)
Subject: Re: [PATCH v13 0/7] arm64: ARMv8.5-A: MTE: Add async mode support
To: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <de24f34c-3cbd-39d6-fe7f-6ea801bc76cd@arm.com>
Date: Thu, 11 Feb 2021 15:45:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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

On 2/11/21 3:33 PM, Vincenzo Frascino wrote:
> The series is based on linux-next/akpm.
> 
> To simplify the testing a tree with the new patches on top has been made
> available at [1].
> 
> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v11.async.akpm

akpm tree seems currently broken due to [1]. If you want to test my patches a
possible workaround is to remove manually the content of $KBUILD_OUTPUT and then
do the usual:

make defconfig && make menuconfig (to enable KASAN HW TAGS) && make -j<n>

[1] https://www.spinics.net/lists/netdev/msg721547.html

Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/de24f34c-3cbd-39d6-fe7f-6ea801bc76cd%40arm.com.
