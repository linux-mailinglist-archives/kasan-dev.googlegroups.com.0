Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBEECUGAAMGQEUHROQVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E41A2FD2DA
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 15:41:21 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id w3sf21408289qti.17
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 06:41:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611153680; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yq43jpeDRiMT7N5uK8nCTCGenudkyaSBwbI/sDWhMxulWHorVj+dCNNeRY3Anj2cMa
         KJSTmq7AlfQ1GrxDcw3BAXUaXpkZQa/PdcJFu/+Ls2pcK0Yx8FYtjBMJK53p7scAWxsL
         ly8ijmXTvuVwBLSUKmiVMWGSao+Ff+H4PzrLU76eZViXfLtJS3lBa4XQjLG4VDNDd2nN
         SGVkMBueMXwoyMG5i0IYrrDrLEbK0PmJycq/rmeaf/oq1ezPaEI9iAuBoLeOocgxa769
         ghKchcpNMQOUmIy8b3YJabwYa/WDbFdvKFycShVdCkWjZLXdLxfl61MscRO3I6gZ20f7
         stIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=4a/ZNouMvx4QUKYsK3LtvucZ8Gj5PoRSiguz7WWDEzE=;
        b=B93sNiucYcRsoro+6CJQRVeT64LsMMzUtmTFIPGon/aO6jDcCa2GFz9yhCI3y/kH92
         aSrcqu6q3/4qdA7Kyz1fb2an6DR1B54JbLmQzvOpixKMmoAM9H/9iwZt7L/xGmPcZlBc
         qUmP3w6KpW5+PACJBzsa0gfZZ7Fc6n8vesxss0pW73AnWDvra86i4qHzmCv/Z0Vgap9z
         af2bd4wISZFg386sNe+63tn3Ala0vt120lxY8Rf8dhrVY1/tVEsqB9Wu1OupsFndj9nr
         uWD2TGgx2Koa4Ve96EztkJTNDDHQwCjDjhS+eguOhai3NL2gWAxL8gZ9+GZvzvSebc9+
         yolA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4a/ZNouMvx4QUKYsK3LtvucZ8Gj5PoRSiguz7WWDEzE=;
        b=aHryBeaypJgChIEI5sAjz2HjmN1KSR/jumlaoy9Gw8wHXbliqVer3YOhrfnC0B1sfK
         pzRBngwmdXzn8dEilU1kJLUkwNT2e7Xal7ogAvadDJOZ71yZ2C3vO+DWHjfdjpREi5+z
         iDtsetOXnMnd2n15ahWIKacWhmkZ4DC0zZUUVr6mFzpKgbsduqrXdO4xrNQwQ59oscea
         D3SHija4ApaAg55gxO5S8eksAoitwmUJmImM+6djmlIqKcPf4AM9xppeq5HaXiHUpIvp
         AqgVBG5QJ8VE7TJErUBqtPVfIdQXzCR726bI4sDW9eH5a7Wej4MSl1UuGgbQh4imZUYX
         eIPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4a/ZNouMvx4QUKYsK3LtvucZ8Gj5PoRSiguz7WWDEzE=;
        b=WUIAG/QsO+7CPSnU9Lrc2MZscsbMpQB43huTE3QMpe/bP52MLpVwn2NuAbHdGRjmD5
         w2EaoJbgocrbNhceOp5qpT5gmh4n5KCU2WLAGm1SA2V0bBxttsLGVB8Ws8nm2Sf3CLpp
         mYEs/pWVxK3RJ4i7CSyDqAPNtivCvZ15CF6erGtUz5zV9pHZRD2+j6n4b5dKQ3R90zKj
         sLHuuMWKbxZaB9fmWc5ugjgRJUuD7uxvMZgwmW/9W/QMX7Yq5C+S5RK3pyCDrZvxhGnl
         DKtXRXrtv3ZWLiWTVKDyQQqHbQ8WwRVGD4FWY/BhX5//d5qGa444i9sHZZx3S5xMwuUG
         WszA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Sk1lS5HD6ykTTMAprMwG45FT/gXtAyoyGp6gB4Ymk8xmgBYZV
	5A7K6SQnS8NHr5jR+fafZXU=
X-Google-Smtp-Source: ABdhPJydpm41UBdxrNm6WJJr1ChzitBFQtYBm0YCY9udJTbqQ/95HIW5qKG6sfdeqyEFOmb47gAU3w==
X-Received: by 2002:a37:4815:: with SMTP id v21mr9609183qka.130.1611153680367;
        Wed, 20 Jan 2021 06:41:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5884:: with SMTP id dz4ls670960qvb.4.gmail; Wed, 20 Jan
 2021 06:41:19 -0800 (PST)
X-Received: by 2002:a05:6214:d6d:: with SMTP id 13mr9521454qvs.60.1611153678718;
        Wed, 20 Jan 2021 06:41:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611153678; cv=none;
        d=google.com; s=arc-20160816;
        b=JFxuG5f8mq6cNcaYZaMwwlSNWudB006nuZyQIZ4xbTaWMV27OOeOD7Kp/KK5rHXwTg
         PL0kDfnnr+OHlnYqhHmEKoTibAyB7LV7pkUyNs9ELOzGnJRjIQQcWvqeURtlSBKZ2ZC6
         8VQ+yJk4ON/AA6toaA3kGSDC/qMly8qwneeeT8wzrBA55+z4tbs750wQZCk8DOxbEjlX
         ToG7kNtrW11cmyUIW38jq+Juf7bpK+QUVXKoYsXfgrapX4VYjzJqxb49doZloakl0z3C
         mOZFE52LhCZvWoEgLDZ9gi3hzABDKGnnoEiwLhpk1PnZA7ou3GB+NfGyA4roPdWlmJr0
         PvEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=1p07txl3egEt2YaQQXwOeM6GCzWHqqK1TpxzfRCH1DU=;
        b=C0+/sqEBY8DP69WU3rqbzEeeMsPSrDEMWfmcVdkMm9NHRdhBpGhtok3n941jphqZiR
         Esew9+lCcQhSXqM7OEm45nGTd4gJWcOnl45AochP9l27NL3j2zOsObI9TfAGxw08HbeT
         aaSpNmlnMCBN1r9dAzLrDRwyUgE3jejriZGSzzeblcvbNl61j00KiurkS7S/EIdSslr7
         uei13htDm1avsL+UT44UYOOyc9yyt7YBDgGKy4a3a6vnlEJyty3IBYx/GTB/JEUoMYX5
         ooqjaLRJf7dRXC4z/kx12xptysahvgroCiU1nJzKHs0eTMeeMQPIPtiENKBHWKiIh7jG
         AHtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z94si325932qtc.0.2021.01.20.06.41.18
        for <kasan-dev@googlegroups.com>;
        Wed, 20 Jan 2021 06:41:18 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C01D0D6E;
	Wed, 20 Jan 2021 06:41:17 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CE3F33F66E;
	Wed, 20 Jan 2021 06:41:15 -0800 (PST)
Subject: Re: [PATCH v4 2/5] kasan: Add KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-3-vincenzo.frascino@arm.com>
 <CAAeHK+xCkkqzwYW+Q7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <555f43d2-2753-b8b8-5ca9-53bc580c9def@arm.com>
Date: Wed, 20 Jan 2021 14:45:05 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xCkkqzwYW+Q7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ@mail.gmail.com>
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

On 1/19/21 6:10 PM, Andrey Konovalov wrote:
> On Mon, Jan 18, 2021 at 7:30 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>> --- a/Documentation/dev-tools/kasan.rst
>> +++ b/Documentation/dev-tools/kasan.rst
>> @@ -162,6 +162,9 @@ particular KASAN features.
>>
>>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>>
>> +- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
>> +  synchronous or asynchronous mode of execution (default: ``sync``).
> This needs to be expanded with a short explanation of the difference.
> 

Ok, I will extend it in v5.

>> +static inline void hw_enable_tagging_mode(void)
>> +{
>> +       if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
>> +               hw_enable_tagging_async();
>> +       else
>> +               hw_enable_tagging_sync();
>> +}
> It's OK to open-code this in kasan_init_hw_tags_cpu(), no need for an
> additional function.
> 

I added the new function to keep the code cleaner, but I do not have strong
opinion hence it is fine by me to have open-code here.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/555f43d2-2753-b8b8-5ca9-53bc580c9def%40arm.com.
