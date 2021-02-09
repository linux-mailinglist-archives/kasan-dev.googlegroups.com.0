Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHH2RGAQMGQEJX7IJOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 728BE314EC9
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 13:16:29 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id r126sf1329424vkb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 04:16:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612872988; cv=pass;
        d=google.com; s=arc-20160816;
        b=OwYOv68YWyaxQio+JMko9fnHAwOw1RbIZ0FDW7Z3oqvmkfD4oX7Z794A/xcP4q2Y11
         /XuxGGTeDu8EG8eTL2NrcLGg5ftUtqyM39mIni7Bec0WxdpnifCa5Ts08NvvfLPbSh1u
         D/pPPBG1xG8Z8T4Nk2l7QkG7cxYlZXdUyrrbF8AO+9pgvNDQ9WPQjGUwA39dXr3Vbt2O
         g5yDN+iOUbVeUbmI4zIM0zef+48ryVhLkzcf/UDlW8CVjIXng1FYpM7L9W357AG7JCil
         NpfQl19+TxB0wvOqg4H5WdP9PdzQ6BxWxCu8Yv93YS5DOmalCOysv8BMC9gQvkTsRw9a
         A4wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=+pGhJMxxji8a6cZaoHS2mpFGl4rBXuV0QMHt5GIY1io=;
        b=uo7X+bU4WnIjoAZ0i0rzsFcBCkX3DkZwk2ArT8IY7gIGPrT2gnk9kA/Vg+4Cs1JITK
         IQnALNkaC4Zkx/PrTR78e3aiKL/aHAHAXyvhFOezMwaRyX08k7z0sNX7eSUnbUjn4USw
         ksP9mfrSu+aIbJr53ISl/A/6Q1qLeqbhcJKJUiE+ojV9mapkeh1ZyYpuKql3ruLAi4eu
         XdqYLb6xiSdO5A8vPk0dVsgJKvdXwKmDYBubocaMR/t9ryRU98z7EuHJKougGYhmPdn/
         MDyZWZWDUDI36N202Chbd6FxqV75I7MsfEMt2sjse7bdN5TziTKxf7z5pJFaN6QqsY10
         jiog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+pGhJMxxji8a6cZaoHS2mpFGl4rBXuV0QMHt5GIY1io=;
        b=ONgIQkmUvO4Ab7nc41sO33dOEQ3qfwiEa00YPT3WUV7e62U293d0sBvhqL+duq9uxT
         iArPqdtZW7mZ5wnuKJyjDJkSYwVmce7StTCP3cRATeGoBJv+iMI0qDOrpaMn11BuYw5S
         24JDaruzvN2shKhL2a443i3XUiYWsVWj9m6hBvAs4FKBg/JwKWBrKoRfnBLqo19oaLok
         bVT0ZMp2y3k2pzsgJVaOwxi5jpojXXcMZbDZmMq4ClfPQBMFowEKFfNKM9XdJU22rR7z
         q9R5RM63YkGiGn17ag5hEK/DzIlo6XIBGGB5hJBM0tK50B5OYYCiK/JsxaMdQ51M3ugL
         ++hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+pGhJMxxji8a6cZaoHS2mpFGl4rBXuV0QMHt5GIY1io=;
        b=CvID8+rpsrZi5NVMUpCWlVTG4Arv5BpdO9W0TdLTmQJE31feU3GkBHtWGkk67WqL6a
         UCZXV+Ya7bBqXxBZFODhiT0dGXWQ3ZW12q6N70iyxO4P4HdSX2ev+Jc4TwY6nx75q8yy
         ZHlyl2Dn1/8JnHAcbZp6lQv5ekOfgvSRGUKpDC7EcF3qKz4xExbuaYWQuyxSfz3J8N/i
         AhzVsaKgfcOGx9CETJYrMksoDq+lUMrQX5LWYQG8AfA69rilmqPh8ZWcqX1xyEDG7ymE
         S9fMA8iLncV5rHFkMbcWDaQb6qc5pNn9GLnULkjgeqU+TZ2frvqJ1tIrX1SkFkaqhk99
         k1Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zkD50jsLxJGq41oSJL9v+t3rAztJVHYMd/qVkWdVwPHm+VCuZ
	hNlNPx1Vm0ec2ku3JkNUAEM=
X-Google-Smtp-Source: ABdhPJzfRg45PtoU9vUNfIEjWxTbPy3V1DJ+6dRljYHBg7+1W+RbZBDO0L2h8eLdBeUGj7cksouquQ==
X-Received: by 2002:a1f:c18b:: with SMTP id r133mr13159620vkf.25.1612872988355;
        Tue, 09 Feb 2021 04:16:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:30a3:: with SMTP id y3ls714346vsd.5.gmail; Tue, 09
 Feb 2021 04:16:28 -0800 (PST)
X-Received: by 2002:a05:6102:11:: with SMTP id j17mr13784101vsp.27.1612872988028;
        Tue, 09 Feb 2021 04:16:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612872988; cv=none;
        d=google.com; s=arc-20160816;
        b=nLIT6slUU3QGaZHfrpO8kHrPCf+ZFUAu5o58fCYHojyxEQVcBykdsxZiC5AsXOziFW
         hac+mN6sXE2qxZuGh0LxXcpUgh0vTVCTQxagZk2iorbGrY6+Sb+kgAxa2YWXXR1BNu5O
         qYR24biPXNMQKhXoQ7lL7oCepY8sef8Izbi4j10g9UlYTsHG0//zOooNrW0w56bzHMFw
         TBD/RRF9fWOtqgi/Lh3GviWyVw6we/V5W/lZkb3kp5FnWvuwufo3lyEJVAUff36cdCT9
         hmHIUGSCEgIfmHCZ2Zb+xGC6bxU1jVmfjyGzaMoizDVxD//ic0a8Aj7qEP035b7ifbiP
         Jlaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=wOh/I+8BXRnRMDFOVGuKZBrbMpOHcXWHZ/uFwpdcQ7E=;
        b=H9sKj7bB4/FlpTiZa23ehmuLlUeZps52cDgGQIWaqPVrdkU3t0g/yaNkZac6+Ub31N
         WCe3LuW740EXsm6rTTJmysO0vVCvF3mXO4D97gcxMOp9kjZRUo+psocGVs3yf+V7Z/6z
         RZE5t+gUfkZvXIZcNnOGfaFV1ZKsUGzLTE0UWuosTX08fWAmAjo2KevmESWRaipP+0V+
         xIaoYQ4xOd4OP5opotcY7V1dhTZJEMPSXfDsnkcxfZCvKOlgzOc4dGu55g/NiRSxOPvk
         qLCsruYOW4UnrIiSWZzk91WmztH1OH/1pVkdZmt3rqxywIhaRTmm04M41Z8lIGJoc+Y3
         Ik3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l11si833511vkr.5.2021.02.09.04.16.27
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 04:16:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3537CED1;
	Tue,  9 Feb 2021 04:16:27 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3E5F43F73B;
	Tue,  9 Feb 2021 04:16:25 -0800 (PST)
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com>
 <20210209120241.GF1435@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com>
Date: Tue, 9 Feb 2021 12:20:28 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210209120241.GF1435@arm.com>
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



On 2/9/21 12:02 PM, Catalin Marinas wrote:
> On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
>> From: Andrey Konovalov <andreyknvl@google.com>
>>
>> Asynchronous KASAN mode doesn't guarantee that a tag fault will be
>> detected immediately and causes tests to fail. Forbid running them
>> in asynchronous mode.
>>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> That's missing your SoB.
>

Yes, I will add it in the next iteration.

>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 7285dcf9fcc1..f82d9630cae1 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
>>  		kunit_err(test, "can't run KASAN tests with KASAN disabled");
>>  		return -1;
>>  	}
>> +	if (kasan_flag_async) {
>> +		kunit_err(test, "can't run KASAN tests in async mode");
>> +		return -1;
>> +	}
>>  
>>  	multishot = kasan_save_enable_multi_shot();
>>  	hw_set_tagging_report_once(false);
> 
> I think we can still run the kasan tests in async mode if we check the
> TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().
> 

IIUC this was the plan for the future. But I let Andrey comment for more details.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e373526-0fa8-c5c0-fb41-5c17aa47f07c%40arm.com.
