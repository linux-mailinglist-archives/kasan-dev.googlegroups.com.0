Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBF5A22AAMGQEEAU5VQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D9CDA3096F6
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:58:00 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 33sf8229629pgv.0
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:58:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025879; cv=pass;
        d=google.com; s=arc-20160816;
        b=eqDanfnjD5aKuGmwUVJPEHZpuCTzRTgxdnBXbNOV4yj7N8wsoVSEqsutccknYgLqGU
         L2SWg2NG2/ojf/aixhKV17ZnMZkAV19viHqrL/8GGWQGOl1/9V+e06374Az0ypBnzK0O
         AZGPRimnI9ZgqU8hWJZZVfCzg2MRxKtC4gqD0RbSiq3MQNiYcifRWygILgMgerfATvqF
         G1Bm5Roqztat07EQCsxaHdvqDNg2P5hVn9U3iQ8c0EtyzSzUNiAjs5lO1aszw07WgwiZ
         Os/eKOH761DwGq2bargNvWI5A0qfKTNR+vTYNqDh+j023i9w7zonjJufk2/k9mKmeSr1
         R6nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=wXaN/B8ifVGbHTsp6AiHPPhIU/qFxu+S/uVfhP4tfOQ=;
        b=ZbazCDt5rIKn/gt1cjEbQqr3nGsH7FOM7f0Z/T5lXnJoV6qzYCltulE0cIJTEBMaHS
         Z51YfaPQeI9krxizfR3tL/Ow+jx2Rfmz7SjR/P85PXtS05N+OA+Nsn8rYDd/KoZc3R9A
         B7f4WbSGczJuxIFfgvEdQTAlHVzPTC3ArS+WZdNpW7jCxkbxROdoPLC343ewkW4xh6Wp
         HknHvi571y3qcq0PovmDM1tr9rsFJCPwNX5vqEi43ucBYDUOfXmzwBOulxznDCMAkGop
         1oDLZZfwx9jDGS/+cvTDBGiBVqk4YfCsP5jnheEnc0RR0bHUziRxmZCuT/768YoY12zk
         0dIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wXaN/B8ifVGbHTsp6AiHPPhIU/qFxu+S/uVfhP4tfOQ=;
        b=TotPqJU77Kpwo5hbJjQ+tTa5ohWD6xVjrEkkDuDtfvaP/xjHyvfeYGfujO7zxT5VBH
         cyktKrFhAWd2bmEjc6gDkYZcrfgp04p4K/lIGIMi1ae1kLPZNwtXdKZSEkaLAY/vOVRo
         A87w/HoiAfaPwcAE2/s2HWMgSLXfQd/ni1HfSXrr+MDStWGmFnl75NonxqPM71TEJVHs
         oMX4fpDSYlSCs2reJrs3d8Qeq9eyC4A6FPUyjWyJqKvKG4TdHQ+fa/kkRRYGMfXGOoVB
         uVWqd5EfBqnBRfs+2K/0xZNJKchmjJoFcTUKnHsA82EtMh/r0BpsYgojf00khHibObTd
         9Esw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wXaN/B8ifVGbHTsp6AiHPPhIU/qFxu+S/uVfhP4tfOQ=;
        b=jq1Xbf70fJVwCeQQjJRozOagfQlgoy2aRzW++Wh8iX5D9E5Y6mlJARnWFAaY1M5UoV
         wRoj+08RHlhDAAicnJyJ12oNrutXb3OPTdm19cfwgDGXMVdKozTMyIA+bCpl579a8wMh
         IFRMZhmun9oQuKZGlTZnfId8Gbl869sdVWzrKTOKYzihMn5GqrLpXQV/z02oUXSk5wUS
         2Yu+sE7Y2pC6EOCQLQhRlhF26U4Uz+CDRIje4fV7L5ggHIwFJvuxvzLUF1jbtxFT3nj4
         libjDpQGuMUhINa6bmGHH4tSwdie5OdlC23ILSUGD3SQB5rCuPaMl/uF83JJqlykHSt0
         KWag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SFnR4zpQ+onGSSLMKV9Hc1WDSVxKEoNJeYy+82rscIYXbu42/
	ISUCQqVn3CQ8dXX1OoDiwO0=
X-Google-Smtp-Source: ABdhPJyCpcOpdqMFVubLRzO30BTstwAZbGnWIqSvZunpQnrLsCucKb4UIovqbUEr5GxfofcEXESW3g==
X-Received: by 2002:a05:6a00:158c:b029:1bd:ea8:6d6d with SMTP id u12-20020a056a00158cb02901bd0ea86d6dmr9177464pfk.16.1612025879383;
        Sat, 30 Jan 2021 08:57:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8d53:: with SMTP id s19ls4796510pfe.7.gmail; Sat, 30 Jan
 2021 08:57:58 -0800 (PST)
X-Received: by 2002:a62:2acf:0:b029:1bf:e549:fa4f with SMTP id q198-20020a622acf0000b02901bfe549fa4fmr9032246pfq.69.1612025878693;
        Sat, 30 Jan 2021 08:57:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025878; cv=none;
        d=google.com; s=arc-20160816;
        b=fS3W3RMFxy9UaMNagu9tVhcPwBxKwRsfoJv75GU0MAbRw1Ctkhnh6/UYzi5SZnOquG
         Dooao/OxT4YjdnQWCEetNWJTXgG6njbhx7fNaOsAUnhCwnHljgoyt+bjBz0j/fUfJtKM
         H5jlTf30H+6d4lanpZUoIo/B66c9dfEiXpDV8XtNi+FtkXKembEnn4aPLk55lDIGMmfI
         iC87pnMD9FeZzW16Et1L2ZYBYIFYNvmywDyidbdQhjTSky0jQS3ZN4/ynfJGCzAA8LR5
         fO1maOprbJ7xG5etgPoqgAFpE1Dr6EtIdPui3m2RtP77xTXf25MzoT9LNGSPML6DfT+1
         crAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=TQy/pwLJGx9Ht8Yuuig1VbrQqjtwHoDcizDNc+9di74=;
        b=n7WMns8s2/4ZCXztiFzS9u+Xy6mGBR4TXlA22sU8pPbF4CTKx8y4+arYPL/7CJ0RTB
         dZnAPjuHwzdXQtck6FeZEaiaeaYo8ID0OrTD/TIk66y0+rbYmyXRohCzDPBd7nP4RrnO
         1PqkZnoHVX6KyA73+zmPhKS4ALpPPMMg1mdv7ujS/gNn+OSm+z1AN7Rx8gyq4M63yPWl
         YLgGTuEpL0TdBTJDkv3SScBcWyJ4jXSDD3ippq15PNDaVa3QhqNj2xGFof4/YKK1eZOw
         7Xee8oM3F+nLG5+bcAWw3EdHy5+moc5doV3Ie6FOrLfzobptJXid4vUcAj55FfTZv9SF
         WYoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b189si582238pfg.5.2021.01.30.08.57.58
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:57:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B6BCB1042;
	Sat, 30 Jan 2021 08:57:57 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F0B243F73D;
	Sat, 30 Jan 2021 08:57:54 -0800 (PST)
Subject: Re: [PATCH v11 5/5] kasan: don't run tests in async mode
To: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-6-vincenzo.frascino@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ba95b920-9007-bf10-a09d-59f5d715a8c2@arm.com>
Date: Sat, 30 Jan 2021 17:01:48 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210130165225.54047-6-vincenzo.frascino@arm.com>
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



On 1/30/21 4:52 PM, Vincenzo Frascino wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Asynchronous KASAN mode doesn't guarantee that a tag fault will be
> detected immediately and causes tests to fail. Forbid running them
> in asynchronous mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

With:

[   18.283644] 1..1
[   18.284167]     # Subtest: kasan
[   18.284444]     1..45
[   18.295536]     # kmalloc_oob_right: can't run KASAN tests in async mode
[   18.296873]     # kmalloc_oob_right: failed to initialize: -1
[   18.303714]     not ok 1 - kmalloc_oob_right
[   18.316439]     # kmalloc_oob_left: can't run KASAN tests in async mode
[   18.319466]     # kmalloc_oob_left: failed to initialize: -1
[   18.325001]     not ok 2 - kmalloc_oob_left

Tested-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  lib/test_kasan.c | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7285dcf9fcc1..f82d9630cae1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
>  		kunit_err(test, "can't run KASAN tests with KASAN disabled");
>  		return -1;
>  	}
> +	if (kasan_flag_async) {
> +		kunit_err(test, "can't run KASAN tests in async mode");
> +		return -1;
> +	}
>  
>  	multishot = kasan_save_enable_multi_shot();
>  	hw_set_tagging_report_once(false);
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba95b920-9007-bf10-a09d-59f5d715a8c2%40arm.com.
