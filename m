Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBS7YUCFAMGQECFNVVTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E6DD2411070
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 09:46:19 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id a28-20020a056512021c00b003f5883dcd4bsf11575007lfo.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 00:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632123979; cv=pass;
        d=google.com; s=arc-20160816;
        b=A+D7FBEV5T9I3Uv06empdHjjShucbHzZ2RkdFgmVA9cVrtnUd7WYmxzJe27Wu2giOy
         oF65hUHXZhFU8j2n+U/Y+oJClk2bbgIv7wlLqjOqOXBuw5b8IEvrOsMw7dy3jnncx/8h
         sy44F4TbgOJyHXtcwC7QU2bEJoScez4XbB5qeREfuApiSNJ0aI4U23sls6gFjmYC8AG+
         j7uqOmvyebheh5CGUHIGvlJKpDBsJvySkSkpJoxauCZP/akAUKAeuv0ldlmNFLeNEdHE
         eAbblRFuHWNo0xs1oe3qEorFlr75E+w11R9EoB3fHVJO1pUW2RFZGzT30TfVNXErUfeN
         FDEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=0BZGJHlh8eBaBlaeqX61LXnCSIT7Vl7MQWiVfSG5dOE=;
        b=aEZHrh7nLEeM7ukMGdIrQsnbuQtmtDipyhfmG3JTJfSrGwPOtHF99/vpF0SD1YhIRG
         UoSZXgwpmmcTisolls1MqwETfRNrKNZUSLDeVz+ilB60T5aLCZuye11fzIwOs23jcL9U
         uaW6N2cwD3eBLOex7IiL+WFtf9u18bEOju18qLU6lx1svT4I4q02ed4OLOuiLKwhMaN4
         BnajCjQrE83oceDuIDt26o4mEz3qhDlX0ncBQEnBO2Qc7kD55KqNBXTn31Nn0pLPf6D9
         n/WrdwZ187DKI/NvpYnGqRn1PT9m4gUe7t0mzY/eur4oanVfVFQKtll/aUMeQXcrHX12
         lJcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0BZGJHlh8eBaBlaeqX61LXnCSIT7Vl7MQWiVfSG5dOE=;
        b=iE4LPgbUr1IB6NzF11pjGDcd2wUJRijSCfGQ3fgjCH643yWW51rhm8ZJ/sauRe1iXV
         xlV1pUafuN9qhRTsAJRlDPa6M7uYon9rhMA9PDrEOo3jBQNp0IaAvP5cAlSVwOvQKKD6
         4khGEEL1B0pZQ1CKwtcwU/iYlw9ePI/WkL137SlbrG6ZSFdZakSHYGcxfKoN2pRzcIV4
         n/Wl58v4I5eQtZBnSdUnWCOjPSAt/ioN+nzxN4ai6KH8t1HGD0e/sMnORgNkoR4CjLvu
         e61ofEYfIO1SjGDhWlpMjY9qS+zsn7Y9SMzmbEue/P3sZgPNiXhtpDoVpYsOHUsfzZsO
         pjuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0BZGJHlh8eBaBlaeqX61LXnCSIT7Vl7MQWiVfSG5dOE=;
        b=fClglhZ94fdI7ai8J/uYMtcM284ayBt/c9YLP2yyOAG0f8Uf5VLNu27I9bt3Jis92c
         xnDu0lVC9GgL0VEn5lKRIsimXvnraZBLBPXIhqXwfxHTuC3xnSlt5Q7fSkfZYX4S+MwN
         ZJrF6Bi63t2m2wT/3wUUMbmScAEnvjX5q+9xciFFdsR6oUvelSmPbAvSqJlhbPy/GNyu
         oiK+oJ8E+4j3ege3JhV0l4kR4XvblbfvCHfeRaOZhPvStadvJ+nKKXNLtD3P/d5CzsZ4
         j7P4A+RdU2WJVhir86BzYFiwiO6JOHo3x/JRvyBWIp/lb2agXW1ulmr5+kKoDQbfaSUM
         FGdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+cG3JutDAgs8LZIiImhSg6dQqxfm2csCgJnrlwnHPgIUzwiJP
	xrUPwfF6Cz9KXRPhsmnHriE=
X-Google-Smtp-Source: ABdhPJypD8xzWkqJxmmCYg4mtQbUTlejav4MzsMkIiehva1XYxlf+fGOd+1CTf8MPo4ssBqekU4kAg==
X-Received: by 2002:a2e:b8c7:: with SMTP id s7mr23073063ljp.105.1632123979513;
        Mon, 20 Sep 2021 00:46:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls274588lfi.2.gmail; Mon, 20 Sep
 2021 00:46:18 -0700 (PDT)
X-Received: by 2002:a05:6512:3257:: with SMTP id c23mr17933358lfr.90.1632123978469;
        Mon, 20 Sep 2021 00:46:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632123978; cv=none;
        d=google.com; s=arc-20160816;
        b=BPA/xpPngzrRtKkr57pMlpeR/v94WdSY1O74UUReujn0moSebROzjXT76lko7gDyAN
         tgcrvzQgQj/4BUf4qPcfPYe0jFVrnPKvFc0GZ4NVEG+pRa9EO9XWsqFdjKS5HO1PQdRB
         P33HQ3IAXFAUzTVMT3ia9MNMZ7ttqUxLoohjRuOC2FDF6PIzMxiutxAatOybXexELoPD
         xg8CK31omtHltBNN/XErQotsrLXpBbNBtRYK18WHkFhdGteN9+GaZiCzwOk/iLPZaoIh
         g7P3KorxiUO8N+WD3eid4LorDfx/OE21LSbCzjc2kbKmSmLQRP6ZaN/a4u7ekmv8FCJ0
         8gig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=p43K+S74FVeZ9BdvDt0STJMX+/NRSLjHCvP3npCf0Mw=;
        b=OXDA7NOq5upifDXiR70o42BaCwcOE3nB5JsFtkOEwvnPNieXYjnuWukSiYi6dBbtlp
         H7B8RN+FbQ1fWO+o4/IIS0dU/C9UoXHKd3v8TscIW+4gjfCmsKdWEEYE1kcDdulUugFC
         9nVw1qnLzKiiTPzp9KbKltQEECigTQ7P/QOU4mSqot2dvJ/Kkw0v1Ywd8f+DmzZAop71
         i06Dn/RObFywt0vkDHQuey1xGRZmLgpqXmHQLidlMvGYB554kWqoq47uDdiN+t1jlThg
         eMWvnihIrri0YxItkqufKY/xJPalkYLzG06fH7hlNb+oSqQn9wVwA30/ufLBzdWe0hqL
         ePPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m7si418723lfq.0.2021.09.20.00.46.18
        for <kasan-dev@googlegroups.com>;
        Mon, 20 Sep 2021 00:46:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4B4B41FB;
	Mon, 20 Sep 2021 00:46:17 -0700 (PDT)
Received: from [192.168.1.131] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4B9283F59C;
	Mon, 20 Sep 2021 00:46:14 -0700 (PDT)
Subject: Re: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
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
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-6-vincenzo.frascino@arm.com>
 <CANpmjNN5atO1u6+Y71EiEvr9V8+WhdOGzC_8gvviac+BDkP+sA@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <f789ede2-3fa2-8a50-3d82-8b2dc2f12386@arm.com>
Date: Mon, 20 Sep 2021 09:46:21 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNN5atO1u6+Y71EiEvr9V8+WhdOGzC_8gvviac+BDkP+sA@mail.gmail.com>
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

Hi Marco,

On 9/16/21 12:43 PM, Marco Elver wrote:
>> +       case KASAN_ARG_MODE_ASYMM:
>> +               /* Asymm mode enabled. */
>> +               kasan_flag_asymm = true;
>> +               break;
>>         }
>>
>>         switch (kasan_arg_stacktrace) {
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index 3639e7c8bb98..a8be62058d32 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
> Shouldn't kasan.h also define kasan_asymm_mode_enabled() similar to
> kasan_async_mode_enabled()?
> 
> And based on that, also use it where kasan_async_mode_enabled() is
> used in tests to ensure the tests do not fail. Otherwise, there is no
> purpose for kasan_flag_asymm.
>

I was not planning to have the tests shipped as part of this series, they will
come in a future one.

For what concerns kasan_flag_asymm, I agree with you it is meaningful only if
the tests are implemented hence I will remove it in v2.

Thanks for pointing this out.

> Thanks,
> -- Marco
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f789ede2-3fa2-8a50-3d82-8b2dc2f12386%40arm.com.
