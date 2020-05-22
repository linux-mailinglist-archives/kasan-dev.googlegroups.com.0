Return-Path: <kasan-dev+bncBD55JLOZ34EBB5FEUH3AKGQEZK44FCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id C789B1DF1D8
	for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 00:30:13 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id o89sf9985876pjo.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 15:30:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590186612; cv=pass;
        d=google.com; s=arc-20160816;
        b=OmcvCpuM+THjbAVxoh/Adh+mNPMyjUDBz8lP712VA6JDYmXWR6k8q15C2jzLgtM16R
         EolfGy8t7Uz5e5SnRj9e99Ki1TpfYk5WtScr0xrwtg477iRrA9VYXcSAYExxKaBMKTEW
         dLGfqc5yH3B+s1EqNvI9eWWldor6hrsPu+f5DpaJO7wFXkA/FWD/KGLMnLCDyOP8PBmL
         rnfWuWwiwg0/SXCKEQJUtjgkFOE2RFfWC/HZggMmSv+cEGJBI1Pq4zPqICQsaWmAUa2t
         wiOc3gAThEp7MJw/qyUuwWY8Yk1rovmj9aMAMghsqMCcHRTH7CyZwYOOkXxgrbTOvn85
         3q4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jmFAFIwshKlAH+NrYWttLgTtX6TUViHjZiKIawXtnj4=;
        b=S59H0KQvKlWsfMiQfX3Rlp9dWtAg3bkvpApQ+Viq9esdIZmonlYojmHFYAlw2cP+nM
         p/4Ews5nTp7/6Y32yAACysqVmmlFakNu/SVS4snnE2MYP9F3V2u4aGJpccPKHjT7JEMj
         a3BL1aTyxp6qA2xAtCs1Wwwvfwyyw1sJOZWBe1eWI0NWiaZgwss8k235TkB4FMUbnyI4
         ZazYK+fZ1lhhxvbotWFaH/o4TrI148vgn+eq8YviGtKGON/+XNlG/4KphYSfTnGzvS33
         h6+zL7JOTye7CRkIxlGjeyCjuqSnRuCpxIHE1SawZAeR+XwdiefE+QH07thdysnD/Stu
         VAkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=squkeIoz;
       spf=pass (google.com: domain of shuah@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=shuah@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jmFAFIwshKlAH+NrYWttLgTtX6TUViHjZiKIawXtnj4=;
        b=lwNA+F3RnE9FKn5+zuxA/Ft4yCrP6MaWlDXlY5eeISAqfnulvSKnpOply8Vs46BMDm
         yrtLcG+Mp3onbjjRL//WfdbgRqwTLGgjt7rBVrL2go/YZBn+8R1XHemIlfko8NeoxCH6
         Kg98SXXm60eU0lenJ4tscLOrTxcc/nF63DVuYc3XuiaNftRpeiGOWTFMEXLLz3pry59p
         k6ZT01YAlU4Tc6bTAgjUWzks+Lsi7CtF9Ttr0J+LfIcHu4RNahgFPtwvdhpTaD6YFnSb
         JSSUz7ZXuGtlPeAFEr5B8/SSNr2/DDlpNHsnnTXm2au+prfMEemc+2yLDOdBcDh+IdYH
         Qmqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jmFAFIwshKlAH+NrYWttLgTtX6TUViHjZiKIawXtnj4=;
        b=f+TanMjT8kKzJbbDvUC12kXQZm6HbcfFvAjSIuvPIP00lgcHg6r/YwNtstu+bvxJN4
         CicM9XHkrL0KH8X+iAmbdTWqJhL4vNjVEqQG2BUurpjY/RTq/ZhFOw4kmCR89xjAWnOp
         ti+yn/2Zp9WUBO/Kh80C3B7X41/+1hg8lbqtvyZcQHeL2pb2XTFdTJSXDKuUb/rvs8Zf
         DVL6LG8yZR76tJ5/XlI83JdatH9WxsMsxuY0HlUlIw2/sQvER2Wlu6CWrHXsN175okSQ
         BY9/Q15Fncc+uJ5b0AtyuUvGiiiehWNAAPRacHL6jrW3rOvZ4XbcQg/XW3axN41VAMGD
         caXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PE4wVscH7/LLZqCNWRwY7cztXuzA9lmtg5oBV6bncJQGbffS9
	Rfx3BPOXTiRO7XTwh29HZyg=
X-Google-Smtp-Source: ABdhPJy5k/9gYXYA9YVSW1ccg/rKZPnzq1rsn66L3urYYJqs/fILO3TYXAH8l0FqIQHYJBNmv5E/Kw==
X-Received: by 2002:a17:90b:30c5:: with SMTP id hi5mr6895015pjb.110.1590186612381;
        Fri, 22 May 2020 15:30:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:668c:: with SMTP id b12ls693665pgw.10.gmail; Fri, 22 May
 2020 15:30:12 -0700 (PDT)
X-Received: by 2002:a63:f242:: with SMTP id d2mr16215320pgk.212.1590186611997;
        Fri, 22 May 2020 15:30:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590186611; cv=none;
        d=google.com; s=arc-20160816;
        b=DkkauKGkbPLLLDisnOvyRv6CtFt572GzyT4wxq8sHFCL+Kd0hbBXRGomu43a1V8ap0
         yZSED7mxoGsKEcd7DxweYV9Ws86qzPQ3zxPNF8tU6584Gb+DtL9/3AjHaCuCADSmIqQ9
         xcmdeIsNazo+Bk4+WQq3rZRVjQ7ZKsaLZEdFLxlX8vE7X3/2ZSC2MfhyuWL7TxZztsZQ
         w6gKFtLjXn2ZVE0+xYG9M1cFgBUuOOkJioiau0r2hsoywmIaK3pkYx9IRkqCddjmPWeh
         DMLg328qQ5BqmD/Mpa24fWCZqLwRqkmtmfbSXkNwXMX+jGzGWFicoapUsLc3QAOpBYZB
         kACg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=MD73iyvc2D6cuh2zaRiEzbthWk0N4+4A23FvKCERbtQ=;
        b=tTRGqmkKtj2f5O1fcAL0ROCA5wdKtQySJcsX3WPrDr3SVREhjBVu5h0bD/bPOi6srg
         oBp52hdPVZ0WTcjmA7Gs+QSJT3NXXQy/m2msHnmo+3zBPqJxUtrHa9EUVlpyJSqVhwbu
         KvbxQeICmhqrNjSF94OLMsubq2n+TQ7YGENb0b9vzGNMtb9SICQUmph+j4lEipNcSIJm
         EIinSfWsslu2Qk4TJnuAGykBB3RFS/qIzWkIxzv3uA0JJN2t99y/RfX4T1PpsDpaPyfA
         Fvjfd0eDmNNQOfJ3iM41KaYz0WJunvuo/RPQafwcxOFwp/tcDB9busVh5y3fALryjIEu
         f1aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=squkeIoz;
       spf=pass (google.com: domain of shuah@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=shuah@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si706095pgg.5.2020.05.22.15.30.11
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 May 2020 15:30:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of shuah@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from [192.168.1.112] (c-24-9-64-241.hsd1.co.comcast.net [24.9.64.241])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B1E282100A;
	Fri, 22 May 2020 22:30:10 +0000 (UTC)
Subject: Re: [PATCH v7 0/5] KUnit-KASAN Integration
To: Alan Maguire <alan.maguire@oracle.com>, David Gow <davidgow@google.com>,
 brendanhiggins@google.com
Cc: trishalfonso@google.com, aryabinin@virtuozzo.com, dvyukov@google.com,
 mingo@redhat.com, peterz@infradead.org, juri.lelli@redhat.com,
 vincent.guittot@linaro.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, kunit-dev@googlegroups.com,
 linux-kselftest@vger.kernel.org, shuah <shuah@kernel.org>
References: <20200424061342.212535-1-davidgow@google.com>
 <alpine.LRH.2.21.2005031101130.20090@localhost>
From: shuah <shuah@kernel.org>
Message-ID: <26d96fb9-392b-3b20-b689-7bc2c6819e7b@kernel.org>
Date: Fri, 22 May 2020 16:30:10 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <alpine.LRH.2.21.2005031101130.20090@localhost>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: shuah@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=squkeIoz;       spf=pass
 (google.com: domain of shuah@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=shuah@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On 5/3/20 4:09 AM, Alan Maguire wrote:
> On Thu, 23 Apr 2020, David Gow wrote:
> 
>> This patchset contains everything needed to integrate KASAN and KUnit.
>>
>> KUnit will be able to:
>> (1) Fail tests when an unexpected KASAN error occurs
>> (2) Pass tests when an expected KASAN error occurs
>>
>> Convert KASAN tests to KUnit with the exception of copy_user_test
>> because KUnit is unable to test those.
>>
>> Add documentation on how to run the KASAN tests with KUnit and what to
>> expect when running these tests.
>>
>> This patchset depends on:
>> - "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
>> - "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
>>    FORTIFY_SOURCE" [2]
>>
>> Changes from v6:
>>   - Rebased on top of kselftest/kunit
>>   - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
>>     incompatibilites [2]
>>   - Removed a redundant report_enabled() check.
>>   - Fixed some places with out of date Kconfig names in the
>>     documentation.
>>
> 
> Sorry for the delay in getting to this; I retested the
> series with the above patchsets pre-applied; all looks
> good now, thanks!  Looks like Daniel's patchset has a v4
> so I'm not sure if that will have implications for applying
> your changes on top of it (haven't tested it yet myself).
> 
> For the series feel free to add
> 
> Tested-by: Alan Maguire <alan.maguire@oracle.com>
> 
> I'll try and take some time to review v7 shortly, but I wanted
> to confirm the issues I saw went away first in case you're
> blocked.  The only remaining issue I see is that we'd need the
> named resource patchset to land first; it would be good
> to ensure the API it provides is solid so you won't need to
> respin.
> 
> Thanks!
> 
> Alan
>   
>> Changes from v5:
>>   - Split out the panic_on_warn changes to a separate patch.
>>   - Fix documentation to fewer to the new Kconfig names.
>>   - Fix some changes which were in the wrong patch.
>>   - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
>>
>

Hi Brendan,

Is this series ready to go inot Linux 5.8-rc1? Let me know.
Probably needs rebase on top of kselftest/kunit. I applied
patches from David and Vitor

thanks,
-- Shuah


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/26d96fb9-392b-3b20-b689-7bc2c6819e7b%40kernel.org.
