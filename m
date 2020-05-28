Return-Path: <kasan-dev+bncBCCZL45QXABBBB5YYD3AKGQESIM7NAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 74F0D1E6C40
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 22:16:09 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q5sf23008252pgt.16
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 13:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590696967; cv=pass;
        d=google.com; s=arc-20160816;
        b=xhZ8r/FV6Glwt/78bEwTkAa3D8Hxk26gkCzVrNPYxCTf1VxZWiiPt9vyvsmMiGwLPi
         cbT33yC7827JpnnK3hrJXjgL7DhZNfa5VxaTPrGirYuDR9MZtC/Qqu9+pDo9M+2Qithv
         jQbT7Slx+53y+63/rjR0lQwsxOg9JlYiubMBzZtabp/tCT6n8FqGUYRbTMf16X1c2T/5
         KrYCXGFoioYPGDKI2RyphhiYBcaW2TIeQJd47X52poiCU6ugEGPh42u/RS0L3SwEoTeu
         NHUCW7fsZ/yE7ypUTyM1FatgQ8L8tsIG+kPw6iIOAqSPywc+i+bhSEn5uHAAxUp9j0zH
         /xaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=96rk6qkaUPKhkWkNqSsc2hvCb23TNo/dZTGrmyPKJA4=;
        b=NWM25OAKOSiHjzxjnqKW0eXu4TswHhk1iLxTs6HXqyXa2rBHTqhlNcOJ/gLpS8uEzM
         3R5FVcpDQxt1Pjd0xuxBoUNI3QsyELSK02dilGppngzCs/JOSe12VSJ7CNPwIRPg5O0N
         uG1URn7x9G6wnQPL0KOmWvouJb+ismEQ+uEh1BjDrAkW38vf4tsGlqGS+l/+XRyBVm9d
         tlqvuvwX72DLeVr4K9yPGSL5kDJft5l/68VJnlLcfKXHA2gn620XoiCS//1tWpkSKqoL
         KCOm3ncEhoifDUsW/RuZNucFM+hJivCby9OJ9Nyklea1gDMSm3k30KjClSwws20LgYuF
         qF4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=eBP0mtNv;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=96rk6qkaUPKhkWkNqSsc2hvCb23TNo/dZTGrmyPKJA4=;
        b=iweQeqdOVHxaRuWqH0Fh7ghtewvs77naLbWQG1CdYZPpGiN7DT3A56qkybh9K2NyV1
         tsBkLaWYnQT8p+6W0gMys/NKiNIQu/Wto1FYcXpqc+a9pUvXDGlqEE18Ruc3sokIurmH
         pYIVkc1jRj6Fb/mVC43x0zDHUyvspesiCjGNJIbSTZKtfbyRjIx4lHFzgGoinxr137Dg
         8g7/ipEEu1kVmw7PY+SY1zSGijDBnSt1BVTYVasKUck81v3G6uLVk8qhKCfbQDi03YYf
         55T9/Ww0yutC6cc3C1XH3K2TUNkKUDbFr4H8Uy025F/2Z+3e2HKvMwhB5UqHbvdVcbux
         lRiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=96rk6qkaUPKhkWkNqSsc2hvCb23TNo/dZTGrmyPKJA4=;
        b=H80Egixm+Q+97NCLepEricd08RL+Odg/XrFQQdT2rz3IbP0Obm/a1WvC0Af4cmo50y
         JGtUAnBkvsDQOVXq63O6grqPZWBKGVuS7YDUXOpZcsHDLCjcs7qK3w3U4urHVm7EwVN/
         Vp25lt3gWnmd/fvCclhdG6ldA5YVAO1NTzPnNQyP6uj8D/a0dWy+9JkousYGcIzkigb4
         p3NKLY55m/h2AlEWQn45AGVYMi/zWa+MALOHbJzzSk/gB9CBC47XmS49YJRgSzknRAcD
         IP81ZhZ6lQX8QmK4+GDd5UDPMAHw6y8n72/YkwCfoYVsWVnavxTXzFghS1h0MAc/tAEY
         ZyHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329lZh8/qOZWBMp/XKEcNDF95T7rsdVIjlwjcX1OCPpaCrKoiZq
	Tv04UinfmmV8TOhDFH87+E8=
X-Google-Smtp-Source: ABdhPJxlUuDzyyH2Y4Cc/eNhruMhs4bX2a9c8Aq9He7Mmj81xRELnddr6d64uzzcjjIaQLXIGnIpFg==
X-Received: by 2002:a17:90b:1288:: with SMTP id fw8mr5598183pjb.160.1590696967600;
        Thu, 28 May 2020 13:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b219:: with SMTP id x25ls1024314pge.8.gmail; Thu, 28 May
 2020 13:16:07 -0700 (PDT)
X-Received: by 2002:a65:6799:: with SMTP id e25mr4886521pgr.9.1590696967169;
        Thu, 28 May 2020 13:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590696967; cv=none;
        d=google.com; s=arc-20160816;
        b=rrGysIDOSnSAjD+XZkjHK8a+k+Wq8qNKHKbhs6MhRQa+0DcRg3c/ceMeHLfLP8mhXv
         nJMem0JnOku2Ilz+Zi/MljDH0nnVhLnKRFwj+6TRCjqxhlPljhEISBfri2AQ5Yz00Y7L
         p4eIisOrMtLv2y5BBqA6yNyntJ7DdC/2iWnhoQCDGI5NDoSk9EgVS1uJDov8fKtj7awE
         rAD/uGRHXCnGUwouTDT0Vyt+wY3eJNoPRmBwdgd+jHmoc7OYemvwqtT2oKh/O4VXLQu2
         Ti5Pj7ZuIPOkEYsoi6WRVJN/ckJNyTnfjP1GEFrUHnGwbzlFPZZr7wxTM/u7Dx2d+IV4
         b1QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=G9v5weXtyKc3IseC+Bgo2LPHDLXxu13c4mrDGZBtUCE=;
        b=Dii0Ho0sMRalXAmU/0krGPFkRGPWYcNvetoblxCaEs1iJzAfroNJKLux4ehI5VTGQT
         p+xF1rXoanqmzD/3+MD+AMNaxN4QZwdGEslNywU77I9IgJvQAiSgthgYMEDfLWm4CHZN
         2AZPyfuSt5W4qpM+amSI6JFU1zD7vsIo07HS0VP/JE8rWdhZllj4XoyapSWPGf8gruOs
         5uXdCyt/bxGT+jrNVzLGixnfgHBtvx9Hs2CiMo3SAuRt8s/y5kSqrZLnCLlHJnJfrpqE
         cdxu1wQwYdB1y3s1ZXMKenOEzPbvDJRs47aPXljSlorLlWWwkyI9qXD/DtT3T8rovZ2i
         +biQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=google header.b=eBP0mtNv;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id a22si191363pjv.3.2020.05.28.13.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 13:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of skhan@linuxfoundation.org designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id m67so376526oif.4
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 13:16:07 -0700 (PDT)
X-Received: by 2002:a54:460a:: with SMTP id p10mr3528564oip.136.1590696966382;
        Thu, 28 May 2020 13:16:06 -0700 (PDT)
Received: from [192.168.1.112] (c-24-9-64-241.hsd1.co.comcast.net. [24.9.64.241])
        by smtp.gmail.com with ESMTPSA id k69sm2109002oib.26.2020.05.28.13.16.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 13:16:05 -0700 (PDT)
Subject: Re: [PATCH v7 0/5] KUnit-KASAN Integration
To: Brendan Higgins <brendanhiggins@google.com>,
 David Gow <davidgow@google.com>
Cc: shuah <shuah@kernel.org>, Alan Maguire <alan.maguire@oracle.com>,
 Patricia Alfonso <trishalfonso@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
 <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
 Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>,
 Vincent Guittot <vincent.guittot@linaro.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 KUnit Development <kunit-dev@googlegroups.com>,
 "open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
 Shuah Khan <skhan@linuxfoundation.org>
References: <20200424061342.212535-1-davidgow@google.com>
 <alpine.LRH.2.21.2005031101130.20090@localhost>
 <26d96fb9-392b-3b20-b689-7bc2c6819e7b@kernel.org>
 <CABVgOS=MueiJ6AHH6QUSWjipSezi1AvggxBCrh0Q9P_wa55XZQ@mail.gmail.com>
 <CAFd5g46Y-9vSSSke05hNyOoj3=OXcJh8bHGFciDVnwkSrpcjZw@mail.gmail.com>
From: Shuah Khan <skhan@linuxfoundation.org>
Message-ID: <cadaba3e-f679-e275-4196-4e497eb27624@linuxfoundation.org>
Date: Thu, 28 May 2020 14:16:04 -0600
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAFd5g46Y-9vSSSke05hNyOoj3=OXcJh8bHGFciDVnwkSrpcjZw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: skhan@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=google header.b=eBP0mtNv;
       spf=pass (google.com: domain of skhan@linuxfoundation.org designates
 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=skhan@linuxfoundation.org
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

On 5/28/20 1:52 PM, Brendan Higgins wrote:
> On Tue, May 26, 2020 at 7:51 PM David Gow <davidgow@google.com> wrote:
>>
>> On Sat, May 23, 2020 at 6:30 AM shuah <shuah@kernel.org> wrote:
>>>
>>> On 5/3/20 4:09 AM, Alan Maguire wrote:
>>>> On Thu, 23 Apr 2020, David Gow wrote:
>>>>
>>>>> This patchset contains everything needed to integrate KASAN and KUnit.
>>>>>
>>>>> KUnit will be able to:
>>>>> (1) Fail tests when an unexpected KASAN error occurs
>>>>> (2) Pass tests when an expected KASAN error occurs
>>>>>
>>>>> Convert KASAN tests to KUnit with the exception of copy_user_test
>>>>> because KUnit is unable to test those.
>>>>>
>>>>> Add documentation on how to run the KASAN tests with KUnit and what to
>>>>> expect when running these tests.
>>>>>
>>>>> This patchset depends on:
>>>>> - "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
>>>>> - "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
>>>>>     FORTIFY_SOURCE" [2]
>>>>>
>>>>> Changes from v6:
>>>>>    - Rebased on top of kselftest/kunit
>>>>>    - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
>>>>>      incompatibilites [2]
>>>>>    - Removed a redundant report_enabled() check.
>>>>>    - Fixed some places with out of date Kconfig names in the
>>>>>      documentation.
>>>>>
>>>>
>>>> Sorry for the delay in getting to this; I retested the
>>>> series with the above patchsets pre-applied; all looks
>>>> good now, thanks!  Looks like Daniel's patchset has a v4
>>>> so I'm not sure if that will have implications for applying
>>>> your changes on top of it (haven't tested it yet myself).
>>>>
>>>> For the series feel free to add
>>>>
>>>> Tested-by: Alan Maguire <alan.maguire@oracle.com>
>>>>
>>>> I'll try and take some time to review v7 shortly, but I wanted
>>>> to confirm the issues I saw went away first in case you're
>>>> blocked.  The only remaining issue I see is that we'd need the
>>>> named resource patchset to land first; it would be good
>>>> to ensure the API it provides is solid so you won't need to
>>>> respin.
>>>>
>>>> Thanks!
>>>>
>>>> Alan
>>>>
>>>>> Changes from v5:
>>>>>    - Split out the panic_on_warn changes to a separate patch.
>>>>>    - Fix documentation to fewer to the new Kconfig names.
>>>>>    - Fix some changes which were in the wrong patch.
>>>>>    - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)
>>>>>
>>>>
>>>
>>> Hi Brendan,
>>>
>>> Is this series ready to go inot Linux 5.8-rc1? Let me know.
>>> Probably needs rebase on top of kselftest/kunit. I applied
>>> patches from David and Vitor
>>>
>>> thanks,
>>> -- Shuah
>>>
>>
>> Hi Shuah,
>>
>> I think the only things holding this up are the missing dependencies:
>> the "extend kunit resources API" patches[1] for KUnit (which look
>> ready to me), and the "Fix some incompatibilities between KASAN and
>> FORTIFY_SOURCE" changes[2] on the KASAN side (which also seem ready).
>>
>> This patchset may need a (likely rather trivial) rebase on top of
>> whatever versions of those end up merged: I'm happy to do that if
>> necessary.
>>
>> Cheers,
>> -- David
>>
>> [1]: https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
>> [2]: http://lkml.iu.edu/hypermail/linux/kernel/2004.3/00735.html
> 
> As David pointed out, this series is waiting on its dependencies.
> Sorry, I thought the "extend KUnit resources API" patchset was ready
> to go, but I realized I only gave a reviewed-by to one of the patches.
> Both have been reviewed now, but one patch needs a minor fix.
> 

Yes. Thanks David.

> As for other patches, the patches from David, Vitor, and Anders should
> cover everything. Thanks!
>
I pulled David's and Vitor's patches. I am waiting for patch from
Vitor to fix a problem that was introduced when I was resolving merge
conflicts between Vitor's and David's patches.

I will pull Anders patches.

thanks,
-- Shuah


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cadaba3e-f679-e275-4196-4e497eb27624%40linuxfoundation.org.
