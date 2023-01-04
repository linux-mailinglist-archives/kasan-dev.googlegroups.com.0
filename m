Return-Path: <kasan-dev+bncBAABBNEL22OQMGQEMBWMRKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E15865D4C8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 14:57:09 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id m8-20020a05600c3b0800b003d96bdce12fsf16447042wms.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 05:57:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672840628; cv=pass;
        d=google.com; s=arc-20160816;
        b=CfDtk94bfPriLBA2tTIUCumBJVf8MwMYEU6Y+FclHlwDB8k7aefxNcrxAvlB0iFtf9
         kf5JgMlPTc3rVs5IyVVpD3OXXYcO9lCLHw0G87Sl7ckqHEI9tortFHCpZ6E4Lhy3YAGO
         ynWsYKhbODt7VN9uhUaVDonTaXJ3YZy1X9vGE94evF/qXXKtDBoRR05AJeUTnM9vkAvs
         2dfxMneZaVV+WQFadJ0+mhDZ3W6naTFGgWfzQYvelvwmmV0vkTPC6l76SsUPytRB5WU6
         VM8zM/AiG3Q+3eDGqZkDJuJIk7TlNc/K/d4nphWgtytG05/q53kdiOTCdXyDUGJIJnyt
         MTmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:reply-to:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=8qdfHmoEoqqoSv2LNgQML9PFYV/ElTfRrBZefpgH8CU=;
        b=SQN3g00V5iCk0/xm9KSHevK+IB2zaIegj1U5E39kBUqBHmx8CcKHBlwyElyJYkrXBZ
         OArGRgL3aY1RC8UlZer8F8GbQd1vbLN6qrERadzfVOAZv/4Sj63InuplxGpkp9N4WA4J
         KXFBpwLd+TUlUkj6AtKnOXnH7zC3zjWVk1CpJYxx9Zxf9ZIXhLgJW7Tuxwuz3i2bSFE+
         p6ItOAqfBgpBurZDvbZnfW7ZJccwUk17ZaTtMAe3shMTVyKQzH73QwSy6ac3hiIwdk9N
         w37iK2vGxSTT4f61jYiRpLc1RR9uCjJMRCl+48Yi5y6wQK7lZsriTQ/1IAL1GyBDuzpO
         bWuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) smtp.mailfrom=regressions@leemhuis.info
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8qdfHmoEoqqoSv2LNgQML9PFYV/ElTfRrBZefpgH8CU=;
        b=hHKn8F3G31iI8Ki2OPax1UbFjrKVwz6MZgRDgyBktQ1CAojik6kzdnCpVHRogBbSoB
         CZqaZ75r+GYaFsczodQgJ3EpqGg8M1mcTgniUlIYS6SZN2wdPDfKkmsL/zNEuu4D2hfN
         S90mvol0rawR16XctWyOr9Xa2rwCiW9rLCtl50uWGryfej0fQh60MicvFM5c1qIzzqjV
         POurCuYs+fABwo33zWE2f98p3vugi96zYqD4wPWkcLaQARML5KeTu0cyzQB2Bebz9QYZ
         QnEBnodDA9Ld6NzmZhRy2j22o/SU562jH8U/jeRndmC5zCBzVfOFwJqLJNF1pI+f5XyK
         7vIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :reply-to:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8qdfHmoEoqqoSv2LNgQML9PFYV/ElTfRrBZefpgH8CU=;
        b=01tEYgmNI7tfCVATqtUTi9EbIfW7kju3/1XUBRMiTaETBYaPxrwXb0EG/KNgwX9sdC
         +PqEATcKVvcW8Dg4PNA+2Lbpicla+6zjgXEBzW9tOrlXJJocpKu0syDg9SdvpHmSG4tq
         N+r6JbJ1fS0E6Kk8GnHp7iJvfqXI2cXnZBnuvOngrAUSUmJ7MIBrpPeVVrTP6HvQviKd
         XpCfIo9xaUTjbLx1ipnOLxCzBxEjUBRnWoC+ZyzyiyFpk2uyiFlRQ/WFhc61b0KAmn9P
         9Vv7ke9qw3wnT2MDQFYvOHcomYpgf6sQWNtiris3R724V9+1sPo7qv7KM/Wp+Zy13xzv
         XUgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp2FhPLfzyRShIp5UIHw/aZXFvm+jBMjOnMMA6LQ9srcFwKu3I0
	l0DcQ47oRjTEjalIhfckras=
X-Google-Smtp-Source: AMrXdXuHoUZzuCSHl/pYeldlK95EfdUbPPculWJpTEupQ/dsklgpUfRg6uqO4anYSEyOMs4y/yZbPQ==
X-Received: by 2002:a5d:4b8b:0:b0:27c:cef5:8c68 with SMTP id b11-20020a5d4b8b000000b0027ccef58c68mr772539wrt.466.1672840628607;
        Wed, 04 Jan 2023 05:57:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:43c3:0:b0:3d1:cfa0:aeda with SMTP id q186-20020a1c43c3000000b003d1cfa0aedals224914wma.0.-pod-preprod-gmail;
 Wed, 04 Jan 2023 05:57:07 -0800 (PST)
X-Received: by 2002:a05:600c:539b:b0:3d9:6bc3:b8b9 with SMTP id hg27-20020a05600c539b00b003d96bc3b8b9mr29659085wmb.9.1672840627907;
        Wed, 04 Jan 2023 05:57:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672840627; cv=none;
        d=google.com; s=arc-20160816;
        b=PXvpMx7RbPUcc9vhGSnGRjK1/7etDRhX76LExamRzhc1Ghv1pnLFzkgViA8q6Lcuta
         jAZNsGMJv6SOEnjE4+nr+eIPp+oryPJqn16sIQODRWA0kF10JgNQzzqusVFSF0+OXe2X
         onWP9ztFnqvAd+ZTSBNYTdE3xENFs80g56m9F6sIBg4Gpd8bGjta9YThtQctLdj/gJDy
         ds82KVF3kf2sTGp5GrcZBi0ERI3iP0uIpCxHuff2wvEaDbN0PP/Vs9W/ZwsjXz/umWsK
         Ov8HnqoHzv1Wzs5EGkeKruU3oTFhVZvNp+ItGpziDmjy4wgg084RMbtknnDTk9vz61Mv
         460w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:reply-to:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id;
        bh=V0gT+0nbI8Qr5HW+tezOO5vgp2SqPa+od4OpgG0LRBM=;
        b=Kj8h9L682F2xuy7oyN3ms0T9CpWS9ZVWHxRT07m+QmYoOaOkl6sW8MoJxS8BN2jC/Q
         3idX2YROJIQMam5Wn7ztxR+4TkbqPVq/PTn/ozdFjgxDOTXGCDPCHDji0c49CEOfw/48
         8NRs4AkG7/adVDilqe9F0oEpQvBM6mGV9C2pVGSSAD9MmoN7R5n7x/nwNc3nipGH7jfF
         KurkJSojVQ9V9a7m9okBHVrCRPwfppwfGL0ckhmW08BFbA3dunK6vgHAiF3pHsjkAbHZ
         2PEodatMcWMWcU7ha1vdzUb9XzyjPNwlaak/oLKXCm/p8uib1shQc9JxwdNMBtdnVaWF
         ndVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) smtp.mailfrom=regressions@leemhuis.info
Received: from wp530.webpack.hosteurope.de (wp530.webpack.hosteurope.de. [80.237.130.52])
        by gmr-mx.google.com with ESMTPS id ay6-20020a05600c1e0600b003d9c716fa3csi70937wmb.1.2023.01.04.05.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 05:57:07 -0800 (PST)
Received-SPF: pass (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as permitted sender) client-ip=80.237.130.52;
Received: from [2a02:8108:963f:de38:eca4:7d19:f9a2:22c5]; authenticated
	by wp530.webpack.hosteurope.de running ExIM with esmtpsa (TLS1.3:ECDHE_RSA_AES_128_GCM_SHA256:128)
	id 1pD4GR-0000ho-7t; Wed, 04 Jan 2023 14:57:07 +0100
Message-ID: <0825ab19-d07f-ff3a-96dd-e8ba79e1aed4@leemhuis.info>
Date: Wed, 4 Jan 2023 14:57:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY") #forregzbot
Content-Language: en-US, de-DE
From: "Linux kernel regression tracking (#update)" <regressions@leemhuis.info>
To: "regressions@lists.linux.dev" <regressions@lists.linux.dev>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org
References: <Y5hTTGf/RA2kpqOF@debian>
 <962eff8e-8417-1096-f72b-4238ca4b0713@leemhuis.info>
Reply-To: Thorsten Leemhuis <regressions@leemhuis.info>
In-Reply-To: <962eff8e-8417-1096-f72b-4238ca4b0713@leemhuis.info>
Content-Type: text/plain; charset="UTF-8"
X-bounce-key: webpack.hosteurope.de;regressions@leemhuis.info;1672840627;58f9a971;
X-HE-SMSGID: 1pD4GR-0000ho-7t
X-Original-Sender: regressions@leemhuis.info
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of regressions@leemhuis.info designates 80.237.130.52 as
 permitted sender) smtp.mailfrom=regressions@leemhuis.info
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

[TLDR: This mail in primarily relevant for Linux kernel regression
tracking. See link in footer if these mails annoy you.]

On 22.12.22 13:06, Thorsten Leemhuis wrote:
> [Note: this mail contains only information for Linux kernel regression
> tracking. Mails like these contain '#forregzbot' in the subject to make
> then easy to spot and filter out. The author also tried to remove most
> or all individuals from the list of recipients to spare them the hassle.]
> 
> On 13.12.22 11:26, Sudip Mukherjee (Codethink) wrote:
>> Hi All,
>>
>> The latest mainline kernel branch fails to build xtensa allmodconfig 
>> with gcc-11 with the error:
>>
>> kernel/kcsan/kcsan_test.c: In function '__report_matches':
>> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
>>   257 | }
>>       | ^
>>
>> git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
> 
> Thanks for the report. To be sure below issue doesn't fall through the
> cracks unnoticed, I'm adding it to regzbot, my Linux kernel regression
> tracking bot:
> 
> #regzbot ^introduced e240e53ae0ab
> #regzbot title mm, slub: CONFIG_SLUB_TINY causes various build errors
> #regzbot ignore-activity

#regzbot fix: kcsan: test: don't put the expect array on the stack

Ciao, Thorsten (wearing his 'the Linux kernel's regression tracker' hat)
--
Everything you wanna know about Linux kernel regression tracking:
https://linux-regtracking.leemhuis.info/about/#tldr
If I did something stupid, please tell me, as explained on that page.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0825ab19-d07f-ff3a-96dd-e8ba79e1aed4%40leemhuis.info.
