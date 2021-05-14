Return-Path: <kasan-dev+bncBD4NDKWHQYDRBW5S7OCAMGQED7OVUXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 282B0381178
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 22:11:09 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id q11-20020aa7842b0000b029028ed2e63c85sf390365pfn.15
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 13:11:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621023068; cv=pass;
        d=google.com; s=arc-20160816;
        b=exi/kAqWPeMscoZvFBxEvvKEZX0sHv1RNrbdIfm05XOKJy2Jl1TFt31NhDMaPbvE8j
         sQfVLqAmdkNqxGL3GwzeGJlf9Q0s2XqYEPkbYG6jLvqF67npjgv+gO+S/Wirh59ODeSl
         4elD87QXinX+OofXMSm4xw0d5zSJLgyeCJQxEtZvf64RzkfHc0PaNOzDZ54FDqS1OnbD
         /Mw+4iraEsZ2Qanis2gj1hhOm4JCw7QiB5X4qX6uM75LWZvxvTkfuUqw/Wjaq20Qycyj
         JIw7FnA4GwKSlT1Q1+mmIHsmw4qsgy6QyAV+H2QDnF3JahnmG4KcTTTnpLKD63jpdZtC
         6dbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ocKDHpxK9y95CXn76CKg3OIDxaAIryCPFpqplvA/NJ4=;
        b=jKjVzuJnkDkwMZT2B2JpKk5Bk4kyNxH+VhDNeX0S8wlIouPUwWjOx5DjqaE1bClZYK
         8RKWsm0J9zdCNKqAPmPQSrka7hWnPLl766pH8RHnfYBlwier8JzRn4c3GciJdbNtT2KB
         6MQNgYLMJkH195vi7ef9BEGo4Uqsg0TX6IOUlSz9SeAjscRcrof34PyBJP+2f3HIA68J
         t+GO9s+H1hZJ5E7VX14Qv/Gxufq86CR1U9WCed84LgUbWC7xLVHJY9lsq1QJNvxXysAZ
         E2eNBcssIN3X0qazrQyg3K0zj5x7+cqY2n4Ab0oaIOgiFE8XlF3i8VHm5/4fn7OEHyvA
         U2aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CE+KCPG3;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ocKDHpxK9y95CXn76CKg3OIDxaAIryCPFpqplvA/NJ4=;
        b=R1iRr+3lOYD5sz9o5cIfWlFMdAlx7slKzncVk1YPah0XyxnwrA+Z0vN8pEFxWceWct
         7Nmwzp+/iBjqnRfLapV+wR/rsIdRe/gzEi1sd39V+BcR2teprnXs+sU99mlcm/4Hgvp8
         hbzM0TfGBllesJ8Z7v1dugmC9ONUARfw3fIPvIwlwYfURinM6faqXvclVnUTIWRc4SNw
         O7AHtDmxyWGlGkAENCcz3zG1t1Sx60HDUOL3C/LTWXk9ZqqHHS9aEIOvj2Wm8Mnng5SJ
         /n+uGCvu1tMwhdOfLAKVGZwsgvk5SsqcZvdlMvS69EPoaMdEb//afl1Sxz10nTc/z1Va
         nzng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ocKDHpxK9y95CXn76CKg3OIDxaAIryCPFpqplvA/NJ4=;
        b=iWMjMTplHJIInIPNEuvSOCGjdSQKxC3lTZGGcXXTrxbx9ar43UlCaSrMQktYOoYoAY
         hjpNEhyMtWpHZ7/j+2dcF1UCRTNjXzn9eCHZInoQKkoDASnTdw/ULQzuumHvlhwkZyTF
         sw9+vkX6mPIOkoIuoQ7/xEZI1JChPvLI95BVPU3odOcKPFsB7Fnr9I/estu0hZTZ6gM4
         evF7dzIwamt2SOq28Ec6Y88Vj069uCOy8SoOTokA7kU1Ht+Kgo1AcQfv6BcnAvyMwHMe
         TWP2CfLNnRlF3DxVm8rU13oItOEVNHUaEMaZ7BPtOH1OYfvUFYpHOjTzk/WLv5S2XOoE
         UZUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307II68cd3ahUfhyTT2QTuRDNVgsx9TKlaHnXsTi6XyGRKpuUtr
	QpNBZeVXl6V8jND0+HAiEKQ=
X-Google-Smtp-Source: ABdhPJxjUks098jNqRVhuTRu+WrISdgyd4jReNrxyICNQAlL+AyWT9BSAeuUcf5KE9EYCgeMBk/27g==
X-Received: by 2002:a62:1d0f:0:b029:2d5:3ec2:feb8 with SMTP id d15-20020a621d0f0000b02902d53ec2feb8mr5626915pfd.19.1621023067904;
        Fri, 14 May 2021 13:11:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea8d:: with SMTP id x13ls5473313plb.2.gmail; Fri, 14
 May 2021 13:11:07 -0700 (PDT)
X-Received: by 2002:a17:90b:1486:: with SMTP id js6mr54148731pjb.210.1621023067319;
        Fri, 14 May 2021 13:11:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621023067; cv=none;
        d=google.com; s=arc-20160816;
        b=vnrg1TTgjvcOf3Tnop82gdfzjWygz0UDTJK4dskCQDCTh192/XAAGnkpj7roHbZtRb
         4x3Q5twyrgttMijFo1TWaNaVveyphcNQA3Ng8R9xdLLazK/TMVpyQzp98BxAt0inY2gz
         xs/1DpgJ6Bva8XOkLgCVul0WmS3vDaQeV7EDNlTAvxbXWkQaGbUQ/mUom1Oayqbxuw1P
         j4Q/MfiX/w4c3KWcy2DjMFIDy8Z+twAyRMHQSOPI1Nf9ykbQhYp6cDWiC6/zyH9tfd72
         OeswnDMEVALI5EuA7uw88j1Qqy7CvdqPFAaSHmfM6+b1MMnHTkMYMZjmC+8hY60Qh79o
         VqJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=InUJSC3uUs6UlgrpIzr6BCEqZZ5gt6IQ/2V4QtFRIUk=;
        b=vnGihXysT1hRPTr+p3U3fHGIHGPLKOEooFCv7UhgO4puk0Khib9i5TJfOSnvtg82Wv
         on4fUHQ5kFjPUOQMsGD1lJCMqTiMuiBmSc+GW4ucxPbEE4x41z3cvYLoq4BnY1NZ8m0e
         FDa795NYNbem+fqrq0TfIFThHnAY3Q72zgX49IF/rfwFgIKn0xMeUFnX1UYzZUIwLx2f
         3rrQsJyBywSaFvyw5zMZ0bt/Aezqi+7VJiIAi+vc988fZRnaZTmDSjMXjr+oSYKo/35K
         eO7E/BgTohtqymc4UnGbOEq2U9YVmZwgIBBwzSeyPDNMOyFwJxYEqCWua3eQXywdCf2c
         8kiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CE+KCPG3;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si47625pfv.6.2021.05.14.13.11.07
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 13:11:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 78928613BB;
	Fri, 14 May 2021 20:11:06 +0000 (UTC)
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: paulmck@kernel.org
Cc: Arnd Bergmann <arnd@kernel.org>, Marco Elver <elver@google.com>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 clang-built-linux@googlegroups.com
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
From: Nathan Chancellor <nathan@kernel.org>
Message-ID: <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
Date: Fri, 14 May 2021 13:11:05 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CE+KCPG3;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Paul,

On 5/14/2021 12:36 PM, Paul E. McKenney wrote:
> On Fri, May 14, 2021 at 11:29:18AM -0700, Nathan Chancellor wrote:
>> On 5/14/2021 7:00 AM, Arnd Bergmann wrote:
>>> From: Arnd Bergmann <arnd@arndb.de>
>>>
>>> clang points out that an initcall funciton should return an 'int':
>>>
>>> kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
>>> late_initcall(kcsan_debugfs_init);
>>> ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
>>> include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
>>>    #define late_initcall(fn)               __define_initcall(fn, 7)
>>>
>>> Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
>>> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
>>
>> For the record, this requires CONFIG_LTO_CLANG to be visible.
>>
>> Reviewed-by: Nathan Chancellor <nathan@kernel.org>
> 
> Queued with the three Reviewed-by tags, thank you all!
> 
> Nathan, I lost the thread on exactly what it is that requires that
> CONFIG_LTO_CLANG be visible.  A naive reader might conclude that the
> compiler diagnostic does not appear unless CONFIG_LTO_CLANG=y, but
> that would be surprising (and yes, I have been surprised many times).
> If you are suggesting that the commit log be upgraded, could you please
> supply suggested wording?

You can see my response to Marco here:

https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/

Maybe some improved wording might look like

clang with CONFIG_LTO_CLANG points out that an initcall function should 
return an 'int' due to the changes made to the initcall macros in commit 
3578ad11f3fb ("init: lto: fix PREL32 relocations"):

...

Arnd, do you have any objections?

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/534d9b03-6fb2-627a-399d-36e7127e19ff%40kernel.org.
