Return-Path: <kasan-dev+bncBDCZTXNV3YCBBAEVQ37QKGQEA3JQTFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-f59.google.com (mail-io1-f59.google.com [209.85.166.59])
	by mail.lfdr.de (Postfix) with ESMTPS id 16FCB2E05DC
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Dec 2020 06:56:18 +0100 (CET)
Received: by mail-io1-f59.google.com with SMTP id b136sf6799127iof.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 21:56:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608616577; cv=pass;
        d=google.com; s=arc-20160816;
        b=SlEtGq4/RExRZVRam/K5uly4s6FqlKcyeUL5lTAehc50dTmeQ3TpVftlNuVJpaQivd
         l/FSd3Hm1Ga5/NBuwQa8x3bH2go8zKw+7mR8ycBPKmualsAdieHqa8A+h6oSJ9a0EgVq
         CPTM5EZEYvhNByQvwMW6gvJcrHlYR1F94O+E6cGR7qhHmCCBtJsmf60z7ilr2jixUsr1
         p+YH95jwhs/mjp4Jd0063Sd0U4c1y3vUASu6Ol+IzTsgVAhx2qqT/OU+2yrbHTwFYASM
         xLGYLMQTV7pTat0uiJfUeVtevHXq4SYqgYKYJozd6ybMZ4LQFH/L7delc7NGFrnql9Pp
         FGGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:dmarc-filter:sender;
        bh=dOy/qpLl8w1tu0q/7shPCH00Xlwto1PwgoVGL5I13cc=;
        b=gdISriez/vo5trT3GHGEsuPByyCUrpm3zqcw8JI7jPrATZw3V1WEqkEfT/JZtzPNEt
         NZSH0s1qefoyBiBNtDU0wlQrzLVPkjAeb9sGcywHTFTPgW0sZADScXh1UqqemVH1d/9C
         O/rQ/LPN8RhpwJsdtLggk7hOWUj00GLIN7BIWN3C8U6e7PDqeUoI7dak+k98YLJmpnA/
         Os1qLdIYM2tpNxHhcj/33/h6eWUHeEPXAn3PJSMvXEBnrDXpOoKtBF9yispVmYu5mELE
         SWBQL4UwybHu/f4PvNDCrATWzKu+WhX4yZj0H4ZK3DDYWgWlprRcVz4xT+rVCNQ8S+Ek
         M9JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=Ty0xUdZz;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:dmarc-filter:subject:to:cc:references
         :from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dOy/qpLl8w1tu0q/7shPCH00Xlwto1PwgoVGL5I13cc=;
        b=rTABv1gG1apoYEQ81SsPn58J+rCtLMmNL9/BeGGuK+9tAB8UMRsFbJVrwKKkaFP/pL
         FCTD9UPLMzOJSgJp9qnlH20hp+FzY+TxrCJsG2BcC5eS0I9cm3zRsuv5njfS7U7D84vW
         jhMo46jUd2Uadm0RJClotHNQmrmLB9u5T8vxTKOU1QCcg+zHi1NLqYVsKlN9UfF7dccw
         Mqsr3KdyIKji174DViYy83naNMw2hhpV7kRbmfGGNdo8TbQK/xpHPo8JbN67j3pADchv
         omaImMs6xbKXiZA4Up/LvgsPM7nwGPeOtJ17RSzuzTN4rWtQHykyOA2tYb30m6lI4nnc
         EDUg==
X-Gm-Message-State: AOAM530xJ9TN7Z1fk4y1GIf5PlA9MWoU7hOimMh8kEKAwv3tymHUaR3s
	VCVg5ciSUkUQEiVSRYKPLY8=
X-Google-Smtp-Source: ABdhPJwWrYIUYAIs2fOxl3VxZb0N9/3AjcAUIrqCO0Ws8V5AQfc+rbMGs8QcCjW1NYz7c5r0TvhqoA==
X-Received: by 2002:a05:6602:3154:: with SMTP id m20mr16930066ioy.188.1608616576838;
        Mon, 21 Dec 2020 21:56:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:97d8:: with SMTP id k24ls4738267ios.6.gmail; Mon, 21 Dec
 2020 21:56:16 -0800 (PST)
X-Received: by 2002:a5d:9641:: with SMTP id d1mr16751681ios.123.1608616576463;
        Mon, 21 Dec 2020 21:56:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608616576; cv=none;
        d=google.com; s=arc-20160816;
        b=Gf7EjxoRAu1YuuUylARZb3jTlK0yOaIZeauy46sXPSXgZW+Q6bATKuQRGb23yEO/kB
         l4c4E8PG5wzODENzqN9WtgPj0/zR/iymzN7IHk+fWL7+ejavdu3zTYG+aKNXqaB+HlJP
         +EiTVKvX7Rxa95XbmOeniHbbBknF8JcWQS16y8ELZPLbTxn0F5I8uyd4zorJ8M2+C9L8
         0YM41u1DBNVtcqltVyXPPTh8IRRpMchi6BC4GJ0+lwmurYL/Gxl65Gp2iE4qvzuoP8S7
         +Mw4aefoFC9sWyf6Gyv8RJs5pBgajJTCkk414XkyF7iZEUUoy40ckAlbmdwpsvbXWq49
         cR5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dmarc-filter:sender:dkim-signature;
        bh=1thyFUC//ehpP0yAbCIk5YNRG3RLSn2U56velYq8ZPo=;
        b=a47Ujxqldv2O6WJPVemP8F4qyNn7UqDUsmEmK33Pu+2eT/ZqDz/VKZfD1NHvSL+icQ
         AwlqchRLFyHVQbsUDnsDY1qnLy7HjGRQUzVrElTYcPfeuAxPIWWaWYvhe3zlvte9F98e
         beUhGDN0q2omtLB9rrbw/Clt62wAl4FCLuJvTXkTH1yFyf9iNtJufFkUBnlfSWN7mNSd
         y90IWxQsw9C/kM7X5FlMrVE2cLw1lEgd8PDBIisiwssvD9I2shCFnnC4yo0jeG50/bvt
         R5UAfXS5RA0Fz/N4BSLEUBRuYKGIvkd4JslzjzI5PaviVBKZph6Pni3grCu2OPO/Wxji
         IVEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=Ty0xUdZz;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
Received: from so254-31.mailgun.net (so254-31.mailgun.net. [198.61.254.31])
        by gmr-mx.google.com with UTF8SMTPS id b76si1780854ill.3.2020.12.21.21.56.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Dec 2020 21:56:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 198.61.254.31 as permitted sender) client-ip=198.61.254.31;
X-Mailgun-Sending-Ip: 198.61.254.31
X-Mailgun-Sid: WyIyNmQ1NiIsICJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsICJiZTllNGEiXQ==
Received: from smtp.codeaurora.org
 (ec2-35-166-182-171.us-west-2.compute.amazonaws.com [35.166.182.171]) by
 smtp-out-n05.prod.us-east-1.postgun.com with SMTP id
 5fe18a65120d248bb5f06f87 (version=TLS1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); Tue, 22 Dec 2020 05:55:49
 GMT
Sender: vjitta=codeaurora.org@mg.codeaurora.org
Received: by smtp.codeaurora.org (Postfix, from userid 1001)
	id 6831DC43462; Tue, 22 Dec 2020 05:55:48 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-5.4 required=2.0 tests=ALL_TRUSTED,BAYES_00,
	NICE_REPLY_A,SPF_FAIL autolearn=unavailable autolearn_force=no version=3.4.0
Received: from [192.168.43.216] (unknown [106.76.209.12])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	(Authenticated sender: vjitta)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id 3A59FC433CA;
	Tue, 22 Dec 2020 05:55:41 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org 3A59FC433CA
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
To: Minchan Kim <minchan@kernel.org>, Alexander Potapenko <glider@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, dan.j.williams@intel.com,
 broonie@kernel.org, Masami Hiramatsu <mhiramat@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com,
 ylal@codeaurora.org, vinmenon@codeaurora.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org>
 <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org>
 <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
 <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org>
 <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
 <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
 <X+EFmQz6JKfpdswG@google.com>
From: Vijayanand Jitta <vjitta@codeaurora.org>
Message-ID: <d769a7b1-89a2-aabe-f274-db132f7229d1@codeaurora.org>
Date: Tue, 22 Dec 2020 11:25:34 +0530
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.0
MIME-Version: 1.0
In-Reply-To: <X+EFmQz6JKfpdswG@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-GB
X-Original-Sender: vjitta@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mg.codeaurora.org header.s=smtp header.b=Ty0xUdZz;       spf=pass
 (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org
 designates 198.61.254.31 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
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



On 12/22/2020 1:59 AM, Minchan Kim wrote:
> On Mon, Dec 21, 2020 at 04:04:09PM +0100, Alexander Potapenko wrote:
>> On Mon, Dec 21, 2020 at 12:15 PM Vijayanand Jitta <vjitta@codeaurora.org> wrote:
>>>
>>>
>>>
>>> On 12/18/2020 2:10 PM, Vijayanand Jitta wrote:
>>>>
>>>>
>>>> On 12/17/2020 4:24 PM, Alexander Potapenko wrote:
>>>>>>> Can you provide an example of a use case in which the user wants to
>>>>>>> use the stack depot of a smaller size without disabling it completely,
>>>>>>> and that size cannot be configured statically?
>>>>>>> As far as I understand, for the page owner example you gave it's
>>>>>>> sufficient to provide a switch that can disable the stack depot if
>>>>>>> page_owner=off.
>>>>>>>
>>>>>> There are two use cases here,
>>>>>>
>>>>>> 1. We don't want to consume memory when page_owner=off ,boolean flag
>>>>>> would work here.
>>>>>>
>>>>>> 2. We would want to enable page_owner on low ram devices but we don't
>>>>>> want stack depot to consume 8 MB of memory, so for this case we would
>>>>>> need a configurable stack_hash_size so that we can still use page_owner
>>>>>> with lower memory consumption.
>>>>>>
>>>>>> So, a configurable stack_hash_size would work for both these use cases,
>>>>>> we can set it to '0' for first case and set the required size for the
>>>>>> second case.
>>>>>
>>>>> Will a combined solution with a boolean boot-time flag and a static
>>>>> CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
>>>>> I suppose low-memory devices have a separate kernel config anyway?
>>>>>
>>>>
>>>> Yes, the combined solution will also work but i think having a single
>>>> run time config is simpler instead of having two things to configure.
>>>>
>>>
>>> To add to it we started of with a CONFIG first, after the comments from
>>> Minchan (https://lkml.org/lkml/2020/11/3/2121) we decided to switch to
>>> run time param.
>>>
>>> Quoting Minchan's comments below:
>>>
>>> "
>>> 1. When we don't use page_owner, we don't want to waste any memory for
>>> stackdepot hash array.
>>> 2. When we use page_owner, we want to have reasonable stackdeport hash array
>>>
>>> With this configuration, it couldn't meet since we always need to
>>> reserve a reasonable size for the array.
>>> Can't we make the hash size as a kernel parameter?
>>> With it, we could use it like this.
>>>
>>> 1. page_owner=off, stackdepot_stack_hash=0 -> no more wasted memory
>>> when we don't use page_owner
>>> 2. page_owner=on, stackdepot_stack_hash=8M -> reasonable hash size
>>> when we use page_owner.
>>> "
>>
>> Minchan, what do you think about making the hash size itself a static
>> parameter, while letting the user disable stackdepot completely at
>> runtime?
>> As noted before, I am concerned that moving a low-level configuration
>> bit (which essentially means "save 8Mb - (1 << stackdepot_stack_hash)
>> of static memory") to the boot parameters will be unused by most
>> admins and may actually trick them into thinking they reduce the
>> overall stackdepot memory consumption noticeably.
>> I also suppose device vendors may prefer setting a fixed (maybe
>> non-default) hash size for low-memory devices rather than letting the
>> admins increase it.
> 
> I am totally fine if we could save the static memory alloation when
> the page_owner is not used.
> 
> IOW, page_owner=disable, stackdepot=disable will not consume the 8M
> memory.
> When we want to use page_owner, we could just do like this
> 
> 	page_owner=enable, stackdepot=enable
> 
> (Maybe we need something to make warning if stackdepot is disabled
> but someone want to use it, for example, KASAN?)
> 
> Vijayanand, If we could work this this, should we still need the
> config option, then? 
> 

Michan, We would still need config option so that we can reduce the
memory consumption on low ram devices using config.

Alex, On this,
"I also suppose device vendors may prefer setting a fixed (maybe
non-default) hash size for low-memory devices rather than letting the
admins increase it."
I see kernel param swiotlb does similar thing i.e; '0' to disable and
set a value to configure size.

I am fine with either of the approaches,

1. I can split this patch into two
   i)  A bool variable to enable/disable stack depot.
   ii) A config for the size.

(or)

2. A run time param - '0' to disable and set a valid size to enable.

Let me know your comments.
-- 
QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a
member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d769a7b1-89a2-aabe-f274-db132f7229d1%40codeaurora.org.
