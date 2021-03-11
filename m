Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBDENVGBAMGQEMW36SYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 91BE6337976
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 17:34:21 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id b21sf10198698pfo.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 08:34:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615480460; cv=pass;
        d=google.com; s=arc-20160816;
        b=0HJ4PvDb9QwggJt1qcz4p7inhk9DZIOXC7rHnYn7q8zG+eHKL2nSGsWxXO9jkXhHiY
         NfBPFnqA2pE1a2iPhUD8LqKuzf+tvGmMfcV7AIIPz1ih8CGECDWE7p/lpGBtEm+62tYA
         HFgsHwYl6fIRsXXBwnG2ghp+0CMBS2mDePnfUin69HY5GE7zXINenkA0CBBU0fgbDZfo
         ddQU/B8qeBn5QDQLquk+igiJOI1MOrcZ3g7yQZ45yDvn/fFREDZZNhAJKdaK1IrURddG
         fzHCAy3z649JEUJtFMvP85cNIvozn5P6tCI8pBlnkkbBSAph7W3AbU4AHzIWk9Jdx1UA
         HOsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=oRGX/SeGn0DayXoAk4gTR8ImToe7TsCUpK7oWi7Zat8=;
        b=NetGcuodGwrD3y3yR/xZorhvigvpl/SPE9KeVa1xS1r95BmPKjMRWBftZTON2HNWWE
         P8SZyN7aOgbPBMR8MLBss4DbOCF+HHCujWLcBQYHlY2A90sWXZTh/X5N1/SkiJylyqNE
         B+2zsZTvcOYYcg1ZkFkQLKe+8oF1U3qskJs7Q37Bwo09fpVsEMEdQz3//KsDkeoMiNHK
         XT0GKHdm4qhe8aARssmdbPmo/jlmgpW6Ta4GvhF31IzKOYcWFNf7ZLbZRQDQEoHuQL1L
         dwy/md6Oxcvyw8Ov0LeaDfKmcZE6bLZRoDxz3PwhuADFUkBn6gOfnKzh09UoC9qfjCrX
         geew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oRGX/SeGn0DayXoAk4gTR8ImToe7TsCUpK7oWi7Zat8=;
        b=pfe+zXBas5zOGgSFqMnDwvCR5sLYF9wt0zJDgU/AbCklA/HzL51uZnHUQiu64zmY61
         ozZJ2ICaUQctaUEtp7RrFLgzb7RyQIVnKCxW5GVbsvOUTfnmQlAc4ItdGX2I8CamqVoD
         ZOOvf7beOm0zewQ+oCu97JHDI1T8fWCnxUPQm3qHTFnAN9CupIW9wVdzO9aEKDLdqPUT
         GR0eGaX0sXcRESRK7m5FyEToLIB2PRtOU7KUxgaiMo3yuqMAMf3XmGI1xbHdSxw0rY3h
         aPTrSTkQI3KdgtJA1X2m7Xwy41vlhDGvSMgtP3Pr8tmvVAnYY9ph2ItHznNIqm4c4gjH
         tknQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oRGX/SeGn0DayXoAk4gTR8ImToe7TsCUpK7oWi7Zat8=;
        b=mbbG0cMbH9tI/8pdxDA6pO5CF7vEXkBug5l5E/1xjfJOScFg55lSa/vivWa8ZZ7sDJ
         AephwF5eEWbE1nHC6ULQuibrKibrDWkjDImke9OVbbi4lV9PNbJfxnPelK51kH/8o/iV
         vheiUIe6bnjMcmNzM5HyJirqCFfoobDADIiK65H1myLlxJorFKfjaCAtwGSrZ3E3R3IS
         cMYTvthM6zgBuDbGj8U4YskNAAf6dPxCUK11zlctoUF+5C+dhylF63yYM/Hu1Pd0f9+l
         16xVAxsWjNP/3hxs0Wl5HWiMgJoW3C92rhQg79awqE1UHEyFFisVFVnXQ6df6q6+JNJa
         ULPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aTsNF+3pg4H/8y1m1tdGJIyYzxtahGnpHDmMIFPYfsRvO1IE+
	dC9+d2oL/3jZtBXtXMGTqbQ=
X-Google-Smtp-Source: ABdhPJyzBzyTLxa5RxRkZaIW/NfgNQiQef3FozJJlBnbGvj0A3j1oxD1+PxNrU7Ye24mAQodsVY8IQ==
X-Received: by 2002:a17:902:aa0a:b029:e4:c090:ad76 with SMTP id be10-20020a170902aa0ab02900e4c090ad76mr8971991plb.2.1615480460291;
        Thu, 11 Mar 2021 08:34:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5302:: with SMTP id m2ls2474809pgq.5.gmail; Thu, 11 Mar
 2021 08:34:19 -0800 (PST)
X-Received: by 2002:a65:4049:: with SMTP id h9mr7805272pgp.215.1615480459741;
        Thu, 11 Mar 2021 08:34:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615480459; cv=none;
        d=google.com; s=arc-20160816;
        b=CaOyPMI+A3ausL9H+kOMpySqKHpQsOnPCg/RrCVoja2aqsvSCLmcAdzZVKergmknbo
         mcHX1ooDnJ5yMJKHFt1TH+XGDMdO9WICZm4va7gltHgc6DBbcw1I7+h5497X9d7AUFJz
         Lnu5a+z2g8jGbEbiX3tMrb88QJx61o+OVfINAy/QKzAYCZuH+Ai7FdiGlOKzRbQ/g1jV
         tsyW+zJaXNoKKhwEncdFSu4SyD37A3WD2SqWzL0uis1E+samBlzTMGv0SBF6RhKKXeQ9
         Shj92aTTRtu1bIFoIwzDe3ykFXWMyPlVJlwOmlYE1vSLli60lwWuygp0LIGaCZhFZ4MP
         AmSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nQIwblRfTbQNALXZOJq8XnRJ6w+AUHUJ2fMZTKOlCuY=;
        b=vjtzwBrfFXPNc6yCQ87ucAIjIFF7rOnq3oD319pVN/bzp++GJKQleID9NBNN1kQN8K
         zJW5p7cw/QdAUDt33Gykid04zVnbb4Jnb5/bs8gX1+i+b6KjYOSzaQXvjEjDyZtgydBA
         XXqgkBYEVNeLKHmzbqiWWm+GmvuanX83vEFuwNaB5F9HAGCZG/tgAwRMjim8/yQg0k/e
         moJbzPcBZD5GRzhv/iqaaMxfnAI62xuBNgiwBaG9KiWJVctqymMzJxtJvMfI8wS67F5h
         ti+38mgyj2nS7HqURc5Uz4WirxMUht1mbL3adqSqlE0Pc3jJRR+XXRNMJViQLKzvU+oi
         zgRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id md20si792108pjb.1.2021.03.11.08.34.19
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Mar 2021 08:34:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5F0EA1FB;
	Thu, 11 Mar 2021 08:34:18 -0800 (PST)
Received: from [10.37.8.5] (unknown [10.37.8.5])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 61A193F70D;
	Thu, 11 Mar 2021 08:34:16 -0800 (PST)
Subject: Re: [PATCH v14 8/8] kselftest/arm64: Verify that TCO is enabled in
 load_unaligned_zeropad()
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
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-9-vincenzo.frascino@arm.com>
 <20210311132509.GB30821@arm.com>
 <bd403b9f-bb38-a456-b176-b6fefccb711f@arm.com>
 <20210311162820.GE30821@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <60c1eedb-edc7-e92f-73ed-b26f97a21b97@arm.com>
Date: Thu, 11 Mar 2021 16:34:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210311162820.GE30821@arm.com>
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



On 3/11/21 4:28 PM, Catalin Marinas wrote:
> On Thu, Mar 11, 2021 at 03:00:26PM +0000, Vincenzo Frascino wrote:
>> On 3/11/21 1:25 PM, Catalin Marinas wrote:
>>> On Mon, Mar 08, 2021 at 04:14:34PM +0000, Vincenzo Frascino wrote:
>>>> load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
>>>> read passed some buffer limits which may include some MTE granule with a
>>>> different tag.
>>>>
>>>> When MTE async mode is enable, the load operation crosses the boundaries
>>>> and the next granule has a different tag the PE sets the TFSR_EL1.TF1
>>>> bit as if an asynchronous tag fault is happened:
>>>>
>>>>  ==================================================================
>>>>  BUG: KASAN: invalid-access
>>>>  Asynchronous mode enabled: no access details available
>>>>
>>>>  CPU: 0 PID: 1 Comm: init Not tainted 5.12.0-rc1-ge1045c86620d-dirty #8
>>>>  Hardware name: FVP Base RevC (DT)
>>>>  Call trace:
>>>>    dump_backtrace+0x0/0x1c0
>>>>    show_stack+0x18/0x24
>>>>    dump_stack+0xcc/0x14c
>>>>    kasan_report_async+0x54/0x70
>>>>    mte_check_tfsr_el1+0x48/0x4c
>>>>    exit_to_user_mode+0x18/0x38
>>>>    finish_ret_to_user+0x4/0x15c
>>>>  ==================================================================
>>>>
>>>> Verify that Tag Check Override (TCO) is enabled in these functions before
>>>> the load and disable it afterwards to prevent this to happen.
>>>>
>>>> Note: The issue has been observed only with an MTE enabled userspace.
>>>
>>> The above bug is all about kernel buffers. While userspace can trigger
>>> the relevant code paths, it should not matter whether the user has MTE
>>> enabled or not. Can you please confirm that you can still triggered the
>>> fault with kernel-mode MTE but non-MTE user-space? If not, we may have a
>>> bug somewhere as the two are unrelated: load_unaligned_zeropad() only
>>> acts on kernel buffers and are subject to the kernel MTE tag check fault
>>> mode.
>>
>> I retried and you are right, it does not matter if it is a MTE or non-MTE
>> user-space. The issue seems to be that this test does not trigger the problem
>> all the times which probably lead me to the wrong conclusions.
> 
> Keep the test around for some quick checks before you get the kasan
> test support.
> 

Of course, I never throw away my code.

>>> I don't think we should have a user-space selftest for this. The bug is
>>> not about a user-kernel interface, so an in-kernel test is more
>>> appropriate. Could we instead add this to the kasan tests and calling
>>> load_unaligned_zeropad() and other functions directly?
>>
>> I agree with you we should abandon this strategy of triggering the issue due to
>> my comment above. I will investigate the option of having a kasan test and try
>> to come up with one that calls the relevant functions directly. I would prefer
>> though, since the rest of the series is almost ready, to post it in a future
>> series. What do you think?
> 
> That's fine by me.
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/60c1eedb-edc7-e92f-73ed-b26f97a21b97%40arm.com.
