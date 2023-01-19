Return-Path: <kasan-dev+bncBD5LPQWS74GBBQVWUWPAMGQEOJICAZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 59AE4673CF5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 16:01:24 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id i1-20020a170902c94100b0019486e621d8sf1499485pla.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 07:01:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674140483; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNZV42umcxiKB5ssMuZws87yIiuumzbVp4sY3SO3zSgSvbrsYBVhNPFRXiQQdk+jnd
         +ByP0QQvlB8iYno4xTLVSMXRCBiitMjFhTUZG9CMXIzeQbLXK60/JiBh4rupKLTuP6V5
         LVOD1tsBVvNLZlNz0Wzjk9IKQNnJ95gvhjTh7PPLtGmgKWB/xNG526ife9mDL4JN53TF
         eXdSO9PrJLiR0dR2uvY+gMKnFnApw4+cdWIwvZxVKU9Bh4t5j85HKsiGWM9RVDl2Jtkz
         jeRccNnPQj/ol+KcVtYEUg3H4Pxbt4oUnpHG8VXrhw22/N7I6OKJ0Tqi/+tsRIqMnSm4
         dhkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:from:references:cc:to:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=eocAAJgmoo0sYEukRFjGFDLjqu6aK9EBWNzPawIOJ8I=;
        b=tPbYPPwzn7bzTAd9fwHNIppv6q5wcpZrK0w0yQar+caX9USAS5KNmX02SsJUiRQuky
         0JWxO1+HR8X1InAy2//ZukJBP7FJwaDNDHmFz8sgddybID6o9pR15L8SeLIcjV4p3Mr9
         XXKA/bB0LT9wKCLiOr7myovYofp/OdIHYCkUozkNs4353D2MLlZT0SNeyRb9QDRMuCt+
         ozUMIiuoQNvwWk0sH9tKDuu1tT0qdEl6oq/nS0B0Ok5f9ff0jdeyqeJn/3LJlLvb7x7u
         XHshXRFDGiHrqwoaSyTuEj3vOR4gWDCObhOAXiwa8B/ZBqKQQBzOkrEsGdpOJ/ldafPD
         OnSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gAxDc4Qq;
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eocAAJgmoo0sYEukRFjGFDLjqu6aK9EBWNzPawIOJ8I=;
        b=D0N4MnNGtvvJczYLt762xIuzeXorMOWbcH9MjkQXbWuh8aWHGAKQ4A1fRAv8UTzMZK
         h4tgqzSgSJdYlYyvjS/bc1YrekTii6ua+kAZcWY3vP9e4KfDRmQKHY9BCrgw2T/BlL4V
         whbCUiRitmfl7a3qMsU5Z+0XXGJ9D/EXxiu0yBy8JGJW34mHuGA+dpfJkmvUn+vnrJDp
         RuMmpB//vNo6/xVuBn3TzsHepgc1RBnQM19TPidlpaJzgbarO/xOnZX2Rozc3VOE6vOF
         TnKQ8Gp06ppclccUNwvhJHvMNV05VBZmzOcJWpqKidtCRkMQRdMP8SoPGEeFs1BpB0z7
         2K+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:from:references:cc:to
         :user-agent:mime-version:date:message-id:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eocAAJgmoo0sYEukRFjGFDLjqu6aK9EBWNzPawIOJ8I=;
        b=DhiB8m0txDS1+sAmrfoEbGUsAgnXsPgMOsyxXZBcEtM/bIkdOqBJT4su1pIdKNSsWR
         WBaSXnJNlOe732DXjGD5yqj3OxLOxZL8ZgmZ/iUVkY0A8LsIIPC9D+E64dIcu1cWB5pl
         My6x4obsUeleLkKOiXtJarykkgxevAIPxmrnWTh6TJzo5VbMu1Y8Zsprr7mgyGvqc8HA
         c4pID1HZW/7xH3ONiMF79uGDBVE/5Jt/XUKl/knfnczGPHcldAX/0tUfgzz/ynUYkeGD
         rJLxxOQmsrG0r8zFWARRAvDzlS8eASkL5PES0YGDgSVmKjhIDp48a9VN+5MebK0eUJzC
         e9zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpeGM8WMIBijRUhj7F8MebBrcc25BNCTSE4p3XfaPcpDZUxI8yn
	BtVPFHFJNxl/+ikLZtY4aCw=
X-Google-Smtp-Source: AMrXdXvKOM1Ly452I72zrhnpV1jAkbRmdOkdlfrZwXr+iZ0ovEWfUdyY51w3THV30y+Yl6nZskR3pg==
X-Received: by 2002:a17:90a:fa97:b0:219:8d13:2898 with SMTP id cu23-20020a17090afa9700b002198d132898mr944253pjb.124.1674140482686;
        Thu, 19 Jan 2023 07:01:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3801:b0:227:1b53:908c with SMTP id
 w1-20020a17090a380100b002271b53908cls5669365pjb.1.-pod-canary-gmail; Thu, 19
 Jan 2023 07:01:21 -0800 (PST)
X-Received: by 2002:a05:6a21:1511:b0:af:c491:c7d2 with SMTP id nq17-20020a056a21151100b000afc491c7d2mr10003132pzb.29.1674140481786;
        Thu, 19 Jan 2023 07:01:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674140481; cv=none;
        d=google.com; s=arc-20160816;
        b=NCHbHleRp58pz0QhqJcN+zv1SKwzmYvpJyagjjYWYmZzJKeCuWosRmlV20LHl/wLEU
         TjhJ+sBSMxofjelI5aSxx5NZXthn4ytVTe3HuQm5OUIuN47Pf2ekWQs1pi6Upd8KVFkQ
         Z7a808VZcnk1wCX82ULUJBmqYC5RulRWJRQ8os7Hmuc5GXhxU07iMKstAo8nfjUmVibg
         yAop7CXGJwEMgcKBJ23gGjhgSQUWlF+YkLiDqIPKe5kghMs5dDPyjwggI4F2WAu20Ruc
         oYfKaD/zyA+qW2LtABKnj/V5ts3RQ2CsYzKHkrjtyoF+p40u4enKPrOMr6lTQImsC0S7
         M5Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7SmtQcnIT3RiHwPCNASDo0OkzYhNOXTiAQFhu13/4dE=;
        b=MYvyFTtPPWUKDqvkDFr0FuYadPdtTurOi8RNJpHjVnsBzf/1dfFCQ8Ti23/B81g9+b
         KvKUujkWWPJs2J7VfxJ69J3K8qGZCkUnmL4lzGB/EMHsMNlliu/DzEs/uthw0CffgAvI
         slnO7ywNgBd2Y+DD5Bt6Qo/2tOMTe9TPRX86svAMIhRVQm2QaqdF6TA+6PhI90Yw/LOR
         eq3AKRCOG0ze9cfLJvI6XKMhiQ9t9QewYAJeSUgFQXD+loEhdLArySmLWcRzRDbil7L/
         LFRQoe3HeOCK6RL5svtRIhPO8zsdynGg3GAIrFxBbXKD5PhzxqLXm8ZhsoeaZvN83ZOJ
         LQvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gAxDc4Qq;
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id s22-20020a639256000000b004ac6ba951f1si142919pgn.2.2023.01.19.07.01.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 07:01:21 -0800 (PST)
Received-SPF: pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-oa1-f69.google.com (mail-oa1-f69.google.com
 [209.85.160.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-438-DcSy23TONmKmSpI-XWl_HA-1; Thu, 19 Jan 2023 10:01:17 -0500
X-MC-Unique: DcSy23TONmKmSpI-XWl_HA-1
Received: by mail-oa1-f69.google.com with SMTP id 586e51a60fabf-15fabbf0a85so585358fac.11
        for <kasan-dev@googlegroups.com>; Thu, 19 Jan 2023 07:01:15 -0800 (PST)
X-Received: by 2002:a4a:c90a:0:b0:4a0:2ddf:9da2 with SMTP id v10-20020a4ac90a000000b004a02ddf9da2mr5408273ooq.5.1674140474321;
        Thu, 19 Jan 2023 07:01:14 -0800 (PST)
X-Received: by 2002:a4a:c90a:0:b0:4a0:2ddf:9da2 with SMTP id v10-20020a4ac90a000000b004a02ddf9da2mr5408229ooq.5.1674140473564;
        Thu, 19 Jan 2023 07:01:13 -0800 (PST)
Received: from [192.168.1.16] (pool-68-160-135-240.bstnma.fios.verizon.net. [68.160.135.240])
        by smtp.gmail.com with ESMTPSA id w6-20020a05620a424600b00705be892191sm19702394qko.56.2023.01.19.07.01.12
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Jan 2023 07:01:12 -0800 (PST)
Message-ID: <99fe4173-0e6c-a834-719d-c477cb003311@redhat.com>
Date: Thu, 19 Jan 2023 10:01:11 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev
 <kasan-dev@googlegroups.com>,
 address-sanitizer <address-sanitizer@googlegroups.com>
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com>
 <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
 <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
 <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com>
 <CACT4Y+YYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV+ob_A@mail.gmail.com>
 <42499854-b0ca-9efc-80a1-8d6dc0c968ea@redhat.com>
 <CACT4Y+ZA_Up4Hn_qcTczuUh0RHdm0seUPGKxf-Eh09n34PcoXA@mail.gmail.com>
From: Joe Lawrence <joe.lawrence@redhat.com>
Subject: Re: kpatch and kasan
In-Reply-To: <CACT4Y+ZA_Up4Hn_qcTczuUh0RHdm0seUPGKxf-Eh09n34PcoXA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: joe.lawrence@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gAxDc4Qq;
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 1/19/23 06:53, Dmitry Vyukov wrote:
> On Wed, 18 Jan 2023 at 17:10, Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>
>> On 1/18/23 10:21, Dmitry Vyukov wrote:
>>> On Wed, 18 Jan 2023 at 14:45, Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>>>
>>>> On 1/18/23 02:21, Dmitry Vyukov wrote:
>>>>> On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
>>>>>>
>>>>>> +kernel-dynamic-tools
>>>>>>
>>>>>> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>>>>>>
>>>>>>> Hi Kostya,
>>>>>>>
>>>>>>> I work on the kernel livepatching Kpatch project [1] and was hoping to
>>>>>>> learn some info about compiler-generated (k)asan ELF sections.  If you
>>>>>>> can point me to any references or folks who might entertain questions,
>>>>>>> we would be much appreciated.
>>>>>>>
>>>>>>> The tl/dr; is that we would like to build kasan-enabled debug kernels
>>>>>>> and then kpatches for them to help verify CVE mitigations.
>>>>>>>
>>>>>>> If you are unfamiliar with kpatch, it accepts an input .patch file,
>>>>>>> builds a reference and patched kernel (with -ffunction-sections and
>>>>>>> -fdata-sections) ... then performs a binary comparison between
>>>>>>> reference/patched ELF sections.  New or changed ELF sections are
>>>>>>> extracted into a new object file.  Boilerplate code is then added to
>>>>>>> create a livepatch kernel module from that.
>>>>>>>
>>>>>>> The devil is in details, of course, so our kpatch-build tool needs to
>>>>>>> know whether it should omit, copy, or re-generate an ELF section
>>>>>>> depending on its purpose.  The kernel is rife with interesting sections
>>>>>>> like para-virt instructions, jump labels, static call sites, etc.
>>>>>>>
>>>>>>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
>>>>>>> data..LASAN0 from the gcc source code, I was wondering if these were
>>>>>>> documented somewhere?
>>>>>>>
>>>>>>>
>>>>>>> Regards,
>>>>>>>
>>>>>>> [1] https://github.com/dynup/kpatch
>>>>>>> --
>>>>>>> Joe
>>>>>
>>>>> +kasan-dev
>>>>>
>>>>> Hi Joe,
>>>>>
>>>>> But why not just build a new KASAN kernel and re-test? This looks so
>>>>> much simpler.
>>>>>
>>>>
>>>> Hi Dmitry,
>>>>
>>>> Well yes, testing an ordinary (fixed) kernel build is much easier, however:
>>>>
>>>> 1 - Sometimes kpatches deviate from their kernel counterparts.  Examples
>>>> include ABI changes, fixups in initialization code, etc.
>>>
>>> This does not prevent testing in a normal way, right? In fact I would
>>> send the patch to the normal CI as the first thing.
>>>
>>
>> Exactly.  At Red Hat, we typically wait for a corresponding kernel fix
>> to pass tests before starting on our kpatch conversion (emergency CVEs
>> aside) ... that way we're usually confident with the overall changes
>> before we even start our work.
>>
>> In cases where the kernel fixes are verified via reproducer and KASAN
>> enabled config, as long as our version is mostly 1:1 we can still be
>> confident.  Giving our QA team a similar obvious verification with KASAN
>> enabled kpatch would be bonus.
> 
> I meant the source patch used to create the kpatch, not some other patch.
> Kpatch is also based on some normal source code patch, right? If so,
> that exact patch used to create kpatch can be testing as a normal
> patch, right?
> 

Yes and no.  Kpatches are essentially kernel modules, but the major
differences between a kernel patch and a kpatch are their runtime
requirements.  Kernel updates occur via reboot.  Kpatches are applied on
a per-task basis while the machine continues to execute.  That means
that a kpatch = kernel patch + code to gracefully handle
pre/transition/post-kpatching states.

So while kpatch code could compile in its respective vmlinux/driver, it
may never execute the parts that handle unsafe pre-existing and
transition states.

> Back to your actual question. I think sections like .data..LASANLOC1
> and data..LASAN0 should be treated just as normal .data/.rodata
> sections. git grep "ASANLOC" in llvm does not give me anything, but I
> would assume these contain string descriptions used in KASAN reports.
> 

Ah so it may be compiler specific [1] and I haven't looked at llvm yet.

[1] https://github.com/gcc-mirror/gcc/commit/21a82048

-- 
Joe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/99fe4173-0e6c-a834-719d-c477cb003311%40redhat.com.
