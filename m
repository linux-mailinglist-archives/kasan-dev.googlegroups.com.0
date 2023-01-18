Return-Path: <kasan-dev+bncBD5LPQWS74GBBBVUUCPAMGQEHBQT3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 59BAB672297
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 17:10:48 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id b9-20020a170903228900b00194a0110d7bsf4259182plh.6
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 08:10:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674058247; cv=pass;
        d=google.com; s=arc-20160816;
        b=jgBSfZIG/eygn/2wBO1tiaDtBTUPpKQa1HZef8KSlWRRitk/7td/Snf2sIrdRFbuUY
         zA487Tt3PCdsDqrbCIOwWtjpEMfsbAOX3SgNK0Gx7QpulmfkmGRZBGQb3D+MqVuV17/M
         WW/2OHCaX4De5zUWYsKWOFg+HuNQM6zuHqxPSdF3gXfa4oDaMSwFQQAzPhbvtbMy+WkP
         p6Iku0nqkRljvwmprdKgwmVveLiYu6EA9WnPOK6e6MbC/r0ggwVsy/a18mLh42ihkKED
         Vyl4EWTFTnfZc11mXu2RQlhhXpm8mJRiIx49IeaQyshRy/Oo9T7Q2lDlTlVXEXshsUI/
         QeAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:from:references:cc:to:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=uNRn2uNAuRccuhMk23ORmhLXIc2ZHBCgNcCl+NsUB7k=;
        b=w0cMz5JtXgJnJy8QjQ3bqIJQLF7SUGMsurzyq3APo0sC5SREqz/36sovF2glA4rOnG
         HwWV3ilNQHBOsF+FlAN4jB8lzizKdLpiooSxPU4WGW/RAxv7WS73/q1+1pqTvbCgPSMf
         fKyvz5WUiEunbAS1kPNulnHrAkFcwa1QEpXG4LWEiWztT+bh2lnbIIL4iphtr1SRZ9CF
         Phnic6rAFBhXPX0Abuo7Mcba7icVBS/RDk2b0L05QVs83Df8Q422P3Q7pbcinZ8Wj68P
         EfmmyEpLJJ77kGoWw4B8dCvSQHeEJ1UlVicDSIDHCMfXTdlPccclmhY7I/rhIVlHn3ee
         kqFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Bjza/95z";
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uNRn2uNAuRccuhMk23ORmhLXIc2ZHBCgNcCl+NsUB7k=;
        b=IPTPGJuschyh6n9x+so5w+IFX0zq7X7Wzzbn8cgbUD7HtYDwlNjoDt6ug3J8xqnsz7
         ZDPY3Bdq+AnB6U4tiQDiDPd71FFl2DSVw4MdqOHu5QXHkhZ+lCzfwGlFWj33tiLhPX4v
         yowfROpo0aYdNLrFng2Zt0xlbs37csjN848TR8hvRT2drcGbYMQXm07iQvqByHiQqYo1
         uBrgN03buNAxOP9jZ9MqTeLReBxhOQqnAP7KYUjb0t2bggvTBFbNkdU5DwwvHsKqWtRm
         RYiMDFKNSW0AgEvmlfMMRq7IRmjZScdrKCrZ9qSPoS6aNdw2HoPju15hZn41OWQ/dgrU
         RaKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:from:references:cc:to
         :user-agent:mime-version:date:message-id:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uNRn2uNAuRccuhMk23ORmhLXIc2ZHBCgNcCl+NsUB7k=;
        b=MFuDI7Atp2KkgxtqMS/DgPzbozkvaNTHH/WufELbhM/LnjUNHNcLPhHjZows1x0m7g
         xBZJiPTY1B0YtPg1X8PHDe3idB31+L3pYoTTo45sCHqBd4A701NCZ2F2ibIpDmawoz/j
         fVbNu5YLONnJ4y1CiyXdnP5+uwgOkBRCj06rTYCa/FqvBcML8BTzTrvg/OuxA4KCRAEl
         MXvnl45ca8MSQdUZ9jBBdrlyKG80MtZamheReGL8wB8fXW7dDrSL/46ONzAV5JDNRar2
         0Rd26yqTrGHlbadRrg+iRT4xvYc40AvsioNXLgtLbqwutvKCQTX63IIYFuVXdCRwmlah
         nueA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpIpNIu97V80cUJXaRQxmzbeUMuSbtMuFA6ByOpSd03DfgVJpuK
	HgXIimzLnRWjmkr9KTN93rc=
X-Google-Smtp-Source: AMrXdXviZCqVM0Mwyshf+FLGqBxNAYmFyfpdGri0/p89iEabFNtwGKH2CHZpW1K65ztUAUZCpN+fLw==
X-Received: by 2002:a17:902:7c97:b0:192:7c0a:e137 with SMTP id y23-20020a1709027c9700b001927c0ae137mr662739pll.99.1674058246732;
        Wed, 18 Jan 2023 08:10:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6946:b0:191:1e85:3329 with SMTP id
 k6-20020a170902694600b001911e853329ls19508140plt.3.-pod-prod-gmail; Wed, 18
 Jan 2023 08:10:46 -0800 (PST)
X-Received: by 2002:a17:903:12cc:b0:194:c04c:deea with SMTP id io12-20020a17090312cc00b00194c04cdeeamr1450655plb.15.1674058245928;
        Wed, 18 Jan 2023 08:10:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674058245; cv=none;
        d=google.com; s=arc-20160816;
        b=1Idi6pwp7Z4Ti7VFYIMuMAySpVx6epeLGfceofPPqywoYzj0IOkk44jFD7RHsaDvK8
         m0YAg1miiwEmJZ7vZSJFfLK4awmNFg2iKbI7+t8WXDNXA8sJPUTudUboGmOupgh8RCC1
         bGjoCpnHkxeM3GFs79E+ft08AfEeEGDZw3DFRdgvQHUHk0F2Y0GhoXRtMeBKzpNjEX25
         MSQXBaSRgZKquZQcS53Q4C6CB8m2tqeYKRGIvEFRmKCuAuPsJtdfCqBhWCVh2Jjclxmz
         4MM5anYmz2A4wyGZ5Wcxn71maAkIbZ34cOZmlPA7pqCHXg4GX3UAxb1aa4z/XXINapks
         n4qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=TsK70ryPdXW1s1KVy/uENOtHAZLYuMoVX6dcDpOTb+Y=;
        b=xsRvxGms8Ybopfh6tBhrnFzPDIkXSFacujp2l/DdNh+Tacgvn6X0Ky4lvRo9vw+ayx
         GDZZfEGL2v1lHbX0EfFfEnxWlGlxauA4bkOf5iPWVUlsV//dgNIY1Zp9ijpmoUbCn7O+
         qRR92os8SJBqAqMc+wY8aVoKbzVhrqZK1a8Mq7umLWHbpIUt510kOUkY1WnIjLerhanh
         Ynzwq7zXInRYv7VzECnb+9ay3dCVG5W2MqlOoBv2vRLBRxTVgNol4TTQffabuhY5WdWs
         p1pDuzhtzlNw2ZKFuAKnFv+pICosRUKO+gE8FpoBTvGiWQquFAw8qfe7Adys+cAWIcgE
         fDdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="Bjza/95z";
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id j8-20020a170903024800b00178112d1196si2777919plh.4.2023.01.18.08.10.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 08:10:45 -0800 (PST)
Received-SPF: pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yb1-f200.google.com (mail-yb1-f200.google.com
 [209.85.219.200]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-192-OF_vKXGfMaCdPbsL9_Ks5A-1; Wed, 18 Jan 2023 11:10:18 -0500
X-MC-Unique: OF_vKXGfMaCdPbsL9_Ks5A-1
Received: by mail-yb1-f200.google.com with SMTP id u186-20020a2560c3000000b007c8e2cf3668so20212842ybb.14
        for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 08:10:10 -0800 (PST)
X-Received: by 2002:a81:8392:0:b0:43e:a87c:cd86 with SMTP id t140-20020a818392000000b0043ea87ccd86mr6674806ywf.29.1674058209612;
        Wed, 18 Jan 2023 08:10:09 -0800 (PST)
X-Received: by 2002:a81:8392:0:b0:43e:a87c:cd86 with SMTP id t140-20020a818392000000b0043ea87ccd86mr6674746ywf.29.1674058208847;
        Wed, 18 Jan 2023 08:10:08 -0800 (PST)
Received: from [192.168.1.16] (pool-68-160-135-240.bstnma.fios.verizon.net. [68.160.135.240])
        by smtp.gmail.com with ESMTPSA id h18-20020a05620a401200b007064fa2c616sm8125910qko.66.2023.01.18.08.10.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 08:10:08 -0800 (PST)
Message-ID: <42499854-b0ca-9efc-80a1-8d6dc0c968ea@redhat.com>
Date: Wed, 18 Jan 2023 11:10:07 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com>
 <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
 <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
 <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com>
 <CACT4Y+YYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV+ob_A@mail.gmail.com>
From: Joe Lawrence <joe.lawrence@redhat.com>
Subject: Re: kpatch and kasan
In-Reply-To: <CACT4Y+YYRc0_uG4y8YuX3f3WQUdmOjcRu4kP9xjhF4HVV+ob_A@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: joe.lawrence@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="Bjza/95z";
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

On 1/18/23 10:21, Dmitry Vyukov wrote:
> On Wed, 18 Jan 2023 at 14:45, Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>
>> On 1/18/23 02:21, Dmitry Vyukov wrote:
>>> On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
>>>>
>>>> +kernel-dynamic-tools
>>>>
>>>> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>>>>
>>>>> Hi Kostya,
>>>>>
>>>>> I work on the kernel livepatching Kpatch project [1] and was hoping to
>>>>> learn some info about compiler-generated (k)asan ELF sections.  If you
>>>>> can point me to any references or folks who might entertain questions,
>>>>> we would be much appreciated.
>>>>>
>>>>> The tl/dr; is that we would like to build kasan-enabled debug kernels
>>>>> and then kpatches for them to help verify CVE mitigations.
>>>>>
>>>>> If you are unfamiliar with kpatch, it accepts an input .patch file,
>>>>> builds a reference and patched kernel (with -ffunction-sections and
>>>>> -fdata-sections) ... then performs a binary comparison between
>>>>> reference/patched ELF sections.  New or changed ELF sections are
>>>>> extracted into a new object file.  Boilerplate code is then added to
>>>>> create a livepatch kernel module from that.
>>>>>
>>>>> The devil is in details, of course, so our kpatch-build tool needs to
>>>>> know whether it should omit, copy, or re-generate an ELF section
>>>>> depending on its purpose.  The kernel is rife with interesting sections
>>>>> like para-virt instructions, jump labels, static call sites, etc.
>>>>>
>>>>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
>>>>> data..LASAN0 from the gcc source code, I was wondering if these were
>>>>> documented somewhere?
>>>>>
>>>>>
>>>>> Regards,
>>>>>
>>>>> [1] https://github.com/dynup/kpatch
>>>>> --
>>>>> Joe
>>>
>>> +kasan-dev
>>>
>>> Hi Joe,
>>>
>>> But why not just build a new KASAN kernel and re-test? This looks so
>>> much simpler.
>>>
>>
>> Hi Dmitry,
>>
>> Well yes, testing an ordinary (fixed) kernel build is much easier, however:
>>
>> 1 - Sometimes kpatches deviate from their kernel counterparts.  Examples
>> include ABI changes, fixups in initialization code, etc.
> 
> This does not prevent testing in a normal way, right? In fact I would
> send the patch to the normal CI as the first thing.
> 

Exactly.  At Red Hat, we typically wait for a corresponding kernel fix
to pass tests before starting on our kpatch conversion (emergency CVEs
aside) ... that way we're usually confident with the overall changes
before we even start our work.

In cases where the kernel fixes are verified via reproducer and KASAN
enabled config, as long as our version is mostly 1:1 we can still be
confident.  Giving our QA team a similar obvious verification with KASAN
enabled kpatch would be bonus.

-- 
Joe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42499854-b0ca-9efc-80a1-8d6dc0c968ea%40redhat.com.
