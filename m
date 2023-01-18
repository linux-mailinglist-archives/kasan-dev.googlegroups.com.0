Return-Path: <kasan-dev+bncBD5LPQWS74GBBZPPT6PAMGQE3NB77GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D9D4671E4F
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 14:45:10 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id v20-20020adfc5d4000000b002bdfcdb4c51sf2257323wrg.9
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 05:45:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674049510; cv=pass;
        d=google.com; s=arc-20160816;
        b=K9em6/cYKibCcvuw+t6lInRB1rtrLj7NXFpsU7vJQJiA5xRevy/CKT8osO0AyUH29u
         5X3TkCUtFoXI3cUOJNIZ88AcXZHOU/m7NI8nwCbxeUFdPOdXisDEcrfibtH/ZDqskWnK
         R7hDGXnfNJCN6GBhxbkn+Hs+AKUv+Jgqaq1N7eItyR63knExcHjiqCk3U70mjiaS9tLi
         x5wWbW/OzOjFI7saF3LVR9UP6B7ueTTynv1ty7f5N28bYU8RxbFLyymFyPOAWTQ21DH7
         xTuQodNv1xcy0dl51fqCtMK5o2a2ORst/Q1GwpngFRkY/SoEGr8iYbEU+dvF/BwihAza
         KJIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:from:references:cc:to:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=jmMqCOxeGg/SYoHBWRsNhyjnj9FNnsynAK0fAE56RU8=;
        b=xgHrf9+vD8Fcr/In9EA02fLOKmBbA6KbO08gFN/JytGbF5JEzvB2SKhGXdCHnEZOJv
         po+hTnIfSCWsH1V5xJn85WGbeJRtkpu8FOniXDLnnknMhtL8tUqY3vu6ldXlR666F4hv
         8HBH6dTA1UK0FRZvWYzaHH//kYGYkxQtu10YVOHVJXheFPHDEq4QqN639nvTgxGvIvJO
         I1MxwlwcUe3Ch/aXN8jRK4jdHvrFnddV1O/urb3Dp+jQKrOoj2BhUMn0cG7IUS7xOZZN
         lFt0NxOQtBmuqjr6BUEWdR9riqYisGCewhJLO1pN+hSkWFP0MNpl4efXSp5wfezAkpHL
         uYaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ckMPGY1p;
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jmMqCOxeGg/SYoHBWRsNhyjnj9FNnsynAK0fAE56RU8=;
        b=KRR9ZleToRko9WCOj8KHP5FnkBtoA3+zYnnsdHdXv3Ep84ja4SWCMfpw+ZPDdmLY0q
         LZdyRJX1nuGjJYtCEB/RzxfuVhTU3DHZmeRDA7jdfWuUoIw9HVF8F9UzpokolctMiMuA
         zOQNN/xff0A2tJuB2fVpcfelHLTRKxeq1+da3Pdyyqz5Jw+bhSteR/xUgwBFRdbm9KNe
         mRdaU55MTok9yOTcWm77U89pldC9bLguqjUheUt4qcn01uLZblDk01CzH+7Eh/Mn9t4G
         lLxYAX8F5GXGnWwpeikJGJDtikOPzrEhwDvN0LpL3yFDlDgKd8NI+/LVhBmYElz9CqU1
         ZPtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:from:references:cc:to
         :user-agent:mime-version:date:message-id:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jmMqCOxeGg/SYoHBWRsNhyjnj9FNnsynAK0fAE56RU8=;
        b=SY5wOA17tdkiKKJ65xxbI33wtJ04CKfqNbS+wRRcWyTTfF1ILakCKBTjyVatboORK8
         BI/7yf1tWY7cqM2uB/fY4VojwftOY4QZqpxnYaxSXS6HXSKZ/c3PJw1shM0abCPXmLO2
         26BSPdFsr1BuEEb4TQnV34Lega0SQjrzjYckp+5oxQjqWQKrZEqKEK9uYi1pO6QXrYT2
         h7reuIE0FIali3sgUsPLQCrvLm4mLG8P3NWsbqGQboHqMuoy+I4L+dikmAeo6wTxupOR
         Us8LP4tJrkTk52J2nyc+i2bh3tvuHacRmTNGVPhs4B2ORED/KYC3ea3twQBwAJtvI2WG
         oXog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpGsqYqC5Vb0S6jEnBnF7YY3oLkBVh8UaScKz16zSTy5WSY8aPx
	TmznTRlDBi6AUVj9rLS0CME=
X-Google-Smtp-Source: AMrXdXt5D+kkVW56D7HnDW335HnabVyXgXYXmqRfsI6o8dwPIHku8RxnjEcTWxKukcj/5hTX3qz/2g==
X-Received: by 2002:a05:600c:42c6:b0:3da:1d23:152 with SMTP id j6-20020a05600c42c600b003da1d230152mr565648wme.49.1674049509760;
        Wed, 18 Jan 2023 05:45:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:248:b0:269:604b:a0dd with SMTP id
 m8-20020a056000024800b00269604ba0ddls1677639wrz.0.-pod-prod-gmail; Wed, 18
 Jan 2023 05:45:08 -0800 (PST)
X-Received: by 2002:adf:ea52:0:b0:279:53e1:5178 with SMTP id j18-20020adfea52000000b0027953e15178mr6094013wrn.45.1674049508724;
        Wed, 18 Jan 2023 05:45:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674049508; cv=none;
        d=google.com; s=arc-20160816;
        b=DVbVL+sgGMtkh+DvoeGKoCAkJhjPmtTBUVWHlSnHJuQU8+2sipKwLlZ0w3YdJ0JutR
         bCMnwPytJvKMrUmxRbpZ6Ah5HL9a28hqAnP/l7JrEcpHZIgp/6FP1OZRxRXklmiu1lSM
         ibOjOZF3wN2duFgTKQAOlM4n/HM2aiwEqOnqUOLyeznCjTybzGp7gp35zIyFVRTkVrPp
         B41I9gmmsFQx6+eEa95Tzdm4x8d0a5+njoZNYxK/b3kvJ/uLPSGJp+bWnrgkNyrH7Z95
         /K61LZDXEw/tG6FB61RS/63JJF37FrCo459zgHD/QLH5J2ZqV1GThBlwU1u4cdR5NFLi
         CZyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject:from
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=be6dUY9kdz3Fa7rKyQt/05EH6CZ0e1zlfBn543tAP30=;
        b=or4sC6i/5kezZoo9JFExm6fMxLFigm8j+hP7grxGyPXt8976ORrSsvihA+GjbF/UTp
         BA02U9b1IANqOr1B4K75lZ/J+IVrixWkN/9MlUu+5rWKLoEqROww02y3FLYwI33lzgSJ
         25ulte+9W/RTARAI0pP9jKaK4bJPpfxeDFVv/CxeyuET+U4sHcGKjtppJG3BOoGsDSoH
         5Q0UKhdxtW6SdeWmAHq1wcw0hVySNWdvxVOQoSmsntGWMdjyZdVXN/0tYyAPgDPPggrt
         AobT13Wo0o6EJZceQ5gmyiPqWRNvwtdKJpxdLC5BlGgwL9fd8e4FyXpqb3hB3rGYF9l/
         0Z1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ckMPGY1p;
       spf=pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=joe.lawrence@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id m7-20020a5d56c7000000b0023677081f0esi1530420wrw.7.2023.01.18.05.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 05:45:08 -0800 (PST)
Received-SPF: pass (google.com: domain of joe.lawrence@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qk1-f197.google.com (mail-qk1-f197.google.com
 [209.85.222.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-122-efGcvmgZOv2gOCWryDb23Q-1; Wed, 18 Jan 2023 08:45:06 -0500
X-MC-Unique: efGcvmgZOv2gOCWryDb23Q-1
Received: by mail-qk1-f197.google.com with SMTP id j10-20020a05620a288a00b0070630ecfd9bso9723718qkp.20
        for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 05:45:06 -0800 (PST)
X-Received: by 2002:a05:6214:5093:b0:535:1b98:327 with SMTP id kk19-20020a056214509300b005351b980327mr13463820qvb.30.1674049506386;
        Wed, 18 Jan 2023 05:45:06 -0800 (PST)
X-Received: by 2002:a05:6214:5093:b0:535:1b98:327 with SMTP id kk19-20020a056214509300b005351b980327mr13463797qvb.30.1674049506115;
        Wed, 18 Jan 2023 05:45:06 -0800 (PST)
Received: from [192.168.1.16] (pool-68-160-135-240.bstnma.fios.verizon.net. [68.160.135.240])
        by smtp.gmail.com with ESMTPSA id d136-20020ae9ef8e000000b006ef1a8f1b81sm22011400qkg.5.2023.01.18.05.45.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 05:45:05 -0800 (PST)
Message-ID: <d4986b01-2386-b75b-ef4d-9b4a58fceeef@redhat.com>
Date: Wed, 18 Jan 2023 08:45:04 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Kostya Serebryany <kcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>
References: <0c87033a-fcef-7c7e-742b-86f9a3477d78@redhat.com>
 <CAN=P9phn2xLw-saXVL2Y30KAMV3kgE-Sn0ASxpeZJfQLVZOZRg@mail.gmail.com>
 <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
From: Joe Lawrence <joe.lawrence@redhat.com>
Subject: Re: kpatch and kasan
In-Reply-To: <CACT4Y+acK9nPmCFU7kPL2M0EeXzAL6rCQ5LhScGbzvFAFwHAQg@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: joe.lawrence@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ckMPGY1p;
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

On 1/18/23 02:21, Dmitry Vyukov wrote:
> On Tue, 17 Jan 2023 at 17:50, Kostya Serebryany <kcc@google.com> wrote:
>>
>> +kernel-dynamic-tools
>>
>> On Tue, Jan 17, 2023 at 6:32 AM Joe Lawrence <joe.lawrence@redhat.com> wrote:
>>>
>>> Hi Kostya,
>>>
>>> I work on the kernel livepatching Kpatch project [1] and was hoping to
>>> learn some info about compiler-generated (k)asan ELF sections.  If you
>>> can point me to any references or folks who might entertain questions,
>>> we would be much appreciated.
>>>
>>> The tl/dr; is that we would like to build kasan-enabled debug kernels
>>> and then kpatches for them to help verify CVE mitigations.
>>>
>>> If you are unfamiliar with kpatch, it accepts an input .patch file,
>>> builds a reference and patched kernel (with -ffunction-sections and
>>> -fdata-sections) ... then performs a binary comparison between
>>> reference/patched ELF sections.  New or changed ELF sections are
>>> extracted into a new object file.  Boilerplate code is then added to
>>> create a livepatch kernel module from that.
>>>
>>> The devil is in details, of course, so our kpatch-build tool needs to
>>> know whether it should omit, copy, or re-generate an ELF section
>>> depending on its purpose.  The kernel is rife with interesting sections
>>> like para-virt instructions, jump labels, static call sites, etc.
>>>
>>> So, before trying to reverse engineer sections like .data..LASANLOC1 and
>>> data..LASAN0 from the gcc source code, I was wondering if these were
>>> documented somewhere?
>>>
>>>
>>> Regards,
>>>
>>> [1] https://github.com/dynup/kpatch
>>> --
>>> Joe
> 
> +kasan-dev
> 
> Hi Joe,
> 
> But why not just build a new KASAN kernel and re-test? This looks so
> much simpler.
> 

Hi Dmitry,

Well yes, testing an ordinary (fixed) kernel build is much easier, however:

1 - Sometimes kpatches deviate from their kernel counterparts.  Examples
include ABI changes, fixups in initialization code, etc.

2 - AFAICT, Kasan is the only part of our distro -debug kernel config
that kpatch doesn't currently support.

We could certainly live w/o it, but investigating how it works is the
first step in scoping the effort.

-- 
Joe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4986b01-2386-b75b-ef4d-9b4a58fceeef%40redhat.com.
