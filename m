Return-Path: <kasan-dev+bncBC5L5P75YUERB34X7PVAKGQEZPTWOYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F7AD999DA
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 19:07:59 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id q45sf3745733eda.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 10:07:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566493679; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kg7sXLvSikcsm+5Brj88HgDezckGDwENgsmmu+W5D+USwCeyhPM4WZ7D03RmvFtjwc
         eQT6VjzUuDXzp1284zvZaa4VIv73xYEXD0RpCswTNuiCdzlBdkVj8N0YRZQtQsdIKIkr
         iief1lVas/nGrdcZWB5OU3xWHekS/cdO+bIBws5JEUTdglHzgnbdnCZIcQ7J6QFPzTyw
         3C65muznCy7ewEcEmrooW3MtIsKTV4Q+dCCr/APPRFb4gj+cTGHskBcYwWq5+pe8Di8F
         WbTGqTCYzkvnBHF3GN7e8vOLcw3QCFyWP/TcY9WOs9W9/RTOAeX8zXFt04VM7yhs2Pfg
         tyDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=vNgZ360K8nT/MKkIJZ0sQ23YJ1d5C8DsKLhpOG6mnNQ=;
        b=TnXX4lCJSK/CvRVAJhfPPy8oIkSaJxbjTU46imPboPIyh4Fcggh9Pi9W11jhMijJo+
         8rOmGlAHp7fmry9VAB+1i5+7zvPZvuxYmyUy2ZiBMqyVQ8ql/+zIpSeUYlOwgKG2S+Wu
         eLtujfNfWn5B0Ras218pXiFS7Xo1ESotTVIDEnihD64FNUaQxIGA+LNUIk76rGbjFv9K
         BNGznQvc6UpJdOnxAK746ZjC/Bhp9SGcM+mALDseyEqzxIulcJC+2mjqbMRI/sV7boPM
         ra2U1suLq8thVVP3cPMzHBZSw0J9JKr5RPQAg/+x8Ug1E38miZIBclvKv2PlvfuKHocC
         PLyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vNgZ360K8nT/MKkIJZ0sQ23YJ1d5C8DsKLhpOG6mnNQ=;
        b=mL1E/FW2RmKSAkxcaCyZcVYQWx5R3nJvfqCXUtW9opbjD2bIyP0Sbv179Fol8TNeIJ
         UH/wRjqb56rkZW4q05OaH70AT++gO1ApelZA+fNGhhVjC9AWPoZj+pg6A2/KGpC1EEuQ
         kNQyZdyBtodyYVIDumLhx3EAbsIoYopsE4pI88tePTYRso+IVTXP5u686T285G7s9Q81
         xZ2MXFGbmUJ1vFiaPLAW8lx7bpM+YMGis1lXKHFe9pZvTIX9BuANNO+m+Z6rVTYoiRZA
         0SuCp9zefet1j/gtCqNqPrhKNYTjvR2tijRR10YgYTuYa0kmH7VmoaYK1ICnPH9iqFhO
         2PFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vNgZ360K8nT/MKkIJZ0sQ23YJ1d5C8DsKLhpOG6mnNQ=;
        b=EVY584yCb6tRqtSYpYrT1iGHcryAXMZgdgPn+EIFkNm3mqynBQW9ycCM1SI1jbxiEi
         HrezsWbmeqdYDhzHj69jYyn1O35Uxc2eU+haQysCYZuRU1H5+fG6DUGGCu2ROU24Tq3A
         HIQP+FMqUi86jOz/oXto/fOHyg0IyIp7a1TVHovxh7OOrbfw3gFnknr8tP7raEvQ4omu
         XYt7RVoIs7xZc5CijTj2T9hXdzAHhQ4QkxeuUlkQgegcNUEEgyHbRE673YFpvbv2Gk5r
         LIR4Oen3tlx3WWTOI1XrPIviG93y+7sr2xGmTZQSBKQuAXVwFwVxVEEUGWVJz7IvWhcN
         jbXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXJZlwBurPamWTfKSykRowoJ5rzFD2dIkAB+BFeErhBj+eBRjqL
	kirz39jTpeLAteC5vZ+5n+k=
X-Google-Smtp-Source: APXvYqxDBcjaJcGDlIU2oOlDhTinz+yZdYxVnr2j+kXxqQ64Xrmnw86svNro9m8e+s7ME3R9LsRlNw==
X-Received: by 2002:a17:906:3144:: with SMTP id e4mr285075eje.31.1566493679140;
        Thu, 22 Aug 2019 10:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:89f6:: with SMTP id h51ls2214025edh.15.gmail; Thu, 22
 Aug 2019 10:07:58 -0700 (PDT)
X-Received: by 2002:a50:90c4:: with SMTP id d4mr43960305eda.107.1566493678791;
        Thu, 22 Aug 2019 10:07:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566493678; cv=none;
        d=google.com; s=arc-20160816;
        b=ArTVR/VtCCHEmQuybODOrcZ1kIdmOSjPo/GDWwgMWXDG0XVsVRs0NPIqQNZY6Me2zB
         gKnaUZ5aBugXBTPs37QXUwQSudoBN2tCjL91+iOwjHxsJAYIXrl/LSuSPIzxwl/IyY6p
         2So/UnjJn400n+PivggE75xIZqBI3a4ek+ckFI0pKVwOq1a8QvK2c9549TP2tN9nFvQX
         VAp56glXXfxXW66DBem85ZTbvPzc1MMi35lTd7J5WlEgqyg/T4dMactNFVc9U7AwvFFn
         /TOLkBXh7/bYawnWDqLxbaIhEQXYUBdIUMHYntcKxWVLG8abQKG++ar7pg2s7ZawfTXN
         ewEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=D8xKfN1FTLZi6OOKi6UQk9VeFbtaJRLMVagWkD74TzQ=;
        b=VvjbA/O0z4UZXHabBLJruYuabjU9FT8fs2YDk5aEHZ4/YfFL9QbIuB8JvUbXMZ+nWy
         mfbhSPdfO3v6hI6UYz3t7CHXwDsntT4CgVvQ66I9Fvx6JRO9WrmIsI2dEnGsWDIOlq9o
         jFl91yfx8C/p89EaTRpfj4+syaXq+/bPOhZrpNQ9SvbzFFDa3Xaxh+ElE9E5mXs/0dXJ
         SfMHam4RwetQDHFnEuGfe2LM5QEvGY9bfkzh7JxYT5NFsm9dLnvrcjAz9TFqcTMGdC82
         Hll1zt/rDyPg3SxVVX0IAWtzcAgSV/BnyQEUkJPQ9aPoDrKbGiyNjqzh0vjDtUnxHpdl
         JK1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id l17si4087ejg.1.2019.08.22.10.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Aug 2019 10:07:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i0qYx-0000iY-OZ; Thu, 22 Aug 2019 20:07:51 +0300
Subject: Re: [PATCH 2/2] riscv: Add KASAN support
To: Nick Hu <nickhu@andestech.com>, Christoph Hellwig <hch@infradead.org>
Cc: =?UTF-8?B?QWxhbiBRdWV5LUxpYW5nIEthbyjpq5jprYHoia8p?=
 <alankao@andestech.com>, "paul.walmsley@sifive.com"
 <paul.walmsley@sifive.com>, "palmer@sifive.com" <palmer@sifive.com>,
 "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
 "green.hu@gmail.com" <green.hu@gmail.com>,
 "deanbo422@gmail.com" <deanbo422@gmail.com>,
 "tglx@linutronix.de" <tglx@linutronix.de>,
 "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "glider@google.com" <glider@google.com>,
 "dvyukov@google.com" <dvyukov@google.com>,
 "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 "alexios.zavras@intel.com" <alexios.zavras@intel.com>,
 "atish.patra@wdc.com" <atish.patra@wdc.com>,
 =?UTF-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
 <zong@andestech.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com>
 <20190812151050.GJ26897@infradead.org> <20190814074417.GA21929@andestech.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <cf7a4259-afa5-53e6-f8f2-c243339cc3e9@virtuozzo.com>
Date: Thu, 22 Aug 2019 20:08:00 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190814074417.GA21929@andestech.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 8/14/19 10:44 AM, Nick Hu wrote:

>>
>>> diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
>>> index 23cd1a9..9700980 100644
>>> --- a/arch/riscv/kernel/vmlinux.lds.S
>>> +++ b/arch/riscv/kernel/vmlinux.lds.S
>>> @@ -46,6 +46,7 @@ SECTIONS
>>>  		KPROBES_TEXT
>>>  		ENTRY_TEXT
>>>  		IRQENTRY_TEXT
>>> +		SOFTIRQENTRY_TEXT
>>
>> Hmm.  What is the relation to kasan here?  Maybe we should add this
>> separately with a good changelog?
>>
> There is a commit for it:
> 
> Author: Alexander Potapenko <glider@google.com>
> Date:   Fri Mar 25 14:22:05 2016 -0700
> 
>     arch, ftrace: for KASAN put hard/soft IRQ entries into separate sections
> 
>     KASAN needs to know whether the allocation happens in an IRQ handler.
>     This lets us strip everything below the IRQ entry point to reduce the
>     number of unique stack traces needed to be stored.
> 
>     Move the definition of __irq_entry to <linux/interrupt.h> so that the
>     users don't need to pull in <linux/ftrace.h>.  Also introduce the
>     __softirq_entry macro which is similar to __irq_entry, but puts the
>     corresponding functions to the .softirqentry.text section.
> 
> After reading the patch I understand that soft/hard IRQ entries should be
> separated for KASAN to work, but why?
> 

KASAN doesn't need soft/hard IRQ entries separated. KASAN wants to know the entry
point of IRQ (hard or soft) to filter out random non-irq part of the stacktrace before feeding it to
stack_depot_save. See filter_irq_stacks().


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cf7a4259-afa5-53e6-f8f2-c243339cc3e9%40virtuozzo.com.
