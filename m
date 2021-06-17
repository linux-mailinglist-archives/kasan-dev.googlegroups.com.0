Return-Path: <kasan-dev+bncBCRKNY4WZECBBYXUVKDAMGQEBOIBPGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 31D253AA943
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 04:58:44 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id e23-20020a6bf1170000b02904d7ff72e203sf905285iog.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 19:58:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623898723; cv=pass;
        d=google.com; s=arc-20160816;
        b=TeoOH9rRsoPL3+W42VOQEv9E7ko8tZsCXCYwQtVVUs/qfxFFThfJAAYs1+fctFORvo
         1k7eZX2aiPC91Bx25TiTByIBWdizysYhQig31v+pUJJnbE1tv7+7L9zta7DjT03Dh8Og
         Lr6w8dL4SMMZkO31fFcJYsJb0787eh+LAl+LMbYdBABRhWZdh54AkOqMsyPZfw5g+Z5z
         viK8kceM1cJzY7S7rYYxGN3gYCZBZ5cLr8We48Ky29+AnAxb3CQRsnOH6LuRJYdRJxdQ
         H0ugfvbp1dwqycbiAEhPjzO7s4eCGTVFkeVEf9g5bSD7WEGQH8bMeomHJ1xP7GVfuxZN
         GN8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=cUrA5uaqBZjF1mVOUULDog43ET1xEDVV84ampZyDOFE=;
        b=LlFLPSnzSi2i/0V3NFwosHLVKoYryla2HVxrcTJOjcjT1wHnqTxQtwVMV9Xe73N62K
         v5A54+/tScMb9ttWvWZn0WdEf1d1X7GWJ1OqaA5M0/NQhT9J/8gitofQqK9zqED5yPcS
         ufQ1Mh/na+ZMIXb+wkSoI0TNLpV8CZq5MmRl0dpjh8YIL1eJ3cpAX3qQcvk7C1qd5P/E
         HLRk2AcghCtITCzOfteuWjUtrCxIaeAcJn184tl7ZeOOer/PnUKMsansCP196aapEPFp
         1vq8TSj/5EHjy/oI/AN3G41NIU4a9Fm4fYU9UB6S1BqKzINYzqooymFRFVPUKphpNPKG
         o/LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=ukzHIYxm;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUrA5uaqBZjF1mVOUULDog43ET1xEDVV84ampZyDOFE=;
        b=gZ4u+jL78aidvbg1ReHrtNDX1jRA3qmV+UzLRcOjEtsC5RAB231XX4LrPndOm9T7Kx
         rad7NQygGbcnymcItuyOcDATA7McfkfeJqqHd+O0EinN2vtE70A+cfsyVFydHI9GA3Yx
         TxSYMCugXfTppnvIgvBJzYtjroFz7gl7KAP4sRJFJBr0rEAn2YS1/yBp/2G7u0GnglsH
         MjaRLxr4JfkPnAeS+/ScYMqgUnz++YZWnFdKHXbAlUepPpIUe81sDfVeEC/HcHfTGkvd
         E8VaURo7nnLG37HhMaSndEJsxOGL3OY+yU725jaKfrJp038zI6MooHEwnviDTx5CRDKu
         /OdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUrA5uaqBZjF1mVOUULDog43ET1xEDVV84ampZyDOFE=;
        b=KpnL2sxVyJbCxbjK+Vqz/4YQmbeyXlQN9tqzfT+Uo5dh1Ma/FwPGxHOs5EZ2EaIeiU
         i7jrcMQS0eXzqEFieVu4j4xJdYwpSpL8f0+6LkIqhuRWeNTRKHDmgnd31qJHRVsUiH/T
         gwNrciknryI9GycH+B1mgw0cRUJg78q4zyHjVm/2iiR9ud6ukDTJ/DU/yGHRTBfG5j/m
         z63zsECGoSfMcTLy35lZfkxYK0NOVWifJk5eImXaY6J9LRahfTA+0vEHHzZ3dJOffhJE
         mOFl3BovqtF97eGyR+Xf7thzQg1F5PeCBUoDH1ZX/1N9+mGaAMd9bIluNHtatwh257QS
         mMQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lE+vyMWBB8gZQ7ths6jdhIo/F0G6+629ONAYf4XiDCYan43Gp
	nbKvmoGUK1j/KusoAPqcuq8=
X-Google-Smtp-Source: ABdhPJxkkHKqeC19t//6s8OYO9fjkC3hfC8BzEMsAsK3RSRCnc6YL/Ce2cZGSQU7pFAsDalb+mHepQ==
X-Received: by 2002:a02:4b44:: with SMTP id q65mr2346415jaa.28.1623898722955;
        Wed, 16 Jun 2021 19:58:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8d02:: with SMTP id p2ls694175ioj.6.gmail; Wed, 16 Jun
 2021 19:58:42 -0700 (PDT)
X-Received: by 2002:a05:6602:2c47:: with SMTP id x7mr1970099iov.26.1623898722523;
        Wed, 16 Jun 2021 19:58:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623898722; cv=none;
        d=google.com; s=arc-20160816;
        b=obhylrUOHfX0AQY5n8FPQB0pA/ELYaekAZ7RdpSe3C7BhAeF828LEcmzGJsFEVzwP9
         MRd05KXSynETga3Otuobd0/JHQ+6r9LKS06D9GdDmuqu9Q/0vAcU2qHPE8VBVzAu9YgS
         cNZbWHNRpGKUg45mH6s5gQ155txDt0j0uwpbHDwc4XqkZ3LOwsBWXi8pMTPf3xBc6YC9
         bDI8wa3MLGLwBiYyRjwasfSrlEfc0Hf0D+GOJyRX//ShZgpPJ7LOuHEpvQkm9CcsKjBW
         wj6LaKD/k7WdPztyglWSX1/gng9f8Buhy+iPdLryeIjQEhWVmWr+l5lGvS9VkCt/e+Lv
         /aYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=pAetusrXJOJzWSJzpj/wpmSbSm54E0/FhIpgunOB9fg=;
        b=omF0mT8kDi5pOKC8wIgBwzHxSI7B/18QcQg11yP8XAipRarTCkRJNfd0mOzxmcabjR
         4hKGr/PuNVnWMlqUKeIXIvc/6VbFkdXK/Fxua+Y7ul5Liwt/ZOFmcyOprEI6cX2PbZ0X
         tjCTrR+uBzjUQMcBmwz3YPRSndYIY4NEEGntbZ2jyZHFPNplHcFrX701f/0XrG4dAlDO
         3LoJhclgKAH6HXh2JV0acO5eFL58CIMVoWfokDjo/KOgoWfblS20/vQaxLWjROFrclLx
         YgsBlRlkn1OepaNrsGL/DpKYy/ATlvLS1Am3uBP47E9mERNh18p59t/wUCtMLlMLHWnB
         uLbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=ukzHIYxm;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id v7si361764ilu.1.2021.06.16.19.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 19:58:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id m2so3722797pgk.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 19:58:42 -0700 (PDT)
X-Received: by 2002:a05:6a00:c2:b029:2ee:9cfc:af85 with SMTP id e2-20020a056a0000c2b02902ee9cfcaf85mr3098604pfj.78.1623898721881;
        Wed, 16 Jun 2021 19:58:41 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id u9sm3633698pgp.90.2021.06.16.19.58.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 19:58:41 -0700 (PDT)
Date: Wed, 16 Jun 2021 19:58:41 -0700 (PDT)
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear mapping
In-Reply-To: <20210611110019.GA579376@roeck-us.net>
CC: schwab@linux-m68k.org, alex@ghiti.fr, corbet@lwn.net,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com,
  glider@google.com, dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: schwab@linux-m68k.org, linux@roeck-us.net
Message-ID: <mhng-569bbfda-00d0-4c1f-9a88-69021f258f7e@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=ukzHIYxm;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 11 Jun 2021 04:00:19 PDT (-0700), linux@roeck-us.net wrote:
> On Thu, Jun 10, 2021 at 07:29:15PM +0200, Andreas Schwab wrote:
>> On Jun 10 2021, Guenter Roeck wrote:
>>
>> > On Thu, Jun 10, 2021 at 07:11:38PM +0200, Andreas Schwab wrote:
>> >> On Jun 10 2021, Guenter Roeck wrote:
>> >>
>> >> > On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
>> >> >> On Apr 18 2021, Alex Ghiti wrote:
>> >> >>
>> >> >> > To sum up, there are 3 patches that fix this series:
>> >> >> >
>> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
>> >> >> >
>> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
>> >> >> >
>> >> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
>> >> >>
>> >> >> Has this been fixed yet?  Booting is still broken here.
>> >> >>
>> >> >
>> >> > In -next ?
>> >>
>> >> No, -rc5.
>> >>
>> > Booting v5.13-rc5 in qemu works for me for riscv32 and riscv64,
>> > but of course that doesn't mean much. Just wondering, not knowing
>> > the context - did you provide details ?
>>
>> Does that work for you:
>>
>> https://github.com/openSUSE/kernel-source/blob/master/config/riscv64/default
>>
>
> That isn't an upstream kernel configuration; it looks like includes suse
> patches. But, yes, it does crash almost immediately if I build an upstream
> kernel based on it and try to run that kernel in qemu. I did not try to
> track it down further; after all, it might just be that the configuration
> is inappropriate for use with qemu. But the configuration isn't really
> what I had asked.

This seems a long way off from defconfig.  It's entirly possible I'm 
missing something, but at least CONFIG_SOC_VIRT is jumping out as 
something that's disabled in the SUSE config but enabled upstream.  That 
alone shouldn't actually do anything, but it does ensure we have all the 
drivers necessary to boot on QEMU.

It's entierly possible there's a real bug here, though, as I don't 
really see what these relocatable patches would have to do with that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-569bbfda-00d0-4c1f-9a88-69021f258f7e%40palmerdabbelt-glaptop.
