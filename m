Return-Path: <kasan-dev+bncBCPILY4NUAFBB75FWO6QMGQEVWDPX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A020A32C9B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 17:57:37 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-6f9ab3a1392sf92779887b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 08:57:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739379456; cv=pass;
        d=google.com; s=arc-20240605;
        b=C8EOvj721yfclOaIrLYNXRiVjC65ICap+RcJlMTW/tEXeYep7ki03CuG12cZmDLtiq
         G7lP4nj6ltEsNhIJQvAHCby2Z6YNFW8PN6qWHXeRdXqumzN/xBorHY+i43R10kGuXFcZ
         SKlF0yeAiYQQ6CI7DrJt2+Eu7B9Yd4s01awjVMlP0LXA5F9rvCI7i3oc5NB/iEBo6ksb
         gpD6rJG0i81ejxpbj0noLLnZ62zuPPZUtSnTcnauUd7WBIseOjpJnxlFC4JmnYBaqNzV
         UPdhN8Ih0ia9BPLo8xzssnaCkPkGqTWPtmPhLzZ8cqz0BjTqCpr+Zg+HYX2CvPig6Yi2
         ezHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=NlKxM87aGx6jwPy6qUWr4xj9MSFZH2mmnJFmM2ZLGA0=;
        fh=ruwQ1oQpyWeMlOTmFARFxhQjGogdmZn0WZGSRghYmEw=;
        b=LBM6FPg9WY/unorwv3vWEfcezQ59cV262FTMr7glHl1B8vvyNEijSKhDw9jr4wlPSD
         GtN9tQDhVCvDwFG3g1dcSQFPkx9+D6EdSwSC8JkaY2KXaXUyKJwpWbFHRMj3dFJXZrkP
         rJiumGTyHFI653kSxjsldeXTtPpk6wdRKBL6UOZ5GudP61IyBNbUbAqzO59cjniQI/ce
         wXXkKgDb14j9ow/TS8x0JhLh9mcKmBMCo8GWU765RcfzmtyVvRuG3cF9tYT9EZ1TmDZ0
         KbgZNep75xiduNJtScVnxJz+YhaSppSpONyJTJIjjJPRZ7ppgw0b3nAubZ+5ywrZHYMl
         lLgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MPTRQjLT;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739379456; x=1739984256; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NlKxM87aGx6jwPy6qUWr4xj9MSFZH2mmnJFmM2ZLGA0=;
        b=kvJSa6tmbqsr/TyzUqOdTetAJJnb05TSEo/WUXWpuECz77huod76hNbaP6DXfpJJs2
         si8AYMkOWK0gqKvhCG7ddlNDZGtzOeJ9+PQsb8oB4P2vKUWMuOwTl8Ua/2cduFTX92Tu
         b7xBIXsmg3PZg6BRm8WrMhpAv317h8O5XMcdyZM3LQaxrdSUEFQhRS1igsN44VLObn+x
         +Mbj1mqOfW4+qBDOdKnwEzNyOsYNsczqRefmJLWDRlE1d76CxdrAaald1SdvgZSpn8xg
         zWxQEG2wRZVTsgH372/HQ2G8jlhR3ZIe/B//+GLxCSVyTtmMvTZof6UA7+caM7Gj/QUr
         4NHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739379456; x=1739984256;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NlKxM87aGx6jwPy6qUWr4xj9MSFZH2mmnJFmM2ZLGA0=;
        b=vfqdFVysaS/6IujNC+7q7mkHQQHOB4OwwEGojTaVyB0T/7saYtNNMcamD50JVn7ed+
         OsVPnw/PncFj1SRNoU5hzUbfWF2SBHsP2+CD/aPf6QzXlUxM7wjYEBmvbtHMPxxuWlSu
         A1TBaiW0IDTpju495GZ5YqqY30LmQyHt/JcpKSihqiLTra+Cgb5t1OWOqTb/YHfHL7N0
         8QniB72mFgI2OK3IFVJ4qT6avUjhh0TJ4DuJLDoCGF+HZhLAU/X6SDL9+AX4PHGpYa1F
         sn2zR2d7mQ2XSInwtsTbRi+Q981ZRsdkDIjzchUHobs63EtjvA+yghaGEmkiFJ3TAzCI
         Shaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5Obkcg9WtInSIpOV+YylznjEkiidC6bRO4o/rzyo7bPb7ggT4BNS18IgLobUJ0Y5rpxbYNQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYhHOwgY9ZMxn23BAFQinxLkKMWea/E1J0WRDnCgaubwvE/3vS
	NEzsK3NtKQ5Dz8uTWdew6MIleaRUq95m5EzPY6jRT4eqph/l7jnu
X-Google-Smtp-Source: AGHT+IGfy+NJcjR62VQOe5XmxaNLhEaziNIHEbRoe2emPRHuuW43x7xYWpcaOOk52EWyPrSqpo+ITw==
X-Received: by 2002:a05:6902:2b03:b0:e57:87b3:d2e0 with SMTP id 3f1490d57ef6-e5d9f0cfc61mr3327303276.3.1739379455876;
        Wed, 12 Feb 2025 08:57:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6083:0:b0:e3a:b6b:4ac5 with SMTP id 3f1490d57ef6-e5da79edc08ls39755276.1.-pod-prod-06-us;
 Wed, 12 Feb 2025 08:57:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCViKibVFyXiCVVMgjqgXz29rwmy8kLSV5Z8ss+9PNhh3yEZF61lSmrn+VBjCzKqiPSao0zLP4l5JBc=@googlegroups.com
X-Received: by 2002:a05:690c:7004:b0:6f9:af1f:fdcd with SMTP id 00721157ae682-6fb32c991bbmr324317b3.11.1739379454914;
        Wed, 12 Feb 2025 08:57:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739379454; cv=none;
        d=google.com; s=arc-20240605;
        b=hSIBID2n+drSly13lEJnUSglCk1xwJaFoYVcJkvyX+z3Mzu4NAKxq5EtTgVXdZcw0V
         sPVbSTBXTrKOSp01Xp96l6QnREIUT9wZqeMSIn0BVSxSY+VHFhbOAdHuFe9eIFT/lLEN
         kCTHCh1aBxJ40puQp8DssGmbFzW7SFTpkfqCrtaNuhhtm8BRO0FGn6BY4K/MfKcw74og
         cVyJk/BGUh4WuhxZRUBf0g/ZyxRc52v64gK+YVqBL4NCvK1EfXuY4nInNgcAlMShV2IQ
         lbcdUiw4U7bmMwlGpz2iB4AO2omoV836Adx6rAVaC4jr+s5NqlRrqGKbrSH1pJV5J3+s
         CYAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=uFYuB4nYKmjSwIRVjNdGoef98U/NaR6F7yyw8uBNWDE=;
        fh=IYhbi8eI93rcYIkym6EiEED7L0R1p1O6rzLrPGA4sIg=;
        b=G72pX71vngmxJ58uKLYaiZeHbNme2KXLP6osdHPmKizjpsOIAJvIEmGSWWwtc0jWg7
         sJjFYp/Mt3VYxfKy5fdf7mWJpaxv5XgBPvs9uyx4ny3048DumTZdMz42oJxGYMS5U6tj
         GLmvQILLCEvNDTDrmvhF4DRHEWqVPPOGW+pYWhBhMgy0xpRGpfrkTIZXbJHjqle+zEJO
         VfalVF4GtnlhQl7ALHWDT84r5x/+TGeYb7E/sNVElAl0y4LTxXRV+86GVIBYSK9yZ6K0
         F7+xokzWfS+MR5VhncOX315YgytCDM0yLF6RI9FwXKx5zwdt4S6LKkB+HFYmbBx1VcrC
         mhyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MPTRQjLT;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f99fb8bd63si4684067b3.1.2025.02.12.08.57.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 08:57:34 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qv1-f72.google.com (mail-qv1-f72.google.com
 [209.85.219.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-629-oOt75LyiNLS1xzpYW4Fpcg-1; Wed, 12 Feb 2025 11:57:31 -0500
X-MC-Unique: oOt75LyiNLS1xzpYW4Fpcg-1
X-Mimecast-MFC-AGG-ID: oOt75LyiNLS1xzpYW4Fpcg
Received: by mail-qv1-f72.google.com with SMTP id 6a1803df08f44-6e4434d78e5so144966d6.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 08:57:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXfL36m6DzaUCNSFZryqc86jYM9pdp3eS5ZGg1oVtSdY63UYlJ8Cndt+BuVcZeegFpkzSN4Ry2eFMg=@googlegroups.com
X-Gm-Gg: ASbGncv3q8SLJPYRwuO7yiWJg5MKp8QvtPEAtH22h/uegSEAB2FHDKTeo2yav9AR0e8
	ldVMabVLoY7E4XncJ3IgpxlOKqs2C2tyMizSSIuyFb/RZ4QbDI0xd/z2S14bFK1TWdqZy1ogNwA
	RpRNWek3Iljib7oj8zPnJQtG7Wa45+MofC9gCvocYJVIIorNizLnVQ/q9f0wQhjRcz2Euijlhj/
	wNbb3S2lJC2e4S1bZpJXNbBum583EKknfii/eqQMEnkFxSVqyVBnYDEwtBUzpCuEiLHrcOwa6PU
	525+5gFyiITdrl4E08r+DWPkb3oF/xc9i7VWBm3kL4Gm5RNr
X-Received: by 2002:ad4:5c4d:0:b0:6d8:e5f4:b969 with SMTP id 6a1803df08f44-6e65bf45437mr4032236d6.10.1739379450708;
        Wed, 12 Feb 2025 08:57:30 -0800 (PST)
X-Received: by 2002:ad4:5c4d:0:b0:6d8:e5f4:b969 with SMTP id 6a1803df08f44-6e65bf45437mr4031716d6.10.1739379450296;
        Wed, 12 Feb 2025 08:57:30 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e44da75f46sm66264716d6.58.2025.02.12.08.57.29
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 08:57:29 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <a6993bbd-ec8a-40e1-9ef2-74f920642188@redhat.com>
Date: Wed, 12 Feb 2025 11:57:28 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 3/3] locking/lockdep: Disable KASAN instrumentation of
 lockdep.c
To: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will.deacon@arm.com>, linux-kernel@vger.kernel.org,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
References: <20250210042612.978247-1-longman@redhat.com>
 <20250210042612.978247-4-longman@redhat.com> <Z6w4UlCQa_g1OHlN@Mac.home>
 <CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.com>
In-Reply-To: <CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: _153Vw3hUFT2pQBTgakZC6z4JgCAKpDRZuJ78haPYyk_1739379451
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MPTRQjLT;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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

On 2/12/25 6:30 AM, Marco Elver wrote:
> On Wed, 12 Feb 2025 at 06:57, Boqun Feng <boqun.feng@gmail.com> wrote:
>> [Cc KASAN]
>>
>> A Reviewed-by or Acked-by from KASAN would be nice, thanks!
>>
>> Regards,
>> Boqun
>>
>> On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
>>> Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
>>> Each of them can significantly slow down the speed of a debug kernel.
>>> Enabling KASAN instrumentation of the LOCKDEP code will further slow
>>> thing down.
>>>
>>> Since LOCKDEP is a high overhead debugging tool, it will never get
>>> enabled in a production kernel. The LOCKDEP code is also pretty mature
>>> and is unlikely to get major changes. There is also a possibility of
>>> recursion similar to KCSAN.
>>>
>>> To evaluate the performance impact of disabling KASAN instrumentation
>>> of lockdep.c, the time to do a parallel build of the Linux defconfig
>>> kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
>>> and an arm64 system were used as test beds. Two sets of non-RT and RT
>>> kernels with similar configurations except mainly CONFIG_PREEMPT_RT
>>> were used for evaulation.
>>>
>>> For the Skylake system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 0m47.642s             4m19.811s
>>>    Debug kernel                        2m11.108s (x2.8)     38m20.467s (x8.9)
>>>    Debug kernel (patched)      1m49.602s (x2.3)     31m28.501s (x7.3)
>>>    Debug kernel
>>>    (patched + mitigations=off)         1m30.988s (x1.9)     26m41.993s (x6.2)
>>>
>>>    RT kernel (baseline)                0m54.871s             7m15.340s
>>>    RT debug kernel             6m07.151s (x6.7)    135m47.428s (x18.7)
>>>    RT debug kernel (patched)   3m42.434s (x4.1)     74m51.636s (x10.3)
>>>    RT debug kernel
>>>    (patched + mitigations=off)         2m40.383s (x2.9)     57m54.369s (x8.0)
>>>
>>> For the Zen 2 system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 1m42.806s            39m48.714s
>>>    Debug kernel                        4m04.524s (x2.4)    125m35.904s (x3.2)
>>>    Debug kernel (patched)      3m56.241s (x2.3)    127m22.378s (x3.2)
>>>    Debug kernel
>>>    (patched + mitigations=off)         2m38.157s (x1.5)     92m35.680s (x2.3)
>>>
>>>    RT kernel (baseline)                 1m51.500s           14m56.322s
>>>    RT debug kernel             16m04.962s (x8.7)   244m36.463s (x16.4)
>>>    RT debug kernel (patched)    9m09.073s (x4.9)   129m28.439s (x8.7)
>>>    RT debug kernel
>>>    (patched + mitigations=off)          3m31.662s (x1.9)    51m01.391s (x3.4)
>>>
>>> For the arm64 system:
>>>
>>>    Kernel                      Run time            Sys time
>>>    ------                      --------            --------
>>>    Non-debug kernel (baseline) 1m56.844s             8m47.150s
>>>    Debug kernel                        3m54.774s (x2.0)     92m30.098s (x10.5)
>>>    Debug kernel (patched)      3m32.429s (x1.8)     77m40.779s (x8.8)
>>>
>>>    RT kernel (baseline)                 4m01.641s           18m16.777s
>>>    RT debug kernel             19m32.977s (x4.9)   304m23.965s (x16.7)
>>>    RT debug kernel (patched)   16m28.354s (x4.1)   234m18.149s (x12.8)
>>>
>>> Turning the mitigations off doesn't seems to have any noticeable impact
>>> on the performance of the arm64 system. So the mitigation=off entries
>>> aren't included.
>>>
>>> For the x86 CPUs, cpu mitigations has a much bigger impact on
>>> performance, especially the RT debug kernel. The SRSO mitigation in
>>> Zen 2 has an especially big impact on the debug kernel. It is also the
>>> majority of the slowdown with mitigations on. It is because the patched
>>> ret instruction slows down function returns. A lot of helper functions
>>> that are normally compiled out or inlined may become real function
>>> calls in the debug kernel. The KASAN instrumentation inserts a lot
>>> of __asan_loadX*() and __kasan_check_read() function calls to memory
>>> access portion of the code. The lockdep's __lock_acquire() function,
>>> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
>>> added with KASAN instrumentation. Of course, the actual numbers may vary
>>> depending on the compiler used and the exact version of the lockdep code.
> For completeness-sake, we'd also have to compare with
> CONFIG_KASAN_INLINE=y, which gets rid of the __asan_ calls (not the
> explicit __kasan_ checks). But I leave it up to you - I'm aware it
> results in slow-downs, too. ;-)
I just realize that my config file for non-RT debug kernel does have 
CONFIG_KASAN_INLINE=y set, though the RT debug kernel does not have 
this. For the non-RT debug kernel, the _asan_report_load* functions are 
still being called because lockdep.c is very big (> 6k lines of code). 
So "call_threshold := 10000" in scripts/Makefile.kasan is probably not 
enough for lockdep.c.
>
>>> With the newly added rtmutex and lockdep lock events, the relevant
>>> event counts for the test runs with the Skylake system were:
>>>
>>>    Event type          Debug kernel    RT debug kernel
>>>    ----------          ------------    ---------------
>>>    lockdep_acquire     1,968,663,277   5,425,313,953
>>>    rtlock_slowlock          -            401,701,156
>>>    rtmutex_slowlock         -                139,672
>>>
>>> The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
>>> non-RT debug kernel with the same workload. Since the __lock_acquire()
>>> function is a big hitter in term of performance slowdown, this makes
>>> the RT debug kernel much slower than the non-RT one. The average lock
>>> nesting depth is likely to be higher in the RT debug kernel too leading
>>> to longer execution time in the __lock_acquire() function.
>>>
>>> As the small advantage of enabling KASAN instrumentation to catch
>>> potential memory access error in the lockdep debugging tool is probably
>>> not worth the drawback of further slowing down a debug kernel, disable
>>> KASAN instrumentation in the lockdep code to allow the debug kernels
>>> to regain some performance back, especially for the RT debug kernels.
> It's not about catching a bug in the lockdep code, but rather guard
> against bugs in code that allocated the storage for some
> synchronization object. Since lockdep state is embedded in each
> synchronization object, lockdep checking code may be passed a
> reference to garbage data, e.g. on use-after-free (or even
> out-of-bounds if there's an array of sync objects). In that case, all
> bets are off and lockdep may produce random false reports. Sure the
> system is already in a bad state at that point, but it's going to make
> debugging much harder.
>
> Our approach has always been to ensure that as soon as there's an
> error state detected it's reported as soon as we can, before it
> results in random failure as execution continues (e.g. bad lock
> reports).
>
> To guard against that, I would propose adding carefully placed
> kasan_check_byte() in lockdep code.

Will take a look at that.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a6993bbd-ec8a-40e1-9ef2-74f920642188%40redhat.com.
