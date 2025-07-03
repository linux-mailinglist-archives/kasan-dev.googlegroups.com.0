Return-Path: <kasan-dev+bncBCSL7B6LWYHBB3HTTLBQMGQEQJLUN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65677AF7E6A
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 19:12:14 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b4a06b775sf752191fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 10:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751562733; cv=pass;
        d=google.com; s=arc-20240605;
        b=WCs+kh36IliUYmwtMChOX9zvsGjREkwID6E7qvZVw5zxMEpeTgNcFJZFe3oSJxt7EU
         QlGyvg7OOUGhKvWAqtBO38hAUEUX5W5mrjD5GDhPuHyU0zLkOJGkubhR3UCSIjjtP03C
         DIj77k2H5kugJd9udCjFMGBfGtng5jFMPMPuRdiOJB08g64XeT1So+kSOCChZRH/viGe
         cSJwi00godqSOWF242/cxJJ6++u+iGUWR3WR326SRTtpKmsIqDQfsW5Q2atEKkaZgBUN
         12LZIVksSq+7aAkHItrrKuIzZARmpMWPH1U5ZqHqjhshMt5N7HfdsNdW4eSaO7PVBDof
         D28Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=f4cFeRgxDmM8wwju8nLLss+pT4MPCTK3jHk0vSbN710=;
        fh=fC2A6ZUnE4UN16lLdc8BDpvTEeknVUp5fFATYSbWHNQ=;
        b=Xl0a3aKo3N7VtEFI65dmKLo7HGL1cKO+vllzXPWXvjoo0vaDVC5kMBJ0fAr7dIyf47
         N+46Y4BJZmYYCJnlft6Ns85WgcH+EZXLH5/44ki0bK09Qv179e9M81TOjrJMsspLLeeL
         aVHtHeKtHVxKqCfzd5RB5qz6TWK45HJXiF8MOquKTGhtGSlh9btHAWtjBU1u1rq/D+T0
         ffgUUyu01GX8W1jo+0ycI9U3RPkGgQAWA7e9qNyQcJU3tnSeyGEfCLsVbWn8g5Uf7vsK
         d4kN+S19LIszm8Y7UEBaW0JtVgxoawQsyzs7ubPkFV3HvNkfZbYSjaCb7KtRXwA3A+QR
         W1KQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PPwJ93NH;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751562733; x=1752167533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=f4cFeRgxDmM8wwju8nLLss+pT4MPCTK3jHk0vSbN710=;
        b=i0RKffsMThaCCz3foAEAqARdRdRmpB2LkBtYKgld0kE//rl5tuLlPykhnYm5k+D4gw
         NZMIYvif40Exss0xyJpQDw2dk12WjXt+pUrU7ZLXFD4DLXs6+uADXs/fxPj2kkEq/HtL
         osSbAX1abooHvgcRKCGwuzz49cMaxgtVEuuF460OFsFXBSa0D3cHPhh3//b9JzxqI3K1
         LRr7rRf0d95ZON2MKZieAEUfdB8RJgK6/uMN3UN5zPXB9JcF7UxXrCS4cDACY4qXY/R3
         KdNFRGqs0JsLROa+sxdClHmJUylCptFqnl9qSLWS1KpjPwhhaIXmEmWsdqVH31z1n/G8
         2oTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751562733; x=1752167533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=f4cFeRgxDmM8wwju8nLLss+pT4MPCTK3jHk0vSbN710=;
        b=YaoS6E3NV8Ey9hF03iDe8w8O+21XFrzP2WjqlEQnUngl/qnJlkzKpmLrPH5rnZApSj
         pW2rK0Cwqg2gIZRNhnL/w+RlkLk2ImdFwCp4K7x2z54kVKLHl9s4fwGXoXGyMZWduja2
         Tu84FXZv88lu8qy+MNwzt8ySSR086+BY6RXCmCMFUL+Fma8gJr42wQ1R+Bzoa/w9wpk5
         +rKc5sic+YdpmPFAmiE56zNV7DdhMYJVW14SE7RKyTTk/q1suxRDWnWApG6uTgyBxG05
         /tdOdwkHcwD2bbxDZ7Voak1pFbsJbXyNxnfRavls6NcrUTpjfYC2SmxFsmuDB58mmlcT
         FWXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751562733; x=1752167533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f4cFeRgxDmM8wwju8nLLss+pT4MPCTK3jHk0vSbN710=;
        b=ZoqgwkcqINXgOkf3oMirZO7/+ni+6fVjmpQa+7iKyHE574KDI1TJObc8IZnAEapnYL
         2pbVq2LC5R826Pqqdhd5Y+jk/JjR8oOTlWK3kjy3YYAoYrxA2uKMoZG5NJl8/uozJxb0
         6/6nzRW06aAF9VqlZfZBkSr4ah3vi6ThxWVaRoczT53y+/2Ez1+BkNIjdLRS+RxfwY6s
         ktV2iUv0fN3IbclFARrqBpU7nRaKORpkCr03BATCIy+9te/e2t/AywbvvPKq7mn/Rhta
         dPQXASre/6VvqCzJDGeVlH2I50iO4gaWw/tyU6cnhMNKaImTY/EMAdghr8EIeiWCefhM
         FTBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoGCMALtreHMRhOEyOFf9kFftnWkxzlTMBfW32+nuMQuqtgRK+T+cTYPsK+wR8t7l2t7vczw==@lfdr.de
X-Gm-Message-State: AOJu0YzX3hSBs5ouw0znvmBkl24aHLrvOmtlI/TmVk6mZjyEP+NxLRMz
	q5E2YE/PyqbL4sugUPcCKXe9CLZxt3VK+iGDlRcN2tdC64G7f9zoDbhp
X-Google-Smtp-Source: AGHT+IENl+op/l9aXBr2txUoRGevLXsY76gWTXRoroeYsZrRH1T5cT0BdXWzqEcAw0vMtrA3+YPjhQ==
X-Received: by 2002:a05:6512:158f:b0:553:2869:3a5 with SMTP id 2adb3069b0e04-5562834ee60mr2908321e87.48.1751562732973;
        Thu, 03 Jul 2025 10:12:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZee/tpoM8lssmdDmzzJtPZjc4rrmwOip0UiHn+uBIP4Ig==
Received: by 2002:a05:6512:608e:b0:553:d125:e081 with SMTP id
 2adb3069b0e04-55638493872ls35515e87.2.-pod-prod-03-eu; Thu, 03 Jul 2025
 10:12:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVC8YdcoWD790w+EhidyfUxt7C+jPKlmml6qxrxS1yooUfDLqcj5gF2AeBDdDx59dD8zRZ0SkGDqa4=@googlegroups.com
X-Received: by 2002:a05:6512:1149:b0:553:2a16:2513 with SMTP id 2adb3069b0e04-5562834d984mr3219808e87.47.1751562729421;
        Thu, 03 Jul 2025 10:12:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751562729; cv=none;
        d=google.com; s=arc-20240605;
        b=i4e8uKk/cqnIMG8gGC4Ifovg8Sk9kaMwxzYn7v/Y5k7S3LL2TVbjPAA4CsY/H5oKcI
         txx4Q3OV0mrqsR8wb9bJT8FsnSuFhg5ZtimFiafzSn/Bo7VXtsDNS2BwB4fVHBkdVNgH
         DAjjGoz5qkMbL0+ThslkDv8DimbsIrpf9e14SECNeVC9tqZZF0Rsk/9X9dY4VMoLRpnj
         mfO7U9NtGdWGXwZdatEB3Wa+wD2veECDOJakjnHyE10C2A0gb12bQfs3QMvXU6iqusSS
         KBKOHqjVMWHnNGJRiZTmOdiXVZMZcpxbXi9jRxBwB07duG46iUcldqTWvAdCbzf8DQQV
         eBPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=8JHsACmNVQDqMzth3zHYUx+TIWM589NbxHC9P7ivfVY=;
        fh=E9/+1Erx0RgV6n5uzYwTD2Vm0OjarSQG5qtT6g9a2l4=;
        b=NczQo911ToFpQz8V9ZeQsHZYu878kg27I8+F1zgsl8qjK5Tsjo0kJMnJLCF75gMkVA
         wCtDWL8nHdjUzD6jwxGbAddYmwDmkg0uBzHRaAENSfvpovWvRAuxBmY2rQq+kfz/m9zJ
         5PbuOsZo5vvzCpvogA7YSDZFvSFREz1vRdhwmsg2ILNgebGX7EMXYJvjQp2JdFrNov4t
         lwNevk/S8Z264OOKVR/FQ+Lt7cvN5HNQLFbkNtPxaw6FyvwJeuYC6AGddR25U43Z82Ua
         uQgUopUb+sQvAwkYU2VuVTcCNw+FoNTS0tp/rWqBzwQg4SQQxi342pBspfoRUELGojQH
         whPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PPwJ93NH;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5563844fff3si9320e87.8.2025.07.03.10.12.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jul 2025 10:12:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-5562a92734dso14353e87.0
        for <kasan-dev@googlegroups.com>; Thu, 03 Jul 2025 10:12:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZJcljvpSVHMuI71XPajMpKmMsOHcp9Uh86xb1Bh8JWStGKTlox39MtbRUPUfm7itu0HKoH9G0A9Q=@googlegroups.com
X-Gm-Gg: ASbGncuo4NrjlzlZ9VVuX88EKmmUub4hcxw5SSGGyNbOt5Mu9PtODCpSWjkizIIPU+O
	heb+85WISVrGsXMok+1BhICXJQjt+f902mDZ2VyogNW6Rus7g6pkmohPD2aS8O4XvhRCijojEQc
	sIcALUkCbHLLmpa5M5wXI83iUPTib24JBXbNc0PBPWlqbN6rDHflbWCJk5xwIis0SVUqgs01k9a
	uNubzyNRFi918jkrGtRUlCX3Ap28BVYU3vmIbxseK6t/9stLWvOKj4MpDsA/yDJEsNw7KP7anBh
	PGS8V/5NURwnh9tSDFld1o2fuYP3BMbEg/M/nfJVGD+81uG6/PNFrOJrlH2+CTh2ehXw
X-Received: by 2002:a05:6512:3ba6:b0:553:a2a2:21b6 with SMTP id 2adb3069b0e04-55632c86b8bmr327098e87.4.1751562728608;
        Thu, 03 Jul 2025 10:12:08 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-556384a9e43sm24902e87.173.2025.07.03.10.12.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jul 2025 10:12:07 -0700 (PDT)
Message-ID: <1a7f32a8-16ff-406c-9542-8d2ad628d7f4@gmail.com>
Date: Thu, 3 Jul 2025 19:10:50 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for
 possible deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org, bigeasy@linutronix.de,
 clrkwllms@kernel.org, rostedt@goodmis.org, byungchul@sk.com,
 max.byungchul.park@gmail.com, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-rt-devel@lists.linux.dev, Yunseong Kim <ysk@kzalloc.com>
References: <20250701203545.216719-1-yeoreum.yun@arm.com>
 <4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com>
 <aGVYoEueYjoC1hQh@e129823.arm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <aGVYoEueYjoC1hQh@e129823.arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PPwJ93NH;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/2/25 6:04 PM, Yeoreum Yun wrote:
> Hi Andrey,
> 
>>
>> FYI some of email addresses in CC look corrupted, e.g. "kpm@linux-foundation.org", "nd@arm.com"
> 
> Sorry and Thanks to let me know :)
> 
>>
>>> In below senario, kasan causes deadlock while reporting vm area informaion:
>>>
>>> CPU0                                CPU1
>>> vmalloc();
>>>  alloc_vmap_area();
>>>   spin_lock(&vn->busy.lock)
>>>                                     spin_lock_bh(&some_lock);
>>>    <interrupt occurs>
>>>    <in softirq>
>>>    spin_lock(&some_lock);
>>>                                     <access invalid address>
>>>                                     kasan_report();
>>>                                      print_report();
>>>                                       print_address_description();
>>>                                        kasan_find_vm_area();
>>>                                         find_vm_area();
>>>                                          spin_lock(&vn->busy.lock) // deadlock!
>>>
>> ...
>>
>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>> index 8357e1a33699..61c590e8005e 100644
>>> --- a/mm/kasan/report.c
>>> +++ b/mm/kasan/report.c
>>> @@ -387,7 +387,7 @@ static inline struct vm_struct *kasan_find_vm_area(void *addr)
>>>  	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
>>>  	struct vm_struct *va;
>>>
>>> -	if (IS_ENABLED(CONFIG_PREEMPT_RT))
>>> +	if (IS_ENABLED(CONFIG_PREEMPT_RT) || in_interrupt())
>>
>> in_interrupt() returns true if BH disabled, so this indeed should avoid the deadlock.
>> However, it seems we have similar problem with 'spin_lock_irq[save](&some_lock)' case and
>> in_interrupt() check doesn't fix it.
>> And adding irqs_disabled() check wouldn't make sense because print_report() always
>>  runs with irqs disabled.
>> I see no obvious way to fix this rather than remove find_vm_area() call completely and just
>> print less info.
> 
> Right. unless there is API -- find_vm_area() with spin_trylock(),
> kasan_find_vm_area() should be removed.
> 
> But, I'm not sure adding the new API used only bv kasan is better then
> just remove kasan_find_vm_area().
> 
> Do you have any idea for this?
> 

I'd say the info from vm_struct is nice to have, but it's not essential for debugging.
It's probably not worth trying to keep it, so I'd vote for for removing kasan_find_vm_area().


> Thanks.
> 
> --
> Sincerely,
> Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1a7f32a8-16ff-406c-9542-8d2ad628d7f4%40gmail.com.
