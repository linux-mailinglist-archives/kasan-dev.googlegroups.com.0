Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIGOVOAAMGQESXTPCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AB1F4300618
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:54:25 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id u1sf4007901qvq.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:54:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611327264; cv=pass;
        d=google.com; s=arc-20160816;
        b=emuWXMJ9pU7GHPx6RVTaPqYRfo6lDhTJjt58nWzbAYlO9VUf5P0473/6c1qTiDdG4+
         4AT+SB8eYH5mv43v1OrdfCnnhn6GMBb8RLkcmnGTszOOTH4dCrBUiILv9iSBLsQZyKWG
         ftaCtHrR9mRx31LhKXTO5BYT2apykAH/qTM5CytHSi09GMzOjsornGRjEgRbKr9alM3t
         6WwfX/EmUHOYwu0SBB+iic/ofZAj7hJqc19Ndf59Ksfxi6uSwpaqlFBW6P3JOQphKEKq
         YZhSW4uPzMC+RXMk9OpaubA0TpTZ117WF8t0FAfAngFQ9mIpaDmbUwjaWF4H+efngboa
         QSIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=H7z8ucjxZA59+I7du51Qy5+sXlAr2iQOSlMN2HDHaS0=;
        b=IYzbyId23pabXyHmi2TGUWGc8Rmq3nCRTNitL9xMIK8kEPwHbB78H0qXfGH+iQ2qIG
         a+Q8jjFjwj46xVVg0LhxxUSuxqCxk3vrYUdbz9QZnayZgYuWFcGIC/hjbenJ8UOJDV3h
         rX8xiCp44LkoR9uHyfWu6WPMm5oFNIPiBKC43xvIkmq54HHOFSPl7CdOwo02IG+uRwmf
         dUtPef7j0nZr2Wh2YtUtyXZ9mduCdRD/cnyFD+iXcktPH7XqE7e1uU6jIY5VpwMbn3lJ
         1VbsmLYAIrItF8rfUb+HFpUpMgZBtwIuf9D6NBo+Kd6P2HSRHy+M+GZsoad+s4o4Awmp
         hwAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H7z8ucjxZA59+I7du51Qy5+sXlAr2iQOSlMN2HDHaS0=;
        b=bqwXLzqlywGlZ5HKW4vfS8SNQ8QLoL+MEhwCec1WCaQQMEo63iURfz7cdq/2IEDuGR
         EfPbjzhh9iHyn1lxyelr3dMFUKib1zm1gyhHMCFYqJY29scoI/s9awdi8eHd7jMi4fHT
         qj6bpuF6iaC4F88GZ6f7PTf2AvsOmsT9NA5imNd4/A2KJobXk0T/6hoNM7wGn1y+u91/
         hmkFsYyPxKXVoSCAj6STY4SCjSfdHZU5lWlvrFZZtezW4oA6GfigTm7qLVsW8ljUSrsP
         gOJSOOZhYxYEd6iJGPpeRhAqCduU3HOGJyjt51pY6LVOtWdETLfrY6Y4bH4jFfUuD1Vm
         Dh2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H7z8ucjxZA59+I7du51Qy5+sXlAr2iQOSlMN2HDHaS0=;
        b=qm0rIIvKvzSfIDlCE+VqJHmtQRuIVrBrv59xETMYTpfJf7i4uhivLKNWFiVQjBa8BL
         9WY8GpJETqdgsj0sGUz2wrQvQZ4WTQNeJj0ZYHSYZS3ghy8O+Q+e5f7iaZEyXPO8m8AO
         yC1Xfq7dkAiZAjb0FrlVdYLjtBTBX2eD7QyNf6m7Yio0RLw1/Nx5L71CwaqA5c9YJqWg
         FO1lD1tphUJj5teNgt2QYgy6m6QGwwW8fEs8TLwtwRgklVjYSNas0Pt89wEofjfwOG3a
         za6WeAnY98Iuy7YSiZMw97asfqDQWDRMHw+v4CiG6DjXv9jmWsAwJqeee8w2nDrB7FQ+
         Yb+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KMvyZ4OktFPBIZ9SKWlhsEenMZfAOP5KBGMTuMQkqF3g8bxbs
	GH6YeB9/2fwmgPe3L40TREI=
X-Google-Smtp-Source: ABdhPJxVyz5zxF3nHjIeakN7oBQUxVfh1BaX2qnaXqLngx0Ft3lImdVhTe2YzMNMPV9XM9BkDoFoMg==
X-Received: by 2002:ac8:5a82:: with SMTP id c2mr4766522qtc.90.1611327264738;
        Fri, 22 Jan 2021 06:54:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea19:: with SMTP id f25ls2928989qkg.7.gmail; Fri, 22 Jan
 2021 06:54:24 -0800 (PST)
X-Received: by 2002:a05:620a:24a:: with SMTP id q10mr5073406qkn.388.1611327264284;
        Fri, 22 Jan 2021 06:54:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611327264; cv=none;
        d=google.com; s=arc-20160816;
        b=iahQRLJfVj5NN50X+NlWIYB4Gt8QW9XAWqgYVkTSsY2DYc3I/Fhj/qkuIHAwSf1/PA
         MGjVUTWqNUTf7hUvFFRLJLF6vu7qd7scbjz6My1Lk/y83BXFxzrCbOMUQ9y37KjyXzGW
         oF6TyH/75/KAvGEWjQJJtHk6henUHWFmbjw+EoiSHNNs5tBI9G/9WQiQLPnXlcPscZrC
         Wi/24DgXaWrG1EMpiSflWiPqpcT2sUWJYrtcqHpCFkCZ8eYn2NVu2bba1VZFbhScZ6n6
         NRQRze+i6W5Jr5pT4NeV9Ba/K0eiabTycCjCc7uuS6KXIE6cIpTkD93smVBuUvAkWQpN
         bYBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=S+blNI+4HJhjuXhTLkzkkr/YFIIdkdksfJAFjEKIbU4=;
        b=rSII7Wnuw/uGZ34/jJ/A2OihPGg1VCupXvopZC/AvopNVBFInxUhbvlDSwvK0Sxr2h
         b9+gWR4/Lg9S1p6gebrcgcOXvSEC4X3yoDYQdfOnPyzYANZoydFf7GjDXVDT/7cJmn9i
         SBpB3LvOCazeE15qzY4KlD5lWznwmkK0a7Wrp+Moa6+jIYllPeKu6YMaul6dsHFoMG3o
         zNmK59VgwEvwG/t4D7812JHQ24OGG65z4/5R1/+NyGEcyJ0/zxstdo9bcFxcDa3QEXBv
         XxdLXIPwBS6KVE5DDwSMRERcqCFBTcI/7U+SIOiO+xJsVAmOulEZQBPLoS5fkBDjSLXP
         vxKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g51si745337qtc.4.2021.01.22.06.54.24
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:54:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CE3ED11D4;
	Fri, 22 Jan 2021 06:54:23 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AEEBA3F66E;
	Fri, 22 Jan 2021 06:54:21 -0800 (PST)
Subject: Re: [PATCH v3 2/2] kasan: Add explicit preconditions to
 kasan_report()
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Leon Romanovsky <leonro@mellanox.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, "Paul E . McKenney"
 <paulmck@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
References: <20210122143748.50089-1-vincenzo.frascino@arm.com>
 <20210122143748.50089-3-vincenzo.frascino@arm.com>
 <CAAeHK+yyJia6zOCMpy6ZJDX-Brvr_s88gZ6HwG2TxfLgtw=SSg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <be55dae5-e654-7673-fea6-7ee4055d2be2@arm.com>
Date: Fri, 22 Jan 2021 14:58:12 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+yyJia6zOCMpy6ZJDX-Brvr_s88gZ6HwG2TxfLgtw=SSg@mail.gmail.com>
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

On 1/22/21 2:46 PM, Andrey Konovalov wrote:
> On Fri, Jan 22, 2021 at 3:38 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
>> the address passed as a parameter.
> 
> It doesn't dereference the address, it accesses the metadata. And only
> when addr_has_metadata() succeeds.
>

Yes, this is correct. Seems I forgot again to unstash something. Will fix it in v4.

>>
>> Add a comment to make sure that the preconditions to the function are
>> explicitly clarified.
>>
>> Note: An invalid address (e.g. NULL) passed to the function when,
>> KASAN_HW_TAGS is enabled, leads to a kernel panic.
> 
> This is no longer true, right? Commit description needs to be updated.
> 
>>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Leon Romanovsky <leonro@mellanox.com>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  include/linux/kasan.h | 7 +++++++
>>  mm/kasan/kasan.h      | 2 +-
>>  2 files changed, 8 insertions(+), 1 deletion(-)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index fe1ae73ff8b5..0aea9e2a2a01 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
>>         return (void *)arch_kasan_reset_tag(addr);
>>  }
>>
>> +/**
>> + * kasan_report - print a report about a bad memory access detected by KASAN
>> + * @addr: address of the bad access
>> + * @size: size of the bad access
>> + * @is_write: whether the bad access is a write or a read
>> + * @ip: instruction pointer for the accessibility check or the bad access itself
>> + */
> 
> Looks good, thanks!
> 
>>  bool kasan_report(unsigned long addr, size_t size,
>>                 bool is_write, unsigned long ip);
>>
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index cc4d9e1d49b1..8c706e7652f2 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>>
>>  static inline bool addr_has_metadata(const void *addr)
>>  {
>> -       return true;
>> +       return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>>  }
> 
> Let's put this change into a separate patch.
>

Ok, it will be done in v4.

>>
>>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>> --
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be55dae5-e654-7673-fea6-7ee4055d2be2%40arm.com.
