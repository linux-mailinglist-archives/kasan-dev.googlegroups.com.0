Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWPKVKAAMGQEVSC6YIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id A178830015D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 12:22:02 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id 16sf3207352pfn.12
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 03:22:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611314521; cv=pass;
        d=google.com; s=arc-20160816;
        b=QTGTH/WTo/Dv7lNGKevXSZLolMc5EG1qT8IvwVvSjlnvCAvVRbS4tVtlqisv8LDKO0
         /6oywkx1qv6s4oQOEI2zffVCZUM+9+sobzYONoUrhFbMyARYD2yM6jQqBxj3pqZAzsvE
         hP4sS6bKy7Zcl6Lbiz8TZM/m3vcv362+1lhrtt4G14KI+asTilZBAmQxGgUMYTgsBsDi
         T69aU5XQo2H2wtYWT1CwsMiXZIl1UVZn6RvsYOqzAuV6OVv/DTG3lVb/6r62MdEkOuXZ
         41iCNRLQTGhUMySal6CQnV8ydTwhEBqSVCychfbuwRAJMHM8xvcfVdKBHUv+wT8uFFlY
         TDNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dCzvmcqJ0BxmbAX9btHeqZa7+E7jYlOTjJz94r0dLH0=;
        b=yrNT1f3ACw1wDIXVAWN47efxXo09uu1Dsskm9bU9bbSdnFBZZiRRS4p7DAoxxVUhjz
         mJK9Q/tlhbYxEnIopFb06I7UahcaOpCvd/LcE8LFoNaTCR73gtJ8j6rHZJsIE5BOi/9A
         IDkUQy6nRowocRaCrbD7DmdZFMkQzwmVQx2YUtQVYDu44HFCEUS3xTdiD0aEnx8CtkGr
         Gsb3iTHATGbCu+YU3Jo5abyxs9R/WF3CFKUOUX1sTNRgmf5H9YcBdivSrjw+S3nxwWQx
         sJM6erC6UwTEkp5Qk94iRApaUzYmOwKKsi8fPeue+B6gMIUU9SkQRwDfuGkLyGf2CLjo
         22MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dCzvmcqJ0BxmbAX9btHeqZa7+E7jYlOTjJz94r0dLH0=;
        b=HuKGN5wfUsUns4bs5d3dWKATyrIjlYPBbjBUr2bBIJj/HmEr0bqKrWID1GvpEkEPjN
         mfFa/USanNUre2WOMmEpaBjWLn7k7Yje7HEata9onGpjm4JoOKDbnRKX0bhB35uIFSvn
         FSBerumfgrfnjhTASe26lgZXr1E70/XyEgN0TkorFyz1GSjylxM1ffa7zn2pstNdx9Bp
         xCIxh+9ijC6WDBLMw7XnEVgNd1VM/tmGm/til6L4q6Tv+Q+/P2V2Ys0IcWAWwcpFreko
         MWu4MeTQfSLZAZWZcGqHZkxGVi7P8pK+thskXo0OGVgMHVAjty1f62iKU1EqFPyHmv6c
         0c4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dCzvmcqJ0BxmbAX9btHeqZa7+E7jYlOTjJz94r0dLH0=;
        b=aIL6y9FyK2vNX39toOQJxqMwpEIRkt9XHi5a02P1Wn+VLjm/c8KV2w64PyMQayrpv6
         a4X1HG445CS0d7zrElvhHBwPqnxBJvP8pt7vMQnkWpiRD32qw0/o7mWqaxC/CUzNoMrL
         oM1fh7U6J7TFnHCpqxLjzkBVC9k2BvW8+t5i4pAq0jDLRHH23zEMDnAGJ3xeFoImnNwe
         cqKrRi7Qw/v9L2jG1rJTQ8Mix/0YrW1DPrZcjtZ2fdmrorl+T1Xgg9uoj8u41lCBpwag
         ZAzI2+sdSbtsuAqdqjBOzRxNXPZ6mTiAXyBpzJWprjO416cojgFR1V/SBp1kP/Or7J6m
         hFIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EQp9dzkYMxLQ6juVYW150LYSXqFiq/c1RGYle5+7v1et6o+3i
	6kXYq6Us0fhXh8yEJP/aX0k=
X-Google-Smtp-Source: ABdhPJwv/KvFo5DVqFHDxDc2yrXIJPtET10BY9ggn/pPBXQYggfSQV2gGSg8Ncjnd6HxQteE4rLFHg==
X-Received: by 2002:a17:90a:c7cc:: with SMTP id gf12mr4923301pjb.36.1611314521408;
        Fri, 22 Jan 2021 03:22:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls2062113pgc.8.gmail; Fri, 22 Jan
 2021 03:22:00 -0800 (PST)
X-Received: by 2002:a62:8895:0:b029:19e:92ec:6886 with SMTP id l143-20020a6288950000b029019e92ec6886mr4277195pfd.12.1611314520869;
        Fri, 22 Jan 2021 03:22:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611314520; cv=none;
        d=google.com; s=arc-20160816;
        b=p83TV4n1edIViEalfj47d4OukSQZRj//vXxEFy1OSH2ZGJfRb9eTuQjfzCnPIAVTu/
         70rO5dQb2+6Ctewku8uf0eyheK54NMVFB8DvWt8lLWYnrO9l4B3GvPwaqsPvYaoWud0Z
         LrhGX3M0cvGQvU2ymt1QY74BxYBnV2nF1wtj1VE5nP7KQ03NmKo1DVdzjW7rmbD24+ip
         fe8b4l5qv2TzbhCRaVKDH1xTD0EL55OnGownzyh4t6mQaIh5sStomHIdaGqkKlZjwSl9
         YYbe3qP6jbY1KES1PNpVZCH9yLA7hfrByhVmJRTyNvScg9SBmWu4hHPH0d6KVsborCHw
         ZKhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=QIY08jLFU7eat3vtfYfsJLYJ12eg845xPL4mAETo6jI=;
        b=PlE+yqkIK9ywz1Zl47BAzpoHATo2cW/fcSGcQptGx5lqiYU8n1X/3uRn9//1YE8zAy
         JrmZ+wFrw2qf/c6Ktn/oeWLaVnQ21LWr8OJy1oQcFFpZQOF9uk2MiH8DQvR7bBgVPjTY
         /XqwJoll+seoqKGK3ubuCybW5/Mo7qdyjsXOebc+UXPZAyXVgmIktA+c83NZuxyatS7o
         71D01sFoggjve4xq1/gz42hlkFrXtgzKS35uUNCWa+1owx5aj0UzJ9jc/x2i1Qc43+xI
         DaE/scdUBbbwDynP0l8K607FY9K+RxPoDFw+hsPvFP5nRR8DXXVKukT56LyNRs7QuzWG
         tFXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j11si515527pgm.4.2021.01.22.03.22.00
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 03:22:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 15C6B139F;
	Fri, 22 Jan 2021 03:22:00 -0800 (PST)
Received: from [10.37.8.28] (unknown [10.37.8.28])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2479F3F719;
	Fri, 22 Jan 2021 03:21:58 -0800 (PST)
Subject: Re: [PATCH v5 2/6] kasan: Add KASAN mode kernel parameter
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-3-vincenzo.frascino@arm.com>
 <CAAeHK+z3QrZr3OWcvetyChk9GMPuBZVTBjWoqQB45ZSFBOJHwQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <770c1426-3e62-e320-9928-37f6ac580c79@arm.com>
Date: Fri, 22 Jan 2021 11:25:49 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+z3QrZr3OWcvetyChk9GMPuBZVTBjWoqQB45ZSFBOJHwQ@mail.gmail.com>
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



On 1/21/21 5:34 PM, Andrey Konovalov wrote:
>> +- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
>> +  synchronous or asynchronous mode of execution (default: ``sync``).
>> +  ``synchronous mode``: an exception is triggered if a tag check fault occurs.
> Synchronous mode: a bad access is detected immediately when a tag
> check fault occurs.
> 
> (No need for `` here, "synchronous mode" is not an inline snippet.)
> 

Ok will do in v5.

>> +  ``asynchronous mode``: if a tag check fault occurs, the information is stored
>> +  asynchronously in hardware (e.g. in the TFSR_EL1 register for arm64). The kernel
>> +  checks the hardware location and reports an error if the fault is detected.
> Asynchronous mode: a bad access detection is delayed. When a tag check
> fault occurs, the information is stored in hardware (in the TFSR_EL1
> register for arm64). The kernel periodically checks the hardware and
> only reports tag faults during these checks.
> 

Will do in v5.

>> +
>>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
>>    traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
>>    ``off``).
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index d16ec9e66806..7285dcf9fcc1 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
>>                         READ_ONCE(fail_data.report_found));     \
>>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                 \
>>                 if (READ_ONCE(fail_data.report_found))          \
>> -                       hw_enable_tagging();                    \
>> +                       hw_enable_tagging_sync();               \
>>                 migrate_enable();                               \
>>         }                                                       \
>>  } while (0)
>> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
>> index e529428e7a11..224a2187839c 100644
>> --- a/mm/kasan/hw_tags.c
>> +++ b/mm/kasan/hw_tags.c
>> @@ -25,6 +25,11 @@ enum kasan_arg {
>>         KASAN_ARG_ON,
>>  };
>>
>> +enum kasan_arg_mode {
>> +       KASAN_ARG_MODE_SYNC,
>> +       KASAN_ARG_MODE_ASYNC,
> For other modes I explicitly added a _DEFAULT option first. It makes
> sense to do this here as well for consistency.
> 

Will do in v5.

>> +};
>> +
>>  enum kasan_arg_stacktrace {
>>         KASAN_ARG_STACKTRACE_DEFAULT,
>>         KASAN_ARG_STACKTRACE_OFF,
>> @@ -38,6 +43,7 @@ enum kasan_arg_fault {
>>  };
>>
>>  static enum kasan_arg kasan_arg __ro_after_init;
>> +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
>>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>>
>> @@ -68,6 +74,21 @@ static int __init early_kasan_flag(char *arg)
>>  }
>>  early_param("kasan", early_kasan_flag);
>>
>> +/* kasan.mode=sync/async */
>> +static int __init early_kasan_mode(char *arg)
>> +{
>> +       /* If arg is not set the default mode is sync */
>> +       if ((!arg) || !strcmp(arg, "sync"))
>> +               kasan_arg_mode = KASAN_ARG_MODE_SYNC;
>> +       else if (!strcmp(arg, "async"))
>> +               kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
>> +       else
>> +               return -EINVAL;
>> +
>> +       return 0;
>> +}
>> +early_param("kasan.mode", early_kasan_mode);
>> +
>>  /* kasan.stacktrace=off/on */
>>  static int __init early_kasan_flag_stacktrace(char *arg)
>>  {
>> @@ -115,7 +136,11 @@ void kasan_init_hw_tags_cpu(void)
>>                 return;
>>
>>         hw_init_tags(KASAN_TAG_MAX);
>> -       hw_enable_tagging();
>> +
> Let's add a comment:
> 
> /* Enable async mode only when explicitly requested through the command line. */
> 

Will do in v5.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/770c1426-3e62-e320-9928-37f6ac580c79%40arm.com.
