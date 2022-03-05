Return-Path: <kasan-dev+bncBAABBFHJROIQMGQEF7WPQ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 03C874CE307
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 06:26:46 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id mm6-20020a17090b358600b001bf2381b255sf2573799pjb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Mar 2022 21:26:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646458004; cv=pass;
        d=google.com; s=arc-20160816;
        b=suTkE/VCa+Con3fuRHR9mXJMLIyY5F+SMn2YvnvLCt2Wrxs8BS53mdbtCEBJr2YhdA
         sCRGcKCAnMeD2NcvcOshIBtoIzz3+cySX2ftt4/xsI9jb40GAO8Fm8GqRbwgpwLbQ0IR
         e6y1oxUaQaCjT5jNJxlkLjr+d6OSNwBdqYrfCAOHTldzcs8tuvbJagrD1F8GE/3N7OfE
         FyXaiX5Mc7MHmnjdxoqbsBdDOd7dvoAgxQNMVJnCP8nEf7ChLLOpyw/d71p32xqbHw+d
         PERJeNHPmIIrV6fGY2sWnDXPc3mKIK1E361FBBrDVulPxfC2SqqOhWWAHEJDOB0RJfNH
         ZfEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HCSqmWI8BgjQ3Ru/URPS7Lp8j5DZ//Eg5rzsED/v4os=;
        b=Ues6rxVIVejacfbfAAGj+RJw8O4S7f0+0k30N4xGAwm2C+5ee1Zfc02OrmCYFt0+Jx
         VQLJD7o14wKvAIN/Ljt26VdrcXQNU7RnrFmCMCMDqC1ul2RczdTeuJb0aIv8HiOZBZ8p
         OswfnPugwRinwiGciLK5b/WG2ii63eD3BcIFXhK9x6AbRyQ0C7pjEl4N+BnrSd/aPApn
         WBVc2PJtmy/Sftd1utI5nV7zngvMi+EWXp5WPq1gP/nunAXi2l9GPIZPGWK0JZEhMoQP
         sXonuBjNoe/h4vJP3OUYTVU7eGVT+NCTrHYZZU2soY0t873RCwPE08K5hXbJG0nd9cip
         fa+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.3 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HCSqmWI8BgjQ3Ru/URPS7Lp8j5DZ//Eg5rzsED/v4os=;
        b=nmbDX1TvhezEtrzNGixSCwRuvkzGMPUlSrTtQMfYiW1TWMqlW+jQYIYwxm+F2iLJzF
         rpRLL/DnN4nvn3Q0g4Mhf1pRo9ovr/bo/2mLnuvQOCP9gI/a5XuRf8dk5UzIx9vG8EJV
         /vswepqAhOvGaeH+mF9eDLJbKdIdOSDIjNPtnal5lYz/0ezyQ5vIxFxsCbeXtW+d9lgi
         g4d4vZDq/GiuO4W8GV2DhmkQMbCnBdsZ7VLjbAv1hStdAY/G0dKygY8L6dp8L7hGdg+h
         O252XvTEzbR6aK2J6wjWwtjnytr+oUmX+tftGfQajRYNaQB4xBOkRyDA+HYrlGMeGrYT
         bjZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HCSqmWI8BgjQ3Ru/URPS7Lp8j5DZ//Eg5rzsED/v4os=;
        b=Lg37po9PxgllJ+DiiRsITt33RmUrKwNpi8Pv18iStDfbWLm+diiThfnsQGHnHipjmn
         4UHPB0hlzLOXOCnW8I6JfrFl8rgTHSU48BETk1ReCVYhlKefF5zTdM+1CUs14JWn438A
         9e7xijgZyVA4HGKH39djxigydtKn7lSKKMkadGe/0VJI5cbepatahOHFMvZI0an7/cOw
         T5d7MhBQa83RzVJmPTiKqJlzuJyApvO/uNrIJHc1h7MP73nmT5L4F73gaTIWelMhRhrf
         pn2+VjyW0fqgWr+tSVCzLFWeMLaznbdn387GC4PxmYcRdB9p5/JnIQW06ln60bzRZ8+i
         JeIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h+smAHxRBLkm4DL417i21n3wvrcRKFVexIk0YgZksMNwWQ43A
	y+ofb5cbo8IXPWrTwbeLMOc=
X-Google-Smtp-Source: ABdhPJy+qF+HXyL5wBQL1akPMZgP7a6Qdp0HA0crXMkYdxWKeuRiO55mqNSpBJI0UkyYb0EnI5f/6A==
X-Received: by 2002:a17:902:8d93:b0:14d:d2e9:37f with SMTP id v19-20020a1709028d9300b0014dd2e9037fmr2047302plo.83.1646458004403;
        Fri, 04 Mar 2022 21:26:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9152:0:b0:4f6:aaa1:9027 with SMTP id 18-20020aa79152000000b004f6aaa19027ls2250487pfi.11.gmail;
 Fri, 04 Mar 2022 21:26:43 -0800 (PST)
X-Received: by 2002:a63:2a4f:0:b0:37c:4e54:c399 with SMTP id q76-20020a632a4f000000b0037c4e54c399mr1521537pgq.324.1646458003791;
        Fri, 04 Mar 2022 21:26:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646458003; cv=none;
        d=google.com; s=arc-20160816;
        b=dvx21VnmSToAtesS2AMnwMGh65WZzyAvZ6m5NPK5Gcmmh/ixgxvNah6+aqL1ds1Gtq
         9nEa/7WS0INHsXN3QRyzmIXJokNmXZo4nvEQ7xbzN94vQ+ydoNmLVmQm0c+Z90uAyFhW
         /YRuTc6riLQJSmfRvQZcwColBM45MoSAbtBxCYLONMCtSgKjWRkBTwOwD0Fv5eNGE/TE
         bKyZ6SMnk3PJ8bSStKxfe4YrixUl0M9GURas+va1neNyTVYpVHAtDQ5dderawi8rLVGC
         8Sl2W6/SV6OYQKqW5TXAshGRBJ0CnkBL4nvKSLLWE0vTWGYCv6UotONNCT1cw1olCm3d
         VziQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=HzBLVc7cAH2Rrw0EFGpaeRuNrPjuGK2fMSUJU85CxkE=;
        b=YCLpOSNrxuqEI1G3S1T66y9YWR8irepfSIhkZS0JK7qMY3YOAL+03KPenzyFFDN6P7
         tcVgBFgfX6Fsg6T+cQMw7G/eeKbuEndwkIdPZe3rSoIiOt0tFbCejpuxXIhUJ/8WGjpz
         AT6w6jfGj/llCi6DzsqXLmgJmCxbW3PPnDDYSQ+iJkphyFs57H+WnHBrCDlRRt8z4SM+
         bkFG+1q1LAWqqf6EXjIhoEdDAtt+L3HY760F9akawTFoLNxg6z9Bcj30WtXqHthTnPw5
         kxglWljL5QFdXPyAwpOQazhMMKWfuwMY/XCl8azZl2YdF0CMW0wriHvp0Njks0XLtFdH
         EiIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.3 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out199-3.us.a.mail.aliyun.com (out199-3.us.a.mail.aliyun.com. [47.90.199.3])
        by gmr-mx.google.com with ESMTPS id d24-20020a170902729800b001514a005025si222750pll.5.2022.03.04.21.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Mar 2022 21:26:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.3 as permitted sender) client-ip=47.90.199.3;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R191e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e01424;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6FOtNg_1646457995;
Received: from 192.168.0.205(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6FOtNg_1646457995)
          by smtp.aliyun-inc.com(127.0.0.1);
          Sat, 05 Mar 2022 13:26:36 +0800
Message-ID: <ea8d18d3-b3bf-dd21-2d79-a54fe4cf5bc4@linux.alibaba.com>
Date: Sat, 5 Mar 2022 13:26:35 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.6.1
Subject: Re: [RFC PATCH 1/2] kfence: Allow re-enabling KFENCE after system
 startup
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
 <20220303031505.28495-2-dtcccc@linux.alibaba.com>
 <CANpmjNOOkg=OUmgwdcRus2gdPXT41Y7GkFrgzuBv+o8KHKXyEA@mail.gmail.com>
From: Tianchen Ding <dtcccc@linux.alibaba.com>
In-Reply-To: <CANpmjNOOkg=OUmgwdcRus2gdPXT41Y7GkFrgzuBv+o8KHKXyEA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 47.90.199.3 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

On 2022/3/5 02:13, Marco Elver wrote:
> On Thu, 3 Mar 2022 at 04:15, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>>
>> If once KFENCE is disabled by:
>> echo 0 > /sys/module/kfence/parameters/sample_interval
>> KFENCE could never be re-enabled until next rebooting.
>>
>> Allow re-enabling it by writing a positive num to sample_interval.
>>
>> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
> 
> The only problem I see with this is if KFENCE was disabled because of
> a KFENCE_WARN_ON(). See below.
> 
>> ---
>>   mm/kfence/core.c | 16 ++++++++++++++--
>>   1 file changed, 14 insertions(+), 2 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 13128fa13062..19eb123c0bba 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -55,6 +55,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>>   #endif
>>   #define MODULE_PARAM_PREFIX "kfence."
>>
>> +static int kfence_enable_late(void);
>>   static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
>>   {
>>          unsigned long num;
>> @@ -65,10 +66,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>>
>>          if (!num) /* Using 0 to indicate KFENCE is disabled. */
>>                  WRITE_ONCE(kfence_enabled, false);
>> -       else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
>> -               return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
>>
>>          *((unsigned long *)kp->arg) = num;
>> +
>> +       if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
> 
> Should probably have an 'old_sample_interval = *((unsigned long
> *)kp->arg)' somewhere before, and add a '&& !old_sample_interval',
> because if old_sample_interval!=0 then KFENCE was disabled due to a
> KFENCE_WARN_ON(). Also in this case, it should return -EINVAL. So you
> want a flow like this:
> 
> old_sample_interval = ...;
> ...
> if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
>    return old_sample_interval ? -EINVAL : kfence_enable_late();
> ...
> 

Because sample_interval will used by delayed_work, we must put setting 
sample_interval before enabling KFENCE.
So the order would be:

old_sample_interval = sample_interval;
sample_interval = num;
if (...) kfence_enable_late();

This may be bypassed after KFENCE_WARN_ON() happens, if we first write 
0, and then write 100 to it.

How about this one:

	if (ret < 0)
		return ret;

+	/* Cannot set sample_interval after KFENCE_WARN_ON(). */
+	if (unlikely(*((unsigned long *)kp->arg) && !READ_ONCE(kfence_enabled)))
+		return -EINVAL;
+
	if (!num) /* Using 0 to indicate KFENCE is disabled. */
		WRITE_ONCE(kfence_enabled, false);

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ea8d18d3-b3bf-dd21-2d79-a54fe4cf5bc4%40linux.alibaba.com.
