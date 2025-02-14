Return-Path: <kasan-dev+bncBCPILY4NUAFBBA7WXW6QMGQEETMFRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 953AEA36441
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 18:19:00 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6e65e1c57cbsf38078706d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 09:19:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739553539; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fc4C025WqKeAGKYUJCRXxrop2+Ew3kfya8EZBxgXRyqUKegQdc/Z5ul+HqkCPv8iYm
         M6beUDIAswjNqxF0rZj3cEIltJNBV9rwC7q8IjbptEybk+yF4ILwDq7E3GqwX8kAi0Hw
         WZASvMbg634Fky1lyQEmpEIhYgDoeuaQPXT4byDL0cLqmLWfk3qc5JAl1Deff0TXYh+R
         eh220PBzOiibCSYN/4pdpbAwSXMIoehowdqZKdPPfMHNLLPy3F4bhjeLp6/E6gY4AgY6
         zCXELiURIImqckvkxkzNv81qOIvVAEP2LKAcMvdIKpOWYeC1lL2vWgxFTnjABGlh44Mj
         o4ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=+g5Fyk/2sJ01w9DkzKSZqOJyJFSbsb2WuRezQoI6KEs=;
        fh=QNlDf4uNvmILCrC31LkfLwFeyTJCmkI/ncEjiycIE9k=;
        b=I9LMBhBJ86E2weEa6h2M2ZkW3qKzrbwUM4oYqeN34wun6TDPNw+cujPy7vHe+M6Adx
         INLu5lg6OcnuHtA7Z8jnHY35p/euLBE6VuG4/LI7hW7jS3FfgNRRYoxkVrF0SG4W6baE
         kNTM3EvkmQ++P/O2lRyAU5zwhpO6mQ0yg40wq1uZrz75iBJCrmO+U8WNHTGKbVO4cylq
         fF1aFpjp5gJX2gYRo9aisAxvWM4yph3/KWHLZtnr+HjlGS0jY6amBWIObXCjkO53sFpT
         394ao7N+hOeF+KW+6wnumCfnQiSl+6GrJ+JL9Ta1IZiHjRCw41NeVVtfuuqb/i7jOEci
         Audw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="c0Uu/I6g";
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739553539; x=1740158339; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+g5Fyk/2sJ01w9DkzKSZqOJyJFSbsb2WuRezQoI6KEs=;
        b=exjfLzt59wlQRK8PsYg9B/QXkVDItVSPlJpfMEpXJD7FHpUn9OBl2peMa5tMYZTMsg
         atfta9UgyXAFkhA+XNRExgMIREfg7NdqRWOlNby/VezWtybND5VeqkOvG4ljw0bSbB0+
         PjGwnH/DeZof6ffvGv4xSqzCV7xFsn215Mr5RbyWv2a5bzp640ceNh4gSE98NMMM0W2U
         KC1KNqy2eMN3f+NhFROZQNkrrEn5euUzb4GYnT4gDq3vywdcs1pZciXoMg6JXLHnLzRK
         Lt5N5uX9G1GAAhMfkIEribNNELuHg80zBgTec/IHGgTeS35C2C+ICwiOXt/AICmXAkAn
         fl5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739553539; x=1740158339;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+g5Fyk/2sJ01w9DkzKSZqOJyJFSbsb2WuRezQoI6KEs=;
        b=kFZ3SsfJ4DAfzwFlZq77ZgD3NIgAJot0Ula6ztGhixfWlBeLFJ7E6JURwjvc4Uzh/S
         +98gPpgiPt5XLLPk7b/LWCAigo9eEvp6KrScu39bx0zZGgfFmoJ8eaNhuO8CDRIs2+ne
         URIhSzfydV5/2OIuc5b4t+YIUBY3dsLGA13Qvnga6rMp0Ixhtv7Zlpb9UGhdRKzbNVAx
         yPNIFRHQRbylpei2k7i+GULW730VV2AwJ8QJlAahb3WqahKzHL+pzCRS6t2G+Dp/ucef
         Vb9I01PQm/1iCYgRJYgc9XthWiUDGJ0/AgZfyLX296HyFiLD8AcMAQxLM7HiRWtMW1R9
         qt8g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVM17TvCdpRE/BGCfEdBq3I2VNZ9Jb/PuTpKl9qfmuo1pwPuUATB4g7eFolwNFBTv9FnTvukw==@lfdr.de
X-Gm-Message-State: AOJu0YxTU6YlJY2Vjwrx/hI8cYR7t8xQkK0Qm7LoxGDR+9n5cTZS5qzI
	SHlHm7WXbeMLfyT6vGi7tyUOTae4JC2mY0fVk65t+vDHS0ALH/Ha
X-Google-Smtp-Source: AGHT+IHhHLOMzVDq2zHSzVtUju+yTkgIgmFA+1Ogmm/O0GqcHkNiR/I8IUEtIHt0fIhvjqNy0Jgl2g==
X-Received: by 2002:a05:6214:627:b0:6e2:49d0:6897 with SMTP id 6a1803df08f44-6e66ccce2bamr333626d6.24.1739553539384;
        Fri, 14 Feb 2025 09:18:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFld8cLDioI+b0NcykQOzsCwwfH+p3Us04qnnlu+miNuw==
Received: by 2002:ad4:5894:0:b0:6e4:41b5:919e with SMTP id 6a1803df08f44-6e65c24795cls14746686d6.1.-pod-prod-07-us;
 Fri, 14 Feb 2025 09:18:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDQYiZs6TDgqyW2q003OQIYMc3Atm/fvYLn2Fmxr5MbFyjDrr8xkF1FAjG9HSv9yaPf9zoE9A6LeQ=@googlegroups.com
X-Received: by 2002:a05:6102:419f:b0:4bb:e8c5:b162 with SMTP id ada2fe7eead31-4bd3fd74907mr384060137.10.1739553538432;
        Fri, 14 Feb 2025 09:18:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739553538; cv=none;
        d=google.com; s=arc-20240605;
        b=VD5Ghd2KqnbVWFIJSwHiOsN8TnH8k8E5qDQcI7URbUcL0hAK0+XxeOvyVUWCedmYph
         Kd06HaLFhLvkhiffoKxnCytnyFKKw6bQDgirSD8c7aLLurEUgDF6+jEXeSAfStuDak9+
         kZqiR3QMh+E30XlTtK5eEu+QOZc5EoZD946nAaJxmcEVDuuSreAfJFCXyHuxQI1c4B/4
         T2951ofE/YGLGtKO5evCkOcaapV/W6yjkXDzkpE49klF+OdjN1yJw3C0sUxyQAPOD+Gp
         pvyPIN4SSX7st33ugNX7JDYspr53Yj4QXPCrrqMSXxugKgzkCiUYbGTmOhFpOZ17nlM3
         bGHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=miJRz0qz2+SDHVCWyn+86rl9+qDF1PxK6piRfHk43rg=;
        fh=XMoRpio+y3RGTHMWT8kwgYJHFIC0AipenCsejjs/Y1E=;
        b=baCOvti/JWtBOqr2EIuaQeR8u66JJ961ZQnZb0vJgtTH86ObAOh3ARM9uqrKNZnGj+
         nAR3WwjyByf2PI51xL6775AR+3QTxoi9qsT14N6nkyi+l4J57vVwU1fjSvpxT5E1abmm
         ggOhyqq2cUnB8tRqJveG/pEJxcPqOtT5vf2aIRxxRQ7LbjzQyErStIrvIU0p+xLZayXq
         7CorqHm9urH2tWBmrZSt2l230uJUS1IjQnMdnLTNVxUcg99N8lclSCcqbLNYdRaPPp+x
         5mTOmugzdSMRsG5D6KArbQ1R9rQE7kXI6k0BAhhEB+5F2ymYXmSV3+pDQ/U/UfXlXvmk
         1/FQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="c0Uu/I6g";
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4bc07577e29si184317137.0.2025.02.14.09.18.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 09:18:58 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qk1-f199.google.com (mail-qk1-f199.google.com
 [209.85.222.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-259-YY8BFZ-pORqLldVca8PRHA-1; Fri, 14 Feb 2025 12:18:55 -0500
X-MC-Unique: YY8BFZ-pORqLldVca8PRHA-1
X-Mimecast-MFC-AGG-ID: YY8BFZ-pORqLldVca8PRHA_1739553534
Received: by mail-qk1-f199.google.com with SMTP id af79cd13be357-7c07903c49fso391809885a.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 09:18:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUgEAC7zAsZBEJQhz7aMpDs1hcAqHNdWShMvMMLNq/dRwTnVarP+DvAkgVLiwnhWLp6bnH74He5rf4=@googlegroups.com
X-Gm-Gg: ASbGncvPG7gG3JQsFXoOMmq8g7Dmwu14bwaIPZA/lGC1Mrzj0eJmq8I0U4YwOqsH8Qw
	KEBmgKI+cVZUiGHpalIHA6QDlmTycnpFs2KMZJz9oYTvHwprCOMeL7RqJwY7/IcZKfyJLVgKufA
	lP3vLByWAOE5kfNFNceCU/iQ3D0zgKXo3rpXWzUOPb0ZNhFdSf/I51zAPG+iZoWPtc6PLtexlox
	gad9wtkmOJI3IhzQcc+GLI8rwunOHQNV9oTMGdRZUHKzbhtfHSvHpnI4Jek//I1QNtynI9S5skd
	53lQt0ZTfs8EM5x69qNfydTzpJPo/9U1mshnDAMNVJRvthrD
X-Received: by 2002:a05:620a:4808:b0:7c0:78ec:1ee3 with SMTP id af79cd13be357-7c08a9e6125mr23710685a.28.1739553534418;
        Fri, 14 Feb 2025 09:18:54 -0800 (PST)
X-Received: by 2002:a05:620a:4808:b0:7c0:78ec:1ee3 with SMTP id af79cd13be357-7c08a9e6125mr23707385a.28.1739553534104;
        Fri, 14 Feb 2025 09:18:54 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7c07c86131esm223681585a.68.2025.02.14.09.18.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 09:18:53 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <dfe06175-1c19-407d-9583-43576ab9b588@redhat.com>
Date: Fri, 14 Feb 2025 12:18:51 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 4/4] locking/lockdep: Add kasan_check_byte() check in
 lock_acquire()
To: Marco Elver <elver@google.com>, Waiman Long <llong@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20250213200228.1993588-1-longman@redhat.com>
 <20250213200228.1993588-5-longman@redhat.com>
 <CANpmjNM-uN81Aje1GE9zgUW-Q=w_2gPQ28giO7N2nmbRM521kA@mail.gmail.com>
 <3d069c26-4971-415a-9751-a28d207feb43@redhat.com>
 <CANpmjNNLn9=UA+cai=rL+6zsEQyppf6-4_YL4GAFi+dLt+4oSA@mail.gmail.com>
 <f2f006e8-3987-4aa2-b4f5-114b4e869e86@redhat.com>
 <CANpmjNPYFjv4TTCG+t0zyr2efCtjPKV7zQQu-ccsgX5XtGtDLg@mail.gmail.com>
In-Reply-To: <CANpmjNPYFjv4TTCG+t0zyr2efCtjPKV7zQQu-ccsgX5XtGtDLg@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: sAyneHPNP1PzDMedhT5xgyrUmF9B-7UMkNWZfhZ1KiI_1739553534
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="c0Uu/I6g";
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

On 2/14/25 11:43 AM, Marco Elver wrote:
> On Fri, 14 Feb 2025 at 17:18, Waiman Long <llong@redhat.com> wrote:
>> On 2/14/25 9:44 AM, Marco Elver wrote:
>>> On Fri, 14 Feb 2025 at 15:09, Waiman Long <llong@redhat.com> wrote:
>>>> On 2/14/25 5:44 AM, Marco Elver wrote:
>>>>> On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
>>>>>> KASAN instrumentation of lockdep has been disabled as we don't need
>>>>>> KASAN to check the validity of lockdep internal data structures and
>>>>>> incur unnecessary performance overhead. However, the lockdep_map pointer
>>>>>> passed in externally may not be valid (e.g. use-after-free) and we run
>>>>>> the risk of using garbage data resulting in false lockdep reports. Add
>>>>>> kasan_check_byte() call in lock_acquire() for non kernel core data
>>>>>> object to catch invalid lockdep_map and abort lockdep processing if
>>>>>> input data isn't valid.
>>>>>>
>>>>>> Suggested-by: Marco Elver <elver@google.com>
>>>>>> Signed-off-by: Waiman Long <longman@redhat.com>
>>>>> Reviewed-by: Marco Elver <elver@google.com>
>>>>>
>>>>> but double-check if the below can be simplified.
>>>>>
>>>>>> ---
>>>>>>     kernel/locking/lock_events_list.h |  1 +
>>>>>>     kernel/locking/lockdep.c          | 14 ++++++++++++++
>>>>>>     2 files changed, 15 insertions(+)
>>>>>>
>>>>>> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
>>>>>> index 9ef9850aeebe..bed59b2195c7 100644
>>>>>> --- a/kernel/locking/lock_events_list.h
>>>>>> +++ b/kernel/locking/lock_events_list.h
>>>>>> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
>>>>>>     LOCK_EVENT(lockdep_acquire)
>>>>>>     LOCK_EVENT(lockdep_lock)
>>>>>>     LOCK_EVENT(lockdep_nocheck)
>>>>>> +LOCK_EVENT(lockdep_kasan_fail)
>>>>>> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
>>>>>> index 8436f017c74d..98dd0455d4be 100644
>>>>>> --- a/kernel/locking/lockdep.c
>>>>>> +++ b/kernel/locking/lockdep.c
>>>>>> @@ -57,6 +57,7 @@
>>>>>>     #include <linux/lockdep.h>
>>>>>>     #include <linux/context_tracking.h>
>>>>>>     #include <linux/console.h>
>>>>>> +#include <linux/kasan.h>
>>>>>>
>>>>>>     #include <asm/sections.h>
>>>>>>
>>>>>> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>>>>>>            if (!debug_locks)
>>>>>>                    return;
>>>>>>
>>>>>> +       /*
>>>>>> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
>>>>>> +        * the first lockdep call when a task tries to acquire a lock, add
>>>>>> +        * kasan_check_byte() here to check for use-after-free of non kernel
>>>>>> +        * core lockdep_map data to avoid referencing garbage data.
>>>>>> +        */
>>>>>> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
>>>>> This is not needed - kasan_check_byte() will always return true if
>>>>> KASAN is disabled or not compiled in.
>>>> I added this check because of the is_kernel_core_data() call.
>>>>>> +                    !is_kernel_core_data((unsigned long)lock) &&
>>>>> Why use !is_kernel_core_data()? Is it to improve performance?
>>>> Not exactly. In my testing, just using kasan_check_byte() doesn't quite
>>>> work out. It seems to return false positive in some cases causing
>>>> lockdep splat. I didn't look into exactly why this happens and I added
>>>> the is_kernel_core_data() call to work around that.
>>> Globals should have their shadow memory unpoisoned by default, so
>>> that's definitely odd.
>>>
>>> Out of curiosity, do you have such a false positive splat? Wondering
>>> which data it's accessing. Maybe that'll tell us more about what's
>>> wrong.
>> The kasan_check_byte() failure happens very early in the boot cycle.
>> There is no KASAN report, but the API returns false. I inserted a
>> WARN_ON(1) to dump out the stack.
> I see - I suspect this is before ctors had a chance to run, which is
> the way globals are registered with KASAN.
>
> I think it'd be fair to just remove the lockdep_kasan_fail event,
> given KASAN would produce its own report on a real error anyway.
>
> I.e. just do the kasan_check_byte(), and don't bail even if it returns
> false. The KASAN report would appear before everything else (incl. a
> bad lockdep report due to possible corrupted memory) and I think
> that's all we need to be able to debug a real bug.

Fair, will update the patch.

Cheers,
Longman

>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dfe06175-1c19-407d-9583-43576ab9b588%40redhat.com.
