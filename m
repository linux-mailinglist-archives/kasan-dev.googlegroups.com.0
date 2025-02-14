Return-Path: <kasan-dev+bncBCPILY4NUAFBBEODXW6QMGQEJAI7ABQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EA92A361B7
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 16:30:27 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e5b2875af12sf2830761276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 07:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739547026; cv=pass;
        d=google.com; s=arc-20240605;
        b=QMyuYjMzjGvHX2XMD+8uasZvhwpgGsnw/TlUvqJ8oK70J6HNQRmiUt+hYAEEPtoaY0
         a0sHQtl5dB5RCKty7D0HzR77Qqy7a5JnpHAkFMkLqj/z8gq/SPykljDyAMTYI+eFX94f
         e/XtXYphflLOVYg3yJfkdYiu0Id571Hz525bEBsRV8j/DSCE4cd6d4moohcLESd+KKX4
         Dp/RSaDTbLhgsxAHOcAiXhgfLowQh8hNbDcqd62ceNFmn3Bhk6Xh8Ot8iHdfl9bbCthm
         E/Uy1agIGcApFTaGBIlCmg1xHNrW6vCTcgyQz5uNeJlah8UBogzL0O2nzW1bLayoHjAb
         ZBeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=SJ1KjT3uHhhd6L0oHdmveQWaLVvDajCQ+hLxyiQlOgM=;
        fh=E2cMbxGAmxuXQvrTUgzo96C2cvYxB0u5wfRpD8dttHw=;
        b=YerjxHhC0V2xcMH/zStdiOecSeddVP7q0MIEmtd19wOkZuxmTdzN/YIpidtA5uU1DI
         8Bst7d2oFrE9OHulhQpruH5PPUeE0X+3nWhBhEhgTNGunxtE2CkHo3j04yBICuVhl5rQ
         xxAWIA+OyuG2i7FIUQRlvMwize/OQs+I3ulUiCxZUNBfRsWpb/rg6RORwQtMSg0205IU
         0rmQ+j9y4NJxm3eNLen3tfVGCvIG8+qABL3N9o9iYGgGBn9OCCXxDWWHzOu3CZZImXV5
         zq70iSujq5Xp4ryIbKh3LHw9cM92hLzc4xtwXjGp12L9lxyMarif11E5J9TxAgUk1ltA
         5Apw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WOFFspyy;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739547026; x=1740151826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SJ1KjT3uHhhd6L0oHdmveQWaLVvDajCQ+hLxyiQlOgM=;
        b=NA868FGE5mZzDzNgoWX4ARdFlawxB4cN1RVAzw9hL4FLkW3gEnLz4xFHMb779cIhXN
         Ds+k4QKsVSFKW2ZscfJD45HTvLW9qQOvZU7GK04OUvJHOy1XyKmUBruu/z8QAwJ3T6vj
         TBY4+C993k8Z+UVdZUQ+VWb0kKDOXpAwXNrUUea+39P6QcCWRe5wI/PoDAvH6/aAld27
         3G1FFhtxgnjQ7061uj1CCzH5XXv4OqkUGmoMkYephJ2AVs3HZx9ylhtyNH7RsqCZeByg
         CRFgwticXwhoFQ6PgLn4Blf5BHJLtPGouer3DDzCjhiwlvndXskLSc/O7gFcfUta3VML
         6YjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739547026; x=1740151826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SJ1KjT3uHhhd6L0oHdmveQWaLVvDajCQ+hLxyiQlOgM=;
        b=SBb7mc9dmaxXgRrtuEoMfVzUA0u57ylEOjL3m8m8fPRWJdugr6aU6HupNLut8uXNG0
         WpC2SGkaB+eDkqdPxUKAmu53mSMRnSQOFLVFtbe7v7FFJgqzS+LNMfOoVOQACbW2p+Dm
         7SuHKLm1wVy/ykp4mIYtyNytfKIHT8laLqlXPhkSJEgIFCyxNVm2b+rthr6ZK8iseIkU
         HrX593DYcIPSfX6/Fj26R6RiKDROtyWorGjKPSIKppw/G9Gxdd+XQ0Rdp5RWtno72bvx
         jM5zw9Zua8C/iE65uuHeOSV/0xIXrA3FVNLenaCX335Kko+WvWA8066icm/pfceDdo4G
         ttGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjsNztG7840eiAtAK87diwyGIMNgtqZ1c8AP8E60bJwgbTSx99CXRB2yRALOhtk6CXx7lEOw==@lfdr.de
X-Gm-Message-State: AOJu0Yx6zUxOMr37+5SkLw5CQTBIv/56+or/6n5AqTWo8A7r8DgUsy2A
	0ITNlOrGm9YMs0CjOFn2m/r4Pq9/Yfp0dRSUERj5xQq++6il5jkr
X-Google-Smtp-Source: AGHT+IHDrXy8/fr4FyUmfhFKxpUOsYNUaGkr3Kqro9I6ag4jDxDAE3RobhM/8M4egJdVO/2uOKAGvw==
X-Received: by 2002:a05:6902:2804:b0:e58:fd2:2cdb with SMTP id 3f1490d57ef6-e5daac50a70mr6910733276.7.1739547026080;
        Fri, 14 Feb 2025 07:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFHdP5w4B6a85+qxr4F6Lci1TmmW6Usv3D+gJD1ZZ2+8w==
Received: by 2002:a05:6902:f03:b0:e5b:393e:d379 with SMTP id
 3f1490d57ef6-e5da7a527f1ls1412508276.1.-pod-prod-00-us; Fri, 14 Feb 2025
 07:30:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXioBJsvKIxgZMLnxj7x8UsqoLGwniNywYDPm2h5SdZtPm9hhnBHfslvRru8tmB+J/q634vgxtk0Ec=@googlegroups.com
X-Received: by 2002:a05:690c:2e13:b0:6f9:b027:1bfc with SMTP id 00721157ae682-6fb33c5a833mr63471907b3.3.1739547024659;
        Fri, 14 Feb 2025 07:30:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739547024; cv=none;
        d=google.com; s=arc-20240605;
        b=br+epc6Er33Wxf/66nH6L7UK5Qg1LNo3dDFN/6/T6Dz2fpRnBCQW1a8XAD3p5CWNWk
         cYWzHVOkEHpreSv9q+8YZAArPn/aTQ12cpencyztqSGHaNQq/x7BUCWMcKRuHL2bJjHh
         ze+fqGdCWZoMSst9DmyNxSUumA+3d0XJWeKBKiVPyDCR6biFUKF3KqqHHHkKxcuLuyVs
         sAOaP/8YE42p9FlNu61Hw1ktbmYhvBFYE2QgeTeERupu53ZXQQXRtoTOEHXsP4GTQvxG
         /vAB6a3ipYGnwp5zjlT8OdlE4rbISPxFhvpjG5r1hu8Gle2k8d6e6TYMwLt6Zwz6C0+u
         H9Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=o20OYWODIVHTwZatDY+hi4cXur9nivP5VYl+8yx8ZgQ=;
        fh=GvjSpvyEtWQxJsiEInST2BMB4YuaenbUgu0D089zwWI=;
        b=O+pyD3suo37EjBpy1iUyoVIVpvysYZqz/TB0xBotUwBtt5RtmWwiK18c6jHdp4gpyQ
         Q5U7/3dfihVT1oHzfdNv/vXBwYcXjHX32EG7I4kT0+9griS/GKMiI+dRPyMMhLzHD3z2
         t6Tl5tmGfLO8+WBu/IkGKINqIRyeVt/+ZN9Mg7ybJFuULvTt41LGm5HjiB2yqYvkdK5+
         qVMraK7vcVPe0K7CjNDyj4Vlmg8zqmj29cCoJac4ryFUf4g+j/Az/VilBHtSX2w8ZcvU
         WXFPXhrT7XTewcQMTai7H2PotR8nB11dwIA2vDlTI7VaQpa4KVRM+1A8Sp0HDViQ05O4
         vDpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WOFFspyy;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6fb3612392esi1747567b3.4.2025.02.14.07.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 07:30:24 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qt1-f197.google.com (mail-qt1-f197.google.com
 [209.85.160.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-611-bWmVmEefN4-YnZdzn7RIAg-1; Fri, 14 Feb 2025 10:30:21 -0500
X-MC-Unique: bWmVmEefN4-YnZdzn7RIAg-1
X-Mimecast-MFC-AGG-ID: bWmVmEefN4-YnZdzn7RIAg_1739547021
Received: by mail-qt1-f197.google.com with SMTP id d75a77b69052e-471cc4c347cso24037291cf.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 07:30:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV9bLHfbhyYvlQJCvJoQnRRRPPNmjHIC9cDUvU23W99Fh2612HS3vw+Z5lPsitdEL2SHiUXqZt5PkI=@googlegroups.com
X-Gm-Gg: ASbGncsRkuS10RHuvwD1iCy5VeXu8tDg5KBcg/IP7czsm+MTGqYKll7LoLOu956ISqG
	KgSSzTTWC0hNur3uvqCleldVJ3Ds4x+7ybVu2RD3QHZuRWw3tWCBVJZhRNCYgZWxs2NTvzjo/8A
	L84xj5CpgX3SCW0v10KogJviWi+OigTA9d5MViObDezglnOZF/1VM4AwIiAmvk8wQ9+83sL2rHE
	MpqfDh7jWPz8xka8nd87YX3CJNbtmkCHXIr9bzh40TTEqHoFaWXJ1a4CNoTMYtc/zFFjLfCq5bh
	O/vVTIH7RovyjbeAneDITykS5V5fx3VjflRkUIYqfRDa8XZ3
X-Received: by 2002:a05:622a:6a42:b0:471:bd5e:d5da with SMTP id d75a77b69052e-471c02791bamr82414531cf.0.1739547021174;
        Fri, 14 Feb 2025 07:30:21 -0800 (PST)
X-Received: by 2002:a05:622a:6a42:b0:471:bd5e:d5da with SMTP id d75a77b69052e-471c02791bamr82414111cf.0.1739547020777;
        Fri, 14 Feb 2025 07:30:20 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-471c2b06532sm18535991cf.79.2025.02.14.07.30.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 07:30:20 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <12563ec0-90ef-4613-9931-319b2a2bfceb@redhat.com>
Date: Fri, 14 Feb 2025 10:30:18 -0500
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
In-Reply-To: <CANpmjNNLn9=UA+cai=rL+6zsEQyppf6-4_YL4GAFi+dLt+4oSA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: _2JGpFzGKGBnjmidQ_tcbOkx6UWUTzRt4dIE4jCEI5g_1739547021
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WOFFspyy;
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


On 2/14/25 9:44 AM, Marco Elver wrote:
> On Fri, 14 Feb 2025 at 15:09, Waiman Long <llong@redhat.com> wrote:
>> On 2/14/25 5:44 AM, Marco Elver wrote:
>>> On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
>>>> KASAN instrumentation of lockdep has been disabled as we don't need
>>>> KASAN to check the validity of lockdep internal data structures and
>>>> incur unnecessary performance overhead. However, the lockdep_map pointer
>>>> passed in externally may not be valid (e.g. use-after-free) and we run
>>>> the risk of using garbage data resulting in false lockdep reports. Add
>>>> kasan_check_byte() call in lock_acquire() for non kernel core data
>>>> object to catch invalid lockdep_map and abort lockdep processing if
>>>> input data isn't valid.
>>>>
>>>> Suggested-by: Marco Elver <elver@google.com>
>>>> Signed-off-by: Waiman Long <longman@redhat.com>
>>> Reviewed-by: Marco Elver <elver@google.com>
>>>
>>> but double-check if the below can be simplified.
>>>
>>>> ---
>>>>    kernel/locking/lock_events_list.h |  1 +
>>>>    kernel/locking/lockdep.c          | 14 ++++++++++++++
>>>>    2 files changed, 15 insertions(+)
>>>>
>>>> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
>>>> index 9ef9850aeebe..bed59b2195c7 100644
>>>> --- a/kernel/locking/lock_events_list.h
>>>> +++ b/kernel/locking/lock_events_list.h
>>>> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
>>>>    LOCK_EVENT(lockdep_acquire)
>>>>    LOCK_EVENT(lockdep_lock)
>>>>    LOCK_EVENT(lockdep_nocheck)
>>>> +LOCK_EVENT(lockdep_kasan_fail)
>>>> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
>>>> index 8436f017c74d..98dd0455d4be 100644
>>>> --- a/kernel/locking/lockdep.c
>>>> +++ b/kernel/locking/lockdep.c
>>>> @@ -57,6 +57,7 @@
>>>>    #include <linux/lockdep.h>
>>>>    #include <linux/context_tracking.h>
>>>>    #include <linux/console.h>
>>>> +#include <linux/kasan.h>
>>>>
>>>>    #include <asm/sections.h>
>>>>
>>>> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>>>>           if (!debug_locks)
>>>>                   return;
>>>>
>>>> +       /*
>>>> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
>>>> +        * the first lockdep call when a task tries to acquire a lock, add
>>>> +        * kasan_check_byte() here to check for use-after-free of non kernel
>>>> +        * core lockdep_map data to avoid referencing garbage data.
>>>> +        */
>>>> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
>>> This is not needed - kasan_check_byte() will always return true if
>>> KASAN is disabled or not compiled in.
>> I added this check because of the is_kernel_core_data() call.
>>>> +                    !is_kernel_core_data((unsigned long)lock) &&
>>> Why use !is_kernel_core_data()? Is it to improve performance?
>> Not exactly. In my testing, just using kasan_check_byte() doesn't quite
>> work out. It seems to return false positive in some cases causing
>> lockdep splat. I didn't look into exactly why this happens and I added
>> the is_kernel_core_data() call to work around that.
> Globals should have their shadow memory unpoisoned by default, so
> that's definitely odd.
>
> Out of curiosity, do you have such a false positive splat? Wondering
> which data it's accessing. Maybe that'll tell us more about what's
> wrong.

Will do more investigation about this and let you know the result.

Cheers,
Longman

>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/12563ec0-90ef-4613-9931-319b2a2bfceb%40redhat.com.
