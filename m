Return-Path: <kasan-dev+bncBCPILY4NUAFBB5OZXW6QMGQEFLXW3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8814EA362D9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 17:19:03 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3f3d417cb65sf675425b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 08:19:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739549941; cv=pass;
        d=google.com; s=arc-20240605;
        b=XlPC5e30VptkqhwTgKEAscaHWAAtKw8oT2tw14u1bxylQZ4JJfdQYpH9xyZ09ZuRFF
         7ci4NdGbhp+akxvl7w9EDjYuZkeuOdhlMmR3LN/I7XWn3jaXkJzeZz2WlAgV8kDvYvXn
         d/bkigfAR8LtgW5Sm1PMQ0Lwf/8V7BCNdaIxICxnc6Lc1IIOr5EZP/1W/mty7RhHcyOw
         3a6QxXkz8vxbVqWytnLHQRoyrAUt3LW1Qw0KbAFV9mfEVP2nfunq5Sq+YPfl0o5qA971
         PNDpKHSnncaSYcnk+jqiQp0eXyFotu3RCQWLPPzjaLxtChS0FGmGEo1FwNE2oCoHvW+p
         rgOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:sender:dkim-signature;
        bh=cxfrrZps3oIXV/gImnamKtrO3y+Sja6nNWKWmGIT7x8=;
        fh=KVurCZoMGqrLr9fPIx9VwN8aptcZV6Af4i2eHksrTdM=;
        b=JkGMK52CWTep+DHgZeqlSoCJMSaPMuo7k6m2vMSWqgmjXhQMohptPP4zdgitoHXomy
         19e6t/ukXZzXfIjbuZj/gefbvlUzqCitBYT2C5fVza1r8f4xBZmRo1bDLXMXgiFmqjRq
         onsVHO7YZnsi5axRmzACk9B/Dsj1ADgc/1fQ+QwMbCnyUDAHqRfTm909k4i+eYCCGQoN
         UqfNjx+w1gyUs481bZ6dtgDzOg6LE85/fM/QredbLh93RxugilVmBY/geyHI/VuLkpcw
         R1i8N0r+wnUlEr1cXwZe4GncmYKGqL3V8nxbA7IlhIrdqw9rLbZK0dPezCuJK4/tpBqz
         88cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=euCJ3aaL;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739549941; x=1740154741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cxfrrZps3oIXV/gImnamKtrO3y+Sja6nNWKWmGIT7x8=;
        b=bQ6xW2Zo1DjZJ/RsOlgwfgY0Wh6oPxtcT/iBIOYhmiD8kfYtPdkH0fld2dh9gcAAem
         00ObVZ+XmNYFabH3Shum0gShJ5xhGgt5WowG2/P/X1IXeyRK3jUJ8S4dGxPIljpLRFaF
         TQwL+7XpvZ+6e/m+fNre4U2dZK1nKY1zbanUxil4tz5EGyPYbSBzuWoqIH4nhW8bl4yF
         5//Pe/QAFzX5sNJTfkgPmAErXDAGg6zOf4WWyE6MSjl8z0p89k1K0c0SJQ/tKk0y9kQx
         aJZ5+VQmQJ02anLi58Lrq/XC2OoZ9yok9D85kSjVE1YvN18uZnGJwTJbwwLRbT3EWqmg
         HeUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739549941; x=1740154741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cxfrrZps3oIXV/gImnamKtrO3y+Sja6nNWKWmGIT7x8=;
        b=ZWsyM6to7hK3JVwqaZjKjeJDRbobQHc0zTiCchciaVvb3DdEu9irHJXD9tz00EVGcK
         ttExpSfBjHj46afIa7+zcAqPqILQs6wnIVOG/vc6dCWnWvX9rLfeEhLuPrxiPzBqPCbx
         pPYiknhjN3JOhzjJeLMgx5tCKs4LvBWI667FnRbyuzWM047pIRqB0/vLuumlkivlrCMj
         okMVmje17rwFobS5gG+V2aMpdsje2yDzrdvNQXcYprtWp9pd7QGjQyB9XXUdJfNi/djv
         L/cXkPGJHp+18Bq0ZxEjcza0jRp/4qZvK/D4ogAnpCBMcTxSXi1aX6A0t02kULWixRx0
         eDnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDn3L8oQXTVew/xM+JMvMZ5lGfguBS0lHUtvH+bThTTohFVWMp5ITsjKKDiQ2E2A8zlS8ZvQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx9wjbK6AU0ZLmMJ+VbHGkphjgB/1t40G6bvnXyBONHc+9QS1vt
	0LuhZ1XNY8MF5OSKVyGBVQ0v1wPiCT9kJ41jCk6LILNuxcw/qvOj
X-Google-Smtp-Source: AGHT+IEWFWdsR6RIpdz6a13qC+3V4roD699zV+KiuGj/7UuXVmgMAHqfmso69/Qq3SVKCRJrk1Zgow==
X-Received: by 2002:a05:6870:6110:b0:29e:2801:43e6 with SMTP id 586e51a60fabf-2b8d6591683mr6241962fac.23.1739549941670;
        Fri, 14 Feb 2025 08:19:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG1CcDWQZVrS4H8ZPBNSJTBXOowlt9Xcq8g+ClkFUvcRQ==
Received: by 2002:a05:6871:729b:b0:2b8:f3e5:a817 with SMTP id
 586e51a60fabf-2b8f7fe9c0als293139fac.2.-pod-prod-02-us; Fri, 14 Feb 2025
 08:19:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWaTn20slLalsy9aQFo+FFTzv7ILdq0EMp+kAxN+klVZquTbYt9Qj4Bxz3JJiSUCMK2gsh6if7cwRE=@googlegroups.com
X-Received: by 2002:a05:6870:65a9:b0:296:e10f:af14 with SMTP id 586e51a60fabf-2b8d68c8c52mr6456285fac.39.1739549940790;
        Fri, 14 Feb 2025 08:19:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739549940; cv=none;
        d=google.com; s=arc-20240605;
        b=VdeD7ylI0aBZjGFt4C7Sv3/7QU83cnIwfX3u3CZT5VS+Cg5UbaWnYpZdjRUdAnhfc2
         qtfbsB8o/AFTtvHsBYSLW5vyCGIrA3uOT+2lCXBzflrypPda8xj8EwLbcber2xNckHPS
         0n2UQy3+tIBQw6or+UL8FCiHcBRiD+GAqiazpIMymxte6B0lygKEir7fbEpawggcjV5j
         fRYfgvWkpfoxBB3KaS3wnm8M2SgQorMal8gpUHdUQJVxGTfvE3AqSOYXyQ0VcE/lBovD
         hpMi32BVhxXV24JwlYd72R4APYpmiFmCPY3BLIkzvsWrc1NpHhmcC7eOh1DVjh8sasLs
         9XEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=aG8Kjzwld+BC+gKborzD0wPyk1VseyZvEiHws+jsBUM=;
        fh=CZHbUIhMqQRlFzFDu2oIk5Dd6s/CMPaeuSNL6ihoFuI=;
        b=XSQq6FjF4PhISqb4FWqKzTbuwJQSQVPSy2t0lHL9yWDWbFV/LHqSO+EqBPFlftaL1z
         Qhswd3xfR7JHvVI5FJc6e+wtoE8+cbODVo+hdcGxvbroubSrg4sEzErN2Bt3MFL9iENE
         k2HOcYkz6ufd+BK+1Shh+tiMib7oC/SSs2L4lMAtg23VhEP6BIUCwBvkphwB8MxrOAM0
         utkE8Lb3acaVfuDs4cdT1oiiYE33a0ncHdTmVnEYUjm6PiwJjXUQseHgNYY37XGMmPX8
         UWSIdF0NyVNsUifGBvXLN6G5Z+7DTtDbKDhuPs/IGICkC7MKTInMbSGTLxPTDmtq445q
         6mTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=euCJ3aaL;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b9639d7b4bsi183918fac.4.2025.02.14.08.19.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 08:19:00 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qv1-f71.google.com (mail-qv1-f71.google.com
 [209.85.219.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-543-tpBJUioHPXyA6xSLlUejBA-1; Fri, 14 Feb 2025 11:18:56 -0500
X-MC-Unique: tpBJUioHPXyA6xSLlUejBA-1
X-Mimecast-MFC-AGG-ID: tpBJUioHPXyA6xSLlUejBA_1739549936
Received: by mail-qv1-f71.google.com with SMTP id 6a1803df08f44-6e65a429164so49331896d6.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 08:18:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUl9UUhrDmCsRhHliE4NfL/7Z4UdWdvPeOcrQeCNrxDqhLTgFVKe257V3/kiJTNCMXtA6jy0JZBT9Q=@googlegroups.com
X-Gm-Gg: ASbGncscRpaeNwv1VGcu1znsTnFPackNunvuwvC4GaHSP7vPHWHw659mksXICW3nch1
	nM7+UHBEVcb84HBf515ZiELBCAa9Eb0SSXPJFr64fsUYuMtAaojvT7DGWkPyKhi3rqxh/12KlW1
	bVFqB3T9sFAnc/cxf/Od+388l9xldhxqHW+uFKRJZZVU7b2L5VDHl+EjbIWqG19BCKJjae+V/+Q
	FQCADF4fPg29fJ6PY/cVNvFpxi8xF0BJzG+CxQ1CcyBZlczI6GEqW9D9Vz9A/OXCi/3WKb8T3Ml
	ZqexTy8HvTsK5cKV/4bBpveXWpmZclF4irmSCqvBZCY0UPjk
X-Received: by 2002:ad4:5be2:0:b0:6e4:41a0:3bdb with SMTP id 6a1803df08f44-6e46ed88629mr171075146d6.26.1739549935612;
        Fri, 14 Feb 2025 08:18:55 -0800 (PST)
X-Received: by 2002:ad4:5be2:0:b0:6e4:41a0:3bdb with SMTP id 6a1803df08f44-6e46ed88629mr171074406d6.26.1739549934937;
        Fri, 14 Feb 2025 08:18:54 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e65d9f46a8sm22145466d6.82.2025.02.14.08.18.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 08:18:54 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <f2f006e8-3987-4aa2-b4f5-114b4e869e86@redhat.com>
Date: Fri, 14 Feb 2025 11:18:52 -0500
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
X-Mimecast-MFC-PROC-ID: G0vzlozlkvABmSEA76y1PhTKey0YqkS5eGBgzyRq_CU_1739549936
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=euCJ3aaL;
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
>>>> incur unnecessary performance overhead. However, the lockdep_map point=
er
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
>>>> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_e=
vents_list.h
>>>> index 9ef9850aeebe..bed59b2195c7 100644
>>>> --- a/kernel/locking/lock_events_list.h
>>>> +++ b/kernel/locking/lock_events_list.h
>>>> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handl=
e_deadlock()'s    */
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
>>>> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, uns=
igned int subclass,
>>>>           if (!debug_locks)
>>>>                   return;
>>>>
>>>> +       /*
>>>> +        * As KASAN instrumentation is disabled and lock_acquire() is =
usually
>>>> +        * the first lockdep call when a task tries to acquire a lock,=
 add
>>>> +        * kasan_check_byte() here to check for use-after-free of non =
kernel
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

The kasan_check_byte() failure happens very early in the boot cycle.=20
There is no KASAN report, but the API returns false. I inserted a=20
WARN_ON(1) to dump out the stack.

[=C2=A0=C2=A0=C2=A0 0.000046] ------------[ cut here ]------------
[=C2=A0=C2=A0=C2=A0 0.000047] WARNING: CPU: 0 PID: 0 at kernel/locking/lock=
dep.c:5817=20
lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000057] Modules linked in:
[=C2=A0=C2=A0=C2=A0 0.000062] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainte=
d=20
6.12.0-el10-test+ #15
[=C2=A0=C2=A0=C2=A0 0.000066] Hardware name: HPE ProLiant DL560 Gen10/ProLi=
ant DL560=20
Gen10, BIOS U34 01/16/2025
[=C2=A0=C2=A0=C2=A0 0.000068] RIP: 0010:lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000073] Code: 69 d1 04 85 c0 0f 85 fc fe ff ff 65 48 =
8b 3d 2b d8=20
c1 75 b9 0a 00 00 00 ba 08 00 00 00 4c 89 ee e8 19 e3 ff ff e9 dd fe ff=20
ff <0f>
0b 65 48 ff 05 ca 5f c0 75 e9 ce fe ff ff 4c 89 14 24 e8 bc f8
[=C2=A0=C2=A0=C2=A0 0.000076] RSP: 0000:ffffffff8e407c98 EFLAGS: 00010046 O=
RIG_RAX:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000079] RAX: 0000000000000000 RBX: ffffffff8e54fe70 R=
CX:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000081] RDX: 0000000000000000 RSI: 0000000000000001 R=
DI:=20
ffffffff8e407c40
[=C2=A0=C2=A0=C2=A0 0.000083] RBP: 0000000000000000 R08: 0000000000000001 R=
09:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000084] R10: ffffffff8a43af29 R11: 00000000002087cc R=
12:=20
0000000000000001
[=C2=A0=C2=A0=C2=A0 0.000087] R13: 0000000000000000 R14: 0000000000000000 R=
15:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000088] FS:=C2=A0 0000000000000000(0000) GS:ffffffff8=
fb88000(0000)=20
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000090] CS:=C2=A0 0010 DS: 0000 ES: 0000 CR0: 0000000=
080050033
[=C2=A0=C2=A0=C2=A0 0.000093] CR2: ffff888000000413 CR3: 0000001fc96e0000 C=
R4:=20
00000000000000f0
[=C2=A0=C2=A0=C2=A0 0.000095] Call Trace:
[=C2=A0=C2=A0=C2=A0 0.000096]=C2=A0 <TASK>
[=C2=A0=C2=A0=C2=A0 0.000101]=C2=A0 ? show_trace_log_lvl+0x1b0/0x2f0
[=C2=A0=C2=A0=C2=A0 0.000105]=C2=A0 ? show_trace_log_lvl+0x1b0/0x2f0
[=C2=A0=C2=A0=C2=A0 0.000119]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000124]=C2=A0 ? __warn.cold+0x5b/0xe5
[=C2=A0=C2=A0=C2=A0 0.000133]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000138]=C2=A0 ? report_bug+0x1f0/0x390
[=C2=A0=C2=A0=C2=A0 0.000146]=C2=A0 ? early_fixup_exception+0x145/0x230
[=C2=A0=C2=A0=C2=A0 0.000154]=C2=A0 ? early_idt_handler_common+0x2f/0x3a
[=C2=A0=C2=A0=C2=A0 0.000164]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000172]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000177]=C2=A0 ? lock_acquire.part.0+0x3f/0x280
[=C2=A0=C2=A0=C2=A0 0.000182]=C2=A0 ? rcu_is_watching+0x15/0xb0
[=C2=A0=C2=A0=C2=A0 0.000187]=C2=A0 ? __pfx___might_resched+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000192]=C2=A0 ? lock_acquire+0x120/0x170
[=C2=A0=C2=A0=C2=A0 0.000195]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000201]=C2=A0 ? rt_write_lock+0x7d/0x110
[=C2=A0=C2=A0=C2=A0 0.000208]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000211]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000217]=C2=A0 ? probe_roms+0x150/0x370
[=C2=A0=C2=A0=C2=A0 0.000222]=C2=A0 ? __pfx_probe_roms+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000226]=C2=A0 ? __lock_release.isra.0+0x120/0x2c0
[=C2=A0=C2=A0=C2=A0 0.000231]=C2=A0 ? setup_arch+0x92d/0x1180
[=C2=A0=C2=A0=C2=A0 0.000238]=C2=A0 ? setup_arch+0x95c/0x1180
[=C2=A0=C2=A0=C2=A0 0.000243]=C2=A0 ? __pfx_setup_arch+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000246]=C2=A0 ? _printk+0xcc/0x102
[=C2=A0=C2=A0=C2=A0 0.000254]=C2=A0 ? __pfx__printk+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000259]=C2=A0 ? cgroup_init_early+0x26a/0x290
[=C2=A0=C2=A0=C2=A0 0.000268]=C2=A0 ? cgroup_init_early+0x26a/0x290
[=C2=A0=C2=A0=C2=A0 0.000271]=C2=A0 ? cgroup_init_early+0x1af/0x290
[=C2=A0=C2=A0=C2=A0 0.000279]=C2=A0 ? start_kernel+0x68/0x3b0
[=C2=A0=C2=A0=C2=A0 0.000285]=C2=A0 ? x86_64_start_reservations+0x24/0x30
[=C2=A0=C2=A0=C2=A0 0.000288]=C2=A0 ? x86_64_start_kernel+0x9c/0xa0
[=C2=A0=C2=A0=C2=A0 0.000292]=C2=A0 ? common_startup_64+0x13e/0x141
[=C2=A0=C2=A0=C2=A0 0.000309]=C2=A0 </TASK>
[=C2=A0=C2=A0=C2=A0 0.000311] irq event stamp: 0
[=C2=A0=C2=A0=C2=A0 0.000312] hardirqs last=C2=A0 enabled at (0): [<0000000=
000000000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000316] hardirqs last disabled at (0): [<000000000000=
0000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000318] softirqs last=C2=A0 enabled at (0): [<0000000=
000000000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000320] softirqs last disabled at (0): [<000000000000=
0000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000322] ---[ end trace 0000000000000000 ]---
[=C2=A0=C2=A0=C2=A0 0.000331] ------------[ cut here ]------------
[=C2=A0=C2=A0=C2=A0 0.000332] WARNING: CPU: 0 PID: 0 at kernel/locking/lock=
dep.c:5817=20
lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000336] Modules linked in:
[=C2=A0=C2=A0=C2=A0 0.000339] CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=20
W=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 -------=C2=A0 ---=C2=A0 6=
.12.0-el10-test+ #15
[=C2=A0=C2=A0=C2=A0 0.000343] Tainted: [W]=3DWARN
[=C2=A0=C2=A0=C2=A0 0.000345] Hardware name: HPE ProLiant DL560 Gen10/ProLi=
ant DL560=20
Gen10, BIOS U34 01/16/2025
[=C2=A0=C2=A0=C2=A0 0.000346] RIP: 0010:lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000350] Code: 69 d1 04 85 c0 0f 85 fc fe ff ff 65 48 =
8b 3d 2b d8=20
c1 75 b9 0a 00 00 00 ba 08 00 00 00 4c 89 ee e8 19 e3 ff ff e9 dd fe ff=20
ff <0f>
0b 65 48 ff 05 ca 5f c0 75 e9 ce fe ff ff 4c 89 14 24 e8 bc f8
[=C2=A0=C2=A0=C2=A0 0.000352] RSP: 0000:ffffffff8e407c20 EFLAGS: 00010046 O=
RIG_RAX:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000354] RAX: 0000000000000000 RBX: ffffffff8e54fe20 R=
CX:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000356] RDX: 0000000000000000 RSI: 0000000000000001 R=
DI:=20
ffffffff8e407bc8
[=C2=A0=C2=A0=C2=A0 0.000357] RBP: 0000000000000000 R08: 0000000000000001 R=
09:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000359] R10: ffffffff8ccf84d2 R11: 00000000002087cc R=
12:=20
0000000000000001
[=C2=A0=C2=A0=C2=A0 0.000360] R13: 0000000000000000 R14: 0000000000000000 R=
15:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000362] FS:=C2=A0 0000000000000000(0000) GS:ffffffff8=
fb88000(0000)=20
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0 0.000364] CS:=C2=A0 0010 DS: 0000 ES: 0000 CR0: 0000000=
080050033
[=C2=A0=C2=A0=C2=A0 0.000365] CR2: ffff888000000413 CR3: 0000001fc96e0000 C=
R4:=20
00000000000000f0
[=C2=A0=C2=A0=C2=A0 0.000367] Call Trace:
[=C2=A0=C2=A0=C2=A0 0.000368]=C2=A0 <TASK>
[=C2=A0=C2=A0=C2=A0 0.000369]=C2=A0 ? show_trace_log_lvl+0x1b0/0x2f0
[=C2=A0=C2=A0=C2=A0 0.000373]=C2=A0 ? show_trace_log_lvl+0x1b0/0x2f0
[=C2=A0=C2=A0=C2=A0 0.000386]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000391]=C2=A0 ? __warn.cold+0x5b/0xe5
[=C2=A0=C2=A0=C2=A0 0.000396]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000400]=C2=A0 ? report_bug+0x1f0/0x390
[=C2=A0=C2=A0=C2=A0 0.000407]=C2=A0 ? early_fixup_exception+0x145/0x230
[=C2=A0=C2=A0=C2=A0 0.000412]=C2=A0 ? early_idt_handler_common+0x2f/0x3a
[=C2=A0=C2=A0=C2=A0 0.000419]=C2=A0 ? rwbase_write_lock.constprop.0.isra.0+=
0x22/0x5f0
[=C2=A0=C2=A0=C2=A0 0.000427]=C2=A0 ? lock_acquire.part.0+0x22c/0x280
[=C2=A0=C2=A0=C2=A0 0.000434]=C2=A0 ? rcu_is_watching+0x15/0xb0
[=C2=A0=C2=A0=C2=A0 0.000438]=C2=A0 ? lock_acquire+0x120/0x170
[=C2=A0=C2=A0=C2=A0 0.000441]=C2=A0 ? rwbase_write_lock.constprop.0.isra.0+=
0x22/0x5f0
[=C2=A0=C2=A0=C2=A0 0.000448]=C2=A0 ? _raw_spin_lock_irqsave+0x46/0x90
[=C2=A0=C2=A0=C2=A0 0.000451]=C2=A0 ? rwbase_write_lock.constprop.0.isra.0+=
0x22/0x5f0
[=C2=A0=C2=A0=C2=A0 0.000456]=C2=A0 ? rwbase_write_lock.constprop.0.isra.0+=
0x22/0x5f0
[=C2=A0=C2=A0=C2=A0 0.000459]=C2=A0 ? lock_acquire+0x120/0x170
[=C2=A0=C2=A0=C2=A0 0.000462]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000468]=C2=A0 ? rt_write_lock+0x85/0x110
[=C2=A0=C2=A0=C2=A0 0.000471]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000475]=C2=A0 ? request_resource+0x29/0x2b0
[=C2=A0=C2=A0=C2=A0 0.000480]=C2=A0 ? probe_roms+0x150/0x370
[=C2=A0=C2=A0=C2=A0 0.000484]=C2=A0 ? __pfx_probe_roms+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000488]=C2=A0 ? __lock_release.isra.0+0x120/0x2c0
[=C2=A0=C2=A0=C2=A0 0.000493]=C2=A0 ? setup_arch+0x92d/0x1180
[=C2=A0=C2=A0=C2=A0 0.000500]=C2=A0 ? setup_arch+0x95c/0x1180
[=C2=A0=C2=A0=C2=A0 0.000505]=C2=A0 ? __pfx_setup_arch+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000508]=C2=A0 ? _printk+0xcc/0x102
[=C2=A0=C2=A0=C2=A0 0.000513]=C2=A0 ? __pfx__printk+0x10/0x10
[=C2=A0=C2=A0=C2=A0 0.000517]=C2=A0 ? cgroup_init_early+0x26a/0x290
[=C2=A0=C2=A0=C2=A0 0.000525]=C2=A0 ? cgroup_init_early+0x26a/0x290
[=C2=A0=C2=A0=C2=A0 0.000528]=C2=A0 ? cgroup_init_early+0x1af/0x290
[=C2=A0=C2=A0=C2=A0 0.000535]=C2=A0 ? start_kernel+0x68/0x3b0
[=C2=A0=C2=A0=C2=A0 0.000539]=C2=A0 ? x86_64_start_reservations+0x24/0x30
[=C2=A0=C2=A0=C2=A0 0.000543]=C2=A0 ? x86_64_start_kernel+0x9c/0xa0
[=C2=A0=C2=A0=C2=A0 0.000547]=C2=A0 ? common_startup_64+0x13e/0x141
[=C2=A0=C2=A0=C2=A0 0.000561]=C2=A0 </TASK>
[=C2=A0=C2=A0=C2=A0 0.000562] irq event stamp: 0
[=C2=A0=C2=A0=C2=A0 0.000563] hardirqs last=C2=A0 enabled at (0): [<0000000=
000000000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000565] hardirqs last disabled at (0): [<000000000000=
0000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000567] softirqs last=C2=A0 enabled at (0): [<0000000=
000000000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000569] softirqs last disabled at (0): [<000000000000=
0000>] 0x0
[=C2=A0=C2=A0=C2=A0 0.000571] ---[ end trace 0000000000000000 ]---

Cheers,
Longman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
2f006e8-3987-4aa2-b4f5-114b4e869e86%40redhat.com.
