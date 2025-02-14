Return-Path: <kasan-dev+bncBCPILY4NUAFBBKU5XW6QMGQE6277K7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E009A35FE5
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 15:09:48 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6e637c24051sf38282156d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2025 06:09:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739542187; cv=pass;
        d=google.com; s=arc-20240605;
        b=ExhfpMMEVJ5fmMqRm22i0WtRfsTNQ6acZ5Hqo7cLdq5YccyijmgftAQ2sFlbHdHUNc
         e7XLMwY0X9UGUbbDbT1OFe6o/sQjH7iyfz7IVKltsGL5sxQPv4sxtUnH4zzpeidO2bT2
         ultMEniaIZkItth7j72IvP3b4LBeIzcMskCNFfeWRE9em9Cd3d2v7897JYl5ASB0CzT1
         Q2jJZeTLD4OQJ5df7ACP6pwBER8ML2vteIuEhGTmPY7ixSf/3kHTcwvoIojoIMBaq3WZ
         lwo1MHBRJqziMRb2At1anYb+1rgKYhFiXk2qpmMKmySCNbwpbizOgkgc5vmODfl67645
         T2HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=heQuVC7DDG+imo1NvAQIHuaiFRnMnixt6wbfBWz/g/Y=;
        fh=srvkSDgNh1UlYOZVef0sUoRqb9/igT3fJE2Vcb4bPxs=;
        b=ioRwHQFkg2u8ctj0YNVPo6hMWNQZQ5CQnu+6wqnSGafcXk5Bfd4iNdtb12zf/ZfrJC
         TBLkfDzj9ZDuP/qjperxWRoMUu0r4LKRxlBjDNVBKUPVjauxseoH4ISBETbxfgVVXydV
         CXM5jO0iEYi9nqqV9X+mNsIAYDsNt64a3hYkWcxG9BLS+VP+DPSSMjCdxT5FXPR95rVr
         92FCJsOxxutqOMfcwEoDKaoiF5VSGLOrd4CKbOpZJyfWH4k5PHa1Vc59Tevuu46nZiTt
         +yixLNpun4Y000QrCmhxWBeQF7zYDBKBl3cMwl1q7uasCyGUOhp9Fu1V79dfRxBhaOSH
         fJYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PPNJrGj3;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739542187; x=1740146987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=heQuVC7DDG+imo1NvAQIHuaiFRnMnixt6wbfBWz/g/Y=;
        b=CNTw7ibGkIgdPU25WXL3ybwZKKv1c2psdtmJeWnId2gxP3U2v2+3iCLBzMEeq4l2Uz
         WgGrrCs6JohRXRkFhC6nnFbu5s3RzMvHMnU7C8Q6sV0K2eC80PFGkl0V+ipHfLpgaE2F
         yztT7GkyJoE+pMeycsMHX3XractjjChGR6x3SMAq7vrrGORYKa5+PcNqH1DV3QreJqCb
         aTR2rtfhLto++OMYzKKsP6gp/JQ3gaf+IHCuiKwLF29hNbUCpXghaMzFpkt/wSgSKoVC
         RLz+egPSaBZq7t0/tA6z3nArJRDl6rByvlT/6ya4+J6TT10MqsLaemadjXsHEjRWcSok
         InlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739542187; x=1740146987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=heQuVC7DDG+imo1NvAQIHuaiFRnMnixt6wbfBWz/g/Y=;
        b=hqR6mp0UOl4AFg653xOwXQXGsoBEXsbCQRWP1j9jRX43Gs3aLlFVynnnWVYtKwGG9e
         3jCCKsx7m763N6SkRS6oSlZEcU6AtQmHRRjfE4IHdkmWU3+Xg7gWH85gCZgd5TlVWky8
         VDTnJCgn2xJIU5dadrxt2AxikrQoQYAgJRFMuJ1S0U25vGblpb/sHyAFW1OsW9oH71aT
         zmqyul2GTNuYbRWoncQEXJaMVLDQudQ3XVLGEc4nCn/qPkk2y/21nd+/VzRL9HvxbW1f
         H06eE0cFWq9mSNV0HEZShH2kFKBmdgiSnUDeKTfYM8EhtIJr5Yb3Xk250lBsndIdH0YY
         2l8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVv52OhoMHpxMdUS66yjiu0eFl5hiFdCmCnrYQ5pUHZxAxr8mjN9UY6SSNuRbNOab5FICntMw==@lfdr.de
X-Gm-Message-State: AOJu0YxJzR4uINhEwYbRR2PlW+lemrdhzJgqSl0/zJAmm0NRF1cVxI/q
	G19wQ3PKLRbGdyGxxYPrqKaWj8T9gCCaJqd+Ycdfj3YV33G8RBMd
X-Google-Smtp-Source: AGHT+IHZM3emh7x5tj7ZoFRYsWPKQvRKxvCSf6KuypRmqtTMtf6l72EZY9CuoY8Y9rcff4GGopHu8w==
X-Received: by 2002:a05:6214:130f:b0:6cb:d1ae:27a6 with SMTP id 6a1803df08f44-6e46ed8b028mr157177716d6.24.1739542186800;
        Fri, 14 Feb 2025 06:09:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG0LyKp5kXenkWHFZrYFlncDvi+UXcJTRQCrpydToXdlg==
Received: by 2002:a0c:aa18:0:b0:6e6:58a4:e16 with SMTP id 6a1803df08f44-6e65c2588a9ls16252166d6.2.-pod-prod-03-us;
 Fri, 14 Feb 2025 06:09:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVOyoqxzgFV+LnoVmJD2wESjNl9TGFiW2vvgk/aQgH3bvDdT0EBfAKDN0QrvPSlKLQUaXMN2wwzjoY=@googlegroups.com
X-Received: by 2002:ad4:5ece:0:b0:6e6:5efa:4dfa with SMTP id 6a1803df08f44-6e65efa4fb2mr90429476d6.21.1739542185308;
        Fri, 14 Feb 2025 06:09:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739542185; cv=none;
        d=google.com; s=arc-20240605;
        b=ifb0sz0fhl09eVpIH5TXA56AD5bg31nG6p0G9JX/JKC0S1QdYfo9XOQRBXWvaJ2+ER
         lfhAfmbF2ueWImUraPY8mQ+Th7l6COOvF7+9Q2YiMxgGzKCR+gHr6Q0gqm9t7BE8WNP0
         dJn6rvroyi80gyhojoLQTROtWDFPo0WwztjLHQKcieDI7RzAV3JOmJo4UUvojM8jFmOS
         f182TPOoF+p9r7/kLoIKgj4WcQP2Q7gesPWLlIpf9lC/xGbUYasATqqna9DuZK4cjg9R
         Y+rmQ50mWXASSAW8PRGeI6eiZ83LJm3jQRTt/vOBf1RhaySORmlB04G4W2uMBDplA0Ut
         e0UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=cvGobuu5yf2ROvpcfD7xIalvhR+r0zTyAfpxi1cLeBw=;
        fh=RTjAg/cHjB0l6qs0BnmGuyX7HXZWFbPEH03acsJHM48=;
        b=KLaN3An+WMB1WVJYYgphP6lke2KbmMSt9flc6Kms71BUH/ULmWvqJ+P+gJ0uxdVfiM
         MVILP10JcqJ2qnQqcops9yBT6TXFdYSlmj7fPWS4j8sQ7jgiismfSPjsDGaaEBzlP4Y8
         t2mEYIESXu4yuT6yLC3oyTBS58XjORulqSfwkJT1c5tH9GNie8u+pYPmtUilyBc4/+eQ
         kP2o9bEnc4HCZ21yvE4fmofCugAykFupONXmI2z/YAStIwNPGE3zqunYeZzaaF9Qj3w7
         DVgzx3gzyXE4War47Mi/AGjeLgLpC/+GPZ9gN2tbyZh8EmUXToE+7VvkQxhzamiqwS5n
         J4oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=PPNJrGj3;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-868e85a11f5si144245241.2.2025.02.14.06.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2025 06:09:45 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-qv1-f70.google.com (mail-qv1-f70.google.com
 [209.85.219.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-132-V6TLch79MOOS4N-DJKLW4w-1; Fri, 14 Feb 2025 09:09:40 -0500
X-MC-Unique: V6TLch79MOOS4N-DJKLW4w-1
X-Mimecast-MFC-AGG-ID: V6TLch79MOOS4N-DJKLW4w_1739542180
Received: by mail-qv1-f70.google.com with SMTP id 6a1803df08f44-6e664e086f1so17734506d6.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2025 06:09:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX7HVBNH0ImLmrlYeWZA6tFB81EPHd56+hP4RF0rP//cVuGakHoZBe+U5FVPIEKs2NYNkSF8938lEg=@googlegroups.com
X-Gm-Gg: ASbGncuddkKrMw3tLc4HRUvYqCEVQ1cImfE2f2ruLwgb6lCZVcqwpSZ4AAr6B9rfHBq
	EX5YFu4W4eP2ASriIukeyw+1zJ4YLX00pPfuE1F/BO4zLBQ/0l3yRlvubTanR8el1jrEFuLCuBC
	we3c7vygNYjeC4OU+0yVd/pv+wvaMnip457nhlP9ErjtwUePL+yoysM4ss96ZHCsu+UwYWTlgPt
	XUjMucj1hlHYi45veWRKiGcv9c0lsVX5DXQ92zxTlX4nqHUkKF4Rzdog/Z9x3NI6v/Pp2aTt/fh
	GdAEIg9xSPPjVvPQzCwe7+PtYaYyamLLn7TMm+PGabLgwUJj
X-Received: by 2002:a05:6214:21ed:b0:6e6:69e4:650d with SMTP id 6a1803df08f44-6e669e46531mr16751796d6.20.1739542180126;
        Fri, 14 Feb 2025 06:09:40 -0800 (PST)
X-Received: by 2002:a05:6214:21ed:b0:6e6:69e4:650d with SMTP id 6a1803df08f44-6e669e46531mr16751416d6.20.1739542179802;
        Fri, 14 Feb 2025 06:09:39 -0800 (PST)
Received: from ?IPV6:2601:188:c100:5710:627d:9ff:fe85:9ade? ([2601:188:c100:5710:627d:9ff:fe85:9ade])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-6e65d785bdbsm21242156d6.38.2025.02.14.06.09.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2025 06:09:39 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <3d069c26-4971-415a-9751-a28d207feb43@redhat.com>
Date: Fri, 14 Feb 2025 09:09:37 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 4/4] locking/lockdep: Add kasan_check_byte() check in
 lock_acquire()
To: Marco Elver <elver@google.com>
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
In-Reply-To: <CANpmjNM-uN81Aje1GE9zgUW-Q=w_2gPQ28giO7N2nmbRM521kA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: G-QGhk0DId5SCsaI7WSpBMoKKOtZ0qQfzw74tQ5mPRY_1739542180
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=PPNJrGj3;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
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

On 2/14/25 5:44 AM, Marco Elver wrote:
> On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
>> KASAN instrumentation of lockdep has been disabled as we don't need
>> KASAN to check the validity of lockdep internal data structures and
>> incur unnecessary performance overhead. However, the lockdep_map pointer
>> passed in externally may not be valid (e.g. use-after-free) and we run
>> the risk of using garbage data resulting in false lockdep reports. Add
>> kasan_check_byte() call in lock_acquire() for non kernel core data
>> object to catch invalid lockdep_map and abort lockdep processing if
>> input data isn't valid.
>>
>> Suggested-by: Marco Elver <elver@google.com>
>> Signed-off-by: Waiman Long <longman@redhat.com>
> Reviewed-by: Marco Elver <elver@google.com>
>
> but double-check if the below can be simplified.
>
>> ---
>>   kernel/locking/lock_events_list.h |  1 +
>>   kernel/locking/lockdep.c          | 14 ++++++++++++++
>>   2 files changed, 15 insertions(+)
>>
>> diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
>> index 9ef9850aeebe..bed59b2195c7 100644
>> --- a/kernel/locking/lock_events_list.h
>> +++ b/kernel/locking/lock_events_list.h
>> @@ -95,3 +95,4 @@ LOCK_EVENT(rtmutex_deadlock)  /* # of rt_mutex_handle_deadlock()'s    */
>>   LOCK_EVENT(lockdep_acquire)
>>   LOCK_EVENT(lockdep_lock)
>>   LOCK_EVENT(lockdep_nocheck)
>> +LOCK_EVENT(lockdep_kasan_fail)
>> diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
>> index 8436f017c74d..98dd0455d4be 100644
>> --- a/kernel/locking/lockdep.c
>> +++ b/kernel/locking/lockdep.c
>> @@ -57,6 +57,7 @@
>>   #include <linux/lockdep.h>
>>   #include <linux/context_tracking.h>
>>   #include <linux/console.h>
>> +#include <linux/kasan.h>
>>
>>   #include <asm/sections.h>
>>
>> @@ -5830,6 +5831,19 @@ void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
>>          if (!debug_locks)
>>                  return;
>>
>> +       /*
>> +        * As KASAN instrumentation is disabled and lock_acquire() is usually
>> +        * the first lockdep call when a task tries to acquire a lock, add
>> +        * kasan_check_byte() here to check for use-after-free of non kernel
>> +        * core lockdep_map data to avoid referencing garbage data.
>> +        */
>> +       if (unlikely(IS_ENABLED(CONFIG_KASAN) &&
> This is not needed - kasan_check_byte() will always return true if
> KASAN is disabled or not compiled in.
I added this check because of the is_kernel_core_data() call.
>
>> +                    !is_kernel_core_data((unsigned long)lock) &&
> Why use !is_kernel_core_data()? Is it to improve performance?

Not exactly. In my testing, just using kasan_check_byte() doesn't quite 
work out. It seems to return false positive in some cases causing 
lockdep splat. I didn't look into exactly why this happens and I added 
the is_kernel_core_data() call to work around that.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3d069c26-4971-415a-9751-a28d207feb43%40redhat.com.
