Return-Path: <kasan-dev+bncBDAMN6NI5EERBIUI6SGQMGQEWM5SJ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DF399479667
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 22:41:54 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id h18-20020a05651c159200b0021cf7c089d0sf1021678ljq.21
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 13:41:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639777314; cv=pass;
        d=google.com; s=arc-20160816;
        b=aJs3FKhu8dIWKpxSFwnLsYMjPUZE3ujDdAe5WAxDOS6KoZ6o7kaOhsDOFIo34u4V0E
         u4r65aLE36IsrvYDKmOO9AC38srwJY3BT7LNa+UB25JMpIsFP4u4h2y1aVQlnSEdbxyq
         La42JtZ85LyCkzpVyPGwWwsJ1K28bATCTT3d+OCu8Y7yuoCVeeQ8mkr1eLBXYrfoUw6C
         TMWvgeJeMr1EFtyCK2IdN3rMRFcJcxlnVYY0ViJe6Ma9FRUUqemUR6TLdxoQBcKwk8j2
         5mtiWlfTrKE9Gg7t1SZVmUj7dh5yAmmI7+UBbmg3r7WQtkdqcFpmqLX6P4DatnBzgvY2
         ekUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=7kHn7q4NR8XT5i2UnenRtgL+Nju3t5NOo9fcBayEpu8=;
        b=EQkBahQEjpsCf2Lg4F3GjeBJ3PpJOGzszQs+caYYiQq7/JYZLYrZYDq70nM7txmnk8
         17fq731Kr++s0aYmClrfN3fDsvIrHjKtMrbAY4kPLLo+r2MqUqte5nGk7hyENQpE8Hkd
         bITOY8orHz5n337U4PlioS9Y4sfKYnCrj2W9IZzRPVAH7tWsDxBrhTC6JimSgcNXwzYN
         23vnQDdngyoYFC48VhTV2iahxAIha99WCaqYD0m2U+BNEZAOmI6xCqUzLyXS1LRdjLJZ
         TZGGtZoPmqNXNQKw4tOwK0TNEklBbPDriw4RNCg1nzeR5k1cDT5HlaRGehxwdzZqHulU
         23NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qv1nFbWt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kHn7q4NR8XT5i2UnenRtgL+Nju3t5NOo9fcBayEpu8=;
        b=hM5cNE2zVhM8Hn8qt8GLX8/Viyo1KPU95eBnsfNLEqhOzohVSTUhhHH8YPumTdNRMw
         bOVRs+HS/Zs1xn3YQn4CBPU/q83wRXy/GV9RyA9aoY+9dbZ3AEZvgLNqGPe5HHWRetC1
         GLcuU8s7EdP0t71oxz+nfYh5UcGg3LX/S/0ZWVsz+VE7DAY1WfEspHhvjYVeMxQ5+SxW
         AVi5Q62epBawlRtlmbPUO2ZPjMTE+tYYCa4bjFsi5l6qNPtm/4qaZi124eO9WI9VLAVq
         h9WIirID8daDcCvm06VhfIxtCsW4MBNgjuBh3ytNnJw/GwKz3wKcxC970nWo8EbiBzR8
         Djsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kHn7q4NR8XT5i2UnenRtgL+Nju3t5NOo9fcBayEpu8=;
        b=E2yMDdKwmcdoVl2PvtEz7JHNQgLmc5bhlcC9BuSRilqQVHhZZ2hjy0NAfJmXoayJsQ
         98v40fG+3oPovpPX30IsO3/AEDC3qD9fW2o9drt3+g50MXovtj85aAR+nHTog3InuoSd
         rmDvDFCMMHPuQkKi3WxG7tYJc6I3RpxEzl5m5CXrXy4ivdB8qyhJ73TBMx33FWQ0jHHg
         HSFPONNxhuKQMEjaLKWRn8GKObDbzzf56xF8dUOJErNQ5X0RdDnh4tML11ltiHdx04/0
         Yro7e/cxgPTW7vj1FHPKqCSvZOzZSv5bqnkwHbi3xSmbbO3VvKSVECigmA25ANiiX5BL
         d2LQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w3fgOKoRrZqF4BfxZOAYoue3NDOfa+W8CwJDRU3i7q0efp8tU
	riD5QEA44T9ouxF20SBl3Wc=
X-Google-Smtp-Source: ABdhPJyX/bdTbb9uZ8BJaHYFj58nDDSq4kC7sf1S9D4ifQK5DLdaPWhlDyJgux0FFQzArCiDfCpXlg==
X-Received: by 2002:a05:651c:1049:: with SMTP id x9mr4277735ljm.121.1639777314345;
        Fri, 17 Dec 2021 13:41:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls1734204lji.1.gmail; Fri, 17 Dec
 2021 13:41:53 -0800 (PST)
X-Received: by 2002:a2e:a376:: with SMTP id i22mr4375805ljn.201.1639777313420;
        Fri, 17 Dec 2021 13:41:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639777313; cv=none;
        d=google.com; s=arc-20160816;
        b=Us954XB7/4X3s1UYONcv+892U/rmbDnNu/y0Y9bM3JURjt7DaXdw9kQo0fUN8USNkR
         +cyk/77ECgMwpLGZdP+J/10Wb/LpSWAPnV2S8y20QydjVr08yogya8jUzwWmCnkrwlG5
         SQA4He/i60sSNDeWgnjVT6igr4F6KrjnkHPU+sKJLv4h9oJo/QCJvwrqNlojrHnKL6Bo
         EMf3aCl6eDgYdRJys0R/N6w8BUnSIPLL4IBFM7ZBtazldQxcdBS4HwASXnhq8XULzniY
         srSsgubt46ZJwhVh2HAU2daf35MF/SttOZE1l7BuRcoqf+jmC01S2d9nmPly9OqyJwW7
         lAsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=5y3J7Tby5HG9Z/kf8KBxRk8HRJWB6fZTjqhP8qW1XRc=;
        b=Q6IK0Pi+LVVugrOI5SQpAGQuBsWNCW3QiKaDbx72QoF8HlGOBxmgFjILllvGJjHG29
         +DRTu0NGVeR8nPLNxi3OGCCbwC5ACWdvYiFHifot9O/SEApQnngAkvRpEQY0H1jr/qjE
         ItqbvTPhWBDejGj977jMqftbIrVpBolmEeUnc3flh5nCS+PnqAq0c55izZDzS3Nj11fY
         NAF5NwP2mOZxZ94HfTzQ4ImP+dq4lc8V73dG2GQ2hRMPIYMy28oFFPd5cqMDwC8UUi9W
         gGVUl/+5W1HaUB/ePabZiN0txbuttFNiBgCL/QSD/QQjJZJASYV6oFHkFT5D5vdk8p12
         VXew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=qv1nFbWt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id j15si42662lfg.9.2021.12.17.13.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Dec 2021 13:41:53 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Waiman Long <longman@redhat.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, Will
 Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>,
 linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, Mark Rutland <mark.rutland@arm.com>, "Paul
 E. McKenney" <paulmck@kernel.org>, Kefeng Wang
 <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH] locking/mutex: Mark racy reads of owner->on_cpu
In-Reply-To: <2f67a2d9-98d6-eabd-fb5e-4c89574ce52c@redhat.com>
References: <20211202101238.33546-1-elver@google.com>
 <CANpmjNMvPepakONMjTO=FzzeEtvq_CLjPN6=zF35j10rVrJ9Fg@mail.gmail.com>
 <2f67a2d9-98d6-eabd-fb5e-4c89574ce52c@redhat.com>
Date: Fri, 17 Dec 2021 22:41:51 +0100
Message-ID: <87ee6ac3j4.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=qv1nFbWt;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Thu, Dec 02 2021 at 10:46, Waiman Long wrote:
> On 12/2/21 06:53, Marco Elver wrote:
> I would like to see owner_on_cpu() extracted out from 
> kernel/locking/rwsem.c into include/linux/sched.h right after 
> vcpu_is_preempted(), for instance, and with READ_ONCE() added. Then it 
> can be used in mutex.c as well. This problem is common to both mutex and 
> rwsem.

And rtmutex.c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ee6ac3j4.ffs%40tglx.
