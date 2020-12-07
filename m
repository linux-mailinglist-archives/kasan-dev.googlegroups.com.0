Return-Path: <kasan-dev+bncBDAMN6NI5EERBYHYXD7AKGQEGLF54QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 370B42D13AD
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 15:29:53 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id q15sf4679123ljp.23
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 06:29:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607351392; cv=pass;
        d=google.com; s=arc-20160816;
        b=yzAyAzF41KHLNan0Bx7UXkQz1b32SL9Yx5IHd1DvHsA/xHsACSp/XNEMIcCOJ5mxQz
         8Ty3Zp0n0cYF0ELQoB0RDI9GvrB3+K+aoVtYUHyCD76EJzCrtxpvMyqz7hSw8O4ME82Y
         Sww4Rqu4+kaFV3EKR6wKySvtdfmeNUSd9WDHkGhnhyi1HQg91OZc1nQz4BS1Z+dKdXie
         av1YXCtTWyf1lZr7LP2o2ge0rJcM+pYJ0L/4qCRkTw2V7bsUf1w/iEkDSfcL04x+7wP2
         pvyby3w98d6cLhchC7rAsH2sSOJMo/+3E7+EcI+ypAYLKmaXy261iz7HIKjbpn3YJrQc
         hEbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=He0Fc7RcTcfVTkniiTSQ32D4LFWoRfP1Sij8GIQD7S0=;
        b=ikcJxES1/YLYPuaYEoxlU6JoZOZLWTdH/wZINGLeO1sY3fOquYaI8HCDzMTBq+jqTA
         4dSQBcS828KQnaicQwHBVFScf2LoI+dk9GiTDGCY10dQlg7e4/fF0tgLSMNb3k+25ljp
         xfuZj6MSQOSAzl24QTE/Uc8Atm8e64rvDvVmCffm6gozhRdz9kFBDNNzZWhMCwS6kX3t
         z4hNmVM/eS53Mzn0GX3nBnJlAQSDM98W4PFWGfUiE1MPDqSRFe9Z61RkPFzRLg0/YQBZ
         HYQbmD/4R6taGzuIH/H2qAnIjRLhZT3Fd5qtafIFTz+wZ3FGRESePUOt5nXrg68dxVzG
         pVbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hi4ARtp9;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=EE6nikc6;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=He0Fc7RcTcfVTkniiTSQ32D4LFWoRfP1Sij8GIQD7S0=;
        b=JkNXXJ4PK2ruUMdDENhVHZ8BgiT+1iBOkdH+a73vvWFR5T8kQfprkUdRJ/qqxSJuxc
         txQLp35s7pRVK9uu0b4ZzfPWl7MmLfd7tXAMsoBs4U6zVDBglMEkT88osXycxMPPXXyQ
         pYk9/TZiXxpBiPd58K2uIeHCQ7AWK0UV/8r6eBArUOGLhS9LN4pjZ2uxQB8pliYgok6l
         aL9/soSLW/3i/KeGx+220z6JCbcnU2ErkHuVuTlXYdi0h5RIYP24Y8AAsgdDSRzBJRKe
         QBHJIGKciASqrOy1iFBhWRhvgumqI/Bj9bA5Njgq27AC4w73zhSKpoISrtRYj5WBQkXH
         J88w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=He0Fc7RcTcfVTkniiTSQ32D4LFWoRfP1Sij8GIQD7S0=;
        b=rUznhJ7cwK1otxbP40EWS8syKH3HLtFh4+CxS9yI8pnFU3tDVyq23jURqNiLXRk9z1
         7vTDmBWyiJxbQTokCOxPSU70hOvyZTK9xZm0YHSK5G81w6mALkoGGi9eGnhYRZHnz0qK
         qFk9vCHhcQCLL2V6W0AwVp6NJzQUqHY6FgCexhsA0hpEWotVQmFlI+owqHZHLq0m9unJ
         LaNMVbWB8FnEOcKxyQeN4V6EpEadJt9W1wZKVHnItIS2cAI4x0kKRGC1q9MqrbrSqklF
         Cn2HZYi2XmAH2jsOR7e8VVTIYSlGKOtrHPAVmuwwaLtz8ZCJjJQwW2y68Wv3NlIyJyhB
         ve6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+vCnuc77gI3/LuMhT87OXjCm/yRL7LoTarEQpBFCib7p9iecZ
	/+0K3B9VKX1Pyw9Z29tiIMM=
X-Google-Smtp-Source: ABdhPJx4Scy3jU4dgB0FtHtKFJVfk0J7m9tv6d1ouYBU2f92rcKL4G2wwXyEUm+/WgEVur4EryGFGQ==
X-Received: by 2002:a19:5e5c:: with SMTP id z28mr3321438lfi.294.1607351392768;
        Mon, 07 Dec 2020 06:29:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4942:: with SMTP id o2ls1280668lfi.1.gmail; Mon, 07 Dec
 2020 06:29:51 -0800 (PST)
X-Received: by 2002:a19:8c8:: with SMTP id 191mr2576636lfi.492.1607351391785;
        Mon, 07 Dec 2020 06:29:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607351391; cv=none;
        d=google.com; s=arc-20160816;
        b=MQXl/8GxXItcaf9W7P99DtUCLtmjIdXCkDSF/DmS9pE2I3Wu3b2rlhVh8MrlaJ3bwM
         KdfuZJrKPzvF+f4AjBh+TiYVPU8nBQA6R+9sF6+ajyswPJ07PNSTftpnAsn5rQTyHBMk
         RKWbXS09Eztvzjz4yU+ox+Z7b5537A+a0fqPsH3AxAItVYPMbSWEggcAgBMlYLFY5ExC
         5YCaG6hXUavCUWfvHEDRWeLCWs5w+uRpIWSgsF99zvN8AsP1Qe+q155zMvbSGMvwBUcS
         0mqflKqczyqrBEestgggs8Wq+JkaJpvPHULJMozsbULaYA1UOcaSYF+CVkp9sNiARHog
         3X4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=Lah/+c+Ehtzql4vM/HHQHHurw4w3/5r9VJI3o7azYjo=;
        b=w56lyHeFhPr1kpa2LYrHl8PFWvIvldYbpqN8oHwTng4fUMl8zGIFaL/c5r5sOPlSyF
         U4i5lVtmUXg1/rVXUzMlQiBKFiCvnOEroFkaA43l/66M7I8NfCk7DXk1CkdvNK0m6YL1
         mRHWG4Y1n82ia44yKFj3HMg6jTX6xeEpTYCDY3iZfCuQPJr+sr4ErmqoCF5b83b325lK
         7WuTg2yqZ1WBE+efzKQ9eVjQMbkVlFt76bI5Vhp9SLINOMY96koTUSgkCWTM7bvqNacs
         sipnbz0I1NlCtCLB6Q0QoFbJJANEOuw930Ag+LDkhZvPl1W2R213i4oKeGAfP0aOcK/r
         tYsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hi4ARtp9;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=EE6nikc6;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id j15si234872lfk.12.2020.12.07.06.29.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 06:29:51 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
In-Reply-To: <20201207130753.kpxf2ydroccjzrge@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de> <20201207130753.kpxf2ydroccjzrge@linutronix.de>
Date: Mon, 07 Dec 2020 15:29:50 +0100
Message-ID: <87a6up7kpt.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=hi4ARtp9;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=EE6nikc6;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Dec 07 2020 at 14:07, Sebastian Andrzej Siewior wrote:
> On 2020-12-06 22:40:07 [+0100], Thomas Gleixner wrote:
>> syzbot reported KCSAN data races vs. timer_base::timer_running being set to
>> NULL without holding base::lock in expire_timers().
>> 
>> This looks innocent and most reads are clearly not problematic but for a
>> non-RT kernel it's completely irrelevant whether the store happens before
>> or after taking the lock. For an RT kernel moving the store under the lock
>> requires an extra unlock/lock pair in the case that there is a waiter for
>> the timer. But that's not the end of the world and definitely not worth the
>> trouble of adding boatloads of comments and annotations to the code. Famous
>> last words...
>> 
>> Reported-by: syzbot+aa7c2385d46c5eba0b89@syzkaller.appspotmail.com
>> Reported-by: syzbot+abea4558531bae1ba9fe@syzkaller.appspotmail.com
>> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
>
> One thing I noticed while testing it is that the "corner" case in
> timer_sync_wait_running() is quite reliably hit by rcu_preempt
> rcu_gp_fqs_loop() -> swait_event_idle_timeout_exclusive() invocation.

I assume it's something like this:

     timeout -> wakeup

->preemption
        del_timer_sync()
                .....

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87a6up7kpt.fsf%40nanos.tec.linutronix.de.
