Return-Path: <kasan-dev+bncBDAMN6NI5EERBNMGSPCAMGQECYCUK7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA6DB12A52
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 13:59:51 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-456267c79desf8165615e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 04:59:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753531190; cv=pass;
        d=google.com; s=arc-20240605;
        b=PJutP9Q5aqCziSLjxKpCm6FTz0WSSCyQkGO5HMTHq6blrHRS34bu43TkGFfjo404iJ
         oGaqmf/5gCDYBNEC+uSUsi7QagrUyhi37myARWgf1CF311e9oz+B83pN24OVJXiZ/kpb
         iLmeodZwNkBuhs9qKYBrj0CAyitgfKLDhm63RO1rp/pmiMvgVAhrK2qjAIGShc2pnnP9
         /MjkRFrxHo4TWEdAMO6ZXEb53uKJKiEqZCdUVNcaUjDKWBc+HbjomI57srgazJp3+FkV
         fGfrdJzRziVcyihtmCBABdgEiOfkwz7rWeRPNfaKCS9us0fbWceNIr6uVejq4uAQYRm9
         QSOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Tn7HbzUVxDX/e6EfpDGUJ3o2rT+znE8jf3F1K819P1A=;
        fh=cWrgP0rRbL/sYi7beLTWYXt6+AIrhEJi8rX60rHl8zs=;
        b=jEHbWknJK4rHhSYd3iJcCzXDlBYxgxTLLPj+qnM4wL0E654RZqb5n0VPGqBz8SjvT3
         okIySvYN8RHr4P9sTFD9P3uk9u4XTUYQ8nEC6qqzyS9zvAEbZ5Bc5fOSRF2sa5FQ7gSn
         U2v79r6zOSm9ENBu7Dl1O3jcgwSJaBMCybc/wfMeb+Ms2VXo5/ytkTtQOnBrul87XKV8
         Ne0/SXUlwyVRUH8e12c8rrMcCo5ZoJdMlLoKNFOcITFNf+MO2h6PZqprGxTfBnXotMXH
         WruKtKopgibVURBCm+MfAxC9+Ub3Pk3riZeM842hHCFcwQH0QrLaZhArFEbIkVvJzz7A
         Vm2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cfXFPJlk;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753531190; x=1754135990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tn7HbzUVxDX/e6EfpDGUJ3o2rT+znE8jf3F1K819P1A=;
        b=g8F98BaReZSOhHDKuXMPZ2KMwCLlGT9j+94TdfiT6BdxpHAqLCFtwfU4r9b/Nv5Qo8
         scqLOJCXiIOnE9KQ64z9LlcltoXS4MWCwb3y5tYEM1AzYY3/PPxyXKX5Ef4kXKzjPxlj
         F6eOwIpS0qZIDFzGrMMcc5Ynk1/5IjjwrOl7Ti5+dv/pp2GgHQ0BpnAJfEjNzEuLqsA6
         GJAQqsv6qxD/PRChQKGXX9c01MOlCk8t2MPCWPfbxwlxL7PMFgAf96FKtw60/aE2Y7zy
         FDowMVJzlrZKY3cReuVF6llQ5aE9WAceecssNdq5jJ/VoaSQHg+fOCIYrIFsXUADckVI
         nbXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753531190; x=1754135990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tn7HbzUVxDX/e6EfpDGUJ3o2rT+znE8jf3F1K819P1A=;
        b=HCN/PlH2zSzPMDADQbYQhNISNgDJj+60UrFg5fXpk8VKmN7Vl2pPbYtmBBCLfUPp6o
         uuuGu8eGbWiAsA7flzU7zVQJcLjZt+iLgWNZ+mJkLT4f7uEteRnbuvMfLKqTYaeXUFeL
         ZjLP+OhSS42emrweaXwDVgGcf4h/8PsKuzPV1YB9P8jw/SoSS5Bi0vlsrxTUQ/veja6l
         6lqaHLxN1paOJ3qYz34/2sYXsOf+iy9PmpqKzwM8M25gtKs9j1aAyCvFmGMhuR36JnNJ
         whh1g32LQXB0NqrkxXiUHulEGobEcaNDxIm3pUyHoCEG0gPjvBLIpy6vMJHBmpz1Avlr
         9XMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzxpGbOr80AIEq10lZHniCDds7/a82e6STJ/Bu9ay9gYli2bxZ3xk5v1MTVb/+o9amuNToEA==@lfdr.de
X-Gm-Message-State: AOJu0YyhL6yIW619sYYFQ/PIGmASbnPAD03KDHl3HaFBw6VrbzJfaUWY
	dlQ0ExAdc8FbGomHpX2FMq6CrSHHUt/M/RGUkPjiz1PQXQmdKXYLGCgY
X-Google-Smtp-Source: AGHT+IGgJXJvZrBENbAL2h+AX0INDGpj3PABsMz5O+yXK6NO7ZNcXWo8u30YFaWzABdZEREThthe2Q==
X-Received: by 2002:a05:600c:4f0d:b0:439:643a:c8d5 with SMTP id 5b1f17b1804b1-458791252f3mr28495035e9.0.1753531190345;
        Sat, 26 Jul 2025 04:59:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZel/4NWhdpWP4uRphPhoOQwWzFe1Wlbq39V0rRmSgGu8Q==
Received: by 2002:a05:600c:6387:b0:456:241d:50de with SMTP id
 5b1f17b1804b1-4586e643aebls14534785e9.1.-pod-prod-09-eu; Sat, 26 Jul 2025
 04:59:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWxFtfhAK2yCBYhQ/xcdeDPynWOJ1CjdficPmRtV/8uruy74T/5xTeDO25oZQsw/soIMoDNB2ATsE=@googlegroups.com
X-Received: by 2002:a05:600c:470f:b0:456:e1f:4dc4 with SMTP id 5b1f17b1804b1-45876331bddmr52309325e9.15.1753531187064;
        Sat, 26 Jul 2025 04:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753531187; cv=none;
        d=google.com; s=arc-20240605;
        b=gZ/pCWisqt+JFSbtXc2GkCr9PuH3hLffCss2gk2PRiF0UTzF6gpZFDqXgMejhk4MEL
         /DZhkvzdpEJgo0+pOk6mDiNsvOhs7bq7z31GnIijtR2e9WkPNwdsg0StNiWz77ayeju0
         O7XQUc8xcluUwDlLfe1oAmUdDsq7PkylqHkfVULyEQAxOR4EzkeN4HgZyUrz+2njW7fn
         lZYEI7BNlVj93BPRSbXTpXtLd/jN+b6gjqFVQwlbQV5sAhKgYRy+dG3hb22w7spD5x7C
         T6JBjAqHlXJIDSCJgte/0OPBzTfHqTF9InZe9ecu59o5EoKq2wGw0lmDxoBCJpCl9CjP
         nvqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=6QLD/9vDRaxK7wnQrPT92N/0V2GDCn8DkNHpJH1+2ME=;
        fh=AQEcWLCxP68B3muzQBhKFZUT0wnFHNEQFxHn5z5QIiw=;
        b=F11En7Ohcl7uhmoULkDWMv4Z2oY+/RVfbzoMSF2LZ5m1FnIvRpKW+7evs3/lnZkGzJ
         OuLmNAqcKkRWKICrKOGhqkoTZ1rD/7JckEzN+65Q5pCBqoqnnGNk7A6TPNtU+YuV3sf9
         c4goaK933RSr8AQjILR4VNt2JKZiuAUOqIoyHUSwQLrGdetax+MyDndP/JEp8pyYFU8i
         /lcywPKqLYoijno6fZ2w7OgI5ZB+8vis72adNzWlC5oRgHThAsEA37oN0AkhjIMm8BhF
         nqukAqacPxkkZmm2K6ViWlyStgUw9PeZmvpFHbIOuKbMbMoxgE07r1n8+syv4neaoLhp
         EAdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cfXFPJlk;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4587ab452ffsi705605e9.0.2025.07.26.04.59.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Jul 2025 04:59:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Tetsuo Handa
 <penguin-kernel@i-love.sakura.ne.jp>
Cc: Yunseong Kim <ysk@kzalloc.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Byungchul Park
 <byungchul@sk.com>, max.byungchul.park@gmail.com, Yeoreum Yun
 <yeoreum.yun@arm.com>, Michelle Jin <shjy180909@gmail.com>,
 linux-kernel@vger.kernel.org, Alan Stern <stern@rowland.harvard.edu>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, stable@vger.kernel.org,
 kasan-dev@googlegroups.com, syzkaller@googlegroups.com,
 linux-usb@vger.kernel.org, linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
In-Reply-To: <2025072614-molehill-sequel-3aff@gregkh>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <2025072615-espresso-grandson-d510@gregkh>
 <77c582ad-471e-49b1-98f8-0addf2ca2bbb@I-love.SAKURA.ne.jp>
 <2025072614-molehill-sequel-3aff@gregkh>
Date: Sat, 26 Jul 2025 13:59:45 +0200
Message-ID: <87ldobp3gu.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=cfXFPJlk;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
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

On Sat, Jul 26 2025 at 09:59, Greg Kroah-Hartman wrote:
> On Sat, Jul 26, 2025 at 04:44:42PM +0900, Tetsuo Handa wrote:
>> static void __usb_hcd_giveback_urb(struct urb *urb)
>> {
>>   (...snipped...)
>>   kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum) {
>>     if (in_serving_softirq()) {
>>       local_irq_save(flags); // calling local_irq_save() is wrong if CONFIG_PREEMPT_RT=y
>>       kcov_remote_start_usb(id) {
>>         kcov_remote_start(id) {
>>           kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id)) {
>>             (...snipped...)
>>             local_lock_irqsave(&kcov_percpu_data.lock, flags) {
>>               __local_lock_irqsave(lock, flags) {
>>                 #ifndef CONFIG_PREEMPT_RT
>>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L125
>>                 #else
>>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L235 // not calling local_irq_save(flags)
>>                 #endif

Right, it does not invoke local_irq_save(flags), but it takes the
underlying lock, which means it prevents reentrance.

> Ok, but then how does the big comment section for
> kcov_remote_start_usb_softirq() work, where it explicitly states:
>
>  * 2. Disables interrupts for the duration of the coverage collection section.
>  *    This allows avoiding nested remote coverage collection sections in the
>  *    softirq context (a softirq might occur during the execution of a work in
>  *    the BH workqueue, which runs with in_serving_softirq() > 0).
>  *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
>  *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
>  *    the middle of its remote coverage collection section, and the interrupt
>  *    handler might invoke __usb_hcd_giveback_urb() again.
>
>
> You are removing half of this function entirely, which feels very wrong
> to me as any sort of solution, as you have just said that all of that
> documentation entry is now not needed.

I'm not so sure because kcov_percpu_data.lock is only held within
kcov_remote_start() and kcov_remote_stop(), but the above comment
suggests that the whole section needs to be serialized.

Though I'm not a KCOV wizard and might be completely wrong here.

If the whole section is required to be serialized, then this need
another local lock in kcov_percpu_data to work correctly on RT.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87ldobp3gu.ffs%40tglx.
