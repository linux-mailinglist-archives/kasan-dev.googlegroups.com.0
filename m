Return-Path: <kasan-dev+bncBDGIV3UHVAGBB274XT7AKGQERVGQFTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6081E2D2696
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 09:50:52 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id u18sf7111714edy.5
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 00:50:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607417452; cv=pass;
        d=google.com; s=arc-20160816;
        b=sEfnEebMyzVkSGN4JghPolofBLvVgnmlo6vGXy/A9EkbEjV/lKrYfmItn2bHHE2Kpo
         /T7w+2M5LxK229O4yLolK977yF+vfQtSZAvW0BdJbZjXdLFTgb/iabIHfEF1iN+xyvOg
         HmLoZZaG+ztzLhdj03cQC9V0A/gr80o8QnV1FURzoUqN2ihbrrZUmSZOGK2gPScJn9sa
         XXgRHMS6CuN4J/hP2/FBfVcM3td/kUufB5Ve0v271uSNwGHJgT1w3AfWAEJk7bEiuUd/
         FwnAmqEAUcPR0SdJQ/f/QMYa4znXpIHSNtrmP1I8oZwBDL9zcQhhfFXT6SvbBPP1Zlgv
         tKrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SYH/qhXSHvXCRfRKqEWR+/6vQjID0GNWUYocN7gvC4A=;
        b=gBzRjj5ic8yVNz21Wzp1RZFsA2OjU0qc0hqcZ3knpI0xVBPQgRFjx3uObf2AKkfRTU
         jj2Vor3WWOuAsLypdgfRmt9luV3c6lFrD/wDz+QtHeeGlo/zRyeNr2Hka6PQU6Z2EPIv
         s2TKXl0+FX2RVsgxhQLUOtwDTbYhYbX+aBEGE4WM20cID4PjzywRH1LvH8mU9HrbQrjB
         7MLGm6bfg5YTQI+H0FCOVz5GFPzvuYTciiDaNRH1Sxl6cjrYyp7ZPMkdoCo7F3M5nmcn
         8dBJX8YGavS3nuPEr1K+ZMVgRwP1Q9ayJCOjJZx76TVQBrBkzlD2uX3SKr90br3jp0HA
         UGKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=jxPjds6v;
       dkim=neutral (no key) header.i=@linutronix.de header.b=OOXklvFT;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SYH/qhXSHvXCRfRKqEWR+/6vQjID0GNWUYocN7gvC4A=;
        b=Os2rAteVoEPHxNsGxBFFEe7HwPv7ri0j1xowWG9sCUCcIQqm63zudIsOICuYbnVe7t
         w0EXmXMYqMEpoiK2tQfEHuzz+RI33FGW1xeuXUdxPj1UsocWKOckYvxcXa2JkIkI0kQT
         uH7Da80PSbIj0RBFBKHn/9mnJWZHPyh2R5SLY4Cj0BefhMKaHwzimigQTVsncX5wtDL6
         N8C+vzF27/hRi/VGF3JAOoQ8I/4iHyiiDVE9W06kJSSjnaXQwKMXkzicErwgq3ebkSkO
         aSdIGdMo7rpqwzF8c7K8L8TdxJ7gvNoT+R1xGX33CfVV5OHm24ghBiLVYcLnS0ntx4SH
         AZAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SYH/qhXSHvXCRfRKqEWR+/6vQjID0GNWUYocN7gvC4A=;
        b=WxlPsVRP2QZzbLA4TfGcUzU8GpQaqiDBJRqblKQOQgp7AFcgk9HL8W2P7jkf4qlnDu
         2b5kZBpX5lmKRrSW9+pjS93M8ZI/WSiUOX0v+sYjcstOo6nlB1SWtxURqNBww4NXFtPa
         IaiOXepnrejVCRwwiQ8YPO35N3R3/aZdBU5dBGiYJTCzEdcSdyCp8km8T/obG7YDadO2
         8QEbMj22r26EAGA6nmNS6m2FPM57d5evLRSexXTUiuWI0eMnsZWnyxqQQLAoExDMzazM
         r8B87oYQFyuQszPiqSBSLtqPv5aKKE6py5dW7MECFbP+dO9kWI36uzJoUxbAcWuh3L+V
         g8Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53059SokEL6suMdvG1jV66AlsAhPn62KmyNIih2VJ14FVBcsdHl6
	uU3kvFDy0rfVZ3feUg5MmdA=
X-Google-Smtp-Source: ABdhPJymJ/rZ3J6dLwIz1paa8ZdxBztczab5wPHhsGPz6612ap6BriCJPLy0LywPFXcJ2k8Y0Nl5bQ==
X-Received: by 2002:a17:906:74c1:: with SMTP id z1mr22980593ejl.182.1607417452105;
        Tue, 08 Dec 2020 00:50:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cec7:: with SMTP id si7ls8762419ejb.2.gmail; Tue, 08
 Dec 2020 00:50:51 -0800 (PST)
X-Received: by 2002:a17:907:41e3:: with SMTP id nb3mr22796855ejb.378.1607417451269;
        Tue, 08 Dec 2020 00:50:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607417451; cv=none;
        d=google.com; s=arc-20160816;
        b=EpMCNCwKXvMU2AiJq6GCkWUXdJxqhzeKIKr5htxrGUBXk8QxJ4ZPN6SSFXkimqYaI5
         Z3cvfrwhh1Q4uh6iHlaf7I9oDTh0DU4bC8gyB2X6tpiZoKzKqpzdlg0000tNAgpTNt9G
         P4IlP/K/sHPdGEVgPZUCy8utDyb69IB+1ry7a3kblghDdE8DD5MAhPhITIooP6DZJWe8
         MUVqnVbvXD0upAXbJYPHl/uZwxRYGHwi5apmcud5tfULKqo/2PkpQMG2Sy5Y3Y7p1/Id
         /hoXh+OZbgQbg7MuF89aA3iOcjlE7sXC/LJaGfYhsP8ezBCY5LUDbpzY/d/KgU1J9n6B
         +6zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=vhmaTjxVT0XVhHW1xIN82oE/hpEXmuE06ThvXKAzb4s=;
        b=sR9R9qFv/xYEIztsUn3a9AVptCB7W8M5x1cMeUHiafehkpxPsE2y/fGILWXWJBKgnt
         yqC0EQGmZnxeTiKgdKrr+u9S4aoL8xsN3mone9CsQoJv7tkfuWr0nDCgNzUpGLwOxUo2
         4wb7FUs+vW39ucNNxh/uI97UHO9JD6khSADVSDJw1MJVfw35b5wifPzt30U2TsVBDw9n
         YyaXYMfSwN6bLgeMJ/QxilvRZOslc5WLQK1FW1GzBZdPYO5qwwyvAKCmAs4OFVTMpSMu
         QGSNRMrtMEgmeLHzgEFOY9w5cDnAuT8VmdnCMZUfznc8blp7bNvgcgUWW5PzzM28CkrO
         bTHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=jxPjds6v;
       dkim=neutral (no key) header.i=@linutronix.de header.b=OOXklvFT;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id i6si582364edk.4.2020.12.08.00.50.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 00:50:51 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Tue, 8 Dec 2020 09:50:49 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207130753.kpxf2ydroccjzrge@linutronix.de>
 <87a6up7kpt.fsf@nanos.tec.linutronix.de>
 <20201207152533.rybefuzd57kxxv57@linutronix.de>
 <20201207160648.GF2657@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201207160648.GF2657@paulmck-ThinkPad-P72>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=jxPjds6v;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=OOXklvFT;       spf=pass
 (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2020-12-07 08:06:48 [-0800], Paul E. McKenney wrote:
> > Yes, but it triggers frequently. Like `rcuc' is somehow is aligned with
> > the timeout.
> 
> Given that a lot of RCU processing is event-driven based on timers,
> and given that the scheduling-clock interrupts are synchronized for
> energy-efficiency reasons on many configs, maybe this alignment is
> expected behavior?

No, it is the fact that rcu_preempt has a higher priority than
ksoftirqd. So immediately after the wakeup (of rcu_preempt) there is a
context switch and expire_timers() has this:

|   raw_spin_unlock_irq(&base->lock);
|   call_timer_fn(timer, fn, baseclk);
|   raw_spin_lock_irq(&base->lock);
|   base->running_timer = NULL;
|   timer_sync_wait_running(base);

So ->running_timer isn't reset and try_to_del_timer_sync() (that
del_timer_sync() from schedule_timeout()) returns -1 and then the corner
case is handled where `expiry_lock' is acquired. So everything goes as
expected.

> 							Thanx, Paul

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201208085049.vnhudd6qwcsbdepl%40linutronix.de.
