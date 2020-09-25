Return-Path: <kasan-dev+bncBDAMN6NI5EERBDHBW35QKGQELUOD4GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 70E57278356
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 10:55:41 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id i10sf818310wrq.5
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 01:55:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601024141; cv=pass;
        d=google.com; s=arc-20160816;
        b=DOHQIy6e9iaoNIp9hjj1kCMu1FG0uL6dpL2chKeD8q8vIjLD3Sr2XFUoUi6qGFto7f
         dyIGToHDp92kjPcGSnj5xBsgoW9pdqZDitHmZve98xe3tCEg/sQkXLHZU8LPdSjZkqKC
         l9yH0jjkWp1Hba9qFfn+EkgQzxCZyB7nsDiICnYxPoTa3IC7TOaUz82v3Ke2IErhOBaw
         NwXsk63HEf2IXVsnF3qEl9zbyYihOTFdtzbRZtJdIaeCu+9O1hjeyjSI6Chwz5gpvFnq
         tQRrjQUcNXqu1s/jGjodoRRnlnQ48Jl6i4Ez9ofG8XhH9XDhKfWYHs1p2fsL2YXmrLB/
         jbZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=adJ7ANHIGKEX4vfsAUTLlrEJbHOvC1271j099eKW8mg=;
        b=t5zmW/w9N/q+EyNPdOWN1O5FH2h5UtuqmfAqDH1IP8hyVZCkYQ59VRQYex8sMCrCfQ
         68nv2vnm0nJ26g3eoeNh/1PGfhXtYDmIxq2zR3TwyK7ZlUQ+vDxP/Mvy2msTEOsJbz+b
         7hywkvx0irLV/eJu1s7UghTvnOsPXMh8qmoFI1cQgyYIKEUsOZ4YDYRAu3yzZeKHkBAd
         gp8GOMWp+IShQOUwcyz03mQeGzOil8EY7sqPLcmuaKzEhWqsS3xfGqrExWr0gFhcMdIY
         MR6QO3S5MmE7RsigADQPEyQhyhUqacijU0g6WrBbzQhGDrFampmZ3enEdKgccDiU6oLw
         eE6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Byg4yL3t;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adJ7ANHIGKEX4vfsAUTLlrEJbHOvC1271j099eKW8mg=;
        b=lEEFM9oqyGQrfj9ucuGehPE7fJB6a9krkZF/ZQSBt3YXymTggwAPK4B5met6sCLLg4
         MTIJOT6TrINDOyhvuLg2IuWbDg1VTZgU2YCrYdbplxvPQkAgxymzJ4ybB4fNCKGxnHKW
         t1/Mv5VmF0syZN5MMsT+Ja385+BiimD8KXkJ0/2CmeYcjdf4Ax4DrNoWtJszlaCcHhpB
         Xnar0g9P2cmqKw4Bc5jj8k6ERrCOyG4XDEvBtjpjD/rNuZzYhpX+LwglBLrX/qN3ez/c
         WLE/hpCRr4o87NcqwjOQQ4TVz2MbLzjNJr/Bc/vheM5qwustzj6o+2fQTybp7AMRmHVs
         NQEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adJ7ANHIGKEX4vfsAUTLlrEJbHOvC1271j099eKW8mg=;
        b=WFjAdWJIfn5AonGOMw0ybh0FX5Q+Clba509NkEMzZDQgUrNQSf+xP0Y/VDxB8QqiCZ
         7zt2T9mpcfk2pHknOhj1umvWuUuw479DK23S0KNeLrqpLZBYVJjSxLYmUFbnoid0C2LM
         SpwM0ujOKFbfXAztIpRDo/pHPSY+A6IDNxZ84niDrW/39UFPLnMVHTSPdw9gsgdRJelk
         uQvlY41ltXW1jbuQQyJOvIJgw7Uhy2ZcPufIZP1Ec1TGjeP0I5gzBuAbpxzhUKuL4zMY
         qEOPuATzqjWf2w0OA/NdKMp/gTfaY+CwZ1b5dpgdrXZJE/1m9HqF9g137mCgjOWo7e/b
         vd3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bxhEuluopRmciGWdTtl46HiBWAtC1Sy06D3LBypByKrLDnPaA
	KCinuJItuxlyNcVbHoT/rN8=
X-Google-Smtp-Source: ABdhPJxSPXE30IgchoxrArdxQe0UW5rg+MOylp9zufid+erBOEq6j3VduOa2gMK68D1eWPVabGC8Rw==
X-Received: by 2002:a5d:6b84:: with SMTP id n4mr3563435wrx.55.1601024141243;
        Fri, 25 Sep 2020 01:55:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls2521912wrm.2.gmail; Fri, 25 Sep
 2020 01:55:40 -0700 (PDT)
X-Received: by 2002:adf:e58b:: with SMTP id l11mr3548328wrm.210.1601024140250;
        Fri, 25 Sep 2020 01:55:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601024140; cv=none;
        d=google.com; s=arc-20160816;
        b=BPrsmw/dAU4+zXygfhxbG//1qQWoMoQtZ/1Ow8cPQVq/uvfKugFEXfqGT2bUokMSW/
         muQlXRXLrG4jlLlsdzQQGq4OLyvtSfZQsBpwnksNJWj5ODrEHJfzDE3q8xTKX+nJ9FCc
         lTGLO7iY2VgiZZZOcVWVjeYspuCXBrPeCOdg+eutu8Hc3QiWE9THtuEZZmUTL6dintNz
         DR56gYl+QKK3R55QntcBIIdK7XpnXnMRN9S8jkNpcc9ZVA9/XeeosIWVNZ3a37zE05Xk
         JiWuiQMqjCWNNM++sFrFA/ym3liwuqZQ0jXgKe3wowNSsNvi2ReAjmyRoY4Mjqasq/rF
         d6QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=27rpXJWZJemqCR5/J+kJk/Ytwunk5JlcbUzkum+S4N4=;
        b=uuo6lU58Kt9Z/8oiozx4+2C2FaKYH7hlc4Sd1rOOMkETysRmaDh5ZqoQ4yAmQ6d3Yp
         iG2pfeG70LqnxcCyydibJwLmD2whoCXfZCRHRlfm14aljiugyt933OmVz/QpEY0S1S4v
         p+2vYiwq055RSQHEOqq1biP7snyJu4K0AgG6NYHqx/ZD7eTtI9/1q+89/BpiZ8637zpx
         2cH4a3NbfMZbL7n6fjA4gJzDkeIz2YG08zbGkEskZ696RdZzf9EVpTP8yWHIhS7qWYbV
         bJwAHMqc3S7+8hyW0ypsz1X0q+1A+UcXb5fE9QhfGano9PFV2ofFR4FXEQf4B0mbEaN1
         kj0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Byg4yL3t;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 126si45543wmb.2.2020.09.25.01.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Sep 2020 01:55:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v4 1/6] timer: kasan: record timer stack
In-Reply-To: <1601018323.28162.4.camel@mtksdccf07>
References: <20200924040335.30934-1-walter-zh.wu@mediatek.com> <87h7rm97js.fsf@nanos.tec.linutronix.de> <1601018323.28162.4.camel@mtksdccf07>
Date: Fri, 25 Sep 2020 10:55:39 +0200
Message-ID: <87lfgyutf8.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Byg4yL3t;       dkim=neutral
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

Walter,

On Fri, Sep 25 2020 at 15:18, Walter Wu wrote:
> On Thu, 2020-09-24 at 23:41 +0200, Thomas Gleixner wrote:
>> > For timers it has turned out to be useful to record the stack trace
>> > of the timer init call.
>> 
>> In which way? And what kind of bug does it catch which cannot be catched
>> by existing debug mechanisms already?
>> 
> We only provide another debug mechanisms to debug use-after-free or
> double-free, it can be displayed together in KASAN report and have a
> chance to debug, and it doesn't need to enable existing debug mechanisms
> at the same time. then it has a chance to resolve issue.

Again. KASAN can only cover UAF, but there are a dozen other ways to
wreck the system with wrong usage of timers which can't be caught by
KASAN.

>> > Because if the UAF root cause is in timer init, then user can see
>> > KASAN report to get where it is registered and find out the root
>> > cause.
>> 
>> What? If the UAF root cause is in timer init, then registering it after
>> using it in that very same function is pretty pointless.
>> 
> See [1], the call stack shows UAF happen at dummy_timer(), it is the
> callback function and set by timer_setup(), if KASAN report shows the
> timer call stack, it should be useful for programmer.

The report you linked to has absolutely nothing to do with a timer
related UAF. The timer callback calls kfree_skb() on something which is
already freed. So the root cause of this is NOT in timer init as you
claimed above. The timer callback is just exposing a problem in the URB
management of this driver. IOW the recording of the timer init stack is
completely useless for decoding this problem.

>> There is a lot of handwaving how useful this is, but TBH I don't see the
>> value at all.
>> 
>> DEBUG_OBJECTS_TIMERS does a lot more than crashing on UAF. If KASAN
>> provides additional value over DEBUG_OBJECTS_TIMERS then spell it out,
>> but just saying that you don't need to enable DEBUG_OBJECTS_TIMERS is
>> not making an argument for that change.
>> 
> We don't want to replace DEBUG_OBJECTS_TIMERS with this patches, only
> hope to use low overhead(compare with DEBUG_OBJECTS_TIMERS) to debug

KASAN has lower overhead than DEBUG_OBJECTS_TIMERS? Maybe in a different
universe.

That said, I'm not opposed to the change per se, but without a sensible
justification this is just pointless.

Sprinkling kasan_foo() all over the place and claiming it's useful
without a valid example does not provide any value.

Quite the contrary it gives the completely wrong sense what KASAN can do
and what not.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lfgyutf8.fsf%40nanos.tec.linutronix.de.
