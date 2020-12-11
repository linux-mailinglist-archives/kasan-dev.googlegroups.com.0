Return-Path: <kasan-dev+bncBDAMN6NI5EERBBMMZ37AKGQEV5D4BAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 42CB92D7819
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 15:45:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id m67sf40671lfd.6
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 06:45:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607697925; cv=pass;
        d=google.com; s=arc-20160816;
        b=ri+lrx1Nb77+CF8xCFCX5lV+nnr2rtSfkE1O8VV5FTlymckov8ry7mk40L+Tw0rq/n
         hxKN3Jx1hQAgpAGlLyjc+BKnrCSV1FcDZqBMcEtpaFVpnIRHnmH3a1H6pm7CBykJvZ2Z
         xNzJvNxfXRaUM9PF2cY0ZZT97+VYE3Fra3WOFj/bnYcJFv2KIl1ZOamqVgXU6VXaAsy5
         64ds9qMGj/Si/4yLuU6+JkDf+XFxc2BCrtFL8znQJ3lfSQ88J+DLTkPsV9RJn91mybi5
         3y1OzIHs0k+1ZOGldZaibv2/lROcRjoPqSzaLv+JgsZ+JrIq/Nq0phkxfPHsQNsOjXvH
         lfmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=FI/QG7DjeUafi33FSIsC8A82bfXle3UtggZhR+YORTE=;
        b=f2RSieao9RiDJr10bzD3nVtDNU02r7vCzeFRIXQHJvnyHr9tkvzqz0GHZF3Vgm/bxn
         p9uLybGrxZbekrlid+v9ocsvRZBIQqJJJ06PhDWDeI/klb1cG2bDFnvXKen5YunQw+s9
         1V9d5uaFOemw1fHiI7G8Rarq06t8unFxCI7iXT/TlWOwQun7s/jK49qF9IdxIuFrPP0b
         uOHW97V7NE/Y7pvw5DUvyLtsKDr6ieaGL3NQl9zkcJiLfj88L7weFjakw7ZSKxCxTwD1
         hCKPzi/NjyFnWNU2QGxiqIdI+dpjnNU2Umadd+sbRY0G+oR4EJWctu1i/vFDytVZ+erh
         lXBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=TcScHttl;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FI/QG7DjeUafi33FSIsC8A82bfXle3UtggZhR+YORTE=;
        b=mafsSTOmxPIw5g6OQn8GNtxZ6nmacZPG2OxOHLjZzdx8YM8XZ7eFcKXDgiiLVaFopU
         Ti3qiAnusZCO3NN5g8xP9ka6YSHzB/mgFXWL7LxEAMXWY2gv8KxzVgcbhMjiihd31p44
         7LkfjtEFvfifu+MzKJuoshY6ry3tT16fcUZfqWGqWY3vxq16gms8izHo8KGMChEutfXa
         JKWARlIWQGAatRGkymGmZ/DPvu3e4vy3bPdWz7RxN2FggkWUAydReLbuRT3JyC0ZaQ/D
         dHgDns7A5q1AY0FB4XbKrE5/HxGIQvau5mlHBdpr01JfemVmOmvzvTdqkwcmIBWXsDrQ
         VdBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FI/QG7DjeUafi33FSIsC8A82bfXle3UtggZhR+YORTE=;
        b=eKBJ3uflRClLWbgIRiLsRTWTnL3Fw5xc+9gn18/azEUVxmI35Bw7Zv+bpWqyASXzUp
         Qe8xJl/CpnKGjJ2YtmTgcrYMIjMESFtYN33F8zU84X1DkEzxiCQN/k3PtcHcZij0Jw8C
         96cjnB3MFEpARwAnB4jOxH+aO8VlqQjLMd2T/H+N//kvdfzMgtdBVEtsTHWzDsCY0yxz
         sVlv2zhT2yaFAi/rlYE1kM3G7u7UAs4tWk0avPrBvvZQgj6wF5SBGKbBnETSs3IiGvp9
         /Od934W/tkHyhER1A2qRW8CQJQSjLRbrzs3PVmrFWFCR/ZlnnqI3RXdxpxWq6B2us+j3
         QNpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MK6ZuC1qosRW8x2esOvdlxmLWh9j3o82a3VQQfO8PeR+fcqrd
	ZZ9RsEAw4FE/y4RMYaoIIn4=
X-Google-Smtp-Source: ABdhPJyk4T7CBWh75CVEOoTmPkHPKl/wcNmAeSd7GgL0dok54gAxhEpMs1S6z+8u5KBNA3bi3jHU0w==
X-Received: by 2002:a2e:6c04:: with SMTP id h4mr5256689ljc.391.1607697925807;
        Fri, 11 Dec 2020 06:45:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d4:: with SMTP id k20ls3700939lfg.3.gmail; Fri,
 11 Dec 2020 06:45:24 -0800 (PST)
X-Received: by 2002:a05:6512:242:: with SMTP id b2mr4756570lfo.460.1607697924729;
        Fri, 11 Dec 2020 06:45:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607697924; cv=none;
        d=google.com; s=arc-20160816;
        b=ZTwlyxhKpNTFn6JvVyFkHQqHq325S2E9uuQqF3l0TlanQty+4VvmSdPcvXlE5Rk50w
         BKlrPeXFyL5zUN4Vg5dkU4hM0bDtmnpNwycpscmhy6djVqqxAuBKFnOjzbtUpZWu2P/p
         m4DRIVJC6gKVulDq0X8FGyeBH3+UE7q0Fq42bKTPRKAmiVqcpas7ZkQvb60FzA9IN3z9
         XBzyuJNj6TModESryf3hxYamAVKpE0ZBmQ8pxsdXmwI3IPhCy4WSuMoAAjfDEYop1eTR
         yb9wEZvv7HprSa9Fu3XRe4iud/asUahDslflyLit0X2/JyyZJj5WIdvT1keTGzg9AYUO
         S7tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=FzGg7LxXohhH6b7FeHSZ2e3oXZj5TWyywquXxDIeY1M=;
        b=WT5aFNXWhznXU15EUqQGLL0KnBdn16u9xEtVG1AuF9Gsy3Y879itWeG9YPnWphNj5b
         4i9E1BxMfaJ1rPc1kWbbpF91G0DQDuIQ1BXHPWHhJBTRUlPH6IqEKdihL1pr6eXJ+pSG
         mavZfhOtrNBxlqgMguSODhpv15wMQAizkCYHbNjxQQCEbkbf/9Vv7SWYUgTMs/xBAjU3
         vkAgfD92gZcFudOyCKjHZNM0fSHWgcaVNm6Cwbqb7u6lakVCaakly+aIxugRZIoVu2NM
         JdTPpAkVwuZBumereD7nSk1RWMRt4T7QDiFT0MnXe1fIXwPobfpq9Rvh+Q8pd+PqrUHG
         /O6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=TcScHttl;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id h21si368811ljj.6.2020.12.11.06.45.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Dec 2020 06:45:24 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Peter Zijlstra <peterz@infradead.org>, Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
In-Reply-To: <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de> <20201207130753.kpxf2ydroccjzrge@linutronix.de> <87a6up7kpt.fsf@nanos.tec.linutronix.de> <20201207152533.rybefuzd57kxxv57@linutronix.de> <20201207160648.GF2657@paulmck-ThinkPad-P72> <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
Date: Fri, 11 Dec 2020 15:36:27 +0100
Message-ID: <87sg8ch0k4.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=TcScHttl;       dkim=neutral
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

On Tue, Dec 08 2020 at 09:50, Sebastian Andrzej Siewior wrote:
> On 2020-12-07 08:06:48 [-0800], Paul E. McKenney wrote:
>> > Yes, but it triggers frequently. Like `rcuc' is somehow is aligned with
>> > the timeout.
>> 
>> Given that a lot of RCU processing is event-driven based on timers,
>> and given that the scheduling-clock interrupts are synchronized for
>> energy-efficiency reasons on many configs, maybe this alignment is
>> expected behavior?
>
> No, it is the fact that rcu_preempt has a higher priority than
> ksoftirqd. So immediately after the wakeup (of rcu_preempt) there is a
> context switch and expire_timers() has this:
>
> |   raw_spin_unlock_irq(&base->lock);
> |   call_timer_fn(timer, fn, baseclk);
> |   raw_spin_lock_irq(&base->lock);
> |   base->running_timer = NULL;
> |   timer_sync_wait_running(base);
>
> So ->running_timer isn't reset and try_to_del_timer_sync() (that
> del_timer_sync() from schedule_timeout()) returns -1 and then the corner
> case is handled where `expiry_lock' is acquired. So everything goes as
> expected.

Well, but even without that change you have the same situation:

      timer_fn()
        wakeup()
          -->preemption
                        del_timer_sync()
                          if (running)
                             wait_for_running()
                               lock(expiry)

     running = NULL
     sync_wait_running()
       unlock(expiry)
         wakeup_lock()
          -->preemption
                             ...

    lock(base)
     
So the change at hand does not make things worse, right?

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sg8ch0k4.fsf%40nanos.tec.linutronix.de.
