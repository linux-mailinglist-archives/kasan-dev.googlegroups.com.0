Return-Path: <kasan-dev+bncBDAMN6NI5EERBEPLQ2FAMGQEMOOOVXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4157540C22A
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 10:57:54 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v1-20020adfc401000000b0015e11f71e65sf754081wrf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 01:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631696274; cv=pass;
        d=google.com; s=arc-20160816;
        b=gg1V/cJ/wOCbMuEemJjbERYp7l2ATKeKHoGE5befLvVHkv0FOEBmTh5oAROTj5rYuN
         UbTWWEc8ABdivXMFb0LywspJvndHR5tEGZzPUEGTMamk+vQGn+ixs/vkNlg3JY6zgTDN
         jIY+TW7Y9ba18dRTnm+eaHYz6/kVoC2hkTPApn7qNgyIX95UBRWAGmZ5S3sNOdLbNpKH
         CInwYG1O/qGLzpsxTIbSLduxRG3rYCNPympDjb2A+pOIzNGjkYBlVKpscEB+od78EG9k
         imv1TuNlNOoarUSQhqqfMQGA8GBYdiCchFIPQqPAj3uXy6SYj8tgkSqfUWJKXazBX6ID
         Sf8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=r4q7qInig3APIMsSCZIW9RK3hd8jyEi6j84qF9IBsBA=;
        b=gKrbuDXvvx6aBOOqjw7xCcQGIbaknjv5eOKWtTfRLbbNFmQJSNTdz6dyf4w0Hd6Nyg
         f5PwB2oVWcwTEJsubUWtBR/p/5dCVunCvc4Zbw2COBc93q9EyEReCuq5jFHlezU8wrFs
         R5tWJnTIWWTktFmjgiFiyxlawyEWGl09lenq06PdPgkpOCZ1bkNIGh3YqKcsPuOk7bFk
         4lX0EvAC3aCbOEApfon5FjyKxkWU7SQD6YWgxb9BOWFSLvqUB2Pj3O8m9wsNxxMqKiir
         pv18R4m4rz4gXkKtCd+HqlVKumAh8gKahTC0A1MWcUyZd8IxeQ9opRzMr8MDgyGCeMhd
         60RQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=vgC8kAEu;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r4q7qInig3APIMsSCZIW9RK3hd8jyEi6j84qF9IBsBA=;
        b=otj9AqklzoNV1JQ7QObx2kSQoUno+attCjZzDQn7jYW2hirK4eaEwpg+0U3AlhYiOb
         lJDDzf/P9tByZa/e+L0wX4C5GYUOwC+X+sOCOEi5UDfIJL8muyObWBKqDon7TOB9AzVS
         9wRac518HotnSAmV5aYb1v5fqN7P/a1sBVbXOJRuAc84166aguiMA4UY80bhqBlsy5/E
         13GEYH4MGWxkNaqppdbUj7B4C4ahtEsLgHvuJOw+dj7R5rtqs80eYJU20BhfleTJ5S/Q
         JVSZj+U3OsEbO0YKpFhplWxVzJh9D9osDmy1yOvmBhDocUOqisVYCUOFgx0YQTZLRmVt
         4tEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r4q7qInig3APIMsSCZIW9RK3hd8jyEi6j84qF9IBsBA=;
        b=4PmqcRIjuSrlMJh/1zjoI68hA4X/W0f3q0RWo0tJeI5yKRIxBzYk5IJKbl+L6Mo54W
         Fg+Z/NJKRHygZlaocZoIDXePl2Hp9+g0I2qN0qFNaGFl+RTwY4Co0oN71IcB3xBJjNlL
         X7r2YQ6zVoxzf4TGo3Rg9jZ4VWdCYGmZk6vUiCLFU8zFVwU/nbO37OIV1Dv6PbOCzOGu
         zJ6tjCSF1flkD0CL+Ssz3LW8xJ7YIfpZNhzj50gf8OqaXvSNX6KnmEY0J1ZofrsO5qUg
         lE3b/hK8ySnBsQ2cgqdQSCWxiGG4xoFnXUA6ISUMQxnEXB90p39m1BMeT7Mwl+6GsYOF
         rRGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KGeiLjPEIh6ipw6MZEdoLCs8B10mIg2MfpQZdm0HKjjddfcup
	kQMivuezxFvjcbDBDyeQIBg=
X-Google-Smtp-Source: ABdhPJxNcmyjXBF0akvEGobMPvvSXT+um9lKGtrOHPH3BUFTEjlDTk7yd9XF3YAwSnwRqFxaFur2Ng==
X-Received: by 2002:a7b:c04d:: with SMTP id u13mr3269497wmc.66.1631696273943;
        Wed, 15 Sep 2021 01:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:190d:: with SMTP id j13ls2206762wmq.0.canary-gmail;
 Wed, 15 Sep 2021 01:57:53 -0700 (PDT)
X-Received: by 2002:a7b:c441:: with SMTP id l1mr3047125wmi.69.1631696273073;
        Wed, 15 Sep 2021 01:57:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631696273; cv=none;
        d=google.com; s=arc-20160816;
        b=jz5nshqn4hZZ8Ula9pUfNDl5KlNNjbJbG7a9F1cDcqwA92vodRSwjEU3EaHLG73VFq
         SghMz3Toi4/jOUh9t3jRogjUV8ZfE3Kot6JKnZwabyWCuD/c6mkCQyyDDig2l78mspTN
         6FIjSLxEVz//otQ336d9k/d3KdH1vFlc5Dsq2B4EAA+6XRroJX0RTBUpHSbFnbcC5k5Y
         NJrVDRy8Nmc5T4XSogvXTh5Jq11RpJM5Vshy9NhzNBoxTqYCaTUGx1rAgUncsEB3SCwu
         YYocnwWNo4Ft1gmgaZHNGuMHs+OTHVZ/8FgMZeIh2TXHmvCdzXSjdpRm6MtMeVapBcFJ
         RTVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=oO9OrB1G0+YxTYn/JMvLtBpJYNEF69i2CP96bjIn7ik=;
        b=o0u2bdKAVaAn7CFkvaEYoo2BmwBUYvB5qwMjMNhuCGzBdpeP/zeS3RXxntcFA6+jBG
         yZYycds3kHXvSbPR+tZEMfiM6E7meiPE0pjmdHQOxCjeANvBXkM/Yn4za5ACed74cl1a
         YxSsXcmllmamxjz/rP7rXkUnQ+w1MU67WcxwP9CXxX+bxXflU3eok9v2sYpDo1rEnA6s
         e/K0iA62i9jvIm9oUxLZnKwNKKYdcT/Ij9GNdpDzOh2bTvrdqzFxswOdMIvUS/i7bARm
         5qORWvRls3MplFEXlmZ7b6ZOyeJEXBXO1Tj8pj3fqrG9ibwdCnUNEgGCQWKHIpn6Kqdu
         Yhlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=vgC8kAEu;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id c4si192590wmq.0.2021.09.15.01.57.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Sep 2021 01:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Hillf Danton <hdanton@sina.com>, syzbot
 <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>,
 linux-kernel@vger.kernel.org, paulmck@kernel.org,
 syzkaller-bugs@googlegroups.com, Peter Zijlstra <peterz@infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Johannes Berg
 <johannes.berg@intel.com>, Kalle Valo <kvalo@codeaurora.org>,
 linux-wireless@vger.kernel.org
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
In-Reply-To: <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
References: <000000000000eaacf005ca975d1a@google.com>
 <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
Date: Wed, 15 Sep 2021 10:57:52 +0200
Message-ID: <87mtoeb4hb.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=vgC8kAEu;       dkim=neutral
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

On Tue, Sep 14 2021 at 20:00, Dmitry Vyukov wrote:
> On Tue, 14 Sept 2021 at 16:58, Thomas Gleixner <tglx@linutronix.de> wrote:
>> Now what happens when the mac80211 callback rearms the timer so it
>> expires immediately again:
>>
>>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
>>
>> bcn is a user space controlled value. Now lets assume that bcn_int is <=1,
>> which would certainly cause the loop in hrtimer_run_queues() to keeping
>> looping forever.
>>
>> That should be easy to verify by implementing a simple test which
>> reschedules a hrtimer from the callback with a expiry time close to now.
>>
>> Not today as I'm about to head home to fire up the pizza oven.
>
> This question definitely shouldn't take priority over the pizza. But I
> think I saw this "rearm a timer with a user-controlled value without
> any checks" pattern lots of times and hangs are inherently harder to
> localize and reproduce. So I wonder if it makes sense to add a debug
> config that would catch such cases right when the timer is set up
> (issue a WARNING)?

Yes and no. It's hard to differentiate between a valid short expiry
rearm and something which is caused by unchecked values. I have some
ideas but all of them are expensive and therefore probably debug
only. Which is actually better than nothing :)

> However, for automated testing there is the usual question of
> balancing between false positives and false negatives. The check
> should not produce false positives, but at the same time it should
> catch [almost] all actual stalls so that they don't manifest as
> duplicate stall reports.

Right. The problem could be even there with checked values:

       start_timer(1ms)
       timer_expires()
         callback()
           forward_timer(timer, now, period(1ms));

which might be perfectly fine with a production kernel as it leaves
enough time to make overall progress.

Now with a full debug kernel with all bells and whistels that callback
might just run into this situation:

      start_timer(1ms) T0
       timer_expires() T1
         callback()
           do_stuff()
           forward_timer(timer, TNOW, period(1ms));


T1 - T0   = 1.001ms
TNOW - T1 = 0.998 ms

So the forward will just rearm it to T0 + 2ms which means it expires in
1us.

> If I understand it correctly the timer is not actually set up as
> periodic, but rather each callback invocation arms it again. Setting
> up a timer for 1 ns _once_ (or few times) is probably fine (right?),
> so the check needs to be somewhat more elaborate and detect "infinite"
> rearming.

Yes.

That made me actually look at that mac80211_hwsim callback again.

	hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
			ns_to_ktime(bcn_int * NSEC_PER_USEC));

So what this does is really wrong because it tries to schedule the timer
on the theoretical periodic timeline. Which goes really south once the
timer is late or the callback execution took longer than the
period. Hypervisors scheduling out a VCPU at the wrong place will do
that for you nicely.

What this actually should use is hrtimer_forward_now() which prevents
that problem because it will forward the timer in the periodic schedule
beyond now. That won't prevent the above corner case, but I doubt you
can create an endless loop with that scenario as easy as you can with
trying to catch up on your theoretical timeline by using the previous
expiry time as a base for the forward. Patch below.

/me goes off to audit hrtimer_forward() usage. Sigh...

After that figure out ways to debug or even prevent this. More sigh...

Thanks,

        tglx
---
 drivers/net/wireless/mac80211_hwsim.c |    4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

--- a/drivers/net/wireless/mac80211_hwsim.c
+++ b/drivers/net/wireless/mac80211_hwsim.c
@@ -1867,8 +1867,8 @@ mac80211_hwsim_beacon(struct hrtimer *ti
 		bcn_int -= data->bcn_delta;
 		data->bcn_delta = 0;
 	}
-	hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
-			ns_to_ktime(bcn_int * NSEC_PER_USEC));
+	hrtimer_forward_now(&data->beacon_timer,
+			    ns_to_ktime(bcn_int * NSEC_PER_USEC));
 	return HRTIMER_RESTART;
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mtoeb4hb.ffs%40tglx.
