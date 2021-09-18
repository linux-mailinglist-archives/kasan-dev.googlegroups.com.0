Return-Path: <kasan-dev+bncBC2OPIG4UICBBYV3S6FAMGQED6J554Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id A002A41066F
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 14:39:01 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id q19-20020ac87353000000b0029a09eca2afsf112627007qtp.21
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 05:39:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631968740; cv=pass;
        d=google.com; s=arc-20160816;
        b=EECZV+D/4vj9SBUnmOl3Oo/uD2FvBsPtvG4Tytl6RvxytJJEPtWzFwIoWUFnv21c49
         GuFnfv8eKsBSxNWAKDaqejNgu9ubIK19ewfDq95kznb45S7R4t0SVBNBsS7VSL5dWauv
         Uze/y44DmIsP+RdMPnWelJjq6VFuyhsHpKrsm+9NRde7R0CoGoQuU+JBodoKXDr/PCF6
         fqW/JuaBwTejKIVIFSrf8tK4F4FDOu3L6g55EoiORvC3E2t4mEJpjQsE6TDVhc1k3bLJ
         IZhUL08m8RaEaveavJ/G/mNkwqp47vqe68K2zOHQbDFh2N4Fo755Gpe/d4OGHNL/nkIh
         jFuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CmfqbFkNAYulCpkN/C6Qa/2rYSeCdTAOJPmhxec2VTE=;
        b=gtwjdeaawsayJLFFTeImm1wahOSxyycJcwhZpvXdy3kV6Qd+pEjmap8o1t11I0Bs+S
         A81I3QHixX2Zh7DWTDRdjXKrycrLsXXICTKfr2ko9jiqh/2bzNHzyHoRoeFWQreCx00Z
         rLNhVoyqU2ZuKvCi/3NrWGWgegSWHRMje6cmMnr+TagsKGdFVV48OfTKyUIxoRUudarU
         I72tGaUQmPRBUn7DaiIFGswD3Bi0vT25HDzmTP/KIwuRBTs5cDoPG8WNrDz7zN/S/TYW
         8vFC/06g+4QRxunDdwJFqi3gM4LNzydj5EonkfFngTKRQvFy5zCLKjKGEj9ioY1wRtwH
         5QIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.162 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CmfqbFkNAYulCpkN/C6Qa/2rYSeCdTAOJPmhxec2VTE=;
        b=VJPOZ0XvfnpqNCbgkiNWLC3KXS0YiB5w+b+dBgkl51XGAHveQL7Af4WWHGt9kUv7Tr
         UGEuvW/AOAcUj7wj5qj8Nq94WKpj4Wcb3vyXY4Er5RHhjl3PC3myVxJQMvUGzIzueit0
         q8UB8fT2iL6LigxFVl/s1TTE05z6vn8S3/NcNXnqU3/6hW3UZ/URzXjBTrMRThqRFopD
         TYy5ZtayryJnjBmsi6iJIEUK5tglVdZG8yyy1N+cj917E1L0LBz4lUZlkXCTAQBSC2OG
         hjzMDToHl+2EnFLKwtnRM6LzEP0lzuXk5NMi7SBiBd2baWFGzk35f7oqPBZKtmOHYx4M
         wsKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CmfqbFkNAYulCpkN/C6Qa/2rYSeCdTAOJPmhxec2VTE=;
        b=XU+hHPgm196L2/nmhiRiYwsGPpvtviaoIbSbnLJboEWLe9ijwyVZFIiFJf4hE6ODFH
         BLR79TrF7ozhpC1WgEyTeQstScwiKkNhVhZJvN/1/ZpxwAp4MF/FGD1lhDGv6bYg4ftM
         zRBR7UFHpyaVAvEHEh9T3d6ze58DhIlJmv3aI9QaHJaZyRyp32JW/v5tj2FvqLLlafF0
         whtwoT2FGjFK/tFG6lapEh3/MU+EXgq4s6hA7lDS1+9x1DIV4ZU8aKsnBtgLRMoNWKOa
         E94LHG4yC3p2XvkEOwKgY2h+zFDO0Y9eF4x+GrDL36bOp552VaM9OJXp2keJHgyYqT1T
         ug0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wv1pox07RMZB24/GSW0gnrKET8bDmpgQexluxsWxlC58zKits
	BnMkyMmKtr+C7M6YWi0LWhE=
X-Google-Smtp-Source: ABdhPJyjO9Jvx8/Fgi3h3By5o0LmgYSipq+LjylyXcHI6gZDnKkKJ6A2D/Z7NOf1QPdywEJmc9ykNg==
X-Received: by 2002:ac8:7d81:: with SMTP id c1mr14725011qtd.229.1631968740647;
        Sat, 18 Sep 2021 05:39:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5ce:: with SMTP id 197ls1100578qkf.5.gmail; Sat, 18 Sep
 2021 05:38:58 -0700 (PDT)
X-Received: by 2002:a05:620a:2a14:: with SMTP id o20mr15009045qkp.286.1631968737964;
        Sat, 18 Sep 2021 05:38:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631968737; cv=none;
        d=google.com; s=arc-20160816;
        b=BxvVGO4xj5p9SvGTozsPTsg15OVLSW0FQgapzNTfIFMN/V1JTwebVYhCKcTBT2M/C+
         eMb8onYRR5CXmsEzfLjxyxg41eAfOXLVqNUrH9kQXM7Dz1CRYr/GKTz8cN8hN0zC3f84
         jSFBBTy85MzbDENfTdtXvguLL41+wQ0owziIju+fAmJJT81Z3J8FmYFBivPoNZGV5Bi/
         fwv7EMgqhOWIwtkavsk6JcSPN0tUkJVh0rPqDlgNMfILOAEKCKG0H3owCMl7joohqRnX
         qwTxP5acUYnXV95tz1cRKXsh4FIWVLzyU05pBzncW0fAf5wiG/Pton9uyBFEDHcPwFu6
         gxbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RrO90kbvcyNt+e9ZVX7pwr1F7sA4fApOPrmHyw0+q+I=;
        b=Uo1HBJwow/JoNsjfj14CUKfdevnN7ewEmGCP6+Ej+iD0YRNKOs8nnEeZ8RxlbcNqNm
         kiJc9r58mmfRslm9vUc3SNzbq82lHboaRQQ6Fd/mOpXwnSd2cvGjLq+KCwVAoYJyou0B
         VDJ0Ta81xzf99NqTLSl+1X+3kcTyA9aDkQRSGYTL1xGEqy1JNhc1Bgda6g2rGL9TlThJ
         Kc+2DAcF+lXW4p1PO9FfVyNHK3Iwsw+xujIvpfwgyv2fBiCXwAcnN1jkMKUDJT0OEWFS
         ZYEt5qLPCRS6eLHhyaSBTKYY7ej9plSCm3YMGPPpASRdsoxEx4JUxwVMhfu0Pq6ivZN0
         AWrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.162 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from mail3-162.sinamail.sina.com.cn (mail3-162.sinamail.sina.com.cn. [202.108.3.162])
        by gmr-mx.google.com with SMTP id f13si999937qko.2.2021.09.18.05.38.54
        for <kasan-dev@googlegroups.com>;
        Sat, 18 Sep 2021 05:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.162 as permitted sender) client-ip=202.108.3.162;
Received: from unknown (HELO localhost.localdomain)([123.115.166.15])
	by sina.com (172.16.97.27) with ESMTP
	id 6145DDD200032DEB; Sat, 18 Sep 2021 20:38:46 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 39170349283440
From: Hillf Danton <hdanton@sina.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Hillf Danton <hdanton@sina.com>,
	syzbot <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>,
	linux-kernel@vger.kernel.org,
	paulmck@kernel.org,
	syzkaller-bugs@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Kalle Valo <kvalo@codeaurora.org>,
	linux-wireless@vger.kernel.org
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
Date: Sat, 18 Sep 2021 20:38:35 +0800
Message-Id: <20210918123835.4295-1-hdanton@sina.com>
In-Reply-To: <87mtoeb4hb.ffs@tglx>
References: <000000000000eaacf005ca975d1a@google.com> <20210831074532.2255-1-hdanton@sina.com> <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx> <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.162 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Wed, 15 Sep 2021 10:57:52 +0200 Thomas Gleixner wrote:
>On Tue, Sep 14 2021 at 20:00, Dmitry Vyukov wrote:
>> On Tue, 14 Sept 2021 at 16:58, Thomas Gleixner <tglx@linutronix.de> wrote:
>>> Now what happens when the mac80211 callback rearms the timer so it
>>> expires immediately again:
>>>
>>>         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>>>                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
>>>
>>> bcn is a user space controlled value. Now lets assume that bcn_int is <=1,
>>> which would certainly cause the loop in hrtimer_run_queues() to keeping
>>> looping forever.
>>>
>>> That should be easy to verify by implementing a simple test which
>>> reschedules a hrtimer from the callback with a expiry time close to now.
>>>
>>> Not today as I'm about to head home to fire up the pizza oven.
>>
>> This question definitely shouldn't take priority over the pizza. But I
>> think I saw this "rearm a timer with a user-controlled value without
>> any checks" pattern lots of times and hangs are inherently harder to
>> localize and reproduce. So I wonder if it makes sense to add a debug
>> config that would catch such cases right when the timer is set up
>> (issue a WARNING)?
>
>Yes and no. It's hard to differentiate between a valid short expiry
>rearm and something which is caused by unchecked values. I have some
>ideas but all of them are expensive and therefore probably debug
>only. Which is actually better than nothing :)
>
>> However, for automated testing there is the usual question of
>> balancing between false positives and false negatives. The check
>> should not produce false positives, but at the same time it should
>> catch [almost] all actual stalls so that they don't manifest as
>> duplicate stall reports.
>
>Right. The problem could be even there with checked values:
>
>       start_timer(1ms)
>       timer_expires()
>         callback()
>           forward_timer(timer, now, period(1ms));
>
>which might be perfectly fine with a production kernel as it leaves
>enough time to make overall progress.
>
>Now with a full debug kernel with all bells and whistels that callback
>might just run into this situation:
>
>      start_timer(1ms) T0
>       timer_expires() T1
>         callback()
>           do_stuff()
>           forward_timer(timer, TNOW, period(1ms));
>
>
>T1 - T0   = 1.001ms
>TNOW - T1 = 0.998 ms
>
>So the forward will just rearm it to T0 + 2ms which means it expires in
>1us.

Thank you, Sir. I could not see the 1us without your explanation.

Hillf
>
>> If I understand it correctly the timer is not actually set up as
>> periodic, but rather each callback invocation arms it again. Setting
>> up a timer for 1 ns _once_ (or few times) is probably fine (right?),
>> so the check needs to be somewhat more elaborate and detect "infinite"
>> rearming.
>
>Yes.
>
>That made me actually look at that mac80211_hwsim callback again.
>
>	hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>			ns_to_ktime(bcn_int * NSEC_PER_USEC));
>
>So what this does is really wrong because it tries to schedule the timer
>on the theoretical periodic timeline. Which goes really south once the
>timer is late or the callback execution took longer than the
>period. Hypervisors scheduling out a VCPU at the wrong place will do
>that for you nicely.
>
>What this actually should use is hrtimer_forward_now() which prevents
>that problem because it will forward the timer in the periodic schedule
>beyond now. That won't prevent the above corner case, but I doubt you
>can create an endless loop with that scenario as easy as you can with
>trying to catch up on your theoretical timeline by using the previous
>expiry time as a base for the forward. Patch below.
>
>/me goes off to audit hrtimer_forward() usage. Sigh...
>
>After that figure out ways to debug or even prevent this. More sigh...
>
>Thanks,
>
>        tglx
>---
> drivers/net/wireless/mac80211_hwsim.c |    4 ++--
> 1 file changed, 2 insertions(+), 2 deletions(-)
>
>--- a/drivers/net/wireless/mac80211_hwsim.c
>+++ b/drivers/net/wireless/mac80211_hwsim.c
>@@ -1867,8 +1867,8 @@ mac80211_hwsim_beacon(struct hrtimer *ti
> 		bcn_int -= data->bcn_delta;
> 		data->bcn_delta = 0;
> 	}
>-	hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
>-			ns_to_ktime(bcn_int * NSEC_PER_USEC));
>+	hrtimer_forward_now(&data->beacon_timer,
>+			    ns_to_ktime(bcn_int * NSEC_PER_USEC));
> 	return HRTIMER_RESTART;
> }
> 
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210918123835.4295-1-hdanton%40sina.com.
