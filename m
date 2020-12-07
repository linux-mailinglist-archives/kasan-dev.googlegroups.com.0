Return-Path: <kasan-dev+bncBDAMN6NI5EERBCOVXH7AKGQENZGWRVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 95A392D17C1
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 18:46:50 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id r5sf4877241ljg.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 09:46:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607363210; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xali96sp2bIfjuiVdxYqKImvmwycFa8zt0PvO1GuCgJ+wzmmJYBtAMH8XOf+G/GEdR
         mfaVIyrM2zVMz2HHORqrRTTNTwH91RfPgdvuzHb3T2R/+FSt7FJSyBN2zJtTwcV0knPh
         uE74UvEU1q1jv6G/el/PZxB1G0KftH6mNJVtqN/Wow2kU6bj/ZrqI2LZxFY0TnkN20W0
         QtpL2RiPbr8v6GSNH3fv3Rcq6keFAiF7S4dzn7ghYB7xoAHW/ANhd1ERMrKvHuj8TbyH
         S5BzPw74U+1AFXZVgBCng+49DVrvwoI0o777A/3m5oZ1ZOfYErAQVkxTEQZzJ0taRT6U
         faWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=uz3AHeX4KXQ5wV+73WoTrgNkpQFOqyiPlsQQVvNUpIM=;
        b=faieTcrsUgEVMVCuELo4HfGyXcU3IV5+ezotrzMYjpeD82ynlGZr+S3AW4Es1fqMQO
         csgDBHcpOVifUmjiznkuXyO0m5YveafEbrhBTvlRhkUzUH8STdWkcasc7UhRSDm2YGmx
         tzWa8UJKoHBqZeQhOlxJKGhla6TZfoOifaLRVTxMX75GF1vVsbmhC9DdgFyPGvIy1/nL
         7l7Nsr1/hjRgFEt/Jdq5lr3izXQFpnNyZIrceJQ1+6VvywToZz89G8waZo12G70B5cY+
         7JD821MpAVqOJ3KJO56SiQjRcT2nbMuu0h9VauCb20JWeDG1x+WGMYHNc5EZG770imbf
         TICQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=OVGEyYBn;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=LVuezxMd;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uz3AHeX4KXQ5wV+73WoTrgNkpQFOqyiPlsQQVvNUpIM=;
        b=Fkvn6UA+Nak/C/M1GmLOq0kAYZqc5sM/lp1kdIMjJ8ocsrH8qbjAHzvHooF0MAl78B
         pQ+Mfz6tJXymOqGN8/ndhh85w9b8zXNlH+NQGLQVtqD1P93mHHojeTVgcE8Gc4e86kAx
         Wa1RiPj6w3ZkDFzaxkLOfMPp/YVIkM63dOGA4K8Y7XDEZ9fKLQnNj4oEiO1iR1BoIaTa
         U7Z6TS9A6qN2nWQ53jOk61K0aK2RowXFzQk8lmiv5JbmtSZDsMOZ34DiT5G/9n4nfuFW
         MAQLaFsKIci/7XTqKguaChU9nXWuSz63PdmZLHaNWdHRe/NeNqYkbyW+EDJ2lmo7iUJ+
         kspQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uz3AHeX4KXQ5wV+73WoTrgNkpQFOqyiPlsQQVvNUpIM=;
        b=cATgzkl9WMN1YcGxepqaHA7jlD+Wok+KsfZjYOw7B6sbxynKwCg1Td6jZ9hEoiQo6G
         +sjpSLQKG5TRHRPPWb5yY/nZMMMkUVLsnGOh4ac8m9ui/UDQxPrCrL7LgVVFgJm8jxsl
         yzyqAlxRT6u9tm57xDlByqIWdzi5HbMrH3MSc5bLZH5Ho/1YwH/xyQIixPeEwron5uHF
         rueo1F3kXqm6m6FlETo7vUpv0IlzsrkouJW+4U5OaaUpl708bqZUfWWmtavw5lkAeWdE
         9QEo2zQfJLY/jNpEb+VlQSOO9uGDzqKMDNQ/L7FbrAipQCzXOMkajtsT5p6WmRyK/KWi
         9HIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mh4Jx3ASKLwZfB/b09D+anr0swRXzZevD8PMyGHsn1AyjAjXh
	XncLIFC/BuuCttTJjy8uWXU=
X-Google-Smtp-Source: ABdhPJz4maowxAhRn2qNDmvDhC45eav/1hziiK3k5ugH/DL/jAxWbDshUE1eyrZgQa17yMPFTAkAew==
X-Received: by 2002:ac2:44a4:: with SMTP id c4mr1242121lfm.214.1607363210202;
        Mon, 07 Dec 2020 09:46:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d4:: with SMTP id k20ls2377592lfg.3.gmail; Mon,
 07 Dec 2020 09:46:49 -0800 (PST)
X-Received: by 2002:a05:6512:21c:: with SMTP id a28mr9023257lfo.486.1607363209177;
        Mon, 07 Dec 2020 09:46:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607363209; cv=none;
        d=google.com; s=arc-20160816;
        b=vkkyUTqnwddlFHjQahcxzhkTCvlDE6PQuoaXnv5B7N0+6HoXskwfWaDZGDfutnFZUj
         mJphEvMwn4QMAe67L4NS5qhqkXsG7Fc2A7ERCsJC2xistRSbA16ZRjV+9am53kowBzm+
         99pq1PN5bvwp5uRLMQtpl8+04AjQEF8Z4yd6pHao2hNjr95CrWtyD5b5UrW/mVHN72An
         6aikzqf/KC+H7j0Xer7rAkRGQkFkeLKj1/9GDDWMOVNUfj8TqnD4aYg04LM2tNHSNVUh
         0rloLKZTTzWDwxswvCOwrft90l7Lfcu9NkhK2VDSugJ8bsLI3ASeWZ4yxtGpETHYebi4
         8xqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=afDC03InAXZsSNwfef2vWGfi5DTW9+sgf5g7C6+1NsA=;
        b=t0/YDSPuIlrEJkQE7eoNwCHsFn2ccIehGZwYgAMuXqpJ7yXmkRnr+S5XR59IN7+C+C
         0flmMEjA9pyzqvl9X3cYY0cdmdpyeCIBiN0EyS+y7hI6D0/jk5rrDssgTAtskv3bYmwe
         tHR0/GGDe4qV6mDDe+IlzB8KSPrUgrIKJJpBV9pBpFBa7YH1V5eDz0yglIZRst8Ks1g8
         mhMHs5QImnAaSIU5qPCeBew3pB3LZudY41Dz8TKlQL63+vcRmi3c+ZyIQA2sWkKSCFaZ
         GNPxW+j9L7I2U6clIePh6RAGwKY5LkdG/VlWIP9HbuirAq3yp2piWQOe6dkv0rxtYO5B
         aaMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=OVGEyYBn;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=LVuezxMd;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id y21si571343lfl.7.2020.12.07.09.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 09:46:49 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <20201207120943.GS3021@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net>
Date: Mon, 07 Dec 2020 18:46:47 +0100
Message-ID: <87y2i94igo.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=OVGEyYBn;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=LVuezxMd;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
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

On Mon, Dec 07 2020 at 13:09, Peter Zijlstra wrote:
> On Sun, Dec 06, 2020 at 10:12:56PM +0100, Thomas Gleixner wrote:
>> +		if (data_race(tick_do_timer_cpu) == TICK_DO_TIMER_BOOT) {
>
> I prefer the form:
>
> 	if (data_race(tick_do_timer_cpu == TICK_DO_TIMER_BOOT)) {
>
> But there doesn't yet seem to be sufficient data_race() usage in the
> kernel to see which of the forms is preferred. Do we want to bike-shed
> this now and document the outcome somewhere?

Yes please before we get a gazillion of patches changing half of them
half a year from now.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2i94igo.fsf%40nanos.tec.linutronix.de.
