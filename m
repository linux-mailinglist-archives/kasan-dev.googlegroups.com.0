Return-Path: <kasan-dev+bncBDAMN6NI5EERBWULXL7AKGQEHFL5AHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FC4B2D19E3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 20:43:23 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id x16sf5171547wrm.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 11:43:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607370203; cv=pass;
        d=google.com; s=arc-20160816;
        b=T9BRLRfmBcwcR1NX/+e5T2NXXBWTHhL0cBGlEC6aEgA/WmjZX178OKZDqKkjl/usC/
         +OvcqhOjuu2jeDiKhffvgqbeiDwLIzV1d4jaOd5MEAi6xOiYvUf3r0qpbFZyHs23wRXV
         HlNXA0QX1I8crhmSa4xR8djqcQNNQm5IfhErhVukfdTxJjec/HgqBZeTGD9UjRuZrVA4
         Rw9GNKwC1CFKSuY98n2NHYvPJKZS26uiyvlp2gah4w4N66AagmaKHF1SDra+hZjAddrd
         RkxBdxQlTQQtVw3Gx2efmj37KsITsd5LKf5W2B+12l7UVWW/DrIPiLEawUUb9BQS8KNI
         oRgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=tX8jwesPSUxPzOdIkKJugdLHGsZJ/cHodJkKf+15pww=;
        b=Y/XDvNtQrG9rFuaKcJG1TM/HK7WSYu2RK/YnJRc9IySODCVzXnJhUis1wHztqnLGr3
         Cqh8SO+ZjqhUJMy3Wl/XpocQEoDIjpwUc36v4BTuP3aXRpFaluqWaKUeGmcIB6ywsmxh
         dTH19IvuVnjbDmzvUvfJdManpXgJtR1akQIHF8P12yu/fZGvCpvAZ3WUJztbkvRmHNLC
         1TpeEbAxKyCXNa0cEBMmp5t8HOAyugs7ywPbvxKmVtc/ri8uKXU8WhKkJOGIBHEG2aa8
         DudBKrsYfunAlnVeDLXZYpiPLSVGV+IlvkbTsEya7syYo+mdu3ThpIsm8BTeTjPinqd4
         XBcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JZByJyfF;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tX8jwesPSUxPzOdIkKJugdLHGsZJ/cHodJkKf+15pww=;
        b=MzXusyTdVp+fpPTwsGSRqLDRqZ2+eNTYBzeXsU/8fG0du+PhQsY7yRdc5t6C9OdUpo
         vK2LUS2/R5reIH23PkJ0kYnecx87Rn4DNZlkJLmricw/NjLaXTDtifXLBus3RhFYDKdv
         8YLNgNucT1u+p2vdy9z6QYsMBEFeQ9MNMmpZvOCXn+eAT7RBfIMDcWRABph2n/2Yjiht
         9kT43Ff294X5MB4y0xd9ta9cOZJZVMlKn5njz9LjbFa/8bb5dZenjFRbENRf0aNyuFm7
         kNitJLrlVlX/4/5DHKhTUMZoH97XjB7itTiuiHq0Nq0AIiDxDNv77kcNxY3FiCvWlHS1
         +M5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tX8jwesPSUxPzOdIkKJugdLHGsZJ/cHodJkKf+15pww=;
        b=fbYd1kCXh5pvflXq9V8drGnoPUCZqgqU5SVCjfkcKDuS0XIlxbezrHCJvREAgKIPXV
         SxDVc4s763Vrlx6Z8s3Rpam7MqoCUAUAxT56Ahb+SQs8tvebwjculA9HKNRhOKA9oqIU
         1o2Ew4CIEDLTLR8ET02wWvJ3nXfRx15E0ua4UZ9BF+Ru+iYzMCfMacaWh4HSXNTYpv6V
         QUNbSioj5VncQMfntLSx0SQEay3t9yzgG8+/bnh8VIet/k6iTbdSCdcDXjdkdKgzj8sG
         z4njin7XTz/XAr7GUyrrwiS1HMVsOQcwnPuBHREfZ/ALhsWJRp/gS+dun01Kr+NoYpJQ
         jzqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533woVcwdr/iv4tdx5o09lqDFTopSyw60p3qwZBh7xBkDFNrxVOA
	Aaf/xaSiYlYdHRMoBV2fsQA=
X-Google-Smtp-Source: ABdhPJzrAfrvpFGKMWsTg6VGLSBYOi5belFTV4JQPy5U9u4zATmMkfUkxMFCvJXgCabgB1+OeLvEGg==
X-Received: by 2002:a1c:24c4:: with SMTP id k187mr470988wmk.14.1607370202950;
        Mon, 07 Dec 2020 11:43:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b688:: with SMTP id g130ls106966wmf.3.canary-gmail; Mon,
 07 Dec 2020 11:43:22 -0800 (PST)
X-Received: by 2002:a1c:1bc6:: with SMTP id b189mr392412wmb.71.1607370202119;
        Mon, 07 Dec 2020 11:43:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607370202; cv=none;
        d=google.com; s=arc-20160816;
        b=m3Q6MMW+5MFchPcmf1ZezrIYBBgXMCmDHxbnqnM7j8Lj8NqcmamK3jMrkbVk8xJSZA
         IktiWPgpMHz0gXwPTwXwvj7ULWA8H425LUL55XQCa4VP8aIWOOfX98prBnZ9HMilEWlP
         5dahovFIKCMjtGaSU8GDdaDL2b9nU2hvPUR9Cn780TQcug9RP7nj47gTdBCCp1ZVLTHN
         gOk15Hym08FUbkvd4kPgLFjv212J+hehhDWBwR4HobOpoOSNJ1MZHdxkO9ijBCb8wSyf
         c2LQ/uHo9XDiO43mASOqXPTbc6ES2RKVhlyLYUB6IOZcMNs/b7YPy8uPXsn4lNfyqBr5
         qRXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=I334otsRnjsdPvZNHbr6PY/AxaoibaWvPiqif0DnRJQ=;
        b=YcDctgiq03okIdy2ThCiSwWJzW1qOjyj/ovnQ3/CorM6brzMcOe7rR9JgXQpR5PlYu
         VSzk4wyTIf1xYORjtjTJ0zfYDjpgAcW9hd5c1rpecSGosUJsNoxuBzKX1UVi8vXhcZC2
         n2XKzkabiy1SD4nWbGiarSxIZwEv17LFDvjuuNFHdzYkMAYDmc0EBS8ubZyHaf+peRuq
         PsigNdSN3hRYgcHhX7oYyHzkAwBJGHoycHarCOq7PF4G7USeDc4vOuWmGPhcRcNwx6wp
         RHv8Xbbc0KJDlaNkPK1fvFFaYVcng4C2LQg7eGSJ8d9ZFo9gE+LzuaNhq/TEB9Mx83i7
         hbWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JZByJyfF;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id v15si19627wrg.5.2020.12.07.11.43.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 11:43:22 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, syzbot+23a256029191772c2f02@syzkaller.appspotmail.com, syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com, syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
In-Reply-To: <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
References: <20201206211253.919834182@linutronix.de> <20201206212002.876987748@linutronix.de> <20201207120943.GS3021@hirez.programming.kicks-ass.net> <87y2i94igo.fsf@nanos.tec.linutronix.de> <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
Date: Mon, 07 Dec 2020 20:43:21 +0100
Message-ID: <87eek14d2e.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=JZByJyfF;       dkim=neutral
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

On Mon, Dec 07 2020 at 19:19, Marco Elver wrote:
> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
>> On Mon, Dec 07 2020 at 13:09, Peter Zijlstra wrote:
>> > I prefer the form:
>> >
>> >       if (data_race(tick_do_timer_cpu == TICK_DO_TIMER_BOOT)) {
>> >
>> > But there doesn't yet seem to be sufficient data_race() usage in the
>> > kernel to see which of the forms is preferred. Do we want to bike-shed
>> > this now and document the outcome somewhere?
>>
>> Yes please before we get a gazillion of patches changing half of them
>> half a year from now.
>
> That rule should be as simple as possible. The simplest would be:
> "Only enclose the smallest required expression in data_race(); keep
> the number of required data_race() expressions to a minimum." (=> want
> least amount of code inside data_race() with the least number of
> data_race()s).
>
> In the case here, that'd be the "if (data_race(tick_do_timer_cpu) ==
> ..." variant.
>
> Otherwise there's the possibility that we'll end up with accesses
> inside data_race() that we hadn't planned for. For example, somebody
> refactors some code replacing constants with variables.
>
> I currently don't know what the rule for Peter's preferred variant
> would be, without running the risk of some accidentally data_race()'d
> accesses.

I agree. Lets keep it simple and have the data_race() only covering the
actual access to the racy variable, struct member.

The worst case we could end up with would be

    if (data_race(A) == data_race(B))

which would still be clearly isolated. The racy part is not the
comparison, it's the accesses which can cause random results for the
comparison.

Thanks,

        tglx


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87eek14d2e.fsf%40nanos.tec.linutronix.de.
