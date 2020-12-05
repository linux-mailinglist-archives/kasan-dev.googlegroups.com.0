Return-Path: <kasan-dev+bncBDAMN6NI5EERBA5YWD7AKGQEV247Y6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D91C2CFFCD
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 00:47:16 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id h68sf3918352wme.5
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Dec 2020 15:47:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607212036; cv=pass;
        d=google.com; s=arc-20160816;
        b=OghXW1Gao9Zzohop+vQ67uLkeuw1Uq6aybuFfdMf3M8PpDWKZkzRALX2jEWtRL5CIA
         sG+67/k8l0y3D5qVtNfqojBzUfUxQqQhoTPFbHuo44C+MsVvg+1bEwUHXEjpgyHglulf
         +PxbvI3M4Gszc35V9o9z8empL6cAu2di/DZGwOYv84gz2ZM/Q1GtFTza7kNgxtArau+/
         edG2ir4O2EPAG7BgguhyibsCPRsv72/9hRhLsqNI4r1Q7HHDlawVcAAtF0521YqPN4fe
         TCegkIEM7xrl1UynhNeJ7tS3fLUE4wIuUD0xg8/4GL70p/QEdNZUiWmJjF61Fvz81mnV
         W5ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=i5rbM6KiupLN7JRHVzWow8h1VJy8HOn1T5eQ9QLr2SY=;
        b=etv4Fl76oOHTxB7neZoanVxZe96a8p1qg5cEK7wyTojh+hwiDTmKsTrDHCZ7q6vzCP
         Pqf/pCQReAEVzq9k8insPjeE7pHQmTvUWoj2Nurd5j3fpjFhxmhni7jPPn9WZo++SnZL
         Vm8Qi5LHKZSCoUGE+7dtq7DMKt7sudBYXb6MBRk3DVmgExcggFc6+iY06yvSn0iUxo7s
         7LC26d9obFA4wlwfIzUn4X/gWXgUn40e5z2f7HV+81SXgzOmKvHWVljU5ZmzAptK/2sb
         UpXm8KL/RFV5NjA+KlZpmvT7d13Jp9utYNYPGl5BOFjbluSbLH9Q1cHj22QxcfMrduVP
         eW8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=VyPbPWrI;
       dkim=neutral (no key) header.i=@linutronix.de header.b=05aQoE1F;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i5rbM6KiupLN7JRHVzWow8h1VJy8HOn1T5eQ9QLr2SY=;
        b=KlfteGnUa5VXYDFkD/tNqUQjuIJb0dQO1jqTkG7UDOyi+HJVWoDfovpRna1xUp9UDS
         jTROzlWWtECX8Th9+NggWoIezfZzKGyyaBgnKK0V9HOTRvpZRmgzJ3Aqap8TV2DHyjcu
         ysQLBLpmgJ3ypkc3zETmRYyB2+L/IEezqGbPJZ9Nzysb3TamfU6XTKQl30gfj/j55/sv
         658t3N59ghYYuPbytGHnIQnAiZz7NIyokD/3jrAyf0vvdpJc0a0u73txn+mU2BNTtvhe
         INAvEVZpI+rkt9OUsoRauSl2Zr69mfkIV+7+ybdyXmV/tMo7ekmop77mZY0fEAf/UD8s
         pZuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i5rbM6KiupLN7JRHVzWow8h1VJy8HOn1T5eQ9QLr2SY=;
        b=U4AbJPFQFWnIcwjWwN1Xc+3/jif0q0rXcTUDo4VxzYxXV26XRRm5IHuMuL7Kw6AsJ6
         SoZ7d4Q3OM8A7EaQ5e0zVCY3zvhHAJQpiblmg262lrw8wvtL/1V1FIlOWsCbnYZ3OS0X
         i1CVjYU2kihdKYIjtaiDrRL4R88pc7orQZ3Wj/VA3FpCyq6MvQZnWZPNnrbJNwOPIzAn
         6ZKdbZCA8B0Y3pW0c1+X6vAXVm06hTmSMQgIX4n2i8icaZQ+wo6K5+ksR+5C4ZkfbqpE
         q4O5yeIzYquzFwnve5rtvQ5SUVe8X4ibhZR9+vrFP4n1e0ZI5SJl0LYnnyZSTwRp0bSM
         Iy/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LwPEwEL9zSSgizlevAuCBI2+27poWfZdehOQY5Di24bkdKCc1
	2azQYgwUzCviQsFGVpR8QuQ=
X-Google-Smtp-Source: ABdhPJzuGDaW4mULUv5tztD0EUic7w+50t0yrn7aaPRw3pYLCkN5hJxxC8E23WCWtIXgByQ/DZ20qw==
X-Received: by 2002:a5d:4a0a:: with SMTP id m10mr12321901wrq.16.1607212036129;
        Sat, 05 Dec 2020 15:47:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb0e:: with SMTP id s14ls879610wrn.2.gmail; Sat, 05 Dec
 2020 15:47:15 -0800 (PST)
X-Received: by 2002:adf:f881:: with SMTP id u1mr11931161wrp.103.1607212035293;
        Sat, 05 Dec 2020 15:47:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607212035; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9xQxRMCrwPUJgZwv645tNkZf3lzVJmPKkERrRWdMg4IgKaORVvkBLQHfV6qEqEVPC
         MIHmnZoZ9x2/akqIWbL0l/QDdsuYfZF+CAQfuhtPJRnrScuS0lnaPLzRZM/PiFOntyCG
         PPENkQDp8w/wUZWktw72jrmiVLcDkxl6uWvDeqn6c73vfQAqC76zdLffFAyNNdebOon1
         Wpn6rQTjsBKW5MySrriL127FV7TlzY/gXX5VoUsF5nRmONudceJiAZvyVfwxh5QQQe7m
         P5Jj0UGjg8h4JJf1rimgN54gh9fq4ruSmZB9jG1Sr3LJd+a28nsJXcHUPG5FC3rCDgbw
         04qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=cCD+MM2ELmrBKfWFSQdz97hYPn7ejqug1YoM2ZlKSVU=;
        b=TtGpNsmE6spJx09h9XGLKSFCPinDoHKhAFVNZ0SrTsjIsA5ii58d6JHSBElrK7SLyP
         oOyeLaevj4aJymrzje4aMpAhFrIvXkSKBj6uxq/VQAn7G+yjKn0RBRaLI72iaKH/Gbrn
         6secxBhXENONP63BUCP8X1fbwE59T72eVsye9p2BJexOaU/WSk9d6m7KOcYEHJ1TqK3P
         cqUZWCHEf9EeQL93TnwhCMAKQoW3Vw4B0T/F+hW4QjRZS4K0GEoLdDTeOkYIFOrJBZLA
         UY5/gasDbE9O7koTaSzat6NIahYZ1lfYv0jpgNj2VuM/deWeBui2QNp3nCBlfOJvkuiI
         8ybQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=VyPbPWrI;
       dkim=neutral (no key) header.i=@linutronix.de header.b=05aQoE1F;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id x12si258233wmk.1.2020.12.05.15.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Dec 2020 15:47:15 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Marco Elver <elver@google.com>, Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, lkft-triage@lists.linaro.org, Peter Zijlstra <peterz@infradead.org>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, fweisbec@gmail.com, Arnd Bergmann <arnd@arndb.de>
Subject: Re: BUG: KCSAN: data-race in tick_nohz_next_event / tick_nohz_stop_tick
In-Reply-To: <87wnxw86bv.fsf@nanos.tec.linutronix.de>
References: <CA+G9fYsHo-9tmxCKGticDowF8e3d1RkcLamapOgMQqeP6OdEEg@mail.gmail.com> <CANpmjNPpOym1eHYQBK4TyGgsDA=WujRJeR3aMpZPa6Y7ahtgKA@mail.gmail.com> <87wnxw86bv.fsf@nanos.tec.linutronix.de>
Date: Sun, 06 Dec 2020 00:47:13 +0100
Message-ID: <87eek395oe.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=VyPbPWrI;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=05aQoE1F;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as
 permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Sat, Dec 05 2020 at 19:18, Thomas Gleixner wrote:
> On Fri, Dec 04 2020 at 20:53, Marco Elver wrote:
> It might be useful to find the actual variable, data member or whatever
> which is involved in the various reports and if there is a match then
> the reports could be aggregated. The 3 patterns here are not even the
> complete possible picture.
>
> So if you sum them up: 58 + 148 + 205 instances then their weight
> becomes more significant as well.

I just looked into the moderation queue and picked stuff which I'm
familiar with from the subject line.

There are quite some reports which have a different trigger scenario,
but are all related to the same issue.

  https://syzkaller.appspot.com/bug?id=f5a5ed5b2b6c3e92bc1a9dadc934c44ee3ba4ec5
  https://syzkaller.appspot.com/bug?id=36fc4ad4cac8b8fc8a40713f38818488faa9e9f4

are just variations of the same problem timer_base->running_timer being
set to NULL without holding the base lock. Safe, but insanely hard to
explain why :)

Next:

  https://syzkaller.appspot.com/bug?id=e613fc2458de1c8a544738baf46286a99e8e7460
  https://syzkaller.appspot.com/bug?id=55bc81ed3b2f620f64fa6209000f40ace4469bc0
  https://syzkaller.appspot.com/bug?id=972894de81731fc8f62b8220e7cd5153d3e0d383
  .....

That's just the ones which caught my eye and all are related to
task->flags usage. There are tons more judging from the subject
lines.

So you really want to look at them as classes of problems and not as
individual scenarios.

Thanks,

        tglx


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87eek395oe.fsf%40nanos.tec.linutronix.de.
