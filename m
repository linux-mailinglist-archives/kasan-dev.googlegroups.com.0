Return-Path: <kasan-dev+bncBDAMN6NI5EERBGH5Q2FAMGQEDIK6R7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A832240C2D5
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 11:36:25 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id e10-20020a05651c04ca00b001c99c74e564sf1212818lji.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 02:36:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631698585; cv=pass;
        d=google.com; s=arc-20160816;
        b=rwTeQ3Jci8jAlG2dhqCJJD8NRhofONlRkmwvtibbv1GBylyl1S7c5uJZzxmddJkI7x
         S6AHfAJ2lZurrLRz4yb/RNsndtTe/DUrNpi6PzibNEUlXXD8+3gduv6hZIwVLcmIV5HO
         pmjmaRPcmwidShx8k6S+d83217UAKY0AWhnsF/7Nw6XPrMBsTt1O1hoOfo7FIhPA3RZ3
         PzpEoCeIiMvuy4qRHgTXXzebV4xZPq+COlwY18GV6kf+wuZG5Jl1QH9nkctMQV5Ddsgr
         aT4/Zsut9sECffuaiseluiUZM3vLaPfSyXnnCEj0dSIBvW7SoSin0mDUxKEqZY4Gr+uR
         he5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=/R9vK2NFlnUdm0z4bR/t8+dVUfvJOhuV8jDHSjdyCek=;
        b=VvxWivhY8/6R5K/Xl9N9z9oE0w3SzYBEgAaWEcPR3KC+TjBGM8ltluFwDxzgrX2LsW
         yoHsmYAxS3TgyuSNJ8ZkggwfAx8k88HpAUzSLuUm0nQJztwhJZmyUUl67IFa+mN2OWFT
         K44y4vVM1Cs1DLDPt/fgp6H/RlAOWVC8Fa+/GsWQiV7WuAAPuv6DMdpzw6Ta2ht94Cfl
         yTfgWyPM9OMTOsI1ZlGi+Zf0COGtvM9z628srfYzjleErcj/PZVe6a1lS8cZ0AfGjUrw
         pKhF2p43/QCUSZCiwSghwF61SoeaJHhK+v9pNSbWfAMiDnFfAbaVbyvprICcRkptiM22
         VbSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=tybsb7EQ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/R9vK2NFlnUdm0z4bR/t8+dVUfvJOhuV8jDHSjdyCek=;
        b=R3nBhGG7IP1B7RnG6CMhKoVpVfpSVn3V7rfl0nl/qaA7jI8fKanA3nCkUF0tIUyVZM
         RXUBpW+ESm602JOxHKp9QFyUIKJ/8/MpXmSoVEevwvYuDvKITODNH1dZH3EU0RvoLwTT
         lQKDvlJobY6uEILNkRdxPby6hHyStMjbvfr9Y48bdZpKcTO/CSWx9AIqC58c9tFk9GS7
         SLeYvFRxYgPzsASFJI5oz6p6fwI5tlm+8Xf4SJC0gCo4DIj28hKDWWQ7dFAtFdo9211V
         QPA9zxzpc6xt2pZkkA0xnF7/ivGV3LpEHM5WYYFZObG9sStB9nKRJWm8CoLEHC641DN0
         JF1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/R9vK2NFlnUdm0z4bR/t8+dVUfvJOhuV8jDHSjdyCek=;
        b=w4P/vY5dTcIBSfIdf5MGMD0yPqs7C47b2xk0Qb/jHBDxh6SnXZ4RchxmSSUYntfQS0
         iK7VJ9Rn0byKwdcUR6jQV63tct77thToSMQWJaOLj1b5H+B9y7bCoEhwAfetzN5OMHB+
         aMUxtLWcMek/UJEbF9zx1Hm+YpwqKRlGcRd0hkP5OSv8XKA62OWJDPhOrJv01iqqz4Uv
         Ne0G1ugMOj0d+PJYnkSPV4+9aFo6NHHlarfmYQ6cuBWJzZyfrLKctKNo1qu2N7aAwRcj
         76Hu22jd2zzPEa2GSw2FCAi65w8oXcCZpmTOWkqDga8Z2kpq9gTE9/E+xpr107yftOTv
         SZtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WKJko8wZ2rBG2yakWjWzdSSDHQMGTGty7ji61Lm4Ui6jnXUon
	krI2IrLQPAEzVg3U3pdLxKc=
X-Google-Smtp-Source: ABdhPJxwcU4Yy+4nVbD4uSiHikOGE+NbXk0LpL6k+hxuw7Wb5IAfKQ9ya9SIkvL2abUz4DBjnxFcAw==
X-Received: by 2002:a2e:b610:: with SMTP id r16mr19416658ljn.367.1631698585202;
        Wed, 15 Sep 2021 02:36:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b88:: with SMTP id g8ls1731911lfv.1.gmail; Wed, 15
 Sep 2021 02:36:24 -0700 (PDT)
X-Received: by 2002:ac2:561c:: with SMTP id v28mr2661331lfd.457.1631698584182;
        Wed, 15 Sep 2021 02:36:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631698584; cv=none;
        d=google.com; s=arc-20160816;
        b=RCpS9yKa0gt3LnicaJ6b2WpYP30AqmOGn2ltBbnfJ6Lde0kfNgsqXVzC8VPWshnCPm
         58NBI7LeEMvjU7UrEIeeAQtasC8iy5K1V8zbe1WF+mCNt2RZnBpbKLp8v0pIikVqS2K/
         YeGDTDbyYbtcwlkDjLvEMPSsxLnx5tzW8UI7befEEjDMJgZtYhBxSZIXT+lHDL5L2ND7
         akktcD+eldhxeYOLQV1JgP3hV/1lStdnfJTBclAcXVS0x9/2glgK7JgD2kcv+o21FYOb
         MhTMg4xoVPR6E0jnwBgmsGdOVYOWkbNqa0F45MjhNsutoRIsP1gjbW7DkibwlWtlPJWY
         lnfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=4Sotz2qZ3V6mRPHb85bGHa5oilfi1mvXzoQ/qd51OsQ=;
        b=obtUI6DDloFIUflnWoby4QyynzZiKTtJHa/xRqx9j2HWV1I7WWF12oVCGES0/Az4VE
         UtwzWL/5f1n+yfPfS15zeXrTHeHwemxKaDq07bAvOacbq0RbS3mEn/OW2+4BH3pXSTBc
         sNj5MDnm3y6wErGrdyvnRdC2GRM51iCo4LBJPF0u+rum5veL8BXIIt9kcDnXKDkEAOy9
         aXr7EosYawjylGv3Uxto/z92LHPH6JiqdYORZDqac/v3xrUK02R2zb4ccEEF3aXr8Lvf
         k4FvDf0W7eGJTRzBuuSE6myeLUuz8JaPR4fcU9D9pvG0/8ga4Ern9oxUMjS8Hw9j4pHo
         xDMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=tybsb7EQ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id g11si869576lfr.3.2021.09.15.02.36.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Sep 2021 02:36:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: paulmck@kernel.org, Dmitry Vyukov <dvyukov@google.com>
Cc: Hillf Danton <hdanton@sina.com>, syzbot
 <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>,
 linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com, Peter
 Zijlstra <peterz@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
In-Reply-To: <20210914183142.GP4156@paulmck-ThinkPad-P17-Gen-1>
References: <000000000000eaacf005ca975d1a@google.com>
 <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com> <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
 <20210914183142.GP4156@paulmck-ThinkPad-P17-Gen-1>
Date: Wed, 15 Sep 2021 11:36:22 +0200
Message-ID: <87ee9qb2p5.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=tybsb7EQ;       dkim=neutral
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

On Tue, Sep 14 2021 at 11:31, Paul E. McKenney wrote:
> On Tue, Sep 14, 2021 at 08:00:04PM +0200, Dmitry Vyukov wrote:
>> If I understand it correctly the timer is not actually set up as
>> periodic, but rather each callback invocation arms it again. Setting
>> up a timer for 1 ns _once_ (or few times) is probably fine (right?),
>> so the check needs to be somewhat more elaborate and detect "infinite"
>> rearming.
>
> If it were practical, I would suggest checking for a CPU never actually
> executing any instructions in the interrupted context.  The old-school
> way of doing this was to check the amount of time spent interrupted,
> perhaps adding some guess at interrupt entry/exit overhead.  Is there
> a better new-school way?

Set NR_CPUS=0 and if then any executed instruction is observed the bug
is pretty obvious, isn't it?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87ee9qb2p5.ffs%40tglx.
