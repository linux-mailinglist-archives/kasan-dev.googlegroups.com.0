Return-Path: <kasan-dev+bncBDGIV3UHVAGBB4ESXH7AKGQE4HNIQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id A79032D148D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 16:25:36 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id r1sf5460927wmn.8
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 07:25:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607354736; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovrMHqPoeHR86gAXxwTsffpE0GJszFflsZKn7mO+l9vECw7FCO69y0Rpmj+7t7GyeM
         bgpmVDhtIOKJ+/UC8jH8yvurRj8WsnSzovi7Y3LE5TB4A5QLwkIONHQUb0qXjFSlcQQg
         5uvB1glV/Mmlq19OzOCRVTEgHboiikZjN/VZ7YBVaPQaKlHR6u6H4u3PD9XRJcOvxI60
         N+QR+pJrxQd6Wcpt6v8FitWDtxTLrSUH1umfyDxi3zxoHX2U4fcZU5SEKHLisyOH5iKb
         TXdm3HSka2DfPGnkn/ycHq5ssv83lZ3IG0upK4braKKKKmV0e26WdyuQvYvq2hmSpqTe
         Iv8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KznFjIlMemvsuSolLUMr0v0L2kkREWBC3f5sZX4De0g=;
        b=AwAfS/sXicVBnCYEbew4fqFkEtyaU+VSTgUqcyIMsy1HbBEWDWkhEeLdqmQ8GXDF85
         q0BZgyE80xgVROvVj6BEXQt93z+nd5xNYGAS7auig24n6KyIUk6WFluUoQ6Wwx8o2OGU
         ab7yGh09dwHLL3CUV/mmk0adfR4j7eHX8UmoH+gHFE3U+kCJtKXKWUKziWcKv4hPbmem
         hZFmNJOOOYywDmFqvVRjZDmeVzihRO+rPYPAY+4RwvjuWO/hbfuPSKu6n4tI5Ge0NQfi
         EVZMR2ll1lOPCXCRX4+aMVPtyanu4Ce0mDKnkom4ZKGL25Boi2wPPtzqeYVTIYRvL742
         Rr7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=GLT2Resd;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KznFjIlMemvsuSolLUMr0v0L2kkREWBC3f5sZX4De0g=;
        b=Nwr5IOvw7khK8elD33rAMrvHFjH1N5SkdWU85plsmOTBCkP/atJZClQjxJMax1et1F
         wrhZvo/amZt6PG0wdo7rA/kQt6PoGPi3W1eJYcbwhaXOTwTUgKtVQfJalyAbwDe42CHK
         5qCCD8DBcsQQaYPpDB6Cj/b+p7afobosXz0xnuyL1TfM2LVc+BqlPrp3/mAcmt1NLVqk
         dFOAIL/WSeLqQjTGoemkYxqI6tZgJMBki/w+Gr0ZiIAG4dZsW6ALg0mufkrrV4gUBbGu
         0jh7mLn/6JWiJOV9wqX+YIVldgskZvmuWWZ/KMJUorH5fyOqWyXB9lwezNEke9/ydWmW
         tTFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KznFjIlMemvsuSolLUMr0v0L2kkREWBC3f5sZX4De0g=;
        b=f4HhZTF31xarPVjWyUkwHd0raYIzQnjUS+hUfJ6xd2lbcTwqWHxh4XtFPHRQb7khtP
         zRC0S6z1GsAqvx61Q04p890z7eUi6NneptQyr3tBU22oLq7IeqcDkwxOyOJNoAss3ijy
         TsjaGYiC0060HRNGpzz5evVrBxd3ZPZJmeZ1K0nBBpkDiVQIH42q6HrRGKi5kLrFhVoV
         Qz/JTTKbm5P7H5f1TyR/ff+x1//X+F2Egm5K7+sqL6E49HqlUjxjYqRZlVOBd4CevHK1
         kSdhRmzPQdivgIbvgHUKbcjid9zX5kYv3Y7mtl3naGM/Mk1nXnwNUHXsI0CNflCu3ypy
         wmQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Lex3DIUBer3yrFSeQcYYmcEYODHOQ+MUgygkm6Xed6bqyRKYL
	9q5GLAbgTVoGZo6UzAS69L0=
X-Google-Smtp-Source: ABdhPJwnmeXUvQ/vjlDZ/ffgCpdkPgo5wYxz8sj8KOdkw/TSxViMh6uWVO7vPaQric8zFWu5B8Ya3g==
X-Received: by 2002:a1c:4d05:: with SMTP id o5mr11157566wmh.85.1607354736384;
        Mon, 07 Dec 2020 07:25:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls2675867wrp.1.gmail; Mon, 07 Dec
 2020 07:25:35 -0800 (PST)
X-Received: by 2002:adf:e80d:: with SMTP id o13mr17979333wrm.293.1607354735545;
        Mon, 07 Dec 2020 07:25:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607354735; cv=none;
        d=google.com; s=arc-20160816;
        b=mFOI2DYhP5KANoGX+X7XHtnp5iRABXeNXp3UjGIzpjrdFhDE4bgA5yRdhU6JHBNJ8I
         tAOUrpquKRrulPKczZu4pwx18GeuUYzf8FPBqBeHP+TdmdsP8Pb4QgTQwy5OHEhuewoE
         FS8NjRA77BQ9dvTd+r80ig0RgQPM6ampXl2NS3bIcrURzZ70fA73vf+JeaJ/Ofsz5EV/
         TD23mJ1fFvwIQWLEMh+Xs5U/IAtNi8HrKPBo4/IZkpO5HTrDH23YayIeiUsEFL9VQMIV
         rKLxjHW8UB8vfFSBADBmJ6XSq51mmhEFJ/ty+7ebRoX5a0+JmZ0trYkT95M7IyvKnItO
         n62A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=Sv4eRfw6q+BoSj9ElHesitQZKO3ngXQI1PVZppTaTS0=;
        b=UcQ9BMA8ZHNIREB1Ipv0NtDoB/RhShZYYFbHh2RvwWYlBpcqyrMfnfu1NB25Mwijwb
         g3je+AH7AcqRPMtLv5VZ/5svFSsQycQX8G5LdXzia/KsnBuEsYWWLjGI03dxWArjzoAt
         zuOauw4qonNiQwQ8V5luyzjZJQxkfx6qRS9XUrkmgQiqifaoNRulOSMIIufeMqu41m1A
         rdhG/5W1hQa8f3NXJmRQo0ePc8CG1PcFBquY+9We50Sa/A5/4vHe7ht61Zghaur/PiWh
         Pm9RVrR9rb4bmrK7cFlXholddv0bDIOmC8qpgSyIGj+vPeg5kLg7j7yVi/S2zxnDCHBx
         Cjmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=GLT2Resd;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id r21si647976wra.4.2020.12.07.07.25.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 07:25:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 7 Dec 2020 16:25:33 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207152533.rybefuzd57kxxv57@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207130753.kpxf2ydroccjzrge@linutronix.de>
 <87a6up7kpt.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87a6up7kpt.fsf@nanos.tec.linutronix.de>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=GLT2Resd;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
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

On 2020-12-07 15:29:50 [+0100], Thomas Gleixner wrote:
> On Mon, Dec 07 2020 at 14:07, Sebastian Andrzej Siewior wrote:
> > One thing I noticed while testing it is that the "corner" case in
> > timer_sync_wait_running() is quite reliably hit by rcu_preempt
> > rcu_gp_fqs_loop() -> swait_event_idle_timeout_exclusive() invocation.
> 
> I assume it's something like this:
> 
>      timeout -> wakeup
> 
> ->preemption
>         del_timer_sync()
>                 .....

Yes, but it triggers frequently. Like `rcuc' is somehow is aligned with
the timeout.

|          <idle>-0       [007] dN.h4..    46.299705: sched_wakeup: comm=rcuc/7 pid=53 prio=98 target_cpu=007
|          <idle>-0       [007] d...2..    46.299728: sched_switch: prev_comm=swapper/7 prev_pid=0 prev_prio=120 prev_state=R ==> next_comm=rcuc/7 next_pid=53 next_prio=98
|          rcuc/7-53      [007] d...2..    46.299742: sched_switch: prev_comm=rcuc/7 prev_pid=53 prev_prio=98 prev_state=S ==> next_comm=ksoftirqd/7 next_pid=54 next_prio=120
|     ksoftirqd/7-54      [007] .....13    46.299750: timer_expire_entry: timer=000000003bd1e045 function=process_timeout now=4294903802 baseclk=4294903802
|     ksoftirqd/7-54      [007] d...213    46.299750: sched_waking: comm=rcu_preempt pid=11 prio=98 target_cpu=007
|     ksoftirqd/7-54      [007] dN..313    46.299754: sched_wakeup: comm=rcu_preempt pid=11 prio=98 target_cpu=007
|     ksoftirqd/7-54      [007] dN..213    46.299756: sched_stat_runtime: comm=ksoftirqd/7 pid=54 runtime=13265 [ns] vruntime=3012610540 [ns]
|     ksoftirqd/7-54      [007] d...213    46.299760: sched_switch: prev_comm=ksoftirqd/7 prev_pid=54 prev_prio=120 prev_state=R+ ==> next_comm=rcu_preempt next_pid=11 next_prio=98
|     rcu_preempt-11      [007] d...311    46.299766: sched_pi_setprio: comm=ksoftirqd/7 pid=54 oldprio=120 newprio=98
del_timer_sync()
|     rcu_preempt-11      [007] d...211    46.299773: sched_switch: prev_comm=rcu_preempt prev_pid=11 prev_prio=98 prev_state=R+ ==> next_comm=ksoftirqd/7 next_pid=54 next_prio=98
|     ksoftirqd/7-54      [007] .....13    46.299774: timer_expire_exit: timer=000000003bd1e045
|     ksoftirqd/7-54      [007] dN..311    46.299784: sched_pi_setprio: comm=ksoftirqd/7 pid=54 oldprio=98 newprio=120
|     ksoftirqd/7-54      [007] dN..311    46.299788: sched_waking: comm=rcu_preempt pid=11 prio=98 target_cpu=007
|     ksoftirqd/7-54      [007] dN..411    46.299790: sched_wakeup: comm=rcu_preempt pid=11 prio=98 target_cpu=007
|     ksoftirqd/7-54      [007] dN..311    46.299792: sched_stat_runtime: comm=ksoftirqd/7 pid=54 runtime=7404 [ns] vruntime=3012617944 [ns]
|     ksoftirqd/7-54      [007] d...2..    46.299797: sched_switch: prev_comm=ksoftirqd/7 prev_pid=54 prev_prio=120 prev_state=S ==> next_comm=rcu_preempt next_pid=11 next_prio=98


> Thanks,
> 
>         tglx

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207152533.rybefuzd57kxxv57%40linutronix.de.
