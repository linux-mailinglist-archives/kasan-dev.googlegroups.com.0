Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXESKGQMGQEXHMLJTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 72B654612FC
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 11:57:38 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id eg20-20020a056402289400b003eb56fcf6easf13292836edb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Nov 2021 02:57:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638183458; cv=pass;
        d=google.com; s=arc-20160816;
        b=K/7mdMgv5AbiQ+nXCuDxnx+c5Qw/zGolNcWDw1XyLA4tspzQeKMVJv6w3kp77LrhYa
         mR8ZERYwUgyX615HaPTES7j8ra8YYxQ/N3M9TWEizAakkLJcs0ErY7IqF7wLoVOgtXKT
         e4TlG5RNiF77LuAMDigdPq/GFUjOYbnfi6UkYWv1zjIpQJ9Pd6VmHh6Vwn4Y+G5g3GKf
         8Jz4G2fTAXurDl1B+os+UkFXC5QJJ5jBmENiT+iZfQpJSXcJJxoglqffyrvhPA05M66L
         l2i4ZNqItn9zDIeTEm/VzySG+pnI5RPYL8pC7hKKx7djKvnS/mmNWcenVjUafKe7qWYI
         c6dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cKepdnVdo4HfoivtYMO1RJoMR1tfwrAazbtIRBIA+Es=;
        b=G7z/hgosZ2cUBhYfmxWEAxJMUqDQSULr0j6t3sVkF4TkCdorfWJNmWBJaxGU3BADEV
         qt/wXGs93d5X+LkKaOJ9y4wl1UqH7TG6WkRpPMftlKlkO/ng7fc7JrwWz4KELIFDolYT
         j8GDnbcRfhe9hjo+aF/npoJ6nAwPEfs/uuyiWwRzxXxUg4Gn8GEUzS43tOPFUkYfu9Zu
         Fa41RinQjDT/khbs6SBE+LRZw3VdictywyczvgeQRoyUPGvQToQAfEWnhQo/R2CnTwPl
         AP570x3SJPhTvyjjgL4pNr+4ZVmFSfH0NEtAASFlZbtIxtATQBcYhrzfD+dPLPWio5QK
         mrpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FpAGCEzp;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cKepdnVdo4HfoivtYMO1RJoMR1tfwrAazbtIRBIA+Es=;
        b=gWUrsdFL027+Wu2sLUuZ+UR/N1+CusalZ5a5QetvLVBSykF3fW7Cxa/brMKLC95xqu
         W82Iv0bJGb9ODG1fCrFl5V/HtSxj4bpipufZlnXJZd1wfyDrOYhVkXMHuY6zO4SjZFXv
         yd8swDjGzZGO0Nh9EyC/Rn5hDOxLAueZzM1G+ZBwQeHZMQ0qm40BqcRveML+vBAoPGpX
         lguEAHC1yBfbrmyxOkjKmwmPWvcwY0aId8/FM8BnA+GpmDiwtud8DpMKl7D6HKeNuHRs
         t1k0oRtQhpeZ9QutC8Nmn+wc8w2+A+MShxdgiQCufJ9dmSuROVz6vvGtxd20Q0UFzcpE
         1imA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cKepdnVdo4HfoivtYMO1RJoMR1tfwrAazbtIRBIA+Es=;
        b=fCYb3cX1nh+8OLwGEIoOyLrUXQQm8EHeyMdbdQJJoQ+c8cFiZr+LltZsdOE6elptrn
         Gqf4b/+yVVV0ZQMobHEjL9EmaSAhbCc5pHXKoYdorzhNw+YFBDCGHE60o0PSomP2A5AK
         Zf8JgBAaMFgC8fQHkPHVNtsfaTqQlUm3tInPl1IrW3NsuEuLkt3PM41wEdqbdyLLoPq0
         MWMKqsOY8MVdMVuazZnqo76TMnGdp/69BFIt70DgNDIN5+n408vO6/BdyZ2mxt5k3lHu
         t20eukyNSO7AlpSkvR44Ul1S5snbnE3/F99nptC2i7qc883qSdRU+4lbKBnbqsZ4E291
         gQpA==
X-Gm-Message-State: AOAM533d7COeO8Kvh49hkQfsTWy+j+lg2EfYWnc9m3lZ6PstiHuoFTWZ
	eEse8rCFskbwYAeQMZ2vdbg=
X-Google-Smtp-Source: ABdhPJxUYzLoH2tkWxR/Gkfkl+ThdO0agdt0w0MIPnbwR/IW8HpcuTxXf1CLxJW79xzXCaN19JRwVw==
X-Received: by 2002:a17:906:3e83:: with SMTP id a3mr60217643ejj.383.1638183458212;
        Mon, 29 Nov 2021 02:57:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c013:: with SMTP id e19ls1595989ejz.3.gmail; Mon, 29
 Nov 2021 02:57:37 -0800 (PST)
X-Received: by 2002:a17:907:2d12:: with SMTP id gs18mr57652126ejc.126.1638183457287;
        Mon, 29 Nov 2021 02:57:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638183457; cv=none;
        d=google.com; s=arc-20160816;
        b=OoSKO1je9IWENt0hJjfYtP2GlfsuRisAVyr4yR5rJAhVVxPC7eYSaSt5gx9mK+hUAL
         QKYQQnApiDr0zdbblgZXWlwX//fFcPxfReEmy/eqFe+mwFiHYzywmrfbff0Dl7V0by28
         H6oRwXwZu8k3iZL975gS4yhWRYoAnVhFmR8ePoiBXkE88hsJlJHb2FcSHKjqoFUo5Ycg
         CqMmDgzQOfCKS4Prj0WSMvf2F7Dhvvhr/ItKFgwbs2Ejbyh+kNGQWQPqxGTtWjVCfPa+
         Q27scMgLsFSDC684ITzVvG4DnSG5x1DGau8KFtvaJYCwIaod9GJ2EuGua7o1+uznHFcU
         SODw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7vafQL9VRNu9gFf/4mCpAetbH+x6q7yQT0LZFBgrIEY=;
        b=T+7JqmEZApQf1YzPx2SOhHCPsgM315F3oPMrNYJyRfVWVo68kNw6uDvyN5yTj+aZGH
         YaTZIE4FvLpt3pUz4U4kc2dl2hcMPgxcnmlajiwNKBko0tw8KKXW7+dg6Eqyiqdou9C/
         n5ywA5l+5Fxa6iodH9JYRZvazsvRbPJNYJLbVP9R05IQKqNQPPjnpJ9cD4cOrQwosO/h
         ShhV7fiywT/dJzc7MEVj0vWRwMIvOS00dMI2r44CuiNr8sDE6tSYtlvAVkDEs+tiQvqa
         /D/ffzTMyuBAZmfs1zCHCRfJBL82t4vo1N2XQroYBw7/z5SMg9WWECsEwgh19ATT5Zcc
         oOdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FpAGCEzp;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id d5si1075145ede.2.2021.11.29.02.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Nov 2021 02:57:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id i5so35830010wrb.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Nov 2021 02:57:37 -0800 (PST)
X-Received: by 2002:adf:d082:: with SMTP id y2mr32476986wrh.214.1638183456845;
        Mon, 29 Nov 2021 02:57:36 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:aaf:77c4:3d2:af75])
        by smtp.gmail.com with ESMTPSA id n1sm16528943wmq.6.2021.11.29.02.57.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Nov 2021 02:57:36 -0800 (PST)
Date: Mon, 29 Nov 2021 11:57:30 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 03/23] kcsan: Avoid checking scoped accesses from
 nested contexts
Message-ID: <YaSyGr4vW3yifWWC@elver.google.com>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-4-elver@google.com>
 <YaSTn3JbkHsiV5Tm@boqun-archlinux>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YaSTn3JbkHsiV5Tm@boqun-archlinux>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FpAGCEzp;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Nov 29, 2021 at 04:47PM +0800, Boqun Feng wrote:
> Hi Marco,
> 
> On Thu, Nov 18, 2021 at 09:10:07AM +0100, Marco Elver wrote:
> > Avoid checking scoped accesses from nested contexts (such as nested
> > interrupts or in scheduler code) which share the same kcsan_ctx.
> > 
> > This is to avoid detecting false positive races of accesses in the same
> 
> Could you provide an example for a false positive?
> 
> I think we do want to detect the following race:
> 
> 	static int v = SOME_VALUE; // a percpu variable.
> 	static int other_v = ... ;
> 
> 	void foo(..)
> 	{
> 		int tmp;
> 		int other_tmp;
> 
> 		preempt_disable();
> 		{
> 			ASSERT_EXCLUSIVE_ACCESSS_SCOPED(v);
> 			tmp = v;
> 			
> 			other_tmp = other_v; // int_handler() may run here
> 			
> 			v = tmp + 2;
> 		}
> 		preempt_enabled();
> 	}
> 
> 	void int_handler() // an interrupt handler
> 	{
> 		v++;
> 	}
> 
> , if I understand correctly, we can detect this currently, but with this
> patch, we cannot detect this if the interrupt happens while we're doing
> the check for "other_tmp = other_v;", right? Of course, running tests
> multiple times may eventually catch this, but I just want to understand
> what's this patch for, thanks!

The above will still be detected. Task and interrupt contexts in this
case are distinct, i.e. kcsan_ctx differ (see get_ctx()).

But there are rare cases where kcsan_ctx is shared, such as nested
interrupts (NMI?), or when entering scheduler code -- which currently
has a KCSAN_SANITIZE := n, but I occasionally test it, which is how I
found this problem. The problem occurs frequently when enabling KCSAN in
kernel/sched and placing a random ASSERT_EXCLUSIVE_ACCESS_SCOPED() in
task context, or just enable "weak memory modeling" without this fix.
You also need CONFIG_PREEMPT=y + CONFIG_KCSAN_INTERRUPT_WATCHER=y.

The emphasis here really is on _shared kcsan_ctx_, which is not too
common. As noted in the commit description, we need to "[...] setting up
a watchpoint for a non-scoped (normal) access that also "conflicts" with
a current scoped access."

Consider this:

	static int v;
	int foo(..)
	{
		ASSERT_EXCLUSIVE_ACCESS_SCOPED(v);
		v++; // preempted during watchpoint for 'v++'
	}

Here we set up a scoped_access to be checked for v. Then on v++, a
watchpoint is set up for the normal access. While the watchpoint is set
up, the task is preempted and upon entering scheduler code, we're still
in_task() and 'current' is still the same, thus get_ctx() returns a
kcsan_ctx where the scoped_accesses list is non-empty containing the
scoped access for foo()'s ASSERT_EXCLUSIVE.

That means, when instrumenting scheduler code or any other code called
by scheduler code or nested interrupts (anything where get_ctx() still
returns the same as parent context), it'd now perform checks based on
the parent context's scoped access, and because the parent context also
has a watchpoint set up on the variable that conflicts with the scoped
access we'd report a nonsensical race.

This case is also possible:

	static int v;
	static int x;
	int foo(..)
	{
		ASSERT_EXCLUSIVE_ACCESS_SCOPED(v);
		x++; // preempted during watchpoint for 'v' after checking x++
	}

Here, all we need is for the scoped access to be checked after x++, end
up with a watchpoint for it, then enter scheduler code, which then
checked 'v', sees the conflicting watchpoint, and reports a nonsensical
race again.

By disallowing scoped access checking for a kcsan_ctx, we simply make
sure that in such nested contexts where kcsan_ctx is shared, none of
these nonsensical races would be detected nor reported.

Hopefully that clarifies what this is about.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaSyGr4vW3yifWWC%40elver.google.com.
