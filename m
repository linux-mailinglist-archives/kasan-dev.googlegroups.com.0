Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJORXH6QKGQEFNUUEKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F9402B1992
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 12:06:14 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 201sf2785180lfo.12
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 03:06:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605265574; cv=pass;
        d=google.com; s=arc-20160816;
        b=C8tltqgpOBZ0wgy+s+sefnrfTfA8+0dvCriPpV+4W1GVQECaeZWpnppShpgsHcrHKR
         vuxu3VlI423ai0uacF+YbWM5gvr9ojRFjDV9VN3DFT5njQ98CidLa1Dp+dPZSDrttM/5
         YUu8hCry5XS3Xds0Wkrf8F3zNZuOZ6qmWhnpbhg38lyYF/6DBm3XOCQXD7+fA2hy6xTv
         kPvwf2jA2mpBBbHYKadILQEYitydXONhGWnaShIaT4Eb2zyuU+i46ivt7eQNF6RoVQ/x
         lagrZc9/42ZOQsTfefjyDfDuwUfOj5jZpls2ywRcFYnx7Xe9d+O1cYUx2Un4/kGH1eHg
         Otmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6drklEUs5QvVW5MSeMKpvX0vkzmeg7cjA0AKhwkcXPI=;
        b=UTUEDd99qupYJz9Wo6eOqMpoupiXBC72P3Uvs1a3Ekxgk8vpX6cpaUMyr+q3x3lNwx
         cnlp/5kxVpEFRr19LucsscZVD4+V3yrb9M5zTPHPYjuhTAqtggcmuTaZ3ETboDUQkDax
         UciV6/aPsqCxm3zOqfNr2rZDWXNpbmqCWlCnlk+Dgt+H5Q/uUKsGfI6/hW2iCxql/L7p
         wKC7Bi48fjdMtrf3KyVB39TyRspyBmXhSWnUOwO3CczWJp/2SkORraS5rt1QEWAL4Fhv
         SDT7tCxq1h0ir5FLc/K300pFU3VZJhxOQHPwjJmz2+5gg48OAjzv2mjhsvw9GvqPzT2S
         cIbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fBXair5q;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6drklEUs5QvVW5MSeMKpvX0vkzmeg7cjA0AKhwkcXPI=;
        b=NnU8Rmz0MCK5MzVo23jLUXJXiTpushqvWTRGDmiL0kEFIWERn3TJXndTdzbivO+yyU
         0IAQ1f/Li58SCh1GKKYdVcl80GXD21kzK62CWXCReUuEBF6yPXLUMuQn7Vbj6FMmuWQW
         wXblNivNEZPeXREPBuKmsfcnwGSlVyiE7TatU+7K6YuKy23Rcy6qDkiwE2Hf6okBlJwr
         MPQr2wiiPlPrAuaQzMOlQLP3NVxbdvzJp2byd234S9pSin1G717gK4zCeMCZmZuwjlil
         8KAMJ66Rh5ZnAvCwgvq+zfbAkhVBUL2RZQWvlpc6/nr3DXFX9Hr/IhJCPNs89j59cjhj
         NrIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6drklEUs5QvVW5MSeMKpvX0vkzmeg7cjA0AKhwkcXPI=;
        b=kyeY0IfchSZw9pqPtdsZm/Q7Vf9v4p/DdfHOXc/7xCDJ1bAzcQ6pjpnBMhcklCgRKe
         NSjgsHrebFmxYjR5fqgoAkTqpHUdpMiqsl02497Z0D6xTymFKZANS7CVSUsTkVRCrLgR
         3zXNqHHhYdipl0OvRzaopAhch+kUuKObyfcoCJF3MQK9NYvjnGxQiKnRE0a0ZGSATL3+
         UYaMVwssi1GDzIujwAE+oENjuWwzIrbbM+iJcAi+LiM/M6tRGT1ESRyzRfsfYwLo0YQz
         f2Qnv3r8xZKZ0l2kvry9CF9N/jVLOGJVRKhQF0oZs5EOI/IuQLyifI4uTpY8ieV522TI
         AOxw==
X-Gm-Message-State: AOAM5333QeyJGk29pdZMRL1ZSZwyyAH6BVSlVLmiMVoqBrK+Ui4CJykn
	hjG4MMnqh2lC9Rs5MXWqcc8=
X-Google-Smtp-Source: ABdhPJxRyKmK9/C6ZGaXwqzaI0O8H8OZ6DwKc1UllNybz5yB1GjaqIPKXJMAMLUcleFNpBnpXe72ZA==
X-Received: by 2002:a2e:7a18:: with SMTP id v24mr928606ljc.224.1605265573873;
        Fri, 13 Nov 2020 03:06:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls4318056lfn.0.gmail; Fri, 13 Nov
 2020 03:06:12 -0800 (PST)
X-Received: by 2002:ac2:5b50:: with SMTP id i16mr722068lfp.586.1605265572699;
        Fri, 13 Nov 2020 03:06:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605265572; cv=none;
        d=google.com; s=arc-20160816;
        b=JrBSx5p0e0FBqgBlriJW2Y2friSvdiJRbayvJ2ZIisqVIayjOyzEilfqhnxGfFZSNa
         bOC3jRVCBXL4zbcfbO8K3k9ay+7s027HGzumYR8NkMei470MbmKYW7AtXvYWUIK4+K2C
         O4soq0kQJHBRj7sIXDnxUfXpyLxPnURsT1VQtaqnpWRA7a/TyUNUj2oQ9owPgmUniJEm
         5Z8IFNhgkKy3qK8ifHgglJuQrdkKHcJAHP3fbJXWqmcpJz682CzbB5dq2EoHfpzepWfo
         Imj5ttUHzbDhs1+vtl6mqSz8v6yQ8PaJuSpnJKmISj00Fdz21YEOEpmqk87CZ0qfon7e
         Pz9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dA+kEQkhcLw+SoSuv0AIeD6qXLVmu5Sr7MknI9qkwoU=;
        b=kitY0LdVDH/+9YJp8mTLlTVaxVkN6igR5Axcg7rMnK+QWJ37Amdy7e9q3T31pqWBrv
         k1wKzlZCZChRFIFVhaiZutyCD1EsksLGBvmbvieFI+BCEqfd7QqAeNpe7xaEvO4cDBSu
         T8UGQsIAx6pBxk97hS2hFIFSVL6shvY7zdZ2Z0TuFB/95T/7LPW2nmIcCxXFtIX9TAqy
         E4YxiUJMeWoN+nX3wEFfdYuiwZ4aYTrd5yX+hZXiXG8dTAL5VDUDrizi8VUAYlXtMO54
         M2vHryeYqge0h3manL9HV7Vgx/kdNok5HB84fpKrJ3+TREul0Ror681htmvSAKJXIQeD
         UoYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fBXair5q;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id y12si197477lfb.1.2020.11.13.03.06.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 03:06:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id a3so7988984wmb.5
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 03:06:12 -0800 (PST)
X-Received: by 2002:a1c:9916:: with SMTP id b22mr2042128wme.105.1605265571824;
        Fri, 13 Nov 2020 03:06:11 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id q12sm10935062wmc.45.2020.11.13.03.06.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Nov 2020 03:06:10 -0800 (PST)
Date: Fri, 13 Nov 2020 12:06:04 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, joel@joelfernandes.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201113110604.GA1907210@elver.google.com>
References: <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201112181254.GA3113918@elver.google.com>
 <20201112200025.GG3249@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201112200025.GG3249@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fBXair5q;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Thu, Nov 12, 2020 at 12:00PM -0800, Paul E. McKenney wrote:
> On Thu, Nov 12, 2020 at 07:12:54PM +0100, Marco Elver wrote:
> > On Thu, Nov 12, 2020 at 09:54AM -0800, Paul E. McKenney wrote:
> > > On Thu, Nov 12, 2020 at 05:14:39PM +0100, Marco Elver wrote:
> > > > On Thu, Nov 12, 2020 at 01:49PM +0100, Marco Elver wrote:
> > > > > On Thu, 12 Nov 2020 at 01:11, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > [...]
> > > > > > > This assert didn't fire yet, I just get more of the below. I'll keep
> > > > > > > rerunning, but am not too hopeful...
> > > > > >
> > > > > > Is bisection a possibility?
> > > > > 
> > > > > I've been running a bisection for past ~12h, and am making slow
> > > > > progress. It might be another 12h, but I think it'll get there.
> > > > 
> > > > Bisection gave me this:
> > > > 
> > > > | git bisect start
> > > > | # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
> > > > | git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
> > > > | # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
> > > > | git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
> > > > | # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
> > > > | git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
> > > > | # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
> > > > | git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
> > > > | # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
> > > > | git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
> > > > | # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
> > > > | git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
> > > > | # bad: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
> > > > | git bisect bad b790e3afead9357195b6d1e1b6cd9b3521503ad2
> > > > | # bad: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > > | git bisect bad 765b512bb3d639bfad7dd43c288ee085236c7267
> > > > | # good: [01f9e708d9eae6335ae9ff25ab09893c20727a55] tools/rcutorture: Fix BUG parsing of console.log
> > > 
> > > So torture.2020.11.06a is OK.
> > > 
> > > > | git bisect good 01f9e708d9eae6335ae9ff25ab09893c20727a55
> > > > | # good: [1be6ab91e2db157faedb7f16ab0636a80745a073] srcu: Take early exit on memory-allocation failure
> > > 
> > > As is fixes.2020.11.02a.
> > > 
> > > > | git bisect good 1be6ab91e2db157faedb7f16ab0636a80745a073
> > > > | # good: [65e9eb1ccfe56b41a0d8bfec651ea014968413cb] rcu: Prevent RCU_LOCKDEP_WARN() from swallowing the condition
> > > 
> > > And lockdep.2020.11.02a.
> > > 
> > > > | git bisect good 65e9eb1ccfe56b41a0d8bfec651ea014968413cb
> > > > | # good: [c386e29d43728778ddd642fa73cc582bee684171] docs/rcu: Update the call_rcu() API
> > > 
> > > And doc.2020.11.06a.
> > > 
> > > > | git bisect good c386e29d43728778ddd642fa73cc582bee684171
> > > > | # good: [27c0f1448389baf7f309b69e62d4b531c9395e88] rcutorture: Make grace-period kthread report match RCU flavor being tested
> > > 
> > > And the first three commits of tasks.2020.11.06a.
> > > 
> > > > | git bisect good 27c0f1448389baf7f309b69e62d4b531c9395e88
> > > > | # good: [3fcd6a230fa7d03bffcb831a81b40435c146c12b] x86/cpu: Avoid cpuinfo-induced IPIing of idle CPUs
> > > 
> > > And cpuinfo.2020.11.06a.
> > > 
> > > > | git bisect good 3fcd6a230fa7d03bffcb831a81b40435c146c12b
> > > > | # good: [75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374] rcu-tasks: Make the units of ->init_fract be jiffies
> > > 
> > > And the remaining commit of tasks.2020.11.06a.
> > > 
> > > > | git bisect good 75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374
> > > > | # first bad commit: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > > 
> > > > This doesn't look very satisfying, given it's the merge commit. :-/
> > > 
> > > So each individual branch is just fine, but the merge of them is not.  Fun.
> > > 
> > > These have been passing quite a bit of rcutorture over here, including
> > > preemptible kernels running !SMP, but admittedly on x86 rather than ARMv8.
> > 
> > Note that this is ARMv8 on QEMU on an x86 host i.e. emulated. And it's
> > really slow as a result. Together with a bunch of debug tools including
> > lockdep.
> 
> Then I don't envy you the bisection process!  ;-)
> 
> > > One approach would be to binary-search the combinations of merges.
> > > Except that there are six of them, so there are 64 combinations, of
> > > which you have tested only 8 thus far (none, one each, and all).
> > > 
> > > But are you sure that the bisection points labeled "good" really are good?
> > > For example, what is the distribution of first failure times in the
> > > points labeled "bad" vs. the runtime used to make a "good" determination?
> > > Alternatively, just try a longer run on each of the commits feeding into
> > > the merge point.
> > 
> > Yeah, I'm having doubts, and this might be even more non-deterministic
> > that I thought and some 'good' could maybe be 'bad' if I had re-run
> > them? I don't know. One thing I can try is to make sure I run it more
> > than once, but I'm definitely not doing that manually, so let me try and
> > script something so I don't have to hand-hold the bisection overnight.
> > :-)
> 
> I know that feeling.  A similar experience motivated me to upgrade my
> tooling, with more upgrades in the queue.

[.....]

> > > > | [  841.143527]  arch_local_irq_restore+0x4/0x8
> > > 
> > > So we are just now restoring interrupts, hence our getting the
> > > interrupt at this point..
> > > 
> > > > | [  841.147612]  trace_preempt_on+0xf4/0x190
> > > 
> > > From within the trace code, which is apparently recording the fact
> > > that preemption is being enabled.
> > > 
> > > > | [  841.151656]  preempt_schedule_common+0x12c/0x1b0
> > > > | [  841.155869]  preempt_schedule.part.88+0x20/0x28
> > > > | [  841.160036]  preempt_schedule+0x20/0x28
> > > 
> > > I was not aware that releasing a raw spinlock could result in a direct
> > > call to preempt_schedule().
> > > 
> > > > | [  841.164051]  _raw_spin_unlock_irq+0x80/0x90
> > > > | [  841.168139]  rcu_gp_kthread+0xe5c/0x19a8
> > > 
> > > So the RCU grace-period kthread has spent many seconds attempting to
> > > release a lock?  Am I reading this correctly?  Mark Rutland, am I missing
> > > something here?
> 
> And yes, this is the RCU grace-period kthread releasing a lock.
> 
> I have no idea why that would take so long.  It is acting like a
> self-deadlock or similar hang, except that in that case, lockdep should
> have complained before the RCU CPU stall warning rather than after.
> 
> The only thing I can suggest is sprinkling lockdep_assert_irqs_disabled()
> calls hither and yon.  All of the code that lockdep is complaining about
> runs in the context of the scheduling-clock interrupt, so interrupts
> had jolly well be disabled!  ;-)
> 
> Rerunning some of the allegedly good bisects might be more productive.

Oof, so I reran bisection, and this time confirming 3x each good run.
This is what I get:

| git bisect start
| # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
| git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
| # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
| git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
| # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
| git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
| # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
| git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
| # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
| git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
| # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
| git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
| # good: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
| git bisect good b790e3afead9357195b6d1e1b6cd9b3521503ad2
| # bad: [7bd5bb161657717d576798f62b0e8d5b44653139] Merge remote-tracking branch 'drivers-x86/for-next' into master
| git bisect bad 7bd5bb161657717d576798f62b0e8d5b44653139
| # bad: [e71eb4c4d42bcf36a3a7ede30fd320d47b3c8cb8] Merge remote-tracking branch 'xen-tip/linux-next' into master
| git bisect bad e71eb4c4d42bcf36a3a7ede30fd320d47b3c8cb8
| # bad: [c0a41bf9dbc751692c8cb1a44bfd48e70e8bef7f] docs: Remove redundant "``" from Requirements.rst
| git bisect bad c0a41bf9dbc751692c8cb1a44bfd48e70e8bef7f
| # bad: [c293fb8f7de6c2fce11cb01a0218d668df326bcd] torture: Make --kcsan specify lockdep
| git bisect bad c293fb8f7de6c2fce11cb01a0218d668df326bcd
| # good: [5068ab7dcb6a526a401054ebe0d416f979efb3e1] rcutorture: Add testing for RCU's global memory ordering
| git bisect good 5068ab7dcb6a526a401054ebe0d416f979efb3e1
| # good: [bea68a13bbbdc575a2c868dabd7b454c2eddc618] rcu/segcblist: Add additional comments to explain smp_mb()
| git bisect good bea68a13bbbdc575a2c868dabd7b454c2eddc618
| # first bad commit: [c293fb8f7de6c2fce11cb01a0218d668df326bcd] torture: Make --kcsan specify lockdep

Which clearly is ridiculous! So my guess is this probably had existed
before, but something in -next is making it more visible.

Short of giving up, I can try your suggestion of sprinkling
lockdep_assert_irqs_disabled() everywhere, or if you have a patch to
apply that would give some other debug output you wanted I can run that
too.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113110604.GA1907210%40elver.google.com.
