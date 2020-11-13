Return-Path: <kasan-dev+bncBAABB5EAXP6QKGQEG4SQIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 96CFE2B2207
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 18:20:55 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id t11sf6517047qvp.7
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 09:20:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605288052; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZG6O+vI/i+A2q6j7jklYZuvMkSZ7Al2gssngMr9hdkhen/57e2OEEWdmCpgSZGPRJ4
         s8ZEXPpJ5sOsAurD/qPwAPtnzAvAWhBjZM5J72gFTatUAalMzyEhDARUyIDIXTlSs/Dr
         kwuTXyTT98NXBBuxA16D+Z0PLfAMswA4dUf2m9Z2CDW/QTV1eDyqB17naXXu2W1Wklpw
         YLdkhXAgrCvgEGdqTaXHWff+vY+yzb7Qmy8OC2X61PtK9LuCDGzexJuFnCrcZlUnxcBf
         qVDzcAYhl7+qJ+GUOwPa67No73ulHjHwLp7KHYTfG1y9tvydpvt/gqzXC01A8Kjkm4ba
         c8FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=AC+2/XTsQ/xBgczPhXFZLJ2V8VZSHbkUvEyEPW2vOTw=;
        b=VoEi74nhjCkwxEvRQmQiLeIcMH2+fOZnC3sFHrEWrc3QWCgq8dqpCp2pIp02FM2vLm
         GJZcw8Oe0/pEV8G29ay+CGUmOcjKYsS0gqYYtZEhAxYRIZznHT5h8cQY6urbae+OVBVv
         mWM3eWJANShuMZGpVdw7nkPr8k1otL3SU5bcUGXeNKHjIn9bUbmQpHCwEvmT47cTSkzs
         tRbXrcFKTlUyX00s80X1mQil7Cw5TVMp27Ltj1me4pYBj2++7TnK3SfszghunOBE0eHA
         PyKloXayQy0SlRnDLzkReezo9zeMHzupv0hBtmtgdfu6c5erxtcgpeZoLrpVjcbY8UWC
         8x7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=geU1bNOp;
       spf=pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AC+2/XTsQ/xBgczPhXFZLJ2V8VZSHbkUvEyEPW2vOTw=;
        b=p8VgI4Fx7pBec4AoP+Nv867WvNbA3AsaT4sB0RuZiclmbOK7i6nSy7AOvNoDtQOpRT
         UokcoPtVthMEIKDoviTObto5ZBhWB1qxC9fTfHtWFJzZF86AS0lV3WNpww4t0jVKW3CL
         fvMLkhjKNnyJPve+zvhBYTFvV+UzyPfk7SjTzW/rH6zFHH3tk4lW+N/DM3alhJwbEeiK
         +BSdtzxtaOldv4zy/h1Ii1Zcgx4qn23mqHWoGURSm66ywnG/x/n4U1hYRf1bdtD4BoQq
         lLy8+kgr95c7kGhj69O5mNwYy029qF/DS2W+h0XjIiPMkPQ9bHdDvqGOvb6+rM4PDkQk
         FBHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AC+2/XTsQ/xBgczPhXFZLJ2V8VZSHbkUvEyEPW2vOTw=;
        b=jfLNDSZ36O/qqbNShQEutJiEFrqw3dRP3tHnGBzrL1a6zWbZz0WIY4kCsfAku6MElc
         fwMG6kp5VEzPG+n7LjrxW/tb/SH45Scz4ILjG+5s4Ur8yXBTp4oBEgtphmfffzkIpbbF
         qd1RQ5yUH5Dijb6I1THBvazoYUjU2uGjg2tCLYXBuHvgOoBghBL00EXEBwLa3q4btHK9
         wDI6T2MrvNmYHNxzdaAgQwGbLg9uZmy529Hp1WEMSmy6cDJFF/9FoWtHrhX29+hFMOWW
         wPD2zRRmEnKY4sb6TKPkQ8zRvSmrs4hRht01V66VY5gQ1nvxCCVvPVD1gHwT1IXlc/n/
         +7Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53060bGFWcQjDnSy14nXDbt/pKvoja10bxpfLx1oC1KCCXYBRopm
	nQnAFYvW9eu+Osc3YFUJOF0=
X-Google-Smtp-Source: ABdhPJxmXfwYZPlb+xfxihvtFQ5cokcd7tw0Slc0sBe/NE64sufPOAUFO6lGL7QvBewHZYrHizKOew==
X-Received: by 2002:a37:49d6:: with SMTP id w205mr2996590qka.501.1605288052290;
        Fri, 13 Nov 2020 09:20:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7196:: with SMTP id w22ls2426425qto.6.gmail; Fri, 13 Nov
 2020 09:20:51 -0800 (PST)
X-Received: by 2002:ac8:75d6:: with SMTP id z22mr2901073qtq.255.1605288051795;
        Fri, 13 Nov 2020 09:20:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605288051; cv=none;
        d=google.com; s=arc-20160816;
        b=bUg4rgtkcIIITmZz/bVMGtBcmJX2tQStSTtvoqXNBLv4uwuAVcN6QtoVgzYt+fzWOn
         C0kGCnCH0C6AILmqhs3zwaK8zxzDMBcgSC+LCWgVuVQhzEFYDqQg+2NOy0PG2udYDhkK
         C8jdOXam+3uHMwxVZeqXbd2L0OEkrPkPp+iVLxyQRYoZzo5doVsYtrp18Q/PaN3e1aY3
         RpbzIx7hnchIxjBQiVqn8NCPhAcirh/Yy7BSwS1ianls+2LO34gH+WAqpFnpZrqpE1uY
         0oQOGFGchQxVxWD8TU5nbbKn2yHR9NOnNesBLDzN3M28eBcekjLLuEYUIQxhL5+GRzFP
         TGKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=y6Xbtyc6/oQNyFpQ8V5yuw2jjFvJjSJciNxJBzD36sE=;
        b=qzfzjnNtr3ih8DTM7PCXWW3FSVsXSeHWrjE4Mue6zsz1LC4KS0RNBhJ5/EpTfkxFOF
         zELAae3JxsdJzR5lQtoA9kcsOIn80zmSYmV9Qb202/EdEZCxzjC3FiOFf20sjIlbmD8F
         91j+NZT1xJbnpIwfayRM7bV1a595o/fiSCq1h0lebxNbMgAAp1uAsl3f53Lnrx1L/NPd
         gmiZic+RyyegwxsWPg1a8JhUEl5uNnzg392kBU2/3gMSoup/9zVdXX/MTAbq161O0wD5
         RaqRWpTcWVY9pSiXyTNUTWBT/ZRRYF+nzpfDFYCcQZayBDkISsAFfbG4MXn3rysuX4qv
         oONw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=geU1bNOp;
       spf=pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p51si604095qtc.4.2020.11.13.09.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Nov 2020 09:20:51 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 750F621D1A;
	Fri, 13 Nov 2020 17:20:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 2DF9435212DC; Fri, 13 Nov 2020 09:20:50 -0800 (PST)
Date: Fri, 13 Nov 2020 09:20:50 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
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
Message-ID: <20201113172050.GJ3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
 <20201112161439.GA2989297@elver.google.com>
 <20201112175406.GF3249@paulmck-ThinkPad-P72>
 <20201112181254.GA3113918@elver.google.com>
 <20201112200025.GG3249@paulmck-ThinkPad-P72>
 <20201113110604.GA1907210@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201113110604.GA1907210@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=geU1bNOp;       spf=pass
 (google.com: domain of srs0=rztf=et=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rZTf=ET=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Nov 13, 2020 at 12:06:04PM +0100, Marco Elver wrote:
> On Thu, Nov 12, 2020 at 12:00PM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 12, 2020 at 07:12:54PM +0100, Marco Elver wrote:
> > > On Thu, Nov 12, 2020 at 09:54AM -0800, Paul E. McKenney wrote:
> > > > On Thu, Nov 12, 2020 at 05:14:39PM +0100, Marco Elver wrote:
> > > > > On Thu, Nov 12, 2020 at 01:49PM +0100, Marco Elver wrote:
> > > > > > On Thu, 12 Nov 2020 at 01:11, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > [...]
> > > > > > > > This assert didn't fire yet, I just get more of the below. I'll keep
> > > > > > > > rerunning, but am not too hopeful...
> > > > > > >
> > > > > > > Is bisection a possibility?
> > > > > > 
> > > > > > I've been running a bisection for past ~12h, and am making slow
> > > > > > progress. It might be another 12h, but I think it'll get there.
> > > > > 
> > > > > Bisection gave me this:
> > > > > 
> > > > > | git bisect start
> > > > > | # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
> > > > > | git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
> > > > > | # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
> > > > > | git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
> > > > > | # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
> > > > > | git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
> > > > > | # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
> > > > > | git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
> > > > > | # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
> > > > > | git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
> > > > > | # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
> > > > > | git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
> > > > > | # bad: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
> > > > > | git bisect bad b790e3afead9357195b6d1e1b6cd9b3521503ad2
> > > > > | # bad: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > > > | git bisect bad 765b512bb3d639bfad7dd43c288ee085236c7267
> > > > > | # good: [01f9e708d9eae6335ae9ff25ab09893c20727a55] tools/rcutorture: Fix BUG parsing of console.log
> > > > 
> > > > So torture.2020.11.06a is OK.
> > > > 
> > > > > | git bisect good 01f9e708d9eae6335ae9ff25ab09893c20727a55
> > > > > | # good: [1be6ab91e2db157faedb7f16ab0636a80745a073] srcu: Take early exit on memory-allocation failure
> > > > 
> > > > As is fixes.2020.11.02a.
> > > > 
> > > > > | git bisect good 1be6ab91e2db157faedb7f16ab0636a80745a073
> > > > > | # good: [65e9eb1ccfe56b41a0d8bfec651ea014968413cb] rcu: Prevent RCU_LOCKDEP_WARN() from swallowing the condition
> > > > 
> > > > And lockdep.2020.11.02a.
> > > > 
> > > > > | git bisect good 65e9eb1ccfe56b41a0d8bfec651ea014968413cb
> > > > > | # good: [c386e29d43728778ddd642fa73cc582bee684171] docs/rcu: Update the call_rcu() API
> > > > 
> > > > And doc.2020.11.06a.
> > > > 
> > > > > | git bisect good c386e29d43728778ddd642fa73cc582bee684171
> > > > > | # good: [27c0f1448389baf7f309b69e62d4b531c9395e88] rcutorture: Make grace-period kthread report match RCU flavor being tested
> > > > 
> > > > And the first three commits of tasks.2020.11.06a.
> > > > 
> > > > > | git bisect good 27c0f1448389baf7f309b69e62d4b531c9395e88
> > > > > | # good: [3fcd6a230fa7d03bffcb831a81b40435c146c12b] x86/cpu: Avoid cpuinfo-induced IPIing of idle CPUs
> > > > 
> > > > And cpuinfo.2020.11.06a.
> > > > 
> > > > > | git bisect good 3fcd6a230fa7d03bffcb831a81b40435c146c12b
> > > > > | # good: [75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374] rcu-tasks: Make the units of ->init_fract be jiffies
> > > > 
> > > > And the remaining commit of tasks.2020.11.06a.
> > > > 
> > > > > | git bisect good 75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374
> > > > > | # first bad commit: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
> > > > > 
> > > > > This doesn't look very satisfying, given it's the merge commit. :-/
> > > > 
> > > > So each individual branch is just fine, but the merge of them is not.  Fun.
> > > > 
> > > > These have been passing quite a bit of rcutorture over here, including
> > > > preemptible kernels running !SMP, but admittedly on x86 rather than ARMv8.
> > > 
> > > Note that this is ARMv8 on QEMU on an x86 host i.e. emulated. And it's
> > > really slow as a result. Together with a bunch of debug tools including
> > > lockdep.
> > 
> > Then I don't envy you the bisection process!  ;-)
> > 
> > > > One approach would be to binary-search the combinations of merges.
> > > > Except that there are six of them, so there are 64 combinations, of
> > > > which you have tested only 8 thus far (none, one each, and all).
> > > > 
> > > > But are you sure that the bisection points labeled "good" really are good?
> > > > For example, what is the distribution of first failure times in the
> > > > points labeled "bad" vs. the runtime used to make a "good" determination?
> > > > Alternatively, just try a longer run on each of the commits feeding into
> > > > the merge point.
> > > 
> > > Yeah, I'm having doubts, and this might be even more non-deterministic
> > > that I thought and some 'good' could maybe be 'bad' if I had re-run
> > > them? I don't know. One thing I can try is to make sure I run it more
> > > than once, but I'm definitely not doing that manually, so let me try and
> > > script something so I don't have to hand-hold the bisection overnight.
> > > :-)
> > 
> > I know that feeling.  A similar experience motivated me to upgrade my
> > tooling, with more upgrades in the queue.
> 
> [.....]
> 
> > > > > | [  841.143527]  arch_local_irq_restore+0x4/0x8
> > > > 
> > > > So we are just now restoring interrupts, hence our getting the
> > > > interrupt at this point..
> > > > 
> > > > > | [  841.147612]  trace_preempt_on+0xf4/0x190
> > > > 
> > > > From within the trace code, which is apparently recording the fact
> > > > that preemption is being enabled.
> > > > 
> > > > > | [  841.151656]  preempt_schedule_common+0x12c/0x1b0
> > > > > | [  841.155869]  preempt_schedule.part.88+0x20/0x28
> > > > > | [  841.160036]  preempt_schedule+0x20/0x28
> > > > 
> > > > I was not aware that releasing a raw spinlock could result in a direct
> > > > call to preempt_schedule().
> > > > 
> > > > > | [  841.164051]  _raw_spin_unlock_irq+0x80/0x90
> > > > > | [  841.168139]  rcu_gp_kthread+0xe5c/0x19a8
> > > > 
> > > > So the RCU grace-period kthread has spent many seconds attempting to
> > > > release a lock?  Am I reading this correctly?  Mark Rutland, am I missing
> > > > something here?
> > 
> > And yes, this is the RCU grace-period kthread releasing a lock.
> > 
> > I have no idea why that would take so long.  It is acting like a
> > self-deadlock or similar hang, except that in that case, lockdep should
> > have complained before the RCU CPU stall warning rather than after.
> > 
> > The only thing I can suggest is sprinkling lockdep_assert_irqs_disabled()
> > calls hither and yon.  All of the code that lockdep is complaining about
> > runs in the context of the scheduling-clock interrupt, so interrupts
> > had jolly well be disabled!  ;-)
> > 
> > Rerunning some of the allegedly good bisects might be more productive.
> 
> Oof, so I reran bisection, and this time confirming 3x each good run.
> This is what I get:
> 
> | git bisect start
> | # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
> | git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
> | # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
> | git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
> | # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
> | git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
> | # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
> | git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
> | # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
> | git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
> | # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
> | git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
> | # good: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
> | git bisect good b790e3afead9357195b6d1e1b6cd9b3521503ad2
> | # bad: [7bd5bb161657717d576798f62b0e8d5b44653139] Merge remote-tracking branch 'drivers-x86/for-next' into master
> | git bisect bad 7bd5bb161657717d576798f62b0e8d5b44653139
> | # bad: [e71eb4c4d42bcf36a3a7ede30fd320d47b3c8cb8] Merge remote-tracking branch 'xen-tip/linux-next' into master
> | git bisect bad e71eb4c4d42bcf36a3a7ede30fd320d47b3c8cb8
> | # bad: [c0a41bf9dbc751692c8cb1a44bfd48e70e8bef7f] docs: Remove redundant "``" from Requirements.rst
> | git bisect bad c0a41bf9dbc751692c8cb1a44bfd48e70e8bef7f
> | # bad: [c293fb8f7de6c2fce11cb01a0218d668df326bcd] torture: Make --kcsan specify lockdep
> | git bisect bad c293fb8f7de6c2fce11cb01a0218d668df326bcd
> | # good: [5068ab7dcb6a526a401054ebe0d416f979efb3e1] rcutorture: Add testing for RCU's global memory ordering
> | git bisect good 5068ab7dcb6a526a401054ebe0d416f979efb3e1
> | # good: [bea68a13bbbdc575a2c868dabd7b454c2eddc618] rcu/segcblist: Add additional comments to explain smp_mb()
> | git bisect good bea68a13bbbdc575a2c868dabd7b454c2eddc618
> | # first bad commit: [c293fb8f7de6c2fce11cb01a0218d668df326bcd] torture: Make --kcsan specify lockdep
> 
> Which clearly is ridiculous! So my guess is this probably had existed
> before, but something in -next is making it more visible.
> 
> Short of giving up, I can try your suggestion of sprinkling
> lockdep_assert_irqs_disabled() everywhere, or if you have a patch to
> apply that would give some other debug output you wanted I can run that
> too.

I don't have a patch, but if you are still seeing lots of workqueue
lockups before the RCU CPU stall warning, I again suggest adding the
backtrace as called out in my earlier email.  The idea here is to see
what is causing these lockups.

I can send a formal patch for this if you wish, but today is crazy,
so I cannot promise it before this evening, Pacific Time.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113172050.GJ3249%40paulmck-ThinkPad-P72.
