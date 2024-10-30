Return-Path: <kasan-dev+bncBCS4VDMYRUNBBBX2RK4QMGQERDVGBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F9F09B7058
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:11:10 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-20c9673e815sf4950195ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 16:11:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730329862; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gn+89VnZ015nNpA2uRJLqf0n2YR56rC7OiqaDMH0521+EO5wUqF2OJh3gmbdvsqbKU
         q02/ROoV2piRsHCE1mthdI+Ka1mGSJNR8i7ECk/AaEuf7/Z8xbW3q1zlLxdgPNPcCctz
         tz7LGSQir7ODwB/00osaFn2BNKxF4pFIfjAbA9WS6MD9tNF1Qxgy9Zg8dWbDDqaHU0ZC
         gasYtXWurXzDKxtVAXTVpy9lSvy2QD3F/KrDPwHFKMfZ3aJO+kR4FzNX6vADjUVnKEbK
         cqBBgU5zqRcK51YAfa2D8zgE+rctwzQCrDcHCwKxEKqRYjyAv36UnHhO2wgwgnr9FX4S
         DWSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=QrFFtotvMgKwbRTq+ZvUfocyDKOsx4k+Qq+eyij1fiY=;
        fh=kKBl7jFbe3ueqcSIUcgNuf00zc5u70K9cItghplbG2o=;
        b=QiHe0SbtQmm+2f4Qb+Hqr3aF3S5/GmCzFjCbFBvqOLAq9erYMmHTi23dmsgX+A/A4/
         YETn5wNwoiVq4kldb4VlSBehL0rWvKf0/JH4XZHyzvW9L1fwAeIm2Tf2KlUleaZkC/gX
         nZ3eRGbcLQHSYa1QXRG+68/6OxFKHg9Rff5WdYyzbnroV2vfTILg6UayZdZsDXH8pyUx
         hozWMxYbOuF0YGRpRKn0uoC6Pi7cyVjPPKm143zynJ5QGTlt2/O2zTc0HUqH+8iCE/3o
         3IrPvaW0yGx3iIIx2JL844hhGkEB6W5QnxEvcwuSn932xqj5e5aCM5wcQq2NVLJeguS8
         v62g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VopkGahq;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730329862; x=1730934662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QrFFtotvMgKwbRTq+ZvUfocyDKOsx4k+Qq+eyij1fiY=;
        b=rM93pzwgg+tAWNamGVMnvGkUDrSiLzKahcUKgxArbBj0un4xTXtPLzzbeOjg/i6pwj
         6CWV/kj+QcP49pZyISvY7spcm33bfQ4GjtRrR7Wb61BSrVxZR3KMXsyVLF1z8MqRlTO8
         65LKDiVKSD1Vp7g5Y+5aSTVhb2bWV1TCmrylR+foVj8f3LzDuW7oBkoGssd2r8bfoh4M
         bEMjC1DuDxfqU5ud5dhevzc0kyuE9UOqSQjzgu6btmOt2MKzPXg6nzX+H6IyFC/rZvyr
         YS8ilFUpN6YJg1Ww0IWedwNcOBHstzeGjxPULLN6toOqCGD6kglyz8b/JNkaPs/s/G5i
         bA4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730329862; x=1730934662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QrFFtotvMgKwbRTq+ZvUfocyDKOsx4k+Qq+eyij1fiY=;
        b=P9SoCBKVyJBZNUW3bjyC3/+3RRfZ+6HiB2n50SwCP94kVwfs23bupjoKGU4r6/5LTz
         PCMpYJdlMNx1mosqFoN6wqsRuuRuZ+Kgzv6f3dzEg2JOqEdxBe56pLXyY6vYMNPrTJUZ
         e19bvRLQagivhUtg7kvrD+XcKsXXa0e87Ufj/RZaz80PT39jsj3b3hzgpo8aCcu0ee9g
         nSjOkF6MGneQ8LVCPjype8JGZqv6SUsnPuW01MddKzQcF3xzUVOWMwTIAYibBw/OmCKW
         mKM7rQM1SoQa1TnkHhY4FH39EoqWdw6CZRxzDgjfyHl+vyofir0xEcJdUT6n85TaRyLK
         HtUQ==
X-Forwarded-Encrypted: i=2; AJvYcCVNhF54UOCo1DbmplX0iyOUZ+Pgaggcvt6zk+HzTxAJW3qE4aDIyVXPyw0hQovmYtSLFNCfAA==@lfdr.de
X-Gm-Message-State: AOJu0YyZpojOPl0e5qUSl4BbiAEL0dD/GxpyruNRNF16+vTWNrBQGyYK
	bSofiA82Xzi6WcOBYbTnddejR3qT1crE4uOEnlPL+p3IHqOVoDOl
X-Google-Smtp-Source: AGHT+IEF4F4X46skOdlIRTQHVZwaMml50XqsNmDi36YW046JUSuj4eFSa5bJbO5MQdCT6faPtJBA6Q==
X-Received: by 2002:a17:903:1ca:b0:20c:9ddf:a238 with SMTP id d9443c01a7336-21103c78c5dmr10549885ad.47.1730329862412;
        Wed, 30 Oct 2024 16:11:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:80c:b0:206:cbad:e63f with SMTP id
 d9443c01a7336-21103625f47ls2463145ad.0.-pod-prod-02-us; Wed, 30 Oct 2024
 16:11:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJSzvw/BKE71P0jwjICYn5rziEpfYk2ZkGgenHOh+FHr57txVPRbLYhp1Iy7VUsRbI37rPKFWgyLY=@googlegroups.com
X-Received: by 2002:a17:903:228b:b0:205:4e15:54ce with SMTP id d9443c01a7336-21103acde55mr15529155ad.20.1730329860947;
        Wed, 30 Oct 2024 16:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730329860; cv=none;
        d=google.com; s=arc-20240605;
        b=coSuuu4niJZWeDac6hqagFdDf9LWUIzicxdKsDI7U1HKYdm8idpDQzQE5l2oxA7DSH
         4VlDkFJAvOPAdauEul1DeUVVHZ8otf28zB6YOcfGn17G4rBXTEk9TnmzR9T2J8hzFhHA
         tjcN1WrKyQGyWtBW/nxP86Tvn5fR4faAg6JjWnFgvRm6428CPampeJ9q3cnRv5BaYNSh
         h3Ft/e8Ek1NfoxUNYNi5Q0n91RE31adNtpyACqSyn65LFDjaoDMarF+wFyHMc3TWICOq
         B2/PPAMkEXfXmjMY31306eXot7GyqN49UR4OXYliYjgCZTQo1YJlrl7YsJX/a2KYLEFa
         aF9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fx+aMQvnHIPIR/kIiX2EJFAWTHAag/FigDGsXRc8T8o=;
        fh=30vagIL8iZW/K1hNoKt03Lud0MuIDNqP09qn+usGrWc=;
        b=LNv/MN1GM1yiRW9nLxLDynh1tUF2RaeEIRKJrO5aAijzvT5uuKsVwSJjXJrliM33V0
         CVtyjvUFVff6R1qbOiEBwyI7CdIaVmAr5mQEj3tqzNLWfpS00wsXXUCCZC+i40mSk4ZN
         otQ7R4iKbFF6WFEraWIUZD+pLJzrh3r0+vSP0r7eQHGwuYHn3IYq44jmC6DKLEAE1Smc
         Je/PaxzlI1rSk2XXBD/OpRZVgF8X7F/L5bPIzKBsjvJ1ncIHr5ZlLISo3qH6GDlP7KIG
         R5Dr5/+UNKTICNAa4+Wvjejzq4LeuM+sTJq8kzadswRog67zaB7hk2Wh+I0YSla64+bY
         9LAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VopkGahq;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2110572d9easi85245ad.6.2024.10.30.16.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 16:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 53C6E5C6A13;
	Wed, 30 Oct 2024 23:10:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EBEFCC4CECE;
	Wed, 30 Oct 2024 23:10:58 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 82F26CE0864; Wed, 30 Oct 2024 16:10:58 -0700 (PDT)
Date: Wed, 30 Oct 2024 16:10:58 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, linux-next@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, sfr@canb.auug.org.au, bigeasy@linutronix.de,
	longman@redhat.com, boqun.feng@gmail.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZyK0YPgtWExT4deh@elver.google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VopkGahq;       spf=pass
 (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Wed, Oct 30, 2024 at 11:34:08PM +0100, Marco Elver wrote:
> On Wed, Oct 30, 2024 at 10:48PM +0100, Vlastimil Babka wrote:
> > On 10/30/24 22:05, Paul E. McKenney wrote:
> > > Hello!
> > 
> > Hi!
> > 
> > > The next-20241030 release gets the splat shown below when running
> > > scftorture in a preemptible kernel.  This bisects to this commit:
> > > 
> > > 560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")
> > > 
> > > Except that all this is doing is enabling lockdep to find the problem.
> > > 
> > > The obvious way to fix this is to make the kmem_cache structure's
> > > cpu_slab field's ->lock be a raw spinlock, but this might not be what
> > > we want for real-time response.
> > 
> > But it's a local_lock, not spinlock and it's doing local_lock_irqsave(). I'm
> > confused what's happening here, the code has been like this for years now.
> > 
> > > This can be reproduced deterministically as follows:
> > > 
> > > tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"
> > > 
> > > I doubt that the number of CPUs or amount of memory makes any difference,
> > > but that is what I used.
> > > 
> > > Thoughts?
> > > 
> > > 							Thanx, Paul
> > > 
> > > ------------------------------------------------------------------------
> > > 
> > > [   35.659746] =============================
> > > [   35.659746] [ BUG: Invalid wait context ]
> > > [   35.659746] 6.12.0-rc5-next-20241029 #57233 Not tainted
> > > [   35.659746] -----------------------------
> > > [   35.659746] swapper/37/0 is trying to lock:
> > > [   35.659746] ffff8881ff4bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x49/0x1b0
> > > [   35.659746] other info that might help us debug this:
> > > [   35.659746] context-{2:2}
> > > [   35.659746] no locks held by swapper/37/0.
> > > [   35.659746] stack backtrace:
> > > [   35.659746] CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Not tainted 6.12.0-rc5-next-20241029 #57233
> > > [   35.659746] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
> > > [   35.659746] Call Trace:
> > > [   35.659746]  <IRQ>
> > > [   35.659746]  dump_stack_lvl+0x68/0xa0
> > > [   35.659746]  __lock_acquire+0x8fd/0x3b90
> > > [   35.659746]  ? start_secondary+0x113/0x210
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  lock_acquire+0x19b/0x520
> > > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > > [   35.659746]  ? __pfx_lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > > [   35.659746]  ? lock_release+0x20f/0x6f0
> > > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > > [   35.659746]  ? lock_release+0x20f/0x6f0
> > > [   35.659746]  ? kasan_save_track+0x14/0x30
> > > [   35.659746]  put_cpu_partial+0x52/0x1b0
> > > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > > [   35.659746]  ? __pfx_scf_handler_1+0x10/0x10
> > > [   35.659746]  __flush_smp_call_function_queue+0x2d2/0x600
> > 
> > How did we even get to put_cpu_partial directly from flushing smp calls?
> > SLUB doesn't use them, it uses queue_work_on)_ for flushing and that
> > flushing doesn't involve put_cpu_partial() AFAIK.
> > 
> > I think only slab allocation or free can lead to put_cpu_partial() that
> > would mean the backtrace is missing something. And that somebody does a slab
> > alloc/free from a smp callback, which I'd then assume isn't allowed?
> 
> Tail-call optimization is hiding the caller. Compiling with
> -fno-optimize-sibling-calls exposes the caller. This gives the full
> picture:
> 
> [   40.321505] =============================
> [   40.322711] [ BUG: Invalid wait context ]
> [   40.323927] 6.12.0-rc5-next-20241030-dirty #4 Not tainted
> [   40.325502] -----------------------------
> [   40.326653] cpuhp/47/253 is trying to lock:
> [   40.327869] ffff8881ff9bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x48/0x1a0
> [   40.330081] other info that might help us debug this:
> [   40.331540] context-{2:2}
> [   40.332305] 3 locks held by cpuhp/47/253:
> [   40.333468]  #0: ffffffffae6e6910 (cpu_hotplug_lock){++++}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
> [   40.336048]  #1: ffffffffae6e9060 (cpuhp_state-down){+.+.}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
> [   40.338607]  #2: ffff8881002a6948 (&root->kernfs_rwsem){++++}-{4:4}, at: kernfs_remove_by_name_ns+0x78/0x100
> [   40.341454] stack backtrace:
> [   40.342291] CPU: 47 UID: 0 PID: 253 Comm: cpuhp/47 Not tainted 6.12.0-rc5-next-20241030-dirty #4
> [   40.344807] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
> [   40.347482] Call Trace:
> [   40.348199]  <IRQ>
> [   40.348827]  dump_stack_lvl+0x6b/0xa0
> [   40.349899]  dump_stack+0x10/0x20
> [   40.350850]  __lock_acquire+0x900/0x4010
> [   40.360290]  lock_acquire+0x191/0x4f0
> [   40.364850]  put_cpu_partial+0x51/0x1a0
> [   40.368341]  scf_handler+0x1bd/0x290
> [   40.370590]  scf_handler_1+0x4e/0xb0
> [   40.371630]  __flush_smp_call_function_queue+0x2dd/0x600
> [   40.373142]  generic_smp_call_function_single_interrupt+0xe/0x20
> [   40.374801]  __sysvec_call_function_single+0x50/0x280
> [   40.376214]  sysvec_call_function_single+0x6c/0x80
> [   40.377543]  </IRQ>
> [   40.378142]  <TASK>
> 
> And scf_handler does indeed tail-call kfree:
> 
> 	static void scf_handler(void *scfc_in)
> 	{
> 	[...]
> 		} else {
> 			kfree(scfcp);
> 		}
> 	}

So I need to avoid calling kfree() within an smp_call_function() handler?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/66a745bb-d381-471c-aeee-3800a504f87d%40paulmck-laptop.
