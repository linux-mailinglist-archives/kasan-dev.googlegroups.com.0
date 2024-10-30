Return-Path: <kasan-dev+bncBC7OBJGL2MHBB27IRK4QMGQEXSF3VOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D2669B6FE0
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 23:34:21 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-539f5f33333sf243581e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 15:34:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730327660; cv=pass;
        d=google.com; s=arc-20240605;
        b=DoC+q8+Bw/sHqMtadsM0fkOqDB6naCAx31VJHr9xc8qxBKL5GalQ8RorqFOs60VI9w
         zVZ3OSZsyFEeZ1wyBw43PBl11F71BNq59v8N7H3KacFj3MvFTtjKizD8lffduYmz6tHs
         wNAg63FpN6giDqZlVfZXac+E22RHS/9y8mvT+ty5D+EzR3jWPQnnP5VvKFra3wfQPdzD
         w+sgXaO+Fp8d0px6wCkyDili57u70Yc2LVDKy7M8L/GZc/R2wFV2+WQeaNQqPebHnlxU
         RruvqQfNfME6onV+X5VlG8lDZ0omSLWFtfiLGSeV5WTKd3g0RWC8uMo3zLdXU8uTBxLR
         m2rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=je9e3d2BG8+MFHk35JXMmoR3Pj1a6SF3kw/QOXRoFvU=;
        fh=U/saLk/YfO27HcHpvq8vPUqe5CNyfv+9JBwyTPYOBnc=;
        b=fYD/Jqmx9HkvePnf7FbsuMDXwggrNkgLmBuaqzkvOP/TU9gYB3yI5EvoBh+5NqTZs/
         66Z+SeuKYOzhOv0fBDQBxZtePr85xoieYxan32him697gQ+z7k0y6k+nlXwfFW/IGGGu
         zGzF0dwZ1PbsyQdd4kji9Z/N6VI3AQ8Ho/rf2XCTD5ASlvZzuGfTWZKnkJYmMkr0/iRU
         xHWYXYAteWE+X/+9CKuMI4kzyx1HuBd83W4CgezQKLNI2PhYBgNcPzQTcn4iUO1unecD
         fbSaAO/Mhe57IdRhFsSLfBBfSZMBkCxjK+fpaXtoG+6/BbOZh81Zp7hBnZfaa9lv1f0Y
         MrPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GIGTJEUF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730327660; x=1730932460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=je9e3d2BG8+MFHk35JXMmoR3Pj1a6SF3kw/QOXRoFvU=;
        b=Y+oqMG7UaCLOex1hpHbXZI4BheAnT5bXEH8KVs9HKxH9uxN4D9Fp7eJXR/P8+cuWLF
         Iz1/OO7fbC9cWVUpxHd67/Q5xppb8hQJz4v+vqA3XlFahCp52P2iFUSky5Kn7xRNAjVq
         0+t8wqBUqP+I1NspWO2flvVeue2KoOEi53nhiT/4SOBy2fa7BqQx4xk8PaJkaNUtDOF5
         CWG5+KTafm8OGvzXuutZ4jMZvMu/oDAdXYb67NeXYZn9YicpbTb9EpU+Im4HT5O4RZy5
         Kb7x2Iu5tJ2ioOqYfJsO3sh4S7pFmz8svSjmHUiOJqG67fzeAuVj5GVaIIww5oY73lvd
         V+GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730327660; x=1730932460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=je9e3d2BG8+MFHk35JXMmoR3Pj1a6SF3kw/QOXRoFvU=;
        b=N+UHIOCWA8uiOHvpazo6e5+hLaeb05pO/l2hgH/gU022Vx73SXL91qqycMI0vnPPQA
         Haw8JTBhn0hJ6uULq2RoMGiqQtJbLxLsXEmwIRhLFkYi2TH/Ulia/o4F/w27yL8Lnc86
         79Vm7oSpEuIh2AtFjlthuGym2Blym6Gzc7Cw7RItW2FMSNlhseK3MoPq/Xdbe38oeaFg
         /celFkYdtkYvKDpRiUd2Jd8HJ5q20vJVVCw7ODceSlCGTy5C9SGbNDxS8T0YW29akwi8
         Z0o7AUYNiQjXdHdppG1CxNB767iwO4cXNMeowqwenT0sxDw57hfBO3QmmNh9x0hvntV5
         6CTg==
X-Forwarded-Encrypted: i=2; AJvYcCWILzMy0UIsjOThGz2iytlnuuIOzjsZD/UgfpxUW8yD2bFZEoPWeori7w/yMwEZ3N8foTCjqw==@lfdr.de
X-Gm-Message-State: AOJu0YwX3jy0vmLnC2pEPkOPp6V7GASrjExpKrwTC8PrkhA8EGg6piAC
	KZg54wXZisnpt5TM4yslX9Qxg17UyMbVUj5NgNUU6by5EsN6cbkm
X-Google-Smtp-Source: AGHT+IEcM9RBmYu7OiKpVafUZW9T1F3yG/fibVb0OSqkKC3ccH70n7C8WfUMXSCIVOA3mX9y0Bx8Jw==
X-Received: by 2002:a05:6512:b02:b0:539:adb0:b76 with SMTP id 2adb3069b0e04-53b348ce5camr8355753e87.15.1730327659863;
        Wed, 30 Oct 2024 15:34:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b93:b0:539:f77f:bc3a with SMTP id
 2adb3069b0e04-53c791ed967ls192120e87.0.-pod-prod-04-eu; Wed, 30 Oct 2024
 15:34:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVw2UK31rztiG8djq2iH8LkCwOTYHPaBEwy8NvtU3z+xzIDYl3830A+1st9qep7YPyIVDA1L+puLHc=@googlegroups.com
X-Received: by 2002:ac2:4e0c:0:b0:539:f74b:62a5 with SMTP id 2adb3069b0e04-53b348dd3dcmr8181022e87.25.1730327656964;
        Wed, 30 Oct 2024 15:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730327656; cv=none;
        d=google.com; s=arc-20240605;
        b=aNSFQ5drl/YlJYXDKSFFi8IOTdWujUSE4eUlPcztITHwVtEmU6p2l41wyTYRAO2U5k
         v0NnyUDWbOMxe0cJgl0xtOcHd2DhVGQfn/Lu6U0uIQw7oMNmtV+D0apEbij/KSQy1UWF
         rYzK2nk+UdzJwbRFnkixdplMtksvzaTjqwZf6kArZ99ucgkdcTzOxzCXyTXuvOdFrEYo
         E+bxChA4Gqm2gShQdSLRGU1MkHmMgHVxoQuUhYS26aOnvnbLEryAdDpbTojL9lBqZ3iV
         OmxXbTYkhoLNqQYBsBe7zLiqzF12PNi03VKfPUSolWdShDL2eej+3I4WSBSjwzfBJuHo
         fhXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ni3lKjy3PY8T0mBefZFxGJ1yDDh/2Xy0r8Ncbm02QOA=;
        fh=bwHaE9vA1L4J7pzGwtuWiIgMw+l8r0GaToRK/UlBzUQ=;
        b=DU82iwJ3GO8cho7XUmZZxSkhCDFUCm1XIhZaZTGTg3+RIVuGd6K494s9gqI4Sh2tjN
         p6Uwb4CszWeIcvC6ltLnH5LuB/NJ07Kfb/iz5ovTZZROdQN8qAVBhr+gP01XdSpb5UGK
         0BPK9yGm3FSKXvl2gFf0zdpx7BFBRAGCoslwRVdBXSrRlfL4cdXXwzcyTMzjpGMt3d98
         BtnWc5mcOSPC84mqYIq7Au1c1Awo6YUatwwUENcMuvu4wHwpaQAh0Pyu8wQYy15Afhjm
         PxVj906uD8andSeKg5t/QXVsq20WtMu+F1xiqtSACmBW8NqUuIp4/KN8V1wtr3mDc/P5
         QR4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GIGTJEUF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bc961f1si4063e87.3.2024.10.30.15.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2024 15:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-43163667f0eso2758155e9.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 15:34:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUeK8nvpKAcvhYsEYxHuz3r75cJPN3D7xeHOZN0dHUGiTwYdVkDi1oW1N7UH9Fnf2Zw/fqekDhuwDY=@googlegroups.com
X-Received: by 2002:a5d:494f:0:b0:37d:4846:3d29 with SMTP id ffacd0b85a97d-38061162e68mr11660878f8f.28.1730327656290;
        Wed, 30 Oct 2024 15:34:16 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:ca43:df8b:ca42:54da])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-381c10b7b75sm250245f8f.15.2024.10.30.15.34.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 15:34:14 -0700 (PDT)
Date: Wed, 30 Oct 2024 23:34:08 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: paulmck@kernel.org, linux-next@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, sfr@canb.auug.org.au, bigeasy@linutronix.de,
	longman@redhat.com, boqun.feng@gmail.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <ZyK0YPgtWExT4deh@elver.google.com>
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GIGTJEUF;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 30, 2024 at 10:48PM +0100, Vlastimil Babka wrote:
> On 10/30/24 22:05, Paul E. McKenney wrote:
> > Hello!
> 
> Hi!
> 
> > The next-20241030 release gets the splat shown below when running
> > scftorture in a preemptible kernel.  This bisects to this commit:
> > 
> > 560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")
> > 
> > Except that all this is doing is enabling lockdep to find the problem.
> > 
> > The obvious way to fix this is to make the kmem_cache structure's
> > cpu_slab field's ->lock be a raw spinlock, but this might not be what
> > we want for real-time response.
> 
> But it's a local_lock, not spinlock and it's doing local_lock_irqsave(). I'm
> confused what's happening here, the code has been like this for years now.
> 
> > This can be reproduced deterministically as follows:
> > 
> > tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"
> > 
> > I doubt that the number of CPUs or amount of memory makes any difference,
> > but that is what I used.
> > 
> > Thoughts?
> > 
> > 							Thanx, Paul
> > 
> > ------------------------------------------------------------------------
> > 
> > [   35.659746] =============================
> > [   35.659746] [ BUG: Invalid wait context ]
> > [   35.659746] 6.12.0-rc5-next-20241029 #57233 Not tainted
> > [   35.659746] -----------------------------
> > [   35.659746] swapper/37/0 is trying to lock:
> > [   35.659746] ffff8881ff4bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x49/0x1b0
> > [   35.659746] other info that might help us debug this:
> > [   35.659746] context-{2:2}
> > [   35.659746] no locks held by swapper/37/0.
> > [   35.659746] stack backtrace:
> > [   35.659746] CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Not tainted 6.12.0-rc5-next-20241029 #57233
> > [   35.659746] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
> > [   35.659746] Call Trace:
> > [   35.659746]  <IRQ>
> > [   35.659746]  dump_stack_lvl+0x68/0xa0
> > [   35.659746]  __lock_acquire+0x8fd/0x3b90
> > [   35.659746]  ? start_secondary+0x113/0x210
> > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > [   35.659746]  lock_acquire+0x19b/0x520
> > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > [   35.659746]  ? __pfx_lock_acquire+0x10/0x10
> > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > [   35.659746]  ? lock_release+0x20f/0x6f0
> > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > [   35.659746]  ? lock_release+0x20f/0x6f0
> > [   35.659746]  ? kasan_save_track+0x14/0x30
> > [   35.659746]  put_cpu_partial+0x52/0x1b0
> > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > [   35.659746]  ? __pfx_scf_handler_1+0x10/0x10
> > [   35.659746]  __flush_smp_call_function_queue+0x2d2/0x600
> 
> How did we even get to put_cpu_partial directly from flushing smp calls?
> SLUB doesn't use them, it uses queue_work_on)_ for flushing and that
> flushing doesn't involve put_cpu_partial() AFAIK.
> 
> I think only slab allocation or free can lead to put_cpu_partial() that
> would mean the backtrace is missing something. And that somebody does a slab
> alloc/free from a smp callback, which I'd then assume isn't allowed?

Tail-call optimization is hiding the caller. Compiling with
-fno-optimize-sibling-calls exposes the caller. This gives the full
picture:

[   40.321505] =============================
[   40.322711] [ BUG: Invalid wait context ]
[   40.323927] 6.12.0-rc5-next-20241030-dirty #4 Not tainted
[   40.325502] -----------------------------
[   40.326653] cpuhp/47/253 is trying to lock:
[   40.327869] ffff8881ff9bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x48/0x1a0
[   40.330081] other info that might help us debug this:
[   40.331540] context-{2:2}
[   40.332305] 3 locks held by cpuhp/47/253:
[   40.333468]  #0: ffffffffae6e6910 (cpu_hotplug_lock){++++}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
[   40.336048]  #1: ffffffffae6e9060 (cpuhp_state-down){+.+.}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
[   40.338607]  #2: ffff8881002a6948 (&root->kernfs_rwsem){++++}-{4:4}, at: kernfs_remove_by_name_ns+0x78/0x100
[   40.341454] stack backtrace:
[   40.342291] CPU: 47 UID: 0 PID: 253 Comm: cpuhp/47 Not tainted 6.12.0-rc5-next-20241030-dirty #4
[   40.344807] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[   40.347482] Call Trace:
[   40.348199]  <IRQ>
[   40.348827]  dump_stack_lvl+0x6b/0xa0
[   40.349899]  dump_stack+0x10/0x20
[   40.350850]  __lock_acquire+0x900/0x4010
[   40.360290]  lock_acquire+0x191/0x4f0
[   40.364850]  put_cpu_partial+0x51/0x1a0
[   40.368341]  scf_handler+0x1bd/0x290
[   40.370590]  scf_handler_1+0x4e/0xb0
[   40.371630]  __flush_smp_call_function_queue+0x2dd/0x600
[   40.373142]  generic_smp_call_function_single_interrupt+0xe/0x20
[   40.374801]  __sysvec_call_function_single+0x50/0x280
[   40.376214]  sysvec_call_function_single+0x6c/0x80
[   40.377543]  </IRQ>
[   40.378142]  <TASK>

And scf_handler does indeed tail-call kfree:

	static void scf_handler(void *scfc_in)
	{
	[...]
		} else {
			kfree(scfcp);
		}
	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZyK0YPgtWExT4deh%40elver.google.com.
