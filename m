Return-Path: <kasan-dev+bncBCS4VDMYRUNBBF57RK4QMGQE52BBUKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 461EE9B6E5A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 22:05:29 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a4e52b6577sf2861205ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 14:05:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730322328; cv=pass;
        d=google.com; s=arc-20240605;
        b=YS0sOCFky9W7En4wnyoutrg1EYi+lw9DfZMuXCCLMJCPPnOgyB3dJAGtVGM3qj4bg4
         IOyhPJdUjZ0YoM0uO6f9CA59nyTvAABvRu9+VFPfrAKUGPYYuj0pu2wFLrvINFBzrbgK
         Ivhej2usUaI7ki/0wxRinUPxfO31sFYTPcyfhEpLp81Cpfx13zBmujUb2ab+TFE8Eq4N
         SQ8aclco/LKeZ92lTn6h3pD/Rcr5tIb42GD7+VtXTzUf64YtxSqatyxMSZI6/bCiPZvU
         +iWyYrMrFNyJGRqinKnQZBA7ag4lK371CD2GVUP5Pxl31g+OH77tKd7Na+z/nAbEfVqU
         Yu7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=/+bN5sg6hFXK2yJqaTr5D1UFrXg08ibv66pLSXlVSyg=;
        fh=59h9/03xPxSVSMy6NRHh5WVBCciGt1m5Vt/9UelZiOI=;
        b=Of8IUARsRn2LZXE4CLnfhAHO2uNuBmZJPnhEM1D3LO3F5Czrlix2OG3o36753lgdvh
         H99oL1pjlv7YGtPy28Noi0LklVsk4KY/vZRzN5k/bGKdjLp65x/vQDRB9XQf+IZ5ebk+
         ze7zAC0T9tUNMkcFnF7igWOQQ8UzK6QwvDQ1lVIzFSgvmrC+aiHdDEakblkU3a0po/WH
         +m1rza1ksAEdYMlCb2c7EJqjvkSK3lpWn0ooQOiDZ9q5NRZLPEtRrYnnDm8sWMSmOh0Z
         nB0ScMk1pSLYP5jYsgiJ7g+MrUU90AKrc4FgsltblVQbPvpNLC/YZCORxfZRBwSjVIQS
         G/XQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dtz6TJ3k;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730322328; x=1730927128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/+bN5sg6hFXK2yJqaTr5D1UFrXg08ibv66pLSXlVSyg=;
        b=OKUu10SpuEI1dBZjNL08oeLPHm0gdpMRugcRxVWwVc90XWfQUsxQi2VI6SkG13mxK5
         Tiec5unks2ud1slQaN9Fpquc2N9vZ8DRGwpy6rq3sHRTCJ+j3BZIHJPUlxCCJTBoT2hD
         SnSRaSl4BiXSrkOsXJlAcPjV4CVcqUz8aB9z2LPmuTKONARX3xqG5BpdKipXWdlnMvjw
         CXAh+j2ImeApeYSA/RxjGZCpmTHhsq7vtEcMJ7EreArWUSEBI8PsjB/snZbN0QhnoqyS
         ASQPiL/vXz0rV5GK+TlXPknSv5aDQ/UnOV6acr3Juw+GoNbpujJZc1WDyC6ASVXxijbr
         38XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730322328; x=1730927128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/+bN5sg6hFXK2yJqaTr5D1UFrXg08ibv66pLSXlVSyg=;
        b=nYH0oXSNBlFkMYLFYdVI7SYsejACR3Qaqn1oxAJaZNRP+q2MPVPwiN8xVyRgonVzvd
         sby7rJZcOXpu/+bHAkVheWh5jp/6dpn0B2WtpLqFcc0hqWxZZtVpQqjf8OBu2BZwR3GN
         M1L6O2bY4EqkXv4V5I0Uh+NxQFaeNhFxS2VzKtTQ0V2r8g6BbpmH8J4hTs7YAunnUYoV
         RvYL0IjKFMsmU6Uaiy9HsMTgt0RkKZgAvuVtk+kUkpokQ9AAu3Pn7BzKS67IeyIVtihn
         tCq4odBEbtA6JVkyRUCD3tiZUC9jJTxnJtA4bO6JRcio+IgcVSWc5n5BjaAkVwingeLp
         vUmw==
X-Forwarded-Encrypted: i=2; AJvYcCXJy82bbVoCchtlriNIfeRankWl+PyP255El5BF+FMrlw3P/yKlXwuTBzWZQbdgxqBUK9mfcg==@lfdr.de
X-Gm-Message-State: AOJu0Yx2hWeNLhzgRtrfIcve23PgGJGxEOh1WwZvP8xrKprg+00/fdxq
	X3xPEiS5sFze1KCp8xSvrNvixyozecYsXEbJYFWo6zJmz+D5QpRg
X-Google-Smtp-Source: AGHT+IEYM4wkMa8hqWPFohSwfdXzUaDAeTPA0FZnLSPCJs4gP4D3XHFcWv9ZndRbC+rvxC2l21RiPw==
X-Received: by 2002:a05:6e02:1d04:b0:3a3:449b:5989 with SMTP id e9e14a558f8ab-3a4ed304cebmr137920395ab.21.1730322327668;
        Wed, 30 Oct 2024 14:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:144d:b0:3a4:f2e2:f413 with SMTP id
 e9e14a558f8ab-3a62812d00els1266315ab.2.-pod-prod-09-us; Wed, 30 Oct 2024
 14:05:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoE43D+YW9RN9lLhRDR43GFrl6KS/OAICSGsXIGgYfoZtLIQp+qfVIceFI9auAF3NIb8s4HfJbFoo=@googlegroups.com
X-Received: by 2002:a05:6602:1555:b0:82d:129f:acb6 with SMTP id ca18e2360f4ac-83b1c5d8e3fmr1662795739f.14.1730322326675;
        Wed, 30 Oct 2024 14:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730322326; cv=none;
        d=google.com; s=arc-20240605;
        b=YCMMXgv9dmA1609dImOxMbdwCWgMkFFRnPlvUWTFn6Bmbaw/1KBrDGtMO0UsTcpNXR
         sP6RZNGaPU2sMJsfbXHViW0WuH2kIhBimcdQ1zgIsbMYzMJTetyAaVrXvVS1skJwllBR
         H9p3ougUST+7cPtngULhaXDgn3ml9EpLoABjQbbt1P5BWPn5qK2h/FLFHe8clKYv3/Ot
         9mcPy6GYaKnHEIfkSQ2b6w+04geuNpIevPNDZzpDVKdHqOham4dPWaWXOMP+nHUusKh3
         uNykKPpVi75a5q/vX6HXYnqqj/nlNGyjEXOvINm+fyE1ZsrKtX0a3ztNSe2vB/2m23vp
         E/Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=W63dxzR61iELVyFdI+F9Lm9cDA3lWQH9GFiwf3VbvWs=;
        fh=RGjW18Cjyk4lQwH0+t8F2kGuoq5PVuRWR4HIaBx65R4=;
        b=ANhnmIPn/sNJpW4ouSKSlzOTE6OrT3fMDBTWNhWfnuz8IaYmBD+IxV9zSIn4on/PFX
         rjz9Q+2VscK4BNXXEL4stwndRRYlR+qqEV73JVgUnI1PHUyoWkR9+dBqaYHeYzgCJfvv
         IGXLqwi5Z97V8L1vqiLwKZvemRvDqxl4kS/YWEzPd38dyDv+oVSu0IXb4sHWM9KlpACM
         EAyVsYlaBlFzXEd2aEO/rWpqcwZrRUOPH8Gul1GTwrTFUn1fYsTAbhZKlfYOrY+d8hSp
         iGvw2vUDF6xIocMpn5h1AJkqp+Cv7zMEnfrtC2Sh4mTjSkyCYp8q6QzKmrRsX2Kq4jF6
         pZVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dtz6TJ3k;
       spf=pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=rUt/=R2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dc725ecb47si478695173.2.2024.10.30.14.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 14:05:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rut/=r2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4A6825C5950;
	Wed, 30 Oct 2024 21:04:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E0A13C4CECE;
	Wed, 30 Oct 2024 21:05:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 84629CE0BB3; Wed, 30 Oct 2024 14:05:24 -0700 (PDT)
Date: Wed, 30 Oct 2024 14:05:24 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: sfr@canb.auug.org.au, bigeasy@linutronix.de, longman@redhat.com,
	boqun.feng@gmail.com, elver@google.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, vbabka@suse.cz
Subject: [BUG] -next lockdep invalid wait context
Message-ID: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Dtz6TJ3k;       spf=pass
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

Hello!

The next-20241030 release gets the splat shown below when running
scftorture in a preemptible kernel.  This bisects to this commit:

560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")

Except that all this is doing is enabling lockdep to find the problem.

The obvious way to fix this is to make the kmem_cache structure's
cpu_slab field's ->lock be a raw spinlock, but this might not be what
we want for real-time response.

This can be reproduced deterministically as follows:

tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"

I doubt that the number of CPUs or amount of memory makes any difference,
but that is what I used.

Thoughts?

							Thanx, Paul

------------------------------------------------------------------------

[   35.659746] =============================
[   35.659746] [ BUG: Invalid wait context ]
[   35.659746] 6.12.0-rc5-next-20241029 #57233 Not tainted
[   35.659746] -----------------------------
[   35.659746] swapper/37/0 is trying to lock:
[   35.659746] ffff8881ff4bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x49/0x1b0
[   35.659746] other info that might help us debug this:
[   35.659746] context-{2:2}
[   35.659746] no locks held by swapper/37/0.
[   35.659746] stack backtrace:
[   35.659746] CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Not tainted 6.12.0-rc5-next-20241029 #57233
[   35.659746] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
[   35.659746] Call Trace:
[   35.659746]  <IRQ>
[   35.659746]  dump_stack_lvl+0x68/0xa0
[   35.659746]  __lock_acquire+0x8fd/0x3b90
[   35.659746]  ? start_secondary+0x113/0x210
[   35.659746]  ? __pfx___lock_acquire+0x10/0x10
[   35.659746]  ? __pfx___lock_acquire+0x10/0x10
[   35.659746]  ? __pfx___lock_acquire+0x10/0x10
[   35.659746]  ? __pfx___lock_acquire+0x10/0x10
[   35.659746]  lock_acquire+0x19b/0x520
[   35.659746]  ? put_cpu_partial+0x49/0x1b0
[   35.659746]  ? __pfx_lock_acquire+0x10/0x10
[   35.659746]  ? __pfx_lock_release+0x10/0x10
[   35.659746]  ? lock_release+0x20f/0x6f0
[   35.659746]  ? __pfx_lock_release+0x10/0x10
[   35.659746]  ? lock_release+0x20f/0x6f0
[   35.659746]  ? kasan_save_track+0x14/0x30
[   35.659746]  put_cpu_partial+0x52/0x1b0
[   35.659746]  ? put_cpu_partial+0x49/0x1b0
[   35.659746]  ? __pfx_scf_handler_1+0x10/0x10
[   35.659746]  __flush_smp_call_function_queue+0x2d2/0x600
[   35.659746]  __sysvec_call_function_single+0x50/0x280
[   35.659746]  sysvec_call_function_single+0x6b/0x80
[   35.659746]  </IRQ>
[   35.659746]  <TASK>
[   35.659746]  asm_sysvec_call_function_single+0x1a/0x20
[   35.659746] RIP: 0010:default_idle+0xf/0x20
[   35.659746] Code: 4c 01 c7 4c 29 c2 e9 72 ff ff ff 90 90 90 90 90 90 90 90 90
 90 90 90 90 90 90 90 f3 0f 1e fa eb 07 0f 00 2d 33 80 3e 00 fb f4 <fa> c3 cc cc cc cc 66 66 2e 0f 1f 84 00 00 00 00 00 90 90 90 90 90
[   35.659746] RSP: 0018:ffff888100a9fe68 EFLAGS: 00000202
[   35.659746] RAX: 0000000000040d75 RBX: 0000000000000025 RCX: ffffffffab83df45
[   35.659746] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffffa8a5f7ba
[   35.659746] RBP: dffffc0000000000 R08: 0000000000000001 R09: ffffed103fe96c3c
[   35.659746] R10: ffff8881ff4b61e3 R11: 0000000000000000 R12: ffffffffad13f1d0
[   35.659746] R13: 1ffff11020153fd2 R14: 0000000000000000 R15: 0000000000000000
[   35.659746]  ? ct_kernel_exit.constprop.0+0xc5/0xf0
[   35.659746]  ? do_idle+0x2fa/0x3b0
[   35.659746]  default_idle_call+0x6d/0xb0
[   35.659746]  do_idle+0x2fa/0x3b0
[   35.659746]  ? __pfx_do_idle+0x10/0x10
[   35.659746]  cpu_startup_entry+0x4f/0x60
[   35.659746]  start_secondary+0x1bc/0x210
[   35.659746]  common_startup_64+0x12c/0x138
[   35.659746]  </TASK>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/41619255-cdc2-4573-a360-7794fc3614f7%40paulmck-laptop.
