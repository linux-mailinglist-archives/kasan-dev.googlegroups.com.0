Return-Path: <kasan-dev+bncBCS4VDMYRUNBBAURRLAQMGQEKYL5OZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DADDAB4807
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 01:47:16 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-72e1e89b532sf2257506a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 16:47:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747093635; cv=pass;
        d=google.com; s=arc-20240605;
        b=dG4ikei0P3OhWW1Hxpk4z1PKbJs+78CKzsO2ZTc9nUvUtcTT9b9FAEXjfU3AHOhYk2
         C/ILodkprf9mLXcTgUTmhUpTYq7RRUiEROA8c9uvhwsaxs/2rXcLx31YlJTpzOjxIU/s
         PVDppsun9VDGu/ol3xPwH9bjWczWzdq3CDZCyu4tky18CDE9XYIGCrqTcz+x0Eq8SMaf
         cNnDgydMFrSRz0zeXZHizVe9phz7lvoKgPdOwT0POxwS7LGPGay7rNUyr3wgbHx+ARfq
         FqaUY+X2xk0aeHH9uNjmR4XD9k3mO3m+fJcjDM90sf9CBXNHl7FWyye0CUN6ZK7o1dL5
         /L9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=2bFZhkeB2qCPe4Zv7hRfDyVRnNsRK0ALX1rdD0gQ/xU=;
        fh=q2BpcuFgjo3RmJT3nEA8pD4D38J7wNGkBQlru5U14I8=;
        b=Avu8bpxXDPMHub0iXdkmgspqzmgKHN2R2EUWXsv0oO6Ckt5mbeF9moeOolWd3WenXO
         x4Un8TjmmerVPK2Pm45gLwRdCynkDt8otxATbQ+aoogKglCU9z2Opu7sfvBU/LPpDh1y
         Lua+Js+CPyR6Hy9tvIIwH7mF9kSlL4gAtzo5H2tjvVo88r0yLtq40Z82JMCzFuqfsC1B
         H66A91y4MW8cpkDHjVCYcfAsE6/BJI0WqmjA93hz1MYzriigofE60Euz1FfUahRnT9dW
         7IRQZzmqZ+Rd/pkdwy7Ai6NTyWFrRUhyZRHSYIBGexKbTMFLr6p8hEQZ2X7iCrw+AjBk
         BHvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KFF5XXF7;
       spf=pass (google.com: domain of srs0=nbks=x4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=NBKS=X4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747093635; x=1747698435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2bFZhkeB2qCPe4Zv7hRfDyVRnNsRK0ALX1rdD0gQ/xU=;
        b=niXTAPK/9TZntcbbIYDcQz2ObG2m0p5OAow4fjMY0WQgHL9Guq9aRH++I3qj1dh8tL
         UbpMHPsISiK8hLCZfHzviGPwhDwzv8aNN2d4CdHsYaMUhNqvxFW47qPl4wPydjKL13uq
         SVdD/sZXhRNYUXaYFjZcMtUwP3uZnWZyMvTt6SbcHicZf02/sdkcIXno3ujzHNVSTMr1
         1F64/i4TRt0/Ny7ms7URaYpXJf2Ft7/W0H9MFwmDMwzjvdjM15cmjX+h4kdcFbymvMh/
         4kWRsU30H6o9MxXOTn85pkNe4Vt7f9DH7MQ9S7z1OeLZc0dyHxX3G0Mh4JoruqosJRl7
         INKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747093635; x=1747698435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2bFZhkeB2qCPe4Zv7hRfDyVRnNsRK0ALX1rdD0gQ/xU=;
        b=hn55mIJucvfmOvjD4xZ0Via4mnabO7+6hOScPaOLC1/avktPUP8s9VBcrxxmegOtLq
         pNnBzDPUDg9VlVc6+ZFBSnceDhjZ3st1yf8FQj+lZ3mXDKITDgZyMbjVdX+1/6YuOdbz
         At1LiQVaD6PCsMWsSwFbXymQWrcAAd/+JIj8vsdiZ+w4lrJBJISi/shXErHnczQmwpt6
         dgV6rtB7cNh/pWAr7YmLNnALluA3vDUIv1lVn7B1AMl4eg8vB3iT+GgoTZ9rqxeY1ciQ
         EcwlbomTZK6Nsr5qZWX/jJ1nnMuNeKO68V9TbtA9QThKFi19HKVV87rtL4C0u/LQxrZy
         pfIg==
X-Forwarded-Encrypted: i=2; AJvYcCX1eT3DcQRroewgMyWBtt9oy641UwzvD6Zr+/FmkSXx1k75wTBe61avoFoyl657EpY6Mm4FJw==@lfdr.de
X-Gm-Message-State: AOJu0Yz75RqTmbV4O3/RDhutPzB+tBPMdGytnKrN2vLVj7BPjK/kp+F2
	+xm2M3T+zAlNjVl6QzIhcOrEo9hjKBGntB7yOdP40Qdnr8mXNCpC
X-Google-Smtp-Source: AGHT+IHXm7XEbOAGnV8kNEAX0PnAXlQwSPekwqFSI7EkbVE2h8y8kNAc8qX+T3OoitVlz/y+ji8KSw==
X-Received: by 2002:a05:6871:28c:b0:2d6:b7b:a83 with SMTP id 586e51a60fabf-2dba42ae727mr8311290fac.13.1747093634885;
        Mon, 12 May 2025 16:47:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHvQ8C4RO6KOZCMpegBcASyV+RpYLsaOP00n2C39U2N5A==
Received: by 2002:a05:6871:6106:b0:2a9:5c2a:c3b8 with SMTP id
 586e51a60fabf-2db7fe512e6ls2018898fac.0.-pod-prod-02-us; Mon, 12 May 2025
 16:47:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXc4UW4YmnYLqfq3aaUJOj81NULmetzKeTaVfg1jScqnh8FzBcfCO3LXhyzzmUykg1WP0vZLfriCoU=@googlegroups.com
X-Received: by 2002:a05:6870:a2c8:b0:2da:462f:ead4 with SMTP id 586e51a60fabf-2dba454b075mr8000587fac.38.1747093633771;
        Mon, 12 May 2025 16:47:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747093633; cv=none;
        d=google.com; s=arc-20240605;
        b=ZGIFbdi9KO5Aor8pJCte6xCHtnnY4pozzjXls8tdLOAd5zQpuYH9ZA8FcVFUJ9n+B9
         Nc67gPc9szlkEPW33HHZ6d4iJVx6yR0kgSMQy920MasMW2QRVmE5jjZUxEILYRxnvaUF
         /kJDw8DJlH1SDQBwsTNEeOG+nMDS/SBMW4nxRS4+7XBTIGMfg75RGa4CapmWzWzSIpA4
         W0gCyYwFg8NigaDLQh1gMHnjV5dLYz06pOdvLb26tD8GdXQbd2avO8OFqxWOQlLpUhYO
         vvHOE4jWI7gBgyyhUdgtfPhNOkw5BSOM4PffxhSBEQXh63OT58OxX3qPZ6GyABJpnMnH
         d3iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iJH57wymul8JC3fhpPQaU9T0FxJxIDLrbsCuPe7HJmM=;
        fh=WzNe9Tor9Rf5AeHUjwFyngvmXiqzuGwythMBDCz9GJs=;
        b=lxl8IdeUoXbfXd5po4DXJ4rldnUGXnrB0wM9HXZNqOeqo7QryiKMw28x6ZhXuTiTIn
         UOhv63ozN558UbWobLVAaESpMooGYMzmWgPoz+ebqmw3b+IFFXiZ5jLCKAfT72EqsMcY
         sQChwOd1JK7lOpZ3IiLyR1oiTzw6Rv/LvN9YcB2A20rjPOTBX7bFmvJulPUCOulelZuw
         /dh4vQ2iCB+Wv082p7dNepVOEm8K50decaAvz8iWcinZ42yFxNqVw8k20wyBdMR5VADv
         ATqnhmALXEJh3GbZwV4ECw15GI2MeQsnSKoA4eDiilgQkUCEEq+e6l+uaUyU/Xla2LMY
         Hj0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KFF5XXF7;
       spf=pass (google.com: domain of srs0=nbks=x4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=NBKS=X4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2dba06c9695si298819fac.2.2025.05.12.16.47.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 May 2025 16:47:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=nbks=x4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B384D629D8;
	Mon, 12 May 2025 23:47:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 63499C4CEE7;
	Mon, 12 May 2025 23:47:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 02A9ACE0857; Mon, 12 May 2025 16:47:12 -0700 (PDT)
Date: Mon, 12 May 2025 16:47:11 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Stephen Rothwell <sfr@canb.auug.org.au>,
	linux-next@vger.kernel.org, linux-mm@kvack.org
Subject: [BUG] sleeping function called from invalid context at
 ./include/linux/sched/mm.h:321
Message-ID: <a5c939c4-b123-4b2f-8a22-130e508cbcce@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KFF5XXF7;       spf=pass
 (google.com: domain of srs0=nbks=x4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 172.105.4.254 as permitted sender) smtp.mailfrom="SRS0=NBKS=X4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

The next-20250512 release got the following while running either of the
rcutorture TINY02 and SRCU-T scenarios with strict KCSAN enabled:

BUG: sleeping function called from invalid context at ./include/linux/sched=
/mm.h:321

This is the last line of this function:

	static inline void might_alloc(gfp_t gfp_mask)
	{
		fs_reclaim_acquire(gfp_mask);
		fs_reclaim_release(gfp_mask);

		might_sleep_if(gfpflags_allow_blocking(gfp_mask));
	}

The reproducer is as follows:

tools/testing/selftests/rcutorture/bin/kvm.sh --allcpus --duration 1m --con=
figs TINY02 --kcsan --kmake-arg CC=3Dclang

I ran this on x86 with clang version 19.1.7 (CentOS 19.1.7-1.el9).

See below for the full splat.  The TINY02 and SRCU-T scenarios are unique
in setting both CONFIG_SMP=3Dn and CONFIG_PROVE_LOCKING=3Dy.

Bisection converges here:

c836e5a70c59 ("genirq/chip: Rework irq_set_msi_desc_off()")

The commit reverts cleanly, but results in the following build error:

kernel/irq/chip.c:98:26: error: call to undeclared function 'irq_get_desc_l=
ock'

Thoughts?

						Thanx, Paul

------------------------------------------------------------------------

[=C2=A0 =C2=A0 8.862165] BUG: sleeping function called from invalid context=
 at ./include/linux/sched/mm.h:321=C2=A0
[=C2=A0 =C2=A0 8.862706] in_atomic(): 0, irqs_disabled(): 1, non_block: 0, =
pid: 1, name: swapper
[=C2=A0 =C2=A0 8.862706] preempt_count: 0, expected: 0
[=C2=A0 =C2=A0 8.862706] 1 lock held by swapper/1:
[=C2=A0 =C2=A0 8.862706]=C2=A0 #0: ffff99018127a1a0 (&dev->mutex){....}-{4:=
4}, at: __driver_attach+0x189/0x2f0=C2=A0
[=C2=A0 =C2=A0 8.862706] irq event stamp: 83979
[=C2=A0 =C2=A0 8.862706] hardirqs last=C2=A0 enabled at (83978): [<ffffffff=
8b01a83d>] _raw_spin_unlock_irqrestore+0x3d/0x60
[=C2=A0 =C2=A0 8.862706] hardirqs last disabled at (83979): [<ffffffff8b01a=
616>] _raw_spin_lock_irqsave+0x56/0xb0
[=C2=A0 =C2=A0 8.862706] softirqs last=C2=A0 enabled at (83749): [<ffffffff=
896e22d8>] __irq_exit_rcu+0x58/0xc0
[=C2=A0 =C2=A0 8.862706] softirqs last disabled at (83740): [<ffffffff896e2=
2d8>] __irq_exit_rcu+0x58/0xc0
[=C2=A0 =C2=A0 8.862706] CPU: 0 UID: 0 PID: 1 Comm: swapper Not tainted 6.1=
5.0-rc5-next-20250508-00001-g3d99c237b0d4-dirty #4043 NONE
[=C2=A0 =C2=A0 8.862706] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009)=
, BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
[=C2=A0 =C2=A0 8.862706] Call Trace:
[=C2=A0 =C2=A0 8.862706]=C2=A0 <TASK>
[=C2=A0 =C2=A0 8.862706]=C2=A0 dump_stack_lvl+0x77/0xb0
[=C2=A0 =C2=A0 8.862706]=C2=A0 dump_stack+0x19/0x24
[=C2=A0 =C2=A0 8.862706]=C2=A0 __might_resched+0x282/0x2a0
[=C2=A0 =C2=A0 8.862706]=C2=A0 __kmalloc_node_track_caller_noprof+0xa1/0x2a=
0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? _pcim_request_region+0x55/0x190
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx_pcim_addr_resource_release+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 __devres_alloc_node+0x4b/0xc0
[=C2=A0 =C2=A0 8.862706]=C2=A0 _pcim_request_region+0x55/0x190
[=C2=A0 =C2=A0 8.862706]=C2=A0 pcim_request_all_regions+0x37/0x260
[=C2=A0 =C2=A0 8.862706]=C2=A0 ahci_init_one+0x2f0/0x1750
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? rpm_resume+0x48d/0xc30
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pm_runtime_resume+0xa7/0xc0
[=C2=A0 =C2=A0 8.862706]=C2=A0 pci_device_probe+0xfc/0x1b0
[=C2=A0 =C2=A0 8.862706]=C2=A0 really_probe+0x1ba/0x500
[=C2=A0 =C2=A0 8.862706]=C2=A0 __driver_probe_device+0x137/0x1a0
[=C2=A0 =C2=A0 8.862706]=C2=A0 driver_probe_device+0x67/0x2d0
[=C2=A0 =C2=A0 8.862706]=C2=A0 __driver_attach+0x194/0x2f0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx___driver_attach+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 bus_for_each_dev+0x17a/0x1d0
[=C2=A0 =C2=A0 8.862706]=C2=A0 driver_attach+0x30/0x40
[=C2=A0 =C2=A0 8.862706]=C2=A0 bus_add_driver+0x22a/0x380
[=C2=A0 =C2=A0 8.862706]=C2=A0 driver_register+0xcf/0x1c0
[=C2=A0 =C2=A0 8.862706]=C2=A0 __pci_register_driver+0xfc/0x120
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx_ahci_pci_driver_init+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 ahci_pci_driver_init+0x24/0x40
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx_ahci_pci_driver_init+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 do_one_initcall+0xfb/0x300
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? prb_first_seq+0x1ba/0x1f0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? _prb_read_valid+0x627/0x660
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? prb_read_valid+0x47/0x70
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? console_unlock+0x179/0x1a0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? vprintk_emit+0x43d/0x480
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? _printk+0x83/0xb0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? parse_args+0x24f/0x5a0
[=C2=A0 =C2=A0 8.862706]=C2=A0 do_initcall_level+0x91/0xf0
[=C2=A0 =C2=A0 8.862706]=C2=A0 do_initcalls+0x60/0xa0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx_kernel_init+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 do_basic_setup+0x41/0x50
[=C2=A0 =C2=A0 8.862706]=C2=A0 kernel_init_freeable+0xb3/0x120
[=C2=A0 =C2=A0 8.862706]=C2=A0 kernel_init+0x20/0x200
[=C2=A0 =C2=A0 8.862706]=C2=A0 ret_from_fork+0x13e/0x1e0
[=C2=A0 =C2=A0 8.862706]=C2=A0 ? __pfx_kernel_init+0x10/0x10
[=C2=A0 =C2=A0 8.862706]=C2=A0 ret_from_fork_asm+0x19/0x30
[=C2=A0 =C2=A0 8.862706]=C2=A0 </TASK>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
5c939c4-b123-4b2f-8a22-130e508cbcce%40paulmck-laptop.
