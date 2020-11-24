Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFF6T6QKGQE7PWNS2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 44D9B2C28EE
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 15:03:25 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id r2sf3952808ejx.9
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 06:03:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606226605; cv=pass;
        d=google.com; s=arc-20160816;
        b=rOZ8rWcXsJr/3ATJysvxErmiUZt8U2a/XKeEgk5qDXWDU/fbN8MqvbXN8DWiGwv0bK
         lIEfLxKj5K5CML26ijJmA3xCnW8TAqgnMmlpdt1IPOcK93f3HMaMo1Y18Px8L8KBVdC7
         dx7AbZTppTrVXhcapPN1E9u+wsfGOnGfuwkzHXdmscQoxtqxhkUUBJjHKEf4H7P882wm
         g5SXdycVQSfAi/9bMzKl+GNb+bDC9OBCXHHnDoQpSbtrk1KrcUr0qLvXZKD+gln9+Je9
         6TpndM1FxX8cFi3g1gyN3WqIGs3KjP9J7Wo+1PAWJ1d8B1cRp2YxjK/ppWZ16EoDRRax
         G1rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=brCPYlB3a5aiLamgLVCMvrEIYt9ORqQgCqdnbc5DA/Y=;
        b=B+AJ5MD0eaEOtqB663+X9l1CYomZGnkpO/ForaXTSeOgXqpiwcp6xH/sMhKJN+gtFK
         2M5PD069wNXUnFVoGNiSQw0Nktma2LRI5SeAVcDDJ0jP3AjVwmciVetPOfE/GDNI1zHz
         T/OyPjeOLYEu3Zj5OYEJIM1NlOC5JJnHdGRbJKO/ps1Nu4+oL5cRwOvNCZdvuqiUlAAl
         TwKw9wS2DHfpQ6tPOGLV0RYnZm1sut5spOWVF0ZekYytXZeuN7XWMvqHP3LxSxdzwHlW
         kfbEUmgS/6ZrFSkfKDpTUdMMxNZO9nOR/hEGOxfAl79IxUQ/L2HlY0kXBkF+3E/je/c5
         B3rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sYb5b6iX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=brCPYlB3a5aiLamgLVCMvrEIYt9ORqQgCqdnbc5DA/Y=;
        b=YKzQjau9dVxSJIwMQpm5PuFOyJyxGoqPKmwQM3mS0MEGtgU3Y9/+UA/RTRefgPY9La
         pfVw0m6uHtvlfMih53opcHX5S48R/Y8lR2tdw00QoLPlCZGDYL3CgJLuQ41C+jgNZ1Yq
         HqDRA+BpXSEvgeIIU38T6PE9Tiws7vB2kSPAw1V5jfByvT/Uh2E33jaiQuqTmMiwveEL
         lutOvn3luFpZJdNhgLimHmeVFkhUCp0AwXNzKD005vdLjEo9r851MWRWuFlamcfNmcws
         xnWvapXEnPRDMgsOAM8eksjTDNGfHA32lknmz42MWZXFqFO8wa4sEQ/gX89CSpp43Ou+
         OK3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=brCPYlB3a5aiLamgLVCMvrEIYt9ORqQgCqdnbc5DA/Y=;
        b=BecBjBn+bsxgZpsROu6xUDsuo13G+qdpQVUFXWA0jipgbXbgwZvlv1VfkuwzXm9H2P
         +kJMV192LBpgSS1lue00pWU8DPAdrEAA+3c23EFW7Qgs6Fym3ONwUwjV1CHwvw47bWYa
         mE38XS0kiE5C5ia4CDsnkRsvO0rVx0oxeC4fWEjij47ZUhMM66lxDXwrCfAfEqp1OB7z
         /C4YMBvg92OEpmiLqBLCe8gI3zOuxIdt/hYAjE54YypMjqn1oChRts2zDvmJKlD8zKqJ
         hBCIt7vDcEg0Y1N+rJ158TS5MwSt9sPTT/CZ6/kAt3bsoJ88wWfEWHfs6btJWyP5JggN
         m9Hw==
X-Gm-Message-State: AOAM5312pmU5hAnkxJAocyftBmDNWns7mUsOqyNLOIvpUYuVkJLp+ptN
	N8HyRH5lU+xWPFo0+Rp1Gb0=
X-Google-Smtp-Source: ABdhPJzAOUCLRbLebD255sUJ2rwHo8rbdNUkHshUjWRo/K2iNokeQCZiv/HZM3h3afMykHUj+HeKEg==
X-Received: by 2002:aa7:c30e:: with SMTP id l14mr4034107edq.315.1606226604996;
        Tue, 24 Nov 2020 06:03:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:68a:: with SMTP id u10ls7729860ejb.0.gmail; Tue, 24
 Nov 2020 06:03:23 -0800 (PST)
X-Received: by 2002:a17:906:dbd6:: with SMTP id yc22mr4475001ejb.252.1606226603608;
        Tue, 24 Nov 2020 06:03:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606226603; cv=none;
        d=google.com; s=arc-20160816;
        b=AtjtW4ODKzysNYgQFTuzWqoNa7Jg6DOcCt3B1pW4RNR0L9wbMd1fe8IM6x0wfbmCpX
         veSg5i7FDIG43god6skAOtHw1fefB4rE25koB1UsiFFkovm82SH5Qp0r63OU4U3npTJj
         seZI3AuQsxf8WCdwkFhcrTBYSPrc//RIxI+Ti3RQRAKD0H9vtEpc8j8VprlfARKLo2CB
         cqPOtxa+kZJPGDuyrNm2Vv7Za1dMgbPZjP4tvBMcZ0AgZLWYsEMmug4AY6CKuM+5Nnb4
         UaIW9QGbPI1IWa1f5nEIdkf0IEdxHYbrhQivH1LaWvmsYsHQKKjDML7aK2aLe8hcXNTu
         SipQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FtzUUQfqG2taWVAOgcDrTawqRkA9wUblCM2QNuqO65s=;
        b=Z0hgQY2N5DhokmUmdr1LHRoc2+y6OH4z0Wjl7aPNGSD7P5mSvWdH0zJZBZVoEcHAlz
         daXU8EquLVvXVzG90HfuAuAwOJTlTDboe/JnvKp0+x0toQvoplVRbRpDSA764SSbDYzM
         Ypc+PvF4PW+DHE2bfnLvBfoyVUjFvSbVgMtlZ+eszLy5TiBctqAc+Idao79IRkFOvIMt
         SkZHVJQayeDUqCg2+gz2NdhGG3s1UR9ThwLADpQNwk/Mlt/RcWgdnK4HRI1KVKZfJ7S9
         5C4NfUjlGY2ymvXDsYA8fR3hqXdC+jUK69leNUiHJyrxW7/ve9exjJ4H8eJ/6rqlawwb
         CKXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sYb5b6iX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id v7si822874edj.5.2020.11.24.06.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Nov 2020 06:03:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id i2so3389148wrs.4
        for <kasan-dev@googlegroups.com>; Tue, 24 Nov 2020 06:03:23 -0800 (PST)
X-Received: by 2002:adf:9043:: with SMTP id h61mr5572911wrh.237.1606226602547;
        Tue, 24 Nov 2020 06:03:22 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id g138sm5501366wme.39.2020.11.24.06.03.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Nov 2020 06:03:20 -0800 (PST)
Date: Tue, 24 Nov 2020 15:03:10 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org, boqun.feng@gmail.com,
	tglx@linutronix.de
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201124140310.GA811510@elver.google.com>
References: <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
 <20201123193241.GA45639@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="M9NhX3UHpAaciwkO"
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
In-Reply-To: <20201123193241.GA45639@C02TD0UTHF1T.local>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sYb5b6iX;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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


--M9NhX3UHpAaciwkO
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Mon, Nov 23, 2020 at 07:32PM +0000, Mark Rutland wrote:
> On Fri, Nov 20, 2020 at 03:03:32PM +0100, Marco Elver wrote:
> > On Fri, Nov 20, 2020 at 10:30AM +0000, Mark Rutland wrote:
> > > On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> > > > FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark h=
as been
> > > > looking at that and I think he is close to having something workabl=
e.
> > > >=20
> > > > Mark -- is there anything Marco and Paul can try out?
> > >=20
> > > I initially traced some issues back to commit:
> > >=20
> > >   044d0d6de9f50192 ("lockdep: Only trace IRQ edges")
> > >=20
> > > ... and that change of semantic could cause us to miss edges in some
> > > cases, but IIUC mostly where we haven't done the right thing in
> > > exception entry/return.
> > >=20
> > > I don't think my patches address this case yet, but my WIP (currently
> > > just fixing user<->kernel transitions) is at:
> > >=20
> > > https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=
=3Darm64/irq-fixes
> > >=20
> > > I'm looking into the kernel<->kernel transitions now, and I know that=
 we
> > > mess up RCU management for a small window around arch_cpu_idle, but i=
t's
> > > not immediately clear to me if either of those cases could cause this
> > > report.
> >=20
> > Thank you -- I tried your irq-fixes, however that didn't seem to fix th=
e
> > problem (still get warnings and then a panic). :-/
>=20
> I've just updated that branch with a new version which I hope covers
> kernel<->kernel transitions too. If you get a chance, would you mind
> giving that a spin?
>=20
> The HEAD commit should be:
>=20
>   a51334f033f8ee88 ("HACK: check IRQ tracing has RCU watching")

Thank you! Your series appears to work and fixes the stalls and
deadlocks (3 trials)! I noticed there are a bunch of warnings in the log
that might be relevant (see attached).

Note, I also reverted

=C2=A0 sched/core: Allow try_invoke_on_locked_down_task() with irqs disable=
d

and that still works.

Thanks,
-- Marco

> Otherwise, I intend to clean that up and post it tomorrow (without the
> additional debug hacks). I've thrown my local Syzkaller instance at it
> in the mean time (and if I get the chance tomrrow I'll try to get
> rcutorture setup), and the only report I'm seeing so far looks genuine:
>=20
> | BUG: sleeping function called from invalid context in sta_info_move_sta=
te
>=20
> ... as that was reported on x86 too, per:
>=20
> https://syzkaller.appspot.com/bug?id=3D6c7899acf008be2ddcddb46a2567c21531=
93632a
>=20
> Thanks,
> Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201124140310.GA811510%40elver.google.com.

--M9NhX3UHpAaciwkO
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename="vm.log"

[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x411fd070]
[    0.000000] Linux version 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 (elver@elver.muc.corp.google.com) (aarch64-none-linux-gnu-gcc (GNU Toolchain for the A-profile Architecture 9.2-2019.12 (arm-9.10)) 9.2.1 20191025, GNU ld (GNU Toolchain for the A-profile Architecture 9.2-2019.12 (arm-9.10)) 2.33.1.20191209) #25 SMP PREEMPT Tue Nov 24 13:47:30 CET 2020
[    0.000000] Machine model: linux,dummy-virt
[    0.000000] efi: UEFI not found.
[    0.000000] cma: Reserved 32 MiB at 0x00000000be000000
[    0.000000] earlycon: pl11 at MMIO 0x0000000009000000 (options '')
[    0.000000] printk: bootconsole [pl11] enabled
[    0.000000] NUMA: No NUMA configuration found
[    0.000000] NUMA: Faking a node at [mem 0x0000000040000000-0x00000000bfffffff]
[    0.000000] NUMA: NODE_DATA [mem 0xbdbf6000-0xbdbf7fff]
[    0.000000] Zone ranges:
[    0.000000]   DMA      [mem 0x0000000040000000-0x000000007fffffff]
[    0.000000]   DMA32    [mem 0x0000000080000000-0x00000000bfffffff]
[    0.000000]   Normal   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000040000000-0x00000000bfffffff]
[    0.000000] On node 0 totalpages: 524288
[    0.000000]   DMA zone: 4096 pages used for memmap
[    0.000000]   DMA zone: 0 pages reserved
[    0.000000]   DMA zone: 262144 pages, LIFO batch:63
[    0.000000]   DMA32 zone: 4096 pages used for memmap
[    0.000000]   DMA32 zone: 262144 pages, LIFO batch:63
[    0.000000] psci: probing for conduit method from DT.
[    0.000000] psci: PSCIv0.2 detected in firmware.
[    0.000000] psci: Using standard PSCI v0.2 function IDs
[    0.000000] psci: Trusted OS migration not required
[    0.000000] percpu: Embedded 49 pages/cpu s162704 r8192 d29808 u200704
[    0.000000] pcpu-alloc: s162704 r8192 d29808 u200704 alloc=49*4096
[    0.000000] pcpu-alloc: [0] 0 
[    0.000000] Detected PIPT I-cache on CPU0
[    0.000000] CPU features: detected: ARM erratum 832075
[    0.000000] CPU features: detected: ARM erratum 834220
[    0.000000] CPU features: detected: EL2 vector hardening
[    0.000000] CPU features: kernel page table isolation forced ON by KASLR
[    0.000000] CPU features: detected: Kernel page table isolation (KPTI)
[    0.000000] CPU features: detected: Spectre-v2
[    0.000000] CPU features: detected: Spectre-v4
[    0.000000] CPU features: detected: ARM errata 1165522, 1319367, or 1530923
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 516096
[    0.000000] Policy zone: DMA32
[    0.000000] Kernel command line: console=ttyAMA0 root=/dev/sda debug earlycon earlyprintk=serial slub_debug=UZ slub_debug=- workqueue.watchdog_thresh=10
[    0.000000] Dentry cache hash table entries: 262144 (order: 9, 2097152 bytes, linear)
[    0.000000] Inode-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] software IO TLB: mapped [mem 0x000000007bfff000-0x000000007ffff000] (64MB)
[    0.000000] Memory: 1903696K/2097152K available (20800K kernel code, 4024K rwdata, 8508K rodata, 8896K init, 11238K bss, 160688K reserved, 32768K cma-reserved)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
[    0.000000] ftrace: allocating 56178 entries in 220 pages
[    0.000000] ftrace: allocated 220 pages with 5 groups
[    0.000000] Running RCU self tests
[    0.000000] rcu: Preemptible hierarchical RCU implementation.
[    0.000000] rcu: 	RCU event tracing is enabled.
[    0.000000] rcu: 	RCU lockdep checking is enabled.
[    0.000000] rcu: 	RCU restricting CPUs from NR_CPUS=256 to nr_cpu_ids=1.
[    0.000000] 	Trampoline variant of Tasks RCU enabled.
[    0.000000] 	Rude variant of Tasks RCU enabled.
[    0.000000] 	Tracing variant of Tasks RCU enabled.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
[    0.000000] NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0
[    0.000000] GICv2m: range[mem 0x08020000-0x08020fff], SPI[80:143]
[    0.000000] random: get_random_bytes called from start_kernel+0x468/0x670 with crng_init=0
[    0.000000] arch_timer: cp15 timer(s) running at 62.50MHz (virt).
[    0.000000] clocksource: arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns
[    0.000291] sched_clock: 56 bits at 62MHz, resolution 16ns, wraps every 4398046511096ns
[    0.014280] Console: colour dummy device 80x25
[    0.015796] Lock dependency validator: Copyright (c) 2006 Red Hat, Inc., Ingo Molnar
[    0.016131] ... MAX_LOCKDEP_SUBCLASSES:  8
[    0.016378] ... MAX_LOCK_DEPTH:          48
[    0.016626] ... MAX_LOCKDEP_KEYS:        8192
[    0.016887] ... CLASSHASH_SIZE:          4096
[    0.017138] ... MAX_LOCKDEP_ENTRIES:     32768
[    0.017385] ... MAX_LOCKDEP_CHAINS:      65536
[    0.017633] ... CHAINHASH_SIZE:          32768
[    0.017884]  memory used by lock dependency info: 6365 kB
[    0.018144]  memory used for stack traces: 4224 kB
[    0.018400]  per task-struct memory footprint: 1920 bytes
[    0.021247] Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=250000)
[    0.021914] pid_max: default: 32768 minimum: 301
[    0.025132] LSM: Security Framework initializing
[    0.027343] Mount-cache hash table entries: 4096 (order: 3, 32768 bytes, linear)
[    0.028580] Mountpoint-cache hash table entries: 4096 (order: 3, 32768 bytes, linear)
[    0.115959] rcu: Hierarchical SRCU implementation.
[    0.135096] EFI services will not be available.
[    0.139828] smp: Bringing up secondary CPUs ...
[    0.140267] smp: Brought up 1 node, 1 CPU
[    0.140587] SMP: Total of 1 processors activated.
[    0.141037] CPU features: detected: 32-bit EL0 Support
[    0.141769] CPU features: detected: CRC32 instructions
[    0.142144] CPU features: detected: 32-bit EL1 Support
[    0.547379] CPU: All CPU(s) started at EL1
[    0.548418] alternatives: patching kernel code
[    0.606936] devtmpfs: initialized
[    0.679006] KASLR enabled
[    0.707823] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.708867] futex hash table entries: 256 (order: 3, 32768 bytes, linear)
[    0.710674] Running postponed tracer tests:
[    0.714449] Testing tracer function: PASSED
[    8.629279] Testing dynamic ftrace: PASSED
[    9.591794] Testing dynamic ftrace ops #1: 
[   12.266300] (1 0 1 0 0) 
[   12.266797] (1 1 2 0 0) 
[   20.579408] (2 1 3 0 1141111) 
[   20.582238] (2 2 4 0 1141539) PASSED
[   24.613636] Testing dynamic ftrace ops #2: 
[   34.951883] (1 0 1 1116153 0) 
[   34.954384] (1 1 2 1116600 0) 
[   35.023400] (2 1 3 1 3074) 
[   35.024655] (2 2 4 200 3273) PASSED
[   38.154182] Testing ftrace recursion: PASSED
[   38.921470] Testing ftrace recursion safe: PASSED
[   39.687688] Testing ftrace regs: PASSED
[   40.462198] Testing tracer nop: PASSED
[   40.466389] Testing tracer irqsoff: PASSED
[   48.407206] Testing tracer preemptoff: PASSED
[   56.413646] Testing tracer preemptirqsoff: PASSED
[   64.506770] Testing tracer wakeup: PASSED
[   72.330196] Testing tracer wakeup_rt: PASSED
[   80.131803] Testing tracer wakeup_dl: PASSED
[   87.972631] Testing tracer function_graph: 
[   91.178997] 
[   91.184432] =============================
[   91.188301] WARNING: suspicious RCU usage
[   91.192316] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Tainted: G        W        
[   91.197536] -----------------------------
[   91.201431] kernel/trace/trace_preemptirq.c:78 RCU not watching trace_hardirqs_off()!
[   91.206546] 
[   91.206546] other info that might help us debug this:
[   91.206546] 
[   91.211790] 
[   91.211790] rcu_scheduler_active = 2, debug_locks = 0
[   91.216454] RCU used illegally from extended quiescent state!
[   91.220890] no locks held by swapper/0/0.
[   91.224712] 
[   91.224712] stack backtrace:
[   91.228794] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W         5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
[   91.234877] Hardware name: linux,dummy-virt (DT)
[   91.239032] Call trace:
[   91.242587]  dump_backtrace+0x0/0x240
[   91.246500]  show_stack+0x34/0x88
[   91.250295]  dump_stack+0x140/0x1bc
[   91.254159]  lockdep_rcu_suspicious+0xe4/0xf8
[   91.258332]  trace_hardirqs_off+0x214/0x330
[   91.262462]  trace_graph_return+0x1ac/0x1d8
[   91.266564]  ftrace_return_to_handler+0xa4/0x170
[   91.270809]  return_to_handler+0x1c/0x38
[   91.274826]  default_idle_call+0x94/0x38c
[   91.278869]  do_idle+0x240/0x290
[   91.282633]  rest_init+0x1e8/0x2dc
[   91.286529]  arch_call_rest_init+0x1c/0x28
[   91.290585]  start_kernel+0x638/0x670
[   91.295524] WARNING: CPU: 0 PID: 0 at kernel/locking/lockdep.c:5279 check_flags.part.0+0x1d4/0x1f8
[   91.296302] Modules linked in:
[   91.297644] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
[   91.298317] Hardware name: linux,dummy-virt (DT)
[   91.298975] pstate: 80000085 (Nzcv daIf -PAN -UAO -TCO BTYPE=--)
[   91.299648] pc : check_flags.part.0+0x1d4/0x1f8
[   91.300303] lr : check_flags.part.0+0x1d4/0x1f8
[   91.300960] sp : ffffdb60f8d73a50
[   91.301628] x29: ffffdb60f8d73a50 x28: ffffdb60f8d84000 
[   91.303527] x27: ffffdb60f869cbb8 x26: ffffdb60f6835930 
[   91.305431] x25: 0000000000000000 x24: 0000000000000000 
[   91.307343] x23: ffffdb60f8daf360 x22: 0000000000000001 
[   91.309242] x21: 0000000000000000 x20: 0000000000000001 
[   91.311145] x19: ffffdb60f9bcf000 x18: 00000000749f6e65 
[   91.313044] x17: 00000000dcd3f761 x16: 0000000000000005 
[   91.314954] x15: 0000000000000000 x14: 0000000000000028 
[   91.316854] x13: 000000000000067a x12: 0000000000000028 
[   91.318753] x11: 0101010101010101 x10: ffffdb60f8d73820 
[   91.320657] x9 : ffffdb60f6960ff8 x8 : 4e5241575f534b43 
[   91.322582] x7 : 4f4c5f4755424544 x6 : ffff4454fdbd3667 
[   91.324486] x5 : 00000000ffffffc8 x4 : ffff4454fdbd2c60 
[   91.326413] x3 : ffffdb60f6800000 x2 : ffffdb60f7c60000 
[   91.328308] x1 : 1c0af7741e0f0c00 x0 : 0000000000000000 
[   91.330227] Call trace:
[   91.330880]  check_flags.part.0+0x1d4/0x1f8
[   91.331547]  lock_acquire+0x208/0x508
[   91.332200]  _raw_spin_lock+0x5c/0x80
[   91.332849]  vprintk_emit+0xb4/0x380
[   91.333528]  vprintk_default+0x4c/0x60
[   91.334189]  vprintk_func+0x120/0x330
[   91.334863]  printk+0x78/0x9c
[   91.335523]  lockdep_rcu_suspicious+0x2c/0xf8
[   91.336195]  trace_hardirqs_off+0x214/0x330
[   91.336854]  trace_graph_return+0x1ac/0x1d8
[   91.337518]  ftrace_return_to_handler+0xa4/0x170
[   91.338190]  return_to_handler+0x1c/0x38
[   91.338841]  default_idle_call+0x94/0x38c
[   91.339512]  do_idle+0x240/0x290
[   91.340166]  rest_init+0x1e8/0x2dc
[   91.340840]  arch_call_rest_init+0x1c/0x28
[   91.341499]  start_kernel+0x638/0x670
[   91.342147] irq event stamp: 1727
[   91.342832] hardirqs last  enabled at (1727): [<ffffdb60f7c33094>] exit_el1_irq_or_nmi+0x24/0x50
[   91.343502] hardirqs last disabled at (1724): [<ffffdb60f7c33060>] enter_el1_irq_or_nmi+0x20/0x30
[   91.344193] softirqs last  enabled at (1726): [<ffffdb60f6835930>] return_to_handler+0x0/0x38
[   91.344866] softirqs last disabled at (1725): [<ffffdb60f68c6880>] irq_enter_rcu+0x88/0xa8
[   91.345546] ---[ end trace e131d25144579308 ]---
[   91.346413] 
[   91.347055] 
[   91.347707] =============================
[   91.348363] WARNING: suspicious RCU usage
[   91.349058] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Not tainted
[   91.349714] -----------------------------
[   91.350398] include/trace/events/ipi.h:19 suspicious rcu_dereference_check() usage!
[   91.351025] 
[   91.351702] other info that might help us debug this:
[   91.352324] 
[   91.352949] 
[   91.353626] rcu_scheduler_active = 2, debug_locks = 1
[   91.354291] RCU used illegally from extended quiescent state!
[   91.354965] no locks held by swapper/0/0.
[   91.355590] 
[   91.356257] stack backtrace:
[   91.356937] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
[   91.357611] Hardware name: linux,dummy-virt (DT)
[   91.358270] Call trace:
[   91.358925]  dump_backtrace+0x0/0x240
[   91.359597]  show_stack+0x34/0x88
[   91.360255]  dump_stack+0x140/0x1bc
[   91.360932]  lockdep_rcu_suspicious+0xe4/0xf8
[   91.361594]  smp_cross_call+0x220/0x228
[   91.362264]  arch_irq_work_raise+0x40/0x50
[   91.362925]  __irq_work_queue_local+0xb0/0xe8
[   91.363580]  irq_work_queue+0x5c/0xb8
[   91.364252]  printk_safe_log_store+0x1a0/0x1d8
[   91.364906]  vprintk_func+0x23c/0x330
[   91.365566]  printk+0x78/0x9c
[   91.366215]  lockdep_rcu_suspicious+0x2c/0xf8
[   91.366883]  lock_acquire+0x340/0x508
[   91.367538]  _raw_spin_lock+0x5c/0x80
[   91.368192]  vprintk_emit+0xb4/0x380
[   91.368866]  vprintk_default+0x4c/0x60
[   91.369521]  vprintk_func+0x120/0x330
[   91.370191]  printk+0x78/0x9c
[   91.370845]  lockdep_rcu_suspicious+0x2c/0xf8
[   91.371519]  trace_hardirqs_off+0x214/0x330
[   91.372172]  trace_graph_return+0x1ac/0x1d8
[   91.372842]  ftrace_return_to_handler+0xa4/0x170
[   91.373503]  return_to_handler+0x1c/0x38
[   91.374158]  default_idle_call+0x94/0x38c
[   91.374825]  do_idle+0x240/0x290
[   91.375479]  rest_init+0x1e8/0x2dc
[   91.376152]  arch_call_rest_init+0x1c/0x28
[   91.376804]  start_kernel+0x638/0x670
[   91.377475] =============================
[   91.378132] WARNING: suspicious RCU usage
[   91.378793] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Not tainted
[   91.379466] -----------------------------
[   91.380129] include/trace/events/lock.h:13 suspicious rcu_dereference_check() usage!
[   91.380769] 
[   91.381432] other info that might help us debug this:
[   91.382066] 
[   91.382690] 
[   91.383349] rcu_scheduler_active = 2, debug_locks = 1
[   91.384023] RCU used illegally from extended quiescent state!
[   91.384675] no locks held by swapper/0/0.
[   91.385316] 
[   91.385962] stack backtrace:
[   91.386647] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
[   91.387307] Hardware name: linux,dummy-virt (DT)
[   91.387956] Call trace:
[   91.388626]  dump_backtrace+0x0/0x240
[   91.389283]  show_stack+0x34/0x88
[   91.389952]  dump_stack+0x140/0x1bc
[   91.390602]  lockdep_rcu_suspicious+0xe4/0xf8
[   91.391270]  lock_acquire+0x340/0x508
[   91.391926]  _raw_spin_lock+0x5c/0x80
[   91.392580]  vprintk_emit+0xb4/0x380
[   91.393259]  vprintk_default+0x4c/0x60
[   91.393913]  vprintk_func+0x120/0x330
[   91.394581]  printk+0x78/0x9c
[   91.395230]  lockdep_rcu_suspicious+0x2c/0xf8
[   91.395899]  trace_hardirqs_off+0x214/0x330
[   91.396555]  trace_graph_return+0x1ac/0x1d8
[   91.397243]  ftrace_return_to_handler+0xa4/0x170
[   91.397901]  return_to_handler+0x1c/0x38
[   91.398556]  default_idle_call+0x94/0x38c
[   91.399231]  do_idle+0x240/0x290
[   91.399883]  rest_init+0x1e8/0x2dc
[   91.400562]  arch_call_rest_init+0x1c/0x28
[   91.401227]  start_kernel+0x638/0x670
[   91.401909] ------------[ cut here ]------------
[   91.402584] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())possible reason: unannotated irqs-off.
[   91.403248] irq event stamp: 1727
[   91.403939] hardirqs last  enabled at (1727): [<ffffdb60f7c33094>] exit_el1_irq_or_nmi+0x24/0x50
[   91.404614] hardirqs last disabled at (1724): [<ffffdb60f7c33060>] enter_el1_irq_or_nmi+0x20/0x30
[   91.405305] softirqs last  enabled at (1726): [<ffffdb60f6835930>] return_to_handler+0x0/0x38
[   91.405976] softirqs last disabled at (1725): [<ffffdb60f68c6880>] irq_enter_rcu+0x88/0xa8
[   94.124678] PASSED
[   94.137271] pinctrl core: initialized pinctrl subsystem
[   94.166010] DMI not present or invalid.
[   94.181220] NET: Registered protocol family 16
[   94.221500] DMA: preallocated 256 KiB GFP_KERNEL pool for atomic allocations
[   94.222319] DMA: preallocated 256 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
[   94.224040] DMA: preallocated 256 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
[   94.225379] audit: initializing netlink subsys (disabled)
[   94.232973] audit: type=2000 audit(82.136:1): state=initialized audit_enabled=0 res=1
[   94.251959] thermal_sys: Registered thermal governor 'step_wise'
[   94.252110] thermal_sys: Registered thermal governor 'power_allocator'
[   94.254016] cpuidle: using governor menu
[   94.259177] hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.
[   94.260165] ASID allocator initialised with 32768 entries
[   94.280847] Serial: AMBA PL011 UART driver
[   94.897305] 9000000.pl011: ttyAMA0 at MMIO 0x9000000 (irq = 47, base_baud = 0) is a PL011 rev1
[   94.899357] printk: console [ttyAMA0] enabled
[   94.899357] printk: console [ttyAMA0] enabled
[   94.899994] printk: bootconsole [pl11] disabled
[   94.899994] printk: bootconsole [pl11] disabled
[   95.136385] HugeTLB registered 1.00 GiB page size, pre-allocated 0 pages
[   95.136940] HugeTLB registered 32.0 MiB page size, pre-allocated 0 pages
[   95.137256] HugeTLB registered 2.00 MiB page size, pre-allocated 0 pages
[   95.137555] HugeTLB registered 64.0 KiB page size, pre-allocated 0 pages
[   95.172131] cryptd: max_cpu_qlen set to 1000
[   95.238749] ACPI: Interpreter disabled.
[   95.280884] iommu: Default domain type: Translated 
[   95.286381] vgaarb: loaded
[   95.292824] SCSI subsystem initialized
[   95.295892] libata version 3.00 loaded.
[   95.301200] usbcore: registered new interface driver usbfs
[   95.302249] usbcore: registered new interface driver hub
[   95.303362] usbcore: registered new device driver usb
[   95.319691] pps_core: LinuxPPS API ver. 1 registered
[   95.319974] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[   95.320522] PTP clock support registered
[   95.324309] EDAC MC: Ver: 3.0.0
[   95.356513] FPGA manager framework
[   95.358764] Advanced Linux Sound Architecture Driver Initialized.
[   95.379906] clocksource: Switched to clocksource arch_sys_counter
[  109.397497] VFS: Disk quotas dquot_6.6.0
[  109.398763] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[  109.404469] pnp: PnP ACPI: disabled
[  109.525997] NET: Registered protocol family 2
[  109.539351] tcp_listen_portaddr_hash hash table entries: 1024 (order: 4, 81920 bytes, linear)
[  109.541579] TCP established hash table entries: 16384 (order: 5, 131072 bytes, linear)
[  109.546171] TCP bind hash table entries: 16384 (order: 8, 1179648 bytes, linear)
[  109.550508] TCP: Hash tables configured (established 16384 bind 16384)
[  109.553087] UDP hash table entries: 1024 (order: 5, 163840 bytes, linear)
[  109.554809] UDP-Lite hash table entries: 1024 (order: 5, 163840 bytes, linear)
[  109.558939] NET: Registered protocol family 1
[  109.569986] RPC: Registered named UNIX socket transport module.
[  109.570338] RPC: Registered udp transport module.
[  109.570584] RPC: Registered tcp transport module.
[  109.570826] RPC: Registered tcp NFSv4.1 backchannel transport module.
[  109.571261] PCI: CLS 0 bytes, default 64
[  109.591131] hw perfevents: enabled with armv8_pmuv3 PMU driver, 5 counters available
[  109.592826] kvm [1]: HYP mode not available
[  109.700178] Initialise system trusted keyrings
[  109.703933] workingset: timestamp_bits=44 max_order=19 bucket_order=0
[  109.829691] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[  109.839361] NFS: Registering the id_resolver key type
[  109.840697] Key type id_resolver registered
[  109.841002] Key type id_legacy registered
[  109.842732] nfs4filelayout_init: NFSv4 File Layout Driver Registering...
[  109.846885] 9p: Installing v9fs 9p2000 file system support
[  109.923870] Key type asymmetric registered
[  109.924235] Asymmetric key parser 'x509' registered
[  109.925108] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 245)
[  109.925557] io scheduler mq-deadline registered
[  109.925920] io scheduler kyber registered
[  110.181262] pl061_gpio 9030000.pl061: PL061 GPIO chip registered
[  110.220260] pci-host-generic 4010000000.pcie: host bridge /pcie@10000000 ranges:
[  110.221906] pci-host-generic 4010000000.pcie:       IO 0x003eff0000..0x003effffff -> 0x0000000000
[  110.223253] pci-host-generic 4010000000.pcie:      MEM 0x0010000000..0x003efeffff -> 0x0010000000
[  110.224080] pci-host-generic 4010000000.pcie:      MEM 0x8000000000..0xffffffffff -> 0x8000000000
[  110.226250] pci-host-generic 4010000000.pcie: ECAM at [mem 0x4010000000-0x401fffffff] for [bus 00-ff]
[  110.229496] pci-host-generic 4010000000.pcie: PCI host bridge to bus 0000:00
[  110.230080] pci_bus 0000:00: root bus resource [bus 00-ff]
[  110.230473] pci_bus 0000:00: root bus resource [io  0x0000-0xffff]
[  110.230784] pci_bus 0000:00: root bus resource [mem 0x10000000-0x3efeffff]
[  110.231097] pci_bus 0000:00: root bus resource [mem 0x8000000000-0xffffffffff]
[  110.233438] pci 0000:00:00.0: [1b36:0008] type 00 class 0x060000
[  110.243007] pci 0000:00:01.0: [1af4:1009] type 00 class 0x000200
[  110.244685] pci 0000:00:01.0: reg 0x10: [io  0x0000-0x003f]
[  110.246053] pci 0000:00:01.0: reg 0x14: [mem 0x00000000-0x00000fff]
[  110.250653] pci 0000:00:01.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
[  110.260991] pci 0000:00:02.0: [1af4:1009] type 00 class 0x000200
[  110.262072] pci 0000:00:02.0: reg 0x10: [io  0x0000-0x003f]
[  110.262820] pci 0000:00:02.0: reg 0x14: [mem 0x00000000-0x00000fff]
[  110.264321] pci 0000:00:02.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
[  110.269991] pci 0000:00:03.0: [1af4:1000] type 00 class 0x020000
[  110.270750] pci 0000:00:03.0: reg 0x10: [io  0x0000-0x001f]
[  110.271274] pci 0000:00:03.0: reg 0x14: [mem 0x00000000-0x00000fff]
[  110.272464] pci 0000:00:03.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
[  110.273043] pci 0000:00:03.0: reg 0x30: [mem 0x00000000-0x0003ffff pref]
[  110.278520] pci 0000:00:04.0: [1af4:1004] type 00 class 0x010000
[  110.279261] pci 0000:00:04.0: reg 0x10: [io  0x0000-0x003f]
[  110.280022] pci 0000:00:04.0: reg 0x14: [mem 0x00000000-0x00000fff]
[  110.280997] pci 0000:00:04.0: reg 0x20: [mem 0x00000000-0x00003fff 64bit pref]
[  110.293126] pci 0000:00:03.0: BAR 6: assigned [mem 0x10000000-0x1003ffff pref]
[  110.293948] pci 0000:00:01.0: BAR 4: assigned [mem 0x8000000000-0x8000003fff 64bit pref]
[  110.294793] pci 0000:00:02.0: BAR 4: assigned [mem 0x8000004000-0x8000007fff 64bit pref]
[  110.295597] pci 0000:00:03.0: BAR 4: assigned [mem 0x8000008000-0x800000bfff 64bit pref]
[  110.296522] pci 0000:00:04.0: BAR 4: assigned [mem 0x800000c000-0x800000ffff 64bit pref]
[  110.297205] pci 0000:00:01.0: BAR 1: assigned [mem 0x10040000-0x10040fff]
[  110.297717] pci 0000:00:02.0: BAR 1: assigned [mem 0x10041000-0x10041fff]
[  110.298201] pci 0000:00:03.0: BAR 1: assigned [mem 0x10042000-0x10042fff]
[  110.298701] pci 0000:00:04.0: BAR 1: assigned [mem 0x10043000-0x10043fff]
[  110.299193] pci 0000:00:01.0: BAR 0: assigned [io  0x1000-0x103f]
[  110.299921] pci 0000:00:02.0: BAR 0: assigned [io  0x1040-0x107f]
[  110.300409] pci 0000:00:04.0: BAR 0: assigned [io  0x1080-0x10bf]
[  110.300883] pci 0000:00:03.0: BAR 0: assigned [io  0x10c0-0x10df]
[  110.359603] EINJ: ACPI disabled.
[  110.756520] virtio-pci 0000:00:01.0: enabling device (0000 -> 0003)
[  110.766562] virtio-pci 0000:00:02.0: enabling device (0000 -> 0003)
[  110.774880] virtio-pci 0000:00:03.0: enabling device (0000 -> 0003)
[  110.781745] virtio-pci 0000:00:04.0: enabling device (0000 -> 0003)
[  110.894006] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
[  110.949875] SuperH (H)SCI(F) driver initialized
[  110.962431] msm_serial: driver initialized
[  110.995190] cacheinfo: Unable to detect cache hierarchy for CPU 0
[  111.135917] loop: module loaded
[  111.155979] megasas: 07.714.04.00-rc1
[  111.179577] scsi host0: Virtio SCSI HBA
[  111.201653] scsi 0:0:0:0: Direct-Access     QEMU     QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5
[  112.559093] random: fast init done
[  112.595812] sd 0:0:0:0: Power-on or device reset occurred
[  112.611860] sd 0:0:0:0: [sda] 524288 512-byte logical blocks: (268 MB/256 MiB)
[  112.613211] sd 0:0:0:0: [sda] Write Protect is off
[  112.613728] sd 0:0:0:0: [sda] Mode Sense: 63 00 00 08
[  112.620764] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA
[  112.623873] sda: detected capacity change from 0 to 268435456
[  112.697968] physmap-flash 0.flash: physmap platform flash device: [mem 0x00000000-0x03ffffff]
[  112.704568] 0.flash: Found 2 x16 devices at 0x0 in 32-bit bank. Manufacturer ID 0x000000 Chip ID 0x000000
[  112.705537] Intel/Sharp Extended Query Table at 0x0031
[  112.706704] Using buffer write method
[  112.707437] erase region 0: offset=0x0,size=0x40000,blocks=256
[  112.714453] physmap-flash 0.flash: physmap platform flash device: [mem 0x04000000-0x07ffffff]
[  112.715449] 0.flash: Found 2 x16 devices at 0x0 in 32-bit bank. Manufacturer ID 0x000000 Chip ID 0x000000
[  112.716117] Intel/Sharp Extended Query Table at 0x0031
[  112.717014] Using buffer write method
[  112.717344] erase region 0: offset=0x0,size=0x40000,blocks=256
[  112.717696] Concatenating MTD devices:
[  112.717962] (0): "0.flash"
[  112.718183] (1): "0.flash"
[  112.718396] into device "0.flash"
[  112.733693] sda: detected capacity change from 0 to 268435456
[  112.734221] sd 0:0:0:0: [sda] Attached SCSI disk
[  112.868897] libphy: Fixed MDIO Bus: probed
[  112.896853] tun: Universal TUN/TAP device driver, 1.6
[  112.932681] thunder_xcv, ver 1.0
[  112.933749] thunder_bgx, ver 1.0
[  112.934733] nicpf, ver 1.0
[  112.968658] hclge is initializing
[  112.969507] hns3: Hisilicon Ethernet Network Driver for Hip08 Family - version
[  112.969832] hns3: Copyright (c) 2017 Huawei Corporation.
[  112.971113] e1000: Intel(R) PRO/1000 Network Driver
[  112.971392] e1000: Copyright (c) 1999-2006 Intel Corporation.
[  112.972667] e1000e: Intel(R) PRO/1000 Network Driver
[  112.972954] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
[  112.974131] igb: Intel(R) Gigabit Ethernet Network Driver
[  112.974412] igb: Copyright (c) 2007-2014 Intel Corporation.
[  112.975297] igbvf: Intel(R) Gigabit Virtual Function Network Driver
[  112.975775] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.
[  112.985686] sky2: driver version 1.30
[  113.009304] VFIO - User Level meta-driver version: 0.3
[  113.048551] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[  113.048946] ehci-pci: EHCI PCI platform driver
[  113.049956] ehci-platform: EHCI generic platform driver
[  113.053241] ehci-orion: EHCI orion driver
[  113.056368] ehci-exynos: EHCI Exynos driver
[  113.059235] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[  113.060113] ohci-pci: OHCI PCI platform driver
[  113.061205] ohci-platform: OHCI generic platform driver
[  113.064420] ohci-exynos: OHCI Exynos driver
[  113.075583] usbcore: registered new interface driver usb-storage
[  113.146880] rtc-pl031 9010000.pl031: registered as rtc0
[  113.148308] rtc-pl031 9010000.pl031: setting system clock to 2020-11-24T13:08:31 UTC (1606223311)
[  113.164111] i2c /dev entries driver
[  113.325456] sdhci: Secure Digital Host Controller Interface driver
[  113.325754] sdhci: Copyright(c) Pierre Ossman
[  113.336779] Synopsys Designware Multimedia Card Interface Driver
[  113.363215] sdhci-pltfm: SDHCI platform and OF driver helper
[  113.400526] ledtrig-cpu: registered to indicate activity on CPUs
[  113.441824] usbcore: registered new interface driver usbhid
[  113.442164] usbhid: USB HID core driver
[  113.560589] drop_monitor: Initializing network drop monitor service
[  113.562809] NET: Registered protocol family 17
[  113.566122] 9pnet: Installing 9P2000 support
[  113.577170] Key type dns_resolver registered
[  113.581865] registered taskstats version 1
[  113.582937] Running tests on all trace events:
[  113.583197] Testing all events: OK
[  136.678315] Running tests again, along with the function tracer
[  136.683603] Running tests on all trace events:
[  136.689620] Testing all events: OK
[  349.011031] Testing ftrace filter: OK
[  349.030607] Loading compiled-in X.509 certificates
[  349.062241] input: gpio-keys as /devices/platform/gpio-keys/input/input0
[  349.080633] ALSA device list:
[  349.081036]   No soundcards found.
[  349.081340] TAP version 14
[  349.081565] 1..0
[  349.088742] uart-pl011 9000000.pl011: no DMA platform data
[  349.105332] EXT4-fs (sda): mounting ext3 file system using the ext4 subsystem
[  349.195485] EXT4-fs (sda): mounted filesystem with ordered data mode. Opts: (null)
[  349.197107] VFS: Mounted root (ext3 filesystem) readonly on device 8:0.
[  349.201501] devtmpfs: mounted
[  349.369972] Freeing unused kernel memory: 8896K
[  349.371955] Run /sbin/init as init process
[  349.372238]   with arguments:
[  349.372474]     /sbin/init
[  349.372689]   with environment:
[  349.372927]     HOME=/
[  349.373135]     TERM=linux
[  349.373345]     earlyprintk=serial
[  349.838705] EXT4-fs (sda): re-mounted. Opts: (null)
[  349.840571] ext3 filesystem being remounted at / supports timestamps until 2038 (0x7fffffff)

--M9NhX3UHpAaciwkO--
