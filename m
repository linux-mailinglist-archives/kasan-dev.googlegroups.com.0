Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54M6GBAMGQEYYVF5ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 8348C348B4A
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 09:14:48 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id t4sf1047520lft.7
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Mar 2021 01:14:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616660088; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQz+V8AzLAUTuqj36v/j06wE6pe0vwIwldnPb+YNeu0zr4HxECY3QrsNczq7ocBXTX
         OMRkcZK/wJ/Kz+kMRKqalkqXZT626LP46AXDKALSB7F8wGfUbp3c5emiFs4cN6yORnyh
         Mw+T3oV462SdvWRGii4aMzD2j9EUA7jfNzokrBljYQQTbdhydjlxRLMyQGA6HtuZ8DqH
         gvAqwVLSWOaBu01UCZJniZqkscSgjA3X7po2Z4UVT9f2HvovMSVu2jlaC4vUxoRub3lH
         +vG42Kh9dgB+KAyOAQn4yuqJLeb/QUkPIPtqsD6W5ESusq+GaJJAIN0yHM50i4xUqbTi
         G0gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=F3vcJIWgYDbZvC+gFJZo+bbpRB7Q7Zmx6Psi0afgBCk=;
        b=biCPihJT2/PPlvsPl+8UkDLW82wkmphL/C8PmaxF7EZRgPbUp6e4hVS7zoKkCmtGCn
         SlwkpDitH/ojOycRAN7zILZkDuSKdA+77B/bSCKt+KtX597a2O8SiWfpOim0CXHy5m8b
         B63Ywxh2T46uBYRXNgYd9CJ9G+4fm5BC2N6SeD3z9pZcOcX/OOf8I6zEZDQTo16QLU5t
         Z7I4HfBCksDvJ4s5v8KPqncNbGXKL0Twduos6aWEc1/h8j+QsKxQcrixvtMDvQUTDcG4
         gVpCryanSjoMmJR8v5bYFf5rA6vIY8ZxKdDE+MVHcjtXBCqKOvWFyLIaZYCS4XTx/udx
         h3eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pJJ6zz9w;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=F3vcJIWgYDbZvC+gFJZo+bbpRB7Q7Zmx6Psi0afgBCk=;
        b=p4EhheCYDZM5asILd9t65/2NBD6xnorMo1t3WEZI8JYPbigZGXPljqxW5FgPzQLvjs
         cnVjdGpMonDT7/00xPVSO/NKTH589Lv+I790aqJ3tRmQsaLyPD7YnMxK/CYOV6MXI+/b
         o0ZHM/HvCQK5uefKD+MMBZU+FrVt5CAO3z2N3hVYHISbxGC4v9FEQmHbZNc5cKJWuqIn
         VYfRD3Uc3eGueEUHTwKkEO11p2ksAIb0WMjLK8T7jCqPdun956TFnyMKMpNZqtKV05XR
         Lik2QInLenkl5mIRWbORwAU1WkoaZDojuImBNN30EzWwa0iIvUt0uxBHDru0kduwNx+p
         FoHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F3vcJIWgYDbZvC+gFJZo+bbpRB7Q7Zmx6Psi0afgBCk=;
        b=bfplfDXDdstnJhQCtXc99lVbtgBaVV9vZUgu85H34qA1ZyhemQKU+sqb3DdImFuCHS
         MgeTukeUgRribNN7q5dhqMztGhrOYs9qJoc10kYArEQbTb9L+zE5BHXijl2aCyAaeJP8
         4wxNuP4vVQZhtv6US2b7PsbD0ICiUV/SQWjFZf97K7gsx33GsePVzpm5YNZcyYiDRM2m
         ihzwhFk9dqSKkvnhkjR61o1u/FrLyErlAroyXy6YBZFOOMKqNywrkxFLdGXts9pIOA0B
         Ldfyhg8J3QIOAeoSsIchnWVX3fL+hFt7h/7r1X3K+1IryqoTJxg/XoeTsMLxmQpL5yqa
         0aRQ==
X-Gm-Message-State: AOAM532Y+0QCmIpS7TIHxikNlKXLvJb7hO00Gmf/ETbRa5gtXzjSYJer
	VTRPBYrh9f6Pdiqqnj61IVE=
X-Google-Smtp-Source: ABdhPJzQmg9kAn/HC73i1ytZe8LwZ2WO6ShCYJ35LkYMPJUrSrk2+67E5DawNEVa3k8pakHKtCpJgQ==
X-Received: by 2002:a19:791e:: with SMTP id u30mr4337116lfc.621.1616660088069;
        Thu, 25 Mar 2021 01:14:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:589:: with SMTP id 131ls1048864ljf.9.gmail; Thu, 25 Mar
 2021 01:14:46 -0700 (PDT)
X-Received: by 2002:a2e:8e78:: with SMTP id t24mr4878986ljk.161.1616660086914;
        Thu, 25 Mar 2021 01:14:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616660086; cv=none;
        d=google.com; s=arc-20160816;
        b=1FEmuiOVXnUZ6fN0tV7Em0/3xUpHlCrFHctO1UY5Z6wDltiWjOIEXWFpXH6Rwul0IP
         rzAowZIIHXschtSZHPGKIqjnWtIgF0C8Rs+RhZ174UPZi92SpddKE/b+pJrr3n1IizYI
         aYqf5gw8XKRWcL+L1Qs4sVefAFUBuBG3d8Sz8K7ZZmdVq/jCqPL9l7ixcPJZK0LGWkaQ
         FpuQ3T59ZQ/D52SS85KTpLm3Lz6OINOlFAVMkKwWR4Y92ieC5ulJ3X5swyLSLITHNMMd
         D6NB7PDx6KB/3UIGX+ekYBNacNw6UpfXlbvzrzi58ALvxK4bvHs8BcmRRpiFFqlWxcrs
         WM4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OJh6Qrqk5/XT39gDll+pnHq9fpQbzFStOmpgSVUT43U=;
        b=LC/ognntjqP8GiXwVbVQ1ubGtOlG+2zKGS0ca04Z9GxhIGfkm1MPmxzKOaHUMkZR8R
         G5idUK1GFKMv5ByMjB/cBRjBM2kTAoHtJA7kKwE4/tzCiOMSYUvB3abQgaMOEbagQgx6
         2WZh4n5oWoZkg26Xve+a0vlCdHu4270E003NFYOWFVrM8KECXbFEt8LP3X2lIpEs4jov
         VQyhXw7OakYRVac2sP8PYMTVvyhRkI8nfKB3vNU3l8TPklRpSsH49ToLOTfD63JMS7Uz
         69v1lTv9mS+cIN6/O/UDyCqIGyuMyXqna0ogO1OJdenLIqggbsG/+QZWZIZEv6OO1c7J
         NGlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pJJ6zz9w;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id i30si254729lfj.6.2021.03.25.01.14.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Mar 2021 01:14:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id b9so1306800wrt.8
        for <kasan-dev@googlegroups.com>; Thu, 25 Mar 2021 01:14:46 -0700 (PDT)
X-Received: by 2002:a5d:4b0e:: with SMTP id v14mr6914126wrq.61.1616660086259;
        Thu, 25 Mar 2021 01:14:46 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:248e:270b:f7ab:435d])
        by smtp.gmail.com with ESMTPSA id r10sm5713418wmh.45.2021.03.25.01.14.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Mar 2021 01:14:45 -0700 (PDT)
Date: Thu, 25 Mar 2021 09:14:39 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, alexander.shishkin@linux.intel.com,
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com,
	mark.rutland@arm.com, namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de,
	christian@brauner.io, dvyukov@google.com, jannh@google.com,
	axboe@kernel.dk, mascasa@google.com, pcc@google.com,
	irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v3 06/11] perf: Add support for SIGTRAP on perf events
Message-ID: <YFxGb+QHEumZB6G8@elver.google.com>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210324112503.623833-7-elver@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pJJ6zz9w;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Wed, Mar 24, 2021 at 12:24PM +0100, Marco Elver wrote:
[...]
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index b6434697c516..1e4c949bf75f 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6391,6 +6391,17 @@ void perf_event_wakeup(struct perf_event *event)
>  	}
>  }
>  
> +static void perf_sigtrap(struct perf_event *event)
> +{
> +	struct kernel_siginfo info;
> +

I think we need to add something like this here:

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 4b82788fbaab..4fcd6b45ce66 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6395,6 +6395,13 @@ static void perf_sigtrap(struct perf_event *event)
 {
 	struct kernel_siginfo info;
 
+	/*
+	 * This irq_work can race with an exiting task; bail out if sighand has
+	 * already been released in release_task().
+	 */
+	if (!current->sighand)
+		return;
+
 	clear_siginfo(&info);
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;


Because syzkaller was able to produce this:

| general protection fault, probably for non-canonical address 0xdffffc0000000003: 0000 [#1] PREEMPT SMP KASAN
| KASAN: null-ptr-deref in range [0x0000000000000018-0x000000000000001f]
| CPU: 0 PID: 28393 Comm: kworker/u9:4 Not tainted 5.12.0-rc4+ #5
| Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
| RIP: 0010:__lock_acquire+0x87/0x5e60 kernel/locking/lockdep.c:4770
| Code: 84 c0 48 89 7c 24 78 0f 85 10 26 00 00 83 3d 53 64 59 0c 00 0f 84 84 41 00 00 83 3d 72 8a 01 0b 00 74 32 48 89 f8 48 c1 e8 03 <80> 3c 30 00 74 19 48 8b 7c 24 78 e8 79 8b 60 00 48 8b 7c 24 78 48
| RSP: 0018:ffffc90000007c00 EFLAGS: 00010006
| RAX: 0000000000000003 RBX: ffff888048058000 RCX: 0000000000000000
| RDX: 0000000000000000 RSI: dffffc0000000000 RDI: 0000000000000018
| RBP: ffffc90000007da8 R08: 0000000000000001 R09: 0000000000000001
| R10: fffffbfff1b6b27e R11: 0000000000000000 R12: 0000000000000001
| R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000001
| FS:  0000000000000000(0000) GS:ffff88802ce00000(0000) knlGS:0000000000000000
| CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
| CR2: 0000000000970004 CR3: 0000000040d91000 CR4: 0000000000750ef0
| DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
| DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000600
| PKRU: 55555554
| Call Trace:
|  <IRQ>
|  lock_acquire+0x126/0x650 kernel/locking/lockdep.c:5510
|  __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
|  _raw_spin_lock_irqsave+0x73/0xa0 kernel/locking/spinlock.c:159
|  force_sig_info_to_task+0x65/0x3f0 kernel/signal.c:1322
|  perf_sigtrap kernel/events/core.c:6418 [inline]
|  perf_pending_event_disable kernel/events/core.c:6433 [inline]
|  perf_pending_event+0x46f/0x620 kernel/events/core.c:6475
|  irq_work_single kernel/irq_work.c:153 [inline]
|  irq_work_run_list kernel/irq_work.c:175 [inline]
|  irq_work_run+0x1da/0x640 kernel/irq_work.c:184
|  __sysvec_irq_work+0x62/0x70 arch/x86/kernel/irq_work.c:22
|  sysvec_irq_work+0x8c/0xb0 arch/x86/kernel/irq_work.c:17
|  </IRQ>
|  asm_sysvec_irq_work+0x12/0x20 arch/x86/include/asm/idtentry.h:658
| RIP: 0010:__raw_write_unlock_irq include/linux/rwlock_api_smp.h:268 [inline]
| RIP: 0010:_raw_write_unlock_irq+0x25/0x40 kernel/locking/spinlock.c:343
| Code: aa fd ff 66 90 53 48 89 fb 48 83 c7 18 48 8b 74 24 08 e8 3e 34 04 f8 48 89 df e8 a6 1a 06 f8 e8 21 85 26 f8 fb bf 01 00 00 00 <e8> 56 19 fa f7 65 8b 05 77 65 a9 76 85 c0 74 02 5b c3 e8 2b c1 a7
| RSP: 0018:ffffc9000202fd68 EFLAGS: 00000286
| RAX: 2a7870700b93e400 RBX: ffffffff8c40a040 RCX: ffffffff8ff9cb03
| RDX: 0000000000000000 RSI: 0000000000000001 RDI: 0000000000000001
| RBP: ffff888047b24790 R08: ffffffff817f0f50 R09: fffffbfff1b6b27e
| R10: fffffbfff1b6b27e R11: 0000000000000000 R12: ffff888048058000
| R13: dffffc0000000000 R14: ffff888047b24701 R15: ffff888048058000
|  release_task+0x10bf/0x1360 kernel/exit.c:220
|  exit_notify kernel/exit.c:699 [inline]
|  do_exit+0x19b0/0x2290 kernel/exit.c:845
|  call_usermodehelper_exec_async+0x39c/0x3a0 kernel/umh.c:123
|  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:294


> +	clear_siginfo(&info);
> +	info.si_signo = SIGTRAP;
> +	info.si_code = TRAP_PERF;
> +	info.si_errno = event->attr.type;
> +	force_sig_info(&info);
> +}
> +
>  static void perf_pending_event_disable(struct perf_event *event)
>  {
>  	int cpu = READ_ONCE(event->pending_disable);
> @@ -6400,6 +6411,13 @@ static void perf_pending_event_disable(struct perf_event *event)
>  
>  	if (cpu == smp_processor_id()) {
>  		WRITE_ONCE(event->pending_disable, -1);
> +
> +		if (event->attr.sigtrap) {
> +			atomic_set(&event->event_limit, 1); /* rearm event */
> +			perf_sigtrap(event);
> +			return;
> +		}
> +
>  		perf_event_disable_local(event);
>  		return;
>  	}
[...] 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFxGb%2BQHEumZB6G8%40elver.google.com.
