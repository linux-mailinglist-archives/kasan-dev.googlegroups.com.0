Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C75474D8A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id v1-20020aa7cd41000000b003e80973378asf18261668edw.14
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=MPf3rKeECYvyZ24be0E64yp9N0648ku2XgUeBIrn2AE/BibAP58t7at4kgjYfz2ef+
         y/OKr7KGEWwjxxAoWp5RZ4b4n4PtBC9BYcULbagd1Aj1AhzQuStTqysuHhcMccrbc2Ur
         IOaMeWsks0YIHq4O3UX4oNdN6pe7W5Q5Lto2gjJtYOgDzsSihUKuhyXJ9CqWPPMIs3aL
         UPmBrVeClVj1in4vhwHG3w0rFsl3fg5oHeF/AoelYVGBewkRT3m4EaYc5CqHTOcyXKEo
         RxzqPcUmpww+KEbWLbOqTYfGcu7kkMhu40DQL/Een4/fYK2vZ0pJCXo6UqVv0ShvESH+
         a+hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=v4FWBwPtMgC7Wr4XZ3j3dCkU6iCMmOgi2AvE5Xx6AXo=;
        b=gH7nJiiXayIpZlJXK2nyaNjYx9fkMmHOT43N+lnFrXB2E+ndPzfQdtotaMqGvCxyiU
         UyrveES3Fg5273W4A5dHED6wjOzU/eYHfcxogau4Op/0rXyeR+O49kIAa08U/6shPVoG
         gklpv93iWxDZajvsYK0UdaZOZd+RibX9/8NmW0apYdxwlZ4GTTKFGHJGSbzAe0KCMzPa
         4+sJ5x+N1teJ/XiumF8N1MYakDhS2Y/vQDNiKOThgLV65GGXCfba5zb68mEt/AH8tYOS
         zkKSz4Z3kEp7d8WLaaOWnHkRZD0V4ZNwp4O8P3+XNx1cCgJsgQR0z0/atp2l65ofZty+
         sgfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eL0okwhy;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v4FWBwPtMgC7Wr4XZ3j3dCkU6iCMmOgi2AvE5Xx6AXo=;
        b=CiHjqq868RaBa5CMuQKEgxvSe0s2Wtp1Qo9pZ/bw5cQ/ad54T1bxwF66mnZI2h6gz9
         x3+roIk94VBQTuhTzomq9rMvKilr9On3YBcIMgbMm+twLjpks0CHrJiEnF68HRNXIoBA
         Ho1BQn0nj/kxSgz1rcGklK3Sc+L46H+sNS0hMDfvblBGRv3HhNrCb6+gQhbl/x6hTJ7S
         wt3DSpzBfB+YL+lldzveIO4+RUcNDwQh+aXaraI6Ry0if0JQQz4bwC8MP2Q6zYMolt4Y
         5mZqaEfv6CUgT8FR/v/6zZ4zcMTrdtRZP3X3C/Evy9LaGb1pm/CINZL51CBks1z7t18y
         /fOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v4FWBwPtMgC7Wr4XZ3j3dCkU6iCMmOgi2AvE5Xx6AXo=;
        b=tarJH1H5rWc5mAh7P5inlLKO3chgkuLcIBF39l0PHdLpEj8/zFv0sDjfx8q98NCRvv
         uw9286Ms72EMhae8SIrMO0i7a0XZSggpbpuvpRSeEY8S9d9sAZwAZLLyZJEzSHyqVFW0
         oXbq3wi06G24X2qiL219AkSOiDHNID/zfzQ77s0MYJOjRLlJYrQ2cRDxJNLR8jOPNgAr
         2bIyNKQ/RAR10p8EP9nweYvWv9nPGufXqlg5P3t/TBbo1s7YzOXto5fMbGtZumb9LEjX
         GXiMb0H9xXlA0JHNF4iyEchwwv5AEarqxcmwNaKbTuGm/qQZj0YZQqdo2j906puU6Xdw
         pJcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335P8JhTt92YBsoEWYDbMK30oH9rFyHpZ7SUbghYKc7Vn8LgA57
	qOcA3OYLAsPENIgY5uJycX8=
X-Google-Smtp-Source: ABdhPJxYQnXvnzwfWMAJbt7oSTzZlXJrZFW/kwdB//CjGbaFtVtiuIyNyovUd720+iBAkuAhTC/HLg==
X-Received: by 2002:a17:906:9746:: with SMTP id o6mr8401321ejy.714.1639519487086;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4246:: with SMTP id g6ls45619edb.1.gmail; Tue, 14
 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a05:6402:1395:: with SMTP id b21mr11549358edv.299.1639519486156;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=AG2xki3hmBXtif2LeaqRu11yFyXNCtOyrBF+BfsIGPJrnPXUZbth/8OHn7lqlLxXUK
         OWF0Y7fITchXw3Bm+RX47bSMNdvW8gLQbwafjx6aweqdUh4LXoKeM/NdNekG9RPQrrIE
         XYybnRoQmnpqqS5MZ0Hz+rS/MgtdhuEZ89YkFLpU7wSyJTi3eXyyIZciIsUIWJoDjj0S
         H2bd+W3OAzYSr82ssKKoLshnliJ4HLUgsHrDUXIqNpye41aWKCBpoNc3rAIUeNtUNTO8
         3eV7IUObURv8hh/LvdY4SBD+VcN3Z3Gw0kvhRbQphqThbycBbxZa7W+/gDjiUXJyA5Lv
         BmjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=u0IoCJPQoUfBoZZzJ3Q/6e0MGU1busUEzhWbyzIflrM=;
        b=NPJ4QIFLI45VQc9Ko2TADiFGEFTJq2sdAM6myyKCqbhuQlP0U479aiUJ3cvJL1teY5
         mhzl19xlOrHYLs5VhfbwqHybuBVSubhCvxmKCPYTczTX91giiwl1oFldD7EH6/TCbaeE
         CpqAlrm/zzytYRLVpJN3ETBcrArlFPGYNh04Zx9NWjp68vLbUsRz5VX46+DKs6x/b7Xy
         4Dppt/rzUxnmgSChc0NJclK94Wh8AaA8f7+EpMTO9MFTZF1AUS61ttUVc2scEY5D7wFP
         LXZtvdRi66f1yzwKGeiEgrBc623uXS1MEgTwGlQJxroxaA8t6cYgCTD1CnGmc3/65GZY
         DZOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eL0okwhy;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fl21si7328ejc.0.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AAF41616D9;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A3F9C341CB;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 900775C2C7A; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 28/29] kcsan: Avoid nested contexts reading inconsistent reorder_access
Date: Tue, 14 Dec 2021 14:04:38 -0800
Message-Id: <20211214220439.2236564-28-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eL0okwhy;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Nested contexts, such as nested interrupts or scheduler code, share the
same kcsan_ctx. When such a nested context reads an inconsistent
reorder_access due to an interrupt during set_reorder_access(), we can
observe the following warning:

 | ------------[ cut here ]------------
 | Cannot find frame for torture_random kernel/torture.c:456 in stack trace
 | WARNING: CPU: 13 PID: 147 at kernel/kcsan/report.c:343 replace_stack_entry kernel/kcsan/report.c:343
 | ...
 | Call Trace:
 |  <TASK>
 |  sanitize_stack_entries kernel/kcsan/report.c:351 [inline]
 |  print_report kernel/kcsan/report.c:409
 |  kcsan_report_known_origin kernel/kcsan/report.c:693
 |  kcsan_setup_watchpoint kernel/kcsan/core.c:658
 |  rcutorture_one_extend kernel/rcu/rcutorture.c:1475
 |  rcutorture_loop_extend kernel/rcu/rcutorture.c:1558 [inline]
 |  ...
 |  </TASK>
 | ---[ end trace ee5299cb933115f5 ]---
 | ==================================================================
 | BUG: KCSAN: data-race in _raw_spin_lock_irqsave / rcutorture_one_extend
 |
 | write (reordered) to 0xffffffff8c93b300 of 8 bytes by task 154 on cpu 12:
 |  queued_spin_lock                include/asm-generic/qspinlock.h:80 [inline]
 |  do_raw_spin_lock                include/linux/spinlock.h:185 [inline]
 |  __raw_spin_lock_irqsave         include/linux/spinlock_api_smp.h:111 [inline]
 |  _raw_spin_lock_irqsave          kernel/locking/spinlock.c:162
 |  try_to_wake_up                  kernel/sched/core.c:4003
 |  sysvec_apic_timer_interrupt     arch/x86/kernel/apic/apic.c:1097
 |  asm_sysvec_apic_timer_interrupt arch/x86/include/asm/idtentry.h:638
 |  set_reorder_access              kernel/kcsan/core.c:416 [inline]    <-- inconsistent reorder_access
 |  kcsan_setup_watchpoint          kernel/kcsan/core.c:693
 |  rcutorture_one_extend           kernel/rcu/rcutorture.c:1475
 |  rcutorture_loop_extend          kernel/rcu/rcutorture.c:1558 [inline]
 |  rcu_torture_one_read            kernel/rcu/rcutorture.c:1600
 |  rcu_torture_reader              kernel/rcu/rcutorture.c:1692
 |  kthread                         kernel/kthread.c:327
 |  ret_from_fork                   arch/x86/entry/entry_64.S:295
 |
 | read to 0xffffffff8c93b300 of 8 bytes by task 147 on cpu 13:
 |  rcutorture_one_extend           kernel/rcu/rcutorture.c:1475
 |  rcutorture_loop_extend          kernel/rcu/rcutorture.c:1558 [inline]
 |  ...

The warning is telling us that there was a data race which KCSAN wants
to report, but the function where the original access (that is now
reordered) happened cannot be found in the stack trace, which prevents
KCSAN from generating the right stack trace. The stack trace of "write
(reordered)" now only shows where the access was reordered to, but
should instead show the stack trace of the original write, with a final
line saying "reordered to".

At the point where set_reorder_access() is interrupted, it just set
reorder_access->ptr and size, at which point size is non-zero. This is
sufficient (if ctx->disable_scoped is zero) for further accesses from
nested contexts to perform checking of this reorder_access.

That then happened in _raw_spin_lock_irqsave(), which is called by
scheduler code. However, since reorder_access->ip is still stale (ptr
and size belong to a different ip not yet set) this finally leads to
replace_stack_entry() not finding the frame in reorder_access->ip and
generating the above warning.

Fix it by ensuring that a nested context cannot access reorder_access
while we update it in set_reorder_access(): set ctx->disable_scoped for
the duration that reorder_access is updated, which effectively locks
reorder_access and prevents concurrent use by nested contexts. Note,
set_reorder_access() can do the update only if disabled_scoped is zero
on entry, and must therefore set disable_scoped back to non-zero after
the initial check in set_reorder_access().

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 9160609139666..fe12dfe254ecf 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -412,11 +412,20 @@ set_reorder_access(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size,
 	if (!reorder_access || !kcsan_weak_memory)
 		return;
 
+	/*
+	 * To avoid nested interrupts or scheduler (which share kcsan_ctx)
+	 * reading an inconsistent reorder_access, ensure that the below has
+	 * exclusive access to reorder_access by disallowing concurrent use.
+	 */
+	ctx->disable_scoped++;
+	barrier();
 	reorder_access->ptr		= ptr;
 	reorder_access->size		= size;
 	reorder_access->type		= type | KCSAN_ACCESS_SCOPED;
 	reorder_access->ip		= ip;
 	reorder_access->stack_depth	= get_kcsan_stack_depth();
+	barrier();
+	ctx->disable_scoped--;
 }
 
 /*
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-28-paulmck%40kernel.org.
