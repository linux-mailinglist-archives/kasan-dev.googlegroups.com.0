Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAPCW2GQMGQEHH6MAXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7728446906E
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 07:43:14 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id i123-20020a2e2281000000b0021cfde1fa8esf2247492lji.7
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 22:43:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638772994; cv=pass;
        d=google.com; s=arc-20160816;
        b=cfzUrcPHqPinN8+ZuZMpp/G6RAH7/g3PBPqnrNw9sTLYT5Qaj755cfF3Nlf+POs2jC
         mlbm6D479C6MyP2S4/mdpwCCWaiIJvUsIGeX2tge2lUME1FuCr7iYncBN+5lUjjmeI8g
         VP3GmB7d/fJ13gdK1twrNYZuvZ2995a8RWYhWtHeBlMuNpvhK5tcnH0rY0edhUfQ69UK
         DQ8OKDdgvJGkk6ZJIWw6+ye87rieOuLnA6GRmsQ47QNCug4A0irouA04H2X++z+MyQaY
         28MnOI5n7GMzSQFLSIw/HLBI4h2zZr/Licp62cgNqm+yhO3W0NkNLFsWbDIlIcCUOCkZ
         u91g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=fHPPUE12BPEOhjcBRdEH4J+Kp/8VSJC5k/zv962Jb2Q=;
        b=zORYS5Emzrtylsnl7jynk1tk+PEliUw0X/+6dkg1XKrt7HVhayGh6jDdVX7sicO5y2
         nC15jHNSjQLGyxBJhZw7QcCvRNfEdZ8Wk3nBJBslyb5InJHr+qWSgIyUbz99TtzNk5Fp
         MBxlGN0PaUA4BzLPN/d0N5JuHxjjXV9H0RaUQNHhOEqvspGXAzvMAAb+x17/7N8k0wTT
         K6lwNb+UWdZHA0fti5SHsR+IgzHDrs75x5QrjJrzpK0IOieP4ihCL8J1xBCET/lZIVuK
         AupqTYlVkLKNZW6nJpQnSQ/CLMBG0+TZPvAjwqtxw/eSl20QLrrQd6b/mnpVdjmI3Ymh
         06IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pu3nHfeE;
       spf=pass (google.com: domain of 3algtyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ALGtYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fHPPUE12BPEOhjcBRdEH4J+Kp/8VSJC5k/zv962Jb2Q=;
        b=lY4MPDKGUfuF9xCnIWkB/d7LFSLoEtIoFuPpHUjMRizqTh50L0CZzjsvRHTnlYjpkN
         yqx6K3igYMZ+EprXjRyDw/XXle3yyWlgIdVYxe0Zv+vs22xBRXhtUCAEz4J0E6ePQFDh
         I2K8KJ4uyXpCBkARMKe2qKG504EKM1zrdiFyvhJnngoBmoCPTT5wM8iNMaamFbsOFsFx
         HQbX9r9enYfWE5CUkSNk1S7ryFa29NLPhkah9L9mG/UJXZ0EKp/MG5yb6A8fL0DK4Zzf
         cdJ7wXZsU+Rc1RQVHTxb6jBH13orcbwTGVJeiU1XuYaaF9y9s/ZCzxDRGf9xLzJpvHRa
         oBmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fHPPUE12BPEOhjcBRdEH4J+Kp/8VSJC5k/zv962Jb2Q=;
        b=U8hCdjAz6Xlx1rFsI2EW9eb9e9iuS59XVTgx10syRETAJpRPQG6YGJKCjmjpE8VGv7
         zuN5Z8NJu16sZArQdtRneD+ex05okAfh5nRCJnfLwlF6/ARAqxGj3sqgncA7rVly/Ic6
         r+O0J29ItGWMo2XIT9oEI8mRmZv5RtS9684DLe3AtqGsKWFLz0bE1qteQYBty6uLk+1F
         yYRFl5NnGqBfdKkrDE61k40No30Rb8XX63hnQdaE2za3WVReAmQP5H92Yf7L6Zs2Vfgp
         SIckCqfZI+DV/IDpel5DGnXQabwc/gJi1N+3dFRQ0NjJiBT8KJwnoOkzSK43GOEBAalK
         MXaA==
X-Gm-Message-State: AOAM531ssBWEUyBUAxg47xIkAbLnI1AtOJKW6GLdAE4n+UPpMLxycx5X
	wWFvPf1OILvZeAUX47ABFgc=
X-Google-Smtp-Source: ABdhPJwQAv1u7kaDAZYDrvd6ZAzbzdiVyK2KKFJ4WHnIKnlDR0eeGQ7tmn78YjBHoSbqV43nE34rRQ==
X-Received: by 2002:a05:6512:2351:: with SMTP id p17mr34211813lfu.243.1638772993939;
        Sun, 05 Dec 2021 22:43:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls263399lfv.1.gmail; Sun, 05
 Dec 2021 22:43:12 -0800 (PST)
X-Received: by 2002:a05:6512:158a:: with SMTP id bp10mr3585296lfb.407.1638772992829;
        Sun, 05 Dec 2021 22:43:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638772992; cv=none;
        d=google.com; s=arc-20160816;
        b=VrI6vJPTH+PG1KemXS2wni8y5TVSfwRUusQHfBosowVJPotpd7yxOPrxGPmPzmcL33
         kdbeFBaz+bWhj7dqGFKyC9o+S4G1MjUsX6n5YixUWjy5X1AjGcuGX6CQkkjUyEXFXnN4
         R4nvCb6rB1g0fNMoPFcIXEAfneJX6v6A/6kxcxy3h9kf1qA/sQlNTWINu0zMvcZqayn+
         9Kx2g8H+lhLXv4JKiqqtorfvQsluZDJZfSlyrNacHZ/M1L9nJH+l19HFJE+jepm5sNkb
         ehTcq3QjyN7sorOLg2Wmg5cKyNaBYQpe+A2wwfd4v5nRx76KVWTuMrRQ+Sg62CrzSJiQ
         Lo4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Mof/wiYmoBGxtT831oqCwy9BE2boVy0/SSf3ri1WpLU=;
        b=ro/yB89coRZo6RYZjQL3oQFxkXVA21vM8fehdWCeu6BMqf7Z38pedwYOfmio62vt8U
         SvSKWahcEDJHBNZL+fGOS96bgbyBbYOaFSzGs6c5eiI+BTUGRhRLPYmiJdzgNWe9eqWI
         VaIXC0ppyHug7v38D7dEWG5LrJcNuO31acRtkqoQa7O8Acxw/Qz9QkRF/e+/u2ePxYhc
         l4VoaETDhdQjI2BJaKHGdB98kUQVH78OL2AUDDQdOXt0kMJ8FDq2bobszgHVn16P2+o6
         cU6QOVU1FiRJKQZkP6N5gXQs0UbWWp5zeulv31sbJw3H0nH6P3aGTvPMhmN7RYuoj0o/
         OEoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pu3nHfeE;
       spf=pass (google.com: domain of 3algtyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ALGtYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v8si656827ljh.8.2021.12.05.22.43.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 22:43:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3algtyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h7-20020adfaa87000000b001885269a937so1694044wrc.17
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 22:43:12 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:88f3:db53:e34:7bb0])
 (user=elver job=sendgmr) by 2002:a05:600c:3c91:: with SMTP id
 bg17mr37190024wmb.80.1638772992245; Sun, 05 Dec 2021 22:43:12 -0800 (PST)
Date: Mon,  6 Dec 2021 07:41:50 +0100
Message-Id: <20211206064151.3337384-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.400.ga245620fadb-goog
Subject: [PATCH -rcu 1/2] kcsan: Avoid nested contexts reading inconsistent reorder_access
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pu3nHfeE;       spf=pass
 (google.com: domain of 3algtyqukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ALGtYQUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 916060913966..fe12dfe254ec 100644
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
2.34.1.400.ga245620fadb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206064151.3337384-1-elver%40google.com.
