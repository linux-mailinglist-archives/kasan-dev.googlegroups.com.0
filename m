Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZFP72QQMGQEP3S6GXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4B156E73FA
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 09:27:34 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6a604fbda57sf817648a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Apr 2023 00:27:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681889253; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4OTNKrC5yjjCHC74SA5aNOaohKbVpUTj1rCQqQccvPuemKhJdZIkeEEeOLX2a1MNY
         mz/RrFxoBXJEb6CryQ7VO23PU1i03nUYn+z7rFbEs2dv+Icyr6LhkaMWoi3aP9EiTiz+
         wFeU+7O8lEfCT5iGq7hw3P2uICFTiQYiZZpzG4B0k2aZwVvSXEWXh1c3TVwAbvsqhNAe
         9N/GAM6vG+UN/zjB5hTGR+iIRRQFRMeV6DJ/RvZa626i/FWGBq+R3URsVMx7Bj5ItB0s
         ED7KkYqIm/qzV+QSOsu8bhcpduK0gMRz0bMgrwpUu9CLaVUXieJxuvNNsTUfH0I/h+7z
         sLJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7hXzH+3At9NWOeh64b0ve4DBAdVJNryKsuL5RNY+T04=;
        b=JNbGnHV45/b7C6iAPA883M3LZdQaTjLOqSFaF9UBOer8A1BR4hHe6WCnyAVg1+hntQ
         kjBki8u4tQz1/JyfTE5/N4oxZ5RgEgJd4/yySS1442FIt64XK6gopP6A0md7mfdeMUdS
         8hWLS5812vil0JttJ5JFbo6Q5kBRnQx4KMhXHGQfuwm/c/bg58yxEgxPWzLTP7QJLqXG
         vjuuytZgI9M740l9UJeQqR2dn9zo7axEXJapp76UkcMimulCGIPuG3WUReXMbbed7mfE
         OAZbg7kwenjAXYzcGbqSiRO0mn05U0dJBRYgoBELS2Fjg0gApPRCvW399G7UrCVgE6eg
         XwkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=coR7f4X0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681889253; x=1684481253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7hXzH+3At9NWOeh64b0ve4DBAdVJNryKsuL5RNY+T04=;
        b=Dtfr+JPNJSUBqb6+jOskJsmLQIw1+NZS5Shvg4gCWBvnylmgeg2TOX5IZU7Rvg5BPo
         rtIdTvhR5MhQVW9SgN4lJk0aTF2frLlXXk6vdgSoId+Pvsqbat/4drYY+HSCAgQ5kv51
         1V7xcxd8SdPtRXKnMkjU5JHSac+luncp2ZwuWU3gUhV4vVaT6mPCOrcN+d9roCDP2GsF
         6d+ccqBlLE6Qt2ymBMmhiZ0NWM5WLEe30kKk7hnv8PUOFwFP0PVJuzV4s6/komB6+lyh
         8oQmnXmDwq5ITa7jYt7MfKDtQ8V+nhRjTiUfL++5st4fQmWybWNSIyJLnMlE1OZCmRG6
         ow1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681889253; x=1684481253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7hXzH+3At9NWOeh64b0ve4DBAdVJNryKsuL5RNY+T04=;
        b=YZhkbuSVbKeXqjJmDfiR2JB0tnrIXS6WN0voiu6brDzBcNXoybWE+EZBQksv1StSt7
         xch27EU8sBttO5ZVCY0PG8fpiUrTv/H/WslC0LJRI5hAVA2PIMvNU+Cf8uzbPDQeCiwp
         xb18KSaQDIIaGyx0JhvQy2lhkHNwnPEudh5oGxu2nkVyOY4eeerDHzexXxICrqBE2WKU
         9/XiomisGo3tn8wFYNCKvGIT8QUjnoM1jNsUz4Lmnb0g1+vj51Cql+TcBn3inOIlphaC
         f8N1Bgz+jpVgvsLAS11hqxuZAscLSuaAuHE3/MCp1L3sp+ZTuZBP56Wls4IDFhIjPfV4
         XtuQ==
X-Gm-Message-State: AAQBX9fqN54RLYAayFVu4Z4iJCtd5shj7e8b6hmVoHtsPgb1C3cSvpj/
	egLehR5TL/zHIDDKunqe1pY=
X-Google-Smtp-Source: AKy350ZleCnfQ+uAbfkCMIJTOofFl8AB8XJhoizrjUuoQpdnkVX0267zEsVE5UjfxolwsOGhg+qh1A==
X-Received: by 2002:a05:6870:2402:b0:187:b0bf:313d with SMTP id n2-20020a056870240200b00187b0bf313dmr1981745oap.2.1681889253067;
        Wed, 19 Apr 2023 00:27:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6018:b0:6a4:2aff:59e5 with SMTP id
 bx24-20020a056830601800b006a42aff59e5ls3183447otb.7.-pod-prod-gmail; Wed, 19
 Apr 2023 00:27:32 -0700 (PDT)
X-Received: by 2002:a9d:6747:0:b0:6a5:d944:f1c6 with SMTP id w7-20020a9d6747000000b006a5d944f1c6mr2543192otm.12.1681889252578;
        Wed, 19 Apr 2023 00:27:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681889252; cv=none;
        d=google.com; s=arc-20160816;
        b=hh/aX/zKm3kQMXd7ftpdcFagMtzjvcOVq0OU6BRVcNb78NScWJV/o86JQ6oLnfBThE
         y3fh2G953oRbrQL3zbuGV4XNh1aDncfGPRNWQgOGB0G4To0cQMTUmMXBjg8lnDKFusul
         EDyh7pjBmobplJqFrllN5670SIiwmhkaL+PhK1gBzaE8mqPX9vFkgmXs19Lb4z2SYUr2
         SQSNTzUxSSdaL+4jk8ktg9JNeAUmFXBPFFBC9GMtJSsS+JVguICo/QAvuG0m2XZAh4cO
         0cuxywbS0V3tPtG4BXeWKdd4OVjqJGY+kux1WaWW+qko+t1e1empmGET1teQTfiKgISv
         Ik2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4+jpKL/ey0sd/NtAlMmoATIMCLxVjtS/CGh7GhFIsWo=;
        b=fTv6G3Lf555LLBAcUvaAM6LcPyd7thHcY/F0gdaE/DS5w0SEQogXfox/W+rsGk/jT0
         WWzLpozw5NdYR+HpD6f/xXKzFtynIeaNPb0m6atpmnDM5Jm1b1x9th4nRJeYOp3oYIhw
         rlv78Dg+r3FuRX/1j4dL2aSg2jt2T+1liUU5jl2TFp258TiyQDr+il7p6hrVwfYf60GB
         Ic8n5xzCAwb6+gf01YI1YF1VkzrBaPyHM6MsQFxnh7dpecABqQGteBPUi4YKcw/I8ueP
         mImDyBxdb40XpvKTGMn1V6jSH+5IqftKI47KzTIin0w4cdkP1X1okrMnqblElPJfak7t
         +VlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=coR7f4X0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id n17-20020a0568300a9100b006a42f0f76f4si91197otu.2.2023.04.19.00.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Apr 2023 00:27:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id ca18e2360f4ac-76375982b6aso12921439f.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Apr 2023 00:27:32 -0700 (PDT)
X-Received: by 2002:a6b:e618:0:b0:760:ebae:4f8d with SMTP id
 g24-20020a6be618000000b00760ebae4f8dmr4016341ioh.8.1681889252043; Wed, 19 Apr
 2023 00:27:32 -0700 (PDT)
MIME-Version: 1.0
References: <20230327120019.1027640-1-qiang1.zhang@intel.com>
In-Reply-To: <20230327120019.1027640-1-qiang1.zhang@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Apr 2023 09:26:54 +0200
Message-ID: <CANpmjNOjPZm0hdxZmtp4HgqGpkevUvpj-9XGUe24rRTBRroiqg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Fix lockdep report invalid wait context
To: Zqiang <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Thomas Gleixner <tglx@linutronix.de>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=coR7f4X0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2c as
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

On Mon, 27 Mar 2023 at 13:48, Zqiang <qiang1.zhang@intel.com> wrote:
>
> For kernels built with the following options and booting
>
> CONFIG_SLUB=y
> CONFIG_DEBUG_LOCKDEP=y
> CONFIG_PROVE_LOCKING=y
> CONFIG_PROVE_RAW_LOCK_NESTING=y
>
> [    0.523115] [ BUG: Invalid wait context ]
> [    0.523315] 6.3.0-rc1-yocto-standard+ #739 Not tainted
> [    0.523649] -----------------------------
> [    0.523663] swapper/0/0 is trying to lock:
> [    0.523663] ffff888035611360 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x2e/0x1e0
> [    0.523663] other info that might help us debug this:
> [    0.523663] context-{2:2}
> [    0.523663] no locks held by swapper/0/0.
> [    0.523663] stack backtrace:
> [    0.523663] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.3.0-rc1-yocto-standard+ #739
> [    0.523663] Call Trace:
> [    0.523663]  <IRQ>
> [    0.523663]  dump_stack_lvl+0x64/0xb0
> [    0.523663]  dump_stack+0x10/0x20
> [    0.523663]  __lock_acquire+0x6c4/0x3c10
> [    0.523663]  lock_acquire+0x188/0x460
> [    0.523663]  put_cpu_partial+0x5a/0x1e0
> [    0.523663]  __slab_free+0x39a/0x520
> [    0.523663]  ___cache_free+0xa9/0xc0
> [    0.523663]  qlist_free_all+0x7a/0x160
> [    0.523663]  per_cpu_remove_cache+0x5c/0x70
> [    0.523663]  __flush_smp_call_function_queue+0xfc/0x330
> [    0.523663]  generic_smp_call_function_single_interrupt+0x13/0x20
> [    0.523663]  __sysvec_call_function+0x86/0x2e0
> [    0.523663]  sysvec_call_function+0x73/0x90
> [    0.523663]  </IRQ>
> [    0.523663]  <TASK>
> [    0.523663]  asm_sysvec_call_function+0x1b/0x20
> [    0.523663] RIP: 0010:default_idle+0x13/0x20
> [    0.523663] RSP: 0000:ffffffff83e07dc0 EFLAGS: 00000246
> [    0.523663] RAX: 0000000000000000 RBX: ffffffff83e1e200 RCX: ffffffff82a83293
> [    0.523663] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8119a6b1
> [    0.523663] RBP: ffffffff83e07dc8 R08: 0000000000000001 R09: ffffed1006ac0d66
> [    0.523663] R10: ffff888035606b2b R11: ffffed1006ac0d65 R12: 0000000000000000
> [    0.523663] R13: ffffffff83e1e200 R14: ffffffff84a7d980 R15: 0000000000000000
> [    0.523663]  default_idle_call+0x6c/0xa0
> [    0.523663]  do_idle+0x2e1/0x330
> [    0.523663]  cpu_startup_entry+0x20/0x30
> [    0.523663]  rest_init+0x152/0x240
> [    0.523663]  arch_call_rest_init+0x13/0x40
> [    0.523663]  start_kernel+0x331/0x470
> [    0.523663]  x86_64_start_reservations+0x18/0x40
> [    0.523663]  x86_64_start_kernel+0xbb/0x120
> [    0.523663]  secondary_startup_64_no_verify+0xe0/0xeb
> [    0.523663]  </TASK>
>
> The local_lock_irqsave() is invoked in put_cpu_partial() and happens
> in IPI context, due to the CONFIG_PROVE_RAW_LOCK_NESTING=y (the
> LD_WAIT_CONFIG not equal to LD_WAIT_SPIN), so acquire local_lock in
> IPI context will trigger above calltrace.
>
> This commit therefore move qlist_free_all() from hard-irq context to
> task context.
>
> Signed-off-by: Zqiang <qiang1.zhang@intel.com>

PROVE_RAW_LOCK_NESTING is for the benefit of RT kernels. So it's
unclear if this is fixing anything on non-RT kernels, besides the
lockdep warning.

I'd be inclined to say that having unified code for RT and non-RT
kernels is better.

Acked-by: Marco Elver <elver@google.com>

+Cc RT folks

> ---
>  v1->v2:
>  Modify the commit information and add Cc.
>
>  mm/kasan/quarantine.c | 34 ++++++++--------------------------
>  1 file changed, 8 insertions(+), 26 deletions(-)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 75585077eb6d..152dca73f398 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -99,7 +99,6 @@ static unsigned long quarantine_size;
>  static DEFINE_RAW_SPINLOCK(quarantine_lock);
>  DEFINE_STATIC_SRCU(remove_cache_srcu);
>
> -#ifdef CONFIG_PREEMPT_RT
>  struct cpu_shrink_qlist {
>         raw_spinlock_t lock;
>         struct qlist_head qlist;
> @@ -108,7 +107,6 @@ struct cpu_shrink_qlist {
>  static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
>         .lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
>  };
> -#endif
>
>  /* Maximum size of the global queue. */
>  static unsigned long quarantine_max_size;
> @@ -319,16 +317,6 @@ static void qlist_move_cache(struct qlist_head *from,
>         }
>  }
>
> -#ifndef CONFIG_PREEMPT_RT
> -static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
> -{
> -       struct kmem_cache *cache = arg;
> -       struct qlist_head to_free = QLIST_INIT;
> -
> -       qlist_move_cache(q, &to_free, cache);
> -       qlist_free_all(&to_free, cache);
> -}
> -#else
>  static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>  {
>         struct kmem_cache *cache = arg;
> @@ -340,7 +328,6 @@ static void __per_cpu_remove_cache(struct qlist_head *q, void *arg)
>         qlist_move_cache(q, &sq->qlist, cache);
>         raw_spin_unlock_irqrestore(&sq->lock, flags);
>  }
> -#endif
>
>  static void per_cpu_remove_cache(void *arg)
>  {
> @@ -362,6 +349,8 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>  {
>         unsigned long flags, i;
>         struct qlist_head to_free = QLIST_INIT;
> +       int cpu;
> +       struct cpu_shrink_qlist *sq;
>
>         /*
>          * Must be careful to not miss any objects that are being moved from
> @@ -372,20 +361,13 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>          */
>         on_each_cpu(per_cpu_remove_cache, cache, 1);
>
> -#ifdef CONFIG_PREEMPT_RT
> -       {
> -               int cpu;
> -               struct cpu_shrink_qlist *sq;
> -
> -               for_each_online_cpu(cpu) {
> -                       sq = per_cpu_ptr(&shrink_qlist, cpu);
> -                       raw_spin_lock_irqsave(&sq->lock, flags);
> -                       qlist_move_cache(&sq->qlist, &to_free, cache);
> -                       raw_spin_unlock_irqrestore(&sq->lock, flags);
> -               }
> -               qlist_free_all(&to_free, cache);
> +       for_each_online_cpu(cpu) {
> +               sq = per_cpu_ptr(&shrink_qlist, cpu);
> +               raw_spin_lock_irqsave(&sq->lock, flags);
> +               qlist_move_cache(&sq->qlist, &to_free, cache);
> +               raw_spin_unlock_irqrestore(&sq->lock, flags);
>         }
> -#endif
> +       qlist_free_all(&to_free, cache);
>
>         raw_spin_lock_irqsave(&quarantine_lock, flags);
>         for (i = 0; i < QUARANTINE_BATCHES; i++) {
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230327120019.1027640-1-qiang1.zhang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOjPZm0hdxZmtp4HgqGpkevUvpj-9XGUe24rRTBRroiqg%40mail.gmail.com.
