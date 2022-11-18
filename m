Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXEZ36NQMGQEQVHLDQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA4B962FC61
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 19:20:13 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id r23-20020a1f2b17000000b003b89463c349sf2048438vkr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 10:20:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668795612; cv=pass;
        d=google.com; s=arc-20160816;
        b=HeyqfEgZw030PsEKZDShJbU85QD2QChrmoj2jzQUTWMeh/h5o4L7vvJaJF2VKAJzN7
         NIr1FN5yMigZYmZCGxoIgzEg28nq/ma05Wi/I+Dta0o+gIR/xIXwWWHQR3lGb6uKgOEF
         mW9yONWmnuDbpmE/cQNxWVwRPzB8c8eb0lc97S13RCo5WMKy5RFYVbuXZKfhyfwBXOEH
         u6tiqYPzR3ExmCYGCkbCu414FsKddG2Bx/JEgpXwLt5b0JOWfLu89e0O/k3T4vCicNhv
         K6OMV6fjiOU/ttI703Vr/h3t7fRXffz0AmJkZUrPslESGS9vCmTPZb7eHdBHaR8BRgSf
         LmAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aJ1nxnmYbKYhsHqgsK/4KortFqTBfCmaOfR8b1JilPE=;
        b=F/BfmmzFWjdlJUjsQYH3Ex4QLfvq/4UUzKp+XB93Hpj8Fa5SR5+EjLJ9P1W9xmIkJj
         wIl7n3UhafkpIZO4IUOtn+RGDfm8Y0RR/1XQgsL/GmXqLuCBfpHgpKnMApgBnSmfhVYS
         SYdvorS8vyQdLchTMRpyp0Iyo2AyAmrgqI+7Ldv4//pl+mLSQxSUI1xBZEef+5rWs2Pm
         zog+arbU0wXMGLdUvlpl7yh9+JuIothcfr+v8cEUaEpvTMjbYMzhRNBdkfJPT4vSIVgo
         d0WhGz0HU8c6pu0KfUIFgQR9hTyvemn/al55bFRoBUiNL7/7ScSjGa11qxynCAf1ZpI3
         PFYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tja3Im+s;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aJ1nxnmYbKYhsHqgsK/4KortFqTBfCmaOfR8b1JilPE=;
        b=H9F+5opKund7BKBP8Tyg/IOkLDlpsoVyFgP+3ZcHvk2Pni0yaXa9VdeH2uQFiCn043
         xCnsY9CrJM9DXPRHXlC6sw4RV0FpLZn5nblI044MxsyJchkueqEBcNwahJmC/XIWG8MF
         qSXEWY8Tm43B2icL3DHV9d3r0FlMcGZVKFKH9huT37VWPF7Fzl4qqwe1Wk/hBxCCZTo7
         ouBKIN0A4VVziSsKDXAb8I0KfrGN5FJ68x5B3hTIpDA4SehF0hf2xA7CqbiZJydhugnq
         kv6lvQcJ3Agb5s2uHWRqJqCyQTiJXaUPTg+vUdsT5oCpIx907YMGSbqZFGEQ6Q5U7Slj
         upOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aJ1nxnmYbKYhsHqgsK/4KortFqTBfCmaOfR8b1JilPE=;
        b=1L3s51vu1c/q6G0XWLh3GG9X7jD6feYhKcg4EanJQ/gL2MVy4pSgz/g0UYACP1wfFu
         Ebs4CsY5CxRP0sUfmDfLobfCAk1tXJBh6jrv1clnSD1bptYHddwAxbPmw5mSgFsNqvN3
         kKmavMlkWAGPR0xpcvuR+gWncBRHnYHeMg/rsPp3ZNbAQ2GbLyfhEDbd6Gpfg8g3nKC7
         qnfYhFFITiiKGRUKFBurDMY2M6bcE6x2FFazL5UWcsP0A3fJGhdh4Icn2Vw1hJIrOqmx
         Ej6Os7dJ0CeubDIlOTo0eJxJZXJn2QUgmeY6FQQNa/NXfzBurHCnB22XdGg7ra8u5zMI
         1iTw==
X-Gm-Message-State: ANoB5pnZnNXK2tDdVNg5/FVc3TLyWjcCoLzgSfIop3O94JCadIAEPeGZ
	1VYg4HV2B3baBVMmgJEk2GM=
X-Google-Smtp-Source: AA0mqf4Rnvi4PoMu6SuxgeqZP/Na/oyHkxY4KgQdOi3g17gFZJKc2jtexs8T9i4SJdvzVF2KuIK6JQ==
X-Received: by 2002:ab0:77c1:0:b0:418:620e:6794 with SMTP id y1-20020ab077c1000000b00418620e6794mr4667948uar.59.1668795612313;
        Fri, 18 Nov 2022 10:20:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e0dc:0:b0:3a9:e441:5ef with SMTP id m28-20020a67e0dc000000b003a9e44105efls1344472vsl.3.-pod-prod-gmail;
 Fri, 18 Nov 2022 10:20:11 -0800 (PST)
X-Received: by 2002:a67:c785:0:b0:3af:881d:1e68 with SMTP id t5-20020a67c785000000b003af881d1e68mr5617428vsk.10.1668795611574;
        Fri, 18 Nov 2022 10:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668795611; cv=none;
        d=google.com; s=arc-20160816;
        b=Fc2ENQX63iDMEu2hLp5ChuHjLB84+f+M39ZcVaiFlHg4lE+uadY+IG87sTa16fP2mS
         YaS23DDqOuetPAZBhJNUJ20qHaRTbIGXuRiSSNmKenqk6wbIJXId72lWkxgK0MRgrFO9
         vPRItFlp4KsIcPy6CYL/dUaOEHPh+34QpMrOd6bJN7GH0OJ+s9/DKic1hL68YzhOQlZu
         jvGdPuWHepUrPsExRgUuisiJXhwQ1HE9cRvi66wcfGEA+iAZrpRgT9qguqGaX6LG0peX
         EYVa63/pGd4A3l6HS8jTnT10+ocme0y2IU9RZIV7UashuG2edeR/ubLK1pUGeJ/lU0NK
         Z4RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mzosd7qcit/DhyEuPxX/KZLd3/ECFAwDjLQ9cH17uEU=;
        b=rbGBU/CfwnAzM4+L7/XkZ/v2MeRnCaHwxR6w18UobZ912V0R8jAOH+dM1iZAbLY4ET
         Qw8v8nAD2QRT8BVqPQWL4dRpx+VofLGcOL0AWu/ujCouRTQgcXd8ill3Ok/zsoqBTY62
         mkEeihox/GZnmMs1IoiWX8FOnR+bYlAQ0IH6xUCnBkUuUt67uRsWew5dINxBI2qhb4+E
         V1l4fCwGUcVS3Sf0wcMkQ503T8Fr8ZvsDR+EfSFNevQ1GAr1cr3kQPkejwfA5CDU1iRR
         CK0SMluWI/31nVy8kAzvFevRZFiEG8zim1etFe13JlJwO2aqCn14U3IIMAN4Zb0BHKFI
         ILZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tja3Im+s;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id h19-20020a1f2113000000b003b87533e1eesi298992vkh.3.2022.11.18.10.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 10:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id g127so6556832ybg.8
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 10:20:11 -0800 (PST)
X-Received: by 2002:a25:6a07:0:b0:6d4:84c5:8549 with SMTP id
 f7-20020a256a07000000b006d484c58549mr7428459ybc.376.1668795610233; Fri, 18
 Nov 2022 10:20:10 -0800 (PST)
MIME-Version: 1.0
References: <Y3VEL0P0M3uSCxdk@sol.localdomain> <CAG_fn=XwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA@mail.gmail.com>
 <Y3b9AAEKp2Vr3e6O@sol.localdomain> <CAG_fn=Upw7AsM_wZq0ajPixbAKp-izC7LMxyN_5onfL=OBhRzA@mail.gmail.com>
In-Reply-To: <CAG_fn=Upw7AsM_wZq0ajPixbAKp-izC7LMxyN_5onfL=OBhRzA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Nov 2022 19:19:33 +0100
Message-ID: <CAG_fn=USmF4fm+CDgfwGtJU2XXT8fuKrYVFFdouYrh+zRmnFsQ@mail.gmail.com>
Subject: Re: KMSAN broken with lockdep again?
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tja3Im+s;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Nov 18, 2022 at 2:39 PM Alexander Potapenko <glider@google.com> wrote:
>
> > > As far as I can tell, removing `KMSAN_SANITIZE_lockdep.o := n` does
> > > not actually break anything now (although the kernel becomes quite
> > > slow with both lockdep and KMSAN). Let me experiment a bit and send a
> > > patch.
>
> Hm, no, lockdep isn't particularly happy with the nested
> lockdep->KMSAN->lockdep calls:
>
> ------------[ cut here ]------------
> DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
> WARNING: CPU: 0 PID: 0 at kernel/locking/lockdep.c:5508 check_flags+0x63/0x180
> ...
>  <TASK>
>  lock_acquire+0x196/0x640 kernel/locking/lockdep.c:5665
>  __raw_spin_lock_irqsave ./include/linux/spinlock_api_smp.h:110
>  _raw_spin_lock_irqsave+0xb3/0x110 kernel/locking/spinlock.c:162
>  __stack_depot_save+0x1b1/0x4b0 lib/stackdepot.c:479
>  stack_depot_save+0x13/0x20 lib/stackdepot.c:533
>  __msan_poison_alloca+0x100/0x1a0 mm/kmsan/instrumentation.c:263
>  native_save_fl ./include/linux/spinlock_api_smp.h:?
>  arch_local_save_flags ./arch/x86/include/asm/irqflags.h:70
>  arch_irqs_disabled ./arch/x86/include/asm/irqflags.h:130
>  __raw_spin_unlock_irqrestore ./include/linux/spinlock_api_smp.h:151
>  _raw_spin_unlock_irqrestore+0x60/0x100 kernel/locking/spinlock.c:194
>  tty_register_ldisc+0xcb/0x120 drivers/tty/tty_ldisc.c:68
>  n_tty_init+0x1f/0x21 drivers/tty/n_tty.c:2521
>  console_init+0x1f/0x7ee kernel/printk/printk.c:3287
>  start_kernel+0x577/0xaff init/main.c:1073
>  x86_64_start_reservations+0x2a/0x2c arch/x86/kernel/head64.c:556
>  x86_64_start_kernel+0x114/0x119 arch/x86/kernel/head64.c:537
>  secondary_startup_64_no_verify+0xcf/0xdb arch/x86/kernel/head_64.S:358
>  </TASK>
> ---[ end trace 0000000000000000 ]---

In fact, this message is printed in both cases: with and without KMSAN
instrumenting kernel/locking/lockdep.c
I wonder if this is a sign of a real problem in KMSAN, or just an
unavoidable consequence of instrumented code calling lockdep when
taking the stackdepot lock...

> > > If this won't work out, we'll need an explicit call to
> > > kmsan_unpoison_memory() somewhere in lockdep_init_map_type() to
> > > suppress these reports.
>
> I'll go for this option.
>
> > Thanks.
> >
> > I tried just disabling CONFIG_PROVE_LOCKING, but now KMSAN warnings are being
> > spammed from check_stack_object() in mm/usercopy.c.
> >
> > Commenting out the call to arch_within_stack_frames() makes it go away.
>
> Yeah, arch_within_stack_frames() performs stack frame walking, which
> confuses KMSAN.
> We'll need to apply __no_kmsan_checks to it, like we did for other
> stack unwinding functions.

Sent the patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUSmF4fm%2BCDgfwGtJU2XXT8fuKrYVFFdouYrh%2BzRmnFsQ%40mail.gmail.com.
