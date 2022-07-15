Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOAYWLAMGQEDNSRLEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 37B3D5761FE
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 14:40:31 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-10ca937d5e0sf2784132fac.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 05:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657888830; cv=pass;
        d=google.com; s=arc-20160816;
        b=xG8S7gL4ZH+BAx/bDoPa7dNsJXBfhXMP5+uHpe+ulaeWkoYTgeBO9YUzKgo7KgAykq
         krDUKB1KG4vlF6YKZgsVA/nSz9O0UI4mr52hQGlaY7cBOuvB6QaMderuwAocxMVyaGWC
         taaA7q3vhEDuIhtAsHuxxfApblhP2/LvvgwskgVlJ3aD4fjHykp70yB8EBYBjpeZ1tbp
         UE+/Jt+gzHwHAqMV0AqJWk8HCWdm0WJ0kYU93XurxHXRNglOPZ06cAz7FO5zJcGZKopr
         OnlC5WJoNSe6G9Cq9Td94MIMV7qZEet0T5zKHqk1o1eVD/bYlo4ebVWO4W1NbCmw53dh
         xdAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AwRhklPqsXKgj1xCDhjBcdwXMZdd0Z2pameV3iZCY3E=;
        b=rejZ8VT209j2ADDEKefAdQemx1z3GX27KT1esy9vWDJFEMtTR0j1SjDCS98+Gs2gFU
         //HqMnmdnptIuy8qG1iqy1PA1x/0xhF7pRDpRdfBz+rdpkxNq7FUg1P8CgvAA/0gEIwJ
         IbY3Bl98f/4dqZHwLPlnYD8mkz661x+iR2/z9yyqabFfmmbwLvHPvVeyTR0zt2G+hK4O
         Tkz9/53o2v+MOL4+h/XgbKz6Q4SpwolLDICh/myG/Iolc5zBakrgqZZ3IoEugdIOIJKv
         mBR6jeovPmUVN05rRTgcgvBjWCNdfzICSKf349eabWYN7Eq5EfMJTGRCFRe8477A4+sw
         ocIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MgzKUYmw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AwRhklPqsXKgj1xCDhjBcdwXMZdd0Z2pameV3iZCY3E=;
        b=KP1KmnhTyYvMeISSnfxqna5DZ6LH1YG+6zGIJuuAa7mLfhV1iSPIR6pZE1vpegJjLg
         jknOsbJZyha4uaNpv90JAixr1F5j+QGELoV1KlG2hVnXq7mN6WXvqQRQ6ErxnWImR6tG
         c1UZ5Qdc6VlxFJYO4HRpsJ3lMUWyNQqjLK8HNh5nIF5nB/NZOZOfs5Pzz3T7rNJzIbBw
         qq+/yR8jOfpSikeWa2GC/yPt5urXIT8e2IMUFhDmzGvwaKB4JOipmxpfLo+MVpHoy6X+
         BBXl6hQQugb1IybBTwfaVCDDWYWuTbLx0UbNpAIwsB4/vxS+8ZzoFYm6PVDffxKbxcUk
         X53w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AwRhklPqsXKgj1xCDhjBcdwXMZdd0Z2pameV3iZCY3E=;
        b=h2Q5stni5qCDpWmepoAMFMi/r3bJ+3eHgZ4d4r7vFUSpRXXwxOi9/J8QdnBjsBiH3j
         wVht7+g/HSTqJR93j7epeUlAA9vgAUSfAxElVvlV0fdpNSjSeRyriSOCw3nyuEUiqhxy
         E32VbkjIJeF3FrJeZFpGXRR6DH2u1Z+NlEtwq2aZDK/VEjFHilu0F2YCgp/MQhL27/0E
         1Z9i+2/xuR2+48dL0/P1AWGwzYVIEsy9a3bU2suOmr3LadkaTJh3C1aC4ijTipP8ci+1
         ZyHv7CAQxJ4gLqhQm8CUxwnWmn51mBCHxdpIUyN0ypkWOnCwIfVRXvbykOGLMMQrf71A
         UX9w==
X-Gm-Message-State: AJIora8qcYddGHFr2/mj48nqMJgnGH/OYxXmjymWr/IyIVxVrGFKG2Qr
	gntbN01QU6Lk15VuESLYWpE=
X-Google-Smtp-Source: AGRyM1v20SSfvz7vAILN39fo8V+grqe+9nQIslqZR7gG2H4u2r9wUc0NUx+hwN2gnt4l1yW9ShqK2g==
X-Received: by 2002:a05:6808:200f:b0:33a:4a58:d55b with SMTP id q15-20020a056808200f00b0033a4a58d55bmr2205545oiw.92.1657888830040;
        Fri, 15 Jul 2022 05:40:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6a86:b0:104:a34c:437a with SMTP id
 mv6-20020a0568706a8600b00104a34c437als249238oab.7.-pod-prod-gmail; Fri, 15
 Jul 2022 05:40:29 -0700 (PDT)
X-Received: by 2002:a05:6870:4799:b0:f1:46f8:6ea4 with SMTP id c25-20020a056870479900b000f146f86ea4mr7345931oaq.223.1657888829438;
        Fri, 15 Jul 2022 05:40:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657888829; cv=none;
        d=google.com; s=arc-20160816;
        b=EdOE+eZDVeelkpvLYSLn/CjZUM+r2Sw6VIZvS2fikimN6v444Plx3CiYt+TxXx+T4Q
         mQ1LsmHxxRM89npofYzkFTaHkTDYJN4VyWeR7DhJdQmND8OJUsO8siXwYMuUKxzAoZ8X
         PmERoSDuClGQI/mmVUJ9J+8yN4T1dFLTbbCuvoXg6oxND3Ys6lDkY6TJWhB7qrT6dhCh
         lLwdXcfaMzcaN8M2tuFPt6/40TbHVf6qmZpv5JALlL21SLRU8YGD6KPcLoDoQ3uwH2Z5
         lHooQeS/abQaAvbnPkYAOQqovJQgE0P2YXBnfFpFB55+5yQX2VVQzu4bNnGglOnf5xW/
         1zPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rFg14LcgZeTXkwnfeYDRgexezyvnv3PPOW7dv1pA4P8=;
        b=Z5qWGDpNMviNNttHSU+kpSSu86gOjw6fJu92MWxzx11PXgRL6ZzbQ114I8LwvHzJ67
         gfqAlM6Jn45dqtFQm50Wddrd56Cn6PedduQS+cfMKZpoTBTRdplX1hrmIaECfTnX4Iym
         mb3UI07GFkuKDl3WU35e4PD/IAUCe2PV5Q/loKYTLHBqpC5bZMH2u9Q5/HSWIqbo4N1n
         BJrLtQgmobdLWOP8SUxex8NUewe+MrYj+7xB0oZGuBfN9gZyUSOQJzbHdCGTnj3K164k
         LZ7oDcOsQ3XvcPQmYEdcMJPOQng9L78ankThjujKnDaTUBMijT57qdll0KLUfcJZpeTW
         EPZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MgzKUYmw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id k22-20020a056870959600b000e217d47668si607003oao.5.2022.07.15.05.40.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 05:40:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 6so8226682ybc.8
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 05:40:29 -0700 (PDT)
X-Received: by 2002:a5b:885:0:b0:66f:a7f5:23a4 with SMTP id
 e5-20020a5b0885000000b0066fa7f523a4mr13203832ybq.87.1657888828869; Fri, 15
 Jul 2022 05:40:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220715120152.17760-1-pmladek@suse.com>
In-Reply-To: <20220715120152.17760-1-pmladek@suse.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jul 2022 14:39:52 +0200
Message-ID: <CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
To: Petr Mladek <pmladek@suse.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, "Paul E . McKenney" <paulmck@kernel.org>, 
	John Ogness <john.ogness@linutronix.de>, Sergey Senozhatsky <senozhatsky@chromium.org>, 
	kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, 
	Johannes Berg <johannes.berg@intel.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Peter Zijlstra <peterz@infradead.org>, Linux Kernel Functional Testing <lkft@linaro.org>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MgzKUYmw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Fri, 15 Jul 2022 at 14:02, Petr Mladek <pmladek@suse.com> wrote:
>
> The commit 701850dc0c31bfadf75a0 ("printk, tracing: fix console
> tracepoint") moved the tracepoint from console_unlock() to
> vprintk_store(). As a result, it might be called in any
> context and triggered the following warning:
>
>   WARNING: CPU: 1 PID: 16462 at include/trace/events/printk.h:10 printk_sprint+0x81/0xda
>   Modules linked in: ppdev parport_pc parport
>   CPU: 1 PID: 16462 Comm: event_benchmark Not tainted 5.19.0-rc5-test+ #5
>   Hardware name: MSI MS-7823/CSM-H87M-G43 (MS-7823), BIOS V1.6 02/22/2014
>   EIP: printk_sprint+0x81/0xda
>   Code: 89 d8 e8 88 fc 33 00 e9 02 00 00 00 eb 6b 64 a1 a4 b8 91 c1 e8 fd d6 ff ff 84 c0 74 5c 64 a1 14 08 92 c1 a9 00 00 f0 00 74 02 <0f> 0b 64 ff 05 14 08 92 c1 b8 e0 c4 6b c1 e8 a5 dc 00 00 89 c7 e8
>   EAX: 80110001 EBX: c20a52f8 ECX: 0000000c EDX: 6d203036
>   ESI: 3df6004c EDI: 00000000 EBP: c61fbd7c ESP: c61fbd70
>   DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010006
>   CR0: 80050033 CR2: b7efc000 CR3: 05b80000 CR4: 001506f0
>   Call Trace:
>    vprintk_store+0x24b/0x2ff
>    vprintk+0x37/0x4d
>    _printk+0x14/0x16
>    nmi_handle+0x1ef/0x24e
>    ? find_next_bit.part.0+0x13/0x13
>    ? find_next_bit.part.0+0x13/0x13
>    ? function_trace_call+0xd8/0xd9
>    default_do_nmi+0x57/0x1af
>    ? trace_hardirqs_off_finish+0x2a/0xd9
>    ? to_kthread+0xf/0xf
>    exc_nmi+0x9b/0xf4
>    asm_exc_nmi+0xae/0x29c
>
> It comes from:
>
>   #define __DO_TRACE(name, args, cond, rcuidle) \
>   [...]
>                 /* srcu can't be used from NMI */       \
>                 WARN_ON_ONCE(rcuidle && in_nmi());      \
>
> It might be possible to make srcu working in NMI. But it
> would be slower on some architectures. It is not worth
> doing it just because of this tracepoint.
>
> It would be possible to disable this tracepoint in NMI
> or in rcuidle context. Where the rcuidle context looks
> more rare and thus more acceptable to be ignored.
>
> Alternative solution would be to move the tracepoint
> back to console code. But the location is less reliable
> by definition. Also the synchronization against other
> tracing messages is much worse.
>
> Let's ignore the tracepoint in rcuidle context as the least
> evil solution.
>
> Link: https://lore.kernel.org/r/20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1
>
> Suggested-by: Steven Rostedt <rostedt@goodmis.org>
> Signed-off-by: Petr Mladek <pmladek@suse.com>
> ---
>  include/trace/events/printk.h | 11 ++++++++++-
>  kernel/printk/printk.c        |  2 +-
>  2 files changed, 11 insertions(+), 2 deletions(-)
>
> diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
> index 13d405b2fd8b..a3ee720f41b5 100644
> --- a/include/trace/events/printk.h
> +++ b/include/trace/events/printk.h
> @@ -7,11 +7,20 @@
>
>  #include <linux/tracepoint.h>
>
> -TRACE_EVENT(console,
> +TRACE_EVENT_CONDITION(console,
>         TP_PROTO(const char *text, size_t len),
>
>         TP_ARGS(text, len),
>
> +       /*
> +        * trace_console_rcuidle() is not working in NMI. printk()
> +        * is used more often in NMI than in rcuidle context.
> +        * Choose the less evil solution here.
> +        *
> +        * raw_smp_processor_id() is reliable in rcuidle context.
> +        */
> +       TP_CONDITION(!rcu_is_idle_cpu(raw_smp_processor_id())),
> +

Couldn't this just use rcu_is_watching()?

  | * rcu_is_watching - see if RCU thinks that the current CPU is not idle

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHY1GC_Fab4T6J06vqW0vRf%3D4jQR0dG0MJoFOPpKzcUA%40mail.gmail.com.
