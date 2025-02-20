Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRFR3W6QMGQEYISYVKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FFE7A3E0C8
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 17:31:02 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3cfb20d74b5sf9681055ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 08:31:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740069061; cv=pass;
        d=google.com; s=arc-20240605;
        b=HQKXFGdxhw6H7AFIETgBd+xOEmML7i/lj2TZrztcSKZusHn7pUeJVs2zjO49eeM9SH
         qUK3h8lzoDz54KMwheIwsOFNdOJBqj1QVzwoLXtttUNeaw9Ye0CJ1nChvXxAhDu1asYA
         oRLDZCOajIA3t/dag6OEgKUiKBx0CK6G19TeUThRNKdNQULVGYWeq9Wr0wNlyvp5uE8S
         PLFr4ICtltfCxOgDKZO7Ne5X3iuLHW9w3uo4E1KmFmUdW51zmhqxUPiupWJvQUISGZ+8
         8+5cNcWiF8P08NfyjfhYFs3rxtpTCpve5EzqMB6R+vIn5eS36EldB5vqdcv8UCl32gOp
         QBpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pmZPaNnnhZDSrxYVEB3Y33YiJ5TVW3kzO0kQLmuG/V0=;
        fh=2OkdGcalqvqzWxjt/a2PbBR3YQ7mxJcdImXW/HloaXk=;
        b=SmCRs/rnLXuLXHHTmYbC0PILE60oZpmvdW5OaudYjgwM30E/Dw2qf7/wyuxNVchpJT
         EVSXAZ2Js9c6N2cG6cBtJ0ocx0orBriH1zGxkgxVCGimP2K5whFebTKt38HFl0BaX9TW
         lNtJhaJVxkQWA8vYfL/yubwYdCvqsqqEYwaL/yEfKQLpy1txO31M5X3ea7iavgAj8RaL
         /MSd8wWsxbHSc4tHvqK2aJ8MkmSbZutZ0hu8hJfCMGw7EPU/upI3OpFlbbmSBXebHPb5
         Cgj1+sdKpm7rCjMM1aXzidif9S45tergJ8lELl8O2Keodui0wzjf/XJXjEusqF2rRDxL
         SivA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="F/4xmqsX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740069061; x=1740673861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pmZPaNnnhZDSrxYVEB3Y33YiJ5TVW3kzO0kQLmuG/V0=;
        b=oZa0w+kwwj2oospxyNlZG6G+0fZGsRSnjuq5Hyip3ttHH/sHphs9XO5zlqgufTZnqT
         3wwUiq1yktyPdeYIvboiL26ZmFFZY/h2P5vmbE0pjpvzF4xmbEWjd4eRcDWzCr0mZxcT
         BE+eGhI4oD8g/EFZSKEPpkM58sI45kGkZjQwrTOOmagsYIu1ITscizkFfqlR/MyQxlXV
         sjUvPR+2K358c3NyMO+wDK8r8nzEnk8gOedOW0KweU0Y7dzrhOr66kLPo/55zGwWV4wq
         Ux0hqLT9MCu3cG101UoMWWBhcci3H/KQaSksxNftxP8t2BnvhezlPaS2lEN1VxXBAQzC
         RIKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740069061; x=1740673861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pmZPaNnnhZDSrxYVEB3Y33YiJ5TVW3kzO0kQLmuG/V0=;
        b=UcFGvuugCBS8HIHUv2xaacEKWUUEIN1no2nt07V7V4sglKvmaFH0/TQDmG5ZNeh+aT
         748Jn5fHyXKOMZGut4WcnwUK98UiK1O1/4HjdJj2ODvXe8fAeWVvLZUamvHR2izihw7/
         mLg8zigRPZKPzCKaIUVV3VuiVQtPFBL5H0AwdSdpgC2TWxcmvl5Eg5swXWo2gBgwazvG
         Q/XYmoDl3ND/XsqvinnhGD6c3wsyL5aTmIZFtaf1/FFkkSFlRLrO0YEBd/IerRAzImmO
         bZnq8XiirVEpHYP7AXDmOeTM3Eiimgn0BgZyin+3qqLYSwnyOAaqGnARQjAGIqUgdN9J
         OdNw==
X-Forwarded-Encrypted: i=2; AJvYcCU4eRfPmTuFXJDO+/saGFOIjenYwMQ3BZHU03HH08O4NEuRSd1tZlbYfYiV7EvHS862xCfsPw==@lfdr.de
X-Gm-Message-State: AOJu0YwXD4/GG2T+HcXmVjMM2ERmdAQEjiHrBWHx2MFYcCR5zFWNTZYC
	wLWm7AHzHLA9erFUrlxlW+wWT3ewySnjFiwtZsQuri7uYkVLMNCp
X-Google-Smtp-Source: AGHT+IFC2jFSyOlGrR+hh9yCRn3RoXLya1FGkQj5hITsTEUZ24lwzjFTfDqAXYJd7vfuYcD7iQTDqQ==
X-Received: by 2002:a05:6e02:3190:b0:3d1:78f1:8a86 with SMTP id e9e14a558f8ab-3d2b536efe8mr83535675ab.15.1740069060650;
        Thu, 20 Feb 2025 08:31:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGzhxEFnQQxiju1uoHsjffJ5ppIOCO8pskrNxcenH+ybw==
Received: by 2002:a92:ca4b:0:b0:3d0:f28a:b0da with SMTP id e9e14a558f8ab-3d2bfbb65d0ls6155615ab.0.-pod-prod-09-us;
 Thu, 20 Feb 2025 08:30:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVsfolWK3eGGj1C3IlTXoHzsud7qz32ZwW24cDykwAYwP3QUMg664R1KxpxGh9h58bi+LaDig+iIO0=@googlegroups.com
X-Received: by 2002:a05:6602:15c7:b0:855:1a4b:8f43 with SMTP id ca18e2360f4ac-855b399b16dmr971584039f.8.1740069059771;
        Thu, 20 Feb 2025 08:30:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740069059; cv=none;
        d=google.com; s=arc-20240605;
        b=b/7XDhYegpXH8O7rFYqDDrcvjqaLxgpcyxpiDkoIWbdNowXd39dBT7qNbaSgL3JenF
         w6GIGVB3IPz4+eALVzvzHkeyRo3h94MGf4ta4p8/2vNxQKRW64xst5Za0ulw2oekPSPC
         eeWFDWh3aAfUDOfjdomGqIuYzrUHeEYds871gWT3/oWVk95e4VPGvxO3pz1aNd5SpvA+
         2OfEetxfX8BP/gqLQ8JjzHKjU1zMTUsWa0LobkGbjQLzP1Jvr0R6aQgjHZ9hUvho5Oc0
         GEa+tYs3rkxGSrf9glD0zgWpEsCEt+vpspOCx16XrltYuqMxa+ovWe+n/7Wh1IRlbVCK
         Sijw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RunbDwqsCKiDMq6NQxy4XFRnim+xmAlewv0MU2PV7ik=;
        fh=+X32dSnDt7s4k7wh4MGGP9JG+erB3MPjel6pmCaiqSk=;
        b=LzMj5HuegozHD5eChStUpi/3PYGYfAyUhU0lI301Q3xRuDcMuuW/yofgBsNS1cRx2R
         ICxZaplojH6umswTnSaRcL7zXfCaSFTEtu9L7SI6PoUnc69wFZM/hRle853Tfx5eAH+w
         CGQVvujKjz3jG/mw1YZmQlSNZlXUrB+lDVJQrxGK/6+tiFH6Eg0PptTXPjUtZroaaV69
         Fn/aRSTVAWOvgdfGkDdz/f9YptRXy+fbJorwSOVO+L12igugLTP58C9zXSNrIXMAvKpm
         7uaNUeVwYZlc/V6kDcybQ8YR8zxLRgQXDijDLFI5SEldv+77OL/MhSFPRUw4ir+/rUK1
         23MQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="F/4xmqsX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-855afd2a82fsi21694539f.2.2025.02.20.08.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2025 08:30:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2fc042c9290so1957451a91.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2025 08:30:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUuH84Xm9VZaI+qS27JDTrWh9PU2mZN2ZzbWdIFI8iuQgtINsZ4nK7ltAQeZSl45iJkOSnm8DcsbC8=@googlegroups.com
X-Gm-Gg: ASbGncumaQDyhPDEV7ylmjj+TcVkBeiZpZkIIqB5e+dZaCP7MrunhtWHNlPQ8/Z4Y9E
	O79p3kqALFJDRbeDhEXr8Kt7R7uVDcf5Z7trg0i87uQRxl+3BxyXpqXWF41NVknDvr4gWIDGj10
	RCVkq1br1Ct3x91D7n6M7wtlrJeuE=
X-Received: by 2002:a17:90b:278b:b0:2fa:1a8a:cff8 with SMTP id
 98e67ed59e1d1-2fcb5aba7admr13293676a91.29.1740069058693; Thu, 20 Feb 2025
 08:30:58 -0800 (PST)
MIME-Version: 1.0
References: <Z7bUC9QY815Cv6nb@xsang-OptiPlex-9020> <20250220155722.2Z2a-3z0@linutronix.de>
In-Reply-To: <20250220155722.2Z2a-3z0@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Feb 2025 17:30:22 +0100
X-Gm-Features: AWEUYZl9XyuxFIVLWSjhfqqO0OUA4wn0EYnMOUYAgeDjJV6JjoSIe-IH-I10jY8
Message-ID: <CANpmjNN9zpcPa4S+Zq+vJWJ3EcO0zCZJ=Z4FgNzDRXdi0YQA9g@mail.gmail.com>
Subject: Re: [linux-next:master] [x86] 66fbf67705: kernel-selftests.kvm.hardware_disable_test.fail
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Oliver Sang <oliver.sang@intel.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	Petr Pavlu <petr.pavlu@suse.com>, "H. Peter Anvin" <hpa@zytor.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Kees Cook <kees@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Waiman Long <longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="F/4xmqsX";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
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

On Thu, 20 Feb 2025 at 16:57, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
[...]
> Now. Based on this:
> The RCU read section increased the runtime (on my hardware) for the test
> from 30 to 43 seconds which is roughly 43%.
> This is due to the lockdep annotation within rcu_read_lock() and
> unlock() which is not existing in preempt_disable(). After disabling
> UBSAN + KASAN  the lockdep annotation has no effect. My guess that
> UBSAN/ KASAN is in charge of countless backtraces while enabled. Those
> backtraces seem to be limited to the core kernel.
>
> How much do we care here? Is this something that makes UBSAN + KASAN
> folks uncomfortable? Or is lockdep slowing things down anyway?

Does this series from Waiman help?
https://lore.kernel.org/all/20250213200228.1993588-4-longman@redhat.com/

> If so, we could either move the RCU section down (as in #5) so it is not
> used that often or go the other direction and move it up. I got this:
> | ~# time ./hardware_disable_test
> | Random seed: 0x6b8b4567
> |
> | real    0m32.618s
> | user    0m0.537s
> | sys     0m13.942s
>
> which is almost the pre-level with the hunk below after figuring out
> that most callers are from arch_stack_walk().
>
> diff --git a/arch/x86/include/asm/unwind.h b/arch/x86/include/asm/unwind.h
> index 7cede4dc21f0..f20e3613942f 100644
> --- a/arch/x86/include/asm/unwind.h
> +++ b/arch/x86/include/asm/unwind.h
> @@ -42,6 +42,7 @@ struct unwind_state {
>  void __unwind_start(struct unwind_state *state, struct task_struct *task,
>                     struct pt_regs *regs, unsigned long *first_frame);
>  bool unwind_next_frame(struct unwind_state *state);
> +bool unwind_next_frame_unlocked(struct unwind_state *state);
>  unsigned long unwind_get_return_address(struct unwind_state *state);
>  unsigned long *unwind_get_return_address_ptr(struct unwind_state *state);
>
> diff --git a/arch/x86/kernel/stacktrace.c b/arch/x86/kernel/stacktrace.c
> index ee117fcf46ed..4df346b11f1e 100644
> --- a/arch/x86/kernel/stacktrace.c
> +++ b/arch/x86/kernel/stacktrace.c
> @@ -21,8 +21,9 @@ void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
>         if (regs && !consume_entry(cookie, regs->ip))
>                 return;
>
> +       guard(rcu)();
>         for (unwind_start(&state, task, regs, NULL); !unwind_done(&state);
> -            unwind_next_frame(&state)) {
> +            unwind_next_frame_unlocked(&state)) {
>                 addr = unwind_get_return_address(&state);
>                 if (!addr || !consume_entry(cookie, addr))
>                         break;
> diff --git a/arch/x86/kernel/unwind_orc.c b/arch/x86/kernel/unwind_orc.c
> index 977ee75e047c..402779b3e90a 100644
> --- a/arch/x86/kernel/unwind_orc.c
> +++ b/arch/x86/kernel/unwind_orc.c
> @@ -465,7 +465,7 @@ static bool get_reg(struct unwind_state *state, unsigned int reg_off,
>         return false;
>  }
>
> -bool unwind_next_frame(struct unwind_state *state)
> +bool unwind_next_frame_unlocked(struct unwind_state *state)
>  {
>         unsigned long ip_p, sp, tmp, orig_ip = state->ip, prev_sp = state->sp;
>         enum stack_type prev_type = state->stack_info.type;
> @@ -475,9 +475,6 @@ bool unwind_next_frame(struct unwind_state *state)
>         if (unwind_done(state))
>                 return false;
>
> -       /* Don't let modules unload while we're reading their ORC data. */
> -       guard(rcu)();
> -
>         /* End-of-stack check for user tasks: */
>         if (state->regs && user_mode(state->regs))
>                 goto the_end;
> @@ -678,6 +675,13 @@ bool unwind_next_frame(struct unwind_state *state)
>         state->stack_info.type = STACK_TYPE_UNKNOWN;
>         return false;
>  }
> +
> +bool unwind_next_frame(struct unwind_state *state)
> +{
> +       /* Don't let modules unload while we're reading their ORC data. */
> +       guard(rcu)();
> +       return unwind_next_frame_unlocked(state);
> +}
>  EXPORT_SYMBOL_GPL(unwind_next_frame);
>
>  void __unwind_start(struct unwind_state *state, struct task_struct *task,
>
> Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN9zpcPa4S%2BZq%2BvJWJ3EcO0zCZJ%3DZ4FgNzDRXdi0YQA9g%40mail.gmail.com.
