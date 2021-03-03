Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEN772AQMGQEUPWJRVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F00732B8AA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 15:39:14 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id o9sf26782469yba.18
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 06:39:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614782353; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2nRShYAgGU9ITv0JxBbG2uQfpLZ330ULpsdCo23R1afDVy9fXglUCFf2a5S+f0UAk
         HGHluNC1Ab0fyJP4RpIojuFMquFzCcxSBIy/6bVedKSbZYoPTgBYAanHTHyRrR6LqrXw
         Dtpqcb62S6yKQXZnr0AGewm6wNlTEk6rRxUfws8DKLLyz4MDkoA0DHmF6Aqv/zZHnqTM
         zIkjB4maItY2YxOi/j5ChIt1GvaCUiJnBlycoG0jTfKo0n/2TjWGmehRYmo3UtusuEam
         QfRmUoOHxpL3OskQqGd5mwngZ61VkOiAvLgSUJAEnwvhJqF1NQGzk/KIly74eI+9EgBQ
         kqsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pxKqFfVihZuJK3Ktg67tujR1wZGuf/6ZLARojNAobaw=;
        b=ncXCZquWhYVg0HyltbeFMYXUCKPNvcc/WjG1ve46m5paWpVpS6VGuSgWuo67t9eIm5
         8TlwuKyiWAbdkkFsVs8hbzH+gsyRArhDJ7Y4aU/cWXvQ2CYGMTqWy7PkUDR1gNONGycc
         cq6AwXF+pzSbvPm+nN6/NVP/+HQl0EfkFfNRv9YIFiVN0tYDSDHaUQDkyIsiwZLvaAfi
         aWfBXHWvpr2/qGjRDOuJCZWk0ntXhqZorkiujy7xXp+AP0sfnauw9rKPOYjYBy3/pDqb
         TtS/hotvGdPmEI5MGRpjwtuLr/kv9bGi4yRE8W9JUmYsMN1wgJpZv8hLiF6dRM4n8K2k
         rHXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BipVVFvF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pxKqFfVihZuJK3Ktg67tujR1wZGuf/6ZLARojNAobaw=;
        b=bpgJtqxbiWE75MOT12WnamzE4uzGGU6R4wiT9XTOoRbMFHnee94gG+295QCe9BTq0B
         Qlx4ZI/hN3+KJItygbnHvHtDhhUsgc0n9DvaElr2/YZOwdoM0YRzeBJ/MgboSNW9mT7W
         52D9aCUPFdawGU+T9XRnrgTr903NBTdIC8WZQ/hDfDlHRk7SP5KbIbXoi4SrJY4LLA6Z
         mGSKHQovhjCuj6JQJLP+3aIS9o5efScT6Nder3Xu2P0GCZLRLUjil/8NmklLAgobQ70o
         9KHUdUrbR/qL4UObjSwkA4YHP0tBnQLlNogWoDFlG7d25gsf2iCS5fsJAWx/stkkqttj
         iWLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pxKqFfVihZuJK3Ktg67tujR1wZGuf/6ZLARojNAobaw=;
        b=DKO4M3/IMaRZs+0Cke8LeKBDhCMkq8iigbSUpQtix964SS0SwJewams33s+/RRaJXG
         MVipyh0qN0ROKMIMOI2AyB4SIpOkeadwSeoSq9Oogty84wt2Ii/2oqoTJc42eBxN+sfo
         +yUCRzk2B9DsBNEbaWkFMln1PN9qxcWx/ZrQUrDAemwgP5xHTBSo5Ll3aysZfkh5REDt
         Vl4VkuNQXVPsFTchOa8JI40WYAZwsI+cIoFrOAfBOJURgNvI1Tr/Lvek126faTQXmJYa
         jyuzpxddovxe2EbaAiHGkwdGJss3dmF4b7xjt4bEsZNTPHt5ZOH73I5AcZIYXhYWtBz8
         UrzQ==
X-Gm-Message-State: AOAM531Vg3pWNTVFgP2Kj+/wboCpr8Ju3ZfkpdXZV4MYt1sPnwsPWg2P
	z4RHl0O+rxA6iDGf3A2J1do=
X-Google-Smtp-Source: ABdhPJykaRDjlFjcNEzgdHJy4nwIj9x23q7ANUmhyTOAKSbARO2nxsgCzK35w+qNMo21n+wf6r0F9Q==
X-Received: by 2002:a25:ab54:: with SMTP id u78mr39655894ybi.276.1614782353303;
        Wed, 03 Mar 2021 06:39:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc49:: with SMTP id y70ls1205076ybe.4.gmail; Wed, 03 Mar
 2021 06:39:12 -0800 (PST)
X-Received: by 2002:a25:2603:: with SMTP id m3mr39440724ybm.434.1614782352783;
        Wed, 03 Mar 2021 06:39:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614782352; cv=none;
        d=google.com; s=arc-20160816;
        b=zS6GTBaBVLouyyHgmNleivbx2sr8/Y+r4n1jlvSIoXrtXBQuZr+qeFzJrq52maLlS9
         MdhYKjHoCVy63CxWZXBDqLEu7M1W1Et9le+bw6eg+5eShoXsVOc0RaoeWf6w4lgaX+cb
         4Ub31rF0Yv2KsaxhdE3d0OWtQ6QuADoAAb+KDqUahFpk6mRFAG/+nsWZHgC84rBLVBU/
         ED/M6ZwUgJ7ldpfoCaZN2zv7RgK7NvxX8tufZZrrlA/3/wUqA4ioIF8amqlhSfTQpjjD
         h5oe/QUqKdp14gIBryZov9wLhsrTkTJWj0auiQHtysH5VcsK7Ww5KOB2GxuUzgbeAhhC
         09kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ydBX+pGjF/hly9LCkDMks/XbfuRt2icO3LWw0ubnZBg=;
        b=WIZjNpNzniPM4ptjZFNftLtVpZeRyK/XLBKaAHxdfMbc0yUC4A3dpvWVAbSKTEo2hm
         Lp+rCQARU5wBUQKegIIhdvPf6r5DVL/gqgAx3CTpvQ8mJB4J2O6sR7sGhfTDTKgW+C0p
         CmMgpf74hLUBS0D4+FwyGow+XjNAeQ5ws7YrEKQ14LSIKo7Z1TunK2JpZFpYl/1LZeGx
         +0UNbh3QbnGMxWgAiNYaGl2YI1KtEV76S4o0foEn4xziG38fNdaqDXUpjhjjGgrhXkjC
         AQrzZ4FyiaJvprcy1ayfdEzao5JXV9D4QmNaifLRB4eBWAd0qjDks0+vMbvym72wQftY
         en6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BipVVFvF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id x7si1772339ybm.0.2021.03.03.06.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 06:39:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id r19so23763561otk.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 06:39:12 -0800 (PST)
X-Received: by 2002:a9d:644a:: with SMTP id m10mr23005815otl.233.1614782352144;
 Wed, 03 Mar 2021 06:39:12 -0800 (PST)
MIME-Version: 1.0
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
In-Reply-To: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Mar 2021 15:38:59 +0100
Message-ID: <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BipVVFvF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Wed, 3 Mar 2021 at 15:09, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> It seems like all other sane architectures, namely x86 and arm64
> at least, include the running function as top entry when saving
> stack trace.
>
> Functionnalities like KFENCE expect it.
>
> Do the same on powerpc, it allows KFENCE to properly identify the faulting
> function as depicted below. Before the patch KFENCE was identifying
> finish_task_switch.isra as the faulting function.
>
> [   14.937370] ==================================================================
> [   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0x54/0x108
> [   14.948692]
> [   14.956814] Invalid read at 0xdf98800a:
> [   14.960664]  test_invalid_access+0x54/0x108
> [   14.964876]  finish_task_switch.isra.0+0x54/0x23c
> [   14.969606]  kunit_try_run_case+0x5c/0xd0
> [   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
> [   14.979079]  kthread+0x15c/0x174
> [   14.982342]  ret_from_kernel_thread+0x14/0x1c
> [   14.986731]
> [   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B             5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
> [   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
> [   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B              (5.12.0-rc1-01537-g95f6e2088d7e-dirty)
> [   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000000
> [   15.022043] DAR: df98800a DSISR: 20000000
> [   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13c 00000008 c084b32b c016ebd8
> [   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> [   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
> [   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
> [   15.051181] Call Trace:
> [   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x54/0x23c (unreliable)
> [   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
> [   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_adapter+0x24/0x30
> [   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
> [   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
> [   15.085798] Instruction dump:
> [   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f0024 907f0028 90ff001c
> [   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 812a4b98 3d40c02f
> [   15.104612] ==================================================================
>
> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Acked-by: Marco Elver <elver@google.com>

Thank you, I think this looks like the right solution. Just a question below:

> ---
>  arch/powerpc/kernel/stacktrace.c | 42 +++++++++++++++++++++-----------
>  1 file changed, 28 insertions(+), 14 deletions(-)
>
> diff --git a/arch/powerpc/kernel/stacktrace.c b/arch/powerpc/kernel/stacktrace.c
> index b6440657ef92..67c2b8488035 100644
> --- a/arch/powerpc/kernel/stacktrace.c
> +++ b/arch/powerpc/kernel/stacktrace.c
> @@ -22,16 +22,32 @@
>  #include <asm/kprobes.h>
>
>  #include <asm/paca.h>
> +#include <asm/switch_to.h>
>
>  /*
>   * Save stack-backtrace addresses into a stack_trace buffer.
>   */
> +static void save_entry(struct stack_trace *trace, unsigned long ip, int savesched)
> +{
> +       if (savesched || !in_sched_functions(ip)) {
> +               if (!trace->skip)
> +                       trace->entries[trace->nr_entries++] = ip;
> +               else
> +                       trace->skip--;
> +       }
> +}
> +
>  static void save_context_stack(struct stack_trace *trace, unsigned long sp,
> -                       struct task_struct *tsk, int savesched)
> +                              unsigned long ip, struct task_struct *tsk, int savesched)
>  {
> +       save_entry(trace, ip, savesched);
> +
> +       if (trace->nr_entries >= trace->max_entries)
> +               return;
> +
>         for (;;) {
>                 unsigned long *stack = (unsigned long *) sp;
> -               unsigned long newsp, ip;
> +               unsigned long newsp;
>
>                 if (!validate_sp(sp, tsk, STACK_FRAME_OVERHEAD))
>                         return;
> @@ -39,12 +55,7 @@ static void save_context_stack(struct stack_trace *trace, unsigned long sp,
>                 newsp = stack[0];
>                 ip = stack[STACK_FRAME_LR_SAVE];
>
> -               if (savesched || !in_sched_functions(ip)) {
> -                       if (!trace->skip)
> -                               trace->entries[trace->nr_entries++] = ip;
> -                       else
> -                               trace->skip--;
> -               }
> +               save_entry(trace, ip, savesched);
>
>                 if (trace->nr_entries >= trace->max_entries)
>                         return;
> @@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *trace)
>
>         sp = current_stack_frame();
>
> -       save_context_stack(trace, sp, current, 1);
> +       save_context_stack(trace, sp, (unsigned long)save_stack_trace, current, 1);

This causes ip == save_stack_trace and also below for
save_stack_trace_tsk. Does this mean save_stack_trace() is included in
the trace? Looking at kernel/stacktrace.c, I think the library wants
to exclude itself from the trace, as it does '.skip = skipnr + 1' (and
'.skip   = skipnr + (current == tsk)' for the _tsk variant).

If the arch-helper here is included, should this use _RET_IP_ instead?

Thanks,
-- Marco

>  }
>  EXPORT_SYMBOL_GPL(save_stack_trace);
>
>  void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
>  {
> -       unsigned long sp;
> +       unsigned long sp, ip;
>
>         if (!try_get_task_stack(tsk))
>                 return;
>
> -       if (tsk == current)
> +       if (tsk == current) {
> +               ip = (unsigned long)save_stack_trace_tsk;
>                 sp = current_stack_frame();
> -       else
> +       } else {
> +               ip = (unsigned long)_switch;
>                 sp = tsk->thread.ksp;
> +       }
>
> -       save_context_stack(trace, sp, tsk, 0);
> +       save_context_stack(trace, sp, ip, tsk, 0);
>
>         put_task_stack(tsk);
>  }
> @@ -84,7 +98,7 @@ EXPORT_SYMBOL_GPL(save_stack_trace_tsk);
>  void
>  save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
>  {
> -       save_context_stack(trace, regs->gpr[1], current, 0);
> +       save_context_stack(trace, regs->gpr[1], regs->nip, current, 0);
>  }
>  EXPORT_SYMBOL_GPL(save_stack_trace_regs);
>
> --
> 2.25.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw%40mail.gmail.com.
