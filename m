Return-Path: <kasan-dev+bncBDEPT3NHSUCBBTXX43XAKGQEYGKFQKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D32D1080F9
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Nov 2019 00:08:00 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id g142sf5110919vkg.7
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2019 15:08:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574550479; cv=pass;
        d=google.com; s=arc-20160816;
        b=pgAYBjftDmn7utkx20dJAuC/wUlWWtDPxmlgWAENcv6yY3do42DDny6nqt7Q1b45sd
         GZf6D2RirvNYNd4ftEzDPuFN7wiBOSQxfbuFQqtt4f5BnTfNnEWCe/0Hh5d22JI1E2FD
         coAisnMYA6o/WJZ2hvimUn3aFS6egNNX+kZrKla+7fs835Ep3Esx+OCYUbcf6tYHaq50
         C7n4Fr8OROO0zdko9qylwqeWyVCRPrnlNHmuKNqTtbKP9jwsSCWoHFrACq3vo+rZ5qka
         tBCBU8wgByr4OEfX4Oya7U+eHEPYnWeDoNeOBS5Qfk+Pj73b3od6Z6wzjJiiXgJw1s5P
         7l5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=r3pQv+dCdj3+qjfMJ4HaL+orJPVsVhE8tphjSBU2vfE=;
        b=THxpr2OdGiX7tFHF8zu5ahXp1BXPvqT4AhtuiYyDqnUxsVyB3bhhMgLftYx/DJ3aRv
         2OB8RyRf+JTm040ptcMmG52YxqGrgaQkyzDtP8LvbbXl82R0nSzYMJmCM6b3z4eFnB5J
         MB6pVJHFqGySv4rI8F6TmcavOAbbiDt42krD4laZXexVj2xZHrzKys+IKX9uXdx9rND9
         S7I9xQ9oEajv4MG1yB8yU1emy41SEa7uPN6Grfwxiz+Tp+rS0zRGfi0lRkMvEexr18Np
         xwk9fWLN314ZAmT2gv8rP+LcxHoBWHgC3wCu7KE5aUv7dbq2PF53PYVxUhMKYQdyKOlD
         3GzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=juPH+U2U;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3pQv+dCdj3+qjfMJ4HaL+orJPVsVhE8tphjSBU2vfE=;
        b=nNC6N8dJcS8SHM/xFlkP1BqFXvIn49QgV33/wmylWL6+1ywa4cVaMlYNUeRq6KF6TV
         KlRKrzYpM56vyHpjGJ0MdTf6dVyd/5vi4fRCwqU3XMbnbiefGAWocezF3t0JCZge/mus
         QxVidEXsJ3TofYMdm8Q4zh58ZpB2c8aezdw8OrfG+SC6YgjUwcgBiECDDJQwtr6ttY4h
         ZDzv/6GM/mA9a3B0c2duHG6arCJtAfbxUkPxolAijF+WggmaajBLLnpCh1ICH5G4u1Qv
         AYNSKvpHZdrvlWzRoDEy5MkblSWWL61MEG8+jDV1AVQAXyqdfqnuBpPuM/2hwDS2uWBH
         RXeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r3pQv+dCdj3+qjfMJ4HaL+orJPVsVhE8tphjSBU2vfE=;
        b=SCcoqopBthFrK5hsS1Ev2R6phzZdx2xLvsPu40boYHmbILLkw5c85h7TIrUocORmOh
         q+5+XoWYTaz2UXHIkIQ0Ek4rjLgHn4VeR5SKdenMLNToXzphb7WQJauaKq/5VRHe7UNq
         n8pLiNX7ZBXCk7/CxCLvfNOVqJaqpmEqhhveWylCnymTjxYawGtnaV9erRe2WLphhPmR
         OdAbRm6dYcYQiaxxgUuDXww+9nn4ru5Qc5kavBV8dXNvNPp8f6db9PjbiAEIOoc6tfFs
         0ZKecqo2t5/aXnTMAGAQau1E8iZWHWU3XsGqxcQGLBC+WAND7VQdTIbGSAHv9yh2LfSL
         sPZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVMGfVGOZJXF9MNTDb71oz/+dN8agvrhZBgFbVzGOLHf+ER6kEs
	B0/irtqjvF8ecugT2lMXeW4=
X-Google-Smtp-Source: APXvYqzvArWCKVieLXjyXTkTut9DfuVFwzoWM5AUKS/eWboeEcxOq9UzTB/2r2LYK+xBC3nfxu7lGA==
X-Received: by 2002:a1f:1e52:: with SMTP id e79mr14303547vke.64.1574550478953;
        Sat, 23 Nov 2019 15:07:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e8ca:: with SMTP id y10ls1707119vsn.7.gmail; Sat, 23 Nov
 2019 15:07:58 -0800 (PST)
X-Received: by 2002:a05:6102:386:: with SMTP id m6mr14894588vsq.147.1574550478594;
        Sat, 23 Nov 2019 15:07:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574550478; cv=none;
        d=google.com; s=arc-20160816;
        b=lvYvKW2ZtCi2rxGt0DCTploXo0/FoSFALGzFgVouv+Ugl5sBMx96vZLkdA27h1Ib/o
         J99E9zDj9VuDItG3v19Rb6AGr9xtYI2hopUmn0E+T6dNppI4rXGMWZohQ8TiRQ/crlCw
         MaLdoLYKBDA8SNjpkpR8CKWzlSzv0FqcX/9dIkT34+h1jvNHri0R2EqdDShoehh8JhSU
         JletQpiBdd/x9CENmMRZr5PcPCzw8IkaXCI4BoIy1x3MVKJHtdiWGJau4a6SW1taaW60
         M7iJmBD8Ld/MP8J69Ycb4V3yFSNSsO518X7Fo/NJzZRT7pv8eGYgC6euRLLuIOvVZfzR
         RA0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pu/8OX6HlfSaoPCzgUtGzljI+oHPoVje9Ch4WmQwZdE=;
        b=dJbSN2rniSJ4IdLGVvKqC0kfHZb4bO6cxO4oR1+kyg8SrmyHvFBVLQVJXiW4vKWxOM
         Fc1oKT7ZfSc2wzF21TGFpgvGMW3KA3574umHO2rYwMdcyO/U/84x2QVuwJdcWpKLlYBr
         J3Tt1REIPvjk2Q+eDQEuGneV9oXPRwK4lzH0XDIw1DWdf5v3KOSi6Io0FvuetO4EfA0r
         5WWqRLsef2uKQ7+cCWlPFpjo9q9h0LWr6NJn4xO9Zl77/+4kW03w+59Z8s8LaPVumQCU
         8IPZfoFFL3T/WD86PY1mskO1TLnVJZO2GA+7C6q2Ym6NJilGBOp3K3Gc1/qQwBb9s7vJ
         I5PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=juPH+U2U;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o206si92916vka.4.2019.11.23.15.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 23 Nov 2019 15:07:58 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wm1-f47.google.com (mail-wm1-f47.google.com [209.85.128.47])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1D8E12072D
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2019 23:07:57 +0000 (UTC)
Received: by mail-wm1-f47.google.com with SMTP id g206so11081480wme.1
        for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2019 15:07:57 -0800 (PST)
X-Received: by 2002:a1c:1f8d:: with SMTP id f135mr11373714wmf.79.1574550475449;
 Sat, 23 Nov 2019 15:07:55 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
In-Reply-To: <20191115191728.87338-2-jannh@google.com>
From: Andy Lutomirski <luto@kernel.org>
Date: Sat, 23 Nov 2019 15:07:43 -0800
X-Gmail-Original-Message-ID: <CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A@mail.gmail.com>
Message-ID: <CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=juPH+U2U;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Nov 15, 2019 at 11:17 AM Jann Horn <jannh@google.com> wrote:
>
> A frequent cause of #GP exceptions are memory accesses to non-canonical
> addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> the kernel doesn't currently print the fault address for #GP.
> Luckily, we already have the necessary infrastructure for decoding X86
> instructions and computing the memory address that is being accessed;
> hook it up to the #GP handler so that we can figure out whether the #GP
> looks like it was caused by a non-canonical address, and if so, print
> that address.
>
> While it is already possible to compute the faulting address manually by
> disassembling the opcode dump and evaluating the instruction against the
> register dump, this should make it slightly easier to identify crashes
> at a glance.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>
> Notes:
>     v2:
>      - print different message for segment-related GP (Borislav)
>      - rewrite check for non-canonical address (Sean)
>      - make it clear we don't know for sure why the GP happened (Andy)
>
>  arch/x86/kernel/traps.c | 45 +++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 43 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index c90312146da0..12d42697a18e 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -56,6 +56,8 @@
>  #include <asm/mpx.h>
>  #include <asm/vm86.h>
>  #include <asm/umip.h>
> +#include <asm/insn.h>
> +#include <asm/insn-eval.h>
>
>  #ifdef CONFIG_X86_64
>  #include <asm/x86_init.h>
> @@ -509,6 +511,38 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
>         do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
>  }
>
> +/*
> + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> + * address, print that address.
> + */
> +static void print_kernel_gp_address(struct pt_regs *regs)
> +{
> +#ifdef CONFIG_X86_64
> +       u8 insn_bytes[MAX_INSN_SIZE];
> +       struct insn insn;
> +       unsigned long addr_ref;
> +
> +       if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> +               return;
> +
> +       kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> +       insn_get_modrm(&insn);
> +       insn_get_sib(&insn);
> +       addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
> +
> +       /* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
> +       if (addr_ref >= ~__VIRTUAL_MASK)
> +               return;
> +
> +       /* Bail out if the entire operand is in the canonical user half. */
> +       if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
> +               return;
> +
> +       pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
> +                addr_ref);
> +#endif
> +}

Could you refactor this a little bit so that we end up with a helper
that does the computation?  Something like:

int probe_insn_get_memory_ref(void **addr, size_t *len, void *insn_addr);

returns 1 if there was a memory operand and fills in addr and len,
returns 0 if there was no memory operand, and returns a negative error
on error.

I think we're going to want this for #AC handling, too :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A%40mail.gmail.com.
