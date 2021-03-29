Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXVERCBQMGQESKZ6H2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BE8D734D638
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 19:46:07 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id c15sf7834406ots.14
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 10:46:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617039966; cv=pass;
        d=google.com; s=arc-20160816;
        b=MSb10dJtN1WkfClubfKyDbtWX/DAyuQoSEEtPETDXH5Tz1IMtDcPpQZVcaNI/+vvHW
         zZgnhmL4NaJr0p6uYLAIvHQMzuzcmTEU84VU3K6QEUgsTeNnjKQvB0Y14M2xdXSLx1C0
         m3vnNcVBYpaU2MTA3NeaVp6WtcIWTc3vohlpseXWpewrTdf3Luc/Xdiw7OFV+aiBpR0P
         xciNA359iAqs6A/GTv+VoEpBoVvmYjdya4aZvKv7YknTxMO+rKaVpmNvoWuqgW8IQyil
         3e3GgdSVvfLBMKV6O/KZr4yO1o1pQaQN32HqagqWUlgFHhj2KDln879wnn6wruOFMfL1
         z60g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XItPvnTmXbrU8ZXnFLc+vIGQA59uqg3zRrhy/SsfUsc=;
        b=ABTfQd+mn3c1zr3rgebCyJV1KD/foraia+KClfjHtcVetXdXNPQHGB1gMiQk4OZIf8
         i+TWFiYYU+nHGS9NxGFfyuQ4FALaJySjrbcNTnBNzufLsliCiqIQmzTTORgvP5YB10y+
         0Sv2jdgm5Tet+6SStVRcM77vooFy5h6Z4LVGllqmSt01On7L/Ni7+bpeHxJVmFelAE9G
         HSGQsy6/PDSk9kzPSc+DRP472CXLMSLty+66+tpt92RvgmaGUI4/6Y4uXFEuGKcj1r0r
         sEAwZG5Ip9EUIDLWNKukueyg88Dm7jNE/InQNvG+djmK8AAYLnEFRdy7ZTdWd7EgvyWA
         4NXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mcP8xaGR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XItPvnTmXbrU8ZXnFLc+vIGQA59uqg3zRrhy/SsfUsc=;
        b=DTTxiGaAibGqrZ/PZOI7+Zxy2NJjZ/peT/UJ+HxivQThLimItB+0SOFJLNwut9qIfL
         SsHn0HOFiHzaptBehdU6hHF36ONZuhfo6AuKTKL6EJYNu7FdK4kGXo7q7ce5jHV7cFyy
         SYVBF4oyEhBC/58maX3RAb+DCTT7o7LDVd9/eSCB+83BboTM/HTIy5ejbCI8/B15rUrv
         CyaIZG2opTAmHr+XYum4MSVyBeDwOmvR7uOvuC6q3lwEZ4ibbDhInvK/VqUt63VWUP/j
         Qt6j1Ljw+q26gF8fnF9xauTYmkHz//M3W9HEoARIGAwu6uSl00juZWobepPEX8/Fseyd
         6zFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XItPvnTmXbrU8ZXnFLc+vIGQA59uqg3zRrhy/SsfUsc=;
        b=A2/FxGey9wCmU8MRcXna9UlVN2z7erWDLovVHcH/YJ2T/JvHgB4UoL8OqvKClWeGdG
         z7sihJNUDlciOahu5S6i8M0aMIY6TwgrSD61qD5+sO4tKW2HOfejscdo3K9wglX15+R9
         0ZpKl6wXBxakdbHThvViNJ2doB0ezPfB41gZPu3rlnCm9BK4ylZA1WFjvXXxS1MXl2jW
         najF5d7scqazgIFyOwb/z2vHEf4XcbU9g0i6IwL6ENhpTeVLGd9oCJBoh8vMxS/5a6YP
         pyn9JLy0SKNEaxlDaXvNDyjYOmmplz5ZevzT1aPz4xFpSHzy7HvgAYBG3P/YpyyuNqUj
         p71w==
X-Gm-Message-State: AOAM530tuIvK+hgNOS7KrxzfZs6lpmr71QTkCFH+2UqTWoTRuO1n9NxH
	Ohl4popjMDn3k3QkpRFQm3E=
X-Google-Smtp-Source: ABdhPJw/Ho1lSFtgyv8+HLjKyVP8RRp2+FiYpfZyBua7ueHJIBdM4w7zO/NrTJj/zS6yiAWONIry6Q==
X-Received: by 2002:a9d:5d0a:: with SMTP id b10mr9932257oti.180.1617039966794;
        Mon, 29 Mar 2021 10:46:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2421:: with SMTP id k1ls4388100ots.0.gmail; Mon, 29
 Mar 2021 10:46:06 -0700 (PDT)
X-Received: by 2002:a05:6830:15d2:: with SMTP id j18mr24357017otr.75.1617039966468;
        Mon, 29 Mar 2021 10:46:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617039966; cv=none;
        d=google.com; s=arc-20160816;
        b=Yx68Z8/nmpCAPKAO1iMGrS+dTe6CblSYfmUzdU4axo+WtnGAIFyYLBYFVSIwhC74bv
         AFhAhX0hsvhShyD3CbsW4g/nS3ukmX3ADDj3tLFZ0duRwUNBTO9BnNK1N0YbuE51SVi9
         Z9NjtNLQDxyZyBTM2xBNJve8CHxj2dCHrc7B1nQjsCWKxeIa8kTGoeOC8WxKdW2273/w
         adWepijSHabqEl6AZguFXZdlc4S0vM/42268fMwWqX5sp8RA+Iz9JE3C2ryIHMkHsdUq
         JTyC6M3S78E5oXpHyQfpGWMhdGW/FfesMpYMFacn940642SEuraSaA2lR3ybz4gLlRlI
         38KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BQKkZ6Ug92WKVE3kMUgFwD2xtwQ5flzTIZnOczAKft4=;
        b=F6GK46lCzn7x2VLJ/an9FcSx8smiwOnKoWbHHcqSLloVFOwffYvWaj0gKsxt/iUUI5
         Gpv0RyXkC9Bf7PztIi3v+itVKqwQOMtPc9HDCPbV5a9HR9X51IikedWceV8WgiWsuW+H
         xiKeBWchjEt3VDnAYBJl/BFJg7aho/YF6iyPGMv0ikfMGTYFyCVGxHvxqvePFKYG4wL3
         eCC2CyYrdB/kfBj7h8sPpppVo2PwgDHr9dR4VboRDES0RACQG1xwOvKtZoOVEI65UTbp
         jyfWfDL7XTkfDm2mrhoGrpWqVyKZcNaC9UVq/80m3osdl3i9qKbguHgCbRYg8jpzzt2G
         Xk7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mcP8xaGR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id y26si1255979ooy.1.2021.03.29.10.46.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 10:46:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id w21-20020a9d63950000b02901ce7b8c45b4so13067556otk.5
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 10:46:06 -0700 (PDT)
X-Received: by 2002:a05:6830:1c6e:: with SMTP id s14mr23850224otg.17.1617039965937;
 Mon, 29 Mar 2021 10:46:05 -0700 (PDT)
MIME-Version: 1.0
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com> <66f453a79f2541d4b05bcd933204f1c9@intel.com>
 <YGIDBAboELGgMgXy@elver.google.com> <796ff05e-c137-cbd4-252b-7b114abaced9@intel.com>
In-Reply-To: <796ff05e-c137-cbd4-252b-7b114abaced9@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 19:45:53 +0200
Message-ID: <CANpmjNP4Jjo2W2K_2nVv3UmOGB8c5k9Z0iOFRFD9bQpeWr+8mA@mail.gmail.com>
Subject: Re: I915 CI-run with kfence enabled, issues found
To: Dave Hansen <dave.hansen@intel.com>
Cc: "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mcP8xaGR;       spf=pass
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

On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wrote:
>
> On 3/29/21 9:40 AM, Marco Elver wrote:
> > It looks like the code path from flush_tlb_one_kernel() to
> > invalidate_user_asid()'s this_cpu_ptr() has several feature checks, so
> > probably some feature difference between systems where it triggers and
> > it doesn't.
> >
> > As far as I'm aware, there is no restriction on where
> > flush_tlb_one_kernel() is called. We could of course guard it but I
> > think that's wrong.
> >
> > Other than that, I hope the x86 maintainers know what's going on here.
> >
> > Just for reference, the stack traces in the above logs start with:
> >
> > | <3> [31.556004] BUG: using smp_processor_id() in preemptible [00000000] code: dmesg/1075
> > | <4> [31.556070] caller is invalidate_user_asid+0x13/0x50
> > | <4> [31.556078] CPU: 6 PID: 1075 Comm: dmesg Not tainted 5.12.0-rc4-gda4a2b1a5479-kfence_1+ #1
> > | <4> [31.556081] Hardware name: Hewlett-Packard HP Pro 3500 Series/2ABF, BIOS 8.11 10/24/2012
> > | <4> [31.556084] Call Trace:
> > | <4> [31.556088]  dump_stack+0x7f/0xad
> > | <4> [31.556097]  check_preemption_disabled+0xc8/0xd0
> > | <4> [31.556104]  invalidate_user_asid+0x13/0x50
> > | <4> [31.556109]  flush_tlb_one_kernel+0x5/0x20
> > | <4> [31.556113]  kfence_protect+0x56/0x80
> > |     ...........
>
> Our naming here isn't great.
>
> But, the "one" in flush_tlb_one_kernel() really refers to two "ones":
> 1. Flush one single address
> 2. Flush that address from one CPU's TLB
>
> The reason preempt needs to be off is that it doesn't make any sense to
> flush one TLB entry from a "random" CPU.  It only makes sense to flush
> it when preempt is disabled and you *know* which CPU's TLB you're flushing.

Thanks for the rationale behind needing preempt off.

Though in our case it really is best-effort, as long as we hit the CPU
of the currently running task most of the time.

Doing it to all CPUs is too expensive, and we can tolerate this being
approximate (nothing bad will happen, KFENCE might just miss a bug and
that's ok).

> I think kfence needs to be using flush_tlb_kernel_range().  That does
> all the IPI fanciness to flush the TLBs on *ALL* CPUs, not just the
> current one.

The other problem is that this code can be called from interrupts.
This is already documented in arch/x86/include/asm/kfence.h

> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on KPTI
> being enabled.  That's probably why you don't see this everywhere.  We
> should probably have unconditional preempt checks in there.

In which case I'll add a preempt_disable/enable() pair to
kfence_protect_page() in arch/x86/include/asm/kfence.h.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4Jjo2W2K_2nVv3UmOGB8c5k9Z0iOFRFD9bQpeWr%2B8mA%40mail.gmail.com.
