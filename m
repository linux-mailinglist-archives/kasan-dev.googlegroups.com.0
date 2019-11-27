Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBIXR7PXAKGQE2RXOLEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A14410C02F
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 23:28:52 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id a11sf10291612plp.21
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 14:28:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574893730; cv=pass;
        d=google.com; s=arc-20160816;
        b=gs4TnWCWNhSNvTX+GQ+FquIED6mQkH2VWhvHFgsaK5RTy3hgprit61YNtE9FE7Hgac
         ueOeSxDCvOiEj91LkfbWHowi/pHeQpusvD4uHfynyPXt28AQOCTQEoMX2VhJ+ifEcylV
         /ziKM0KlUJRY+HWGJjPB0r4eKSPekIEAqagsIAgVkfywaMvosNRc3bxQMwMWt5V/pcZc
         bL+vjPB1Ri+dLCKUpCYQF2z2Z83ZJjEIxbYbomUOzr4MuqthyesydE7CSc6iKrMaCNo+
         Zh75rwbKF/WEA3BZ1PEwDUmA36rjSmQ7q55ee2t0CNqNU+3WdTqaDCJ60aI7bvK6mvCf
         /yQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CEw+XjfFdIXZz5JPmUSLbJhGC9lDKzADkaF0uGqgujM=;
        b=uh5Tr8w63C8aKxOHvpn0Fus/sxj/WmQc6FSR4wUhNGogE3cSGPqUQSTB1UsiM1VEuk
         sH//FQ7LORSN/D+PtelNkT0LvUgie2AYr042LQ2FCoQ+fFJI2SZf3L+/gb/rtsfxhL3u
         /l9L9Vl8YPNeZit2uzK3c4IAEZWKn/+SJdARmN78SlqkuW7WeqE8JdHQ05pWg9Y7bjmE
         tq623FJ6T+jEupCa9dJg3NQ875hcIfyKSPCRRH+kn24y8W1QFvOlClBDAjAnn6mql6l7
         9XqWCybuaDl7JBzFI5b45clxoO5NR+HNc8+ZsCw3czp4UMWb+7k2L4VZpz6CF7m00Yea
         U76g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=li5wluUZ;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CEw+XjfFdIXZz5JPmUSLbJhGC9lDKzADkaF0uGqgujM=;
        b=dBn65GkJ9K12m4Q6zA3a7qLfSvCZvcTJ/DrU2JXenCvibQg5csZCR2feWB/LuZ4nFD
         2FGR5teMZfgegBv5LOYucXqje/Oh3OP9p1p+eqE4pG1uxRBr3yBoR67P+eBswzC8zw4j
         Jvi96JScbHecXDCrT2pUUbE1VoNEYEnkAvzL3jLVL4XkL1X9qzTv158lE3FhLm9kt2Nb
         JT0JyMS906VLQ8dypQKdV1HB0QFcHXLsgTCLaBItTkPiFIOP4qBErF47e9t4VYOTgxJl
         NJO4zp13I/2pUUxBsSIUUPedmbKzCLgu74YH8+scy6x61kzPQQB8QgYOLWk9MC16I6VR
         2BXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CEw+XjfFdIXZz5JPmUSLbJhGC9lDKzADkaF0uGqgujM=;
        b=jTfjNWt95gIk+fXsmU4iEJrLvT31rj04F1BrJtfybvyfk3mqeAZkOLbWoTDJ/3qQAT
         e4Rlmc9IfAzc9UiSvLxmZMOGcMnOiVDtkUJHlFeovSj1s6QbWgYVPKRw5rDAWXY7hbML
         bYaxXUysgwP3vkCKLaFaMm3V/6OJ8TkrNV/L9T2hL4o4v+Gh5dzZpiCXSNDRrgFVJcsK
         s5dqJxZ5eCJSZSEjzaXidZ1doKHVyncVSIWQerJZ9MMVFgjKwoXCTF2O5To5fWyBJO2+
         4HWp4WzNVupkVcIStNKoTNHvXIsc1gmPRnZIuEzQrCkCqI/2lqLM8Ung+0FtGCfbsilK
         ++QA==
X-Gm-Message-State: APjAAAVFWYqo++qEpl6qxh2DxIsNTu4KlJnep1UnhT//TCrVlwzOTNsb
	qL69dgAEWUXbfCS/eFvJdto=
X-Google-Smtp-Source: APXvYqyZ+TvplmtEcWqg7fsdG3Pt0Dsj1ICuXSY2Nvg3QIdMpVVl2q3QGv13WUpA0dqSWJ2afkRyLQ==
X-Received: by 2002:a63:1b5c:: with SMTP id b28mr7519085pgm.69.1574893730550;
        Wed, 27 Nov 2019 14:28:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f8e:: with SMTP id o14ls2198886pjp.3.gmail; Wed, 27
 Nov 2019 14:28:50 -0800 (PST)
X-Received: by 2002:a17:90a:c082:: with SMTP id o2mr8901711pjs.94.1574893730178;
        Wed, 27 Nov 2019 14:28:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574893730; cv=none;
        d=google.com; s=arc-20160816;
        b=d3XGozt28UGvrIoutZhZEvNmW/MbEkbu3k8/xvh2HaAbPUL9L54ZrNi8+EmWsqQm/6
         q9wa84hKtLo0gWcWK5CtYofKaAAfgOJutXR7C/Xx2SgWb0+3W+J62wrlzMhMSWHGIoh5
         wvhhvVMtAnVoGQsGtQJx8zrwHRykV3y8/9ee/CYC9RPvDroHrEYEWoZUNl8DJ7dSGxhT
         cKSqa0txV2RCE4Vs5OfDbVPzw/G7TqXWxLNngZBWGEfeMypQ+UN5S6B7cHYma77Ovb4X
         rbsFZZ2+rKFCiwuWLI3GkGeIAEgmVL3P8vxlESpBzlNXy3bCA6l+CxxDxjKVdM/lRsOd
         AX2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KeXZ4luqCFNOPNM7E+9i6XZwG6Bi3IeNYp/i0vjoN04=;
        b=A9ROmT0ttPLOItBMTV0t+tukO8w4KMZY/RQyvBoCir7mtUF7lf7i9oADS/AdRgxBRG
         YGUu7fHys91F4u2IOxq9pcZU7zl2lrPT702lD3ebvha83lxASOOViJ0xA/UyZMAGy2EH
         jiTBGY6Zfssijbd8K7dcZBsWDlnHTgJbn4MHfUbiD8m5g5g98pM+2XjZrHq1R+e2hpyG
         IuFoKrgpuCr27iqnWT952+gBqmkpGANQrvgIE77z9jNZAA0aGlMQq65emnLvVR6nYt2i
         X3eRB+8uVW1GPD+M8TjcfD8oo+AyNsOBfkuJGfli7+L870VcgFj3WMRLRdEjywe9QgrX
         lZNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=li5wluUZ;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id q207si293742pfc.5.2019.11.27.14.28.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 14:28:50 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id x21so14462893oic.0
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 14:28:50 -0800 (PST)
X-Received: by 2002:aca:ccd1:: with SMTP id c200mr6180503oig.157.1574893728992;
 Wed, 27 Nov 2019 14:28:48 -0800 (PST)
MIME-Version: 1.0
References: <20191120170208.211997-1-jannh@google.com> <20191120170208.211997-2-jannh@google.com>
 <20191120202516.GD32572@linux.intel.com>
In-Reply-To: <20191120202516.GD32572@linux.intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Nov 2019 23:28:22 +0100
Message-ID: <CAG48ez0D2Neddh5WTX-agdpS=Xyf3XWXFB=DebxxV9nAVY43Gg@mail.gmail.com>
Subject: Re: [PATCH v4 2/4] x86/traps: Print non-canonical address on #GP
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=li5wluUZ;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 20, 2019 at 9:25 PM Sean Christopherson
<sean.j.christopherson@intel.com> wrote:
> On Wed, Nov 20, 2019 at 06:02:06PM +0100, Jann Horn wrote:
> > @@ -509,11 +511,50 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
> >       do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
> >  }
> >
> > +/*
> > + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> > + * address, return that address.
>
> Stale comment now that it's decoding canonical addresses too.

Right, reworded.

> > + */
> > +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> > +                                        bool *non_canonical)
>
> Alignment of non_canonical is funky.

Fixed the indentation.

> > +{
> > +#ifdef CONFIG_X86_64
> > +     u8 insn_buf[MAX_INSN_SIZE];
> > +     struct insn insn;
> > +
> > +     if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
> > +             return false;
> > +
> > +     kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
> > +     insn_get_modrm(&insn);
> > +     insn_get_sib(&insn);
> > +     *addr = (unsigned long)insn_get_addr_ref(&insn, regs);
> > +
> > +     if (*addr == (unsigned long)-1L)
>
> Nit, wouldn't -1UL avoid the need to cast?

Ooh. I incorrectly assumed that a minus sign would be part of the
number literal and wouldn't be allowed for unsigned types, and didn't
realize that -1UL is just -(1UL)... thanks, will adjust.

> > +             return false;
> > +
> > +     /*
> > +      * Check that:
> > +      *  - the address is not in the kernel half or -1 (which means the
> > +      *    decoder failed to decode it)
> > +      *  - the last byte of the address is not in the user canonical half
> > +      */
>
> This -1 part of the comment should be moved above, or probably dropped
> entirely.

Yeah... I remember changing that as well as the comment above, I think
I lost the overview and accidentally went back to an earlier version
of the commit at some point... adjusted, thanks.

> > +     *non_canonical = *addr < ~__VIRTUAL_MASK &&
> > +                      *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK;
> > +
[...]
> > +             if (addr_resolved)
> > +                     snprintf(desc, sizeof(desc),
> > +                         GPFSTR " probably for %saddress 0x%lx",
> > +                         non_canonical ? "non-canonical " : "", gp_addr);
>
> I still think not explicitly calling out the straddle case will be
> confusing, e.g.
>
>   general protection fault probably for non-canonical address 0x7fffffffffff: 0000 [#1] SMP
>
> versus
>
>   general protection fault, non-canonical access 0x7fffffffffff - 0x800000000006: 0000 [#1] SMP
>
>
> And for the canonical case, "probably for address" may not be all that
> accurate, e.g. #GP(0) due to a instruction specific requirement is arguably
> just as likely to apply to the instruction itself as it is to its memory
> operand.

Okay, I'll bump up the level of hedging for canonical addresses to "maybe".

> Rather than pass around multiple booleans, what about adding an enum and
> handling everything in (a renamed) get_kernel_gp_address?  This works
> especially well if address decoding is done for 32-bit as well as 64-bit,
> which is probably worth doing since we're printing the address in 64-bit
> even if it's canonical.  The ifdeffery is really ugly if its 64-bit only...

The part about 32-bit makes sense to me; I've limited the
CONFIG_X86_64 ifdeffery to the computation of *non_canonical.

> enum kernel_gp_hint {
>         GP_NO_HINT,
>         GP_SEGMENT,
>         GP_NON_CANONICAL,
>         GP_STRADDLE_CANONICAL,
>         GP_RESOLVED_ADDR,
> };

I don't really like plumbing the error code down to the helper just so
that it can return an enum value to us based on that; but I guess the
rest of it does make the code a bit more pretty, will adjust.

> I get that adding a print just for the straddle case is probably overkill,
> but it seems silly to add all this and not make it as precise as possible.
>
>   general protection fault, non-canonical address 0xdead000000000000: 0000 [#1] SMP
>   general protection fault, non-canonical access 0x7fffffffffff - 0x800000000006: 0000 [#1] SMP
>   general protection fault, possibly for address 0xffffc9000021bd90: 0000 [#1] SMP
>   general protection fault, possibly for address 0xebcbde5c: 0000 [#1] SMP  // 32-bit kernel
>
>
> Side topic, opnd_bytes isn't correct for instructions with fixed 64-bit
> operands (Mq notation in the opcode map), which is probably an argument
> against the fancy straddle logic...

And there also is nothing in the instruction decoder that could ever
set opnd_bytes to 1, AFAICS. So while I think that the inaccuracies
there don't really matter for the coarse "is it noncanonical #GP?"
distinction right now - especially considering that userland isn't
allowed to allocate the last canonical virtual page on X86-64 -, it
definitely isn't accurate enough to explicitly print the access size
or end address.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0D2Neddh5WTX-agdpS%3DXyf3XWXFB%3DDebxxV9nAVY43Gg%40mail.gmail.com.
