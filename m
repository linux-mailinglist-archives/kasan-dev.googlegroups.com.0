Return-Path: <kasan-dev+bncBDDL3KWR4EBRBW7BT35AKGQEGN5VZLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A65F72545B6
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 15:10:52 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id mw8sf3169987pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 06:10:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598533851; cv=pass;
        d=google.com; s=arc-20160816;
        b=0sa+v71+O3BRZ79hXtVo7cn2p/1WQSOOKT/dekGZ+Rw5U0TZWo4lZIAXkpK8yLCT8X
         n+LB8Z6+A8qd3g0Z9g5NUGhTV42tv2o+7+b48B+uQTqEjPs2patoX3J4xoyDA5gHj+Gl
         S5QKv1DmYuPv1W18tIeczxFoalu8lnNpBD79/pH3YT9dyMq2T5aGcw8FPXyUzIkWrM8b
         cBzEGd7R4sj0Y/m9LvrQv/7DvNNoSA7NiEx6sc/F7lZ0sda+Yy7k9eQxpAVj2TEja2IG
         e0LsIAqpvZXwPp6lhWhJ7VgpNJQ6Or6FnC/qTsydEQmawH7adSA+7cIfBFqAWj9wGFX+
         mQ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nSRjnrnfvJaitKnXlV7FMOLmkOklvRuOBb2Bts23Png=;
        b=uzIPKYzPBkNnKLp+EiWahR25auY9507R9FSIWbm5g/A0sIfvBPPC9L3u1WcZyveyJ1
         gEF/rism+dSTVPQGuyJVZsC1qAwvVoIcbbxEXekIkTuhPE4pd+0NMpfaG0avsCwy/12q
         Kqo+rEPsq/Q3Xg4y6gGx968NLk77FDiBdR43W0LqlDsK9xo91ToRaCSEgb9Lj7RJb4WB
         YavZkt748ryiwl9F4L19BMzEWUW8o97lxs3EFujkEjb+WrZOfO0AQNRmJgLrhTwQUSzc
         AEjVg0AohNlROfsisw5c/D5yDfVJJPhaCG/Z+NPhAEP4yQ47UXeyBGUBcNOvW+A4ymRZ
         CBlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nSRjnrnfvJaitKnXlV7FMOLmkOklvRuOBb2Bts23Png=;
        b=TbIhv8yFNVop+fW3ioI97tzC1cIdRMtlKy/AF1qjKi4RTcUzk3p4r2lB2mkujw9ZpN
         VMXKi0WV4l+D4HMBWnZdS/T0+m7bndATx7IqTHFONPEYkk1sDVF9XC/BQaIzIB/Eh2lf
         WMBx9/K0BWsXZHAa8nQvjTxtD/u2fAmO1u0dhKXs8FNKhnbQ6DiKWF3CuwzhnbEaLjeH
         VWeturJEp6EdI+qsWg3rKu+kdefletmD8hUz5t6kZecTCCPtm+g+JO274ngLVpw0n0ts
         tPQ1see8pBzkksBCcfRBhZXgN1QUJFiddCiSrHG5IBs1iWVOQUaFO8vzjWraWgz8Havp
         8zyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nSRjnrnfvJaitKnXlV7FMOLmkOklvRuOBb2Bts23Png=;
        b=srREX1z+HwgMz8fwTYKBDptRiNn9AzQFQDRrWBfhZsnSl9+koxA8X26HCjtvto4YTm
         iPLAqMtbSWJf17NNH8xacFUG+jsto3PQg6vxmMu65S7bLpnSFT9rmh/Uu6CCdhDcotTT
         U3U2Ed6RbOtbiU+FO7oL/XDv7SGPRmQ/mEf5Tgjao18+fTfuyWCFcQ8293QiquF310oh
         N0hSgZOhsP8843//khDDgzt3M6QpSMdCG/EN3J3R/VQcnPp3vpKBspIkMHNsm7pqxjQO
         r79L/2nMlxT4xJBz4kXpsicbj+SW6ILNXJCKV+F7lmdJB/OolrKnoYK+r2GAd9vVlrIi
         npzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BXK+JUVkbyTrzes0GiZfklC+i93xiN9wJPN0PMtDO80Bmldum
	dLX6Za35VHSxTn8PQexFkh4=
X-Google-Smtp-Source: ABdhPJxHD77/xDnvvnkIXOwpQ6fPq2UWXjy+lxoP8NVBtYOzk06CUY7Hux3bBqbL1L9OodLxaz9cpw==
X-Received: by 2002:a17:90b:1214:: with SMTP id gl20mr11100249pjb.225.1598533851338;
        Thu, 27 Aug 2020 06:10:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b107:: with SMTP id q7ls1222992plr.1.gmail; Thu, 27
 Aug 2020 06:10:50 -0700 (PDT)
X-Received: by 2002:a17:902:e9cb:: with SMTP id 11mr16599821plk.216.1598533850829;
        Thu, 27 Aug 2020 06:10:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598533850; cv=none;
        d=google.com; s=arc-20160816;
        b=ySh9uA9TRP5PP8vlLz7uUA3QVV0OH83CguSKB5y656RwW2P07P/lf7jnBr54tQddSZ
         GhckX8BDsGN2/XTZqKSNI/Q0e+AqLCVm1d7wcDjhdKsKWjCZ9RVY/QgQwPFcw4vQTLdq
         bwfizm7sL1zxzkaG3ny1u671TSCKh8yDlqV/d6xLvCs9rQCntoEMhH8AEWpHl1JKuwEy
         Pf4vGOGJbrORCNV/nzQTUEC0OA/o8dxLsoTX8jnqOs+rQJKnOTb/gKlZ/2laNsAj132O
         DhjZc/b73JFZxXfO2SfjecCAelXTI9mag+3+mBhErlob9nWPbpiS9GWddfMM0uSYU3cL
         e/Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=M5ytjJxKxU7wUyTQaQ/T1WyGq4hSu4S+y4z/z0e+HNU=;
        b=THXP9lY+NDDgJA5VHT3Aam/kuh68Tm0ZXMcuo8N3eXOFyK4G2Av4sMDvUwS7mtI/SU
         YhBWH+Sh7uhOL2UtzvtVpiWmTiEF6eVEmxe7JO65xaynQ1u5bYVUoNuP3uLPpwBbRCrI
         4wd+YjmqdNAGWmgwAGXLAfmg88SQpdcEaEfGDv5RWJ8J0REWDtyvCqMU4k0PQSOlA7/I
         2pLGJUXi8nypM/EH3NUAlquvMpmCxGybApvj74z96hAGOIp7+VukqRWG73c28b0oi1x/
         uN6TPqIKiHxdgyRvGC0Lw40BzZrxHzRdo7QbpsQJ9c4e8skwk+yDM9lhXdF/hj/rd10s
         O05g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 129si91665pgf.2.2020.08.27.06.10.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 06:10:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 10065206F0;
	Thu, 27 Aug 2020 13:10:47 +0000 (UTC)
Date: Thu, 27 Aug 2020 14:10:45 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200827131045.GM29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia>
 <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Aug 27, 2020 at 02:31:23PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > > +                        struct pt_regs *regs)
> > > +{
> > > +     report_tag_fault(addr, esr, regs);
> > > +
> > > +     /* Skip over the faulting instruction and continue: */
> > > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> >
> > Ooooh, do we expect the kernel to still behave correctly after this? I
> > thought the recovery means disabling tag checking altogether and
> > restarting the instruction rather than skipping over it.
> 
> The intention is to be able to catch multiple MTE faults without
> panicking or disabling MTE when executing KASAN tests (those do
> multiple bad accesses one after another).

The problem is that for MTE synchronous tag check faults, the access has
not happened, so you basically introduce memory corruption by skipping
the access.

> We do arm64_skip_faulting_instruction() for software tag-based KASAN
> too, it's not ideal, but works for testing purposes.

IIUC, KASAN only skips over the brk instruction which doesn't have any
other side-effects. Has the actual memory access taken place when it
hits the brk?

> Can we disable MTE, reexecute the instruction, and then reenable MTE,
> or something like that?

If you want to preserve the MTE enabled, you could single-step the
instruction or execute it out of line, though it's a bit more convoluted
(we have a similar mechanism for kprobes/uprobes).

Another option would be to attempt to set the matching tag in memory,
under the assumption that it is writable (if it's not, maybe it's fine
to panic). Not sure how this interacts with the slub allocator since,
presumably, the logical tag in the pointer is wrong rather than the
allocation one.

Yet another option would be to change the tag in the register and
re-execute but this may confuse the compiler.

> When running in-kernel MTE in production, we'll either panic or
> disable MTE after the first fault. This was controlled by the
> panic_on_mte_fault option Vincenzo initially had.

I prefer to disable MTE, print something and continue, but no panic.

> > We only skip if we emulated it.
> 
> I'm not sure I understand this part, what do you mean by emulating?

Executing it out of line or other form of instruction emulation (see
arch/arm64/kernel/probes/simulate-insn.c) so that the access actually
takes place. But you can single-step or experiment with some of the
other tricks above.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827131045.GM29264%40gaia.
