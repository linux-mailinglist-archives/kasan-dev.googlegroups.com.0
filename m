Return-Path: <kasan-dev+bncBAABBSFSW3XAKGQE2RNRCTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E021FCCE4
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:13:28 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id i25sf2212847lfo.4
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:13:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573755208; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLCYxctdVEysVvdBc8ZiWONumpLBBz4DsOPWfJyUCfVfgOq2vFhfUFV83CTXkwRu2l
         Cs22SrvUI8M4XELVbJaDc7pC/qG+AiMmsCIyqquOxbukCHpQfssC16AX6qJgsgDc3DnG
         NXl485/LXXnU8STk+fbBWoNl1J8lPNlrlQxdzBjwXKxZfMRAWL1sqvd1VQkjs1TE+N5P
         VyHVmboCHET3A1VlXaorgwQQqyZbuNPyWp+6gcIG9T4FRWZuU8ZJapgezb4TCBjXtLh1
         UxIQ1L+Q/zrVI5hteLM94gH702Bj/M71bKTpSBVNdfdY16iLud4/RO/ZaRbN3BRLUL6X
         BEvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wihf58E26I1C4PmvAaS/oZAWaooNEx1TU7JdmvFD5eE=;
        b=XDQKxWd8l7Eo6/GVGH1MuV1euYqqvqGfH5V5J7wm4RnVQDPhALmkkwOBs1GoV2aAVg
         aQSg1tLwrG2K/fJxu0eQoLSs/1HrJlPneq9LmraqGPkNg/O3d0sq30k78m+nL7H1MWWM
         Zh4uluYEYdpOQxVJqq+IxMZMRc3g7J7FqocuC6L0yYrJCO3GHFyKAzlKsJ803dVpVrkq
         3I7JeEthXYH2H+TrjvboUjafmC4K2JH0jAX1Jw6n+cCGtdn+KRe8bAwkmvhUnBWho8MX
         LJ2XvTMhCEzH+r4Ac3l9Koeg1GWN5Wn/QCdfR8GQawTmDSaLc+4EQ6nc4CONhTNH3+gB
         nkdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wihf58E26I1C4PmvAaS/oZAWaooNEx1TU7JdmvFD5eE=;
        b=qmfG6ypgXpkk9+e0RktiznyNGadrJSdisVeEMFeClLeS40jpIWficsPuHjBPgSddg5
         0WOBjcSdXWRQf1ZzaVN/7g9VQx0qgvCwc4HAesKN7DG8u+MQWFHj/rk4xKqFepx5tE2R
         QWEd1Lz4qaZT+ujDqhZsLDHyouKR6MC98Iy2vkpWgWvEwRKlrU4Z8BITCFJCYtzf9ZHV
         F5OdW9S2kfVgaDqi6IAz+HgoIMnN+UZhzk4uJrKLzD5zB0rAWXC92HF2nSioUlTx+uTQ
         zQBxjR2iCg+q9sCD1i8RvxLeWJ1PGQSziBkZP4YJc63h+d+QTfAfj2GyWx6CthDzJ1Qj
         24AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wihf58E26I1C4PmvAaS/oZAWaooNEx1TU7JdmvFD5eE=;
        b=Pfc9gbJkI3pWqRmAvfddtlzeMREU9B/a/nPtQezHHktdmG9Mnz8s7J2SVxWwj67Jpb
         Y/b6hPK1KMU5dL36c233Ko1lKSW1pKKZ724PiuWzlH7i2BseQWZ3eWBTjF1kI8XAgtaH
         K/Kav8vD83sdPPzFPw0zLe0YZEl2TbFp9HqSfT7+pVP4B7yxx+CAc7ha/d+O1lQuz+bG
         6uDB31KBVoRrKrML4cDaW/iMOAeB/kpMeM2zJgwwuVC3DWOd75eT7tWOh1mwuL0jZPDP
         z1deBePztzan9f0ORckg54fK5F0eI9/jkDA5wKYlES8/WiQni7OSDAMQ15F/tfJrysn3
         j89g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUBEamOOOoxeDACp8PsElpwpSv19YeGMTwuk704p+SLJ3RuTCmv
	phmVzGLX4S10bAN+nwyM0dM=
X-Google-Smtp-Source: APXvYqyCoZsqBcG+9+hIdwPv6DHjGCHirml1pjJxoz2aS5dDcozyCph308ooT3slQy2hPvHUczHv2g==
X-Received: by 2002:ac2:4357:: with SMTP id o23mr7845406lfl.51.1573755208150;
        Thu, 14 Nov 2019 10:13:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b161:: with SMTP id a1ls1336967ljm.15.gmail; Thu, 14 Nov
 2019 10:13:27 -0800 (PST)
X-Received: by 2002:a2e:9449:: with SMTP id o9mr7853844ljh.75.1573755207555;
        Thu, 14 Nov 2019 10:13:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573755207; cv=none;
        d=google.com; s=arc-20160816;
        b=HNA0Bo6Fnh484T7VCTt/VRoWglZ7zxP7s9a61oYurqbxQFC71EbVeQXXw+WhEVcKrt
         O7PFhkU3Ol/rLblibDOyDnGUtXbCE7j2iCNXhRzw0bqVznrXOHDro3m4gnqILds8F1SF
         kmzVAKFbBkpR2jmzmZUL6fHdyt7rYM+m6MvXlCvzP/5RozGtGBxJPlSC4lvCHELsG5wY
         kj5G586ydo6tPGNoj4Ncgu8oocMq1QXVwyNSLYnFVJ4IG+exZ19m8cVWNRUhygBwkOIp
         KZr8i9ibAoUn4hyTX9OxW33Kk32qzk5h0qKmmyl+CYKZkovE2yhAz06djCSL3CUb0Jr+
         HPIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=znDROffvNftezwPpxvEstocvzIZENMxE2k1cHTZQwUU=;
        b=YrMyfKo5UJBCtBnPE6QBNK92vHgZ6/0vx2WVNY7GvOOF7kVPotAroQBAWNSVT8X3oQ
         SE5NZNRJhLzRebPSZiw1DXkUQfwKwcrTZ5Lp4Rnh7ZJNqftXhHwnDyMAQW5Mrmv+WmyO
         4jVr/HUQ6K2RIXI6c5wmYPvx314vwdHh1PjZa/3Ldm+q0FR9f6fTf0b5ftY3RdzJg1LM
         JVhY1sp8nfe6g9NLbu5vkXSupWY1JxQkKpSs1IwXd9NzJFjye/OpOPC4eviKHTSOD/pj
         FBlCQN2FZg1AOdFkuzuSpXPYQOXx2WBGWjLTnz62m6KRyjkOqM5zoOmBGFyUrYUc4eMd
         6iQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id x23si386812lfq.0.2019.11.14.10.13.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Nov 2019 10:13:27 -0800 (PST)
Received-SPF: pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from pty.hi.pengutronix.de ([2001:67c:670:100:1d::c5])
	by metis.ext.pengutronix.de with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVJc0-0000jD-Rz; Thu, 14 Nov 2019 19:12:56 +0100
Received: from mfe by pty.hi.pengutronix.de with local (Exim 4.89)
	(envelope-from <mfe@pengutronix.de>)
	id 1iVJbo-00011h-3P; Thu, 14 Nov 2019 19:12:44 +0100
Date: Thu, 14 Nov 2019 19:12:43 +0100
From: Marco Felsch <m.felsch@pengutronix.de>
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: linux-arm-kernel@lists.infradead.org, mark.rutland@arm.com,
	alexandre.belloni@bootlin.com, mhocko@suse.com,
	julien.thierry@arm.com, catalin.marinas@arm.com,
	linux-kernel@vger.kernel.org, dhowells@redhat.com,
	yamada.masahiro@socionext.com, ryabinin.a.a@gmail.com,
	glider@google.com, kvmarm@lists.cs.columbia.edu, corbet@lwn.net,
	liuwenliang@huawei.com, daniel.lezcano@linaro.org,
	linux@armlinux.org.uk, kasan-dev@googlegroups.com,
	bcm-kernel-feedback-list@broadcom.com, geert@linux-m68k.org,
	drjones@redhat.com, vladimir.murzin@arm.com, keescook@chromium.org,
	arnd@arndb.de, marc.zyngier@arm.com, andre.przywara@arm.com,
	philip@cog.systems, jinb.park7@gmail.com, tglx@linutronix.de,
	dvyukov@google.com, nico@fluxnic.net, gregkh@linuxfoundation.org,
	ard.biesheuvel@linaro.org, linux-doc@vger.kernel.org,
	christoffer.dall@arm.com, rob@landley.net, pombredanne@nexb.com,
	akpm@linux-foundation.org, thgarnie@google.com,
	kirill.shutemov@linux.intel.com, kernel@pengutronix.de
Subject: Re: [PATCH v6 0/6] KASan for arm
Message-ID: <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Sent-From: Pengutronix Hildesheim
X-URL: http://www.pengutronix.de/
X-IRC: #ptxdist @freenode
X-Accept-Language: de,en
X-Accept-Content-Type: text/plain
X-Uptime: 18:55:45 up 181 days, 13 min, 127 users,  load average: 0.09, 0.08,
 0.06
User-Agent: NeoMutt/20170113 (1.7.2)
X-SA-Exim-Connect-IP: 2001:67c:670:100:1d::c5
X-SA-Exim-Mail-From: mfe@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: m.felsch@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
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

Hi Florian,

first of all, many thanks for your work on this series =) I picked your
and Arnd patches to make it compilable. Now it's compiling but my imx6q
board didn't boot anymore. I debugged the code and found that the branch
to 'start_kernel' won't be reached

8<------- arch/arm/kernel/head-common.S -------
....

#ifdef CONFIG_KASAN
        bl      kasan_early_init
#endif
	mov     lr, #0
	b       start_kernel
ENDPROC(__mmap_switched)

....
8<----------------------------------------------

Now, I found also that 'KASAN_SHADOW_OFFSET' isn't set due to missing
'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=xxxxx' is
added. Can that be the reason why my board isn't booted anymore?

Thanks for your reply.

Regards,
  Marco

On 19-06-17 15:11, Florian Fainelli wrote:
> Hi all,
> 
> Abbott submitted a v5 about a year ago here:
> 
> and the series was not picked up since then, so I rebased it against
> v5.2-rc4 and re-tested it on a Brahma-B53 (ARMv8 running AArch32 mode)
> and Brahma-B15, both LPAE and test-kasan is consistent with the ARM64
> counter part.
> 
> We were in a fairly good shape last time with a few different people
> having tested it, so I am hoping we can get that included for 5.4 if
> everything goes well.
> 
> Changelog:
> 
> v6 - v5
> - Resolve conflicts during rebase, and updated to make use of
>   kasan_early_shadow_pte instead of kasan_zero_pte
> 
> v5 - v4
> - Modify Andrey Ryabinin's email address.
> 
> v4 - v3
> - Remove the fix of type conversion in kasan_cache_create because it has
>   been fix in the latest version in:
>   git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
> - Change some Reviewed-by tag into Reported-by tag to avoid misleading.
>   ---Reported by: Marc Zyngier <marc.zyngier@arm.com>
>                   Russell King - ARM Linux <linux@armlinux.org.uk>
> - Disable instrumentation for arch/arm/mm/physaddr.c
> 
> v3 - v2
> - Remove this patch: 2 1-byte checks more safer for memory_is_poisoned_16
>   because a unaligned load/store of 16 bytes is rare on arm, and this
>   patch is very likely to affect the performance of modern CPUs.
>   ---Acked by: Russell King - ARM Linux <linux@armlinux.org.uk>
> - Fixed some link error which kasan_pmd_populate,kasan_pte_populate and
>   kasan_pud_populate are in section .meminit.text but the function
>   kasan_alloc_block which is called by kasan_pmd_populate,
>   kasan_pte_populate and kasan_pud_populate is in section .init.text. So
>   we need change kasan_pmd_populate,kasan_pte_populate and
>   kasan_pud_populate into the section .init.text.
>   ---Reported by: Florian Fainelli <f.fainelli@gmail.com>
> - Fixed some compile error which caused by the wrong access instruction in
>   arch/arm/kernel/entry-common.S.
>   ---Reported by: kbuild test robot <lkp@intel.com>
> - Disable instrumentation for arch/arm/kvm/hyp/*.
>   ---Acked by: Marc Zyngier <marc.zyngier@arm.com>
> - Update the set of supported architectures in
>   Documentation/dev-tools/kasan.rst.
>   ---Acked by:Dmitry Vyukov <dvyukov@google.com>
> - The version 2 is tested by:
>   Florian Fainelli <f.fainelli@gmail.com> (compile test)
>   kbuild test robot <lkp@intel.com>       (compile test)
>   Joel Stanley <joel@jms.id.au>           (on ASPEED ast2500(ARMv5))
> 
> v2 - v1
> - Fixed some compiling error which happens on changing kernel compression
>   mode to lzma/xz/lzo/lz4.
>   ---Reported by: Florian Fainelli <f.fainelli@gmail.com>,
>              Russell King - ARM Linux <linux@armlinux.org.uk>
> - Fixed a compiling error cause by some older arm instruction set(armv4t)
>   don't suppory movw/movt which is reported by kbuild.
> - Changed the pte flag from _L_PTE_DEFAULT | L_PTE_DIRTY | L_PTE_XN to
>   pgprot_val(PAGE_KERNEL).
>   ---Reported by: Russell King - ARM Linux <linux@armlinux.org.uk>
> - Moved Enable KASan patch as the last one.
>   ---Reported by: Florian Fainelli <f.fainelli@gmail.com>,
>      Russell King - ARM Linux <linux@armlinux.org.uk>
> - Moved the definitions of cp15 registers from
>   arch/arm/include/asm/kvm_hyp.h to arch/arm/include/asm/cp15.h.
>   ---Asked by: Mark Rutland <mark.rutland@arm.com>
> - Merge the following commits into the commit
>   Define the virtual space of KASan's shadow region:
>   1) Define the virtual space of KASan's shadow region;
>   2) Avoid cleaning the KASan shadow area's mapping table;
>   3) Add KASan layout;
> - Merge the following commits into the commit
>   Initialize the mapping of KASan shadow memory:
>   1) Initialize the mapping of KASan shadow memory;
>   2) Add support arm LPAE;
>   3) Don't need to map the shadow of KASan's shadow memory;
>      ---Reported by: Russell King - ARM Linux <linux@armlinux.org.uk>
>   4) Change mapping of kasan_zero_page int readonly.
> - The version 1 is tested by Florian Fainelli <f.fainelli@gmail.com>
>   on a Cortex-A5 (no LPAE).
> 
> Hi,all:
>    These patches add arch specific code for kernel address sanitizer
> (see Documentation/kasan.txt).
> 
>    1/8 of kernel addresses reserved for shadow memory. There was no
> big enough hole for this, so virtual addresses for shadow were
> stolen from user space.
> 
>    At early boot stage the whole shadow region populated with just
> one physical page (kasan_zero_page). Later, this page reused
> as readonly zero shadow for some memory that KASan currently
> don't track (vmalloc).
> 
>   After mapping the physical memory, pages for shadow memory are
> allocated and mapped.
> 
>   KASan's stack instrumentation significantly increases stack's
> consumption, so CONFIG_KASAN doubles THREAD_SIZE.
> 
>   Functions like memset/memmove/memcpy do a lot of memory accesses.
> If bad pointer passed to one of these function it is important
> to catch this. Compiler's instrumentation cannot do this since
> these functions are written in assembly.
> 
>   KASan replaces memory functions with manually instrumented variants.
> Original functions declared as weak symbols so strong definitions
> in mm/kasan/kasan.c could replace them. Original functions have aliases
> with '__' prefix in name, so we could call non-instrumented variant
> if needed.
> 
>   Some files built without kasan instrumentation (e.g. mm/slub.c).
> Original mem* function replaced (via #define) with prefixed variants
> to disable memory access checks for such files.
> 
>   On arm LPAE architecture,  the mapping table of KASan shadow memory(if
> PAGE_OFFSET is 0xc0000000, the KASan shadow memory's virtual space is
> 0xb6e000000~0xbf000000) can't be filled in do_translation_fault function,
> because kasan instrumentation maybe cause do_translation_fault function
> accessing KASan shadow memory. The accessing of KASan shadow memory in
> do_translation_fault function maybe cause dead circle. So the mapping table
> of KASan shadow memory need be copyed in pgd_alloc function.
> 
> Most of the code comes from:
> https://github.com/aryabinin/linux/commit/0b54f17e70ff50a902c4af05bb92716eb95acefe
> 
> These patches are tested on vexpress-ca15, vexpress-ca9
> 
> 
> Abbott Liu (2):
>   ARM: Add TTBR operator for kasan_init
>   ARM: Define the virtual space of KASan's shadow region
> 
> Andrey Ryabinin (4):
>   ARM: Disable instrumentation for some code
>   ARM: Replace memory function for kasan
>   ARM: Initialize the mapping of KASan shadow memory
>   ARM: Enable KASan for arm
> 
>  Documentation/dev-tools/kasan.rst     |   4 +-
>  arch/arm/Kconfig                      |   1 +
>  arch/arm/boot/compressed/Makefile     |   1 +
>  arch/arm/boot/compressed/decompress.c |   2 +
>  arch/arm/boot/compressed/libfdt_env.h |   2 +
>  arch/arm/include/asm/cp15.h           | 106 +++++++++
>  arch/arm/include/asm/kasan.h          |  35 +++
>  arch/arm/include/asm/kasan_def.h      |  64 ++++++
>  arch/arm/include/asm/kvm_hyp.h        |  54 -----
>  arch/arm/include/asm/memory.h         |   5 +
>  arch/arm/include/asm/pgalloc.h        |   7 +-
>  arch/arm/include/asm/string.h         |  17 ++
>  arch/arm/include/asm/thread_info.h    |   4 +
>  arch/arm/kernel/entry-armv.S          |   5 +-
>  arch/arm/kernel/entry-common.S        |   9 +-
>  arch/arm/kernel/head-common.S         |   7 +-
>  arch/arm/kernel/setup.c               |   2 +
>  arch/arm/kernel/unwind.c              |   3 +-
>  arch/arm/kvm/hyp/cp15-sr.c            |  12 +-
>  arch/arm/kvm/hyp/switch.c             |   6 +-
>  arch/arm/lib/memcpy.S                 |   3 +
>  arch/arm/lib/memmove.S                |   5 +-
>  arch/arm/lib/memset.S                 |   3 +
>  arch/arm/mm/Makefile                  |   4 +
>  arch/arm/mm/kasan_init.c              | 301 ++++++++++++++++++++++++++
>  arch/arm/mm/mmu.c                     |   7 +-
>  arch/arm/mm/pgd.c                     |  14 ++
>  arch/arm/vdso/Makefile                |   2 +
>  28 files changed, 608 insertions(+), 77 deletions(-)
>  create mode 100644 arch/arm/include/asm/kasan.h
>  create mode 100644 arch/arm/include/asm/kasan_def.h
>  create mode 100644 arch/arm/mm/kasan_init.c
> 
> -- 
> 2.17.1
> 
> 
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel
> 

-- 
Pengutronix e.K.                           |                             |
Steuerwalder Str. 21                       | http://www.pengutronix.de/  |
31137 Hildesheim, Germany                  | Phone: +49-5121-206917-0    |
Amtsgericht Hildesheim, HRA 2686           | Fax:   +49-5121-206917-5555 |

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114181243.q37rxoo3seds6oxy%40pengutronix.de.
