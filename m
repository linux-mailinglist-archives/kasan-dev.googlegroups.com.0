Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQXS63YAKGQEUYL5MXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id E371F13A9B0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 13:51:15 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id u6sf7911139iog.21
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 04:51:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579006274; cv=pass;
        d=google.com; s=arc-20160816;
        b=QqxNZJC6RlUmZeDu90EVZz/gK5izmj5UHz8Z7LMnln3U547eOFXr3Km4Zdoe1i/82L
         bkMbcigwwwvTwsoIxKeq7BfQ4sK+E5BHVWoaf+j3Yxt6X7DAnSqnbdN9Mu9MELGv1b7N
         Lq5AgqwQdXW79b23x9Dm6jIdpRsv6Qr+KMpk9RKzqKI9rs1URExvzdauX2l63oXsOFVS
         PRdmq2+qIXAsRIYlDbbqpuwFlS1ooygmmBMYT/WuiQXKZL8fdIaCh6nN51sWkI6Dw25q
         5maDm0DczC0+MSDK2mVeIQHy0rmTYbc5ZbT8RchMk794xmhYMAULffz0GGkqc34AUM3b
         MT+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N362QqOfYisBx2+p4Do1njm0Rn70Mk9uztqgc7wuQZc=;
        b=xaw+rieyuHWz1WA2XibbCYHAAOenfQKJowQ3G7He+oLer7qsEzvjbS++5DEtCYQYko
         wmFgTrPubXenp1DPTUZ5RTCnwgdsyTrgTaH6ZEdFGlisV8uGRne5dj0iifSdxNqCAwNR
         nClHAt2lPm0cqSfMFWBN5HO85VNa0zysJd7muGw/UqbClB3V6+JTT+1yvZRGNtcuuz9i
         7u9uy/GUN9b6LKMJRImmEt0krUhELzMGCcR3cgp3xid9/7JSA2eGHTvh9Xp14d4oVXZz
         jvFTXwg1ro6/V1Fan7JL/0v72XGDLMiuJrSHY1w7sX23w4n0YRzKxK0Ue38GrTPaVKO1
         elLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8ogLJT4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=N362QqOfYisBx2+p4Do1njm0Rn70Mk9uztqgc7wuQZc=;
        b=rt/F5D+tsgi2RnollzF1IDYNtQhrq5wxfXVAG5YaFe7LnrRH4xNAXgA/jkC6Y+oHD+
         u9jkCS/oM3Bk+5TueUstn5x+IRXC/v6b9sa/pAVz/1Dkat5qtVkABsOxSiib4jd26lCp
         2Ovj6/HwJ4YHXc7vWsdBovC24jmehZ2NNakQjid89ZoPnc3EmXeKFPFKOlaDkVnXd+Qc
         mbp3dUTzlY5ew/SzBZcSzfqFVl5ohF0N1YUeBBSv2lBa6lC8rgA52r3tMPoNdCmU47wa
         kUYduEOvBtaBodnFLMP8fIEHM8SBzGOXJzpHi3rmP5SlRVeAyeIb10N52QLAY4NNzcIX
         AeJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N362QqOfYisBx2+p4Do1njm0Rn70Mk9uztqgc7wuQZc=;
        b=WJ+MrEIgv7/W2Aniyxez/2a5T/DANya6Z1Ec5I1c9Th+dI/ckyDYCddGXL3og3NXXB
         ELSkTG9qaYyfAFcu6dZ03iBhElOpF+Zv9T2Iv9MBcLmA7BWOky6deTuXrf4VUJmYugk7
         4wLfQRlOBPd+KAy6taWkFMz1T9drQhJNN1vbqTL0dPF+sQV5PkzW7/5KNqijYZx0hbbr
         LLXBEcKdKpnYrEEUnruzBzN3hPB2rYRLrtthw7CBDJN+Tg6vDM5dxp9L+tSeRl4pg4qZ
         /sgyUWMTAI8K0HywdnYS00gHN2pieLE1rHbR921F5A0wCn8Utwzg8oqS/yZz5IM9UsFJ
         CEFA==
X-Gm-Message-State: APjAAAV2/aWaUPCHVINCoqoUMS++bISnqfdspfDCKHsXMHNhqe0nbKnx
	a7bdCFQOsQLvx1nLWjpu8iQ=
X-Google-Smtp-Source: APXvYqz9mMrN6xF/KWevSgTiTnsnZ9md34bebLaXLljOSevCHIiRJQELDp9+sAvBUGBYetYbaMY8Fw==
X-Received: by 2002:a05:6602:220b:: with SMTP id n11mr17715373ion.6.1579006274561;
        Tue, 14 Jan 2020 04:51:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce86:: with SMTP id r6ls2639951ilo.13.gmail; Tue, 14 Jan
 2020 04:51:14 -0800 (PST)
X-Received: by 2002:a92:3b98:: with SMTP id n24mr3491317ilh.108.1579006274210;
        Tue, 14 Jan 2020 04:51:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579006274; cv=none;
        d=google.com; s=arc-20160816;
        b=w8F28bcMmOiwrd+861LZqDfErC/ycqBm6obZN5xlvQz06xIfRO8MrSrry0qAgNKV8V
         tLjsiuAizycKaVvTin5PijOT+0LOIqXNJJNPitylpPTQx+vkSb7URzemqF2lB9PGTzHD
         nqgS+AxbAVv3192jSTJ82gvWNP/mXY6+67ITiblq+Qy5Tg0Bl2UVMWeGHaeqfZNdqeOv
         HHr0Xf5QyMSuTgj10fvywAvmuuQrpGVZwpQ/xH6o9Uo2TpRRd7l8swPcU60Z+p1ojH8u
         n7kEEK7mzYSfAuIOrOAPpdQPH0cJAhnPOKy1zz9dV+tJuusxLdZ85esbBDAash4ITaKC
         z1yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W+Q9dUTyz/K5v7vEopmSX1VV9yqJ2uEeGg7eL1QYRZQ=;
        b=px+MMDYbQUjaV4/WVxaMgDI/HKat43RquPWmnqzT1N7eWCbxGWNKVV2gMDdUQr8QxY
         1B6b7prxYyULL5DHnKMot008UxErB13G90Tgz1m2XiNBBPyoU4QXVs2kaXSKIngoMlxb
         vDHS1bkf90x8ZjQILXT2l78TLNZZ9Mh+fhheSTZfAO3W6HyVPWXaIjf2KLTllcavWtXl
         qk1an8k2R0bzoPahty+yEQ43jTB131nv/NRkovtO6birLaS4+SlmYkUgoD712IPYsuDe
         s0r6lIK2KvdoKixPcSdD7kmRDdn1vc+8d94dgUQMmIjTQTDf573bQ6dcY1HvxXF8lBUl
         bacA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8ogLJT4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a1si721872iod.3.2020.01.14.04.51.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 04:51:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id m2so7612979otq.3
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 04:51:14 -0800 (PST)
X-Received: by 2002:a9d:588c:: with SMTP id x12mr16233506otg.2.1579006273570;
 Tue, 14 Jan 2020 04:51:13 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNOC2PYFsE_TK2SYmKcHxyG+2arWc8x_fmeWPOMi0+ot8g@mail.gmail.com>
 <53F6B915-AC53-41BB-BF32-33732515B3A0@lca.pw>
In-Reply-To: <53F6B915-AC53-41BB-BF32-33732515B3A0@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Jan 2020 13:51:01 +0100
Message-ID: <CANpmjNMXD3Qzj748CXWtmenxx4cC3Q8Fr70L5PWNe6ZSARcZ9w@mail.gmail.com>
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Qian Cai <cai@lca.pw>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <Mark.Rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H8ogLJT4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Tue, 14 Jan 2020 at 12:08, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Jan 6, 2020, at 7:47 AM, Marco Elver <elver@google.com> wrote:
> >
> > Thanks, I'll look into KCSAN + lockdep compatibility. It's probably
> > missing some KCSAN_SANITIZE :=3D n in some Makefile.
>
> Can I have a update on fixing this? It looks like more of a problem that =
kcsan_setup_watchpoint() will disable IRQs and then dive into the page allo=
cator where it would complain because it might sleep.

KCSAN does *not* keep IRQs disabled (we have a clear irqsave / restore
pair kcsan_setup_watchpoint).

If you look closer at the warning you sent in this thread, the warning
is not generated because IRQs are off when it wants to sleep, but
rather because IRQs are enabled but IRQ tracing state is inconsistent:
"DEBUG_LOCKS_WARN_ON(!current->hardirqs_enabled)" in lockdep checks
that if IRQs are enabled, the trace state matches. These are only
checked with LOCKDEP_DEBUG and TRACE_IRQFLAGS.

In other words, IRQ trace flags got corrupted somewhere. AFAIK, this
problem here is only relevant with TRACE_IRQFLAGS -- again, it is
clear that IRQs are enabled but the IRQ tracing logic somehow ended up
corrupting hardirqs_enabled (TRACE_IRQFLAGS).

I believe this patch will take care of this issue:
http://lkml.kernel.org/r/20200114124919.11891-1-elver@google.com

Thanks,
-- Marco

> BTW, I saw Paul sent a pull request for 5.6 but it is ugly to have everyb=
ody could trigger a deadlock (sleep function called in atomic context) like=
 this during boot once this hits the mainline not to mention about only rec=
ently it is possible to test this feature (thanks to warning ratelimit) wit=
h the existing debugging options because it was unable to boot due to the b=
rokenness with debug_pagealloc as mentioned in this thread, so this does so=
unds like it needs more soak time for the mainline to me.
>
> 0000000000000400
> [   13.416814][    T1] Call Trace:
> [   13.416814][    T1]  lock_is_held_type+0x66/0x160
> [   13.416814][    T1]  ___might_sleep+0xc1/0x1d0
> [   13.416814][    T1]  __might_sleep+0x5b/0xa0
> [   13.416814][    T1]  slab_pre_alloc_hook+0x7b/0xa0
> [   13.416814][    T1]  __kmalloc_node+0x60/0x300
> [   13.416814   T1]  ? alloc_cpumask_var_node+0x44/0x70
> [   13.416814][    T1]  ? topology_phys_to_logical_die+0x7e/0x180
> [   13.416814][    T1]  alloc_cpumask_var_node+0x44/0x70
> [   13.416814][    T1]  zalloc_cpumask_var+0x2a/0x40
> [   13.416814][    T1]  native_smp_prepare_cpus+0x246/0x425
> [   13.416814][    T1]  kernel_init_freeable+0x1b8/0x496
> [   13.416814][    T1]  ? rest_init+0x381/0x381
> [   13.416814][    T1]  kernel_init+0x18/0x17f
> [   13.416814][    T1]  ? rest_init+0x381/0x381
> [   13.416814][    T1]  ret_from_fork+0x3a/0x50
> [   13.416814][    T1] irq event stamp: 910
> [   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f=
3>] _raw_write_unlock_irqrestore+0x53/0x57
> [   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba7=
6>] kcsan_setup_watchpoint+0x96/0x460
> [   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>=
] copy_process+0x11fa/0x34f0
> [   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>=
] 0x0
> [   13.416814][    T1] ---[ end trace 7d1df66da055aa92 ]---
> [   13.416814][    T1] possible reason: unannotated irqs-on.
> [   13.416814][ent stamp: 910
> [   13.416814][    T1] hardirqs last  enabled at (909): [<ffffffff8d1240f=
3>] _raw_write_unlock_irqrestore+0x53/0x57
> [   13.416814][    T1] hardirqs last disabled at (910): [<ffffffff8c8bba7=
6>] kcsan_setup_watchpoint+0x96/0x460
> [   13.416814][    T1] softirqs last  enabled at (0): [<ffffffff8c6b697a>=
] copy_process+0x11fa/0x34f0
> [   13.416814][    T1] softirqs last disabled at (0): [<0000000000000000>=
] 0x0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMXD3Qzj748CXWtmenxx4cC3Q8Fr70L5PWNe6ZSARcZ9w%40mail.gmail.=
com.
