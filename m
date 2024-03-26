Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBZW6ROYAMGQEUM4WLZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A58F88C80C
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 16:53:12 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4148b739698sf8307315e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 08:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711468391; cv=pass;
        d=google.com; s=arc-20160816;
        b=KvHmwTQWelTLzBkjuFvP/PzWEfACCwtN9/hvq8U2w+EwcaByb59LHHq4jvhG81O1Fv
         uKiYFwez49Vgm3AhBXKyOOYHv5pg5HY/r7WgxC9rabLQ4EZSqLWgqiLzcnDwqjcvSMDE
         fjWgHp+53wf9lBgoDx4j0HmqqY0LEDQoox4NaS4QR7b2WTwStpr8QraEF01dGousPL0f
         TYNL5pL00khQp30+/UyzLwXMwL0O+RS8e5HMfJrh4eap1OHPMfOxWl+MGonqZfpmqbjz
         Dq6TJYL2PPJ/Szzr4xZ+/4855giID/XDVuMOF4dV0C2aQNcOzuHwhb7CcI6kiUPNTYj/
         n7eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kLY4/dAA6IRcEtL5iPpBi/x3geMT6yz7X/EJyh1SAKk=;
        fh=fndnz/4zfl8aJk+pKqVvr8cdMlu4T/z8bgDCjXbS1K0=;
        b=h1Tr78FjAweCiZY9LNnDsxTs9ZN/GvBeMFrkUe06hx/N46s/EBGhV76ybDjZXXLMFh
         7RGtDVtrFD8BeltfiMtWChme3SFzHiR5Cg453odvQC6ClzZJ2KQWXIeVcHVG4tTd3gku
         5v700pAwRVANDdJOAWLb7qb/eD/5RIn4jO5FlOg2pr9bQuhBt5KiC8KovAd/44agvaGe
         QH2fws/Oh1609M39XJYkoiMUKbpOflKFcwxJPsRFto0TkuXbnt+Cl71OEJHvrLEx+a9f
         rHsLgH7mNXt3WAwx6H05A7ZKKlVWLSk6CDrXbIfKjzPfkBMyKAEawyomyzzK4pbfJnEE
         C2Lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=bZhX3a6w;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711468391; x=1712073191; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kLY4/dAA6IRcEtL5iPpBi/x3geMT6yz7X/EJyh1SAKk=;
        b=jn0LkFHXEX2XexRZf613T6Y20iXmRH4T9NWGaPK8bdiYsA4NmjUZ3hjRuT2/O5MJRf
         ZhlZdBqWpZU/P6CeTC1Ixg7Obw0A9J1/xSX1izfU5qexmcc+QeB5ft3p3bSyArXrM9tU
         MLmzd3K2V0ZM2HIciT1XDC5KYZDAE/K2dRmbD94bz7W1pyvP1+JoJdZtHwIR2cCCotDE
         HhfTdXkXBJte3+KIRDCHUz+KbYJaCSTaoO3IAvM8toQMHAL6XP8gNteoiknaQ3m2P9Lc
         fRx+h5VHkiLULwSxCiMnxegAvJ0z9uZvEkRjK2vgvV9taAC2iUfFOv6MHqnXYnEdwPoE
         BoQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711468391; x=1712073191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kLY4/dAA6IRcEtL5iPpBi/x3geMT6yz7X/EJyh1SAKk=;
        b=fzWd/bM9Rb7TpomDhCUjh9qjuMBVfZF9gGsys/frInup6oaLHyQtuujPLij4Lc4M2j
         JgUtD0YF+Y+E6KlRINz5xDMYVKzSZq7ZNiPu6iGQDqErXih2Y64RneFtuDB9hLJjFgmb
         bnFAkQg9sDoM/LnEexGxrGxwBl8xlp4B3lplR19IKwzIQP65LAbJkCmWKOHsv9iL1W7/
         LPbF+06ITRWxFWwLEn/KTlbpR33oF60awFP9QRFBcEg8AvYR639bMpUUoAIpMaZ0II8p
         F4wtB+1e/LJTpYDWGcGTm+YnrqkimLL4rcg3mciBvhVros/PeeL5hki1otcis9m8gNAn
         U5Pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTdqm2z1BjSXQ7fmImHquLZgQiYzqcJYH8LCqvtU6mptWPZKdQvIxkFw25fucLCV94N4WGRMjqOZaSP4QaTHxin5A+SzoDtA==
X-Gm-Message-State: AOJu0YwIXQzn77nwIYAxMPlpEf7vb6ZQ3W1E+xd/UvWLr2XO+P6l9ggJ
	lhEQfrpBYrqmoDgSKNjv29p2He3y5fTAADRjLYfsX+FwSL8gWNm7
X-Google-Smtp-Source: AGHT+IGAJH8wfJc4L0Zc6blEeJPf+TWJZvEEW8zjnibtrfRXIvEScSzdLunBrWm34YsxbxguF46mOg==
X-Received: by 2002:a05:600c:3ca7:b0:414:d95:cc47 with SMTP id bg39-20020a05600c3ca700b004140d95cc47mr8245156wmb.30.1711468390609;
        Tue, 26 Mar 2024 08:53:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:54ea:b0:414:81f6:d201 with SMTP id
 jb10-20020a05600c54ea00b0041481f6d201ls1516078wmb.0.-pod-prod-08-eu; Tue, 26
 Mar 2024 08:53:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQTdHrhhyHn3sUUT4FEgDYHSTpdm1jERqv8Eac2F3FPLxBZDepQfrSLuVk1xS5uRH6zXrvnclaQ0fyrqJTYrUUjYxOr6eZ8jjk9Q==
X-Received: by 2002:a05:600c:4e8f:b0:414:8ce5:9e47 with SMTP id f15-20020a05600c4e8f00b004148ce59e47mr2432372wmq.14.1711468388811;
        Tue, 26 Mar 2024 08:53:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711468388; cv=none;
        d=google.com; s=arc-20160816;
        b=GvbF9WLO4JWfnuJ4gXDyyz0fZIpd9tvEl/kn0m2mY6V1Eh1fQObLIpHp+Ue6sjzlF7
         L+bbm/uiJ/6DLIY4ao86nO2su9G+MFu3oK7+es5qwgjsJVti+Pltn0b96snR2jKbH26a
         XkQH1TPYuno4gOe2qsIOsjkLU63/YSJeV4M0uv04XD1oGHxBMiZhuwIQ1MS/bIkZ2v2P
         Y/ufYpRMi8k0/5RfcCHyHZBExQXtBzDv7+1PAv7CcYc0+gxWbXN9kH7rQ1phZT+0LzT8
         g4B6sWpmjhgQZuplBWxjB3UfkcVz4MnwWrL/s3+6ZLxZ84r9Sr6x7l4IzMiydvrifH+W
         6FlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TcZAuev01yKZaJPvDyAUZzPEAjCX2jHAgYb7hloP0qg=;
        fh=GCe9F/SJsCQDVIQkIctqdfDW0R7HEzQtn00OOTEYumU=;
        b=gnW1kN99J9xcXPGNCfVLOuithB0cH7is4msRiImUDCvUJ66OZdvvSf9JEy+GEbVcZ+
         iglAPyYFUqtDxRQ7xFm7fVM0ySRlgVLOguKpu74HGOpgng6DdyAYzXnCmD2tEiZC/Yah
         VbEvOlOzOgcmFnP4B8AC88beNW4tKk832q/jeP206nIRbl9F8gAiNaXTwlOd1qTtyIl/
         sldqkg5Z1p5Z3Hrzye91WJXMsNbeG0cyjljRMMeiDLq+74MxO/FROpNgUt9ZBW7p9wx1
         +36IGIC7F8NNX56s3LxFXyp1oEUxXOR88lkXO52AmR53ixx7jYYGNyHNXp4gbSPFi1kU
         b7nQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=bZhX3a6w;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id e4-20020a05600c4e4400b004132f97fa43si142178wmq.0.2024.03.26.08.53.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 08:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id C6E0E40E02A6;
	Tue, 26 Mar 2024 15:53:07 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id Xxzb6lMyPGkW; Tue, 26 Mar 2024 15:53:04 +0000 (UTC)
Received: from zn.tnic (p5de8ecf7.dip0.t-ipconnect.de [93.232.236.247])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 8004540E024C;
	Tue, 26 Mar 2024 15:52:53 +0000 (UTC)
Date: Tue, 26 Mar 2024 16:52:47 +0100
From: Borislav Petkov <bp@alien8.de>
To: Nikolay Borisov <nik.borisov@suse.com>
Cc: Paul Menzel <pmenzel@molgen.mpg.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: Unpatched return thunk in use. This should not happen!
Message-ID: <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=bZhX3a6w;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Tue, Mar 26, 2024 at 04:08:32PM +0200, Nikolay Borisov wrote:
> So the problem happens when KCSAN=y CONFIG_CONSTRUCTORS is also enabled and
> this results in an indirect call in do_mod_ctors():
> 
>    mod->ctors[i]();
> 
> 
> When KCSAN is disabled, do_mod_ctors is empty, hence the warning is not
> printed.

Yeah, KCSAN is doing something weird. I was able to stop the guest when
the warning fires. Here's what I see:

The callstack when it fires:

#0  warn_thunk_thunk () at arch/x86/entry/entry.S:48
#1  0xffffffff811a98f9 in do_mod_ctors (mod=0xffffffffa00052c0) at kernel/module/main.c:2462
#2  do_init_module (mod=mod@entry=0xffffffffa00052c0) at kernel/module/main.c:2535
#3  0xffffffff811ad2e1 in load_module (info=info@entry=0xffffc900004c7dd0, uargs=uargs@entry=0x564c103dd4a0 "", flags=flags@entry=0) at kernel/module/main.c:3001
#4  0xffffffff811ad8ef in init_module_from_file (f=f@entry=0xffff8880151c5d00, uargs=uargs@entry=0x564c103dd4a0 "", flags=flags@entry=0) at kernel/module/main.c:3168
#5  0xffffffff811adade in idempotent_init_module (f=f@entry=0xffff8880151c5d00, uargs=uargs@entry=0x564c103dd4a0 "", flags=flags@entry=0) at kernel/module/main.c:3185
#6  0xffffffff811adec9 in __do_sys_finit_module (flags=0, uargs=0x564c103dd4a0 "", fd=3) at kernel/module/main.c:3206
#7  __se_sys_finit_module (flags=<optimized out>, uargs=94884689990816, fd=3) at kernel/module/main.c:3189
#8  __x64_sys_finit_module (regs=<optimized out>) at kernel/module/main.c:3189
#9  0xffffffff81fccdff in do_syscall_x64 (nr=<optimized out>, regs=0xffffc900004c7f58) at arch/x86/entry/common.c:52
#10 do_syscall_64 (regs=0xffffc900004c7f58, nr=<optimized out>) at arch/x86/entry/common.c:83
#11 0xffffffff82000126 in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:120
#12 0x0000000000000000 in ?? ()

Now, when we look at frame #1:

ffffffff811a9800 <do_init_module>:
ffffffff811a9800:       e8 bb 36 ee ff          call   ffffffff8108cec0 <__fentry__>
ffffffff811a9805:       41 57                   push   %r15
ffffffff811a9807:       41 56                   push   %r14
ffffffff811a9809:       41 55                   push   %r13
ffffffff811a980b:       41 54                   push   %r12
ffffffff811a980d:       55                      push   %rbp
ffffffff811a980e:       53                      push   %rbx
ffffffff811a980f:       48 89 fb                mov    %rdi,%rbx
ffffffff811a9812:       48 c7 c7 c8 9f 6a 82    mov    $0xffffffff826a9fc8,%rdi
ffffffff811a9819:       48 83 ec 08             sub    $0x8,%rsp
ffffffff811a981d:       e8 5e 51 0d 00          call   ffffffff8127e980 <__tsan_read8>
ffffffff811a9822:       48 8b 3d 9f 07 50 01    mov    0x150079f(%rip),%rdi        # ffffffff826a9fc8 <kmalloc_caches+0x28>

...

ffffffff811a98ec:       e8 8f 50 0d 00          call   ffffffff8127e980 <__tsan_read8>
ffffffff811a98f1:       49 8b 07                mov    (%r15),%rax
ffffffff811a98f4:       e8 27 d1 e3 00          call   ffffffff81fe6a20 <__x86_indirect_thunk_array>
ffffffff811a98f9:       4c 89 ef                mov    %r13,%rdi

there's that call to the indirect array. Which is in the static kernel image:

ffffffff81fe6a20 <__x86_indirect_thunk_array>:
ffffffff81fe6a20:       e8 01 00 00 00          call   ffffffff81fe6a26 <__x86_indirect_thunk_array+0x6>
ffffffff81fe6a25:       cc                      int3
ffffffff81fe6a26:       48 89 04 24             mov    %rax,(%rsp)
ffffffff81fe6a2a:       e9 b1 07 00 00          jmp    ffffffff81fe71e0 <__x86_return_thunk>

where you'd think, ah, yes, that's why it fires.

BUT! The live kernel image in gdb looks like this:

Dump of assembler code for function __x86_indirect_thunk_array:
   0xffffffff81fe6a20 <+0>:     call   0xffffffff81fe6a26 <__x86_indirect_thunk_array+6>
   0xffffffff81fe6a25 <+5>:     int3 
   0xffffffff81fe6a26 <+6>:     mov    %rax,(%rsp)
   0xffffffff81fe6a2a <+10>:    jmp    0xffffffff81fe70a0 <srso_return_thunk>

so the right thunk is already there!

And yet, the warning still fired.

I need to singlestep this whole loading bit more carefully.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240326155247.GJZgLvT_AZi3XPPpBM%40fat_crate.local.
