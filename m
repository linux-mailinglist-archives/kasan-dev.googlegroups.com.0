Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBE4N37FQMGQEX4TRTQY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sCSnOJTGd2nckgEAu9opvQ
	(envelope-from <kasan-dev+bncBCP4ZTXNRIFBBE4N37FQMGQEX4TRTQY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:55:00 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8851D8CCB5
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:55:00 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-6580eb3fe28sf4937092a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 11:55:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769457300; cv=pass;
        d=google.com; s=arc-20240605;
        b=hil6Q/2XkR6Pn8Y+jZeZXyOWR9/H+Y7MKuQC2tU6hNT4EZnCVkDvy45bR7WgHi/ZG0
         GkhN2y/Qs/cWBTi1FNoLvmBe5N5HcsRpQWDG3KZG0NzdOysXMWQiqL4iCKWjTjdT0Q66
         OfywRmgkBvtuf3VrbDzdQ7NA0JuV2S/VzVmDwmjIoFE+TX0G/gGkytqk+1OMv+Gz45ph
         ImEHXfSwmolxYQ1T2UvsDOhuki2HF+zQo8xZTqr3JUFFPT+cPIsaTvBT7hQd4N7v4qRI
         X843fOugz58HMeVQz02duxDK3HsLvc9E5XlqliWcO9QbrXq/D7XhKk/cN9ppVPZgIEeF
         PYgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7SjFfEV/fG7kN6Z1K4C/fpINAoUR1sEFpBa9KQqwEmI=;
        fh=LnkaH8aDcCPrKPOrY6YkNk98cIVPMClL4lc9RtxTLHY=;
        b=ke1/r18B08VR1iKjqB/sl0wZMCjnOygVRRRYKpBO8sDSR07xucupv9Yo2qanSrsjg4
         gq0mjMPLWZ8yXYWGD32AUpCkjUFY3BlU7ACpEA0QIx/Q7WFaO1NIpQ62p2YyShFl/ljH
         mXm+r/c1gnG2bs40gRByfxnowwfsfmtu64QDTip3LVT4SmPActTRmp3voAA0+Rv/Tgn2
         ULbNWvDDiT57ZMKhoQRNDN0//62hg8Lx7qniE0bh+KNkttX0t5CxQ8SsBoFOLxFUoUvy
         r2QjtXxYOf0NSeQHWfCz4N34BOQaFz6cwwy+IB2qhE3tTPLACxccY9hF2VctPiEr2W7M
         Bo4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=gD0pJxOI;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769457300; x=1770062100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7SjFfEV/fG7kN6Z1K4C/fpINAoUR1sEFpBa9KQqwEmI=;
        b=ZQH9hZh6TG+HR94i9e+c2qfgA3tEjG9evmfRPOvhWH98ih3aGDZBmocBdfAWAdAUbG
         +zLCuom4X8Z5j/tv3UjSPHgMmMC3nEB+6tcRBQEPuX60jnHQiVye1ax2s0e9heonEZZl
         GjP6OuROuJZIxY/9B4K0ws5FZs6uD9XOFL7H1iNqwJ3eT8lUoxxk2UaV8Uop9a/KirXg
         2wEGlCIdVP0RLXfrzVY/Tkw8D6CC90BXqJ/GXosCqsCtN0ALkEgFn83OkzqB6tDrIkZ2
         JjfYC5EpEEiZiZEWABdFypyunEB7d9fBqXCP4uf5sPd+DHIxfULXvni/4oYBRlOYpzDq
         bsAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769457300; x=1770062100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7SjFfEV/fG7kN6Z1K4C/fpINAoUR1sEFpBa9KQqwEmI=;
        b=o6NF5x8/FtYhhZnYd3Y9zMqu2uW0KiJihxVafkBvi+GqN59VBHDaT2yts/p0Sp8siz
         EzTt3SYkJ3YSi3BaNigu1kykcTaF5uXEcd7iJSljUa6Io/iUmmGMOSlVIGwxnswRtRLq
         StP43bWtpJJQC3lZSJRwV0UdAmyk/4IPsdbGW+0UeBytymAUCx83ZZz5R391EABRFErP
         fq4RcyKukdYksunVP1Eh12AzLDN/nr3lIdxrtbRuo0R7Mmy2+w3vPd8SWjiPUoYRQ3ic
         QGsGSCFO/9jbjopdxMFlBuvcOfHbfn1PVZZKo6AN4tRkJn4rLX3gOflq5rsGCjkZGKzA
         0SUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVVnFOztnrTVo8jNQjFUgUPri86cY5j1a6rx8pMOkVthYm4ZCZx/imol7l3ScXshGpNZ9jfQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbK0kjzFdFLsQ3wdyX7eqc6WuReUm9qk55sJK30Vu7cBW9vSqF
	rSYO/jhz619ssokXFmxhhL8QV7T1yTVBIKpTA6/16dO3CQR9hpdXWPvv
X-Received: by 2002:a05:6402:f19:b0:658:132f:71ee with SMTP id 4fb4d7f45d1cf-65870699cf0mr2646172a12.7.1769457299809;
        Mon, 26 Jan 2026 11:54:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Flqr3b+Id+lyiZqJVyk35ybjLCG0GG0ljoUNvQu/00BA=="
Received: by 2002:aa7:c916:0:b0:658:1d2f:b8d6 with SMTP id 4fb4d7f45d1cf-65832d62946ls4461591a12.2.-pod-prod-09-eu;
 Mon, 26 Jan 2026 11:54:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVfDJtYKw1ggG9q7IHUiD7AY5gr3kG+kmXFaA+YTEdFY3KubYoJis08dC+/u/EFBLYoItTnIsr98vg=@googlegroups.com
X-Received: by 2002:a17:906:f584:b0:b87:28f7:d3b6 with SMTP id a640c23a62f3a-b8d20deb745mr378850266b.19.1769457297572;
        Mon, 26 Jan 2026 11:54:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769457297; cv=none;
        d=google.com; s=arc-20240605;
        b=gNEeHFGKEYbV2zxdxvoeXVKh+ThuMmHsxajrQvh8e7DrAdcrYgrdNvD3ejN1RCNhuN
         Fo5ht3RwAExl1ly50urL7DrZ/OAKZkpc4j05+LNEjDUXIXWe0DTtoKDCDfllmCa67TV7
         NEX6OurFBhpqGt4T3TjYH2GqAoa4xBCEJm8xW12Mg7EbY1KiRtEfwDKf6YK+haMhvVrS
         cm+bSjLbWuRbTb64L8klSntPLj9BK1urooikJNlEUO2QmI+a0JZp7a6PEcTufUMv5duI
         H2Wa60z7aGT7PxD1skPC9uZ1J1m+x8nWfZTLJDEkICN6Lewikn4IO3fQuVi6vrd4CUHd
         jW1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=So6sh29yhd8J8wOhqQLfrf2g3bYdpmdSFE95zpdXVL8=;
        fh=yfT/eAGXU0Pkmn25jGP3oJPJDBbpky2pZdGEsq8S6NM=;
        b=V0tlCVY+6UQErYeZaqOB+L4xuFZM8yvlWprZ7vA0g+zmQesD1iUM1KUQnw1e0k0OeX
         5m7JAhOuami/P5Jsp8LbSLBg8ozitjfGJ00ltxqn0Rtk0ZuJgWSByTA6DLtTXWohVdiJ
         M5ZluznfZ02Efygb1HWsGjbrBuz8I1sOxRNP4qFIVlGjTZwiGla8XY4xkUd6JD7Lnhmj
         cg86aF2yVMwYcuyCqx+2lkHLQZWF7FPPdZyB2ZJrEHRs4sZfRV0PFGidtOIVKb/0Y2Vb
         xvgS8gtlmhc0V1xLAUoVoErlKIHg1L7XDZKJ/4XICR9aUkK/LbeMyJK4P+KsXlfylwyf
         twGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=gD0pJxOI;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b885b67f781si25765066b.2.2026.01.26.11.54.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 11:54:57 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 91B1F40E01A9;
	Mon, 26 Jan 2026 19:54:56 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id 1KmPzUstV6f3; Mon, 26 Jan 2026 19:54:52 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 1291C40E01AB;
	Mon, 26 Jan 2026 19:54:38 +0000 (UTC)
Date: Mon, 26 Jan 2026 20:54:31 +0100
From: Borislav Petkov <bp@alien8.de>
To: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
Message-ID: <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=gD0pJxOI;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[alien8.de : SPF not aligned (strict), DKIM not aligned (strict),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	TAGGED_FROM(0.00)[bncBCP4ZTXNRIFBBE4N37FQMGQEX4TRTQY];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[bp@alien8.de,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 8851D8CCB5
X-Rspamd-Action: no action

On Tue, Jan 27, 2026 at 04:07:04AM +0900, Ryusuke Konishi wrote:
> Hi All,
> 
> I am reporting a boot regression in v6.19-rc7 on an x86_32
> environment. The kernel hangs immediately after "Booting the kernel"
> and does not produce any early console output.
> 
> A git bisect identified the following commit as the first bad commit:
> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")

I can confirm the same - my 32-bit laptop experiences the same. The guest
splat looks like this:

[    0.173437] rcu: srcu_init: Setting srcu_struct sizes based on contention.
[    0.175172] ------------[ cut here ]------------
[    0.176066] kernel BUG at arch/x86/mm/physaddr.c:70!
[    0.177037] Oops: invalid opcode: 0000 [#1] SMP
[    0.177914] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.19.0-rc7+ #1 PREEMPT(full) 
[    0.179509] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[    0.181363] EIP: __phys_addr+0x78/0x90
[    0.182089] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
[    0.185723] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
[    0.186972] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
[    0.188182] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00210086
[    0.189503] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
[    0.191045] Call Trace:
[    0.191518]  kfence_init+0x3a/0x94
[    0.192177]  start_kernel+0x4ea/0x62c
[    0.192894]  i386_start_kernel+0x65/0x68
[    0.193653]  startup_32_smp+0x151/0x154
[    0.194397] Modules linked in:
[    0.194987] ---[ end trace 0000000000000000 ]---
[    0.195879] EIP: __phys_addr+0x78/0x90
[    0.196610] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
[    0.200231] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
[    0.201452] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
[    0.202693] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00210086
[    0.204011] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
[    0.205235] Kernel panic - not syncing: Attempted to kill the idle task!
[    0.206897] ---[ end Kernel panic - not syncing: Attempted to: kill the idle task! ]---

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126195431.GDaXfGd9cSwoH2O52r%40fat_crate.local.
