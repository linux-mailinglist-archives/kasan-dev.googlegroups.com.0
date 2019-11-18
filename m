Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBXMUZPXAKGQEUX7ZPJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9011A100967
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 17:44:13 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id f26sf11742524edy.16
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 08:44:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574095453; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+CWHF1ZZxaMA95EdO711yD8/a9atGEpuyDiGWnm1J5cp1K6twCD6bvWi/dkBLz87V
         ziaKoO+KbIdShpfueBeDZz+6oIymElrI6Z99ynJvby/o9xcbMZFP0MEa4W2pdiqMWCXc
         bZFqZ+rx23O3N4e6OkMTOPCiaMbJ4GwpPbqViblVEb7f8aXG9UFOscx/K60gEptRgP3T
         V4pgwffUJj3x1IN8yCMFcFh4wBna3vB2Hywjd84YjNrYwf0wVxqR9TbiIPissJx/HurC
         QHVaVXbIWQiQQuFbrWM6kBTaaRFVF9Sq5sSdF3Q4kzt01zJgbJmYNTkjCMyKLTm7/KFk
         Lgkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gVGk7pO/Ik/0JMdQEBb+8a2YP+YoH9wdRObNvVzBlJw=;
        b=akp2aZG4A8H4yA0u28nEXNUOP1vc2fMY8jDv4U9Vqm3PnMyuqEZI5M/JZ8BbAla827
         dcE7lgHENZbKiogDa0Zom1QEcncy4ybpHAScmughrwITsHY0IGkeruPn1fP6cg+OvOl3
         b3L1B4IH8EVIJiOjqTGGnp0mNcWpbH32xMGBVEpAwS/KsAYC+hfuwZlvQk6NcEtq1eeZ
         BY8GsCqmI7wStVy0xJBPOfp+YzHLI55gwVsriadQuXSy5i4RDRxPZtVOiDEgVqEtZ7Ao
         2A3enJQEqtRWLxXsXrMecY0AbB03dBP7EaGenIze21/6+k/K/BoOOetBmKysoJ/awxWS
         AhgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=nX8hO1n9;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gVGk7pO/Ik/0JMdQEBb+8a2YP+YoH9wdRObNvVzBlJw=;
        b=EHtHsx6MNjfWpmE9eqSjj67ITHfbNxzoYzMY2N4aN6fYxl0vdF7bWp/nUcG+K0xvMK
         doo7Zcgkwm3JlV5xJvXj40RZwo0qFX8cMWyhUqsH7wCGOzYM6MclzrrOEydV4+ztVfZ7
         2U5ZqEkrSvFzN4lynL27RQnMdTMJSIn9L1NBlsGDzZ3vPXXo/Jvo1LBHVbQiEAK9VgkS
         uxYqKJzqNcby9AT2d5uW5IoHHMDYYmHtiSM46V+P4+/COvgRb9dIvn0o6SL9oSxjeNMf
         FQKB+a8CEXm8TCsAmQh9xzQEhyhac+51cb+4lOaFpB3o66bxgZQF44gyyBOBkSm9Y+Gi
         nkHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gVGk7pO/Ik/0JMdQEBb+8a2YP+YoH9wdRObNvVzBlJw=;
        b=GAWi3c/Hh2Aq8b8QdwarqGa3W/+5yuV1lCwN5oH2CzKWpOlyUmB8fp/dZ5FzCDpjmd
         nlpVHp4q949ytRFawlptJpZqMKRcLbDPYrfS8zsS10I4CIEUSDWvFJnMxPRAIjzlgGz+
         PO5elGyDL4EhW5LG005ikleZLzPUuzU9Yye3uqpYpYmGUgo++PeBdfoUfiUAG/uF91cr
         c42yj1rPCL9MmSlHTB+0/G1XJ4hYlXQaG0YXbzYPswv/3paGKHPeNzIRb7AwfD3ZpIoJ
         5HAkhnpcvqJ4dEk4NoFhpu9dW03NfxpVfhPrTfT0FVpq/eLk3PZ/PUIOSuHncjs+FfN1
         XF6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW2Gx2jGll9zB6fZKimOXPvnXZ4x3ROjjOET7dMD2yUF8EUOmwe
	PqetlHAvXgTrjt/6arHrmRw=
X-Google-Smtp-Source: APXvYqzTMMAyeD5endSkt04JN/ymkty0w5mbj9PH8JXyiY8XqVqTVXzYHnbqhsESol/l/74nq8hhZQ==
X-Received: by 2002:a17:906:3f8a:: with SMTP id b10mr27488409ejj.315.1574095453274;
        Mon, 18 Nov 2019 08:44:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2493:: with SMTP id e19ls5813584ejb.4.gmail; Mon, 18
 Nov 2019 08:44:12 -0800 (PST)
X-Received: by 2002:a17:906:f108:: with SMTP id gv8mr28618851ejb.180.1574095452793;
        Mon, 18 Nov 2019 08:44:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574095452; cv=none;
        d=google.com; s=arc-20160816;
        b=OXSkDlrmg8DHE8yv4Lm4aQlQokz8BHZJPrYFb9Kde8fqd/8Bw5U73TagPQnB+AqrDq
         lMlr67uSD3MM8q0KS9gKkK+M2/wUE6koDDl0WxoNR16Pz9CiaLs2+UsYXsCNl9Az+Jwu
         /H1J80b2pq3MyGqKwP03MID1mjlj1fBUU9ktvqebJLlBProaG51olyxTJ/a/cjXla8rx
         ig21zhM5zMEbZTAWpxDk47gSlP2dYIzEmPwcrgZA7oflWhfj6VfQhee2JRyZKpNEhaNL
         F8tzH8gPPSfBEEKFvYUG0LJA627HoxS4OjP3qHGNpmBUEa/ymJsw2F3eGx7oXDIUSxdy
         S3VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/12TPIe9NGWwR5n7WZI8L7PfOwYBBYIH7pXbgDhu9SQ=;
        b=xLser4qNt/HHkXHmayaVA6HzL4vHaU7+5tp0D+x2uVWleZha0RxDSE+S4Stty+aqRI
         TymvvXcVNh9J1zUAb36yFyVXDbkDd1WEaHP02aAwjYHnaxRrDSSSkjK+qjwF9worPI8c
         GDLEMreT96I61QrigSrQSuro7MUSU+wTWr05wS/xo+j7m95wVIUInhO2kmAmAj4rM5j4
         kMNqbWYComqXdICA7/TF5sOy2xHmnvYkjuE4UVaXmXnLTQRPwfhIolYQxAuLnipr5pdq
         05fggxuPejcYzYZGt1Nfgy/UgJn89Gybi6NMC+YuF8BvHZDgBFFKRk9VdwXEotbIz0HU
         ej1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=nX8hO1n9;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id v57si1545927edc.3.2019.11.18.08.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Nov 2019 08:44:12 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F27B5003D22FC05E431AFF8.dip0.t-ipconnect.de [IPv6:2003:ec:2f27:b500:3d22:fc05:e431:aff8])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 30B521EC0BF8;
	Mon, 18 Nov 2019 17:44:12 +0100 (CET)
Date: Mon, 18 Nov 2019 17:44:07 +0100
From: Borislav Petkov <bp@alien8.de>
To: Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191118164407.GH6363@zn.tnic>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
 <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
 <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=nX8hO1n9;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
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

On Mon, Nov 18, 2019 at 05:29:42PM +0100, Dmitry Vyukov wrote:
> > And of not having a standard way to signal "this line starts something
> > that should be reported as a bug"? Maybe as a longer-term idea, it'd
> > help to have some sort of extra prefix byte that the kernel can print
> > to say "here comes a bug report, first line should be the subject", or
> > something like that, similar to how we have loglevels...
> 
> This would be great.
> Also a way to denote crash end.
> However we have lots of special logic for subjects, not sure if kernel
> could provide good subject:
> https://github.com/google/syzkaller/blob/1daed50ac33511e1a107228a9c3b80e5c4aebb5c/pkg/report/linux.go#L537-L1588
> Probably it could, but it won't be completely trivial. E.g. if there
> is a stall inside of a timer function, it should give the name of the
> actual timer callback as identity ("stall in timer_subsystem_foo"). Or
> for syscalls we use more disambiguation b/c "in sys_ioclt" is not much
> different than saying "there is a bug in kernel" :)

While external tools are fine and cool, they can't really block kernel
development and printk strings format is not an ABI. And yeah, we have
this discussion each time someone proposes changes to those "magic"
strings but I guess it is about time to fix this in a way that any
future changes don't break tools.

And so I like the idea of marking *only* the first splat with some small
prefix char as that first splat is the special and very important one.
I.e., the one where die_counter is 0.

So I could very well imagine something like:

...
[    2.523708] Write protecting the kernel read-only data: 16384k
[    2.524729] Freeing unused kernel image (text/rodata gap) memory: 2040K
[    2.525594] Freeing unused kernel image (rodata/data gap) memory: 368K
[    2.541414] x86/mm: Checked W+X mappings: passed, no W+X pages found.

<--- important first splat starts here:

[    2.542218] [*] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
[    2.543343] [*] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
[    2.544138] [*] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
[    2.545120] [*] RIP: 0010:kernel_init+0x58/0x107
[    2.546055] [*] Code: 48 c7 c7 e0 5c e7 81 e8 eb d2 90 ff c7 05 77 d6 95 00 02 00 00 00 e8 4e 1d a2 ff e8 69 b7 91 ff 48 b8 01 00 00 00 00 00 ff df <ff> e0 48 8b 3d fe 54 d7 00 48 85 ff 74 22 e8 76 93 84 ff 85 c0 89
[    2.550242] [*] RSP: 0018:ffffc90000013f50 EFLAGS: 00010246
[    2.551691] [*] RAX: dfff000000000001 RBX: ffffffff817b7ac9 RCX: 0000000000000040
[    2.553435] [*] RDX: 0000000000000030 RSI: ffff88807da2f170 RDI: 000000000002f170
[    2.555169] [*] RBP: 0000000000000000 R08: 00000000000001a6 R09: 00000000ad55ad55
[    2.556393] [*] R10: 0000000000000000 R11: 0000000000000002 R12: 0000000000000000
[    2.557268] [*] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[    2.558417] [*] FS:  0000000000000000(0000) GS:ffff88807da00000(0000) knlGS:0000000000000000
[    2.559370] [*] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    2.560138] [*] CR2: 0000000000000000 CR3: 0000000002009000 CR4: 00000000003406f0
[    2.561013] [*] Call Trace:
[    2.561506] [*]  ret_from_fork+0x22/0x40
[    2.562080] [*] Modules linked in:
[    2.583706] [*] ---[ end trace 8ceb5a62d3ebbfa6 ]---
[    2.584384] [*] RIP: 0010:kernel_init+0x58/0x107
[    2.584999] [*] Code: 48 c7 c7 e0 5c e7 81 e8 eb d2 90 ff c7 05 77 d6 95 00 02 00 00 00 e8 4e 1d a2 ff e8 69 b7 91 ff 48 b8 01 00 00 00 00 00 ff df <ff> e0 48 8b 3d fe 54 d7 00 48 85 ff 74 22 e8 76 93 84 ff 85 c0 89
[    2.591746] [*] RSP: 0018:ffffc90000013f50 EFLAGS: 00010246
[    2.593175] [*] RAX: dfff000000000001 RBX: ffffffff817b7ac9 RCX: 0000000000000040
[    2.594892] [*] RDX: 0000000000000030 RSI: ffff88807da2f170 RDI: 000000000002f170
[    2.599706] [*] RBP: 0000000000000000 R08: 00000000000001a6 R09: 00000000ad55ad55
[    2.600585] [*] R10: 0000000000000000 R11: 0000000000000002 R12: 0000000000000000
[    2.601433] [*] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[    2.602283] [*] FS:  0000000000000000(0000) GS:ffff88807da00000(0000) knlGS:0000000000000000
[    2.603207] [*] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    2.607706] [*] CR2: 0000000000000000 CR3: 0000000002009000 CR4: 00000000003406f0
[    2.608565] [*] Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
[    2.609600] [*] Kernel Offset: disabled
[    2.610168] [*] ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---

<--- and ends here.

to denote that first splat. And the '*' thing is just an example - it
can be any char - whatever's easier to grep for.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191118164407.GH6363%40zn.tnic.
