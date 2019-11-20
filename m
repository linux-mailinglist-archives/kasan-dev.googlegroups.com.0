Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBDGS2TXAKGQEBKG36IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D3255103926
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:52:44 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id u6sf4737379ljg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 03:52:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574250764; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRW1Ay2uYXkyYEC6y7pdjXX1/ZtZneNdQJRsabliRQgZZ9YmgTE02ZcmcxHjgUo1FM
         D6idazffpTlNK3cPS/DN9pdTlqEBI6kPHLxcSiSlXAJgTnrPlvABTFASUvkAMgKMKV1Q
         wZ8AkqR9wBzAvaqpcPjlWqy1M7lXzalUip+tM32Sry4faoYTIEfuRCw1e3kdl7VOQ80I
         T5NsYFQPkvQDZlV2MLBTDD18FVzTL6WejRKoGCjaWVXzuJIR4tOyFJwkgDIXk5WAKRNw
         mzR3/QhE2G94cCvtNvSzvt/pff71/kAlHXaognKGH5Wzrl1W802s5TkB8jIeiWG7Tcit
         2QmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=quVq+sMWqROfcpTGjGsskpPk4wxOUnjtI7tUJU4Zos0=;
        b=CEWaUNUlSVn27dN5Rn8LW/xazuqHhOmI0Fs6LUHGJoLw8Zrhw/Ts7Bt7IjxMYR9sWK
         ceov/b1V+DXTyG3Bz4rk4Z6/NU0nauNxNfzYGTuElmxI9rfrsEEd3pqxvVw93gGz7+jO
         GngwpTfQ28MbLTku0+zkUl7dnwyXQszo5hYdUuXCfo9a2UWblWStiG+7oyn4ws7S2cTX
         ZYOAnBtd66o6D9UejJRYwtwfr55PyT6MiSLOT5tpz9oS8muwnVIxNOGYaICTIPMmOszL
         l8o5oom8ZQRQ16UQk/nwfkHiWcI3O0Cg8O60NO+5o/SeNIUMtLSBr3CxGUlLkwFZET1p
         llOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="BNR/zhrD";
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=quVq+sMWqROfcpTGjGsskpPk4wxOUnjtI7tUJU4Zos0=;
        b=swVEOEr2t/JC1dhp5UGU/k2CIvvcoom2SzkDAQQsFdwNe8N8El5Y0EJ0QxmTBjGfCz
         pWAmj0sxP5zFBiQhTB2tfhXzFCuyZmxa6xaKLMK+Qwz8wPNYJi7pzpvnW7EQWQXknaPv
         hlPJRqjJ+k44GdQDWk6+QiCCdgzkha/zvBqnP7dSYq7JYKFF0vhzJZsoitPpg2B0AsKp
         XFb+JHdpsGztxXuY6JDcCpcsQ9pPvG3iAAQ+dUy7p7y5a3cqLjaHaZBVewM2oQVJI2yy
         9HHccRBOjfyk0DjA//d2yMnUzZSDRkSa8soaxwwFcdhfOrMdwDF2/NDNb1uJahHWlbjD
         /JFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=quVq+sMWqROfcpTGjGsskpPk4wxOUnjtI7tUJU4Zos0=;
        b=FmFfKSnRiSHgcYSiDcCC32t83QW58RzJuQcQpx7FKAuj04UEiiV0p8eRHH4GxmOeFv
         4uwmckVspaln1w1l9ccyo2zoQw7jHb1QJzbSfxRrFKJlzXAC1pZG6IapePzWAJYRY5WE
         eOX6TlSBjRCqfFt9NMxMnuqyGH5MmaEyEBg30AOMj4ZSrkLjqu7HxCcAfnhSsPghLKw4
         1mdAoY7LXxxHsRqrUEGRqswoBQb9qRb11vEwWUg54C75IzVSVNISp6p1fQs1naKFsQi1
         rRsBQyWVwkojn7R5XwttrHEhyK0a2vX3P+oSMKIUo9Qd1L44aBBfwqtWopyk/Mot6d9L
         TAsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXaYR333nlT9L8CsE3PvdWf5gPNBlecIlBw+SzUHMEWR1HBHsJp
	YAzo8eM2FstkLySaQ5Zt7qs=
X-Google-Smtp-Source: APXvYqxbBU9tWWa18LbzDvnhx7iM99E8GdtLYPX0o7xXNElXvfDqBgeWKhzsv8OgSTTG25z3/yhXxA==
X-Received: by 2002:a2e:85d0:: with SMTP id h16mr2444174ljj.75.1574250764360;
        Wed, 20 Nov 2019 03:52:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7719:: with SMTP id s25ls188198lfc.11.gmail; Wed, 20 Nov
 2019 03:52:43 -0800 (PST)
X-Received: by 2002:ac2:4a7c:: with SMTP id q28mr2493229lfp.172.1574250763848;
        Wed, 20 Nov 2019 03:52:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574250763; cv=none;
        d=google.com; s=arc-20160816;
        b=vLrKqsjgSGX72R/4vUiViOjA2q55OsZk5P+7WWQO6ObUoAV1JHKJhJu3K40heulwg4
         HrH19j/Y8f+w4Mkuy2A1tJLKj7I/PLbvaeUsZ27OQIwFqQxqPBBoOtiF/VXX8jf/O4ab
         LB0sBn9n9jBrl53YFY6MFJwqnZ/T768Gz7hDndamoCDZAwZTWgvVu0GD9k0n6Q6RI9lD
         nWTJMSoNQGUmlEchKm9pL7C1kkqDWjNunppexZfbUIP1RLiGdtvLBT5BXk3J4lpuTMKb
         b8zCzLxGdzeb5vtCFN36ri/mE/pxvqv1qFvYsg23VyWVDFucf1jrnK7sqW/J9KtehMNS
         1ZSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RLkoxGNHE0MpSItY0sfwHmmrOz4TIxYH/DdJiVvVqKA=;
        b=tcw1U4AIzKnJL4FFytXl9U1GN5LSwaY1+B+ygu6BPcr67N1B8Bs3/EUAeJqKWvj4lY
         JPqHjHNxMI5fm3sdOEhR3qsKyn4sFZW8iMjRE8HZ7incIj7Y9t42Mf6ghRTJ6xucRtW7
         MEJ2X8Y4hl7srkxSdXHRfmfe1XjYao9nXZUCH0A4gXABGPoSejDUtGKy3PlTrZac4vnt
         233A9G8crsqw8XYSszVrjubNvgN885G9sE2gfWgnTA/bVH1bndS/YXLOUdvXhJ/E0mgc
         sJ3Zf3Bt9B7PvQYQmCTPeck0JUvCjVhMGzqEl9Bo2LJ5b1VKJJSPCgluzz4XCkA6zt9O
         7pdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="BNR/zhrD";
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id v4si128783lfe.4.2019.11.20.03.52.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 03:52:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0D8C008093FCEEEFCF892F.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:8093:fcee:efcf:892f])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id CA7C21EC0BEC;
	Wed, 20 Nov 2019 12:52:37 +0100 (CET)
Date: Wed, 20 Nov 2019 12:52:31 +0100
From: Borislav Petkov <bp@alien8.de>
To: Ingo Molnar <mingo@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120115231.GD2634@zn.tnic>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
 <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
 <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
 <20191118164407.GH6363@zn.tnic>
 <20191120114031.GA83574@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120114031.GA83574@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b="BNR/zhrD";       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
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

On Wed, Nov 20, 2019 at 12:40:31PM +0100, Ingo Molnar wrote:
> Well, this would break various pieces of tooling I'm sure.

Well, if at all, this will break them one last time. Ironically, the
intent here is to have a markup which doesn't break them anymore, once
that markup is agreed upon by all parties.

Because each time we touch those printk formats, tools people complain
about us breaking their tools. So we should get the best of both worlds
by marking those splats in a way that tools can grep for and we won't
touch the markers anymore, once established.

Also, "[]" was only an example. It can be anything we want, as in "<>"
or "!" or whatever is a short prefix that prepends those lines.

> Maybe it would be nicer to tooling to embedd the splat-counter in the 
> timestamp in a way:

Or that. Whatever we agree, as long as it is a unique marker for splats.
And it should say which splat it is, as that is also very useful
information to have it in each line.

> > [    2.542218-#1] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> > [    2.543343-#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
> > [    2.544138-#1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
> > [    2.545120-#1] RIP: 0010:kernel_init+0x58/0x107
> > [    2.546055-#1] Code: 48 c7 c7 e0 5c e7 81 e8 eb d2 90 ff c7 05 77 d6 95 00 02 00 00 00 e8 4e 1d a2 ff e8 69 b7 91 ff 48 b8 01 00 00 00 00 00 ff df <ff> e0 48 8b 3d fe 54 d7 00 48 85 ff 74 22 e8 76 93 84 ff 85 c0 89
> 
> That way we'd not only know that it's the first splat, but we'd know it 
> from all the *other* splats as well where they are in the splat-rank ;-)

That's exactly why I'd want the number in there.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120115231.GD2634%40zn.tnic.
