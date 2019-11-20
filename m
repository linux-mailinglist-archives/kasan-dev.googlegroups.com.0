Return-Path: <kasan-dev+bncBD7LZ45K3ECBB5WM2TXAKGQEE3CFY5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D3C61038EC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:41:43 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id t11sf10979758edc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 03:41:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574250102; cv=pass;
        d=google.com; s=arc-20160816;
        b=wRAU4KD+hXynYqzPIr+oYh22wKpgL9xcyrbcAHot81aME1pTPiizGC5n9od8BgE2eD
         llxWyWjfB0nXf4ue9cokdg4d4AWnm2P7w0b//XPGOXaUO65fAIxVTGFVyF1ejeUjPfxh
         EU/ru8uwNGMc4aHrc3+QbXu7SVGpS/H9GN7RsPqj9Li25KhATmJiS0Er8K7cQ1XHS094
         Kv+ZqtAVhUSqaszDQZUQywLz7IA6KaQcXjjsRwkMk3yoI7R3EcFkehAP0BXgsxGD4S0F
         AD1oHAkqeNSkP+1UPkO97fd/xLIDlxBY2V493Dw56+z7VJUPjswWuL/A/I1uCy24pdkX
         +z1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Ct9pcrI3MHXuYtdXCfpJDya25F//rtAOqeN5iQy0N5w=;
        b=m5wHAnVacUaVkGPyUcLcskjMIqHwCsnyfVKcM5PJa7tn106eA6Uk2r8OOPvH26jiHb
         u5fiMMxGtKYxddgJRoZK8eUyWB5SzHnLxyWqS8wyGqnKa2+/ysj47k2gt/vFhy1I2lzx
         AZkuyMD4wQKfTTaOiGjUTViwr5PBEKOusfcEe3fyuKAoYQQP3lwgiZzJShwC+uJUUI87
         FGuDFC+Z7HVjDQotWC+y/gHunmd/4rTWXFojdNJIbym4YCMYKHrwK7veY8FvyoEXshgO
         viyQihw10MVkcticRKiHwSq/+bXzxKWucsYAiHSuSH7m6Kwt35DtA8OwvymQ1UdS2qsG
         v3Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eXkRJGZL;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ct9pcrI3MHXuYtdXCfpJDya25F//rtAOqeN5iQy0N5w=;
        b=EwY0kP5cNmp4UDDxLkt7pBk2JDOjuBzOTZi4OJau4ii24qatkYZ/2QHx2gVqgOaEWQ
         APbI/Zd5tFCuJmdA6RBW4sKEa93tXLQKHnpxBD11QIljqQw5qnIQmP90E3BXPzQ/qk2G
         B+SdhW72QHZOEhl1MR7jM+UPW3G2mhxNBs2ST+tSFmCnF1PTRxCsYE/V2W66XDrymCoP
         8suk734hVAhSgpe7toNrgtdfIMw0oc1JY4md408uSb3vJwGILK5S8gE6b4bulTw0D4CO
         9xmgEfgAm5aXwCAc1L0lNy8wTB20XhUKF7wH/NQAK4UVH0q833CKLnxWcLZuQlAsA3Rt
         tsqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ct9pcrI3MHXuYtdXCfpJDya25F//rtAOqeN5iQy0N5w=;
        b=Di42pJfAO5noa5nK3cZnTdSSu4dG4szhugyaIUEojVC9BllGRotICABkM5sz8M/AfX
         /T4Pj1ojyvs7iC9P6/6bzLe63fQ0TGlYUS5rI22xmphQYxPcGHRUycK0LJHdSafwtJTw
         2u3bx5kNppDIweb8jHuk1W5kOjmMpeC8Qa9K1ITpObmpKJlpbE1FF+Hd4XueLJgA0e8H
         0++uXB7PfK/8r+aDJ1NFXX5srIQ4HAngRwBN30g0AKrUmxJdzHj0Sj1R2Xq3CespM9jY
         OinRktKyIuLeCRb86cDvd8MS4zDfDyK6QkN5AkW563EdPtSDVCIBiCSRBofLmbK55BSH
         iIpw==
X-Gm-Message-State: APjAAAUpFoz0BteZFZoTCGnYLWR8C4ZUqQmbKd9100f80lCoHDiMQlGm
	dXsm1Uu06Bq0mxhavyPGWsk=
X-Google-Smtp-Source: APXvYqxQbHGtseE0II3y/NrJlXm2AkUDaTVJoFjx1+t5YvMzDzbuR03elo0i+2hq2tgKHXEiY3b8Vg==
X-Received: by 2002:a17:907:426e:: with SMTP id nx22mr4688990ejb.139.1574250102755;
        Wed, 20 Nov 2019 03:41:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b245:: with SMTP id ce5ls964817ejb.13.gmail; Wed, 20
 Nov 2019 03:41:42 -0800 (PST)
X-Received: by 2002:a17:906:9417:: with SMTP id q23mr4924631ejx.37.1574250102141;
        Wed, 20 Nov 2019 03:41:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574250102; cv=none;
        d=google.com; s=arc-20160816;
        b=a1J4CHjhapG+tVKbp/0XLKXzarSKxUtf5R6NxXt+ovsndyrhC+KHSZb8z+JNmEyLn2
         vCIE70v7qJYFyDME84rJnJyxPfBBTwKYusFc+64AhrAY2dkSyadFMso3TI3HAA5wJ8Ld
         MGIVS3Wd/oPrdB07BpjE7p4e4UsEAa0H5/ZiLbS0iHPHM0wg5tP6nAunoGEHhh+5GQCO
         vFeG6iHFcJbWpKWXE7/nNX7bVggKyQD3ITkYU7AC228D7iJM6N+2wu6b+LokG0vLViLB
         POs9aRUmgEXLQbIR3K8Bd12Y3Pw7YEPpcFzh7ZIAgreTEfnQT38gLJjpTxhOtmwA07Kj
         ZF6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=x9xVJ7mXWw8oZuqrstfEkI3veCueqnyo7bS5uNfNe1c=;
        b=SOPQLdNOKrNykYFTO2AE7cS3A4wD+f1NhNGix9rksw2kUp+/cdFJ7Z8s+KQ+5YWDP0
         Wfdg+RE+AkgWOtjByvORIlBvs3PDXqC4BjSYlADex3YYPSn3KR7/B/fwoniyw0CR6Y99
         YgIGVDIOVs5JHvo6IkOGuGib0lkBU+XN3TqaYzt3FLI1LiSQlbF8F7sufFhQ8Z3AV7g5
         N9XYZXir38UqHMpLZYMGVkTrLpOx74erUeOYSOn3rlmw0nu3mtH6KhU9Uw4N+4fBg9R2
         Vx/zyl7kVZ3FI2EeDUAfBfd6qOaTMG4VwQi6HeU8at68XPykblEl8tcgoNH+JIZ6SU/m
         ZE7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eXkRJGZL;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id w4si292625eja.1.2019.11.20.03.41.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 03:41:42 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id b17so7465168wmj.2
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 03:41:42 -0800 (PST)
X-Received: by 2002:a1c:a512:: with SMTP id o18mr2592588wme.4.1574250101878;
        Wed, 20 Nov 2019 03:41:41 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id v128sm6875441wmb.14.2019.11.20.03.41.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 03:41:41 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 12:41:39 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Borislav Petkov <bp@alien8.de>
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
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120114139.GB83574@gmail.com>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
 <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
 <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
 <20191118164407.GH6363@zn.tnic>
 <20191118173850.GL6363@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191118173850.GL6363@zn.tnic>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eXkRJGZL;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Borislav Petkov <bp@alien8.de> wrote:

> On Mon, Nov 18, 2019 at 05:44:07PM +0100, Borislav Petkov wrote:
> > [    2.523708] Write protecting the kernel read-only data: 16384k
> > [    2.524729] Freeing unused kernel image (text/rodata gap) memory: 2040K
> > [    2.525594] Freeing unused kernel image (rodata/data gap) memory: 368K
> > [    2.541414] x86/mm: Checked W+X mappings: passed, no W+X pages found.
> > 
> > <--- important first splat starts here:
> > 
> > [    2.542218] [*] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> 		  ^
> 
> Btw, tglx just suggested on IRC to simply slap the die_counter number here so
> that you have
> 
> [    2.543343] [1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
> [    2.544138] [1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
> ...
> 
> which also tells you to which splat the line belongs to.
>
> Also useful.

Yeah - but I think it would be even better to make it part of the 
timestamp - most tools will already discard the [] bit, so why not merge 
the two:

> [    2.543343-#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
> [    2.544138-#1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120114139.GB83574%40gmail.com.
