Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBMFOZPXAKGQEYJK7ISQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 018A3100A6A
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 18:38:57 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id g143sf5205270lfd.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 09:38:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574098736; cv=pass;
        d=google.com; s=arc-20160816;
        b=lR91wAYl0N2rBprg9lO+sRvNzNkOkYmHwb2vepEqgeM5kASYCdmwwQo+50wBj2jKcX
         g+tgM8g30ylKado7BCiE5e0l4g0//IHpDAwxX9oOjc3KZpFZx0O5ckoRIl1XZtMOPY9b
         5F9GCeuu/XeNPZ3/we4WU1f9Bbf9kmgFdB3f3Ljw306rjwGucsnDCprUCb5FMCwRqgqv
         FGlMjBl0D0wM9Ty/5+Kx3Q5q9r0tT4KmHCEjGwGtr7tiBJGfUFN3pjHPexa/sViuOaPs
         a8GNCQ7ld4k/l5BuOM8xJW941dO8Fc3t6JgpucS0DV/C1hiivxVGUsgC1W9r5mCD5p64
         kOSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3+voi2/jS/jXeH49nTpUVoiWU/ktiCgY13u0knITBFQ=;
        b=x7hh/N8OAiLQBQ5S6+RwhILFu9OpTsA6aPQLlPzVli/o+s1i48OBEcNPGR+gwIpXBN
         pffeBht350XIuM+IfrghNfVqZc3/FySGWJwzXb13K7Abv72lXpP9Ajtf3pYFLT92Okpj
         DQSb4Y3444+mqZ4EY/ZbaxKQxp3V/KC2XjrGnzjlOHr1BSPcwUH9Qs2rRjuU9MogAr5M
         CJXJYsCyBl4MFa4cbN/QHChZy9alTQCrOlkS511KcEGsqhPgq5I40/G2ZeQ4ywHmdBWy
         w7epWmrEYIYjcXWsx+5++9gxzj1RfUl/Teu591AZfCx5TjUgxaFDSxrZyRdPbDoIUJ7O
         MTdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JVrUTk3g;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3+voi2/jS/jXeH49nTpUVoiWU/ktiCgY13u0knITBFQ=;
        b=MIViqbmIz2dK8bYHrEMC9DvnwC9UmB2726o69387isngVVSweIfogR6tDxYYvndUhJ
         qtq4hd1ZtOHnukbYlNdbTQzaUlaFppThUIGav2wncR0pxthLZBAy4EBYMeSaqeLuXktq
         zGIvEdZgFEJ6yGph3tjvGELjO7qCS5XvheZMwxHkXyzI8uQOSrUJ6M4Bljjx6A7PbfGf
         vA8YsCkX9g+SFpBl89hYgqpXxNmNWeKsnq6UJGuPNuKPVTp5mLQatpMQnxL7QJ076dwP
         LA4G1PbhBnRrm9v1mYHt5jE+SGoKViORTEUw6KXGjA9gwtiTe0dzEc+SSFBWWoBJOKqM
         dAEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3+voi2/jS/jXeH49nTpUVoiWU/ktiCgY13u0knITBFQ=;
        b=tW7vRnEibWVs5/w2dZ6Gtf9El47gxZwqwc/0zgJpAyNbp/akiGgJVg5byTrcHN0Xp2
         U8SwMMRE6nJObNRM5GJqMHuOsrwy8L1i+NZ28RRRSMAKFjDwLb3Z9GfxUENX9yvde8DV
         H+RfkWp+EEJcqcrgnynUgA6a1mwWcMnk3S6Hhxld0slHAyjgTrhbAEvHzxOjzXT2pMEy
         xcgc5yjSgjcVAQU1+PfylWJjgUI+gmwbV+zhLKdhuQq4DuvnZhDlUht20dBmto3i0PA6
         QQviOol26DVa1tOPS6rMkJJXVArJA79MbSU7ka5rXjlmyOMCoH7Uns3zkY9TuByrl2G3
         rl2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV2cqutmFIXEHH/gu9sHkFgZvjlvTAQLw9PrM9WwBqSK7UJMk/3
	aK8S0FugBwQB460ce4rTvec=
X-Google-Smtp-Source: APXvYqzmp8LYl7WLEllr6ORfPgBoidGHCqDropycSIpW0Jd/qnIeRQy/OWTzMAK4p6q7RaiSdtWyVQ==
X-Received: by 2002:ac2:43c9:: with SMTP id u9mr437489lfl.180.1574098736559;
        Mon, 18 Nov 2019 09:38:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:864f:: with SMTP id i15ls4462759ljj.11.gmail; Mon, 18
 Nov 2019 09:38:56 -0800 (PST)
X-Received: by 2002:a2e:2e03:: with SMTP id u3mr467264lju.115.1574098736040;
        Mon, 18 Nov 2019 09:38:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574098736; cv=none;
        d=google.com; s=arc-20160816;
        b=SaLY7kc5gtg1ZUOwTbryyIR+wT7PCU+4YibGQVaooFQ6DkiHsP6YcSFFRLr9P793wP
         AWnZTf2OFq2ZHA/8E2J7u3As70Jtubcm0puF3zec5wKkbOSitwFccVkZd2RE/0kVtnY0
         acYKDHsapg5puctaGuC++49ga+IqVA7v6zkfhOhqdt8qVdsDeDEzEl1aXKI/iMKFOPkL
         E6JsKUGMVpm4fBV4G+bqMpKPV1zn2T1++bYSxb3SQfgFKm/WPHL2hf2R/rOUCoJ1aq68
         Suxy0C3NSieAUcHYFQYy13fXI/HTl0HCGzvOJJRlunKlasOIHXOYCrTfXrFi0sCj3xY/
         j8xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/zpixmJKEK2DyhKs6AeIjcFfA5HziA0TuK8uE0/KAJY=;
        b=Gn+YH37GyuzgGdYTBGgsrqrf7vw5jRHdg9fPAJf4AFhbmZcrkHOHAdNGSK8tecRu0R
         W/uUF4xVDLEf79AWz62cdeiWswnatgBSpv5JC5cH67si21LBzWhcfH+dW1QqHRkH0I4+
         pWEuFEM9y8lWJgh+JqejRvN8Xk75LNW9Eg0/MO6yaRn7aBKN+qhJqvfZpdhdNITR2QvC
         YoH23hVWw1AEiv8+6VRRPUrgOGSOFNrKi1ZX7nLcoxV9e6cItu8k7/pq9LJiYvO8h5JA
         DIsL3qiMpKDjWapx0xEXFFE4wjyhp/HzXPNCysqnwZN1t1VdPZN3aalcIKQbRuirt1UF
         M8/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JVrUTk3g;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id z18si903363lfh.1.2019.11.18.09.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Nov 2019 09:38:55 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F27B5003D22FC05E431AFF8.dip0.t-ipconnect.de [IPv6:2003:ec:2f27:b500:3d22:fc05:e431:aff8])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 1D1D11EC072D;
	Mon, 18 Nov 2019 18:38:50 +0100 (CET)
Date: Mon, 18 Nov 2019 18:38:50 +0100
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
Message-ID: <20191118173850.GL6363@zn.tnic>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
 <20191118142144.GC6363@zn.tnic>
 <CACT4Y+bCOr=du1QEg8TtiZ-X6U+8ZPR4N07rJOeSCsd5h+zO3w@mail.gmail.com>
 <CAG48ez1AWW7FkvU31ahy=0ZiaAreSMz=FFA0u8-XkXT9hNdWKA@mail.gmail.com>
 <CACT4Y+bfF86YY_zEGWO1sK0NwuYgr8Cx0wFewRDq0WL_GBgO0Q@mail.gmail.com>
 <20191118164407.GH6363@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191118164407.GH6363@zn.tnic>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=JVrUTk3g;       spf=pass
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

On Mon, Nov 18, 2019 at 05:44:07PM +0100, Borislav Petkov wrote:
> [    2.523708] Write protecting the kernel read-only data: 16384k
> [    2.524729] Freeing unused kernel image (text/rodata gap) memory: 2040K
> [    2.525594] Freeing unused kernel image (rodata/data gap) memory: 368K
> [    2.541414] x86/mm: Checked W+X mappings: passed, no W+X pages found.
> 
> <--- important first splat starts here:
> 
> [    2.542218] [*] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
		  ^

Btw, tglx just suggested on IRC to simply slap the die_counter number here so
that you have

[    2.543343] [1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.4.0-rc8+ #8
[    2.544138] [1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.1-1 04/01/2014
...

which also tells you to which splat the line belongs to.

Also useful.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191118173850.GL6363%40zn.tnic.
