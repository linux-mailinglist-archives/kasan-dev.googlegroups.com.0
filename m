Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBEGPYTXQKGQEN3DPB2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id EEE1611BA4F
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 18:29:52 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id b12sf4603167ljo.11
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 09:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576085392; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgiSHE9WeRSc9OhAjK2eqOd1haCQnyvYAEQA218vsyYBH2sRjb8M4RsEGt4MAGx5CZ
         7eW+JTb/f++0rh/sQ7inw9a1r5NFls+aRCl2vvLBhPqtGK26ns85/FDoIwnzgsp7EL1N
         1iUEcgJyRbKJ+P+hP3QxCp2oW7ukEIfzk/xWT48ZGGNQL/pKOo9cbTCJcHNLGBjyhgxC
         dcsKUT60gka18TkLAkvZz8hM6h6JBO6DRw0D8+fjK/HHjXraj1CdbyvyiOwladlVzv89
         yL8A5IufYM7ZLaiAWLeYYA2Ck0ESzcUZDfj8qHywXjeoUa6qiwB3HFPcAks+WQGNc1Ab
         gwew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=CzQ/s08gTPRk7JvMlJbBY14qiETi8lJ9KBWtomCDhMQ=;
        b=VZAMQqS3QzzHW1Wb1Gh+kJM+pzJECvpRx9hW0ewbzduYkbrh0h6xrcP44kplhObUq1
         eCiLEIYZbOEGfB0qdIPis0ujTcYAYxOdxdzw/ixJBToE9uoq49kwm1l2mPUhXr2DTVEl
         50TnSt6UOo+oH9THHa4TRb8OQWlg+vTj0Tpp3GUX9yL241DeMd/U66HRqjZnGsH0FfiY
         5vd7NWk5Y7FgkK6cH90u0epc1tiQUz/AYq2vcFLsvMEyffrMRVY3Jh1Vy1R2lX8qt0N/
         7GlH2YnkaW0NvNQvxkg3Zs9sZy4CoOYmGFQ4uuOS37ahCJvqCUjJB5LbZdbJsLQLisZ7
         K18w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=h0neVSvp;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CzQ/s08gTPRk7JvMlJbBY14qiETi8lJ9KBWtomCDhMQ=;
        b=b9KKOthv9Fajtl3LGc74v3737qVDLoByre89sD2Y9a3/63jCB2BRCoUZTQov2s+nHf
         ip4BuDtn6Y58rWvFIe3Ny4G8GiObMpTRurYEnH6KtegxghZrYnM+CessH7OT37zMiOnc
         cqWGKp5s62hwmbrDIJx1xdYUOKguXmJd+K+BTruVtH9VKa5d2oKrGrFNF6q/N30k3Yfb
         lv1fZ1yWMNtfRaM9g/ItVXmJXEI1c57a1U8PQAfwVZqHDaV7hc8x1TJO7uuhdhewZdWy
         1vjzFkXO6fGqvltKLbFfziCCk2+Gl6f9/6Sbkp+ajUtUU0b4lpqPb5yatzrK5oMvsuSg
         ZMGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CzQ/s08gTPRk7JvMlJbBY14qiETi8lJ9KBWtomCDhMQ=;
        b=McgS1kc7OzzRRh9W+5a872/HBFsfTqJZA0UC1VT3gZdvJTZjGgR1vJQQTrjLbWthD6
         A6eRPXP8Ev328kCAXm5vjdGeJ2ajIhJarG7Nr7GRvJiQMjMn6bKiES3G1j7XFVPCk/CZ
         YtiQ0Ehob8S9ctehwIfX60dOIzvYx1YZgPcZSgVaIAGIBnLnNLiC//Nkdwj5J8o9VaBC
         e6ge39NlHVXnkD1z/Gnm9FlGC2xxOOFuffGPYp9dCEz0CH2UazRGS5y7mmo9MvCmahjL
         CsN8uo9jXnmzt/Kgi+57GhgJptviuGsSvSZYAR3se5Wgmskq1CVO6F6du4OJaAgI4uX/
         XQHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7DitqVeMxjB5dCsoqn1Wp4voP8aww/FWHtLYgVQXQ2z6GnzbF
	1Ru6uRXC8zQUF6/xtB4GLf0=
X-Google-Smtp-Source: APXvYqz11JlSFFzgATSsmSRik+1OLmvUlEDl0Mfn0X5rG31OvubqHM6aB8//iEz4h3qMbdpLqAIWAA==
X-Received: by 2002:ac2:57cc:: with SMTP id k12mr3105344lfo.36.1576085392399;
        Wed, 11 Dec 2019 09:29:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:915d:: with SMTP id y29ls277284lfj.7.gmail; Wed, 11 Dec
 2019 09:29:51 -0800 (PST)
X-Received: by 2002:a19:8456:: with SMTP id g83mr3047977lfd.0.1576085391849;
        Wed, 11 Dec 2019 09:29:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576085391; cv=none;
        d=google.com; s=arc-20160816;
        b=xllo+I7245egtJde3kCbdDTmxhAZyN/L1rf4CQ9xEAesHP2+smxqyS6Ca9M1z2L86U
         YxMgTBd3k76nzzt64d+NgMgIWkjZ3wZooqNiyv1f/db5zGMLPtO9J8zKKuJjtrPk1/lK
         BVpTk7wv64zUBtjiDjoQCfkskMBBBTGckypf3J6QpUZVikofb1MGOg4ZhtD38eqX4lbZ
         9+5AaXsdRsDy+DpOTZXbKpetSDiCug6hEaW3WHDp4xHa5WmlEYZlRsht8FzH3Mr/MVTi
         Gl1Fvipke2sG+2M1XtG9ivYv5cCSdSC52W8oB1F2qzVWDjD01mwPD4bnGbTAFhiCeHRU
         c4jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8aesE0e4I0F9DuRAYP1dhgNCcsnczB3N1jlspP6j4Fw=;
        b=wSMO1etzuT7AbLY09J3lbpQAq2S/AHx+5Ax4UCPV2y1dbTMKHi8ctuAZ4PrmIKcrnf
         p/hAI4Huw2RVutvHOiYB+R/qlRtnqJE8KhT/8NZffCoy4WhyIqzm1dRJkcydlDFcT/3d
         VzQDADiaoE5k3BH8UPGssivmZRdnQJazcj+ftNlo9Q5UXPp6wXCxYzkZtpd6mD3T1uG5
         q9yVpJvgd9/2zlLicS1pAbPTHpAc9K06eH29iGd23HFULXo3qeiMM6EvpT1QJEs34f+0
         9p8gCo0grWCbEnSkeP4lxfLZEH1C5t4jlSWdwZiMj9qek17YVrK6Nzi2QQduobMN/0uB
         5RPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=h0neVSvp;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id o24si160593lji.4.2019.12.11.09.29.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 09:29:51 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F094900329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f09:4900:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id F213C1EC0591;
	Wed, 11 Dec 2019 18:29:50 +0100 (CET)
Date: Wed, 11 Dec 2019 18:29:45 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andy Lutomirski <luto@amacapital.net>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
Message-ID: <20191211172945.GE14821@zn.tnic>
References: <20191211170632.GD14821@zn.tnic>
 <BC48F4AD-8330-4ED6-8BE8-254C835506A5@amacapital.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <BC48F4AD-8330-4ED6-8BE8-254C835506A5@amacapital.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=h0neVSvp;       spf=pass
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

On Wed, Dec 11, 2019 at 09:22:30AM -0800, Andy Lutomirski wrote:
> Could we spare a few extra bytes to make this more readable?  I can never=
 keep track of which number is the oops count, which is the cpu, and which =
is the error code.  How about:
>=20
> OOPS 1: general protection blah blah blah (CPU 0)
>=20
> and put in the next couple lines =E2=80=9C#GP(0)=E2=80=9D.

Well, right now it is:

[    2.470492] general protection fault, probably for non-canonical address=
 0xdfff000000000001: 0000 [#1] PREEMPT SMP
[    2.471615] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1+ #6

and the CPU is on the second line, the error code is before the number -
[#1] - in that case.

If we pull the number in front, we can do:

[    2.470492] [#1] general protection fault, probably for non-canonical ad=
dress 0xdfff000000000001: 0000 PREEMPT SMP
[    2.471615] [#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1+ #6

and this way you know that the error code is there, after the first
line's description.

I guess we can do:

[    2.470492] [#1] general protection fault, probably for non-canonical ad=
dress 0xdfff000000000001 Error Code: 0000 PREEMPT SMP

to make it even more explicit...

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191211172945.GE14821%40zn.tnic.
