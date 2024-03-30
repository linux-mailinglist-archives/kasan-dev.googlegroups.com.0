Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBQVNUKYAMGQEG4WIWEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B7602892DAA
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 23:48:36 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-341bdc085fasf674835f8f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 15:48:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711838916; cv=pass;
        d=google.com; s=arc-20160816;
        b=kx/zBLnWNb25Ybe0pZNJuxKKP122ade/A7pyB6/KlcgaHXzSijdO8+HHxjMcDpDdHw
         7/b5mfb83OVXilrXEDkGccvfHKpIihrjKMgBywsmGkxC6J28xaDnq4XP3z834KO8WL+c
         dtEOsmmRK6vN//1qsHw+kw3RXMY1qcNieJ0X5zTrEfn7zvEg2mZiXAW1vp3AjCGF1Gww
         VUbQf3CkRSpmn88KAr7tPz/dJPYou7HbJJXB1ti8XzwtIBd9iRCOHXDXG1iN1pCQGwUq
         sRZn2niS04od1oazbDfWOS6zROQuNhbgU1NwhAHvGCEDgWRyB6GlVtdFexVlXE0WpwGR
         xP8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rel7jZSgyH4iyD8m/BKPudglNkWonEOSdaBN9wEDAZI=;
        fh=C5Vz5T4Oc6VL5IGlngPnaASOovc+yTzPXweohx5Pjug=;
        b=0F/IPRajPuC7ASkUDst9nY3z3lxBgbM4N9P4srdghQ43fvNemNGPSKfA5MiiSGRx2H
         xbQw/n04xeQZAq//FgCqD0n3/IAgQmPq1kbCIo9WKZdy6wd7IvPM8/h4nwdg12ZcqTSg
         9wXiM9WYgAz3uuSu605acpzk/NuMMqqMuxvbD8vQSIsn2WVq/QEl1pKl5YnYVrKcardq
         oBMNh2Z1QV8RTs1CQ9J2oHPlJitPcsjV211uqtxrnsKcaL8mEjMkUcEVRKTPPPH2537+
         AyDwxqEC3oJTjerC3ScFRwSKDi1B3htpac66VlQy42hd6Yqm/xEYPmZCKlZTNFq5LLZP
         iUgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=C0B2YKox;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711838916; x=1712443716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rel7jZSgyH4iyD8m/BKPudglNkWonEOSdaBN9wEDAZI=;
        b=LBYd+/03PVC0Y15BZ+rmkF17w/0vFu57iIXkttxDj9gjucZXyRbd4yeAJaGk47NF8m
         01xxOPFSkb1i980xEbjtzgVWqbqhsP3R10SH7FdL11e0hkD4d2fCZYlf7WXxba33S0hf
         qJPuUnCRcgqT7V6nMs5fTih5sqn9TuutBMjf5dylKrW5ennYObHbjeo4fzJ8JDjpHNBZ
         PTPXk9TQMhQ2EPA8OYMYETFVxy9GTgwwnyNZ30uZ1PX8xvsfPDZev0+6Hq73zrFNMunB
         OgsqxIchgPmJGdzxV0qhQPApi+K3Yy7e1tkI17UPSIGY2hZ7Ax+qhlx6fvJetm2uYpaw
         ch3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711838916; x=1712443716;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rel7jZSgyH4iyD8m/BKPudglNkWonEOSdaBN9wEDAZI=;
        b=A2G/aQtf7N2bXf1VK0sb7pNBRq3pN9GJyfAZJ63KmDt8qV8iWt9ezkE8CM2/x68IgZ
         kZR+r1doT5Op+lvwq3A0OVbhjPJdLIOUn4EgLtr7GO8Hp1hiPeLNrdXc/3rvCD1Rxzc9
         B44hSrOqMnu1xmkvzUHz7VhOz6bDkCrkr4SrwWOgvNUguGEppf+R1BVh1pSfX/hvhQla
         v6SMIZZXGJFWwLwpdk+Ar9HbJfyL65o8Bv2lGU4EnFw4+RovAtPengYxy9NAe3mzg9nu
         KiE8z84dOg/pZJY5ZRuA8LuD0QFhMTbfKQ6Tu88MxBPwfJusxVvoWUOZ3ewXXady9jOb
         KhHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3eWCkGNNJDMyDqfZbYLBf6fJ7LZlP0RNFloMWlY5WXmXrWNGVvurMR8uvAGGYgGZyyaqt7Jd9LgXKcxPs82uAIMHNQLWtgA==
X-Gm-Message-State: AOJu0YyawKXva0DC9qzy+QzY18PlFa/35HzwSS+YXrz8GfvlDAxj6dLR
	H8Wz0NfkY2FfeabVKoIivRqdZER5TJG10SNJpL48Re1E/J+eZGlY
X-Google-Smtp-Source: AGHT+IFnRtgf2nPON2P4/fDgIpC7V1j61UXzSot2BcNaTtqVhFQp66Krfc5dvN/18gIpzl3TXbv99A==
X-Received: by 2002:a05:600c:3545:b0:415:456c:a2d2 with SMTP id i5-20020a05600c354500b00415456ca2d2mr4057724wmq.4.1711838915151;
        Sat, 30 Mar 2024 15:48:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b87:b0:414:bee5:aa8d with SMTP id
 n7-20020a05600c3b8700b00414bee5aa8dls610325wms.0.-pod-prod-00-eu-canary; Sat,
 30 Mar 2024 15:48:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCmnJgIaLf2b2WTNseN6nFP2MNf6bsJttLj5a0hMABmvrVYGRIJQ7tfS2B/fQN8yGsz7VcLGA79aB5c/+l0+/lgveTMLsJMTTmCw==
X-Received: by 2002:a05:600c:1d14:b0:414:90ab:9d29 with SMTP id l20-20020a05600c1d1400b0041490ab9d29mr7439602wms.0.1711838913195;
        Sat, 30 Mar 2024 15:48:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711838913; cv=none;
        d=google.com; s=arc-20160816;
        b=RC4gnJK7WOWg+qvcc6G9eZspyS29n+yUDPGnCrPSjlb+XrNRCZrFZN1NwyTGW46TSv
         jdBCCER2MrEd+e9r52NIheE53jWsLzorxpz+uGEk1sR0m5I0AeIts+1JpJlPu/lx+RG3
         vy1dRtxPQWPZ9ViPBkPPbYDpm6UujAG4dwMC6mM7u3HxjmgXWgrJlt6D/Ynj/+XSOIa0
         DqZvMVv7VAbRMgEKax1RrPqp4cSihgi3pZymxVDPDXSeifOTGHt5BN8Susn5v5te3viF
         h15xTjKutKPOZLCyvXomJqWGoE9n6F1GkUMShwexCrrUQp9Z1G2KHFsV9YAqPpoAKH24
         Dduw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9He/xRJ3v1u5Z/fITkbp2xLhYx5Y0tXLgjuKhvKMsHk=;
        fh=t4paR6ZaN6+H9+kRbIaxhgqx7ZOpy8t1JxQ7BcyuKFU=;
        b=h/a5fQ7Jn/bJSCK+LuaOo1QEbKOSCE5cL2B1DnVEoQ/GFVTzYMbF2lIrXh9rznbUqt
         KrEnCiFj12NUBP7+g1oapES1eyFQtIbaGYrZ6DSMKl/loELgK0n5QQeSjxGh5yccotxk
         Ox9236pEFyopM17PSYK/Tmzl+DCed4gZUnJlzLzyl0Pz6vA25hna7M4VYPWYVDEhEoF7
         bcngTv1ccYyItwHPCXgpC0jl2RmmKKGnJ7rjD0BhFc3LKjhBt5qAh7v6tPVDHsC03YFS
         oCtl9HKT0os0BiaT2kLqh7OnWxliVtivxOnEvNOMBdSaL0PTj1f8WWA8aP+eniOuv/NI
         pT6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=C0B2YKox;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id p12-20020a05600c468c00b00414946c557bsi874137wmo.0.2024.03.30.15.48.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Mar 2024 15:48:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 099D540E024C;
	Sat, 30 Mar 2024 22:48:32 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id ZuXWyArIyMwn; Sat, 30 Mar 2024 22:48:28 +0000 (UTC)
Received: from zn.tnic (p5de8ecf7.dip0.t-ipconnect.de [93.232.236.247])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id B456640E00B2;
	Sat, 30 Mar 2024 22:48:11 +0000 (UTC)
Date: Sat, 30 Mar 2024 23:48:10 +0100
From: Borislav Petkov <bp@alien8.de>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>, linux-kbuild@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Nikolay Borisov <nik.borisov@suse.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Paul Menzel <pmenzel@molgen.mpg.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
	David Kaplan <David.Kaplan@amd.com>
Subject: Re: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c
 intermediaries
Message-ID: <20240330224810.GBZgiWqnW1JZvwzOdK@fat_crate.local>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
 <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
 <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
 <CAK7LNASkpxRQHn2HqRbc01CCFK=U0DV607Bbr9QA9xDYhjcwyA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK7LNASkpxRQHn2HqRbc01CCFK=U0DV607Bbr9QA9xDYhjcwyA@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=C0B2YKox;       spf=pass
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

On Sun, Mar 31, 2024 at 07:32:30AM +0900, Masahiro Yamada wrote:
> I applied.
> 
> I fixed the typo "the the" and replaced Link: with Closes:
> to address the following checkpatch warnings:

Thanks!

> Instead of filter-out, you could add
> KCSAN_SANITIZE := n
> to scripts/Makefile.modfinal because
> it is the reason why KCSAN_SANITIZE exists.
> 
> But, that is not a big deal.
> GCOV flag is also filtered away instead of
> GCOV_PROFILE := n

Ah, that would've been more readable, yap.
 
> I will probably use a different approach later.

Right.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240330224810.GBZgiWqnW1JZvwzOdK%40fat_crate.local.
