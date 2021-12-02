Return-Path: <kasan-dev+bncBCV5TUXXRUIBBQURUSGQMGQE3OUZZKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 081AE46697F
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:56:19 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id d7-20020a5d6447000000b00186a113463dsf56323wrw.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:56:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638467778; cv=pass;
        d=google.com; s=arc-20160816;
        b=SK/rp94ap1uIjRlhg3AmYpbWaKkl/aakpKzqiPGxObJQD7/Lb3tpfpHtpkdbrLLcc3
         UBy2F2d0mitO1KPM2H2DrXfCeR4t6+4JCcMZTpI5tKdlLhyYkuPm+OJjpLvPNUfkk2ak
         Ax8Ru1s4yAvEHBpQchqekQH3F6GkM531qckUnRMAqsTzfmkFBRHSVTNi2e2Pri7uA7qo
         yd/NKx7qLY1hVZZSzGyOoJlio6wMLQMwpsamDpTH7+BmPkr08d6Nh9Isw7ptoTj6bIcT
         VAxQ7YRZhGRSHjz1g3/pywy8ydrOYXpEJXpxO0EpR4yytPKbwfY0b7UuPSkUTyp/dZSq
         C7+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=q2mK0h+TmtuQZUxr258fSXrxHlQz0yFpvzpHZScJW/8=;
        b=lXICpiWrosxc2bZYHUb1AkrV5c3uxrwKzdfR0DwFqsyPGi4nAsqs+Gw6pNCsd5EsS1
         adWDXECd2/Uvr/S9qC1fxgnSOloyeusNNVeKDzOn+PIQ3vBzCnNTy2yX0b8nFEHCrDka
         AuobULGcx4dtChAcWYToCSVcG0kbZgfKyXoo0tTDede5luz8wwWlw4zbosMX8/uxtBTe
         U1Nssw2OOmmn+RXLaYjT3Eo8eelI4iLZbSzcQC2PmBKq7mhdkTuK+V+ahnttdGlsmhA4
         fqO+05aHf50EtPVi0m+JFPtVD5Fz18qagkmSs5dBCcwz/ibekTu01dqtYSj6VhaOsGGY
         R7Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MfClZJKe;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q2mK0h+TmtuQZUxr258fSXrxHlQz0yFpvzpHZScJW/8=;
        b=Fub3iRL+6DQ2D2GuVqSMLtvPTa6lJmKje/6r79y3GlMQomSfMwcg6UXG5f3tz7FERF
         G3wcCvlikcZFx+UrYb65o764ChZfQLVP2OALe2Vn0iXqf3t8z3CMb7u2/tuqW92wFPh7
         B2/ZW1zlZKHtSpInpndV6Tg1JLBvsNaLA2ef7vo0JV0r+eZop7yjcN78wAf99qfHCCyc
         Y7cQtgPwS+BTXLSUvIv8mcBTwpO8OUBKhBsFAUjlto5+WjxZ9pdAPDnvVu1MrVxtvGpw
         oUc4VF2cNlzbJ6GQG7xx8tiDs0Ace0Sckfica3Ww/o1RkiGFVszzyyZB/fB+5cxttlsT
         agQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q2mK0h+TmtuQZUxr258fSXrxHlQz0yFpvzpHZScJW/8=;
        b=DzfE89YCXRsOBhrOipG6FW2WT0ZhytPPC4ZQM3funaMFMtAWVGQqNLzhCr89wMoVds
         NeYjPNbzt5rLFys8bIeCuZQR3uQqsV+aqJEeMlbXETM47argN246PPrPrBlyWkM49s8j
         SOYEFQk0g1B/X0oK09YhUfBITxCvN8hg+TiEoJ0UeP3iwrTTRhRGS8heNUwMcolwR8DI
         zJoLxM7GL/+QB2e8Mfz3WtbrEQ/0lqNhlJ4/1/xUUbNsjhHP2QslooQoTxJTpQB2EWnq
         ALFJiQ+/PZFi+A4HOUMJlSaxACS5iyaajlElbM8mJD9vzx/p4413chKmt64xIR8BMyDq
         1w0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53374pJMuYDBdVZhhdrGFA9o/amVHg4DFaJsrSV3vnreU+5OEVgc
	MYa8GjKwiuftOCWpv3rw82I=
X-Google-Smtp-Source: ABdhPJyrzVwNzaEvQCasqmuaXsHoQOzXA8yfKTiOaNajvRDu3lD5eD2ofaLvz18HgdZ28ixiNhfkcA==
X-Received: by 2002:a5d:6a8f:: with SMTP id s15mr16005174wru.544.1638467778836;
        Thu, 02 Dec 2021 09:56:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls5390794wme.0.canary-gmail; Thu,
 02 Dec 2021 09:56:18 -0800 (PST)
X-Received: by 2002:a05:600c:3510:: with SMTP id h16mr8098767wmq.144.1638467777911;
        Thu, 02 Dec 2021 09:56:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638467777; cv=none;
        d=google.com; s=arc-20160816;
        b=Mg8D9Dj4IZqAqpGBi9kkgpfv/boUss4tvGYcCbwqfJPWvRkaQ6OU70sz7khbDX5woS
         hMtEC+OEc2GEDAOtmxwIAyKN/GIGsz8BWusdbr4EVndhM0y8RyNN9Jr7VYFoogKHGUMg
         iPxQBNycArScw59Ld4O9MO8m6rwLH9rjIm29DWJVP5CvlUudEBmHS9UxNI7vu/NymHvj
         yG/0GLcFMetMqSSKsJuy2oD5DwY4j+mboLumK+2Ir+HRjiKUafjP+2ouqIEx/kQPBoep
         XIPfD/EMJUaTn1m9HUMqU2PZnXDDGySpVVieINtE2gPNG4Ew5XdDIo4B9Z4kEFFn3W89
         BhMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z5l4ZowOfON8DShmpXR1Eklfg8s5dDGN7l9e7OCgVe8=;
        b=TdwwwPrl3Z4IHWzRAIjcPOH8D6eAmU2bcSblUL/THjFlwr1kB7BpSJZC2oZ1hz6KDO
         x5/41CxVJ24UZvurSpiMoQ2zG+ALnJkih6FtDMYvvAM/oYWLViKH1pJ449QvWOQensxh
         +Pwb2oRe6rnwWM0zhLKh0RAKy1bCmJ/dwUZjolLppUhd/W8w2xhrdB4Bi6qXjAd9egyl
         5S0jAwY489ySpjds6qin90t6o+TNchSKRuZrFAPARdoTTx2I44yapOzTX2XD3531Jik+
         gSCmOAqeEXSklFh/h1i+AFVJseYaKzMTJvQ9lWrVC7iupixQQQJAtxVp1SrqupeUcpR+
         wAbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=MfClZJKe;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c2si492338wmq.2.2021.12.02.09.56.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Dec 2021 09:56:16 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1msqJU-0050IV-2P; Thu, 02 Dec 2021 17:56:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EE626300293;
	Thu,  2 Dec 2021 18:56:07 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id D8E85322A81C1; Thu,  2 Dec 2021 18:56:07 +0100 (CET)
Date: Thu, 2 Dec 2021 18:56:07 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <YakIt2aPZeeNzug0@hirez.programming.kicks-ass.net>
References: <20211201152604.3984495-1-elver@google.com>
 <YajdN5T8vi2ZzP3D@hirez.programming.kicks-ass.net>
 <CANpmjNM4nxnwt7iWF+kCT862H21CHL-cshYyugBei0ysGAt5uA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM4nxnwt7iWF+kCT862H21CHL-cshYyugBei0ysGAt5uA@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=MfClZJKe;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Dec 02, 2021 at 06:38:13PM +0100, Marco Elver wrote:
> On Thu, 2 Dec 2021 at 18:30, Peter Zijlstra <peterz@infradead.org> wrote:

> > > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > > index 9ef7ce18b4f5..589c8aaa2d5b 100644
> > > --- a/lib/Kconfig.debug
> > > +++ b/lib/Kconfig.debug
> > > @@ -1977,6 +1977,8 @@ config KCOV
> > >       bool "Code coverage for fuzzing"
> > >       depends on ARCH_HAS_KCOV
> > >       depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> > > +     depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION || \
> > > +                GCC_VERSION >= 120000 || CLANG_VERSION >= 130000
> >
> > Can we write that as something like:
> >
> >         $(cc-attribute,__no_sanitize_coverage)
> >
> > instead? Other than that, yes totally.
> 
> That'd be nice, but I think we don't have that cc-attribute helper? I

Nah indeed, I made that up on the spot.

> checked how e.g. CC_HAS_NO_PROFILE_FN_ATTR does it, but it won't work
> like that because gcc and clang define the attribute differently and
> it becomes a mess. That's also what Nathan pointed out here I think:
> https://lkml.kernel.org/r/Yaet8x/1WYiADlPh@archlinux-ax161


Urgh, that's one of them MsgIDs with a '/' in..

/me substitues with %2f and magic...

Hurmph yeah... so if we can somehow do that it would allow back porting
those fixes to older compiler versions and have things magically work.
Not sure how realistic that is, but still.. A well. I'll go do something
useful then :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YakIt2aPZeeNzug0%40hirez.programming.kicks-ass.net.
