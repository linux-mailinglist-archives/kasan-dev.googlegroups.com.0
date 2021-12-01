Return-Path: <kasan-dev+bncBDV37XP3XYDRB4P5T2GQMGQEV4ZFA3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B32946556A
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:29:05 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id g80-20020a1c2053000000b003331a764709sf269181wmg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:29:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638383345; cv=pass;
        d=google.com; s=arc-20160816;
        b=EuFqS+j6rfkSQUMWmhwPApLuJSAkuBpQEAdbwML7NxW3Xvpy7OV1smJCRgq8gE29Yd
         GWQzf9oQMwSYhnTcUMEYBLZJdfi/vhPDOcYvwMhjOfFQwjuyVnhJL8D8VkwWTsZDSwAF
         uA9zeR2Lwh8uFTqNgjJbU9SQiuQHJDVA2ESWNA3JuwgeNi7CuF8vnObBXPrX47yx7ixk
         LQTY1ZJPGwAErPrC8F0009UCK2qb2zCLMisCD0aSmjTQiKqLGGmblMKow87YMyA3Oe37
         gu9pq60UMovIBOyQ2MLXt6cKTFhyhg5Bg6WSmtLZ2Exbzxu/SlCI2k9m1CyUwfxbMF1h
         8KPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DLlODWU7drdeZPX/YnmDZlmwoWUTZonZ+bnoe3Ni5Kg=;
        b=zl9J8Hu5qz8ac0HBjZ/RNx/fyYWMF6acYT/nH/ko0W4INghkb1qLepNOdM9Akgaw5w
         cWGfE428RX2Ibs9h0gssxjh5FNfACE7WW+W1t5KtpN2ArSU2RNG29O5ChiKLVYNQ5uIg
         ejEZP8F7byvlOn3ciYxMsT67oV0mb9+sZx2IXdGNhsclzcqkEkUplG7zOqUFsA5mDFNU
         dnJnsdxtK+ajANRjlctTkP/j+wsbbMCV98TI182jwwcA+D8kWsiquu/qzRKELgDFqw4R
         JMSpu3KOigcGBy/m4c46G2ViWKvV/RxNV8uRcxGzNPk5mV6Fg+86QqDvakW4pyJfXhny
         AfuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DLlODWU7drdeZPX/YnmDZlmwoWUTZonZ+bnoe3Ni5Kg=;
        b=Ye+JqK26U44K0e55DELw0bxijKdYbNmWTttiHyTU2eSh5TtTViQ5ohrS/QpZVahUxs
         +rzP8d3f2Nf7+k9dzhE4bVSGuY0akROkarTf6P715hvkqdH8CGZURCkdftqJ/UF/7DHe
         +F0ystaT13QRT4bIejzvzF1ieIaNDy3lU4cPt6fSXXlF+h/nMpHth3IRi4OKuJd5HtoY
         xGaSqBEsikJKK5jEjCHdCeL0JuH4OH1Eb5XFj69ZNod+PmZH7t+5p7z/Yt52Cl8IShx/
         CQdLbnQJhIIIHp6VlRsgrsXQ4vTze0UtpvCdBcxihEjchVrJNVHo5VzpyhNriUckToNF
         /vrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DLlODWU7drdeZPX/YnmDZlmwoWUTZonZ+bnoe3Ni5Kg=;
        b=ZdRJPqr/2Kq5K40bwyhaSCv4a70DMC7CCHirRNexWZQgNQlqdBrRnyjqD8GHKCML8g
         f00O5qNKFwUc7sDVKUNwJ9x8s6QQ6WQCG+GQmRGXY4fEXrWlJKMr5ZiZb76Q0MsTKgzY
         ho56Rnu1ox3BzHfhGcXGDVcNoFJNo8gS9eejrTr9vZwTGF5xwzBZXF+0AfOf8FTPX7+V
         XmPn/buTOVpkEqL5kT5oYK6Q36h3ZIIRI3VT0hmIcC9Zeh+c4+ZnE3s9hY96UNH9+rAs
         j2YFCDImgskMMZC59Actcwh8pzJgo/oTc1Js9q86qix1YbTwFtFZ+ZAUGNuBim75mctW
         H/Vw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lmAQyXShkuhz2r50vu2TvGoABVejcfF4LvMx4S+tPZxF9ou+I
	t4S928HG+upWs+2+mfopKcE=
X-Google-Smtp-Source: ABdhPJyOoNp/rFzj83kZfVKdo0COHXdg3IFInAdPPJFD4+jhQg94dhPlWv9Xj7BzPjCsyJeJBBNbuQ==
X-Received: by 2002:a5d:456e:: with SMTP id a14mr8504838wrc.256.1638383345236;
        Wed, 01 Dec 2021 10:29:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls293856wro.2.gmail; Wed, 01 Dec
 2021 10:29:04 -0800 (PST)
X-Received: by 2002:adf:f8c3:: with SMTP id f3mr8662897wrq.495.1638383344324;
        Wed, 01 Dec 2021 10:29:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638383344; cv=none;
        d=google.com; s=arc-20160816;
        b=SLMdpcM6fcEhG8IzI18GlxqilT+cTqsVDNACv79piez1PgJDBg3A0+ZhiA3HFxzNNH
         D5oxcM6jowRhHzYmATwRiJXED3NFde25Voqoh7Y8RoThKq33clq5Jb+PYXfdrlwlxlds
         y5CuKYureeqR2rqfEq78KDYuFM1J9TsHjftnxJigUpBTAwvwBQ5ePrODvw6hwIzUkLFf
         DjD4nQc1dgySBC717p/7+Bik5cFnSyI+DsDSTdQarjZPn+HNOueR9hKPDtBc18yjCJ4G
         rTo2oQ58VqhCGrQKL3ft3REtmHu2780lg/TX1hBTd7hc0L9s2FuPsKChz8swXfQPXmt4
         19KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Sjzyr5qu2VZ6r+wX+YU2jJV39hDmIehsfbEqCinIs5A=;
        b=vqQKyNszCF3PMkfnkk6mg2lMvfIrKYc/6TERST4YguLeYHeWHDIRcqf7Nyn21fBdjE
         dfbmkJL8DAR2phmCPs5D2d2Y1AWHL5YJsxlvQywnFFClP0jmZoJ66smyNQU1gnpNw1VV
         Jr33WLFWLVLRop4pPsFcGGt7VyobqpVic4PDqoiOok+raKPrlHPZLrtaHOCNb2M051ET
         tl4h4muB32gZimrDNP+1lU0PeQKn53UhppC0Ie/XCZ+G+G+HTd8r9K1h74sgluSwSTDP
         jj56WjglM1X1hvM53w7n46MZqWFxlFRbnixBrY22z4PCIVHA+2RypQJgICKIl70l1HYF
         xw/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q74si43125wme.0.2021.12.01.10.29.04
        for <kasan-dev@googlegroups.com>;
        Wed, 01 Dec 2021 10:29:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4AAE01477;
	Wed,  1 Dec 2021 10:29:03 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.65.205])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6AFB73F766;
	Wed,  1 Dec 2021 10:29:00 -0800 (PST)
Date: Wed, 1 Dec 2021 18:28:57 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <Yae+6clmwHox7CHN@FVFF77S0Q05N>
References: <20211201152604.3984495-1-elver@google.com>
 <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
 <CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q@mail.gmail.com>
 <Yae08MUQn5SxPwZ/@FVFF77S0Q05N>
 <CANpmjNMW_BFnVj2Eaai76PQZqOoABLw+oYm8iGy6Vp9r_ru_iQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMW_BFnVj2Eaai76PQZqOoABLw+oYm8iGy6Vp9r_ru_iQ@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Dec 01, 2021 at 07:16:25PM +0100, Marco Elver wrote:
> On Wed, 1 Dec 2021 at 18:46, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > > > Currently we mostly get away with disabling KCOV for while compilation units,
> > > > so maybe it's worth waiting for the GCC 12.0 release, and restricting things
> > > > once that's out?
> > >
> > > An alternative would be to express 'select ARCH_WANTS_NO_INSTR' more
> > > precisely, say with an override or something. Because as-is,
> > > ARCH_WANTS_NO_INSTR then doesn't quite reflect reality on arm64
> > > (yet?).
> >
> > It's more of a pragmatic thing -- ARCH_WANTS_NO_INSTR does reflect reality, and
> > we do *want* to enforce that strictly, it's just that we're just struck between
> > a rock and a hard place where until GCC 12 is released we either:
> >
> > a) Strictly enforce noinstr, and be sure there aren't any bugs from unexpected
> >    instrumentation, but we can't test GCC-built kernels under Syzkaller due to
> >    the lack of KCOV.
> >
> > b) Don't strictly enforce noinstr, and have the same latent bugs as today (of
> >    unknown severity), but we can test GCC-built kernels under Syzkaller.
> >
> > ... and since this (currently only affects KCOV, which people only practically
> > enable for Syzkaller, I think it's ok to wait until GCC 12 is out, so that we
> > can have the benefit of Sykaller in the mean time, and subsequrntly got for
> > option (a) and say those people need to use GCC 12+ (and clang 13+).
> >
> > > But it does look simpler to wait, so I'm fine with that. I leave it to you.
> >
> > FWIW, for my purposes I'm happy to take this immediately and to have to apply a
> > local patch to my fuzzing branches until GCC 12 is out, but I assume we'd want
> > the upstream testing to work in the mean time without requiring additional
> > patches.
> 
> Agree, it's not an ideal situation. :-/
> 
> syzkaller would still work, just not as efficiently. Not sure what's
> worse, less efficient fuzzing, or chance of random crashes. In fact,
> on syzbot we already had to disable it:
> https://github.com/google/syzkaller/blob/61f862782082c777ba335aa4b4b08d4f74d7d86e/dashboard/config/linux/bits/base.yml#L110
> https://lore.kernel.org/linux-arm-kernel/20210119130010.GA2338@C02TD0UTHF1T.local/T/#m78fdfcc41ae831f91c93ad5dabe63f7ccfb482f0
> 
> So if we ran into issues with KCOV on syzbot for arm64, I'm sure it's
> not just us. I can't quite see what the reasons for the crashes are,
> but ruling out noinstr vs. KCOV would be a first step.
> 
> So I'm inclined to suggest we take this patch now and not wait for GCC
> 12, given we're already crashing with KCOV and therefore have KCOV
> disabled on arm64 syzbot.
> 
> I'm still fine waiting, but just wanted to point out you can fuzz
> without KCOV. Preferences?

If it's not used by Syzbot, that's good enough for me -- I can apply local
hacks to run with KCOV if I want to in the mean time, and I can debug my own
mess if I have to.

So FWIW, for taking that now:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yae%2B6clmwHox7CHN%40FVFF77S0Q05N.
