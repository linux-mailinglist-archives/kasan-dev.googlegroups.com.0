Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7YT2GQMGQE4HEADEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F93465503
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:16:40 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id i3-20020a170902c94300b0014287dc7dcbsf10639101pla.16
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638382599; cv=pass;
        d=google.com; s=arc-20160816;
        b=N3P7ODSCOvkuH49/layRIlnVEOdidw/MuWn1Q7Y3UBFTxFNovKKR98Urb9axU20Dto
         bNcqry9GVqtVWFXJGTNSKh1qYalv0hEUXiN440rPelYf+aCyiCHbylEJIIrDOgQzeGjN
         HpZNnS3GpErmLBUkarOrfvAE9ba+Lx4++sqwJR7xPKdHbRDbldbyDTsCHS2E9MTMxzC9
         jo4ujCvWpDXLyTvjhjj75Xja6afkbLm9Ds1rtI1Xgu19Xc2oiCqzpvPxvDQWiPLaW5b6
         X1kauvmqmNgF5Dn+/dKjDlIJom0JPOh9w7RKC+uo2nT+0ZET0dQ+MmIQz5hmQFx7kQkp
         p1Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DFzigi1FhytZWMh/VkSyq9REGnb7++cxNnlmxmtzvos=;
        b=WSWAqnpW7oEXTR/Ro9F/TEDKPfbnhcOgJRH/Dq19VkPZjhHnpMQUJCJnSGora5M9Yq
         gPIUt4RyT4Va4QTy4lOVL1qcl+dD/xx6uBibRDg2UhTiWK4FnixuT+PBL6weLMNZKIFt
         YOrhOSFLRga9f1Mn4oQja6For/qH5evUAyI/uho+M69hNEN24rXhQl/lASOaI+MUAkyt
         1q/NVblRIAZO6/LdcviyG+u8WAxZUqyTxpR2whS1N+1LZep3n0PR7kp24PTLLRQGetvi
         Qtz6XSr61B576iVCFGO/1gGs7xZzBujB/zf7qvZjTIHLrBsZghURtWiOd/L4nDcZvYM0
         YTog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Cg02J9Ge;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DFzigi1FhytZWMh/VkSyq9REGnb7++cxNnlmxmtzvos=;
        b=WkQ5sxwGmmiLkYsT7uY0WuUSGEaEQmu+1/1N/wTyK1cahahupoURWp8jDFwjhm7zEY
         YLgHEpwcUfRBvahKJLDoMAI0UqF0Z4Ax3o203a0GkJb+X2rvCdZ0X/82GKTLdo5UtXR4
         rx0GCtdQYccSDLhXRH0ZZDqfEISApu2fuXeNq9fmSp4gR7kkU9i46DFCWXnRFqMH5OjG
         Bsgv7Z/6Le+dW7Sy+OcUKYyNXuJG8FlmXDPF9hjc+5HPz5JgBax9DAxfv+CbTEdG2Cdj
         Z1yst3gS8ia3C/MY2cTkY5g4ci3sFIyyBTo6XqRz6VNw2IWL0acGT35h+axIGSYlf9cw
         CpOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DFzigi1FhytZWMh/VkSyq9REGnb7++cxNnlmxmtzvos=;
        b=UG/VfrFDn0dLytqB8gZYyzlGtA8o4j6NqH6r8EoDySKV7HNR6mW91ZUuCdJHe36uye
         7NAoxJzEX+/c4QIX2M7CFrQQlumnOrNsVFTOpHUanmzyIN+hrzZvMV+8zUi2eNsRIbGn
         LNRrxV+CzI9rol2VZ7gyyHKHtVqreqLQa96O9oqpPHx9dBjz9ExrM9ms+1Hg6bEeKTkx
         XSIjke0btjxqMdyXKPCGZsAMXitRfYrH9B2HpKRWkM3+AXi5qMhZu3Tos/8eFpUl/g++
         CqtL7GtU/3Wv8CJvAdI/fu/5lXpWHpZljfWA/dMZ9xL8y33cNSiAAcK2VAIKT+qrX5F8
         DUhg==
X-Gm-Message-State: AOAM530cmD8adg8N3+e7SKjzb/coeGDlNwrvr/UIhgYjxJ2d/ViHcXJR
	nNQZx3GwRkS9itLXP6Foe4w=
X-Google-Smtp-Source: ABdhPJz8vpGRCT2v+Itm7Y+tA0rf2KaP5A4ysH3qHKHKrcPENMUDI1z7Ic6wC+G2qC1dGtcJBFr80w==
X-Received: by 2002:a17:90b:4b01:: with SMTP id lx1mr9546485pjb.38.1638382599437;
        Wed, 01 Dec 2021 10:16:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:73c2:: with SMTP id n2ls1542948pjk.0.gmail; Wed, 01
 Dec 2021 10:16:38 -0800 (PST)
X-Received: by 2002:a17:90a:8043:: with SMTP id e3mr9589957pjw.130.1638382598772;
        Wed, 01 Dec 2021 10:16:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638382598; cv=none;
        d=google.com; s=arc-20160816;
        b=Aq1OidKoE4+UaBaimh6sZd9B7bU+19t4p4WkgYyYGyYjj/ruKiQgoLXM0WjNnRcUSq
         bxIwV/R/xlMZYcWOt7pfCIOpuIShMcF3T2iVmrCl7V+qZOFYyRJ/y2rve593FZ9tquN2
         1y19dfPGbGpOwv4eFZ//51LkhL7k1TCe1YhyACaRfiVcNPKvMnFwEkoQ+QeK496Yq6vk
         SCm/mhdWQoB+ihgMeH5bO4Tq4qUs6TR9rP0qC+uzrQCN7kw4My/9MDgoD2PveLj9hLhS
         tq/C2jb5gcxwefbZxYLJQ/aANZQ8+f2Qvpl7SrsIkq4V9ZRyM4OotGyc8dQdXzk9JFnk
         XRfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wGrsaWNUagkaLBjhVNdr8PrYlBPFyk15DPESvwSI7wQ=;
        b=k2gtOooq6VxrU2ypBHjbcRTvsSvT+MJysHG0ym5WNaR9fILwYStzOTj3j+luOsniBN
         +nSH95uUZwKsze3JH3sQcf1D57hxFcT7+rblcVMLJfzP809rYoWk+TwESFjfPWBSvKKp
         laWRh3Noi0y5/zGqwArys+sQn9IaEmwx36QLKN0qSfUiFmySH8iRg0WRcxZ3Kae4Rh3N
         7+ye/ruuXpxsr5IrouQY19R0gHunFS54FaI4O2dEhgByX0P4ykmdxQo+HW/WuLnzx4uC
         l5aIa6c9z77ZSPEgqAcpKn/QEn/NSVsfI+TRXZLIxpE6wwNMte4+k+5gHRspyZ7EUjss
         d+uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Cg02J9Ge;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2c.google.com (mail-oo1-xc2c.google.com. [2607:f8b0:4864:20::c2c])
        by gmr-mx.google.com with ESMTPS id z21si83035pfc.4.2021.12.01.10.16.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Dec 2021 10:16:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as permitted sender) client-ip=2607:f8b0:4864:20::c2c;
Received: by mail-oo1-xc2c.google.com with SMTP id m37-20020a4a9528000000b002b83955f771so8042093ooi.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Dec 2021 10:16:38 -0800 (PST)
X-Received: by 2002:a4a:cf12:: with SMTP id l18mr5335169oos.25.1638382597543;
 Wed, 01 Dec 2021 10:16:37 -0800 (PST)
MIME-Version: 1.0
References: <20211201152604.3984495-1-elver@google.com> <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
 <CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q@mail.gmail.com> <Yae08MUQn5SxPwZ/@FVFF77S0Q05N>
In-Reply-To: <Yae08MUQn5SxPwZ/@FVFF77S0Q05N>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Dec 2021 19:16:25 +0100
Message-ID: <CANpmjNMW_BFnVj2Eaai76PQZqOoABLw+oYm8iGy6Vp9r_ru_iQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if ARCH_WANTS_NO_INSTR
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Cg02J9Ge;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 1 Dec 2021 at 18:46, Mark Rutland <mark.rutland@arm.com> wrote:
[...]
> > > Currently we mostly get away with disabling KCOV for while compilation units,
> > > so maybe it's worth waiting for the GCC 12.0 release, and restricting things
> > > once that's out?
> >
> > An alternative would be to express 'select ARCH_WANTS_NO_INSTR' more
> > precisely, say with an override or something. Because as-is,
> > ARCH_WANTS_NO_INSTR then doesn't quite reflect reality on arm64
> > (yet?).
>
> It's more of a pragmatic thing -- ARCH_WANTS_NO_INSTR does reflect reality, and
> we do *want* to enforce that strictly, it's just that we're just struck between
> a rock and a hard place where until GCC 12 is released we either:
>
> a) Strictly enforce noinstr, and be sure there aren't any bugs from unexpected
>    instrumentation, but we can't test GCC-built kernels under Syzkaller due to
>    the lack of KCOV.
>
> b) Don't strictly enforce noinstr, and have the same latent bugs as today (of
>    unknown severity), but we can test GCC-built kernels under Syzkaller.
>
> ... and since this (currently only affects KCOV, which people only practically
> enable for Syzkaller, I think it's ok to wait until GCC 12 is out, so that we
> can have the benefit of Sykaller in the mean time, and subsequrntly got for
> option (a) and say those people need to use GCC 12+ (and clang 13+).
>
> > But it does look simpler to wait, so I'm fine with that. I leave it to you.
>
> FWIW, for my purposes I'm happy to take this immediately and to have to apply a
> local patch to my fuzzing branches until GCC 12 is out, but I assume we'd want
> the upstream testing to work in the mean time without requiring additional
> patches.

Agree, it's not an ideal situation. :-/

syzkaller would still work, just not as efficiently. Not sure what's
worse, less efficient fuzzing, or chance of random crashes. In fact,
on syzbot we already had to disable it:
https://github.com/google/syzkaller/blob/61f862782082c777ba335aa4b4b08d4f74d7d86e/dashboard/config/linux/bits/base.yml#L110
https://lore.kernel.org/linux-arm-kernel/20210119130010.GA2338@C02TD0UTHF1T.local/T/#m78fdfcc41ae831f91c93ad5dabe63f7ccfb482f0

So if we ran into issues with KCOV on syzbot for arm64, I'm sure it's
not just us. I can't quite see what the reasons for the crashes are,
but ruling out noinstr vs. KCOV would be a first step.

So I'm inclined to suggest we take this patch now and not wait for GCC
12, given we're already crashing with KCOV and therefore have KCOV
disabled on arm64 syzbot.

I'm still fine waiting, but just wanted to point out you can fuzz
without KCOV. Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMW_BFnVj2Eaai76PQZqOoABLw%2BoYm8iGy6Vp9r_ru_iQ%40mail.gmail.com.
