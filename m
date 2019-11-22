Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQVE4DXAKGQE7KVIBGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E0C3107600
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 17:52:20 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id r3sf4144774pgs.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 08:52:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574441538; cv=pass;
        d=google.com; s=arc-20160816;
        b=f5lelLQ/L9elCBP4GkIkAWZnlkFYCxwb4GM+izrKRPvkYoKU2nLZX0l/z09niFsJiv
         vyqGdlKQfSpAIWdkgAWchxU4jFsGzdYqCNZlcGy0KoAXCv++YpAkake5ovdbLxu4y4sh
         Gm/noOm+Adt5Kx9cZknYs3MGKbbmfOzYXNtMtbQrFZBWuxkdylsjZSrDdz/S6QSY+pwD
         GXA5GfHgdJBCaRKk6oDWBLuVOK5wbHDjPCxDQ15W47CG2RCtgSDRrNE9tGg7L1QUAFMN
         38/N23AD4g2sfQnvgHwEdIscyMzM9OvdaygUZiM5GRE84yb88QfUzsB5WEZTNrYw5KyN
         4q7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=s3vxo+qXrccJpVplVx8XkppcCd73oBvCXcI1EOMDVJA=;
        b=NFnQXLadLmio/91cz8gLFGZya3uFDFg/KvLRodWF1nVpL0eN1qOiPrag8c/T/+yjHu
         itq8BzY+w6TC8pIhfJluoJdhZC6DzlIb4aJlnjJNQZu9CdMzr/b/TfNMOMaC8WwG7aJF
         63cu0sG4yOLhLdsBS4vOEcixaxY2SUV85sD4ENK2P64haXe7PAl85L0j57pJlhJ7w1U/
         XiMdrsSOG06Pkh2df1/AyDhlft2tJaeL3vYw4ly9fWlPlIn2ZWm3o6KjdfvfkphgeWKR
         S4alpb7+Lgtit4LD9zZqcqgxqYWKG5EduZxVmIuC3w/GfqOdAm/EFkYH4U6B3hv256Vs
         lsnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YcLtVyut;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s3vxo+qXrccJpVplVx8XkppcCd73oBvCXcI1EOMDVJA=;
        b=llUN0IhCKH1UNNEAlmFgzHqjpnLcaU79zBlMUIE3yOf+pzRMm2ZQc+OA3/2YRiUG+i
         2QATrkvIVSlzAYugH5ZfdLPwqp41KeOU2H3wEG1ONT/PeHh3j0/N1Why5cXpo6zbI/12
         FRMMlrVGvcFj73xgRTvx1vPMV3JRvkZxQIURMJuTR2a/msjFOqvrRFeCWjgPwRzI2n7/
         xS3FUiractaNM+Sy5jTGpIot7bxVY5+cmSNeNjgdTJin1rG6Q74HwYHySqWYFt2m/oOc
         FMbNTHc4Wf6/km/0r2GuWmxLm6lGq/3kpyBM5Cht+Eks6V9MskN+p4rMS0A7V6/ofv6D
         s2OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s3vxo+qXrccJpVplVx8XkppcCd73oBvCXcI1EOMDVJA=;
        b=Nn9TVj5judFxfI07sXxj3TFDbIjy350K/QbMPQxN7HeGWiWq6SaVJxv9rYjn/OQKmK
         jB/ui7iyOAYbBjc42O7HdXrOzwcRCRs7OSwKRlUed+Ub/fWFZWA+Whb+cXuZWfAksgyp
         vNUK/Y3ujtlF+q0ns6JBwCU74aHbTCVvyWRpjLuIQnRKveiyuSxosTLfd2WF+bEBvWGg
         d+Z2KQhHt9cE+e8vBYavEkFf3azWyz8CED6uJ7NxOOXmzlKzoieeNeRSxifkeCnPcv3q
         mjU0CAEIu6R52PSF54k5nau++n2F9Ant5IGa04sIIW+mHx9xic9GDNDoeipYO9UcRBJi
         XN+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXt0z46c8KWX/SJvtLp9gwd4CJIfpicuqR/e2PAngllWlWmsMrV
	g9nVBKV3g7YnVX9TJedf3zg=
X-Google-Smtp-Source: APXvYqyQIcHCFsRFK4cJq3bAwDBWDsjHKkYkGhK7yeQ3IYiXOwBZ/OgwpJoE//12zIW19XVsIff8BA==
X-Received: by 2002:a17:902:244:: with SMTP id 62mr15680625plc.14.1574441538323;
        Fri, 22 Nov 2019 08:52:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b30b:: with SMTP id d11ls2449358pjr.1.gmail; Fri, 22
 Nov 2019 08:52:17 -0800 (PST)
X-Received: by 2002:a17:90a:f496:: with SMTP id bx22mr20464563pjb.101.1574441537937;
        Fri, 22 Nov 2019 08:52:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574441537; cv=none;
        d=google.com; s=arc-20160816;
        b=Ep1SWnJFRsjk4IGE8VwzC2x2MyCVMbemOSczT3t9gBt47XVNymr89N3FksyhhI6oj+
         47a5d6mP1B6O6JSMnNxzhYmDTGZHkXTnOcniePLLsozsWnu8yeugdtBI33Jg1SGQzoGo
         Yh6/HwcNGfNv/RjaCrVJFDZ7eGMZvwdRbaMEB7bWsg/dwUvbzFpLGJseUSSr9/gUJD/9
         2ADvD80XPMLEQgNEZo2RmlkQEpj/hmc8QSOCFseO00lFRysHGYRJj5gy+Y3V3ry7grbd
         7SbQP6ATTJ1GQjznYHlYeXfJ8PdmhiTnlxLNiOTN8JZLSfTJZg94XkJlKfxDBoVaBN/Y
         UZKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bIBZ/pDagkMXdQDKDvezMxRb4iRHYel+ahYnkHe//Mw=;
        b=rgEvXUpNH6UuC39k2gAEQ9wvYSXW4eJwHyxe/Git0eEsY9TATjh67TpDSZsrBXnE3l
         wrjkNSg7RSSUzKgAAnpmLMEYF7uSj/MYEUO2GYUqv1q2DOPRKYGefeH6gvfJ7AiaSYq4
         yfhf70s/L0yOt7AQg0Hnj31b6Zfz/FQ++aZ5jqf0ViIQJM8v0ztaJ26wnS5N4xfNjWWJ
         YWfxKofpicJ5XJpr+XQlz68cjmJGJ6F14Z9ezPus9Gq6BO1L8MpBvciVpC5xhy6ZNr0o
         CJjuejQYaNiroGXVhgzPNAmNnHuRrvT16FmzYkLVLeZjQCTx9gSKND+lj4+wfyTkhVgf
         D1VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YcLtVyut;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id ba9si270547plb.5.2019.11.22.08.52.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2019 08:52:17 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id s8so3275760pji.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2019 08:52:17 -0800 (PST)
X-Received: by 2002:a17:90a:de4:: with SMTP id 91mr20505683pjv.113.1574441537644;
        Fri, 22 Nov 2019 08:52:17 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id u65sm8020297pfb.35.2019.11.22.08.52.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2019 08:52:16 -0800 (PST)
Date: Fri, 22 Nov 2019 08:52:15 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kernel-hardening@lists.openwall.com,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
Message-ID: <201911220845.622FDC4@keescook>
References: <20191121181519.28637-1-keescook@chromium.org>
 <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=YcLtVyut;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > v2:
> >     - clarify Kconfig help text (aryabinin)
> >     - add reviewed-by
> >     - aim series at akpm, which seems to be where ubsan goes through?
> > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> >
> > This splits out the bounds checker so it can be individually used. This
> > is expected to be enabled in Android and hopefully for syzbot. Includes
> > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> >
> > -Kees
> 
> +syzkaller mailing list
> 
> This is great!
> 
> I wanted to enable UBSAN on syzbot for a long time. And it's
> _probably_ not lots of work. But it was stuck on somebody actually
> dedicating some time specifically for it.
> Kees, or anybody else interested, could you provide relevant configs
> that (1) useful for kernel, (2) we want 100% cleanliness, (3) don't
> fire all the time even without fuzzing? Anything else required to
> enable UBSAN? I don't see anything. syzbot uses gcc 8.something, which
> I assume should be enough (but we can upgrade if necessary).

Nothing external should be needed; GCC and Clang support the ubsan
options. Once this series lands, it should be possible to just enable
this with:

CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
# CONFIG_UBSAN_MISC is not set

Based on initial testing, the bounds checker isn't very noisy, but I
haven't spun up a syzbot instance to really confirm this yet (that was
on the TODO list for today to let it run over the weekend).

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911220845.622FDC4%40keescook.
