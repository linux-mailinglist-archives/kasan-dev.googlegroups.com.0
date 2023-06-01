Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPOG4ORQMGQEDYB67HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BE2871F1BE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 20:28:14 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5584f4512a1sf778161eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 11:28:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685644093; cv=pass;
        d=google.com; s=arc-20160816;
        b=KR4FiJMojmsyZz0dWcQR1TV8wM7Kdy4StQqAhO+vcEnNXlaY6nrk+4jbVgHtLVKdX4
         w2rDmsjjCSHgGVRkh57+8CFNA9ZstVqJbmEbFkpxXBrV8B5FFUUMu84AU8LTsmQYdJnL
         VxEPA95j/GAz0wtzYl8OOEHbBFooObaTcZ+LuQlN/otmOYKHeF8d8fuNd+BpOThe3iX3
         JxJZzMJrp3s4ijAZJyHK7S6qk6MS5V/YDcpJ4AtNCVIMdTPRcWXuO1LOdiXUPiAvhZTn
         dpuMyy2leM39PV5mZ3DAteZmmvYBiqjvbphwH7zLOjC6pZL/7lHCjimDARzRxMgipk8X
         X2nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xO6SUTwAKCkdYaavEALa3tvFw62FrW2XvGQfgE+u4Kk=;
        b=ydtDG1UhUiG1tzZxrG72TdHGXTiPU3kxEeAjDdWeyCsEu8fDw5QfhZC5dusmt/hF2r
         0C20rrc/zeNbPggWyyv1sxVuR/KKmux1A0HW06tAWnEujNBphth5uXASOZvwL1j1DXWJ
         JjWOBDEIx65roiXm7tQD3blwYLHHD9TF/UlwhfxopMPpZs/NE3/q45d88PHcGb/+6MDn
         moJpLoz88/fdrMW4yiUp+LMFVhd8Dz9IGnh9krBWtqNEzL4/usqID90QtYdH8GgQPozs
         5YzYEn5DdhiHFLuvPz4VhlaxuQ0WsaMHMkYFdzBH60WssRUnc30ALyS0foZPGrSZU4/j
         6Piw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ac+D7llp;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685644093; x=1688236093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xO6SUTwAKCkdYaavEALa3tvFw62FrW2XvGQfgE+u4Kk=;
        b=a27ZwVKzrNP1HiKF1xjc4cCuyzlmgRlIrUjWc/prfWlnV/MLjl3gzWn/tdwlVezF9H
         F/yA9u0QqWo+3DmXzssP8CrI4UWb45pIMlCDNJ+PQ7SXLjumb2Hc+9RLHNnO3qHgP4IA
         e2UDHoKA52RjF8dLZa/1B/qr3rUGhxAwvUd3EQrMUUM55VhdD+Iz95/lMQ16Q4r0VyAI
         TgTAfQZ08YXfmRVgtvb/c/22eRAdE7qCGaNPQd1lntECE+zskifOca2uvR1LYfITmiTm
         m2WnyF+sdX2hUh2111EB8suir/vXYPLwtYZ2T+5hwdWqSESfMCPBAggd08uXhYJt2oOi
         VDVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685644093; x=1688236093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xO6SUTwAKCkdYaavEALa3tvFw62FrW2XvGQfgE+u4Kk=;
        b=EpUb0w4p+VIujdg+bdmhQjtxCYLbZyz0pgnOIMxD9lJwN2Na+srAWP3SkdMraei0DX
         kEGl2jc4RaD7gCF0qouPFHU+oY25/m/qgK75ez/7w89hJscV6dRBuC5FwNlcUPXVCjsR
         p/v1tv4rCRgJXd6/qEbEzS7nPgjpObC/O71za+RWZVq82rdDxZXccSMBNOrVLGKOBSOI
         3ZwSA9eRuJA2ABG01Zvyo6zTwdtLFI57ULDfUIDXmphIftPJ26+bmn6hyR+PgSc2ldu8
         qLZerPjrRBHQcQkaMssZydaDsd8+Bo6SuWbH9dfKOQGywxaLJnxD+IAt/5hhYkaZ5guv
         z4ZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzbQzHr+pa+deCcW3pmFbXXCh1SYCcpdZJ2t1PpW43SN6CCk3Y+
	VEf0cQ8uPQkLixwL/T2qWjU=
X-Google-Smtp-Source: ACHHUZ749rA7X0AkswHQaKStJ7TFucCVpVv77JqUQPHZtM8ILCtJHOallquP3uuTUdlDTzhX3WpvkA==
X-Received: by 2002:a4a:4913:0:b0:555:8c22:a169 with SMTP id z19-20020a4a4913000000b005558c22a169mr4866908ooa.9.1685644093182;
        Thu, 01 Jun 2023 11:28:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ca8b:0:b0:555:66e1:464 with SMTP id x11-20020a4aca8b000000b0055566e10464ls428223ooq.1.-pod-prod-03-us;
 Thu, 01 Jun 2023 11:28:12 -0700 (PDT)
X-Received: by 2002:a05:6358:7e8e:b0:123:5208:30d9 with SMTP id o14-20020a0563587e8e00b00123520830d9mr3406645rwn.15.1685644092734;
        Thu, 01 Jun 2023 11:28:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685644092; cv=none;
        d=google.com; s=arc-20160816;
        b=f9Rod93VmtSkBG/V/MBHreaMDutSQOjvvZv7k3Q5QW72ojVR0hnscrbl7bdPUO7XOx
         P2l0BAf0k2MHUlfAp3yaYx9ivLiDbKxViNzjH2HZoZ8rQIkdSkMXZx4N4cXHIOyRIAmv
         6GYPvznJuT2ch6WwOyTVT9yo+pJNgdbWywZFp/wWEyEIrndSr5zYVgDEGAajfc2ZL4lx
         jE+8kITEC+fdIhkaF3JZBkqxtRv/VT+AIb0PWh4eWZtU69zoAXe7Rk7ofinTK6EaV9j4
         cOClZ+aXGskyxGZP1GyX21QKjkCQkiT1R7HBVpbxjDiQY4GWK0U2noNzHKn0iBq+O7AX
         B8ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZZLQgV5OTogJ1ylkCDiOjxfc1T+CJXFQFeKoN9hX3ug=;
        b=R9H9vHz7hNgHPbMIALmXy5CTnRzEHLCwS23tn9WuYJTEQg1wQ4DCogeMkl0U8kjiUQ
         7XCeZMIvuHhZ8d9hxLtZOw6UvrVBLxUdGSb+Qmh88IwvwDVQpNVLZgL8SAZ3g1w2DctR
         yn7WUmV5SBQFAiTl+6OM83uXiP7VdSxqyQEnmQaeQibTmOQ/BSBAeRhCv6qz7uoTYpbG
         j/gPxus0El8p6rM7gZETPdS3r3B3wEX+a9Ka9u0/eKxaCxJ7m4l/bJ2x7Dvxs3r0MMFw
         hRjlZAC4dtJzs+BjZBupLVqScwxV4yXttS4vzEU6idwrBNEOX0cLfjcd8JZg6h9FENcJ
         DyNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ac+D7llp;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id b4-20020ab00b04000000b0078701842199si695135uak.2.2023.06.01.11.28.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Jun 2023 11:28:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1b075e13a5eso10310915ad.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Jun 2023 11:28:12 -0700 (PDT)
X-Received: by 2002:a17:903:2286:b0:1b0:1036:608c with SMTP id b6-20020a170903228600b001b01036608cmr261752plh.25.1685644092279;
        Thu, 01 Jun 2023 11:28:12 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id n18-20020a170903111200b001ac4e316b51sm3833178plh.109.2023.06.01.11.28.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Jun 2023 11:28:11 -0700 (PDT)
Date: Thu, 1 Jun 2023 11:28:11 -0700
From: Kees Cook <keescook@chromium.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Arnd Bergmann <arnd@kernel.org>, kasan-dev@googlegroups.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>, linux-media@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ard Biesheuvel <ardb@kernel.org>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Dan Carpenter <dan.carpenter@linaro.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, llvm@lists.linux.dev
Subject: Re: [PATCH] [RFC] ubsan: disallow bounds checking with gcov on
 broken gcc
Message-ID: <202306011127.B801968@keescook>
References: <20230601151832.3632525-1-arnd@kernel.org>
 <202306010909.89C4BED@keescook>
 <f6fcae8a-9b50-48e4-84e9-c37613226c63@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f6fcae8a-9b50-48e4-84e9-c37613226c63@app.fastmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ac+D7llp;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f
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

On Thu, Jun 01, 2023 at 07:50:38PM +0200, Arnd Bergmann wrote:
> On Thu, Jun 1, 2023, at 18:14, Kees Cook wrote:
> > On Thu, Jun 01, 2023 at 05:18:11PM +0200, Arnd Bergmann wrote:
> >
> > I think more production systems will have CONFIG_UBSAN_BOUNDS enabled
> > (e.g. Ubuntu has had it enabled for more than a year now) than GCOV,
> > so I'd prefer we maintain all*config coverage for the more commonly
> > used config.
> 
> Fair enough, I can send that as v2, but let's see what the others
> think first.
> 
> >>  config CC_HAS_UBSAN_BOUNDS_STRICT
> >>  	def_bool $(cc-option,-fsanitize=bounds-strict)
> >> +	# work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
> >> +	depends on GCC_VERSION > 140000 || !GCOV_PROFILE_ALL
> >>  	help
> >>  	  The -fsanitize=bounds-strict option is only available on GCC,
> >>  	  but uses the more strict handling of arrays that includes knowledge
> >
> > Alternatively, how about falling back to -fsanitize=bounds instead, as
> > that (which has less coverage) wasn't triggering the stack frame
> > warnings?
> >
> > i.e. fall back through these:
> > 	-fsanitize=array-bounds (Clang)
> > 	-fsanitize=bounds-strict (!GCOV || bug fixed in GCC)
> > 	-fsanitize=bounds
> 
> From what I can tell, -fsanitize=bounds has the same problem
> as -fsanitize=bounds-strict, so that would not help.

Ah, did something change with GCOV? This (bounds vs bounds-strict) is
the only recent change to CONFIG_UBSAN_BOUNDS...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202306011127.B801968%40keescook.
