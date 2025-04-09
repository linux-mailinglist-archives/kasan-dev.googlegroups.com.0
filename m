Return-Path: <kasan-dev+bncBDCPL7WX3MKBBC5O3O7QMGQEWFT6DKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 63CD4A831D6
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 22:22:37 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-72bc3351885sf98585a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 13:22:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744230156; cv=pass;
        d=google.com; s=arc-20240605;
        b=aa90Ii3If8HNNtya3V4Bdwmc6Z0okxpvgZlWAmUlvDB//gTgAoWYAx4y8qOqqEOh3s
         LkSfBprlD8DY8aBA46MaWHpxlLDyQL0qrnE3hcWeZFFa+iLDxkvPIcC4VGlnW8A/PbKq
         MsAzA0yJsCqMC/bw9uizZN9vWiLxLTjqmj9bZtvCgGwyaZh5n8ew6jo6kSwbROenLbYO
         6L37FgC026TtnrAU1koo0f3LAYdJIQ1Bm2hrd/tTBEbrhXD8pGsoThH/K70+toIorSrd
         1WLqk+5i2qntpn2vQG77TbdyO5WR+aWSqr1nTSVM1x0UXxzfDhnQ+VlgoXclziHmGM17
         hDoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GP67cVNj8uWWlM+4USLXeuAITh3fodaAHlLRrnbWQ5U=;
        fh=JqSeUy/ZlHgQhCO1LqjyIKv20XSROnK/NjWTgto8fAM=;
        b=KO2OEWa3iGEVUpAUq4ERhuFj/w3yuelMVEIionQpm6NKG6i9OoZHskz7F6rfESICeX
         MPuXL+AUh77GiLmfq0vRP0Ll8j7nZm0sUJOTEMEQVZh4I63HGTAPJfYNtWQraDxEODGb
         Y1BTH67GdrG3cgcjTojzHOkqXDP/vSYLE0FMkx5Cphl8pwEiqDZOzvQUU7fsEHCx2jBJ
         CAbzleD1TfpMZ/XMw8HwloGvxu0wCYN/GLMyREdvBtQMwpSnYf3H6yNh5mQTWuywtcqU
         VeLi6DqcND0LeT34NLV7IzePuc7qBywR72AhY4hk5zkMnMB+BaYX69njp3Nxhw6IdaVj
         GKFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dOnDX4dL;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744230156; x=1744834956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GP67cVNj8uWWlM+4USLXeuAITh3fodaAHlLRrnbWQ5U=;
        b=MjlRpMF7BN/nk5B3FQZe2CC5zNmnjSkHoqt5ILruX3mUH/vHiMhutgD6xAuxd5AfKn
         zVCGtRtWOT2KxJiXwYaNUoVVZafGpBQjHuJnUd0hdjzYzLkhiLZ+9TKiRieVGERomFG8
         NrPq+Rn15cj18+L2AvK/l+264rDYIhjuYB41Yc9pZqshm1YMUoafdNA63hJJ6ZWbNZag
         YXs98LssdTLrU6R2Pfa8KIMnT0tgGSZXcIq2lc85QK6P6AIP0RgX3jokqQqDiAzmTaps
         gbXuxgXbmk3WaWbdHQPu6w/4DP6EvTsm6FUcTl5+GXPppw+Z7WETLTmGKhWDGqwg+uPh
         w9Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744230156; x=1744834956;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GP67cVNj8uWWlM+4USLXeuAITh3fodaAHlLRrnbWQ5U=;
        b=bqAQ8Sb/6NouJieXr5tvJWuoh3QpyRIbkh/pcj2hNO0YwBxMy9H66xxnfZV4WhmXjJ
         3Xu02m4eyERp2XVp6lr0fSCsOnJI9PWffZWo9CBHmkNSM6Cs7U/zu4FEv2J5VuXYPcfV
         wFXqfPaKdBEdwr3Nvredr1M+FEVx/+F3uWfVRy1fGPyT23Az48VSUsbEGgNEFq1ygVpu
         wY2LJDnDu9xKj9GYjubSUJmq0Vb2ep86ohCvd2ZeV8KPP9xHATLKf5vB0gFhaBOTw5iA
         YfR7WHs4pvmRUxIx7k24Nbu5JRqzdH2SMQ1+2p4Bw75q9/cw0kwPfe/t0H0N9o/y2BlD
         CK6w==
X-Forwarded-Encrypted: i=2; AJvYcCV8CjJDuy6RAt2f7k3pDTVeFLZ3I+fKSFiScl9IJwbcheKcecSeaRAfNHuHUAK0TjCUNkS6Gg==@lfdr.de
X-Gm-Message-State: AOJu0Yy9f6xjUVXXeKQgM0WenC3ZKu+rzZEX40GwQXZU/fQYBCdi6rUH
	l4CbtHWWsxqxiM2tZJyuzLYDBLdfaic8i0DAt42YnYwck4yKWhLw
X-Google-Smtp-Source: AGHT+IGMIMLfbisclG0h80Sog4B+Cv3sQy/lbcRkI8iEA2MPhWKmwN4GuVTzcZjXRV7/+yoW855m6Q==
X-Received: by 2002:a05:6830:6019:b0:72b:9387:84c5 with SMTP id 46e09a7af769-72e7ba8a0e4mr244773a34.3.1744230155794;
        Wed, 09 Apr 2025 13:22:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALbKWjca2e7SSzTRbmmJl/nCwOWkoRUqevpE3kMW/HhAA==
Received: by 2002:a05:6871:4102:b0:2c1:52da:c80a with SMTP id
 586e51a60fabf-2d0ad0d6a5cls116988fac.0.-pod-prod-07-us; Wed, 09 Apr 2025
 13:22:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9ECMc+TrM1Xh8uF4DzuDp6efYrgwK2optOh6Er1vcPv6QFvS65n+Pk+Beb670e1g8l8aI22LF27o=@googlegroups.com
X-Received: by 2002:a05:6871:d043:b0:261:16da:decb with SMTP id 586e51a60fabf-2d0b3613048mr72214fac.11.1744230154984;
        Wed, 09 Apr 2025 13:22:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744230154; cv=none;
        d=google.com; s=arc-20240605;
        b=D44V6X/S6eiuwgrTkRZkJwbq055SIO4RBdTh3RWnW0vTGCA+vH9X/clo+pdESjQTST
         fHmhzdFhVaSJaYd38F3lxwmjAPSyaUwzANglgXVm6FOy4mNaBCHSDbym3OZIQBIcCjta
         LlKVLxTOXdLxi2ERnUF4DQSf+Ko0E+5OiG1KbLf1H+h/fm0c+GjXAvxxo9pjOUPW6RAZ
         S+5KqfmGOiLQbDrP5cWiGLqcIcoOjIGToc6+ucJ0AeuUCiqcz7F0sPNOCu5xiFvnXtU8
         W01wySOyra6VcDfNe0mM+eki/NGyAZR8Opuke9/+VNBcyCaBNGZdZaxI1UTZbZ+fIqza
         rowA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xqncvkmL5FUmnJKzMAnmLNAMgl3jFeiT7AG7fOS+EVQ=;
        fh=GGSsy7+1XFV2osQAgZOdt+BHIQkY4zrIeIzu+f1I/AU=;
        b=eMWGIrOyWAZEZSxh8Sx0M9DCOma64up70Dx2YdjX48k9qZfOeckSz9uc6DaDxHdytD
         EtvDXaScd+NV38Qv67kN/VapNY6BJmSA091VWl9uKcLpqEvniaj0o4BYPN/nD3cS4jJl
         gKSv/aebgTbcAnx7MKw1YDfOZuZenp/K/yuSdsT1iJ07hQ1ncdZQ0pKzklMxwdZ/sXPh
         SIOyyMjM92yUE1J1VQAosxKuniwKiD5HjO4SEKp7YLtV4pcyOe+6R4Xjr9OIlk6QRiCq
         4uaHjbXo00rogzD9FxONzAlyUrzCA+A3sHKVB0X1ZEjv3NGroGL87TkguEjnWqwm0WL6
         v9Lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dOnDX4dL;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d096c6b127si58232fac.4.2025.04.09.13.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 13:22:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A9A0BA485BE;
	Wed,  9 Apr 2025 20:17:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E9ABEC4CEE2;
	Wed,  9 Apr 2025 20:22:33 +0000 (UTC)
Date: Wed, 9 Apr 2025 13:22:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com, Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] gcc-plugins: Remove SANCOV plugin
Message-ID: <202504091322.A6EBAC8B@keescook>
References: <20250409160251.work.914-kees@kernel.org>
 <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
 <202504090919.6DE21CFA7A@keescook>
 <6f7e3436-8ae8-473d-be64-c962366ca5c8@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6f7e3436-8ae8-473d-be64-c962366ca5c8@app.fastmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dOnDX4dL;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, Apr 09, 2025 at 09:28:22PM +0200, Arnd Bergmann wrote:
> On Wed, Apr 9, 2025, at 18:19, Kees Cook wrote:
> > On Wed, Apr 09, 2025 at 06:16:58PM +0200, Arnd Bergmann wrote:
> >> On Wed, Apr 9, 2025, at 18:02, Kees Cook wrote:
> >> 
> >> >  config KCOV
> >> >  	bool "Code coverage for fuzzing"
> >> >  	depends on ARCH_HAS_KCOV
> >> > -	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> >> > +	depends on CC_HAS_SANCOV_TRACE_PC
> >> 
> >> So this dependency would also disappear. I think either way is fine.
> >> 
> >> The rest of the patch is again identical to my version.
> >
> > Ah! How about you keep the patch as part of your gcc-8.1 clean up, then?
> > That seems more clear, etc.
> 
> Sure, I can probably keep that all in a branch of the asm-generic
> tree, or alternatively send it through the kbuild tree.
> 
> Shall I include the patch to remove the structleak plugin as well?

Sorry, I misread, *stackleak* needs to stay. structleak can go. I'll
carry that.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504091322.A6EBAC8B%40keescook.
