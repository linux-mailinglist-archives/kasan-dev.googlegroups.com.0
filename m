Return-Path: <kasan-dev+bncBD4NDKWHQYDRBIU4YCUQMGQEFB4HSEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 621A57CE337
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:56:04 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id a1e0cc1a2514c-7b6612624besf28691241.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:56:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697648163; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJKI+LvWlhIZQ1doKs32Ng9oyYiTTwiVXyQjMm8utiyKeYnT6OeZKm1ePjxOHj2n21
         Ef49jSHRyn8U8LqgUrnV31N6ZGc3qLkfVjAiiQK++y44UpIoLpLamozn2W7GDdTXFrv0
         cdrXblCxuI9wTuJy02bHj50I97WP/d8JJe1FuKSCC5GkVWTmXO1jMSMyaibyc09SnBQt
         DlIzZ1rTAl6ZYlu+cSl39Hy+Yb/gu3pPnLIjlu3TeMopaOJj5B60Xo8tY9AN1nFz2g5B
         Vsni0YKUI+DZC0r3otnOkQpl9wOQwoLC/UPhT3HscLiYvw3jXHHJndt0BkRjGHWrhQV7
         iUEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RU5xRmxu+KF1LG5SMOle5TbwsqV3iXcF65quANDJOkQ=;
        fh=u8dRyJvPEF73QXyEqgpj3VkHAebZbv2VfqV0cynRMrA=;
        b=bLKPmCC+JClKLfmzP6sMiL7aNdslyO+dBpZ2F6ZQcmEb6RZtxo0hqWfccqnoro2DhN
         U6Kn9vql9aPUPleRXGzDczOvfyPcMCFGd+q3USecda4XxdrdLQDsi36AbfzNbNUb2NhJ
         e9/LR6SpdaW/l7FBfJE4UdH5TMBo/jSWc1radA4RbBZ/ssTkV7MsxuJsaBRaiyV196d/
         sF51hn1e7LVcXQ6Qe3qVIj1McnyGOifZUeTTf2s+Ia8aBhob5dC7uMEP2vEDKADUSBmO
         Rpp/ycoyHkoIZgj20FCIkpmLOaV39Nq3RwI+3Qpz+fzP2vkALNEK4P/NgwBggSG8hGmv
         3kTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H3cQz036;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697648163; x=1698252963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RU5xRmxu+KF1LG5SMOle5TbwsqV3iXcF65quANDJOkQ=;
        b=LqfZj69yBTp6dhqhiNDxQO+bNq00OIKEWb7d9FIMdleFetlRnCV1StyYNyVoWy3oX0
         ZDpCibzfVd9+gWF4mCIBIMshMcVcDPRlaEimTtHNFDLx+paLNLk6lwh3OtxekuNm2prt
         FTlHwOJkSbEdYu/CfKWJD1v97oFwsNV/j7nSyRDei5hPD+6yj3b3jx22mdNJQf+e+Akp
         I32Bz3AFHdHC+Yrn34O70Epk2PT1sDmA177MFYdU3w8r1+ZPSvnsR08keV9e8SZ7281Q
         /zo7gdZ8pLsdWgn+8pyeYrB298u+RfgjM3dkPGlRK1Mby2lLwRX9D9tL95dpwLLfUMd1
         FsfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697648163; x=1698252963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RU5xRmxu+KF1LG5SMOle5TbwsqV3iXcF65quANDJOkQ=;
        b=Vgd3kbPNpx0YVFlRCWiPovxRyLXSORPlF7KXmJbFkNlB3q24B2lBUM3uircOCkrD8Z
         pbl8ssTqxOpHAHI36+qfC6LKFyfQZsUTUIajayWCz1aaDJjaXN82giu+DheLkJi5ypM8
         B777ar777RtvI4xWCUfWa/kZwhblmQtVWeOimPYyKZEWTUm+Zf5O/tVC+AUY5tqB8NCP
         c36aR7Tt8/5/7rTXy1wrE5HDgzZnApdZc1QwFG6PYIig/EzWErfPJi+jdQr2O6QWGDRi
         OWZkKG3PUWs79yDRUdM0VbxpMJOrmFkkiKIi1hN7zjBVbsEhczpRkbFaBr/C4TfAj7rx
         tm1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxjlDsieShRxVPJRAjgIdF6MoYPqDOoUtw2dUKb37wGZVhaHbgo
	9cSs7XIIin7O9wbHHN/5w4o=
X-Google-Smtp-Source: AGHT+IE8Foo8n+ryPmmJf+vHWpPxvr63HKtoZ1HLMSRD/y6YaIXt+hkrmPgi04U3TMC4G1lkl26Eow==
X-Received: by 2002:a05:6122:16a6:b0:493:5938:c8a1 with SMTP id 38-20020a05612216a600b004935938c8a1mr4647048vkl.0.1697648163026;
        Wed, 18 Oct 2023 09:56:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:514c:b0:41b:5e46:aa72 with SMTP id
 ew12-20020a05622a514c00b0041b5e46aa72ls363434qtb.1.-pod-prod-07-us; Wed, 18
 Oct 2023 09:56:02 -0700 (PDT)
X-Received: by 2002:a05:622a:1647:b0:40f:ce6d:775e with SMTP id y7-20020a05622a164700b0040fce6d775emr6987844qtj.42.1697648162065;
        Wed, 18 Oct 2023 09:56:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697648162; cv=none;
        d=google.com; s=arc-20160816;
        b=p2IiDeJ7707c34SQx0ctT4g1acg8Qyu2MzYD3wisXuNDh07eSt0EZUg4Dn4ztMYFec
         s9r49t8nwcTuajR5WnbdYoflJv3AvxiAVQWAIeN1Lx+bXSoJYHQwu6jeMWfQZdbMfMCw
         sCaPvMd14Oz5fnV9chi8Adi7j7sBsncT0ypgvzUrAELhNtO+9sK2+nNyxysZkQfIFzGm
         AyVi9FWBJ1kJUt26WlUkPG6Qbo+qnfM5EJgLqHJwZdeAlEdFzXbpz8w4v433M2VcIrQ+
         cO+e63aeMZ2KI9tlvo84icza+IgYbvLG+6Nkay8ILwHPhd9UB3/PRxxRotLNGqcans/N
         pZWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iEiVddyN23iDfzNTu1H4JbYfUqUWWqwzoO+DN6cFAWM=;
        fh=u8dRyJvPEF73QXyEqgpj3VkHAebZbv2VfqV0cynRMrA=;
        b=sqmYfwt1kcJ2Ab32+UKdINuYLck6XI9CUKLaZAadE72s9mVZ33aWbQyRCXanCWOLVT
         wqp45++2TFk+WwSRjC/i9glLQFZ7fusGkb/N1LOYusm/4ZMXqNNJI2m12Nf4DBvSBoki
         53V5j8IW+cheCMvbEkdPpFK4u7zZOaqqrGou+sihJRrfQTs1V6F97ljIdfGd+tNg81+l
         kE0gtqpyf3G5h4dXA8XgTfn8cevGwSJKdR3DkqK4rQBNs1qBGFfQwD74z240USfHZn/8
         mYTI1hdsSXCrb8btwxVmE7CwEteDONXmykIsoUqQ5Zg+HZ1nBXc0D3WBL/pM/CZ8KidU
         7xVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H3cQz036;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id e7-20020ac84907000000b004181fc30323si21713qtq.0.2023.10.18.09.56.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Oct 2023 09:56:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 53E78CE262E;
	Wed, 18 Oct 2023 16:55:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AB57FC433C7;
	Wed, 18 Oct 2023 16:55:57 +0000 (UTC)
Date: Wed, 18 Oct 2023 09:55:56 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Hamza Mahfooz <hamza.mahfooz@amd.com>, linux-kernel@vger.kernel.org,
	Rodrigo Siqueira <rodrigo.siqueira@amd.com>,
	Harry Wentland <harry.wentland@amd.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, Arnd Bergmann <arnd@arndb.de>
Subject: Re: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
Message-ID: <20231018165556.GA3842315@dev-arch.thelio-3990X>
References: <20231018153147.167393-1-hamza.mahfooz@amd.com>
 <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H3cQz036;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Oct 18, 2023 at 06:22:14PM +0200, Marco Elver wrote:
> On Wed, 18 Oct 2023 at 17:32, 'Hamza Mahfooz' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:

<snip>

> > diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> > index ef2c8f256c57..eb05c885d3fd 100644
> > --- a/lib/Kconfig.kmsan
> > +++ b/lib/Kconfig.kmsan
> > @@ -13,6 +13,7 @@ config KMSAN
> >         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> >         depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> >         depends on !PREEMPT_RT
> > +       depends on !COMPILE_TEST
> 
> KMSAN already selects FRAME_WARN of 0 and should not cause you any
> issues during build testing.

Yeah, this particular case is a bug in the AMDGPU dml2 Makefile, where
CONFIG_FRAME_WARN=0 is not respected.

diff --git a/drivers/gpu/drm/amd/display/dc/dml2/Makefile b/drivers/gpu/drm/amd/display/dc/dml2/Makefile
index f35ed8de260d..66431525f2a0 100644
--- a/drivers/gpu/drm/amd/display/dc/dml2/Makefile
+++ b/drivers/gpu/drm/amd/display/dc/dml2/Makefile
@@ -61,7 +61,7 @@ ifneq ($(CONFIG_FRAME_WARN),0)
 frame_warn_flag := -Wframe-larger-than=2048
 endif
 
-CFLAGS_$(AMDDALPATH)/dc/dml2/display_mode_core.o := $(dml2_ccflags) -Wframe-larger-than=2048
+CFLAGS_$(AMDDALPATH)/dc/dml2/display_mode_core.o := $(dml2_ccflags) $(frame_warn_flag)
 CFLAGS_$(AMDDALPATH)/dc/dml2/display_mode_util.o := $(dml2_ccflags)
 CFLAGS_$(AMDDALPATH)/dc/dml2/dml2_wrapper.o := $(dml2_ccflags)
 CFLAGS_$(AMDDALPATH)/dc/dml2/dml2_utils.o := $(dml2_ccflags)

I will try to send that patch soon, unless one of the AMDGPU folks wants
to beat me to it.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231018165556.GA3842315%40dev-arch.thelio-3990X.
