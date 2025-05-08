Return-Path: <kasan-dev+bncBDCPL7WX3MKBBHNI6PAAMGQEIW55MNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id D322AAAFFB1
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 17:56:21 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-22e3b03cd64sf10606395ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 08:56:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746719773; cv=pass;
        d=google.com; s=arc-20240605;
        b=lZQV5fN9+Os7lzOuQiV8TDty/XHosImeE/JUswtaQJ3pJ6O1FDpOqV5xK3Hrdg9Qup
         UyHDsYgWdzASLc4hWsdWLRofztme8Os0HDXyOru0mErOUPmS+FHapmeLVnG44ErXfkUU
         67I9t4d3EWv7+7Sq1RGdeRdDCcO0XuHuxnTG6b26Nxd0PA8htzfHtoal7+3uETIPNdn2
         oH8GPbTxf4PbzN4MMc8kbjqMFgjrfXO/aZayGkzkIVHNdKHBMSasGeuP5q1StdvjRiTt
         kQMbcLUD85s7vhOWozxSmKtGQGP1iMSH9D/+qhpVxO2wjG6KXXFwPFMX4IhKRuWr4mQB
         cw6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=gxqcg7/OrFdWBEqfGg6nTDnuVhVUGK/aJIz/SVL/HkE=;
        fh=+Sdh/sTuwdfF+atFCUrr4mPFXyZ+vIT3dtIX9aUVZi0=;
        b=PsW6LiF7reLkjelNcmFn3xCypQR1f/JQgtIpts2CAMu54xMQdsyLVV6l5WjaFo3LTX
         G3EPre+6Or+wcocQwLOZusDf685ukOox/wzLO0+DLnObauXtQ+hSDnSk8+jh3pqjkbHD
         Q5pK+WD52h4Q6y6i9cohaPYS4D8ojj4cWWef2Amb4kcHt7I0Suz81Y5mt7GScHl/fIWy
         w5yvwirbwM/g5CSjYymXSHh2pYtfLVSWp7jBDNYzDtNsaAzh7Xk/sYBslpOCu/pLu0kZ
         moZjjM2dXIMHdTH8dQRhY3xGMXZ4iWoSqgeS34WRo0L4Evw8KkxK4LkzUGLiQ0BVLaim
         kEgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Efx2VuLZ;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746719773; x=1747324573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=gxqcg7/OrFdWBEqfGg6nTDnuVhVUGK/aJIz/SVL/HkE=;
        b=tIX0egkZIMOO1wkqwfkMtQkv5YICrHqqgwHno9Cka3x5geagn1bAs49ZcwiHqTwxeB
         8aepNq5Wgm+kwmv8XEAF3Kgt4djE4decOi6OpM9N9Jqke6AfyHykmflw2w9DClbzpeI+
         JccKPhwM135rtsWRWBzDWuJ+1OppqPVeakAm2y6OzbXLZIT1b5cBmfZ+tqLjNS2d3sIX
         U5q8x8PrSg9tCNtPF1OTg7aJMQDIt80R6/tQb/plB3UkUvxjgHuf1H1XD4Msmku6eqVk
         MVwwaKN3M9lmoOGhF/9Yy61JHWmQ0+wnS5YQKYCrkX25nUznVewc0bYwdsISa+9Gvhkf
         3lGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746719773; x=1747324573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gxqcg7/OrFdWBEqfGg6nTDnuVhVUGK/aJIz/SVL/HkE=;
        b=BH8KYoNI2i40Rkfjh2GIba6NdhT/woTnx+LDoAs5sv5ycaBhAY+jbZOWSBampXClf+
         Jo3iROoRR6TQXgHqZDUtFJyIHql4trRFb2fRSjJJkMHzI0zbObeiqR7OBGqUC3nhNOlu
         F2XsWhehMbRsQx7RNXDcJmYk3BkJAxr7ZrS9XVuvE3AQs0X9Zz9oHWKlx7NmZUXjKq+6
         07eOGye7C0GRfUb0bI3yrqDJ7QfXZp6LiKczPp8eSMgXOGgNsqgyU4sqh3I25cPSLtz3
         QZvyqAcWKw4n1RrjeGY0mT1VcSY8RaJybapG3L7J4Hjg1pdoS11AhppOMJRtqw8x03p/
         zp6g==
X-Forwarded-Encrypted: i=2; AJvYcCVT/svloN8gA2DNa48fJvHk5rjrLI7bgyPSjWDU+nnlnDRomI10Lq8yIdRKHA1ZvlV+oVQYjw==@lfdr.de
X-Gm-Message-State: AOJu0Yy1AiiUjfWaIpcRFIQSGW3Vc2Tij42y7eQ4jQEgUdXhsHM7UoT2
	0V+WrqTcC/OYXRcVwz3ezXMJ8FqMnDD71FBE6nCpX//P7WhCRHvf
X-Google-Smtp-Source: AGHT+IHHvd+7OUYUNKSmYl0eqfurMYI0lwacsn/2mAb6skgTSZWBeMrPej5iR+aEAnn9wnuLtbBGSQ==
X-Received: by 2002:a17:903:41c1:b0:220:c63b:d93c with SMTP id d9443c01a7336-22e5ecabfbamr109177205ad.44.1746719773557;
        Thu, 08 May 2025 08:56:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH8JplF5q1W5sovZU658351LdSac2f5OT+A5/y56ch29Q==
Received: by 2002:a17:902:bc49:b0:22e:3d5e:c5e2 with SMTP id
 d9443c01a7336-22e847d6137ls7985645ad.2.-pod-prod-02-us; Thu, 08 May 2025
 08:56:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtJtIEwfulQoPEgErR3mX/VPl5fbM8c0OSQGZNJobqi/wys5FcFgI4xHxC1gAcyLL7ID/VfZryU5M=@googlegroups.com
X-Received: by 2002:a17:902:c94c:b0:223:3bf6:7e6a with SMTP id d9443c01a7336-22e5ea2b6bemr137086415ad.12.1746719772000;
        Thu, 08 May 2025 08:56:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746719771; cv=none;
        d=google.com; s=arc-20240605;
        b=XqF9KaKOgSiFKYazHWP9y/LT7yajaM8D50bNkSgP3lZWdu5Zl8fkwMA5jgTtX82gkG
         mTNbACA+R9VgtHzF0Wjg8sw3DrKh1oMul8YKW4cBDrYpuwLnLgl63W+Yiitb9yiMJs9G
         e8WoAkUujJM2ZxaiFOBmeFInOZI7FJyhojlL+Py0+Y2RXDoqn/auqZuM0oPjjxHp6wU8
         qjds/Y+OIPvqThMTPxZCXHsImBAVC22g+XC9rzOS1L/EHl6DckQiLMl3HhyIPD5xIPpZ
         80eRSKB0GVKdcMOEpJ+IgEk5BzW4AEYmulOpzUxSDmoI3nubPAgLAH2/LtUBUfvZmm6Y
         M29w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M1VaKoEGaioUFl2jnN+EwIYInU1dejdC/HOLAK3BNr4=;
        fh=jNBLBpHI9VQufx5NSUNovS6qARICPjQkHXHrpkaGH74=;
        b=Hsld15CqoYNPgCvYeBTlAkqXaJlsaZR7IVrOiOh85wWYil47sr5mRfYNakbtMQeyXW
         uBtM+0XkGKZmoTJP149itfW7ddE+3lSY0SpdopQOyP4fEU0AOs784QMd5uxDNplf3/Nv
         6684BpL10eSKeTsTIgwHlWmb2cqxDtDPicODdLs7FA/Dlmpt5NcaemtgV2Mw0X07G0pF
         WSGuGzlA70BUEvMGs3JLcFDEXBqDCwe+GUL1C7uCEjgVCXDonumDvqjc/xQOuzCaiISk
         +DO8Vt+PkGN7V2ip3mCNAWXZKe9KEKHWaeNLgEuxEVcUszgn9CUsxW6S+cAEyOBX+7Ru
         Nk8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Efx2VuLZ;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc713d923si57735ad.2.2025.05.08.08.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 08:56:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 10D9B5C5703;
	Thu,  8 May 2025 15:53:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E297BC4CEE7;
	Thu,  8 May 2025 15:56:10 +0000 (UTC)
Date: Thu, 8 May 2025 08:56:07 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev
Subject: Re: [PATCH v3 0/3] Detect changed compiler dependencies for full
 rebuild
Message-ID: <202505080855.DF4FB68A@keescook>
References: <20250503184001.make.594-kees@kernel.org>
 <20250507-mature-idealistic-toad-59c15f@l-nschier-aarch64>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507-mature-idealistic-toad-59c15f@l-nschier-aarch64>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Efx2VuLZ;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Wed, May 07, 2025 at 02:02:42PM +0200, Nicolas Schier wrote:
> On Sat, 03 May 2025, Kees Cook wrote:
> 
> >  v3: move to include/generated, add touch helper
> >  v2: https://lore.kernel.org/lkml/20250502224512.it.706-kees@kernel.org/
> >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.org/
> > 
> > Hi,
> > 
> > This is my attempt to introduce dependencies that track the various
> > compiler behaviors that may globally change the build that aren't
> > represented by either compiler flags nor the compiler version
> > (CC_VERSION_TEXT). Namely, this is to detect when the contents of a
> > file the compiler uses changes. We have 3 such situations currently in
> > the tree:
> > 
> > - If any of the GCC plugins change, we need to rebuild everything that
> >   was built with them, as they may have changed their behavior and those
> >   behaviors may need to be synchronized across all translation units.
> >   (The most obvious of these is the randstruct GCC plugin, but is true
> >   for most of them.)
> > 
> > - If the randstruct seed itself changes (whether for GCC plugins or
> >   Clang), the entire tree needs to be rebuilt since the randomization of
> >   structures may change between compilation units if not.
> > 
> > - If the integer-wrap-ignore.scl file for Clang's integer wrapping
> >   sanitizer changes, a full rebuild is needed as the coverage for wrapping
> >   types may have changed, once again cause behavior differences between
> >   compilation units.
> 
> I am unsure if it is too much detail, but I'd like to see some of these 
> infos in include/linux/compiler-version.h, too.

Yeah, that's a good idea. No reason to make people dig for the commit
logs, etc -- it should be immediately discoverable. I've updated the
patches to include the (slight rephrased) text above.

Thanks!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505080855.DF4FB68A%40keescook.
