Return-Path: <kasan-dev+bncBDCPL7WX3MKBBMV43K7QMGQERR5BWBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id BBD0DA82C2C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 18:20:04 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-af5cd71de6asf4522993a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 09:20:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744215603; cv=pass;
        d=google.com; s=arc-20240605;
        b=iPDkcdKykKMEXeL4mXG73i/6zSEHWPbxGZZsOEFOvFG/8aMKGGQ4Uu5OZzbdAa7CG9
         XixF7iggBZZ6vO+99iux0Sbevly8LwXqInsyUPTbbvpktmhtB50Bn1SAiF9Wl+KHLnUe
         +l46qD0us8gbDnsdZUhXDrjfeZBP7Ax6T7zfMKOs2rL2VOzDAGzqdcD8f8tTRtgbcWJt
         +7YcuaOL8DW/Pk/iBAYxaTOuTziGT2sqWHZLSITzIbpZfF85ADp9J2A4thDI61GYGK8w
         dOM6eRX5SAyz7r9qa5nN/dMEJwGUFaspY78TxeJWoVcvsBGPkFabgUqbMqjcxsE4tUu6
         HSXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HBexv9Myr0lWWQtgsZ/1TYLal7UASSBktIDoTQAs9zc=;
        fh=srfQsT6mfjZq6/fGXUriaPPu+Qu3AtoV+H4BIj0PFPc=;
        b=Ca+V8ZmYkMYX1WWciCG0gn0NNtd8V8gY5wbOadlA7saL9xddg1OFDMo7behRzMmqSE
         CqttJM8XoNO+LeZQ9CWjfQ/Ik1rw7fr0aFPw3knednJyIlaoPT0GLbPdum7tsVSaT1A0
         bVrTxAyW86vMEByG6VCGKg4nt0g2IyEe4HwIy50kel2X1vxYEFmTmzI4CC/L+j2K2hjV
         HpglNShj1OCt6Lca9ypGkeAjV+KZPewcE+xW2xtPsH2V7edjaWpTMQPw4xE4v7Ehirlu
         KLN5S7maZseLvtG57wEhGDw8S7apfKnLasVCthqgKpfMjqt7hHTYHdl9RZlB/H56bFOS
         aSqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hTLMojkk;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744215603; x=1744820403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HBexv9Myr0lWWQtgsZ/1TYLal7UASSBktIDoTQAs9zc=;
        b=ctZxquasZhoxA76P8MdJzsDMES8QTbG7UCWeCwdH6yIrKwpfc0miNIspzt/+1f3PRJ
         9Jwb9LR7I+ofT3pF0DxlzsXZF0AVKRFv3ZYwAuktrnfKpDtBxloqN3T6G8BhjI1/EnQt
         ErO+FUqJ79AxFL04LM1BPpxSDmEIVkKDTuMqFx7yMj8uYSAxvXs2kdDDXNhca62bDywW
         XMuj3X/Nz8LhDNCvpBIjNeytuPcB4K/hkSYGW/xKxhmDCRNgNRwgR4Of8IadtYHmIGQf
         DiRv901pMy/kheTNjUsPmOiS0M0p3iY2loi40KGKvO5C2tUZCoQRM78E8zXDN4LqOj4B
         +Sbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744215603; x=1744820403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HBexv9Myr0lWWQtgsZ/1TYLal7UASSBktIDoTQAs9zc=;
        b=hFgFMnQlGZSYwI5zobF6Uc7M+j5IM3lU2uLdtDmljC3ZEHckDCc3d4TzDe3D7nKiJy
         LB3L+OBD1OlmfwnKU/T1yfgSn/mCH01BqFTtA5hbDo83w2UuUTKGlwICu5FC6639dX1V
         9DxCb43EuAEUfRIOIjR2QGX84DNsMIYGenDGJB2jb7d4tCK3KRVG21pOzuZPVAFAJId9
         WG9MDm8n8+kJnR5g8ORCPh/h3tRQEYSzkfwwGiItawWQOeUFI+rFRszhXfMJatfJWIa9
         hy5G532+uqnip2E32/kUPhYVhS1laJjgm8DugBWcdlrmj/otRnMVTa2fzL6gNkr/DDjs
         9kqg==
X-Forwarded-Encrypted: i=2; AJvYcCXtv/nIgu2GjP437Xp1XAdZeaBFaYfZ0+a0LNMoJiiXbl7T+Li8Lus5oGmJCMxenRe9P4sMxA==@lfdr.de
X-Gm-Message-State: AOJu0YyQxlFRsdNO6L/4Cgtl8n0wQ2b33asQwdGNe2BeP3GVbmpS3H/N
	GwKX6abqtiWwQ4x5/GEax//r5PaKbmP+2KenfPfWStPrqp78m8Ga
X-Google-Smtp-Source: AGHT+IHu5QktOmR2iAmmAbVLJuk4hAhtN7ZSQILqWe4tv4YuRlAxL96vcFXbV7q7DiWiz6mXMrJbBA==
X-Received: by 2002:a17:90b:2f45:b0:301:1bce:c252 with SMTP id 98e67ed59e1d1-306dd556664mr4162703a91.27.1744215602965;
        Wed, 09 Apr 2025 09:20:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAImCk5ANogI6qeP8eH0d4dHh2yVu3njHFFI7s3pAU+3vQ==
Received: by 2002:a17:90b:5249:b0:2f9:b384:bcb8 with SMTP id
 98e67ed59e1d1-306ebf93e95ls52451a91.0.-pod-prod-05-us; Wed, 09 Apr 2025
 09:20:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnt9wZyLfLe4S4IcL6sKi+4j9nsKlwszRaBLCXLsD+1yqNwV/P8P1MJVzTByaMchhB6LuZpN2k5W0=@googlegroups.com
X-Received: by 2002:a17:903:948:b0:225:adf8:8634 with SMTP id d9443c01a7336-22ac40253ddmr46462085ad.51.1744215601685;
        Wed, 09 Apr 2025 09:20:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744215601; cv=none;
        d=google.com; s=arc-20240605;
        b=XbKnVGduHHIMVy2h3FBYJ7zEcAQXYHlgk/bG919dPBT7syFpoFzTz3LBaQSF197X38
         B9mzjpKtQThk4xB+tpq0mULCDhAkuJhWEwuAfVAWpX8Zxse59TQiR5sD36GW1+CkgXIM
         3gwMDH5bkO5r+kMEPFvY0hDTKI65XI6BCF0TGfBgis3hFQmyDAUSH/pQFoXNYNVmeoyV
         I+mSiTyAW0tEidRAPjrse+JDo3/I9Z8Q9iN21HSMNj5HwTSSH2rg+mIO/H7pLittEMbo
         3d8pU8hdC7IowvLVeAFL67E8YkYNnj4wJUMqjXk7N1DnonIMTyTidJ6TLqF3ixtfWSwL
         8ubw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TfEBZn1I589ngJLrZDENnW7cc4fKZMoASsx0vERN6/A=;
        fh=GGSsy7+1XFV2osQAgZOdt+BHIQkY4zrIeIzu+f1I/AU=;
        b=fAKyw2e06mNJJcpE0ipfji/DJszbGwzduIhlNuPqX9td98245eLLdHjH6Zdq+GcXj2
         ZbGgAlCFRuIX6PTZTDlpAPXNOE601KW22IMG8OXcf8xG8+eul5VGq3TNv0QBFTGLsoMn
         BWmxfoQ+RBFbPZ+zVVFOclOH1gTn2rOj97A2reK+XHPp2euwxmHRdO2KcrOypBffUh24
         TR0f+aeHdqshK0P1oyU9kRYos3e0LNZnW3e2hSkRLi0IP6O49ojldutCe3QhbgQDz7b7
         h8xKgLkKQYQguz2zJd7i5GLu15Pv6X0hj5GzLlnvyZfScUL5Hl6pw+vZZ1K+2acN8agV
         UBtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hTLMojkk;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22ac75d5fffsi61085ad.0.2025.04.09.09.20.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 09:20:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 3147CA49AA6;
	Wed,  9 Apr 2025 16:14:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 708EDC4CEE2;
	Wed,  9 Apr 2025 16:20:00 +0000 (UTC)
Date: Wed, 9 Apr 2025 09:19:57 -0700
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
Message-ID: <202504090919.6DE21CFA7A@keescook>
References: <20250409160251.work.914-kees@kernel.org>
 <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hTLMojkk;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
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

On Wed, Apr 09, 2025 at 06:16:58PM +0200, Arnd Bergmann wrote:
> On Wed, Apr 9, 2025, at 18:02, Kees Cook wrote:
> > There are very few users of this plugin[1], and since it's features
> > are available in GCC 6 and later (and Clang), users can update their
> > compilers if they need support on newer kernels.
> >
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Link: 
> > https://lore.kernel.org/all/08393aa3-05a3-4e3f-8004-f374a3ec4b7e@app.fastmail.com/ 
> > [1]
> > Signed-off-by: Kees Cook <kees@kernel.org>
> >
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 1af972a92d06..e7347419ffc5 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -2135,15 +2135,13 @@ config ARCH_HAS_KCOV
> >  config CC_HAS_SANCOV_TRACE_PC
> >  	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
> > 
> 
> My version removed CC_HAS_SANCOV_TRACE_PC as well, as I planned
> to have this on top of my patch to require gcc-8.1 as the
> minimum version.
> 
> >  config KCOV
> >  	bool "Code coverage for fuzzing"
> >  	depends on ARCH_HAS_KCOV
> > -	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> > +	depends on CC_HAS_SANCOV_TRACE_PC
> 
> So this dependency would also disappear. I think either way is fine.
> 
> The rest of the patch is again identical to my version.

Ah! How about you keep the patch as part of your gcc-8.1 clean up, then?
That seems more clear, etc.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504090919.6DE21CFA7A%40keescook.
