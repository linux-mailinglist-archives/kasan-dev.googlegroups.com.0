Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5VD3HAAMGQEFGCR3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0B6DAA81D7
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 19:27:19 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-85dad56a6cbsf524771339f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 10:27:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746293238; cv=pass;
        d=google.com; s=arc-20240605;
        b=iYTSrSuKdWeeEZ/SrsgKwqW3YIj7xrMS176IXi/wNlIbfAfUfeAyBYSI4G3XolFruX
         b2QwkfF0iliFr0nKOeqnbNWh/N9Fku2IcmrlOorWezXrLkpMBw+1Q06NjDCFmhcw6evI
         VXEyrouW0AKL0gZjIA9DSqRz6ttci689tNm0d68lMfQv0gF0/tyS3gsJwgb/BTIQMAnq
         FJQaR3G3OSZR75Y02TrUpsRIv1pdcEfz2IA5As7XxCypmf1ZMy11bOgoxWYYtaf/tO9h
         eYbn4/Y+J2ev025YZMZWS5SvQvrMkelTXEN5B+4M0+JOv2NQDL2LEylob8yhtcAU5/b/
         o2Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4a7uukIsQl2KeSv0XBWOLtANHP6CdS9W1AcrJziZhN0=;
        fh=he0oSveylsxBga+Vao79h59b8gPlSKosK2imhjusFYM=;
        b=SYr+ukULwO+UxPwGNh+rAESdVsiuQPm2ULUchv9W8q3W+4TP94FBwvWGWo35GHxE2d
         YLn+6jFAMDntAga3y1bjSQAg4NGfn46r1kn/YqWH4M6lN8uIK4jjPrSd94C3Gssu3ORU
         qkXSufHypaGFJR8fG14ThsPQWqV9qfeAjbnMnb+U51m+aR4hT+9XeRE/dHUTf7f9Zvug
         026U1de4bGOU4pdZjlpapcx8DTc2s4Li+pA18qolezWUNAP4+zOnuCJEKmd3wdjJUP2F
         rT2RYdXZYshxNxiCXSIluu8fBCIQghGcyktIrVTvDeHZNNeNF6qU+Zyp7MHWMkwUijTp
         kM6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pdfHbD+D;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746293238; x=1746898038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4a7uukIsQl2KeSv0XBWOLtANHP6CdS9W1AcrJziZhN0=;
        b=CTvs82PbTeugRmqm6RPmc2QR4bvB//DyONiKBmVtD0XmK1TkuWdj++JurexEa9b0E8
         iYmpyE3ZvQSHRiWzg0C/1o+CCXmKCOx2Wogi97TPaSMAFuO2wkFxV1fIxWqOdCdtfrMb
         kLWXiB1ilNomfsev/tAO745QSDvVLi/nCaeFU15CYEpOC2SwzNjejyrum4iTGOWoyxVT
         aUvjyEaLv7ky93O/4dPbiSz3oAEI48MD+6LuxCW42RtYQ7zJMieCy3riZVr258E0dFHp
         n7krJKh9Kl0UyCGUlmdJNkvYp5d589MJtPXkDjXZA0xsls7wamehydCIvx2AgVdeNVjh
         X0WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746293238; x=1746898038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4a7uukIsQl2KeSv0XBWOLtANHP6CdS9W1AcrJziZhN0=;
        b=qJbuneetdji8Rf6L9CvlVP6vI9YHwBRca2dyEvoKK4pxk/UVtt7PZmpEggVwusvnhf
         igum9Kpb2wx4IF2NCWjIKdEa5EsChA5J0lXhH/4L7ZWViR1EfMgqVBE4HZqyHtVE5NUL
         O8JFc854GICSAbxBGYg5XhTCP7VXHIeN5KhZTQLnB875Yvu77x/AFtdtSDQZKUx/0cLw
         Qd2HUVHyWSg9ew9x+udnMtcYrlLQRk88QtXCbcYLtZUjpQOIiKLSadwmlXvxVaY2JCbQ
         GvDTPe9tiTVX0YmAp+w7w4rbIfSHb7+hKhm0wBnn7H/13xoHdWf+GFWBWHmD08MQrkp8
         VUlw==
X-Forwarded-Encrypted: i=2; AJvYcCVbP1m4ARUD/c4BEpkjzI0ljkkkfAO0v8J+vq62G/5eLGW7MK6ok96aca2GKcK5ysgr0fucmw==@lfdr.de
X-Gm-Message-State: AOJu0YxnE5v7KMzM/eZ6JUsSBZ6e4sd5vAGeg+Lg4V1j2Iwz0d7UlzXL
	jgWIkfOxFfyXoO1VommPON7hVF1VGEAtyXfj/Cdzi+OadIL88eG6
X-Google-Smtp-Source: AGHT+IGtYQoHKF4ls4FLSfxkgIPvu1AddNAkU2N0yU+mVmTMiZqfEy2ZLZUyhrFSkvQP5M7zm/iwWA==
X-Received: by 2002:a92:ca4e:0:b0:3d8:8900:9a28 with SMTP id e9e14a558f8ab-3da569f8e6amr31659125ab.20.1746293238255;
        Sat, 03 May 2025 10:27:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF8x+d+1nYFD30CtgvUv4Kaqn7fX27ekYovDi0+QMke/Q==
Received: by 2002:a05:6e02:d04:b0:3d1:3d13:5489 with SMTP id
 e9e14a558f8ab-3d96e714f55ls22733805ab.0.-pod-prod-02-us; Sat, 03 May 2025
 10:27:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvC+ZJ47BL1z4oZt+A/VnV5X6Yod0NPPLX19atN1DxSAzX7AydXIIu9yLBddbYyZbGvA8JLYvP09k=@googlegroups.com
X-Received: by 2002:a05:6602:3ca:b0:85b:482b:8530 with SMTP id ca18e2360f4ac-8670b7a0a62mr299445239f.2.1746293236862;
        Sat, 03 May 2025 10:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746293236; cv=none;
        d=google.com; s=arc-20240605;
        b=PwMFRsmS9vMnYdAJ+RK/NP3U3Ue1fv9UBUxQDvrnImrnAopHy3/djkbwaBWv4RgwjR
         Ogxj7AumFvQE7HOiIPk2FrZla0VF70s2Q2XCkYzJVK3Gs594stUe4ArPP+pw4t0jXIQd
         lsjG5aMrwcpZVN7yL5HbZg2Q/ypl2/qepkC2b1vhhgjzfxnJY5K5SqKNT3DxEywgvdfy
         +mjNyVjr8MTbK0m+ECV3YJb/cNB0AeoirFVPWKCtoNLZ07yFGTJhseX1w8p6JMEhOi7H
         G3HKFnqf0vtTozpykXSYahNyHGYwaGozr68+1G5CFlC2sKLOkW/3qf28T1A3UC8GNiMg
         lJUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=UfBITuSYGFjANNp0rWCWBGhPofXTaDFt3Gv2JIctka8=;
        fh=hH3Ogn5E25IiqAnKQgtjX6QXx/1MxdjDz104C9bJ0Lk=;
        b=AQrcbPXIruv++G5ydhFmLGIWpFJrupamtiNyoMMNV9WET93+ih06M/13ED72F1bDU3
         oECzKYBtTVp/3sWl2oE2mFVNSFg5KeuPk5njHC8ND4sDN58S7+zC4YOTyLkL2ad1peIc
         mLlXY2LToCiycUzbKx2ZAIJW6FQbS5wsKqRIM04K678XuO/jw6Ei8F5CEIP3faz0r8FT
         C27G5GyXevsJUlxvwxYxe7sBfMKjZn3ep+hgQprtb3vcnhC5iFDmc65RyW+u2z+M4LZF
         QbgNZKLUXpTjf7BEgIVZDV41feBRGaT7XDhvA+Y/8F1PhgMfH+ssVxAQokfMsECmjb7M
         jwQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pdfHbD+D;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-864aa39a9fesi21760339f.2.2025.05.03.10.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 10:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 397DD5C3FA5;
	Sat,  3 May 2025 17:24:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 032C2C4CEE3;
	Sat,  3 May 2025 17:27:15 +0000 (UTC)
Date: Sat, 3 May 2025 10:27:11 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kbuild@vger.kernel.org, Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Subject: Re: [PATCH v2 2/3] randstruct: Force full rebuild when seed changes
Message-ID: <202505031026.6FB74507@keescook>
References: <20250502224512.it.706-kees@kernel.org>
 <20250502225416.708936-2-kees@kernel.org>
 <CAK7LNATDbxc+3HQ6zoSk9t-Lkf4MSNmEUN6S5EqoVWnBQw_K6g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNATDbxc+3HQ6zoSk9t-Lkf4MSNmEUN6S5EqoVWnBQw_K6g@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pdfHbD+D;       spf=pass
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

On Sat, May 03, 2025 at 03:13:06PM +0900, Masahiro Yamada wrote:
> On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
> > +$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed=
) FORCE
> >         $(call if_changed,create_randstruct_seed)
> [...]
> So, this rule is executed twice; for randstruct_hash.h and for randstruct=
.seed
>=20
> randstruct_hash.h and randstruct.seed will contain different hash values.
>=20
> I recommend keeping the current code.

Agreed -- getting stuff into generated is much preferred. Thank you!

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505031026.6FB74507%40keescook.
