Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6UO3PXAKGQEHHGNGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 035CD10587D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 18:21:00 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id o184sf1443611qkf.14
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 09:20:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574356858; cv=pass;
        d=google.com; s=arc-20160816;
        b=RjSeS3zc4TsXNOtmWZ7Ue1U2cb6exdxR7fMupj05C/GUeewVJ9k8UnCp3kQ0ZkxxH7
         Kkziwdjl2VBIHqt2DMpDb9XNggrNgznbIVC/tJX1tdTDBIIK9Hyi0ojATNlMu7SNljwl
         hxcnb5y/hRlptXjnsV2OkdwDcXMn1o5n4fB756sxGvd0YSPaxG0hZQ3zuK80F0s6JCDh
         CE5WSQ/oOwhwEOPK5V2oxjpjFahJNUiWQ74ejB+2UhKsW85FD83ddH9xa2fUltASe/tI
         Y3I3VGQE/7W7nfILZKjlA4J6Frwdmo46mY17YdgCELzolp9InKPqq2L+8JswmwLLSFoi
         Auog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wL/wP92sMypWQSXE/WWT4fpRuk29roi2UIgQvVxs1Zs=;
        b=fDXTwtG2Zmsw3/WDV3yWbNY1S+zKlGGysDqCQt1cbXvVSA0lO9fsCNuyRiWG1ijwPX
         IpKIGHGr3Q1Qi2SXl2RIXefqZiGneE6RczzAJZfVTovnn7NivocQuodG98lxh2qWU5yC
         Zxz90hilDRq+fqb17/S1cQX6aNkgUqklXHBWu6bRsNRtdHDlKwDuJYb6Nj4eBXN42ENG
         3Rzw/Fs1Q8bFQFpvm57N3UhwlB7shcj2e8wSZZTdPuvTkQxwFTebcwAWys152gykj4p9
         QF4bvphyz0ji/PnD1vivvl0raUX4TpHPUrsUFex1gSQrDi96d+m5mOEPwkmOhC7dfVVv
         mxRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lwi+PHw2;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wL/wP92sMypWQSXE/WWT4fpRuk29roi2UIgQvVxs1Zs=;
        b=Vdcohpmz6UDknjchUtWYxh314Le4EW+JPnwy8x/vbS9fhp437+zeuf6pCRlY+3ou1A
         Jd1nMgktk3uxNgNUWFjAv9BhyCjGOT+paGpkBAVhNBYH0rNnRtiQXy01hM9h8FnD6+/E
         L83zYZIgggxZvy07Mr0gHnOw2igowrCYrVShHWU/fXSBdvznXC4ZmMtEujpkmZfz8mXM
         O05qxtwctaMae1rKe/nv/15XmsEPQZV1dEyLb7Kr3HV2eXKBJEJfnw4saLjxzKA8IIxH
         ViSpqvKLfhCXlOzkz5Ba22jHkT9dugZCb2/PexFcfMYTC7AEOLB+nIK3AOjov5H/k5Ms
         OYzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wL/wP92sMypWQSXE/WWT4fpRuk29roi2UIgQvVxs1Zs=;
        b=TSmyaBD9FR7EbEnVtA+z0TDl6DGvTSPcTfq/MZDD/uxltc/jaAhXzd3BWyNDqACuh6
         39Y2qBFb8q6KQJdjV52fsDGAybfe0uvR/cdB6tLFVo1OHi4XQl3vP6rc/XLATCgRbh9z
         LIsB9e9geaXL0e1MKGP7bzTekMRF1a+FrB5I7r+ETAcs+f4hW5jtMZosj+0MBsIvavs8
         +xUgwnZEF9bnR7w+RRJ+e5ZqZWgFkpoM8f520PJTS5IZLo7YyRxYdTVQY85VX59xJAdL
         kgRduBlS8qqWbMCYn7JVnpQOXQEc3d2vvAAfg/AyBx7dgVQQDm4/39qPvt/PkBB5hdcH
         d4zQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXCXsrA5VrdHxGj0TrVpB5K7zQJNut1W7BMgj9SDjHmui0xV16t
	aIRQMOJqJctiov3HGHPfxVs=
X-Google-Smtp-Source: APXvYqzoqDg9WE3GIZfzDbK2s13cYLDH3LAqE75wnbnnvxsDlITA9DBQo0nrZHCvGJTvc+gKy05Z0w==
X-Received: by 2002:ac8:6f17:: with SMTP id g23mr9775669qtv.104.1574356858763;
        Thu, 21 Nov 2019 09:20:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8051:: with SMTP id 75ls1144913qva.3.gmail; Thu, 21 Nov
 2019 09:20:58 -0800 (PST)
X-Received: by 2002:a0c:e947:: with SMTP id n7mr8411375qvo.103.1574356858230;
        Thu, 21 Nov 2019 09:20:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574356858; cv=none;
        d=google.com; s=arc-20160816;
        b=ZsC9bJDiMd/GAbMTjBGLiYaDuKjUQ93DCQEKVVOIXYKjdrywFUQIu7ZN/T8YJ7h1dx
         j5a4MSQ/R9iXJDO2aYphqkilMlguAWYVNyOTERsg7ckAvu73e4v4cHFiYQgnaNNcXf9o
         iKnfHbF3BlQywGmSIOhSQ0JHYDf1C/GrREi4d5NPaXgLsC6BVFddKLK1Ypuk1XJxKBwJ
         /HUnmw1uYOusKfLKFCpZi3NHSjCkZvHq/ck6+oV6jhizN+wP887GgsERgjxM2hr4vBYl
         KlLhHvTD4hz+owh1MZ3LU03VC4cfBoBh0hzrAnnwtzS8cstAXdUVf5ZYPN7PiUiDOWCO
         QleQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=B9Cd6lsebgbNm4s313iOukfjAkgVHP26MAXbnw9I+ys=;
        b=LqM0hX6O5KjUx0MR8M3kHpz2Ce7L7rPKAaNEykrh/VGdfxEloym+ZTKIMmvrOpGhbp
         a+uznl8jKRCHuqm//x4PeEp4vNZgyiaGy45X0QXDE0HBI9aOWQKUK4z2d6BmMZd6DP9k
         myBMcyj78YiVhnT5EbCAPGH9maJoYh/PWjpYwArXcEm/uB/Qq+i1UD/Sv9vc9yPGKJSJ
         DNkif+II3vPjXKUhvEfBfZhKgzAx4ZFGJUMMwWYq1xKsEAQpmj6Z+wb1Wd6iqh0Nk6kp
         a/2NtHSY7HW5Tla2wnE2nblUd3RA4mURWNx77xwUl/cgUOxK34L51Jg09w7JqSblTwgg
         Mh6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lwi+PHw2;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id y41si215606qtb.5.2019.11.21.09.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 09:20:58 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id b1so1910855pgq.10
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 09:20:58 -0800 (PST)
X-Received: by 2002:a63:df09:: with SMTP id u9mr10657407pgg.20.1574356857223;
        Thu, 21 Nov 2019 09:20:57 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id v3sm4017698pfn.129.2019.11.21.09.20.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 09:20:56 -0800 (PST)
Date: Thu, 21 Nov 2019 09:20:55 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: Re: [PATCH 1/3] ubsan: Add trap instrumentation option
Message-ID: <201911210917.F672B39C32@keescook>
References: <20191120010636.27368-1-keescook@chromium.org>
 <20191120010636.27368-2-keescook@chromium.org>
 <35fa415f-1dab-b93d-f565-f0754b886d1b@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <35fa415f-1dab-b93d-f565-f0754b886d1b@virtuozzo.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lwi+PHw2;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::543
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

On Thu, Nov 21, 2019 at 03:52:52PM +0300, Andrey Ryabinin wrote:
> On 11/20/19 4:06 AM, Kees Cook wrote:
> 
> 
> > +config UBSAN_TRAP
> > +	bool "On Sanitizer warnings, stop the offending kernel thread"
> 
> That description seems inaccurate and confusing. It's not about kernel threads.
> UBSAN may trigger in any context - kernel thread/user process/interrupts... 
> Probably most of the kernel code runs in the context of user process, so "stop the offending kernel thread"
> doesn't sound right.
> 
> 
> 
> > +	depends on UBSAN
> > +	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
> > +	help
> > +	  Building kernels with Sanitizer features enabled tends to grow
> > +	  the kernel size by over 5%, due to adding all the debugging
> > +	  text on failure paths. To avoid this, Sanitizer instrumentation
> > +	  can just issue a trap. This reduces the kernel size overhead but
> > +	  turns all warnings into full thread-killing exceptions.
> 
> I think we should mention that enabling this option also has a potential to 
> turn some otherwise harmless bugs into more severe problems like lockups, kernel panic etc..
> So the people who enable this would better understand what they signing up for.

Good point about other contexts. I will attempt to clarify and send a
v2.

BTW, which tree should ubsan changes go through? The files are actually
not mentioned by anything in MAINTAINERS. Should the KASAN entry gain
paths to cover ubsan too? Something like:

diff --git a/MAINTAINERS b/MAINTAINERS
index 9dffd64d5e99..585434c013c4 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -8824,7 +8824,7 @@ S:	Maintained
 F:	Documentation/hwmon/k8temp.rst
 F:	drivers/hwmon/k8temp.c
 
-KASAN
+KERNEL SANITIZERS (KASAN, UBSAN)
 M:	Andrey Ryabinin <aryabinin@virtuozzo.com>
 R:	Alexander Potapenko <glider@google.com>
 R:	Dmitry Vyukov <dvyukov@google.com>
@@ -8834,9 +8834,13 @@ F:	arch/*/include/asm/kasan.h
 F:	arch/*/mm/kasan_init*
 F:	Documentation/dev-tools/kasan.rst
 F:	include/linux/kasan*.h
+F:	lib/Kconfig.ubsan
 F:	lib/test_kasan.c
+F:	lib/test_ubsan.c
+F:	lib/ubsan.c
 F:	mm/kasan/
 F:	scripts/Makefile.kasan
+F:	scripts/Makefile.ubsan
 
 KCONFIG
 M:	Masahiro Yamada <yamada.masahiro@socionext.com>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911210917.F672B39C32%40keescook.
