Return-Path: <kasan-dev+bncBDCPL7WX3MKBB6G22TAAMGQEJRSWW3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E8BCAAA7AFC
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 22:39:22 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-736a7d0b82fsf3076614b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 13:39:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746218361; cv=pass;
        d=google.com; s=arc-20240605;
        b=FCQnxzTSdhTr7Vi1IZ+jBc1GcXe/C2wBr1GdHqENZozxeP8G0GN28EZKYUpxlRtaVh
         R4BYb02wFqEN0AmGQGi8+h63o2hUdzuciAppotB9pOOybWMfHPlB+1Qq7WuOevPrQEK+
         5MATnqGXT9Cz26g7vZy50e+Ov2ZugzblDlfPA1ADDa3KF+RqrEmalugbs1FFGiJHRvPP
         j1nCS0Wx3qS/VuN1QvB1f19lcGmL3yOIEBHe9Pj4RFFbtTHErNlgf9P06jbIShqbhKq+
         ZJaX+hftQLly7xwxxKAlmM69LJES21WPlaLcrg8BazhzrWzASNRCZFa0yZyEBrEUuJ0J
         oH/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KAy1m0IRqMGvYLIpOe3NCq5PxN3MZOWzpnoDsLMf7Oc=;
        fh=xdUnKOUqKz5M6NfiYCYLNba5zn4ViwGl8Fseq5jYtxc=;
        b=B0KSBQWWld93Wh1FZrEeFTNN6C6WNCCc+tK6bUdqWtL3Ut0KUpSWOELJjwL6ov+h8g
         dqNLNgS++Zwq+vix9UfIKSeSE9yFBGDlyv0eOF9X3AtCmxb0PYuTvVA9DriK8Wc7lfx4
         +qL9lYxq43bTQxBx/h7IHqdMuKOQguAlqlbdv8aWoTSPR9lhnq9iZM0M9ORyZDsQMW7A
         TKCGHXitrxwIRRQI8/RcrOxR4Q6wzzFTTEJ0HBdnxwoDQf9lkLpd6Kt8Wy43Crcb1r1W
         uGBvWK1ZBukwHgnra00iVU+B5InzUtKJksPn/IHixk9GnhGDVXRXjAaqBca0PHv+1oFe
         UMvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GTrMoDC2;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746218361; x=1746823161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KAy1m0IRqMGvYLIpOe3NCq5PxN3MZOWzpnoDsLMf7Oc=;
        b=lP5YktCa9SZ2pmbEBs+foIEsvqwVyaPJ/RsYrdJSZF+ObfjTeCChzxwxJIhYPsMmap
         nQ1QBGCT7hPMZEZVTaBWJQ2SCIxoff8ODAlTSCt24ozQI3QDo7d+DQEZveVTVwJyw/hd
         AocIx1sq00ivSeo8pHY8+x2RQ/B1k5a13hDQDg7EAZWA9076pFs7qTI5FtIG0i26aimj
         BMkWNgCnPP/zj7hsrhhRod4YGLNW0IUBcI0Paz/lREIQoUwiSSHkWm57xaY3yAVMFo4K
         uEyShXCkAzXSxwBZVVKxWHQiDc+NU/gVXS8pRVLt5OZ56fqkhd+3tKYOLWNzRuE56Jia
         DeJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746218361; x=1746823161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KAy1m0IRqMGvYLIpOe3NCq5PxN3MZOWzpnoDsLMf7Oc=;
        b=OYenHxVtyXaJC5n7XLnVSPzQahbcLvcpdnpukE95MKfMgb2zUtyfQFrWHVaJ5Ya1m9
         8XfCp/YAvKHHMzkIPJ52joW489dk/KE88CAZi2u5Yl/9rowPZhjCRtWk0xiil3t0tw1J
         hXVtPXCm74Ye422YxeqGoWxRCFJJ3v4E7pqfp9iaq8EeyXRImhgbIpJcK9C7Gb0MveTj
         R2TM5XMOB1q4zryYUR4lmibDmZM5u/bY883ghXWFFVBvFiDkNqxfZEjXsFUB4eTTq91H
         T4L4RW08y1S7VF86rp91zlc0AB2TcTUg5l/GNqbtWsq2RNhQemCt611O3QzLA5pctG3F
         1AGg==
X-Forwarded-Encrypted: i=2; AJvYcCWJQq4P505bQI5h8MWX/i0Eyq0AGp+r6RHkwiyOcJbRM3fmFSvmDYsv1m+kE07Xmxagola1qw==@lfdr.de
X-Gm-Message-State: AOJu0YyqiEGu0MuWFhj30GCwzHWf5j0X8+kbwASrJK+bT+yHlL0Y/R/c
	VitXGYMi4JnafpM8tbWmUvjMrREegLD8k6K0GRXbS+mDcPCl0z0g
X-Google-Smtp-Source: AGHT+IEUp+IoW/3NYFx+oRNYNhlXYu7Ep4pDFpJ9iL/v4Wq4fFZFJ3ko3vlHA6AbIfPpEi5bnt9p4A==
X-Received: by 2002:a05:6a00:3309:b0:736:baa0:2acd with SMTP id d2e1a72fcca58-74058b1c213mr6812087b3a.20.1746218360942;
        Fri, 02 May 2025 13:39:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHujC4nsG0/By3v/ekYYdGKIRCGy5XC7bdnedMLGRrLXQ==
Received: by 2002:a05:6a00:acd:b0:736:9c5a:66c5 with SMTP id
 d2e1a72fcca58-740458604c4ls2079242b3a.0.-pod-prod-08-us; Fri, 02 May 2025
 13:39:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvLKKOy7H4D4L7Z8c8M0yYtg7DVyjDzT+BDSbp8cD2UjdxR46llJSUt2J6ugP3DbzRHcWKfbVhVzE=@googlegroups.com
X-Received: by 2002:a05:6a21:78d:b0:1f5:8b9b:ab6a with SMTP id adf61e73a8af0-20cde9564e4mr7298191637.18.1746218359726;
        Fri, 02 May 2025 13:39:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746218359; cv=none;
        d=google.com; s=arc-20240605;
        b=fqU9upw3iZhpioIKFeFMr5ljoDb1Qkfeif+KrhZRYpniymCeNtsF0YKx6RsFRFXmOS
         dIQyexIPTCDDcRjiELhEV3LyFoPr5NBD/suwMK8tsZypv80NWsfj2EpACzGGg5ICvY+y
         cdQdGhfMxGLq9T/6eKPLVDISYKqo5PGxfKmjVdyjILE9/DQ0+7fH1Q2SMzAb+ILTHPuM
         X+I33qPjYoZJ5Lmqwgik9kfYYxgWSvLJN+pf/tKiOGqQqGgPq6TfD3Q3/0fbQzvB4BpD
         qUSXBl5O/0OFxBi/Gn96Mk2aKn8ImhZI+fRFS6rJiEeA8j1+jz0g0x9LFdu4A/8samZd
         4idQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=AY9BcKHPUKithoyJy2/efb0czfnOvOx7Gb/h6zbOZNc=;
        fh=HzDYnI0GmZM+RkXfY7xXuGsuyRr/nDi5ZnmrpJVQMWo=;
        b=Z75fpVMVbeEVmL29cSfnumYzmjoujRxYGBelDNYDp2muujQwWCrz5mmOKUzqBkEfoc
         6duq+/0CmKLpUlMBHmXUEoTh99rEPhfIfqoKIs9gdXVNxiFYbiDqnin7JkoRGfBRimWD
         f2+o5gKk16dlmSUw0ym+R+2O65AwtCSnpcQPLyyRPmwap5bxyUHELLvg/SX8Sa1DDChE
         zGflvEfc74FC8yTzmPhDV2DgL6+RaFcuJCISMam1bLJD1ctHLVhwtoFVE9DB55soHFnn
         R/xP43Z6b5FhjpTVMq3W2EPEry1OZPmzXc6mhJA5Ao0AqwMoozpOCTjqbNvNH9sRkL5o
         QhGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GTrMoDC2;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74058db9223si119293b3a.2.2025.05.02.13.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 13:39:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id EC37760010;
	Fri,  2 May 2025 20:38:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5D769C4CEE4;
	Fri,  2 May 2025 20:39:18 +0000 (UTC)
Date: Fri, 2 May 2025 13:39:15 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] gcc-plugins: Force full rebuild when plugins change
Message-ID: <202505021337.DCC59E49@keescook>
References: <20250501193839.work.525-kees@kernel.org>
 <20250501194826.2947101-1-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250501194826.2947101-1-kees@kernel.org>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GTrMoDC2;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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

On Thu, May 01, 2025 at 12:48:16PM -0700, Kees Cook wrote:
> There was no dependency between the plugins changing and the rest of the
> kernel being built. Enforce this by including a synthetic header file
> when using plugins, that is regenerated any time the plugins are built.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: <linux-hardening@vger.kernel.org>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  scripts/Makefile.gcc-plugins | 2 +-
>  scripts/gcc-plugins/Makefile | 8 ++++++++
>  2 files changed, 9 insertions(+), 1 deletion(-)
> 
> diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
> index 5b8a8378ca8a..b0d2b9ccf42c 100644
> --- a/scripts/Makefile.gcc-plugins
> +++ b/scripts/Makefile.gcc-plugins
> @@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
>  
>  # All the plugin CFLAGS are collected here in case a build target needs to
>  # filter them out of the KBUILD_CFLAGS.
> -GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
> +GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -include $(objtree)/scripts/gcc-plugins/deps.h

This doesn't work[1] because CFLAGS_REMOVE and so many other places use
filter-out (instead of subst) to remove flags, thinking flags are
singular. But adding "-include path.h" means "-include" gets removed in
a "$(filter-out $GCC_PLUGINS_CFLAGS, ...)" case. :(

Ugh.

-Kees

[1] https://lore.kernel.org/r/202505021403.blhkPRXG-lkp@intel.com/

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505021337.DCC59E49%40keescook.
