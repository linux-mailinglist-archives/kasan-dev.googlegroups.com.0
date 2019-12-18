Return-Path: <kasan-dev+bncBCF5XGNWYQBRBZO34XXQKGQETZXXACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D680123B52
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 01:08:06 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id c23sf176057ioi.12
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 16:08:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576627685; cv=pass;
        d=google.com; s=arc-20160816;
        b=FYlcFD/I5H2Zo+zYcvCAe1CAiEh/O7NvyIaXy/fZGUduybOmPHllKOV/pjZ5wZg2z5
         R3GfX0MYjv58dDtNBb7+lMNIqsLY2sY71YN7U3NLI43QL9v77XvumkM+xelHUVxV9T1G
         cYahAhWDVG1FrzucwdSQg7gaLsthEzXWHDcP21bV7AOKOwdGhFeCMduHMfgbysFKwN5l
         D7U9adz0bnn6BMyG4GbUf6NoA0tLMMTWiukBFFOZygK/b83Xkc4w0uqEx37Y0usnASpP
         OG5TO9QIhh9ii7lRiPbfnrGlk+6Q2a/UNGcvLCKxvzgDJzxE3PEG5BF/kmYDYmjmd3Q9
         8OMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Flaa7JXsPeD/PJm6ufEMCh/jiUrFEXp/DDy1WMsyyus=;
        b=EKjJ//gX0t7+kz3RdXNwyRYSZOHvFb2Xw2miX3JsLiZ1H7l7E78qXSXlvtkFc5kUDK
         O4sQ997tUIYdmXV3p1vJnIJeGf5CL4yIxkqrBfqpXPipXlincCk9ycjYLIaGw/hicIVI
         9vrOfUfcOcFMWj9XRaqXLg0bS2oc3QTEI7a+Uzwnm0PqlnggbviZfCbcU9Th1ykKzXg4
         zygapc84j9H7DDcWq8x9q4sfbQrXmVLaUp1DZW9eKSP8breFmQp0Cp4YwBJTQY5YDOd4
         9WDq4IZ+i0aTZE/qt6L9IF+PAluXvqdlXDxYvfjKx8wkUX1Bs44iBaEqes+fBOCKp7C1
         ZAWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IHzJ0A0S;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Flaa7JXsPeD/PJm6ufEMCh/jiUrFEXp/DDy1WMsyyus=;
        b=kaAUx4uqettQpBXfCqMi0QY8ZXDcOaXtdweZ7VDO5hBXGzLfwU/iTjgr0op1xUfQu+
         +i7avY59BvRqoyZRU0CVfGnHXh1Z4cuTWEHPstHK2aBo2Y2oYMdqZIiw0TqIJE9iAk5J
         A+i8p/nprH2u98Y8fz/i4JnRfsrgNGs3mRCtWUtQK/6eI73keFWd8qZI/UrFlnO0hKDY
         6ONUrNP4JaWEkvMQJYU7e6jHDN3NGOEywGBgVRJaf6Q/NSF2rzA2RJCcJRxzZsFq7Rcs
         a1HTgbVKYrP4zgu5xBgQIXiAMy0JcchJ9efQD9QXmFDIYOhHu3EZS8XeWXnzGqd5GzGT
         k/AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Flaa7JXsPeD/PJm6ufEMCh/jiUrFEXp/DDy1WMsyyus=;
        b=NViEYeegPGBpClKlKi3kerQbG8eYesyMO9TVeDGYMi9hmxd2evVVLDZo8OJDk2B+ah
         CB8IWwBQY9WdVQqmWq1MzCLqG7qyCsE7pzvB4OfFmLy759vV9uS1aul5BJT90i6So5zY
         ahoEbEfMKhWMHXm7HMlgHJLuheOUP8MQYTmTQ2kI5Hr99sA03eXzZv8SMVN+yJMQsol+
         aUE9NaUaIK6ZmyKMkZwlNee/Q/f4E6teuwDUdlybsNds6Fzpjxj8gnB5IfJhF5unOh/S
         2onGvRF9LsIUc4FEnNnQEONtV7i2q1Xj63nCqI/M1+tpRE0PZJ9k71zTdqTv9Nxg9tWF
         LJKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXbugXk3kobAnPG213JY4Q/jNAiS2BdSMNtj5vkuXe7t0td28t7
	CptP/g4fW8KXAyZjH2zHiNI=
X-Google-Smtp-Source: APXvYqxcfXS2ZvHmEYlZ9GU/omLEggQBhcqwRJMyA2yEEYziuc911inhpTd0HbJ8cWegRrpyG+dqVg==
X-Received: by 2002:a92:1e06:: with SMTP id e6mr505424ile.104.1576627685285;
        Tue, 17 Dec 2019 16:08:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:8626:: with SMTP id e35ls21299jai.6.gmail; Tue, 17 Dec
 2019 16:08:04 -0800 (PST)
X-Received: by 2002:a02:3b14:: with SMTP id c20mr785142jaa.10.1576627684914;
        Tue, 17 Dec 2019 16:08:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576627684; cv=none;
        d=google.com; s=arc-20160816;
        b=iUspSzb6dtyO3k+3+4vZTRnNo4fXA0/PiA9hiA/KyE0u4ZVY+N8UKoDW+XFBprAR2z
         W7rsxpn1+hYY0NuuTXl6svCcvSmWAoruNygg6zKolIdqHLjMoHFyBAPXQy4U6E0WnRdi
         1EDAbeaMHRFKu3dJShOgWsTJtXMo1pTcg1f2YyqFehSz/K1uRWzGdsIj5YopTUAM3+cR
         TrMAiJrCSpsq+ImhGn3TgIP12Dbc8HqwzMoVijeAPt3sIh8e8yD3q2PmMyKBac9H6Ul0
         0V3qL+Wy7lx+K8zNnSnYKEWj3yYWlppnEfrNx9Ax57QWd2jRtC5PEHqAEGDqp2WOHmKC
         kYmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=da4hM4UJKgmO9iz3pXI2WshcEvtAp8fX82/geQVC7e0=;
        b=N6RHmngnCG2LVQINBkzDC98gyPrc72YYXE/4H0aJVvJ84KzrxjOE//cvM9pTBhuAOR
         mv7dOk7QDrUYy5gEt6i20cgZp+nmz4NiCSrQCZyraOuQ8ZsgvO0r/8SwGo5UZeXIainf
         P+82DKx2/9Ar33mdqDTQWBon1Ug73k4NF/JvJJZQa22LFZP81bBnycXbKj49z8Bth9l/
         raD5Qsc3qIOea+lN57Ty5xldeEZqnQ6PVxGi2gapZOhbakx9IjkLoFJ5uFdXKhfB5S6B
         AWEgfpoc6LKcdFvT0xyPh/SeYJNs+GThMYsZAhpx5ztF7+yQLIOrxPAVZI17dTezG9Di
         2chw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IHzJ0A0S;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id z20si30907ill.5.2019.12.17.16.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Dec 2019 16:08:04 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q8so151612pfh.7
        for <kasan-dev@googlegroups.com>; Tue, 17 Dec 2019 16:08:04 -0800 (PST)
X-Received: by 2002:aa7:98d0:: with SMTP id e16mr457396pfm.77.1576627684350;
        Tue, 17 Dec 2019 16:08:04 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t11sm77450pjf.30.2019.12.17.16.08.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2019 16:08:03 -0800 (PST)
Date: Tue, 17 Dec 2019 16:08:02 -0800
From: Kees Cook <keescook@chromium.org>
To: Will Deacon <will@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: Re: [PATCH v2 1/3] ubsan: Add trap instrumentation option
Message-ID: <201912171607.73EE8133@keescook>
References: <20191121181519.28637-1-keescook@chromium.org>
 <20191121181519.28637-2-keescook@chromium.org>
 <20191216102655.GA11082@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191216102655.GA11082@willie-the-truck>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=IHzJ0A0S;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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

On Mon, Dec 16, 2019 at 10:26:56AM +0000, Will Deacon wrote:
> Hi Kees,
> 
> On Thu, Nov 21, 2019 at 10:15:17AM -0800, Kees Cook wrote:
> > The Undefined Behavior Sanitizer can operate in two modes: warning
> > reporting mode via lib/ubsan.c handler calls, or trap mode, which uses
> > __builtin_trap() as the handler. Using lib/ubsan.c means the kernel
> > image is about 5% larger (due to all the debugging text and reporting
> > structures to capture details about the warning conditions). Using the
> > trap mode, the image size changes are much smaller, though at the loss
> > of the "warning only" mode.
> > 
> > In order to give greater flexibility to system builders that want
> > minimal changes to image size and are prepared to deal with kernel code
> > being aborted and potentially destabilizing the system, this introduces
> > CONFIG_UBSAN_TRAP. The resulting image sizes comparison:
> > 
> >    text    data     bss       dec       hex     filename
> > 19533663   6183037  18554956  44271656  2a38828 vmlinux.stock
> > 19991849   7618513  18874448  46484810  2c54d4a vmlinux.ubsan
> > 19712181   6284181  18366540  44362902  2a4ec96 vmlinux.ubsan-trap
> > 
> > CONFIG_UBSAN=y:      image +4.8% (text +2.3%, data +18.9%)
> > CONFIG_UBSAN_TRAP=y: image +0.2% (text +0.9%, data +1.6%)
> > 
> > Additionally adjusts the CONFIG_UBSAN Kconfig help for clarity and
> > removes the mention of non-existing boot param "ubsan_handle".
> > 
> > Suggested-by: Elena Petrova <lenaptr@google.com>
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  lib/Kconfig.ubsan      | 22 ++++++++++++++++++----
> >  lib/Makefile           |  2 ++
> >  scripts/Makefile.ubsan |  9 +++++++--
> >  3 files changed, 27 insertions(+), 6 deletions(-)
> > 
> > diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> > index 0e04fcb3ab3d..9deb655838b0 100644
> > --- a/lib/Kconfig.ubsan
> > +++ b/lib/Kconfig.ubsan
> > @@ -5,11 +5,25 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
> >  config UBSAN
> >  	bool "Undefined behaviour sanity checker"
> >  	help
> > -	  This option enables undefined behaviour sanity checker
> > +	  This option enables the Undefined Behaviour sanity checker.
> >  	  Compile-time instrumentation is used to detect various undefined
> > -	  behaviours in runtime. Various types of checks may be enabled
> > -	  via boot parameter ubsan_handle
> > -	  (see: Documentation/dev-tools/ubsan.rst).
> > +	  behaviours at runtime. For more details, see:
> > +	  Documentation/dev-tools/ubsan.rst
> > +
> > +config UBSAN_TRAP
> > +	bool "On Sanitizer warnings, abort the running kernel code"
> > +	depends on UBSAN
> > +	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
> > +	help
> > +	  Building kernels with Sanitizer features enabled tends to grow
> > +	  the kernel size by around 5%, due to adding all the debugging
> > +	  text on failure paths. To avoid this, Sanitizer instrumentation
> > +	  can just issue a trap. This reduces the kernel size overhead but
> > +	  turns all warnings (including potentially harmless conditions)
> > +	  into full exceptions that abort the running kernel code
> > +	  (regardless of context, locks held, etc), which may destabilize
> > +	  the system. For some system builders this is an acceptable
> > +	  trade-off.
> 
> Slight nit, but I wonder if it would make sense to move all this under a
> 'menuconfig UBSAN' entry, so the dependencies can be dropped? Then you could
> have all of the suboptions default to on and basically choose which
> individual compiler options to disable based on your own preferences.

Sure; I can do that. I'll respin the series.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201912171607.73EE8133%40keescook.
