Return-Path: <kasan-dev+bncBAABBW435XAAMGQE3NAHQHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 879A8AADE91
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:11:09 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-54fbc42dfeasf57326e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:11:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746619869; cv=pass;
        d=google.com; s=arc-20240605;
        b=K0Er/gTcDiTZlSEXunKfNc7G3qWXhTdTUgtIPsnbLu+mELTfrvuv/a81/OL2VVH8LR
         SNpmD5Ksq8OIJGmTSMEcHDOlZMQiXOxdoLNwbEZVRjroQWiPgGn9NKKRuIkCVSLvQUwI
         U7xWqvGfT5rNNSLcxadbDspLjOgLODGNPXw2XCO6+ww+Ua+0EeS8/w4RfoM018O4xOwJ
         6BOoBpLPrqCoprdnXZioo8PSGeDvPEoDaK6LXiMiRehW4QvHkN6PsN9DjqUUbVP5nAno
         izrXSJjKCM3KSa1aGltPrYT2Uf3CKZpICP7ShqY2YilrkvRTQifTqtRWMLYVkBiFdCW0
         W57Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nLnXgZ4DOPdD1upvEdkfAKKLCdrKQde0wQLg5fTJKZI=;
        fh=mj8KbF7fI85egIjUPHkMXSKZkRPwTXddy7xfq7rMpLU=;
        b=TtMSbDCS6vlNaTNjNLSQkmFYfglNG2qJLRHCrF6chREdjjIigch1S9bVZXTmsNITKA
         6o3fUR4x5gTq2yKaPiRh7nV/wp7NIe5O+qDDh5so28mFqTL3KuKiRWvsA/7AsBzMR+Jj
         PDC3zOakPoNsOaWexG+RR451b4+mq58AIOjG6nlieugCM+iguCNS68iTmz33PHxY29cC
         19Gq9oyEYFiTe9lW5MlNkanoN/VXCX/Wq32mpurPhyhou9P3b0eS07lZuA6N5YY4yHW1
         XgzyadvfGdtA8UT2oYfEcRXqSNaSOqio8TgMVbNTd5NApL5IZCGNF98tRD9+OpzBWsHz
         Ub9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xjwuKz9r;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746619869; x=1747224669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nLnXgZ4DOPdD1upvEdkfAKKLCdrKQde0wQLg5fTJKZI=;
        b=XpN/eyYtwEFmz9/6LqNT3cADJeqVZUvrYZxK4+4PXzyte0+znXutHwErFR7X/DxubR
         JZCE24HjiGyMz9Vu+T7g6IyfZjWVsiobd1OhlOB/ACKvmcBGJ4KFNRX3N4PiQdg5fgHH
         L2/Few++UXPBWq+LRDnZyc/GRo2Hu8sGq+XcObKBfV6QobAZVeEuw6NyrvVMw8Y/At1q
         ZX+DWpByCgOu/pSush5JJRgqt91NTq0oQxA7egTeTdMrdwpEtgADSVl5vJ+LAUQw3ByY
         XO8zzWqSgqdMwaTVgUTW/StlE/GqPyrVLu8igZQd8dnHhdDNV6B9jHFO7MTZOwYdIiL9
         OBNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746619869; x=1747224669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=nLnXgZ4DOPdD1upvEdkfAKKLCdrKQde0wQLg5fTJKZI=;
        b=XbP7YdG28ecu/TPZWAhh3q6RBAH6EAdwQJbN4s0lEXwXuB7toWogh3qFRLDdnvWWZ1
         bPztlNV66MaCyMMvIcieFjk7dZt0oRYzfjtjmNc3IEM5mX7vz54OQDct+onfVUq2Y74y
         mt4ROSTmofosM8CHuEllZZf6o8B6aS4SiZnUp7mZM6KpJME7dzcnaC/dGqJKmAy20Qgn
         Z/hIiWrTNqGeBZ9aIbls8T+4HTLzpE3cQlBcuFOYvY04c8VCDSAujbplwpUXaDiwSrVw
         8r0WSknU37G6V9TH5K5imOGspPdDSxIjsfHQpeuwKFLC+KhKgYuvabflUD827/11+yYg
         MC7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDCRSjC0TnGxFLFZp7ShQTJFLgL47HXYeJNJKHCz49rtgk56sf/b7X6uJOUOIq/nbQ1YjecA==@lfdr.de
X-Gm-Message-State: AOJu0Yxdn5mXtSCEqzGwJck+QRgm66CWRKImdGTmI1qgtg8YV0sL6sdT
	r/sIN46bcv87TzxonPKj+j8VKjT5gvR6SbzueOAUg1/uGjU/+BmG
X-Google-Smtp-Source: AGHT+IEAUCQNawXRAZP+1U0cmipfvh12nnf3qr7xr15pvTa7R6HBy00ZB5q3ygS5RGdQSDh+AKxHBQ==
X-Received: by 2002:a05:6512:693:b0:549:55df:8af6 with SMTP id 2adb3069b0e04-54fb95a2a69mr1030919e87.53.1746619868469;
        Wed, 07 May 2025 05:11:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGIz1O/3srLhss81TpshE63TrpGn03MdrEBNIz4JU/Isg==
Received: by 2002:a19:8c54:0:b0:549:9221:d9db with SMTP id 2adb3069b0e04-54ea6700848ls1066354e87.0.-pod-prod-08-eu;
 Wed, 07 May 2025 05:11:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhdeUitxIni2U2jJvslMcrOOKy/ZmsnjrDFFmrBiS4LqZ2fXbtESweCLix95HJRMhmiRxLAbPoRmg=@googlegroups.com
X-Received: by 2002:a05:6512:130f:b0:545:cc2:accd with SMTP id 2adb3069b0e04-54fb9292e42mr1151103e87.20.1746619866523;
        Wed, 07 May 2025 05:11:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746619866; cv=none;
        d=google.com; s=arc-20240605;
        b=Er/ilLbfqe3aCAQk75VzTqjYxiqMzM7kFsyWlooMeZQNfJ7SlddpHberGXadleSYV9
         4GoncUFyF6C+wyUyee8CZgQhzBtEncdaYvtAmHnV8R1biZjJv9ya8t5EA7VLIN80aPY7
         3CRccVyjKyj0lYSNtWMY7z9YE69ZZcCeHehsguLT1qYmNLSMkNYyZqicRVdO9j3668KZ
         MzmAJ4HyRiovJrndTabxRi+m1Rr+I9kxtWt60oM5kQYYqPwK5acdeLCfebqdPNuaE9NW
         e9JbNLcPrwcmG00jDxJSAcZu8oCj1nHfNKfr/9b0k747gEWmWm3Q0Zk6V5x6c3R9BlUu
         RE8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:dkim-signature:date;
        bh=U24XQpAOzVn9OeiX2WXRKmdViNITlRLJUufl1hqU+7o=;
        fh=5LgOg5hMHe1IfmFnW6K8B58w9dkMEP1FykAE3ty86lg=;
        b=Or2T+MkVYF7VzH5Hhx+cPJM//eQKqEUH04vap60sRv8C0O825WpMEbCAuSg2TRHo0M
         wDF8ugA9Yq3CcEPFXEkM0weXBhxAqAGD0NJBW28UfO6+XFnsr4ljalx3Z23+aD/RCV1n
         sJYJ5Q3GV+61Yn5z2ZjmzI265NgN+ZbjBlWTwDsLqMLd7RBSmwFTYZQ9ydkze4WaNHHn
         Lg8xj8I6uOanQwv3A/LjA50L99HTdcJ3s95WT9MnV8h4c7d+ptQ8pl+LHLN5S0j9kyrh
         K6vZQxe0wj5kNoftXcn3BXyuM88BKUK1CEwZVyQaTkBR8DRehTvlB0/vRFLIk26Gxf7+
         /zkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xjwuKz9r;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-174.mta1.migadu.com (out-174.mta1.migadu.com. [2001:41d0:203:375::ae])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ea94f4f36si393731e87.10.2025.05.07.05.11.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 05:11:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::ae as permitted sender) client-ip=2001:41d0:203:375::ae;
Date: Wed, 7 May 2025 14:10:55 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev
Subject: Re: [PATCH v3 1/3] gcc-plugins: Force full rebuild when plugins
 change
Message-ID: <20250507-overjoyed-coucal-from-betelgeuse-4eaa7b@l-nschier-aarch64>
References: <20250503184001.make.594-kees@kernel.org>
 <20250503184623.2572355-1-kees@kernel.org>
 <20250507-emerald-lyrebird-of-advertising-e86beb@l-nschier-aarch64>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507-emerald-lyrebird-of-advertising-e86beb@l-nschier-aarch64>
Organization: AVM GmbH
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xjwuKz9r;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates
 2001:41d0:203:375::ae as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, 07 May 2025, Nicolas Schier wrote:

> On Sat, 03 May 2025, Kees Cook wrote:
> 
> > There was no dependency between the plugins changing and the rest of the
> > kernel being built. This could cause strange behaviors as instrumentation
> > could vary between targets depending on when they were built.
> > 
> > Generate a new header file, gcc-plugins.h, any time the GCC plugins
> > change. Include the header file in compiler-version.h when its associated
> > feature name, GCC_PLUGINS, is defined. This will be picked up by fixdep
> > and force rebuilds where needed.
> > 
> > Add a generic "touch" kbuild command, which will be used again in
> > a following patch. Add a "normalize_path" string helper to make the
> > "TOUCH" output less ugly.
> > 
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Masahiro Yamada <masahiroy@kernel.org>
> > Cc: Nicolas Schier <nicolas.schier@linux.dev>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: <linux-hardening@vger.kernel.org>
> > Cc: <linux-kbuild@vger.kernel.org>
> > ---
> >  include/linux/compiler-version.h |  4 ++++
> >  scripts/Makefile.gcc-plugins     |  2 +-
> >  scripts/Makefile.lib             | 18 ++++++++++++++++++
> >  scripts/gcc-plugins/Makefile     |  4 ++++
> >  4 files changed, 27 insertions(+), 1 deletion(-)
> > 
> > diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
> > index 573fa85b6c0c..74ea11563ce3 100644
> > --- a/include/linux/compiler-version.h
> > +++ b/include/linux/compiler-version.h
> > @@ -12,3 +12,7 @@
> >   * and add dependency on include/config/CC_VERSION_TEXT, which is touched
> >   * by Kconfig when the version string from the compiler changes.
> >   */
> > +
> > +#ifdef GCC_PLUGINS
> 
> Out of curiousity:  Why can't we use CONFIG_GCC_PLUGINS here?

... because compiler-version.h is included before kconfig.h (which 
includes autoconf.h).  Sorry for the noise.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507-overjoyed-coucal-from-betelgeuse-4eaa7b%40l-nschier-aarch64.
