Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRVRXKLAMGQEFEZGY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 67A285733B6
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 12:04:55 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id sh39-20020a1709076ea700b0072aa3156a68sf3171234ejc.19
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 03:04:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657706695; cv=pass;
        d=google.com; s=arc-20160816;
        b=UHRTfQxEAb6XzHn4QbMd39QtkX7Q0rcr3H71c1LlRBrne6FookwV/nKezOwXJeBcqS
         +ugRFvfDdht+KdTIXnP61V0rNoViqA1DEWtzO4LY7ZE5fRU+rUBIHsxuwDUjZHXt+WCX
         y/yeMSpawDjAizTS+NgvFxvDWfdc1b53G2spYh5wf7SAZQy1pzQLZ3Al3u1NknTzMHPC
         WtqZYWwW2OB0ucA75f3Rr7jJX3AY+59mAnPF0RZ8dIh26zec5LsFBaHv0Y1UdJ2A+acZ
         Yh2wnOLBZOEzm87IIaYhMJIjDoXRNoXWHiGtfYYwanJb9MWppKpzSZjQrKZJ1eKXEbDV
         +f0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EiEcANrZH4eRqYJI84uW5XqatA7jZDHf38w3vOPJgJw=;
        b=sE33V5fuLW4j4yF5WdZb4ZnoPyI0wPK6w1Z1pdABVV7A7j4WwKBZQs6cx5rWF4ELEU
         61FzVT8wxYKflp5frZRwRPt3p4KHohGbsVk/S8Mpd+dlaepVp/0XzftoUcxrmHsvMtFr
         gPAmJqOdo9hAe2Pj1p4bsKMMIXxLzPwSgsVwCivXwpCLvqbSvGwkWdUZNTctIq+AOzmN
         kVD7Ms2N+WVd47BFO1Dct5E1gNJ8G/hSX1FakF02GqDzk4vIJrEudF4STS8x1/PisXNU
         kpikJ9jwxsatc+jYBLf1Nls07zbax9fXR+bNiT7gHOq4r7oTWM9mTh3UnJbv3qS6LUl/
         WFIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=he3+yyZi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EiEcANrZH4eRqYJI84uW5XqatA7jZDHf38w3vOPJgJw=;
        b=GNljrc0o9ChkUiPFzZA7tmWQcHPlewKRovfrWpxexXL4g4sw1XYi2+gCyxpFXHemQW
         +734iMtniqquiiXSdIjf0nLEO5iGrpy2NrK3UjgVLds6u09kuaHGgTCq19COBHCZa2VM
         p9sc7Y6/sumkkPmBU37pI+X7G9jnpuEoX7cXjmiK/V7HoDBZ3RpbpLCT0gmSEvJSLhnw
         kUT9m1Gbzi2njo/lQPo4DwYjShTp/cJrWaxuhv4mp8IgvZeTS0l+xSHQdqscCWOA1WoZ
         iRN17BSoTxT2sG1yc8Ac7cQpbAV4x2WwclHC6w+hDkIPdwQcgxktJ7THyrTdXK/s5N5Z
         V2Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EiEcANrZH4eRqYJI84uW5XqatA7jZDHf38w3vOPJgJw=;
        b=yRdWaZQKhuHMP+/Gs4yVPVSXMXtNkqvmQtabOL1Mu/3QwTsPeTBuW0GBjUAZfqPyCp
         ukDYbmlWJ/DYBlM4sVwD9DtxHa4VgboJg4umt/2ICGmSLvy0WE3C0MbFbFAleaz4Tv+z
         Am9lkBuFi47J0NHPlyeBuzXUf9ZxhEy3LQa4eXUgG8VI5Vj0qX+z9ph2oeobUxOnpXYC
         ADs3q/Ob9c/RNMFtwZNz+PLoa4ZZLTfAmSAS3+ExnYM30TG2VwtyWzUCI7ETm7JYs9I9
         9mArRlWlIx0LQzzUWrJ6cqq09hsyFnrboHIQ//yOhh+Gzih41WuKRmG+/LEk5/79Lbr7
         yzCg==
X-Gm-Message-State: AJIora/jQWAYdLBIVR2g8mQC3uc7thnt+cUcDyuTmB76DLBoKQRs6t/+
	p7cW2pCWe7O1OnAN3+J76Hg=
X-Google-Smtp-Source: AGRyM1stZXT5NxGh0jM4jhcdkqaDMO9YasvBPgaR4zPmhawP5kCAUxP4FnxCv7B/gZaqXuhCn3hx+A==
X-Received: by 2002:a05:6402:4410:b0:434:f35f:132e with SMTP id y16-20020a056402441000b00434f35f132emr3667462eda.215.1657706694994;
        Wed, 13 Jul 2022 03:04:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95c1:b0:6ff:45d:c05d with SMTP id
 n1-20020a17090695c100b006ff045dc05dls2755776ejy.5.gmail; Wed, 13 Jul 2022
 03:04:53 -0700 (PDT)
X-Received: by 2002:a17:906:5305:b0:712:388c:2bf5 with SMTP id h5-20020a170906530500b00712388c2bf5mr2547186ejo.559.1657706693658;
        Wed, 13 Jul 2022 03:04:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657706693; cv=none;
        d=google.com; s=arc-20160816;
        b=wx3I2TiN6o8gllqkTFULfVd/Lc+2hHuH8ff+i6qR4E51qf377t0y7Qv8S2e8hVgKfV
         UH2Sz2HnMm5oE8YuWlE0KvYHjIVQoXlbopsB4miqOYTdTCBZhOPwk6954c46aEdDj2p3
         QvQEmuP/bY/q7cBnRDvtGeMAWNTRhHuTKSaJV20VLUYdwgl2Vu1TtmOggVO+uOyk4/nA
         fcc3aGt0MRTCLDYSGBQYzNBf882HPjIkRcWtcvpkeNDIGWLT/2qh4yHQbrbgH6DedIEY
         uiUdVkYKq77GSn7ptRK3Grh+Oaei/7J+dpPYrKfLvpPDP64Cr+WRCtGRpC4hFGrKJuod
         L4TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=f6Y9qjwogxCtal7OxlGnHDAF4wB3anj4wqmO3ly+ml0=;
        b=gM/EflBwx9v5FbQiWq0P3Chz/xrezQbXTmCwUAMLXTCWxoSbjUrL6TBfo5sYPDOivB
         fHn/bghC7XgSLHkchhPSSigv2bXo7l0QaDLIDsa47TzzqLmxpLy54adbK2Vmh99Nljfy
         dZoo91kNjXuZIHuF7idbdWFMgScKHf7PaGu2u1q6cak715U6Kt1qtHDvT3yH5Tb/OREO
         bOx/5mCx6VlMQSAQ7cBaLxFezENdSnb8l3jARQkRe4WQ9loHulTmQN93BPkw8DyKhH+q
         6xtsEnHjsqK8598DVFAgtINqm4R+GVvaKuLh9BAEj2GahjmgXGLHKqlPJgQw6B4d/3Oz
         m0Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=he3+yyZi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id d2-20020aa7d682000000b0043780485814si475316edr.2.2022.07.13.03.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jul 2022 03:04:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id i204-20020a1c3bd5000000b003a2fa488efdso570788wma.4
        for <kasan-dev@googlegroups.com>; Wed, 13 Jul 2022 03:04:53 -0700 (PDT)
X-Received: by 2002:a1c:1902:0:b0:3a2:ee85:3934 with SMTP id 2-20020a1c1902000000b003a2ee853934mr7963222wmz.31.1657706693167;
        Wed, 13 Jul 2022 03:04:53 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:63e6:a6c0:5e2a:ac17])
        by smtp.gmail.com with ESMTPSA id p6-20020a05600c358600b003a2e2ba94ecsm1640729wmq.40.2022.07.13.03.04.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Jul 2022 03:04:52 -0700 (PDT)
Date: Wed, 13 Jul 2022 12:04:46 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 11/45] kmsan: add KMSAN runtime core
Message-ID: <Ys6YvvARDX6pWmWv@elver.google.com>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-12-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220701142310.2188015-12-glider@google.com>
User-Agent: Mutt/2.2.3 (2022-04-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=he3+yyZi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Jul 01, 2022 at 04:22PM +0200, 'Alexander Potapenko' via kasan-dev wrote:
[...]
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 2e24db4bff192..59819e6fa5865 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -963,6 +963,7 @@ config DEBUG_STACKOVERFLOW
>  
>  source "lib/Kconfig.kasan"
>  source "lib/Kconfig.kfence"
> +source "lib/Kconfig.kmsan"
>  
>  endmenu # "Memory Debugging"
>  
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> new file mode 100644
> index 0000000000000..8f768d4034e3c
> --- /dev/null
> +++ b/lib/Kconfig.kmsan
> @@ -0,0 +1,50 @@
> +# SPDX-License-Identifier: GPL-2.0-only
> +config HAVE_ARCH_KMSAN
> +	bool
> +
> +config HAVE_KMSAN_COMPILER
> +	# Clang versions <14.0.0 also support -fsanitize=kernel-memory, but not
> +	# all the features necessary to build the kernel with KMSAN.
> +	depends on CC_IS_CLANG && CLANG_VERSION >= 140000
> +	def_bool $(cc-option,-fsanitize=kernel-memory -mllvm -msan-disable-checks=1)
> +
> +config HAVE_KMSAN_PARAM_RETVAL
> +	# Separate check for -fsanitize-memory-param-retval support.

This comment doesn't add much value, maybe instead say that "Supported
only by Clang >= 15."

> +	depends on CC_IS_CLANG && CLANG_VERSION >= 140000

Why not just "depends on HAVE_KMSAN_COMPILER"? (All
fsanitize-memory-param-retval supporting compilers must also be KMSAN
compilers.)

> +	def_bool $(cc-option,-fsanitize=kernel-memory -fsanitize-memory-param-retval)
> +
> +

HAVE_KMSAN_PARAM_RETVAL should be moved under "if KMSAN" so that this
isn't unnecessarily evaluated in every kernel build (saving 1 shelling
out to clang in most builds).

> +config KMSAN
> +	bool "KMSAN: detector of uninitialized values use"
> +	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> +	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> +	select STACKDEPOT
> +	select STACKDEPOT_ALWAYS_INIT
> +	help
> +	  KernelMemorySanitizer (KMSAN) is a dynamic detector of uses of
> +	  uninitialized values in the kernel. It is based on compiler
> +	  instrumentation provided by Clang and thus requires Clang to build.
> +
> +	  An important note is that KMSAN is not intended for production use,
> +	  because it drastically increases kernel memory footprint and slows
> +	  the whole system down.
> +
> +	  See <file:Documentation/dev-tools/kmsan.rst> for more details.
> +
> +if KMSAN
> +
> +config KMSAN_CHECK_PARAM_RETVAL
> +	bool "Check for uninitialized values passed to and returned from functions"
> +	default HAVE_KMSAN_PARAM_RETVAL

This can be enabled even if !HAVE_KMSAN_PARAM_RETVAL. Should this be:

	default y
	depends on HAVE_KMSAN_PARAM_RETVAL

instead?

> +	help
> +	  If the compiler supports -fsanitize-memory-param-retval, KMSAN will
> +	  eagerly check every function parameter passed by value and every
> +	  function return value.
> +
> +	  Disabling KMSAN_CHECK_PARAM_RETVAL will result in tracking shadow for
> +	  function parameters and return values across function borders. This
> +	  is a more relaxed mode, but it generates more instrumentation code and
> +	  may potentially report errors in corner cases when non-instrumented
> +	  functions call instrumented ones.
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ys6YvvARDX6pWmWv%40elver.google.com.
