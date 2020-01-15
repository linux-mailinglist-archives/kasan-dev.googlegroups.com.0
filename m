Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB7V47XYAKGQEIKQXBAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DD85013CC83
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 19:48:30 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id dd24sf12102174edb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 10:48:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579114110; cv=pass;
        d=google.com; s=arc-20160816;
        b=BG1l53747ytBiUCEjvCwMoNeQoAL25i93z08n9gX11vrNbFIbSAw/1abmKgRTDRz+d
         3IYZ2Uw6XDiDbSiEwcXY4dgziMZ9grzaX30XcNHHkwuAIFw2UCxFNRYq/ZjRaxQSI4WD
         AXBUg4V6SuO+QXmAAbacYXYEKHlonbYbg48nzp6TQDtViZPL9YsRdUAq2UYpAByTJnLa
         m1O4hSgMlbbbZlC2ONKoXoEtStHMwc59qA4zpmAATFkkcap5nSdx6bF3HKV9S2lmi+7d
         SZnzNLwpk+ztZjjRD5JaPdH86sfrGhKnPy99vUD7dXkxfwCIARa1xbz7gVNM9tPl5tl+
         sjkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=aAV3c8+kQAefi8uu+gUw+KflXvpHUq2ebs66OgWrhgI=;
        b=ffZlAk/fiUwA8GVUt2ThqKS/b+anXyQe9gmmt6WbYI91cGQJyaKoJ9BlKBuRnxEsB7
         oZb58FqKF06kUO4/KYM2LlnCLd/SYpNd3NiGTU7fpL+MnsyHgDdAUYiD6mlG5fCttkN6
         2QeCfldliLT3rQMeZtuPd5yq/4r2w2jTlEuJvq+anV8zL3DzAuo9xC1Be6uVzY6ITzy8
         em3p3sLCrsn6VDSr4xVWirnS8F1ulxEjyhu8TV+a7kbUdBHTk5lxJcvlFPbQtp67Z+7n
         N6JZR9mC21bC+flGAtFXxgo5oT1fwYiCwuZYbZVmDxnhBZd2hhQLGbZgxNMRy25JgLa4
         khVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aAV3c8+kQAefi8uu+gUw+KflXvpHUq2ebs66OgWrhgI=;
        b=JYtKduHxYS9JZ1CkET0eQS2bZJ6PQRqsDc2AE787YH3w5DBZ828LjFW7rFm1s4mX7r
         6gfYBvM2zvv9KJVUspyiHLYIqMBs0fuCUhYYe7HUlBFLhiFKAKm8KB4vHK+sQC7Q56x0
         43WUVRzbve2dodOxPUKa7iIvtA98dbJioqQw/tW4PFznKzuDgTg6Zr2//pEISW8+ETmH
         NB9AXY1wyAz6GaaOiMGI1NQyNVbPPvj8Gyb2sdHyIcS5zwgYKhR46dXbYK7zqbfySAsx
         KS8EZMCd29si3FqFBaFOU2IVooIqzwlO16EzoVRwB9p4pJxBG4Ow4v/i7adywPkRv8mt
         xQPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aAV3c8+kQAefi8uu+gUw+KflXvpHUq2ebs66OgWrhgI=;
        b=MFwplYYUtWgqQtrxbZ+cmlSCCKwkgeTJZU8d1qgtPBaailFcE2W4Jmm+bw0KiG1X8t
         1y+PRfeaN4tjrVG8ENGQJ+8YEK9Bh0tsuYX9w9A3luhsULU59yvg84oU6vtJrS0LzuG9
         /PmQcbZizIrb71MMWsE88KVKREPQTM4dJpw9ybJlIs4YD7DL6mHRYxzN7e+va5noBigL
         mnyrDqrd4KHsDjYAJ6lZ6axbfcfmdmRYQXzdu7QWrgJuflfQ1EEWmLej5mWdOD7U1zSY
         XfcNuGFY0HrRtualSQP5lHo+OPf9ah0AuuJW0rKMNnIA4PI5RNSuGsRSgbXZ1an0Ax4R
         Xomw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX69XbX0+e14qwUBzBPTaYnkpAmvcQ+0AP+qE6SLSX9r5Na3fn9
	7KZUT08662yP4RHSKfpjGsE=
X-Google-Smtp-Source: APXvYqxyQotHuZTEVhcDRKLnnaay9wZkMckrAGUp5CVWmILkyzhsnbE1/wHYXyUwqiR2WvTno6mn8A==
X-Received: by 2002:aa7:c694:: with SMTP id n20mr32100660edq.95.1579114110528;
        Wed, 15 Jan 2020 10:48:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bb47:: with SMTP id y65ls4455146ede.1.gmail; Wed, 15 Jan
 2020 10:48:30 -0800 (PST)
X-Received: by 2002:a50:9ee8:: with SMTP id a95mr32066389edf.86.1579114110052;
        Wed, 15 Jan 2020 10:48:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579114110; cv=none;
        d=google.com; s=arc-20160816;
        b=ybjD53eeYyQMYxH7gYjDQ0167fSyEzZOPq8g1RxNWTa4clxeH/8jus3eeM/MW1LLJJ
         5LjK4xhucyu4EuJ/gya9J+ySQm18qkZImO+FieE+JaJaDImWb/34fyuflfEcnFJJGjVV
         P4OOlVbFImoHYUX6mjxA8sP6FHRoYXS/fm+FZSg/mkEkYshxGDW5at8ddt2pFlvj2evI
         JSJU5vZaLKbw3IXREf3fTbX2JEpSFXUrkKZYZWzkNQ4gtoCxVYvIjVI44vFRVytyJBz4
         hAdHJ59T1bnNwZa75TvMrhHGE4I710N61/+2irlAG1BodytkTmnC60FQ8KtfJJAy+GdB
         ffNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=d6yF8qemRhhkAgUCLCDG8LuMLltjeNaCMz6H2I0fcJw=;
        b=SJkZ0LohSwWNae9ZH8Eu+jC40+ULBDBeyGah6Otir4mdcAErlaJ/zBcorEOXjONFEb
         E6Y6IvZDDK6u9GM8b/7r6cva8hDat+lBXzUe78YQQQmV5CbhdlnJa6zs4l6as/j+/QPO
         d+FVERGpaBs2dNI/GvmXLsc7DC/picbBPzsgfd2a0BjpPbzlj/qv4O7hfTELEZBchVyo
         0jdgdocWQg6T3VkiqsoZFVMwTfL02z0vlo6Lrh09ZnNcpevrFlUJWPcuD3fNBit5iGT7
         7CXgy3hsT8ghNEIEjJf5v2X8iDuRW5W2ZSjN5BxkkiiK0S81EQRG5liPqiaOabocrg5K
         4MlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id d29si889096edj.0.2020.01.15.10.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 10:48:30 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1irniB-009spe-PH; Wed, 15 Jan 2020 19:48:15 +0100
Message-ID: <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>, jdike@addtoit.com, 
	richard@nod.at, anton.ivanov@cambridgegreys.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, davidgow@google.com, brendanhiggins@google.com
Cc: linux-um@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Date: Wed, 15 Jan 2020 19:48:13 +0100
In-Reply-To: <20200115182816.33892-1-trishalfonso@google.com>
References: <20200115182816.33892-1-trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

Hi Patricia,

On Wed, 2020-01-15 at 10:28 -0800, Patricia Alfonso wrote:
> Make KASAN run on User Mode Linux on x86_64.

Oh wow, awesome! Just what I always wanted :-)

I tried this before and failed miserably ... mostly I thought we
actually needed CONFIG_CONSTRUCTORS, which doesn't work (at least I hope
my patch for it was reverted?) - do you know what's up with that?

Couple questions, if you don't mind.

> +#ifdef CONFIG_X86_64
> +#define KASAN_SHADOW_SIZE 0x100000000000UL
> +#else
> +#error "KASAN_SHADOW_SIZE is not defined in this sub-architecture"
> +#endif

Is it even possible today to compile ARCH=um on anything but x86_64? If
yes, perhaps the above should be

	select HAVE_ARCH_KASAN if X86_64

or so? I assume KASAN itself has some dependencies though, but perhaps
ARM 64-bit or POWERPC 64-bit could possibly run into this, if not X86
32-bit.

> +++ b/arch/um/kernel/skas/Makefile
> @@ -5,6 +5,12 @@
>  
>  obj-y := clone.o mmu.o process.o syscall.o uaccess.o
>  
> +ifdef CONFIG_UML
> +# Do not instrument until after start_uml() because KASAN is not
> +# initialized yet
> +KASAN_SANITIZE	:= n
> +endif

Not sure I understand this, can anything in this file even get compiled
without CONFIG_UML?

> +++ b/kernel/Makefile
> @@ -32,6 +32,12 @@ KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
>  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>  
> +ifdef CONFIG_UML
> +# Do not istrument kasan on panic because it can be called before KASAN

typo there - 'instrument'

> +# is initialized
> +KASAN_SANITIZE_panic.o := n
> +endif

but maybe UML shouldn't call panic() in such contexts, instead of this?
I've had some major trouble with calling into the kernel before things
are ready (or after we've started tearing things down), so that might be
a good thing overall anyway?

Could just do it this way and fix it later too though I guess.

> +++ b/lib/Makefile
> @@ -17,6 +17,16 @@ KCOV_INSTRUMENT_list_debug.o := n
>  KCOV_INSTRUMENT_debugobjects.o := n
>  KCOV_INSTRUMENT_dynamic_debug.o := n
>  
> +# Don't sanatize 

typo

> vsprintf or string functions in UM because they are used
> +# before KASAN is initialized from cmdline parsing cmdline and kstrtox are
> +# also called during uml initialization before KASAN is instrumented
> +ifdef CONFIG_UML
> +KASAN_SANITIZE_vsprintf.o := n
> +KASAN_SANITIZE_string.o := n
> +KASAN_SANITIZE_cmdline.o := n
> +KASAN_SANITIZE_kstrtox.o := n
> +endif

I guess this can't be avoided.


Very cool, I look forward to trying this out! :-)

Thanks,
johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel%40sipsolutions.net.
