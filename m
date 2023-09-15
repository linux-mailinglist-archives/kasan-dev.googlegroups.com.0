Return-Path: <kasan-dev+bncBD7LZ45K3ECBBO6JSCUAMGQEY7EB7HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 803BE7A1A97
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 11:32:45 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-403ca0e2112sf15101115e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 02:32:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694770365; cv=pass;
        d=google.com; s=arc-20160816;
        b=zGc29pyCsyS/dmAh1lTUTeUkklEuCEhMCeLFlCcSRz+cbYVyLB5KTs2S0+OAZvKQ7Y
         VIsJkNT1/Iht1DIlht/TExzk0RYoEDWLTWoEPQ61JoZPYWn3ToV1k+1poJv6u/2bsogS
         ZzBuQGjpDXG84OIUw/zWdGVvqfmeYQLXIs1ZkJ2vUSz7TGXStdhHbpYUYZmzZjCvXeG5
         M8RwfeH5qIJnYUl0dHfgqQaG+65g8pFXZRVkIjgTY4NUXr6id5VaWVNB96CJtmz4GkjZ
         IFOqEmJ58tQXQj45tV/ttl1Rw4Mp7AfzNBGvpkGWNCmy8iS7Yv/qS7vBcIylbCwLw+mS
         OzNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0wlmZUnHdQA6237rE+MIob63rYVACvkl2183Z1QteSA=;
        fh=aynDOFLzDB2kr2qBsfK7us7ujPaK2T87eZYLEnGhBb8=;
        b=s9BEOlJkZFpWpw5Qs7K9a0ZG3WEc7YSsLyVJ66DJHQHo3VGJs0M0XnloWVusl+AkMy
         XBzNCvBFbUDWKsik8fuWvQ+VIgRWNDGhryod2KTj5OKvweIlLTMWOFc/gKX5txsCGTmT
         xVa0e9EqxT+H/2r44pNMRA3JzaCzMApJvy6A4GOkUPTE8APLt+McxO3V5ib7/euLmTz/
         z0F0aBzUJjJYAxFFb54aSJX9X4+I8aVrTRgIHX1zSjCXGjU2UYKFgL9OelQRDrkOIfNJ
         XhMwsS4+chQGqS+Rk5mYztBpUymBh8aBxTNdxlKb6BMJFSp1+5Aod+0SMv1ZWCScqFXm
         dnHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wt9hM5Kc;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694770365; x=1695375165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0wlmZUnHdQA6237rE+MIob63rYVACvkl2183Z1QteSA=;
        b=XJqLdoxM2n25Gp37/kjTlRZuZLp8rQ8mkRwAMHOkJz19/FqUyP1Bd4VZvJSpmrQITf
         ENDmh9JX7vvU3YkSjcuqZoMvse4SZp5gPIR3MD+yC/FK289q+3QuzEGJa4bdUq7r1T8s
         EojDWoJGDo/ltbh/Hkqq89HEIj8xHE+AdgBdJrerm3DLYkP7BK7BlMKtNaqe5d2l4OMh
         dxMMEG/WLjVHW23We8RBP3UdwaHKX2R5lPW6ZL3HexvlbPGF/7J2iOlLzv9SjU0k4t7y
         jFQLn2KS+4AdpQ5gZaMKTsHH9LX7fKF1oZJp1UHo9eeFjj6YN10kY85h1XZvClpSO2ZJ
         vXtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694770365; x=1695375165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0wlmZUnHdQA6237rE+MIob63rYVACvkl2183Z1QteSA=;
        b=hw9Onzw6ZeEyvsTf4NxSGdZHzEXlm594BPnT3RCth3MhxnYl08EYc511yC1V1fZ+y2
         qtqSc8mOAYojouDB3ntEEdsTTmVKqCj26jtG/SPf51WEM3Iw2BVCxAEfwwhIFbDDdxOs
         diTz1kpMyg602tzsCH8J6nqcPTZiS+fWXgwpEo2B4zZghSDnPRfRjtIQ5vRputSYT+t9
         vrlumuJu13qn/q5VzK3g+5J3SBPdyPFoEBg4zzhyCt4AOdWtdBD1wWmYGaM+44BJ56wU
         CpyVo+U/ZdQBkQ8qRQH+qadn8IuYSpnQm74ou0uMlCzBbNedKFp4QhYgJ0sImkVzO1mf
         FTlw==
X-Gm-Message-State: AOJu0YyMIRj629TFdWX/Ty2+c4MCAbFNFUxPWyQ0WpzCM3HfgHyjEPll
	3mLIOpfZuK4jjwJkY7MJ7HE=
X-Google-Smtp-Source: AGHT+IGQCbcgqbF3F/d31MAd7RbaG1aEdLG+xx//WduBe69NZR1G2HhFGPuOTH9j1Vbzwyg4m6ch0Q==
X-Received: by 2002:a7b:cb88:0:b0:3fb:e2af:49f6 with SMTP id m8-20020a7bcb88000000b003fbe2af49f6mr923056wmi.39.1694770364200;
        Fri, 15 Sep 2023 02:32:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c11:b0:403:419:ad1b with SMTP id
 j17-20020a05600c1c1100b004030419ad1bls117249wms.1.-pod-prod-05-eu; Fri, 15
 Sep 2023 02:32:42 -0700 (PDT)
X-Received: by 2002:a05:600c:c5:b0:3fe:d852:7ff9 with SMTP id u5-20020a05600c00c500b003fed8527ff9mr1016669wmm.5.1694770361917;
        Fri, 15 Sep 2023 02:32:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694770361; cv=none;
        d=google.com; s=arc-20160816;
        b=ihGnIpCwGik1pfcj/JAF6xI03+dPgQoe3Z85m07VadqSkgyw3Sd3MxmTyUQU546vtf
         tYd5P8VogEEeMUGeXauB7KaxFfzR8xypmXs4rz36fpxEzimL1DNJGELXcoIX9ZX8pqXI
         xtgGZtVbX40/Uqa5Ni6h2SEQunPNtmBlD58W6U+HYVP7A7JYGGeb0buUwWxxXCAFiLYS
         hPolE5DlsLcvYz9vtEfeFnSzb2rZtJozXWURyP74clXNgXxFHfj7j48Ak8UyYdcnCd/o
         9ztKMeT5dZ6FjuKUs42hr+i7/UGqWvINab5MeJsq3HbviStOUGI2+LHMfZmPtMMN2e6A
         riJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=HETKbupRhTYs1z9MLvczngFisFfV/0QzW50/Eiut1z4=;
        fh=aynDOFLzDB2kr2qBsfK7us7ujPaK2T87eZYLEnGhBb8=;
        b=p4T1QbhGz7ubm4nrhIHw9+j3HSusgS0PYar9FFAZMcml967+MhE/4JIg+0JvLDF0bc
         E/KJNcft08wfKP1t2bxse3MJEphGld0bZMTxaMPR2+XX7l8GLMacWYUbiZ7UQMgAAte1
         kKkWMxZRsKfk7R6Y4FP1jxSfkwonzdGGgFDQFbQQxwbi5xDmfdcS2VQEXx85OHQKZRAz
         jq/rfNDOdq14MB+lSIXv/ikHxGCmyrLIQCpyfh3AMbEChRRnbqjL5sBBshwhRcUznv3e
         VAe/kkATdMYIRJP5vHyOlV1o+1EBWPr2U2ZUZQnEqrtfHd0mZQjP7h1hOC/yrvU4eixW
         Rh9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wt9hM5Kc;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id a20-20020a05600c349400b003fe16346f71si682308wmq.1.2023.09.15.02.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 02:32:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-401da71b85eso20817475e9.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 02:32:41 -0700 (PDT)
X-Received: by 2002:adf:f7c4:0:b0:31f:ea18:6f6b with SMTP id a4-20020adff7c4000000b0031fea186f6bmr1120906wrq.19.1694770361264;
        Fri, 15 Sep 2023 02:32:41 -0700 (PDT)
Received: from gmail.com (1F2EF265.nat.pool.telekom.hu. [31.46.242.101])
        by smtp.gmail.com with ESMTPSA id c18-20020a5d4cd2000000b0031762e89f94sm3902903wrt.117.2023.09.15.02.32.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Sep 2023 02:32:40 -0700 (PDT)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Fri, 15 Sep 2023 11:32:38 +0200
From: Ingo Molnar <mingo@kernel.org>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-um@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel@axis.com
Subject: Re: [PATCH v2] x86: Fix build of UML with KASAN
Message-ID: <ZQQkthfNuV3dOhZe@gmail.com>
References: <20230915-uml-kasan-v2-1-ef3f3ff4f144@axis.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230915-uml-kasan-v2-1-ef3f3ff4f144@axis.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Wt9hM5Kc;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Vincent Whitchurch <vincent.whitchurch@axis.com> wrote:

> Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
> x86: Disallow overriding mem*() functions") with the following errors:
> 
>  $ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y
>  ...
>  ld: mm/kasan/shadow.o: in function `memset':
>  shadow.c:(.text+0x40): multiple definition of `memset';
>  arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memmove':
>  shadow.c:(.text+0x90): multiple definition of `memmove';
>  arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memcpy':
>  shadow.c:(.text+0x110): multiple definition of `memcpy';
>  arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here

So the breakage was ~9 months ago, and apparently nobody build-tested UML?

Does UML boot with the fix?

> UML does not use GENERIC_ENTRY and is still supposed to be allowed to
> override the mem*() functions, so use weak aliases in that case.
> 
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> ---
> Changes in v2:
> - Use CONFIG_UML instead of CONFIG_GENERIC_ENTRY.
> - Link to v1: https://lore.kernel.org/r/20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com
> ---
>  arch/x86/lib/memcpy_64.S  | 4 ++++
>  arch/x86/lib/memmove_64.S | 4 ++++
>  arch/x86/lib/memset_64.S  | 4 ++++
>  3 files changed, 12 insertions(+)
> 
> diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
> index 8f95fb267caa..47b004851cf3 100644
> --- a/arch/x86/lib/memcpy_64.S
> +++ b/arch/x86/lib/memcpy_64.S
> @@ -40,7 +40,11 @@ SYM_TYPED_FUNC_START(__memcpy)
>  SYM_FUNC_END(__memcpy)
>  EXPORT_SYMBOL(__memcpy)
>  
> +#ifdef CONFIG_UML
> +SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
> +#else
>  SYM_FUNC_ALIAS(memcpy, __memcpy)
> +#endif
>  EXPORT_SYMBOL(memcpy)

Meh, the extra 3 #ifdefs are rather ugly and don't really express UML's 
expectations here.

So how about introducing a SYM_FUNC_ALIAS_MEMFUNC() variant on x86 in a 
suitable header, which maps to the right thing, with a comment added that 
explains that this is for UML's mem*() functions?

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZQQkthfNuV3dOhZe%40gmail.com.
