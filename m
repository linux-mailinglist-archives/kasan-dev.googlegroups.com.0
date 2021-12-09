Return-Path: <kasan-dev+bncBCF5XGNWYQBRBL6XZGGQMGQENKAMYAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3488146F53C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 21:48:49 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id e14-20020a0562140d8e00b003bace92a1fesf11242610qve.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 12:48:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639082928; cv=pass;
        d=google.com; s=arc-20160816;
        b=bV+mv+FOtsB0nXfXZ8BXAU9MaCfsx5CL83yJB92BNnmpjfof4GR95TaBxwijzrICqB
         29lDORQi/2i9mLWNrx/0RMEmFboMzAw11CBrFDmnvtF7jV0NRCuCbG25TIpIj2IpC9JJ
         FrTE9ObnjZjh0hBXUCUUEzQrzBgE2tahaHhXQBK45/a9aYRIfehy7VLeydc+jx1NxeBr
         umH2hD2p/jdiUIp9Z5QBGMlRJc6f6p2OCyu0Nk1V5M09WVMJgPkNySnDFaMdjcMqDFFX
         CFV1kUgD6fHts3GoPxgSTaVaAqMY+3fgbre0z482lgS20v4Z24WGnrSLJk4/hDvhsJtE
         Me7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z55UX7uQ5Dqyj6x8BOj+vhmpdU4rjem7L0AE0TEyS6g=;
        b=OMDhC7GEWIiKGoOsl4OnilrOl0e+KSxiNdckV1tkSC8DR/voYHvo1ZKSVGple1UA2l
         SlFUwrTWGFliDK15HJeFgWy4Q91bYs1724JirD3KRkWaPMgk99jTfj2UV8XblVT20WJD
         zJD3LDEEjOwtAy9MzbhrOnvu3LDI+Sd/hYy+5Im7vLLjClhcubSp0ZYZh/VFV0an3hyD
         oe7TDayeJ3b5RaUEi0LJASs+7ql+QOEV2vlT8TLR0zyah81QMexrS1wa6xyzUDk4PlCG
         LOgFhA3zZEHuRYZZvFnYh7BS7XnyHpFYkNsr8+l37fDbjXduIk6a8NxIx1m5oSCbMq99
         jPLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BYG7unjb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z55UX7uQ5Dqyj6x8BOj+vhmpdU4rjem7L0AE0TEyS6g=;
        b=GIZltjjEHeQywOm+IFXfYC1XGVOd0btdFGzXleQyKsp81MvLXZK8AZsav0wLwlfRUz
         RgZviEOGA6ASmMVVCouAytJ1GXko5QQSwkpcW7ziv3YVPQapE/Wl5cXJKDH0p1S5CjDB
         0Wszqyc1rhcGw5NHhbXCqjaveM2zQf/eYHWUtVDitrIKPVBoxHeWQyhnT9bbHPA5WYGN
         yf2ojUZMtxDl8yzkwSvuHg+/ZYiOGiau/wTIYoV8IKyBoDHVI0LfLssMIh4JL0IJHy3U
         j+QcK4ORQvTcDtCsnfKJ/UvlN5o64oVPCZApL6MIwyk4wJCw7FkhKm3oskWj7S+zas46
         vn1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z55UX7uQ5Dqyj6x8BOj+vhmpdU4rjem7L0AE0TEyS6g=;
        b=rKEAe6jkaHd2Z6m7I+v5wgi+WWV9aQjrtBw0xxmQpCmCf/LIDoNzeORkKCLzxwRc63
         lm69EyV1RknCWPXpOjPnF1stoGdeT7Gqvj0/BnOlnyqdqD2La9kYB1BEAH/25Ilot61g
         LgNc6qOq3o0QUnid9mKCAjiF87Lyw3QNhm7tIUuwPQu/ZQ5XrF4X7jcy/+1NSshNMpE1
         4qMWP51NPNdHyScqXy3KXopQhoZgAHMbujsNZ7wPKAxX6U6UVAxIYwXU0MCc91ajy9Hc
         QlUTBNGShE6i7b9bZq5bJxnFFpMYQGsujaHkGMjk4aVFBSN7f7iyFPUTf+FxGXlNQJtT
         BhmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/v7bHEU6scznJtXjI2M1TnE87hL/ZY1ubX3rpECQM5VTErjk1
	aHEJ63dD4vlcel21VKQNBYk=
X-Google-Smtp-Source: ABdhPJxMqVwUdSbSNyi/Ere4VPJUNiH4HE6ExvoehMPTz5TN8bWjk4Po2+tciM1ajZR81TYznaIByg==
X-Received: by 2002:a05:6214:2341:: with SMTP id hu1mr20270926qvb.76.1639082927986;
        Thu, 09 Dec 2021 12:48:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:dc01:: with SMTP id s1ls3664214qvk.6.gmail; Thu, 09 Dec
 2021 12:48:47 -0800 (PST)
X-Received: by 2002:a05:6214:226d:: with SMTP id gs13mr19304425qvb.62.1639082927400;
        Thu, 09 Dec 2021 12:48:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639082927; cv=none;
        d=google.com; s=arc-20160816;
        b=PJ84Sn79nOSGwT0GPUDspQMRoghbDR3CZM31MjPoESH38zjPDNWkEJ9odawIxq9/tG
         bgefkC8U5sTBFmvDau/aEqMfzKpBvlTiEfdmEm4g4aL0ZI7UU2D+clkUm8T7NgW14o4F
         W/+GT4WNFNPXc0CHvbcAaRrQvrKriG9ivdXABAG1sb9AmwIwVbCchPrtSkOEkiSb7pvv
         89Bq3sDTBJMYbdya6VzPgJoH7L4ne2sEQFhzWimFMb/6+LHWX6FOE0coMSR+sZYpecCe
         ZAHKX1DyVWT2wf4WcDTUiyCVMrz7MgG9HNpl03VLDV2iHTUS9C5Opmuvkpc/74jrBL+I
         RvdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2E9kDLwwNQ0Gbn3Uwe88OJMa9WjF0vo6Kuu7UJb0mUg=;
        b=jUw4JrL/pBS3zjAExAgKrYM0L87gaS1qiundrc+fIirEx/Kzx+pknX7QIE04Jk8ofK
         E5NVTaZdw3QzFSLcc+KFVGulROYKGgkBSqbWWpC4m+HAPYP6E+fuDkuC2ehfrUgsaNOq
         0Sl9KPoa8SnrYAzF8cpMsM+67wYCuIrAVixkDTTRjK81RQkL8h+Y3/gUt5MJ9+NblL3c
         J26/499B+4KuQcedgRJlmiyWniSITj1zeYtVSldlpDJPkFVv48/ufDlvPeLFs5wKjogB
         VCL+yb1Jg+GfpdiyZHMxswI6kMawfPrfPAK4DHtfmfiTyczG+Fz9xe7Bw7cGK86qVXaN
         Kevg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BYG7unjb;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id f38si187297qtb.3.2021.12.09.12.48.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 12:48:47 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id y8so4816814plg.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 12:48:47 -0800 (PST)
X-Received: by 2002:a17:902:bd02:b0:142:728b:e475 with SMTP id p2-20020a170902bd0200b00142728be475mr58367811pls.15.1639082927017;
        Thu, 09 Dec 2021 12:48:47 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y12sm568512pfe.140.2021.12.09.12.48.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Dec 2021 12:48:46 -0800 (PST)
Date: Thu, 9 Dec 2021 12:48:45 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Alexander Potapenko <glider@google.com>,
	Jann Horn <jannh@google.com>, Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <202112091232.51D0DE5535@keescook>
References: <YbHTKUjEejZCLyhX@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbHTKUjEejZCLyhX@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BYG7unjb;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
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

On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> default since dcb7c0b9461c2, which is why this came on my radar. And
> Clang also performs auto-init of allocas when auto-init is on
> (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> allocas.
> 
> add_random_kstack_offset() uses __builtin_alloca() to add a stack
> offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> enabled, add_random_kstack_offset() will auto-init that unused portion
> of the stack used to add an offset.
> 
> There are several problems with this:
> 
> 	1. These offsets can be as large as 1023 bytes. Performing
> 	   memset() on them isn't exactly cheap, and this is done on
> 	   every syscall entry.
> 
> 	2. Architectures adding add_random_kstack_offset() to syscall
> 	   entry implemented in C require them to be 'noinstr' (e.g. see
> 	   x86 and s390). The potential problem here is that a call to
> 	   memset may occur, which is not noinstr.
> 
> A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> 
>  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> 
> Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.
> 
> To figure out what the right solution is, the first thing to figure out
> is, do we actually want that offset portion of the stack to be
> auto-init'd?
> 
> There are several options:
> 
> 	A. Make memset (and probably all other mem-transfer functions)
> 	   noinstr compatible, if that is even possible. This only solves
> 	   problem #2.

I'd agree: "A" isn't going to work well here.

> 
> 	B. A workaround could be using a VLA with
> 	   __attribute__((uninitialized)), but requires some restructuring
> 	   to make sure the VLA remains in scope and other trickery to
> 	   convince the compiler to not give up that stack space.

I was hoping the existing trickery would work for a VLA, but it seems
not. It'd be nice if it could work with a VLA, which could just gain the
attribute and we'd be done.

> 	C. Introduce a new __builtin_alloca_uninitialized().

Hrm, this means conditional logic between compilers, too. :(

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202112091232.51D0DE5535%40keescook.
