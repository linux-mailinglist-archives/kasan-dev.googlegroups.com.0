Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVNVUGDAMGQEMHBZBEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC0383A7837
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 09:46:30 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id jw3-20020a17090b4643b029016606f04954sf1786576pjb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 00:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623743189; cv=pass;
        d=google.com; s=arc-20160816;
        b=fj6SlW+xrQr+PGxlMUQ0ETKfdlC0I/pl8TCkmTp+Vam9vpkkHDaT37xiyQrkq4cAmj
         30vwpjZ8kOOGZaBggkt0owwGRvj9rUs2Td3DZskenM4Bam58+nJBjRS7I1eqWvUAX4j6
         nmoWwVJTNtCc1b6M7CmTEsMkN9RV0siOPGF4hxZOQzVHHwZjr/4SzGxN7r/GDSyV4/Bs
         JHelYK7+3KErrZ3lwmL7RB2Tk0WnUdg5XEgURucVAdyKLzNnx4yszWSGJXPTLB8cHZAY
         Xb78YIeT9bdIKQpcdlsL4gFrFCyRG5zIHC/aRY0c6BHNorjLbszu4CF1pVEcoz4H3blJ
         YS3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RLYhoC8xJ6EE8g26ACAcckui939WA70tHSXAHd/fsE8=;
        b=vNfKUUI71VLdi0Wn0wjiRF0NJEeDn2II+/b03rRmyr0c1bDSnLBg7xErbHCe0ZUq2o
         tfjt8NywANf6IKXLDBpEyKWJ4E3ehAbXhcdekDTC0j9Rx8eoQusSLs14D2y/2tM3mBse
         7yBPvjDCtAWbuvB9ffiYk9kn3GQgzJYOJLcpyn6/f66oBDyYcu3YoHfQ045VdMwQiKVI
         5KsSMtTKoD9vTnZXYP/aGnYpwL8l3ScMf5rDLzsiN6BVVMXuvZF1z7hoWnJjoAtbyxVv
         K+ax2sYQph9AEuYdmcH5NDSWFvOF03DDF4M+xuHUR210rEHBPHv9i/8i4wAfLNRnWam9
         NuDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ma5dk7dw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLYhoC8xJ6EE8g26ACAcckui939WA70tHSXAHd/fsE8=;
        b=DpnFknhmR3bYla/8OwYA10m4EkggKA4lIDTre9ZmOQnzK74U+JoxJync+sTCTII/E0
         BL2e7gjaNy2pqzxcDQGzQa1oQ12ZJbNyEVCc6V5VdEaCfrrh46Joeh8kiZXWIvm+G5cc
         iWteaQS5TZjb48apojHfsdMVnZ437h8KsZx/YCvsDVi5SpYbECLkgA1ZKIj3zHJKmoHX
         Mqs+L9n3PmBAUjqNrmfxIrNtJqg30UX/kB+IiuAb89iVJiF3lqADlGfIUL4tKup0H6Q7
         0EWP6ERVH7c2bfSALiXqF+9l/rHSosJraxWWK7Mfd2ZzeK85IK83wuczfEiB6WQopg7C
         iOPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLYhoC8xJ6EE8g26ACAcckui939WA70tHSXAHd/fsE8=;
        b=PieKWfQCCd+9Gmbw5cJE7H2TtmZnDQaRafzJWOTolTc7GR72+CztCKle8sI1lT8HgQ
         10j66cBKtXLaLUkP10E/CrPRW3n/aud9+SHR6qHnUC4UaO66nSBqVn3vP6I6jPVSQNKq
         MpKBCY0Wzr8fetPVKq5r2sOFZjmFaEyUo4ihoaWVRa4S1YmNm+pgJ2yYyZD4dbI2AqJ+
         G7qfjK1TDhU+OoVpTPXmG/hOtXHQja+tSQTIDGTTL3TIzx0wM/T5EG/+4OYmiMU2WP/p
         bJqw7eXxhY+ZiLDENq7CB3edgJ1mUMm7AgmPQITPHiQ3NlLohOhKAs1uE+lUk5w9FsE7
         O/qg==
X-Gm-Message-State: AOAM531wuuOecPN9ELtLjRTBa8+RPOQ40gTGEMbTtJtKGAUoS/JF83QT
	jb7XLWxm9SyJRoxPKPFMJ9c=
X-Google-Smtp-Source: ABdhPJyWQ+fNa1m1PeEj5mhfqREZX/t86tBLcAUuDUjUZ4k+gZFCFyWQiBZ5m3BUKBu/YrOoSV2rFg==
X-Received: by 2002:a17:90b:109:: with SMTP id p9mr3637858pjz.11.1623743189639;
        Tue, 15 Jun 2021 00:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd47:: with SMTP id a7ls9203851pgj.1.gmail; Tue, 15 Jun
 2021 00:46:29 -0700 (PDT)
X-Received: by 2002:a63:4465:: with SMTP id t37mr7130366pgk.342.1623743189041;
        Tue, 15 Jun 2021 00:46:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623743189; cv=none;
        d=google.com; s=arc-20160816;
        b=pIRD5bJfHSEKEJYkfi7WUySyG0O2XrL6yTSH8HpyAPN10TjLHAsjGTtm1b5HK92Y1b
         LL8PTCtHMCeQFmX57V4uDxrMzNcf8wBiEOILlOA/kkNhPE0KC4RivGyMpjciK7+ypy9D
         cGspGrrFkbTGTig+I68HId+fbGSxp3QyJk1fZ3kTHeA01GwGsVkBID8H2lSrgsvJSRRv
         NqrBc9UFnYRjL8pF23uByXfPQ7h4z4i5ladJYHBbbZ0pVc5G9wQBO9XpOOcBG0JinjRE
         cjbFHFXZCoKGmfwFmePgl9V+WxV148IpMWzb/fYKxNLFFJt5KgbXbbejmluWu3os4Pgb
         eWBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iSVyAacN7l8MRU6+yXnglhfZd0yPT6M71q0qhoSn658=;
        b=fFIoNiXa2s/TqOxgpcslScn/3FCsIvSfUtbZ5OXwAkLw6Jhvv1P9wOojRw453EcY1Z
         Iqm7Wa0ul1xYrdpX5XMsoBau8lvdquPCDUblIGXEi3CKk+HLF5bpyMi5bBybYkLLNSIJ
         5WnNAi7cXexPsn1YpLebkCO03m7E5Ru8T/MZA33pD/EDTVhlxYjCRe1mT3eVRVdbVwye
         ZIoLRiy38sF7u/xV5gVKMTj9QtK6g11iIgImcu5v9QayKuLT0uIgBkmEbGptONz+u2TE
         ix52t6T8P1gkCeim/qS9+3QAY8Pi84iTNMxuHqCi9H+jQK0aURnG++ZDpFtaILZDDJxu
         o16w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ma5dk7dw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id o20si206460pgv.1.2021.06.15.00.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 00:46:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id h24-20020a9d64180000b029036edcf8f9a6so13435147otl.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 00:46:29 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr16704693oto.17.1623743188202;
 Tue, 15 Jun 2021 00:46:28 -0700 (PDT)
MIME-Version: 1.0
References: <20210615014705.2234866-1-dja@axtens.net> <20210615014705.2234866-2-dja@axtens.net>
In-Reply-To: <20210615014705.2234866-2-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Jun 2021 09:46:16 +0200
Message-ID: <CANpmjNOa-a=M-EgdkneiWDD0eCF-DELjMFxAeJzGQz6AgCdNWg@mail.gmail.com>
Subject: Re: [PATCH v12 1/6] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ma5dk7dw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Tue, 15 Jun 2021 at 03:47, Daniel Axtens <dja@axtens.net> wrote:
>
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.
>
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  lib/Kconfig.kasan | 14 ++++++++++++++
>  1 file changed, 14 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..935814f332a7 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
> +# Sometimes an architecture might not be able to support inline instrumentation
> +# but might be able to support outline instrumentation. This option allows an
> +# arch to prevent inline and stack instrumentation from being enabled.

This comment could be moved into 'help' of this new config option.

> +# ppc64 turns on virtual memory late in boot, after calling into generic code
> +# like the device-tree parser, so it uses this in conjuntion with a hook in
> +# outline mode to avoid invalid access early in boot.

I think the ppc64-related comment isn't necessary and can be moved to
arch/ppc64 somewhere, if there isn't one already.

> +config ARCH_DISABLE_KASAN_INLINE
> +       bool
> +
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=kernel-address)
>
> @@ -130,6 +139,7 @@ config KASAN_OUTLINE
>
>  config KASAN_INLINE
>         bool "Inline instrumentation"
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         help
>           Compiler directly inserts code checking shadow memory before
>           memory accesses. This is faster than outline (in some workloads
> @@ -141,6 +151,7 @@ endchoice
>  config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
> @@ -154,6 +165,9 @@ config KASAN_STACK
>           but clang users can still enable it for builds without
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
> +         If the architecture disables inline instrumentation, this is
> +         also disabled as it adds inline-style instrumentation that
> +         is run unconditionally.
>
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> --
> 2.27.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-2-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOa-a%3DM-EgdkneiWDD0eCF-DELjMFxAeJzGQz6AgCdNWg%40mail.gmail.com.
