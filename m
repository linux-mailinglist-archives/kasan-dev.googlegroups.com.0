Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW5ZZ2QAMGQEUPWD5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 975656BDBF1
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 23:49:01 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id i7-20020a056e021b0700b0031dc4cdc47csf1570339ilv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 15:49:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679006940; cv=pass;
        d=google.com; s=arc-20160816;
        b=LEy6jF9B2kapACxFOjQf/uRavFd3qMg+ar/zL/rrRMkVfVIrd0nHVBhGRu1Hs/xAdI
         u8dvirExu+Zrw2sUcz1q6UXKqGczvK1R7BAQlsMwzb5uy8Qz4Bq/hDuwt0WM/38NmmE7
         N8PAgvl8oyR25fhhH0A73ngJdBc+cHrh9YHDOzZxOWlfnMNEjKVNjwNDGqkDpAj/Gdtj
         T3SpX3q/J9Gd1Pmc2zkAr2l2UaTKSHWxq7lyXLhlRcHNKiGl9H99MvMMYISLljUer52w
         LBhbFxpfKL48kH4nI/DXvIGp04vtT3qq6kFIYGiAl2pGih/lVF7ruMv6MnB0a+sbQwtF
         zaLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fjsjd8HY09zlgeYJEk3U71OUZ43Kud0fySKWRpNkvP0=;
        b=b8nGAMJRQ5UAWAKZMrMEqn8KAGo6EdeczDVnGUzUkk8DMrcO7rSVj1BrktTweWQWnL
         WZoTpjC/g/BZIcjGgHR5fPGLiUY4SYPnlmvbANaVreUpr87fQjDjCM0DhGrAVoqEgUOl
         cQi8SjZjITp274AjuOZrP5xdwwSXSVq+P32g0ds+J1BmTx2cZHVQ070YT0rUir+8EPZM
         TXVPFvzKg4xzNlIRjzDfrsaLjxkgVMGnqJMYbQspfc1affmUxRv3GwfTET2hRxIXfOMJ
         yWZheKI5Zyk0FwbFBJPFhxQzIlTVl4Ibzi8RhE6+XvvBScuTAji3d0fRsxs0L1ZpLED2
         1QDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ADu4GbHa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679006940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fjsjd8HY09zlgeYJEk3U71OUZ43Kud0fySKWRpNkvP0=;
        b=DjUSVF2wc5+0yeDLgCMr5vZ7FS7YWAUWgadxKCUee99HlAM/9QzzDkr8xWFIhsAGMa
         XxYFzGpRVbI1DfHxeLUTpJs16MazyD+8P+6DDlt7LyfRWdbS9r/O4rGQCnpC87e5u/gJ
         4kgLnXQgWSEjzQqvfNxHpKzmc2CxlJ0D1iSi93XJvCtfB9rrfQddfiYuE3dgfTOYOSmm
         fukpxRCpyGA+u6iAWJlZSL8RQk/1Qxi6S68bSlPobpT5qeqo1Y2LbZz8346ElxbKbMNo
         Xm9CQTIR5CWgD+szRYtWR9VwOcYu4otP5+gDkAj1Fm3z1BuPSaCQYgnfZFN43LXBj1Yz
         bVjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679006940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Fjsjd8HY09zlgeYJEk3U71OUZ43Kud0fySKWRpNkvP0=;
        b=rKIdZO7KxuWS/VaNEYttCf8FuaHa2PUwgfr9x7XRbISQglQg3HWeuT5DpvAJaOMQEr
         JXsuFjItx6nnHPVHl9tw9r4MvwJlrk6gIRVyrK0FMRB373j9jsF4/H5C8Oin680Gxwal
         BsejUE17rpOqTxtMGFsPNL1k7FdF5FNHoMa9ikejnK310GMWsJcIpKoJgQ9VZRuU5VA8
         bhfgN9ajww5uvAQ73prD+Al3LZ/mRBCLZAhUjeVoesop+S/6s1U7SToQOGuwN+On7Pni
         tVynx4wafJmT4W593xx6AjIutbZ+L4VipzCuWOxQ6Y8Wx7TH02WhN6rj45Gex5HbVjyY
         9JtQ==
X-Gm-Message-State: AO0yUKV+H86AAT6yvDslO0P00I5OQmh8vtPNjMymKiD8WOsilj9c3vit
	kaixk32UTY9mTmt4heY0NWo=
X-Google-Smtp-Source: AK7set/bZ9IHV6RVQNRenLJhOLw3i6CrTYlbrBzx0zF4Nu83GxKO6ig8rK+tln+EnE+r7cJDTY7ieA==
X-Received: by 2002:a02:93c3:0:b0:3f6:e3c2:d4be with SMTP id z61-20020a0293c3000000b003f6e3c2d4bemr397059jah.0.1679006940020;
        Thu, 16 Mar 2023 15:49:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:19cb:b0:316:e54a:82ff with SMTP id
 r11-20020a056e0219cb00b00316e54a82ffls793526ill.10.-pod-prod-gmail; Thu, 16
 Mar 2023 15:48:59 -0700 (PDT)
X-Received: by 2002:a92:c08a:0:b0:323:682:9b8e with SMTP id h10-20020a92c08a000000b0032306829b8emr8559972ile.13.1679006939474;
        Thu, 16 Mar 2023 15:48:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679006939; cv=none;
        d=google.com; s=arc-20160816;
        b=lF3WfENre65owsytNIiyRej+M//nSQTZgNFpHmdVmGYytVnehSis7BmHqx4xRj6o9R
         AYc9rj+FUIRSIm05yutfir2TfWpof6hgJPnhKcBDDCMlJjrV2XkvwrSxMGjsGvGOXm4x
         xePjVfscCxepVwFV69xXEspCjXaazXly2C0QbDoLFhrK79ZqB8X5T6SCjevUCKlGMLXv
         jatQ9BuyPO5BoLQb6o2zFiOWIubWrsKVFOWn9MLAfJfSzmgD0mJhAXgOCT6MaCSvmPCJ
         mzDZRRCxQXcv8k0vpeU4vVAFgED/Aw5vYU3Cr5EJqntk3BU5I3zZi5b975zAXCUBH36b
         xD1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gxr240v7gPTttE+NPLSA84Q9E6emq53Syi5SVB2+hgU=;
        b=pcK41cP2fGt7UNViadET2Bt9TUl0RFjVcSUEo7mGLLDisqxnXp6xaqAR+P8zbpTk2V
         dHu3TWD6MhyCJVPk9+eiqnasm+RZ0Wr/07gupZ3y6ONNKGIF7nhV+oqNa7oj3uN0gIua
         UiXt4pqb4Z/DMB19fH0hX42VBIYD3LybYjaZB5vUhrxWTaiEcfLHPYepnT/dZpYcvP7F
         5cmMceBFQYkgMwxnccLsRfaUpD5chXDCVZPOqTaMjdzco2becx0fHdx70xz7pUGgF82y
         9rTVHMJJFGjVcC9LQ71nvsryDLrzMAAbcfx4Rm99ckPIoyQoOzUyumRzpG3Y4HNouNru
         r9SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ADu4GbHa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id s19-20020a056638259300b0040619abb9aasi73887jat.4.2023.03.16.15.48.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 15:48:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id m22so1515635ioy.4
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 15:48:59 -0700 (PDT)
X-Received: by 2002:a05:6602:228d:b0:74c:8c3c:b71 with SMTP id
 d13-20020a056602228d00b0074c8c3c0b71mr533639iod.12.1679006939131; Thu, 16 Mar
 2023 15:48:59 -0700 (PDT)
MIME-Version: 1.0
References: <20230316155104.594662-1-elver@google.com> <20230316153354.bc31b9583eae6a79a1789de0@linux-foundation.org>
In-Reply-To: <20230316153354.bc31b9583eae6a79a1789de0@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Mar 2023 23:48:15 +0100
Message-ID: <CANpmjNNqmRa3qYPoWcfe=FQXtJvLU5xN05hnZTjo4-cG9B984A@mail.gmail.com>
Subject: Re: [PATCH] kfence, kcsan: avoid passing -g for tests
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Nathan Chancellor <nathan@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ADu4GbHa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2b as
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

On Thu, 16 Mar 2023 at 23:33, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 16 Mar 2023 16:51:04 +0100 Marco Elver <elver@google.com> wrote:
>
> > Nathan reported that when building with GNU as and a version of clang
> > that defaults to DWARF5:
> >
> >   $ make -skj"$(nproc)" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
> >                       LLVM=1 LLVM_IAS=0 O=build \
> >                       mrproper allmodconfig mm/kfence/kfence_test.o
> >   /tmp/kfence_test-08a0a0.s: Assembler messages:
> >   /tmp/kfence_test-08a0a0.s:14627: Error: non-constant .uleb128 is not supported
> >   /tmp/kfence_test-08a0a0.s:14628: Error: non-constant .uleb128 is not supported
> >   /tmp/kfence_test-08a0a0.s:14632: Error: non-constant .uleb128 is not supported
> >   /tmp/kfence_test-08a0a0.s:14633: Error: non-constant .uleb128 is not supported
> >   /tmp/kfence_test-08a0a0.s:14639: Error: non-constant .uleb128 is not supported
> >   ...
> >
> > This is because `-g` defaults to the compiler debug info default. If the
> > assembler does not support some of the directives used, the above errors
> > occur. To fix, remove the explicit passing of `-g`.
> >
> > All these tests want is that stack traces print valid function names,
> > and debug info is not required for that. I currently cannot recall why I
> > added the explicit `-g`.
>
> Does this need to be backported into earlier kernels?
>
> If so, we'd need to do it as two patches, each with the relevant
> Fixes:, which appear to be a146fed56f8 and bc8fbc5f30.

Good point - sent
https://lkml.kernel.org/r/20230316224705.709984-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqmRa3qYPoWcfe%3DFQXtJvLU5xN05hnZTjo4-cG9B984A%40mail.gmail.com.
