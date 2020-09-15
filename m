Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWMGQT5QKGQEUOKMBGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C897F26AB88
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 20:09:30 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id q5sf2322932pfl.16
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 11:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600193369; cv=pass;
        d=google.com; s=arc-20160816;
        b=iJ3NIVUP0CQmmqMu42udEXJpR+QBD4N7FcmXn8OwL15nSheQb0Xn4J3qbe8SCoT/4M
         lmP+oMiSQArZ5htY569i6LR1Azr0rQZgOV91X8Yz2gfILt9rA04BA/NfeaODyeHkfmTm
         OrjcWjXeEwXEmdqX4e58AxLHPHVLE6re97IS1f/Mmy18GpJkaF6a9Ha5kuN7+Jmw+b4U
         1JsPfCgnUKeGYQt2UPMDVZycfCy3VvOsR/CrHSoCkExu7e86kNL8oy+dPG1/zRISLUgo
         YKGiDngrWRLFxAHKSINEWAY56RkrePYyPimxkI3NJTNRP2gs/ToRFjEqq3sR5z4rmwZn
         7bLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cFqFdkQ5ODnTQ5ASmMbF1co/vhgd3SImpyppNUpRYJc=;
        b=CvLunLIqLWzyu60dkNXRiS7YUD0mNMjz+DfpgDa1MzFmRPJkhHckz9IcouaNrPE+6c
         LpJ6GTs7p8kYUhv05ggiDBXYPA8DMrYQxWVJuu04TJstoJq23NEp+IlYL+K4/HTuPJTQ
         Ls0JWMqXZRmdWz86xPzPIILmASnf+2oOob8zQCjFiK5Er01WHI9OPljvG6pXqNYFIQwl
         oE83u9GxmS5XCgqz08fiE3VGmxOs5AmdC0J47MYXZ6Qd00UJbNDIDnh+6mGKT/XnZpOY
         6WqM7EoaKw9KBnVevxas2DmocVJ0ZMU1XtAyVnY0NZH2Kf4msatA53g2s+aW+9LfjyIu
         UJ4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YL4lnyzm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cFqFdkQ5ODnTQ5ASmMbF1co/vhgd3SImpyppNUpRYJc=;
        b=kQ12j0vRI3TgTnumd2+yaoG90TrtMWQehYmPtsl9yrdaFAsVpOqL6/wrntj8eiGmbM
         saQvIYcL/e/VxnoJxdCZLOBfbiZsWaryso9XiAODuBIoIyT5fLSBEUchIffUbsRfs9PQ
         mUzuzfW2cnmQy8rOM2l02TnDgfgnJPzzzpcpV2tHB+DTv9xCK4CedB18T0upv+PulOGt
         BRLCdb5z+OUUQgczWRACU4YUWUK62E9S176I7V6KrLODtGLMlnOO8n6kBEcJnVROR6y8
         yesTVhjwOi1AD7/JOJiDdWkdadwRjR+/mPJP9U9o66TMaJcYZWI6t9KVKKJNd9M1YHBt
         18Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cFqFdkQ5ODnTQ5ASmMbF1co/vhgd3SImpyppNUpRYJc=;
        b=emE24up0W7nu2eVeO+tIoBTNx8+P2fje+WQWPFTXMddi9dYXgj9Jl/ceLnXfLr5B0R
         XdEg1n20IGs93q3vJFkulmQi/dZjgx0pEpiKyWWJ1SZEGxPjlhbDHDNNuadp0WuUoCuS
         NTakXWSSQTqznQMnegNmPhoNiG+/8IyKocauOvCewuueGjieO9Yel+w+dvGtrFXZoPBT
         FfpZZ4xcN3faWAXbuiEGVr9id7CeMUU4B31n1SoOroM29il8nbmLJGgJyRMbEV2WJ/iR
         eT9kOXEL1h8ACaCUaE00RtMTf3ePpbzfb10RzXkhmWw02AN9bcQ+BF/HIQYhuNbRfM5F
         fkNQ==
X-Gm-Message-State: AOAM531VzHe226LylmNMTCSfB+GWnmc2w4P3pNCGoxin1+QiQKxJUoMi
	mauP0+j1nwl5qRrhM8k5eSg=
X-Google-Smtp-Source: ABdhPJx38dgjLSeRXpLCmEeE1/mEAIvZKJPOAX47f1pp3rtJpDu3w9JXXMotxp+65njv6Dc7SCD21A==
X-Received: by 2002:a17:90b:4018:: with SMTP id ie24mr555676pjb.9.1600193369445;
        Tue, 15 Sep 2020 11:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:480c:: with SMTP id a12ls171609pjh.3.gmail; Tue, 15
 Sep 2020 11:09:28 -0700 (PDT)
X-Received: by 2002:a17:902:c212:b029:d1:e629:92f4 with SMTP id 18-20020a170902c212b02900d1e62992f4mr2497738pll.75.1600193368849;
        Tue, 15 Sep 2020 11:09:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600193368; cv=none;
        d=google.com; s=arc-20160816;
        b=whEc/okloKTHev4/gwM8gEO1eKFAxssHc7C6MFz3uteQ1LyVeCTJo/xMgyyXVdfHh2
         T+et0Yz34PPIfQxelvugywxUV5yHq892XIynI85kll+CSC/so5QxzDDdMQ7eLhbtp3qG
         QebZ3SSgWxVF0MPm2V7KFuCzdwDTlN82lyWWRA2Ihsnz+eubKtucjW428TULOtCVj5B7
         WbwgaubQMxh9tEzse71jE7F41l1Xts/NYTNyj9JFVBIVuwxN2JDnZojkUNO/M2nHCIUm
         J7QGaum9orJdGXMJRTvrYpvnxRV9MEHNl11mZVviR+gD5PirDJhT/QdKKaDY5nWwMQK/
         uC9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aWsKZVXnxNV86nxwMhidD6aX4g78p96DDVvRBJQ0WvQ=;
        b=JsrmE3vvoHEe/7ep0gqVcj6zRafYgrB8tLiBOu7QNsDgEIqo+8LlgOj2GT9SA2Hjxh
         OsRQaZga74j9LM1K+S/Z1KlgOR4rF4Oe51FCGATcLHIhRuHco352vqnGU688sN5RDF1C
         T9r6zWXXdcLD1YG4iaiBzsvBp7+QNMuqayZhjcQtYlb+Ht9bgJuIqiMa7sW3T9ZmSI0+
         Jq7S4+T8+C8jlPVANy0DKx4YnGiY+ZHvwXeRyRl/OP572UHlmhR4lGNITtbbWpPp31gJ
         pbd7keRDUmgfWNxIp1I7Pn5dU+WPpXEtEX4XiS2CPIjR/XcSusXnCQR5DiCmvpf3yhal
         krsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YL4lnyzm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v62si850904pgv.0.2020.09.15.11.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 11:09:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id y5so4144252otg.5
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 11:09:28 -0700 (PDT)
X-Received: by 2002:a9d:758b:: with SMTP id s11mr13003629otk.251.1600193367937;
 Tue, 15 Sep 2020 11:09:27 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <20200915172152.GR14436@zn.tnic> <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
In-Reply-To: <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Sep 2020 20:09:16 +0200
Message-ID: <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>, Nick Desaulniers <ndesaulniers@google.com>, 
	Rong Chen <rong.a.chen@intel.com>, kernel test robot <lkp@intel.com>, 
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YL4lnyzm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Tue, 15 Sep 2020 at 19:40, Nick Desaulniers <ndesaulniers@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 10:21 AM Borislav Petkov <bp@alien8.de> wrote:
> >
> > On Tue, Sep 15, 2020 at 12:02:48PM -0500, Josh Poimboeuf wrote:
> > > If somebody can share the .o file, I can take a look.
> >
> > If only I could reproduce...
> >
> > So I built:
> >
> > /home/share/src/llvm/tc-build/install/bin/clang-12 --version
> > ClangBuiltLinux clang version 12.0.0 (https://github.com/llvm/llvm-project 74a9c6d7e1c49cd0e3a8e8072b8aa03f7a84caff)
> > Target: x86_64-unknown-linux-gnu
> > Thread model: posix
> > InstalledDir: /home/share/src/llvm/tc-build/install/bin
> >
> > and I don't trigger that warning even with that compiler.
> >
> > What I do get is a lot of those pairs:
> >
> > init/calibrate.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > init/calibrate.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > init/version.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > init/version.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > certs/system_keyring.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > certs/system_keyring.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup

This one also appears with Clang 11. This is new I think because we
started emitting ASAN ctors for globals redzone initialization.

I think we really do not care about precise stack frames in these
compiler-generated functions. So, would it be reasonable to make
objtool ignore all *san.module_ctor and *san.module_dtor functions (we
have them for ASAN, TSAN, MSAN)?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA%40mail.gmail.com.
