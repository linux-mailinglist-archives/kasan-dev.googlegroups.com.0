Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXES7KQQMGQEQGQ22IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1486D6E60E6
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 14:13:18 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7606df33b58sf215634039f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 05:13:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681819996; cv=pass;
        d=google.com; s=arc-20160816;
        b=hrDWSIvm+by8fwH3wahaxnW0roM0Vhw4bFkv/0dA7pjF5aNEluAYO3Rul9X1IzjtPt
         klnESeRdB+3nCEKVc+nUl7rDxI04sWnS6Byr58kYjZt45ZpMWir8CIqjz82GSo4Gi6o5
         JOgJaNWtQmxnhjY6Fz0KBkUC15gdk+ysOubYN15/IhSJUa2PM7gAk45peIL1zmysKGaY
         wnm/Dc8bsXKduSDTSUKKUU+TREmc5Tg7jR0DLSEQ3TSMvFZoO7C+lkBmu/wOZJyvG3we
         C3Bo3Ie9cRKvr86jq+Af33usEMlD6We8mPvZ91C2BrgWhGKt+XsFU9TZuoFcMfEI/H5g
         9IOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FUTSQ0rK9pPWm93xJJTI51fEquZLac78hVY+zqZGbOI=;
        b=gPV5qU3vDFtRj32jKQ7WBKWg78w1+E738Dwy9mRu9CDX4uXVLk9RiNzn0INmJjGIM+
         DahZDtFnLDRgJrg5qpGPxg0wLgPrzJbvpEdZm1jDQokHmPJr2ImGM8FY3t5iSazlbiEk
         GZ2nxndAhe1g38y/NaYFd5TRlxO+3sKN+BuTs5bDEFyuuumAp2q+dSCQM/CdOaELefHh
         csGMG/3POfM6W4iGSj+3QdXeOcxRCCCKhuBW38upoIC+q4SjwE2f5xJUG85wqBIVywn/
         AOOwW8ZK3ba9pokKS2ad4FeNMIMDc6yuvIFg60R5XmERO+7Gn6rSKzKzSY7gZogcEMkN
         fWCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Jyi6R/m8";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681819996; x=1684411996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FUTSQ0rK9pPWm93xJJTI51fEquZLac78hVY+zqZGbOI=;
        b=JxS356Hq5Qt5jG/jAwUHbu24kpCZVZKjd0R4YqexmpHJyIjNK9RDeWAFuWf3RwlL2Q
         sJ0TzW02gmidFEmTNRJ88BbU1UiTo68A0VkL8DnG1y4N+WxniIW3At2JtbdY/LKaWCtm
         Q3uvg3qS8A75AXR31iNXIXPOwzKDLjzmgbdAbWssyPtznpnk3Vr2Uf0NnxgUnXbpgLAf
         jXNi9Thxqkdt8ogc0GcFrjfeYImtPimz8drRwp2MldjhMc9U6dVvTZ4zFoQbJ8PSq0yd
         hYVDswOX3bbwtRf4P7axxUf2CzcGMpIXONRjzGrpVvcbS7yGX/KJadEYm+hILLDjDk0/
         EURQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681819996; x=1684411996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FUTSQ0rK9pPWm93xJJTI51fEquZLac78hVY+zqZGbOI=;
        b=MNyJb43amoPsZM0XBCdGdfyb0FGz/cqFtni1UI4a1beisQNMBdOiqEU2MNDCcmFR6D
         srV5SVbFTeVfrGi+4I94YkQFPxSkhUC1UjtCOjAl6eTUsNVMvV4NCamJzrk5UfgGsdfR
         MdkUS1wUwxEZPTFflcHjOlqtU0rdTcs89FN7GjjfiT0fATH5C9OOR1TfG/QYazCxO1L0
         fD0aTOC3UdGNZEvERkYyET2xboiSSrYi1ug2adAJzv+CFluFWE+uGpGskTsLwliV17hK
         0WQJ7nU2jQ7gqKefw/9SDj1ay7BMpWKP+Rc0XIPDTZQaxj0ZKgUhC6+T5/ju60aIK6Zm
         fcOQ==
X-Gm-Message-State: AAQBX9dm65c3bGpMb1B11Qzv+dFxRshIna/ZHL2BFdVOqDeovv1Gg0cW
	OkoZAnANlpP8+2nUQZDXkiY=
X-Google-Smtp-Source: AKy350YFGAoj3i8Kb3QCdYuUAxdvhR/BB1oIwduA+XItIgkSy9pOmTauhhmD4WlLci3FTWrHZrXDWA==
X-Received: by 2002:a02:8643:0:b0:40f:b259:434f with SMTP id e61-20020a028643000000b0040fb259434fmr1341333jai.4.1681819996712;
        Tue, 18 Apr 2023 05:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:3799:b0:762:bc18:99b with SMTP id
 be25-20020a056602379900b00762bc18099bls941159iob.8.-pod-prod-gmail; Tue, 18
 Apr 2023 05:13:16 -0700 (PDT)
X-Received: by 2002:a6b:7307:0:b0:760:eaf6:59c6 with SMTP id e7-20020a6b7307000000b00760eaf659c6mr1825855ioh.11.1681819996124;
        Tue, 18 Apr 2023 05:13:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681819996; cv=none;
        d=google.com; s=arc-20160816;
        b=fcvZVAqzNsKV3CBjEhxF2z48yJOt419BM4kmGDznwagzpNcvz4+nBelO2+5H86+0C4
         zIE3SAuXon+7KVhyCG5wfBpNemld9akQ7libCHo8S8S2BCNBe5DktbOP9sqybwOnADC1
         RUtqo1DKR25/+T4f8a2Qpwh48uLO2OJpTrb5bvjlDIsQn3AF+2oZY1YefN/yMd52YE2g
         dhuroomtprd3U6maUUBl/1GxsEPg91vDndfL6Hrs8htfNKdhEFa3uYUvV/0TfBFQvJj6
         OWb/YhgZUBOWyMcL20qIC+ujnPfhLr1OHBwG4+Qs+9Q/WPnMnCyUpTJnw956hvhc+Hmq
         9x/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3C41xG4p1BHPpadBDL6pJd1psfwz5yd3WchMAQj7wTI=;
        b=ufIoJm2xzlTa7cqNbLpbPu6c4HAbh2APMk+nPbxrHuk9bCIyn//98jqMJtd6hFVTfj
         K38eRr0/qBq61VCP6xxClhd4rhI2azjLF8PpjE8arm+0uxSgUvDJcc/1lVirsViWLTba
         F+JRc5LZOg+QFg3qibblu8uGjWzyWmuvefzgaGUZ7wjoUVEK8V/HtTagpbNPPosnoZ88
         qTMhWKUpsgaq4K3XexBkyyILNMdn5ua6yvriQ/QTG1BrCffY907wWMhUe76QpjDN3bK2
         mfoWpzisD8kmojbfVsIH5c1dBTSEoqgwm8Rnc5gvvag7NRQJQewxGjMbvk4X7PLavHfQ
         geVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Jyi6R/m8";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id 69-20020a6b1448000000b00760f0b7ff47si359355iou.3.2023.04.18.05.13.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 05:13:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id ca18e2360f4ac-7606ce89ebcso90795239f.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 05:13:16 -0700 (PDT)
X-Received: by 2002:a6b:6e06:0:b0:762:7e58:8d38 with SMTP id
 d6-20020a6b6e06000000b007627e588d38mr1759080ioh.10.1681819995595; Tue, 18 Apr
 2023 05:13:15 -0700 (PDT)
MIME-Version: 1.0
References: <20230224085942.1791837-1-elver@google.com> <ZDgOSp30Ec00u8wP@arm.com>
In-Reply-To: <ZDgOSp30Ec00u8wP@arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 14:12:39 +0200
Message-ID: <CANpmjNMNNc8yizJE8T1+Xrg1rGm+EbBuqybF9j1YE9miqdtasA@mail.gmail.com>
Subject: Re: [PATCH v5 1/4] kasan: Emit different calls for instrumentable memintrinsics
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra <peterz@infradead.org>, 
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kbuild@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="Jyi6R/m8";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as
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

On Thu, 13 Apr 2023 at 16:14, Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Hi Marco,
>
> On Fri, Feb 24, 2023 at 09:59:39AM +0100, Marco Elver wrote:
> > Clang 15 provides an option to prefix memcpy/memset/memmove calls with
> > __asan_/__hwasan_ in instrumented functions: https://reviews.llvm.org/D122724
> >
> > GCC will add support in future:
> > https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777
> >
> > Use it to regain KASAN instrumentation of memcpy/memset/memmove on
> > architectures that require noinstr to be really free from instrumented
> > mem*() functions (all GENERIC_ENTRY architectures).
> >
> > Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> > Signed-off-by: Marco Elver <elver@google.com>
> > Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
> [...]
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index b9e94c5e7097..fa9f836f8039 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -38,6 +38,11 @@ endif
> >
> >  CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
> >
> > +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> > +# instead. With compilers that don't support this option, compiler-inserted
> > +# memintrinsics won't be checked by KASAN on GENERIC_ENTRY architectures.
> > +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
> > +
> >  endif # CONFIG_KASAN_GENERIC
> >
> >  ifdef CONFIG_KASAN_SW_TAGS
> > @@ -54,6 +59,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> >               $(call cc-param,hwasan-inline-all-checks=0) \
> >               $(instrumentation_flags)
> >
> > +# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> > +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>
> This patch breaks the arm64 kernel builds with KASAN_SW_TAGS enabled and
> clang prior to version 15. Those prior clang versions don't like the
> '-mllvm -hwasan-kernel-mem-intrinsic-prefix=1' option, end up printing
> the help text instead of generating the object.
>
> Do we need some combination of cc-option and cc-param? Or at least
> disable this instrumentation if earlier clang versions are used.
>
> It's already in mainline as commit
> 51287dcb00cc715c27bf6a6b4dbd431621c5b65a.

Arnd posted a patch, but the reason why a workaround is needed is
quite unfortunate:
https://lore.kernel.org/all/CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com/

Clang apparently interprets unknown options that start with "-h..",
i.e. "-mllvm -h..." as a request to print help text, which has exit
code 0. So this is only a problem for hwasan options.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMNNc8yizJE8T1%2BXrg1rGm%2BEbBuqybF9j1YE9miqdtasA%40mail.gmail.com.
