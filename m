Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDPK56TAMGQELOTK2RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B85177D56C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 23:58:39 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-40ff56e1c97sf171611cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 14:58:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692136718; cv=pass;
        d=google.com; s=arc-20160816;
        b=TMD51QeCDLQ/oqUz6yWKNp7Qat5D7YM7QPOSm4vXqAi6h+ku0Ex+/b306Ga0o2TQCh
         9pdHP9B1S5Qjo2HnT6h1qJMC3jV91rsrqvmugV9xZw5oTaz6NEhQiZ4uRKpdEJ6jpqJy
         QRFBWQ27ZYchqRtTmAbOVdCTdRFPWSw77DVW6LalMDo/miSKbrOQEypouiatw4iS7Mqc
         624xnIXa6qnzozLlkAOlvYi26mH+e67QRD5dJ1LNi0SwHr8M08H+lcUt23RvdzXiLytW
         u4NWHZypQiftpEuQDCA2oC+z4Eyi2ECkvfwT7u3qYltihOhq0LhmKx9Med7J4wWnzfp2
         0ZUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=frrosoABEk57OLEkGIZ0c36BNXCP0vDrnAJCkF7w7Sk=;
        fh=G92QM+5hXAnVTsl3gF+ekgLUuCXMi7qIXWWCe92F/dc=;
        b=MZoLr5qQLzJGUnhTWuc5xOTdrEoGxAP7fmppivXwtjYBQap7jZh0NtiyfuyPl1bUfS
         ufoQSexgSPfmQ2saqO9JQkmSpkXrHDCcAt384r8Eq0e0XM1L/xY0jjnGvZnvsahtk76O
         6m8Wnjoru6eWV1grRmCYClGKW30TkDCMkuRCHVi6B8ryE7M/bWFl4RFxp8gbxccXpI4+
         6ojkmwwykEMkGw7t9UUNe9QyW1z3tl4KkchcVfbGPBrl/Qu0uPX27i1ARqTUtXkBlkXr
         LXGAV6sIOJNdzEIPloSczKqCfeWL0JB14bSpHOeYVIUeL48l4nYPYKYe6mZuBX6ornUa
         UQ9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=P5OEd4Nl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692136718; x=1692741518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=frrosoABEk57OLEkGIZ0c36BNXCP0vDrnAJCkF7w7Sk=;
        b=KyzyF2ULDIWKOX9N6m7OeTFwnoG1+6TOYHQwmdtPGkfMqjw+JTXxrk2RGDDrTUb4LJ
         ersUg/oWzcgzbZETSYXQ3lmX/9gUxEJ5PCaaPIcq415qtYs/8bFQGltsnJ0Vpp+/qCx/
         jL0UtdyBzMS/9vSGp7vXGgnc6jw1dZVEskoOKzmYqaj6UdrokXjjwyiAP3p0+pMT9XwD
         UnmM+CTlREDszL/pS22sOabyXAXDP/7qL1fnw/6OceTXFkuITynvXMBI2gChdCXTQVgZ
         PXF+0m2fQEtI7UAFcI2cOa9Dxrn34OaBQraFsBIX62FSkh+FKrMzm+89yHyW8YJkXL+l
         0owQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692136718; x=1692741518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=frrosoABEk57OLEkGIZ0c36BNXCP0vDrnAJCkF7w7Sk=;
        b=EVuwfNyELho5pg7MeR1/EGmKZwQuOJDUtGgWTiXfBfyVI3aJYsbGM4zc+RUHIwrrHQ
         wDGRLigEoui9uOXzUoHFBLeukfV7+Z+rXBut/fgmz+FrLXUTRiW0w/EfffSAbcgODb9r
         t4kdKkMQovLmSEJOF8sZkVV6KgB/AXLrsjvNrx/z0f5/u0VjH0JxiYrQHVaTaZQT6mb9
         EUUVEVa8iiXgqlgVSWOTYkVecA6GjKOKA7qC5azKvwF16Rjz+hKP6fl/dR7hlXNXZY5H
         V4JX4PmWnPwNnaeQllfUIZqBXp0rB0yWe4B/zi6tKcUz40pS680bmnj/3Z3/wqO9rWza
         utnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx4YuiniQFBWmSllqhYMlEvAAQguJVd5iXZzpSuPWqSlPD/i45S
	26pDwCe8biHRaL28ltmu6Q0=
X-Google-Smtp-Source: AGHT+IERPwcHlU84vwVry3kOyQyeE375MPM7Ivx+ZK9ozS0SnH3MM5+do/8RZHR+1CM+nmz+SGpepA==
X-Received: by 2002:a05:622a:3cd:b0:3f2:1441:3c11 with SMTP id k13-20020a05622a03cd00b003f214413c11mr106876qtx.2.1692136718084;
        Tue, 15 Aug 2023 14:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7356:0:b0:40e:c8af:ea83 with SMTP id q22-20020ac87356000000b0040ec8afea83ls2072772qtp.1.-pod-prod-06-us;
 Tue, 15 Aug 2023 14:58:37 -0700 (PDT)
X-Received: by 2002:ac8:7f92:0:b0:406:94f8:ee14 with SMTP id z18-20020ac87f92000000b0040694f8ee14mr13605qtj.67.1692136717242;
        Tue, 15 Aug 2023 14:58:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692136717; cv=none;
        d=google.com; s=arc-20160816;
        b=P2rbg5xUBZrn/YobkZdiZFYwvIxW5y1XYcw3QU3T2iZeaUcR++GISgNBj9HHNi8x4R
         uOQQ9nx4x9c6wQymzVF2l+ZpoGUkvmeHF2OPUy2MOcLAyZ1YKcRSLG/F3yzDZdQl4zBC
         UU5MxK+XThJN+iOoyYCelC7TEpiCa2ZaVZehMKBOAyaHSRJWl7nn5b+vleBj4WB4zJ6U
         2vr73lO1abq9GBOUHbZA1uPVDTOFJqSVs9y7t6rnTk5DeVul/7qIGQbhIL5OFCQeRee5
         9eDyfwus1fGFmtfKNnodg46Oe3xIB6coNFzRJ9lpc8ZnAmBJYeNxcqGJ5gE1z0qPXR+Z
         Q/HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7Z8K31bkMTbdIni3NCgyAAMv9oewxKBq0qkaddr2kYE=;
        fh=G92QM+5hXAnVTsl3gF+ekgLUuCXMi7qIXWWCe92F/dc=;
        b=D7hkweuIV2JfqbGYR2W6AXVYQIjN1lPZe5qnU0j4fnLT6fOvBtZcdjWwUL/yyGxa+l
         7tKlS0I8V4jnv+gOOqqW8aglwkaTGEM8lpLflkuL+gPhjxluh73swrS29rKsSMwdN6YP
         wcrkRvvue0m58XJTy4dptE/fRdPk/Yx1UObb0fSTFQfDkRxPXCrNQkD8/7Bvo3ANaiKY
         ZM6DBkaDd5gkTETieuoFpjMYYJ5U747ea50V9X2yQI1xgKraBIj8vGCZlnaH9Qtnfkt/
         6TZEnhnlkORpva9cvyX+QmaxzCSvZP2iWGDq2iCdTes/OhQni8hS0EXrt35kz3sD8Lxt
         yoWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=P5OEd4Nl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id ey10-20020a05622a4c0a00b0040ff1c7e229si1398820qtb.2.2023.08.15.14.58.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Aug 2023 14:58:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-5654051b27fso4491961a12.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Aug 2023 14:58:37 -0700 (PDT)
X-Received: by 2002:a05:6a20:938b:b0:141:69d:8041 with SMTP id x11-20020a056a20938b00b00141069d8041mr158650pzh.48.1692136716284;
        Tue, 15 Aug 2023 14:58:36 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id z17-20020a637e11000000b0056129129ef8sm10583401pgc.18.2023.08.15.14.58.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Aug 2023 14:58:35 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Paul Moore <paul@paul-moore.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v4 1/4] compiler_types: Introduce the Clang __preserve_most function attribute
Date: Tue, 15 Aug 2023 14:58:29 -0700
Message-Id: <169213670578.656151.9756083800563304743.b4-ty@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230811151847.1594958-1-elver@google.com>
References: <20230811151847.1594958-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=P5OEd4Nl;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529
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

On Fri, 11 Aug 2023 17:18:38 +0200, Marco Elver wrote:
> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the caller.
> If the arguments are passed in callee-saved registers, then they will be
> preserved by the callee across the call. This doesn't apply for values
> returned in callee-saved registers.
> 
> [...]

Applied to for-next/hardening, thanks!

[1/4] compiler_types: Introduce the Clang __preserve_most function attribute
      https://git.kernel.org/kees/c/7a0fd5e16785
[2/4] list_debug: Introduce inline wrappers for debug checks
      https://git.kernel.org/kees/c/b16c42c8fde8
[3/4] list: Introduce CONFIG_LIST_HARDENED
      https://git.kernel.org/kees/c/aebc7b0d8d91
[4/4] hardening: Move BUG_ON_DATA_CORRUPTION to hardening options
      https://git.kernel.org/kees/c/aa9f10d57056

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/169213670578.656151.9756083800563304743.b4-ty%40chromium.org.
