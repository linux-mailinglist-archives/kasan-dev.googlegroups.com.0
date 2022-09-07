Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT5S4OMAMGQELRMSDRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 00BA85B0BC4
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:48:00 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id j6-20020a170902da8600b00176a4279ba4sf6520727plx.18
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:48:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572879; cv=pass;
        d=google.com; s=arc-20160816;
        b=liBn64WWvoJWBTBCr5b51I4uaRL7gHuqBivo4sVxudgisiiYxnxRZwKq9wmJv0pB5g
         6efEGFpPWxcr66TsYUbs7Zj3zXkvdAK9/YTQxNE96ix+Q+wt6IgQs3A1D9FBWPXr4pqs
         7io+QmF+q3BdtlaEPxyfkJ7jcaTJHhyj2qbfWUOUDspwJogCF+LJ81mJojgL9hi8+Bb4
         a5uTo+5HevUMythGu3lDdvu9PvjRa9I7hByPaczFMe33Gn7oS8EN3b3o03euQf32IYdI
         OKyrwzop+VKrmZqBrhq3OWu4YzfMv6TRIHa15A/XplMhXdss6UHowC3/Iq9Y6P+AtJ9a
         0dTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=z4jeE5yKYroFtQjJz7SMsaZOjG3F20UgYXrwPWrBqRw=;
        b=ntfvgdvEfEf5GQev7fQu89erUy+Mcm6zmjDw49+/04tRtZ5JG7kZlv5edRowQgJgN3
         YQfuCIeg9cfxpi45rBFEKuY0Q0h/spFoJIE1kOkVKSaO5hnfTF/4UAYsIhOYeoC/vISt
         x4C5WR/PcbXHKlblRbj3fIo5e/3DdV6dV5xGlwhHdcJKB0kVQ9/VqqysOy479ZLVhB84
         09tEd1hN5iKLs29/SP2XiqXFZ0ok7O5cUK/eRPSpeFvibdp5KorG28H3BNarQmoQmofj
         goqOfdS91RaaROD1KwouAWbVAw808XxktMiFGsF9pwXHvm6mElmf3MxgrGkvCz4hz4Po
         5TVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sUTHKS44;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=z4jeE5yKYroFtQjJz7SMsaZOjG3F20UgYXrwPWrBqRw=;
        b=V6c4J3D4prePnudiDj0UdQvo5i2FtSiK/wWUnRuFOU2hnaARlDeQtqgZcA0PhiCRV6
         n4lSyyKFvcbgK12yD3uFNmD3BnIaAsasNkH2KSADktTm9tgDv8hENuVS6HrYdjwKXAkn
         50hkpjpKkJ3VE3dKlvj59TD9rm4n42y0lX6WtKB4JkHOsr/9u4weEBpKwz7Y1qUfVHf3
         LKpMlMqTIz+qEhCVzB8AzmgdgvuJ4UkR/7k4gINKls8RB8GMmYNLOOO6t8Ig9kAm//G/
         d3hbcHTcIuRcUoSMb5ldQJsCcpWtnXa6LPN4RLrjuooccIO0xUf4Gxl9TierVUd3fpgc
         Jz0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=z4jeE5yKYroFtQjJz7SMsaZOjG3F20UgYXrwPWrBqRw=;
        b=a1v153jlwlLYwLF7wDqCwrxsskxTRkUCUH24qgm3c0o+KHJC3ZzvJ3kUTbcGoU3Kq/
         GD/YR8cffTdOAXSwv7yJA1DQ0QdMfPJ1W5tomDM8Y25wXKiIt5PUcnSX6a73EbeEpGGZ
         S5z7P3T1KQotG6xuHI2MSzUQ6tdTZnJyVIVM5jFMqWrePmWdt1BQCCmxr1FQ+g1hTUXL
         +eNAOtCd6qXNJ75EwF1Ojn8/Fg6HOxrUwkitJ/po9MZrpucpROMAawf/uPvkc86sisHC
         a6fINqH93jhcrgL9ug085PYdho4yoMCe/SxklCfemAw4rXWkAMQAFZBRvA77objZuzPl
         a0gA==
X-Gm-Message-State: ACgBeo3Pzh7gBAu2Dl5Y8ULYMBK9fm3x7+Knn45FT4Av5SLcuc84wQic
	mRXttvgZsGCmTQTAvmeY6Wk=
X-Google-Smtp-Source: AA6agR7iNVBlstex2vNAuBCRN0pI+V4cXRzUoJtr97cQo8M6RK+jBrkdr7fgG1GGqzfLD/S2Oe2GhQ==
X-Received: by 2002:a63:68f:0:b0:434:abbe:caec with SMTP id 137-20020a63068f000000b00434abbecaecmr4360993pgg.363.1662572879362;
        Wed, 07 Sep 2022 10:47:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d550:b0:16c:2ae8:5b94 with SMTP id
 z16-20020a170902d55000b0016c2ae85b94ls1878208plf.0.-pod-prod-gmail; Wed, 07
 Sep 2022 10:47:58 -0700 (PDT)
X-Received: by 2002:a17:903:11c7:b0:170:a74e:3803 with SMTP id q7-20020a17090311c700b00170a74e3803mr5076395plh.156.1662572878552;
        Wed, 07 Sep 2022 10:47:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572878; cv=none;
        d=google.com; s=arc-20160816;
        b=WBbZvDu35EHlH6iuO/Rlf4+O5SYzOayDQqSuGgcrKBJ8HrPrHGE/ujt6xmRMnmimT1
         irbvq3fQOG9aaSKjB2AQP2k7FPlpFENif3rKU8CSXu28P+TPpSizeRq0yGgbuC1lDhJe
         Fl3DnMXRnTmo5OWkK39bzrLg7g+sgd2s9CioThFSbyl9i/reuqJzyq6rCXgwZ/E7pCga
         9nJuJfa/HMzl3fv5hzVwpHvSFrwPB7oZaaF60BiVYwuBwWOd/rdYgwd5FTtH/6mS348c
         HSiSNpJ/zhIm2teF4I22+HboSMU3S479EtwwDxjzEcuKdRr3+KEp2CrSygsPX8BgNOMO
         74vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PJdZjFOGYcZr+6GORZ6uuk20no/Y1w8QVrjJZltjb1s=;
        b=Jvch4xhFHvk6I4h+ozcBEZhHrJWs4unk02IUOuFDgc4XFCAalPRB//4Jhpygyws1At
         4dtQDMEogLLQ1+M11BBGMiPGXf9PvqvxLQBM9kq0xoSmF1UZszEWnnYpgRAG8RLGsc29
         o8oQqOKLwEInjHGCgy4ih1ubOl9Ow9ffW3FWGi3wDmHHNEMrWPxIGlbFANYMFGPpjZbN
         dSWFw6xhqEvwtaMZQgzv7FRbpHM9/qZpVF/TwumK5ij+7ZzkRDOjLvn1p+WiHRbCoYoe
         QvXOMYj0uBI5BHXRl2FgDxXhIumpi734ouZLmGTLjfPPhfUgLhmVt/c1J6VvGJN1YZlY
         bjqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sUTHKS44;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id k4-20020a170902c40400b00176b64754aesi894848plk.3.2022.09.07.10.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:47:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 130so17125522ybz.9
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:47:58 -0700 (PDT)
X-Received: by 2002:a25:d487:0:b0:6a9:3faf:ca99 with SMTP id
 m129-20020a25d487000000b006a93fafca99mr3769610ybf.16.1662572878122; Wed, 07
 Sep 2022 10:47:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com> <20220907173903.2268161-2-elver@google.com>
 <YxjXwBXpejAP6zoy@boqun-archlinux> <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
 <YxjYY6SJhp1PtZos@boqun-archlinux>
In-Reply-To: <YxjYY6SJhp1PtZos@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 19:47:22 +0200
Message-ID: <CANpmjNPpSvWH7eV38NoPSdB0Qxov2cOsvYnSCCLy_vz4GQq3fA@mail.gmail.com>
Subject: Re: [PATCH 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sUTHKS44;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, 7 Sept 2022 at 19:45, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Wed, Sep 07, 2022 at 07:43:32PM +0200, Marco Elver wrote:
> > On Wed, 7 Sept 2022 at 19:42, Boqun Feng <boqun.feng@gmail.com> wrote:
> > >
> > > On Wed, Sep 07, 2022 at 07:39:03PM +0200, Marco Elver wrote:
> > > > Adds KCSAN's volatile barrier instrumentation to objtool's uaccess
> > >
> > > Confused. Are things like "__tsan_volatile_read4" considered as
> > > "barrier" for KCSAN?
> >
> > No, it's what's emitted for READ_ONCE() and WRITE_ONCE().
> >
>
> Thanks for clarification, then I guess better to remove the word
> "barrier" in the commit log?

Yes, that'd be best. (I think it was a copy/paste error.)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPpSvWH7eV38NoPSdB0Qxov2cOsvYnSCCLy_vz4GQq3fA%40mail.gmail.com.
