Return-Path: <kasan-dev+bncBCF5XGNWYQBRBZG5XOHQMGQEC7YUGOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57AC049883F
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:24:37 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id 193-20020a6b01ca000000b00612778c712asf696496iob.14
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:24:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643048676; cv=pass;
        d=google.com; s=arc-20160816;
        b=A1p4UAJ0quRi+sni4eWEofCuMV2eHxcnyg3cxoic2qIsABY/V8zy7jM8DdCUkY0MVp
         GsmXQ/zuEoIYCfIpBHryjxSyTq/WqpNPw6TOFkgbPMETn5i3Xns7LFFI91ndDg47zz3Z
         vgdGhtA1YMXCFICGFXmf+cncakRGz8yHPk77AatsSd6MLE7tXBQXH5hXCdKn+gQ0mw1T
         Ba/TtThOM/neO7kiR/MTITlBzDxIzVAiFZO8UvX31MyUlU5ohqQiVV03aqc47F8RasuN
         TA9O6JVs0LhjFChXnGWHhilCl2wkDZk4nhIPqytDGH79f0YGXtbCWsx6S2qTRZQdOKqo
         DR5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Aty+sr5ar23yzj+gYN0arol9r1pMHzQdztdJ6/B1zvc=;
        b=GkUtIlvYw7a9f4VMegWUXz4NakKXZrrJRJl1fohbw2huHaY8SIJilgmyqu85ISbSg9
         PSlgvWqlT+c7JKYpJ7lc5UIyVnnS5GMPsaNmOF3zZFV4V7SL4quo9j/HfCDRFRtyeDVT
         ueqDeGvdpz4O27vhOu6P2dEpcqgDT2uwbhSOcMOOe2ck0I2gmeWFObGPLPmycyyCf3cL
         DGDD3DR3HxYVqwc5RmD5+S9R9A3Kdbb+Ez6nT9USggKXUgxgvNe7yEYTTp0H+bHq/kjP
         RlXIBuE0/z4jm3QbZjhrHUSh+5yM9fJpEciWgBlnJCY7iuB8RFszbl9j+12bZghhDUkU
         BwJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=alUnBjwA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Aty+sr5ar23yzj+gYN0arol9r1pMHzQdztdJ6/B1zvc=;
        b=F/ycjR+lnfa47rjrl4VlgM4p6Bzy79sF8g1IS4Uyh5d+3fjDIvIVg4018sT9T4qPvq
         na1NhgHp8viGUG4EAOsvLy6Tkg04TSmix58fTr7bY9k+W47J1s8H4sHQkA93G6+s0qyI
         hNBxDT+86A8hUK50UbT1oCfjf0FWP2Yx7Uy5V4nafo6der6GDIycwVMFUIsbYvClHyfI
         3j6WGaU5QKXLMp0iiV5DNkGz07pzFbghghuIv6wMUL/B2ueJV150S/h2fU5LpLmeDPGi
         dBXOc9j9iKbW3D6eq7ngi9+DtntmQkCnJHDy/ekb/uWmv2k9tJ2fBImc4NjZOGS2dsRI
         unyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Aty+sr5ar23yzj+gYN0arol9r1pMHzQdztdJ6/B1zvc=;
        b=OGXHT1ZR/tX0SBj0fnAon6s9/k32EBRQjFzs0JJC205xNF7yrO8lUieMHBFJlr7QAC
         rs4iajs2vK3n4Ys91UdrW6ifBq4rUEAaWC1yX1tiVC/tN3ykxqYTU02/EvOBg+RSB33x
         nt9SWpz5qdEv22Kknktks1pWrszrnusoZQk6+wUSQsRp/oO9d+VQ3+Cgh5kgyXvlO5X6
         iQGcLCF0eOUbBqZjOXE0BQwuFxsCmtph65TKYKUtRbqw7McZdYB0ubWbcm3MHEXs4smW
         sto1abHWq4jk1dalcKGGGRES20zpliRjxAyzqjDtOWq5Ta52CcGPC/4twQaBj1n/IQlf
         rfew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bPGusI1gq1M+cihAQA+OOK+bkFLq5lWzpH7iWVO3/EeHZedpr
	PL8saFxIUWMVC55OCa6J8n0=
X-Google-Smtp-Source: ABdhPJzN0finoHW5SeycyXRtjbRn0OD3nKMThiIByyhG5Tf9cUWZnITiGBeFY94h28ZPuScTkEflfA==
X-Received: by 2002:a05:6602:2d02:: with SMTP id c2mr8701659iow.40.1643048676166;
        Mon, 24 Jan 2022 10:24:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2165:: with SMTP id s5ls2999188ilv.3.gmail; Mon, 24
 Jan 2022 10:24:35 -0800 (PST)
X-Received: by 2002:a05:6e02:1a26:: with SMTP id g6mr9223264ile.52.1643048675783;
        Mon, 24 Jan 2022 10:24:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643048675; cv=none;
        d=google.com; s=arc-20160816;
        b=aCt//6v7VPR4dRykui2/7nHp5HBsMQxm28uKV6gZof0TpJ09I3Tyr+UO7679FvO8ZY
         7qvsqi4bKAzdy3GR7fk19hTeeE8iwRv1syJiue9IOiYMfZKpw5wi+Vjba9lZ7YG6XltR
         fYN+ZVquHhdVxhfEQvwtM5qBqjbiZoGcK6f9W3xz6tNcZXhNXBXHWq2K4I44r+3cZ2Ff
         5nSHHsm9HW4T65mDZwW1gqGWgEVVOJhD/7SvhEu3a3dsx3u+uzpbYvk12Qe4FqJ43/Ft
         Cbc/jA545NNfNAdEds9NzrNxxrj+O2QIUGVIN7HxJDRtuB1iy8TGWt6wlRLE13jLcmpc
         3ANg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uhZIz3/JykOBz9VP0YFQFFJB6JHp3P7kosVSER8JbCs=;
        b=mFtAD/zy2VK8LW0bn4dwv5gguvp3qiHtk8jF2b7O/1eKjCxuxAkV1rS0VmCv98ABWk
         piIApQasnKokD9jdlQnyZdjHLJFd/pR8q91adt4brRvGd+jtUnUQUKGY8NT8IAaTYRak
         bpL4dCVoHV78QZjlGr3/C/ykYuUbhdD8s6YyUiJ22rMZPK+Cag3YJyMvi8GnnZuO9k5M
         g6NPW8sMXB4JH9XqZl3KhW792Aewr7YUGthswPzs7DMLxCm52ByCMyfjOYMmgumhnUQN
         v+lHa7r4AsuE1m8UPceSCil0uwILvNEQFBZJ/vGQdK95uax0tuCAgVjJoj8U8vysPdkI
         PpEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=alUnBjwA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id i24si305964jav.7.2022.01.24.10.24.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 10:24:35 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d1so16486372plh.10
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 10:24:35 -0800 (PST)
X-Received: by 2002:a17:902:bc88:b0:149:2032:6bcf with SMTP id bb8-20020a170902bc8800b0014920326bcfmr15462814plb.44.1643048675213;
        Mon, 24 Jan 2022 10:24:35 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id e1sm12311920pgu.17.2022.01.24.10.24.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Jan 2022 10:24:34 -0800 (PST)
Date: Mon, 24 Jan 2022 10:24:34 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Brendan Higgins <brendanhiggins@google.com>,
	linux-hardening@vger.kernel.org, Nico Pache <npache@redhat.com>
Subject: Re: [PATCH] kasan: test: fix compatibility with FORTIFY_SOURCE
Message-ID: <202201241024.DA581869@keescook>
References: <20220124160744.1244685-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220124160744.1244685-1-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=alUnBjwA;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::630
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

On Mon, Jan 24, 2022 at 05:07:44PM +0100, Marco Elver wrote:
> With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
> dynamic checks using __builtin_object_size(ptr), which when failed will
> panic the kernel.
> 
> Because the KASAN test deliberately performs out-of-bounds operations,
> the kernel panics with FORITY_SOURCE, for example:
> 
>  | kernel BUG at lib/string_helpers.c:910!
>  | invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
>  | CPU: 1 PID: 137 Comm: kunit_try_catch Tainted: G    B             5.16.0-rc3+ #3
>  | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
>  | RIP: 0010:fortify_panic+0x19/0x1b
>  | ...
>  | Call Trace:
>  |  <TASK>
>  |  kmalloc_oob_in_memset.cold+0x16/0x16
>  |  ...
> 
> Fix it by also hiding `ptr` from the optimizer, which will ensure that
> __builtin_object_size() does not return a valid size, preventing
> fortified string functions from panicking.
> 
> Reported-by: Nico Pache <npache@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>

Yup, more good fixes. Thanks!

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202201241024.DA581869%40keescook.
