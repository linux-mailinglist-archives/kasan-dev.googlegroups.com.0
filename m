Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXOMYCPAMGQE3QU6OVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 64C2267A181
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 19:41:34 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id g24-20020a056102081800b003e5476c947dsf655858vsb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 10:41:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674585693; cv=pass;
        d=google.com; s=arc-20160816;
        b=pjLEYQ/PNMjgl1MWgDE45AOCr7Mm5fOSIG996T4LjJjzk9tpA6PIzDnIniFTrftBCF
         lwRqBDKiA7lJjY0WpfHafKWqWFooBSw7coq87pNXzkDa4/icytnORDRqY1NodgbMForP
         wsBWWM8lVtB2dMHxf5xPZXN3a2xEH5dqm54AdOvl5OrfuqKpekH44av4uoVnsWvfygM+
         fTYMT9qHNorYCLpSONLDIIMlTl6jbQNdL3vzFqzuCYpyP4kvD3VwuWlGMaDqS6ahC2Nk
         cX6lz9wsdaDTC3qiLng77gCQbT/SUgAY2S1g/R2ho2YMPfbePfh15+mMzn6Y6CJQX8FW
         WGKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fNfuINvBff9E1L9i1ySsTGaOKPO+sJuyvZJr2RlYwf0=;
        b=Z1PX/dNyFUqjmz8+Yu7sQZqel5fw37ds22Rblh52XR8CIsVzodRGpBLBOme/imvQtq
         Hov4JdAIogyWbJ1Oayj6rBwZokftXCfg++H7uZnNaUsz+DzwC7U5zf8/ISW+6GjPaFeg
         3o/WhIss1n2EVleV5xriL41zXumNgoVXwHRcVHHIxAvpVe5ErkwOSjzH9BQYlRSBGHDu
         iLkLIKdW2gfs8eeaNkYpag+aFx68C/X1qdYBHPn1PoTn1iENNHgm7Zv2c03uWEUdZEqP
         y/4hzTAHUW44lBVkF8x44SpMpCUguxlPRgX+ynvDyTgF2IyZHYTMqyP9ol9nf7jlP7FB
         LlIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Qj/2f56c";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fNfuINvBff9E1L9i1ySsTGaOKPO+sJuyvZJr2RlYwf0=;
        b=CE6SPHu2wsxMsMI1A/R0zF9NXS0VOYTq9VkkmG1UBPCZgo/pZuzWGkEQvpWsA/YyoP
         BAa/AIUmV7o3XvuM0ZR2aC3wUY4fpHFyK8J0wpDfOJt9zR2FzTgh51JOmUeXNu7l0oHO
         ZDTdJZvg9jOpxyXBZJkkK552fdvszdsVwn/6JaT67RjrmbmwEuklvjcU+rmdRRP8Zx4t
         /Y5KIVAdxR5r2D/fJeXPTpA57c05rfJsQZZ6iWh8SI/GXmMSMwFvHcTTORFV0K2JiEjk
         y4QKvYKilOwkL7Dal+e4i4w5v/yIYpZcXCAZMxdUEfjUMAoWjHRNLXvfIp0MS9ueupsC
         Tlsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=fNfuINvBff9E1L9i1ySsTGaOKPO+sJuyvZJr2RlYwf0=;
        b=acPbfufxDdFSBkomPYyT8VZP0rT9A+gl6H9q10LrKS+eL6I43BG9XJzonWXXF7B0lV
         JJRvkDK/K2eMZbOSFmEReInTKkgLIFtuaZiYXFLTe4+VEmNA7+PktXcFiMq014C8nU8t
         hf8cNPGtv992ePhGqzCqXWPJaha7Wg16xgADzPOP3Z1xls12F/lxnYxTIQU5bW362+0x
         ngyh+u+KN+AkC2kbbiGLlMgUycH4poj9Kk6jvvktGs8ekOxSHKBRt8yuoimvwN8SMsGk
         x2BDh0fKmoZZ8Eizk4TcNMpJjcDjKftPv4bAkA5DUA6rNzf6YnN0wc6GxjUj9Lal5uDm
         uTvg==
X-Gm-Message-State: AFqh2kq/PqA+ECMF74TogIB8n3qaNvM201seuUm3o8uMi//FS0jVaBAv
	ZXVHU4KjaG+PAj+CMhKCPsY=
X-Google-Smtp-Source: AMrXdXswjUOyBLup8BWNE1vIxQPnyinNL4o6GCkQR5KdjuvIGIW6LVGqgvzBR5CC6PeYYNJhgMmLmQ==
X-Received: by 2002:a05:6102:2847:b0:3d0:d8a3:af2c with SMTP id az7-20020a056102284700b003d0d8a3af2cmr4027080vsb.74.1674585693242;
        Tue, 24 Jan 2023 10:41:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d488:0:b0:3cb:9ab3:81b0 with SMTP id g8-20020a67d488000000b003cb9ab381b0ls5596658vsj.7.-pod-prod-gmail;
 Tue, 24 Jan 2023 10:41:32 -0800 (PST)
X-Received: by 2002:a05:6102:a15:b0:3d1:7e22:f037 with SMTP id t21-20020a0561020a1500b003d17e22f037mr17322740vsa.16.1674585692514;
        Tue, 24 Jan 2023 10:41:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674585692; cv=none;
        d=google.com; s=arc-20160816;
        b=Vw0DClmNoHQfK8ujvOCxq9PWdGCI3wC9tFWpmLf3vEur2jN6nSlu0KovGztlSGiN3W
         wu4z+b1ooXAHR0e6sSuc0RxfcVZkkeuwlZJVfzJND7KHOBkYBclo1tVCjEKmId0KRafq
         lWi5/Qa/2kjr2zQPR4NM6KiN2WQXHo8RE0KcKrVD5GU1zkzxECJbzkgSh2DQyeUg6bvM
         ZT93TtX18PosbYJu73UwnUS28XLS/JsGH6ysjiSiiPLTjV/nPVA/E3mWHrnC9iErZ4If
         VYIjz0dKXZpMKsvxifj3xBaUrv7DyNLm+HGVVL5s192FP80QaedDl7bc7FwnYeJncBVu
         X1bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9+Yt0CkwIbd85GrAKd4j3/Yh/keaU+8k8lD2GhYWx/4=;
        b=OxRraQC0K74LbDaazMSdAkt0dqtsXa8af9vJmkbLzrErobOtdwBk/khgpQdFIhTMGY
         KWJh7r6WwMDXmE1eRieYAxTj2DW8vwjtnaulghI+qjhBmw5H3VnEvfgjVr1MAw0KreGY
         MUxpCyYkdzALVTbcFgT0DiGk4oVHdhj8qKYePu/7GZtXHiCTzoWEjIxi5zRK002DEJXR
         sE8qOLQnYu6InIe/yakVEjnLMdGJP9Z8jRGAa/x6glzsxZ0TAuNoSjh5zzLPyNhz13mS
         QHjKYwKf54J2OzL008z1GH2eSPwRaSi/2P5SyNLjHKZc1Lcs44DADhD4mtsBZsPtPvQo
         aCSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="Qj/2f56c";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id i8-20020a0561023d0800b003d04209e4e2si186037vsv.0.2023.01.24.10.41.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Jan 2023 10:41:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-4b718cab0e4so231148857b3.9
        for <kasan-dev@googlegroups.com>; Tue, 24 Jan 2023 10:41:32 -0800 (PST)
X-Received: by 2002:a0d:ea43:0:b0:506:38f1:918b with SMTP id
 t64-20020a0dea43000000b0050638f1918bmr553482ywe.255.1674585692103; Tue, 24
 Jan 2023 10:41:32 -0800 (PST)
MIME-Version: 1.0
References: <20230124181655.16269-1-rdunlap@infradead.org>
In-Reply-To: <20230124181655.16269-1-rdunlap@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Jan 2023 19:40:55 +0100
Message-ID: <CANpmjNOx9CmRc8=nri9cYk9+3mRvGqxawNOep4_OpF10_523UA@mail.gmail.com>
Subject: Re: [PATCH] lib: Kconfig: fix spellos
To: Randy Dunlap <rdunlap@infradead.org>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="Qj/2f56c";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Tue, 24 Jan 2023 at 19:17, Randy Dunlap <rdunlap@infradead.org> wrote:
>
> Fix spelling in lib/ Kconfig files.
> (reported by codespell)
>
> Signed-off-by: Randy Dunlap <rdunlap@infradead.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Steven Rostedt <rostedt@goodmis.org>
> Cc: kasan-dev@googlegroups.com
> ---
>  lib/Kconfig.debug |    2 +-
>  lib/Kconfig.kcsan |    2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff -- a/lib/Kconfig.debug b/lib/Kconfig.debug
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1876,7 +1876,7 @@ config FUNCTION_ERROR_INJECTION
>         help
>           Add fault injections into various functions that are annotated with
>           ALLOW_ERROR_INJECTION() in the kernel. BPF may also modify the return
> -         value of theses functions. This is useful to test error paths of code.
> +         value of these functions. This is useful to test error paths of code.
>
>           If unsure, say N
>
> diff -- a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -194,7 +194,7 @@ config KCSAN_WEAK_MEMORY
>           Enable support for modeling a subset of weak memory, which allows
>           detecting a subset of data races due to missing memory barriers.
>
> -         Depends on KCSAN_STRICT, because the options strenghtening certain
> +         Depends on KCSAN_STRICT, because the options strengthening certain
>           plain accesses by default (depending on !KCSAN_STRICT) reduce the
>           ability to detect any data races invoving reordered accesses, in
>           particular reordered writes.

Reviewed-by: Marco Elver <elver@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOx9CmRc8%3Dnri9cYk9%2B3mRvGqxawNOep4_OpF10_523UA%40mail.gmail.com.
