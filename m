Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHP4QKQAMGQEHK5K3TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 928706A8511
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 16:17:51 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id v24-20020a631518000000b00502e6bfe335sf5581069pgl.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 07:17:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677770270; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGn+NAyUxaQAQsUEL6Fv46roRMhaH2z3+hAErvhEWYSYB+JRJRB84Y6p3Hh9aSIjT1
         Er3bkaINqSXCtxpXbR6H7WIcwA1IsRBhy9cIvMj0PnGraO+TaSsXmjjwpEvLpF13BgZ5
         Zb8cp/57SGOuvMuqxNVCpNGWMH64nmAbH7rOBPXhojwN1o7opGB1kUdOfoK/MAGKyKcR
         EJdsuNh64gU9AB+DicEaRWePmCRts1hkLJnIG4pcDq+syHJ+HDABXFSFzNENaDin+Muc
         A0w7as7fwbjfVJ4IsEZQVhmIdXRKMcwFrc0OyaFBU7/u6LdKEmuYwg25jCr19n0bd9v+
         WCjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bx0DWNkwCuHYHwie55irGbPzyhvyYYmHyDz4zD4A8aA=;
        b=Umb1JShdpLlpvPRwRrUbR9XHguQNbDvM3KNOCbKh3gWtYyNZSEMK0vq9xhRhWTMXoj
         IMAi7D1RcW6J91d5IRXuLtjm81j1nPwT1BiM1rcYqm5jZDeOes6Qj20P7LeiGfZ7h+TZ
         b0zoEeSTBh5mr3ssjbup9L2HkGOW0BzXAqsi4FevDqZNOr+9e/I442jk8UXIQhZ3zVdk
         TIcwrJEZ6OZBXTs78QNtJHxgsl4fgs5/kgIzO9GAOEQRsFTGXWAHDiQUqpTQr6Y+UvIz
         UT6BLyF0Z0P6y2r/1mq2EYUqshhMuJvsBSDBQjp9441OVI4sZ+yvHRFigFZa868BOBdO
         hX4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CF2YWaUf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bx0DWNkwCuHYHwie55irGbPzyhvyYYmHyDz4zD4A8aA=;
        b=prKGeAZg5ow4DqFi2Pvqpx4B8ezdrCaucJAygkMY76u7NVgu6VpSX79aYgcdNpSWPW
         1U4lVJ0BpqkbY5ih4ozVDB7pKU15GnY/iNcO+YeeHJREIjTQq7mRUHgDvHRk/PpKuggW
         2XP5x2V+7QJdQM4CyZUVWcD0Kp4epjH45hRiG74HMtIWqPkqwRYSRWdVni9YDjQMXCCQ
         34B4+8iAD5WkT4jt/hsfpXUxS+Cpc71Qz9OCnq5BobXGqPOwbT4phA4EPYS69HDa/XSr
         IzTwZwZQyTqQBOiQA+VsF6h12OAnUc1DgI4DLpRnx1hajZXfx2gFZcLjiF2t1RyAOvPw
         R+vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Bx0DWNkwCuHYHwie55irGbPzyhvyYYmHyDz4zD4A8aA=;
        b=V+K2+uUQlbkb88fhN3zQLh51UrW3iefNSEZKVWQmZ3wwMVV2mFGzYsCMg2gy+uBCH/
         kQ+wcG/wXEfP1vqY03V11ar/5inXp9n/F38m1YIoqexLOTCQ/MfzOGx6YwPtPj1XCfvR
         /i4z7jfx4agTUuTveqHF7otlYptxvBI2BxKUb+3w/xxZr9/+IIctELN/1+vl0gTukSDt
         E+TnHwzCcgUyGE43893nB4Cs2G8kLVVVGgg+92ELZGpeaASa4HxuPtMP5NSregxvx5Ly
         wyt2GMYQGAEmE9QeX8/6Bu+Le0au7LF5RupCLJBj2mcVWoIIHZP6imKbHjqjKd8Xdsdw
         Oy1g==
X-Gm-Message-State: AO0yUKVrvvo6erf9ivqHAJ7y6azQXiny1WAQsy1wGa9MQZArCKfvANnA
	QEcfS9OJXyYpQP8U2LuYsaU=
X-Google-Smtp-Source: AK7set9BS//2kWv8ipjSEphgC4w5D559ZCToaSoqeYNqfM5Su29ySItHWmI/QXzG+uYKz40BYFAw/g==
X-Received: by 2002:a63:6fce:0:b0:503:77c6:2ca3 with SMTP id k197-20020a636fce000000b0050377c62ca3mr3404359pgc.5.1677770269750;
        Thu, 02 Mar 2023 07:17:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e615:b0:23a:3333:a3ff with SMTP id
 j21-20020a17090ae61500b0023a3333a3ffls3179976pjy.0.-pod-canary-gmail; Thu, 02
 Mar 2023 07:17:49 -0800 (PST)
X-Received: by 2002:a05:6a20:8412:b0:cc:6699:dd8a with SMTP id c18-20020a056a20841200b000cc6699dd8amr13723852pzd.45.1677770268988;
        Thu, 02 Mar 2023 07:17:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677770268; cv=none;
        d=google.com; s=arc-20160816;
        b=iF3PWDCjmHrA/utnBYk+Hxd6weLX9fnNL5u9FKUPyu6xDcENOpKJgJ7a8mbg+L6igq
         zaonPmPtHPMb3O0WD0xx3VAOKd/xEBf3/+xxSsvDgDsRJ3PpN28CwaHBlh3iepJGzQ6A
         VOhEHY3A+p+ZFECy+PDWkvh3lxBqiS2Wa6ZEMONi+dnk55GuQnUFKhtMkx4Dnu3Qq0Aa
         iJVGbfiCksOmpX8upc5mka/sF+pdrcEmnRnhlWzZAXtPUzfL2Gqqr799R3vvNzeIO033
         87ll7/5Kce5lANIAw+5hYwjhAeTqF8P3Hqygi/rxr4ozYV97uPoSl5R5gMqf9Bfp6iQ3
         FxAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=swy0Vvp7k1UShoRmUJ7j46CPAn/D6prvkxRY/qzs/SE=;
        b=m+2qkNO7nvHAGW05h/GtFGEoszcRgx1PrXv/4g/UK6qUzmp6MUiRdizgR9t0WWBKXp
         2gqEm+VmgO96dcY5KtltV2gRy1n9tbDOFpZjqLUjjTVg7UiEAZRMyaoe8RNfAOA6ElrW
         hg6myzp0Lh09TRD/RwPFlFXdbL8eNmXOjMMXTpCWRxoLvHWJz2RGaZZqo7b2eBSm0Y08
         icpO6xAv0T512zKIkfb9KqdAESIK7qDFtmQAYy2iM1rcb1n/NZAXiQzq/PzdrT09/Mvl
         MyLAJEe+jvDhfCZVjY1Sp0GIzayO15g/yf+J6cn8gX+bW+A/Dq9yRZ7SSfUpj+6tQZyK
         hVFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CF2YWaUf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id 7-20020a630607000000b004fb840b5440si777692pgg.5.2023.03.02.07.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 07:17:48 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-536c02eea4dso433397467b3.4
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 07:17:48 -0800 (PST)
X-Received: by 2002:a81:ad58:0:b0:52a:9f66:80c6 with SMTP id
 l24-20020a81ad58000000b0052a9f6680c6mr6418676ywk.9.1677770268490; Thu, 02 Mar
 2023 07:17:48 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <CANpmjNMR5ExTdo+EiLs=_b0M=SpN_gKAZTbSZmyfWFpBh4kN-w@mail.gmail.com>
 <CAG_fn=U9H2bmUxkJA6vyD15j+=GJTkSgKuMRbd=CWVZsRwR7TQ@mail.gmail.com> <CANpmjNMtXudXbVy4cZDAUUVjHX+hQ0P+FY6La3bsp2zp4t-pZw@mail.gmail.com>
In-Reply-To: <CANpmjNMtXudXbVy4cZDAUUVjHX+hQ0P+FY6La3bsp2zp4t-pZw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 16:17:11 +0100
Message-ID: <CAG_fn=Ubagz667ZEM2wyabshZhY-wyJRFUzqxZkBj3AES+KnXg@mail.gmail.com>
Subject: Re: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in
 uninstrumented files
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CF2YWaUf;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Mar 2, 2023 at 4:13=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Thu, 2 Mar 2023 at 15:28, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > On Thu, Mar 2, 2023 at 12:14=E2=80=AFPM Marco Elver <elver@google.com> =
wrote:
> > >
> > > On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> =
wrote:
> > > >
> > > > KMSAN should be overriding calls to memset/memcpy/memmove and their
> > >
> > > You mean that the compiler will override calls?
> > > All supported compilers that have fsanitize=3Dkernel-memory replace
> > > memintrinsics with __msan_mem*() calls, right?
> >
> > Right. Changed to:
> >
> > KMSAN already replaces calls to to memset/memcpy/memmove and their
> > __builtin_ versions with __msan_memset/__msan_memcpy/__msan_memmove in
> > instrumented files, so there is no need to override them.
>
> But it's not KMSAN - KMSAN is the combined end result of runtime and
> compiler - in this case we need to be specific and point out it's the
> compiler that's doing it. There is no code in the Linux kernel that
> does this replacement.

Agreed. I'll replace with "clang -fsanitize=3Dkernel-memory"

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUbagz667ZEM2wyabshZhY-wyJRFUzqxZkBj3AES%2BKnXg%40mail.gm=
ail.com.
