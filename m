Return-Path: <kasan-dev+bncBCMIZB7QWENRBIPX5OMAMGQEAXVMKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id F2A8C5B31E0
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:38:57 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf246130ljr.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662712737; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZCXxBcuwC9osTHeHxZcO/u9FORVOL3YF0b2Gsq5kUHtdj4JfyP1MesA0bDKv+7fCXr
         bgJHXxTmhGF/euFEQ2ngv4BEWHexmSC6arUGcbdzGwV9owrt236nujhQ3ewzzA+d7gHK
         Hyv6ewv1972uI7b26dbXvJfW8UqaAixkjwOW2myEaMHyh6MIXtqtaYCHh5LXfVCergiQ
         9Zx0P35e1rn0gEpnd9TKtexRJqrYgVicibGV1+hYyeoSL8tmtO5Rxu3CpMsegj+rtg4c
         16n6eSpfxbjXKPBKHcMmAKAsaZRT1WM3trjmneWNUoO2OJ3Lsec87h/7RGU8t45PDQQf
         H++A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3lgBgWlJ+k9hHoHQMAAZHCorZnzda5c0ff6OOcL3mI0=;
        b=u2WlPvuf20TcbE9qzzYUM6rtKLnz5Z6d/oXxSaHIzsVh7oU2YO4sgSezsQmjwa4fgy
         7UC1/I97UffB9F+wnO6yv5bwq3nrhyKoyY64aTz8vo6Gayod9cjxE5maBIyQgAgrlB2K
         7tuPmvQ8Iey6zjm1kzQRLLn7qZn6uGEdo39QEZ0ICBHESAIr1exjff1dI6SBlDL4tMcN
         TmGhVjAY+ZqUVWI5auxCOzgOmxZOVyEIiKKwrlOvuvXlVr3YJocGFiTkZwN38/GJmQJX
         cYMZwjObyauOlwow3acxmwKbIpa2ECK0K/tr53c7ioNGsPmQVScz8fUPTJPcpYIm13lB
         eHQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ta7vUt+h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=3lgBgWlJ+k9hHoHQMAAZHCorZnzda5c0ff6OOcL3mI0=;
        b=O/StUOPrn4uX8hpjsX5/FMcegradGolP405nTPE3ZIspiHlA0UIt9nv8heB4sAzTIn
         ApVIU3E75hTKLhEaeS0tFsaVdc9YJaIB1RpY41Ch9GPamMyH2QgueoS6A35hlEhVeAH4
         LCuthiJ7VWUX+BQlccxwB7Hjw9fyeIP6mycJZjs3odReT3gq1gpwQZz3oozDa9o4Cjmy
         w66GoW9OXfDFjQwxClv04dnCQ7b69Yu4xIjCTQMBTOC3+6vuNxp2nMUrffbf3rIPzS6R
         5mwwV7BkyG67ns/hSuBScW9RcLQ9QNbYizSTJDAA4k3UmZtWYnZIcsvu7FxtV9BnVc6c
         KHow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=3lgBgWlJ+k9hHoHQMAAZHCorZnzda5c0ff6OOcL3mI0=;
        b=vq5FYFUHX+8KrIVDTn6L1YI6lssrQ6ZUovcW+PuEnj//8BHZawGejzr7lE54xggp/N
         Gjy7+ZSrjtx4hOAg8Z7shbMJZdmP2zrdGMoMZjvqX1G5IjDZmh7JSA6QafN3jU/5ZGJ+
         1AgDavEom3vizRn8PdaL4RlySt8ahGtKmemmKveBNUWtfLP4Ip8XOXedJBsu5Zs3D30b
         kIQkr6rW0bcH+CDq52GBsd+Zafug5OiXUyhfwXSUeEtZQVBrh7LCNHqOrEjAm6sIEshH
         TWM/NSoO2Z1Sd3Ot5H+mEoodGCr26KHzuOgFyrYVcZYmGmFdf95s3u2bbwpooBZA1M9e
         T8pg==
X-Gm-Message-State: ACgBeo1wt6R1y3arHM00+3PJBJMsAdVPiC/tFOEkI6vkKIJ8NbPh4wDU
	hpx0MBOtn7+dGsr4aXrin6Y=
X-Google-Smtp-Source: AA6agR44V39OVF6JOSQ3AkgRHKL50qYPCZY58X9qCQ+x802z+UViFe4OxYnM4PI2QwNA5nSTaXOqaw==
X-Received: by 2002:a2e:740f:0:b0:26b:da32:1b9c with SMTP id p15-20020a2e740f000000b0026bda321b9cmr1892671ljc.262.1662712737425;
        Fri, 09 Sep 2022 01:38:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls2810552lfo.1.-pod-prod-gmail;
 Fri, 09 Sep 2022 01:38:56 -0700 (PDT)
X-Received: by 2002:a05:6512:24b:b0:497:a7a7:2ddf with SMTP id b11-20020a056512024b00b00497a7a72ddfmr4216375lfo.379.1662712736270;
        Fri, 09 Sep 2022 01:38:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662712736; cv=none;
        d=google.com; s=arc-20160816;
        b=GEr4MQo45A7dbggYZyw5LRe3kPkOad0z10fASoe76oOi+RxOFisO1GfhdCBGsxMn6b
         UBg7FRPUcKygBOsC3eel1iU6zaAzrbyv+7BxiAfzL+d27sBQ4hDliC3FqTMe0dYvUIAJ
         /xEFPWggv98ZCBcc8a+KY4k49L8TjSRyW6ryAlNhivyvtynSzDOeFEyXG1HixbFyCgLq
         F1NyFUQO/E7lixW3fYz/RC6N+HDDk9HGpKWhyF0zqXrHXE74s3JugqAvXKDit5BYjLP0
         0IeLGEGE6cqXCIw/mbTDmEhzZLBmSnOVrfu2Y2vMFMeGM5dutThGnOo1S6gOlnG19IOA
         ToPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BZdXdwTdKGe0baQEwZY8VKfE+Zui9u+0KrTmD1YE7Hc=;
        b=eundbrQFIUPWbIJWoPc8iolNil9OGtsRusMNzNjsJLZDXEstducli1QVssHus+HV2U
         3LWusXaDAfAofbEAjz3euJ52g7ToCn/iulRFZTJ2HMJSrPhFSRh93r7TyRkzMcXfyrPl
         SR046tX5KzF4jKDqO8A1yhPQjv+VrYza2nBHkQzsV9AX0XvYmxanDeO/MPpZpvy2b6l6
         4IrtjSxtSBmP+RfkqiGrOOYHxyQgRXs787psdwBjROg1fVOOH06I8zYesJrwWwqXdo6L
         Yf2t7SeCrRJJlREcWvCTsjjDOQQpmMpBFWf6AF7qleSKaRzPa/C+qL9p1CgoysKzS9mj
         50gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ta7vUt+h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id q3-20020a056512210300b0049495f5689asi49254lfr.6.2022.09.09.01.38.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:38:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id f9so775244lfr.3
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:38:56 -0700 (PDT)
X-Received: by 2002:a05:6512:118b:b0:492:e3c4:a164 with SMTP id
 g11-20020a056512118b00b00492e3c4a164mr4400289lfr.598.1662712735864; Fri, 09
 Sep 2022 01:38:55 -0700 (PDT)
MIME-Version: 1.0
References: <20220909073840.45349-1-elver@google.com> <20220909073840.45349-3-elver@google.com>
In-Reply-To: <20220909073840.45349-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 Sep 2022 10:38:44 +0200
Message-ID: <CACT4Y+ZJXS0Hcj4D-O+KfXT0SJ9pUhEx=zDqhwgOa9Pz2te0KQ@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Peter Zijlstra <peterz@infradead.org>, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ta7vUt+h;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 9 Sept 2022 at 09:38, Marco Elver <elver@google.com> wrote:
>
> Adds KCSAN's volatile instrumentation to objtool's uaccess whitelist.
>
> Recent kernel change have shown that this was missing from the uaccess
> whitelist (since the first upstreamed version of KCSAN):
>
>   mm/gup.o: warning: objtool: fault_in_readable+0x101: call to __tsan_volatile_write1() with UACCESS enabled
>
> Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * Fix commit message.
> ---
>  tools/objtool/check.c | 10 ++++++++++
>  1 file changed, 10 insertions(+)
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index e55fdf952a3a..67afdce3421f 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -999,6 +999,16 @@ static const char *uaccess_safe_builtin[] = {
>         "__tsan_read_write4",
>         "__tsan_read_write8",
>         "__tsan_read_write16",
> +       "__tsan_volatile_read1",
> +       "__tsan_volatile_read2",
> +       "__tsan_volatile_read4",
> +       "__tsan_volatile_read8",
> +       "__tsan_volatile_read16",
> +       "__tsan_volatile_write1",
> +       "__tsan_volatile_write2",
> +       "__tsan_volatile_write4",
> +       "__tsan_volatile_write8",
> +       "__tsan_volatile_write16",
>         "__tsan_atomic8_load",
>         "__tsan_atomic16_load",
>         "__tsan_atomic32_load",
> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZJXS0Hcj4D-O%2BKfXT0SJ9pUhEx%3DzDqhwgOa9Pz2te0KQ%40mail.gmail.com.
