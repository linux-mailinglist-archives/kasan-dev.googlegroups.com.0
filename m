Return-Path: <kasan-dev+bncBCT4XGV33UIBBVVSZ2QAMGQED2ZPKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C28BB6BDBBB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 23:33:59 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id m10-20020a05600c4f4a00b003ed74161838sf450024wmq.6
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 15:33:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679006039; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q5vgpt7hmqXlrULGxjTYLWWBU9906N+U24i7Je/4iaYXhCQerkIl48lREXqrbe7J9T
         m3OlGR5TsSCl+bsPgxIc5bKraLxHe+AKDHqcKGHSgXmhNN/aOoiv6RrE4ERjtAjdnMIn
         0PWbVEyA1Qttq0z+meA2vEVZ0S10i+kML9n83L6z9vV0a9eViD2ZlJJ8u6Zi8gNnj1uc
         7jSUjGsTB47SIrb+WEOLMWrP6+G1tFpGAbZ5T8Zrtbg6ExDkgsfW9ZOVPH/kRG88j47s
         ZFeVvcSPDIrQlKWZ1OZm0TszZUff2kqlnij8wqMwbrRgbVOzR+Kj7hf9a7SNlyRwMP/V
         /YvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=S7BM95bG59ghm8k//xgHAapaeG7b0XUfpQGJoTEhq1M=;
        b=dH9U+Dr16cBSoJbiAoMnPmBuh8Pjxc+Dro7m8YcPsl0HRFfUYquqE7kWcKs216J14l
         hlXin+hKqzhK/Y/mtQ1PnxwK5BgfDCb2XY34KMiFdEKKlUyImFpv72k8+dx1Jp5MPjNc
         fOFYcGXHJ/YNszuarrbu1sxRmnS7daWslRZ+fRTNkrupkEI7ldZaeh+qW6CShyzCOTcs
         XtUFKhpVM2ZSdzZEyJoFc/eFiQMrySwnnNWeXIBVqyyHPG2WbAaULYHNxDzutePUk/rz
         YNers08ADk/n7fh+o9N9J1aZoXJxNwIK0xzfLrKeGgC7hynbX6ZCxgdwMQ4K+QZKNu7+
         KhCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fYPeQi0l;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679006039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S7BM95bG59ghm8k//xgHAapaeG7b0XUfpQGJoTEhq1M=;
        b=rhapCvJSqBakAnN1hhKdWM35HniOcUDT0TvauNL5iJSQ0fUIE7y+7BGCKU10qK1RIY
         V0ZeBuUI7ZPHZ2MvoidxZMAYnv0X748zCOvThFC60q9tgeP48yUn+te2rLIBLgSGtKI2
         +ViOj4RzWIXoTIfFik47MNiZgnjeDUSBVzXsjKHvK5EzNv+Xk8FZOt7xcsNh8XQxTCwg
         7uo/zacjZeUCw6vP3vXScbBpeNe2ReYY+PBsKMI/uLHRlfjPgDAQh+rO1iCti1CJI6vm
         6kK4L8EsoZq4RxLRFLsWITtVUeNLrbgQOL+vv8Il7ae+TC14zVueKVWbHlThVa1FrCfP
         ufJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679006039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S7BM95bG59ghm8k//xgHAapaeG7b0XUfpQGJoTEhq1M=;
        b=jbtTA5iNnsk+ixWj6UbyZKE8/LoXrWxtNOGONdT7+YLCgNNGeM3W8Y/X4CWwuRz/ni
         xwssIPVaJ45QzuGp3lSMmMAEPbyYSUfZfRQTHqAVDHuz54ocXGHpIFi/2gZKfoh9Xa76
         VW6lp2B4LMZnBwPMNOsqLs3p+lt5fKwZlq/Fu1Btl7f5c7SECe5TlyBFgp/9XoTj4/iZ
         nBWtu3EBkO0i0F1SwICpO9rB6ubT2IC3cnGZ9PIfP5ZJURTspe85SAIsG/68HzZMmtQs
         zc7DKBvaiB9nRD4FvEHhDcCKMsEz49JY+BJuZ4e5o4bZ1YEOJMSbt4ZGobqmtFnwBivQ
         DR3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXeKDPt3ZIRoCDWFyQSRq3PmVDRdq5kjLC42QCbCxTWsa7RhBUs
	2W9fG8nvEzMyc55RrtNEg2Y=
X-Google-Smtp-Source: AK7set+z19hs1jcaxLOCGpA5v5LMCSHylLaD9BVQC1tyeaMH/k41jg40g60MiJhU9qT5QNBdrfVQIQ==
X-Received: by 2002:a5d:58ee:0:b0:2ce:ad49:c2e5 with SMTP id f14-20020a5d58ee000000b002cead49c2e5mr1377838wrd.8.1679006038991;
        Thu, 16 Mar 2023 15:33:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f685:0:b0:2c5:557d:88a3 with SMTP id v5-20020adff685000000b002c5557d88a3ls4572503wrp.3.-pod-prod-gmail;
 Thu, 16 Mar 2023 15:33:57 -0700 (PDT)
X-Received: by 2002:a5d:4985:0:b0:2cf:f140:52e3 with SMTP id r5-20020a5d4985000000b002cff14052e3mr5430071wrq.9.1679006037301;
        Thu, 16 Mar 2023 15:33:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679006037; cv=none;
        d=google.com; s=arc-20160816;
        b=p5Ddhcr1D7AFxFFfoJATdKAZMwgxjjSjE8W6gXR9JYpuLmSDBVs/t+gJAArEg5i2/M
         FmNXeVlilR8UTVeGIuoBv4qz0Bf6X8itd8NL7kWlF6bWm7UlkQZjfQzxp944Q7DS1d+B
         cL3bg8nJOXeDHZhBEQcxakz17z8AnqPBSwPCss6vZYDfVolUBxGdRFy0rhNn/GNR7jq1
         GN0VXzmX8DNLsYGvpD9v1BQsAFp+pusalC+fSAivRvDjlFUFph6vscbDTbcw8j+0F9KV
         +w6/LkapuYdNleNGveahF+4s6NsjjWqNXKTtGQmR7PiVhciwTmXfxDExNCEAFheuYJ4W
         SRKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uyFd85UNzU7sYn9+aS07IUk5elz8iS2M6TGrZaSrwgk=;
        b=iw8Y/+uG4aYGKt8m8r+UPXkaMxYYjvB8zVeUCFb/MdEV1xpKIwvptWX1Fg3crxolEm
         IbOQWKotXOEDnS7KSh7e//vbhjRWSyiUEuIgvdjgRUd/6zDmsLQYQ9YtUxgyim1c8MRa
         Y/+WKCXcV9eqStlbY06pW2dLi0ehPfx3mWFMYNeKjm8wiegoN0aUYfvHniCmavIkVjgp
         0/glHqXOAyFJ3wiBop8pxaZm5MCbJaSsoRwoJ1FLupZHz/JQ0IEQiOAQdwyi/WS7zgix
         wqADkNsVkJ6DDvz46PZmv1uIxQmreyind+/+r/gHp+jUh8bown5YUzQ93n3k6WVEdX1X
         sOGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fYPeQi0l;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id o22-20020a05600c511600b003ed29f3d6e1si563581wms.2.2023.03.16.15.33.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 15:33:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id F2E28B82347;
	Thu, 16 Mar 2023 22:33:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7BB5EC433EF;
	Thu, 16 Mar 2023 22:33:55 +0000 (UTC)
Date: Thu, 16 Mar 2023 15:33:54 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, Nathan Chancellor
 <nathan@kernel.org>
Subject: Re: [PATCH] kfence, kcsan: avoid passing -g for tests
Message-Id: <20230316153354.bc31b9583eae6a79a1789de0@linux-foundation.org>
In-Reply-To: <20230316155104.594662-1-elver@google.com>
References: <20230316155104.594662-1-elver@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fYPeQi0l;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 16 Mar 2023 16:51:04 +0100 Marco Elver <elver@google.com> wrote:

> Nathan reported that when building with GNU as and a version of clang
> that defaults to DWARF5:
> 
>   $ make -skj"$(nproc)" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
> 			LLVM=1 LLVM_IAS=0 O=build \
> 			mrproper allmodconfig mm/kfence/kfence_test.o
>   /tmp/kfence_test-08a0a0.s: Assembler messages:
>   /tmp/kfence_test-08a0a0.s:14627: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14628: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14632: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14633: Error: non-constant .uleb128 is not supported
>   /tmp/kfence_test-08a0a0.s:14639: Error: non-constant .uleb128 is not supported
>   ...
> 
> This is because `-g` defaults to the compiler debug info default. If the
> assembler does not support some of the directives used, the above errors
> occur. To fix, remove the explicit passing of `-g`.
> 
> All these tests want is that stack traces print valid function names,
> and debug info is not required for that. I currently cannot recall why I
> added the explicit `-g`.

Does this need to be backported into earlier kernels?

If so, we'd need to do it as two patches, each with the relevant
Fixes:, which appear to be a146fed56f8 and bc8fbc5f30.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316153354.bc31b9583eae6a79a1789de0%40linux-foundation.org.
