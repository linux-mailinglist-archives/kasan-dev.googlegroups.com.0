Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGFM7WPQMGQEYTUCTNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A74DC6A6D34
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 14:41:45 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id f206-20020a4a58d7000000b005250d9d616asf2519530oob.20
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 05:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677678104; cv=pass;
        d=google.com; s=arc-20160816;
        b=tykaIEra9M349otzS+xYvmDpoojmoR8ZmqBJDsLkeHuHJfQbcaWPY03XMN33XAswGk
         PRtzl27gwD5KAhC33M5MTrAAzS3cIWpTjAh5787zb6+0whbUTp3mgQWqtVnrX/hGX+k6
         TKN1olITZYFzBcSL/FF2zARtp6YM6qlGSE0jj0Ep0tQ20WL2H0m55JXo6rRWACKtys8K
         aPJLTYuEx7QYnc7/vRuJV7a514NDxcHYFDBAjaKhv8EHLBcCizNp965EAqVwcKgXz7px
         q6duSob6nW2YfC+OEYc/BytuK7BW0Bd+UWC9kFwsTUA4n3TDiM973kb0JhlGYJNt+0gd
         B6RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e73Cjod8XVcT/0KGZwjaW08bUeKMlH4AskHa7e02lOE=;
        b=K+qLvxyA/xTy3j0tv4X1qzpN7XUphxOWt44jrtu9l9SfisBKgCoHGlbpjvKVbvaO2S
         TcaCtyer0MRUm2QF2YEjy0GhlJDx12NAXepwrs4PsvN0/7VysEJtqsddUgSFKBfH0F/U
         ldRdGwYyVLyhUrY2EzOVsGiSgHIo/FNbLSZN07xnZKmWws1WS4xWzTVRPx3PfjD4AVox
         UtP9pAKuF33RM2tYQrmjqmX/YUthQZD1aA/LjPghm8L11yY2KsmLstb/XGhqgf/lbOQw
         Edw+GNpPlE9qGHGeaxnqEfdPsWUimd23jtUBXMzjpO9ITAmBSlGGSCE7AffTpB1sYlwZ
         18lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RNGjW0fK;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e73Cjod8XVcT/0KGZwjaW08bUeKMlH4AskHa7e02lOE=;
        b=Z+V2BRJfKkRyNjd0y5MedooJ7Ya+SlvAzVxWk7tEyHr6qRE4SdIRFmcCD5jPIS4vci
         Ii1xjo5UuXEd6PbTPoyi2g5VSPOMyuukdRZTCb3St5z4Kf3d56AUgzlk/zp5lffGW2yR
         8V0cbIC7BWvAHXWRDYxcToq36jNcn1NDWRRGuRIRmMUGEnIlb8a3FhcVD6U6QGpJpib0
         ovguBwJt31HNtnsECIuMu7STK+M47ttX869kKzdkZZx1Igugxf/oZA20iXmgILAbm0pg
         E+U3IFqmPHYEAy6xI+y+OjsYW2IDAf1v7LOexIl4UCeMpuY05av9xZAN+WwDFLMXsG4Y
         BTaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=e73Cjod8XVcT/0KGZwjaW08bUeKMlH4AskHa7e02lOE=;
        b=6/lr+iFWkBKdQUpUpvyRqgKlYIkvrJkSuH1gjriIf5lyYdHTlpagYcvrxleQIlUR+i
         iX0KpvqrW6302h1ri6a9UW6fezaV2uR+WGAOnABgwXFxBp4LoV8733UA6OoOSuA9EZm9
         ZXYJqwG+YAb7bNyYqU9aeuzJyGzy3x9l/k5msEGnc9LePyNmJNxEyFDbc0hKLsyT6Xzj
         78I8YEy1FYwyXdl1OMV9FfXHvhTI5fzeTGULN5TCkLSehyMi5ciGY/N/r/LE1r+6rt2b
         cr/Xkc8Dyqk9uivYIT2+3CgtM1AQDsYo7roJLiXe1nIcFXCCDdz31tFhJYOntMja0AL5
         83tQ==
X-Gm-Message-State: AO0yUKUKV+TENiI5JEs5Rw3IMpqYSGr1HIMzCVPFE+IL7yMpjJyaLMqx
	9i9abjV5kslhknWburJCo7c=
X-Google-Smtp-Source: AK7set8eXeH4E3HedeLYp+L7lo3G5KJKp9goCQRQ0fwcjQYEvaZ7nDRlQ0vt2y/Y5mqySGZL4/GbbA==
X-Received: by 2002:a05:6808:615:b0:384:65af:e554 with SMTP id y21-20020a056808061500b0038465afe554mr910380oih.1.1677678104273;
        Wed, 01 Mar 2023 05:41:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2901:b0:690:d198:4d74 with SMTP id
 z1-20020a056830290100b00690d1984d74ls3461157otu.2.-pod-prod-gmail; Wed, 01
 Mar 2023 05:41:43 -0800 (PST)
X-Received: by 2002:a9d:107:0:b0:68b:cb6a:d1c5 with SMTP id 7-20020a9d0107000000b0068bcb6ad1c5mr3397189otu.36.1677678103814;
        Wed, 01 Mar 2023 05:41:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677678103; cv=none;
        d=google.com; s=arc-20160816;
        b=Jg0OYyXFfpbhtg1TZNFc4+yAL28yZK1LJqtamIwD9HgS3kT/jgGmxnOYOIkOmZwrlW
         77vOIO1G8wQIfPXrjfGRDUrr2MUoKBbB+FW0sSAZvfks9j5oSYgErPx55mIGoo5dxrWY
         AXyQR25fPMYxw4kWxFtgyYqs5W9Xbp3Wc8FcGjOwGhDLnpxt42XewjYryX7GmltPS4B8
         BsabW9H9M8qL2vaMD7+/VGfokwELV5a/GZYTGfBo9DE4+/RQtmWRRm/dKwuN22H/Oc39
         YJRRNUgQtImAd7CZ2iwcbsMw9RgCIc3q0ou9iotmH0CmwMLSPpBEvO70WXWVRoieizhg
         MrKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Kq5OR9hoC260+bemchGBNuQjrNOZhrK9iuZRCuifkTs=;
        b=pJekSCuQ2XUTqt10H+37q8tvUznv064pX8JbXxBqdMYiaHjoSLAaxuh0RIYAIP94jX
         TSytzYlw7bqGX/0Y37HBH/Mad184uBPqEbCW3umQxL1cTOfQh9NDcYr2jS09gKapC11R
         9ixEv5I+Q6m2f0DK+ImLJ57/Veq/H8dJBws2WdtekdyggVZADUM8nODEnfXf+YmX/Aho
         DOkK3QHbxAeF6PM+EmJax3Gu7sBTXu2Z64bzDJb7KdBktWgEX2s5ayj+2WxBlP15a9H9
         tW64KU5E78aQmkP4WaqdAqHG65v4DSMC5mVkWzGYRy3vtw7a4wVgn65/rrGNFIBP48uz
         +rmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RNGjW0fK;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id t26-20020a05683014da00b00693ccf8c864si459414otq.2.2023.03.01.05.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 05:41:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id f14so5383876iow.5
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 05:41:43 -0800 (PST)
X-Received: by 2002:a02:85cb:0:b0:3c5:b47:539a with SMTP id
 d69-20020a0285cb000000b003c50b47539amr2818912jai.5.1677678103307; Wed, 01 Mar
 2023 05:41:43 -0800 (PST)
MIME-Version: 1.0
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
 <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
 <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
 <Y7a6XkCNTkxxGMNC@phenom.ffwll.local> <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
In-Reply-To: <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Mar 2023 14:41:06 +0100
Message-ID: <CAG_fn=V4-zzo+6HFG+wCbJRYHRh+Xx=r1weyCBJG-afpaG4Hag@mail.gmail.com>
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Helge Deller <deller@gmx.de>, Linux Fbdev development list <linux-fbdev@vger.kernel.org>, 
	DRI <dri-devel@lists.freedesktop.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RNGjW0fK;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

>
> I'd like to avoid touching per-arch asm/string.h files if possible.
>
> Can't we do like below (i.e. keep asm implementations as-is, but
> automatically redirect to __msan_memset()) ? If yes, we could move all
> __msan_*() redirection from per-arch asm/string.h files to the common
> linux/string.h file?
>
> diff --git a/include/linux/string.h b/include/linux/string.h
> index c062c581a98b..403813b04e00 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -360,4 +360,15 @@ static __always_inline size_t str_has_prefix(const char *str, const char *prefix
>         return strncmp(str, prefix, len) == 0 ? len : 0;
>  }
>
> +#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> +#undef memset
> +#define memset(dest, src, count) __msan_memset((dest), (src), (count))
> +#undef memset16
> +#define memset16(dest, src, count) __msan_memset((dest), (src), (count) << 1)
> +#undef memset32
> +#define memset32(dest, src, count) __msan_memset((dest), (src), (count) << 2)
> +#undef memset64
> +#define memset64(dest, src, count) __msan_memset((dest), (src), (count) << 3)
> +#endif

The problem with this approach is that it can only work for
memset/memcpy/memmove, whereas any function that is implemented in
lib/string.c may require undefining the respective __HAVE_ARCH_FNAME
so that KMSAN can instrument it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV4-zzo%2B6HFG%2BwCbJRYHRh%2BXx%3Dr1weyCBJG-afpaG4Hag%40mail.gmail.com.
