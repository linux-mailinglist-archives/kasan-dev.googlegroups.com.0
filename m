Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPFRGIAMGQEA7TY4GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 138ED4ADA1B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 14:39:19 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id a12-20020a056902056c00b0061dc0f2a94asf11021678ybt.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 05:39:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644327558; cv=pass;
        d=google.com; s=arc-20160816;
        b=vJa88QVEpcj6eFLBzdLB0jOHl5qXl8SArZ8Sx0s5iVwYrmHVvE4nUp8axcP0TR+pwf
         CIepU6BvPDQsGyzjoOokUfq+eojkdFYLlwadpCa/bezEdKQeIU0f32R5anEJknMdkokc
         UG/fbMzdkOb19NEtYTltl87ovtSQqJ4bLlQbDdq0X9KB8LMCSCzCZCi2mfPeZZfOT/b1
         Quemixw7o2P2gyTQGz5Vv5EUm4dqCHP1pKsrgUEiV8og6GM+qSsjtHKTWNikGVUNP4KK
         3KilkGmg/b5aGBp3R4CVEa+hYBv49p+wt/B5xmxls7UcxQ9CXEo0d98zknXusA0Vu+L6
         58Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mJIip1V7D470HCo7/10xdz9rZt2KtUW1G/0GwBxbOLE=;
        b=yGR9qDZ7q1nUaOpQ95A9ZkjRmffDdqzGlmLmsmKbiHtaMJLAM74EX8Q4ZjYrC0bkO0
         M7iYw82SjqJSI2KBtFcvqigf6/TUXEyOzK61CEoju3URRoxLTt5jhJQRcuw22tPWiOek
         vvAfahOXprNcHkgyLv6PL4rCcxpknvBzdEKiYUVZXMddrwVjFpl1bbUMqfmkqL903Cwl
         TgLAl0BVqVcnwwudstY69ZCLCYYqFANXwTsEFfr8RBVCAgecIl3cZJolyJ5kz6+rIZt9
         qhMzNTL4gUORaRzOROO31bDSrcY2YUziZ12f33pWQBb4OB0SghLjb0J6KSoT+/8MJqUl
         Y3/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=roCaBezV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mJIip1V7D470HCo7/10xdz9rZt2KtUW1G/0GwBxbOLE=;
        b=r0hBI9zaiz4g0HEPIGnWKLJtod4+wzDaMIHokdsukRup6PpZOlG+U1cTvN/yoZ9YQW
         ksuAcOiSHcU0Dgp8Y/vwo3YE8/CJ8B+7cUrw6jNhRZoUmOQ7ODDJuLcTEVnOBPJyiHQJ
         /2IBct3GU+dqTtzWf0jeDDvl3unbx/WXTzSU6JHZ6MQmZbXNYvQOTOy05Fpvq/cW/sa6
         9wIrrcEfZiiAEaYyTFrlirKUFQ1UudgCCziksP9CYeEOD68aVThQI78Yte1ZGvgu/iNm
         Xi/ERLu8RCdDflvH09Uyr23Ib2Df9QIcccQm/9Ta7L8pH/EjLE11TqlK6ePxq7HTD1on
         q72Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mJIip1V7D470HCo7/10xdz9rZt2KtUW1G/0GwBxbOLE=;
        b=UVeMzOI+b7Qv5ADKXJDZikl1Di/jXkJTlCc+pa7exA5unwLQr9PJTKmHfkdrT3ErBK
         NPe5UBbud65YxdHJe/uYTXJUo/0eVOXu3PNlWK40IKXzI0xjnktbCUNwwtgo2iOvLZkT
         cOV5AJteOVLLNXk4X83HB+bcRxKPUX4f3rInILE22NuJcP9sjjNJjKK319jS0Guj4FU0
         yQH/yQ9jxGfuItw588Tq5SdOZP671riS21VZzzF01vWDuhdtnTDwech7SJn/M/GENbbl
         cr3eUGi+H3qUBREHCzppC8nOHTdXPN8I/75l85ANEm3m/CPyKbQSlHyyqSvltLPdpaiw
         NnHA==
X-Gm-Message-State: AOAM5319/g4Rfo3hvHQwehj8nYfd+Qv0wy/lUDpenvEhJ8uavML0sCvI
	ANMEXOdBSLBJDhDWd/JG3a4=
X-Google-Smtp-Source: ABdhPJym3Tk/+zx/rFjPnvjKswhhGvNvD3gtnR/MTGTzhrJuHqOIWc3GCfdap46G17WF54DXUvYNKA==
X-Received: by 2002:a25:9c02:: with SMTP id c2mr434471ybo.685.1644327557923;
        Tue, 08 Feb 2022 05:39:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:34d8:: with SMTP id b207ls2964875ywa.9.gmail; Tue, 08
 Feb 2022 05:39:17 -0800 (PST)
X-Received: by 2002:a81:bd8:: with SMTP id 207mr4641226ywl.125.1644327557373;
        Tue, 08 Feb 2022 05:39:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644327557; cv=none;
        d=google.com; s=arc-20160816;
        b=i2wOtxeYfFRcEpGMiMZELdrIVZGtYpDObLlXIZbqhZFpyb8ZouBdEjxLHtcwoQgJEx
         mhyXsq7azeISaUyeIEENjMd673r0tKokq8kdbeLsghbHdCQCSTy6t8h4gMBVZMec3wUt
         gpc/qqG3Xt/w0JBcp64/04b7wyCgkHQYo66WADRCWZagqZdeQ2hyORwvqJ7yR+6S7P3t
         oyzp5QEdTWjUC3pDF9jvhZP473ZzSri/1q8uMNGfpc4KsXt/S28Q9c8uwzYrcLUPwkvY
         6EI450m+VrLgC9CP8C+F4pwEBSQoljCDzf4kKL6f2B4RbfztOlF1l2VpiztNf1kFLheG
         +yRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jkWKVFY9Ane+4hLx7KO8wJLB4fAu322gdHrEZT3DJhA=;
        b=weUPAzKz3DDcs1rIYneohooGjpm6wDML5x8EgMCi479ZKQ5KdD6xhMhklOTQuZUyBb
         HoT5yDflrezRClxuC7q7hOmTMEi9nb3klOXp8i1yqyPQXi4bWvqNXP0QdLY0mtdLVwv4
         FRwgDtkBFdiGAuE4EvxOgP7UIgbPySoOGQIUL3TS0BqVccirkar3PdF6/mz385DxdXiq
         W3uZbnqwH4/OA/Zvb8EQBqeZxXc5HU+rZNI3LMtlf1w5XJowxGl6T20nmNdm7sbRSXnT
         25+hhm1hIGGqeSieuD+feG86KS42KxBQUbVxFszzPMZ0DY6e2vxzakQB0dIONEaLHZ8K
         IXpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=roCaBezV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id n4si472748yba.3.2022.02.08.05.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 05:39:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 192so23729672ybd.10
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 05:39:17 -0800 (PST)
X-Received: by 2002:a81:1153:: with SMTP id 80mr4667357ywr.327.1644327556844;
 Tue, 08 Feb 2022 05:39:16 -0800 (PST)
MIME-Version: 1.0
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn> <1644324666-15947-5-git-send-email-yangtiezhu@loongson.cn>
In-Reply-To: <1644324666-15947-5-git-send-email-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 14:39:05 +0100
Message-ID: <CANpmjNOFL1vTZS28z_DWSz+X64_ghXBiGj3Fhee=wpRexZy7kA@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] ubsan: no need to unset panic_on_warn in ubsan_epilogue()
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Baoquan He <bhe@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Xuefeng Li <lixuefeng@loongson.cn>, kexec@lists.infradead.org, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=roCaBezV;       spf=pass
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

On Tue, 8 Feb 2022 at 13:51, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> panic_on_warn is unset inside panic(), so no need to unset it
> before calling panic() in ubsan_epilogue().
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/ubsan.c | 10 +---------
>  1 file changed, 1 insertion(+), 9 deletions(-)
>
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index bdc380f..36bd75e 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -154,16 +154,8 @@ static void ubsan_epilogue(void)
>
>         current->in_ubsan--;
>
> -       if (panic_on_warn) {
> -               /*
> -                * This thread may hit another WARN() in the panic path.
> -                * Resetting this prevents additional WARN() from panicking the
> -                * system on this thread.  Other threads are blocked by the
> -                * panic_mutex in panic().
> -                */
> -               panic_on_warn = 0;
> +       if (panic_on_warn)
>                 panic("panic_on_warn set ...\n");
> -       }
>  }
>
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
> --
> 2.1.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-5-git-send-email-yangtiezhu%40loongson.cn.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOFL1vTZS28z_DWSz%2BX64_ghXBiGj3Fhee%3DwpRexZy7kA%40mail.gmail.com.
