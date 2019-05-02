Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIF3VTTAKGQEJN57AKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0766A12064
	for <lists+kasan-dev@lfdr.de>; Thu,  2 May 2019 18:41:06 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id w200sf1436866oiw.1
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 09:41:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556815265; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vj+QAKlgShAb5J3YHuaZGDZSynZEKoHFj7vC5CVFrBVhp8nwN4q/Wg0ZoQ2rSlYK/P
         NvLmivj71D95u4Ooknb36KCtcP3X58e9xC6Z9P0bUUNmEm0xHUoAg7SDRqqWNG0fKYA+
         MdFg+DUj3KLHtAeYdEu8bylUuF2hXF+rxYcBP9pbIQNYi2TPpjCQdK55W5Q5iPb+6Vck
         f1zMIi7lriTCpvmDLx2VHty2cBdy+t6H2hOuv/ypQP+TsgloWa2lYm3twffvRU6vO/Kr
         VnGZu9JgSJ5n4ZEDEHvDifZKKont3ekKqxiqgmJAf/UdgXEVCqk7yQPusTyQWqDJaL6Y
         J5IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t5XadcHWy81hn9++bIoQ9z35/09Vw5ZREqFo3QBOzuQ=;
        b=VLRb1OekCAm5Y/4drP8qNJK/VsrOVAQtjP44gbgiYStZ0HXAIkC538xINEf4+EMyGz
         I9k6j80VkyLaa/9EkqGuDBocr2HP6Q0CuiXzcH/IFnTRyV4FyjZqg2BtL6toP8ONgVat
         vp9tOr0uDSEgYxxpoiauwSD404b6SzqPcIbDPqcgapaHoMmw6lUpHBs4RGy6STBBENT0
         rdyVGPjgKO+jNEhodL5K5zftYoYOrYyU2gjYNpzUlxLMkaU/EXbQORtRTmH1vOIf2fu2
         1YCN9hbtxGNpnInjqwHwBBA36VtWJPbFJf0ln28rf5Ueic2PvqozGOOz3soKyFRvf6Gi
         esiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pW9Mlh00;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5XadcHWy81hn9++bIoQ9z35/09Vw5ZREqFo3QBOzuQ=;
        b=G721yGWuPG1IVURmF5yMP7Q+7zkDwnvx57815hdUXIqdvJgDE1QWuXTSGbtXumHd9d
         /IiCRNsj+ctnDybMtyK+b1HzUdhtwBKFiZiXO97ShwS+ALjA5Tm03LwG7mEZIuxHhsyz
         Em80/RqwXP9rjWKzYqOvUHaO0+dYZHy7kdHEOClr4Am0vvjanRack8dxYHu38d8CN+o/
         5S7BKCHgi1tTFbzRFu/eNFuSjE967/jUfMlBrZGqD555ByymnJs4uTof/8n44+vxqSvA
         FbduuvGsv7u0MabdyhB4jyA0aPHZvSbJn0eqw4Zk7bpX8WZxs0rrTB0Py59IEbQa9h0w
         rczw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t5XadcHWy81hn9++bIoQ9z35/09Vw5ZREqFo3QBOzuQ=;
        b=E3dtpiNTrZFJ53MlCyjH7E4f7R5iBSESKUwHGzUfZb5LzOUpbGRGVBzghOpexRNmGf
         TGqSWhnul6qhkzUAFOCrglwBfJYpdDn5esWX4mjnaHnJnznxJBiKuSCFQIhmTLhUDYj1
         FtCGdcNt06OLTWlqpTKVLKj2iCdNExr4rqaVBRLLL9LmQ9zrIQoi8T4d3FmUrSqLrfG3
         BpFn2cJ5q58AShiR2+0Y8+t+46FaF93KrbW11vFpO0DS4J4u/QxH0O8jf+5/FNfeuG1Y
         VcrAE4Z1muwudo545m/nMrBe1OZkbosMG+R49Pwyc9tyqajyRtj8OosPEmsoTTa1uwKY
         tySg==
X-Gm-Message-State: APjAAAXg/tmysRfyJk1v08w3xV1cqy+ZLrY48mzNURil6ATGyi3uXgoU
	KMZf9kBfGqB5/3Xm2+75jZQ=
X-Google-Smtp-Source: APXvYqwpOlKprXoPH1DfR8amXbbQYl3+Q1uMUwr879qhJRub4hVvuddvxD1shKnE88j2x210KlY7/g==
X-Received: by 2002:a05:6808:150:: with SMTP id h16mr1471933oie.25.1556815264806;
        Thu, 02 May 2019 09:41:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:11da:: with SMTP id v26ls319776otq.9.gmail; Thu, 02
 May 2019 09:41:04 -0700 (PDT)
X-Received: by 2002:a9d:609e:: with SMTP id m30mr2610525otj.337.1556815264566;
        Thu, 02 May 2019 09:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556815264; cv=none;
        d=google.com; s=arc-20160816;
        b=TqHRbexeJzOFcFfu8ATk3h+2ybRC3TVroXU4Esb5Mc7xFAsETAOXgw1Dk9WGXf8Wx3
         oMl8EQo9EocQMMlRmKqaO4rcjH2b/74ytCFHFXYs+IJnfgXLVust1O/hxKodh7/5Lihj
         hDKmqGDOvHQYHOiKlt07JxI//AN5UnYu8sGpZYKKyqrrb3czOStssh2CwyflJGE8w4GV
         ljMeOC8bMKj3CsYNlISJZUUoLrLxzZPiXClS6DGsH0OAW7vuMwWwJ16QEkw/VrFdbYdn
         tUgntdF0T0NnkfAk2kO2NQd/nlcAEl8o0R9eOsInjyPyPOfJ75pb2du84tVsC4G8tWMP
         5mPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=92karzGId4kTiPxbclHEQu/kjCIMGVKlDvLxWKLPllQ=;
        b=02KgwUgXyqUjPMYr5lSu706JmcAbe9BxjqkTIVW0CbFLBUPVHgvd3FF4LwJxVhwq0c
         E7Tz2vdr3IxEML80uDD2O00vGVUGUd6y6tCdFN5OS7a3RTz972/ZN/QG31H14IULIo5L
         GBvOm1aLJp7lsVh01ypadRKyTsw4vqZDRSd2CdNbz8YTbjQ9Ld7hK0o8ZPJntyohxNN3
         IP1Nsq9ZM5OdfIPIHbNBMljWqNu3RI6pOJjjPtvdVcbvl9jcJXptTcJ+NqIhz0CZcNvs
         l3X3h+3ljO8GPuv7e724RO45PB9LaJseGJrFX7f5DzjQPthHO/dG/hb++NE9dHS7GlvG
         eDuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pW9Mlh00;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id r62si2441031oig.1.2019.05.02.09.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 09:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id t22so1300623pgi.10
        for <kasan-dev@googlegroups.com>; Thu, 02 May 2019 09:41:04 -0700 (PDT)
X-Received: by 2002:a62:46c7:: with SMTP id o68mr5390737pfi.54.1556815263742;
 Thu, 02 May 2019 09:41:03 -0700 (PDT)
MIME-Version: 1.0
References: <20190502153538.2326-1-natechancellor@gmail.com> <20190502163057.6603-1-natechancellor@gmail.com>
In-Reply-To: <20190502163057.6603-1-natechancellor@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 May 2019 18:40:52 +0200
Message-ID: <CAAeHK+wzuSKhTE6hjph1SXCUwH8TEd1C+J0cAQN=pRvKw+Wh_w@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Initialize tag to 0xff in __kasan_kmalloc
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pW9Mlh00;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, May 2, 2019 at 6:31 PM Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
> warns:
>
> mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
> used here [-Wuninitialized]
>         kasan_unpoison_shadow(set_tag(object, tag), size);
>                                               ^~~
>
> set_tag ignores tag in this configuration but clang doesn't realize it
> at this point in its pipeline, as it points to arch_kasan_set_tag as
> being the point where it is used, which will later be expanded to
> (void *)(object) without a use of tag. Initialize tag to 0xff, as it
> removes this warning and doesn't change the meaning of the code.
>
> Link: https://github.com/ClangBuiltLinux/linux/issues/465
> Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks!

> ---
>
> v1 -> v2:
>
> * Initialize tag to 0xff at Andrey's request
>
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 36afcf64e016..242fdc01aaa9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -464,7 +464,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  {
>         unsigned long redzone_start;
>         unsigned long redzone_end;
> -       u8 tag;
> +       u8 tag = 0xff;
>
>         if (gfpflags_allow_blocking(flags))
>                 quarantine_reduce();
> --
> 2.21.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190502163057.6603-1-natechancellor%40gmail.com.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwzuSKhTE6hjph1SXCUwH8TEd1C%2BJ0cAQN%3DpRvKw%2BWh_w%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
