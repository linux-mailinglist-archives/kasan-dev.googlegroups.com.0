Return-Path: <kasan-dev+bncBDW2JDUY5AORB3XNSGWAMGQEJYQJDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 8057381BD49
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 18:33:36 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1d3e38ba247sf10911025ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 09:33:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703180015; cv=pass;
        d=google.com; s=arc-20160816;
        b=xAoRo0pMoa0Tg6ZzIRHuiydHfdhxQmyvMop58Hl3yccMpoZftRcePgmnu7lK60QaMU
         M1UD+qZ3HuJeNYZFVdAsmy+m2fTZqoxQbp1GcXYUQX+/x9wLXr1jdw9gLHqdPZQPJ2Vr
         xAnqe86rvb1aPF4fCxd7GeLhU+lu3UCMBLoPGzrds6XuHPZfF78xUPkYcXYdCk99PHv2
         c8E+AVulTQOr8nPf2T3CL/qcBrPV4qw0m8hAyaT/x5nAbfUkhGPIR+hDJ2Z/7EnNxwvT
         PiYI4BwFK4aXGsLJkP8dPvQYYt/U/aPcbSq1PPQ6PohgCXJHW6MPJMb7f4Vf8xPp3Zkr
         1hFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CP1AtKYagcJqYE15DEmXc/Q7I4sLvBqzNcUwixoYCjE=;
        fh=CB4ptyjYu7VnqzlBYLJm816Cx+cYjKJLqHHW+myXDTg=;
        b=hQyKbBt3P6Sx30xsgwM0pQnM4bujSFRz3BVH/J7pCHn0XpUF05Ft6ZqNL97CAS3e9e
         cwj9w0JFmv+MA/SBuIU2LlCKZIjo7NklJ1GJeYqDZcnlGqrncez3VIWUdZGRZ04uZgDJ
         UQ5x68sdipR9E+uEjLYz6dJv50BlZwK24KyFSaXaHKRO/Y7R7w3hPNxOuCkVgmqcTMT4
         JG8YEmXWQDWM+ABNg647J3BQRhtij4M0tFH4K5rDbNa1JcAc6pCYVnAt+xg1fA8UmHeE
         6w0nmluq3vodZP0MoaARFyrZY9RubIe7axf0YyDeGjGd+xovlyIi8t5zfkwcux29uZYK
         +3tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lu++Cys/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703180015; x=1703784815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CP1AtKYagcJqYE15DEmXc/Q7I4sLvBqzNcUwixoYCjE=;
        b=hHlsVPqbTzxfrIrIcMcNAPZWOQst2ijeIqPx8vUNHpuXFhf+BOzgFN9/Q9JsR6QvV+
         RgLG/UGoFuEmZBMP6Lbo3hCFtudAn/xGpDGTUX6r8cAChbVo+HY74pwP3m8R2wu/o+s9
         KTnkrB5RMYj+fWvhgV/8FPVZfA5NsYU92TC86twOHTUMWLviChCI+Ad6p6lH+eoe/MA2
         DBY7dGFFGpPAP9lSl0b/KbAjoEJaJOUyXSKJW/6+zFBHIgpzA+Nd4XsJEa+s3daAONy+
         pnv1YAokly1KLQgNgVsPYCk7xKKRS1u+jXM9pRhUGrp84pFIkEsQfYlcxk55NK+qPRDY
         cN/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703180015; x=1703784815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CP1AtKYagcJqYE15DEmXc/Q7I4sLvBqzNcUwixoYCjE=;
        b=XQxvTDM/BI2s2vv6n8aR33tHFs0yFDcIKEA/vLhjYvPLLB8G0SaPRkxEU5FPKcnke8
         Ia2HhuwpBTYYrGsEGwiEX4DNZM8lVvJATGpb5QErrFOoUX0pcrNvnSyczeyDzw7kvkSn
         PYxAT8ZCAg4x04ytiZYlzxtcbrJJ7ZEPL9fvZt0F7wGNOtaWxiNLF9d3Q2SzpFlcrNwg
         h5cgq6OMImrWRIlW7gWuKBq7mLHRDNgCWE06pfIJJqcXfxfWdV3dLRrQimCu1lGUQXJC
         7b04IECAeJaHKD+Yqln69jxw3xccaf18gfqy29UGTImdx6tQBuISR983a5A+Kv3j8ve1
         +v9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703180015; x=1703784815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CP1AtKYagcJqYE15DEmXc/Q7I4sLvBqzNcUwixoYCjE=;
        b=aZ8yGpwX0UvXo/MHnUFQi7LdPDfpsAxObXdZ0+hCpjA2ZhKMiM+GnWkqReH5yKRwlP
         fOS/CZr5biSJ7VLFCiL6nlbt+DFlFblLrhg2sOTIJqFidXTs5aF31VD+SWoFDKVPxfz1
         gdnfIfdjnB4H9R/DguVK9YihmvXtCvkM6qmE392CamwTf+jsRzJjNZ5dv26UyW0Gp5uZ
         ZUAu3Ac2g9iBK7+2CYt2tc3aolxp3KoRPFgSU71QbYza4TtUCIC3Zknt0f64fanIlG6v
         z7R2ITFKI3L9OwzQyctsAdHsiP0Ac9r5D+1LGlAnskSwXzF3VCziM1IJvpssx41ytJt/
         Tj0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyLynl1un3UC+3X7AVpG57JHEdYySrIRRVTRUiLt5HQnQ4R67ty
	kFfT9qzlYtv73YYnLgn7jh8=
X-Google-Smtp-Source: AGHT+IEgjrT5pF0UTs9moVSm7FzvXdv+s4eJXeY2pDRLdGfP+5WTKccWv86LUrTLPNRb+8nfvkbofg==
X-Received: by 2002:a17:902:d547:b0:1d3:5b0b:b049 with SMTP id z7-20020a170902d54700b001d35b0bb049mr20646262plf.33.1703180014710;
        Thu, 21 Dec 2023 09:33:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce85:b0:1d0:54ae:202e with SMTP id
 f5-20020a170902ce8500b001d054ae202els959627plg.1.-pod-prod-06-us; Thu, 21 Dec
 2023 09:33:33 -0800 (PST)
X-Received: by 2002:a17:90a:fd04:b0:28b:e7d9:ce3 with SMTP id cv4-20020a17090afd0400b0028be7d90ce3mr76107pjb.98.1703180013650;
        Thu, 21 Dec 2023 09:33:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703180013; cv=none;
        d=google.com; s=arc-20160816;
        b=y6vWdsvHd16mt3nij/Ov4lvozs4dcqNHjLjIXORr52uhUjpqN1YvPclDvIwmcwumgd
         VlMuw5x0uo8VF7Q7RsCGvlUTQd0lREFcVWI4SMiFxqLK+i17GNoXKbWrAhW5EeBmNPXl
         jZBPC7IVshT4gN/5FjVK6xsdGKiRS6JbScgWCntBoVefr0Ef5fQ3/tnCG0blyhdzyEXg
         CDJI/y/Pu+2Lh1rB0C6Lpk1jqUFNWWgZY2QrfA3c+aVrYaLy5z/RJv5qnTWUuGnIfYRN
         xPDGyIGy4HLq6Wd11MZe5e7qZnhIED8O9TcHQsjFway+6vtIzauCIEtxjGsMxeTVjVE5
         6YBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=E1w4+dtGj/8F8JaerQ8KRIMdSrjR4dovsf8QQX0Vak4=;
        fh=CB4ptyjYu7VnqzlBYLJm816Cx+cYjKJLqHHW+myXDTg=;
        b=j2CmLbg5lhiNTDklh1YP9AgRC0mG/b2uH94/uncBl5Gv22mP6dakHJlA1BNzzDytHw
         OSWuxh0oE5ImfJ6sZkm0KAwJHK4iR0uRLU8Z+TeiYTd6lpbsTtUDEubRrnLFC/ZEQJEi
         /6EbdNxGxxyM97YTUe7PuGsGgAoH+DEwcFWCqWw/Vul+s7G66xal6x0rTNzrsiCiA4Gt
         0Y4nVlA+9L9R/VBglRg04jBVNigSDnaBDb60mipc08bkyZ4L7blgCsCPrBaIXhAObygS
         UW0EE7XoaXXv4A6tQPWVIrohsI3MbyiJGNTUoGIlCRroqfCdBN+2saI5Xxg2bWwRTgPq
         L6bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="lu++Cys/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id r14-20020a17090a4dce00b0028beeaca240si122255pjl.2.2023.12.21.09.33.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 09:33:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-28bf1410e37so687790a91.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 09:33:33 -0800 (PST)
X-Received: by 2002:a17:90b:46d7:b0:28b:e688:6b97 with SMTP id
 jx23-20020a17090b46d700b0028be6886b97mr95676pjb.1.1703180013162; Thu, 21 Dec
 2023 09:33:33 -0800 (PST)
MIME-Version: 1.0
References: <20231221-mark-unpoison_slab_object-as-static-v1-1-bf24f0982edc@kernel.org>
In-Reply-To: <20231221-mark-unpoison_slab_object-as-static-v1-1-bf24f0982edc@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 18:33:21 +0100
Message-ID: <CA+fCnZfO6JyNvf7Wt7sOBoPKTX_UGexuWpyvgXYq9XSJEp-dLg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Mark unpoison_slab_object() as static
To: Nathan Chancellor <nathan@kernel.org>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, patches@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="lu++Cys/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 21, 2023 at 6:27=E2=80=AFPM Nathan Chancellor <nathan@kernel.or=
g> wrote:
>
> With -Wmissing-prototypes enabled, there is a warning that
> unpoison_slab_object() has no prototype, breaking the build with
> CONFIG_WERROR=3Dy:
>
>   mm/kasan/common.c:271:6: error: no previous prototype for 'unpoison_sla=
b_object' [-Werror=3Dmissing-prototypes]
>     271 | void unpoison_slab_object(struct kmem_cache *cache, void *objec=
t, gfp_t flags,
>         |      ^~~~~~~~~~~~~~~~~~~~
>   cc1: all warnings being treated as errors
>
> Mark the function as static, as it is not used outside of this
> translation unit, clearing up the warning.
>
> Fixes: 3f38c3c5bc40 ("kasan: save alloc stack traces for mempool")
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---
>  mm/kasan/common.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ebb1b23d6480..563cda95240b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -277,8 +277,8 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>         /* The object will be poisoned by kasan_poison_pages(). */
>  }
>
> -void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t =
flags,
> -                         bool init)
> +static void unpoison_slab_object(struct kmem_cache *cache, void *object,
> +                                gfp_t flags, bool init)
>  {
>         /*
>          * Unpoison the whole object. For kmalloc() allocations,
>
> ---
> base-commit: eacce8189e28717da6f44ee492b7404c636ae0de
> change-id: 20231221-mark-unpoison_slab_object-as-static-3bf224e1527f
>
> Best regards,
> --
> Nathan Chancellor <nathan@kernel.org>
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

I'll fold this fix into v2 if I end up resending the series.

Thank you, Nathan!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfO6JyNvf7Wt7sOBoPKTX_UGexuWpyvgXYq9XSJEp-dLg%40mail.gmai=
l.com.
