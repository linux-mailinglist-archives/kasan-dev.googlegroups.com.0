Return-Path: <kasan-dev+bncBDW2JDUY5AORBYHDSWPQMGQE33ZX5ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F0D3691326
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 23:21:22 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id bi31-20020a056808189f00b0037804b06dd1sf988956oib.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 14:21:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675981280; cv=pass;
        d=google.com; s=arc-20160816;
        b=sHYq7UrZOIOc0DNXV5NPVD1c7hR6S3ehsaXry7K72MsjbPqaPf1WPQiu0IKRp12Aww
         HPekVKaELOuLpDKdifRbBaCyWMUNDIeF3+fsE2cxEwGyOzED38ar/SmW1eQ/dF5btENE
         WP4jtQ7UlY7HUIUZeIGfxVmxNoY8Jl9M5UmDGm9nXjhFaUwHLKb1QZu2ncy2BJNCMyWC
         236E1a6yvjKAxjp5N/ANaRi81zowpTsJ8fzfvfHSO8GPq/VnpNYioZLJvbVX1vVlpuXu
         6ZCCXtpeViW3T6BM8/3I/DHRNtmbCyF2wlDMyr6ydan9QWmyztgNTqX6AS+2JDFMqs8k
         jRVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rnwsH0t+RVVvMvYFS5V5XiVxq5EaWtn/M4NF8skuhug=;
        b=j4Qi5PUfPgFDm0cA8Kg96XDA26Q8mERI8FQMz2QCQuOwPqDWq+s9Eh6bz9xWkQo7q+
         DEdlgqtlT7QLK3BleDngA0Uua5AWSip2KGKcBT+XwDZBLNIzDtUwIx+priToh4SSXZzR
         7iLBeN1GqB8reI8Vp+KTbyg+m2st0nljK4In717qNeq/dLqfOk8GFmpeqZxCTvNpq3K1
         a5BKwm33pg8WvhaHXkOfGduEZvmwBzlc3cjzuDL7ayXfmE4oSi3W0ZUxyaa5sy4ZtaXe
         rptkZtBOFccyKioa5kxxugVjpGUdb9KLUPWOVllNGqJvC1OWh/L9Rq4Z1k0YGvOjuVNC
         XO0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l4GZzGUs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rnwsH0t+RVVvMvYFS5V5XiVxq5EaWtn/M4NF8skuhug=;
        b=Kr3i0cs1xEdjiRMHcGEXZ5Qp7Zym0Y+zVJnWo01tpjj3uVxV3NTHJHzZcG8AZMC/J8
         OcXFhCsK3KfYbfoI97T38u3GijBpF/bWiuKsxI0Jbsp+XeNmUcAL0O66tbmzbvqP1EOP
         Qirf9nx7dMfDQ5jnMdu2AhdXdJWgZ2UpcE23LxInXpVnDK1RB7ye48Iwm9tc78pk6/c3
         N3A561MeNu3f3C2vEMmlmIKNzaE5w0ISNwfhRkw+JQTcaNHwv04ULVCJVaAXlFeQTfPi
         18YNnX2SEShJ4ASRbf6zLngf7eoGKpDDzdg73u1Zq3GZ3efsHxnEa9rgLLIvLuBAOAo6
         CXLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=rnwsH0t+RVVvMvYFS5V5XiVxq5EaWtn/M4NF8skuhug=;
        b=Pgt0coNKCSzn/b+KgnOLKf8wKDeZDdqeAP1zcvaBvUlswv5QmcrdYatPyBZRwH90rR
         btTo6C6Bw4h6eUgFoBZgee3muy9ufwWfKUCzGBWk8/H82/T5huG36dq3Sg+YvtOYn0zk
         NU7gc2QYhjhEPiEQJCS3Nl7Q83lPsrywLRulW24L3tLkM1mwT893KDJB4FGyGC2vYNKF
         qtljxKTE7e7Ke4SeEngg1nT2RW/4AriBoMSyLBh7DoF4xHhTknaZ26T7ZQNLZiof4wmn
         ZS6nM6VdeVWaJOWCq15ecfhcJLlBOtpqeDL2EchU5HbacTPoD07SPe0jebMMTfjX2RV+
         TElw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rnwsH0t+RVVvMvYFS5V5XiVxq5EaWtn/M4NF8skuhug=;
        b=EPbfOJKyAubU8Xtc0KruS/+y/p7ykt2hPk+F+bz06bKAa0HOOPT2WZDEc8KQABW38s
         jTVfc8HPveUQa2HtMoZTYmZWALDe/ve+spPloa2dmD3nTsEY3XoYX/S6ibX5GsE5woaY
         gGhjEEh/nfIXU29YQJcysieXW6hQy2a2f7mAsAyGSaeGaJMkpg/3ch2c1HAIqY93XPfM
         IbRUJDJfeFnURB199M30+Lz4s3y8vpX3/tPIsXYNMsP+fNnYP91Q1nTnj9GWXvfmIwqL
         BaTQDYJPchYWM/xmmSnKR51nqwSFkKfICsewGVtOpY2XuBhL/SYIYdTvps3D4QlVuq3e
         Vxvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXD8+IdkT6itbs1aSEdQEN1G/BUpDOmtb6Zy1VCFUyl/s+JvMNU
	vZESq6dNcpm48BXi0MRcuRY=
X-Google-Smtp-Source: AK7set98fNZj1+bOvAez/lUT73o0SA5je39fhLnIdOoqpY5mr4Cnps9Hi+gqfjivKYRBbtnLbWlqSw==
X-Received: by 2002:a05:6808:95:b0:37b:4630:961d with SMTP id s21-20020a056808009500b0037b4630961dmr910539oic.246.1675981280082;
        Thu, 09 Feb 2023 14:21:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5387:0:b0:68d:68bc:8d10 with SMTP id w7-20020a9d5387000000b0068d68bc8d10ls523302otg.4.-pod-prod-gmail;
 Thu, 09 Feb 2023 14:21:19 -0800 (PST)
X-Received: by 2002:a9d:734c:0:b0:68b:daba:9b2b with SMTP id l12-20020a9d734c000000b0068bdaba9b2bmr6487849otk.13.1675981279596;
        Thu, 09 Feb 2023 14:21:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675981279; cv=none;
        d=google.com; s=arc-20160816;
        b=AyN0ic0cSmw92nPnlWCmssTvwvCg8LPWQUSgH9Iq277PEZlw8IQr+hvuXT50fLeyAA
         qsaW8qROWJfnzq0lLLCqkB3M3QTILveqJLCQl2s1R5xEfMR1MvnUWH7Jw2BthTsKozeO
         fFQmCURzWw/JtiRxWyYVKoNN95pD4KSTIhMyek4fRO1xTkFRggjTixAeEXPEEYrf/j86
         2OncY9yz5UDr40RQV9u8J+AMwK9IhRHsfH+MPmXKFhEiKfI1rWI/sn9oLMtjxqVaBF4q
         X5Wefx+jBxhTs7p5ea3AJUzbPavH+VRuqsABI5u9YsdOCPaLjIxpm8lVCxE/i6TcFY7g
         r1qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=INi0TWgkRSLsbjVpaGDFPzQPHb0f2T5aCT1XYe2Z1mU=;
        b=iNElgANLyxt0JnG+pn7FRdWZozOaNDhgTbomWfLMEpAJpxWYnD+KWNoBYkcyYr2Az2
         iNOF1HOAW1D9PTnqi2f16a1XoYOn6ZPXCL1sW70+OMniKJz8BAeBPw6BM+5/KtaxhkJA
         dfAyZoecCI+b4EoqYLUPIlk+cttWPN7tzGgFff6MKPbG1EL93JBT3pp9lNUPBdemlNDW
         V9IbRfhTEUfvXzGVZopw8JGfa0EGeSUes0iEYJRntm/uFzwAuC2mfGD0sQZkjmI+xBHh
         kA12zDp2Fg22GafeS+n140gZyujL1rirkOLR7vNufQBHBL0TBBX8z5zSxtKnC+nXGBbg
         OYog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l4GZzGUs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id bx21-20020a056830601500b0066e950b0580si479538otb.4.2023.02.09.14.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 14:21:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id s8so2516018pgg.11
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 14:21:19 -0800 (PST)
X-Received: by 2002:a62:79cf:0:b0:593:b73e:49af with SMTP id
 u198-20020a6279cf000000b00593b73e49afmr2777705pfc.24.1675981279155; Thu, 09
 Feb 2023 14:21:19 -0800 (PST)
MIME-Version: 1.0
References: <20230201071312.2224452-1-arnd@kernel.org>
In-Reply-To: <20230201071312.2224452-1-arnd@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Feb 2023 23:21:08 +0100
Message-ID: <CA+fCnZfKAF3AF+m0_Jpv8Di3G7ZOLe5-TBXuLiASCC7y1Onjsg@mail.gmail.com>
Subject: Re: [PATCH] kasan: use %zd format for printing size_t
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=l4GZzGUs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::536
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

On Wed, Feb 1, 2023 at 8:13 AM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> The size_t type depends on the architecture, so %lu does not work
> on most 32-bit ones:
>
> In file included from include/kunit/assert.h:13,
>                  from include/kunit/test.h:12,
>                  from mm/kasan/report.c:12:
> mm/kasan/report.c: In function 'describe_object_addr':
> include/linux/kern_levels.h:5:25: error: format '%lu' expects argument of type 'long unsigned int', but argument 5 has type 'size_t' {aka 'unsigned int'} [-Werror=format=]
> mm/kasan/report.c:270:9: note: in expansion of macro 'pr_err'
>   270 |         pr_err("The buggy address is located %d bytes %s of\n"
>       |         ^~~~~~
>
> Fixes: 0e301731f558 ("kasan: infer allocation size by scanning metadata")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e0492124e90a..89078f912827 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -268,7 +268,7 @@ static void describe_object_addr(const void *addr, struct kasan_report_info *inf
>         }
>
>         pr_err("The buggy address is located %d bytes %s of\n"
> -              " %s%lu-byte region [%px, %px)\n",
> +              " %s%zu-byte region [%px, %px)\n",
>                rel_bytes, rel_type, region_state, info->alloc_size,
>                (void *)object_addr, (void *)(object_addr + info->alloc_size));
>  }
> --
> 2.39.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfKAF3AF%2Bm0_Jpv8Di3G7ZOLe5-TBXuLiASCC7y1Onjsg%40mail.gmail.com.
