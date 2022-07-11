Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWE6WGLAMGQEIAQUVZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id A40DE570845
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 18:27:05 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id 38-20020a9f22a9000000b00382735c8f92sf1075337uan.19
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 09:27:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657556824; cv=pass;
        d=google.com; s=arc-20160816;
        b=NQHt0ZyR3FWBjprPgSC40F31g0P8RK3ERZMgpFTnyTOlfIbiXsso38EtJAM6WTg8D+
         Ip3E+hM2IgRvQj6wnPFPUR3sxwQ5wh4bgP7oetdRsOYeIsg685nsEN+WBGikQD5fg+pj
         6ZJN+SFuLV+pKap3lwLdVDmZPSaMLqnnczH8nMGwxlquRz6EaQCZI2gBSViBDT9whYVo
         uBv5GlI3Vh9hsR/6m+7KP6VU069E+yUV0W3J3v3VrVztTwJswchCiSRtsd99GbmqhqfP
         x9fr2C8LD+SIHcbpW+i2eP0HibikPuhevxAvUYu065/oqoVHyLIzvcW36A5VqTxTpes/
         mGgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KelKfKE4denfjMOpiAjHkK/nT5GxytAHJsDy1EMFwKk=;
        b=bQrb+mR3b+ixngCDBWvuPlhQBh9lHKURg80s0WdZVh4AEVzCBK0Jxp5OAwITpjjus4
         MNUZ0rto7q1ysfZTDxa2cv+um/9qaPca6lSg6i9FLML9X1yP0PAtjJslx+9HO2EbwgyK
         laX7J75zCn8aXNf0nFdRMDW1pnlf0Kz1lsHDFP173WKMzb3j9MdFRGhZ+NiGKbdUbPQW
         oBRc/zl1aTJtV9QMZP0iEHpShGUfniGvhOXTlom9Xpok4JNypxmfLI/UWUJcnfvN2cpe
         q8EvW86YfW1bnTpJBD6d1KmCKwAgD2Moj+nNusLIc/NCWYI/jR9AdZnzSoryzDbbxYKe
         BOwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TEsjKApZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KelKfKE4denfjMOpiAjHkK/nT5GxytAHJsDy1EMFwKk=;
        b=IMKWe8ysWlpb1LZfVi3l07ZTnc4kt8aaoXa2K6nmZVVh/qdKW40GayAPG1nSUfd3Lg
         xSx6dSBHVLrIAsnE/YAxXVWoapXsMONVyO6get9Z3Y1SULdI+C8wknY9K5ng6qjFV0P2
         0rbRbgCSJV6YHx9Tu7tnVdEmayQDG0lv0F6kJ3WEIBHPLpeIqkCw0E3Gbk2uMUUSrU5a
         E7HcZhj6O4mexWIK4h/VxP7xvQaZUpHRMCx/6zdlYxiEGoTCqg/6X0SZUyuzgDSs0hq9
         ltUk18O40W7BJd5dxU9NbwGA1yRQvPovAdUDWgON0FmYxR/sF6DQJWY+BuySxmiT+sQJ
         3t9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KelKfKE4denfjMOpiAjHkK/nT5GxytAHJsDy1EMFwKk=;
        b=hC2JesOy7cMCfJ14ede+bbqiqJnmu/jF8v6iqcq9NGLbNB657AhJgIM480cYKLlnXT
         9UEHwA/jSK7lBxAdJ9/gzR3msukiUxuB5wDWmZKfO2ziHxqlhwlTWyM4XxXz+Gt/XB3B
         R8KvTjRkR9WCLZDqBPMROc1DeobrVyeIq9NrePNstspHnZyoylOvLt0lrLEfhtqmttwP
         Ld0q4Yn9RiKDpWhzAviKx5O50+eB8QjGHd3l8NYhYxDy7m3kcCdLf9w6QP1qJ628R8Ku
         25YKOIOzv3JyLpXVnbAdKKyBGpZaO1FtzskpCKwl+CjgSu412XH/lapHZ0VFhY0f5lfQ
         SADw==
X-Gm-Message-State: AJIora/eOcOYO5HuPbVbxcJV+6aLp6YZD6e9ZY6aBPtJkPQQ59Xh5BD+
	FRWX8lbUsaXrtrulwkn0S9M=
X-Google-Smtp-Source: AGRyM1tVfbcoBb54Wr9YDJ3D9J5Nderjo2c+dqW3ynW6Vjrc9U9elAvByy2nQS14JD5p3OSlPfiZOQ==
X-Received: by 2002:a67:f8cb:0:b0:357:3103:f704 with SMTP id c11-20020a67f8cb000000b003573103f704mr7210427vsp.47.1657556824559;
        Mon, 11 Jul 2022 09:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1905:0:b0:357:4852:339b with SMTP id 5-20020a671905000000b003574852339bls71186vsz.5.gmail;
 Mon, 11 Jul 2022 09:27:03 -0700 (PDT)
X-Received: by 2002:a05:6102:54a9:b0:354:522b:3fdb with SMTP id bk41-20020a05610254a900b00354522b3fdbmr7195681vsb.30.1657556823672;
        Mon, 11 Jul 2022 09:27:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657556823; cv=none;
        d=google.com; s=arc-20160816;
        b=bboaTphMINcSb1pCu4x7cqZH4yrXrsrRfF7PXz65muMvtW3qZMoSS90uahC477hnun
         2/2+87vOVuJdqx0zr+FWsOtoDJwsgeKEP2cFgEvyDFJuepCI6xoOGwrvD9ibsUSbmdVt
         Pda8Yds7/bnV1Xf+7b6TBiUM3PlZL9LYHOjnxTzsFj+dxqG3CSkC7YkyWuFsV51Ezc5V
         /WdeINqy8Q/ZqoIeQQ2635diAi9A2S/jpNLaU5A/vhHHJA5sEjCXqDYErnp8uxqScYMp
         LOfD3JDn/1XP/GJVpUKewkuzuCrNSily+aPUyzuGwzgLPriFQlJd4n8lpcTPj4k2ENT3
         bnUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MNiOG9VLTXfyIumAzSkdBTE4Ro/vczfTyGGlVgeFa4E=;
        b=ZbrTb2RnrgApJWA0ZrHp49Xveo0PX6KqT9HzPnsAfyICDN3tdgEJLK1egg0+D52mbN
         oGCBbgaXBUGbS3gpqyiCQ+JWHhaK7sj4viyd4peic16Fy+6Fbk7RXpsartosuupsC3AA
         QZLrfV7JQkx1Yob4UNZVRPyt8PcDZZ737NEABLrUUsyZnxWL4u0o0LOKGzpkzOlBkimA
         eaL7Zoarn9/uB7Ef4bq2wlIl4UMpwg9R7vpSLsdKkqmCb290PyOka8XDkn9l+9CJA/3S
         cXOFTkzGecESD800l4LqfwLLvUMP7b0GUmInrCNsX4fvPRDoUYDgf/NI0BkBnX1abaSE
         YPfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TEsjKApZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id i78-20020a1f9f51000000b00374cefbb1d7si56218vke.3.2022.07.11.09.27.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jul 2022 09:27:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-2ef5380669cso54488987b3.9
        for <kasan-dev@googlegroups.com>; Mon, 11 Jul 2022 09:27:03 -0700 (PDT)
X-Received: by 2002:a81:98d:0:b0:31c:921c:9783 with SMTP id
 135-20020a81098d000000b0031c921c9783mr20064789ywj.316.1657556823180; Mon, 11
 Jul 2022 09:27:03 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
In-Reply-To: <20220701142310.2188015-11-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jul 2022 18:26:27 +0200
Message-ID: <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TEsjKApZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> KMSAN adds extra metadata fields to struct page, so it does not fit into
> 64 bytes anymore.

Does this somehow cause extra space being used in all kernel configs?
If not, it would be good to note this in the commit message.


> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Link: https://linux-review.googlesource.com/id/I353796acc6a850bfd7bb342aa1b63e616fc614f1
> ---
>  drivers/nvdimm/nd.h       | 2 +-
>  drivers/nvdimm/pfn_devs.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> index ec5219680092d..85ca5b4da3cf3 100644
> --- a/drivers/nvdimm/nd.h
> +++ b/drivers/nvdimm/nd.h
> @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
>                 struct nd_namespace_common *ndns);
>  #if IS_ENABLED(CONFIG_ND_CLAIM)
>  /* max struct page size independent of kernel config */
> -#define MAX_STRUCT_PAGE_SIZE 64
> +#define MAX_STRUCT_PAGE_SIZE 128
>  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
>  #else
>  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> index 0e92ab4b32833..61af072ac98f9 100644
> --- a/drivers/nvdimm/pfn_devs.c
> +++ b/drivers/nvdimm/pfn_devs.c
> @@ -787,7 +787,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
>                  * when populating the vmemmap. This *should* be equal to
>                  * PMD_SIZE for most architectures.
>                  *
> -                * Also make sure size of struct page is less than 64. We
> +                * Also make sure size of struct page is less than 128. We
>                  * want to make sure we use large enough size here so that
>                  * we don't have a dynamic reserve space depending on
>                  * struct page size. But we also want to make sure we notice
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOYqXSw5%2BSxt0%2B%3DoOUQ1iQKVtEYHv20%3Dsh_9nywxXUyWw%40mail.gmail.com.
