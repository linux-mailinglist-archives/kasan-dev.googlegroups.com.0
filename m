Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBE7XSMAMGQEW2EVNPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id C19B75A7796
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:36:42 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id x9-20020a4a8009000000b0044a835beeddsf6413474oof.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661931396; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Id3SN0KWBmyWz01dP3w1b76w9VOCrS8aNJxAV7PuN87SnTq7Fwi3QeikAt6Rd7egd
         qqtTJRtpbk+gL8G4nLMOdp7dKqICRjoKTZ2EpPzRm9KcGC1XTvwBfXsxF+H9xxaFYXGW
         uGlh9PQuNSgILFUCqoQMATBCKiXfg/JvETAjYr/cpeENbdlGdviUOPocDRc8bxa4YaXf
         jnRUlsBz/1vm4SfcSpGK52c/3lnTLi+OnQsK8GD5LXJQF2MmZktmJ8429RTsLErlkU9K
         kqZb8beGSHe/1Nt/1ldGUjo18HNrWpepuGOxU06/w17PSuxRjzHLC2PDfqWdgpMxo4mJ
         ebQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j+jZlI7JMAneQ7WaKEF68QM4smx5v5ycA3oQ5LBBbfY=;
        b=wgFoQfYfgx5yd+sdTmHxIkD0Jt4JPcCs3avH+6daaz6z11mEis4q3YQRxACyFBg9ub
         wgGrVcobw0Mriz7tfk9HW5JkTX6sgsnBl2OgubRvRGuLpXdZ+yvPiQvcWGawSr64ekKv
         yQS/01mZb+TsLeRpkfvlnNRN6TCwc9I98Ai8EkI/rbukOWvbMeqsg3go7nejEWmDU2k3
         Ghk+b8A01uJk5twMty2i2LA1KGM4Njvl5NYvJVWltzt/qVOSszSO5JRYyt11gUZVabmv
         X1IlJ8Y76StfuSxHRf8ApY7TEsfduzWhCdJxH4Adc2gSoMzZvZGkPm7dS5qtTrm9yyHN
         sp6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aVNtNvuF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=j+jZlI7JMAneQ7WaKEF68QM4smx5v5ycA3oQ5LBBbfY=;
        b=r5ipctIQ1cWx8+oNR9X4ckw0j8OifLyIs+41YhEjqoX58ORNE+6iI+indBdAuSnfGi
         ou6mMoGIx/eucf2Ta1VkmgaAz1L0JYqNGrc+TGVRifTZeIt9QH7dWS9g8lV4mtZwSvVy
         lM//F0u1Egd4znVaFADSNer0FkLG2xiKdlcXt5jfeKbG5osFLAyiMvrdyoKKGXAu2jEc
         HP8HmMjLnzg71PET9c0QKJD2O+O7g2BCewDa0ZUrOOdiaEMmPcZXl9hrh6WZrowt3PsD
         hDbJfd1PDXpYh2aAbkpF23d6S9x/1LW93zbPv+jbITwedvVseRssnV2R5jWo5UQNIzyQ
         0hTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=j+jZlI7JMAneQ7WaKEF68QM4smx5v5ycA3oQ5LBBbfY=;
        b=nL2e93IKhXyTW9KN0Kl5jQ7ScCgnsGbulkqq/BWE47pcj18+whZDrIpQNVnrW3kes1
         bjAfIGMceaWBbWfy3QITsJHXZiX18ttGecFOj4xG+03HxhOiwhkJDfY7E3xmI26pELCj
         eFbyKnQVJ3m1/Y4FZ2fQJx2Y9PRQp/4C+OfsfsxEGswizmf3XSDwa0LJui2g8wi9Kh2c
         xBYVRxL2GdeaRCZ1tCJjZTyxWOh1E8ORXk7abeqIVhDgffWpdG3u/Xuj4enBGAVfraaN
         3EKn6G8b7PRxk0RjVxPepbyFVxOEfqR6GpqIRQN+oWTH/wiZ6nlBnt3RZmqvgZaA5rg3
         +sHw==
X-Gm-Message-State: ACgBeo3LLovOTyuKQhcSx79Cze4SQOz9S0yKH6NTt79fubca7cV30akh
	mtS8f66tDaWD7DW+66hCtLk=
X-Google-Smtp-Source: AA6agR5Kk4gq7aMJurw6z78QkpH8e9GIUOKZuFyA6CJ2dlBfR11fBeNHGrYWot7gNKdrE0ygVE3mMQ==
X-Received: by 2002:a05:6808:21a5:b0:345:81a8:ab6 with SMTP id be37-20020a05680821a500b0034581a80ab6mr661317oib.91.1661931396536;
        Wed, 31 Aug 2022 00:36:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9d10:0:b0:44e:1e14:3ed5 with SMTP id w16-20020a4a9d10000000b0044e1e143ed5ls56014ooj.7.-pod-prod-gmail;
 Wed, 31 Aug 2022 00:36:36 -0700 (PDT)
X-Received: by 2002:a4a:b0ca:0:b0:44b:3c19:3170 with SMTP id l10-20020a4ab0ca000000b0044b3c193170mr8412384oon.75.1661931396067;
        Wed, 31 Aug 2022 00:36:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661931396; cv=none;
        d=google.com; s=arc-20160816;
        b=BVO5Z3JSSw8JhPwh0YQebrwKiyXHtwZgGA/exYFM7DK5qJw0LvmbcjFaamKr6h1jmP
         7pBemPbCZyiy+hJ+KhGjvEPnEgyOnidKTx8pFSzTeCVcRY/jar30bSRgZYpOZWE2juF/
         3lz+5+IGukbW+vXIhs9OV6ciOdCni9rjItGutfOJoQpSY1/6S5egbn6e1gfx1hDFc4u2
         M7d9BI+JpeaaxxoSbtKjtNSt9GW+9x9MjSVDFXw6YT/brBkHrdkQE4Tu5QmTa6plRG6R
         YMKqTcU4zQfaquYtUEecsmLcR+J3kyma9g/261zJjdDVo7y0MIVXG9I0LL4WRLNUN0Vi
         QuuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CiwUOjsI8eLOGXg0PzvmS8sm5Q3oJ41Lwox9FPpug3M=;
        b=HUZVK9cnSybFfe8CKDrc2EPQGNA5TzKbFww1Q6IA41+9Hxu0ISbjgN8u7b88vkVdWw
         5iNbQhXXhXTVFO2VXBoYrelmZWj0bQ4znSgg9i/F421xDbyljn3mBNMgWYCkqPI56DUu
         k0zF/R9CGsdxwpeRqcyaQFK1kQng+u1kpe2Ly5QCdHSyLEHTU5EKYco4fmNoVzPq9YXS
         kD36GjoOpKSowZKCOAW6DcYVWYDSlnP5l8wDKgP7b8LpXfP65ODT/b6/mwB389/XJs/7
         DpTwSC2oseIfLf15heqjkma2lRxrPGzITn4GRg8lC6P9elGOmwyWEsX5z4U9pcvmUO6/
         ZXcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aVNtNvuF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id u18-20020a056870f29200b0011ca4383bd6si1471050oap.4.2022.08.31.00.36.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 00:36:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-33dc31f25f9so299202097b3.11
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 00:36:36 -0700 (PDT)
X-Received: by 2002:a81:4a04:0:b0:33d:ad51:8efb with SMTP id
 x4-20020a814a04000000b0033dad518efbmr17956723ywa.86.1661931395663; Wed, 31
 Aug 2022 00:36:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220831073051.3032-1-feng.tang@intel.com>
In-Reply-To: <20220831073051.3032-1-feng.tang@intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 09:35:59 +0200
Message-ID: <CANpmjNPDce6n4scfgwYMz+B2qmJB6+v-2u+Xe5+koxaA=xsmWA@mail.gmail.com>
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip list
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aVNtNvuF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as
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

On Wed, 31 Aug 2022 at 09:30, Feng Tang <feng.tang@intel.com> wrote:
>
> When testing the linux-next kernel, kfence's kunit test reported some
> errors:
>
>   [   12.812412]     not ok 7 - test_double_free
>   [   13.011968]     not ok 9 - test_invalid_addr_free
>   [   13.438947]     not ok 11 - test_corruption
>   [   18.635647]     not ok 18 - test_kmalloc_aligned_oob_write
>
> Further check shows there is the "common kmalloc" patchset from
> Hyeonggon Yoo, which cleanup the kmalloc code and make a better
> sharing of slab/slub. There is some function name change around it,
> which was not recognized by current kfence function name handling
> code, and interpreted as error.
>
> Add new function name "__kmem_cache_free" to make it known to kfence.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you for catching this.


> ---
>  mm/kfence/report.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index f5a6d8ba3e21..7e496856c2eb 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -86,6 +86,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
>                 /* Also the *_bulk() variants by only checking prefixes. */
>                 if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
> +                   str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
>                         goto found;
> --
> 2.27.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831073051.3032-1-feng.tang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDce6n4scfgwYMz%2BB2qmJB6%2Bv-2u%2BXe5%2BkoxaA%3DxsmWA%40mail.gmail.com.
