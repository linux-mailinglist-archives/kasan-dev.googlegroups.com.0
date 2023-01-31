Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM574OPAMGQELUTAMAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9574B6828DC
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 10:30:29 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-5065604854esf161811387b3.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 01:30:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675157428; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ap4riJ0z0wUd+6zIdtGqzDWowO6tMa4VLpOuMibE/+uN1N4zQMPYtDIwyPHvkUMf2E
         VnLGfgur8gjyL4wCgSLHzfFPrtIy/hVC4WWmgAslD9hYUlqrvqCQAHCeTxwQD/X6THwu
         hoaXHAUetnaEe6MDRlVMAzVOWWWujigpxRsNjT1orxT+cxjrBvJ0d8tzswBGgCD5VAN3
         wXxpf5yOrhRVqoyHSF+B95tzX8QB3yalQU4fPj8E6xf9EP8b7gotRpK5alYkEti3gNDO
         4zKAWPozUEb+jDlDQ9bCGtKyHsWYcYTlPR9zvwyx4w7MgyXZbPUgrm+oMf5tmRFlh2uJ
         fw6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7pV5SXxAO9zLIvbCf3VBtoSy5V45b6n7sc7lLUtIqMU=;
        b=De0hcTqw/1CrfQObH8yDkPTgmef/Wn5zxeQqAkQ1My3JBnBDFeLdiefu4PS8wv/aTA
         iuzrC1HhN+AQALgmeuaydH3qYlznoB75g0huXdzXm6GsY2bND9LimmKVC2NriieLhalD
         HQwZkY0O3w+49WI1kf8pKdBb/E7BU63j65LtPEQjq0y0txrj7qYrxJeWMhpGdLXsuoqF
         PwZEcjScHpz31tw0sNSqrmJR++E0PGHFqaYND/e5AmSfVfUV3TX+AUPXVpD2cFANiT8I
         lZdwOeY34SYbG/guMQVloCuTtNoHFOH04BXoBktA63nBNxMgCbARxx9zD20H0ik4Is3R
         0nXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XRAHzGnG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7pV5SXxAO9zLIvbCf3VBtoSy5V45b6n7sc7lLUtIqMU=;
        b=Y0hXDY6F4K/nVAT3aeNXjO0EH0bwa8KwonA45TQl/TZRkbULBsP5uvtNuRbO1bGjHD
         RGHe+efmj/i3idA1g+1BKdjXNjSpqG6ltJHfjkxdaJn7gRvApLDk8MikmersCXbbtPcV
         M/3CUqxS8bm2aKRmdELSxJPjq1I6cGDWSHkd3uMZRRbouudRie/sMKnQ8tPlt5MQfXzV
         hSR/vac9YEdvB8C/1xnGcG615YtF7S6tfLxbmZWS9fmBly0ElNCk4DV8gg7fpsUnOgBj
         NQhEZRpykMFjI54GfLzYnUDKvRuDzAYZkuyP6ptgYcBiKo1Xwg8a6PDTHKWQkW8dBHrR
         ZwsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7pV5SXxAO9zLIvbCf3VBtoSy5V45b6n7sc7lLUtIqMU=;
        b=PvrPxGOop9+wbopT1Qto0RfOJnIXau9fHAbwhvefNoWVBI7s7iUL7kKkmImqqJ3wDb
         +x2Ktu2m2qMBVM5uyDF+bL0Cfk1c/qZqW+z6of3wGiyXSzNKR0JZJ/54uzdO5rtGbaZB
         HPg+zBsf+7xq+DWkjwYWDQGPgAX6T5wqiCIXOcC7sRoSXNDzY00wK7d2a/oJLJwzPPtr
         PX+b1nkI033T9NyfSuNXuMYapxPXjMYsDwGVfuIAbrWslNKw4qC6oi+Dmey/Rj3dZjsg
         KY4bQc/YjnedzdELeIJ9tRU19zUJwmAsa++CCOglRQ87lcR26OigyrWVlkdbFglCoUhF
         nzoA==
X-Gm-Message-State: AO0yUKXjSEY+g+VMfZ9hcuarmXq07ASW1+xRH9uFsgr0REpFL9tUK8sJ
	GBPOph3yyttEOoi5Ifw8Q9w=
X-Google-Smtp-Source: AK7set/s1eZmChGztvslLc+h7/Y0Uts+qzqaoqD9Wi847APLmJXPOOXKJWQcRswKI5Prsw5c8RHAKA==
X-Received: by 2002:a25:c04d:0:b0:832:37b2:8402 with SMTP id c74-20020a25c04d000000b0083237b28402mr292946ybf.475.1675157428124;
        Tue, 31 Jan 2023 01:30:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:c746:0:b0:519:ebb1:f8ec with SMTP id j67-20020a0dc746000000b00519ebb1f8ecls2078209ywd.5.-pod-prod-gmail;
 Tue, 31 Jan 2023 01:30:27 -0800 (PST)
X-Received: by 2002:a81:ed6:0:b0:4b2:7:d0cf with SMTP id 205-20020a810ed6000000b004b20007d0cfmr35917799ywo.33.1675157427508;
        Tue, 31 Jan 2023 01:30:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675157427; cv=none;
        d=google.com; s=arc-20160816;
        b=coguxksvm1yZZcEmdIuxshuWES/id+2b/wZV4P/rsXswk08oChOD9ZC/Iy08ACMvGb
         rYwQtKKu5IDLdsoYU9toD6JE0SRaJ9mc1zs4i3SxY+3RJZsys6tHRmfag+K+iMLqflb1
         Wot5HgrtEE7ru8BfDUFnrshilDLX14leXYLUdyG9S7SuXWlCJR/3NAfVKMw9pyjAZ6Np
         h3/W+plGCYo3VUoT3vSdAvzZHiv/ZCOizmfLfjJhOISgWvBHIoM3pCZ4DA7BGEveDJvO
         bDYRdw/MBhgakFVNeV7QCHWhT7Y+yvybnxcvC0OKrCpwF7Rx9ZSVonFnsX3G7yweYuyV
         YnAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cb4ZLvwVAqQMn3anowjzMX/KwREznkusXpss39hXIZs=;
        b=ObBn20PSv6FvmNBeTvSA2E6qmd6Lyvp+PxkTtm8vXuhz4ek4EKrZPBXu63raX3WVbw
         RCPr6z9wcA3U0re7D8suEmvpYev7qZzJoGdhZhizsO19jrXrt0AXHp0N1HR+ZmoPfHg9
         PXIWN90IptGtpSz4Z0swc3mLS2e/NVVvnY4Y8oZrYRzb97xua+d6RhVH1ble18gWuH5r
         0r9298cE6YNTFbnRhzo9sAWbKevgY3Rmwec4gNVQMhNAOzLXAWMlqpCqpNkJKMRpZMGc
         2w2wIXj6agZox99wgTdLo1pUkQU77tQPBseqMAm9F5rBxH0q5ZvmwZqlcPtARQe3p+Mc
         0Vzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XRAHzGnG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id bc29-20020a05690c001d00b004fa49c05aa9si2618917ywb.0.2023.01.31.01.30.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 01:30:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id g12so2813827uae.6
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 01:30:27 -0800 (PST)
X-Received: by 2002:a9f:372c:0:b0:5ff:91d2:ea36 with SMTP id
 z41-20020a9f372c000000b005ff91d2ea36mr6350452uad.43.1675157427073; Tue, 31
 Jan 2023 01:30:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
In-Reply-To: <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 10:29:51 +0100
Message-ID: <CAG_fn=VO0iO4+EuwDR0bKP-4om9_Afir3fY6CExKGRNad+uPLA@mail.gmail.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XRAHzGnG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> In commit 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in
> stack_slabs"), init_stack_slab was changed to only use preallocated
> memory for the next slab if the slab number limit is not reached.
> However, setting next_slab_inited was not moved together with updating
> stack_slabs.
>
> Set next_slab_inited only if the preallocated memory was used for the
> next slab.
>
> Fixes: 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in stack_slabs")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Wait, I think there's a problem here.

> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 79e894cf8406..0eed9bbcf23e 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -105,12 +105,13 @@ static bool init_stack_slab(void **prealloc)
>                 if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
If we get to this branch, but the condition is false, this means that:
 - next_slab_inited == 0
 - depot_index == STACK_ALLOC_MAX_SLABS+1
 - stack_slabs[depot_index] != NULL.

So stack_slabs[] is at full capacity, but upon leaving
init_stack_slab() we'll always keep next_slab_inited==0.

Now every time __stack_depot_save() is called for a known stack trace,
it will preallocate 1<<STACK_ALLOC_ORDER pages (because
next_slab_inited==0), then find the stack trace id in the hash, then
pass the preallocated pages to init_stack_slab(), which will not
change the value of next_slab_inited.
Then the preallocated pages will be freed, and next time
__stack_depot_save() is called they'll be allocated again.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVO0iO4%2BEuwDR0bKP-4om9_Afir3fY6CExKGRNad%2BuPLA%40mail.gmail.com.
