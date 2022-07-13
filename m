Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNAXKLAMGQEQYWWNBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 70838573277
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 11:28:42 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id o200-20020a2541d1000000b0066ebb148de6sf8062612yba.15
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 02:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657704521; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihVZ0Klfb6FP6es70Nfjql5VrIFQIGlnV/gPGvcDKViYS3roqteNUDrg7qRC6QZLpZ
         r1VjjMF230jevK+nIBZQVy3qv/d2YZaQHImFMcR1bXEqeOnH9XurhoLNyOvJ5jmhWn7y
         BgVcAqYIvrtzEEnkVVbXlVPtkHjQ1dbhPgNT75drBTPu1NdDoDmaZxvxBYQLL0yB1jQr
         O6DtyYdKxxIkFy4sVYbLRRfidx7jNBTIvg46npO2QtVsO/n1WCttq5ZZPuNGNkSI4XGJ
         8Rr4kA3mgKGyy0f4d04ePKqheCSnVDN5NF7KCtldaAXWNxiOm+Ip6lP72iu7L8KwD2gX
         QFYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OmCDOPVxpjDImY4l6VLyhTVe+jGmgK3ND6oxQNlNktE=;
        b=wzQ7CH0qkzBpfS0y7uGNA4jZlxdtrSE9pYJR718UgHX1YvzGrmQWLQnIU6Nh4izX4L
         Psl/I3lPwrRI27HU9qcMMciWGMV2NAEu28Oe9+x6GN6hCvGL/CvZzg3RcleGgXC94jXF
         8PT+PkP7te8elcKDxAPgqPxByRi54KYeIqaRLrW03rvxNwF+YbdW3PVguJdXxR2owDWT
         9LdqxITg1ssiBrltO2ne8WXfSMKzvTVeOLYnKVK+hsdQE1Kum2bZDNmYkhH/P1I1uymS
         iwNuGXlisNzBaMtUHbqNxO5egAPH4YkFHV4ZvfRhUELYzJF3YkoRZmJyJc1gI80yjdbh
         MfaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WCXPC3m3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OmCDOPVxpjDImY4l6VLyhTVe+jGmgK3ND6oxQNlNktE=;
        b=LBe7xBOmymulPE5qkcsLlH4wvIg3Z/IQZGUxTYIUtqg5fKwl9OKHRe2XIeSl14ovJd
         t5djeiLqfqfGnJLOXwvywm8M8RUIZt0b11XPhk/UvlI9JejciiDKKhnGVRRkUTJdN7aB
         l7MJAYUBnYh/OMAqEu+yrJVmDGn61Q3uiCu8zJNNKUKwwqgmCCOIzKZlyqY3UkEPCMxr
         a3T4Q4atgx30ODCnRM92bPqBRPKZKfJuwxMPtT9eU4xJXbR+LLCeK7ZuSQgu4q0hrOIx
         vwightkPM2CYxVwjMHIZS2DsXim7Bbn/Ren5bcTiVi7qyj4kAEXcY/T4Xeg6vM2mYv1b
         Pf7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OmCDOPVxpjDImY4l6VLyhTVe+jGmgK3ND6oxQNlNktE=;
        b=o4dMLWP+4+6R1LnGx8wc+V/w7H4p22ezuUaB5Ax1cNw0xGeapUQByDNl5mV7RvRLU7
         +fcqi/8gnIVV1yqXiWeATkGQ59F/4mOdY5rWa8mcSVtYg22FtLHiG4/Cjr6hRpXi+Ih9
         cenMKIwLmIcVkZ+HZ3tfssbkkua919iSrIKOzu+TvCsyyHOjwbILcyBseT/gfjQF0u1y
         63bnvppcAEV+b3Wi7Pq3Rp1HuxkQpFI/s+d4I2OVEsYKXk4VJnLkop1h4uVkgYnYlOgH
         Zuj/cGqo/bx2F6AAwyuxSLaNRIDPFC7V9SbPIfenRF16OJKJGt5PErS7qVpHgBP4Ywwh
         JXdA==
X-Gm-Message-State: AJIora+BMXk+CcPgTX6kgB/IfBvOHhUo9xWhBN4FTbfsgCByyjwp50aN
	Yy9HCPcwGJsSwJYBrKRQA6k=
X-Google-Smtp-Source: AGRyM1vsN2NS92XZg6KCaiiQwsgAexeVJWyAwz/wWMDXZv4jclfJE97aRkgUPy97W/QwoNZ+eMdVSw==
X-Received: by 2002:a25:6f83:0:b0:668:b531:cefd with SMTP id k125-20020a256f83000000b00668b531cefdmr2588596ybc.495.1657704521253;
        Wed, 13 Jul 2022 02:28:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:dac6:0:b0:31b:a77f:6e08 with SMTP id c189-20020a0ddac6000000b0031ba77f6e08ls2408768ywe.1.gmail;
 Wed, 13 Jul 2022 02:28:40 -0700 (PDT)
X-Received: by 2002:a81:3a56:0:b0:31d:64e:f818 with SMTP id h83-20020a813a56000000b0031d064ef818mr3095988ywa.223.1657704520573;
        Wed, 13 Jul 2022 02:28:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657704520; cv=none;
        d=google.com; s=arc-20160816;
        b=JiyYuSXjvn55u/xBIauoQ5b0h/YSOcWhbq342VmNhjA9mVwHnCn/mXNA2mDsuwmjve
         X/wSqBkrp+IhvL710po+ZPhyE4k5h5rjfUd9CmhQrGZsoZH5AC1Pgt+mRjPmCnQTF6ea
         MYb7vnz4bcFS8FDA9ooa67Urvd39JrY85TnF2n1KYHxKMRb5V/afUvrX+xw2AzMzOc5V
         0AWoi34pPv+rczfWZkLwsjFpeeHL7ZXtxUJ1nUz2DexMUvZvUIyXh2dmAyt3eQOeUq7p
         udhCUJSPCM5bmFCvquKWQT302RWkjp3fuVBQZl1cuwzHde7WPjLNAXsKYnHbQBvo2lIl
         A4SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YLa+B7g0k4vjWxV/5/J/yQw4cNuAt3dnRpzqWxr+dBM=;
        b=ZMiMhXg0EYWCClIr7Hgexb1hjgca1cTNwkPw0SvZX2ha/8xPjcrhs7D4PfgFGX5w8o
         IKF++GsCcyLxfJhIww+HlmsyCITXa33ADvABtCHSpOIxDsTTrUnd+hx9hRcrrb23cVKX
         VyPTviFZUtdCKZrFDvASWsWP+wToEW0UDqQSObbDXFoKzQTeYLs2OXA0yFEgV5La/bDA
         pigbt8KfWf/Dy1bgLMy6a92iXeLa/+jya0ubDfZRJXDXZj82SyqzJLhLJmWcGDj8FwAB
         PmmO9T9/wlFDF4LTXcYoCf4kVDLzXRICD5sFQOq9agrET5hSrRzhAdBOsxOmEnsowiFm
         1APw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WCXPC3m3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id j128-20020a25d286000000b0066e6b723ed8si359731ybg.1.2022.07.13.02.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jul 2022 02:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-31c9b70c382so106457307b3.6
        for <kasan-dev@googlegroups.com>; Wed, 13 Jul 2022 02:28:40 -0700 (PDT)
X-Received: by 2002:a81:5dd5:0:b0:31d:c5ac:e3c0 with SMTP id
 r204-20020a815dd5000000b0031dc5ace3c0mr667093ywb.264.1657704520206; Wed, 13
 Jul 2022 02:28:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-20-glider@google.com>
In-Reply-To: <20220701142310.2188015-20-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jul 2022 11:28:04 +0200
Message-ID: <CANpmjNNmZpw5P4y9XLT-GsfNOegNcQD=fZLFagHW=XsDqF2fxQ@mail.gmail.com>
Subject: Re: [PATCH v4 19/45] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
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
 header.i=@google.com header.s=20210112 header.b=WCXPC3m3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as
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

On Fri, 1 Jul 2022 at 16:24, Alexander Potapenko <glider@google.com> wrote:
>
> This is a hack to reduce stackdepot pressure.

Will it cause false negatives or other issues? If not, I'd just call
it an optimization and not a hack.

> struct mmu_gather contains 7 1-bit fields packed into a 32-bit unsigned
> int value. The remaining 25 bits remain uninitialized and are never used,
> but KMSAN updates the origin for them in zap_pXX_range() in mm/memory.c,
> thus creating very long origin chains. This is technically correct, but
> consumes too much memory.
>
> Unpoisoning the whole structure will prevent creating such chains.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
> Link: https://linux-review.googlesource.com/id/I76abee411b8323acfdbc29bc3a60dca8cff2de77
> ---
>  mm/mmu_gather.c | 10 ++++++++++
>  1 file changed, 10 insertions(+)
>
> diff --git a/mm/mmu_gather.c b/mm/mmu_gather.c
> index a71924bd38c0d..add4244e5790d 100644
> --- a/mm/mmu_gather.c
> +++ b/mm/mmu_gather.c
> @@ -1,6 +1,7 @@
>  #include <linux/gfp.h>
>  #include <linux/highmem.h>
>  #include <linux/kernel.h>
> +#include <linux/kmsan-checks.h>
>  #include <linux/mmdebug.h>
>  #include <linux/mm_types.h>
>  #include <linux/mm_inline.h>
> @@ -265,6 +266,15 @@ void tlb_flush_mmu(struct mmu_gather *tlb)
>  static void __tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm,
>                              bool fullmm)
>  {
> +       /*
> +        * struct mmu_gather contains 7 1-bit fields packed into a 32-bit
> +        * unsigned int value. The remaining 25 bits remain uninitialized
> +        * and are never used, but KMSAN updates the origin for them in
> +        * zap_pXX_range() in mm/memory.c, thus creating very long origin
> +        * chains. This is technically correct, but consumes too much memory.
> +        * Unpoisoning the whole structure will prevent creating such chains.
> +        */
> +       kmsan_unpoison_memory(tlb, sizeof(*tlb));
>         tlb->mm = mm;
>         tlb->fullmm = fullmm;
>
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNmZpw5P4y9XLT-GsfNOegNcQD%3DfZLFagHW%3DXsDqF2fxQ%40mail.gmail.com.
