Return-Path: <kasan-dev+bncBDW2JDUY5AORB2V23GMAMGQETNDDWGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 870725ADA49
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:34:52 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id i20-20020a056e020d9400b002e377b02d4csf7839505ilj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:34:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662410091; cv=pass;
        d=google.com; s=arc-20160816;
        b=TFmmxvQIL03+Qkdz0RSKjlcWUEnfoQ87VsYAKPfgDjGwBtNrr4iSOtBc2kJ67dhRm1
         CmdEMUihwvesuEKRWNL/nh5V69ORPp7rOhc5yc6vxzWPSwD2rhu4/a6IwBhj+5duzCR0
         +m5xKt4Xq6or2o62FKGvNxmiUQwPVc40TjVtyfm+3/gWTWOdCPvUA02TcvbUGz0GDiXf
         W/ThL+PziDH5QIkXbNQW01sx+/pvPu9DG9aiYv4Mz4cPdVGwi9ZZgyAMiTgRzQe3Qlgz
         U/qbvRVGqdJOordI3qzK9PboQC/MvAQK/5q4oUjY1fgw1161gGVHi1ykr2mkez3ETA0P
         kJgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mjx5ZCN+Wx08Kn2m82AI4AqAt034LD4Lwa6egh1AToA=;
        b=yvPzxyweJt6rKtTGTljsKzb0EjvkaoNZlohApXt7E06wRCvXfXqnED0eiqj+EXv6df
         Q3AbsJsFT9L8RjOrvQbwH8EnlbYdfk7RxuoQW0WcElwH45GrpE5uKgl0+/7TE9S3E+d4
         oV5+J5cp2XvsLlPmYaX9ahyJwC7eTk4LMvvKQQiS6qtdruidXL1JsYQNp/79r7CBvBbV
         Jdx24RwwBxwYp1V4IKDNDbrweIBrpa1lemIjbbU2HQBT/s23QkFWxZybJSxwq0fiv8Nj
         0+mnjROH19/tLmvxrk6USaA7d/Fkw2msnN5zyehV8jhHqGdv9ammgU/I+SkA9P3M/OfY
         ZoMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aUO5ZddJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=mjx5ZCN+Wx08Kn2m82AI4AqAt034LD4Lwa6egh1AToA=;
        b=rcz66Vf2yvxMHX5hqSjLPdo7INmNXauorVn19TsycHjU85BhDfWiFslUL3OT6OYkxN
         26sfZAVW/UJ43C7Qe9uBpT8jDJdo2IlyNbNPjAvCQSqkttDXNiJiApJhxjA/5zQ2Jobz
         t9pSmrjwq8YWnuFpaOas7s0DXJEeiMpvz3R0dE69R+iUndHQZZEfIAa47rrVt0lz7jHI
         IherwwC133B3nB357ogWUKNVuB2d4ZtsLujFX3+4nS8MknyUC9tPR9tfoQt+hYV14KWS
         uv3gx3JJaxGVIAfsH0L1JccXLRQQWwxMkFDj+STT26jVIQh1eGjq5j8b9C2bPhpzesgE
         lt9A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=mjx5ZCN+Wx08Kn2m82AI4AqAt034LD4Lwa6egh1AToA=;
        b=hfsfaTMcgE3l+N6Miwgr+RXgVLkWTX3t531myswdEBUGzuWDWA/wPJsRXB8a1u9kMF
         nxThGzc+Vd9XZyBOfXRNredJjXLbWvXpSYfx/XKUAdyBKoVrocmcaJHZA2/it+779L59
         uv1Go1wUYD3Q+np0GgE3qOJaIHHXKpc0hGZAXZYmzYyGgxjnLA4a0vZpf66oYUIlAuBK
         UMCsyx79GqpPkM0+Au/yd0YKhCxsppBVAGWU8VVOnJKqNOFdw/nAof8Z3QwcqtbwNvD9
         2Psi455KzlkNoFEBUKygWAdVS0OQGATdUs4XSHzJCiAtbUkhcwkaKX90cYRtpeAXYxAN
         KUyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=mjx5ZCN+Wx08Kn2m82AI4AqAt034LD4Lwa6egh1AToA=;
        b=qqwroItm2NHKyF1+KoZLZPbjh518hwjVO0kRS9QTRVVxPqyBc2MHCVh5jocoOlOGSU
         Le0pcIDFzvbc2eshNQQqjsoakk/ZFqLUORCfPQpF4BMn5GvecuIMoqyLIvRFbOLMn5U6
         KL0tPP6GRGicC0kXAye2M7jrPQhNZbcn1bDLWWn0aswhzSwjkrhULap5Z98e31/9fHCD
         X/b3yD6yy/HKGl2NHb5HGbMIApcz8LnDYoFD7LkQ+7WzyKQpOv9ix/DU6Vco9tWiOjTl
         p/YmLbHgEOP2GTazcmfPVekSMWuJuyj5XBk6qvHEwQxHfQ+rsOa7x9pso5NBWC4UC/7C
         aoxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2jlfG1HGAkVbtpi7dFuagdNXDlCalgt6T/Q8THRVjIUOgaTTgV
	T1sqywRypa83xd2eL6Ulf9s=
X-Google-Smtp-Source: AA6agR4BUmWHqdbM75GMKOHuClhlEY4R5YSTJ3DWmdlaomBImYVLPB91HPjREui+hLOZCZ/qgywx9g==
X-Received: by 2002:a05:6638:3f16:b0:346:ca4e:47b1 with SMTP id ck22-20020a0566383f1600b00346ca4e47b1mr27282803jab.11.1662410090770;
        Mon, 05 Sep 2022 13:34:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7352:0:b0:332:109e:3b77 with SMTP id a18-20020a027352000000b00332109e3b77ls2725955jae.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:34:50 -0700 (PDT)
X-Received: by 2002:a05:6638:304b:b0:341:d6bc:7bd9 with SMTP id u11-20020a056638304b00b00341d6bc7bd9mr28079791jak.294.1662410090209;
        Mon, 05 Sep 2022 13:34:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662410090; cv=none;
        d=google.com; s=arc-20160816;
        b=tn3U58rrtP+nR3YcA6+BpNO0oUHsHuvfxN0wdX0Sv8ii/Lj2ybsRHJ0R+D04/ZkHkB
         WzDcfsCSIG0iTkHuTiCjU4MMc3kBumNzrP9DtsgxlsrIYqs1YCWAI0rA03bmIwkHvYQB
         4aAfWvnh703g1d2JVyE1+9LR0nX4w3ag/ynNOF30jBgAL9z+X2FgIEVQ5/tijnbFQuTi
         yaNN5/sAY0HHOfgEQWhsaDZ0wbmmSilUMZHSB0P6IS7sYbEJW02G00L2LCyTAkS4KGSj
         Ry4nw20j6BXfH8b2sGgaX2nFSVwv9JeOoAgtFJQ8KG+8nZIyPG3vpOBlGgiP4S9W2pER
         j21g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LWWc9wTEKH9JOgE9QE9gnp320f8DJyBjkMZd1oJSX5c=;
        b=m/vKOv/7I/hze2zta/Fnuo1FHP0AJIjDQ6yOO/3COp8D21F9dyusJxlFXxVWvSobFP
         5GuPSusAaTRFhWGO/haozV9Ia8j/rMjqenSVdabAE40w4pumQ7QGPv9npRC+dA4udm5U
         uYTQQeqQGxSapn9WosVNCsvM0dWSKW0ga65g9V6fqLUPiryamHuJygrHerNI/uuSTan1
         EZ++M92k34QGpXnkUHW4EYtr6RmfL4tlYmZHtqhUH8ShBdI+KZQaiPPiFNlDOdZ+krFl
         wwvHxZxy0RZEYP4YM4jpJCMMdQifLyUoPOyPyNjEr4tW5BltHew5bWIdi5jOoQ8n3D/T
         /QsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aUO5ZddJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id y10-20020a056602178a00b0068aba53032bsi738043iox.0.2022.09.05.13.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 13:34:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id o13so1232878qvw.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 13:34:50 -0700 (PDT)
X-Received: by 2002:ad4:5741:0:b0:4aa:4772:8835 with SMTP id
 q1-20020ad45741000000b004aa47728835mr2393789qvx.56.1662410089701; Mon, 05 Sep
 2022 13:34:49 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <4db564768f1cb900b9687849a062156b470eb902.1658189199.git.andreyknvl@google.com>
 <YurV+SDkF2dQCQLn@elver.google.com>
In-Reply-To: <YurV+SDkF2dQCQLn@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Sep 2022 22:34:38 +0200
Message-ID: <CA+fCnZeXEi1=fpNxUKLhwWJ=yeTFWLteKzDnLfwKFFC-uDbcHw@mail.gmail.com>
Subject: Re: [PATCH mm v2 32/33] kasan: dynamically allocate stack ring entries
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aUO5ZddJ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f33
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

On Wed, Aug 3, 2022 at 10:09 PM Marco Elver <elver@google.com> wrote:
>
> > -#define KASAN_STACK_RING_SIZE (32 << 10)
> > +#define KASAN_STACK_RING_SIZE_DEFAULT (32 << 10)
> >
>
> This could be moved to tags.c, as there are no other users elsewhere.

Will fix in v3.

> > +/* kasan.stack_ring_size=32768 */
>
> What does that comment say? Is it "kasan.stack_ring_size=<entries>"?

Yes, will clarify in v3.

> Is it already in the documentation?

Will add in v3.

> > +     if (kasan_stack_collection_enabled()) {
> > +             if (!stack_ring.size)
> > +                     stack_ring.size = KASAN_STACK_RING_SIZE_DEFAULT;
> > +             stack_ring.entries = memblock_alloc(
> > +                                     sizeof(stack_ring.entries[0]) *
> > +                                             stack_ring.size,
> > +                                     SMP_CACHE_BYTES);
>
> memblock_alloc() can fail. Because unlikely, stack collection should
> probably just be disabled.
>
> (minor: excessive line breaks makes the above unreadable.)

Will fix both in v3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeXEi1%3DfpNxUKLhwWJ%3DyeTFWLteKzDnLfwKFFC-uDbcHw%40mail.gmail.com.
