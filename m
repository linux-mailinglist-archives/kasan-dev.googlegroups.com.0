Return-Path: <kasan-dev+bncBDW2JDUY5AORBSUH66DAMGQEUTHCZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 70FD93B924D
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 15:31:54 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id v25-20020a1cf7190000b0290197a4be97b7sf2079781wmh.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jul 2021 06:31:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625146314; cv=pass;
        d=google.com; s=arc-20160816;
        b=BQcC8y05x7c/WRrhGv1QCIQ8FFdW23An+SUiRRuUZGMzw3lIsh5BXwtlAjf7S1VsZs
         AZ16GVOKKmEZ4XwLBr+pNuxJXqnRdA8Bc84XXKyuPlD4KuvzXOcaDkslYT7DrSaCG077
         SPUY40ZYQX3tcWVbGbLnW9xjfS7tx5nm7H3/IFSJNjexTjl65FIVUVZyCMMIeaSClz6b
         WhghG7jeQLlZMc9efqmXhTItF1sBUD0kVmtZjheXL64YGOCQiyxfUd4tUv5KRaCZeeeN
         eJ+NlMbY63qnujqcncu4PuECxPnzBlNzgt3CZPHR3yxtHNZU81FPzAMt5ML9wsl9cYA2
         E9Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bClyUtN2iO+Agoe4NwoKyl+eZ+EyxQyji5qqH6b3Gas=;
        b=ksaRSRP3YkJkLV37ZiKYZBUFYhUSRuUbsILUBoA+HWZjfGdWcBS39xnp0uvnvEYwVW
         s3IaLpmSuFY770RzEvTJskQp5rnQx96lNYYoiD7/f9808XzJUVRBldf8tGDkd6Gm5ex+
         pdyC4PS5HIL4LYZsJvOFAkdFcQmYiVWHTY5wvujNNOnTp1OtuuFh2b/wAaDNccYPqrbV
         jeYRAqHgAW9YyGdYgrJ3q8MCNygNrvtUtw7FFcpj5QKfHAJEJ6zSnOSx7tTmfAs+Tww9
         LabJ2olm2da2qftf0YsYDm9DQXAVIlcHDfpRrtK7CLNj3/Ab4kOx4eamFsJkgAToNSkh
         awKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rPkrb7S1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bClyUtN2iO+Agoe4NwoKyl+eZ+EyxQyji5qqH6b3Gas=;
        b=CbZbb67EGg2Ri6G8NojGDcGp87WSAQbvaYAbLHDjejl4uLKFMUh4AH4C0mGGxFyP+C
         oCQTUnM+vEAHo5evatTy0D6/TO99+Px6oFtkYd3VQa+vD7VmNdrUdCgervVvsuGQA2MH
         AIh4tfZpV6w73XDMuwO15V2LE3bDCy7ErlN7bph63IqRLv3utoOx5YhMNioeq/EcjwZz
         SwKpxoQq9+vOYzifeWZWRG6ww5HRdjp11E27L3pUBUgzF4lt+cefQb616PvdNRBxu/P9
         mRTe0KZG46BzrA5ZTw1sXnZllKXfyvLqnACHlHh088b3w7bWpPSGPOl5/IYiaXzRVBFS
         VcCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bClyUtN2iO+Agoe4NwoKyl+eZ+EyxQyji5qqH6b3Gas=;
        b=LHRJQlTxxoqw59dUWFK1gUtiZK98vN72HQdfwWlT9cFl90gyaXiLS+uaBdDt6IqW3X
         NFd135/+FDHrQuiQ02vEJehYOZu+DXeUcElE6wZ9HmYZn8fBJKL9vhF92+7i0BpwU9p4
         KRXMoPIuJLohKYUxj+sGB9HNo/SqYKNopIDI5TdiAg8VebbgTn1/KY7wzQelYFx9vmbS
         u5RJJuhqVKGgUx8JywqPWUsqll6HUXNCqhcyFsR2oDjAMoxzBrS33nOOv4YQ00JQ/q4F
         orw7C9k6zaEqoRT/Z3JOnvq5oFgQOwde0YIPVExpQTIMFnvnoxv8IU4WwjjOUYU1nk19
         PCOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bClyUtN2iO+Agoe4NwoKyl+eZ+EyxQyji5qqH6b3Gas=;
        b=Kf8962bIwnkPSqMCrdzLacFe+T0Mk3ujm68/YS7nCbdD3MtCnPeQnkz5LeIWG+T9Eq
         tcEY5keZNx4Rt2mExi01V1Q0bRHASgDT1c/RTp/qU3QtCnDt2Jq76c+kJ0OrbHtAaqoh
         Q8VsQqe4BguYeid0Qs7z8sEv5kjos/swG9drFJGuUtETIjfHPLm4bcukf1UMomzjj78F
         vTD3GSxw8PVliXD+UQ/W8vRsbMXmQmfP9AXO/XUXjOd9HdN98pPrZMgDdhRZEk3Kpmkk
         n+JT8LKlY7RM0fXUrDZivCRQQdhaNmXcVZGkMG1fHX2BbY/3IRe4JLVgnDJ5ZHgRIZP5
         BN0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bnyhWjQWpE3PhBpZqBg7fv+8/vMNiNZJq16nNCnrMPYsVTdjt
	qa5jxhbpgi64BRV/OjWIx8E=
X-Google-Smtp-Source: ABdhPJzZsmOMFE3hFwW31/WCwRdAA8eRk98XB1CYhBGJO+xqNZ4UZDXnct3N4982BgyXsHQC9GApsw==
X-Received: by 2002:a5d:648e:: with SMTP id o14mr46623774wri.5.1625146314203;
        Thu, 01 Jul 2021 06:31:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ecd0:: with SMTP id s16ls1146505wro.0.gmail; Thu, 01 Jul
 2021 06:31:53 -0700 (PDT)
X-Received: by 2002:a05:6000:2c4:: with SMTP id o4mr44674456wry.79.1625146313416;
        Thu, 01 Jul 2021 06:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625146313; cv=none;
        d=google.com; s=arc-20160816;
        b=YErhPrmYdq4iiXgHlZTR9ddfIgemFUF50JXw8ut5vLYWlSUKdsfjx/gQA0S4c0/zSU
         UPBMBHAsHStIF5rq+ityrHyTOi3hBL3YmUh45YgRIR+XvT0TkAtKiIq7RGFEskFVVqa0
         PgLDX+/M2gRvmnKjvzftUwd3aB5MZODI9j41g1ytIrZqrOf+ljiBOeNWZFCYGKSz/D1o
         HCZy29JNt0by6VgXq9nnCidVe4LXiA5nLPM1e1pkri9JpJyPIpOrV6NQ1hs6sBY6NVvG
         bRvnFCdfZ3TGUlvNjmNx5UVSBVd2z6dsFsGNMmMnlbdBkcJ9o+MKzc/LjEKRfGnvtBIm
         nm0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F9xHPQXfeX85p/WzrKNX5asqql2B/nD64WETM/hhNus=;
        b=FWGcBagHOuIMrP8CieGChlDnTlpmMQeX5VnRYJEc/8HCtDw674mrZMntmGLtaIKV/C
         DouJGwDchz7WRLvUqBaMW3yV435BLmDgprXGzvpHIQDo/sp6KLYwhw2IS/mZTQeEigcC
         2yqHujBtxxtQyvfmA7ULZfEDmmwkVj6s9jt5gSLENWl2icuMk5J00302Urb3VXyHmzZy
         aLGSBQcvdpsR8G8IOk3qf0EiCEzpRHSSK8yzkU9i/zl8vaWpXH2fbTu4t4YpiX8fpVaM
         i+n/gPXUtaNLreM7fq5yDLUfit5cZjO7UdIzx13Qh+5k1P2yddaGKyW7ZVmlkGcVz/CT
         1qYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rPkrb7S1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id h15si755226wru.3.2021.07.01.06.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Jul 2021 06:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id b2so10410697ejg.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Jul 2021 06:31:53 -0700 (PDT)
X-Received: by 2002:a17:907:9f0:: with SMTP id ce16mr42484016ejc.126.1625146312962;
 Thu, 01 Jul 2021 06:31:52 -0700 (PDT)
MIME-Version: 1.0
References: <20210630134943.20781-1-yee.lee@mediatek.com> <20210630134943.20781-2-yee.lee@mediatek.com>
 <YNzCVxmMtZ1Kc6XA@elver.google.com>
In-Reply-To: <YNzCVxmMtZ1Kc6XA@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 1 Jul 2021 16:31:42 +0300
Message-ID: <CA+fCnZcPXLZxCVAk2Cmhfvov9KNGxALQuWun_yKf0O+q=rbnfQ@mail.gmail.com>
Subject: Re: [PATCH v3 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
To: Marco Elver <elver@google.com>, yee.lee@mediatek.com
Cc: wsd_upstream@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=rPkrb7S1;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b
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

On Wed, Jun 30, 2021 at 10:13 PM Marco Elver <elver@google.com> wrote:
>
> > +     if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> > +             init = false;
> > +             memzero_explicit((void *)addr, size);
> > +     }
> >       size = round_up(size, KASAN_GRANULE_SIZE);
> >
> >       hw_set_mem_tag_range((void *)addr, size, tag, init);
>
> I think this solution might be fine for now, as I don't see an easy way
> to do this without some major refactor to use kmem_cache_debug_flags().
>
> However, I think there's an intermediate solution where we only check
> the static-key 'slub_debug_enabled' though. Because I've checked, and
> various major distros _do_ enabled CONFIG_SLUB_DEBUG. But the static
> branch just makes sure there's no performance overhead.
>
> Checking the static branch requires including mm/slab.h into
> mm/kasan/kasan.h, which we currently don't do and perhaps wanted to
> avoid. Although I don't see a reason there, because there's no circular
> dependency even if we did.

Most likely this won't be a problem. We already include ../slab.h into
many mm/kasan/*.c files.

> Andrey, any opinion?

I like this approach. Easy to implement and is better than checking
only CONFIG_SLUB_DEBUG.

Thanks, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcPXLZxCVAk2Cmhfvov9KNGxALQuWun_yKf0O%2Bq%3DrbnfQ%40mail.gmail.com.
