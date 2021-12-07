Return-Path: <kasan-dev+bncBDW2JDUY5AORBG7UX2GQMGQE6ZJEPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 81F7F46C3EF
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Dec 2021 20:46:37 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id mv1-20020a17090b198100b001a67d5901d2sf2233198pjb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Dec 2021 11:46:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638906396; cv=pass;
        d=google.com; s=arc-20160816;
        b=F2JlyDbgILIo3ISago7sakhPfYo/Eik+c1/jdGcBpax18kIqO7BQ8IsoCQDFo/Q3hR
         Km9FCNwdUIw2c1Swrv1BkV0cbOaxSnEqz8o61Ejtsr0Ga8uUQ/i6FpLeBdHyANTAQ2AE
         X65pWZNFyd+rg2FJPxF0QzFaitRNmMCOdKYjG+VoYqOckmo+YcpIxqZjD7KGocA7vh9f
         uormNWt8/K4P50qtWRHd1eh78z5hzyvWVIHobMW9GI73+1bFzQW8f5ekJpIbf86gD8VS
         EtSbhkzjtVwljLSxhbkc/YdFlQ8rqVwNlmmueTR+tOE1CEBMTRF+Q5higLmRUxXuUBQN
         n5JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lGGDeTTdPMhLgyPnToGeF+S6yOE73w26ZRuj1R0C0vk=;
        b=smRwQDu3XpWs/6A/FQtvlr1CpCrM+47LZ7c/gZ73n+5S1K0cFlY8FRvcD4pEqomdYN
         7EIW/ALGs/om0ItrRUc3HW8WQL0XU2FcsuWIHmEdJoNYMCuM5ggImY3utGiWJvjb9QV5
         bcrtdY1qV0BPoRPQV4dCRhtmpfrWWoOcNKcwui8dEkyGHAJGVYb638ti3/ditVes/cXt
         6MdsteeH+R+nzbd7dnibfZkkAJsxVwfy8bXuLo1ptdc1S4P7Fh5y9M/Dm+rwJzHjOdLZ
         i5uOTUXeS6ZFl2E9DdnhP60oY63oMFA6xRBVIeRhPauBGpiFrwlkRT1+8kR3y5sDwyQf
         bo/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kbeI/w+q";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lGGDeTTdPMhLgyPnToGeF+S6yOE73w26ZRuj1R0C0vk=;
        b=KPON0xVsTp8yq9RSfcVlb3Cnk+BrXncBBdKqyaqvohHjInIfkBjmG7MW5l9rqmF1G1
         il1ZIvjssJZlsAp+SeHKYExygAMTP26RBz9rOMtMMv81bN3CLPbVMc4zvi2yubtzyRbk
         orX9ZiuS+tzsR6KKS3NuEZzkUeTC4akfRtxc/BoOo57yYDtxJD+Mfox3geHrR5Q7lkHr
         3H6isqGFaGOmf1ow+HfXDQ/16h7qI5j0OPQUKB4tiQQQ+BYe3VdVCFnE/bDkIK4Jbteg
         Sjx0NVk5znZfE6p7Q7pO8CVs5TNW98UibqBFj0DeDDFc7L2DD8Dp8ua8QUp5iJpen3GJ
         ia0Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lGGDeTTdPMhLgyPnToGeF+S6yOE73w26ZRuj1R0C0vk=;
        b=E5NuFNePB/Ynn4KxC3dDc4RfiaMGI9xOZpSED3V5dtTFjMXiLVeLZqqCwib7QgE0e7
         VVSIjOmfupweDRIiFcsaTzjZMBX4rjqAG0oDn2lwxKl381dBpzjjFMW+nunMbb50JanV
         n9f5usqrKvxs1nWT4LL4IYDpaUNvKOnAqchostU3EqQUyxy5ErENv/Tksh8Hzn2BDoj+
         RQbkpQpLm6r3TwYR5hD9AHjXfqNDQbR5CztrUaFuOF6K7gj0pfwjHxHmlsInXiJqUGXm
         A/Z+sOuXqeF3E098/Ve2JCaS27NG3iWl2V7CKX57CNrdthzFIooTzgi07FzwdwsTyoPU
         22RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lGGDeTTdPMhLgyPnToGeF+S6yOE73w26ZRuj1R0C0vk=;
        b=KKn9sgoUCIItsllHg1QQNa482llto4LgXIGNivTE7r4mnA7qgsO9ujrAysvudEqC+a
         tKwGC9JYuBeE8weL54th98LGIG5zyyX7+h69RHJ4gykbL95NWq6Wbak5v5BwQDCOi+3A
         fTcJpNYPJlIEgsxlb3x6ISfReXwAdXyNFExB/5Uki7UMhFYoa1krDCQRlyXxDQvAM9pz
         U7srWDJubNn6th6V/+4O+7reLvPM3eFDD+fiXnQhOTGnm9dobqhOHJUtuN9Z27V8pY8x
         ZkDWA9wwJExSRetaacZC4tLP8rIs4mY13WiZ6uoi6E8Ij4QN658oy2pnOQbOES01UGJd
         vIHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+RfstL3GrlLLU+gI0yFR0KHpV5fgW1DrC12ic/0QtRv0N62Yk
	nXcjELWYdw8k4XFPjhPerzQ=
X-Google-Smtp-Source: ABdhPJwoXYjhLm+kBfcDh8bio8Zpd9W8EMQNVfjSAJpFCLvjL59Vw4Ri+iF7mNJYqDYPkubwDSGg/A==
X-Received: by 2002:a63:d10b:: with SMTP id k11mr15742164pgg.49.1638906395843;
        Tue, 07 Dec 2021 11:46:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c2:: with SMTP id e2ls10653842plh.9.gmail; Tue, 07
 Dec 2021 11:46:35 -0800 (PST)
X-Received: by 2002:a17:90b:4a50:: with SMTP id lb16mr1376724pjb.147.1638906395219;
        Tue, 07 Dec 2021 11:46:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638906395; cv=none;
        d=google.com; s=arc-20160816;
        b=iTnYDnqUKIQdbQO/t43okzF+4S0olLtQjBi14ll+dNzX58RROVyUSboe2bb+Z/1Zxj
         mQZpBy6BJneKJGP8QkDi1VZ6jCUk5JY7o0Ek+AA/6nYbbR8M1lyfmuXzAo6KqMtK8xfh
         WJ3q8RINPnAT36ets2R8PEUhuorVNqy6/qzn09jieN1vWmNMQTgQLYgD6Dqug9RPJeGK
         rUywtKMRceWThNjv3F63liH0JPDAO76P7HlOp4ZOjx1qPq7q9NtiiemdDDFyDz7tXO/V
         fl++6p7M30OWF8EEMJ7n9n2eLRHkHu/tPmLaklOwChdvgVlPdlSppijfO7vw6igv84eJ
         7thQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UOHRGFoWJlaN8tZPy553Y82VWtjgN1BlER86UYqi7dc=;
        b=T6XCploPJP4xF63Uf+aj98U2D5BCMDbToMdvEHN5f9R/usvmtFMRLXI1gr5TB1nrGm
         b8pnMq8sAcPmZ8k3Z5oBXjhUrIL+linG4X3opOeb38qgqy+6TcMG1dUTaEjGXp6WEupX
         XNIDifsb0ZlrHZLdk0NLv2GUx9hA6otD/mrdE5QzB95hwjndkswFPD4BubYslz9IeWft
         4jpo/YwCfTTUMUJVz81ZQgXVJEb8OAfXJIjcmn4GJJU3z6alykr1Y/+C5+toGzXmbPN3
         8Fe+A9VrHAIYAunqwrq0Sus7bdDeFV4vXC/0kEEjGwKtWXi8wwl8iq/ativdKx6Ze858
         k1DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kbeI/w+q";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id pi11si742791pjb.2.2021.12.07.11.46.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Dec 2021 11:46:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id a11so94791ilj.6
        for <kasan-dev@googlegroups.com>; Tue, 07 Dec 2021 11:46:35 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:: with SMTP id t5mr1720750ilu.233.1638906394679;
 Tue, 07 Dec 2021 11:46:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 7 Dec 2021 20:46:24 +0100
Message-ID: <CA+fCnZeHDB4=qJOqoQV3xOJCfiJ4Stnja3y+37x3P-ws2Dtw0Q@mail.gmail.com>
Subject: Re: [PATCH v2 00/34] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="kbeI/w+q";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135
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

On Mon, Dec 6, 2021 at 10:22 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Hi,
>
> This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> KASAN modes.
>
> The tree with patches is available here:
>
> https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v2
>
> About half of patches are cleanups I went for along the way. None of
> them seem to be important enough to go through stable, so I decided
> not to split them out into separate patches/series.
>
> I'll keep the patchset based on the mainline for now. Once the
> high-level issues are resolved, I'll rebase onto mm - there might be
> a few conflicts right now.
>
> The patchset is partially based on an early version of the HW_TAGS
> patchset by Vincenzo that had vmalloc support. Thus, I added a
> Co-developed-by tag into a few patches.
>
> SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> the generic KASAN machinery, but uses shadow memory to store tags
> instead of magic values. Naturally, vmalloc tagging requires adding
> a few kasan_reset_tag() annotations to the vmalloc code.
>
> HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
> Arm MTE, which can only assigns tags to physical memory. As a result,
> HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
> page_alloc memory. It ignores vmap() and others.
>
> Changes in v1->v2:
> - Move memory init for vmalloc() into vmalloc code for HW_TAGS KASAN.
> - Minor fixes and code reshuffling, see patches for lists of changes.
>
> Thanks!

FTR, I found a few issues with a tag propagating to PC (in BPF JIT and
a few other places). Will address them in v3.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeHDB4%3DqJOqoQV3xOJCfiJ4Stnja3y%2B37x3P-ws2Dtw0Q%40mail.gmail.com.
