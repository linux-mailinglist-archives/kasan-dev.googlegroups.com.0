Return-Path: <kasan-dev+bncBDW2JDUY5AORBR4HYGPAMGQEMJLBETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F50267A436
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 21:47:05 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id u2-20020a17090341c200b00192bc565119sf9591912ple.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 12:47:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674593224; cv=pass;
        d=google.com; s=arc-20160816;
        b=O01WjLAofDoYHHDXEwElo47lICYuQwd3Dybjc9qKxImbLu64aPGhpW4dMGy5BiHAmt
         dxp23Un1h1Poq1IgUchE9rTWh55+8gOO9ZyiXvnjltRw0Omq3Oy4V9xP+w8Dz8jGHP7M
         3x/1lvN6MFiHIWfnY1V6Qaej2zK/mjp5epElMskEbJ1h5JjAfeL6QmicbtTYjIa/gxWU
         G+c+nyXFms/mT/XBkIn9NlTi9AE63UEt3QWQ1adrXk+VKbUJdioU7d4jxi+zZiK5RDM7
         1uSZjsPydK1SUzNJ3tT54U3GHlR9tFsaJ+g5OpywRJ9kGURaW4M+E7TwwbAUPauYxUWG
         1cww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=eu8EsA7qKCp6WwUAr1ZAttW7F7kY6+yPCY5+jvKOa80=;
        b=VPc/h2ZE0VHeqxkofB4Zr4Tbzvc6Yo3txyZpYG83bF4lGk5arRcdWCn3UQTAy7MNYW
         R59E39EsdLwo+u46jhf6ZZrWwgxTCf2m+IRzRrRsy8UFJIlhlYQxSJ6n/cJZ8V2FuGAE
         4hzgActWLdqChGQMcpJNABBbQ0zaM70yKD2FWOS6L/bYA/HQihr+HrbTBjkYUmBcwDlL
         SMWLf3FYJV+smThG+f5W6GHJmmbmxY1YuzQ3y2W6j80qVV8pK/8dR5kfPy3lNbU8mP8j
         xFjDPZ3gbXTUcfYzIIdoDzLP9eW4Mpt4DyyO//NbjlyEhMLx5je9yIZ31ExEgFDQkmBK
         N8KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q9gpybKm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eu8EsA7qKCp6WwUAr1ZAttW7F7kY6+yPCY5+jvKOa80=;
        b=DUiBqDRNykZaSzVFOYDjbl3rn9U6F3N8zHvavAjW1EvQdz2148XaLyBTZADg9bnnpC
         KGjrY96QE1QKCrQoqsPbcXPHPRn0K22V2HSLjz7GJQniqXcf2TLKX8FNjt+VUjXhfyYs
         oHJxFLmC3EQuG93PQzTWRjs2i7zKsqVqyDdXIvzal7oOfkgZWYICdUyBuq5W5Fg+7SsB
         MBYuEMvsoZLZntcsSJN1THh2Msq1fI8huuZdegu/uWmkZ+Q6/UJtD0ytLf296/MzZkzd
         XPat3gED4KIDRZxFR3Ob96PFMSKd77qNgIIeQ0RSKCcVB0az2O9raWU4W03tFetGAY/N
         j/Mg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=eu8EsA7qKCp6WwUAr1ZAttW7F7kY6+yPCY5+jvKOa80=;
        b=NAkJls5dwAcQk9nOx7k3I1yaGpMJCbtTpvjoF77JzHSBQSQGkrmlfgxLlep32D2ijA
         iticMYK+erX5MRtJZNq+Bp+X2Dc//JBQ9odZ4APXxK7eHEdVWu/oiRFq7V197eVd9DHm
         QwlAiDjTc0KA6mz8iCk1dSyfuarSxfQvax0DpMFDDnWG1XXU4ZVyrQlWey70eN6c84Gg
         C0Ro7zpRaROfVdyYoOOGH2piF1TXC4K/V90qKUePXK81UkKszeyoV1V/UsYIP4qWBddh
         7I/urqD5r7n2BkG3n2oRJz6T9x9yA0LrMVcx3AuYC/FQzfwykGs0lmgM7WiFHkKVuqdI
         hCnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eu8EsA7qKCp6WwUAr1ZAttW7F7kY6+yPCY5+jvKOa80=;
        b=q12t8rNU2PeyX9NoRANH4KPFJAiBSO5Aj7Cc9TxbgvbYc1Q0QSIAbBUsiRdQw25UH1
         /CGhOlO2Mk9D5qS6JvvpSQRpRTf/UALPxw2qUjSGExKfPiSxrCVnkt2D0CW4drn0KJzj
         WU7COlYppMRdCWKkx0DqPnsy/YvbgfLdXB8MzEh6HHU66x9z8WeXjX+IDcXvOBqRZgqn
         ixEDGqqTCIH7Q/c1y5r7W9NP+YmjtjA8bQfEjsk1DVuJlh7uzVbxIRuZyZlZVQnok0eH
         Y0Zz0x8jE5zaAURPlnrgLiL7eqOeA6J2iS4hQWh7dRwGijjNfHcFXcZwXj+z582zzkbY
         O9ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krvfPe8CAG6R7r+bpRlIibb3FvflCztGew4xySpzE0kJUCTTf12
	ExyGf08V5sPQN7OfckG8RFE=
X-Google-Smtp-Source: AMrXdXv88Hl9kF7whyEo9Dnv+0IzSDBlMEs2cxI+dub16Tptssn256xnUZ0sO+KpTTax+FGcP6HoRg==
X-Received: by 2002:aa7:8c4e:0:b0:56b:f23a:7854 with SMTP id e14-20020aa78c4e000000b0056bf23a7854mr3377965pfd.66.1674593223876;
        Tue, 24 Jan 2023 12:47:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b406:b0:189:b2b2:56d5 with SMTP id
 x6-20020a170902b40600b00189b2b256d5ls17219308plr.0.-pod-prod-gmail; Tue, 24
 Jan 2023 12:47:03 -0800 (PST)
X-Received: by 2002:a17:90a:fb52:b0:229:2d53:3f92 with SMTP id iq18-20020a17090afb5200b002292d533f92mr31471731pjb.36.1674593223114;
        Tue, 24 Jan 2023 12:47:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674593223; cv=none;
        d=google.com; s=arc-20160816;
        b=mSgm1mdkeuwPbLThCtPh8Zm09V8KpcEsIldCGlDMLv6JqrQhkvZNPfM6B/2RQhwAwH
         HEw1d5WBG2TQEHA/MaoXTrt0g/sXr9aT7l4qY9DVQXfhzlk2kFIHivjFsdZavJktXND0
         zOmt5xwM6E3bXHxunZr9KtSKDBtAThERg7UfEdxXLAlw6PiQO4gQsVTczS6jDnbHYkJS
         X+pUBijWp+bgRzANfG6gr6Yd8Zg338G1q0l+nhjClGTt2e/4BQpoXJITJU7yoFw6Nax+
         Tj2OYsco4go9sldq6XqsGa5ZzIy3g+gOcGGKSZ3r23/9jGpCxXLVEMVyG2qSvL8BL+nK
         6qhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WOhLQgtHBlaa6/9LcTJQIUBbipAiIKcaff5d+EZnw10=;
        b=UJ+fSevu/z623c4eMS60e6qbSddoPS8pQWaqxBZgKUdg2gP0q9tuYe/I+0fsbbyw5Z
         58fqxPRdYy2HVFuyCXT0TbsgiRSoXUcmmFNde8boWrYi/NVNFLCvJKhbteT3B6giIwKY
         2a5fG5PqCbV0mfumdQifrGbP1r29Iw9VKStrD47LNULhSrDGY6jmvTu00M/8gK483nnP
         1h6LxubQhap1STmjFL8Xb/ZWHVR6HhW8nCrVj2BYerEirbGloZTn7jYL7VCp8vg+PDkY
         QkGjzoB+kzDaqRdLY+d5WQGQMDKcg/v9zKX8v2MPeUb2F5gpo08NkbrIrEOHGK0IwEX6
         nQZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q9gpybKm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id lr1-20020a17090b4b8100b0022975f69761si240170pjb.0.2023.01.24.12.47.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Jan 2023 12:47:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id rm7-20020a17090b3ec700b0022c05558d22so216702pjb.5
        for <kasan-dev@googlegroups.com>; Tue, 24 Jan 2023 12:47:03 -0800 (PST)
X-Received: by 2002:a17:90b:2541:b0:229:3af9:a0ac with SMTP id
 nw1-20020a17090b254100b002293af9a0acmr4227709pjb.47.1674593222835; Tue, 24
 Jan 2023 12:47:02 -0800 (PST)
MIME-Version: 1.0
References: <24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl@google.com>
 <20230124124504.2b21f0fde58af208a4f4e290@linux-foundation.org>
In-Reply-To: <20230124124504.2b21f0fde58af208a4f4e290@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 24 Jan 2023 21:46:51 +0100
Message-ID: <CA+fCnZeDWxFB0BgUy_tEybtagth=bcGcqqu9LPSOEjKr5j-o8A@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: reset page tags properly with sampling
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Peter Collingbourne <pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Q9gpybKm;       spf=pass
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

On Tue, Jan 24, 2023 at 9:45 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Tue, 24 Jan 2023 21:35:26 +0100 andrey.konovalov@linux.dev wrote:
>
> > The implementation of page_alloc poisoning sampling assumed that
> > tag_clear_highpage resets page tags for __GFP_ZEROTAGS allocations.
> > However, this is no longer the case since commit 70c248aca9e7
> > ("mm: kasan: Skip unpoisoning of user pages").
> >
> > This leads to kernel crashes when MTE-enabled userspace mappings are
> > used with Hardware Tag-Based KASAN enabled.
> >
> > Reset page tags for __GFP_ZEROTAGS allocations in post_alloc_hook().
> >
> > Also clarify and fix related comments.
>
> I assume this is a fix against 44383cef54c0 ("kasan: allow sampling
> page_alloc allocations for HW_TAGS") which is presently in mm-stable,
> yes?

Correct. I assumed I shouldn't include a Fixes tag, as the patch is
not in the mainline.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeDWxFB0BgUy_tEybtagth%3DbcGcqqu9LPSOEjKr5j-o8A%40mail.gmail.com.
