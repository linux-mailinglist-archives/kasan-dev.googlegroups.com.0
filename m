Return-Path: <kasan-dev+bncBDW2JDUY5AORB36J4WPAMGQEDJS5VAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 905CD6835DC
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 19:58:57 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id l17-20020a17090a409100b0022c0ba4b754sf9670936pjg.3
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 10:58:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191536; cv=pass;
        d=google.com; s=arc-20160816;
        b=p4jLCiwOs67eh0xAL9Bp2rpFx0axi8bSPx9BwCv7UFZAC2F2hz6N40CIWSS3FYGjt/
         ObsRoWAd6n7Cmfsb+RWFzvu9Gn/rDUSGKQLxjaSBv2HJHErkZbxsztmCxpJxMn1a3oUS
         8EcWaqcCnDbz3U5o9ourontMN10+zf0xkrVZDY167BPO8w+K/r11qcb5SeLvWJsFhfyM
         KCwD2bKCER23QOs5Y2zi2WPUl/WWrhGif9xGcT/4PSd4YF099mEllj2dutd5MjOkP36i
         3ZFx4jBi0yA5IrN6/EXu/HD0T3F/DFPhZAyP+Kvqv6WPLI7wkTO0Jl9fxAhJ/Z/4hSr7
         fZvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=JhzoUoOZiGA/K/+kId8ifeMd6XJEBu2M4u8hPCwDiSY=;
        b=x2/1B8DJ426wtF3zoEJoynmG0xbdtY+YQjZlhrI/V82twcg/8XcPCnAkqg0/jl7NVB
         0+3E4SxtN78HDXCTNCxxOZeJeIe5rowbhlndTVS3IClNE6z//kzr6h1cVRzy6FSm7EPS
         lVokQuHLXXA3MOEeKrafCyA8bfkHXECxUBXshfSHf6Ugx05XOdBxuAWZiKauONGDTvPV
         Xw8r5Pu7gZs7v2zfpD6mpuCRzJTrJ+J7PxJa7AlafPnnJiXuyVLWAH8FAL5ZAjbr5IJd
         LdUHwXYxHWGYmSYQXvihb0Csb+IgoypCBQqsxvtABk0AujLv77Td0uTivKm28U4oLnKq
         oYyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ksnvyCeU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JhzoUoOZiGA/K/+kId8ifeMd6XJEBu2M4u8hPCwDiSY=;
        b=WcFp/184uegDFXYvB/Zg/yI1g8ZyCGLL5nNkAs2+t7Aa/6k+cI7IJGQujYUFxJ/b4F
         FyPjx8Nd5V0S7EqZDJA287n0gxu4+0m8RzMSXnLlWTqhH267+8JXZdDpBKacoAIemC64
         1jOetBXXqkBmK9zeYgyHJ6Ey+j6ZZQNKBqQAAR3ScRsEMXyh/9/ivhxl9bXYX4wOUIYG
         VAfTO52OkSnhUjrJrN9+KxxA6+f8evLyi0kAykcHXChTj0XCFrdTHf+MvAOrolgP02Hs
         pUNSzTErRiJHFHB/CAYp2f2yquH22jfaOQb7RAcolpZY8nsCRWKH0e6hQ6MboLXobnHs
         yHNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=JhzoUoOZiGA/K/+kId8ifeMd6XJEBu2M4u8hPCwDiSY=;
        b=cjYoeHGEQnf/3KWKsHL/8jzorVWPhz5rkIqjqFqMQzYMR6/bY+pzbesoc5MZ5PyWbP
         82d9QPImLipHPwtTGtQ/DAkML87JpVybRaWCVyqqRXbohuyEItYJtfeTtpKUVcfiFGyY
         J5mWp72KJ2HF8PbZWDtq2IPGEBoLFN3YhW3lLjaUzlPaWQOyfVv7klqV89GULgM3qYJ2
         YL6YbvWKfgxrKGDOy670inVNmbegdBeCHx2W5jv4AXNNsEfi7MhRWJpfDJtu6Mlu0ii9
         jSrLVOIp/UC3PBNbZb8t4UcafKUZCz4NkzjaNgOrZta1K8ju4YAcHSROKI6k/jaE6iZ7
         ycpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JhzoUoOZiGA/K/+kId8ifeMd6XJEBu2M4u8hPCwDiSY=;
        b=WOXlHJp4xbWeT44busNPI3ZyeVSjlpn1DkKxPMMSaw4Ow6Z02yE9Cwuh8/nz2cfFrT
         sczEHM3kDXcxcZ9frq19PBLLtE6ga2JDJCIQS0+x1AouFaMZU0hBqMJ2OlpCHNHICEYr
         czB04K0z7dpMkX9bD0RTweIaSnrnODVdNA27GO85EY9XpalhYrlKwRdKahDTTZqcgZ1y
         jHi9VlFzwXQZLk+PlXaRJ6DO8XD1PbytdIVtBhYW7lA+X6VkUxT6iSFJtrGs2jvHVAnQ
         etyloXIr+5xrb0fjJ29s5UrRdiYmaoMe5+sjasv90TBmeG9uNANe8OwssoZJQhVGXmIN
         yTTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXjs1wXDk9+sVFDgIYm5Kb0wA+iCi+B1BlwNmMLhczTdYFGb7MR
	KCEqXTt1IO0TJsOjYZcaAU8=
X-Google-Smtp-Source: AK7set/HC5DTBC2I9whn13wm7ztQEXcS78o5lBtArwDkTBRi0+2M0iYsGKjQpgmaVsa8XJP/Hx9zpA==
X-Received: by 2002:a17:90a:3ec4:b0:22c:8689:1f40 with SMTP id k62-20020a17090a3ec400b0022c86891f40mr1806847pjc.86.1675191536020;
        Tue, 31 Jan 2023 10:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2312:b0:194:d87a:ffa6 with SMTP id
 d18-20020a170903231200b00194d87affa6ls17383882plh.1.-pod-prod-gmail; Tue, 31
 Jan 2023 10:58:55 -0800 (PST)
X-Received: by 2002:a17:90b:4b51:b0:22c:2da6:f3c0 with SMTP id mi17-20020a17090b4b5100b0022c2da6f3c0mr22431649pjb.42.1675191535362;
        Tue, 31 Jan 2023 10:58:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191535; cv=none;
        d=google.com; s=arc-20160816;
        b=AWIeV41nUINQ7SdMcB6uiC++2K8z+eJLB+wAH7doYuhbxyq4dAsZqOMgFamPC0t3+M
         aKICICe9nsXL8FCtskIioVGJpV2YGsp23OAcYw1sLXGgp76Bc29OVMw4s6PKjo1+NKRw
         ANBUqxLrthulQP+7KpWGs6cCU/kUks9i7Vsqjx576IGyiOjpOxJTcpaMJJQRNRrHY5t8
         GSQ8eIpVKCedkIk5Rxeg4Gnl02o690ygnvkT9XlP1V7SGIIh13W2ggiZIR7+kEBTNZCt
         glVaLCKS+pNMeZ1znopwEnxzQ4Y2pjTI+YdmN1G3RnLdQkn8jFyMOXltZnM8ryKSq0t2
         +FzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TP6A9+wpIMvqF2KNq6LBjoVcO3DYja8lhfZN/jsXFAw=;
        b=lInQU1IPXC5ToVHksw+i749WKnKF3Efkbn++zMSQVQ2LGKeK7T8mkb8G6Kf7w6Pmw/
         44N9xxMt+/oBHDlB9S0CJ4/xfjAPqLj3u5Gq1BTZsnPx6JZ9Elhxg+4v8wj/uj0W5F68
         dAgJdhXB8mYvHYvJ8+8otQ2nfRDrGeDwi1Ad2WCWo3q87nd65COZn8pdyQA2uYyyqRq6
         lV8ftj73DzhTwS39KvzzE5uXWNAlEfpm7zpnpdLAlzB5KlcuOmfvC1Bu6jn1jtiGAxBy
         XtYgLU+HRGPWea+rePYTRytr+8QAcfWFoxbM+evxVuazX7VDVyeqfYyTkCYO13Tiy7yt
         s20A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ksnvyCeU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id cx3-20020a17090afd8300b0022673858f16si11154pjb.1.2023.01.31.10.58.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 10:58:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id cq16-20020a17090af99000b0022c9791ac39so7721954pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 10:58:55 -0800 (PST)
X-Received: by 2002:a17:90a:6ac1:b0:22c:697a:e056 with SMTP id
 b1-20020a17090a6ac100b0022c697ae056mr2201922pjm.85.1675191534976; Tue, 31 Jan
 2023 10:58:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
 <CANpmjNPakvS5OAp3DEvH=5mdtped8K5WC4j4yRfPEJtJOv4OhA@mail.gmail.com>
In-Reply-To: <CANpmjNPakvS5OAp3DEvH=5mdtped8K5WC4j4yRfPEJtJOv4OhA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 19:58:44 +0100
Message-ID: <CA+fCnZeOs6R_Wk=Da-aC5ZUzz_tOPVQWu1DoPsYVORS=dJ6cQg@mail.gmail.com>
Subject: Re: [PATCH 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ksnvyCeU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1029
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

On Tue, Jan 31, 2023 at 9:54 AM Marco Elver <elver@google.com> wrote:
>
> > +depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
> > +                                               unsigned int extra_bits);
>
> Can you add __must_check to this function? Either that or making
> handle an in/out param, as otherwise it might be easy to think that it
> doesn't return anything ("set_foo()" seems like it sets the
> information in the handle-associated data but not handle itself ... in
> case someone missed the documentation).

Makes sense, will do in v2 if Alexander doesn't object to the
interface change. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeOs6R_Wk%3DDa-aC5ZUzz_tOPVQWu1DoPsYVORS%3DdJ6cQg%40mail.gmail.com.
