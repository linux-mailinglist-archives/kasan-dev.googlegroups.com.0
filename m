Return-Path: <kasan-dev+bncBDW2JDUY5AORBEFBXWPQMGQEIZBK4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 9839969A8C9
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 11:01:54 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id i25-20020ac84899000000b003abcad051d2sf71739qtq.12
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 02:01:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676628113; cv=pass;
        d=google.com; s=arc-20160816;
        b=YUO+aZbS5950BtI6gHM5obyA+8Oh37SjfHT2djzwzHF8tA4WrcX2BWZ+N/7Ud3DIe/
         krhNoxnEdEk6Eig+4nrnNXbjF4096gJ/fp56tiZ1OOKPeR70rB1vfYGTx/2ujj9gK7mP
         BoAU90hqpvwN07TmmubBOelxqpxEBeOx2FOdJPDR5KNGsUklDh1QAjqcc5DOjrHv5irD
         RCV+pbuBm7cTdEUlVk8MKBso03dHfpdkaaBVg1jH+fTNhe+0Cs2Y/QSWhiRcRDVzTI3h
         OZenc3fOnUe1fOeh086zM+g344ipZcK/GmFEdQaF5ixfQDz6cqqhETvAEQbtPOlm7ZMv
         sykQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=c3O/2S1Fawcc1DlAZUTdjmTRXIJoBjiGMBQZ2OlQ/7M=;
        b=S57zc6VXd+DTg0LxTc0V+cI98GpaxwX94Vfz5vaHhmgLhKeQhfFIqNSP203rWdtmAm
         f0E+2x+de+Tmh7O3eGoDtwwcYglS8GadPc1JqSLUcCxhDufNScHHcYJWhSXTiRSLluBC
         bHFcz7pCE3VKjUyJ91PxQCGneAKc8duCllRVtYjUb1d+m/EuMYq+mewZM3zUzvVEeTQL
         Nt54F0H1OkJGzoXKvjo9VZXANFg/s3DMhfqc7PD7sBX8RCT7HCBwrLjdxoD996NE7SCy
         C/gL5gfXCEndWQC+x/bCZtu5AsQE5lAx8lSIN1XdUsDuxLuC8qqCNBLQ+sG+91k55376
         4ahA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="q70CP/QF";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c3O/2S1Fawcc1DlAZUTdjmTRXIJoBjiGMBQZ2OlQ/7M=;
        b=TaI5J7keovXoWcH/rtsWASr7/6k4FRKr6x9tYOMDkj0x8Zy3yQptqXq1cwHgluDqkS
         DXzdHH5O0RfvjWSaYGF8Evrwiwacoa0OixSB1V1IGhplvGu6RaO0SWxdkXB2OqxxGHv4
         WOStCt4kwfgBIViL6T5ySqVDptZQ9vTYqJHmfaQNxx80fAmdYywE1fwZsqlp8i1A6816
         BAAmpVjGZfBK6QaX0AYav/GuZMCkR44pBsac5qh4Ov5eYgWqsDnAey2UcAjvk7uebRNF
         aEx8J4iWVtjna+Qmu05t7GUP+pSomcXji/7NRCQtyCMGBD0uLQRRc3kahJ1kCcCgIgbB
         5JIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=c3O/2S1Fawcc1DlAZUTdjmTRXIJoBjiGMBQZ2OlQ/7M=;
        b=XXOyQGoZXITzTJCedYEFFCWsL8qEvJUGQOhMXMYa87myeW8/hk/W0Q4vevxTBgWYC2
         yGoVcMUpix4bp2qPi7lvzk3nrqYO9jfqku/1s9jrA24rYK+NpQVjMBuYYzaMR1XY6iCf
         rATR5QW2UKNtdgcWI7zv6GCllkzI/kmwmnh9HCfyx8E45lRiwvRV7tyN1mSLCRmTcaXv
         IedTj07L2iE71qXAAUXBKnEZUI0TGIcQgFCyd5frS9ocuWB0jqE5cztBEnDhkot0AQZy
         jzxJmyqv1X6QuoBnBerVzoNoUd8/71XIDQZDZzU+LnoLDzKHC1WXX36YDAVmiSHMKewz
         54Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c3O/2S1Fawcc1DlAZUTdjmTRXIJoBjiGMBQZ2OlQ/7M=;
        b=v8bKBiJuN0U+4EigkPO9OcOnIZ3okT/Q6KXUizEga+nVcEP1TCQQqZRkiDbIgZygih
         Pa9ft659UbtbIWtH2rpCm7XwYKEfMSRSmpFisLtr6qhXoPsOipnOg84dwYRW6swai6Rn
         +K+j8ksvPZBkohpqCFwgfPVtisXAeQRhdKWBgXU/zql4L+NV5bWIV5OCp6rN+6fambWK
         r4hkZPFcnsyy6FQfJ90nCQO5Jnz+u4wrowfySFH9844EdnF8AOVQygSevuzPeFm3vCQ3
         nWOd/9zdGBn0kEqdbzfyYXEf0xJ26F2/CeF1FJ2erzvPkkv1pKluNSJETCFNy6J5v5zy
         MK8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWqJ26yuD+o4qHqg1arPDDJmAwxiTJsqIOwCZHGJmv58sKO5wOk
	2Pi4SaxvGspuCohH4ihlqFg=
X-Google-Smtp-Source: AK7set/v42WsKAXStWWYgc4zW5X7EGF+6Qzk7ZcpISRG89S1TOImYQTfc1aNXlVK39gNXdXwOl4Mqg==
X-Received: by 2002:a05:622a:14cd:b0:3bc:fa1a:442d with SMTP id u13-20020a05622a14cd00b003bcfa1a442dmr788989qtx.6.1676628113483;
        Fri, 17 Feb 2023 02:01:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1709:b0:3b8:45c4:4b6a with SMTP id
 h9-20020a05622a170900b003b845c44b6als438311qtk.4.-pod-prod-gmail; Fri, 17 Feb
 2023 02:01:52 -0800 (PST)
X-Received: by 2002:ac8:5ac4:0:b0:3b8:2e36:efd with SMTP id d4-20020ac85ac4000000b003b82e360efdmr14175814qtd.55.1676628112375;
        Fri, 17 Feb 2023 02:01:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676628112; cv=none;
        d=google.com; s=arc-20160816;
        b=k7Ldmhl9yLH+hhyqPae77AgszAkx/uumBVYSQyf4p0sCaMZYeNlQ5g7YCvPkc77fnr
         wgfU7bNX+MVuYmkWG9cqktU92z+VAHxNK24KxaRIq072M1mCbE4vlmg6JXhHyYNi+VSV
         GjRFOlgKCcyg1HTslwYDxsI8JEXKXO9gqddI8EPxTSXbj7b599e2vp62MiG6gGRM17Gl
         KLL6EIjrYc7GCCtvgWUKJk3/obHqUUKoMxhlIfF5ko79zcJVCko/PnSR+j8hrnrjmgx2
         nP/4JA9T8xnyvvpE2f3zTq73GJjfhTPBycTHEyJX45Q6uaXYCUhC83CUS4lEZJMC6FOr
         7AwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c8t7WQSrgRYnzbMUfpx5jhJTpcbpl8qDHziyJ4Fw+Sg=;
        b=uzIHGOsrh5SmM5SVeFLbGBfBiPk/qdNIF4sRDNqytMgD4DLBCve8OIaKwMi64sT33M
         lmIFIWNOWSFByiqkkvc5alwUA1LhVFh3EcBWgiGDsmRbb94Mqh13owVut57pvR2Xr0tQ
         RwR/IbV6rDZCOaUGzescu8mkxl2ZWW2YWpm7VQpcx3kH4qbkjQoNUYvMhp+s608LENxd
         iLZrzRMjrbxUeySJVRTYtfccgkXCyZpMKUbZq503ygUzMkWHQHS4/YZ6929fRanVTRUH
         MwxvLBbnlSH8qWjvLtGLq6EI8LDguMOrblMj2xFTSDpELrAkQWEjXiT0xWPq3CmqbptW
         G5wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="q70CP/QF";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 141-20020a370c93000000b0073b8e384737si250170qkm.2.2023.02.17.02.01.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 02:01:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id p15-20020a17090a2d8f00b00233ceae8407so630054pjd.3
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 02:01:52 -0800 (PST)
X-Received: by 2002:a17:90b:1f8f:b0:233:3c5a:b41b with SMTP id
 so15-20020a17090b1f8f00b002333c5ab41bmr1381346pjb.133.1676628112015; Fri, 17
 Feb 2023 02:01:52 -0800 (PST)
MIME-Version: 1.0
References: <20230214103030.1051950-1-arnd@kernel.org> <20230214114014.4ce0afb658fae97d81f32925@linux-foundation.org>
In-Reply-To: <20230214114014.4ce0afb658fae97d81f32925@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 11:01:41 +0100
Message-ID: <CA+fCnZebcevCZModJKRAVM_-WL0o_C+ooVxNpZtw+-Bwu3GMRA@mail.gmail.com>
Subject: Re: [PATCH] [RFC] maple_tree: reduce stack usage with gcc-9 and earlier
To: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@kernel.org>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Vernon Yang <vernon2gm@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="q70CP/QF";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Tue, Feb 14, 2023 at 8:40 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Tue, 14 Feb 2023 11:30:24 +0100 Arnd Bergmann <arnd@kernel.org> wrote:
>
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > gcc-10 changed the way inlining works to be less aggressive, but
> > older versions run into an oversized stack frame warning whenever
> > CONFIG_KASAN_STACK is enabled, as that forces variables from
> > inlined callees to be non-overlapping:
> >
> > lib/maple_tree.c: In function 'mas_wr_bnode':
> > lib/maple_tree.c:4320:1: error: the frame size of 1424 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> >
> > Change the annotations on mas_store_b_node() and mas_commit_b_node()
> > to explicitly forbid inlining in this configuration, which is
> > the same behavior that newer versions already have.
> >
> > ...
> >
> > --- a/lib/maple_tree.c
> > +++ b/lib/maple_tree.c
> > @@ -146,6 +146,13 @@ struct maple_subtree_state {
> >       struct maple_big_node *bn;
> >  };
> >
> > +#ifdef CONFIG_KASAN_STACK
> > +/* Prevent mas_wr_bnode() from exceeding the stack frame limit */
> > +#define noinline_for_kasan noinline_for_stack
> > +#else
> > +#define noinline_for_kasan inline
> > +#endif
>
> Should noinline_for_kasan be defined in kasan.h?  maple_tree.c is
> unlikely to be the only place in the kernel which could use this
> treatment?

We could also define it in include/linux/compiler_types.h along with
other KASAN attributes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZebcevCZModJKRAVM_-WL0o_C%2BooVxNpZtw%2B-Bwu3GMRA%40mail.gmail.com.
