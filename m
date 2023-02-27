Return-Path: <kasan-dev+bncBDW2JDUY5AORBU7M56PQMGQEYCYSJHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DACCB6A35DB
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 01:16:20 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id w9-20020a67f749000000b0041ec573a9a4sf4298512vso.20
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Feb 2023 16:16:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677456979; cv=pass;
        d=google.com; s=arc-20160816;
        b=mldehUf2iDYOTfX7Jo5R4DH0+CSXY1Q4Nnt97FYk/t5xLThoamjzkUcjHbt4hsgF96
         4OlCVY655k2vRzEPYpzbWwuVtrnSVlFk9KOdm1i6LnGq3KWA39rH8i3sre3Awd1F00+K
         M0ymPGqwywrClmRCp7PQQ/NIhAPZOwskGhH1esmWWPQlcdJ+0sSzatcLvv9m9zRbVHuv
         jxo1CNaYTJQ8AV61r33b77z9wgQONz7b2igbJhwQUisj76Cv4LiQN5RlhjtF2LEGKhyH
         zwOPc7r/FjIAv9FFzwdjkayI5pjOC1exZ9IkoQtI5gnr14wIlZ4EXupOSPq9n4vToj/Y
         lzGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=cNSwvdcsawc6Zs/JSCl4qnJynmCuXWe+VwWZKXl+mlU=;
        b=SQajs4GXHQ/R5xLa2wKCei3Wnk7w1LXNi8Qar5+YVr/OeczEO8kqa/tjbuA0lVnwN3
         UOHjytO872QdhL/HjkJmR/f/zav2SZmYe8+Jh1GX2EQvKXrfJ+Qx3kYFSS4D5+ZyTdt+
         twhFCfEFpLHBhX6WzzOWVg6KBz/csoK3ECDGHmwv2gzgIyqTTKXLL8yBlCxVk+N44jUh
         F95VtVrCW1ioHkL71onDII51PugRiEKhVnsuPq9WL5tJXqrzlhQBoZSlDpDlV7ZMifVf
         IyHJiFjmu4zv6Mqq6hABjNhGfRxFDztsZ6/gnr2QU+hjOUUY61AEfO7RKE7zXdHT23ac
         KaZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ERQewpNA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cNSwvdcsawc6Zs/JSCl4qnJynmCuXWe+VwWZKXl+mlU=;
        b=U562PbpOF2833UsxflQdnnf3O0QAuvpMJv8LG33vzsaVyPvpnTag4zm0kzgQwKFkMg
         wgkO0Tufpxa3NuFMuIEC0iZVITBR93eqvRtvoMQpXx93hzTNKfEm0+OchlR9j7VO0TCX
         1gDOI198aD+RikA0wUvi8KAvlNBQ85SuA38+sO00gB10t/jgMa+Um+ARAL0H8GKScvpw
         bWEfOf6/y1A2LQXpBxu8g0QW3Ts9g4No9ZrmIdYgcItcn8CCB7lT7FqtPJ9CdYbElkG8
         HCkWzUqFEjn0uNJf791O2bo//F5ITYIEWh1OTpkTmQOMbQsy9T8CYz4vjRWgrVFvrHWf
         Ngjg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=cNSwvdcsawc6Zs/JSCl4qnJynmCuXWe+VwWZKXl+mlU=;
        b=iXGtOltLYWC7SjZrv2w+iZg1ZjmYCi0MuF1MgbhXeTZ+zjOwxAYpzCdO1LmQb2j5Dn
         xwgHOTotEts74k9M8B8FopQp/uTnGdu4VXN/1XcCWOW/yYVHNPuRkpeTN4I8l4FURw6K
         3X1yCzdmQEvSKE18ToKMS9S8ooXnnjk9/nf/+kHncyzjRHonzQvE/Pk9AA+oGH2lkKxN
         XLH73CzIzkfmQu6ud3VFK7PY3hNNcaG8Jaj8ra56aADNkc2z7Abapjk+QTp8GHEiAj1q
         Oqj7ajkLVCZUmYbvVTkG9FhLdWo3RAG8bFk//Mk35Vx2SX6YGfjGG6mWaO6E/wx4ujuu
         HT9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cNSwvdcsawc6Zs/JSCl4qnJynmCuXWe+VwWZKXl+mlU=;
        b=Zttqe3VLCoBNfeFXMHg1NI2uG5eHLjWJ8v8M5u1JE17gOAr6rT0iOMqkGjMY9oQR8N
         ob2fr3ftyz6sqb52Ir1ZFgjxpkARQaQZdZRZsrmhT/t0/UOwrU0bNvqa/gDtBoyi7rcc
         5hl4sykYFKQhWVcFooBn6zEIC+waVk3nopWPvilqRTdWYz+pVBs8aE68hJdat68rNWZl
         hMKtDzdecFwqhviDBfImw/Bhi6On7XTAt7lhAEY47mSaXgdUOb/M+dcLwmhD1qv85diI
         rZRnTzPMyNm/S8gwtAQtmgOA5h152MInYUHT13KO6yR/2WFigkD/X24XoFuPtt8ssDAo
         lZnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWm1SkTc56SXvKH9iK0wjFM+bb8EsWNF0Q8Yr5oxf/K3Ypw+WaL
	fCsSG6AtqwFAj19CqmPhgXs=
X-Google-Smtp-Source: AK7set/vZ/Bj0MUEtAJvInPWXrmjQ5dzviN5hbcCN3sShpyZMOSTW8Upq4nALsg6Yh+DkpbrR1XWLg==
X-Received: by 2002:a67:fdc8:0:b0:402:9ba2:bc62 with SMTP id l8-20020a67fdc8000000b004029ba2bc62mr6339348vsq.6.1677456979538;
        Sun, 26 Feb 2023 16:16:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c401:0:b0:41f:218c:5dea with SMTP id c1-20020a67c401000000b0041f218c5deals2565845vsk.4.-pod-prod-gmail;
 Sun, 26 Feb 2023 16:16:18 -0800 (PST)
X-Received: by 2002:a67:cc12:0:b0:41e:d032:840e with SMTP id q18-20020a67cc12000000b0041ed032840emr9902777vsl.15.1677456978814;
        Sun, 26 Feb 2023 16:16:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677456978; cv=none;
        d=google.com; s=arc-20160816;
        b=r4La7qf3K3eZdmjAKTs40s7LbR3M3PQfjvtPLhzGw5LNo7t+35JdyW26C30Vyz+MBX
         GzyRQ2K2TJa34SMjvYRfrr3z2+q5VVRO/goNaDF5xssiavlLCepgJau1k3+v7RtNPDKo
         vf11HFYfoaQDVhWLQcfdyyN1xnr5Wzw0ciBujvX4n5vemcuSnJ+eP5khzCl8XFjuKbIX
         SsD3DTDm6aJjR9Jz2xfcT38fslG4WfC21djcO/t2oT7rLT56KVMSZtCz0RHsJoWHUpoG
         cAuGgXLU4ZFg9+Lh66sMfDIC2WKB92QBEaMJD8tmWwCg2yeW+FP0+sUk3Ml6vrCEoiHm
         /dpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KU2d3krd8jU71w/aSLBfB0ISLKVxkdpbc4h5LL6Vtmw=;
        b=NbhOaArkaQwEgm3e6tXz9F57Gaf2i0HgKe+BGSQT0uYjphNkZEw64V/vpAVTPdQFRD
         cRQYPqpAY0Uczx93t4yqjPaYJbXW/6mGrQFLhb6LP2Oxh6wV8dcupnWzhSxWDbquHNvw
         BWs9Tx7Rr8hlY90pJVoW94Gkccwh6mblcIBE2biegJS1R0mIa3qY3Rcob2kaEOgDZxOm
         97LspYac8Nr2M5bJ7tw++cUWTA2YIPP9SnX33Nl/40PkDGmNixMK7H+H4OQFqRDWtluF
         9djf3oFGcPnzzYW9sBx2w/xBZK8uygs1RJToP7pl+9yP6fBaulqHEW4ufvbTtwQkQxQ3
         jrvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ERQewpNA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id cu40-20020a056102162800b0041404daed81si333976vsb.0.2023.02.26.16.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Feb 2023 16:16:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id me6-20020a17090b17c600b0023816b0c7ceso426400pjb.2
        for <kasan-dev@googlegroups.com>; Sun, 26 Feb 2023 16:16:18 -0800 (PST)
X-Received: by 2002:a17:903:4285:b0:198:dd3d:59 with SMTP id
 ju5-20020a170903428500b00198dd3d0059mr5351285plb.13.1677456977861; Sun, 26
 Feb 2023 16:16:17 -0800 (PST)
MIME-Version: 1.0
References: <20230224061550.177541-1-pcc@google.com>
In-Reply-To: <20230224061550.177541-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 27 Feb 2023 01:16:06 +0100
Message-ID: <CA+fCnZepwNj2OXqHHeztOuZQ7UGp5i0M=SBkzQpTSnnMGL0dvA@mail.gmail.com>
Subject: Re: [PATCH] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ERQewpNA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035
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

On Fri, Feb 24, 2023 at 7:16 AM Peter Collingbourne <pcc@google.com> wrote:
>
> This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.
>
> The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
> flag from page->flags. However, this line of code in free_pages_prepare():
>
> page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
>
> clears most of page->flags, including PG_skip_kasan_poison, before calling
> should_skip_kasan_poison(), which meant that it would never return true
> as a result of the page flag being set. Therefore, fix the code to call
> should_skip_kasan_poison() before clearing the flags, as we were doing
> before the reverted patch.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Fixes: 487a32ec24be ("kasan: drop skip_kasan_poison variable in free_pages_prepare")
> Cc: <stable@vger.kernel.org> # 6.1
> Link: https://linux-review.googlesource.com/id/Ic4f13affeebd20548758438bb9ed9ca40e312b79
> ---
>  mm/page_alloc.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index ac1fc986af44..7136c36c5d01 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1398,6 +1398,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
>                         unsigned int order, bool check_free, fpi_t fpi_flags)
>  {
>         int bad = 0;
> +       bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
>         bool init = want_init_on_free();
>
>         VM_BUG_ON_PAGE(PageTail(page), page);
> @@ -1470,7 +1471,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
>          * With hardware tag-based KASAN, memory tags must be set before the
>          * page becomes unavailable via debug_pagealloc or arch_free_page.
>          */
> -       if (!should_skip_kasan_poison(page, fpi_flags)) {
> +       if (!skip_kasan_poison) {
>                 kasan_poison_pages(page, order, init);
>
>                 /* Memory is already initialized if KASAN did it internally. */
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for fixing this, Peter!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZepwNj2OXqHHeztOuZQ7UGp5i0M%3DSBkzQpTSnnMGL0dvA%40mail.gmail.com.
