Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWZ7GQQMGQEO4JSTGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 29CDE6E5E5A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 12:11:36 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-32b4607696asf15091375ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 03:11:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681812695; cv=pass;
        d=google.com; s=arc-20160816;
        b=MfJCkNthNrXVuOqKgFM5B8cPUXl1ONwWoUeO2wFNgxTvjBSfaOTXyAPLSAaFNtyhKb
         kMD4Gm2HY8w3LGFCcPKfvEOUdZunD/6P5HAVJhMrJZha1OJjfRaWcwbaXnAnvE9E1Cy4
         1YVLmYxUmHvl6WRfvEjb+VRW63ShwUcGomj/bdhU0UgtLiWV8eVbnulXOA5wbd7YqNXS
         /BdlZ2S8uqOJZ5ZeEcdrvC2mhkfiC71Mw/tXqKlbqUQzX5SGLou8u6fw+OMwkpvDp+gA
         ihBblS6nDpx4jahGda7/vUnIJ/GAWJdXrRYevUCFCDolW13m48ltIUDAhO0XAEDZfL6N
         cADA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rIw6xeXOkItRG2DAA40v6WyUPoSy9kDyO0Qn0Q2B2uc=;
        b=JWiGDqe/crTmn8rp2V3dX+VX4G5OoWbe35/tzEk8iRGV7BvsbRBJGXxUqqP8femM7M
         cAr504i6UxTSWBjX4I5w+bwx9V0Ths6/vOi6Nyrpu9tqXny+wSk5FcT5Xn9JVX852PMY
         QaFzTJl6xF2Kx9cZzaH6+lBWbJyqjk5HxdPtGbs8gVX6YnzJhiRLuAicQQBgyhqSdTyr
         3q7GaNxDlKead9z4QZSxzuhwXgHqOvPxZTxGusH23/HchKNzTi0X1u9ZsfCE838xD47n
         TbIRn7CiRKpwRaWRTYfiP+DdCyESPpzERySm1zG0rJjNDXwl23dQo6JYBOe8ubB2WrrN
         TzMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Cv2mPKC/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681812695; x=1684404695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rIw6xeXOkItRG2DAA40v6WyUPoSy9kDyO0Qn0Q2B2uc=;
        b=ZdqLtbTxW/RTxOKPgvPi0bAnI0a2do4cIKI/Anucf7+Wbf2pGLAI9Vz+ZanMmg7M9j
         sdGYiUub7safE9Btc8qhVm3DTrkpJczcsnxCNB7BsHXbEm9HlkcAr65c2aEkWK38QdVs
         eRE/n+5Aw5UTnqsYlhZwxTDttUqLQ9I3jsmcfsqq9cNZvCBKs7h5mSdIbCUO5faBP/zP
         ystFvGnbbne2YY7PXzfd+jx7UAEoY2bmiXL8iifXZkf1ariz9j5+DOYB75+3Na0KQmvn
         Y5GP6n/7snUzRWjbxUoN7ugGOmlmHMuZye/ir6u2x5zcYIi7nRgOyrO7TBp2NZliq551
         36Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681812695; x=1684404695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rIw6xeXOkItRG2DAA40v6WyUPoSy9kDyO0Qn0Q2B2uc=;
        b=a8YB65vYbn62a9mpWWNsskohGSt2HDvkkRUyyV6SvYcd05G8RsRipCxalr7JEWqkh+
         qzlvMGTPCRL18BDWYtr0ZxmF26T8Svn6a+VeaQKBHFC8XpGQPHahBvRDMWNnu7ruK/h3
         /ar5kcjpjnlDuLja/qVKTJ64nq52HmTzA9yQrzKtMnk6WBiUZY6rsKUqxRxHPVJnbqfl
         yboL0hglY0odh9BeO5UvD2HgmD2miJ80gNJwxJin38wyPk1LTPfco9PXndopKufMvJOy
         hc1R/rLW+hLFJ6LshwekGIb0njrNPJjC6llKv0FaICZ/s5zLQkd+Hi2g06gRXC3nI4bu
         7JVw==
X-Gm-Message-State: AAQBX9e09RlhpC1Td9uJ0nkgy7M3sQ9JmLw5sZr5jnn/PZl8/bJfE00z
	/2eUhk7z113puYN4pVTNK0g=
X-Google-Smtp-Source: AKy350Yw451RxKc0fyiJKNG4bMiHgIF6katxCGICnNqlj6X6/JWX3g974QLqt6Kb4mXnuyZC/ZLixw==
X-Received: by 2002:a92:d94f:0:b0:328:49a2:216 with SMTP id l15-20020a92d94f000000b0032849a20216mr7942530ilq.4.1681812695059;
        Tue, 18 Apr 2023 03:11:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2438:b0:763:5829:9243 with SMTP id
 g24-20020a056602243800b0076358299243ls715290iob.7.-pod-prod-gmail; Tue, 18
 Apr 2023 03:11:34 -0700 (PDT)
X-Received: by 2002:a05:6602:1644:b0:760:f293:12d8 with SMTP id y4-20020a056602164400b00760f29312d8mr1752496iow.7.1681812694492;
        Tue, 18 Apr 2023 03:11:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681812694; cv=none;
        d=google.com; s=arc-20160816;
        b=iaJ00JffIE5SJq7JdqT7PwNM0FAvoLGkI+uBRBRhsiIPlY0tjMu99Mo45YJX5ufBGl
         p6GSzf6UL9T4YmQSPx0+1FSCpNFrTsrVipH7U0YPejU8ab1BudjypWnsBuKURGGWVAo+
         bp8zmR2Ho/bDKwCs41yNHDwlY7OClATpbqX3rHGFc4ISXT8JNLtCzEiHrX8gtIOt6M4z
         +RH/TncSdzIuYMCaFJL+WVbiVaWSmLqC/zTrubDZz2zJkZCBcI9VbwHJ/sb6Os761F9P
         ipUi0Z+/9IsrgTk/NemW73D47eETwB1irCutQDru4EOnzpuGwGsziATZPnBtHHWTYT9h
         9h6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t7oNbt6UHUojCngKOJ0DxqaobdP4aHKdK/uVGrFOX4A=;
        b=EPvl6vd1rEsi8Df/UKxCc+OYInbO/HPO8xCh8Dj4vZzDao/3XWYR/JyIhutsUDOM0O
         rcJ1udLRZNDR6+4XQlHUbCdir4+y01xHmMeAdFYhS0cdQjTffTJYl4S1EeBZShF7Rzmz
         rv+LhgPqYydJlitJB4pmjHwqZYRorMKjm6wjNp25nZlNFXzZ76PpNAtWefdfCJGk+iKc
         CHR3ZYWzT7TOyAf0oK4ZAMeaiXMOpzpYscYdlrS+Vb/nEb/jjRFZLjiZht3BKG/5iekS
         GTh7TkRaCqO0l4YKROmYJ7ML0fbIhflIl3x20QKmLI8kYI1QWlesuITz++2RcdOJfv3n
         nwqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Cv2mPKC/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id bg13-20020a0566383c4d00b0040fa18f8039si344682jab.1.2023.04.18.03.11.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 03:11:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id e9e14a558f8ab-32a7770f7d1so30638095ab.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 03:11:34 -0700 (PDT)
X-Received: by 2002:a5e:8607:0:b0:753:989:ebb5 with SMTP id
 z7-20020a5e8607000000b007530989ebb5mr1447879ioj.7.1681812694096; Tue, 18 Apr
 2023 03:11:34 -0700 (PDT)
MIME-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com> <20230413131223.4135168-4-glider@google.com>
In-Reply-To: <20230413131223.4135168-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 12:10:57 +0200
Message-ID: <CANpmjNMVVRg6sVREDYGCiSPO6GOpWd4wuMnyNM5=wRJJvox4bQ@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] mm: apply __must_check to vmap_pages_range_noflush()
To: Alexander Potapenko <glider@google.com>
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="Cv2mPKC/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as
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

On Thu, 13 Apr 2023 at 15:12, Alexander Potapenko <glider@google.com> wrote:
>
> To prevent errors when vmap_pages_range_noflush() or
> __vmap_pages_range_noflush() silently fail (see the link below for an
> example), annotate them with __must_check so that the callers do not
> unconditionally assume the mapping succeeded.
>
> Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
> Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/internal.h | 14 +++++++-------
>  1 file changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/mm/internal.h b/mm/internal.h
> index 7920a8b7982ec..a646cf7c41e8a 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -833,20 +833,20 @@ size_t splice_folio_into_pipe(struct pipe_inode_info *pipe,
>   * mm/vmalloc.c
>   */
>  #ifdef CONFIG_MMU
> -int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
> -                pgprot_t prot, struct page **pages, unsigned int page_shift);
> +int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
> +               pgprot_t prot, struct page **pages, unsigned int page_shift);
>  #else
>  static inline
> -int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
> -                pgprot_t prot, struct page **pages, unsigned int page_shift)
> +int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
> +               pgprot_t prot, struct page **pages, unsigned int page_shift)
>  {
>         return -EINVAL;
>  }
>  #endif
>
> -int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
> -                              pgprot_t prot, struct page **pages,
> -                              unsigned int page_shift);
> +int __must_check __vmap_pages_range_noflush(
> +       unsigned long addr, unsigned long end, pgprot_t prot,
> +       struct page **pages, unsigned int page_shift);
>
>  void vunmap_range_noflush(unsigned long start, unsigned long end);
>
> --
> 2.40.0.577.gac1e443424-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMVVRg6sVREDYGCiSPO6GOpWd4wuMnyNM5%3DwRJJvox4bQ%40mail.gmail.com.
