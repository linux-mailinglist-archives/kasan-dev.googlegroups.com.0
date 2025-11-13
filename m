Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFOK27EAMGQEF25MBQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AA96C57D37
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 15:03:03 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-88050bdc2absf29304226d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 06:03:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763042582; cv=pass;
        d=google.com; s=arc-20240605;
        b=cXd8YtOrxjX6cxTZ6oyUYt/O030QFBs8Pe1wVUwbEaltefBFbOOqEzKKcSVaWzEKYd
         X5uL7/WCbz/KYXKfN7/2vVLYTrNCO0SbJidFmzdSCce0EFqD9NqLrRdU07AWdm/QHVUH
         Y36MA3isyXKWFa5+d/mU9WTFGPFHbGp4JGMCK8OWgsF2gf4AsXnLFLVwV9TFhCz883Zm
         ZF9qcyoefXIbvSxxrELqxYaz7hMrQrFHDonpG25JIU9iMI44N6DxJaUYXJIZ1rMg08tC
         v2e8IzeZQZeDYw7qKfO6Y2osLrW6f5M18cxmXLHeUXlMJ4sCNsMmQzmuAanuBrpGLT20
         2sZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5vUrAjAjJlqYzmvG+9hYNST+T/9FQ/o0uHxDUmt82/Q=;
        fh=vb1SNYsX65TXi6DOEFB2NzQ9OX8YJsHV7mLCF5ncqmk=;
        b=bz7dlGX266zMRZhR6MpkilpuO2VlbPGCJGH7QpzXIeC+ZnlHbnjbvQVyEaQpdBWMZL
         OUQkvUbeJMh1S0t0jLAoZ1kRAe7tNlZuoEifAqPN8LRqVGk7XsvYBJ2Bx2D1AMS+xkkz
         i0+aqiE650Fg8/awIAF6PAFp33XgdJQjtkgDBmxN7KXltvCk2DUsrXmmjmMirQP8Cv5o
         Qg6XCy/ylNXCA0cTnyjMs6cIDjdiTf6N7SDX1HnaazDpwiM7Kr4DWdjBW8HFXrgATQsQ
         40y1rcSuvrypRXqlQ88BiBc8r66Fzl0KR+YgE5KcqMGLBmB3LpvEbJ+ROFbca0WovPh+
         YGKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YyPwsYcW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763042582; x=1763647382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5vUrAjAjJlqYzmvG+9hYNST+T/9FQ/o0uHxDUmt82/Q=;
        b=E2agTZ5zfNEYU+RcfHcS4zQCXBq62euhFTuCApLXl/kTS8/RwZeoD1Ly63Guv402N9
         5Di80EjYIOGHLyaFxijM2W+2liG4JPVHW0PgcPx2tLeSqlYzWscAPPLMJEuVJ+bE4IO/
         FKoCSjkEtUMGqTlAOvrfDLDBhK6QJRAFa+H+fc4n1eo1xrVX9En1a4cjTjOyJx/jYCfD
         G5htwJbioGYYl6qL6sl1jQ/nTRwGEWR7sDTJyxpxmEuTOIiQL97BcVsh1mhbp2Mh/sE5
         gNic+OBgDeAlTnItMr0Uj8B1K1zfzyBMKZ57Q9U+YC70wuOGUT1I+VraRLL9m4OkpWLk
         4JtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763042582; x=1763647382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5vUrAjAjJlqYzmvG+9hYNST+T/9FQ/o0uHxDUmt82/Q=;
        b=HAztsMa8egOWIwDukK1kqumtExQ8MW1VMhjfl5gjKH3KeJO9hJCmO36LxTfY7WVQJc
         aJeYc8JPIT19UNSnWxrtzMbJ5LKka6YgoHmNzPPjzWQi8wcoV3j8lcNeCKiDk5CnUUPa
         bTdxqRiJXZAF4BtI3rFCnQRVS2GSKs0ulKtOHMa8TjwFqOwvlk9Xa0mR9G1N6FJvkvAs
         Lrkgnnw4cyqX/KSlvszk9m6rBQDTNblQdsImBlrr71wYMmntkq1MDgNj7GqHKduv8WWo
         wd3LFFs45H5asR1J3IlHxwR2JOjesKIEECww8E9WNhZoaG8Lym4A9Zs8Mfe8FE5XlY1k
         3/YQ==
X-Forwarded-Encrypted: i=2; AJvYcCXWmSV1nZx126w3LadqWRovmm52jE3ga8SOO5aNsqrgGTpWhlKAlHgbqiVzChYhG32mc2FaUA==@lfdr.de
X-Gm-Message-State: AOJu0YxjGbIjYv2qTugDO65ENkLi+KKk/z1ZSMpsXMMBiGzBA4guYZ/8
	nZC8YR0MPVAIKww7RFdgVzM0RnnAfoKkrescshEl19+T+gzdxbKOmgkW
X-Google-Smtp-Source: AGHT+IEpxOV1jqrjazKd/GVWDEpQr/lGEr2uAOSxswl1dVtNDa8KAXb8AIuv5HbxHAsQVm/aRrWCfQ==
X-Received: by 2002:a05:6214:21cb:b0:87c:1d89:a245 with SMTP id 6a1803df08f44-88271a5c83emr110430996d6.49.1763042581531;
        Thu, 13 Nov 2025 06:03:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aQZsPHD1OS2n5bzAbBEiX3ZO+X6MgZfgORX+42vxXhWg=="
Received: by 2002:a05:6214:ac9:b0:880:4116:d4f5 with SMTP id
 6a1803df08f44-88281b06148ls17572616d6.2.-pod-prod-07-us; Thu, 13 Nov 2025
 06:03:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXrvgMqx68HPHCyoNwPjGLuETLgfceU4g+pgwa/RmVnXxxeodebxzBZrsEiFoO/up0GpaQa5Bx/apc=@googlegroups.com
X-Received: by 2002:ad4:5ba3:0:b0:87f:bd05:1c89 with SMTP id 6a1803df08f44-88271a4ffabmr98845646d6.35.1763042580346;
        Thu, 13 Nov 2025 06:03:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763042580; cv=none;
        d=google.com; s=arc-20240605;
        b=Pyc9fzmd7HmGD0OvILM7h5oemYGJaEMKwt/mNvEVVAwuxmaq/aiDjueP5Qgkemo00/
         b4tmIAd8GhgJcfON4cBJXYkk2xIF0aolkktlcq5ja+GaFKkOdLqNv2f3Jgcm/6Ft0e9G
         +KKPh+l73CymgSY1yBt0ZUPT6/KO/+CENumgv1tXDaE0RtF1JmZPQwhuMBqZilen8Z1h
         yPOjmJVg2vgtAzoiEwGwUQKiv+FUE4VQFbS93w0L0tXwvdg4rH2FvPhs7XatcEfB6gHM
         kenvdtVmonY381NmzyEc60YNu/ZmL6uohwK1Yb2BpHhE+yOZsMMPemE+d7qetyFCh0cK
         jyng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wDQvj6UlQD63iPrmSZxS8C2tXksjrqLXDzCDe6b36Fk=;
        fh=BiAtrPeXJCVrk2qiBILPJ4sab2i6PXdarF8KHy3kvHc=;
        b=EwvH8UHsMIZjBcoll3xkzKHy/1hmWQfCEo8c0TnKl7Z5YLsFex0MWGVyYjnCwq3j9z
         wsuYcj5YKxS+khgGpAQl3RvSCWKUye8hFoaXMosAMgwPP9+wHr+DWXvKEpZo3bHQ283Y
         sw2TSG7QnjGuWVCT3PE18YL7ypzgIA9TlOKkfHeqEyEVgGqMHOn0qYcYp0h6TMmvv9dG
         dPf8nGp+hZQoo732dzR1t9/QIbIB9q+QFxpIsR5p3KXkSNzjEmIt3O41m8okPEPQJ4Ay
         U5maXoSWmHfAaPxO7oouHxdBgwq0MLMV566i2tv355+Dunqy251Kd6IhyN++S5euTxjC
         jLBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YyPwsYcW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yx1-xb131.google.com (mail-yx1-xb131.google.com. [2607:f8b0:4864:20::b131])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-882865f28d4si890296d6.7.2025.11.13.06.03.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Nov 2025 06:03:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b131 as permitted sender) client-ip=2607:f8b0:4864:20::b131;
Received: by mail-yx1-xb131.google.com with SMTP id 956f58d0204a3-63fc72db706so750046d50.2
        for <kasan-dev@googlegroups.com>; Thu, 13 Nov 2025 06:03:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU9pV7rQocJnlzmGsJZjc+Dv/Fa/3+a7gYxEmlA8YGS9lyWaIbeZPr4sqsyOskrffn7NXd7P/zm8QU=@googlegroups.com
X-Gm-Gg: ASbGncvqhXbDVyFgkPmgvTLjJYuvRcrzgcZLr6vynC3nfvLwFOAWC2tvARuniltvzFT
	/qK9P1ObDRYSDKfYtTtV/mo227Icxv64Ic6AKWx4cXJYAf8GesuyWt1UrzSZCwCrS9+/ZWgcXVw
	DGWhu29dLO2UGS93ciBKlj3B1uQJu+Gyc5N8QSouTLw+2uvlizjk5QfhkuHdrMMXEY7NsadyqMX
	JsKjTGmyFz7cDvaeALjCGbJVy/RVORkPaLnew42RjYNJ1MxJMTl9yEB2QXNHhdHAifEQfuR5rG7
	5u3Ud30lKmf/jY9tjGc3lnMdFt+HiqrZZg==
X-Received: by 2002:a05:690e:4257:b0:640:dd53:71b6 with SMTP id
 956f58d0204a3-64101b011f8mr5047415d50.34.1763042579544; Thu, 13 Nov 2025
 06:02:59 -0800 (PST)
MIME-Version: 1.0
References: <20251113000932.1589073-1-willy@infradead.org> <20251113000932.1589073-2-willy@infradead.org>
In-Reply-To: <20251113000932.1589073-2-willy@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Nov 2025 15:02:22 +0100
X-Gm-Features: AWmQ_blhJPjd2aV442pt2egpwN6npTdDWrkyJEPpL0cKMnNAOIkOIqSIOWUamD8
Message-ID: <CANpmjNMF3RSEtLNKVf4m8wMk-O4-FkdPDbunAsZ_N=h+Rc2tZg@mail.gmail.com>
Subject: Re: [PATCH v4 01/16] slab: Reimplement page_slab()
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, linux-mm@kvack.org, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YyPwsYcW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b131 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 13 Nov 2025 at 01:09, Matthew Wilcox (Oracle)
<willy@infradead.org> wrote:
>
> In order to separate slabs from folios, we need to convert from any page
> in a slab to the slab directly without going through a page to folio
> conversion first.
>
> Up to this point, page_slab() has followed the example of other memdesc
> converters (page_folio(), page_ptdesc() etc) and just cast the pointer
> to the requested type, regardless of whether the pointer is actually a
> pointer to the correct type or not.
>
> That changes with this commit; we check that the page actually belongs
> to a slab and return NULL if it does not.  Other memdesc converters will
> adopt this convention in future.
>
> kfence was the only user of page_slab(), so adjust it to the new way
> of working.  It will need to be touched again when we separate slab
> from page.
>
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: kasan-dev@googlegroups.com

Ran kfence_test with different test configs:

Tested-by: Marco Elver <elver@google.com>

> ---
>  include/linux/page-flags.h | 14 +-------------
>  mm/kfence/core.c           | 14 ++++++++------
>  mm/slab.h                  | 28 ++++++++++++++++------------
>  3 files changed, 25 insertions(+), 31 deletions(-)
>
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index 0091ad1986bf..6d5e44968eab 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -1048,19 +1048,7 @@ PAGE_TYPE_OPS(Table, table, pgtable)
>   */
>  PAGE_TYPE_OPS(Guard, guard, guard)
>
> -FOLIO_TYPE_OPS(slab, slab)
> -
> -/**
> - * PageSlab - Determine if the page belongs to the slab allocator
> - * @page: The page to test.
> - *
> - * Context: Any context.
> - * Return: True for slab pages, false for any other kind of page.
> - */
> -static inline bool PageSlab(const struct page *page)
> -{
> -       return folio_test_slab(page_folio(page));
> -}
> +PAGE_TYPE_OPS(Slab, slab, slab)
>
>  #ifdef CONFIG_HUGETLB_PAGE
>  FOLIO_TYPE_OPS(hugetlb, hugetlb)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 727c20c94ac5..e62b5516bf48 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -612,14 +612,15 @@ static unsigned long kfence_init_pool(void)
>          * enters __slab_free() slow-path.
>          */
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab;
> +               struct page *page;
>
>                 if (!i || (i % 2))
>                         continue;
>
> -               slab = page_slab(pfn_to_page(start_pfn + i));
> -               __folio_set_slab(slab_folio(slab));
> +               page = pfn_to_page(start_pfn + i);
> +               __SetPageSlab(page);
>  #ifdef CONFIG_MEMCG
> +               struct slab *slab = page_slab(page);
>                 slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
>                                  MEMCG_DATA_OBJEXTS;
>  #endif
> @@ -665,16 +666,17 @@ static unsigned long kfence_init_pool(void)
>
>  reset_slab:
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab;
> +               struct page *page;
>
>                 if (!i || (i % 2))
>                         continue;
>
> -               slab = page_slab(pfn_to_page(start_pfn + i));
> +               page = pfn_to_page(start_pfn + i);
>  #ifdef CONFIG_MEMCG
> +               struct slab *slab = page_slab(page);
>                 slab->obj_exts = 0;
>  #endif
> -               __folio_clear_slab(slab_folio(slab));
> +               __ClearPageSlab(page);
>         }
>
>         return addr;
> diff --git a/mm/slab.h b/mm/slab.h
> index f7b8df56727d..18cdb8e85273 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -146,20 +146,24 @@ static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(freelist_aba_t)
>         struct slab *:          (struct folio *)s))
>
>  /**
> - * page_slab - Converts from first struct page to slab.
> - * @p: The first (either head of compound or single) page of slab.
> + * page_slab - Converts from struct page to its slab.
> + * @page: A page which may or may not belong to a slab.
>   *
> - * A temporary wrapper to convert struct page to struct slab in situations where
> - * we know the page is the compound head, or single order-0 page.
> - *
> - * Long-term ideally everything would work with struct slab directly or go
> - * through folio to struct slab.
> - *
> - * Return: The slab which contains this page
> + * Return: The slab which contains this page or NULL if the page does
> + * not belong to a slab.  This includes pages returned from large kmalloc.
>   */
> -#define page_slab(p)           (_Generic((p),                          \
> -       const struct page *:    (const struct slab *)(p),               \
> -       struct page *:          (struct slab *)(p)))
> +static inline struct slab *page_slab(const struct page *page)
> +{
> +       unsigned long head;
> +
> +       head = READ_ONCE(page->compound_head);
> +       if (head & 1)
> +               page = (struct page *)(head - 1);
> +       if (data_race(page->page_type >> 24) != PGTY_slab)
> +               page = NULL;
> +
> +       return (struct slab *)page;
> +}
>
>  /**
>   * slab_page - The first struct page allocated for a slab
> --
> 2.47.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMF3RSEtLNKVf4m8wMk-O4-FkdPDbunAsZ_N%3Dh%2BRc2tZg%40mail.gmail.com.
