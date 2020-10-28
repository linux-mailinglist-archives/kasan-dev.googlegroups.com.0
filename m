Return-Path: <kasan-dev+bncBCMIZB7QWENRBM5C4X6AKGQE6EODLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9094429CF9F
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:08:36 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id x134sf1607313vkd.17
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:08:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603883315; cv=pass;
        d=google.com; s=arc-20160816;
        b=KtqkvggcFugbhUnMp5W8HvpZMjs+R1I0WPRto5G3oATGCjxZFCp7wRDMUQFZXJoXgG
         4UKZ8rgdYDC3yBj6KLIxL6g0I9kCKvdLY7keH8SL/womPTM6rkn33rVTtPMaNOMNOgHR
         XWjBMEQrp44OHH/G86Mvn6lk59GXD+muU/p+Mgl2ovnQw1YOq+8zhPHuI2Z9r4xoCoLa
         rYyRbrcBOMZsbHN18Ulfpfpm4bgesUYUhaHLk6Ye9jmH9DvPmRpcbZFf+uyK3LXhDQTM
         5mi+cH2H09jlmgQtRhJBBLviIWmiTL28h+sdGs8HK9F+IeZnz5ZQLSh6VNGfHzS3/YLv
         6Lzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1ISBb2KCu/I3a/YHnPoFU6rvDr9ZbB1CGI366rmUPG8=;
        b=xBmdAa37KylByif10lRwXMupnhO9N8ko4j85FnJjThuNCRAO+9GjXUnfA0WQCTQJQB
         gbaDt1UpKnXpSoX+5LqqM01RDxhl6AMvgXuMObTIetmCwb8X1NjZXOBAotrgluKoky38
         7zOHQQpLrKj1A6iD452xrcXvckC9nvDffQjkFecevexpWHnPW9oYX5ntCKxOFxJk9tUK
         UKzZcns5qCx555V7pq+POL19QkX8H9xG7oapqgQD5rSS0oRs0vq2eZGWfsjtHQMEB1cW
         bsUEEZXgJ7n5VFsxkJ0NO/9vmfme/nFQ/bJ75Jf8Eu9ZPBMCj3tfEiSIENmIlQirB3AR
         rakg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HT0S21FF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ISBb2KCu/I3a/YHnPoFU6rvDr9ZbB1CGI366rmUPG8=;
        b=YAlkCVuryjaz9FhhkucdB8xwRBkWsxlbyTqn1pdxoI96VcCesVP0ZbvSED9tqaJ66o
         i153WW2AomwNBmdkbPsb++BP47/+R76bPu9BR5MT/0qccPCpBrUhgSWYn5QeyS+U5+Kr
         ZgSSFqFKNW/p7ELQja3SG2ks+nfFZlnDYAtrQW8G8sfWv+c+FPB2fN08qMWl9u9iLWFi
         bhQi+KVe+uANLwOrBI4avZqi0iO4DEaOvtxNc0W6KL8WOCsc2/QXNeyWk/JX5udUkBxu
         NaGdIK5xoRMjdeFb/NNOyC7oawD6vIbLxOSpeJxIH4WQg6ydYL+Vxt9vnMqg7PZ8XH0g
         5n0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ISBb2KCu/I3a/YHnPoFU6rvDr9ZbB1CGI366rmUPG8=;
        b=LeDDMcrvbAihACHZU2rzPHC0MmTGDzzK0Ctee0HKxBcnlmrWteHq6rYg7N9m7rdyhM
         nCMMuNyAQBE9LyvZfFTSe29dW5j+UsXjTDuRi/bXi00v+SylGuZyDc8dcrftIk46XaAB
         8kND7ni+LJKYXQZPNNBmxzJZjXMZqfB92yAHn5YbauPDDyYPoLU+1EYeyK3zk9MrOKyF
         K9ZJqNNXbvr9uavNFFXl7H9/Lyz1uj7JZfzMKASgMEN6hMeSc7TRPvSDMBqMS+P3ri7x
         PEZ9+WY7TRrLWO7YWPSubOU5ZevgGSLAVMbRBWDD1xU2fTt/KVorSNZH3T5tChOUYUb5
         ByCQ==
X-Gm-Message-State: AOAM531+LD9uHZK5ukmFTgy7Ksp9RYLj89X5BgtLIDDUpnAfZ9rMXYB6
	ezBwgeLvNk6Y2jv6vmMdWtA=
X-Google-Smtp-Source: ABdhPJzxexdZkl2qYwCLrs4tfZ3al0E558X05AJw42+JqKfDuiSaNtxOhtEWcB36GbTyh/iT7tRHRw==
X-Received: by 2002:ab0:67cc:: with SMTP id w12mr3879752uar.123.1603883315566;
        Wed, 28 Oct 2020 04:08:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e29a:: with SMTP id g26ls582198vsf.6.gmail; Wed, 28 Oct
 2020 04:08:35 -0700 (PDT)
X-Received: by 2002:a05:6102:342:: with SMTP id e2mr4961509vsa.3.1603883315082;
        Wed, 28 Oct 2020 04:08:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603883315; cv=none;
        d=google.com; s=arc-20160816;
        b=GhTXLkuRZIDp4zLcLCGj77wVEIiZUFz6qex6+//3d54vw9XktJqFo27pyy6qKQmSOl
         Ci+qDJTnZEQT4pv9e2puxAvOZl5iV7gam31J3a7oRIIP12Xe/J0/P5Vx8gUHlDI/V5WV
         314obNLaSjEC4+yKhQ9PfrNINmEtyPrtkTqWrhSBN+RHI4jLWq6IcJBI9kQVxM+lP61I
         zuYm3eEFF/7HcEU7yWxFsrE17kEeeTQVwyFCe2Lz97hIedSoInkEGYZktQxy4qQENGVX
         1rOEldkZfh4MVNF8j4LSTBzFoz2p3DLp949ZeidnBihQEkUSPkWvJUKjHn1apIfLxuEB
         CE+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BV2fbXkevBYTBJzl8kvjc7MGIINM37SNxFV2YU5u4pc=;
        b=d496Uvv3kfIm/p5iRozMfg8Gpo6eQqkYJtqiW8fytgCnoYxJTRef3GiLQAtwqhmBTm
         n/L0hFUhtIoScg/xlbup+pzuyAIq5EPpe64OmCND9G9R50q7oH/lo3u9LjjXj23QzTX2
         6iFitvdn2JIu2e6Us3vsxcTFz+qyMPZbbB71/mUAW+HBQjwlHRKnN588RQWT+1XDHhlP
         WrUeZKb4HryRGPoXwwWR70KYZbnTtUCWmVt2cazAMZciAXrhslUQa8WlP7++tUxQFVGi
         0lKcnLT+hW6pCtVXOrfMhXEp9Gqs3YDkGc6NzIEy/eOQEvnBe+t9UixtWGZIQTg09aMg
         FBNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HT0S21FF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id r131si248023vkd.0.2020.10.28.04.08.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:08:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id 140so4074085qko.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:08:35 -0700 (PDT)
X-Received: by 2002:a05:620a:5b9:: with SMTP id q25mr6625803qkq.501.1603883314438;
 Wed, 28 Oct 2020 04:08:34 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl@google.com>
In-Reply-To: <56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:08:23 +0100
Message-ID: <CACT4Y+ZVjEQaQExenOPg-tXQKRE5wUEm_iDn5DUQH_4QC-DBzg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 10/21] kasan: inline random_tag for HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HT0S21FF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Using random_tag() currently results in a function call. Move its
> definition to mm/kasan/kasan.h and turn it into a static inline function
> for hardware tag-based mode to avoid uneeded function call.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> ---
>  mm/kasan/hw_tags.c |  5 -----
>  mm/kasan/kasan.h   | 37 ++++++++++++++++++++-----------------
>  2 files changed, 20 insertions(+), 22 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index c3a0e83b5e7a..4c24bfcfeff9 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -36,11 +36,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
>                           round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>
> -u8 random_tag(void)
> -{
> -       return get_random_tag();
> -}
> -
>  bool check_invalid_free(void *addr)
>  {
>         u8 ptr_tag = get_tag(addr);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 0ccbb3c4c519..94ba15c2f860 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +void print_tags(u8 addr_tag, const void *addr);
> +#else
> +static inline void print_tags(u8 addr_tag, const void *addr) { }
> +#endif
> +
>  bool check_invalid_free(void *addr);
>
>  void *find_first_bad_addr(void *addr, size_t size);
> @@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
>
> -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> -
> -void print_tags(u8 addr_tag, const void *addr);
> -
> -u8 random_tag(void);
> -
> -#else
> -
> -static inline void print_tags(u8 addr_tag, const void *addr) { }
> -
> -static inline u8 random_tag(void)
> -{
> -       return 0;
> -}
> -
> -#endif
> -
>  #ifndef arch_kasan_set_tag
>  static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  {
> @@ -273,6 +262,20 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define get_mem_tag(addr)                      arch_get_mem_tag(addr)
>  #define set_mem_tag_range(addr, size, tag)     arch_set_mem_tag_range((addr), (size), (tag))
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +u8 random_tag(void);
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +static inline u8 random_tag(void)
> +{
> +       return get_random_tag();

What's the difference between random_tag() and get_random_tag()? Do we
need both?


> +}
> +#else
> +static inline u8 random_tag(void)
> +{
> +       return 0;
> +}
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZVjEQaQExenOPg-tXQKRE5wUEm_iDn5DUQH_4QC-DBzg%40mail.gmail.com.
