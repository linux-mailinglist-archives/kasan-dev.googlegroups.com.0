Return-Path: <kasan-dev+bncBCMIZB7QWENRBCVM4X6AKGQEIVRWGKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AEFDD29CFB1
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:29:15 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id z8sf3214953ilh.13
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:29:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603884554; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQbwtnENnbbUPNGP5drypQco3eNKkIWCTvd6ZskENYkBlsASkG+BSVrlGeURPLhfou
         suGHGZamjYycYaeBnw1/JN5S+415eTn74q5cdvVJgDrXb0kxVjwOS8Gl7l2HF0vD5GIo
         ZtcQggi3P5Twn335u7ZLVF3YhDawhkrI/J/HcgHucmo56KVYE0OqVu62V0vsOy4vF1vF
         XKOAoU1fK2lPlbQindqDZFCGb3IJNwTTw9NYnbr0kaTrpYWWDbSSDX6X6hPdvAVXsUZV
         VbdVknZoFu/2zMa9oSMlI46OIdReim1zzKBwq5dDNl7iNltzz0uT6S3A8hAh9NN6U+R+
         LLXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V+ogOjSmDL/+3vLsBs4yU5s19tw32LA/uZUqaNhuTF0=;
        b=Vdzcayr/4V9czeQKlDHWzhFZgZopN64iVPmFjzjcsedkR6h670xayQXOGKAovk9gWD
         D4ZW/LGt7wz4vPjwUQiYyOZ24+lckr70A9/N5dk6A70be5skoZKepAGa5CjzcnXYmeY0
         92Ff/DGH9dTDjoeezeg2LG+wq5goWD9MwacYDAWgz9GNepI/epDUTTlxD7eheC6CdDk6
         2jcC2jG159xiexs4SCZWIbDG27do36QFC86Ptuuy5QmICmadViqa+QkwvvyY0G8xxr6W
         6DT4FXnMXC7Pv9NzSuNZ0PcJyYm7tql5XGewKgJQZRvFFkauoFdl+X6KuKjc1t6RP7+Y
         jPcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hMNvDItC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V+ogOjSmDL/+3vLsBs4yU5s19tw32LA/uZUqaNhuTF0=;
        b=lXAVmOR4bylclPuFDJKXAORAP0dYjDpnn4RE6vpN4LZ5VgLmxylkLLoS8R7g5fZI5t
         E8LdoYRNBiapxO+LhxFT4ja9UYn3+nLl2XJ2BV7DPRuY3u3TMAuO+E4i09JVL6txKyHF
         NB1z0D5yvaiHOl5alO9KBDnyQzCGhCbVDl7K7IvQwKuw956cuQul+T06voE3FVdlWjQn
         H3LiKY83WwrX2SJURXnh/UYlfKqwEBZRnbq5X35i6DyH4ZRddNwsbQR09v5fHQvDRvTb
         kTXtw3UXfwUcuz0iaYC41IEPY+ImIGtDNLZ89WBZhO1+0bbk97DIwTar3YrIFxSXr9QY
         iF/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V+ogOjSmDL/+3vLsBs4yU5s19tw32LA/uZUqaNhuTF0=;
        b=jA9p4NSeurQ6sGQpNiCRrn+EW8FyefZpLTzQcnEs0q3b9zCZchRqFKl8yBGFRxLr/L
         IhgBSEy7WfYp47h3t3va5509QTUNr/yChgGfGH88ugSacYmlAD+qC7m1BaU7TrKfIWmU
         K9eqUD9E1SJbmGOU+tYL8cO5tnzdMZH2666xJZu4gNaZbwWPxXFdqq/wJQqk0oxBMVMC
         qKtuwsnlYIYWJ42Zf+sJainmrktwS6eSNwyMLvG1YTP0Ys9TXcQFXujmEcyKA14PvISa
         WOoGYsD5xa1KvuTO5QvZSeUGiI48r0pu/KFYVDmJi6Tth55xPe0SkHalUm7gHkjX6gMi
         4kOg==
X-Gm-Message-State: AOAM531moQ9XecMeGRxK+fC4uDLnQLpjytWECuvr0+1tHUfEK4+HbFYD
	ou1IjSoFtbXSIRM9RfY1HzQ=
X-Google-Smtp-Source: ABdhPJwWPVi5vK5bUwYUVsXQ9SkkYDNOpW5Al6+NdZSQOdqitDgi8nyR+4bN9DQ5sZkgvDsBd1aTOg==
X-Received: by 2002:a02:76c5:: with SMTP id z188mr6405564jab.74.1603884554617;
        Wed, 28 Oct 2020 04:29:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a07:: with SMTP id t7ls1045890ili.8.gmail; Wed, 28 Oct
 2020 04:29:14 -0700 (PDT)
X-Received: by 2002:a92:5409:: with SMTP id i9mr5035545ilb.67.1603884554163;
        Wed, 28 Oct 2020 04:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603884554; cv=none;
        d=google.com; s=arc-20160816;
        b=F2hLzoFMhnxqUjUgEUFGMoOqCVjjJ1PsWn3uLuSTEYjybwTgPym9GEPd+cluhD9q8T
         D5icsD8gj2QBHuuBinF4bueNovN+b8IL5O/hDx6q2nwusqviSDm2qG5je2080yL+Rk1c
         SFsKh3gpjVlOu4nnmzigb1Lo+7y8J5e9wPCGwGpvR8nk6/krY7lW5PDAxNTWGLI4tQl4
         38cCvcBHKG4G/nilU8fOasy4JNmuD8sD7oFUzSMQmdAvoAfhFTQejwsMg3gVagZ15MLu
         nj/iH22auWgOPt+DEuLEpuS5WVZsD3wU7PajGw5vDe5d438Rjr/whamKVWjcI7T8uWje
         x7Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OCUxgFfsZm5hmmiU0cs7ogr7Bp2NfxesKIPOcc2vAD8=;
        b=utzNGirSgDpDSkyZ9bq7VGyL5uWBhXhxAZ+mEoAF0ghdH+RCZBK65RKF6uG5UTpvqQ
         26HX4Agsykvzk1r/jUaFfWlZ0Hk46v9LTEx4ro2QhEE+DO6FBOYYCFLbkn1r8HtOA7rP
         /fee5mjBp4BYOLpepQdpYfMG7DWSTltGYuwa4BG1lxBfXjAhdD/c7WGNxmVs33tqdbTr
         fGVKmfCLJbSJlIE7rbwtlrfWARGOIX1ZAiFVR3kRRkpwwV83S7cNN9q+O7V3LDzIcNJr
         13fWVcw6J5wodXUTRdbK1KsVfLq75QpgsZQ1zQkkCAK/s2v5uyOtb2IZCTxGyMLHy3HR
         6PQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hMNvDItC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id p5si271617ilg.3.2020.10.28.04.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:29:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id k9so4111718qki.6
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:29:14 -0700 (PDT)
X-Received: by 2002:a37:a00c:: with SMTP id j12mr931915qke.231.1603884553300;
 Wed, 28 Oct 2020 04:29:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <a3cd7d83cc1f9ca06ef6d8c84e70f122212bf8ef.1603372719.git.andreyknvl@google.com>
In-Reply-To: <a3cd7d83cc1f9ca06ef6d8c84e70f122212bf8ef.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:29:02 +0100
Message-ID: <CACT4Y+ZXp1+_EV5=1Zwf4LCi+RR1tiRYesTsjhFBdZ5owrSCZw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 11/21] kasan: inline kasan_poison_memory and check_invalid_free
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
 header.i=@google.com header.s=20161025 header.b=hMNvDItC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Thu, Oct 22, 2020 at 3:19 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Using kasan_poison_memory() or check_invalid_free() currently results in
> function calls. Move their definitions to mm/kasan/kasan.h and turn them
> into static inline functions for hardware tag-based mode to avoid uneeded
> function calls.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/hw_tags.c | 15 ---------------
>  mm/kasan/kasan.h   | 28 ++++++++++++++++++++++++----
>  2 files changed, 24 insertions(+), 19 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 4c24bfcfeff9..f03161f3da19 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -24,27 +24,12 @@ void __init kasan_init_tags(void)
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> -void kasan_poison_memory(const void *address, size_t size, u8 value)
> -{
> -       set_mem_tag_range(reset_tag(address),
> -                         round_up(size, KASAN_GRANULE_SIZE), value);
> -}
> -
>  void kasan_unpoison_memory(const void *address, size_t size)
>  {
>         set_mem_tag_range(reset_tag(address),
>                           round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>
> -bool check_invalid_free(void *addr)
> -{
> -       u8 ptr_tag = get_tag(addr);
> -       u8 mem_tag = get_mem_tag(addr);
> -
> -       return (mem_tag == KASAN_TAG_INVALID) ||
> -               (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> -}
> -
>  void kasan_set_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 94ba15c2f860..8d84ae6f58f1 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,8 +153,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>                                                 const void *object);
>
> -void kasan_poison_memory(const void *address, size_t size, u8 value);
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> @@ -194,8 +192,6 @@ void print_tags(u8 addr_tag, const void *addr);
>  static inline void print_tags(u8 addr_tag, const void *addr) { }
>  #endif
>
> -bool check_invalid_free(void *addr);
> -
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  void metadata_fetch_row(char *buffer, void *row);
> @@ -276,6 +272,30 @@ static inline u8 random_tag(void)
>  }
>  #endif
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
> +static inline void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +       set_mem_tag_range(reset_tag(address),
> +                         round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +static inline bool check_invalid_free(void *addr)
> +{
> +       u8 ptr_tag = get_tag(addr);
> +       u8 mem_tag = get_mem_tag(addr);
> +
> +       return (mem_tag == KASAN_TAG_INVALID) ||
> +               (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> +}
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
> +bool check_invalid_free(void *addr);
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3cd7d83cc1f9ca06ef6d8c84e70f122212bf8ef.1603372719.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZXp1%2B_EV5%3D1Zwf4LCi%2BRR1tiRYesTsjhFBdZ5owrSCZw%40mail.gmail.com.
