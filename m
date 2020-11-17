Return-Path: <kasan-dev+bncBCMIZB7QWENRBROZZ36QKGQEFKN223A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D98E2B5D8B
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 11:58:14 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id c2sf8881662ils.7
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 02:58:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605610693; cv=pass;
        d=google.com; s=arc-20160816;
        b=hbBPfKR0VIBdRGqweVCLK4md3+KQgpHujwcQ7p/4T4JcB2t49ogx9pbjbSWOJf7wcJ
         e5mKppaJ2BjLXpej70Xzt3KlCgU9N3J8FP53g+44MEA4NVrOdyaWjwOpVYG/n2eHplaW
         2T1IDUfKO72nbMaD3zwpmw2oqgxXkd4Wl880p2F+l+Ra+cWxK7I21Ev9maZyCrRq66PE
         76Mh9/vBf6999qpvU4JWkqZRX4OjOSr76xzZXqxXb9SrzG73zyrULLP5x0002YhdHXxj
         dDGbWMdkjPozckmuHPD/6mG3ESd3fvZb/761RiDZOtajxBZ0B9Rsl7cZDn9AC7uONiJH
         E9QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V/8JVXea+2aYSpDl99jVSrFQpij9fUARiUJeLEO0Avg=;
        b=cHRb9eObCNLeeuPA4oSip6o8w7G2cq60WKgCp1yZmiKYYoZwt0cHA1SKRHTnc7de8h
         QuwUobD+iKnZfYmDVrzyg3VBZuBdHDqIauMgZ5XGMxi7R7OkQZ1R0ml3xrhtxViIhcY8
         IWb/75JaDMp3LmgNlZGjkmMASLE7lMu0i1vllb2jG0ebceSf8LEhKweIUzx2vZkzCpO3
         qaEcgPkAJNOlF6JUBQ1UG7kvqpKUusguH+T3PoxzKPtT7+C9oI+UiejftaNEl8XIvUwe
         87NsaeJk7OPB2X1pBm2Nk3SvzAmhOM6OcZiwMb1++I+XB6iGRIk6omloVzcR20agc1HY
         Etig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fDqno3OW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V/8JVXea+2aYSpDl99jVSrFQpij9fUARiUJeLEO0Avg=;
        b=SVU3NJzSXYgC0R73a3hg3ME5Bh0E0+DnR7GxiFDmaBf2r8cLtivY+7Tc/77L7PP8vD
         AcpUNm+xSXqSGTHZVqntdhwFm1wy3P6PGhZJkcYTMwnAvEmYIDZTHyoHCIT6e3WcjEUn
         QPWSk7qgNXWSp/+bDbIBarolDM7y2GpZ+o9Q3pUlNUNUI+1x5c5BjfxzBZQDOJ8Nylkg
         UlX2G18SjaB5jtVQF3ctHyzB9zKGQf6tLeTM09wf6lMuTrgri2tcxDxxr5aA1kgRqaHH
         X0gLyBTcYDvPkcea56VN9HSf5C55nLVliKPTYboXUF7/qgtCLcS5eK5nCXUNG0FYTcEo
         Emuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V/8JVXea+2aYSpDl99jVSrFQpij9fUARiUJeLEO0Avg=;
        b=srE+XZpvrqnPiL8fsf+7EZ0NnTpMvZruHJbsx/BRMDSm0fTYOsgDeDwIKxiX06rYy1
         JcaimAlJS5HzeUnYp794KkMVq9rReAPfdvLIwMA4EQtQ1S9CWtJ7axi7ub2lShyOLmTP
         tSmenyiHcFiCXujLkoA+loyqFk4zbS7e8OsuVaDyzTIfBy53sqeUbDlRrDHQpv7vaCSr
         94t0swmdsDJutQOb1w53gx8AlDxDcXGAEep+/05vgSe5WYyZCJPbktVbSmI3B/EV0Ona
         g1LcZe946+SWCcIRm6P4C9suu8HqQYHKqs28wiOsoZwyVipuBN/yZ8GE0tIZFSqxAydQ
         wLuA==
X-Gm-Message-State: AOAM530VZ1P9/Vv/NbuWNKFAtEsdhQdGEDAu3zMXhmRYDLXoyU/30YEu
	2xYOoujlhaLdYjns3ZBo0Fc=
X-Google-Smtp-Source: ABdhPJwMpXoOdGvwSqjxAZHWz8cPJiVPlmyQfMV0vKhN3t/1qsTyJ/3SOLrM162XI2r31xUCC74dpw==
X-Received: by 2002:a05:6e02:bc5:: with SMTP id c5mr12347966ilu.132.1605610693428;
        Tue, 17 Nov 2020 02:58:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:968b:: with SMTP id m11ls373225ion.10.gmail; Tue, 17 Nov
 2020 02:58:13 -0800 (PST)
X-Received: by 2002:a6b:3c14:: with SMTP id k20mr10881248iob.12.1605610693054;
        Tue, 17 Nov 2020 02:58:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605610693; cv=none;
        d=google.com; s=arc-20160816;
        b=mFlvM+gqTzTIDGG5Jv9s69YPRHmuBTwcgFRVdpP5qlK657zUy9fNPIjg5Jt9l/shjO
         eeajB9HTA76oP5fpC36Qmy9Qvm+jZhzAXqp7zgcfcmlyhNOCgguPgEDlXz9J7q5Jsf9x
         uKIhUHiMnHcO223GTQ5pAx49h+Fdn3ETIc9LQsx3u0UPJnDHQi5bNGQfK3aNIMONAdHC
         IvJdZ4I6GEwJ9kxWv7NqeXT91zoGCnE651XJRyFbaxrxrL1EyXfj8wL7fnLwvQvn8Txx
         cFOYbjG0nym0aZnMW6umOxxg4jAxQRR7Orgh3OxJpGVvVO69opcke5B5FN3i1VtO8KWI
         ocEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+Jz410s78Ji+rZ5O7FNsycPBxAAt6VG4My0PmY/OfBI=;
        b=KmgkPBseWhSbm/KEORd6mTmYa60doSYZ6jaEATuIs/Xe0hYrNB/D02hrQVhzV9pktX
         m05KzXf6y4l5paVtzYB5XBuknhfXJA4jowq5RolT471tm60b4yB4F2IWcofqWEZ0AifC
         CbnIT94to8gbn539B6i+zZzJzqkNt6Dji5ZCSGob42nTIGtbm2/WCh0tB+I3LzeWEAUL
         R3iUXtu6UZ3s6DH2fypeRqKHPzdlL3yzrjFHVLd5fI03BfulPO7pZCOczRc98hGAcwL7
         JN/d+sve2TO35y99wo7qbx7vO4OcpDhFbUqmCs0xPFSKPcIcPzBazpjSiujpLpbF66Eb
         FcZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fDqno3OW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h8si1225619iog.4.2020.11.17.02.58.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 02:58:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id 199so19887403qkg.9
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 02:58:13 -0800 (PST)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr19464097qkc.350.1605610692298;
 Tue, 17 Nov 2020 02:58:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <d42cdd23c59501ccc4ab91cf4e04dd134be57277.1605305978.git.andreyknvl@google.com>
In-Reply-To: <d42cdd23c59501ccc4ab91cf4e04dd134be57277.1605305978.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 11:58:01 +0100
Message-ID: <CACT4Y+aYcegV8ZqxYGa0PuK-J97Lh5jXoVyciHW0fuEJPzZBvA@mail.gmail.com>
Subject: Re: [PATCH mm v3 08/19] kasan: inline random_tag for HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fDqno3OW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Fri, Nov 13, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Using random_tag() currently results in a function call. Move its
> definition to mm/kasan/kasan.h and turn it into a static inline function
> for hardware tag-based mode to avoid uneeded function calls.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> ---
>  mm/kasan/hw_tags.c |  5 -----
>  mm/kasan/kasan.h   | 31 ++++++++++++++-----------------
>  2 files changed, 14 insertions(+), 22 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index a34476764f1d..3cdd87d189f6 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -51,11 +51,6 @@ void unpoison_range(const void *address, size_t size)
>                         round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>
> -u8 random_tag(void)
> -{
> -       return hw_get_random_tag();
> -}
> -
>  bool check_invalid_free(void *addr)
>  {
>         u8 ptr_tag = get_tag(addr);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5e8cd2080369..7876a2547b7d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -190,6 +190,12 @@ static inline bool addr_has_metadata(const void *addr)
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
> @@ -225,23 +231,6 @@ static inline void quarantine_reduce(void) { }
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
> @@ -281,6 +270,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +u8 random_tag(void);
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +static inline u8 random_tag(void) { return hw_get_random_tag(); }
> +#else
> +static inline u8 random_tag(void) { return 0; }
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> --
> 2.29.2.299.gdc1121823c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaYcegV8ZqxYGa0PuK-J97Lh5jXoVyciHW0fuEJPzZBvA%40mail.gmail.com.
