Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSHYUGDAMGQE3B6DAOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E0753A7B6C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 12:09:13 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id w12-20020aca490c0000b02901f1fdc1435asf7300022oia.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:09:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623751752; cv=pass;
        d=google.com; s=arc-20160816;
        b=zNn5oi3F6EfZd9U4tKns4ZDEGh+J1QA13VTkdZjNL8JrhFqvbpGfYMxpw1XZ2XiAHX
         bS+VcYuakbCh/tPXvZOeVhdJpmlk/toMOGmI5j3lIvAefT6eJ1AQFlkH/fvF6irS9t8w
         TddV77nY4ggGKlr/9MJo0WuLUwh6bS2HCFTi75kSf0HPstehTa5p6i1hg73G5Jim46QQ
         0EaSFXxJuT/SdaM1uRiACXKlsEMfDNuREWBQmEqU1FS0DpccMZlOnHYInsNUCs3Y/wMX
         U+1B+n6PuBMli30mQuSL3U5BPjSKrgwXfgyHo5yXRXzGbTwC98SgAt5K+Zt5HMUd3LrE
         daKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xny432D1kDzZ38HxExC9V8+BkUe9HRfhkvAYsb8fZuY=;
        b=vnFSa975q+kQHCjoSHfP4auuxL+yr5fTn7eMLZ/7xkMVcvh9hWq4uHAuvi3nnzRIyQ
         +wxhV9yN2ulhx8eCiB2Am/zhvIVyjTOT4u+Rpd+PEyX1jrTDJfSV9yN3vjg6CV4R3RFI
         h5/mpIDkwekHEdewa/4WriQKQU7HdWkjUBSmstPonYFTRvqgx0A6jptdf1JDbLiZSMyn
         /Kim3ra+12h57RVBArwTRCGWY2os5GzchPuQ7AhbfrhU7zXsl7MYOgfcl18q2Xm8SRda
         JfWFUWw2OunLKRCA8FbFFCdn8ZCZalGIs7zr75ngZxUrmd5WHZyF9Ki3Mt+x0LMZh1vL
         DZfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W/lfR0zL";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xny432D1kDzZ38HxExC9V8+BkUe9HRfhkvAYsb8fZuY=;
        b=J2ah5K/U8UBsP3Qy3UXiOuxXYwasTYCstUgy2uraDl6U1uY+Mu3hsYh5BGzBRo5hc0
         DDLhL+9L0TcHv6SmzLxXVyaGveNwZxjYu9NAW3vCZYQZGyzLSlGmXYKs+4h9sHQaoZZo
         pce1R1n83WmW6cnh9fNEXWZMEQibwy+cVU5g3EQybm5Qm5+WxuFCg1+7SXrgJPPfwCZ8
         FtrJVktK7YZydvTF1CyZjsXt2JwAbwaxB0Bf7H/Vvb1ZjwjYfluitcC/Nec1pOw78Mfj
         VktjWpS0j4E8aAMZTLGhpJOkXEuMukQ32V7qhWjH0BAyruBJ94/chxEHfeTTt5dw0p/1
         VM0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xny432D1kDzZ38HxExC9V8+BkUe9HRfhkvAYsb8fZuY=;
        b=qiHZsvzxYRbWJhU8H/M1NfEUb2rsbqimojTZwbNgMXWqGVgXpEP0fmuTDlQS9l+VSn
         mcQyF0WGAzDybpq4bQg88k0wZZ52hfWyzY9e4/GkkMnocijHDRal6cic3jBIoNMjeK4l
         pdiKOirn42IxG5UznRMM8k91ZDdIzU/NpIoAa6At6+gTXwLo2m79N3ohmfTEXbVgJAHB
         rrMZL9utfSN6GEcdM1+MdX1uAuLYdIVWM3Wnt5eVdvz4i8w0tGoTzdbz60xAk6fpACjF
         g6YNMk9Tb1ook9RLbdCtGre2d78Vl5YyffJusqaj9TzUukbURALLPu054O3Y+j2dxyHa
         qp6Q==
X-Gm-Message-State: AOAM530iEfj3bKf7IXsPDfZYCFSQHX38i6hcUb8nQVtJuMdjh7hv95LW
	1vlq0Dl6JtgdS0XqvuluXN0=
X-Google-Smtp-Source: ABdhPJx1Wa6nc54QWLEvLTa82E1CE6oWPuX39nxpjbX7l8ZZcXiy1gxT/0oFB1276k03Mg6oaBiC5w==
X-Received: by 2002:aca:f482:: with SMTP id s124mr2594109oih.167.1623751752194;
        Tue, 15 Jun 2021 03:09:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:494d:: with SMTP id z74ls1759728ooa.9.gmail; Tue, 15 Jun
 2021 03:09:11 -0700 (PDT)
X-Received: by 2002:a4a:a744:: with SMTP id h4mr17048427oom.26.1623751751822;
        Tue, 15 Jun 2021 03:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623751751; cv=none;
        d=google.com; s=arc-20160816;
        b=d3Ey3hvyOspLFbU6WGwyxRwzxKvfyKZod2ERGiaCm33ixVF3WuUu/1I6R7yuAb2pwx
         celYa82V/Cgcusu5eLgVjwQ2H/d3CAmF8DGzU/G5+i6Z/jDFR8isLSgdYuSBvpSuXTcS
         O2trdUrMrNjmNdWZnsaaLXRVAVXMLY/pnzG6xxKk6GOfJHmdllS4ALPZoK2ez+QI85en
         /5wwuP6WOA5N0QO/HxyRdQGmWB8sDdSfiomV7bGp9EFPu+aE2Q+Dcb6YSCyys2B+HAQB
         Kw1UKcEGGLMACjeyPgcVK7oxVgPUKk/GHjpdZ2+IKVwgUM500R3bZ6kr7M90uX/tuTDv
         e7Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D/L9M46eaaH0QBqlJTDr9j5/a1oRGHp298rEoHobuSk=;
        b=IMMK1NTu2FkAy68LNguViaF3nrnvteZt5EOx6hYNtdQwIsJLV0CE8vMvf75L2L2xMG
         I+LsxB/ICUeQ+ShUOL3VYoI+33a9wvJ3gnDjjhciCgUn7pzB1Rq5NqspThjj+lyITJD3
         QHawH2GRt8NzlRCF2Cz8UBejFbRUgnPpS73Qr111ma82dzm/hqSb+jPJlMuw4pq7Wcnr
         i5i2MERPzkctEjSGbWWDBJM/qFvLR/d8VAxchu/SJzUh1siE0cTTYrmWhYdCubuwYRq9
         Jf8Xf5iIZU3mJ/17bqP3jTIwsxvZgHttu5XWUeR0nZMN7UoTe1KCtLfmw23ScSq+W7ao
         t2Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W/lfR0zL";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id k18si205243otj.1.2021.06.15.03.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 03:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id 66-20020a9d02c80000b02903615edf7c1aso13705798otl.13
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 03:09:11 -0700 (PDT)
X-Received: by 2002:a05:6830:1c7b:: with SMTP id s27mr17651144otg.233.1623751751394;
 Tue, 15 Jun 2021 03:09:11 -0700 (PDT)
MIME-Version: 1.0
References: <20210615014705.2234866-1-dja@axtens.net> <20210615014705.2234866-3-dja@axtens.net>
In-Reply-To: <20210615014705.2234866-3-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Jun 2021 12:08:59 +0200
Message-ID: <CANpmjNN2=gdDBPzYQYsmOtLQVVjSz2qFcwcTMEqB=s_ZWndJLg@mail.gmail.com>
Subject: Re: [PATCH v12 2/6] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>, 
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="W/lfR0zL";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

On Tue, 15 Jun 2021 at 03:47, Daniel Axtens <dja@axtens.net> wrote:
>
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>
> This will only work in outline mode, so an arch must specify
> ARCH_DISABLE_KASAN_INLINE if it requires this.
>
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> --
>
> I discuss the justfication for this later in the series. Also,
> both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
> ---
>  mm/kasan/common.c  | 4 ++++
>  mm/kasan/generic.c | 3 +++
>  mm/kasan/kasan.h   | 4 ++++
>  mm/kasan/shadow.c  | 4 ++++
>  4 files changed, 15 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 10177cc26d06..0ad615f3801d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         u8 tag;
>         void *tagged_object;
>
> +       /* Bail if the arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return false;
> +
>         tag = get_tag(object);
>         tagged_object = object;
>         object = kasan_reset_tag(object);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 53cbf28859b5..c3f5ba7a294a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
>                                                 size_t size, bool write,
>                                                 unsigned long ret_ip)
>  {
> +       if (!kasan_arch_is_ready())
> +               return true;
> +
>         if (unlikely(size == 0))
>                 return true;
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..19323a3d5975 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,10 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 082ee5b6d9a1..74134b657d7d 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>         void *shadow_start, *shadow_end;
>
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +

What about kasan_poison_last_granule()? kasan_unpoison() currently
seems to potentially trip on that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2%3DgdDBPzYQYsmOtLQVVjSz2qFcwcTMEqB%3Ds_ZWndJLg%40mail.gmail.com.
