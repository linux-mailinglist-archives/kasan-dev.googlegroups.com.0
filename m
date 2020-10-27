Return-Path: <kasan-dev+bncBCMIZB7QWENRBUVK4D6AKGQEWARGSHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 46E0C29AC4C
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:40:51 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id j10sf1231447ybl.19
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:40:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802450; cv=pass;
        d=google.com; s=arc-20160816;
        b=RRiGGo9aHku04lG/ixXIf19Sxi0YOOO27PB2sERsNrb29QHcanTS7NkNUEhofXFJE3
         nHkdhBwJLsFgDH/z8YJSIpK3Oi0TkxBRZZ4dTkwHmN588ooKNAMmnE5NmO/rkB6TN4r8
         BVt0YhVwM50CrjJpinIeS7//Ni8zo/4YNEGW5+l9Qv/1UwBe/o06XKXOwz1tnArZu5d6
         rBfDqzIbK+cvXXEPBmvMCgdgFAAKrAR1/iSeSJCqLqlSPnK6MKGWsFCgx/OQ37CySGEn
         ALiNi25/ytIpUvpoteiWTYqJqGNf1AFcZDA6Em2PRzUGQwk4LzvTvc5px7NbnFywLv3w
         7lLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2V+iI5K2tBV7UglpdxkTxuFvRGRGX1eP/W0f3q923HA=;
        b=q2MHdBFLJN/odCRxIiTmhyshhw6k1a4NLAdFRnGdJ4pAZWXORraAz540LY7VeX/IBE
         pofy2jzkIWUOfw0Dr8oMYUNdnji89P+5mtVO7Gz2fQ4DFZdaq88kh8Tw2bYvrCDxtRYs
         iB4K/nFxXQTV1z//s1etAGe2OwpWoK6uZNq1Pg1yhRmIQ91h8fwcxfv7KVcUIcwBCboM
         OoJSIVxN5SKzHU+5cIUhY7G5n0tMu/lidNvM8c+DyJ6Lwyt4jWi80229gOoRlpO8ndTi
         wsgtCc4SCRGJnCNEDuhRcWh/X3n46nrVuvwPVsvliFL48aAHK/3ghewtfZgo5Gg7Zv/D
         i0gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eXyC7a+k;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2V+iI5K2tBV7UglpdxkTxuFvRGRGX1eP/W0f3q923HA=;
        b=DgsBKc3ORhBSPJ3+r0G+uhAJCalC011nuNYQwcVnQhCZCabOBqAt9pRpPeupCVIPec
         q8yG98y96yr2QMhFkdu7sS/IOYuB3Mdb78Ri3gFkcX6kCz+OglXuVPMH5IKixxUY8V9r
         6iCbH6E86Q1lhNFlurajnbyU/E+Sd/gxeeXS75s0K13MuOvRgT6r/phR74LCMVeZpqwa
         OLWz3zTAEXAlP/WCSYi8x/7yyylBkU6hlmN4/ZK8k0LF9r4gLl7UcsqD91bbcR7n9gfQ
         UJu+N0ddHxyCd/ucU5skkAiT0UTLkX12umdSy/jTlNRUBJrzS42q4rrYmRJHXuV4qNqi
         Xnrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2V+iI5K2tBV7UglpdxkTxuFvRGRGX1eP/W0f3q923HA=;
        b=THkOxp5oE9YRDopiNItlWApb1hG+XYQt6NWnK1+AWlc8ml0hl48lYeUBnkHhBZOyrq
         Wtebiz1G8n/ySd4TvnjC36gCU3ZFmkog6G31RKxG3+oV38SMhR0l+MKLpSEKdNJ1Fq/1
         cSPzaPpZrxEC+7xBGG3T6imwQfb/pbDnhWDBg5j78gr0HqQBgO+toJGUZy0qvKKWZBsA
         dgPrmiokgxmgMgxt8Md/5OWlX8eFsp9LDT+OsJeUCMv3n/DeBUarCjLxhseX31EZN/bV
         SjPMZffEATzX14hhnipUfXYhFR9Pd0Ewf40043urEtt7aMiewemdFFFBFw57W6gjzsyn
         1NUg==
X-Gm-Message-State: AOAM533pHwXblB17TiJKpDRjsu5MsmlvE0YuSkM+2q3wPVFQodeqHP9W
	EWpD+BKekg04cirzmC+qiwI=
X-Google-Smtp-Source: ABdhPJzGMixw0v4IkDGJAqKVqA+dF8B3g0DVl9tqllu13Ey6NXfT0I37ROf5xDuBxXCy/KfbVvRQ6w==
X-Received: by 2002:a25:7444:: with SMTP id p65mr2895391ybc.57.1603802450319;
        Tue, 27 Oct 2020 05:40:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c04:: with SMTP id s4ls729783ybs.0.gmail; Tue, 27 Oct
 2020 05:40:49 -0700 (PDT)
X-Received: by 2002:a25:69cb:: with SMTP id e194mr3055198ybc.227.1603802449859;
        Tue, 27 Oct 2020 05:40:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802449; cv=none;
        d=google.com; s=arc-20160816;
        b=VEm9ilsqTd4TzYNEEvuCU9cNzZtsTMW8e5FrpIL4sseuFiamJo5HR/5j87YAoLp4Wn
         9lFLFQ9SQn/OLzkiH+iWiXA5U1E6VhAumtZ/ds5hm5mgDhqvpbfaFNxMh3SeTA2mOBXe
         EZYuc59ZXtv+q6iNidk6/106zmSpDG0oc+10hYRWHtPjxcA+85YOGz/SFqPzlFEMtsOb
         snMRa43AqV9Un85iBejMUUMF0quZIJQq2cSlHRj3GSr75KWX+W3FZzWmhMG1RnjA03hC
         w+WWiYR/ye38bmYQC6fjDW+jTU3gIqcI96oUz2AnhSUMySAeEmxm1n54mMGI1OhTdI40
         zVSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O2tDKAOxc+uu+1RBFzTdO3JlDCHYZwi+KFiWnGXj6D4=;
        b=yZfEREdPhJ4uy+Ju5Dinj3u3UYiOJIjiqR7Rt7AZDERyfuhua8O5w2zhMHSFb0RVVc
         7EkzlKEz6Lu12OH0Be5Yb8JlQcpF2gCLgS1GfZO240xDqg6VrEUs2siOSl9PszKG/ZtD
         BdKgezrBkT5qAKk58HQT6UToh751VdY5pKTGbomBKJ24f9g5DYQBjW+87gGVrnGGS/vA
         +uGfg+nYi/puX1usyJnwUbvNvqfZKSS9eeBuqLtxis0pXzlXmtrb52hy909xHkzOVgda
         X1Zn/6eddFeS6rzYJyT7xhaYWTP2M9w7BypKKaOG0npD3ixTNMRVE0hkrIqJE99ZJ80k
         vE6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eXyC7a+k;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id r8si82790ybl.1.2020.10.27.05.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:40:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x20so937557qkn.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:40:49 -0700 (PDT)
X-Received: by 2002:a05:620a:1188:: with SMTP id b8mr1912592qkk.265.1603802449178;
 Tue, 27 Oct 2020 05:40:49 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <eaeb053a84e82badf1ade6cf7f9caf6737fcd229.1603372719.git.andreyknvl@google.com>
In-Reply-To: <eaeb053a84e82badf1ade6cf7f9caf6737fcd229.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:40:37 +0100
Message-ID: <CACT4Y+Ywj+q8zsED+oqAj__2_gBKVcjr3ngVoCwCe7HQKssS4g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 01/21] kasan: simplify quarantine_put call site
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
 header.i=@google.com header.s=20161025 header.b=eXyC7a+k;       spf=pass
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Move get_free_info() call into quarantine_put() to simplify the call site.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c     | 2 +-
>  mm/kasan/kasan.h      | 5 ++---
>  mm/kasan/quarantine.c | 3 ++-
>  3 files changed, 5 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2bb0ef6da6bd..5712c66c11c1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>
>         kasan_set_free_info(cache, object, tag);
>
> -       quarantine_put(get_free_info(cache, object), cache);
> +       quarantine_put(cache, object);
>
>         return IS_ENABLED(CONFIG_KASAN_GENERIC);
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 6850308c798a..5c0116c70579 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> -void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> +void quarantine_put(struct kmem_cache *cache, void *object);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
>  #else
> -static inline void quarantine_put(struct kasan_free_meta *info,
> -                               struct kmem_cache *cache) { }
> +static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
>  static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 580ff5610fc1..a0792f0d6d0f 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
>         qlist_init(q);
>  }
>
> -void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> +void quarantine_put(struct kmem_cache *cache, void *object)
>  {
>         unsigned long flags;
>         struct qlist_head *q;
>         struct qlist_head temp = QLIST_INIT;
> +       struct kasan_free_meta *info = get_free_info(cache, object);
>
>         /*
>          * Note: irq must be disabled until after we move the batch to the
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYwj%2Bq8zsED%2BoqAj__2_gBKVcjr3ngVoCwCe7HQKssS4g%40mail.gmail.com.
