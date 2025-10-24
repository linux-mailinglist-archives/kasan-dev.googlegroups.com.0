Return-Path: <kasan-dev+bncBCUY5FXDWACRBZVN57DQMGQEOHNHRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 143C6C07F16
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 21:43:36 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-592f0214ee8sf1824887e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 12:43:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761335015; cv=pass;
        d=google.com; s=arc-20240605;
        b=U2Un9Uex09i9FYPkvcggxxTxU/fvK2/aI+Q9uq8v1RIEmsi9UfIPhptCrCik9AmJ07
         +SWoGdL78uYYtLT/8jXhr+7cvsDgnHT0S+Oy9noeZ9m8ebZPPn7Gm/XMYgMAhJI8UJ+r
         TIgcmJJ4NgKBDiSYR4XlGHIZ8JH9wxJvDB1st62a2nZFkJHMK7O9IpCpCRzdlvrRQqid
         z3K1FEW+qp8k66CJ0RnPw80mpFEBy8nULboDw6d49bTLjpzY2KdGNCuJbaJdDDASO2ef
         DMybFuv8ZKVoK4uW8wwSoJvhtGz0aVOCWhgu1yWV4QwI1DRx+CUK/87A4V1yx7XsEgNc
         MWrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qKnsuP2nwIg9OdbABczugKceoUbQO6q2GnedMy2AMA0=;
        fh=ria7HfThvvIZqKCQtyDsnGoEj44MbFW8YL6ZATfKtLg=;
        b=BOu2R1G7sdwLsfAvKoaI0NrLfFWuLuUt2v5G9gZOwuVi9MOYl6CtiFUDhBCVDEh3JO
         X3mIlKB9L3pYR9LHd1jqA7V+BWYq69XHWgwT7PD0/EuoVy9Ao2ECiTFg8ZOx1XP7Gmnh
         pgR2JHACjXXhifCmGtZSyCsEK2iI+OFb3cDT3aXaZSOiSyUJ8SI47NZ1/pSbPC4YRVmU
         u3YKZtdcPoyL1X6EfSk7Lb/JdOTvYWNYmOX9ZByihbu2Xk3VAw66WbUoUbQbWbCh5j+1
         qrSIEWVdX5UGjX/CeGQ5rseZEHARIeBcMe437nhbhLCzkF2gPpXamZ48vpNJVkq/nlkN
         nB3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="G+h/yCUj";
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761335015; x=1761939815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qKnsuP2nwIg9OdbABczugKceoUbQO6q2GnedMy2AMA0=;
        b=OsPVxbIyav+TmCar0UrmSnG3QEwEeEuVr1fVCAUOoZ19KZ7L+VoQ77xiQPToTLVhy1
         68m4X/fDbdIdfj/Wc1u4SjyDGa+S4eCbmseg7KJFCmbJiml6LX+qoOqC/3Eo/z9YFBOl
         8aV9k/6vV9kEzPNmkTPJm2l9vlWkqGeC7sOphcOTZyEP1wbr0UAbqw9WqaWumBHOWpJx
         9QrM+ME6nSsxeQsRe1o1O+2Fb7ehrtLpU7i7PiNHDAz+jKQKIPJztzvlPeugAy3sTPU9
         5VjXswghlOtyBnX+uO/7MDQ+qzgFfi9rlUmwbtSrJNE2fKkRFbyY5v1KQNz71qrdKD6E
         /yfA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761335015; x=1761939815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qKnsuP2nwIg9OdbABczugKceoUbQO6q2GnedMy2AMA0=;
        b=lYFYVRcOGHdr6nwqDgRfZpjXVhzX+O1FyoTwaWDOceq3A3ATi7gAw8oXdKUuxjRo7b
         LW796rdoKICgttiu+q25g+PKln4AUP/1mX4TXuQdC01ZqId2nnZCnsqBxEvaElL0phkf
         gfUbPtXBKe1VU6Lyno+eVSRigu5FqiK94HxlLpsz/wL2LcWe9G6ZysQw6ZRbZcQSA5tb
         8/jI/rNhDIsYW6vYEn2/lAWswLzajqlSikMARgvloG1gTwTQQgYMbItkwETPr+HcnxlE
         eSJcc3695nvkEgREkNsiXbPcuh13GAfC39j1hY7c3KRXYlgcUKpvvPN2iJzGVXvmZlQF
         zkZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761335015; x=1761939815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qKnsuP2nwIg9OdbABczugKceoUbQO6q2GnedMy2AMA0=;
        b=BOpveZZRCmjCDKwcuFvUKXHCQzuBK/rLf/hUHicfh/UajOlKNWTQ4YjVpJbXN1zgaY
         cW9RAM5zStjBvGahpvscql3+ERuPI5SXoTJjtd96y3FikL/bUiPT7gR83uCMjsQzTAxn
         fG32s4W+ofvZuXKWhkqXF0OHKUT2hgZY3XuvUQ4RuBr+R57P1FtRYHX3AoSkf/+n1D6y
         m9YxKhnMsGR4uOj512j49c+2E5IjRlruuBonZ0ZLWu58y1VH5XCvAvXeFKUu+4OLMYI1
         A+6yjdFonTaJ8/2tJDNSafdcpmpFzszkGuV1BQ9ytqaXi0YFh3KtbETBhuH3Zqt7Ry6I
         UdXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIGrwCJb4W8klYqDePfwgTVuv8HmyOl/m+xCI18GCzeDdU2dApXV1yVbLoLhIEn9Z51tYMuQ==@lfdr.de
X-Gm-Message-State: AOJu0YyoaJ0dMOxJVMjjuXzLBtEIklHq4Cj4EJ9PzjreUCWroS0hSi9r
	VG4MzmX6AVm0VnLJUvJqVMj+oZuwjSee6LCpiD/dMs6iY5x3RmuIotsF
X-Google-Smtp-Source: AGHT+IHPFRR7CBgkwdASFcK7snqWcdxGrGe/P9Zsv2y7aEagaEHkrnw4Jc85nzpLEF3F7zcIw2ebMw==
X-Received: by 2002:a05:6512:4012:b0:592:f31d:da18 with SMTP id 2adb3069b0e04-592f31ddc4cmr3397729e87.14.1761335014813;
        Fri, 24 Oct 2025 12:43:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bxArtAQy9CXbJiZTe5KOj0eO2UKq8mjwdyav9GiK4OjQ=="
Received: by 2002:a05:6512:ac4:b0:564:4dfe:5a41 with SMTP id
 2adb3069b0e04-592f54d4d7fls221318e87.1.-pod-prod-09-eu; Fri, 24 Oct 2025
 12:43:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUhv6/O+/opR+XKBNHL7xqUGJjjSQsWV9r2ndGYlNNLPPeN0U5MoVjcud0NRS3H7Tp+Wq2qOL4N7I4=@googlegroups.com
X-Received: by 2002:a05:6512:3a8e:b0:592:f521:188a with SMTP id 2adb3069b0e04-592f5211ademr2488731e87.49.1761335011333;
        Fri, 24 Oct 2025 12:43:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761335011; cv=none;
        d=google.com; s=arc-20240605;
        b=VpOdmwFUaT0z/P3WWSMsy9MBaZbJHg35QNG7FGDQvWKyN9nFoBfGF9kjbuBPDg2Dj1
         H6RAgIH26CjQeibHI9BcG543qYhKKgn6gIv1BBL8jrP5BgGIv8VOf3s5poXhlMFlD90j
         NFOKfE6yLIptZgEoAMmjKmLfIuP0i3h4B/2b4gj1Nt8PRfag9++mGJ7+VMUOrF4q1buh
         UqcgF6L11yRe1zpWiJVt01Y94hHzi+BXMrjS6Cs7VcS/EYIKEDmHOc5vQOPpn40jE7B5
         PTyfVL6eTENg6qKexVqABEyVgPWBryEsuPZcXP4AgO9HTTbNISvmf0CAIefolX1gWDb6
         EYbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=90XaxFEyCpkV47QCzVcKxG5N1KKEds9BtveeKPxtNeE=;
        fh=Pj6i4bYSrmhKIG4TqG0aUaC/bh8leyn6C2oUVfBhtlU=;
        b=LdfDjJKCZ68/rvQwc2ma/cE+hhvRTAGPcDXDT/pUNPvDxG9nD06mb5PgNN7xQ4POuh
         msIDLJXDeeVdKuO+JSEwLmQLiyKljb8PdvM2cUR7O5dedBPc7TzuJmGu3cxgE3PZTbhL
         cYbtlcWgd18w3Ra10dhI2m1iGmqXF4436KjpN7XawAIArtBoKUpWxS9wEyfPLtOAuxjm
         uu+XEbOfITW0lKtWPyVMXVA5i7NObVm0ynJVngBOXMjqHLZzhIiNggk48LCVdmDYp3sd
         3SvvgzI//w5ZFYrJrUI7WuMM088YaGWXLq24D+ZjsUEMEQoCFnDicYJUJOI8tWidvuET
         +LGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="G+h/yCUj";
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-592f4d1adb2si138616e87.3.2025.10.24.12.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 12:43:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-46e6a689bd0so23440365e9.1
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 12:43:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDo83BD/if8GHit4mmwg5B0kqQG6b+Hr/48cgIDKjWZqUEUUFGxE320YEp8U004cvAo0qacW/CI4k=@googlegroups.com
X-Gm-Gg: ASbGncssFCfqdtZ+7VoADMCcVit9ly7crSYUbxhxGi3jq3xAB9JRETVEowq7BMBYPQj
	2iE5cW/RcT28+NJRzjIRaSJVvaiYZ6AcMbcpeHRQfF2ZrwTE78jAoMuWrk9t0kD0+7kLbdChmXj
	AnIn1T4MMtl1K7K2KfiLqFB0jfX/SnzEXnQ4j5W4FgwaaCQS8ALmwUaY5jvJ/rVBS7Hdp8Rzgpz
	4on7RJtYg7x2fXzCoONzG8H6GUkUf16gOjYP123mnpxjzq5FNFt9NL7r7xGg2urVqY5+dnRphg0
	BwOlgzo7eugFRbH9lX4M51cx5DWm
X-Received: by 2002:a05:600c:3149:b0:46f:b43a:aef0 with SMTP id
 5b1f17b1804b1-47117925e63mr211257905e9.41.1761335010286; Fri, 24 Oct 2025
 12:43:30 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz> <20251023-sheaves-for-all-v1-7-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-7-6ffa2c9941c0@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 24 Oct 2025 12:43:18 -0700
X-Gm-Features: AWmQ_bk-kyewHYgpxUqtmCiyFoLA8j75cYs74Mz6Re-SJFA0srIhl0qtPOmknRs
Message-ID: <CAADnVQLAFkYLLJbMjEyzEu=Q7aJSs19Ddb1qXqEWNnxm6=CDFg@mail.gmail.com>
Subject: Re: [PATCH RFC 07/19] slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
To: Vlastimil Babka <vbabka@suse.cz>, Chris Mason <clm@meta.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="G+h/yCUj";       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
>
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
>
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 74 ++++++++++++++++++++++++++++++++++++++++++++-------------=
------
>  1 file changed, 52 insertions(+), 22 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index ecb10ed5acfe..5d0b2cf66520 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2876,7 +2876,8 @@ static void pcs_destroy(struct kmem_cache *s)
>         s->cpu_sheaves =3D NULL;
>  }
>
> -static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
> +static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
> +                                              bool allow_spin)
>  {
>         struct slab_sheaf *empty =3D NULL;
>         unsigned long flags;
> @@ -2884,7 +2885,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(str=
uct node_barn *barn)
>         if (!data_race(barn->nr_empty))
>                 return NULL;
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return NULL;
>
>         if (likely(barn->nr_empty)) {
>                 empty =3D list_first_entry(&barn->sheaves_empty,
> @@ -2961,7 +2965,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sh=
eaf(struct node_barn *barn)
>   * change.
>   */
>  static struct slab_sheaf *
> -barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empt=
y)
> +barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empt=
y,
> +                        bool allow_spin)
>  {
>         struct slab_sheaf *full =3D NULL;
>         unsigned long flags;
> @@ -2969,7 +2974,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, s=
truct slab_sheaf *empty)
>         if (!data_race(barn->nr_full))
>                 return NULL;
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return NULL;
>
>         if (likely(barn->nr_full)) {
>                 full =3D list_first_entry(&barn->sheaves_full, struct sla=
b_sheaf,
> @@ -2990,7 +2998,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, st=
ruct slab_sheaf *empty)
>   * barn. But if there are too many full sheaves, reject this with -E2BIG=
.
>   */
>  static struct slab_sheaf *
> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
> +                       bool allow_spin)
>  {
>         struct slab_sheaf *empty;
>         unsigned long flags;
> @@ -3001,7 +3010,10 @@ barn_replace_full_sheaf(struct node_barn *barn, st=
ruct slab_sheaf *full)
>         if (!data_race(barn->nr_empty))
>                 return ERR_PTR(-ENOMEM);
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return NULL;

AI did a good job here. I spent an hour staring at the patch
for other reasons. Noticed this bug too and then went
"ohh, wait, AI mentioned it already". Time to retire.

>         if (likely(barn->nr_empty)) {
>                 empty =3D list_first_entry(&barn->sheaves_empty, struct s=
lab_sheaf,
> @@ -5000,7 +5012,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs,
>                 return NULL;
>         }
>
> -       full =3D barn_replace_empty_sheaf(barn, pcs->main);
> +       full =3D barn_replace_empty_sheaf(barn, pcs->main,
> +                                       gfpflags_allow_spinning(gfp));
>
>         if (full) {
>                 stat(s, BARN_GET);
> @@ -5017,7 +5030,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs,
>                         empty =3D pcs->spare;
>                         pcs->spare =3D NULL;
>                 } else {
> -                       empty =3D barn_get_empty_sheaf(barn);
> +                       empty =3D barn_get_empty_sheaf(barn, true);
>                 }
>         }
>
> @@ -5154,7 +5167,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gf=
p, int node)
>  }
>
>  static __fastpath_inline
> -unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void=
 **p)
> +unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t=
 size,
> +                                void **p)
>  {
>         struct slub_percpu_sheaves *pcs;
>         struct slab_sheaf *main;
> @@ -5188,7 +5202,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache =
*s, size_t size, void **p)
>                         return allocated;
>                 }
>
> -               full =3D barn_replace_empty_sheaf(barn, pcs->main);
> +               full =3D barn_replace_empty_sheaf(barn, pcs->main,
> +                                               gfpflags_allow_spinning(g=
fp));
>
>                 if (full) {
>                         stat(s, BARN_GET);
> @@ -5693,7 +5708,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_=
flags, int node)
>         gfp_t alloc_gfp =3D __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
>         struct kmem_cache *s;
>         bool can_retry =3D true;
> -       void *ret =3D ERR_PTR(-EBUSY);
> +       void *ret;
>
>         VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
>                                       __GFP_NO_OBJ_EXT));
> @@ -5720,6 +5735,13 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp=
_flags, int node)
>                  */
>                 return NULL;
>
> +       ret =3D alloc_from_pcs(s, alloc_gfp, node);
> +

I would remove the empty line here.

> +       if (ret)
> +               goto success;
> +
> +       ret =3D ERR_PTR(-EBUSY);
> +
>         /*
>          * Do not call slab_alloc_node(), since trylock mode isn't
>          * compatible with slab_pre_alloc_hook/should_failslab and
> @@ -5756,6 +5778,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_=
flags, int node)
>                 ret =3D NULL;
>         }
>
> +success:
>         maybe_wipe_obj_freeptr(s, ret);
>         slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
>                              slab_want_init_on_alloc(alloc_gfp, s), size)=
;
> @@ -6047,7 +6070,8 @@ static void __pcs_install_empty_sheaf(struct kmem_c=
ache *s,
>   * unlocked.
>   */
>  static struct slub_percpu_sheaves *
> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves=
 *pcs)
> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves=
 *pcs,
> +                       bool allow_spin)
>  {
>         struct slab_sheaf *empty;
>         struct node_barn *barn;
> @@ -6071,7 +6095,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>         put_fail =3D false;
>
>         if (!pcs->spare) {
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, allow_spin);
>                 if (empty) {
>                         pcs->spare =3D pcs->main;
>                         pcs->main =3D empty;
> @@ -6085,7 +6109,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>                 return pcs;
>         }
>
> -       empty =3D barn_replace_full_sheaf(barn, pcs->main);
> +       empty =3D barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>
>         if (!IS_ERR(empty)) {
>                 stat(s, BARN_PUT);
> @@ -6093,6 +6117,11 @@ __pcs_replace_full_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs)
>                 return pcs;
>         }
>
> +       if (!allow_spin) {
> +               local_unlock(&s->cpu_sheaves->lock);
> +               return NULL;
> +       }

and would add a comment here to elaborate that the next
steps like sheaf_flush_unused() and alloc_empty_sheaf()
cannot handle !allow_spin.


> +
>         if (PTR_ERR(empty) =3D=3D -E2BIG) {
>                 /* Since we got here, spare exists and is full */
>                 struct slab_sheaf *to_flush =3D pcs->spare;
> @@ -6160,7 +6189,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>   * The object is expected to have passed slab_free_hook() already.
>   */
>  static __fastpath_inline
> -bool free_to_pcs(struct kmem_cache *s, void *object)
> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>  {
>         struct slub_percpu_sheaves *pcs;
>
> @@ -6171,7 +6200,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object=
)
>
>         if (unlikely(pcs->main->size =3D=3D s->sheaf_capacity)) {
>
> -               pcs =3D __pcs_replace_full_main(s, pcs);
> +               pcs =3D __pcs_replace_full_main(s, pcs, allow_spin);
>                 if (unlikely(!pcs))
>                         return false;
>         }
> @@ -6278,7 +6307,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *=
obj)
>                         goto fail;
>                 }
>
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, true);
>
>                 if (empty) {
>                         pcs->rcu_free =3D empty;
> @@ -6398,7 +6427,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, =
size_t size, void **p)
>                 goto no_empty;
>
>         if (!pcs->spare) {
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, true);

I'm allergic to booleans in arguments. They make callsites
hard to read. Especially if there are multiple bools.
We have horrendous lines in the verifier that we still need
to clean up due to bools:
check_load_mem(env, insn, true, false, false, "atomic_load");

barn_get_empty_sheaf(barn, true); looks benign,
but I would still use enum { DONT_SPIN, ALLOW_SPIN }
and use that in all functions instead of 'bool allow_spin'.

Aside from that I got worried that sheaves fast path
may be not optimized well by the compiler:
if (unlikely(pcs->main->size =3D=3D 0)) ...
object =3D pcs->main->objects[pcs->main->size - 1];
// object is accessed here
pcs->main->size--;

since object may alias into pcs->main and the compiler
may be tempted to reload 'main'.
Looks like it's fine, since object point is not actually read or written.
gcc15 asm looks good:
        movq    8(%rbx), %rdx   # _68->main, _69
        movl    24(%rdx), %eax  # _69->size, _70
# ../mm/slub.c:5129:    if (unlikely(pcs->main->size =3D=3D 0)) {
        testl   %eax, %eax      # _70
        je      .L2076  #,
.L1953:
# ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1];
        leal    -1(%rax), %esi  #,
# ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1];
        movq    32(%rdx,%rsi,8), %rdi   # prephitmp_309->objects[_81], obje=
ct
# ../mm/slub.c:5135:    object =3D pcs->main->objects[pcs->main->size - 1];
        movq    %rsi, %rax      #,
# ../mm/slub.c:5137:    if (unlikely(node_requested)) {
        testb   %r15b, %r15b    # node_requested
        jne     .L2077  #,
.L1954:
# ../mm/slub.c:5149:    pcs->main->size--;
        movl    %eax, 24(%rdx)  # _81, prephitmp_30->size

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQLAFkYLLJbMjEyzEu%3DQ7aJSs19Ddb1qXqEWNnxm6%3DCDFg%40mail.gmail.com.
