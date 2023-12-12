Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXJ4KVQMGQEUSYPCBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 014B680F6A9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 20:29:20 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2869f25733asf7047169a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 11:29:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702409358; cv=pass;
        d=google.com; s=arc-20160816;
        b=mu4F90HRbjhpM6oUv5dhzNXlvhB7XAsfXMfGFmvhwmpQj0nCJB7u/yCLd50oMwTnKe
         h3CZWcgaoxeCXPtPNkiSavcf1vrGjE8rfFoNANl8CjSq6YhKYhbRPLhAeE43Mg7p2wcj
         lGy2ZC5mXTJ3hEbzVqd0ZLxcW6A6fZNkNou2kHwl6D/khJ9Gl3sIbb2gqF/DmSWTB3fI
         /voB4ixo85gnSJzqPY/Y6wTLSS33GVzmozcuR6QKezbL7Uwa/msC3eTYZXPrdiYZ2VI3
         95css4c2nFBZma9loorXhmwC1UMoF9q8urwEXUYrZQQ97sQtjFVm4JFZDoQ2qumLjSEx
         sfUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xW+WkVc0votLJp9z1slKg81nVN2mYz6TBhqSwHKoK74=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=G8IHH3P4/NzSes9zOIJ6Da7SUQeKbBKhz4Z6gq072F4tZtoVnzpmgMZqBTe3bSGO1e
         9AdvcJ/OR9E1dAujXb+GqNmSCzpEEHO9WE5iKO42YxsLrgYuBQAiwKhY7SmgxAvf3v3P
         mfYGD2557AOE8e+gRqZjK1k/yaLSJ9WP4dOYSjoLkntle4Mo7SqKnw1bfg8s3nGIkbwn
         LpI9zpYq9ONjTaM0ZSRiNFwCLvqh/xSnLBd1F2J7WemG3hSm4Oz+WKN+Glf44va315pB
         B9Ow3oP7POEz9vu38xqPs5l8wSHr8QzKZ6XUjaiVXiZN+VAtqaoyPWm5GpNR0l5p2c7r
         GDnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hnqGo8MQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702409358; x=1703014158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xW+WkVc0votLJp9z1slKg81nVN2mYz6TBhqSwHKoK74=;
        b=LSlNpYmGay/xwuYmD0PDjta+hXIdDzXh+FSxdXhGvCNMRg8AQTLblhkoj1TV/tmiU0
         CMCa7z6qjYyCoGbg52oyKXDej7Vvcc8Kky6EdzZqlhjXO9XcO1b5A2RtOqF8ey9ZsuzW
         p3ZYbjB4mZVzTCbjqy7SJpZ0JPnwUn6ZN8gXOjYAK8ta0MvP002rAqWWe8jE8H1pc3DY
         7RbDOgeTj2tBzeAM4JCdJHNSNrLY52RjKxLcl3EA+wahO1M5lpjhQbvgElJpuZkJEn1m
         AVm18zAKT5hAavq+BUM/KRniLSxEBYotW2kjsVFC60g31QKOVJsiO9ennqM/+JdaXPVm
         l2SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702409358; x=1703014158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xW+WkVc0votLJp9z1slKg81nVN2mYz6TBhqSwHKoK74=;
        b=toHERrfLBf9S6jAxN1g5Xusj/g38Fpc7Tr4HUtSqi7sVxgVYizhmQqKKW/u1PrTfPh
         Sz2NaA7UCQvhJeSV2cqeskZzQVcd/bczan9UXHizm6L9ynwxDUttDu/e58/ntm3XQN5/
         r1AKJMB/HLhnzMnWIMDBif2+TUIthAdpe8ObLp6XU0RU/7LZ62S2E/4KZXBFucm8BEyg
         pPmSiDh3Hy6IJnH/SVYFG17KCmUcooqqyLSmzcZGj9K5H8rb1X3ThXZdOzyDZjB7t3Zm
         s5jhUJqVx1zyRny4UFijeBGp77LrN/Khz4zNGHMx2RG47HoJzkT8ZUVaf+OmnzW4rzWT
         54jg==
X-Gm-Message-State: AOJu0YxVNmPpbyZCMgcuU400byflu5tna4lnVdnLNu9NUedaJCf0mFaJ
	kEcWIbdgmTQynCm7P3UoFwk=
X-Google-Smtp-Source: AGHT+IF0yHPDXdfu7MwgfgF2nP1q1YdX0gcr8otwT07s7+rdQ094t3iIpCaLESRJNI7TsPERJR1V4w==
X-Received: by 2002:a17:90a:fa01:b0:28a:d58a:42fa with SMTP id cm1-20020a17090afa0100b0028ad58a42famr643923pjb.23.1702409358348;
        Tue, 12 Dec 2023 11:29:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fb87:b0:286:f3a6:e609 with SMTP id
 cp7-20020a17090afb8700b00286f3a6e609ls4222661pjb.0.-pod-prod-06-us; Tue, 12
 Dec 2023 11:29:17 -0800 (PST)
X-Received: by 2002:a17:90a:989:b0:28a:bd51:7205 with SMTP id 9-20020a17090a098900b0028abd517205mr1436040pjo.43.1702409357113;
        Tue, 12 Dec 2023 11:29:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702409357; cv=none;
        d=google.com; s=arc-20160816;
        b=1Eeod99cIpcV+cU7JkDIjgrSk/bRKaXklEE7qiQVZlEuM2jBW9D2mXX+rjce9PAqK6
         tvAYvYiWvxhVdQE73HnpoJAz0z44gh5S9iDjVjDi8k5eZT4TptvFFnItYqASW7gFImXQ
         iN9PFQIg99CXkC7L+H3h63yH5bffrRT7SerwWEPgoC6Zrq7L8t3Mjmju9YbWfxaYOvKl
         TZqqqwJx6sv2rHfE6iBUvAihiNw0MntrEIG85EX5uqZl8RM/fkpsyT6L8KAJRolK0Db0
         /YN5Ii+JpWc+Ay1bJQ78xu5A/VZLDIv3/hw0lGgQ+e4N9cTvHCaZq+QhufWMkynoE+oP
         gujg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+rCbqARyeZId11kuEaXWxOwQK5N8S8sXeciQALfHIFM=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=UYX8PvFuOy9INukzE7pH41WSADbUqrOdm0ShaQyIOGtgd4GrN68GS64GxMP0l7jF2r
         RatfvXegR9AXmpIVIqE/lhECdq6b6Dlhw4aiwiY3PiOxkGN7F2BgRLQWDjLeNbDbh1ga
         f0tvqg2eFC2xoxsF/sprllD7oFlMHf7p8paYUBGj2ccNIKgTMovzzlG1Cix1sZ2NvhK4
         ZkD/jx4RechjbiaIC5T6ooOHy70QjlGxtxW2MsRG9lj6H4tOieOFERSUZYTUv0gJmXo3
         PeUr3E+OFWhAddameM9S7Cc4O3CkXP41A9/qwh7Qx/MwA0cqvPX+c0ORs0i2dVgs0zkp
         50zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hnqGo8MQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id pt4-20020a17090b3d0400b002866a7e14b8si941965pjb.0.2023.12.12.11.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 11:29:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-4649daf0dd4so1670469137.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 11:29:17 -0800 (PST)
X-Received: by 2002:a05:6102:3752:b0:464:3cdb:856c with SMTP id
 u18-20020a056102375200b004643cdb856cmr5344796vst.9.1702409356064; Tue, 12 Dec
 2023 11:29:16 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
In-Reply-To: <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Dec 2023 20:28:37 +0100
Message-ID: <CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hnqGo8MQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
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

On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> kasan_record_aux_stack can be called concurrently on the same object.
> This might lead to a race condition when rotating the saved aux stack
> trace handles.
>
> Fix by introducing a spinlock to protect the aux stack trace handles
> in kasan_record_aux_stack.
>
> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> This can be squashed into "kasan: use stack_depot_put for Generic mode"
> or left standalone.
> ---
>  mm/kasan/generic.c | 15 +++++++++++++--
>  1 file changed, 13 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 54e20b2bc3e1..ca5c75a1866c 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -25,6 +25,7 @@
>  #include <linux/sched.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
> +#include <linux/spinlock.h>
>  #include <linux/stackdepot.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> @@ -35,6 +36,8 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +DEFINE_SPINLOCK(aux_lock);

No, please don't.

>  /*
>   * All functions below always inlined so compiler could
>   * perform better optimizations in each of __asan_loadX/__assn_storeX
> @@ -502,6 +505,8 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         struct kmem_cache *cache;
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
> +       depot_stack_handle_t new_handle, old_handle;
> +       unsigned long flags;
>
>         if (is_kfence_address(addr) || !slab)
>                 return;
> @@ -512,9 +517,15 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         if (!alloc_meta)
>                 return;
>
> -       stack_depot_put(alloc_meta->aux_stack[1]);
> +       new_handle = kasan_save_stack(0, depot_flags);
> +
> +       spin_lock_irqsave(&aux_lock, flags);

This is a unnecessary global lock. What's the problem here? As far as
I can understand a race is possible where we may end up with
duplicated or lost stack handles.

Since storing this information is best effort anyway, and bugs are
rare, a global lock protecting this is overkill.

I'd just accept the racyness and use READ_ONCE() / WRITE_ONCE() just
to make sure we don't tear any reads/writes and the depot handles are
valid. There are other more complex schemes [1], but I think they are
overkill as well.

[1]: Since a depot stack handle is just an u32, we can have a

 union {
   depot_stack_handle_t handles[2];
   atomic64_t atomic_handle;
  } aux_stack;
(BUILD_BUG_ON somewhere if sizeof handles and atomic_handle mismatch.)

Then in the code here create the same union and load atomic_handle.
Swap handle[1] into handle[0] and write the new one in handles[1].
Then do a cmpxchg loop to store the new atomic_handle.

> +       old_handle = alloc_meta->aux_stack[1];
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
> +       alloc_meta->aux_stack[0] = new_handle;
> +       spin_unlock_irqrestore(&aux_lock, flags);
> +
> +       stack_depot_put(old_handle);
>  }
>
>  void kasan_record_aux_stack(void *addr)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA%40mail.gmail.com.
