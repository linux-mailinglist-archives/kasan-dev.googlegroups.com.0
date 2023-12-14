Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVH45KVQMGQEJ5K4LKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DEC6812A78
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 09:35:34 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-67ee8a447b3sf7208346d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:35:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702542933; cv=pass;
        d=google.com; s=arc-20160816;
        b=qO7pZQVdEWZ7f1Puk6gL3NjKd2XBrsjkAIHhK8Dw/hO4z32ByuixJ8Uzw+d716Elvn
         nL8p/nv9NYaU5pcP+uJymOMDZ69Xi8dQYLsEEpKEQ015WbOj/bGXjftlrup7vvsQDXj3
         HUMbF9s97uXRhuxWa/DHC1+7e4FrRozCQCSENKv/E1FhDqdP1cfMiYcqRhZUYKsWrBPZ
         SdRzSHwCK82YuQAEBwaWAez/pM8F4butl/tAod+ir6mmk9Xpt/dSUwg38vuvsSrQJGH9
         PwC+S2kZJLfBSuc0aoYz08JpFUzI1+mKcX9NH/OvrDv0XJab+/EtV9dTs9ZaCeqpBUf1
         v/ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i3Uko+BmZC+xKLmMkiNRUmrZ68RqkA51vhqNFFWxC/g=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=c6Wub0CLcnBquRQAWj+wS8T2gz4USyaNZkVk66ljjLKS50CTlCDlFamw29SDshOKDj
         qEFdd/dAin8XQwHxV8Lzy+vcd0MuFzyUu6a60vhqrs5ZooS7jboBzV+d96EK4dZkICVZ
         jX713O7hJpwLvHAy3MHqltb6R4nqiiiw7D++pDNy2Pt8lzfjtDgdOMAjibsySl+aYiFB
         yM/6dQQpHCRisJx459sajikQxbmHw2Jxo5MX1QigKKFZkvVRDsAv3c8sEXoipbVKP0KB
         E79lmb366YL4P/WjaYdPGaKsJQ6EOxsfHorcvdT9czVY/wyJUrvz1Wo0+FuXXTGvSUH9
         O8Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n0JnCKey;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702542933; x=1703147733; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i3Uko+BmZC+xKLmMkiNRUmrZ68RqkA51vhqNFFWxC/g=;
        b=PjXMyJwrnZrWfDq8cyl9jz0f06qOMBEXOGjuo241kvlCjxmfPo4NaQkoIJgLh/Ih5b
         Yy99ZsDrwV/XhTg/jrOXeSGJz4t2Wa8B/Aiuz8Ncblgb7WyjQx53Yveh/MS2xfqlL5fg
         NuqwEuxRhlf9/3qETvzL8znv7V+rYORd3mYTul5WX//+vrZzo8rNyjt0Ctp+/ndeddx5
         qtaFcIPrKTzrV1ImitQ03KMg4IW/a0DDDR4LSf4pE2NHgPORhNGvqOtLls2n4DKOgDqE
         nvfC5ScRhVEf+GjAMy8ZfUV+QIaQX7kRJKgVswjJgI4i+h7paX9BzdMZDqzfsZRQkoPN
         ekAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702542933; x=1703147733;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i3Uko+BmZC+xKLmMkiNRUmrZ68RqkA51vhqNFFWxC/g=;
        b=tBUhZlX2UZ21e6TZMi7ZqUjze4dTr+0Myhuy9rg+uzaVB8THEy5lZg1aDbcu4ES607
         a0jJeSw4iIvGACjvc8BOegNY9utee6QUhcD+ujG+la61efTWaUVYWqjJwhj/PIJmNYKN
         39Ukwzj+OGr1W3UOJ+amEdJYj0Wpzo+LOdjP8+5d171yaw1gDXDjdJi8ymLuWkcwXek3
         vVBvqZBeydNzevwp3XwBxm4+bw7v0A2426traF3us0SoGZLCiXN72VoJYHwrapqJ+aoM
         TfuEJFvfG8iU9S92xSx98S4BBEyKNSoaiHW4ECo2HdYYUjvs67TPW0QdgyGoamoR88LE
         kSfA==
X-Gm-Message-State: AOJu0Yxx2gKx0TYjbb+fzv5HPLJoQmiCYtbTZxEFDqximsMAuSnJFGis
	jC7p2Q7GSNEpue4onvzn0CI=
X-Google-Smtp-Source: AGHT+IGwUGmbKE4RobuK+K21Rxb7RwGgubdobWn8Q3g1p1nxNYKbfubmuYJLXfHl4MbfcDaXwfVANg==
X-Received: by 2002:a0c:f992:0:b0:67a:d9f5:19fc with SMTP id t18-20020a0cf992000000b0067ad9f519fcmr13037697qvn.28.1702542932982;
        Thu, 14 Dec 2023 00:35:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5766:0:b0:67f:e61:7f01 with SMTP id r6-20020ad45766000000b0067f0e617f01ls356510qvx.0.-pod-prod-00-us;
 Thu, 14 Dec 2023 00:35:32 -0800 (PST)
X-Received: by 2002:a05:6214:19e7:b0:67a:a72d:fbbb with SMTP id q7-20020a05621419e700b0067aa72dfbbbmr16441622qvc.57.1702542932161;
        Thu, 14 Dec 2023 00:35:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702542932; cv=none;
        d=google.com; s=arc-20160816;
        b=xbCGZ+jZEjPsR8AXpOjU3x9Tt4pXl3KQikySuW92Dm0smQhI+f42RSJklXk6/kbvXV
         JpjkznypY1AWf5l8cr2xyk62x6gYbTRdLfKAOV/Pz2BZh/wVkOa1UjuPJzbxvi7NGTGu
         xULPUqsr3LR0XkTEMX/ztOHZNTjWe/OBKtX8HKAVuUs4sOc4GS3kunKo7TdfiJw3bLKE
         OyYu/zvRRz8PSHUbEqc5fkq1fWeDBcrBEAqa56dts2eUkL5r+m3cMUlkE5v+Kz5QBi7B
         3W6Nxxa9FNpwwQiuB9mBI0CYqfYgLyJTSInPlEmWyFmdDuniX8WZAPTdp+5JCYjIA7Jn
         Z7Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=59EvNi4lROlx/uAEwIQ9N8BChY4yKEZ29O9hKyzJ3t8=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=fyj4orgQtePTcxdPuxgfjhZio46qsYauRXciyYEG7rr0RL/kDGvODm9vXhVk8KOs7R
         5V36T2LRr4fTVFuHJsvxW8fy2ReN1/bArWXc6D+Tsgrc/iDuWFwpLAthmAiYtFvAKwMt
         92WQNAsBVOEkN71TOwbcpaSck9WlXVkjLdAVNgnIHSuiHLAjEHD1xGmaUH3egT2EQ6xQ
         NvcuHDTLyKg/gzLnk06rg7/AQReuLIsrDb4vz+b7DTHex+cJEbQwKre0dqJPkoMhsmBb
         iXkqbwkJfcHqkNgLNvH6F0QI8XMcQgHNOSqWwur0Tw/7kqLNKNf1CJrYu43pKMmPJns9
         cGkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n0JnCKey;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x931.google.com (mail-ua1-x931.google.com. [2607:f8b0:4864:20::931])
        by gmr-mx.google.com with ESMTPS id o1-20020a0cecc1000000b0067a65d54666si1315483qvq.7.2023.12.14.00.35.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Dec 2023 00:35:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) client-ip=2607:f8b0:4864:20::931;
Received: by mail-ua1-x931.google.com with SMTP id a1e0cc1a2514c-7cb3f1d1ff4so220853241.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Dec 2023 00:35:32 -0800 (PST)
X-Received: by 2002:a05:6102:e0e:b0:466:25f:f281 with SMTP id
 o14-20020a0561020e0e00b00466025ff281mr8702541vst.6.1702542931628; Thu, 14 Dec
 2023 00:35:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702514411.git.andreyknvl@google.com> <88fc85e2a8cca03f2bfcae76100d1a3d54eac840.1702514411.git.andreyknvl@google.com>
In-Reply-To: <88fc85e2a8cca03f2bfcae76100d1a3d54eac840.1702514411.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Dec 2023 09:34:53 +0100
Message-ID: <CANpmjNMNhPOBHr_5iyfP9Lo_tOUiG_bpVnS-RkfrP3JccW3yqg@mail.gmail.com>
Subject: Re: [PATCH -v2 mm 2/4] kasan: handle concurrent kasan_record_aux_stack
 calls
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
 header.i=@google.com header.s=20230601 header.b=n0JnCKey;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as
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

On Thu, 14 Dec 2023 at 01:48, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> kasan_record_aux_stack can be called concurrently on the same object.
> This might lead to a race condition when rotating the saved aux stack
> trace handles, which in turns leads to incorrect accounting of stack
> depot handles and refcount underflows in the stack depot code.
>
> Fix by introducing a spinlock to protect the aux stack trace handles
> in kasan_record_aux_stack.
>
> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
> Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v1->v2:
> - Use per-object spinlock instead of a global one.
> ---
>  mm/kasan/generic.c | 32 +++++++++++++++++++++++++++++---
>  mm/kasan/kasan.h   |  2 ++
>  2 files changed, 31 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 54e20b2bc3e1..b9d41d6c70fd 100644
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
> @@ -471,8 +472,18 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>         struct kasan_free_meta *free_meta;
>
>         alloc_meta = kasan_get_alloc_meta(cache, object);
> -       if (alloc_meta)
> +       if (alloc_meta) {
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
> +
> +               /*
> +                * Temporarily disable KASAN bug reporting to allow instrumented
> +                * spin_lock_init to access aux_lock, which resides inside of a
> +                * redzone.
> +                */
> +               kasan_disable_current();
> +               spin_lock_init(&alloc_meta->aux_lock);
> +               kasan_enable_current();
> +       }
>         free_meta = kasan_get_free_meta(cache, object);
>         if (free_meta)
>                 __memset(free_meta, 0, sizeof(*free_meta));
> @@ -502,6 +513,8 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         struct kmem_cache *cache;
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
> +       depot_stack_handle_t new_handle, old_handle;
> +       unsigned long flags;
>
>         if (is_kfence_address(addr) || !slab)
>                 return;
> @@ -512,9 +525,22 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>         if (!alloc_meta)
>                 return;
>
> -       stack_depot_put(alloc_meta->aux_stack[1]);
> +       new_handle = kasan_save_stack(0, depot_flags);
> +
> +       /*
> +        * Temporarily disable KASAN bug reporting to allow instrumented
> +        * spinlock functions to access aux_lock, which resides inside of a
> +        * redzone.
> +        */
> +       kasan_disable_current();
> +       spin_lock_irqsave(&alloc_meta->aux_lock, flags);
> +       old_handle = alloc_meta->aux_stack[1];
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
> +       alloc_meta->aux_stack[0] = new_handle;
> +       spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
> +       kasan_enable_current();
> +
> +       stack_depot_put(old_handle);
>  }
>
>  void kasan_record_aux_stack(void *addr)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5e298e3ac909..8b4125fecdc7 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -6,6 +6,7 @@
>  #include <linux/kasan.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/kfence.h>
> +#include <linux/spinlock.h>
>  #include <linux/stackdepot.h>
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> @@ -249,6 +250,7 @@ struct kasan_global {
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Free track is stored in kasan_free_meta. */
> +       spinlock_t aux_lock;

This needs to be raw_spinlock, because
kasan_record_aux_stack_noalloc() can be called from non-sleepable
contexts (otherwise lockdep will complain for RT kernels).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMNhPOBHr_5iyfP9Lo_tOUiG_bpVnS-RkfrP3JccW3yqg%40mail.gmail.com.
