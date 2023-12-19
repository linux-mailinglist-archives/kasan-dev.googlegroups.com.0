Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64SRCWAMGQE3UIQANI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ACC7819235
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 22:22:05 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4259f4aa87csf15171cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 13:22:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703020924; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKJNCtzpHr9SlLZER1ifPKqEAK0khHta6Fxuro+JGQt10dwKM2i/HZE22f+WrZPxsH
         w2AiXuEduE0FA37lgVOjxLRFCDGOzH3pFxD+ekWYtCfvfgBfIPRTfmEWjxjDpcnPbD+x
         BUEIRpxcJgk9EGiopNMlsu4rI6wCjqRmOLDFEYUB0q5up+0jC1lbyf1p6ad+NVvulHcy
         kFItKtqPztYGszCwZWAqK57Qpnlk8+88HhxsrbBXvmHyiI2h7XP7zTnzTbv1LjouuF0Q
         l+GlLKnXGC9OPRIgKCi2ZZyzVNQj5hqzXCFmoQr82lSKSmH6TOhDoKe7XQpBJZk5Fgo7
         2XNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xFNi9M5v5hZOk8GLkT9Lb31DobjPjGIib6zaCASsR78=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=XIs3Tb3aGicW2UGUWZAqnntkzx5BomgR1nUcV6WvWWPiHcWwtvKSbrpg7iW+Fl4ujR
         yxJEUl1TANzmOm4RoIL25pkaEttjuMaEv4Z8E2Hn3ZhOFjYPyhe4cNrWanfCiQJbWnO4
         pAHVO/NHQnPGb0Uo90bi9NRgpuHL7cLqH9318gqj598F/Uqqfn0wGP9s6VHU6PfzzpNO
         8j0hVT7jcRQu/CbdRo3TVmGTDuEjnZ0qViVXy+CLeVatr44Gh5AX8fwQsAs2MY4rOBZU
         LxiBqPvJt9l5uD18e1EUVZYLwLhllS/db1Jtbo4VUPojg4Dx6nYRB9zj4+S/9hi4G71S
         BMwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OY1Vff8H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703020924; x=1703625724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xFNi9M5v5hZOk8GLkT9Lb31DobjPjGIib6zaCASsR78=;
        b=DtnfmnkSo5ZlEH+LTjRZS/g47Ovem5dhpXTGgtvLPpAS+EAj+KZZQHKYT9QU9Ysdpt
         YzJWdLXqTaIFi1Y/4tHMY+PPgR1stqd9PnE+CivQsljW35qi+kJLqItZ8ylA3peboZNS
         v1zSLf15FL7ItQKPqRREcZ+quHOttfWxdDxTJPN4J5Ri7Z/RtWyzu4MU1LfaegHADHgn
         KJ1dOx4n/6+B88dr/0MfETxQIj6SOkaeL/Uthu1AR8d0pnsqad/bj2kos/pd02Ymilct
         /MIUB87Nk572KCKOArP/PU20hyYTWYDTUllNpDm2ucJuwBm7LKdjul14AGQSKppvOvoy
         H+ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703020924; x=1703625724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xFNi9M5v5hZOk8GLkT9Lb31DobjPjGIib6zaCASsR78=;
        b=u1BTNUKyC9ANIeyxdEFNWFbLOGcaXB9LWaMpmK6cHvycUOfYX+ntQ9fQlHr2QrhHUS
         nJllW3pOfrgmcSQ3NxT3AfANVIhgeYAKXYQH8aNi1TQ+7fG84dVifobqgu5mcnlE4fAE
         qqG1tDksUW5f9ANAAXHDwb26g0bMUnO8eunKvzBL+gfqtw4h1EGPE/JuGYOLm6G/kPbM
         cAgumoPWI5L/XiEtBz9J/btHqMalgh7JEsz6jWdSdBn7hwcPW7nLjKxfcyYDI63mAGCn
         5bLVL9g4/dlL00qUO0torrB8jOAIFjotcUFeKAOD9ZkCVd7Bozqvwm45d54XPqZ523sT
         w9JA==
X-Gm-Message-State: AOJu0YyV1gFf4JtI7X2kNv1GyoSsgIavsNnGbhEXPy1rgJnKa5IjKZuk
	eX7MV+XzdioktO2+gLArftM=
X-Google-Smtp-Source: AGHT+IGcNIdUYgEDDZO2CFxxIdj5C4rAx31yqYb2HSidsLx3yImwJjH5v4p5TJMp/T+wiabtne04NQ==
X-Received: by 2002:ac8:5ac8:0:b0:423:f9d1:73af with SMTP id d8-20020ac85ac8000000b00423f9d173afmr16015qtd.1.1703020924159;
        Tue, 19 Dec 2023 13:22:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c543:0:b0:dbd:5b60:bcff with SMTP id v64-20020a25c543000000b00dbd5b60bcffls1194948ybe.2.-pod-prod-06-us;
 Tue, 19 Dec 2023 13:22:03 -0800 (PST)
X-Received: by 2002:a81:6d05:0:b0:5e5:dd41:c048 with SMTP id i5-20020a816d05000000b005e5dd41c048mr3966780ywc.40.1703020923191;
        Tue, 19 Dec 2023 13:22:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703020923; cv=none;
        d=google.com; s=arc-20160816;
        b=JtD1GwiGpTcBN7MEsmWMIj2horQNRnM4Dj6wurS61yI0kZynV/SOK9yd9oqLk2hY/e
         POMDC4p/sUHdVou9/OdP2XuzH9vxaXYkmz39RIEG58kNDxrILQa3yKSTgzsiboAMHWs6
         J0+uTCAtXzDpmZGCek6x0lUPx//UFXPUfsoBI/gzTxsrEhFSJ9+XRM8bWwjdRRv8Ge+N
         NZMTEGAaTNuHJtzNrux34edgCYl2+93wfbyvEZoJsg6DfV+xTvdFkLr1UmpXXxWoq1pM
         6hXwwHLfKiyO1XY5xIK6qY6TndTsQsFshM+BowjflMX+w8xcY8ETBL/dAzPHxQbTqFig
         BwRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8LGegP+G5PWWJJoK9xgDRxY4ivR1WBT3Si9rlrLcuhs=;
        fh=2SMY3Ygb4gA67Fm9yk5IPAJMxRWhdsxd8qEuh3AIfK8=;
        b=jxjiteAQJkMCNxHxJQOTMgrZOvKGpSVPEfWNqzx6wb3b4Dj2UvuP8nR0w8HRywZ/xZ
         MMrZosyZnw+7XEp6V+gGDCCP1WxZ+cyPMW0eHbZFxcSmkA1IUXGUWMRaqo52x9Pbb0OT
         N4HHvXnaDFyXzHzyEXqJ5L9BAHCtc8oEdCjtCaDzP2EqurFzsjhBnguFfK9uvrH66peg
         soOSXtiZdr1Cl/EyXGziuja36Atng/tIvCnLtQa4eR27Cm91AmiZJIGjTPO0EGupL/Ms
         QnDAdKUiUYKs/vIVfIJ2i8C9/5Qr/EcWGg/8TuOwXeUQbT0V/8qbnX36gPHnD946Rx+v
         u6Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OY1Vff8H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id r206-20020a0de8d7000000b005e7ac086dddsi318203ywe.3.2023.12.19.13.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Dec 2023 13:22:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id a1e0cc1a2514c-7cbdd011627so726675241.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 13:22:03 -0800 (PST)
X-Received: by 2002:a05:6102:559e:b0:466:9bec:ae53 with SMTP id
 dc30-20020a056102559e00b004669becae53mr2855956vsb.25.1703020922750; Tue, 19
 Dec 2023 13:22:02 -0800 (PST)
MIME-Version: 1.0
References: <cover.1703020707.git.andreyknvl@google.com> <1606b960e2f746862d1f459515972f9695bf448a.1703020707.git.andreyknvl@google.com>
In-Reply-To: <1606b960e2f746862d1f459515972f9695bf448a.1703020707.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Dec 2023 22:21:25 +0100
Message-ID: <CANpmjNMAL0FRdewOfEpTZWBTLquJ_k0L4QdCd_Uau6ewg2hAxQ@mail.gmail.com>
Subject: Re: [PATCH v3 mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
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
 header.i=@google.com header.s=20230601 header.b=OY1Vff8H;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as
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

On Tue, 19 Dec 2023 at 22:19, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> kasan_record_aux_stack can be called concurrently on the same object.
> This might lead to a race condition when rotating the saved aux stack
> trace handles, which in turns leads to incorrect accounting of stack
> depot handles and refcount underflows in the stack depot code.
>
> Fix by introducing a raw spinlock to protect the aux stack trace handles
> in kasan_record_aux_stack.
>
> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Reported-by: syzbot+186b55175d8360728234@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/000000000000784b1c060b0074a2@google.com/
> Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Changes v2->v3:
> - Use raw spinlock to avoid lockdep complaints on RT kernels.
>
> Changes v1->v2:
> - Use per-object spinlock instead of a global one.
> ---
>  mm/kasan/generic.c | 32 +++++++++++++++++++++++++++++---
>  mm/kasan/kasan.h   |  8 ++++++++
>  2 files changed, 37 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 54e20b2bc3e1..55e6b5db2cae 100644
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
> +                * raw_spin_lock_init to access aux_lock, which resides inside
> +                * of a redzone.
> +                */
> +               kasan_disable_current();
> +               raw_spin_lock_init(&alloc_meta->aux_lock);
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
> +       raw_spin_lock_irqsave(&alloc_meta->aux_lock, flags);
> +       old_handle = alloc_meta->aux_stack[1];
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
> +       alloc_meta->aux_stack[0] = new_handle;
> +       raw_spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
> +       kasan_enable_current();
> +
> +       stack_depot_put(old_handle);
>  }
>
>  void kasan_record_aux_stack(void *addr)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5e298e3ac909..69e4f5e58e33 100644
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
> @@ -249,6 +250,13 @@ struct kasan_global {
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Free track is stored in kasan_free_meta. */
> +       /*
> +        * aux_lock protects aux_stack from accesses from concurrent
> +        * kasan_record_aux_stack calls. It is a raw spinlock to avoid sleeping
> +        * on RT kernels, as kasan_record_aux_stack_noalloc can be called from
> +        * non-sleepable contexts.
> +        */
> +       raw_spinlock_t aux_lock;
>         depot_stack_handle_t aux_stack[2];
>  };
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAL0FRdewOfEpTZWBTLquJ_k0L4QdCd_Uau6ewg2hAxQ%40mail.gmail.com.
