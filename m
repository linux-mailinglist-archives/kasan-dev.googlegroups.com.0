Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NXSKWAMGQEY7ANJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D394481BF76
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:11:30 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2cc77fdf765sf8504671fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:11:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189490; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ai0W7EcsZ3Pw5M2Ok6FdB5xl/HG62D7rVQG1hCe9LczrKXATiywcF5Z/DMM0x1tJxV
         ut1RmxH2LxLkFu5VA4jkoJIeEuOF4CvF0NB/GzDCRxVFRSjZL4FsK6Bkc/OPGg99whJW
         LzvcVQYBVx3oErSkrg7LOWnHmUgNu1I3Rqih9YB5vFR0BAtDOR9OfbRrn1iLcfK3Qvzq
         64VsukCxnTU1Jhzjt5vZKcdg6fMt25PQNAnGWUfLnwrZNOvz7UC6UrFN24TFhCCzIccx
         WtqNpSTTmISObhgIzrzPOQ/rwez0SFYOmnuCQFbR+uccxh+MMmipgm0EpEUIQq++E473
         GX2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9sqI96Q00qpNWEnzi23qMLP/Zw++6O4Zo0wH182dvTg=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=xCUQ4cifCb/OuWMG37CADg1fb0VQ9H+cSxrp/CtNWaUHAYP0nEmnjYcozzDi70Ld2o
         QPBQ7niaow9DuqP9qETy4Z/rNDir4JJSrOa+7PfC9PC9PGReFXeLG4GWWKz8O4QbCMf8
         1p8lUYXj3vuv+0DSmTNGrPD7bTVzpsEaLKcmFoBfubhvzpuuRTZjdj3q9+I5AtPOHXM5
         Unnrb32ahfbFD4dv65WsP7OvPWbSbKD3U/uUm6/zUxarTKoh04t+D5LBr3ePqcriBjKL
         T4t6I3V+YisbZ77xJtGUogCHivlyQ0ykPoPQQvJUb2ov8q3LMVjgCysmU/zbsplixPYd
         5gHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v+Z9dGYg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189490; x=1703794290; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9sqI96Q00qpNWEnzi23qMLP/Zw++6O4Zo0wH182dvTg=;
        b=CS9oJ4TVHN/xQF7Tu+j3MvaF33hbv5ArH4hezmBgDJwLTqzPqoP4dNUmoKPnRT8pwP
         jYNnZFmpvAwIGubCDk62BCTmnPYoVEsTXHTJTv6Gql4Lx60mCm6TDeQAbiGtQytKadbe
         UKULpug4i8q/scAU0ZN0yRdqGxOYs1IAhm8TWAPMyI+e8uS49hggpK9gYFeiik7O9uHw
         jEGr6+SuyDktjkxSHVcUNihiTiYUK+3niJc2VrLbqd9WkLskVVQu5qqblTmtRGJHoLjb
         fjlQ69YucxZuNFrHs3fDaBfo3is1W/IqzdRdL2Q/Nc23KIDmGCVS7E8b4zAQPe5p2JFz
         ENQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189490; x=1703794290;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9sqI96Q00qpNWEnzi23qMLP/Zw++6O4Zo0wH182dvTg=;
        b=P42utPYnQzHVqtiRDSYakPMUm8/E8wwKrH/nc4Yg3y5xysiM7fpCItJlXi0bBS0ozI
         +7xRIOYF1dlwUc5kRD/qIOWe5Q+YSQbECQrlD8VJxsCvhtikmmzL/kVUyXOiMYRF94NS
         9lD2aHfWBdtaa8d1m14lI65j6n7lp4ZsEdhLA9rivHzyaG3Nva1CaZr5k9RiS4FkPgaV
         q/rDP2QY20wZ91fCh7z2uUzeTdJnyZLny6RtUDLDJEmogeLhe5wWn1eQCjQ1wffiKxoF
         CIzJd5xcdUkAPUfMmm6+lYKKlZV4VJDZx39vK6BNOUmqqB4H2D/86NmkaTglZVclDcdD
         L7aw==
X-Gm-Message-State: AOJu0YwDyKM0KGRGLu9554Sjnh+A7Vv7mSJOm9+C5iKUphmRwCyeXE/l
	wmYorWOB6fOiEjvBtmMNLW4=
X-Google-Smtp-Source: AGHT+IGVpm2bbGlNmJY/BPUlV+Atq6orJ0rJfajQlvrTB4E8rVMXT5eSiupdcUO8CH2dQ4M2wgPszw==
X-Received: by 2002:a2e:a592:0:b0:2cc:a7fa:fc15 with SMTP id m18-20020a2ea592000000b002cca7fafc15mr69874ljp.50.1703189489948;
        Thu, 21 Dec 2023 12:11:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b0dc:0:b0:2cc:78ed:7c40 with SMTP id g28-20020a2eb0dc000000b002cc78ed7c40ls58200ljl.0.-pod-prod-06-eu;
 Thu, 21 Dec 2023 12:11:28 -0800 (PST)
X-Received: by 2002:a2e:9806:0:b0:2cb:2576:85f6 with SMTP id a6-20020a2e9806000000b002cb257685f6mr66242ljj.86.1703189487643;
        Thu, 21 Dec 2023 12:11:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189487; cv=none;
        d=google.com; s=arc-20160816;
        b=B/f7E9Ny//in67YPFQNC6L4VEhjKvK1N0VJ5vqhhVbziZT2gRQ1EEobgu3V2o95jjj
         6wpHokQNvHd95RBAgRxfkhD4xrl6fL4HcHgzEGDz5XPHUdcWr39Z1HUj/xE4+5mLTM85
         8uOEHU5+Vbsw71zijYnn04hRjlIPH/j/fRN9rgUt8vlbYRuMewhWNENq1C1HHELqD50s
         OWheol78hChtlF4tbWqsPVuKzj2EKEfM6RpvXqJgfDuyl3sHVziOpAWX/aJ2IW/8zZS9
         /a1tE2kIwUIl1lTt/xLesNz1d9NBmH5ESdkT4cqWO+Sitd4Ts+rvbsKHBMPrZH5sFktE
         4eFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n71TmRIpLCKyJ+zhDPnh2JHDUhteUqmqWNotznqdT9E=;
        fh=Ahy40MSztyYZMnTonwM1XBgEig8egyoCalPOkrHuKkk=;
        b=IHKUzpgzH4Cl4VoOEO8h6JZdVznYn/f9O4uUF5JAgEFnAzs0tzjo5gaajaeOlUmldK
         lojxC0IW3Q24V7MN0qEqkFWMIq3jmMPjVDvOenZl+Py0B4G8DBkugg5K3WG+slXW04Zc
         Wwgf4x30ngIp+S4dE0j+vtFlSqg3wSoz1bj7h2cF2gso0R8wKoomg2Z2Zqx9gwfaHflf
         fsQCgrUc5OBZBYzWVq4Ql1OhgiITiGToImwM/NAUiXWpMeGZ+I5+BULPHFWfBp/iGZjs
         FDZ04ga2UHcmH6GgGDsYTdWPxwwbciMheUZYrW67Ea/jcMRy5/wQaNMTnGyOE1uq//vJ
         Zy5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v+Z9dGYg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id l5-20020a2ea305000000b002cca660d558si26847lje.7.2023.12.21.12.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:11:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-2cc5a0130faso14098971fa.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:11:27 -0800 (PST)
X-Received: by 2002:a2e:b616:0:b0:2cc:8472:c97c with SMTP id
 r22-20020a2eb616000000b002cc8472c97cmr72870ljn.26.1703189487134; Thu, 21 Dec
 2023 12:11:27 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev> <20231221183540.168428-2-andrey.konovalov@linux.dev>
In-Reply-To: <20231221183540.168428-2-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:10:49 +0100
Message-ID: <CANpmjNPGBMD6XsPpdL-ix8VTuWAwV-jmBjLpC66Z5y543j0DuA@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: reuse kasan_track in kasan_stack_ring_entry
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Juntong Deng <juntong.deng@outlook.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=v+Z9dGYg;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as
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

On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Avoid duplicating fields of kasan_track in kasan_stack_ring_entry:
> reuse the structure.

No functional change?

> Fixes: 5d4c6ac94694 ("kasan: record and report more information")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan.h       |  7 +------
>  mm/kasan/report_tags.c | 12 ++++++------
>  mm/kasan/tags.c        | 12 ++++++------
>  3 files changed, 13 insertions(+), 18 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 5e298e3ac909..9072ce4c1263 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -279,13 +279,8 @@ struct kasan_free_meta {
>  struct kasan_stack_ring_entry {
>         void *ptr;
>         size_t size;
> -       u32 pid;
> -       depot_stack_handle_t stack;
> +       struct kasan_track track;
>         bool is_free;
> -#ifdef CONFIG_KASAN_EXTRA_INFO
> -       u64 cpu:20;
> -       u64 timestamp:44;
> -#endif /* CONFIG_KASAN_EXTRA_INFO */
>  };
>
>  struct kasan_stack_ring {
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 979f284c2497..688b9d70b04a 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -31,8 +31,8 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>  static void kasan_complete_extra_report_info(struct kasan_track *track,
>                                          struct kasan_stack_ring_entry *entry)
>  {
> -       track->cpu = entry->cpu;
> -       track->timestamp = entry->timestamp;
> +       track->cpu = entry->track.cpu;
> +       track->timestamp = entry->track.timestamp;
>  }
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
>
> @@ -80,8 +80,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>                         if (free_found)
>                                 break;
>
> -                       info->free_track.pid = entry->pid;
> -                       info->free_track.stack = entry->stack;
> +                       info->free_track.pid = entry->track.pid;
> +                       info->free_track.stack = entry->track.stack;
>  #ifdef CONFIG_KASAN_EXTRA_INFO
>                         kasan_complete_extra_report_info(&info->free_track, entry);
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
> @@ -98,8 +98,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>                         if (alloc_found)
>                                 break;
>
> -                       info->alloc_track.pid = entry->pid;
> -                       info->alloc_track.stack = entry->stack;
> +                       info->alloc_track.pid = entry->track.pid;
> +                       info->alloc_track.stack = entry->track.stack;
>  #ifdef CONFIG_KASAN_EXTRA_INFO
>                         kasan_complete_extra_report_info(&info->alloc_track, entry);
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index c13b198b8302..c4d14dbf27c0 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -100,8 +100,8 @@ static void save_extra_info(struct kasan_stack_ring_entry *entry)
>         u32 cpu = raw_smp_processor_id();
>         u64 ts_nsec = local_clock();
>
> -       entry->cpu = cpu;
> -       entry->timestamp = ts_nsec >> 3;
> +       entry->track.cpu = cpu;
> +       entry->track.timestamp = ts_nsec >> 3;
>  }
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
>
> @@ -134,15 +134,15 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>         if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
>                 goto next; /* Busy slot. */
>
> -       old_stack = entry->stack;
> +       old_stack = entry->track.stack;
>
>         entry->size = cache->object_size;
> -       entry->pid = current->pid;
> -       entry->stack = stack;
> -       entry->is_free = is_free;
> +       entry->track.pid = current->pid;
> +       entry->track.stack = stack;
>  #ifdef CONFIG_KASAN_EXTRA_INFO
>         save_extra_info(entry);
>  #endif /* CONFIG_KASAN_EXTRA_INFO */
> +       entry->is_free = is_free;
>
>         entry->ptr = object;
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPGBMD6XsPpdL-ix8VTuWAwV-jmBjLpC66Z5y543j0DuA%40mail.gmail.com.
