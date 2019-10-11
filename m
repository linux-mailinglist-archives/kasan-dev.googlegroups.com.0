Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFNAQDWQKGQEMLB3RSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 538BDD38A2
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2019 07:16:07 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id i28sf6556392pfq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2019 22:16:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570770965; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5Va+KWxLuQ2aTJq/1TWRyhwddQMUZNbLCFY57yKxOhlWu7SurvkWOcSwGKpsMH+HY
         Teqc1Cl8m4AXkp7wUenMPJwEkdGbw3U2FpZAphijI7l8H2M5oQvCjK2ejcCVEczqlWPQ
         JFYOgpvNkwp9mDtxC46gB/fT6Q5DWoJBi22F3j9MeSByhymQAGeBrDXsWL0vv58+SQbM
         78CgCNyu0XyjfL9SryxUQ+9pj0QeTLutJfi2M+ocDw1qTbHX4aOlVkGIzkHxME5jn9Z+
         UEMErck6ZXx/oMNN8Ye5UOlf2d63QjWNqPKmZB++Ixn1DVRdrFpeyO9CjqHEaMRo4fZI
         wrRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=yPbc1ynkkU+DfzmAO30fYB7AS/WOm48LTJiJ7LL0AeA=;
        b=eP3DUObmiFeaw3rdUDohcjWpd6cPzs2KTZNislNpmTfLCECjitVIwwl4M9g5GgbWtt
         mKby5wIsFV5wvesbUYs+e9YSrTMzPZi/uqmCDLv2qf1rVEkZiEs5r/AhTwLZLcZO0t8L
         EndE/Z39NXCW/YAMDR0xg+NvIpDchadHd6wMoJBQeVEaJAlcVBqQ9YuilP1LiWYHTYT6
         k0jcs5qFsRi/EPxtG8f6tDJj036Y5Bt1pXwrdlNxc2MvYvrGiZlXCkcTPLAjaaeRTMdi
         EMCvgKwfnIDKXgUBePlZCMb5D8oXE1f94MO6zoxy8vn9HXxbD43zgQqruhzv1/95iCmW
         koag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AOu22roD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yPbc1ynkkU+DfzmAO30fYB7AS/WOm48LTJiJ7LL0AeA=;
        b=UmBJu+uR17i8l1yQwQiuMNxzj10jfnnfwVZkjC0jYcGcAh67Km1dKWNN6xTRCpesTq
         qLuI4zvrlBcvX+hth+UYRRrXYxtItpXqYwsb6JYPqT7SKxXA6AwOmaWcG6AGNmagjGEB
         995D1Ig5PcDlAMDC43KkJt8RebTc97Ucei+JDvL0D/O3fT/4Y+2FF4H+nb6ckjC0FB2b
         0mPVY5CZ7/TUMc1ECZqQKBvSTplrRD63apDHXBNfDJO7xd6qSGQmDfAWdEBYLKQ8W40B
         ABDoo5E51mil7UFRo9+LuuxaZznWMs4Ui5X3+UOhU2512xRtMAhrMEnb8FmrlkfDVD19
         v58w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yPbc1ynkkU+DfzmAO30fYB7AS/WOm48LTJiJ7LL0AeA=;
        b=VJkLKk84AcyCFODHXwWkV7CcTtH8dFCSeRiufxuCGAimjMaf1/v39RCBUkSwfJWs2L
         iDRA0WxViTZxEr24lGCEiCV/RpTKEV+uMJBKpmleoIJWhCvZvwNcvzJHWM+S26QV2kBZ
         mF4K3VIQ0neblacHqxDbtD1A3YNuaoaCR2gM3v7bYbS1zU+mWQuzXsZypdjqU14uNTUN
         YY1/sKY7RcG6duvQSc/cSgD/7WyV5U/poR0espO1YKVNNLGxQ0hvQB+5r24k7BUD8GKp
         TsjV/D2Vro+XlntGcQT/kIBeCbYmwKKslkjcu0LnnySVbEHtVig8m9c9R/NTFoFh3LhY
         wMLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTZzyzdlh9jwho7bpFkFzIeXruGNU8ZFw2/jqjwoXDl4p5nCxT
	VzxMssmGp3jYm8/KR1Y0ezQ=
X-Google-Smtp-Source: APXvYqxK4L1fZpSCCjIN+EDI/Lolif6Bs7I/xPzgR9qntujgyjEWtwnyQCb2gRahwsNhQyq3JEgseQ==
X-Received: by 2002:a63:fb0a:: with SMTP id o10mr14862548pgh.258.1570770965427;
        Thu, 10 Oct 2019 22:16:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8dc2:: with SMTP id j2ls1780464pfr.8.gmail; Thu, 10 Oct
 2019 22:16:05 -0700 (PDT)
X-Received: by 2002:a63:4e09:: with SMTP id c9mr14272495pgb.98.1570770964944;
        Thu, 10 Oct 2019 22:16:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570770964; cv=none;
        d=google.com; s=arc-20160816;
        b=xX4K2hpRZ8smZFluNyymDvwyDCMcSLyz5hsBhRDySQ0Xoc6sYCjCFIa8661GrR34dC
         zwqnDSjUYFYaduREamBdFDYemfkSA0QuQgCPm27G1Gm0W+KHUNvne4jSKBW7EijJLfmi
         FFcNAZxP6EXcTEBvfwKQ7909Ej1gSmaLDufUq0/GqVWrCdv5TE39NbPJEUlVZDkGFmtG
         De+Eswl4YJ6hBPRdTSwAGEVHNhUvqGkBUn9O65cTStf9mWd6s6lQW5AVZApwEhmP67HB
         KuLNlaW8bKWlZbs4vj+reGakORA1gymDe4oOdO7xaPBGhCB+fQ0z+QzOP0jMrJry8ZZF
         bWhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=JNE3qIp3GwZhiIaVERKeTReBCbfaT6qnnngWA97+jmk=;
        b=RtExFJ4FBVHaMiru6KLqZLHXWh5xDpynLn/vpL/FJbPLQus0tvJvKPVsUPx+QQJfGQ
         tpol5PXy5n3sJC+07uAHbtzcdplCX7C8oPWzCQWRCkKf3fLY9lsj4keh1m5+PznW3t5y
         Y/HRzPCf0FvDEZk1H3aPw33Eg39cZen4pwBA+jEzeJlaRC4Gdcc2yjTkjhtG7Ulq0BPk
         pJG+tT1l53gTC4bZSlIUdOCfYaEseo8zVSMjaKi2oOhd9Q2yv5pq9s6LO2TzOOxVhW55
         aVzBVugpzVaHSHkrfmp70eGSMPFfeiQlLRlD8fp4YS8C5hl8AOunjPOLO55/OXgnuRLz
         8vHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AOu22roD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id q141si714711pfc.4.2019.10.10.22.16.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2019 22:16:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id y5so5355729pfo.4
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2019 22:16:04 -0700 (PDT)
X-Received: by 2002:aa7:8dd9:: with SMTP id j25mr12341886pfr.94.1570770964627;
        Thu, 10 Oct 2019 22:16:04 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x125sm7795793pfb.93.2019.10.10.22.16.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2019 22:16:03 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191007080209.GA22997@pc636>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <20191007080209.GA22997@pc636>
Date: Fri, 11 Oct 2019 16:15:59 +1100
Message-ID: <87sgnzuak0.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=AOu22roD;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Uladzislau,


> Looking at it one more, i think above part of code is a bit wrong
> and should be separated from merge_or_add_vmap_area() logic. The
> reason is to keep it simple and do only what it is supposed to do:
> merging or adding.
>
> Also the kasan_release_vmalloc() gets called twice there and looks like
> a duplication. Apart of that, merge_or_add_vmap_area() can be called via
> recovery path when vmap/vmaps is/are not even setup. See percpu
> allocator.
>
> I guess your part could be moved directly to the __purge_vmap_area_lazy()
> where all vmaps are lazily freed. To do so, we also need to modify
> merge_or_add_vmap_area() to return merged area:

Thanks for the review. I've integrated your snippet - it seems to work
fine, and I agree that it is much simpler and clearer. so I've rolled it
in to v9 which I will post soon.

Regards,
Daniel

>
> <snip>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index e92ff5f7dd8b..fecde4312d68 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -683,7 +683,7 @@ insert_vmap_area_augment(struct vmap_area *va,
>   * free area is inserted. If VA has been merged, it is
>   * freed.
>   */
> -static __always_inline void
> +static __always_inline struct vmap_area *
>  merge_or_add_vmap_area(struct vmap_area *va,
>         struct rb_root *root, struct list_head *head)
>  {
> @@ -750,7 +750,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  
>                         /* Free vmap_area object. */
>                         kmem_cache_free(vmap_area_cachep, va);
> -                       return;
> +
> +                       /* Point to the new merged area. */
> +                       va = sibling;
> +                       merged = true;
>                 }
>         }
>  
> @@ -759,6 +762,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>                 link_va(va, root, parent, link, head);
>                 augment_tree_propagate_from(va);
>         }
> +
> +       return va;
>  }
>  
>  static __always_inline bool
> @@ -1172,7 +1177,7 @@ static void __free_vmap_area(struct vmap_area *va)
>         /*
>          * Merge VA with its neighbors, otherwise just add it.
>          */
> -       merge_or_add_vmap_area(va,
> +       (void) merge_or_add_vmap_area(va,
>                 &free_vmap_area_root, &free_vmap_area_list);
>  }
>  
> @@ -1279,15 +1284,20 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
>         spin_lock(&vmap_area_lock);
>         llist_for_each_entry_safe(va, n_va, valist, purge_list) {
>                 unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
> +               unsigned long orig_start = va->va_start;
> +               unsigned long orig_end = va->va_end;
>  
>                 /*
>                  * Finally insert or merge lazily-freed area. It is
>                  * detached and there is no need to "unlink" it from
>                  * anything.
>                  */
> -               merge_or_add_vmap_area(va,
> +               va = merge_or_add_vmap_area(va,
>                         &free_vmap_area_root, &free_vmap_area_list);
>  
> +               kasan_release_vmalloc(orig_start,
> +                       orig_end, va->va_start, va->va_end);
> +
>                 atomic_long_sub(nr, &vmap_lazy_nr);
>  
>                 if (atomic_long_read(&vmap_lazy_nr) < resched_threshold)
> <snip>
>
> --
> Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sgnzuak0.fsf%40dja-thinkpad.axtens.net.
