Return-Path: <kasan-dev+bncBCMIZB7QWENRBSMUQWCAMGQEWSEORLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8400D367E50
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:04:58 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id t25-20020a62ea190000b0290229c92857besf12774630pfh.21
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 03:04:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619085897; cv=pass;
        d=google.com; s=arc-20160816;
        b=lDk+K+CUlTHFYz1W1PckDaMe1jZNmstfoHmmGTbBg3ylWXHIMHlX1eBsljRmxEk13f
         OlYx9xPb89fsm3qrgNe98Fq+6B65UOqF/7ZOoGH105WGj8iQa7EHPGUsl5FGgGbCfJWx
         vPoUNJbVYElj9VNNrPlzn084wa4zn70s+mfVDLXqEV/9lfXvmA0Bp783PH1cHQC67kz1
         gqf+FkM0C/4fdhjgL2VQlDVHLpw4pd01zvvAxyhasAvJvs3VevQDLWNzomLg8tRlC4i0
         yNDGUok4qcDd/8cT185HBViOjwfwFbnNcKWLXMwS9Ltn8jPFzWYsoRDXeA1kofJGEa23
         Hyjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jIsni7oipKQO6x5Kd2dfWVcq8xq5574YpwKppplMNdc=;
        b=Kgu9AevEWL5xV6ReXQ4fpvSO9adm22SUYC7DmLRzSUqyfRAxl9j9PbYNyBzf6hn3wo
         1FwxPjerh6yCGQhGQ9TBfYKwSN1w/BUQrl9mmRdrPaNqap9wGRAj2LAerCH5UXLlqott
         MHAQhdfOjzDY/WautFQvsECJpe98rEO+YvuG5AFiiIqE5Tx84dwyZQ2uWu+DVNfoo2Pz
         aBqm4Mk5JbEQiOCunwbi9/GZZ9XK/ddrYeccvACj0vHJOqE2kB25z+RiI8eKXX+/rl19
         /4r89LYQSJ49RS8MPsjryjl9MaeW875fncJeWIBqmZMrLooBMZ/LrwbXjWlUti/ld7F0
         Fmhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K1SY+2Ll;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIsni7oipKQO6x5Kd2dfWVcq8xq5574YpwKppplMNdc=;
        b=OVRwABBgo2ZeQuKhKxuRjYfsn4THXBhgmw1frC31BjWsI/JUInxZ522Lwm33LpFmlF
         LgQq/X54d2dTv4fo7jhzgPNhobJTW7cSLQd0L987yxRk748lTnpYQz3h1VLqYYaWQF/r
         /IgRaUkLlQxeuFfqW5EIFyAbh6joe9Tg+GkHJtTixf5+iwrP6QFBbYi1EINYGJGegDiF
         SVfIYfIh6XCl7rMesliI/xRj6TGnMDOyYKB89l40GI6t+6BKjXb/Y2o4mb2DktNjCvtI
         Ym3vv4hRRcRppzovD5n8ctAs27b8svFY5OGZbTSyoi8MQuNtJD05mkzK+CFthuIgubnb
         WHSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIsni7oipKQO6x5Kd2dfWVcq8xq5574YpwKppplMNdc=;
        b=gkz/Sg7qFHZdGdajQZaTvuIqrxUfZnjCvvNNfSpx7R8ljFBgDF41AODwtFMxLUXwGo
         H8v26Ws1AcOwAIef0qw4lsp5pf4qIFS7MQGWwHn1skukQ9ZOWpCCtr86cfseUAOa2EgN
         QU9IoLTwoWjIHx7TI3Ort7NWBlVxI8vjDm07Qx5oCBMcO+CuB+43nElOvSaakncsO5wC
         SESWq88e/cxCTRUXnGP07giTXGaZ7kvFVE8wPVSPzggo6GF5topyY50Lee8c88lWte0e
         XUE6pyNbSQo6jzame5WJiqq6GUffQ6oK9qfoj/Luj4eguduJSO8KT7hjyglXfPeoejnA
         fYCA==
X-Gm-Message-State: AOAM532CAJpFfxeB/ym7l4A+6T9DmvVzy2luaDkCoz6DNmWKWQLn5c4W
	j3cRW0DWit2p6O+c/FayJiY=
X-Google-Smtp-Source: ABdhPJxuM5PHzMfsLW/wsZAl43872DiOOgIO3ALQucNkOyU6lQbewM1lnpI+vgSyl7vNAQc9VwqztQ==
X-Received: by 2002:a17:902:744b:b029:ec:af1f:5337 with SMTP id e11-20020a170902744bb02900ecaf1f5337mr2815038plt.35.1619085897295;
        Thu, 22 Apr 2021 03:04:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:79d5:: with SMTP id u204ls2004775pfc.9.gmail; Thu, 22
 Apr 2021 03:04:56 -0700 (PDT)
X-Received: by 2002:a63:64e:: with SMTP id 75mr2735856pgg.328.1619085896743;
        Thu, 22 Apr 2021 03:04:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619085896; cv=none;
        d=google.com; s=arc-20160816;
        b=RIrxk4u+jwopoMEkpxOuKBOyHZ8eeJQ4u/ggGeAWZRD/miMQfPcWOWoTK1lBN06Uzu
         ngAcIt6wrU4j/tBac0oEd5I0OmIhdjuoIWS7fW6uP3kzU36TSZpfKY37d4gVtcKXXUtm
         hrIVRaLpSm0mBWoYpQvm2jGE9ONaG2NVa2d14oM6xgeV0him2m9Tpul/Mq8UWq8t3Yrq
         qHvpt9J7PedX+XINg5FkoMjEr1PB8CKHVMfLP1kbX9S67pGHnfMj/iYxgEOYv9Y/jKAR
         IfdVx2Jrb3LGmOW72Nkb2O2cC7Nxcfoqko8GwsA9v3xtjfPfsM7kZ3rhblDPmi3rwANm
         0QhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+V4jflKAWnzoYtPoavg8UW7/vmGxKAU/icczA4c4+bQ=;
        b=QmduiuqX7eRV5xfE3uKF7Njd6eb1GjWqDVRLR8n7EayPJIfgDHpErYvuvGZI0j6tKP
         72o4iU6Qrm2Bwsnu1N6Fme0RnoWs2wZT1/uxQWONtut5V9JDaJxuaz11aaW3Hmq/le8T
         0KsMGf1WUxls5uL2s3ZzyZy0R9zzpqARcplGJ31U2SsTrxctJUxUYz9HmlRnkvSmW7VK
         XwKgPFbuYMo100kGiuS+7Q6vxkmMBkyaopTzJ8LkeGijKSGNW1SaqipTUBUD+FzU3hSh
         NeY9YF2xVlzLvQUvczYnrNfUVb7QYvVS+U6OOXosLqI0uA2GpvsRuAWDDpUs6qZAfLLI
         Z5uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K1SY+2Ll;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id u7si320004pji.1.2021.04.22.03.04.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 03:04:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id s4so5524544qtw.3
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 03:04:56 -0700 (PDT)
X-Received: by 2002:a05:622a:5d0:: with SMTP id d16mr2273011qtb.290.1619085895368;
 Thu, 22 Apr 2021 03:04:55 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a@epcas5p4.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com> <1619079317-1131-2-git-send-email-maninder1.s@samsung.com>
In-Reply-To: <1619079317-1131-2-git-send-email-maninder1.s@samsung.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 12:04:43 +0200
Message-ID: <CACT4Y+ZJ95KiFNHeT9k0p6ezDz-apkJVp586UBSdJeHtCYR_Qg@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm/kasan: proc interface to read KASAN errors at any time
To: Maninder Singh <maninder1.s@samsung.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	AMIT SAHRAWAT <a.sahrawat@samsung.com>, Vaneet Narang <v.narang@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K1SY+2Ll;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82c
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

On Thu, Apr 22, 2021 at 11:17 AM Maninder Singh <maninder1.s@samsung.com> wrote:
>
> store minimal information required to regenerate KASAN logs
> from reading of proc interface.
>
> kernel buffer is allocated for 4K bytes to avoid multiple
> checks of sanity for snprintf returns, and it will be checked
> before copying that data to user space if user buffer has that
> much capacity or not.
>
> During long time aging test of targets, it is diffucult to check for
> KASAN reported issues. Thus it will be better it proc interface is
> present to check for Unique KASAN errors reported till time.
>
> sample output and verification for ARM64:
> Run sample TC's of KASAN:

Alex, Marco, can the recently added error_report_notify interface be
used for this? Looks like they are doing roughly the same thing with
the same intentions.


> [   25.450749] kasan test: kmalloc_oob_right out-of-bounds to right
> [   25.452851] ==================================================================
> [   25.453779] BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0x80/0xa4
> [   25.454800] Write of size 1 at addr ffff0000c3f1c27b by task cat/125
> [   25.455891]
> ....
> [   25.488283] kasan test: kmalloc_oob_left out-of-bounds to left
> [   25.488819] ==================================================================
> [   25.489189] BUG: KASAN: slab-out-of-bounds in kmalloc_oob_left+0x80/0xac
> [   25.489601] Read of size 1 at addr ffff0000c3f1c2ff by task cat/125
> ...
>
> After first reporting, NO KASAN reports for same issues:
>
> [  115.078095] kasan test: kmalloc_oob_right out-of-bounds to right
> [  115.078773] kasan test: kmalloc_oob_left out-of-bounds to left
> [  115.079237] kasan test: kmalloc_node_oob_right kmalloc_node(): out-of-bounds to right
> [  115.080056] kasan test: kmalloc_pagealloc_oob_right kmalloc pagealloc allocation: out-of-bounds to right
> [  115.080683] kasan test: kmalloc_pagealloc_uaf kmalloc pagealloc allocation: use-after-free
> [  115.081209] kasan test: kmalloc_pagealloc_invalid_free kmalloc pagealloc allocation: invalid-free
>
> Check same from /proc/kasan_log:
> KASAN Issue no. 1
> ==================================================================
>
> BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0x80/0xa4 at addr ffff0000c3f1c27b
> Write of size 1 by task cat/125
> ...
> ...
> Memory state around the buggy address:
>  ffff0000c3f1c100: 00 00 00 00 fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff0000c3f1c180: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >ffff0000c3f1c200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03
>                                                                 ^
>  ffff0000c3f1c280: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff0000c3f1c300: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> ==================================================================
> KASAN Issue no. 2
> ==================================================================
>
> BUG: KASAN: slab-out-of-bounds in kmalloc_oob_left+0x80/0xac at addr ffff0000c3f1c2ff
> Read of size 1 by task cat/125
> ...
> ...
> Memory state around the buggy address:
>  ffff0000c3f1c180: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff0000c3f1c200: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
> >ffff0000c3f1c280: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>                                                                 ^
>  ffff0000c3f1c300: 00 07 fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff0000c3f1c380: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> ==================================================================
> KASAN Issue no. 3
> ==================================================================
> ...
> ...
>
> Co-developed-by: Vaneet Narang <v.narang@samsung.com>
> Signed-off-by: Vaneet Narang <v.narang@samsung.com>
> Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
> ---
>  mm/kasan/kasan.h          |  32 +++-
>  mm/kasan/report.c         | 377 ++++++++++++++++++++++++++++++++++----
>  mm/kasan/report_generic.c |  42 ++++-
>  mm/kasan/report_hw_tags.c |   5 +-
>  mm/kasan/report_sw_tags.c |  30 ++-
>  5 files changed, 431 insertions(+), 55 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d14ccce246ba..2c2c79551cbd 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -94,6 +94,25 @@ extern bool kasan_flag_panic __ro_after_init;
>  #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
>  #define META_ROWS_AROUND_ADDR 2
>
> +#define SHADOW_ROWS    (2 * META_ROWS_AROUND_ADDR + 1)
> +#define CACHE_NAME_LEN (20)
> +
> +typedef enum {
> +       UNKNOWN,
> +       OUT_OF_BOUNDS,
> +       OUT_OF_BOUNDS_SLAB,
> +       OUT_OF_BOUNDS_GLOBAL,
> +       OUT_OF_BOUNDS_STACK,
> +       USE_AFTER_FREE,
> +       OUT_OF_BOUNDS_ALLOCA,
> +       OUT_OF_BOUNDS_VMALLOC,
> +       INVALID_ACCESS,
> +       NULL_PTR_DEREFER,
> +       USER_MEMORY_ACCESS,
> +       WILD_MEMORY_ACCESS,
> +       DOUBLE_INVALID_FREE
> +} kasan_bug_type;
> +
>  struct kasan_access_info {
>         const void *access_addr;
>         const void *first_bad_addr;
> @@ -106,6 +125,17 @@ struct kasan_record {
>         depot_stack_handle_t    bt_handle;
>         depot_stack_handle_t    alloc_handle;
>         depot_stack_handle_t    free_handle;
> +       const void              *access_addr;
> +       const void              *first_bad_addr;
> +       unsigned long           ip;
> +       size_t                  access_size;
> +       char                    comm[TASK_COMM_LEN];
> +       char                    cache_name[CACHE_NAME_LEN];
> +       int                     cache_size;
> +       pid_t                   pid;
> +       kasan_bug_type          bug_type;
> +       u8                      buf[SHADOW_ROWS][META_BYTES_PER_ROW];
> +       bool                    is_write;
>  };
>
>  /* The layout of struct dictated by compiler */
> @@ -234,7 +264,7 @@ static inline void kasan_print_tags(u8 addr_tag, const void *addr) { }
>  #endif
>
>  void *kasan_find_first_bad_addr(void *addr, size_t size);
> -const char *kasan_get_bug_type(struct kasan_access_info *info);
> +const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug);
>  void kasan_metadata_fetch_row(char *buffer, void *row);
>
>  #if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 4576de76991b..b0cc95fedc29 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -15,6 +15,7 @@
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
>  #include <linux/printk.h>
> +#include <linux/proc_fs.h>
>  #include <linux/sched.h>
>  #include <linux/slab.h>
>  #include <linux/stackdepot.h>
> @@ -66,7 +67,7 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
>  static void print_error_description(struct kasan_access_info *info)
>  {
>         pr_err("BUG: KASAN: %s in %pS\n",
> -               kasan_get_bug_type(info), (void *)info->ip);
> +               kasan_get_bug_type(info, NULL), (void *)info->ip);
>         if (info->access_size)
>                 pr_err("%s of size %zu at addr %px by task %s/%d\n",
>                         info->is_write ? "Write" : "Read", info->access_size,
> @@ -342,26 +343,50 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
>  }
>  #endif /* IS_ENABLED(CONFIG_KUNIT) */
>
> -void kasan_report_invalid_free(void *object, unsigned long ip)
> +static void copy_error_description(struct kasan_access_info *info,
> +                       struct kasan_record *record)
>  {
> -       unsigned long flags;
> -       u8 tag = get_tag(object);
> +       record->ip = info->ip;
> +       record->first_bad_addr = info->first_bad_addr;
> +       record->access_addr = info->access_addr;
> +       record->is_write = info->is_write;
> +       record->access_size = info->access_size;
> +       record->pid = task_pid_nr(current);
> +       strncpy(record->comm, current->comm, TASK_COMM_LEN);
> +}
>
> -       object = kasan_reset_tag(object);
> +static void copy_shadow_for_address(struct kasan_record *record)
> +{
> +       int i;
> +       void *addr = (void *)record->first_bad_addr;
> +       void *row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
> +                       - META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
>
> -#if IS_ENABLED(CONFIG_KUNIT)
> -       if (current->kunit_test)
> -               kasan_update_kunit_status(current->kunit_test);
> -#endif /* IS_ENABLED(CONFIG_KUNIT) */
>
> -       start_report(&flags);
> -       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> -       kasan_print_tags(tag, object);
> -       pr_err("\n");
> -       print_address_description(object, tag);
> -       pr_err("\n");
> -       print_memory_metadata(object);
> -       end_report(&flags, (unsigned long)object);
> +       for (i = 0; i < SHADOW_ROWS; i++) {
> +               kasan_metadata_fetch_row((char *)&record->buf[i], row);
> +               row += META_MEM_BYTES_PER_ROW;
> +       }
> +}
> +
> +static bool match_handles(struct kasan_record *record)
> +{
> +       int i = 0;
> +
> +       for (i = 0; i < stored_kasan_records; i++) {
> +               if (record->bt_handle != kasan_records[i].bt_handle)
> +                       continue;
> +               if (record->alloc_handle != kasan_records[i].alloc_handle)
> +                       continue;
> +               if ((record->bug_type == USE_AFTER_FREE ||
> +                       record->bug_type == DOUBLE_INVALID_FREE) &&
> +                       (record->free_handle != kasan_records[i].free_handle))
> +                       continue;
> +
> +               return true;
> +       }
> +
> +       return false;
>  }
>
>  /*
> @@ -370,21 +395,26 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>   * returns false if same record is already saved.
>   * returns true if its new record and saved in database of KASAN.
>   */
> -static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsigned long *flags)
> +static bool save_report(void *addr, struct kasan_access_info *info, u8 tag,
> +                               unsigned long *flags, kasan_bug_type *bug)
>  {
>         struct kasan_record record = {0};
>         depot_stack_handle_t bt_handle;
> -       int i = 0;
> -       const char *bug_type;
>         struct kasan_alloc_meta *alloc_meta;
>         struct kasan_track *free_track;
>         struct page *page;
> +       kasan_bug_type bug_enum = UNKNOWN;
>         bool ret = true;
>
>         kasan_disable_current();
>         spin_lock_irqsave(&report_lock, *flags);
>
> -       bug_type = kasan_get_bug_type(info);
> +       if (!bug) {
> +               kasan_get_bug_type(info, &bug_enum);
> +               record.bug_type = bug_enum;
> +       } else
> +               record.bug_type = *bug;
> +
>         page = kasan_addr_to_page(addr);
>         bt_handle = kasan_save_stack(GFP_KERNEL);
>
> @@ -397,23 +427,27 @@ static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsi
>                 record.alloc_handle = alloc_meta->alloc_track.stack;
>                 if (free_track)
>                         record.free_handle = free_track->stack;
> +
> +               strncpy(record.cache_name, cache->name, CACHE_NAME_LEN - 1);
> +               record.cache_name[CACHE_NAME_LEN - 1] = '\0';
> +               record.cache_size = cache->object_size;
>         }
>
>         record.bt_handle = bt_handle;
>
> -       for (i = 0; i < stored_kasan_records; i++) {
> -               if (record.bt_handle != kasan_records[i].bt_handle)
> -                       continue;
> -               if (record.alloc_handle != kasan_records[i].alloc_handle)
> -                       continue;
> -               if (!strncmp("use-after-free", bug_type, 15) &&
> -                       (record.free_handle != kasan_records[i].free_handle))
> -                       continue;
> +       if (match_handles(&record)) {
> +               ret = false;
> +               goto done;
> +       }
>
> +       if (stored_kasan_records >= MAX_RECORDS) {
> +               WARN_ONCE(1, "KASAN database reached capacity");
>                 ret = false;
>                 goto done;
>         }
>
> +       copy_error_description(info, &record);
> +       copy_shadow_for_address(&record);
>         memcpy(&kasan_records[stored_kasan_records], &record, sizeof(struct kasan_record));
>         stored_kasan_records++;
>
> @@ -423,6 +457,38 @@ static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsi
>         return ret;
>  }
>
> +void kasan_report_invalid_free(void *object, unsigned long ip)
> +{
> +       unsigned long flags;
> +       u8 tag = get_tag(object);
> +       struct kasan_access_info info;
> +       kasan_bug_type bug_enum = DOUBLE_INVALID_FREE;
> +
> +       object = kasan_reset_tag(object);
> +
> +#if IS_ENABLED(CONFIG_KUNIT)
> +       if (current->kunit_test)
> +               kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
> +       info.ip = ip;
> +       info.first_bad_addr = object;
> +       info.access_addr = 0;
> +       info.is_write = 0;
> +       info.access_size = 0;
> +       if (!save_report(object, &info, tag, &flags, &bug_enum))
> +               return;
> +
> +       start_report(&flags);
> +       pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> +       kasan_print_tags(tag, object);
> +       pr_err("\n");
> +       print_address_description(object, tag);
> +       pr_err("\n");
> +       print_memory_metadata(object);
> +       end_report(&flags, (unsigned long)object);
> +}
> +
>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>                                 unsigned long ip)
>  {
> @@ -442,18 +508,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>         untagged_addr = kasan_reset_tag(tagged_addr);
>
>         info.access_addr = tagged_addr;
> -       if (addr_has_metadata(untagged_addr))
> -               info.first_bad_addr =
> -                       kasan_find_first_bad_addr(tagged_addr, size);
> -       else
> -               info.first_bad_addr = untagged_addr;
>         info.access_size = size;
>         info.is_write = is_write;
>         info.ip = ip;
>
> -       if (addr_has_metadata(untagged_addr) &&
> -               !save_report(untagged_addr, &info, get_tag(tagged_addr), &flags))
> -               return;
> +       if (addr_has_metadata(untagged_addr)) {
> +               info.first_bad_addr = kasan_find_first_bad_addr(tagged_addr, size);
> +
> +               if (!save_report(untagged_addr, &info, get_tag(tagged_addr), &flags, NULL))
> +                       return;
> +       } else
> +               info.first_bad_addr = untagged_addr;
>
>         start_report(&flags);
>
> @@ -528,3 +593,241 @@ void kasan_non_canonical_hook(unsigned long addr)
>                  orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
>  }
>  #endif
> +
> +#define READ_SIZE      (4096)
> +static ssize_t print_kasan_error(char __user *buf, size_t count,
> +               struct kasan_record *record, loff_t *ppos, char *kbuf)
> +{
> +       int ret = 0;
> +       unsigned long *entries;
> +       unsigned long nr_entries;
> +       const char *bug_type = "unknown-crash";
> +       int i, j;
> +       void *row;
> +       void *addr = (void *)record->first_bad_addr;
> +
> +       if (!kbuf)
> +               return -ENOMEM;
> +
> +       switch (record->bug_type) {
> +       case OUT_OF_BOUNDS:
> +               bug_type = "out-of-bounds";
> +               break;
> +       case OUT_OF_BOUNDS_SLAB:
> +               bug_type = "slab-out-of-bounds";
> +               break;
> +       case OUT_OF_BOUNDS_GLOBAL:
> +               bug_type = "global-out-of-bounds";
> +               break;
> +       case OUT_OF_BOUNDS_STACK:
> +               bug_type = "stack-out-of-bounds";
> +               break;
> +       case USE_AFTER_FREE:
> +               bug_type = "use-after-free";
> +               break;
> +       case OUT_OF_BOUNDS_ALLOCA:
> +               bug_type = "alloca-out-of-bounds";
> +               break;
> +       case OUT_OF_BOUNDS_VMALLOC:
> +               bug_type = "alloca-out-of-vmalloc";
> +               break;
> +       case INVALID_ACCESS:
> +               bug_type = "invalid-access";
> +               break;
> +       case NULL_PTR_DEREFER:
> +               bug_type = "null-ptr-deref";
> +               break;
> +       case USER_MEMORY_ACCESS:
> +               bug_type = "user-memory-access";
> +               break;
> +       case WILD_MEMORY_ACCESS:
> +               bug_type = "wild-memory-access";
> +               break;
> +       case DOUBLE_INVALID_FREE:
> +               bug_type = "double-free or invalid-free";
> +               break;
> +       default:
> +               break;
> +       }
> +
> +       ret += snprintf(kbuf + ret, count - ret,
> +                               "KASAN Issue no. %lld\n", *ppos);
> +       ret += snprintf(kbuf + ret, count - ret,
> +                       "==============================="
> +                       "===================================\n");
> +
> +       if (record->bug_type != DOUBLE_INVALID_FREE) {
> +               ret += snprintf(kbuf + ret, count - ret,
> +                               "\nBUG: KASAN: %s in %pS at addr %px\n",
> +                               bug_type, (void *)record->ip, record->access_addr);
> +               ret += snprintf(kbuf + ret, count - ret,
> +                               "%s of size %zu by task %s/%d\n",
> +                               record->is_write ? "Write" : "Read",
> +                               record->access_size, record->comm, record->pid);
> +       } else {
> +               ret += snprintf(kbuf + ret, count - ret,
> +                       "\nBUG: KASAN: %s in %pS\n",
> +                       bug_type, (void *)record->ip);
> +       }
> +
> +       ret += snprintf(kbuf + ret, count - ret, "\nBacktrace:\n");
> +       nr_entries = stack_depot_fetch(record->bt_handle, &entries);
> +
> +       ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
> +
> +       if (record->alloc_handle) {
> +               ret += snprintf(kbuf + ret, count - ret,
> +                               "\nBelongs to the cache %s of size: %d\n",
> +                               record->cache_name, record->cache_size);
> +               ret += snprintf(kbuf + ret, count - ret,
> +                               "------------------------------------------"
> +                               "-----------------------------------\n");
> +
> +               nr_entries = stack_depot_fetch(record->alloc_handle, &entries);
> +               ret += snprintf(kbuf + ret, count - ret, "INFO Allocation path:\n");
> +
> +               ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
> +
> +               if (record->free_handle) {
> +                       ret += snprintf(kbuf + ret, count - ret, "\nINFO Free path:\n");
> +
> +                       nr_entries = stack_depot_fetch(record->free_handle, &entries);
> +                       ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
> +               }
> +       }
> +
> +       if (kernel_or_module_addr(addr)) {
> +               if (!init_task_stack_addr(addr))
> +                       ret += snprintf(kbuf + ret, count - ret,
> +                               "The buggy address belongs to the variable %pS\n",
> +                               (void *)record->access_addr);
> +       }
> +
> +       ret += snprintf(kbuf + ret, count - ret,
> +                               "Memory state around the buggy address:\n");
> +
> +       row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
> +                       - META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
> +
> +       for (i = 0; i < SHADOW_ROWS; i++) {
> +               if (i)
> +                       ret += snprintf(kbuf + ret, count - ret, "\n");
> +
> +               ret += snprintf(kbuf + ret, count - ret,
> +               (i == 2) ? ">%px: " : " %px: ", row);
> +
> +               for (j = 0; j < META_BYTES_PER_ROW; j++) {
> +                       u8 value = record->buf[i][j];
> +                               ret += snprintf(kbuf + ret, count - ret, "%02x ", value);
> +               }
> +
> +               if (meta_row_is_guilty(row, addr))
> +                       ret += snprintf(kbuf + ret, count - ret, "\n%*c",
> +                               meta_pointer_offset(row, addr),
> +                               '^');
> +
> +               row += META_MEM_BYTES_PER_ROW;
> +       }
> +
> +       ret += snprintf(kbuf + ret, count - ret,
> +                       "\n==============================="
> +                       "===================================\n");
> +
> +       /*
> +        * checking for space in buffer only when copying to user,
> +        * otherwise if overflow'ed in kernel buffer, it will
> +        * lead to kernel crash and then size of vmalloc'ed
> +        * memory can be increased.
> +        *
> +        * Benefit: checks on each snprintf avoided.
> +        */
> +       if (ret >= count) {
> +               ret = -ENOMEM;
> +               goto err;
> +       }
> +
> +       if (copy_to_user(buf, kbuf, ret))
> +               ret = -EFAULT;
> +
> +err:
> +       return ret;
> +}
> +
> +/*
> + * read_kasan_errors()
> + *
> + * function to print all the entries present
> + * in KASAN depot_stack database currently in system.
> + */
> +static ssize_t read_kasan_errors(struct file *file, char __user *buf,
> +               size_t count, loff_t *ppos)
> +{
> +       /*
> +        * No need of lock here for reading stored_kasan_records,
> +        * As it is an integer variable, we can read it one value less
> +        * if it is getting updated simultaneously.
> +        */
> +       int total_records = stored_kasan_records;
> +       char *kbuf = (char *)file->private_data;
> +
> +       while (*ppos < total_records) {
> +               struct kasan_record *record;
> +
> +               record  = &kasan_records[*ppos];
> +               *ppos = *ppos + 1;
> +               return print_kasan_error(buf, count, record, ppos, kbuf);
> +       }
> +
> +       return 0;
> +}
> +
> +int read_kasan_open(struct inode *inode, struct file *file)
> +{
> +       char *kasan_kbuf;
> +
> +       /*
> +        * One KASAN error will always be less than 4 KB,
> +        * without page dump info.
> +        *
> +        * Thus allocate buffer of READ_SIZE, rather than
> +        * count to avoid return checks of snprintfs.
> +        */
> +       kasan_kbuf = vzalloc(READ_SIZE);
> +
> +       if (!kasan_kbuf)
> +               return -ENOMEM;
> +
> +       file->private_data = (void *)kasan_kbuf;
> +
> +       return 0;
> +}
> +
> +int read_kasan_release(struct inode *inode, struct file *file)
> +{
> +       char *kasan_kbuf = (char *)file->private_data;
> +
> +       if (kasan_kbuf)
> +               vfree(kasan_kbuf);
> +
> +       return 0;
> +}
> +
> +static const struct proc_ops proc_kasan_ops = {
> +       .proc_open              = read_kasan_open,
> +       .proc_read              = read_kasan_errors,
> +       .proc_release           = read_kasan_release,
> +};
> +
> +static int __init register_kasan_proc(void)
> +{
> +       struct proc_dir_entry *entry;
> +
> +       entry = proc_create("kasan_log", 0400,
> +                       NULL, &proc_kasan_ops);
> +
> +       if (!entry)
> +               pr_err("registration of KASAN proc interface failed\n");
> +
> +       return 0;
> +}
> +fs_initcall(register_kasan_proc);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 139615ef326b..0206d5f9b486 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -39,10 +39,12 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
>         return p;
>  }
>
> -static const char *get_shadow_bug_type(struct kasan_access_info *info)
> +static const char *get_shadow_bug_type(struct kasan_access_info *info,
> +               kasan_bug_type *bug_save)
>  {
>         const char *bug_type = "unknown-crash";
>         u8 *shadow_addr;
> +       kasan_bug_type bug = UNKNOWN;
>
>         shadow_addr = (u8 *)kasan_mem_to_shadow(info->first_bad_addr);
>
> @@ -60,52 +62,70 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
>                  * due to a data race in the kernel code.
>                  */
>                 bug_type = "out-of-bounds";
> +               bug = OUT_OF_BOUNDS;
>                 break;
>         case KASAN_PAGE_REDZONE:
>         case KASAN_KMALLOC_REDZONE:
>                 bug_type = "slab-out-of-bounds";
> +               bug = OUT_OF_BOUNDS_SLAB;
>                 break;
>         case KASAN_GLOBAL_REDZONE:
>                 bug_type = "global-out-of-bounds";
> +               bug = OUT_OF_BOUNDS_GLOBAL;
>                 break;
>         case KASAN_STACK_LEFT:
>         case KASAN_STACK_MID:
>         case KASAN_STACK_RIGHT:
>         case KASAN_STACK_PARTIAL:
>                 bug_type = "stack-out-of-bounds";
> +               bug = OUT_OF_BOUNDS_STACK;
>                 break;
>         case KASAN_FREE_PAGE:
>         case KASAN_KMALLOC_FREE:
>         case KASAN_KMALLOC_FREETRACK:
>                 bug_type = "use-after-free";
> +               bug = USE_AFTER_FREE;
>                 break;
>         case KASAN_ALLOCA_LEFT:
>         case KASAN_ALLOCA_RIGHT:
>                 bug_type = "alloca-out-of-bounds";
> +               bug = OUT_OF_BOUNDS_ALLOCA;
>                 break;
>         case KASAN_VMALLOC_INVALID:
>                 bug_type = "vmalloc-out-of-bounds";
> +               bug = OUT_OF_BOUNDS_VMALLOC;
>                 break;
>         }
>
> +       if (bug_save)
> +               *bug_save = bug;
> +
>         return bug_type;
>  }
>
> -static const char *get_wild_bug_type(struct kasan_access_info *info)
> +static const char *get_wild_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
>  {
>         const char *bug_type = "unknown-crash";
> +       kasan_bug_type bug_enum = UNKNOWN;
>
> -       if ((unsigned long)info->access_addr < PAGE_SIZE)
> +       if ((unsigned long)info->access_addr < PAGE_SIZE) {
>                 bug_type = "null-ptr-deref";
> -       else if ((unsigned long)info->access_addr < TASK_SIZE)
> +               bug_enum = NULL_PTR_DEREFER;
> +       } else if ((unsigned long)info->access_addr < TASK_SIZE) {
>                 bug_type = "user-memory-access";
> -       else
> +               bug_enum = USER_MEMORY_ACCESS;
> +       } else {
>                 bug_type = "wild-memory-access";
> +               bug_enum = WILD_MEMORY_ACCESS;
> +       }
> +
> +       if (bug)
> +               *bug = bug_enum;
>
>         return bug_type;
>  }
>
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
>  {
>         /*
>          * If access_size is a negative number, then it has reason to be
> @@ -115,12 +135,16 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>          * a large size_t and its value will be larger than ULONG_MAX/2,
>          * so that this can qualify as out-of-bounds.
>          */
> -       if (info->access_addr + info->access_size < info->access_addr)
> +       if (info->access_addr + info->access_size < info->access_addr) {
> +               if (bug)
> +                       *bug = OUT_OF_BOUNDS;
> +
>                 return "out-of-bounds";
> +       }
>
>         if (addr_has_metadata(info->access_addr))
> -               return get_shadow_bug_type(info);
> -       return get_wild_bug_type(info);
> +               return get_shadow_bug_type(info, bug);
> +       return get_wild_bug_type(info, bug);
>  }
>
>  void kasan_metadata_fetch_row(char *buffer, void *row)
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index 42b2168755d6..ae516e92f9f3 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -15,8 +15,11 @@
>
>  #include "kasan.h"
>
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
>  {
> +       if (bug)
> +               *bug = INVALID_ACCESS;
> +
>         return "invalid-access";
>  }
>
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 3d20d3451d9e..11c869d4ad3c 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -29,8 +29,10 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -const char *kasan_get_bug_type(struct kasan_access_info *info)
> +const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
>  {
> +       kasan_bug_type bug_enum;
> +       const char *bug_type;
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
> @@ -50,11 +52,16 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>
>                 if (alloc_meta) {
>                         for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> -                               if (alloc_meta->free_pointer_tag[i] == tag)
> -                                       return "use-after-free";
> +                               if (alloc_meta->free_pointer_tag[i] == tag) {
> +                                       bug_type = "use-after-free";
> +                                       bug_enum = USE_AFTER_FREE;
> +                                       goto done;
> +                               }
>                         }
>                 }
> -               return "out-of-bounds";
> +               bug_type = "out-of-bounds";
> +               bug_enum = OUT_OF_BOUNDS;
> +               goto done;
>         }
>
>  #endif
> @@ -66,10 +73,19 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
>          * a large size_t and its value will be larger than ULONG_MAX/2,
>          * so that this can qualify as out-of-bounds.
>          */
> -       if (info->access_addr + info->access_size < info->access_addr)
> -               return "out-of-bounds";
> +       if (info->access_addr + info->access_size < info->access_addr) {
> +               bug_enum = OUT_OF_BOUNDS;
> +               bug_type = "out-of-bounds";
> +               goto done;
> +       }
> +
> +       bug_enum = INVALID_ACCESS;
> +       bug_type = "invalid-access";
> +done:
> +       if (bug)
> +               *bug = bug_enum;
>
> -       return "invalid-access";
> +       return bug_type;
>  }
>
>  void *kasan_find_first_bad_addr(void *addr, size_t size)
> --
> 2.17.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1619079317-1131-2-git-send-email-maninder1.s%40samsung.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZJ95KiFNHeT9k0p6ezDz-apkJVp586UBSdJeHtCYR_Qg%40mail.gmail.com.
