Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZPIV76QKGQE4WDUUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 309D92AF378
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:25:43 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id u4sf1405973pgg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605104742; cv=pass;
        d=google.com; s=arc-20160816;
        b=n5ahDTRGBZOFfpDpKhjvWFd0iNluIgrtFKlQ30ILmrYMdaMz7CphDUsQk71fMOlPjQ
         Ax1JUjvM3fuGpGpTgkqycyBQ2uIiSFI0ovJY5xfT/hmGXyYg7JIgoCzxPWpWEauafOb6
         jG5xyntWrL8Z/mEpGiZXPiqPpa5/+tGm3BfUia40HuCToDcJuj/02y7XwaJKMcpKkNoj
         BWz9Fa1dqO2/QnMdkggalKtObgS3yw+1zt+2597wVBml+orqMZiAjcduYIQTEi/0L/kT
         0Zf9b0UoNaX1xNUKSnfMtKrSu9vgmClihXbNEFR/Vd2E+c0GBU68NsLvGOZQcbkQc+jm
         cbuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q0wdHg60zf+oJPC9M4JkxR2gKdDE2ppNDaErWgzCcGM=;
        b=trMcTyCtjrKoOidfa81cLqysZj7KaKOckAv2vGGKAq2xlrj09z0WPLAm5DCw6uLk4w
         CF7tM+WiwCyY78E+z0rG+hNOqC91gcDQXBoIMVTDk6koHpcQxUU1W6uwEi/bp8GEVCUA
         squQ5H9Sx5+8BZdcNC4vKmObQUOf+TN83qHbTp09uvU+dTue7RMILOdIu5yRKn1KN3Y4
         kaHi/izc/MSAGqgzkJB3YdYTIjKsPqaBm6e7X+eg4xgfVp16vWNZD1QBAvES5/hI8yWG
         1xFLDhElAqTfSffNchfb9rj1Hd8AkoyATvA9orB2uO/ffVXynwd0d4PnMnVaO72m7LMY
         O+vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MhI88VRy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=q0wdHg60zf+oJPC9M4JkxR2gKdDE2ppNDaErWgzCcGM=;
        b=kkUDE+7vNinx9cnUZRcf0HKHLgwFRRcZCFII2aMo7PEBD6WXN9GG9jg/8k84OqFxPL
         Gn0w+EpzRKL0X8xVHFWJpjCIeDyL38+cGfuWizGjEJf6yUe3Mg+dmaRboLt7ezc7S0tZ
         zWCMNZurrya3F7h/WO0fw7CNe3+w15zTHvsetUV9PQ1KN18ec8m5MaGURM/DaLmqzCjr
         WNRq5pEORlpxN2GOba0RqqGnL1PynC79oOr6sG1j21SlbQC7Af74vTSdmMxmyvkvWIvn
         W2Wzs+jBg6eLtd+mKBpWZ9tJrhvS9cePuATHeLbJNIsD4vsTW163Q8B6MAep0r37JShN
         tLlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q0wdHg60zf+oJPC9M4JkxR2gKdDE2ppNDaErWgzCcGM=;
        b=ZNsy/2g2gFSYxr58OxviJ9FRgtnLS00srbayUqzL5PMFNqP1/fapP/jfqv9s31RX75
         H0ECjIe6X3aSTP/QStzDLHSuc8sMEwR51MQlX7VjO67zo5sS2rAmj9h7WZQOZHXHf2hJ
         eZImBzDXyqRCi34EHa+6aN2w5F+wYFa5mVv+2eA/Wuj6sPf49OvvNiQ4HuWXyDLh++kY
         8WTSKyvythGUvzJRoOolPmx0k8+m4l3t9Jy//o7oYL3ATKkLQ/h8XNewNx9d6KTV7OVE
         +F4FpO3qUcgj+u0iigJTMq++TGMNsjfQ+QlEU9vtoCc6HbUgE6AlQm2P37XIEuelrz9M
         gZmg==
X-Gm-Message-State: AOAM5316z6AKTjKYTdcTxdmu+4GCG50qv1WEa344YiDE92H44/N+3KFG
	J3KPDH+GZ9hCU37EkPT3hnQ=
X-Google-Smtp-Source: ABdhPJwdmXa0OxvlojE5er31qHzWStKT0Z0r52fp19KrcvwmGaXuWycxKXxKFKUpwPOPvbXy+ucBuw==
X-Received: by 2002:a17:90a:ce8c:: with SMTP id g12mr4149961pju.181.1605104741842;
        Wed, 11 Nov 2020 06:25:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8055:: with SMTP id j82ls6055037pfd.5.gmail; Wed, 11 Nov
 2020 06:25:41 -0800 (PST)
X-Received: by 2002:aa7:8055:0:b029:15f:cbe9:1aad with SMTP id y21-20020aa780550000b029015fcbe91aadmr23227767pfm.71.1605104741193;
        Wed, 11 Nov 2020 06:25:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605104741; cv=none;
        d=google.com; s=arc-20160816;
        b=Xom2fYsIjQVfNihf7L8GCZQOLmb184C1gEMtWuzGMuvrVYek1f6n48q0sQ9wEglqgi
         A22+XQRwNTsoLzkQGwyQbwwVvdUMhiYP5QZRYRdQJHuKNNPu/mWd8qEJjph/aU7o5/W0
         D/nnnkdVdfggYnb98gJCjG/zmlSxtAMTi0ITXE2Mj2P7W4bpPDxbW7NvAazrExqQJOlv
         djeQfPbfzvm0ZQl8XDR6YzZUi9eycBywmApA1DhCGIH367ziiJeqWF0LT9zK0fGEQ+lU
         dEiDts60S5PRmDhd61bV3Ng6qIYACDCzH8G18ZWqSVaMiKvi77ExZboYvTyxLKfpLogu
         Mmkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ivzJGCKhLp1x2v+oY17etQZN4NoUxQRVrZrrn1pxmzQ=;
        b=U30RiX+cW1Zj6lIA4inJHTxD0ZFHlo6pGo8b4FIfgy51JV1o5QG8LgBol0nnUCebvq
         ghrZ5UgqqjiKnL4o9ySEwa/cl+OVkWBGsq3JKecvrwovYAfcQPc3awxV3rGxD60N6u8y
         ykgQwZyk/ezC+QFWDDPc1+IH8JeDDRsKrieE2Vu6aW8S3MMXFQEtfQJMmJoxYX8dM+z1
         +eabg2K0tO6K8W4Iv33zRuAKgRZiVscwMhnsC5ZcST0XBOMbVD/FgecdSztTPt+j+4Bf
         wskTVrTvcnhOYPtJ2b4icsefzMNlClCByn4HtMdRZfTxzAPJ+QnWvRhchSSKOEXredKx
         D1+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MhI88VRy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id z12si134263pjf.3.2020.11.11.06.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:25:41 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id 63so939100qva.7
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:25:41 -0800 (PST)
X-Received: by 2002:a0c:9e53:: with SMTP id z19mr24687355qve.23.1605104740021;
 Wed, 11 Nov 2020 06:25:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <f19f5aac37051fa10b2a8eb3539c19e113b92a06.1605046192.git.andreyknvl@google.com>
In-Reply-To: <f19f5aac37051fa10b2a8eb3539c19e113b92a06.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:25:28 +0100
Message-ID: <CAG_fn=XTGREjohda7iNoJMFO+cmh250iANoWMBsBn8uVJSK9Lw@mail.gmail.com>
Subject: Re: [PATCH v9 14/44] kasan: decode stack frame only with KASAN_STACK_ENABLE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MhI88VRy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Decoding routines aren't needed when CONFIG_KASAN_STACK_ENABLE is not
> enabled. Currently only generic KASAN mode implements stack error
> reporting.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I084e3214f2b40dc0bef7c5a9fafdc6f5c42b06a2
> ---
>  mm/kasan/kasan.h          |   6 ++
>  mm/kasan/report.c         | 162 --------------------------------------
>  mm/kasan/report_generic.c | 162 ++++++++++++++++++++++++++++++++++++++
>  3 files changed, 168 insertions(+), 162 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3eff57e71ff5..d0cf61d4d70d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -169,6 +169,12 @@ bool check_invalid_free(void *addr);
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>
> +#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> +void print_address_stack_frame(const void *addr);
> +#else
> +static inline void print_address_stack_frame(const void *addr) { }
> +#endif
> +
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index fff0c7befbfe..b18d193f7f58 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -211,168 +211,6 @@ static inline bool init_task_stack_addr(const void =
*addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> -static bool __must_check tokenize_frame_descr(const char **frame_descr,
> -                                             char *token, size_t max_tok=
_len,
> -                                             unsigned long *value)
> -{
> -       const char *sep =3D strchr(*frame_descr, ' ');
> -
> -       if (sep =3D=3D NULL)
> -               sep =3D *frame_descr + strlen(*frame_descr);
> -
> -       if (token !=3D NULL) {
> -               const size_t tok_len =3D sep - *frame_descr;
> -
> -               if (tok_len + 1 > max_tok_len) {
> -                       pr_err("KASAN internal error: frame description t=
oo long: %s\n",
> -                              *frame_descr);
> -                       return false;
> -               }
> -
> -               /* Copy token (+ 1 byte for '\0'). */
> -               strlcpy(token, *frame_descr, tok_len + 1);
> -       }
> -
> -       /* Advance frame_descr past separator. */
> -       *frame_descr =3D sep + 1;
> -
> -       if (value !=3D NULL && kstrtoul(token, 10, value)) {
> -               pr_err("KASAN internal error: not a valid number: %s\n", =
token);
> -               return false;
> -       }
> -
> -       return true;
> -}
> -
> -static void print_decoded_frame_descr(const char *frame_descr)
> -{
> -       /*
> -        * We need to parse the following string:
> -        *    "n alloc_1 alloc_2 ... alloc_n"
> -        * where alloc_i looks like
> -        *    "offset size len name"
> -        * or "offset size len name:line".
> -        */
> -
> -       char token[64];
> -       unsigned long num_objects;
> -
> -       if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> -                                 &num_objects))
> -               return;
> -
> -       pr_err("\n");
> -       pr_err("this frame has %lu %s:\n", num_objects,
> -              num_objects =3D=3D 1 ? "object" : "objects");
> -
> -       while (num_objects--) {
> -               unsigned long offset;
> -               unsigned long size;
> -
> -               /* access offset */
> -               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> -                                         &offset))
> -                       return;
> -               /* access size */
> -               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> -                                         &size))
> -                       return;
> -               /* name length (unused) */
> -               if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> -                       return;
> -               /* object name */
> -               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> -                                         NULL))
> -                       return;
> -
> -               /* Strip line number; without filename it's not very help=
ful. */
> -               strreplace(token, ':', '\0');
> -
> -               /* Finally, print object information. */
> -               pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
> -       }
> -}
> -
> -static bool __must_check get_address_stack_frame_info(const void *addr,
> -                                                     unsigned long *offs=
et,
> -                                                     const char **frame_=
descr,
> -                                                     const void **frame_=
pc)
> -{
> -       unsigned long aligned_addr;
> -       unsigned long mem_ptr;
> -       const u8 *shadow_bottom;
> -       const u8 *shadow_ptr;
> -       const unsigned long *frame;
> -
> -       BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> -
> -       /*
> -        * NOTE: We currently only support printing frame information for
> -        * accesses to the task's own stack.
> -        */
> -       if (!object_is_on_stack(addr))
> -               return false;
> -
> -       aligned_addr =3D round_down((unsigned long)addr, sizeof(long));
> -       mem_ptr =3D round_down(aligned_addr, KASAN_GRANULE_SIZE);
> -       shadow_ptr =3D kasan_mem_to_shadow((void *)aligned_addr);
> -       shadow_bottom =3D kasan_mem_to_shadow(end_of_stack(current));
> -
> -       while (shadow_ptr >=3D shadow_bottom && *shadow_ptr !=3D KASAN_ST=
ACK_LEFT) {
> -               shadow_ptr--;
> -               mem_ptr -=3D KASAN_GRANULE_SIZE;
> -       }
> -
> -       while (shadow_ptr >=3D shadow_bottom && *shadow_ptr =3D=3D KASAN_=
STACK_LEFT) {
> -               shadow_ptr--;
> -               mem_ptr -=3D KASAN_GRANULE_SIZE;
> -       }
> -
> -       if (shadow_ptr < shadow_bottom)
> -               return false;
> -
> -       frame =3D (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
> -       if (frame[0] !=3D KASAN_CURRENT_STACK_FRAME_MAGIC) {
> -               pr_err("KASAN internal error: frame info validation faile=
d; invalid marker: %lu\n",
> -                      frame[0]);
> -               return false;
> -       }
> -
> -       *offset =3D (unsigned long)addr - (unsigned long)frame;
> -       *frame_descr =3D (const char *)frame[1];
> -       *frame_pc =3D (void *)frame[2];
> -
> -       return true;
> -}
> -
> -static void print_address_stack_frame(const void *addr)
> -{
> -       unsigned long offset;
> -       const char *frame_descr;
> -       const void *frame_pc;
> -
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -               return;
> -
> -       if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
> -                                         &frame_pc))
> -               return;
> -
> -       /*
> -        * get_address_stack_frame_info only returns true if the given ad=
dr is
> -        * on the current task's stack.
> -        */
> -       pr_err("\n");
> -       pr_err("addr %px is located in stack of task %s/%d at offset %lu =
in frame:\n",
> -              addr, current->comm, task_pid_nr(current), offset);
> -       pr_err(" %pS\n", frame_pc);
> -
> -       if (!frame_descr)
> -               return;
> -
> -       print_decoded_frame_descr(frame_descr);
> -}
> -
>  static void print_address_description(void *addr, u8 tag)
>  {
>         struct page *page =3D kasan_addr_to_page(addr);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 7d5b9e5c7cfe..b543a1ed6078 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -16,6 +16,7 @@
>  #include <linux/mm.h>
>  #include <linux/printk.h>
>  #include <linux/sched.h>
> +#include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
>  #include <linux/stackdepot.h>
>  #include <linux/stacktrace.h>
> @@ -122,6 +123,167 @@ const char *get_bug_type(struct kasan_access_info *=
info)
>         return get_wild_bug_type(info);
>  }
>
> +#if CONFIG_KASAN_STACK
> +static bool __must_check tokenize_frame_descr(const char **frame_descr,
> +                                             char *token, size_t max_tok=
_len,
> +                                             unsigned long *value)
> +{
> +       const char *sep =3D strchr(*frame_descr, ' ');
> +
> +       if (sep =3D=3D NULL)
> +               sep =3D *frame_descr + strlen(*frame_descr);
> +
> +       if (token !=3D NULL) {
> +               const size_t tok_len =3D sep - *frame_descr;
> +
> +               if (tok_len + 1 > max_tok_len) {
> +                       pr_err("KASAN internal error: frame description t=
oo long: %s\n",
> +                              *frame_descr);
> +                       return false;
> +               }
> +
> +               /* Copy token (+ 1 byte for '\0'). */
> +               strlcpy(token, *frame_descr, tok_len + 1);
> +       }
> +
> +       /* Advance frame_descr past separator. */
> +       *frame_descr =3D sep + 1;
> +
> +       if (value !=3D NULL && kstrtoul(token, 10, value)) {
> +               pr_err("KASAN internal error: not a valid number: %s\n", =
token);
> +               return false;
> +       }
> +
> +       return true;
> +}
> +
> +static void print_decoded_frame_descr(const char *frame_descr)
> +{
> +       /*
> +        * We need to parse the following string:
> +        *    "n alloc_1 alloc_2 ... alloc_n"
> +        * where alloc_i looks like
> +        *    "offset size len name"
> +        * or "offset size len name:line".
> +        */
> +
> +       char token[64];
> +       unsigned long num_objects;
> +
> +       if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +                                 &num_objects))
> +               return;
> +
> +       pr_err("\n");
> +       pr_err("this frame has %lu %s:\n", num_objects,
> +              num_objects =3D=3D 1 ? "object" : "objects");
> +
> +       while (num_objects--) {
> +               unsigned long offset;
> +               unsigned long size;
> +
> +               /* access offset */
> +               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> +                                         &offset))
> +                       return;
> +               /* access size */
> +               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> +                                         &size))
> +                       return;
> +               /* name length (unused) */
> +               if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> +                       return;
> +               /* object name */
> +               if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> +                                         NULL))
> +                       return;
> +
> +               /* Strip line number; without filename it's not very help=
ful. */
> +               strreplace(token, ':', '\0');
> +
> +               /* Finally, print object information. */
> +               pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
> +       }
> +}
> +
> +static bool __must_check get_address_stack_frame_info(const void *addr,
> +                                                     unsigned long *offs=
et,
> +                                                     const char **frame_=
descr,
> +                                                     const void **frame_=
pc)
> +{
> +       unsigned long aligned_addr;
> +       unsigned long mem_ptr;
> +       const u8 *shadow_bottom;
> +       const u8 *shadow_ptr;
> +       const unsigned long *frame;
> +
> +       BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> +
> +       /*
> +        * NOTE: We currently only support printing frame information for
> +        * accesses to the task's own stack.
> +        */
> +       if (!object_is_on_stack(addr))
> +               return false;
> +
> +       aligned_addr =3D round_down((unsigned long)addr, sizeof(long));
> +       mem_ptr =3D round_down(aligned_addr, KASAN_GRANULE_SIZE);
> +       shadow_ptr =3D kasan_mem_to_shadow((void *)aligned_addr);
> +       shadow_bottom =3D kasan_mem_to_shadow(end_of_stack(current));
> +
> +       while (shadow_ptr >=3D shadow_bottom && *shadow_ptr !=3D KASAN_ST=
ACK_LEFT) {
> +               shadow_ptr--;
> +               mem_ptr -=3D KASAN_GRANULE_SIZE;
> +       }
> +
> +       while (shadow_ptr >=3D shadow_bottom && *shadow_ptr =3D=3D KASAN_=
STACK_LEFT) {
> +               shadow_ptr--;
> +               mem_ptr -=3D KASAN_GRANULE_SIZE;
> +       }
> +
> +       if (shadow_ptr < shadow_bottom)
> +               return false;
> +
> +       frame =3D (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
> +       if (frame[0] !=3D KASAN_CURRENT_STACK_FRAME_MAGIC) {
> +               pr_err("KASAN internal error: frame info validation faile=
d; invalid marker: %lu\n",
> +                      frame[0]);
> +               return false;
> +       }
> +
> +       *offset =3D (unsigned long)addr - (unsigned long)frame;
> +       *frame_descr =3D (const char *)frame[1];
> +       *frame_pc =3D (void *)frame[2];
> +
> +       return true;
> +}
> +
> +void print_address_stack_frame(const void *addr)
> +{
> +       unsigned long offset;
> +       const char *frame_descr;
> +       const void *frame_pc;
> +
> +       if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
> +                                         &frame_pc))
> +               return;
> +
> +       /*
> +        * get_address_stack_frame_info only returns true if the given ad=
dr is
> +        * on the current task's stack.
> +        */
> +       pr_err("\n");
> +       pr_err("addr %px is located in stack of task %s/%d at offset %lu =
in frame:\n",
> +              addr, current->comm, task_pid_nr(current), offset);
> +       pr_err(" %pS\n", frame_pc);
> +
> +       if (!frame_descr)
> +               return;
> +
> +       print_decoded_frame_descr(frame_descr);
> +}
> +#endif /* CONFIG_KASAN_STACK */
> +
>  #define DEFINE_ASAN_REPORT_LOAD(size)                     \
>  void __asan_report_load##size##_noabort(unsigned long addr) \
>  {                                                         \
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXTGREjohda7iNoJMFO%2Bcmh250iANoWMBsBn8uVJSK9Lw%40mail.gm=
ail.com.
