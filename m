Return-Path: <kasan-dev+bncBCMIZB7QWENRBMNBSHWQKGQEG43HHHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E15D606B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:40:50 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id w8sf25712879iol.20
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:40:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049649; cv=pass;
        d=google.com; s=arc-20160816;
        b=CyhxH8eqGTCA99XXAu49mZ5zpOf2Mn4k4AH9zaA2AN+UXa69rz0eRucbvRkCyitJWZ
         R9V/Ek0UCVzkP6NfQDyadTfuNT9ZwoOlmcfu+Iir1m2U375rBSubdMj3AT3blJ09bdPV
         XHxH/bXvu47xf0rfkiWHxaJaDBw+dnx6mZ7H7wNdsprsc8/8sDoLuOppzZxHoqQ9budC
         0+LqI+7B2syV2rzl+feNa6DDTMRSTxu6f64nqrDUbi9FdZhmNosVxHxKEbM5hetI4RfQ
         HUsLE/rRW5e/ooHIujKdMrkkQ75yG7QrOoiIEH2pgZly6Pl14Op6bnzJ1fuPhSnfdFj2
         Kclg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1IhAVzNOspOptykl5jmLVhPIUqntv76U34LF+3fcwaM=;
        b=xXOBMzO6xAVICo9+kR9JxhiOfjlUd+jO2Wk/OLTRjjOeGiGTcX05/roDGRYOMERdXt
         F3nUEqdI2588m2Lykfou/ADicB0XgSMI45onLzhn4bgi+zI76F4fooiRCVxyYDl420J9
         dY3HKvvQtg24oeYQGNXQqhE6HZUiP38s6PZYbNNAS2o5myCHv7qX0ja9Y5vAZSTYDS+7
         uPKVhqgrEPzSzRoBWUrpuJqjBNMBkUcY6y2nGJiHyfJsaUfv3ys5YRZRAMCWyqXm9mzW
         8eadUduwnvIRAz1aR/BjvcTOkGfrjGoXgykSaeenbyU7xi6IK3u0MSpmhnvkIyLNduuJ
         afEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ROvJeYaF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1IhAVzNOspOptykl5jmLVhPIUqntv76U34LF+3fcwaM=;
        b=EkogzgfLdfb7NdF7fPukwPwUqCmVLgieQ0PkqVarIsKM6SQ9I6XrbOjFv//crAdgwi
         B92gXD2j/zKjNGDppbZ4ZLZSWXG13TkLuPbEFv8PkP0wyJ2h98E7z3x9Hw2Jn5vCEBZw
         iRybB9/a/fShnR4q0rv9G2dgwP1MvgrEhK3V4xgdNVlV38x8vANWfJxUMA+WV4MMscER
         lPwhCZTH8IrmIBfknZ9cnW/2swRYUIFVf3pS5lgCK/xe7bRgT51CPUTFId5DENhdoA4m
         xV88hvpMLHnMSZ0H9bUtYOD231hFNTfnWNGiOfKdbh0Qy4Q4N0LX5FkWl0d3ImNN20/x
         SZWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1IhAVzNOspOptykl5jmLVhPIUqntv76U34LF+3fcwaM=;
        b=PIYlcUN+P702+dTU028LI1E8TTyY/n4xCcd5RLPHc6u0tnnntDFlv9RqbK7kZxVx29
         3UDI6VXDvVJTsu+YR6Ci9QgtrCUuasndDHw39YM+t9jlyTpsZoHpzpdy7MUHm9klcZAT
         89QHMz2dIcCvzsaJGyx5iZhSAtv4XXf9BGi83fsEb8V/CikL67hRVTWnIDjUtKYFHN9H
         Ri3LrnQzIcnx+JLFvM/iZ/4d8zjjDJliWtSNXXtj95PaZNQ1VjtuG2XmYPHoI7ahhOBU
         0NQq52t/DE4NU6iyqkmvIh0eF3wJsI7vIeuoeA5ZUY3sqt7zPd/Kg10zjiIOFkGR0y73
         0Vbg==
X-Gm-Message-State: APjAAAX2iq2uLv5vy2lnHRV5oCy7YgQo62Ev2d1XZvp5wHKlAE+sW5Ug
	3OXGRhEaG38u079uBbzGgis=
X-Google-Smtp-Source: APXvYqxFyozV+gf2Ic18YQoGSnDJ/Sa4rTQ6tI0p0w9/xpAV0C/QP6RzCbLxX/53cfwaAPRd6iFA5Q==
X-Received: by 2002:a02:6d08:: with SMTP id m8mr37339993jac.34.1571049649222;
        Mon, 14 Oct 2019 03:40:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b787:: with SMTP id h129ls4751129iof.12.gmail; Mon, 14
 Oct 2019 03:40:48 -0700 (PDT)
X-Received: by 2002:a5d:83c1:: with SMTP id u1mr14715408ior.78.1571049648918;
        Mon, 14 Oct 2019 03:40:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049648; cv=none;
        d=google.com; s=arc-20160816;
        b=FWqjljayAFDAcGR3G6L7tMO75s2hB6lwBJFNz5EwMAD2s9NywqNYsfkJE8rrHrUu85
         RMl/1pZLDUdxux/y9kEgINGXmB82ENeeDGAmOA3WFm+4i9gWhG+Cbq7wSl//0XNTcvus
         Dpq/fRmlfq0jKDKtQwcIAKWqDmvPilkPcQpErKOxBond9oNe2yUl6A8k/tcpmnyXHjF8
         Spd+1wPTJeswOk2SahamuMMvFDMOiynwEIGhN4WivdvWbUN0OjM5uZBHow16um4ILc4u
         j/u9yQu0je2nlmHA1D9Va1fClO2JtoHgNFrT+G64Pf/D1JNGK916UFoMlUmYEDjgidZ7
         RTLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3YrhF1CY8Iis1JpXe2D3S6ZujIQpFi34GXY+qWGn3K4=;
        b=lCZAGm8JHZHcKc/EPR5eW+eaoRvuAQRo3FgJPfPrNCF3nX3zp2SAd4MIV48FfRhok3
         0JQOmLEq+7LiTuWzjEkekXyVu1YLT7/JFS0JjeIbYLBLOUd+qc54TI0dSY9go62j1FBb
         +YdZV/dETFG1Tef3T34Qv724f8OoViA/5bazX9ks/zKrrl5Pfa+6kmsBX8SBzVHF44Dg
         MrkwW5h2VQ8hZ9H1sZAMhT2KqgXktjTHpDwrbvYSDpF/2T+HXsnfG4a5CniNLTlFLjQO
         fsrqQ9D3HTEf219kVPYvKG0sJC+f/P3nsXMLMwJNxLG0tnVXmOV+LWKURzh1IMiXzgO/
         bFqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ROvJeYaF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id q207si1004363iod.5.2019.10.14.03.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 03:40:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 3so24803543qta.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 03:40:48 -0700 (PDT)
X-Received: by 2002:a0c:fec3:: with SMTP id z3mr30851968qvs.122.1571049647781;
 Mon, 14 Oct 2019 03:40:47 -0700 (PDT)
MIME-Version: 1.0
References: <20191014103632.17930-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20191014103632.17930-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 12:40:36 +0200
Message-ID: <CACT4Y+bQNDMZE72rcrpfA+eBizx8OGx-Ae78Ci5KU6AN-PBDqw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: detect negative size in memory operation function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ROvJeYaF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Mon, Oct 14, 2019 at 12:36 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> KASAN missed detecting size is negative numbers in memset(), memcpy(),
> and memmove(), it will cause out-of-bounds bug, so needs to be detected
> by KASAN.
>
> If size is negative numbers, then it has three reasons to be
> defined as heap-out-of-bounds bug type.
> 1) Casting negative numbers to size_t would indeed turn up as
>    a large size_t and its value will be larger than ULONG_MAX/2,
>    so that this can qualify as out-of-bounds.
> 2) If KASAN has new bug type and user-space passes negative size,
>    then there are duplicate reports. So don't produce new bug type
>    in order to prevent duplicate reports by some systems (e.g. syzbot)
>    to report the same bug twice.
> 3) When size is negative numbers, it may be passed from user-space.
>    So we always print heap-out-of-bounds in order to prevent that
>    kernel-space and user-space have the same bug but have duplicate
>    reports.
>
> KASAN report:
>
>  BUG: KASAN: heap-out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
>  Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72
>
>  CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
>  Hardware name: linux,dummy-virt (DT)
>  Call trace:
>   dump_backtrace+0x0/0x288
>   show_stack+0x14/0x20
>   dump_stack+0x10c/0x164
>   print_address_description.isra.9+0x68/0x378
>   __kasan_report+0x164/0x1a0
>   kasan_report+0xc/0x18
>   check_memory_region+0x174/0x1d0
>   memmove+0x34/0x88
>   kmalloc_memmove_invalid_size+0x70/0xa0
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reported -by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c         | 13 ++++++++-----
>  mm/kasan/generic.c        |  5 +++++
>  mm/kasan/generic_report.c | 18 ++++++++++++++++++
>  mm/kasan/tags.c           |  5 +++++
>  mm/kasan/tags_report.c    | 18 ++++++++++++++++++
>  5 files changed, 54 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..6ef0abd27f06 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memset(addr, c, len);
>  }
> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memmove(dest, src, len);
>  }
> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memcpy(dest, src, len);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..02148a317d27 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         if (unlikely((void *)addr <
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>                 kasan_report(addr, size, write, ret_ip);
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..52a92c7db697 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * If access_size is negative numbers, then it has three reasons
> +        * to be defined as heap-out-of-bounds bug type.
> +        * 1) Casting negative numbers to size_t would indeed turn up as
> +        *    a large size_t and its value will be larger than ULONG_MAX/2,
> +        *    so that this can qualify as out-of-bounds.
> +        * 2) If KASAN has new bug type and user-space passes negative size,
> +        *    then there are duplicate reports. So don't produce new bug type
> +        *    in order to prevent duplicate reports by some systems
> +        *    (e.g. syzbot) to report the same bug twice.
> +        * 3) When size is negative numbers, it may be passed from user-space.
> +        *    So we always print heap-out-of-bounds in order to prevent that
> +        *    kernel-space and user-space have the same bug but have duplicate
> +        *    reports.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "heap-out-of-bounds";
> +
>         if (addr_has_shadow(info->access_addr))
>                 return get_shadow_bug_type(info);
>         return get_wild_bug_type(info);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0e987c9ca052..b829535a3ad7 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         tag = get_tag((const void *)addr);
>
>         /*
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 969ae08f59d7..f7ae474aef3a 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,24 @@
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * If access_size is negative numbers, then it has three reasons
> +        * to be defined as heap-out-of-bounds bug type.
> +        * 1) Casting negative numbers to size_t would indeed turn up as
> +        *    a large size_t and its value will be larger than ULONG_MAX/2,
> +        *    so that this can qualify as out-of-bounds.
> +        * 2) If KASAN has new bug type and user-space passes negative size,
> +        *    then there are duplicate reports. So don't produce new bug type
> +        *    in order to prevent duplicate reports by some systems
> +        *    (e.g. syzbot) to report the same bug twice.
> +        * 3) When size is negative numbers, it may be passed from user-space.
> +        *    So we always print heap-out-of-bounds in order to prevent that
> +        *    kernel-space and user-space have the same bug but have duplicate
> +        *    reports.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "heap-out-of-bounds";
> +
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103632.17930-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbQNDMZE72rcrpfA%2BeBizx8OGx-Ae78Ci5KU6AN-PBDqw%40mail.gmail.com.
