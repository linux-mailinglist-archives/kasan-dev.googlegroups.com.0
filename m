Return-Path: <kasan-dev+bncBDW2JDUY5AORBY5WW6LAMGQENDADJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 35F35572761
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 22:36:53 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id a17-20020a056e0208b100b002dc52b51d98sf5351787ilt.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 13:36:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657658211; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPIPBVS0ir4ExA60zkEmHliMSkSsBDZvbG5dVifA7e9jhRSmGr60Xg5tQ+FdPrfxMc
         M/9pnj0UflnLBiwsu+iyHJZXJsN7F+eU+ZIYSME1jOj7/vMavnWX0scvPUSfVXE8O/vI
         VDs0Ob2HqK5yiNz4VtbGRz2zqx4h2e6ONqh0heFMQFcfLbGPlMKGYfOpUydkgNjwR9Rb
         GMs73z5oq0/FDdmLS2SoOTZU7DrWahp8OTt5I0yyy/43QamD4Frt4vfM3AS1+q1ARwsY
         OlbewPDPU/VqIHUJuSmVObHncPvVgMoPXJyACqEdFbAxJVvDYMfl4pBY2uJje/ytUWTy
         OnIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=qGjI6L6AB6jeJK6833mvnb7b2Tea1aBakDN9fRXDTZg=;
        b=HxPLcjA8QET6CtItwnHTPTXYzJEegtaUijl0nZrQTv8DpCXmoC1IlGDFr8jDyi4Qmn
         0lF4fhqY5Xd2ESZxZr6KinkagZi+RmkVsuHn0vj4csBlraL7WOr9k5yTINDarKwiqJfg
         XjOL3cQSiNQemBAG8BvH5QkblcsYNVATPiX+1gHrEzLmuWgeQwgbg/mzOkSJoWAtV02v
         zksEdjui7lOnw9sKnkW8Jwcp+aVgyuv1G7A43j6Nspfq2qlsBIeogZ3ufwbiuqHZolIN
         YkvKtpxF+ryU7+fmR69UqmuGjCSG4IJdlQ5T5efF1Th8WArCSJUfXoAndGV56205kAaJ
         xRkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HK+0DWTz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qGjI6L6AB6jeJK6833mvnb7b2Tea1aBakDN9fRXDTZg=;
        b=GG2WkA4B6m+r494YdpSR3nK5RWflEtPkXiBOdihVOgGjWYSkSPyKv+vF80oMJQ9gMX
         xvipm5IpNokHa7VPaNgwUoDz/Fru12MqW5tqdY4mgRrB9XWiYoj+iXeAJ5tj+5WlmnIa
         UVue2nDzTwE62HkWxDxaiRUquEDZjDDkMMebguJkqVZp7Gy3d8Aj7Z4mNjaE0HAJfjYx
         Rj0ffClVhz3ncCH+YZjOBmWdziajw7V5W5D7e69QqFGkPrjktYZxBtwpv1srlO3aLoPb
         4QXOfA8s60NViZZn8WpjJE/+wBMMEdRPftOIHKt6X8ktJR2C8Mh7XidXgB/OPy5GjEbJ
         uM7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qGjI6L6AB6jeJK6833mvnb7b2Tea1aBakDN9fRXDTZg=;
        b=iG6i3mHB+OkIdg9DVBthSTm3H1i3VYqXLyKRIvoOi/clFTAvETXgDFp2gy2nYeQFZc
         2w/XKkXBhbvanUWTrmMbnqrCRYZ9dhrPTl0zDRaJefpHoqQSOS4DfePT+vqt2pV8pohy
         +HZixq6Mdj2ZrYkFIUkvaxkFCyBd2dzNxNK7LysTbmVxL/8rJdYpYnCHYGrIe0jTOe1c
         irjr4vu8lrLCJMS9QFYgLFxqt5G02a8XtJPSDNfOwJ41U9aDBl8p2FUSDVQ58xk0hmyW
         QypY4Cdo+Qm/yTBSa3eo41tmIhjbGZ+utciWElv8E1otXwxCpuRvzVKnvFInnWjvxsL7
         aMmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qGjI6L6AB6jeJK6833mvnb7b2Tea1aBakDN9fRXDTZg=;
        b=2BaLSKWYg0b/Ev85ROODtb/FvEm1cGeyYJsQfsVCttokvZgSY25Ex8JCBWAuELN47g
         JZtGhp+0i6Vj7hMvmTKYmiIlbBO9jywRATh6kmyZk8ATu9NLHEGiAbQEJiuveLJEV9Oo
         VEiDXb56I+FaEH2uOts6RCxeeQm5234/iV9+7pANfMun/d+ewOeXET2qj2PwWcEgV3vC
         NSNpgA6FGh+6+8QIeguY0+A+YeBunT8dhusoAT5IqsDC66t/TOYWTZKzmPuU+DrFOfzI
         XKtYwTYKzM06AOvVwHzqcQNF5VSI71zWYi5kgcYHITcgNFota0OrXn6vii+1jYi1gvaA
         d9QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8rFFrnpRuNLgXviGN7YHTXFy4PDRIm8pXvWgZe7L8rqrRcoYey
	qEeNAaZbSDXh/t7IiwuxV3o=
X-Google-Smtp-Source: AGRyM1ugYUjePMjG1Qu5sdVdAOB/KWqv+NFq/P7XUrDW7ci/dWkE7h8fTdOUigXhPX5UxhLmgOUUWw==
X-Received: by 2002:a05:6638:4185:b0:33d:c7da:b119 with SMTP id az5-20020a056638418500b0033dc7dab119mr14459882jab.101.1657658211678;
        Tue, 12 Jul 2022 13:36:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1a4b:0:b0:2dc:60eb:c369 with SMTP id z11-20020a921a4b000000b002dc60ebc369ls545297ill.8.gmail;
 Tue, 12 Jul 2022 13:36:51 -0700 (PDT)
X-Received: by 2002:a92:d786:0:b0:2d5:3707:e446 with SMTP id d6-20020a92d786000000b002d53707e446mr12885247iln.244.1657658211264;
        Tue, 12 Jul 2022 13:36:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657658211; cv=none;
        d=google.com; s=arc-20160816;
        b=nHnOb1tEmmZuvjUIrhJgFySA/4Yyiq7Hk/KaCaKaphMRx5KEkE57PyYlyhmxBNdmof
         NHmPui2m+gvVpuQ2XDDhxmZ2wvRlyeHOpHAxDjgfH99XQUT4SBr+PB0ba20cPrzUlZpp
         U5SKjBRANxuk7DXk0kBfPi1W0j57jtB3N2TOhWo5xWlPmgu7WAdNGve/NegdoPgnoSNG
         xHFecg7redATLBIpRhoy31TcvoompQnK6Px9efdjORV04Atwcb86OBElXzmiCiKbl/yF
         au+np4CQD9+hw2RXjE1GzmOcuQfIQSdxZGvbCF+EY2Aub4+MffsRLpjdWAF51dkU+iQF
         62Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y/kf7WpiJhpV7S8Lv6B6nSloUE3ZIK760tIURsCB2pw=;
        b=ZJdJVlgfYYNVibDyLaisw0yp4DMdZ1UIuiS+0ulGy/h14JrLTPFcfczPN/VjDBaeVW
         rSB+6NV66hvTcd+r2AjJvBMp80lzr1GtWm1Hs3kzNkWXekP0bVky2UxMUUsTAYg8yb+5
         8NtigPFTy0K3o92fGNuaKlxzteeRDv4E1lee3TVIov4Dq8n70B2EzgNXKHyOujwDh9jc
         f1sk+1kJrtsq9hIoFK71Pw2hLhGt84Y4O4siEgecje6UW5+AgRJn5qS3joxP66lM0OA4
         RValhcHAhcmJuMQdZVevUExhabmclFnFxdpijyG5KoyQgeVa5wuQ7aeQ1pT6M5wT3zUR
         bujQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=HK+0DWTz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id w10-20020a056638024a00b00330f6d2b3basi295012jaq.3.2022.07.12.13.36.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 13:36:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id v185so9012083ioe.11
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 13:36:51 -0700 (PDT)
X-Received: by 2002:a05:6638:3812:b0:33f:4a06:ad48 with SMTP id
 i18-20020a056638381200b0033f4a06ad48mr9488946jav.71.1657658210925; Tue, 12
 Jul 2022 13:36:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Jul 2022 22:36:40 +0200
Message-ID: <CA+fCnZc_sqfp4NOZPMWig9t01-yz2HOswoesTVfzGubrvqECDw@mail.gmail.com>
Subject: Re: [PATCH] kasan: separate double free case from invalid free
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Chinwen Chang <chinwen.chang@mediatek.com>, =?UTF-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <yee.lee@mediatek.com>, 
	casper.li@mediatek.com, Andrew Yang <andrew.yang@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=HK+0DWTz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jun 15, 2022 at 8:22 AM 'Kuan-Ying Lee' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Currently, KASAN describes all invalid-free/double-free bugs as
> "double-free or invalid-free". This is ambiguous.
>
> KASAN should report "double-free" when a double-free is a more
> likely cause (the address points to the start of an object) and
> report "invalid-free" otherwise [1].
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=212193
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
>  mm/kasan/common.c |  8 ++++----
>  mm/kasan/kasan.h  |  3 ++-
>  mm/kasan/report.c | 12 ++++++++----
>  3 files changed, 14 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..707c3a527fcb 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -343,7 +343,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>
>         if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
>             object)) {
> -               kasan_report_invalid_free(tagged_object, ip);
> +               kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
>                 return true;
>         }
>
> @@ -352,7 +352,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>                 return false;
>
>         if (!kasan_byte_accessible(tagged_object)) {
> -               kasan_report_invalid_free(tagged_object, ip);
> +               kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
>                 return true;
>         }
>
> @@ -377,12 +377,12 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>         if (ptr != page_address(virt_to_head_page(ptr))) {
> -               kasan_report_invalid_free(ptr, ip);
> +               kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
>                 return true;
>         }
>
>         if (!kasan_byte_accessible(ptr)) {
> -               kasan_report_invalid_free(ptr, ip);
> +               kasan_report_invalid_free(ptr, ip, KASAN_REPORT_DOUBLE_FREE);
>                 return true;
>         }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 610d60d6e5b8..01c03e45acd4 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -125,6 +125,7 @@ static inline bool kasan_sync_fault_possible(void)
>  enum kasan_report_type {
>         KASAN_REPORT_ACCESS,
>         KASAN_REPORT_INVALID_FREE,
> +       KASAN_REPORT_DOUBLE_FREE,
>  };
>
>  struct kasan_report_info {
> @@ -277,7 +278,7 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
>
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
> -void kasan_report_invalid_free(void *object, unsigned long ip);
> +void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
>
>  struct page *kasan_addr_to_page(const void *addr);
>  struct slab *kasan_addr_to_slab(const void *addr);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b341a191651d..fe3f606b3a98 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -176,8 +176,12 @@ static void end_report(unsigned long *flags, void *addr)
>  static void print_error_description(struct kasan_report_info *info)
>  {
>         if (info->type == KASAN_REPORT_INVALID_FREE) {
> -               pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
> -                      (void *)info->ip);
> +               pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
> +               return;
> +       }
> +
> +       if (info->type == KASAN_REPORT_DOUBLE_FREE) {
> +               pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
>                 return;
>         }
>
> @@ -433,7 +437,7 @@ static void print_report(struct kasan_report_info *info)
>         }
>  }
>
> -void kasan_report_invalid_free(void *ptr, unsigned long ip)
> +void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
>  {
>         unsigned long flags;
>         struct kasan_report_info info;
> @@ -448,7 +452,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
>
>         start_report(&flags, true);
>
> -       info.type = KASAN_REPORT_INVALID_FREE;
> +       info.type = type;
>         info.access_addr = ptr;
>         info.first_bad_addr = kasan_reset_tag(ptr);
>         info.access_size = 0;
> --
> 2.18.0

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks for the patch!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc_sqfp4NOZPMWig9t01-yz2HOswoesTVfzGubrvqECDw%40mail.gmail.com.
