Return-Path: <kasan-dev+bncBDW2JDUY5AORB5P5ZSMQMGQEGWDRHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BB4B95ECC11
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 20:20:38 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id d1-20020a17090a2a4100b00202ec7968c0sf4988590pjg.6
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 11:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664302837; cv=pass;
        d=google.com; s=arc-20160816;
        b=iNmIB6J2K0FS9BsPntyUI6e+tzlMKpa/+Ljx2jfFchsDv2Gfy27AmjdiUjkv6JL5In
         7z47UhPJ4rUktpkDy0of9sfbRGD89RAzTqTXJHq1AxmkIHY3iED5q/SfEMquXeL4hkKK
         8SBOKLqdWqzCZkZIjaAQIdepZ7+6rjP4xPdqyqAs5dycJLNCCx3578Q11RlffkDcGNjI
         1Wq+d8OqWAARnfu/AHAqsgaZbRzzheZGMJb/4j/bfPLxf4ngWP1SgmPVCU1ZQZaUo9vu
         jlzbsKwfmQOm2hQTZxxe/0ck14fSww/7H6q7G1mxbIluIjLyOzTvgCrl94BwPtH0R+MT
         LpUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=om0lZjGjsASJdcgzfhbVAfKnWpWPRksoHk7cIGaOPgg=;
        b=if8IGGJssPeROSEz70M7AZEG6ob2apQHZcBbHsSaB2zOKdbwBs1XjG+jnGi/t9k/4X
         k2lXKp7ahj4tO/kRAknMpTZiXA3X2Ol2qCz+4IhmXe1Yh/NCWC+f4PkAtguMEiAcLTtr
         DiLbn2pbIQ6m+yBlUBHeKCamJvIhiZqsx9ORgfHid2jKRBcHQPMmBHgbLAAU0w9ur1uv
         1iFPKWNhdsXMAomNUQCbLH6I2TcP67kpMX6LqOZNz+0FSgdVHt20XqgTRF7KEdoIF9vU
         +WVNfT7O6Ade/CZZzyTvzRIecv/kR5WtXsr5taSRqIJgyVTwk26uF6tTuARK7p//7MkY
         HkoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cgYtUma6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=om0lZjGjsASJdcgzfhbVAfKnWpWPRksoHk7cIGaOPgg=;
        b=aAHoJBfnDHwO2cMCBq/ISB7HW1ZPS0ov9s9+cwSZ5OsD8Pt0vPjXSsy55w8y5Mx3FG
         jnERlijgqyaeO5pNDbWP5+S31557uxRoW7hd1rPnpBEJDQ8iy/9DOtnpO7jfei+6QSzz
         Y6rOvMvojYKYseu02ypnEK4uGgYD3KZAkno6kylTneCMG2zfxVCaTKPHRXsPCLz4r4MB
         SrPmGMpbrp5QzsAJdnPKCB7VV0jYH8YQrBylxqrKR59NuZJ9Kj3Bs2nkDt34WAaExf/c
         YmYNlAcp/uSuhbEmCJgDwc6tlmcHqT5vPeGNFtkBE1LFuaGKnndAUYUOSsmm9tmWFftw
         zfDg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=om0lZjGjsASJdcgzfhbVAfKnWpWPRksoHk7cIGaOPgg=;
        b=VH+uPrkPnHY//BlLRVMtdLn5wlwY9w/NG1KLaFnk/LYUnB47iV+qzcAMf/kDalw210
         M/B1UXbm9Oh8IW8Yk8X4eV/kMGU0ccCU3ToPtR9JKZchQyZctUhA1QlOlTGPmgjnm9Kd
         aO6gfXfhKIjRssZ6255hFg44TlRDuol6MaPkdObuRdHPcuw//DQs4PHbsafpT6rhf0MU
         KWyczd/o5A6uw9CrQR3lKMJ+Q55BTpSsRBOHf601vnN/TUBrCYIbBOqo9LuiVlI7ivw+
         WgwOeYmlYFJX/2r/2nT5qia/U4FNftMxFRiXVtLhek7AwBhRZQ4+sYSRf5PbqHzfISpn
         IHHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=om0lZjGjsASJdcgzfhbVAfKnWpWPRksoHk7cIGaOPgg=;
        b=1QX7TSzVTQL5B0j+7Twjq0Q8pPO/1GKsAkHfoiDjy5qzoEWNUiIOVFH70Y6WJ2E3N4
         tDMSfFQ2MZtqrGRSSVK9JXrenRWi7vf6l2D2I9fRuX/pJegFM23Y5ZqcA1NGUSyZy0qd
         GRyk0FCVlOQc8XjwaJYghLikEVhi3ejfuuRLi8Inx732VoRAks9KliOGvGGUynAsf2Tb
         48bOnZy9sFOYbtWJRaAEkqK9/5HjNeklt1P2mweL5vbz0myNf1GWCaKDY+Q/n9glr4k0
         XmknSm4yLi+x07czs1jyn4jjcp2xRc+boqR1dNB7yji4dQ/4WJplqZszYxzae2Elo5d1
         qHGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3KtufhLRJxTquJHk/IFcNzuoGtScFYkfCnEegJ6k3IZJJx/xAo
	gBzrW0+4uV0gUL5lD3sToRY=
X-Google-Smtp-Source: AMsMyM4l7MspXcZoBxa34ZdFElw6mst3X9scgI7NPw7+ASO9qeg735UXUM6HStmLNXRzPcKzi29f6w==
X-Received: by 2002:a17:90a:6fc6:b0:205:d070:2988 with SMTP id e64-20020a17090a6fc600b00205d0702988mr5779053pjk.173.1664302837155;
        Tue, 27 Sep 2022 11:20:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:86:0:b0:43c:2618:9c3f with SMTP id 128-20020a630086000000b0043c26189c3fls1608495pga.9.-pod-prod-gmail;
 Tue, 27 Sep 2022 11:20:36 -0700 (PDT)
X-Received: by 2002:aa7:8714:0:b0:545:b8d1:4a9c with SMTP id b20-20020aa78714000000b00545b8d14a9cmr30117236pfo.48.1664302836474;
        Tue, 27 Sep 2022 11:20:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664302836; cv=none;
        d=google.com; s=arc-20160816;
        b=a+2981lSQMWYwmcB7BN6a08k4Fomv8YFSPSE4zIvImipVHyJCC8rVNT5TXJ6xjWS1E
         PbuPB2Zg6YhCz8g3IL88y7apu+LGuqFX7n12XKNvrOhG7v9TAo+c6GmEM53y0lNYHU7M
         k/NTgCNApmai5rembnVp7rn6qXpPhqQBp9/NlXMsFLJTHWXJuxJDwvOClPmCyBXDYlfX
         I31XwJIzFzJIsc6QJbYlp1QTBYZDwrCmBTib0Xl8MjUby1SgPIbi/gVV0oaXTBiLP+yQ
         l7n5gfxP5xK11Es40M28LRZEMKeSQ4IJJ+Zg4rgeYBjU5/fz2x6CjdWH0+vxdrkXgtvS
         pU/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K3EEm+yGioRUPVfrRwhSvMYbgEGQ+F2ANH5pgoFJVpo=;
        b=iSade2QWbaJGrn0iNfzph256GoFVcDwYV8/d2AgHHtY8U3HhxtKvK5zMnJ5LGBXgRa
         3V0HnAHZSpZBP37Lr1yX/HYoEW912jyDJp80RALWg0p1Z1/4NeNyXRxjbyfmld7Ghp8X
         f0RKVKB8jZXT9OUaVZDBg7O8Cwi5DMZ1IFMdzaYnjOCTs5E986bKbfj+N2PYwhJhTz2z
         F8YNe23kF7dn+aGxXGXj1SDnEkDLxLIecxUcAXCr4gGD4bINUSgBCxGrlH4Fv22JtZoc
         NGhXOwbQh1rsTNqj+n+y7HkY7LA910USWgG8QI+irQ+jBJgWyoBjM3pbO+B3VPhNaxGw
         sO8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cgYtUma6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id pq11-20020a17090b3d8b00b0020030aac781si604751pjb.1.2022.09.27.11.20.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 11:20:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id d1so6773004qvs.0
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 11:20:36 -0700 (PDT)
X-Received: by 2002:a05:6214:1d21:b0:4ad:1361:befa with SMTP id
 f1-20020a0562141d2100b004ad1361befamr22055161qvd.111.1664302835912; Tue, 27
 Sep 2022 11:20:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220927012044.2794384-1-pcc@google.com>
In-Reply-To: <20220927012044.2794384-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 27 Sep 2022 20:20:25 +0200
Message-ID: <CA+fCnZeF9n6hZKJo+ZMrZ+0ePRXFSC=gFBJCaZGNgPhN+pH-ew@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: also display registers for reports from HW exceptions
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=cgYtUma6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::f31
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

On Tue, Sep 27, 2022 at 3:20 AM Peter Collingbourne <pcc@google.com> wrote:
>
> It is sometimes useful to know the values of the registers when a KASAN
> report is generated. We can do this easily for reports that resulted from
> a hardware exception by passing the struct pt_regs from the exception into
> the report function; do so, but only in HW tags mode because registers
> may have been corrupted during the check in other modes.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> ---
> Applies to -next.
>
> v2:
> - only do this in HW tags mode
> - move pr_err to caller
>
>  arch/arm64/mm/fault.c |  2 +-
>  include/linux/kasan.h | 10 ++++++++++
>  mm/kasan/kasan.h      |  1 +
>  mm/kasan/report.c     | 30 +++++++++++++++++++++++-------
>  4 files changed, 35 insertions(+), 8 deletions(-)
>
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 5b391490e045..c4b91f5d8cc8 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
>          * find out access size.
>          */
>         bool is_write = !!(esr & ESR_ELx_WNR);
> -       kasan_report(addr, 0, is_write, regs->pc);
> +       kasan_report_regs(addr, 0, is_write, regs);
>  }
>  #else
>  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d811b3d7d2a1..381aea149353 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> +/**
> + * kasan_report_regs - print a report about a bad memory access detected by KASAN
> + * @addr: address of the bad access
> + * @size: size of the bad access
> + * @is_write: whether the bad access is a write or a read
> + * @regs: register values at the point of the bad memory access
> + */
> +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> +                      struct pt_regs *regs);
> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index abbcc1b0eec5..39772c21a8ae 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -175,6 +175,7 @@ struct kasan_report_info {
>         size_t access_size;
>         bool is_write;
>         unsigned long ip;
> +       struct pt_regs *regs;
>
>         /* Filled in by the common reporting code. */
>         void *first_bad_addr;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index df3602062bfd..be8dd97940c7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -24,6 +24,7 @@
>  #include <linux/types.h>
>  #include <linux/kasan.h>
>  #include <linux/module.h>
> +#include <linux/sched/debug.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/uaccess.h>
>  #include <trace/events/error_report.h>
> @@ -281,9 +282,6 @@ static void print_address_description(void *addr, u8 tag,
>  {
>         struct page *page = addr_to_page(addr);
>
> -       dump_stack_lvl(KERN_ERR);
> -       pr_err("\n");
> -
>         if (info->cache && info->object) {
>                 describe_object(addr, info);
>                 pr_err("\n");
> @@ -391,11 +389,15 @@ static void print_report(struct kasan_report_info *info)
>                 kasan_print_tags(tag, info->first_bad_addr);
>         pr_err("\n");
>
> +       if (info->regs)
> +               show_regs(info->regs);
> +       else
> +               dump_stack_lvl(KERN_ERR);
> +
>         if (addr_has_metadata(addr)) {
> +               pr_err("\n");
>                 print_address_description(addr, tag, info);
>                 print_memory_metadata(info->first_bad_addr);
> -       } else {
> -               dump_stack_lvl(KERN_ERR);
>         }
>  }
>
> @@ -467,8 +469,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>   * user_access_save/restore(): kasan_report_invalid_free() cannot be called
>   * from a UACCESS region, and kasan_report_async() is not used on x86.
>   */
> -bool kasan_report(unsigned long addr, size_t size, bool is_write,
> -                       unsigned long ip)
> +static bool __kasan_report(unsigned long addr, size_t size, bool is_write,
> +                       unsigned long ip, struct pt_regs *regs)
>  {
>         bool ret = true;
>         void *ptr = (void *)addr;
> @@ -489,6 +491,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         info.access_size = size;
>         info.is_write = is_write;
>         info.ip = ip;
> +       info.regs = regs;
>
>         complete_report_info(&info);
>
> @@ -502,6 +505,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>         return ret;
>  }
>
> +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> +                       unsigned long ip)
> +{
> +       return __kasan_report(addr, size, is_write, ip, NULL);
> +}
> +
> +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> +                      struct pt_regs *regs)
> +{
> +       return __kasan_report(addr, size, is_write, instruction_pointer(regs),
> +                             regs);
> +}
> +
>  #ifdef CONFIG_KASAN_HW_TAGS
>  void kasan_report_async(void)
>  {
> --
> 2.37.3.998.g577e59143f-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeF9n6hZKJo%2BZMrZ%2B0ePRXFSC%3DgFBJCaZGNgPhN%2BpH-ew%40mail.gmail.com.
