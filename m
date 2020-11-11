Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNFJWD6QKGQEJNACXGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CBB3D2AF6C7
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:43:33 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id w79sf1766186pfc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:43:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605113012; cv=pass;
        d=google.com; s=arc-20160816;
        b=erpI/auyj2MwJtdjJBbMt3h9t3pM2z9cMS0iVRQliGOX7jSSWnidfGBt3kegaUqgpj
         9/wa0q2xUm9mWHYWpdBtBYUa6wFc47lc9j30dugEZJfPgxHNEC9e6uEVhWyqN2Oe/UdZ
         eRvbF/rPvDMetijXlLH4ATuCCHarmrWzzfoAGRQGx+I+/OjAlYsVBbRkn4b75fjegahk
         wAhcFR9jGoPVkfMsY+gTKGGCvkgfQet5D0JW6FZlIpUfZAwZ2b//WT5nYVCvNSO/69Sr
         rRh1hO3jUiHAfmayJc4Ibqgbl6fsJx5QZ6rKpI4w11JFQP+s49bkdpT5Z3ZNRVVshzT+
         3kKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rSiaSdU7Ylb5WizvsckcmFuwLBzupVqQG4yeJv7WdKE=;
        b=gGmSdjDJBejlJll5A5N8g/8IvXxD+2y4x+LhAq/WlfRi9l7bL/hiUfe47Qxjugo+g/
         2nxJ81lOvsZ+koHoTNUlJk1pUTw1YqJS1uukMwNJzGr042wgHBykVwP+CQuUkszDywDs
         XyP6c3XgtOddSdHBWSKjuIYipQK269mh0fSiZaKMesENjTXb7HRFWbuOSWyvSmZ0GYvw
         7DrCsKxK/WjdwGKMLqceE1chyNyMvAPXgGn3i3KDUvYRu+EmWuzNI8WjFQch2IkDY36E
         mWy51jTyGtvJHmIGmWEJxjJo4fnQqpeu8Kcv16J9jq6C0n6SpdOv2xlm5O3Qhmhb6aUa
         5+/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N3Tu/9Mc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rSiaSdU7Ylb5WizvsckcmFuwLBzupVqQG4yeJv7WdKE=;
        b=aD+MiqygIHOwZWu0IzHJA3Is2o6bfxCTPq5weC1rVL4kzd7mipd0LinDoB7JK1HzhK
         pWoQjk+MhQcdiFj0PMGGUQo3ahIGzAsei7mrVq26T9LQY1tJb9oO4uw58Jxg+u0A5lDm
         oPTEP6fR4wP6SXcAUGLmbWHyIIPdAswVqL9wMi6TD5atrzJwzOX5X3+mwj7xfzy/zjMD
         folBOlyUBEiNDOfaldgTsJ/1UjamKgEJVKIhtlvVUN/CpwqqGwBL/q/y8EaI3pdCx2Au
         CKTvZOSB6xOr8xNTJtxP2PE6VJosFX53Ljso0NZaESrY84p5ie0iEfjP2L3fd/lbgh66
         dBZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rSiaSdU7Ylb5WizvsckcmFuwLBzupVqQG4yeJv7WdKE=;
        b=m5qqSKRyQbPU+spsYlEUVeMvd6ROdMAZpJd0xOGZieahaWs6oYrl6d9lSgv50+KowM
         DwA5ece1DeoiQ7ke/x7Pz4kS+97GyFUxo2/hm4wNxDPzS4oIXsYRpP6hJN+it+W7MN1p
         DBcvG/o/zA+C77K0ehfJ1xhvHkcKEVaDf2ngITTUvTsdGy2LGIGFUUTdZMQmSBqrN/ud
         Dk++Riv9Pr6lUVyNuU9/O0UAvlWpxSe7yRZQb/Kbi1OnBCt3aDIj1k0m0HF4my5KjauH
         Zs15ml3LNHvChnRugR2AhHgmlyaM1c8tkyFLWUHvRApaFDe+kfsGV+AbaRsl+czySksz
         HBjQ==
X-Gm-Message-State: AOAM532SEINFu/SsPHUZHZfSMlt8z7yrJZaxKVzY+UxbkvYtNIft18y6
	rkCq3Jtob0T6+0ZiAvCTeYI=
X-Google-Smtp-Source: ABdhPJwW98uEE8D3H+db/D399pD7RzGH0r3FW6akt5QaOQJ3DVhg+ZtzL3EQ0T6/bAhwCZGsBAMo7A==
X-Received: by 2002:a63:b548:: with SMTP id u8mr22176709pgo.356.1605113012561;
        Wed, 11 Nov 2020 08:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e13:: with SMTP id c19ls85292pgb.9.gmail; Wed, 11 Nov
 2020 08:43:32 -0800 (PST)
X-Received: by 2002:a62:2c8a:0:b029:160:d7a:d045 with SMTP id s132-20020a622c8a0000b02901600d7ad045mr24446800pfs.65.1605113011930;
        Wed, 11 Nov 2020 08:43:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605113011; cv=none;
        d=google.com; s=arc-20160816;
        b=JTGHSKAzLNZ/nGyzDryWi5dAUFvRJWrP5qr1yBGeECvMxbxl9UZebwdYOvcAGSIFK8
         OYUAx+zCpf1sZN49NNKXi+Y8R1u4iMxDhbRXo2X/TFYeOheRNzmV1uvHzdrTq4saANTo
         +IQr6iCEQ+R4emUj5gF+o45DCaq8JE9VwCdGkuYQI/ZcrMdrzGJ4N44Tyw3VTa+B1jd5
         /eoKPFkHWAwY9zA/4faagI8bdrePF15pz35u+d/z36jQSglNHeGihjsA3tZMoScVqFNZ
         PMIOO1kGWfkCn7d/FbV1K5vO5Xuf+OUAu46QlghFMn+UaFUvVIgk/awnvK2wtIpYyKpx
         1HmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QCmNt8Y7TG2qC30JLVGE0QaE5aTQ8urrjUT5uMsrL4A=;
        b=M71kOhO2yCT0s5v/P2MeMC7gludgC75cGlPiGP95PR1LT5ygvhMGX+QNON0x3JOyuT
         Kl+Uj+YrNDL4D4mmZj6quDxUFveUgCa5npy/V9f/J8FkMG2JfeR4XOQ7mJ7SYjyJfZVI
         iQaqW9ti0uGD2J1Kwh+13N9bGJZOkesGulWvvoWRiCD4IxW9N9ObePngBlbhcRRa1e69
         D3UyBxoM2nhfwgIF2KbTIgyiSvCSFu7NPhZrZ+CD+KKqM3WzqSRvXMc+EE+ro7ki0oZc
         4vb12m7agVT4StBEOj+wp/B8E77TQMHwrY7DxE3Jn+NHFSE6xgDOWzcvV0nv75Mo+k7l
         ZDUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N3Tu/9Mc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i5si598743pjz.1.2020.11.11.08.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:43:31 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 11so2257569qkd.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:43:31 -0800 (PST)
X-Received: by 2002:a05:620a:f95:: with SMTP id b21mr17412423qkn.403.1605113011275;
 Wed, 11 Nov 2020 08:43:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <fe78d723ba64456d68754a944fa93fe4a25c730f.1605046192.git.andreyknvl@google.com>
In-Reply-To: <fe78d723ba64456d68754a944fa93fe4a25c730f.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:43:19 +0100
Message-ID: <CAG_fn=VkuY7+oDOLWZEvvbxFw6Gduq-XK5r_dn7sEkmYqJA-tA@mail.gmail.com>
Subject: Re: [PATCH v9 40/44] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b="N3Tu/9Mc";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as
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

On Tue, Nov 10, 2020 at 11:12 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Add error reporting for hardware tag-based KASAN. When CONFIG_KASAN_HW_TA=
GS
> is enabled, print KASAN report from the arm64 tag fault handler.
>
> SAS bits aren't set in ESR for all faults reported in EL1, so it's
> impossible to find out the size of the access the caused the fault.
> Adapt KASAN reporting code to handle this case.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
> ---
>  arch/arm64/mm/fault.c | 14 ++++++++++++++
>  mm/kasan/report.c     | 11 ++++++++---
>  2 files changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index fbceb14d93b1..7370e822e588 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -14,6 +14,7 @@
>  #include <linux/mm.h>
>  #include <linux/hardirq.h>
>  #include <linux/init.h>
> +#include <linux/kasan.h>
>  #include <linux/kprobes.h>
>  #include <linux/uaccess.h>
>  #include <linux/page-flags.h>
> @@ -297,10 +298,23 @@ static void die_kernel_fault(const char *msg, unsig=
ned long addr,
>         do_exit(SIGKILL);
>  }
>
> +#ifdef CONFIG_KASAN_HW_TAGS
>  static void report_tag_fault(unsigned long addr, unsigned int esr,
>                              struct pt_regs *regs)
>  {
> +       bool is_write  =3D ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) !=
=3D 0;
> +
> +       /*
> +        * SAS bits aren't set for all faults reported in EL1, so we can'=
t
> +        * find out access size.
> +        */
> +       kasan_report(addr, 0, is_write, regs->pc);
>  }
> +#else
> +/* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> +static inline void report_tag_fault(unsigned long addr, unsigned int esr=
,
> +                                   struct pt_regs *regs) { }
> +#endif
>
>  static void do_tag_recovery(unsigned long addr, unsigned int esr,
>                            struct pt_regs *regs)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8afc1a6ab202..ce06005d4052 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -62,9 +62,14 @@ static void print_error_description(struct kasan_acces=
s_info *info)
>  {
>         pr_err("BUG: KASAN: %s in %pS\n",
>                 get_bug_type(info), (void *)info->ip);
> -       pr_err("%s of size %zu at addr %px by task %s/%d\n",
> -               info->is_write ? "Write" : "Read", info->access_size,
> -               info->access_addr, current->comm, task_pid_nr(current));
> +       if (info->access_size)
> +               pr_err("%s of size %zu at addr %px by task %s/%d\n",
> +                       info->is_write ? "Write" : "Read", info->access_s=
ize,
> +                       info->access_addr, current->comm, task_pid_nr(cur=
rent));
> +       else
> +               pr_err("%s at addr %px by task %s/%d\n",
> +                       info->is_write ? "Write" : "Read",
> +                       info->access_addr, current->comm, task_pid_nr(cur=
rent));
>  }
>
>  static DEFINE_SPINLOCK(report_lock);
> --
> 2.29.2.222.g5d2a92d10f8-goog
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/fe78d723ba64456d68754a944fa93fe4a25c730f.1605046192.git.andreyk=
nvl%40google.com.



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
kasan-dev/CAG_fn%3DVkuY7%2BoDOLWZEvvbxFw6Gduq-XK5r_dn7sEkmYqJA-tA%40mail.gm=
ail.com.
