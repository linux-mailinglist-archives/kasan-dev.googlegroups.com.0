Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYNN7GCAMGQET2RTT3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 911A63807C3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 12:54:26 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id g4-20020a17090a5784b02901560d133779sf1484831pji.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 03:54:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620989665; cv=pass;
        d=google.com; s=arc-20160816;
        b=tj22YI6w8V53fT0gsfXVJpeGAFx/lCCkgLDn2pNbH7saEpk2BTkRYafatIBnAs6NIx
         nyERYv5dc28ZoZX0PgEMl+ZP+mGNiF0oJ30FDxNf5MtyAVu9WlepANPbUpPlsuxAlZxQ
         W4MCr7mS9f+T1Zc4u1+hFsH0QXY88rxXcWpm0PgMK+4gNVwEP1cEh0taDO3EJ2Rx7uTk
         FHWXILt+xZtECsLBLmnNfaG7RHHYnYecC4vmUqZUQlUZ9Z2QXcGsQLZWDnOn1EMrwdt+
         N1ZHaKR/ghj3h+59E/R4F+FpVsmHN7lPVk+O9D8EZybvBqi9wtg32BHkVHi1eE+Mj8F5
         cD7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PO3twrh1Ln30EaqoHpbw3esGTu9NFrMnjYZhwFat1rI=;
        b=bo7sOENbAFLYESAzNoqaeOOdGnwet7DhzifaEW7V8h17yfNzKvAJec6D1oibmyVc1n
         o4SBi1eFzZ2JmXljwfllTXGO6kSAeJlCum12SiXOfLnFD6TuvVk9stl0F6P44f4+EBXl
         976J+1fnnJmfYgVmXfq6PGNfNlH0kfDqJ4Umw5crnMj2bNxBZkAWAQP6XLHn7lupUTQD
         fGbBfWiZcKtRAJHF3zH12roOlgYbJh+wx38GGi6TUgTXZbBd89ts4fsD/RiyVUpOMK3c
         SjheN+MTCwNQZuniYAvRKHzgZDMGuvPMgh9XMYeiQmYHQQq5ldRSDkqIa5TrWbyqjbHh
         8Rvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EgU769fq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PO3twrh1Ln30EaqoHpbw3esGTu9NFrMnjYZhwFat1rI=;
        b=DlRQLfsYMGB2O4KD/g9DESPse5xnVLxuQickkm6iIcqtJ0ktoDDmUQ/4DusKavV2Qg
         rC/cxTDZ+53OAeIDCfg36CYuNrKisUOD2I+WOu0K0nLp9EC4BDCg11kv9Tp6qFl82hGe
         UdVCsLjYdiM84BSrVIp4rvP0rRZs7nwz7Egs8y6wZoKvBu2+oQZPI8z3i5CIlqleUCDX
         AX03onzzsi1BVA/ZOz3VYCe4ZVyyUnpaayNZxl7gHoISFO28bHsJEIyzVgnwTNICOpMJ
         1VRQ044zuCIdYKDzrzsprcDn0eh1o6gF7nOArrjiq74HD9iJvX/vMMFeia784jOmQQKK
         3F/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PO3twrh1Ln30EaqoHpbw3esGTu9NFrMnjYZhwFat1rI=;
        b=k3YRXh3eCMeaEEG590ANef/EYRmP3Gi7Q0TXXXJCt1Z5O5F8+et3ytH4OGHm2H7R3V
         KGwD86oEVME0UZDRWSCg51Yc/hTm0p3cZX8+lWND9nj6D0utHW95f9wZsY3w6Vy+4Vy9
         J3v7F/z3DNnOCoQbNEB/12rXwQnwc4hDEIgIsQqA5Wg8Rz3EGE4a43ojOrfY32p08yXO
         U8BSgNADheg+MgKo+BmJDdh/1s1Z1L6lTrbzYDI+dfdaWLlmkDByorkWYc+xilg5zTs/
         5nzUTo3Xi0IWBa4D+3RAvJNqezKTHbdo2ZZ0j+NszlPHVP0xTMUiUFtTITsPTG/aK+Pv
         mzqA==
X-Gm-Message-State: AOAM5313fAPVyw4BT6jyb7b1OINwrJZRHXLIeu2NC8e6yGaTyFWOC5eL
	0Ye8smInMyd4/Hnp8geQWtw=
X-Google-Smtp-Source: ABdhPJy3CeFX7c3FOZFlzDONEdHPTjm4JCAon7lZGx1XxudJQXacs6gyO1E3h/hInsBqkcHsY/iE/g==
X-Received: by 2002:a62:1b97:0:b029:24e:44e9:a8c1 with SMTP id b145-20020a621b970000b029024e44e9a8c1mr46377292pfb.19.1620989665232;
        Fri, 14 May 2021 03:54:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7208:: with SMTP id ba8ls4763525plb.10.gmail; Fri,
 14 May 2021 03:54:24 -0700 (PDT)
X-Received: by 2002:a17:902:b602:b029:e6:cabb:10b9 with SMTP id b2-20020a170902b602b02900e6cabb10b9mr44542131pls.47.1620989664645;
        Fri, 14 May 2021 03:54:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620989664; cv=none;
        d=google.com; s=arc-20160816;
        b=qvsxcpABIslcZbBSsss4mUaMYo3j3LsJkEg6so6xxvjgxW4g2GaAa+gGmGxIgZ4ZrZ
         h03aofgle4TxLozQJjYDrlVFxWdFmQn396NJI8zSH/uGbZovZSqasy3iBNN7362sdtkR
         F2l0txl+zI7kC+oVN4uNuGw2mxDmaN7kPnPuneAC2QLgQJglwSpZYwptPHuaPYR7ZaiY
         GZg8nh4UNncFsLoe8IMjig87ne2xLESy6HfYrZmI8njUpKVubLdAw+mkRnFZtrJgy1kR
         eyuNJdD9BBJn5B4aElqau+e0MLliKbSVWEaDMea2p691nnQJU/buvHYc5G9LjNOGrqEY
         iFww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=19+6o3O/hPf0SMu1IJyh2NJXMIWlR4MKseltzsIotXU=;
        b=1AVyS9jfdVvR8fNiteq1rNSkQj+NzzCXTGiIvgoz3gKeMP3LVFcQkonsjBjOmQccDz
         CGyYsWgELfrDjag5zrwpwEDj9hqBI33uCRwgUnGyfrscOx5cZlTdq11tls9oef7wuWI+
         vVW8HcFa2H0T6KoOjrSdNiha/TpVw9NDXYJJEXGzmoKmk5G+ML0Xha3v+g2VEFZdgPqX
         b/iCPg5StxTMmy+EDAu+c8akzqDyQRzN2VHrRRweJPyaZxUEXO5sQWwTUGJOf/hNCPtu
         rmXwCcXIWloUAsaa+1dpMqR985m5iMkC3N5VOPrm4AXOK4R1ZLe4Na9G1FCZEjJdWX4y
         vk5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EgU769fq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id o15si481520pgu.4.2021.05.14.03.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 03:54:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id h9so4157147oih.4
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 03:54:24 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr34053651oia.70.1620989663822;
 Fri, 14 May 2021 03:54:23 -0700 (PDT)
MIME-Version: 1.0
References: <20210514092139.3225509-1-svens@linux.ibm.com> <20210514092139.3225509-2-svens@linux.ibm.com>
In-Reply-To: <20210514092139.3225509-2-svens@linux.ibm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 May 2021 12:54:11 +0200
Message-ID: <CANpmjNNB=KTDBb65qtNwrPbwnbD2ThAFchA1HSCg9HKETkQvCg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kfence: add function to mask address bits
To: Sven Schnelle <svens@linux.ibm.com>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EgU769fq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

Thanks for trying to get KFENCE on s390.

On Fri, 14 May 2021 at 11:22, Sven Schnelle <svens@linux.ibm.com> wrote:
>
> s390 only reports the page address during a translation fault.
> To make the kfence unit tests pass, add a function that might
> be implemented by architectures to mask out address bits.

The point of the test is to test the expected behaviour. And s390
certainly isn't behaving as we'd expect, because we really ought to
see the precise address to facilitate debugging. Granted, by default
KFENCE prints hashed pointers, but with no_hash_pointers we still want
to see the precise address.

Is there any way to make s390 give us precise addresses?

Of course if you say this deviation is reasonable, see my suggestions below.

> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> ---
>  include/linux/kfence.h  | 1 +
>  mm/kfence/core.c        | 5 +++++
>  mm/kfence/kfence_test.c | 6 +++++-
>  3 files changed, 11 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index a70d1ea03532..2e15f4c4ee95 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -199,6 +199,7 @@ static __always_inline __must_check bool kfence_free(void *addr)
>   * present, so that the kernel can proceed.
>   */
>  bool __must_check kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs);
> +unsigned long kfence_arch_mask_addr(unsigned long addr);

I think this should not be part of the public interface, as commented below.

>  #else /* CONFIG_KFENCE */
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index e18fbbd5d9b4..bc15e3cb71d5 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -50,6 +50,11 @@ static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE
>  #endif
>  #define MODULE_PARAM_PREFIX "kfence."
>
> +unsigned long __weak kfence_arch_mask_addr(unsigned long addr)
> +{
> +       return addr;
> +}

I don't think this belongs here, because it's test-specific,
furthermore if possible we'd like to put all arch-specific code into
<asm/kfence.h> (whether or not your arch will have 'static inline'
functions only, like x86 and arm64, or not is up to you).

Because I don't see this function being terribly complex, also let's
just make it a macro.

Then in kfence_test.c, we can have:

#ifndef kfence_test_mask_address
#define kfence_test_mask_address(addr) (addr)
#endif

and then have it include <asm/kfence.h>. And in your <asm/kfence.h>
you can simply say:

#define kfence_test_mask_address(addr) (.........)

It also avoids having to export kfence_test_mask_address, because
kfence_test can be built as a module.

>  static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
>  {
>         unsigned long num;
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 4acf4251ee04..9ec572991014 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -82,6 +82,7 @@ static const char *get_access_type(const struct expect_report *r)
>  /* Check observed report matches information in @r. */
>  static bool report_matches(const struct expect_report *r)
>  {
> +       unsigned long addr = (unsigned long)r->addr;
>         bool ret = false;
>         unsigned long flags;
>         typeof(observed.lines) expect;
> @@ -131,22 +132,25 @@ static bool report_matches(const struct expect_report *r)
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
>                 cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> +               addr = kfence_arch_mask_addr(addr);
>                 break;
>         case KFENCE_ERROR_UAF:
>                 cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
> +               addr = kfence_arch_mask_addr(addr);
>                 break;
>         case KFENCE_ERROR_CORRUPTION:
>                 cur += scnprintf(cur, end - cur, "Corrupted memory at");
>                 break;
>         case KFENCE_ERROR_INVALID:
>                 cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
> +               addr = kfence_arch_mask_addr(addr);
>                 break;
>         case KFENCE_ERROR_INVALID_FREE:
>                 cur += scnprintf(cur, end - cur, "Invalid free of");
>                 break;
>         }
>
> -       cur += scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
> +       cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);

The rest here looks reasonable if you think there's no way to get s390
to give us precise addresses.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNB%3DKTDBb65qtNwrPbwnbD2ThAFchA1HSCg9HKETkQvCg%40mail.gmail.com.
