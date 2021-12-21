Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNO5Q6HAMGQEPUYJTTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 94F5C47C24B
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 16:11:50 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id w14-20020ac87e8e000000b002b6583adcfcsf10918566qtj.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 07:11:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640099509; cv=pass;
        d=google.com; s=arc-20160816;
        b=HdOchIyylUwTDSQj66RO2zUJ0/8Vuq+mt9F+2E9jwiMau8HiTaB7d1Eygl7e+Wf+Ds
         Ev207cTCKE5cgRmyByItEaVw7NDQFlAlHBfQ1daxu5SwOK07kUCFiZL3e4IoYbQQSJFY
         HsAOq9Vj0CaDRa/NMjUOeBcHY2/f902w57N/3KddyayTVVHw2wTOF8mHJ62+WfER/nmy
         zFVTpMMXFjJp6Q/pA7Dmodm807HevEeslK2txXKThOpRg2jlyhnnc28FqaCMwxhBCGFH
         lHEZmff6sGzh9M5mnqedetGrnDwSNfgrg3QmLDJRmQAaHCQl5EIE9sNqRLulQg6M9gCO
         30Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o9Wa04EuWCtQzBbwpixmD8N0P5HyUUn8CvyxT8FEsLA=;
        b=XlB5Y0aavqd1tnhBp5HfA5Du4jTtByOklLof8vie7QAHJcaICWS0ZHWP505iJzEXRD
         nh/v7hX7H9/SL3DS0n8wOq+odE62Ro9PFU0JltcjLFmszWKzOLjAtIP9amkLL8iPcY6M
         LvqU+Bru0s8clXs+lFueN1loEluWc7/zHxiHKzyoSfrTvvBeI0Uvocr1y+lZST2Aa0jr
         RdEKxhrzT6YF0cIoOBZPOgNBuxsP1ihXVw29QF4FLWKmGBPo9wAU2pvCs0r4xRILNjpI
         ZKrKm5uZEwTZ2CX8ZSlt0tR6XzmIAi4lmwNz13kRsAvgeqPRvEN7LpToxttbsiho1ysj
         hQTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZXXoTFFp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=o9Wa04EuWCtQzBbwpixmD8N0P5HyUUn8CvyxT8FEsLA=;
        b=I3pxI0l9OSW9e32/BfIfpMhlNWlxSplXcLdQSVc/S0kEGLvFw8HGWTPzMKkaehVAKN
         UQO3p+txsosquevZHjXEoAbAUHyzmcpMu6EN6AxBkxbqQVvRnjThT1OfLLghaXbzCPBZ
         VeHGa0zQj4MoN9sKBQcjtaFWWCuvd+0iRhNaIfzr3wBaUNsAe2G8q4LsM3qqclZJR89K
         4SgInjIg02GeWpW6HH3C2tuEsRZV3DOdrEn4XjLfu3b4pKOj0JWkrpOISrM1oSZCYLt/
         pp0IeDTaSjLzQayQoF0UxGTqcnsTdJu63DY9Yx4myz8TPbMn3crKR9VVfemlsgp2TYt5
         ZWfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o9Wa04EuWCtQzBbwpixmD8N0P5HyUUn8CvyxT8FEsLA=;
        b=ZfHlA/BIW3lYJrnA4uqCFpk6BYmxddtiBDjNc+tm3en7wwQgXXQ4ps67GekP64vkqC
         Wdpj36efww8StqJq444US9z4WeHNmp1MdFJAOMx/VsvoRQLNmYiNmb3BTqULw50aIXF+
         uZTNMh15Dtiv2n6T60buN+PPwDEgcLV8tNBTXgq8dMi7KOJu4iyX5PJ9U80pAdL6/2nf
         rnufn98I3TKUGhDlCdnNBflkH10Dwmuq7tc0tdF9/cKFvH+QJDpdzFQQ2qCT/LXYUr/b
         VqFX3gB/iOqGpb+IRYKtyzI8VnOjCf/MCjfZGSx7WekAh8nWOiV6ewVa9IasaAzxy6/b
         s6fg==
X-Gm-Message-State: AOAM531joYmt1DGr7VcYyv9ldL9W/h6v5nWGfsXweGI+3elxXvZ0gffh
	Ww4p3PGfKDcYuN+1YdtAEic=
X-Google-Smtp-Source: ABdhPJzNAtS9xxNx9+8GfFsXgiQU81yON21nsqiNHbGH+yGXEJEYKWGRBZtiCcTJ7OfQia6r8jaPhQ==
X-Received: by 2002:ac8:5c8e:: with SMTP id r14mr2602652qta.395.1640099509302;
        Tue, 21 Dec 2021 07:11:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d85:: with SMTP id t5ls8745527qvb.11.gmail; Tue, 21 Dec
 2021 07:11:48 -0800 (PST)
X-Received: by 2002:a05:6214:29cf:: with SMTP id gh15mr2922455qvb.40.1640099508824;
        Tue, 21 Dec 2021 07:11:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640099508; cv=none;
        d=google.com; s=arc-20160816;
        b=eZlldm9nPBkCkU0Fvv57uj/FlnH8H8VyloxpckK/ZXEHqFRxw7a5cBzMlvEXlX3KV0
         7MhU8zbzrYNJOp0HGLQ8wiBjoRpuQ3SsGvGTK2fHn6qQZ8BZ1OlaK87KuwIEpwcEeAgi
         uMcCVRpKVPEMQ/8LMVcxFjUlWA11mLUwRMRmCQ4ehH70AsfbrBv7czUYSCpX8nUXw+Xo
         f8XY0rgs5khk5AMVx86xFdu0ci/w9l02o7hoTWvipKOrM3kyOIBDt4ghvwD9YkfCB8RN
         Xli0SiP5oHBdmIk9eXmuDtVIEGcekv4OvtZCaSUkFe19dLnRNLKpaf5xODsBX+YRpfQY
         3eYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=inKnCrxjiVlEFGg7TNsjz8T66oFLFowuMdP2ABAhDNw=;
        b=SdaEaQ0yrJWV6+0EgrkDMBNDdLH25XrJ8oa7JiS9UvoL4Kpktp810tHgu93AymfK05
         Mr2QY/Fl5A0BTtX1+OwiCO9VNfCh12TJsGpppM9lKNmZRWu2xN/tcFiRj/54T/vxEbye
         iYD+bt8KeVgC2IFyJmYKkr7bqQ4T5efRFs8OW+Bz5EoN+F8cmb1/HqNfzGIfQUhIIgEd
         /CGaAb6dBitDu+tOkwg0iypKM/CpeUOl02YMUSmpWgTi4SKSaiJOslE2m6KHF0R/Y377
         Nb93m31xjMxHaHlbHBoHRkVdqTFRT1w7pQ7bpo7+K6a7bc0p7dTW5RXUQfSSfnIt7jUz
         NnuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZXXoTFFp;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id i6si1855258qko.3.2021.12.21.07.11.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 07:11:48 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id m186so12818225qkb.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 07:11:48 -0800 (PST)
X-Received: by 2002:a05:620a:e0c:: with SMTP id y12mr2303562qkm.109.1640099508387;
 Tue, 21 Dec 2021 07:11:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <c3fa42da7337bc46a4b7a1e772e87bed5ff89850.1640036051.git.andreyknvl@google.com>
In-Reply-To: <c3fa42da7337bc46a4b7a1e772e87bed5ff89850.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 16:11:11 +0100
Message-ID: <CAG_fn=UHZe+9sSkpc0=2HWP9ZeVNWU0jR2tEVS-4FP5+zRB6sA@mail.gmail.com>
Subject: Re: [PATCH mm v4 22/39] kasan, fork: reset pointer tags of vmapped stacks
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZXXoTFFp;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72f as
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

On Mon, Dec 20, 2021 at 11:01 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Once tag-based KASAN modes start tagging vmalloc() allocations,
> kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.
>
> Reset the tag of kernel stack pointers after allocation in
> alloc_thread_stack_node().
>
> For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
> instrumentation can't handle the SP register being tagged.
>
> For HW_TAGS KASAN, there's no instrumentation-related issues. However,
> the impact of having a tagged SP register needs to be properly evaluated,
> so keep it non-tagged for now.
>
> Note, that the memory for the stack allocation still gets tagged to
> catch vmalloc-into-stack out-of-bounds accesses.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
>
> ---
>
> Changes v2->v3:
> - Update patch description.
> ---
>  kernel/fork.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 403b9dbbfb62..4125373dba4e 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -254,6 +254,7 @@ static unsigned long *alloc_thread_stack_node(struct =
task_struct *tsk, int node)
>          * so cache the vm_struct.
>          */
>         if (stack) {
> +               stack =3D kasan_reset_tag(stack);
>                 tsk->stack_vm_area =3D find_vm_area(stack);
>                 tsk->stack =3D stack;
>         }
> --
> 2.25.1
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
kasan-dev/CAG_fn%3DUHZe%2B9sSkpc0%3D2HWP9ZeVNWU0jR2tEVS-4FP5%2BzRB6sA%40mai=
l.gmail.com.
