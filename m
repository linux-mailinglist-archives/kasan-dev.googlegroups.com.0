Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGGBTSAAMGQESZSXALA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id B78932FBE99
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:10:34 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id w22sf10703090pll.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:10:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611079832; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sa3P3KdC+Sg1ZJ/l6ZAqC4Rcjfpt8hspkZdgZn1x/mxkkslYTqoaWgYVWBK/ewwBTk
         AsSzTniI9C9rxXxp4yNjO1U8+d9M+dOq2e286UxPgpeF3c80N6mi1ePoCQOy98bkkTma
         3+vNXAtjoXl6pWkEU1YVJqhvb0o9m6zsnpbT+li9c3vSf9beTmDTv6A2g7FFILyhDeZt
         eZbxMrBSJYFxSk86UFaHlV9M0bnK89E/NX1Gi/tcsciiMW8xmb9/tieORR9mSKS6dWVC
         vcJhSD7wmtlIpHG2i1NjncCpufb9ChVX00F1VSIquyrofrKSIdTgJHir7+NTmSFbX0Pp
         sqcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DbR92gibK888NW+B+VOUtg3R2XRC0/pdvP5/eIOmrmk=;
        b=E78omunZGti9PRkrkroTXfsDusW2mkP1Qxn05BDxj+2VtEqkJ6gqgPkfMnTMp+EP+7
         hnwqED+7hdx9qn2Jd0r5C+Jz2QwvL0/sd8Exjz9YIY8UMpkB5/d6wyHnq8O9bU3iHhd2
         SwGuyPMv2oUIquWfs1nLVyKMJKv71v4xyXGUWkosY+xks0G4JUUdpD+TP0FaZkU42GGg
         t+S+viVvbFU+KBuDSAO2UXiyIkJTGfmhsKykq7Cl3nkBaIx2dh2LEWavWa+GdMMM+dw5
         m4kqqFJlIx49uTKjlU8NHvsqH4kHmQ/APQ0hHZ8RT53ORM1ova9V/DlpfL2mXcVW7Uhm
         /M+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PrWo7Cyv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DbR92gibK888NW+B+VOUtg3R2XRC0/pdvP5/eIOmrmk=;
        b=T8xJKpXRDAYp98KFcpQE1spDb7mdqFMBshGViygP94Xgbl379DmlhJ6JzQ0kA+xn4W
         ul64i18khUOpZ2TYtXW8PlkdQ28RVT/1KHqI37eAkuPmfeYL15g7U5cYYGNWcVycxwDk
         mi4VUo5A+eiZghcwqW9G/0n25dzgLiXdY92oP92eYj3GSibDXIz/a/eQrUobXvCxoHDz
         ub/SpGGvtkiomOTA7K3Jq3FlQyNSwgcQ3ZRRpmK4jZ7ZedzQLa1nwkBfOH6epNH/hDqM
         eCC4lbBk/tY+cuXvWnqmFiCA72VpGt01UkfjXRLm3jYSOYWDtrOB2tjIKNQ+cOkkvAF9
         KSEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DbR92gibK888NW+B+VOUtg3R2XRC0/pdvP5/eIOmrmk=;
        b=ncomft4Zs1sUKg2BdteBupuDDfQPDuLnjhcGbYo8k0yDMExc2vYDpDIpbNMTN61Way
         tvyxp72cAomnEPvW/ZNou46M+zv4H3UK+TYSIZjiKNTFVPmhD/8qcfuIowyLzQRt0kqt
         64K5ZOoz7i4AFRoyKKml6SpNyXc6SOMQ+j0NQnyL6RrGWdSplyx2u55CpJZgJ2yDPv+s
         9XxvB0VM90KuWU1h/07R8War7tgtcT/G5SzlNddld2usiWZK2a9Vdak1mVAzVEt7FkP6
         b32JWKKVBHH2ci23OgamNHjepc6mXWNPVzHahstpYGUwgwzUCmixV9b+eAI7zXO1NOj/
         2qYA==
X-Gm-Message-State: AOAM531OOgXWIsmDAToOZMBgc44JbWIXQJ2758/yi85Y/DAop8EJesGu
	hykPX5bHlvuRfvTezgk56E0=
X-Google-Smtp-Source: ABdhPJwEy8pfqVYiu99/gsTgSF9RH85CIp41yqwcDhz85ekaAP+YcIqpX+y+vJaEnS86hrZR+6zhEw==
X-Received: by 2002:a17:90a:5287:: with SMTP id w7mr1001254pjh.17.1611079832264;
        Tue, 19 Jan 2021 10:10:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:768d:: with SMTP id r135ls2416326pfc.4.gmail; Tue, 19
 Jan 2021 10:10:31 -0800 (PST)
X-Received: by 2002:a63:5805:: with SMTP id m5mr5498681pgb.352.1611079831820;
        Tue, 19 Jan 2021 10:10:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611079831; cv=none;
        d=google.com; s=arc-20160816;
        b=hJToRasFcEwzom1ydjjUi2DjTFZQQXmCh9eUgsFlGu6FwKX0q4zTofY1Hsucce9hiU
         GDI8HWgq/rQo3VdS2HL+9lDBqkl1xoBgKyBSzSyxvNXmh7xvKJ4RzM7nuHUw1PcLHzop
         AXu+3NrrkmAegBqj+ZUH9qp/lcP+iaLXMGxeO8DbRJuSulJCEwFn6CLzsT319hN5n4qv
         wmdCuoXlr1L2YPGmg3/UlVGA3Tw/QtNkksHrGdkWzWmu5dijxcr34xYQaacwdl3IZ4e7
         tt2vfZHWqW5lfz71LZ8iv99MoXbjsBcpmF9pJp8cW9yxuSw4q0sGPPd9Bx8gogHgDYK2
         +P9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Opada1Nc74SeJLx5vNBWIsrWjBjEGuHxciJnJB2M/I=;
        b=IvJSe6pWtjui9OiA4i4IEPPYTcap0HfJvk26eh+6HfoL/0DJ5yocCtLCZ2ZlasWJg+
         ND1iISQZC5RvwWZuvHqrmscZ3Xbhr90g4qk2RYLzUqGYwdQcIod/WxPQZT851NMS6seK
         +64sa6qeul2QGxCqDRX3FIw5M4cALblN/1VS31OyyoG4GfeqhLiJZCUHouog32jD2I91
         aJ3AcwUGiF7l4hWQ2HoOeriWwKh4vYD5eVm4ljVBmsi7K6fFX+MKBWKuLGAB1wszBhI4
         HY8jCFIHD5UTBPdsQhnqN30/nMtMQ157Nd2qFgzTmst785te6jfWxt0rM98vX8u3KCNr
         XRuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PrWo7Cyv;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id jz6si468107pjb.1.2021.01.19.10.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:10:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id j12so5587667pfj.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:10:31 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr5572351pgk.440.1611079831408;
 Tue, 19 Jan 2021 10:10:31 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com> <20210118183033.41764-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210118183033.41764-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:10:20 +0100
Message-ID: <CAAeHK+xCkkqzwYW+Q7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ@mail.gmail.com>
Subject: Re: [PATCH v4 2/5] kasan: Add KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PrWo7Cyv;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jan 18, 2021 at 7:30 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -162,6 +162,9 @@ particular KASAN features.
>
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
> +- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
> +  synchronous or asynchronous mode of execution (default: ``sync``).

This needs to be expanded with a short explanation of the difference.

> +static inline void hw_enable_tagging_mode(void)
> +{
> +       if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
> +               hw_enable_tagging_async();
> +       else
> +               hw_enable_tagging_sync();
> +}

It's OK to open-code this in kasan_init_hw_tags_cpu(), no need for an
additional function.

> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -284,7 +284,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
>  #endif
>
> -#define hw_enable_tagging()                    arch_enable_tagging()
> +#define hw_enable_tagging_sync()               arch_enable_tagging_sync()
> +#define hw_enable_tagging_async()              arch_enable_tagging_async()

This is one of the places that conflicts with the testing patches.
You'll need to: add an else case definition of
hw_enable_tagging_sync(); change lib/test_kasan.c to use
hw_enable_tagging_sync().

I'll later add a patch on top that forbids running the tests with the
async mode.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxCkkqzwYW%2BQ7zUOjbhrDE0fFV2dH9sRAqrFcCP6Df0iQ%40mail.gmail.com.
