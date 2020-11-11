Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHM6WD6QKGQEQB7LTNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 479042AF60F
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:19:43 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id n10sf1437067plk.14
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:19:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111582; cv=pass;
        d=google.com; s=arc-20160816;
        b=IeZBhtnH2UMozi8MmM2/CySSghG1XpLVMlj/b6KuPaPzHcIIfpK1TmndUaM/N3Ozr9
         sq6vB2FHXFpxotMpI7UCdl7cN7q7xRtOJgGeN8tqC6umrx4XqbkCXS/0OrLpP31x9VoA
         vrlrlZ6YqEPuCiDI354PNCWTgWRjMrSE24hRM0CvSKWvQUar5yCw54ImjbYZG1Yysq7Z
         AquHZ4eA111nXvr4fFo0iunhgpFxF1QyXUbvubMhotXxpDTZoNrQrix9q5Nj6tmOYHOW
         JC/U9WBW2FdNCHV8mMg0DmvCoc4ggZIjw/MEos50UllEripsuUqCKq7PySi+UquYry59
         RW1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kmEM2A8+3azqv+i+m9J/A0WNVoG9l2vOfYuq1ANBykc=;
        b=LGn+zBNUO2maWajwkpSQABFrcwsYwEKM+0rsPjSIYTkxf+Bn8uY1aRJJtEj4bdjsMs
         MIOv3hufElwdZ/LoFd6zzgTkVm+h6ROXs3o48Xh3DvClnvuqX09tRdSKifsdxhiwEvtj
         ZWs/tBECj1pGhzcaoO6AphuUwGwPXEiqyf3EE5kEXsZPkT067ubZl8xvFGbbWgGKqJsg
         CVO1qPl0UnDF291dOqJG8HXsk3FXi+CNTsRK+AoPXglEz+w4sIAJjcZZ/8RFExQChH8b
         MdGOr7uQXum/NO0LXknf7nWB5Xwyv/nSwCW8GuEsy4R1ye+xBX/D+/UEBAKvFvOyF3SU
         I3zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EDK8+6vZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kmEM2A8+3azqv+i+m9J/A0WNVoG9l2vOfYuq1ANBykc=;
        b=JfiSzCiahf/wznlPPmfcIPaCwwS1iK7ozZYY2rcoNX/XnN8Z9DLmDEefR69Mo7rRhd
         6krdTX4D5cXyfSo37d0kUhhFaxpR61xYR94SrZbx0nUgT4PamGUbcN6xsk8CEwhZKvow
         QfqMyGK2H7FSJqHXkeoRh+cevNNPIItndOdnM6X4EklMs+IHbXXwVd0aGLMrlJ9Gth30
         in/SiGyV/KBJVZzxPyCkoV0qlwvKzVaB7jBHSiew3QG84TDTRhIHYBGw44rNhjTN+gDi
         ygOspmpqIxxFsXdOIkITUvou06gOz4xy6mmvqjbrlOspGBpS8kHfxpEQ1nrMyyL/NopQ
         psyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kmEM2A8+3azqv+i+m9J/A0WNVoG9l2vOfYuq1ANBykc=;
        b=PpSgj1jQr8G8utsvummsXxnR+zC6r5PtPHFgDe2vBA2lUJ+BZefXMrgY9d42EcRtgW
         v8sit8hF86XeYQCi7FPT8lhns55/a8TCdDDPdjlZ9I3o2/cliPNZJlll09tp8PoPmaxG
         mmcyDsvmJCjFUm19KmLhUVGdTYlP3yT/QBXb5FzBeLrZeungtZH+nIu+S3VsOxf0/yh/
         Yer52i5709617O+kc4rqWFloeZDctxLZFqzlnuMim4BRgZW4/aSCpVnJ5u2iALuESvSy
         ti8ZWL3nWpwskiuZGaR/lPJyfDNOl4kCK2tEvpNtzSk+YH/YAL3ET8RA+1pS9j90E/qb
         hfNQ==
X-Gm-Message-State: AOAM531pKhAvoD1g28MzRub1r/gEPMzj739hjZhRjYvqmC8hCjy01IeN
	E0i5Lbvz0BaWVN43p9Eaxrc=
X-Google-Smtp-Source: ABdhPJwIu/ZwJhAm4wfsbfboOVgcuY1u8xmgp8+UOejD2xxKPWZLI6DlgLjx4sLlis1m1ZL+zK+tDg==
X-Received: by 2002:a17:90a:1b41:: with SMTP id q59mr4497321pjq.17.1605111581940;
        Wed, 11 Nov 2020 08:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls93973pld.8.gmail; Wed, 11
 Nov 2020 08:19:41 -0800 (PST)
X-Received: by 2002:a17:90a:17a9:: with SMTP id q38mr1899323pja.89.1605111581441;
        Wed, 11 Nov 2020 08:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111581; cv=none;
        d=google.com; s=arc-20160816;
        b=fJ+fL3x1XmWwYGCSIXkM3LF3PH4DMVmqLWY0SQYUbpoY69ebEEw5U3RG4mdPLWysWT
         Y8zdLvDuVVE/8+JwDD3d29iS2JG9svT7/+mnbgzCaJF6lR/7ZAjTTq/KykHheBAoZAMc
         UrSDgco2fVoX8XXMWAVWJCelo9WMHwqZGoLKjhIP2ZKFNYq7lg7fuDMK5oSrV/JheB47
         nWpMe3bycVtxyzjHTvRbYAmOpgRczi/1DMzmDEe6ee9XnL3qV6pCm2Vn442hTxXgCbdn
         MR46ITipDPNQbyTvgNcNP7yMsPKnfmUv0N5VEDpOMwhouS3ahq7BlCrUYEv2IC3URmyb
         KtEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NdgljsAg/2kl6g/hQQs/nkDVrJD6gaQwZKzBgT4Tycw=;
        b=D2zdEmnS650qer2RIuAAL1KhFd4LEhbfm7j23GtpDfiQUgkB73zNIH9fyNaupSkaag
         yQ88t7JWlFigRhsMImApdmKW9TGTZHlpP5dfaaC/kzE3/lN2MikdtappwCPr3/z2uMCN
         aJBgycrGmv48KjPJRhLFcqgztSdrf0EQqxy4bY/9VaqjgQlASKs/YUwZOrCiwezQ8cUx
         rPUMHMqW44bC7GJ7tcbzA6OPe2qn2wqXPDBab5Gi5umYpfL5h2co10rFfQDZFe96oj2H
         bEvRBTY1zqY6qJVsfjJcpljK/GLj2Fnyq+FrrSogx89QUvdT+56mHSHhrcyu750nhwjo
         dhFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EDK8+6vZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id 80si184844pga.5.2020.11.11.08.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:19:41 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id t191so2182376qka.4
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:19:41 -0800 (PST)
X-Received: by 2002:a37:4552:: with SMTP id s79mr19714490qka.6.1605111580407;
 Wed, 11 Nov 2020 08:19:40 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <560e04850b62da4fd69caa92b4ce3bebf275ea59.1605046192.git.andreyknvl@google.com>
 <CAG_fn=W-H8nHc_DmBOsnJOUygDJ+wg78K-QSY_wHTSHg-b8vFQ@mail.gmail.com>
In-Reply-To: <CAG_fn=W-H8nHc_DmBOsnJOUygDJ+wg78K-QSY_wHTSHg-b8vFQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 17:19:28 +0100
Message-ID: <CAG_fn=WOeX3u7KQaMq1acSszWg=Kq5FLVhK_rWSrXsvzbbvq2g@mail.gmail.com>
Subject: Re: [PATCH v9 23/44] kasan: separate metadata_fetch_row for each mode
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EDK8+6vZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as
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

On Wed, Nov 11, 2020 at 4:22 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
> >
> > Rework print_memory_metadata() to make it agnostic with regard to the
> > way metadata is stored. Allow providing a separate metadata_fetch_row()
> > implementation for each KASAN mode. Hardware tag-based KASAN will provide
> > its own implementation that doesn't use shadow memory.
> >
> > No functional changes for software modes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> > +void metadata_fetch_row(char *buffer, void *row)
> > +{
> > +       memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
>
> I think it is important to use __memcpy() instead of memcpy() in KASAN
> runtime to avoid calling instrumented code.

Please disregard this. Turns out we define memcpy to __memcpy for
non-instrumented files.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWOeX3u7KQaMq1acSszWg%3DKq5FLVhK_rWSrXsvzbbvq2g%40mail.gmail.com.
