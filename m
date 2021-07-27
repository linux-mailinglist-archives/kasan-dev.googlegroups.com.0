Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHD72DQMGQEE775CUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 650BD3D700E
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 09:11:05 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id mu13-20020a17090b388db02901769cf3d01asf13279975pjb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 00:11:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627369864; cv=pass;
        d=google.com; s=arc-20160816;
        b=DrajiWyMd6MSk3l2n0/RVPjNHroY6cS7ndbGAT7ZO+1Toc9RJFQMCiC5NNwNTuydBv
         NZ63NIw15sd50d5ofWss8eePshWB5XsPMwEcQV2gmA+HTVV0ZmJ5DDjbNzXaYKwTZQjq
         EZYDQLxHDLZAP7tfc7HoXvvS2iWuJDrE68zB/4vINphcHj1f6P/9Us5mwQcDw/Z8IBQX
         2RZRPf148gsDR3b2J9KCA5ppQdcTeaCqoPYrCmt3yVCrmRaqaN0iI8UOgRWYUIyeXBxM
         2ROe/r+CB0HqAzbr7i192AQa0rqVAgExTFD5ZkjdrxMRFGrCePB5SuaBygAGMsPvP0mW
         IPFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XJr8IkNTiVoFJiPdhZarF0+VAu7P/E0f7owRHrzLkJo=;
        b=OIxwHpQJOPnaBuIqsHyXTpu1eStl0PUBDwHmx+f/wtBHrms5i3WvMm+WzZDEn1JViZ
         t4ee/PJ43ei1zDn5rWcZ+0SoQEm+940p9HXAl9S93DKz5TueL0g9FxrDQOZTVsr6kpHR
         Zne6KuHLJIV3q3M1QNupjV8rqrQhcTRRtpWMhQpHcT4dFWiZ8ma9PWKm3LApSjjE5kho
         kLEjhhm+TjpQ1E4htD/NwBHPApKDkTfMAs0cumjbN35hDKDEpkVchf6ips6nuVxgFryW
         oiJEp8Yg9iB67Nde3mR9KazEam7YJDRfdxf3lWV4/1gS8ukt63LhyEgrm4h4Kk//siuo
         +qAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ez4vH2iS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XJr8IkNTiVoFJiPdhZarF0+VAu7P/E0f7owRHrzLkJo=;
        b=e0w1Mzx3Wkw2eQCwssp+ZKyP0D0VuvTr4CWRib/aD/onJUlWDbpEWoxdfj2TIiAOLC
         Gu6bhedqha1zi+Nzje8+wqToNGKtt0BktfblcxWFZ/ALVqUUw3QSEmD9GMtuTvgNaJRp
         bMgbpKVdZWbMnuKkiW4hT+B4d4bVOwxzCMNN79LT8XmqvJt8mnuRhVE0+1Kk01r5Ea/6
         tqKPG2jyN1Y31GozwEhgKN3bHs4Y95ik8qmeXtJ0fzUT0k7N0Z2ehS0CfCAGdXpyF4Nf
         YNBSTNrgzhnJjdiC5Ng6TipmOrOZvGmcTLYKICyVHoUf9OOSJOKvwBMy2SencrdJh+GS
         Jdnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XJr8IkNTiVoFJiPdhZarF0+VAu7P/E0f7owRHrzLkJo=;
        b=QzdnvKqLi6mRlboRQD72BoM0z0L+e7+MgoBPisT4tyeL2bq8zpEpa7vrF/RcS9ijhz
         5PxQS0WV3yEs4GzWe6PIzt765f8yzwM9C4jGfHacjfxJ2V7w8vuKnE1Io4jfprIWhjU5
         2tiWm15fD7nhyOiQTpRAutODXOgHINcFWc6mKtjs6/gwHx4FfBE1fIrtEICcdiTZL7JN
         zPkXxikbhwRbtjPBObbmi88A0/NWGyPJGSU+4tVwve4MpIvsSJWD+tP6wCFO2zPA4F3F
         ZrJu4rD9pNKSWd8CvsQmNU3u9wfV/0sI5REL1cRpfK1zIUCm3frFpz84Wngzxx5ULpxH
         XGdA==
X-Gm-Message-State: AOAM533fCV76xTXykuvGQSDBtDzMbmQiqn7acqE5dxQyLpHhZR9lF6y8
	ie/5JZPTLMQANHo5m6STLkc=
X-Google-Smtp-Source: ABdhPJxj2IEQGWtvHJtsiLsc/JQpFRNS0OeeTl7cVWq1fZbSkm5Tg5Va3gYmmnT/NMJNrjcjRf7otw==
X-Received: by 2002:a17:90b:4acd:: with SMTP id mh13mr20887272pjb.26.1627369864157;
        Tue, 27 Jul 2021 00:11:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a1a:: with SMTP id p26ls9059082pfh.9.gmail; Tue, 27
 Jul 2021 00:11:03 -0700 (PDT)
X-Received: by 2002:aa7:990b:0:b029:327:6b3f:8a1c with SMTP id z11-20020aa7990b0000b02903276b3f8a1cmr21485063pff.26.1627369863465;
        Tue, 27 Jul 2021 00:11:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627369863; cv=none;
        d=google.com; s=arc-20160816;
        b=dsjAiOpt8HtR5cTNA1/aGZs0tzhyOOL/8prtmMB04bhY8JzWfjMr6Q7z6yH/CBDTeA
         zRRpCF9g6qTQ6w+LAwnYdX+GLqd9xBJto4Vcz8yvCtMypMYiky8V3oWSHxL9hOne5YGc
         s/vEt/x0yMpEPZr16PsbX6pf6FH683hJTMp45Kck4BYpClXUs+wr3oaWud1OVAYLroT3
         kcl03oVXYKRWkKknC5MLTFF/d/1pwAsgktA/I6IuUhT6rEV1qABDmvusij+UbaSmMcSy
         UNVwkAS8YJS2ptwWgg5rsuRIPy1AUjIAnUj/OMyx2fatolKSx6rgRI5I9Xn199Gm9n+0
         1TnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T4jXR1i3kQRbLOtYJPUwTyuXvag/F8LgWkncG8JS3kw=;
        b=jhv/OcCnBl503L4cnOxa3q96wFsopmMxuoNnxTDv40WuJkN857/PrW+Y/MsY9wPXSC
         S7lIdRrkmGyGuBxn10eEDTRWDV/Rksd/ihS6Vn7WXT9R0jLyf+7N3WBIS0zPxECaHwTM
         UVj6okEwHkJeyPqp76HEp7Yrjbdr1/VzAaRkGSzHXSYdTeueEfisjKlj/X4MbD8px2Jv
         fc/xBqKFCp+xKMP1P7pKxCk8yCnhvDy6yqXyQxxAwnDieiWKjlcmS42Kdtu440gUZUDt
         joibF98K10odj6aFRQ24caLowVR61WAW/ncq26aXgaNrQTfwkxHadazpSkL3JXHavvnZ
         0IrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ez4vH2iS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id v24si173501pgh.2.2021.07.27.00.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Jul 2021 00:11:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id o2-20020a9d22020000b0290462f0ab0800so7870282ota.11
        for <kasan-dev@googlegroups.com>; Tue, 27 Jul 2021 00:11:03 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr15077003oti.251.1627369862852;
 Tue, 27 Jul 2021 00:11:02 -0700 (PDT)
MIME-Version: 1.0
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com> <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Jul 2021 09:10:51 +0200
Message-ID: <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ez4vH2iS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

+Cc Catalin

On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> Hardware tag-based KASAN doesn't use compiler instrumentation, we
> can not use kasan_disable_current() to ignore tag check.
>
> Thus, we need to reset tags when accessing metadata.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

This looks reasonable, but the patch title is not saying this is
kmemleak, nor does the description say what the problem is. What
problem did you encounter? Was it a false positive?

Perhaps this should have been "kmemleak, kasan: reset pointer tags to
avoid false positives" ?

> ---
>  mm/kmemleak.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index 228a2fbe0657..73d46d16d575 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -290,7 +290,7 @@ static void hex_dump_object(struct seq_file *seq,
>         warn_or_seq_printf(seq, "  hex dump (first %zu bytes):\n", len);
>         kasan_disable_current();
>         warn_or_seq_hex_dump(seq, DUMP_PREFIX_NONE, HEX_ROW_SIZE,
> -                            HEX_GROUP_SIZE, ptr, len, HEX_ASCII);
> +                            HEX_GROUP_SIZE, kasan_reset_tag((void *)ptr), len, HEX_ASCII);
>         kasan_enable_current();
>  }
>
> @@ -1171,7 +1171,7 @@ static bool update_checksum(struct kmemleak_object *object)
>
>         kasan_disable_current();
>         kcsan_disable_current();
> -       object->checksum = crc32(0, (void *)object->pointer, object->size);
> +       object->checksum = crc32(0, kasan_reset_tag((void *)object->pointer), object->size);
>         kasan_enable_current();
>         kcsan_enable_current();
>
> @@ -1246,7 +1246,7 @@ static void scan_block(void *_start, void *_end,
>                         break;
>
>                 kasan_disable_current();
> -               pointer = *ptr;
> +               pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
>                 kasan_enable_current();
>
>                 untagged_ptr = (unsigned long)kasan_reset_tag((void *)pointer);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-2-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM03Pag9OvBBVnWnSBePRxsT%2BBvZtBwrh_61Qzmvp%2BdvA%40mail.gmail.com.
