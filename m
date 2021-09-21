Return-Path: <kasan-dev+bncBCMIZB7QWENRBNPSU2FAMGQESVOVISY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 62F2D4131F6
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:51:34 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 68-20020a4a0d47000000b0028fe7302d04sf46215363oob.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:51:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632221493; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFyRUzTWSDXtuYhgJyTYFcCpVoh5KxMG08ZAYR3sO+QcA2Xujm+oiuciQZO1geeCzC
         f2llDGFiFwaEQwNHbqRmUxqGpcmWhOJUg/TR2PXbx5dydUPO+ax3CZR9idHYfUL66YjH
         3dmTLSNwhLi1NdomkWtM6FiAo57G/ysXqk8fnp9Wgv79fx1XhasUt8myo7uT2vh8TMaW
         0tFwzXl8hcSXXHXg5eJNeSDCy/mkhE/F1FVHviR5+uJ2Cgbz8s+Gsy8RoRoFF3VzP1yr
         CPIt6TJWuoTy+sPxUBCFHJO543FMsIvW0ufzR0vjNLdA9z4ULl4/VqSHpOCF/b81riMH
         OX9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kqMgBZAMWLS2PKqUGVIj6ITySzm30hLt0wM+ceOSbCw=;
        b=HxRXJD16MeZEbMJRAc+cGedDSxIkH3sk/BAnWtMfdpovKQrMZZXtFwxwyLtfapo30P
         FglfjeAeJXkR/o2JeEzdPURStNqUZz5YZZa94TGEE4eTiIfuXw9n0TZN56S8zaV4xhBU
         nmvJ2cMMaxZ+2Rz/eh9aleYj654DMA03nygZb7dHUT4R9G4G5/pEGFnUUnvn/QQPaTUX
         8ICTgFBKhxrTMiwnFqqLRdeBw+6HvZOFi2AWHkmzESwrShxzUSBpA4CjBe4jxp0NWmgP
         MwEjBYRQqg4+QvxEuRuujGQlg/non3f28gHW4Uxn2ZPzyaeLr2G/fSNvb5ouSPcjQUjk
         ltKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RR3cWHZ7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kqMgBZAMWLS2PKqUGVIj6ITySzm30hLt0wM+ceOSbCw=;
        b=f8GguZmkRJU1fJxqnqzGKCdPCZawl2BPRFh6zV3jIbgAQzxR1cEaD1nMUC57JDt2sk
         RbHS7VXvT89659pWmZqE7qu4FSehoshJXMMRIvqvubq4bkIOstSh0UwZ75yMJOVjDO4A
         l46LWk5I+79mbqQnsTqmUI7bwlxGVYrG4wY29L4EP5T82XLkilKnRvMzQBcukGzX076L
         F89YiCF80yztGrq4PmDL5HBvpldTZLrHD/4ti/5rXuERcAOdvQpmUzPdfvmKUO12lWWK
         Z32HDEpUqVWbWXLWyfRzJQAmbVM/Q3fTeQcMUCz9I+XNFwCIa61Wk+Ynmk9/M/s/+/pg
         XnFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kqMgBZAMWLS2PKqUGVIj6ITySzm30hLt0wM+ceOSbCw=;
        b=g/42K8TJ9CstWXSlyqpoi85RZfrfnEBR+4nw88B6mljPrjNkl5VGo5tN58sVxDg6dg
         VnY3oAha9FPl68Ef5bLOQqpRqKiYbsijYfRM76pedMXJyrTPOIJLiV6HMXPiAzt8egpn
         IC33a86+xzC3oSzeSQ02J8PNYTvzcGANDLESgpz/GS6Wl9UOQYlgN3kgtI2lXYNUrkOZ
         0v8uzh9SPZHYr8RXP8Bg6UcvifXke3y3173oxvJrIb4tgHDl2D80xRsSqSXzb92+Ohzk
         13BFfxKb8JnPAk9M7qAVLOdhGWIGHFTPJcb9zXRZtQx6IBeceUhlLtiDfquCZwvQzKrP
         Ag8A==
X-Gm-Message-State: AOAM532RhHY68zHUQTVqNoogd3SKSx2dDa7x2JLfTdQYyKn7JJlvfWpH
	SJTuvZMD8pyn2erMw9M3ZN4=
X-Google-Smtp-Source: ABdhPJyHoyeezVc0OJUxpJqynbCjcM9uaRQqV2CV+v+DJfXNlgQDB7RAmGimgK0uwQD73dWTCG3FmA==
X-Received: by 2002:a05:6808:6c2:: with SMTP id m2mr3084489oih.63.1632221493056;
        Tue, 21 Sep 2021 03:51:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7b4d:: with SMTP id f13ls6009775oto.11.gmail; Tue, 21
 Sep 2021 03:51:32 -0700 (PDT)
X-Received: by 2002:a9d:7182:: with SMTP id o2mr25438091otj.173.1632221492714;
        Tue, 21 Sep 2021 03:51:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632221492; cv=none;
        d=google.com; s=arc-20160816;
        b=hdoVjVJnt+D1aAZdK4Vr9BdJjXSOuPPszvNKrL4OF423CRz88qorFP2kkia1n49JK8
         FUiOFJGd3IlvRedhX3Wj9RCRHvY5l4IqC2akiw+Idvg7JYkJRVQnAJxVu3a5NkFMzDb2
         VGsGJcoSvE97sMTBZ0nqRcO9A07fxtb83IzjnoOjMpukIspZa5/CjTMK2SYOqhsjYyMa
         uk1lbyqUNYDKQqZvCgn1EJZPOWq52qKpkmygU1PO88lzoJ3e9XvFthxGhTb46wNlE8gL
         adP2Rbngo6c+QcKyrM1T6Af3kcGwI2Z72ksQ7/U4ZOUndI27AmAAHEaRc7ZHs7LgIeNz
         HU5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N8im2OS98fNlJW2Ij6zQsDpm5TLK4cuMawMCjuGiTZU=;
        b=YQ8nRZmxLxULe3Ep5KJehGxO3cKCvLctpCivI+c5dmFvB5Bt9neNqiLq0Ssx1wOP5N
         Du0ai+5isyx6TWXQ71KDiBZ4UvK0aLCRE8LZY81YIKGnuitHECzYg9Wc2e7pVU/JKoYQ
         QEFGZ/vqzDBWIGbbH5lTzOd/UQnhlHGM2eNKYjginQpmOapmalJ874+wR8oMHdvfQhIu
         8TNF+M9RooO5E4emB7Ffv7rYD/F6ahIuO7Zi3jHRH1ANd98cpy3xCXB10lh9A6KzJ90L
         KaSZas7ZwEQ2QrvyE+V5Zh9X4ltye/XI1w0B63BMieZ1u+VzuU4nxG/PvRYn44MMjGyy
         TZmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RR3cWHZ7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id bf14si226108oib.0.2021.09.21.03.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:51:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id x124so5490850oix.9
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:51:32 -0700 (PDT)
X-Received: by 2002:aca:3083:: with SMTP id w125mr3028189oiw.109.1632221492218;
 Tue, 21 Sep 2021 03:51:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210921101014.1938382-1-elver@google.com> <20210921101014.1938382-5-elver@google.com>
In-Reply-To: <20210921101014.1938382-5-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Sep 2021 12:51:21 +0200
Message-ID: <CACT4Y+aUUNFvVsA86D280e4JqaQ4UdesMnG-+DVc=9v59_ZsJA@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kfence: add note to documentation about skipping
 covered allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RR3cWHZ7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::233
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

On Tue, 21 Sept 2021 at 12:10, Marco Elver <elver@google.com> wrote:
>
> Add a note briefly mentioning the new policy about "skipping currently
> covered allocations if pool close to full." Since this has a notable
> impact on KFENCE's bug-detection ability on systems with large uptimes,
> it is worth pointing out the feature.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * Rewrite.
> ---
>  Documentation/dev-tools/kfence.rst | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> index 0fbe3308bf37..d45f952986ae 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -269,6 +269,17 @@ tail of KFENCE's freelist, so that the least recently freed objects are reused
>  first, and the chances of detecting use-after-frees of recently freed objects
>  is increased.
>
> +If pool utilization reaches 75% (default) or above, to reduce the risk of the
> +pool eventually being fully occupied by allocated objects yet ensure diverse
> +coverage of allocations, KFENCE limits currently covered allocations of the
> +same source from further filling up the pool. The "source" of an allocation is
> +based on its partial allocation stack trace. A side-effect is that this also
> +limits frequent long-lived allocations (e.g. pagecache) of the same source
> +filling up the pool permanently, which is the most common risk for the pool
> +becoming full and the sampled allocation rate dropping to zero. The threshold
> +at which to start limiting currently covered allocations can be configured via
> +the boot parameter ``kfence.skip_covered_thresh`` (pool usage%).
> +
>  Interface
>  ---------
>
> --
> 2.33.0.464.g1972c5931b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaUUNFvVsA86D280e4JqaQ4UdesMnG-%2BDVc%3D9v59_ZsJA%40mail.gmail.com.
