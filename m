Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3ONY2DAMGQEVGLNSZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A3A333AFFC8
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:01:34 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id e25-20020a4ab9990000b029024aa2670b1csf12884327oop.21
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 02:01:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624352493; cv=pass;
        d=google.com; s=arc-20160816;
        b=oXEAPJnxlPF1DjLwKqC6mwVBiARKmPUZHMQeuxD0YYbVO9/WgDbgwccYzzy7vcmFI0
         Bwo6/a3N2VI2mAfYBhY7F1MIDbFKljrozvmJR11nzOGg1nfRGJmo5NUjymi+SXi47enY
         DpIq/vhlTGXFxXlJKhGCY8hKo32GvWJwjG313tEiAcAW3KY7/7RXFM2HPgzJeuGfsW3O
         hO0+13hmQc+aCxoLz1yLpGAMPXoPROC/Iycwb0YpOQNP+Dkk9Ewb40Wtrt6Bj2PYXngQ
         QU/SCOA37G+ehD+yWQ465kQAztFgVfMIMyMFRj/m5w7icqoDrI93vJ6dp5Tr06FLLUhd
         RGPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UPp8ZhnEYzGIQEigfXlSWDgsyy1lTfkwJrMu+yDU6do=;
        b=VbKKsGmzS9QKz7cspVTV12URASd1ImVO+qf7Fb3Yb7iKi+jmGrVrcOyyplAeHPilHh
         gchjSGBSvi+Jjvl6nShJ3PCfHRSo4P+frlrl/5eHtWSOEsm6DI5DOxO3D1f/8dqXKM7m
         gH+1azcv4TyZ0ZQnnY32mjvsYKEiDtLICDGnDw0ohqNr0AZDYoDv68YdK+OwF80Z/0IQ
         idPoCFotJ19yfYhlmO1ktklpfHJPcsKjII2zE7QLMov0NgQFK/CD2G8sqRxymABQJaXs
         VoxFVZp1ucA/RpLu4AJB8ZXzHPSDQ9xrd5GKFsomhsaL4hoFO8RVMH682LJhuDYzKGdX
         jazA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CB752prx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPp8ZhnEYzGIQEigfXlSWDgsyy1lTfkwJrMu+yDU6do=;
        b=cETt1VqplZiWQze44WxhES2RXtW/rfxPw3JX1weiDecmzsTfPJkk2cl2hHaAHVaBQQ
         MqYiGsoqCU8SSuIVRwZolPAnVatUpaHhOoTO+Ka2Y89N8U3zDDMHo7rHLp+56EIPSzI5
         oABf50o3mDUCx9neotFWK79xqUxQ/qx+6SaOomeoN7dp95nRfzXKQiXgRHTt51p3M1oN
         KgRQvlLHvPqFf1kBjdAlE5kk+bV9yJ1oUBO1KElSNro+MsneId0oihv+XFPPpqMFCaCq
         vFn+YIlmVrugLJD1Bpsnz91ymoekMZ+rJIMvAjgvb6qWyBwHPsP0lj51eVSuVX194S7z
         ZSzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UPp8ZhnEYzGIQEigfXlSWDgsyy1lTfkwJrMu+yDU6do=;
        b=DD1agcVDmbYer4x5FZHyWNA9gsYTVIeVt64kdfrJ9GmR9t4SLjPTskQKHCStaHxn0W
         Rh9sBROE7SbLxnx/yu7M5Xq/PcgW7y0jBeR7iEEifXCdTXRjWdIgNtReg/cST7hCeL6b
         B5oqVkOvEOhJjDoylX3jBBUF+/qU+FFr2eaxEfnhoCIc+O79SvBR+DcaT69Dhq7CxDBj
         3+TNS63wpLn2bIvWT/Pyf7Wu17XB1IOYLBDGfwx6hmqcGo1mhXyumOXGMliq8BEXAYCY
         +bUbpWUnZy65slf3XNR9ro5urr9f5rNSN3BGI+PwWKX/dsVvoLl99kunEjTTHDwpQYjW
         I3hw==
X-Gm-Message-State: AOAM530KIR6cRw3SvVVrXIlTzRmthr5PaQe7ZEPCiYoTxoVyeVC38H1o
	QER20qa5h8PFgaxNNZWPm+8=
X-Google-Smtp-Source: ABdhPJzKoAJ1O2F9etnbfU9PASmb26M1EJx19iDtCo2gYaoN+VwqjthGuj5amBDv9jptkrJ3PEoayQ==
X-Received: by 2002:a9d:1ea5:: with SMTP id n34mr2221898otn.340.1624352493596;
        Tue, 22 Jun 2021 02:01:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9553:: with SMTP id n19ls1981367ooi.3.gmail; Tue, 22 Jun
 2021 02:01:33 -0700 (PDT)
X-Received: by 2002:a4a:e907:: with SMTP id z7mr2413739ood.20.1624352493232;
        Tue, 22 Jun 2021 02:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624352493; cv=none;
        d=google.com; s=arc-20160816;
        b=br7Lt37s6+8FBX1U6/qjgFVAdSwfn4ldEQ4IvrSZkk6jeoKm9qVQtTW9MJfIZlRxKQ
         GAoqkrfBRNITupu+XwEq1lJV/C/QSM4F94uU3MSnXmZfISyUmGCcMoB7XeNK2w2fBreS
         K3GRdlTGb5ANx65zXXqoYGGgCd3+wfBwf45KQ410o04hUO2KgOeLJndK0jMYIc6KzPeY
         4wrzfwZgO/xoixu6GLsPbgjKuxsAwFtaq3gpsEvkY1sDrgjdGiEFHvRXQIG/qyAu2D1T
         qLpU8HO+K4/HDYzsw6/+pJyKbXEZEXAZfty3VFsSAvfErW7t1YZ8YRkp5VDG63751MHs
         BLRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E3vujFtQzQ6HHb36nCRkPnI6sILbeapGxmxAb4EfnkI=;
        b=nnryKxSqvQbvTbmgMqTMO9VUsKB9WCtprMb2eRViGV+knsbnhN5VofB30W4PMVZWZ5
         j+skshgQgdz0N4d5CS/Rllf8oSRkN8BcV8VpUN7+wKKsh6rF8OONPeKDDsoMOEScBPsM
         uXwg378O3ajdo3uorP4QlrU70uoFnf2FPUaEr/5j7261UQvOyJpiHK8GF9f2pWAHUOAP
         fvr9Uecw0TcLqtQSoeeV4sfy6Bi/MxUHxcxtR27uiyLhVQttPdrWP9xwjWHUTXsDuON8
         PVMZ2uKGMEvGH7i2Ek0Uik+3N9y4Qumlq5Lg6vCpE8jXPAjfPxG0DlfLypmw1Fw29K02
         Rz4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CB752prx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id u128si180293oif.2.2021.06.22.02.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 02:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id 7-20020a9d0d070000b0290439abcef697so20544484oti.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 02:01:33 -0700 (PDT)
X-Received: by 2002:a05:6830:1bcb:: with SMTP id v11mr2292496ota.251.1624352492722;
 Tue, 22 Jun 2021 02:01:32 -0700 (PDT)
MIME-Version: 1.0
References: <20210622084723.27637-1-yee.lee@mediatek.com>
In-Reply-To: <20210622084723.27637-1-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 11:01:21 +0200
Message-ID: <CANpmjNPyP2-oULXuO9ZdC=yj_XSiC2TWKNBp0RL_h3k-XvpFsA@mail.gmail.com>
Subject: Re: [PATCH] kasan: [v2]unpoison use memzero to init unaligned object
To: yee.lee@mediatek.com
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CB752prx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Tue, 22 Jun 2021 at 10:48, <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Follows the discussion: https://patchwork.kernel.org/project/linux-mediatek/list/?series=504439

The info about the percentage of how frequent this is could have been
provided as a simple reply to the discussion.

> This patch Add memzero_explict to initialize unaligned object.

This patch does not apply to anything (I see it depends on the previous patch).

What you need to do is modify the original patch, and then send a
[PATCH v2] (git helps with that by passing --reroll-count or -v) that
applies cleanly to your base kernel tree.

The commit message will usually end with '---' and then briefly denote
what changed since the last version.
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#the-canonical-patch-format

> Based on the integrateion of initialization in kasan_unpoison(). The hwtag instructions, constrained with its granularity, has to overwrite the data btyes in unaligned objects. This would cause issue when it works with SLUB debug redzoning.
>
> In this patch, an additional initalizaing path is added for the unaligned objects. It contains memzero_explict() to clear out the data and disables its init flag for the following hwtag actions.
>
> In lab test, this path is executed about 1.1%(941/80854) within the overall kasan_unpoison during a non-debug booting process.

Nice, thanks for the data. If it is somehow doable, however, I'd still
recommend to additionally guard the new code path by a check if
debug-support was requested. Ideally with an IS_ENABLED() config check
so that if it's a production kernel the branch is simply optimized out
by the compiler.

> Lab test: QEMU5.2 (+mte) / linux kernel 5.13-rc7
>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d8faa64614b7..edc11bcc3ff3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -389,7 +389,7 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>                 return;
>         if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
>                 init = false;
> -               memset((void *)addr, 0, size);
> +               memzero_explicit((void *)addr, size);
>         }
>         size = round_up(size, KASAN_GRANULE_SIZE);
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210622084723.27637-1-yee.lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPyP2-oULXuO9ZdC%3Dyj_XSiC2TWKNBp0RL_h3k-XvpFsA%40mail.gmail.com.
