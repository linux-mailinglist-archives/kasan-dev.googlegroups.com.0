Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFMUTOJAMGQEZNRA26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE6A34EEAB2
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 11:47:02 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id g69-20020a1f9d48000000b00343eed5c697sf167008vke.17
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 02:47:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648806422; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKD3tILjLTBXa+NI4L/dg9W1oayxAn+pCbloHVGdS0B0fFTZ3i3NkcWMSGKHE35usE
         zSaoUGMeHsVuSjdtNX+sBtd5E2MK3E0mwqfYvUa1gw8qrmEtmQjVJkHdDp1z/Hy1wnY6
         hvKAssmV0wTPbFDZQfXG20A1wKOUtCU8r84agnHxkQZq6miEAVe/n0uPLL9vyY362Uhd
         f8Z3tPCdpFLz9AjJMo/+88l77ILZNAoFYRPPF1Em5SChnX2/2i8tz3jHKoYy4qjlfdjT
         n4bygKv5RDCeXz/nv7AnWgGrFzCd/UUeRPCqddzS+AZUo02+WbdSEq9lsBGp69/+HbG7
         bSxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q2voUx2s6fGRKvUTg4OisbWpUmtw49aFyEa8dgpVOf0=;
        b=vco8tp9fNouYc0OyAP8wZRDe1sYYyPP/nvUjs956yq+F//ARqcSTJcVVmJRGoPxrGe
         b9UKK7PjUXkLXrSQJa03svCwBOJqzOWNevKj/5smMiIih2rV6ak5YsNzR7Gq/41dd/DE
         1GWwWyC5beUzHhB+NE2Q7t2YvMyga0YpF/Pd0gP2Ryinz8+F+7VYV8E7MeMOWuoRdcwU
         Mbk+jY4zgFD/wDArGqPT+sbi+PWaGSyTAhK/LNBcG+rOkQcQSSUB43q3hsZgYcksQ62s
         3pOW7/+erxpwbM4BJpR92H7jLRAG+ND3jui+Dm7p1aUBiV2XcxEA+7GqEtz1drmfY1/N
         BPmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T7TFO+XX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2voUx2s6fGRKvUTg4OisbWpUmtw49aFyEa8dgpVOf0=;
        b=N6VNyeag0wVoTYuZG2KQInm+4QLcb0OcK5YoO66ZQmOcLOk8ayY/VaB2vZs5Qn6bfa
         pifIO6rivXiEcC/DioZn2wmf0UJpHnn8recIGR6bZJyYOnycvWLwXXbhNw8eDNxtK0Fh
         z87cKso5PSCA3ltlGPrf2Bwp/si/Y7NHsubb59aN/ogOQvmmRpXaTB5poha0RPqPOXoL
         7Xb74xERVPo4A1O0u8kV69ZCzHoFbdytUAyWBvP5zYwinYXhmkm1aIAgDqVkEehX7Zb6
         Im4QDUuT6PH/hPE7qBJ1/EEFeUjmnMBQpcaZYSXPaNZ7PZi39nEN/e+Wd1dWylnlDlfO
         5+FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2voUx2s6fGRKvUTg4OisbWpUmtw49aFyEa8dgpVOf0=;
        b=1/i2otpMMhej/b1CcBjkLJFS4Qb5sn8vrsrzQ4krXO9ZAnxddwHYK0cfDDlypZ89Rz
         pyRj/ufyIU4Ldqe4dEeYDS/dus5xtN817VGlHEMHK40/B+9gIbBNh7aeWWIus8FUabjF
         awZ6xqmUQX76LBNR69A63yjIMd04Cv3kZVPzOZyRgicOA0IAs1V8R2t6xFCtNy1/BRE8
         7jCCI+DDgXBxc7UNWzHaCFDiBdDWdSmx/m/LNuAM6Yv+NPqileYGLyOHScsNv53nhWLB
         NFHxKJrWh+g8j2OvbWnAaBcMxcxiyeXoSvUx63hq8/45mGSyhGMg/eZKpCrrsNB8No+8
         +1Mw==
X-Gm-Message-State: AOAM533h5HdcwH95whutMRr71ckhjCGvq8ph+vHOBmGsG2/SbAY3oCLB
	dvM01jkzh3u+OsYDGDDEyzM=
X-Google-Smtp-Source: ABdhPJx2ai15/k9qmxxwb6+FWvrbCdPNnb5zjDdGvrf6B4Eat3Ev2MWFXve8dwiSzRoKe1LZu51s7A==
X-Received: by 2002:a05:6122:17a2:b0:33f:f9b3:bc11 with SMTP id o34-20020a05612217a200b0033ff9b3bc11mr21730449vkf.9.1648806421851;
        Fri, 01 Apr 2022 02:47:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2b12:0:b0:332:61fb:7093 with SMTP id r18-20020a1f2b12000000b0033261fb7093ls196143vkr.3.gmail;
 Fri, 01 Apr 2022 02:47:01 -0700 (PDT)
X-Received: by 2002:a1f:5f48:0:b0:343:fdc7:60f5 with SMTP id t69-20020a1f5f48000000b00343fdc760f5mr401300vkb.28.1648806421364;
        Fri, 01 Apr 2022 02:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648806421; cv=none;
        d=google.com; s=arc-20160816;
        b=tvYHe+cxeyh8XPi6kRO+PYQLS/UzoFPFWieYgcnu9KWIsV4zVJts2HsCW7V3TrYQTk
         OXdXwUb+oDooM8ncpI4p5KaGuFueJkuVOLEpDcq9hzaWPvISO8FiLppRwP0hKxcrCOZk
         SuIjraPejCRRb9v8bkcPKWXYOBLrVmlAsJjLQ/OTWlgp4ncl8xcGCXZmlpOaCS9D3a5d
         s8S325cTrBiQ2aFvmswiV3iaXSI63UM0dMDvjhB8+srvLhb5znWRHN1giFh97hdSA5QH
         LXCxl4en7YTIBDROBtdrdjPY+zoBmEl279jUtg6YlWFutyA5sARnUPmgTEEdl11c0dEZ
         0bvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GAYB7YHwkTinDw7E1Hr055TsYKSrU9cTtU3idS1nwFE=;
        b=If6c22C6YKoQkyRfqOPfTHpKcS56G4PFWZI1Y4qdXcSN8s54nZvPpt80Ste54AMqw6
         C4BPDJwHi5k3qHx/8vdAsXuQgJEZEs61AVDZ6miIVw+wSUxlL1ewQrgGg3GkPnAe8oG7
         RZ6L/FOMXkh2VNb/Hv3Dg38+ZfGEtROZ967w9VkkxsWxPRVT/z7PXYJmlw6qZbjwMlFi
         pV8/sRDqtKp0tyfIf9QBLylx/KpOkcPZZ3bjpi0lnqsDjN19hUiI3HDYfbunahI7ezdq
         /W31BZuFk7Ga/TO7/i60X1GoGBcsKMIXCUDNpntPLstWHBLlNO+JOqRU8gaskQPX3/eB
         5ohg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T7TFO+XX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id i187-20020a1feac4000000b0033f51726b1bsi148332vkh.4.2022.04.01.02.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Apr 2022 02:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-2e5e176e1b6so25962067b3.13
        for <kasan-dev@googlegroups.com>; Fri, 01 Apr 2022 02:47:01 -0700 (PDT)
X-Received: by 2002:a0d:c306:0:b0:2e5:96ab:592e with SMTP id
 f6-20020a0dc306000000b002e596ab592emr9300635ywd.316.1648806420888; Fri, 01
 Apr 2022 02:47:00 -0700 (PDT)
MIME-Version: 1.0
References: <20220401084333.85616-1-nogikh@google.com>
In-Reply-To: <20220401084333.85616-1-nogikh@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Apr 2022 11:46:24 +0200
Message-ID: <CANpmjNO=qjoY+8m9Nf-8vanFZTgsiDwfchv_JsLoksFKwU98BQ@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: don't generate a warning on vm_insert_page()'s failure
To: Aleksandr Nogikh <nogikh@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, dvyukov@google.com, andreyknvl@gmail.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=T7TFO+XX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Fri, 1 Apr 2022 at 10:43, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> vm_insert_page()'s failure is not an unexpected condition, so don't do
> WARN_ONCE() in such a case.
>
> Instead, print a kernel message and just return an error code.
>
> Signed-off-by: Aleksandr Nogikh <nogikh@google.com>

Acked-by: Marco Elver <elver@google.com>


Just minor "process" comments:
1) There should be a '---' so that the below doesn't appear in the
commit message on 'git am' and maintainers don't have to manually
remove it.

> PATCH v2:
> * Added a newline at the end of pr_warn_once().
>
> PATCH v1: https://lkml.org/lkml/2022/3/31/909

2) We should use lore permalinks, because lkml.org isn't official and
was actually down most of this week. v1 was
https://lore.kernel.org/all/20220331180501.4130549-1-nogikh@google.com/

> ---
>  kernel/kcov.c | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 475524bd900a..b3732b210593 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         vma->vm_flags |= VM_DONTEXPAND;
>         for (off = 0; off < size; off += PAGE_SIZE) {
>                 page = vmalloc_to_page(kcov->area + off);
> -               if (vm_insert_page(vma, vma->vm_start + off, page))
> -                       WARN_ONCE(1, "vm_insert_page() failed");
> +               res = vm_insert_page(vma, vma->vm_start + off, page);
> +               if (res) {
> +                       pr_warn_once("kcov: vm_insert_page() failed\n");
> +                       return res;
> +               }
>         }
>         return 0;
>  exit:
> --
> 2.35.1.1094.g7c7d902a7c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3DqjoY%2B8m9Nf-8vanFZTgsiDwfchv_JsLoksFKwU98BQ%40mail.gmail.com.
