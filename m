Return-Path: <kasan-dev+bncBDW2JDUY5AORBMNGTS6AMGQEXJO2TPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D619A116CA
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 02:45:24 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-30033ad0158sf38219311fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 17:45:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736905523; cv=pass;
        d=google.com; s=arc-20240605;
        b=bSCdTJ87QaWNNSbkNkio6EZPtzaTrLN4dGg4RMCKqHcAUfnKMqwE++Lio5Mo6RzuJU
         HCetjl3jhkJ2aAEz6MCU8PpE/5psqNabyCyj2JaddscfqBxN4sc1wZMCDyuYIDGcv3kK
         WiV9a2KwdOKMiW9WIR6jwHocBWjXJovetMkA+SshjVzOiJvVJ3Kcfq6dru2OHLUGsdxA
         kDmd5SNivgOz+/ELhZg+QqeNA4MHssf38kS6NYlmWA+/i2Gvi0W88CIaUyN0iZwxridw
         MtUBsGHas/vwMdXB2hrgwrgoFQg2PRaH3crKxYi4+6LQQzhEd7Af6tnLuD3CeNOV4KQd
         8wSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xp447Jv2YxCj2fKmob12UGVgu604BMcRAKxa096EJWM=;
        fh=G2lqHerzQtWtjvybkTw9JutsCBBRDEjM3o/73ZZ/yck=;
        b=NrgddtSvZwW/Zon7VlHvssWSLLJZokyMY1J2/Gad1z3038hMcbxbmSmm5WIRpmyHTv
         ZxFs+/HJ9Tvt6MDpMqDW2NfhCBJySB2/pyyo5e/kiJpQ1P9L57V2YLfRcoZ6OCzQI/73
         m+t/oLFuTiJReeexkkpKRWm47/J9GLmc7oqr0hvVdDgTDX31W0Yv+BuRcUWcuUCWxGyK
         S1PkL8FlBJcG4Ot+F5K+ZDUfkncIELTmO79n3Z1EIgBId/OMKkLi52x7mbjN3O25Nmgi
         +A5aJLuxTxP8MsGAGmmEt6NE5x3i80M+vkbzZKdF95tG7UNe5YqgGQXuAI4uB/gqJEAq
         g8DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IlAmIspD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736905523; x=1737510323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xp447Jv2YxCj2fKmob12UGVgu604BMcRAKxa096EJWM=;
        b=F277t0JADZMIFFXcbpRWbG+/AS+ai/lTkW+NfGujltgOHprioa8kgdwvCP5X4uaB5R
         xCglip0IqwKLhZOxfQ5nTCFEwHtFCtKS0QD53ixA9ZCMijRx/DyqUgW4hFfO3cZe8gv1
         P4khChmqvUxV7xAMHpjl3n4sYdRO9+tpDMTQJuvA4sqsBob7ottvflCNU8l5Xz0SlNCY
         IrPWGyrt4zOFWaNWS2MVZeTZtnCV5eFdVP9beyeO6jUmakpSqZoO25jtPYx7w0xVRqfs
         ybACw/ZKppU1+lStkny35B/pGd/mma7wfv8A3l4PLmOIvbmGivwQNA/pSWnnj6GxwSXX
         rogg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1736905523; x=1737510323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xp447Jv2YxCj2fKmob12UGVgu604BMcRAKxa096EJWM=;
        b=W6IV0Qborrs0giCRg3sCz0ye6op+l4BhJ0lge4RkijONnkWONoRjlWyYtqzkz411Vc
         BgD7Q/a/WeKM7SYGEsMZ0gEPMG7rsm2UG3uVocQMhESsHtOP85BzS2R8f1r0O+5AoI3h
         fdJY7axs3yAwBs8t5A57ovsnau9Pggn0aypVIc03K3cyiol5Znr6zmdKWdQ7WgefdsFs
         lg+y98/YEwqF/v+MWou9B2AIg3fFRdWWuZlY4jexTN2IR5HTGFbR4kAsiBDpfbuDUG1x
         uf0esPk/tCtO+fYXKMDhSgq2UZ+B/eRBRdoxsLwk50wHlnSIFcKhTcKiOq1KNriAIcok
         MWXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736905523; x=1737510323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xp447Jv2YxCj2fKmob12UGVgu604BMcRAKxa096EJWM=;
        b=SWVdoKFZKt5aUDmWFfLvU3C0/cQM3XIan2rSWYs++aWKDxUyC4tGP2sLFAfhV930ur
         VkR5lAeNs0TTrVWpRVSnbA/V0ZzUBItMXM4InK3mcYO9nQJbqzY1pVqlEbKY/MFzX9yA
         MLL8WpeDTpoRS6hy6OgG1z1N9DnwwHrgU1w8GSFVEb8lM/0V+xASg1bx1kwGeR4OSnpu
         tXRnbAP8RzHw5HzDNtMrDq/9/cNkD55F26dtPKpV/pZMf1BBjkFhoIqPhzx5Wjbrf+EN
         JOnPqDaFUQ24GM6rsU7sQYRBDvPyI1v4fpvXpAyXC8tdedR/H37cMYY15qaBZ/vEFhI2
         K05w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrN7uGmhHQW31dwbtgdJjVnZnH5SdgRzmsHqKixz+RVsYgMbjuo48Odn9q7A+9cnPWpxY/Hw==@lfdr.de
X-Gm-Message-State: AOJu0Yy5D60tjisq6n5x7kX20i9pnl/BvCY1JmmWCLOanEMdf0jbNEQ4
	tYvnMp0V60pW/sokGmZ/Reefwz2nPAEtp0+tdg63h0d7NmGZYvmd
X-Google-Smtp-Source: AGHT+IFTwFlUWOp9qqLg2BUrKrlKnFizlKLYrzVxkFwRL6jcEKuldS7roEgq4sXsG61uBOrQrpijOw==
X-Received: by 2002:a2e:a987:0:b0:300:33b1:f0e1 with SMTP id 38308e7fff4ca-305f445efbdmr87601731fa.0.1736905522117;
        Tue, 14 Jan 2025 17:45:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b2d4:0:b0:300:40ad:298f with SMTP id 38308e7fff4ca-305fcc42127ls7681921fa.0.-pod-prod-02-eu;
 Tue, 14 Jan 2025 17:45:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXP1e4k2HDPjPBJrXa078fxfcdbhBXlFump4CMb6DzDQ+3u2CRrxibHK+f1CpQJ5O7UBx56s5cK494=@googlegroups.com
X-Received: by 2002:a05:651c:4cb:b0:304:4e03:f9d9 with SMTP id 38308e7fff4ca-305f45e84b9mr90887601fa.28.1736905519795;
        Tue, 14 Jan 2025 17:45:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736905519; cv=none;
        d=google.com; s=arc-20240605;
        b=BRnOJkHhhhAFgmSWAkzjLVE6aisDIE40mqzrzwZvsEh+/OhgA1AOR4W+LpnoY6EJuT
         DvnmhK7L1nsirMO5+/04fcfMc9kbrMSUlQRVD5Ga0/YPl/6nwjIVTJLpExTKQ0M1sL6J
         U48nC3CQWhUwXrHKc5JuoS+tK+K0IJIvJ0zGszbaRoOnn4B5mMpPSL0E9/zjeeSGy3+n
         KYmOXyQxIUKPnbR3m9i7x58S4uobU9pSuyQt3fdejYKf14VlJy1Ny/EnHN8n8jWLRLvj
         yCkUC6ancKUDamfpTj/NAbpZQCXahRckVDu/JsrUpkeziD4TzD+6h9zekN04XIfiZZWG
         JjLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XgmjFYpiTgYIuyIBFMXIOV1VwCqRUL0ypQNex6Ys2Vs=;
        fh=3kDvne4pt+BS3kdB2TDlIPrQ9X086KBFpGF/B7AvbkM=;
        b=cDR/5wveXb6s4vh6H0iiOOui5Qbg2UHEHHowAwri2PMRXmJ9X8kuky44XWRdFLj1zl
         BQVj80f5pN/jfl4HFCHZhUWtW7jhF1s85JRV3A/6DcebMmfmvG61PckLiET1P18xnrhI
         nH/Ych7gY0WBCOS/tGpcX7CMVaQOeAwrMxlVpGN/2x36Uxgjli0h00jzwRKRwq8Aa1PJ
         lVAl4xsSHAaCgG+sQqjSo8YrQaNvT2TpSFDT/OBC7Aaxs14D7GhqM4tzx0qft06XyH6m
         vcdWRW9XD+3gkQxmzS26wmM01vVK4mw9fksNvEBws5SOMl5q+sLXnGJm0LpGSXrz6dfW
         NoWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IlAmIspD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-305ff17f650si2226731fa.3.2025.01.14.17.45.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2025 17:45:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-38634c35129so4315779f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2025 17:45:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUIQN2vObQxs+ji87PKTGgluDxHRvczu2B/Rs+YWxH92WA3L45rzEG5XM97zKPwcaXXEZmAqZxzq94=@googlegroups.com
X-Gm-Gg: ASbGnct1uONJGki6ErSPO4yESD80wvZCriOVHfhqRxZGRoFr13vS9/XWLEqQDoI07ig
	82dbaX1HUPe12QT8AvFjzRJGrDsYbVZHXu4mQ54Of
X-Received: by 2002:a05:6000:1564:b0:38a:8c9f:dd61 with SMTP id
 ffacd0b85a97d-38a8c9fdeeamr21864164f8f.46.1736905518920; Tue, 14 Jan 2025
 17:45:18 -0800 (PST)
MIME-Version: 1.0
References: <20250114150935.780869-2-thorsten.blum@linux.dev>
In-Reply-To: <20250114150935.780869-2-thorsten.blum@linux.dev>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 15 Jan 2025 02:45:08 +0100
X-Gm-Features: AbW1kvbYwGqcyC4Y6wXhnrzsnvagjrxrvLFifv8r0TYXBLZmPekoNR3JilBliOk
Message-ID: <CA+fCnZcqRnHyMfHwXFSFY_4wmhLg5jOsTsbV5oLKx=suBfNXEg@mail.gmail.com>
Subject: Re: [PATCH] kasan: hw_tags: Use str_on_off() helper in kasan_init_hw_tags()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Anshuman Khandual <anshuman.khandual@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IlAmIspD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Jan 14, 2025 at 4:10=E2=80=AFPM Thorsten Blum <thorsten.blum@linux.=
dev> wrote:
>
> Remove hard-coded strings by using the str_on_off() helper function.
>
> Suggested-by: Anshuman Khandual <anshuman.khandual@arm.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
> ---
>  mm/kasan/hw_tags.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index ccd66c7a4081..9a6927394b54 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -16,6 +16,7 @@
>  #include <linux/mm.h>
>  #include <linux/static_key.h>
>  #include <linux/string.h>
> +#include <linux/string_choices.h>
>  #include <linux/types.h>
>  #include <linux/vmalloc.h>
>
> @@ -263,8 +264,8 @@ void __init kasan_init_hw_tags(void)
>
>         pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
>                 kasan_mode_info(),
> -               kasan_vmalloc_enabled() ? "on" : "off",
> -               kasan_stack_collection_enabled() ? "on" : "off");
> +               str_on_off(kasan_vmalloc_enabled()),
> +               str_on_off(kasan_stack_collection_enabled()));
>  }
>
>  #ifdef CONFIG_KASAN_VMALLOC
> --
> 2.47.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcqRnHyMfHwXFSFY_4wmhLg5jOsTsbV5oLKx%3DsuBfNXEg%40mail.gmail.com.
