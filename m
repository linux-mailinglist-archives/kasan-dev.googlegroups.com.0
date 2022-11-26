Return-Path: <kasan-dev+bncBDW2JDUY5AORB4MPRGOAMGQEWSSVADQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C26F563975E
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 18:08:02 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id s68-20020a257747000000b006f0a255dcaasf6182432ybc.2
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 09:08:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669482481; cv=pass;
        d=google.com; s=arc-20160816;
        b=o465zOUY6gHuykkZcmCWdC8m5yM28FokP4kSzA1RU6k+/x90fPIUJSSSyIJbDhLX/r
         7PPz5sSPHFjwSx9ccr4cvTWajJlJwXobN4V0nNRdYaOfkyjgJXoPaIEVWjw2Ohs/c8/k
         4f9B3/K/RcljIq7ClUKNrL3Xo6B6XZ+X3ljVgeCSFdLpdHQiW/DBomW5z82R1QJVf58+
         G5I2qoqdUhRHeIAwIdXtpfF6Q8g+6/wg3itU8Jvi0GNqhIGl17y2/RUIUSaMjrKafBJY
         hogWIw89G1+DnS3kguuvOq75kDTbl4k6eCSKMI1S3ECGZ9sDRO7x/axabnggtTzZx0ZJ
         Z3Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Eolq/YVmwQ69/8dqqsjXysi6LH7R4dUHR8k9GhIkdA8=;
        b=VTzHFbpxnqzfuEyS9tZxHBVoHO/I42BKybzSKtqAz1XdSGTDqK2jiDM9HSvFDydqim
         wif/KkpetuVskExOJwfs64MOB/pdmvcQcSTQJ72xawMcNfdyWzWe9GAdlw9lqkGSZYHs
         O0R6sQzX+LAXs67XXTKAjjhjx4J7wA3IIKXxmvakRYgdcI2YZfJAXWGB4y5Z0EJjiAgB
         XIa0ygLeja2zL+SWvcTVl8EwEPlVdmHOay/OBCtB+EQ+GSsBgYoxerP5SYfVrRfceBcS
         PxHEQYSKgt4uyP8Qry+/SWvo397HSh53pTSSGLhGiHkPegpMaOzLcEyCMeH4M3SbeSKZ
         kf3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P0DneLpT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Eolq/YVmwQ69/8dqqsjXysi6LH7R4dUHR8k9GhIkdA8=;
        b=bdcaX7K0Ju3ZakI9+cbVlV/FpJIM/q43ZdPnVwRdK+ZcE+X/jXkM3Ozw/TQOdMF3fM
         jBbsN07VIX28vgxs5IlDWFVmyS2SQythgwWqJ54AfPDVF8PJ9MirlOOWqwABpMIvPpUw
         wpA7Rb5MEgh4BKXV2RN1ZXSvaGZa4VkcicGP0LVQU0MbLj6KZWrr8eE74zP51h+SWxV4
         QeOD5ye00G+7MOFQ68iHcu8+wDjViyPeQcDRbSXCBRnc3LVhELqdtMAGL8T56iflC5eR
         gPIUA9TMoEbnhPIXtnTpoPGBhhXshkrUmOWONr2OGFeezAO9K0wfQLCIfFCWRaU2kv2Y
         fTWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=Eolq/YVmwQ69/8dqqsjXysi6LH7R4dUHR8k9GhIkdA8=;
        b=BB8i7GbIsznLG3vJhq0pALe33Bp90Gurz5lpk4uNKh7Cjnyg/HIwmPKue3B47GzxI3
         Kzh5cre/KGe2mVOuPNtCLcj2jIzip37psE4fj1HAiE1uxdm8hJg8+KSKS/ndtqBkFZmI
         HPaherCNEBLoaaK+jt8/BcfUl/bxtwAMh6NADV2bLebds3ETmOs+8FPb5xW/0gsEjfg3
         CPLTPInkkeop3qq/SV+pFJTpQhJRgvMDOyi0Fhpm2yuBHJjBvvihPlo9AyHCn8X7ZXcP
         AyoOI2L/MG6iiaYH7d8Vk+jEXQOM5XTIi//+uk0gG0mwuh9Tssl06X6j0y2zU9VY/dDH
         G9Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Eolq/YVmwQ69/8dqqsjXysi6LH7R4dUHR8k9GhIkdA8=;
        b=q9t8h5IWxbRejSGhFlApg39Vi5EzZLBh6U1lYq/vaqQqBsmbTT9gz6wx8QUFCbKZhy
         Eo6WHuzqFLXzGqlyIFQ+Hwpy3QfSyJVElYbwNQLdG6CrHJHo2Gu2oDXOgRNOSPZRLyrx
         noyGwI0uDCwmckTkj/4f3mqh80l9SdC0CJ4lJ5hTF41xQ/XRVQ6UrNYloKOO+UYeepxo
         p3PP798P2BsNyOP/Njz3Km0DgNJuhIgQX4mF6tXW1Gw4OMaS2uNdgggCcQpr29Gb6gsh
         vjZmnggccZIadeN2QzvS0csEwtIuWvVSh4sQqupk9K4F7TmRaBIAd7XjI1Mynfvg4E17
         dpPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmrlNrc6R5Mt3JECHKuFUsOq6bvzGsJM4qFEy95fKrv/XK98QiF
	bx1zafYPLvJDQegQaqdexQo=
X-Google-Smtp-Source: AA0mqf5gab6++rQ7DlEBI1XrXO+RvFb06ULAyR7Pmn+yaR4pxlP80wuC84VOl72HHGlSEV2bmM36WQ==
X-Received: by 2002:a81:af27:0:b0:36b:efc9:fb13 with SMTP id n39-20020a81af27000000b0036befc9fb13mr24553694ywh.324.1669482481577;
        Sat, 26 Nov 2022 09:08:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:abc4:0:b0:6e9:8659:fad1 with SMTP id v62-20020a25abc4000000b006e98659fad1ls3610635ybi.1.-pod-prod-gmail;
 Sat, 26 Nov 2022 09:08:01 -0800 (PST)
X-Received: by 2002:a05:6902:1444:b0:6f0:4680:4059 with SMTP id a4-20020a056902144400b006f046804059mr16781407ybv.280.1669482481065;
        Sat, 26 Nov 2022 09:08:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669482481; cv=none;
        d=google.com; s=arc-20160816;
        b=Kr1eEhOT2fqxhsUXwc7l78C/rz6KeFktIcWXIewWJxfKmaPy0zcd0W8HXXM8pp3Iwx
         ON3W6QfbVt8ZKIvtog+BfU1206rSwBgHtisvQPa4sgVoSMLD+FOS1Q4ze77M7fzlxQgk
         hN4sxflr3fX3O1rGtDIakseIg+cWkjcMez5MS/CLLdtgAKH9wJknqr4UzrOs35QeaVhL
         zQUGyZyaE876gqyuJmaaoOJKnSfw7QpIvkgHlMuPICU8bmALiAjsIU0dZPqKA2/au2+v
         CkuYBXM0Pvp4Wc0sf+bhjNBJzwAKSHF9w0aK2aBGEX8vTzIMeK7Un3mzdsYcTqAVblag
         ia3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7x63YXZnelPyg/pT1Bm48iuMcv64hm1Pn46j5qsjmRE=;
        b=pTSljOVcEUI5Lx+7xczMAVyHDvxRGehWTOx5eaoHNHrdca29I6gQeQsyYgO2IqPRPv
         6UnEQbdU7wdOxXISHYPXU6UuCwUXovOtO/RITT0ihcJODb/WFPU1ml4yG2idYDvw2IbW
         3aihq2iZNt62G2JgQmq2nEBLNbpNrBZWacvNPPuBuauXnnc84vVnmw5fi8uILZQJHZ+w
         q9SsDOe8TTK7rFu9Jb0YFUX5La430Y/sAr6RKOX53SOvH+swi+hXL/qHgPxLwf5Ty/qV
         KNOfW+Fn+IijcLb9BOrs7YgMIejyXYRjtT5k7o1oMI1Tx30P0rec+J4miY6JMhbCo6c6
         x89A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=P0DneLpT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id m134-20020a25d48c000000b006cfe797b938si452306ybf.2.2022.11.26.09.08.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 09:08:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id jn7so6526370plb.13
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 09:08:01 -0800 (PST)
X-Received: by 2002:a17:90b:888:b0:219:1a88:727b with SMTP id
 bj8-20020a17090b088800b002191a88727bmr4234546pjb.47.1669482480360; Sat, 26
 Nov 2022 09:08:00 -0800 (PST)
MIME-Version: 1.0
References: <20221114114344.18650-1-jirislaby@kernel.org> <20221114114344.18650-46-jirislaby@kernel.org>
In-Reply-To: <20221114114344.18650-46-jirislaby@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Nov 2022 18:07:49 +0100
Message-ID: <CA+fCnZfBa+MBiAYPOh_djkEcoDY652pViznDQnqX708VaxuTOg@mail.gmail.com>
Subject: Re: [PATCH 45/46] kasan, lto: remove extra BUILD_BUG() in memory_is_poisoned
To: "Jiri Slaby (SUSE)" <jirislaby@kernel.org>
Cc: linux-kernel@vger.kernel.org, Martin Liska <mliska@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Jiri Slaby <jslaby@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=P0DneLpT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 14, 2022 at 12:45 PM Jiri Slaby (SUSE) <jirislaby@kernel.org> wrote:
>
> From: Martin Liska <mliska@suse.cz>
>
> The function memory_is_poisoned() can handle any size which can be
> propagated by LTO later on. So we can end up with a constant that is not
> handled in the switch. Thus just break and call memory_is_poisoned_n()
> which handles arbitrary size to avoid build errors with gcc LTO.
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Signed-off-by: Martin Liska <mliska@suse.cz>
> Signed-off-by: Jiri Slaby <jslaby@suse.cz>
> ---
>  mm/kasan/generic.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d8b5590f9484..d261f83c6687 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -152,7 +152,7 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
>                 case 16:
>                         return memory_is_poisoned_16(addr);
>                 default:
> -                       BUILD_BUG();
> +                       break;
>                 }
>         }
>
> --
> 2.38.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfBa%2BMBiAYPOh_djkEcoDY652pViznDQnqX708VaxuTOg%40mail.gmail.com.
