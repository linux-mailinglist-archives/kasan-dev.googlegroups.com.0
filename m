Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HH72DQMGQE7LDFLXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 401223D704F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 09:21:13 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 30-20020a9d0da10000b02904cd320591a0sf6908041ots.18
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 00:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627370472; cv=pass;
        d=google.com; s=arc-20160816;
        b=IRdkueBAKv20wJ0rHnXpGeMtOVLIagGW3lVnIeyBpwiGHIXG62O3kTNyVatqLKXoCx
         qaSEiSX7drQfLd0neft3oNnSZSNmZM5Yas+bCQsVXB89KUY96+YNi1GnrhILXD2Wgvjx
         9srDikCBwo1v7tK05/EJn3NS0jfYdkBQRLKQlPQ38U8745I0Xj8ZYiooDsGe2tD6rbsr
         o1UZKK1fnNQGw/seWIqsLPx8RZ9R6Yd/vyKznbMfVPwpH7n44hMnaWG0LMjF/Klog9qv
         IrYFOPOvrj8d0xcfZ4wrmCLJgNom0e0bKqREjfjoCWOxPivlgcc3KPDKG8bIWqNN35ng
         +WsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gh1lhk8cYAkwUbj0QabNXXzH+nKBqMG0PMZBx+xlpyo=;
        b=rQrbEPjHeugqmBhN5n2hbRXvllSR7MjBqjhnAsZOGScrPJKyusiGmyt57xEUPiLU0a
         B4F9jeOrF5sCF2tciPgsvxG4CIlfAuq7RT+1MrdXZU9hwNteqDur3JajmSLXQWsyrXVu
         OT4y3NM7z54C0aMWHsitfMAwSxS5W/V0jYEUQAztuH7Iyy74XoprwM019Itp/fF0MlwX
         GiQd5FSohNJdjfL0FkjtX9I8BlQvc6+lNucBnRBS0mAp4HvhOMPfaxb8Z9/de4ov+NN1
         bUsfz9jYb8NNPzBkkEFqQydy0nr8nxXSuAo0Iah7HJWW65UdCt+BV11XDzd7DoIgC5Ti
         J4xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZr5f2Un;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh1lhk8cYAkwUbj0QabNXXzH+nKBqMG0PMZBx+xlpyo=;
        b=WQdJWATwJzcGZv0LFb++ovl2mbRIMu7nPVE4cCrzM9BRAZ6CmzYbchkVZxkwA4hdE9
         xs4Xx2YLod3/yhtnLeX/UHvrDQvQdLNxGNbw8QRa9QVyd98CpKlA4WRH6SlYVk3FMfXN
         N0YJwgvVHNKVJtnApLqoAXQolpaCqA8ypEKGbe5E67Ehu42mZptAwWM+v00s6KNC9KZ2
         fLSsu0aihROqhDbNdBhNKOCWdt3ZpMG6UEqJR4J/eJ723cPEkzQMSpCF50y14X26J7hj
         KWZ+tVRyTPpx9TtlU0u7CWza4eLmgaHCHiBxWtTbuLPp+C5XGSRKBzblyff7ORQXEhEH
         CduA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gh1lhk8cYAkwUbj0QabNXXzH+nKBqMG0PMZBx+xlpyo=;
        b=qJAVNxhSiV3AjwY6mRW/nFbYwZcLvO6J3mtf/NWTyq+VyDhodAJMKl1QkWT4DVgXQU
         +nJsL4UpqVDQNo1zqOhvofWHAMaLceopQ6ct3cby6rUVBCxxAZW+uG3z3eVZ7QFbeTXO
         Jnc4pzIuVK1DT7JbSZu5T0lfDVih+CbVGMsAKRD5hGS310qjuLDnnwzX9oi0DdFtEDn3
         V/wrsZucZcpfkivfLA7iC2kp0+rDDeH+MUYAaLlWTC8V390d6lBW3RJ2zW2hl2OaVb7X
         zmV/Q6EzDVcLds1UouEH5IhbKbGZox2cS1Fv+6S29PWgYvKSXVK7fAoSCOZFBJFOKdp8
         QY0A==
X-Gm-Message-State: AOAM531FsHeBkCAfmQ6SfWTo/fNuUHPXq2IkfDYATCJ0xmQm8W1ZEqwJ
	9iEze7xHdF9R7IbOSi14goQ=
X-Google-Smtp-Source: ABdhPJzaaE7w+ByPqdH5+Uo/KUE37WqF6NKwuypf2gL93Lu37Qc6RkOFEwpbM73fxzqzCsuVw4jV+A==
X-Received: by 2002:a9d:5f87:: with SMTP id g7mr12751844oti.278.1627370472218;
        Tue, 27 Jul 2021 00:21:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a81:: with SMTP id q1ls2857113oij.1.gmail; Tue, 27
 Jul 2021 00:21:11 -0700 (PDT)
X-Received: by 2002:a05:6808:194:: with SMTP id w20mr2009352oic.142.1627370471858;
        Tue, 27 Jul 2021 00:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627370471; cv=none;
        d=google.com; s=arc-20160816;
        b=RP4FPWJ1+Lrhwt5XeTPfTY7sldd809/JT2cDeZtSF5of7Z6epIofRTWu7p8/uckXFN
         cMM74S0s+rL5sJvwUYI0RODbt8UsErbF5CEssLABNqDer2yhF0sjy2LPnWtcM0l4NOyW
         lDo5gK73a999Ady+EG2O0RhIciBXmRkeVRf1mmlwgysOglJ+kcLl98a9WVrGGAO9kuAT
         GGq17/OlX7UVhsoT2jxo6zu4GNCo/XYLr08QGczWIl/71/9nDlzzDgbax+AkXogXPDzV
         nETrmAiyjj9RwG5wbitsf0k2UCP8PQZzQCy4m0CkMZzOr2gpqnwdkujNNR8no4eBCPSq
         pAhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yQhhZe+MXmpfkLnh85/Z8tkXEKIvw/AuYXzOfTRKZJE=;
        b=EvAjiLdDr8TNFZ+ejyPWs2/GF2wfyWrOTqXeY0dD50FLdbQC+ggmsG3xcfI7pUstfw
         LvLFrYPZsubg39ttbd/FCnjKD40/WBu/xdWYyMZMh6RTQ/npBeVCf7Bi9yaIk3aFCxc+
         QgH8ynhnw9DaMXeePntpT0WvPWWxa6nyc9VtySRClK3lyGcqebamXAhSyfzcvcx0zJnJ
         rf1hwbSRZBnGIwQDtDHwjmpu/R1HWmslGC+6S1KXu57bQCudM/lrijhJA/gWCdoogD9k
         BOVmOJIgF0oNSfHFNazv72EtrTyCbWPoX0U955unFszgQ72XIjuSU298DLPHkd3Qx43n
         PH2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZr5f2Un;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id j26si304671ooj.0.2021.07.27.00.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Jul 2021 00:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id i39-20020a9d17270000b02904cf73f54f4bso10730112ota.2
        for <kasan-dev@googlegroups.com>; Tue, 27 Jul 2021 00:21:11 -0700 (PDT)
X-Received: by 2002:a05:6830:23a7:: with SMTP id m7mr14536006ots.17.1627370471381;
 Tue, 27 Jul 2021 00:21:11 -0700 (PDT)
MIME-Version: 1.0
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com> <20210727040021.21371-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210727040021.21371-3-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Jul 2021 09:20:59 +0200
Message-ID: <CANpmjNNOkCspsf4=gPLLw=29vtv4qEDaErB1i1sz-p+bzLxNKg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan, mm: reset tag for hex dump address
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang <andrew.yang@mediatek.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PZr5f2Un;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> Text is a string. We need to move this kasan_reset_tag()
> to address but text.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

This patch also makes sense (I think), thanks for sending. But it's
unclear what the problem is. The fact that when the address is printed
it still includes the tag? Or a false positive?
It'd be good to clarify in the commit message.

Here I'd also use a more descriptive patch title, something like
"kasan, slub: reset tag when printing address".

Also, I think this patch requires a:

  Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")

So that stable kernels can pick this up if appropriate.

> ---
>  mm/slub.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 6dad2b6fda6f..d20674f839ba 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -576,8 +576,8 @@ static void print_section(char *level, char *text, u8 *addr,
>                           unsigned int length)
>  {
>         metadata_access_enable();
> -       print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
> -                       16, 1, addr, length, 1);
> +       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
> +                       16, 1, kasan_reset_tag((void *)addr), length, 1);
>         metadata_access_disable();
>  }
>
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-3-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNOkCspsf4%3DgPLLw%3D29vtv4qEDaErB1i1sz-p%2BbzLxNKg%40mail.gmail.com.
