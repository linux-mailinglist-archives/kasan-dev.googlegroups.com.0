Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4FUY6AAMGQEMHQTK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id DE92A3065EA
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 22:26:09 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id o15sf1617101oov.22
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 13:26:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611782769; cv=pass;
        d=google.com; s=arc-20160816;
        b=l0Um0/iKK+3l9I/g4UE+Qqtj0TDnO80CKj5O60EjglFCBbLMnsTB83wz5sLNVfWDFw
         deYKRXqh+Tba5B39iKvGCV6ARTfZEXaOvWgaIBbVxBMUEeEL3eCiIuc2ceBgQdvbO351
         fhTnT7lX5Z3Soy1qKhZ96n9k8lEACtiE2rDNSg3ch9lw0nEQM9b5JuBNLBIMy9ya5YUM
         f4S1d5CVXvrwTTGZWOTJJH9Abf1pb/95jgMumLfEckYkfUrgp25TZBExnIZxIMyZCUvo
         LIg3MRg4xJE4zMILMtsMv4SoGUAFiboP82Tc2OIARGlhQzQpg+Pj4bGA1Z27alcPJZ8H
         dApA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Dgi1FGcMshOAwgx9Py0mww77TH8Jwqd3+dkHZOCItFQ=;
        b=THivKF2RxrwUmCfensAu2eC4Q0h+qQBRSV6yY3/kUSKaVsWphhGMrIBlXe/2kNb7Wg
         Sh8dch1q3+J7X0F7o+5yN1GKf0UDIq9f87XYVDdXyezGM9W6D9M1ASRi8KUN5DPrUQh0
         g28YlBuf/IFj9uIbkssD61EPRoC4EsFwWJoa6VSayQAFaNwUiW01ZeENelbnrPPkGmFC
         n6HAwubXC2tGC9NlBDrwVpMk/4p2HUgpal7cI4Yos6Lt1EsaIgOTxy+sPf3mjtMwyeyl
         +szfyVQyGLl86wgzg2iBFSgc+STlFuFQmA2kBBGyOx1/DK9TLzJfxJRGHlvF1m9IaCjQ
         UlAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pVvARrOg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dgi1FGcMshOAwgx9Py0mww77TH8Jwqd3+dkHZOCItFQ=;
        b=rTPYFZGQP3JnqhjrVEYl4L03FTquwsuoslY4UCloRC2PSoTG1GssB/53iiSbWzTGa9
         ujZHeCvsJMwVAGnFgs1+xjJPFNKMyzT4Mv75t7zPOSVtSmt62mcmWYGHD/xd0oW7epFB
         YtL7A6MhOm0PBRUecN95xN0gYPr1tce2AyoiT+BpYugVkK2x/t+3h0u6ufuzmhadJFKS
         r15OazFtJsAN6LPeIWVNBtMI64dfvru+/qCYy4UDimP+bifeqCSmQqJvg4oe4np0jiaV
         8RSLz62fOTMjZcZJuC7/s+WPYL9DX300rflXdV5Flsrfu6d62d9+ugHi9qCaz00jxtU+
         8tXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dgi1FGcMshOAwgx9Py0mww77TH8Jwqd3+dkHZOCItFQ=;
        b=fJJVGNKM1IEY75f32i7m9XfWhLR3bm3KLOgsMG2PJ42JIZnpF0MFMGj4lc5iP7/bSy
         WAh/37oAY871tEAWefqm3hlWgFn8bSBSHk9mVcF72vQQ19EGtf41Vm/4tVOkOgzvVFVf
         CLp3pAIDz8MOjtHDF1QZQERHU7kxq4hYYBX/s+9H8m6QgHD0Y2OaKw2KorHeNF/G1Ygp
         7/a9HoMCkmww4+UfhpgyVya33xitLfUpis+7SmbTx9UHUF+vZa5ZPjD+vS6VuDoc7jx3
         N74yKMmk3xfjdNK/xNNVbmf2EypAAUO/IXqxHrKeX0a3SvECPrIFxDp0/PWWB3oCnVA5
         DNTw==
X-Gm-Message-State: AOAM5323eS5dbK1nmmxXBbGSbdatjipxNYkCmUDEfZYkzrnA3mO5/zb4
	Tmt4EUjshRTIlnCt7S3TeEE=
X-Google-Smtp-Source: ABdhPJwLqo+v8sJl5CK2Gvld+RPXVng+PciUC2QJN9YcSfWDLEc5nM4UMucpHhK68O/89PS1zrIHdA==
X-Received: by 2002:a05:6830:837:: with SMTP id t23mr9339248ots.129.1611782768896;
        Wed, 27 Jan 2021 13:26:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:335:: with SMTP id 50ls835682otv.9.gmail; Wed, 27 Jan
 2021 13:26:08 -0800 (PST)
X-Received: by 2002:a05:6830:3494:: with SMTP id c20mr9266032otu.25.1611782768492;
        Wed, 27 Jan 2021 13:26:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611782768; cv=none;
        d=google.com; s=arc-20160816;
        b=i8FURc1NguvPjRRwtgZWryoVidFlG+x3xJWWjzec9tZgKU8MWkyVbSn+Bxe42dv/L2
         ZaaNv60Thqo9bJcVS1EB9uBgHP9AWC3CfCBsovd/UdQc8lBi56myHIob9OpFwM4F4Z0n
         ASQ0Pgb3LM+yzqz1CC+7HIkJV2vX0jwUkycLxrEdt6v4MjpsadTJMXGTZUzMyAEyAtoh
         XMAvMUzV/Elxm664MuZj2Ug1j7tCJClsmoKQcNk1vLRFb4J4K0Bw+jLjBs08FqrcUHAq
         Wk+s+M32tAmlGO0kiy+PZMQSlQvhnGkiSbOxP3Yc5vcW4/DKKqJe4DmanBbrcMNsT/nF
         NaNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H4wYdYZxwdbWGzK2JDLYdiHMKyIE6uo335eyGMtSLco=;
        b=FQpY54ZnuUP8jhUGRjNQ7viytnQn/NaNL0gDYw7MUwj74Nxr0JdtRI0erTwYIfdX6n
         CLnw9G0La+6dTMEQXXAXJlg3oBUCQlvSEWF8jNFurEcnyXyWlZFjJCT6u0Wf25Cxe4jh
         Y25fwaHJhP5I7KZlbiuXy7lZaVmDmiac26m48habRZ0tEpvBYlsvpmHSULs/k2wazxTg
         ZkSg2GzVwBKkYHqkftIelXQ99CnptKnz4e54XMYtGIqUAbgCfbIg7EUfDoWLbaDHDPlS
         Zlw9OlnsaVO/+qu5KZlNkpcVYOjljCbXSrbEankymEaEHgtkCklmow6stCLzDCQ3ihoK
         e31g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pVvARrOg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id j1si345801oob.0.2021.01.27.13.26.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 13:26:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id w14so2168224pfi.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 13:26:08 -0800 (PST)
X-Received: by 2002:a62:18d6:0:b029:1bf:1c5f:bfa4 with SMTP id
 205-20020a6218d60000b02901bf1c5fbfa4mr12428501pfy.24.1611782767499; Wed, 27
 Jan 2021 13:26:07 -0800 (PST)
MIME-Version: 1.0
References: <20210125112831.2156212-1-arnd@kernel.org>
In-Reply-To: <20210125112831.2156212-1-arnd@kernel.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 22:25:56 +0100
Message-ID: <CAAeHK+yOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw@mail.gmail.com>
Subject: Re: [PATCH] kasan: export kasan_poison
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pVvARrOg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432
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

On Mon, Jan 25, 2021 at 12:28 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> The unit test module fails to build after adding a reference
> to kasan_poison:
>
> ERROR: modpost: "kasan_poison" [lib/test_kasan.ko] undefined!
>
> Export this symbol to make it available to loadable modules.

Could you share the config you used to trigger this?

> Fixes: b9b322c2bba9 ("kasan: add match-all tag tests")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kasan/shadow.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index de6b3f074742..32e7a5c148e6 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -94,6 +94,7 @@ void kasan_poison(const void *address, size_t size, u8 value)
>
>         __memset(shadow_start, value, shadow_end - shadow_start);
>  }
> +EXPORT_SYMBOL_GPL(kasan_poison);

Should this be _GPL? All of the other EXPORT_SYMBOL() we use in KASAN
are without the GPL suffix.

>
>  void kasan_unpoison(const void *address, size_t size)
>  {
> --
> 2.29.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw%40mail.gmail.com.
