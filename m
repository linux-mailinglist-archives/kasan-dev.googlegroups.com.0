Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI5Q3D5QKGQEGZFOXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D2DE2280600
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:55:47 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id f2sf564215wml.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574947; cv=pass;
        d=google.com; s=arc-20160816;
        b=dkXnrYf2xVnTJI5eryrUpOkjRI746Sx1kJkxqwW1OlYvNR3wLz8NqiTqRsPapumL8a
         eNUUqG9zh7rx8rHdAEbXgDlQu6dD4N/rCHrJhjwsv+JXo7pjp4tGSwU316i6LmMVLzDn
         yiiO1URksiaKka6Ug/U8fiEu9+/3e/A9GUWPt3EAOBjwxfA1BAOtxzXRAb9Xps+w9uZG
         lBjWmrPFnG2FkmozmREQ9Q437IrNu6iUDl8ro/9EZQGW04qkpAHHUGyPKZAtx9gMmiA4
         qbUQIMKiwBNibnVKe4B7Badi00Am+CkUg+g0iTY3Wf4/mumYSh3Cu44bSAhc1Wbsg08u
         I5hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3AzsyLjpUnKjzWFzNDAcxYkm9pdykJ6HvyTqGWpnfeg=;
        b=uus84fpFYpO0KjQyyshIkgfYfwN+bzNoQ/WvL96Kn4Rdc+v6KbjtomGangYYrD14u8
         RT12BTwnoN5dGnfENL2DX61MdCSOQ6lLOp6PBlznlayMLLJ01xMctC9H6As1sfdknaKX
         WkqmHbbl1zghRwZQ5tGf5leGRqNoOvfjK4hYOHWUB0jTwy/ouaXkRx/o2clbv/hxXr5l
         NPTxM3r9kPErMOH2LBlQNh6qEO1TAwML7NsCNo56rAO2KKP739hxeoP7qIUiWrMcrOPY
         kKmncOgTVER7YJlscIwEwBYzKhZAQMpSvl3E3mtnsPN/gSbC8ddIUjEkdMrRZr0Baquk
         Atuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RBM4/RCc";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3AzsyLjpUnKjzWFzNDAcxYkm9pdykJ6HvyTqGWpnfeg=;
        b=Q89YN++rwsnEeGQ3yi/sMpkP/zb0ssHJuSuDnz0eEWde0+D0lAW22aJK5CQOHJ74Y4
         2g4CJRuhwmU2iwAqFSFjnVQTKGg7ZRaUTf6Iy93YyJ+1lI0Oe2xCBq1a7lzb0R1RyNzx
         1c6lnRj+T0sDXxnEJmOUk2JzKOz/wVyrNghzgRQ611tFMD508cLos6VKKHSygK5ZlPiu
         5uRg/Okv+2cEAloWdl2Xk7VMTPvd1/+NIQNbg2DBd0SR3ts1ix8Dy5eIeiRbebnGjk5d
         yY788NqVymQrkh6L+GJH3S8gcJGg/yn8libWpSRTXgy8If0oethS5rPDy8HKyGb4TNZb
         jy/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3AzsyLjpUnKjzWFzNDAcxYkm9pdykJ6HvyTqGWpnfeg=;
        b=Kcbt+qCsASU9XwVLiYJv2yp7mYKcwmbQ1840J0Es2PwRtuEgspUCu/pbIOwOANvHRp
         4BV70dIqdAWlCsXPhVbO5ou24REJxlJcHroxd+RXenbgNyEfkuKksQNsx1klKbw5+pph
         wifF54IBGYj6YH5g/Zq84+yBCYXuVy5Wkhla7iO5jOvtDuVMgzMLLTg0hb1HiF6tYZjI
         yCks9sCDHXBUXFJANbZj/GsYV32uY7BHypEzFlRJVkpAmfsDvkF+1MLAUsOCKiV1qpmj
         m4x2lXiUjw4fx387kjKa6gDK8/Cma0J7Z2ga1XQirYvPuTUqoYe95tjdn2AEwpzOiVQr
         E42A==
X-Gm-Message-State: AOAM532sW5JAamDFZLLU4qx6/RH+XvZMalggwcMaLuhXjtxpLdavkxkz
	rY1DS5LqozaQAw6ncS5oM+I=
X-Google-Smtp-Source: ABdhPJwl0PTtpC09rCaKqRWhp86Re6hjHnx4fk2SFuavfZS+D3QRBnOVX0mZt3mtWmbwzvTmnOSQvQ==
X-Received: by 2002:adf:e312:: with SMTP id b18mr11062019wrj.372.1601574947593;
        Thu, 01 Oct 2020 10:55:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls5806466wrm.2.gmail; Thu, 01 Oct
 2020 10:55:46 -0700 (PDT)
X-Received: by 2002:adf:e6c2:: with SMTP id y2mr10978060wrm.117.1601574946589;
        Thu, 01 Oct 2020 10:55:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574946; cv=none;
        d=google.com; s=arc-20160816;
        b=tlG8/eOuWLJdGottVYDX5zsRG8N0uOniR6JJ7ZHSqaGhDFtmdgpDxJPvsGQuKfof7K
         mNKNhsUotL73HEdtW3dDvqchVnH1YankJmTo2lmivRFTLvSJwhBPkVIqZjKKGWGVRjB6
         ccV8I1HpiyonmKDam/HGq7Z+JRNsephNMP3JzQjZXcEli8Dcu0JFtwomDSPB8oh5H9e2
         KSRvHQqEKsEo8n5yc/PYps4MknymrTqUEmB2mozwpNPBk2VugF6CWnf0oynVEsJsO1gK
         cYs1rSM+Uwoi8pGwwtxpRc8kMYqMKK6N0IyWaiSWlHRZjvXMSIRUthylWNZk4Osr61S+
         GLRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wXf2yDw1ZzKJ0lA2O+mYUFWQ3CJsg8/AyQ/IRMAajuk=;
        b=kH1TYcP/oX6/lo4vBgCBobWD0YBF7gM9V0i8FWbf5N+yR+jpPpZds5QiyXRU+cn7S2
         GH29e78ojO5NNhpkUgJzoRYXYIsHBIah5myE+8tDJbZZy/DsYSOu1/K1dz7AA15AF9hq
         xXF9PtVjAvgGgF+esPjLIjI5U6WqWT8HzG1T/LWqnlYkec4xbmm+yxxuqSJZujh1Sdpi
         fTb+5GkaJFnMdsHHT3fV5VrhTtKDxyLH/cSlMJOqMlBHiSJCS1UQdYZ/ZAvgSx0Ea9gM
         XIWzmsT6FrqFU/jPzEAjn8yeUJwX8ECWyqibvf066mZ2PqjatnZYcVKG46hyRdk1lcGT
         0ofQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="RBM4/RCc";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id b1si20344wmj.1.2020.10.01.10.55.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:55:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id k18so4073324wmj.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:55:46 -0700 (PDT)
X-Received: by 2002:a05:600c:216:: with SMTP id 22mr1100906wmi.149.1601574946075;
        Thu, 01 Oct 2020 10:55:46 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id m11sm1045183wmf.10.2020.10.01.10.55.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:55:45 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:55:39 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 21/39] kasan: don't allow SW_TAGS with ARM64_MTE
Message-ID: <20201001175539.GQ4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <d00f21f69ba7cb4809e850cf322247d48dae75ce.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d00f21f69ba7cb4809e850cf322247d48dae75ce.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="RBM4/RCc";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

Does that patch title need an ", arm64" in it, like the others?

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Software tag-based KASAN provides its own tag checking machinery that
> can conflict with MTE. Don't allow enabling software tag-based KASAN
> when MTE is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
> ---
>  arch/arm64/Kconfig | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index e7450fbd0aa7..e875db8e1c86 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -131,7 +131,7 @@ config ARM64
>  	select HAVE_ARCH_JUMP_LABEL
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> -	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> +	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
>  	select HAVE_ARCH_KGDB
>  	select HAVE_ARCH_MMAP_RND_BITS
>  	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175539.GQ4162920%40elver.google.com.
