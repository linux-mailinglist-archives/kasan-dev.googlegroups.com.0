Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT6QX6FQMGQEDMRCPXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 755CE43486D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 11:58:40 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id y2-20020a1f7d02000000b002a4b9824835sf4538912vkc.20
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 02:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634723919; cv=pass;
        d=google.com; s=arc-20160816;
        b=xvHdEl8bcCyadB9RgyLK7I94FU0AMifaXxHkiN/LL6tGBTw/Pq0Gxc5beIpH8n7+Ul
         067C15pOZslxT5rJIEqiYGx6dM4TymlumIBDAqb7EVZc9VBtngSL+7e2so0w0lzY9W81
         YSpaQcFvlpN1NJUvdIhdxbUsrASsuuxgbML8LbOVZ6aoJnyRw5w/nqGk6Ss4WWfka1fM
         k1BhhrMKEvyBBALb2Nm2wIYP6ZwjaGOT5x+ZY/ZPgpelWa3VWUBkspfSPnZMYQ9Hul3k
         PjwIEI/T96NNTunYadU3HNdgK6mE/pIRHgwIf9fAHPlDPAxXxl1UVSlkHhsAdN+h7GJ+
         VjYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dKrTGanx6IueusGxHCwID3gnSDecwRjfZAEpNQ/7VRg=;
        b=dZSJ3AO85yjKKNjLVMD6td7OkgwOfJoKB7hfMi7Q1ZiAHvmVnQyUNHRf0o0HBbH+lj
         SIubvFuxN2KUecsEGsjaJRJJvIBjZyeB9AUP6xheOV/hS9vc90/Ibtvstb9et68Smwq7
         CO/FUIWQXYmCoD6Vcc0pkEhf+HZ6aQQbeyYUUR2RsEXe33ETQrVYsud1PG1I2bEXA8yh
         cdwiCk1s0g1psb2LkBR2JU1uOE+4sJR/HmYF6zz4BZcL1R9uLfXGoA0E1ZdQWILwGM6h
         xoJPfbVfGHSL8v2oG/dvRW2SYj/I7nC9Q/Oug2ONAAsbrP8nDFFprzZgPUECPbV8E8dL
         NytQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jgc+NSn/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dKrTGanx6IueusGxHCwID3gnSDecwRjfZAEpNQ/7VRg=;
        b=m5J2bIXge1O6kji6V2GrL2JcjWTmFR5bujZw71R4RC3FQEPtg/gfBuwRt4K1Bxvt/m
         2dxeJYLJToljSj0FOhxxVA322/xR4oKDKPo+Uu59gc0C6m6/PCSCiIuOIlQEstdAsZAu
         nX48pZEzAKvnHuoT/v7bepgegBtYv8Jt5TUsRU8xuqg5AWgWp20C+ohgDfOmMnl23VtP
         SfHRrv0SsLaI+to4Q/fa+H09LzKkCTSVMulFtlHTwKMWEidVwNnOfXS6lBzaT0OV86ku
         dl/k+RLwwCA/B/oXorABogWhkFnXBVwi8ek7Pg2HTQJG/e/wkWI0tZoStK8WuUrqErWU
         1uPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dKrTGanx6IueusGxHCwID3gnSDecwRjfZAEpNQ/7VRg=;
        b=wULUN1WNVTHD2+SzbQgVg8JB6+nc+GgFi0YUVMumxBagEiqDgD9VA5CsT+9aTtyt24
         3R8ssS2J92qqPPwNBHprWlPxmZu51v5LkMqBL7KaiOnbIjvL02Iov5JbL+K64MybEKeK
         Nr2kgRch2nA4TcNKA72wBKIElc6AiEE2qUgJ/hK36eckTwrQtTy/tDs6L7T9bOOGwy7y
         5GhMNUgqKzaQwIVeT46Ey3S74IX+bO64UjzGBTHDZbOq780Av7hXWif42NV7g1HgU5X1
         ajWCa9gRjp4sxfE1+BHn16QayXZXZAYLJtwRE2mMEd1JQ9a+gvAQGpuMHSlRjON4E9Is
         0dDw==
X-Gm-Message-State: AOAM532cPAVptyFTtl3N2qtIAEE+XP57HfmD647fX2igkqQ77bubX8X6
	LLrMWqhGurCvt1x2b661Jzo=
X-Google-Smtp-Source: ABdhPJzizyTvMNgwZl27BnGq9VJdfdLwF7ldDf++wpUMQNYE2QM5JN0HUcw52wBNSzjj3ep9xQpmVQ==
X-Received: by 2002:ab0:5548:: with SMTP id u8mr5755978uaa.0.1634723919579;
        Wed, 20 Oct 2021 02:58:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9e48:: with SMTP id h69ls255222vke.6.gmail; Wed, 20 Oct
 2021 02:58:39 -0700 (PDT)
X-Received: by 2002:a1f:6ec4:: with SMTP id j187mr34190563vkc.5.1634723919021;
        Wed, 20 Oct 2021 02:58:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634723919; cv=none;
        d=google.com; s=arc-20160816;
        b=LcGWzDL0pZt/35nKRMUQqyn3Bq/M9sLmM7BK9NJgnDNFCdyvA2mUy++d1tagTvXpzg
         GAHaf0lh1h8bKSEI3T9CbOLeeqqhECEuQUfLJ833S8uyK+H7myt4Ao41nWnDnmbiRlxS
         xpEpdxLTER/e0pyM055p4pgK0iiYADHSBV4XCNLrekxuPyx/YX+wtTUas3MPwH6bcDmk
         uaDm1pMF1+cJyzNxk9uwcWc2WNMtY8euSSv+Xqe3pJK0EDPqizXcWIbeTieE02EZQ9xz
         grxmPwd92VXKHxicg8X9EdYVDV8dO4z16OCUcgOUSich5X37rd0cbcR497LAprSDxgUE
         5Rxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/MXj6rprc3vo+rohvgYqe3T54Ggc+J0xvFrcFXcAdLY=;
        b=W1aMn4Mky+DFzu/VcLlz4bqgsP3EmM8Kr1KfvcIv+0OWRFsC7CXsGbKAycy3Opw2yW
         16DsjzkPCGnpHbLUcFFRFhD/B3uz8AesKoSH0KTdxiFBXFxkbZgudEJ7oLAKd9r8W4Xy
         mu7EPrzuRVNtW7gdpH0eTr4s9S7phVm/rl5WqyflFFiLMe1UpgbpYRc8Ww8eXHGT3ZAK
         2br+Fd1cjLlvTa9Q4EYbQK1Csu4ENrpqKxu1jauiTZMYwuRdHc+XAdqLJbhtBbMg7Daw
         gIZORziGSbJR/lLKLxX0KsMUC/gIoVadEoeuvG8fuKHbnnzQ+/j3EqEddBoFJF69Oza0
         3IhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jgc+NSn/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id y8si122363vsy.0.2021.10.20.02.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Oct 2021 02:58:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id y15-20020a9d460f000000b0055337e17a55so144805ote.10
        for <kasan-dev@googlegroups.com>; Wed, 20 Oct 2021 02:58:38 -0700 (PDT)
X-Received: by 2002:a9d:71cf:: with SMTP id z15mr10021143otj.157.1634723918292;
 Wed, 20 Oct 2021 02:58:38 -0700 (PDT)
MIME-Version: 1.0
References: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Oct 2021 11:58:26 +0200
Message-ID: <CANpmjNMk-2pfBjD3ak9hto+xAFExuG+Pc-_vQRa6DSS=9-=WUg@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: add kasan mode messages when kasan init
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, yee.lee@mediatek.com, nicholas.tang@mediatek.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="jgc+NSn/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Wed, 20 Oct 2021 at 11:48, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> There are multiple kasan modes. It makes sense that we add some messages
> to know which kasan mode is when booting up. see [1].
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

Because this is rebased on the changes in the arm64 tree, and also
touches arch/arm64, it probably has to go through the arm64 tree.

> ---
> v3:
>  - Rebase to linux-next
>  - Move kasan_mode_info() into hw_tags.c
> v2:
>  - Rebase to linux-next
>  - HW-tag based mode need to consider asymm mode
>  - Thanks Marco's suggestion
>
>  arch/arm64/mm/kasan_init.c |  2 +-
>  mm/kasan/hw_tags.c         | 14 +++++++++++++-
>  mm/kasan/sw_tags.c         |  2 +-
>  3 files changed, 15 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 5b996ca4d996..6f5a6fe8edd7 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -309,7 +309,7 @@ void __init kasan_init(void)
>         kasan_init_depth();
>  #if defined(CONFIG_KASAN_GENERIC)
>         /* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (generic)\n");
>  #endif
>  }

Note: Other architectures may want to update their message once they
support any one of the tags modes. But currently that's not yet the
case.

You could also consider leaving out the "(generic)" bit if it's the
generic mode to avoid adding this to all arch/**/kasan_init.c. Both is
fine with me. I leave it to you.

> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index dc892119e88f..7355cb534e4f 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -106,6 +106,16 @@ static int __init early_kasan_flag_stacktrace(char *arg)
>  }
>  early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
>
> +static inline const char *kasan_mode_info(void)
> +{
> +       if (kasan_mode == KASAN_MODE_ASYNC)
> +               return "async";
> +       else if (kasan_mode == KASAN_MODE_ASYMM)
> +               return "asymm";
> +       else
> +               return "sync";
> +}
> +
>  /* kasan_init_hw_tags_cpu() is called for each CPU. */
>  void kasan_init_hw_tags_cpu(void)
>  {
> @@ -177,7 +187,9 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
> +               kasan_mode_info(),
> +               kasan_stack_collection_enabled() ? "on" : "off");
>  }
>
>  void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index bd3f540feb47..77f13f391b57 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -42,7 +42,7 @@ void __init kasan_init_sw_tags(void)
>         for_each_possible_cpu(cpu)
>                 per_cpu(prng_state, cpu) = (u32)get_cycles();
>
> -       pr_info("KernelAddressSanitizer initialized\n");
> +       pr_info("KernelAddressSanitizer initialized (sw-tags)\n");
>  }
>
>  /*
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMk-2pfBjD3ak9hto%2BxAFExuG%2BPc-_vQRa6DSS%3D9-%3DWUg%40mail.gmail.com.
