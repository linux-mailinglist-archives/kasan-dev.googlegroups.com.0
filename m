Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNFQ6X7QKGQEDBCXUAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E47002F29A5
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:05:09 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id j37sf1123305pgb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:05:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610438708; cv=pass;
        d=google.com; s=arc-20160816;
        b=CMmR8Gn++/j+2qcTGxxUMZRaypRfHl60SGVLDhyCtttjmlvup+/4Ynk50kYxYD5Vnx
         6MwO/huNkOrJcozdZAorkv8ZHtsLJdYCDv4IF8fqQHkrvNcAyVsF62rLtJJICUvlU5C+
         a0Ryu8+Sa2kjHdg4ibOu1rS7QXPIb0GXC6Im5qaBrDYY6/CsznDIAQBB5OO3BR9WHeJm
         t1+Y3eVQmNgQ0+WYRXiA8erzAVoOulk32VRTOyx96btaopEegO/W881MXg68/U3k3DNN
         /4F5rO0ZK/GtR8vPbKMXf4/z1Xf+mdt5VLbloaaDjdZpCSgS7COTHtqnkveycMkT7TyS
         j3aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DAmAMbEVzduz30cvhgw9lZoOWDyJN+CwMpaZ292879o=;
        b=h8dtx4CjVdbIC1q1GVyWCOysKPrSaxgtlWSaZ1CGMHA/QyIY6BwMu3miuliURlRVkp
         EZy7dzCTbDDl28vfdMfntlUEZuJTYee7+No2FLqMd5RJq1cUM2xx3sTIeG+ITZRCIQns
         9xnD3B8vOt5M5kVXXOnTYgAyW1c7GDRyr+VtbJrfRQqthZBXgkY6RCBsWC0rrvQj7pm9
         cxKa3NRFVNkWqmZYLMOON8W114ps9e+X8CmAXd0x5QdTfyV/0KBRKu11TIQdhrFh1ila
         dfEaePSNMTx+jzHUUFR0hqUPEx/jdTHws4r+6MFlXlg9X02gNK2NFrfq7sw+1MRkb1sx
         ip8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YlV263n9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DAmAMbEVzduz30cvhgw9lZoOWDyJN+CwMpaZ292879o=;
        b=W3MVfSACTipN66w4kNLbzk8oEg0FMY6gWOi0UHgwxYIGIfUaPcsNMSZYQLOTa6kk6E
         tpnzFn4UW9WwAabJ0JZH8PyeCeidJAjLRjPcOZxdCuQQFWay9shW+u9E0BeMFuEhdQkm
         +5r4De5RM3AX5j0G4SbLgjQCtY+zJ6kbALGYRuBbgE8i0sDSuM5ZVIJJY6z996bSW3pC
         SbtNEP+Rp+3nh8y0dH1yE5Mzzk0EMv6ta2EIWyCi9Wx9vJZxdUX08j4atDscw/g6xHlz
         5B1r114UrKGoAYK60Bhm+ESfd7Hfl9UvLfwMF69DFlDkMliv9CvtYNYpeanYno945/wx
         fcrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DAmAMbEVzduz30cvhgw9lZoOWDyJN+CwMpaZ292879o=;
        b=MyDtAG96IRB79ND3L90UvLwA2wP5JUe9Dux7PNFShxG1BNsXjS98tr0AOc9Sea9rs3
         EGNkhS/86hN+Dp9ZAj2cAikDFY5E+eUA9MfDanRf2jeX+F5RXt6QyRT+I9NkU5LbFHPx
         8heTb/wVyyoztqUZJzN2xnyE3GTDnT98HWnunTcI2rSdYU1aNJMnORmPow9npgUzrqL4
         +hwrIbu21lMUQUCa5XOqe92gERfcFAbnXdt69FmWUy16AXmrzIH1UhrHUpjM+qxMod3I
         r2vAEjZydjMiH52oj4gA0u3zKGBxeMute9NkibTawv8LtgCQ0HwWB6oFd8tOFHVLJnod
         2IKw==
X-Gm-Message-State: AOAM532Kb3vPZdXgvmOCPayDguR8gKTVpi3l0bWqjnhN1dad7EZL77cK
	woeWGoQslWya7nS09ssI/bU=
X-Google-Smtp-Source: ABdhPJywJTOLS2/VLdxHq8kb5ZCflO5zW8q5tTyH4VlDT6Zb/bjy7tC2r7hjtNFCIGdspEZCAy996w==
X-Received: by 2002:a17:902:76c2:b029:dc:1aa4:28f1 with SMTP id j2-20020a17090276c2b02900dc1aa428f1mr4027333plt.79.1610438708244;
        Tue, 12 Jan 2021 00:05:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7615:: with SMTP id r21ls920363pfc.4.gmail; Tue, 12 Jan
 2021 00:05:07 -0800 (PST)
X-Received: by 2002:a63:c501:: with SMTP id f1mr3563061pgd.1.1610438707747;
        Tue, 12 Jan 2021 00:05:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610438707; cv=none;
        d=google.com; s=arc-20160816;
        b=yRQzMjhr4nYW32TNB/HESKcE/FIylW0N/Lx3Qo86U1tjNMEt6GMdn51a/QzPYWSR5y
         2j8Jh1pe3yqPJ+V3SDtD9lyo4bsJXeIukASosMZSRtxttnpg0xi1gK5S6MdRSKNg1CVr
         OoD2hhLENZMgnKNaFPv1RmBmfhBQnAj3nfpWuhmvQyoOMLetRKN8e7CYadqW8JW+DAUm
         LamW7Y8r/4LV6U1whH0Y6+yial8PQzTP4zguzRU1dM7rzW9mqEV26puHoTacY2s0PWPX
         AT52wl18eOxkhrmHFDjfiQ32+gLzhLLOD30sWt8jx7aKQezZgNGkYPE4tMtg2GSXe6Bn
         merQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BO9LKMYm6WLALY7iBHQnXtdADoInL5KOrbTeEAsVWyI=;
        b=IP8NYyhIBF0+/OQvkPy/7rf9ld/tsMX+URjGRMV/Sx6yZcvi5x/D3KQz++hlmsInWV
         5g11XQWHB2hZUz6sQMmdkrNn9sDYCtSaojqwUZCh2YJKM9jrQg2VMovE0N3Qkv5jtAhb
         hxax3uOLXHZDaxBcj8PwbHc8ZwUFyVTtpOaYg7uxJh3KLQ+LiksxNosv2m6zBYVczHic
         U/OVaLMqqMfANWwnmDpGiOb82ZYvtdvdLSgSBEowf7XiyKqMPrNQhCHLYNAGhf4ktI51
         FqNRpXzP0KpgZYrbOA1fd4htVYbxlnKDkDKfzXqRiIGYKNcr091h1rtsWGJ/mGx/DgFY
         alww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YlV263n9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id d1si140976pjo.1.2021.01.12.00.05.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:05:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id b64so1125138qkc.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:05:07 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr3277569qke.352.1610438706711;
 Tue, 12 Jan 2021 00:05:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
In-Reply-To: <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:04:54 +0100
Message-ID: <CAG_fn=WX5rGMHKPrDVCUoTNFwygW9AP7QrVwrco1R70sZ6MqQA@mail.gmail.com>
Subject: Re: [PATCH 04/11] kasan: add match-all tag tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YlV263n9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add 3 new tests for tag-based KASAN modes:
>
> 1. Check that match-all pointer tag is not assigned randomly.
> 2. Check that 0xff works as a match-all pointer tag.
> 3. Check that there are no match-all memory tags.
>
> Note, that test #3 causes a significant number (255) of KASAN reports
> to be printed during execution for the SW_TAGS mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> ---
>  lib/test_kasan.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h |  6 ++++
>  2 files changed, 99 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 46e578c8e842..f1eda0bcc780 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -13,6 +13,7 @@
>  #include <linux/mman.h>
>  #include <linux/module.h>
>  #include <linux/printk.h>
> +#include <linux/random.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> @@ -790,6 +791,95 @@ static void vmalloc_oob(struct kunit *test)
>         vfree(area);
>  }
>
> +/*
> + * Check that match-all pointer tag is not assigned randomly for
> + * tag-based modes.
> + */
> +static void match_all_not_assigned(struct kunit *test)
> +{

Do we want to run this test in non-tag-based modes? Probably not?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWX5rGMHKPrDVCUoTNFwygW9AP7QrVwrco1R70sZ6MqQA%40mail.gmail.com.
