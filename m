Return-Path: <kasan-dev+bncBDE6RCFOWIARBSH5USJQMGQEOPKKBEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D930511817
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:02:02 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id g89-20020a9d12e2000000b0060217f298e4sf274030otg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:02:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651064521; cv=pass;
        d=google.com; s=arc-20160816;
        b=z73cTNExJJvvsRo/vJHbHhAgByEZruh31CkSvBdT4qh48fmDnqNT223ML7w3S+Gtd4
         +I+XkW4XjJ2dPjQ/9gS7gRTL4lkJUnbJVLLKYQ1QTdegoJAgnYFNsHrWibGn7QGpAd6w
         OdFINKbj35gOat3TLAMHA9DGsCHvhH9p9+Zgc8+dgllA8YuW43Y0wuLiuHewtbqqIvfD
         oHW0NsJ0qt8267DHgGTR373tHls0VCCeUW5tFo8HBXn0lAMkCYkEk/Ibq/c+ZtiNXvIX
         VbSs/7ltY7Cyeld0/RFGXGPmn9/e2GIFvWVjvFWHsAvUi4ick+QoqarBC7AxvkAZijKN
         H1yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=jqo3f/qGUE5iOJ0sWiEpVNL+LDM0CMDmGxb/34A0gY4=;
        b=M7Hj5lQUiEf7O6+YeCYYyqsidG733F+XKyUr7Fz5Uzv5U1ECcjewbrMTsi2KNqx5eD
         UUHWyAYPnmhaU1SQLgokFUUBoHB5z1MPSdHUjYQ91ISaTLau6JDzvVXx6UjiAzu/5+Zp
         h5h4REq4QarjQTsXngLb1psOngf9Ofxh7ny7stPSo9uRPSK7dkUIliD7Iw2J8DRx8MJE
         PeOA6ABlrDHAjpD7DBkx1u/hBsq3MGWEuoPygWvaWqHHX9sU72DKybpWykxhiERQdADb
         FBO03/ldZj0KxGGzXY7oo1KHlix7+h8BoHAQbO4yqozqHBXg6PWjJdZvdI39pl2QCu7B
         61AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=LPG4LILx;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jqo3f/qGUE5iOJ0sWiEpVNL+LDM0CMDmGxb/34A0gY4=;
        b=ouuhuOYucUQ/Ws/wfWrucYPeSElKqerxRzhGBFx9D66VA2RcVZ4LZZ7Tc5XqtsFsKy
         BWPb7CJ4XIhly9o+OfOCkuVxhxU/7QmoG7nw3nBPmPBK7T93YkXZGTeV862iBYZ/8vwg
         W5G6VD0pCtIpDpQ8zK3uS9U25AqOPJ0x/YrBUIY5C1EOhaFx1QEw0fFRDeIbCs0jCb4H
         AaE4wH9Koh/uVvJBgxdESVZV4GwGUIgce9IGGmoxES51gP87AQ9AW+1y8+8s5E4GWVXx
         8+BiEif1LI5532/65y4KlmRyOWRhb+W3zDqiw9LGf/CtRxxObJgBLdfA83+3VBEOIcvM
         ST3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jqo3f/qGUE5iOJ0sWiEpVNL+LDM0CMDmGxb/34A0gY4=;
        b=DBLU7sEAQqstC8rRSKdwIAg/Ea/USnJqDRylsH91aGC/pd8RN7Sly0KZXZpGe/s+Xu
         5sM48DYQ10mA4UMDFwdj6nwmOEIzW5/NfyZA1rZOBUz7NasyvhgV7mZAA1cIAujHKiws
         rst/WbDy7J8oSRzVvgcR20Crnfk2xN0L0jUxfvc2057r99L1Iu3X+09HT2VrrBqRTguD
         G1KIsrICXmbpqAtn4BCsIAcGHYdJNAlNzI7pEd0jV8x6xZ2en2R4DzhMXDR/yPRP1r07
         qm4FkZqaeN50V/jLPmqeuwA3MdS/kqlLqlM4xKewlcul8RZDj9dLozYp5D/8S38f31+r
         UB7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ArScqSy0rRqJtpgE8bwdi9ZcGaZXxFYb6psj7qfVW4q6T+K7t
	bKtXRNjH9UEmB8HfcpqKF/c=
X-Google-Smtp-Source: ABdhPJwz0enuZSDsqMegIvB7g05LKbWxZawswIdKAsT84NPKOK4YknB+53y7OgdKHAuedpYUC8+xuw==
X-Received: by 2002:a05:6808:11cf:b0:2f9:b01b:1800 with SMTP id p15-20020a05680811cf00b002f9b01b1800mr16823625oiv.258.1651064521039;
        Wed, 27 Apr 2022 06:02:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:154:b0:e9:6abf:f9bb with SMTP id
 z20-20020a056871015400b000e96abff9bbls2117130oab.7.gmail; Wed, 27 Apr 2022
 06:02:00 -0700 (PDT)
X-Received: by 2002:a05:6870:440a:b0:e1:a94d:6102 with SMTP id u10-20020a056870440a00b000e1a94d6102mr11108005oah.213.1651064520639;
        Wed, 27 Apr 2022 06:02:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651064520; cv=none;
        d=google.com; s=arc-20160816;
        b=MDNaokGLcRtXV2vt+QTRR6QBGr5ift8Z0eLqbkwXilK6xBr6fQ9BhEQfu5g7e7NjXe
         Kc5ULfMTkxfYEJ8MOk0zGr4Gu1LfRNxJZiA0ZaV16oRyu/1dDOryjWcFSqZ8TOawf0Vn
         2+NLDkWFkVh2Jmi2jeSWQlUh8uE7HyoMZuXjcVFIU5odBIEqzoc19fw1ZEN/XXsLIVnE
         xbXum+zDXncgiVFmoKtXaQkpFF9ThgaI3FwKsUAd/0eMMoA7M9ADNT2q6DsAW0iNxcu8
         jC4jRydtu4M1VqSg/Jd8dv43dCHjt9UO4mshf31ot0FX3kwWnOmkgQa333LND2VH4giF
         oBJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S0RACex1YHTJ+EcaotG2ytIq1qh8idLDc1lxrpTPFYM=;
        b=O413QxQBz5ikqtm3AlbxqJAWq0ZKTxNdyWm8FjLF/Ob92Hp54CWwjSd0343EqCYnxZ
         HtoJfDdR6WJqw0Bkjlg1zJUL8BvkXynXFNEc1/9oUVyxTqjjZrLIdif/xNt5OvPQXV7z
         Bt8/zKhURwVPn6mAeSI39Y5yqBrLvte2CUu2umciJbfs9/TjvoBAgFpOlXWtyH/y5Kq1
         4e4S8tN1E3XrozhpWybxdtmF/0A+YhbzfwFv4PdmDsl0rCGfidVfw+5zwdP+OmNAiusa
         X9zQ3vEgPG6qhW1fSBsx7BKTNP7NaI98PkVY3HA2p96UA7BBJPuBRNPx5ZH2nvg2z6Ts
         eAdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=LPG4LILx;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id s37-20020a0568302aa500b005af6f22afd2si111573otu.1.2022.04.27.06.02.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 06:02:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-2ec42eae76bso17432737b3.10
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 06:02:00 -0700 (PDT)
X-Received: by 2002:a81:2108:0:b0:2f5:6938:b2b8 with SMTP id
 h8-20020a812108000000b002f56938b2b8mr26219124ywh.151.1651064520075; Wed, 27
 Apr 2022 06:02:00 -0700 (PDT)
MIME-Version: 1.0
References: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
In-Reply-To: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Wed, 27 Apr 2022 15:01:48 +0200
Message-ID: <CACRpkda_hpTVxKftKBqRvBtC-KN8c9NWHFJDV10TN4JOR7CQCw@mail.gmail.com>
Subject: Re: [PATCH v5 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linux@armlinux.org.uk, andreyknvl@gmail.com, anshuman.khandual@arm.com, 
	ardb@kernel.org, arnd@arndb.de, dvyukov@google.com, geert+renesas@glider.be, 
	glider@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	lukas.bulwahn@gmail.com, mark.rutland@arm.com, masahiroy@kernel.org, 
	matthias.bgg@gmail.com, rmk+kernel@armlinux.org.uk, ryabinin.a.a@gmail.com, 
	yj.chiang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=LPG4LILx;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, Apr 27, 2022 at 11:59 AM Lecopzer Chen
<lecopzer.chen@mediatek.com> wrote:

> Since the framework of KASAN_VMALLOC is well-developed,
> It's easy to support for ARM that simply not to map shadow of VMALLOC
> area on kasan_init.
>
> Since the virtual address of vmalloc for Arm is also between
> MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> address has already included between KASAN_SHADOW_START and
> KASAN_SHADOW_END.
> Thus we need to change nothing for memory map of Arm.
>
> This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> and support CONFIG_VMAP_STACK with KASan.

Excellent Lecopzer,

can you put these patches into Russell's patch tracker so he can pick them?
https://www.armlinux.org.uk/developer/patches/

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkda_hpTVxKftKBqRvBtC-KN8c9NWHFJDV10TN4JOR7CQCw%40mail.gmail.com.
