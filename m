Return-Path: <kasan-dev+bncBD63HSEZTUIBBFG54X7QKGQESE6RB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E72BB2EFEAD
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 09:51:33 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id z20sf9015937pgh.18
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 00:51:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610182292; cv=pass;
        d=google.com; s=arc-20160816;
        b=z8lq2JuzUaE/wrh/TaZLV5bIbO0j/liUbHRoM2ugi9Ts0lC98ccvoY6rQ+XhFQAnCc
         P48uZJGan6T+z4xWc9o1gEeF8/V5UksjpsHtfC/ZYJXfg6QtiPk0mdvYhFwlc6yAPhB7
         NgyRmrK5ja9NPFO5e9SCHv0NHMmuh6CZzljUOth/cIQikkWV79Y3/mFdYtIQmW9Gu9Yc
         ibMIQqV4xTu8y3Ar7t2Qfw5a6Wlt4x+vGuN9r7BgzRilkP2l3B2GtRIyLsanXC8HAcB9
         2vA8R64U3+DbrKXYpA3q5p28dRmahvAgn0tM6DeEDkAh3yUGPWMz28WHIMrNZw9zZTcb
         Zv9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=qzcqtQCdeppvQRTW/523HZ3Po5y5/ZInanv6t3fFAwI=;
        b=wf/Fp7HlsfhVQ2IOMcVBm7kHq3VTcc6b5HZqg+kSgyNgFhuIh90+4VF9vUK8qxytzp
         p4JIuGOmbzeG4ANNS8wlerBHGVpet0qbTv79Zn4ywdddUGz/PbbbtcbLxVYKv7dXajmq
         /u3Fjgw905xPw+lDtfCHF9384SJUDEd7c4XDvCUf62CQnW3Wv4BT0laYhLjm/YEyOZuu
         Ux913Kr9Qb+zEdwC4m0BIbls61gtskAxIgsBdGACCa2Ah+4B+KUUx7zA/CaxKfdwRC8w
         EspuJowkfVjJchT6K3FcIJ1X9E/sKi4E66e3xQ/q/ps+hsfjswsr0AiDY/lUih/TdYp2
         6raA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N1uENVcJ;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qzcqtQCdeppvQRTW/523HZ3Po5y5/ZInanv6t3fFAwI=;
        b=LlRO/zkzAqSsGkuW179HS16t7He5UcR+OegDR1hJa6WuDx4iCLU7hPKrQL3A6iKVmM
         baf6shtq9RjIwK3092bc1RNxTTRILmvZMxEpGGlXVoJ/QxG5aaVqS3IgI1VQof65/I1E
         /sCI1429u9ZziHwbx4J7+Ri4IZ7rr8QbD/0q7NEzcexaOGuPUqj9I9jAjDaYM9lRauFY
         E6JMfaGgJ4vUig4QCA+a+JFHaa9rD7mnmM2YLeL1NDfZd6Qo7Bvsj2UL/0Q/qE+2ZssS
         N5vQYd1Ritra2L7MN1Gs5sNdWQ9xTagZZb8bemaSuMlVUQjO+8PREnGz12rWrqPw0xwJ
         j9aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qzcqtQCdeppvQRTW/523HZ3Po5y5/ZInanv6t3fFAwI=;
        b=UyrRuRUubVkgRy/HlmrAlXAYCij86NBdCEh/tNpEE1d2ss6tBqNzsPcX8SZKHOeLvG
         jTu+RC1guv34MDPZ9HUge2wZofK9JNyddlhn1sgjABNbCvuhcyQnr1lWtNtbF+8N64Ap
         BGXoxUatdWZb27VTpfqi998SD86s6A8J9mkTuC264r4RWQFL6G+Vzy4VIRsfiu/eb58g
         QVvUNQqHEZrsePmz4hM70PfMAGxhWz5VTZaElYysMqCAzIkfdVkj1mPeotlX365fSWwk
         yGapo6P/p9DNPKNBbcdtLFcC/FK1FbxhHFzPJoLjDFhiaavvrsa5UGoR71Qhq0JzH25v
         phWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310LHJJJrqBV4vad936doCb2qCP1e6i8SEmaiL3EH9Bh57n5l9B
	llw2bKUe7cCS214jL8BZN+k=
X-Google-Smtp-Source: ABdhPJxcO+2wv0DY69RT7FkmQWx9P18RuGrNn5L1bV904EoFGL6QXS2+MMcJckS6x/zrdz74/rd3ww==
X-Received: by 2002:a17:902:9b84:b029:dd:f952:db30 with SMTP id y4-20020a1709029b84b02900ddf952db30mr5801038plp.56.1610182292655;
        Sat, 09 Jan 2021 00:51:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7615:: with SMTP id r21ls4887037pfc.4.gmail; Sat, 09 Jan
 2021 00:51:32 -0800 (PST)
X-Received: by 2002:aa7:8813:0:b029:19d:cd3b:6f89 with SMTP id c19-20020aa788130000b029019dcd3b6f89mr7472673pfo.42.1610182292121;
        Sat, 09 Jan 2021 00:51:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610182292; cv=none;
        d=google.com; s=arc-20160816;
        b=HOKL9rMkSprjL5OeWz267jN+xoJjNnoIkkZs+FEVJaQUu9SOgr6lsFZjo/Qka+M5XC
         4RmBFa90AcKqeL+FtErREYuZGrZ3I/ZHngEmefC7Lo6RsQDQadfLg2Pbez4sEzTFqqLS
         AKkEZGoo+gZt9wLOsNO6kgz0WiS276ZCWC+qbtIKOJcPlciZvDyOgE8KYG6gBJJ01JVs
         bADxMcG12VVs8UMSMqO45VchUfY8Ew2lHRYeTQXc9DYpdghp2fBUQ94P6AF87EzSZ0W2
         LwDneoLKUJiH5+LZUG1nS/tRhzquARpEFlZ/VuqKSDYy45JzGRHY/uewzXrVFuGcC0RM
         hfLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tcTZOWLBSLDICtKFeM/fIyM6GzUQpTACWkG3/0jrQI0=;
        b=ute8RCvMtqBfBPKHPtShamI1gBEX/yEmH1P0Piow+MEIlINdGWMRCPbP06GxR36EqF
         gQLEfHLNSK1ENzlXytnWexC7YzQqgYW7C/dEIXy0IBmCMIUvcmJ3y3D4BIn/If3BqmzV
         vt9Lhw6WpIsvSGZvXYrMQ4l1dAx0MfviEb3K/pLuHZD94ilctvSGBmFp6dP3HmcyRFiR
         MTY/V/xSXoJcQbmZxhWyg6D/k5SxR0OrbsSJF5eR9WdAUDtD3yHfXGcJF11AhdNBCpsk
         I6DhVm30rRk3LwuK55cK/xF/1SFljl2XTGo+9x5cId4Mc0ReWQXTaHSlW26Ddr+B9Phk
         maDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N1uENVcJ;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id kr15si992209pjb.2.2021.01.09.00.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Jan 2021 00:51:32 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id ABD752396F
	for <kasan-dev@googlegroups.com>; Sat,  9 Jan 2021 08:51:31 +0000 (UTC)
Received: by mail-oi1-f173.google.com with SMTP id l207so14311194oib.4
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 00:51:31 -0800 (PST)
X-Received: by 2002:aca:210f:: with SMTP id 15mr4645635oiz.174.1610182290984;
 Sat, 09 Jan 2021 00:51:30 -0800 (PST)
MIME-Version: 1.0
References: <20210109044622.8312-1-hailongliiu@yeah.net>
In-Reply-To: <20210109044622.8312-1-hailongliiu@yeah.net>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Sat, 9 Jan 2021 09:51:19 +0100
X-Gmail-Original-Message-ID: <CAMj1kXGBo_EBg+SYRd_cwPwQRq1NmRwJNyV6vjMMgA_S7Yff=A@mail.gmail.com>
Message-ID: <CAMj1kXGBo_EBg+SYRd_cwPwQRq1NmRwJNyV6vjMMgA_S7Yff=A@mail.gmail.com>
Subject: Re: [PATCH] arm/kasan:fix the arry size of kasan_early_shadow_pte
To: Hailong liu <hailongliiu@yeah.net>, Linus Walleij <linus.walleij@linaro.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Ziliang Guo <guo.ziliang@zte.com.cn>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Russell King <linux@armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N1uENVcJ;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

(+ Linus)

On Sat, 9 Jan 2021 at 05:50, Hailong liu <hailongliiu@yeah.net> wrote:
>
> From: Hailong Liu <liu.hailong6@zte.com.cn>
>
> The size of kasan_early_shadow_pte[] now is PTRS_PER_PTE which defined to
> 512 for arm architecture. This means that it only covers the prev Linux p=
te
> entries, but not the HWTABLE pte entries for arm.
>
> The reason it works well current is that the symbol kasan_early_shadow_pa=
ge
> immediately following kasan_early_shadow_pte in memory is page aligned,
> which makes kasan_early_shadow_pte look like a 4KB size array. But we can=
't
> ensure the order always right with different compiler/linker, nor more bs=
s
> symbols be introduced.
>
> We had a test with QEMU + vexpress=EF=BC=9Aput a 512KB-size symbol with a=
ttribute
> __section(".bss..page_aligned") after kasan_early_shadow_pte, and poison =
it
> after kasan_early_init(). Then enabled CONFIG_KASAN, it failed to boot up=
.
>
> Signed-off-by: Hailong Liu <liu.hailong6@zte.com.cn>
> Signed-off-by: Ziliang Guo <guo.ziliang@zte.com.cn>
> ---
>  include/linux/kasan.h | 6 +++++-
>  mm/kasan/init.c       | 3 ++-
>  2 files changed, 7 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5e0655fb2a6f..fe1ae73ff8b5 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -35,8 +35,12 @@ struct kunit_kasan_expectation {
>  #define KASAN_SHADOW_INIT 0
>  #endif
>
> +#ifndef PTE_HWTABLE_PTRS
> +#define PTE_HWTABLE_PTRS 0
> +#endif
> +
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> +extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
>  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>  extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>  extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index bc0ad208b3a7..7ca0b92d5886 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -64,7 +64,8 @@ static inline bool kasan_pmd_table(pud_t pud)
>         return false;
>  }
>  #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
> +pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
> +       __page_aligned_bss;
>
>  static inline bool kasan_pte_table(pmd_t pmd)
>  {
> --
> 2.17.1
>
>
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMj1kXGBo_EBg%2BSYRd_cwPwQRq1NmRwJNyV6vjMMgA_S7Yff%3DA%40mail.gm=
ail.com.
