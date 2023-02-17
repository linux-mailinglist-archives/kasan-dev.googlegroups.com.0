Return-Path: <kasan-dev+bncBDW2JDUY5AORB6NCXWPQMGQETAC7ZZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 09CB069A8D5
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 11:05:47 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id e8-20020ac84908000000b003b9a3ab9153sf190928qtq.8
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 02:05:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676628346; cv=pass;
        d=google.com; s=arc-20160816;
        b=p7hyOD/KGwkxVuEhzdP8aksmVvcqp6RZVBqYGByC3qibJdsAy/0MUc00RkXIVj2+Wf
         G8PH9EcWqPvs2wk7seLzuHx7ip2cF+CXr9/3iPnFxga6Fy/D4942FTdzkbKJ0kXqOeFO
         Sn6EzmaJuNBth9zxOJZUsh+Ac14OP8SmuBNC6wnBEjfzJmCUzNFHpanyHRuCgNMz0jUb
         +X9GFiv6nqJvor74PxxgNeOgYnHTvACZ/iUsFyCqG8ITBsrAUCraMrX+N+vjoNlGZjVc
         pHwP3zzQGLFkkYI1Pdz9Ubctog3aV6AvVL1955uXHjpa1zutenyPHtr88/5jCCpGKw7D
         PIJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=I5Ws6lVUxU8fIMPwiQmIEOvu8YJoGMtVx2bSXpkyTXY=;
        b=cz9J1+HwUTYKqvx0QcjXTvzHP4SZkS2CxZQ/GuSWsTrPpSl9B/91KvRlLR1m8DFCan
         b3Ieyexk4LYkSLFP8kqH+d+HX5T5PMUA67gsEFwnpEIa+XFG5QMrDNhJNbG91MOPm/DP
         t68REx1caIK0oyhFSKaYUTHAr0vSFSVBolV3Pnq4V7XIJQDZjrpeQnJTs8uuTf17HPK4
         oiCrjDhorU5zMbDPLx/ghVZ5AmMXmLLWyEDjRU8bTvBXLrRQbm0PHcvHrfRYCYC9va4M
         65KjhAHLrq9s0vmWr3ATDm3YC8Js2b4lEktHCs1iFW7iRE/oYh/X8UqARJXu45nMfr62
         qNrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PG5Binl+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I5Ws6lVUxU8fIMPwiQmIEOvu8YJoGMtVx2bSXpkyTXY=;
        b=htgISkEet2WceL9EjWgCKgIlWwixvI4SIEIcz1pIFZFmfjq1yHQtCcmfY8uUrMUfwq
         kKeiJR4E/KjH6+x96pQtl/JzrOj7UZC0YWBEPuEq6Nuw3lj8JbKcyyZ+xQEBFRSbOBKC
         WlOwoFARC3FaSkXWv4bpSAKFkLroGhUWLNhEhUeC5Nq6vTlx94Vg3S+4q9JeVmIelPQo
         4s4Wm4H5RuTuoQTX1bqDpD4bblKnaU6hYtrXxIkenoHHF0I2HybOekTrACls31XU37jz
         F4Qvv/9kEbw2yLNilBsnPivWJXddEfSrnxefwFa80O7gU7Wfbq2JHqTyf0Mc4kUe2DL0
         RUtA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I5Ws6lVUxU8fIMPwiQmIEOvu8YJoGMtVx2bSXpkyTXY=;
        b=HJk7Xa4HuiO+FitCcwy9e7oAcDrQHIqH1SEnPSngETAEZtptyHrsl3ZzNObAhggHgZ
         kLUQH5UvBG4MgNH1aZy9iUxtKfS2fIkVa5QSaNd9P7wOHnDqb9k9XDP+UFapvQaCQmrD
         6CbjNzEh9OQQLPYzKOA0KfIK/3sp/j0TMF6luZ0nNaD941DDH1Iek3qh3ccBylYExtLh
         bw+FWXBJ0BlCYyZSlyC9z/smTJDJrJwuGap1HR13lBZbWDHaBX8tGs0dzUSjgpGlagdH
         T/XC584hP+MVvRyH0w3PR6O68ZHCvUXV3uPbdBwXvU9mkf83UC1TplXs5gXglPv0rjhf
         LD1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=I5Ws6lVUxU8fIMPwiQmIEOvu8YJoGMtVx2bSXpkyTXY=;
        b=1FNEnXFsM3Duend6xP6/gXtxjehx7J9t6fJUrK7Im3RDGRwT1lc2YERbtptJfP9sEa
         ae5v0/c9n/mAYtDy0ZucMMCXiUwEgJd4xCEa7pfcCJC8fRs2jJJM6R5NHsGReSFkio94
         9EonsZRNTaHJaBl2d3NPWHnQZLx3XqdTteso1x1oVYLSqdhpampPiAKQBf6ebS+NsTM6
         x0ssFuFWkku5gsnBWOQ4m8filcD07TrgWX2MKS1yD99xpV+RuOyiU7Zcxpa4XxmVkOW0
         DFV/e13/y+mdxsygbYYA5dGUMHf5xBV25+9IS866rpXP9Fp3Gkw9OjbHTVFfr8gTp3E4
         A34A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWuO8NENwLtFZfzB0Oibu7PvdqJh+sB5Mpu4QARReIR+zjufKU0
	CSGWzNpmTtXetUkhkC34oVA=
X-Google-Smtp-Source: AK7set+qOtbWxjvcvB+DK/1CNS9W6L2l9JgRYT7dcSJ1yplnmwXE+mISLgyrdbeWaVha7xPtcQx87A==
X-Received: by 2002:a05:620a:808e:b0:721:41a:f4f8 with SMTP id ef14-20020a05620a808e00b00721041af4f8mr496795qkb.2.1676628345991;
        Fri, 17 Feb 2023 02:05:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4982:0:b0:3b0:98a4:96b8 with SMTP id f2-20020ac84982000000b003b098a496b8ls595973qtq.8.-pod-prod-gmail;
 Fri, 17 Feb 2023 02:05:45 -0800 (PST)
X-Received: by 2002:ac8:5f52:0:b0:3b6:895c:d18d with SMTP id y18-20020ac85f52000000b003b6895cd18dmr15901479qta.15.1676628345420;
        Fri, 17 Feb 2023 02:05:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676628345; cv=none;
        d=google.com; s=arc-20160816;
        b=CrtEyOCMPhdp4Hq/BYkQqSiMDxHGbgUzj2IP5VJ/Vd8w07JPcux4grtZvkaKa8A4Ds
         xBbEtBfDZc1j6Cm3YcM3DtBjW/CESCiWcSLTtrOygQKuG/himYv1PWH+r9ork9QMc5kQ
         WrG6DHHI9cDvF6zMWk0Lx8om6AoUHGtz/prRj++80F0H5LiH7Wwtduu2ye2XpmDN0Bo+
         POfM2GDaecSehxGM/pzSP5Drk9uuWtbzlMnjNUeP7flSH05kOlx4/buwOL9ZGfCH1Lzt
         33/xpjGkLECWb4Qkw7ErghRbQ47s/5PLDRN1TkmLF4a+7ux4ZU9pPUet1fisue9EgZX1
         Ykcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o0uHfzgv2qkWN2QON21082yWHlyLvuVbZRGsDEiQa/4=;
        b=f2TTlud0ywn+0y/YXyBS3BLov98zN4ZuNkDOxY3nN/bxMC+fPYL13zJitWyIsUByGR
         qjKbMjJn5E3ZlfO95voAGNX6+CzaWzNQiL/qHjTrJiwdnAf8P5OoCp9FYwhY+Ck+vuAa
         7bmwQXHSC1iYGa9HOxSzDgjS2MH55co6kcILdbPbJuoP4D6EmK7yfJHLSGIMvq5h9tCO
         1mt4rmhbBMij0JOpizSCJhzkJRg/jRZcam6NceeJTKW60OMFNP2Pxeg2LW2OvVVbu83C
         kJij0lhHn7Pgy87EVb6DqBoUmR+3oEdVrs/3nMMlc2XXi5EsQncwvh5jYlgZc9jC8H/Q
         3W1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=PG5Binl+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id z17-20020ac87cb1000000b003ba24f1b5cfsi306371qtv.3.2023.02.17.02.05.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 02:05:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id x5so750713plg.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 02:05:45 -0800 (PST)
X-Received: by 2002:a17:90b:1f8f:b0:233:3c5a:b41b with SMTP id
 so15-20020a17090b1f8f00b002333c5ab41bmr1384023pjb.133.1676628344552; Fri, 17
 Feb 2023 02:05:44 -0800 (PST)
MIME-Version: 1.0
References: <20230215050911.1433132-1-pcc@google.com>
In-Reply-To: <20230215050911.1433132-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 11:05:33 +0100
Message-ID: <CA+fCnZdvDY_15bL4zZ442snuq20K+HeAb+OFxGA7t--3e9Y0UQ@mail.gmail.com>
Subject: Re: [PATCH v2] arm64: Reset KASAN tag in copy_highpage with HW tags only
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	linux-mm@kvack.org, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com, 
	will@kernel.org, eugenis@google.com, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=PG5Binl+;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a
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

On Wed, Feb 15, 2023 at 6:09 AM Peter Collingbourne <pcc@google.com> wrote:
>
> During page migration, the copy_highpage function is used to copy the
> page data to the target page. If the source page is a userspace page
> with MTE tags, the KASAN tag of the target page must have the match-all
> tag in order to avoid tag check faults during subsequent accesses to the
> page by the kernel. However, the target page may have been allocated in
> a number of ways, some of which will use the KASAN allocator and will
> therefore end up setting the KASAN tag to a non-match-all tag. Therefore,
> update the target page's KASAN tag to match the source page.
>
> We ended up unintentionally fixing this issue as a result of a bad
> merge conflict resolution between commit e059853d14ca ("arm64: mte:
> Fix/clarify the PG_mte_tagged semantics") and commit 20794545c146 ("arm64=
:
> kasan: Revert "arm64: mte: reset the page tag in page->flags""), which
> preserved a tag reset for PG_mte_tagged pages which was considered to be
> unnecessary at the time. Because SW tags KASAN uses separate tag storage,
> update the code to only reset the tags when HW tags KASAN is enabled.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/If303d8a709438d3ff5af5fd85=
706505830f52e0c
> Reported-by: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee=
@mediatek.com>
> Cc: <stable@vger.kernel.org> # 6.1
> Fixes: 20794545c146 ("arm64: kasan: Revert "arm64: mte: reset the page ta=
g in page->flags"")
> ---
> v2:
> - added Fixes tag
>
> For the stable branch, e059853d14ca needs to be cherry-picked and the fol=
lowing
> merge conflict resolution is needed:
>
> -               page_kasan_tag_reset(to);
> +               if (kasan_hw_tags_enabled())
> +                       page_kasan_tag_reset(to);
>  -              /* It's a new page, shouldn't have been tagged yet */
>  -              WARN_ON_ONCE(!try_page_mte_tagging(to));
>
>  arch/arm64/mm/copypage.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 8dd5a8fe64b4..4aadcfb01754 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -22,7 +22,8 @@ void copy_highpage(struct page *to, struct page *from)
>         copy_page(kto, kfrom);
>
>         if (system_supports_mte() && page_mte_tagged(from)) {
> -               page_kasan_tag_reset(to);
> +               if (kasan_hw_tags_enabled())
> +                       page_kasan_tag_reset(to);
>                 /* It's a new page, shouldn't have been tagged yet */
>                 WARN_ON_ONCE(!try_page_mte_tagging(to));
>                 mte_copy_page_tags(kto, kfrom);
> --
> 2.39.1.581.gbfd45094c4-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you, Peter!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdvDY_15bL4zZ442snuq20K%2BHeAb%2BOFxGA7t--3e9Y0UQ%40mail.=
gmail.com.
