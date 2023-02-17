Return-Path: <kasan-dev+bncBDW2JDUY5AORBWE6XWPQMGQE423WBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id A0C6C69A8AF
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 10:56:42 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id i4-20020a17090332c400b0019ac36d3fb2sf357396plr.20
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 01:56:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676627801; cv=pass;
        d=google.com; s=arc-20160816;
        b=0c6RA+Snq/mHlDwjIqpMsBzyKklPKnWrbktMLNi+Eva6329MCaom2GUntEodflhNGy
         mlWSEk7yPBVA37hhGlE4+Ncft/c1J+8N/pG56i9iQsXYTy52q7JMwHTewtfa+SeKtSys
         R1vxrKYuT8XkLBuL/WfH1Jw8wsmoR/mtQ8Sd3DluADkcPnCcAVTEtUOHRI0mNV9Wq0RC
         bgEzoSTda4U+XrXyhQPevUf9LVF9q3KWRX0qTU7DT7TjU940VefvoRVij08pHU2ktzCb
         O9ZK+WP0rGeIsk1pTthvu2hTOYSY79OPepB/GBP30yIb4lCvIDyH2l4wvTMD6cYEXGlc
         PWpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iQjohgbSLHu/jpfRQNpYXA57M7aWqkpCfk3zzDA2RlU=;
        b=nkQ70ieMpDfvmCwQNFAjV0n68bKEwSksrFtmo5iNNlOPBMyrjbE5g51x3Uo8ukXwwG
         xc+Kk0puuASV69vf1u53XpQmiSV2cr7xJ7hUjnOuyP3axbDo4a+5DPOdsXrIkA3Oo+VU
         1aWgYvV7sWjjDxdH2kfzI8dOA9X+9xONz40ehc4ocBbI618iIMwm9dcLC0N5TUt1HMcs
         zFzZRRon+7O8UYDTmuxXjEwTZWxEhQOnkk5tzJl7mOfTgb0C6dCR/g7XQwRjM1A6l3Li
         skpMsTY+zZRDVXyyLjIR/AozIQyL7Ef68MtpxqDIuHNbWdp1+XCdD/vM7L07Rmo3DiON
         /NLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=W9iEHPEl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iQjohgbSLHu/jpfRQNpYXA57M7aWqkpCfk3zzDA2RlU=;
        b=RzIrSPJlymKI6swrKSSQjx10KLU/HZYDCsm0xS7dnlBn712b8m+MCa7/InCPdBN787
         HbPE5jW8FG/m4JcYovWpoJ/CQwkW2arHie+v8Q/dP0M638OnofmtRkFaSLZmvVNui0St
         0iyK5oTcE3QusAjEOUzXLzL8bzgiL1PfrVKq5tY8/mACucf97khUiXcTx2CYeuW2tGhv
         J5f4Ortjlygs+bFAGINEwZgOOBBvQloP6WgCzgc9+dqj6otNajWTtd2Fkq0QBML5N0SX
         7RG91eDmnhJQcvF1Ij9AKAM3/hazcu9/81gYsX2LtoMxKreDpmyE/K7BxhNeYBxs12Ho
         +1fA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=iQjohgbSLHu/jpfRQNpYXA57M7aWqkpCfk3zzDA2RlU=;
        b=kIxCGlQRK/2ILtDKfP7Kc2Fc/ukvpVU4h1i6d2dtZOrhACbD7toT2HXbvKST/mtDBl
         wGshvQrvDsWtJMPtrwdF9xTdro3qdrKcJHP9CjlC4aqb1TkH+5cvBwiJs3ceCSY+OlQM
         KfdS2C9P0DWSWQGoDGeqDi/FRHGetWk7sgJbkUt98AlzUI0fx6bCi8DQpQBCs9lNeSkU
         QlNEesGykWDSDDiTgHpWvzzn3jTyCC5FxcaTUYZ4rSxkLZ3pvBU1/AVXxYxtGOK2GN3q
         ktehm5taU+IohABINXpZexn8gpl8PX5h37kTXjs8YiHK7MRvdHnz0M1j6koo6oUknOcc
         yaLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iQjohgbSLHu/jpfRQNpYXA57M7aWqkpCfk3zzDA2RlU=;
        b=ZoLCZIEVnC5Qicj83uJE9JH604WhCa7dD6I4DxqvQHjUT7sEeOcL0+onXLm0A7TBJ+
         sVe+WYiZo22/AKjDcRCdet/++Lx+kttrNkSu3sjyA+69qzdbhaKHlwW6bLXsMW8hFP16
         yPHwT85X1T85EnRGAeXavzwfGzWn0pG6XDUMneOFtFaIoNe21BRDcMHeevqiqEl759qQ
         WL1gTQ0DJa0iNfVDSIV9pb9fYESRRkdgblxJ4EUkQs426fBDCRpP1i9GEl6HFgVkkBed
         Y/geyQ2/qU9+mpXiZhpsNp+s7z7td0cefpkaw+mRM1VNjw7cbQ7k8Uk5FRyGTSNV6N3e
         IzrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW9dnhJjH9bmSWT8LZNkoS8NKYoGbkW4T8CZMp+q/cEXaQ0DC3z
	oN0Q4vkqhdTHkgFvPmESzAQ=
X-Google-Smtp-Source: AK7set+A7jAJoqGdMvEQppj1RVqEpqBAL3a2/4CgJCGA0OMI2VlQ/a2yLjIANL2RiZkl2U7COmXvFQ==
X-Received: by 2002:a17:90b:3b85:b0:230:c56e:17bc with SMTP id pc5-20020a17090b3b8500b00230c56e17bcmr1437331pjb.75.1676627801091;
        Fri, 17 Feb 2023 01:56:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2a05:b0:210:6f33:e22d with SMTP id
 i5-20020a17090a2a0500b002106f33e22dls996410pjd.2.-pod-control-gmail; Fri, 17
 Feb 2023 01:56:40 -0800 (PST)
X-Received: by 2002:a17:902:e384:b0:19c:1450:8871 with SMTP id g4-20020a170902e38400b0019c14508871mr1245242ple.23.1676627800125;
        Fri, 17 Feb 2023 01:56:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676627800; cv=none;
        d=google.com; s=arc-20160816;
        b=r1D5tq/vqH0JEYizYy9ftmdUUPDM2UKHhwnosATtO7rWaae9qu4qUD7vyLk2zZXts0
         Uz52ndo6UmPKgYP5dKAsbcZvvfFVKL9rj6nbFwQ/CvBOFDBrLeuNdA195u4ptRQ+7JXd
         4phX0Uh/c597ckXqSaN6t9aDrDTtnA/IPchGNLLe5nVcuDj+Z4rDfHa6bBWfnN5nI61d
         /PEaouBLX4Oo8lWh8GykiRpl5aUJyh6SSEoVw21xrexRp2hey6XuDIRCxHlWxMtT9tFL
         eXMU4uY82VlNZfShpGwm0rRrkP69pvENnzIS0+ACnlK5vPAIWRy1AJbALtyXoQxCBL99
         6y9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5YbBF9fO8IgOoAn7RC6I5vfvltkUyuTHQeRs/MqGpps=;
        b=cOZzMOEsNFt0GgPwOIEr550uV/zZAITo32HeCMTi2agTnkNlEvPZHhDJS+KN32+Sl1
         tnF6PjSQCyaC/KaZsfiPkwhkhrpj9jQkvTySjQIzpRpfjNef4rSsHncFjpNt1CDTaAYM
         dMJJHtkaRZnH0FeJJhl4xvMJaCrTTBvkQLhtl35aDHfCIOD3Gf76FqHlzYvx9WFtGmcU
         ayTVuDY0YVDWKRs68TEE9UaCJNX/2yLSsVoTb8JLqyGNLY74tAYXq0hMFOYgtWd5M14n
         W0cEPb0NInQxuamB6bJhHvpqR0vRdYxRMI605IBQBSnHPm/ofM3c4VhLwuV0EDSARnf8
         wG5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=W9iEHPEl;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 1-20020a170902c24100b0019a723a83d2si206234plg.13.2023.02.17.01.56.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 01:56:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id f7so282588pgu.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 01:56:40 -0800 (PST)
X-Received: by 2002:a05:6a00:2129:b0:5a8:4c7e:bafd with SMTP id
 n9-20020a056a00212900b005a84c7ebafdmr67234pfj.32.1676627799822; Fri, 17 Feb
 2023 01:56:39 -0800 (PST)
MIME-Version: 1.0
References: <20230216195924.3287772-1-pcc@google.com>
In-Reply-To: <20230216195924.3287772-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 10:56:28 +0100
Message-ID: <CA+fCnZd5U3y_UehfBtSV5cJATdS8N58VVM2ZiT=_NfKF-K2SQQ@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: call clear_page with a match-all tag instead of
 changing page tag
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=W9iEHPEl;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52d
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

On Thu, Feb 16, 2023 at 8:59 PM Peter Collingbourne <pcc@google.com> wrote:
>
> Instead of changing the page's tag solely in order to obtain a pointer
> with a match-all tag and then changing it back again, just convert the
> pointer that we get from kmap_atomic() into one with a match-all tag
> before passing it to clear_page().
>
> On a certain microarchitecture, this has been observed to cause a
> measurable improvement in microbenchmark performance, presumably as a
> result of being able to avoid the atomic operations on the page tag.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711
> ---
> v2:
> - switched to kmap_local_page()
>
>  include/linux/highmem.h | 8 +++-----
>  1 file changed, 3 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/highmem.h b/include/linux/highmem.h
> index 44242268f53b..212fd081b227 100644
> --- a/include/linux/highmem.h
> +++ b/include/linux/highmem.h
> @@ -245,12 +245,10 @@ static inline void clear_highpage(struct page *page)
>
>  static inline void clear_highpage_kasan_tagged(struct page *page)
>  {
> -       u8 tag;
> +       void *kaddr = kmap_local_page(page);
>
> -       tag = page_kasan_tag(page);
> -       page_kasan_tag_reset(page);
> -       clear_highpage(page);
> -       page_kasan_tag_set(page, tag);
> +       clear_page(kasan_reset_tag(kaddr));
> +       kunmap_local(kaddr);
>  }
>
>  #ifndef __HAVE_ARCH_TAG_CLEAR_HIGHPAGE
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd5U3y_UehfBtSV5cJATdS8N58VVM2ZiT%3D_NfKF-K2SQQ%40mail.gmail.com.
