Return-Path: <kasan-dev+bncBDDL3KWR4EBRBRHTRX5QKGQEPAEL27I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 477ED26DEE7
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 16:59:18 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id x20sf1515340pgx.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 07:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600354757; cv=pass;
        d=google.com; s=arc-20160816;
        b=MnWHXKA4w5fJHwJaSY5+vM7ip7btTN5097Iaf8B7qXmdzk6OeuVyJtz8tPR3WjsaQT
         6zD1mhAMGHp2XeRdPxjeiPMq4kFXfnwtQkuAA9mAUjsm6TufQOOGrgfjpsIub1eyhWqC
         mzXDaOzL0brPqgy7C1qnhzZXes/ahOO9nOI7DEBZSVzMI3i+SX/VzzReIouKorN7m2+H
         XEvMYsKKyOHNDFhChBAd+XVLHs4UIjSfJzDsfureutTtq+h+w42+pcO/SpeKZa/mPCJf
         EB05pGpfXTZ8ZrccqvBBtwPEPMd9gdyCkB8qrMdNmsVJmPrsEOtoToMIImndSD8iTxI8
         ytcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wuvaz7+NJZ/c36un8c5ZKCSizCEbd5EnkPvOX4eThiI=;
        b=k31G8jqIHfJxuy0fARJZieIC0CLu08YJX1M8tvEsJw/B2M1vWNVtAbxpUSQGBG42IJ
         YXAqQNi3OCBOF4EPk8e3yaAz/WrPiEi9WR2QYaC1b/wqnAY9+/LTMPrpGVtqJukqU53p
         1Q5ajaP4Jcb/9y1q+G+gE+UhVItpnCDLCoJUqihEsgTR2xoLxqv8jLHjme/0I5L/GszJ
         WQ9wNBfrTGLk7plSQyg4J/InuWVwkkuzLzS4+ybgjUfXFcVXUBI1u5hBfFh8yhdU55PY
         BY+73Tg67jvVtdMUSlSJ2Y6wIEEgAnn1juCo6nucil+npKG/telPjW8Urnt0EzNUBX6t
         B8sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wuvaz7+NJZ/c36un8c5ZKCSizCEbd5EnkPvOX4eThiI=;
        b=MJBnwjvbWMcAtOwXyO6s9yx2QpKOaDOOVVgd7CqUpitUrUnK9P5banogAe+iRwYlnS
         pZrh/WKCa5D8emmFYJnU64TB8Ox9xp+joziqtTHTh9/DCw3moo+euqh/JY9zXDZXM1KP
         6BSJ5pFkiMP0fn0R2OQz6U9KhzibFxzQAC0Iqb59QljgVA5Zj6o9WIC86yuZI/FXsj48
         60syEEw9/fmZAkBj6y+z4zDdskv6G6NLl69zHcZbk5yW1Ki2hqaHiG2T9nPkYNkhYYZm
         6aUzZZ09YuiFOVeT0iBSCf1lavyuBhjl1Uf++93fz8hbZkk4dhq1WB+xeue6djatjap9
         MTuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wuvaz7+NJZ/c36un8c5ZKCSizCEbd5EnkPvOX4eThiI=;
        b=B1ztatYq/m+huV8qo6aL5S2LyXw+zZGkjp5OR31CdqrKZJABi8ivtBwNoGk7Hujj87
         RgRSTE2wmLy2ZugWPsgrtHVywRU4iN7++CM+qnSv/sBSBwEOJPVC2C2e6IlbhBWapAvO
         GrH5QfRcMHbn0JcoXgA0z5mMMSj8mheQG8V9imivfcbosJynvZ88ZskI+A43CqgetQfp
         Megg/SQmt1NNkenU1Aa85lQEM6knQdrAXwXkt9X8Y72imaitfN3QicI53RoPDQLhGezx
         pHXEzhoIRrrs/+dNiznhh3uSFnbpE5GF/ea37D5DbOUZASeKXiUNVaBm5GwD/BaKprOq
         ofEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QmmR6d8lQqu1CReTNsKqBQZMoI7tAzqc/gufxGWeAEWjVvkQ9
	7H+cwgqMvkYzfkdCuVr1xTI=
X-Google-Smtp-Source: ABdhPJyh1hPeOxl1h/AJy7XufiN/pzLKNhTM/T1gsXoCWaBPdxNFm8+VDGp9dBmFqINd9Hl2sEiLiA==
X-Received: by 2002:a63:6bc9:: with SMTP id g192mr23537827pgc.236.1600354756960;
        Thu, 17 Sep 2020 07:59:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7591:: with SMTP id q139ls933990pfc.3.gmail; Thu, 17 Sep
 2020 07:59:16 -0700 (PDT)
X-Received: by 2002:aa7:9f04:0:b029:13e:d13d:a13b with SMTP id g4-20020aa79f040000b029013ed13da13bmr26658933pfr.35.1600354756169;
        Thu, 17 Sep 2020 07:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600354756; cv=none;
        d=google.com; s=arc-20160816;
        b=NseIdhmtjp6Xer3EQWPafPec92iuL9i0mFTr+gUVSE85FKGm6v3MOQqKJ1Rbz8Wu/J
         TYIQKfagJlfFsQwr3s4uBOb6FXv0ID905dkzEI/QGNnor56v668uCwH3h/vM3rq21Szp
         IjVoHUYvf6QEat9/82PvJGQ2L05Tj+atPSodQEw/yAgctyEEtG9NriB+CQPbOk2XiXRQ
         iX/hbJD0Z5QvVG0Pz2rHGDIaorGqjaRxr/3Tp1+s/uzjOSwbmNmZud9DBUFH0Qu1b+xc
         2wmHVVT4hnGbJXeur2vdqjFX28JNcBwqG59bmyw2iCl7OZP80BZ3czWYnlm0GKm8bopY
         lfQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4j027av5OwuEBECvjVAZuLuTSmTIvj7LZ7tv1JoidsE=;
        b=L/SVLHVE4t0Dkt1TatBoJfj8UW/Spn8GEIzLk/j1ArUwhF1U3JjyjrPZfDvEiV7Fs/
         GwzV9a/KokU9/sMcnb5xqp1KuaLKWQDt/Vub64R7yRb21nMqnq4xBnVEmDIHPmrsZZ5i
         G2gAsVRjpZqzZEDp+niLnAsT0mCAZDga09jtHqH5WK4pUbxqUsd53Cz+jT4bilwAwLnj
         35oZTB3HsRoPee7cMPHM5U16j9Y5d6fYOet6U8/1Tq6ni0zvrUqmlXatEL2w7Qb5zW03
         QVJfE4HSgqThGTg3OIJnirSP4fTynOin/kN7F96J53TTjU/k0Mka8QsWDF0J66W5RGWz
         6JKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 129si8022pgf.2.2020.09.17.07.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 07:59:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 61ED1206E6;
	Thu, 17 Sep 2020 14:59:13 +0000 (UTC)
Date: Thu, 17 Sep 2020 15:59:10 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 24/37] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200917145910.GD10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:06PM +0200, Andrey Konovalov wrote:
>  static int do_tag_check_fault(unsigned long addr, unsigned int esr,
>  			      struct pt_regs *regs)
>  {
> -	do_bad_area(addr, esr, regs);
> +	/* The tag check fault (TCF) is per TTBR */
> +	if (is_ttbr0_addr(addr))
> +		do_bad_area(addr, esr, regs);
> +	else
> +		do_tag_recovery(addr, esr, regs);
> +
>  	return 0;
>  }

I had forgotten the details here. The TCF mode is per EL, so TCF0
affects EL0, TCF affects EL1 irrespective of which TTBR is used. Now, we
know the kernel accesses TTBR0 usually with LDTR/STTR instructions if
UAO is available (soon to get rid of), so these would act as EL0
accesses using TCF0. However, we have the futex.h code which uses
exclusives and they'd be executed as EL1, so you can potentially get a
tag check fault for such uaccess even if the user disabled it in TCF0.

The solution here I think is for uaccess_enable() to set PSTATE.TCO,
restore it in uaccess_disable().

We get away with not toggling PSTATE.TCO in the user MTE patches since
the TCF is always 0 for the kernel.

The do_tag_check_fault() above is still correct, apart from the comment
which needs a better explanation on why we do a is_ttbr0_addr() check.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917145910.GD10662%40gaia.
