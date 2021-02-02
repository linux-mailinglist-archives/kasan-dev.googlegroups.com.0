Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJPG4WAAMGQEOAVCJJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B5E5430C42D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 16:43:35 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id y8sf2949315plg.5
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 07:43:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612280614; cv=pass;
        d=google.com; s=arc-20160816;
        b=v1mQRbuI2W+lhGRE3uNbF6iJgI8QgN0D2cwJ6xPVOqQr6av08MCRujgCoqT8CXU962
         Bx9g0vpE3g94E44jnwpEV5yTk4PeFboqSMVo4Je0BZKB7hciMwn6gmOmPhX6VbflV+y0
         WxHHMFmqhEn05p+DUARHbuuee9V9KNfUTrjxVyGZArO6h5A6L7hdPbdH4XQ4oJSDtApT
         OKpzW1gdQ90HKPUAN9GyG+K+HyTGtbaqClf5NlCiRXofHVAunspu1Vs2QQb+b0kN8BMR
         4OE93faqixJiMl9WF6GJkAW+iSeXIY2g3HH0BjrAO2XnSp+xVF/FjZF97XjMWNU3wDEM
         Jj2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gJnlhCurupxRg9BR8AXk2t/5Q+dyl1m21ajo368BD+k=;
        b=Vk++DkVhwET8olj1De865GedoVkX7g8hRWwuy8jji5o8Pv0fcpwsaP3AV2iHPz/8lu
         pwn+5/Sjs8A9GESTsysm5XrZw9NtHtFGRHJ95zKswjb3cgjlX9hwyMVzd6mWK2vj8T4K
         UbrSpSkQxRA2CAPpheV/EmSj825ms85eaG7RnAzICcW9u9PrLapORBMZV2UkyuSiwaKb
         MrZfQ9nEMYsl0blvB/roz77xSyD/RVyM02F7ORbc5QjfP+xhUdIsHQ5+KXEhgUqSessE
         /lm0v5EZ/8i+DW8QBIAcAfM5mkG2vTmoQfcaW+BrqVPSmjCeGN7MS32aQ63PTCWF0Wrh
         xm5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gJnlhCurupxRg9BR8AXk2t/5Q+dyl1m21ajo368BD+k=;
        b=i033AGmTWSRQjQGU5SHrFtuLS7KdgCM3NNjmbfiMxz/jKQJi0+UEK+AXFt7drPkc6B
         tJP9P9JdgmFt6waRel730wc+zP0LT3gk6mibrpeYnOAPA7fh0Ehse1h9kuNk/MMSbU1p
         fRS3cJqVTWbWWp80jVmIG3B+NnlpJfCV/ltbZoVvOj51s+HiTIDlLcHl+33+b/GoOSFH
         ljvLrGbdEVMU/MMWWw4gkz5k/S27O7hbsgbojlOln0PWG8ORQoY7tVHaOJV41T1WQfy6
         DJ5cQmmEOu+dx3OvmG5dmQuFaN8QQdrjmQ8X0z8D9/TY3av+TI2BlC/sKvjy89yOj/ME
         CGWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gJnlhCurupxRg9BR8AXk2t/5Q+dyl1m21ajo368BD+k=;
        b=LQ3ipj2RV2pSjFcD7nAULMORvC+NnIyXu0JJcwWWOH63lL6HaLTjB5ktnIaC/K5wIw
         o2vCqkCSDnCIBM3t/KyUpX9j9L5RocRBRWtTtRCBs0wji+dIYExhLa/IaPC4DGjWit8w
         eQUPsxW4F9sdImzGSCJ/cvHuwiI7gFM+L0Bf8OBthHslyKo0dlrL5NJ018KuCeiKkagD
         l8UAQAKVVhWptF/WCYa6DFLdnrqnmVVGiwNxrp6ghF0ghowckjD7Ggh6UP5j9eQQ8VTG
         /uFE8KAhy33syNXzhaMBFpoTHo69G5C2OBqBgYGi4XEHwByBdCetCBNmWx9etE9OIDb/
         69WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532h+b7pRirxBQm2cjltx8q5YBdYvCzvspNMP3g8wqBfWGcnkHIK
	Gi4bmwymOHdwNbL0VnuxJBA=
X-Google-Smtp-Source: ABdhPJwAzwb8NogLvTy+wZtZexp3+qCvYgkLNUrJ1oRpqN/ArhEN2DvHz8IiJH1MK7VRAli6rBc5hg==
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr4969015pjb.166.1612280613932;
        Tue, 02 Feb 2021 07:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls8039788pgc.8.gmail; Tue, 02 Feb
 2021 07:43:33 -0800 (PST)
X-Received: by 2002:a62:1e43:0:b029:1cc:9a5e:c852 with SMTP id e64-20020a621e430000b02901cc9a5ec852mr12381276pfe.40.1612280613153;
        Tue, 02 Feb 2021 07:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612280613; cv=none;
        d=google.com; s=arc-20160816;
        b=dFMIntrwbICXkx+RURC40uqH2Ca9gWxvHI1X1tdRD/VzS8job0IUjuBNKysyXPiiy+
         jGOD8z6VWIZnJUcdzhgtjDZSIFslrEfZTklX3dcGx1gsxpd4nuSUiGGxP4EpdN0jbxUq
         URf+AIqWeUA9662WhefmwKtpcQVNTAIT62VOr0FA2SEiZcBNpBJzaBdhofF3rwC11wYB
         WxQYsdd6JMUiYNX1Qw1IPC1o3hvwC82lBij3gwK2Oo1vSwRzPPaan/lZI2GV4JkLfcbl
         OtTBrGs5mqiaOsnDQuvITCNd9MeOcYNOVP7ok/TowiUH6Pn23P2l67eD3HL55to1W3dp
         MjbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=pB2M6gbNmXLU2B5jgoMnAUjxUVWm2BAt0NkvSWaYKMg=;
        b=xxH82gXezlVWkxj5DpGIJpP93TzLp4Qt7AJpGnzGp+mD4EoKvVjlPRky5EJvIGulx2
         Swa/Yrb6RWqEL4RDdug4ffrgisX5OUkilD6QIgVyLfe6eADTRoKX688Ao3z+RqBKoOZk
         DkBWHo3gYn1J6B+clZHp0nAknyQ4QrkvZw0N3Hwtx9oIpDno9EPWx5TVj+8QTvIXMJ93
         ipUUFlVWAxkpz7ZEEW4nM0WdmOsr4oX/FcQdI8MGM3UaPcdYjJQZENy5T0rhQysv1JM3
         Vhj4xei8JirvqQfwt7++juzTZxnRgy2VttUpoWv6tlUdjB+8BiTUWazdJtgOzOtK2s/t
         unXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c17si205941pjo.0.2021.02.02.07.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Feb 2021 07:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 149EB64F65;
	Tue,  2 Feb 2021 15:43:29 +0000 (UTC)
Date: Tue, 2 Feb 2021 15:43:27 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 12/12] arm64: kasan: export MTE symbols for KASAN tests
Message-ID: <20210202154327.GD26895@gaia>
References: <cover.1612208222.git.andreyknvl@google.com>
 <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Feb 01, 2021 at 08:43:36PM +0100, Andrey Konovalov wrote:
> Export mte_enable_kernel() and mte_set_report_once() to fix:
> 
> ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
> ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/kernel/mte.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 8b27b70e1aac..2c91bd288ea4 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -120,6 +120,7 @@ void mte_enable_kernel_sync(void)
>  {
>  	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
>  }
> +EXPORT_SYMBOL(mte_enable_kernel_sync);
>  
>  void mte_enable_kernel_async(void)
>  {
> @@ -130,6 +131,7 @@ void mte_set_report_once(bool state)
>  {
>  	WRITE_ONCE(report_fault_once, state);
>  }
> +EXPORT_SYMBOL(mte_set_report_once);

With EXPORT_SYMBOL_GPL:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210202154327.GD26895%40gaia.
