Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEVNW75QKGQEESTTSXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6840B27860B
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:37:56 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id c18sf1914137pfi.21
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:37:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033875; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/0LkbQ4lPT481Dl2S41qZJWIHicFvOSXGu2z00CnsDHo1sqMdN/0ZtJKSJhY2hNkz
         M3oQFYQ7ztNe3Ic9wU/fgUfJ6BGGHyiK54AMrzS1LZSMu6PPNN5GkTjwyMTApNP8RPGT
         l5JvzgwcarTri5FWjDla1h2Vm6x2E54bEntNQlo3JcY+fPfHEDUIfMhNroDtt46kA1Wk
         HcSWlyzuivwSVu3JVbQ72yt48S/g4TQcdNO0KMnBY0l5xf4HAJWiceMRMtoTFqjBdQUP
         ZeM5OC/WrO4J/I21RDZCD1tdfMOSVrGx8IbFFooMKI2l2z5PZGjdwdfTizwczb/clj8W
         NcZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5M33e4Y+xKOHZXD5e86Fs7a2K3JwjisyPFGOSYKgxZ0=;
        b=SmD9XNq4IOhcpYdPa0hyS4ZZl2DlUGxgy7+4iYM4NxQTjdVUXm1rUbnvsKbEUDyufA
         KbkZy3lnRJ30DGwFHLmaniTxVLf7cS4KVZ+djg5zrB3P4bia85UpitwDZKQxfPtgLcO+
         qGEUhelBB2zQP6r4CMl/LZVSJCcMHOfWDpYImnWYYYghj641wT2YNrbKPxx5ofwrqS2l
         xWU71pqgJC1i64UVYzv30l4OT4lrjYTLK1ROnG5qOFDhe0OE48d/M6iqzf1enbLngUfn
         V08+6pgXi67MH8tteK1wxGptt5tPpGTpXfEx+9BZzoU2qOWTKU0rjUXA8AvwvkvRbH2D
         4MGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5M33e4Y+xKOHZXD5e86Fs7a2K3JwjisyPFGOSYKgxZ0=;
        b=ky25cuZCIM0EAmUd9ZUFkZBwDsLVAxRXiDpSUdVDyCXal+ens0K2WxX2e7BjN4wLoI
         Ir6BygKZXKni0WjUT/sQkfD+v5mOy7uQnBTjyvUIvLV+Wt+YJOTEhi4PWszm4z1ziqah
         lB3xpriFg+4Bl+G/MUoDFmI1TkXtJ+glxrcxWjS0Pr7LuaEcjCogc8PUmjCOJZQfAMMm
         CJXXg0XTmiGFX3XfpJx3Azfk+f3VcXDteoAFo+iBKalI8L0gJJ+ZH9N6naj/+uL7n/g4
         eQFU54QWjSzm+fB+8eon5UiUi/85IaTYi0cjX5mrDka17QiC6xTehdrO6yi/tOEECk7T
         nWAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5M33e4Y+xKOHZXD5e86Fs7a2K3JwjisyPFGOSYKgxZ0=;
        b=f2bRGwqsGnSFljPzuc7xZvCG/rvQ9rUxco4BOiSEPswugDQyYom03bT7/nvqH8Gv5d
         XR4jXvHd++Dkxrg5taLuG/xJqG509kQ32xlbLcVIxMGEtWwWuFdlBDuZ6SwwYm8K/BMY
         A4DQX46lzXxZMMSlBDr2T8tNWk/CIsfmjfqyFP2bFBe6f7JXTiH+XyY2q9acUHaySLqm
         yArFSbGhwagtCYvTr9aXLR4ScObCYr2q8t8Yb61ftN6+Ymvo/UdXTqgUkp3hMU/yjqvY
         1WEDVL0ZFO+5V/HCUIB3kcSsa1mCjpAKYkr+Y4rPjCcR1SzmDyhxjZDFDicC/nX2MZwl
         xDlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mgH1lw4Bg0tyuCFMfVCg59ST+epF6o2T3889t8bqJQqkJvgzr
	Pg79XU1VciBb5+j0FU865nc=
X-Google-Smtp-Source: ABdhPJwgKCAGl4Ou1HxQ4EUcFI/abEt/+A0kdt7r0yLoRw0YTzyJxi9JaA4x172SY4TolD77ju1gKQ==
X-Received: by 2002:a17:902:b688:b029:d2:43a9:ef1f with SMTP id c8-20020a170902b688b02900d243a9ef1fmr3904529pls.9.1601033875114;
        Fri, 25 Sep 2020 04:37:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9706:: with SMTP id a6ls978909pfg.9.gmail; Fri, 25 Sep
 2020 04:37:54 -0700 (PDT)
X-Received: by 2002:a63:1226:: with SMTP id h38mr3063538pgl.196.1601033874388;
        Fri, 25 Sep 2020 04:37:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033874; cv=none;
        d=google.com; s=arc-20160816;
        b=q4YHUaS1N03/MnSBjZPmN3TWBpCOGEoPMJa00GL4m6RdllU+FhUTyHotjAX+2xay2S
         2RAPSJ7b2HGN3u67CDq5U3wxVd91sOR6t9oZvE9MHsRsvVXsj1W685q+brSB1CWQAIHj
         C9GBACiGRBpXleAGPVU8EdC1NprLk3tOhmKAkiJAun2KzwVw7EIOU587tY3vVQ1FiXzo
         WRgqsFQLHyrwqhD8KWWZtFduf3xxD+c/7p/1wPG2784nRcCmg/edQ+l58545N3zy0jWy
         vP4CYarFAtYQDskqvVLJji48CDBcRlsQQiKcKdqvJQ9dsb6ewFduONQFzjCvV8qceQc7
         82zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uITAw06iGaQA6nOLyt24CeMeNAv4z7e38FR5cUKws/Q=;
        b=biYOX1oxzWcv17WTnrAf0TY68Wf+X1nayrLzssMJuYdykNh3NbfnXqD3EEYDu+670q
         S89GhIs566N7pH9VrnJ7q5fI+ku5E+UxMWLVleabKcCXQ1Udbsntpnm1IQIoBTeOb713
         ct40ym7oh9WHNSuNYXe13cssdYc4AqO3zQGdICqpTHuYZezPB0ifUGAgNkwGoxqBZSi+
         paye8VDuuPu0IbJNQl/PNq/cYUm3qwZYFyRFJgm7u+U3Fh6ACARK5FSymMHC8DJyMwix
         vpAtI4N7Bz0kog2oitK6anCJ9QBqipZHGRguXrlNk+3gxG8rMnVaxrlUa+YrP27nf2BS
         u11A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si219265pjj.2.2020.09.25.04.37.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:37:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A76E82075E;
	Fri, 25 Sep 2020 11:37:51 +0000 (UTC)
Date: Fri, 25 Sep 2020 12:37:49 +0100
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
Subject: Re: [PATCH v3 30/39] arm64: kasan: Enable TBI EL1
Message-ID: <20200925113748.GG4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <733e94d7368b54473b242bb6a38e421cf459c9ad.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <733e94d7368b54473b242bb6a38e421cf459c9ad.1600987622.git.andreyknvl@google.com>
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

On Fri, Sep 25, 2020 at 12:50:37AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 12ba98bc3b3f..dce06e553c7c 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -40,9 +40,13 @@
>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> -#define TCR_KASAN_FLAGS TCR_TBI1
> +#define TCR_KASAN_SW_FLAGS TCR_TBI1
>  #else
> -#define TCR_KASAN_FLAGS 0
> +#define TCR_KASAN_SW_FLAGS 0
> +#endif
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define TCR_KASAN_HW_FLAGS TCR_TBI1
>  #endif
>  
>  /*
> @@ -454,6 +458,9 @@ SYM_FUNC_START(__cpu_setup)
>  
>  	/* set the TCR_EL1 bits */
>  	orr	mte_tcr, mte_tcr, #SYS_TCR_EL1_TCMA1
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	orr	mte_tcr, mte_tcr, #TCR_KASAN_HW_FLAGS
> +#endif

I missed this in an earlier patch. Do we need TCMA1 set without
KASAN_HW? If not, we could add them both to TCR_KASAN_HW_FLAGS.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925113748.GG4846%40gaia.
