Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY5IWD6QKGQEIT75B2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 36C5D2AF6BA
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:42:12 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id h12sf1086864ljc.13
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:42:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605112931; cv=pass;
        d=google.com; s=arc-20160816;
        b=a94c+7HFb684RStnIUd4EITHCUG0kUAJjxu9hJC3h5XaeP+/hqj7g8/TNXr2z1AK3t
         yxGfVw+JdZrQL6yddxTib+GkuVtXuzIi/dXG7mjv5HgxP04Oz8hZXsPoHTW/RIBdVaO2
         rrNnj66eGYqOf7SFrEnc4itDVMy3wxegUTd5Jqsl7SLqOSuPfWcqb7Dxc2v9z1JJyIwS
         2FVBrYK6sS1H8h+C41dWYT5l32uroICFQH/fuD66eP0bPQQsB+21+xVbQ2MUp8q4XuwK
         wcbxa1yaMufztA1ZW7XUqbF7QuJiyfu88T00U1fZFKrrw7H55Qbo5sRb7GVmLsG0nzU2
         VqPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0Zj8X9IXPjKLQuOu2ct1J1jEtak5/bJG560avl72zHo=;
        b=iLmk43c3QViwyOd39Z0sSd2tVaYU/gPyqqFwkK9WDlJIwhxM59OAmgzGvE99hiJtpD
         8oR99RJLarXcVZy1xr2zQomoo3DlsUJ4r7/SXoAkL+d9Far8zqz9ZjG36uo8O/LaZfPr
         r8j7WraBF3sCs3VBMrp1Lsw/XGYJDDQahbiwMvmVNuALcuHbPKwbKQ0zNH4egvIY87wS
         1zdVR4YQX/RpITZ3DHEjWU4/0TKfedk7SNnszBrqWS7C/3Uqtq4RHb7qf/yxOmIgPLw6
         4fm+HF+AQYX/batK1jaLjncGvXftjcU/PojnVTDposFP0g4/k2l1BlQv8fsJX/LKRyeH
         n/gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iZzMR3JK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0Zj8X9IXPjKLQuOu2ct1J1jEtak5/bJG560avl72zHo=;
        b=EZfEXIrpfmr6THju3W5m9T7x1qKbZcFSpJGgu92klpG8wB8rc7QpmJS9EKE+wPklWA
         or1uI1i8K0/ZXTI89vhJeX3qr7baxgWf7EYA1M9y7e/ygT39tQfBHApQwCTy81nxE5lS
         g2MoqWKj5Qdocbz9pn7vSsQKAjskAqWOhURX//HCxi9aWzniIEnAMSQhh13vhOYdMbO2
         bbNudIzSD3v8SqoRfGTWWeu7rcaAc9LRQMxjdlHF14aS1FP61ShwzYnYPfqWDo5oXK+J
         Geebp+oxLad7rp8L+Z7izmsMnsKFTCr96tmoo2xh5lw5e4+RUcxFnUpebo/QBcwt+6P7
         BO+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0Zj8X9IXPjKLQuOu2ct1J1jEtak5/bJG560avl72zHo=;
        b=lYTNAOEZ07nMf+kztRXeYbFs2FLv2xMnKTDU1wDqrSlBP+lqVpomupRKHXEdxGM3xn
         ackTCSeo0tckyW8YLxhkI/pCJ+cjpl5v1Mk92VCpJ7AV2RC1FrKkGNaoi1cin6mfcpIA
         m4FJYvKp2vQLy4k3sPpArfe/xHGdfBAUh4gJn8p+54Y3WKJYUNMEAHSWabwwznTYow3f
         PfMT93eLBeqF3og5LOONYzRixI0rl+2qfozWvUo78Ml24ii5Re8xiGD4IELLQMAgP76x
         QAhk7rotJQlBgj+5s+d7I0Vqsv4ZNdhHYlxi277ymJbELyom5hjwclgpaBB9VvgAAWSI
         vBlg==
X-Gm-Message-State: AOAM531wT2gqxbtQnYVT/loYC4Cl88pOHxiNaY5VMKP5nbFVDOwQKVJk
	bCkW8W4JAsLilWVOjCiLhZg=
X-Google-Smtp-Source: ABdhPJwKd0Mss1LPKx0C+DrTfsqkBA+FxsG/fR/WuGCn+bg0NTJWwU+rBIhjH1o67crB7vWeOWtBdA==
X-Received: by 2002:a19:89c2:: with SMTP id l185mr10555864lfd.92.1605112931785;
        Wed, 11 Nov 2020 08:42:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls70001lfa.1.gmail; Wed, 11 Nov
 2020 08:42:10 -0800 (PST)
X-Received: by 2002:a19:857:: with SMTP id 84mr9375148lfi.235.1605112930711;
        Wed, 11 Nov 2020 08:42:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605112930; cv=none;
        d=google.com; s=arc-20160816;
        b=ncellixCF6u4mzd0EdXmN24H0dyRPDscS+YO50Nz/bTI6TPEkWQlDYOEuV8BihD7dP
         e75WKR4hcp/UjqZZrXuteL2ma3ZReCp4zhAkPONJ8KwgRUPKZ1ET1dScg8OFLh65gQ0X
         AvikUcSWLxl4WZPqR0zXELbH1I+44L8F94IpWvJ98ftPl6f6l48qSEmQB722sQuAsGdz
         8a6b56gJbsHrzn1XtUoU6K58T8/4bUAoafVWfGxsfNgEPOC8k3/RcMc+eXinH8Eozlyl
         b+yVmxL5tCG/+If5eVSUygTkdC0tQVdK4zftPF0cafyZpPAcBQrmBw5ijcdbrqCmtUcg
         7LHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NA9CfSTIvFjKTTcCo0GBZExn6gG0rmPxEPFJJSh1HC0=;
        b=u9OLfc/lT10PTC0fWrebMrheHya6ila+SoMVQ0a9cwLLi0erfJy3dH4midCrr/KsLX
         HP4zfnDNkfSoEufEW3F3rwK9O7sdK+vNQALedpi/kFOISF3XcHISO7NdfDUEIhIC1CgE
         AFTcVt/kCNPdRyqTzsiuN+/T8zuKUAsdYB5LBm7rnOX6ewrKIK4hEajnv2zrljyYM6Eq
         +r8XRSUrE4isbUR4dGXo88ZL8paocARYgmgYBTygUSKpmhkYoSLM03+uA3zjAZNhxoaM
         DrNRXP22F3sGbShBaAprPthFaiiyl1aYGY+47awoeCi9qQCeEg4LK+je1yqWSzMbB2zg
         CgcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iZzMR3JK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id q11si67861lfo.8.2020.11.11.08.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:42:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id s13so2913718wmh.4
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:42:10 -0800 (PST)
X-Received: by 2002:a1c:6a11:: with SMTP id f17mr4945240wmc.24.1605112929933;
        Wed, 11 Nov 2020 08:42:09 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id z19sm3076154wmk.12.2020.11.11.08.42.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:42:09 -0800 (PST)
Date: Wed, 11 Nov 2020 17:42:03 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 06/20] kasan: remove __kasan_unpoison_stack
Message-ID: <20201111164203.GH517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <462c375f39ba8c4c105b3a9bf3b5db17f3720159.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <462c375f39ba8c4c105b3a9bf3b5db17f3720159.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iZzMR3JK;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> There's no need for __kasan_unpoison_stack() helper, as it's only
> currently used in a single place. Removing it also removes unneeded
> arithmetic.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50
> ---
>  mm/kasan/common.c | 12 +++---------
>  1 file changed, 3 insertions(+), 9 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

Thanks for spotting this simplification.

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a3e67d49b893..9008fc6b0810 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -59,18 +59,12 @@ void kasan_disable_current(void)
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>  
>  #if CONFIG_KASAN_STACK
> -static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
> -{
> -	void *base = task_stack_page(task);
> -	size_t size = sp - base;
> -
> -	kasan_unpoison_memory(base, size);
> -}
> -
>  /* Unpoison the entire stack for a task. */
>  void kasan_unpoison_task_stack(struct task_struct *task)
>  {
> -	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
> +	void *base = task_stack_page(task);
> +
> +	kasan_unpoison_memory(base, THREAD_SIZE);
>  }
>  
>  /* Unpoison the stack for the current task beyond a watermark sp value. */
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111164203.GH517454%40elver.google.com.
