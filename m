Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6UT62FAMGQE35BQKQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 480C0423CDF
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 13:35:23 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id m17-20020adffa11000000b00160c1ac74e9sf1776423wrr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 04:35:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633520123; cv=pass;
        d=google.com; s=arc-20160816;
        b=UTXa48/tJBiwu7qw94tCaYnMFaLUThCCzbA1vNhJh9NQzLlUcDw/2YfhjK4qwYWPwF
         Ts7nX5ufV8Rn8GDV1SkFdfgTX0v2ycI2DAXyoGvv4IVogk/G1xkz+1ywC8C0ZN4/rMbf
         L+WsBQEsQSU2X8ShuSVOKu3Qprhz4K5FukLiofsKMFMCDarAQqpPdZ+8hel/F0JKiUPc
         5Y8xblXNf/ns6QpR07DFxyMzeyKAjb4Rex5X+96mzIEJmfzywW8H8G7e06DfaR65+CLY
         i0U6taUxzVYR3ag50mrhJXc+iRMqutph/BNnymhzu2kSg+DcldKs6LKt4AaBovQuMA13
         +LpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2CRQB+Hod4ILIGAgUSk6UZD0JZ9aBKdZi6o8Qnolf+I=;
        b=08LY3ZU/lToyz/fN7dc6ozRK/Tlx66aqqKoLDtMHowV7t9l/NCX/D6U662jUtaQ6eo
         E2VZE6e1UevTMt1E1Wc7XHJ/aJ++su/KsvFd7ygyVcRDeDvkoIKNRfpBaieJ5kBCXXZv
         C0PyAgAD1yrvqMEonzfincXXezb0ZNWOOmtLcCvPTDM8a2YLnv5wS8Mm8l8JvC/BAGb2
         /I4kkfAl39/7ghd/otVOI5FA20+oZ4LiOomgxDhRF/6LbR7Y1E8sES9IsnTz7L8YqHA1
         o1f317IkZq+iTAl1KYCVZv559+wvTeLH2u/Mf+fN9IEUi0ONQP6gkJ6FbnbE6b6mrwX2
         +/0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L2cB28Z0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2CRQB+Hod4ILIGAgUSk6UZD0JZ9aBKdZi6o8Qnolf+I=;
        b=GyXYOf7oQlr1RWSGkNtYl7pShJ7IY0ay2GmjDemjAa0muscBgcHjcJ/X/Lsld3JsWF
         ykkyZ83lBWXkA1TYZ26+Ics4mBnBDgr0y8uB6jsFh33YbHRjTaVmaNnNL3SeJTp3Su4A
         e4T/FjFj9t7P7TNMPMvfJLZ44FF+PTTCXj5wuoFzc9cTUe91LCe6JzjLsw6SLOzqc64h
         vyy2abHnr9WsBVn+ccgyGr32kodp4lvkmMhLOtPQYffshcFVpl1xcFJycH3wfv1VD+aM
         MNOQXGp9Xck+9R1GBMkcWBUtat4+Fzcd6X62KhFduJZrABxskjEN9PjuboaefsoZOdp0
         8Iug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2CRQB+Hod4ILIGAgUSk6UZD0JZ9aBKdZi6o8Qnolf+I=;
        b=fsPZmc5zdNMOBg0TUfk4GYRQeBL2EvW4cXPJyKkx33nFLeQDKV8kCBRz+w7lFbGbDe
         Ps1ObiSvtKDS2tTbKcyybzl6Ig11uMDkUiGu7wfZGtLAOAYuB93hJDMoLBfHYfItjgHp
         tS3S2ETcDJcVeQx3gSVU+XeiRDy+djcTeUiHg7RfxN6Qg1rgAbdQ28zjOJCzWCCrH1PF
         CohO3wrS6xOm4mdYgAvCbqFLFIYi2Q4KpHDX0Rd1Tbp5dsE37ZDX19i97P/E7UUsJbCO
         xyymRa9tfKbnb8W2rLjj+Ma6wdvu8QYVmgJgKWPVu8PnPa/bM/zBJxrAtR2muchGj5Z4
         EcWw==
X-Gm-Message-State: AOAM530IWbPqJYTXigiuU/OpXKZ9tK3D0QuNeme1M51y2weuHFjG+3e5
	D6wKi/2rgZjBLM3rm0TzvUs=
X-Google-Smtp-Source: ABdhPJwJ/oZa8TOG7LZRv+ksUoH88Ki6gHKzRS1YHxf+LKw4cHjuQ/EbQbV7nN+PDtg2YjKjYrrMtQ==
X-Received: by 2002:adf:c992:: with SMTP id f18mr6779360wrh.138.1633520122956;
        Wed, 06 Oct 2021 04:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3512:: with SMTP id h18ls197558wmq.2.canary-gmail;
 Wed, 06 Oct 2021 04:35:22 -0700 (PDT)
X-Received: by 2002:a7b:cb01:: with SMTP id u1mr9214873wmj.65.1633520122032;
        Wed, 06 Oct 2021 04:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633520122; cv=none;
        d=google.com; s=arc-20160816;
        b=fwbmBHHOUhZ5iZZSP26us+H/SO7n2XhmiNSEPz1SHxZch070ExzwwlPRLQuJEjSYRa
         WegNWrCJxKuLzNQspFU/KQG2fz3hqmNNNqznv9IYv70jvUfAkImLtdjtcZFgU/Cqs8uj
         oJRF7PVGghXgaK6vexrN+wjIWecF2MMGa7RdhkigytELf5AtO586dm2HVlCxWnWuVjQr
         WRH9FVf7J0OW6v51LDQkNtcG/PuierrxNaClA14BemFCPTnwVjS1OT/+5W08sayMJWhR
         4wEfcWIKAbaOe4CyInS+bM8iG5dsWYX7t7ms1TTCnMldwSqZ+j4xZ8lrVp5oAL4kwZio
         /GnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WlB+aQwesSqg+PcbUJ65iZtpYtFLGZhjloxXmDYdamI=;
        b=TNSQ/IPgHxJ7rvPZIGYkBYxPmjmHs6uIkNmgQ6D9pDL2zHobFb3sKKpofCUdVwAZzi
         u5Wk8KPuWQPkQzyVTIdnQVdK8h5yckbnaW+IKGV4P0FWLZuF1KxXbudgEs7Xd2THnXXM
         nopmoWK9LN23OjqKAxMqMN1qHyV5GQgWtkHT7ixSGqypKy8JDShl10pMFjn+B0j/VPTO
         7XSO6glPIMNrjmL33pJK/F9nNTXyLKn51gAQ4TQgfJQ1IMONdOSs7kOatCnaUWgPzl5S
         BDtuG39R4q2CdoXK4Ll9A9d+rqmi2VtR+ojs0L/FYDLnd9fz4jRkHIB8NxmLTar9oSqE
         BCyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L2cB28Z0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id g8si1233029wrh.0.2021.10.06.04.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 04:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id v17so7834559wrv.9
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 04:35:22 -0700 (PDT)
X-Received: by 2002:a1c:43c3:: with SMTP id q186mr9058705wma.143.1633520121547;
        Wed, 06 Oct 2021 04:35:21 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:378e:f074:3bc9:383c])
        by smtp.gmail.com with ESMTPSA id n186sm5079756wme.31.2021.10.06.04.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Oct 2021 04:35:20 -0700 (PDT)
Date: Wed, 6 Oct 2021 13:35:15 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
Message-ID: <YV2J8/i7C/FYf4F1@elver.google.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211004202253.27857-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211004202253.27857-6-vincenzo.frascino@arm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=L2cB28Z0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Mon, Oct 04, 2021 at 09:22PM +0100, Vincenzo Frascino wrote:
[...]
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  extern bool kasan_flag_async __ro_after_init;
> +extern bool kasan_flag_asymm __ro_after_init;
>  
>  static inline bool kasan_stack_collection_enabled(void)
>  {
>  	return static_branch_unlikely(&kasan_flag_stacktrace);
>  }
>  
> -static inline bool kasan_async_mode_enabled(void)
> +static inline bool kasan_async_fault_possible(void)
>  {
> -	return kasan_flag_async;
> +	return kasan_flag_async | kasan_flag_asymm;
> +}
> +
> +static inline bool kasan_sync_fault_possible(void)
> +{
> +	return !kasan_flag_async | kasan_flag_asymm;
>  }

Is the choice of bit-wise OR a typo? Because this should probably have
been logical OR. In this case, functionally it shouldn't matter, but is
unusual style.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV2J8/i7C/FYf4F1%40elver.google.com.
