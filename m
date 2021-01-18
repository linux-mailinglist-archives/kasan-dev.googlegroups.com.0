Return-Path: <kasan-dev+bncBDV37XP3XYDRB56DSWAAMGQES6Y5ZCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F8B62F9C4A
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:24:56 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id c18sf12863926otm.18
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:24:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610965495; cv=pass;
        d=google.com; s=arc-20160816;
        b=ziqRFBjw9yZxagzykK1mQ2oKSIHOux5kWrA/nwcPR+AJgMQz5MT+Hi96pExIWTDc+5
         WWiOINV9YllmJiJoo1oOXwPsgOqFBczfXVFp0PlWlRgUpaxAri3I1Tm248RqLivGiTgx
         a1lvzS/U5ah4NEBvDCUVKAGxw3KPSF9BEVDTJwHFzyXYXliVEcqmLWcQ7+RmdjuTs8b0
         z2dlKJEMqaWYFVilo7HQibcJiS2rLXfkTq9YiYEpeHPizN1OOZJofVLfift09LvX+YGn
         qSAV/RWI3TS9QnO7DUvmQYCGZh+rQNRqevKxWKt79CxziJJMs0I2XWrgGd3T3b8pjA9t
         Etjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HKhVZzuJEVsR9eRe7JupPHq1vwf2yrP/hf8McBHouvM=;
        b=bWiAZZ9fDZWTT8Du4Ws/P+jwBHuOfKypCwdYnRp3Hcwo/en95UX1zUzjJDRZCJdkZb
         Xtg7lzc+kjEmMBI2BEKzZXH6gu5JHB92ZCdUNtZz93fV0tFf7clT9kErh9oa5dAL/0ol
         fpvqCKNTVuYvSmwnvc6JT6HGa4w+MG5m1V5oSuzJESe26l3VyzLjCvIKev8cqZFWW21A
         Eph+tON/l9AXH8i7Xg5AEMd8YlboostVbYq8mfz3zzmlZXD66UcgaqONQR6CUeh5tnc6
         rU6WrvxluZud1RpwduvZ+riFD2mZt3dCADclsa3EZcE7vmRJVB+vRNCD7w9tbkt6zj+m
         m69g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HKhVZzuJEVsR9eRe7JupPHq1vwf2yrP/hf8McBHouvM=;
        b=aINnvSKBkzKrb5VBXECNzg1yd7Kn8+RH39u9VzGUMsXma6Q5pEczB7qW8IU4dDdcMP
         tQFg3eT0IhuH8di7hrUom/CeL4Cbz2Ttx7qCGP8iS9ym/czokf6RN2HZobQtrNBHuCLD
         1a4b+hHiNyeOPCBOPh7t9rc3rTeIWEFrcAqGLrmcZpWHpbg1oRF/HfI0SbYIj4FLPNHL
         rnUEFDeRwsso+aTmmOSZBSFl1Zey8yer+KvH8PcLAhUn8kL0/5ia4wPKmGPuBZBkaLh/
         Q3gByOhVrykGqoIPL4ctIJDWubdx/usHGkfo3WViZEh1sSrpo6EIuYGCZNEVMyRJNbw1
         0AEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HKhVZzuJEVsR9eRe7JupPHq1vwf2yrP/hf8McBHouvM=;
        b=ZekZPoDWoV58SGY7bsoGxVwrXmsLSNPSneP+Fn6Kz37S3GT8kDOoIrRBK/vzEaYO08
         Zti+zYbA+kom7kRbjX3dPYdi7u6z9P2SfyxifgdTNmJtJYKUqstBU9DnX6R61mPF4WVC
         7ZU3I924yfL+Qdklne7kdYBgHnoAdsXQJaCh6GYicEJvAoUksQ7iVVcsP+W9uDL+4W0L
         s4i7ngcgDClHkeGpp3TVpQU6dSe3Cb3xhqpV8FjqgmKd8sXxfNqT2a0juAjiit0SHgNG
         TxoCsPm4csJzAsnFPiZrwBQLEtdRkeJw/UKP27A7AB7S35Xp5Z0az9AIOs8YFEHFGF3e
         v58Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dZ0jT8ElTIMIROFX6hKtJBlMkHEoIGeRQrdBFeqSU7l+EZKdd
	EQsxnuuXf8pmZokP11m3stg=
X-Google-Smtp-Source: ABdhPJzuBTj3nIQ+hw0QocwSxTaNWXYEKXPFdJJ4+1pe88Y+Cv6bANX5D5giMDGwo5j3uEFmSO2/Fw==
X-Received: by 2002:aca:add7:: with SMTP id w206mr7587334oie.86.1610965495127;
        Mon, 18 Jan 2021 02:24:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1204:: with SMTP id 4ls4207963ois.6.gmail; Mon, 18 Jan
 2021 02:24:54 -0800 (PST)
X-Received: by 2002:aca:cf03:: with SMTP id f3mr12477995oig.39.1610965494767;
        Mon, 18 Jan 2021 02:24:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610965494; cv=none;
        d=google.com; s=arc-20160816;
        b=CdUQVIKTIG4BmAX6knC0dB3rB9DEpAn0YhxpeqcGi/lq7CfBbVMdScsj3Mv0ZvGcDW
         fMie0JfYwA4uZ+Ii7DSVjh8v9RQ+XC9IjyU8P3s62PgZBBeyCd0NALRawZUl2Dvtz8n8
         PIybFruj4+Tc3JfzW639icv9Zpao3zOGYosfZTd6gBgqhBj2tr2d1W6NkhIu8LQYMqNr
         5/WQBlTak94LhMz2Egnwe1oU1aP3eGope6Qdqp3i/JqTv4jeqCOCWPJ1VeglhQy6SrpD
         iznGPsuWdYcHaMOxqXJIGJiHNm4sy7YncBOSwlg6N3vPCdBX4TrnoD+RmdGQMgx0dMsw
         aznA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=t+5V/3k270mXymFn2x4b65/waMXSiTLsGNGcICmuxBY=;
        b=zqsquuFORtMQ6VTLdnEzKxxGye2Pff77qaQQbajUc6ObmIwKSrgjPFyjgcs5gGeD4E
         fHDjTQRI8zGT4vuI+ZrASRT7D3WOQ5Y0sUJriandjN1bztRXSmlow6XMVharhZsJ0JDb
         xwzXcHDWVD983F0xWmgfjAbouSAA8az9+KLSRhLjU7mBrPgwGxvDZlO9sSxZi5T5cQva
         A1G1xOz6lcLjefDbsl0JhwLCTlSotV6VAjGO7zxs+Qmv2/pI/eczAp6JOYhjrWsN4hXg
         fx5ia5WprCM3SjfMz0UxEdLAerggArCBgnC/knuZqq5f5QVNTV+bGmEUugg1J/CsjZiu
         9wNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i2si532760otk.1.2021.01.18.02.24.54
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 02:24:54 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 888901FB;
	Mon, 18 Jan 2021 02:24:54 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.39.202])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 019A63F66E;
	Mon, 18 Jan 2021 02:24:51 -0800 (PST)
Date: Mon, 18 Jan 2021 10:24:26 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
Message-ID: <20210118102426.GA29688@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com>
 <20210115150811.GA44111@C02TD0UTHF1T.local>
 <ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ba23ab9b-8f49-bdb7-87d8-3eb99ddf54b6@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Jan 16, 2021 at 01:47:08PM +0000, Vincenzo Frascino wrote:
> On 1/15/21 3:08 PM, Mark Rutland wrote:
> > On Fri, Jan 15, 2021 at 12:00:40PM +0000, Vincenzo Frascino wrote:
> >>  #ifdef CONFIG_KASAN_HW_TAGS
> >> -#define arch_enable_tagging()			mte_enable_kernel()
> >> +#define arch_enable_tagging(mode)		mte_enable_kernel(mode)
> > 
> > Rather than passing a mode in, I think it'd be better to have:
> > 
> > * arch_enable_tagging_prod()
> > * arch_enable_tagging_light()
> > 
> > ... that we can map in the arch code to separate:
> > 
> > * mte_enable_kernel_sync()
> > * mte_enable_kernel_async()
> > 
> > ... as by construction that avoids calls with an unhandled mode, and we
> > wouldn't need the mode enum kasan_hw_tags_mode...
> > 
> >> +static inline int hw_init_mode(enum kasan_arg_mode mode)
> >> +{
> >> +	switch (mode) {
> >> +	case KASAN_ARG_MODE_LIGHT:
> >> +		return KASAN_HW_TAGS_ASYNC;
> >> +	default:
> >> +		return KASAN_HW_TAGS_SYNC;
> >> +	}
> >> +}
> > 
> > ... and we can just have a wrapper like this to call either of the two functions directly, i.e.
> > 
> > static inline void hw_enable_tagging_mode(enum kasan_arg_mode mode)
> > {
> > 	if (mode == KASAN_ARG_MODE_LIGHT)
> > 		arch_enable_tagging_mode_light();
> > 	else
> > 		arch_enable_tagging_mode_prod();
> > }
> >
> 
> Fine by me, this would remove the need of adding a new enumeration as well and
> reflect on the arch code. I would keep "arch_enable_tagging_mode_sync" and
> "arch_enable_tagging_mode_async" though to give a clear indication in the KASAN
> code of the mode we are setting. I will adapt my code accordingly for v4.

Thanks, that sounds great!

I completely agree on keeping the '_sync' and '_aync' suffixes in the
the core code.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118102426.GA29688%40C02TD0UTHF1T.local.
