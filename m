Return-Path: <kasan-dev+bncBDV37XP3XYDRB2G7Q2AAMGQE4ZR62QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 30D212F7EF3
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 16:08:26 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id n2sf6551330pgj.12
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 07:08:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610723304; cv=pass;
        d=google.com; s=arc-20160816;
        b=HAuh+ZriBilHMNINsIX/q8IxMRsIz8scfXvvjNSdGXAkeOkSthzq4dBVqh44s7HnFm
         CJUZb9aJFaRlrOugIwKMzvEMRRbHtiWhAx1pCWLbzeXcI9ZgtO+YHlcCc0hfoRPOpCSv
         oijfxB4cBM/iNjUCzp/thChxJ3YCf//Xo+YdmzjmXQrGrdUnbhp1BT10+EUpIZrn93ER
         fbRo/6JyckDm3F/bQ8lh5XhP492MSmK/A+xLOT1U+xibiVbAdfyRkWQyGrDyHXM8fGgU
         vp65liGQM9bitQzx6rorcRWzNe6ne+KYuaKMM4gy9/ensr/UZ7YQ668UGakDPguN5I7E
         UGoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eJOeozAtSwAl6qSoIwYH9DWQ3KbGiCZFLkrJl5X2ENY=;
        b=XuFWsXtCwT6uiNLRUO2bYTFwBFqn9OZXngXcwwXjO8faTrLlItrU5tsXkzgRTzGthV
         oeQMHiW5rUCuF8cp5kNM70mM/mgRgVRGu7jAPqdnXdKc+XPiggnr700VPFwXA5VtOHw+
         ikQmnmdCiq4q6skbxcuQvBqTFDpDmxD2/W3W5S8IaZezqLU7on2aDkwpkEizHzV7UQ8h
         JhZeXq+d7x6ZEkPEphvbB6SgxYTRoXIRxfP0b64cI7NnS6TBxRdXlt77uR5JCrhBEVQF
         CcWdaqUIttSl/iSnQ4qSwTutjEFcm/swqBxYqX7v0c/ni9xVxMPXbHjhghujWe5fpJ/H
         1k6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eJOeozAtSwAl6qSoIwYH9DWQ3KbGiCZFLkrJl5X2ENY=;
        b=DUV2z2KaxEYs22s8DbaTRHNbCd66WwA/BUKhSexgW5klgFbrwRBRf1bM7R0eO6p34V
         ESi2Y/YpSBFFTSkFy4LODMcSzzDkpze5b8WDEwM/cZhhd1ZnwBkrFZ8Nyc1AkMGzCGU1
         B5m8H50h2H01kEyZ+/YoDgkg781pP+PL5c+ga0g6GWcXpx+3gFpa8r8Xz9NJ+XCET9tV
         Q07YzsjxUCWKmytvMH38K2w2xchyfrhbcz6D9HdWLsy6MTywv+uHOuhvjNeS6jmtN6A7
         iF2LZ57w19Pknd+dxnTKsg4ANYpXMA5WPbckyM0te9Rnpf7J0hEQwZXTt/k1AFcFAS4J
         z7HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eJOeozAtSwAl6qSoIwYH9DWQ3KbGiCZFLkrJl5X2ENY=;
        b=UEJgJIagp9KemZNVZmQT6F6N7TYlZsMwN3DScqULVu2cSjJU8yV5Te0fd3eFAkHNHw
         ELmVqE2RULw9cKCnvBmiaJfzGzzfI5lWTIaBKxuI+7eHFbAfINc4zDR+hjHqdf+/XSVY
         UJEBytcAnJijD3voT5PlweJZcecppieHhFrbiXNkgFafWj2IZN9Tv+hJJnuoAXH20oLm
         V2/29oliRWAns3SbPrKUjwIpP8swudbEuUqntmUj9poIBJkMqL5jdI0Fnhk5QnPRa2nL
         CPJXBbRcei2srVArM81yns+Zr3Jzze8XjPBhTBEhGCSUsXP8ovLmq/kZJcBra6feC6hm
         5Rog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iNDGQ0IhLTapaRtf94hSZrVImZ8FIsvVSvhEh5T8ZvFt+Ng8K
	KwCtfd1EMGmfY97pCyPs6Zc=
X-Google-Smtp-Source: ABdhPJxcvNs9oXyjVwduKjIwGZqvdfzLBdF1a7s7z5HuWN7btG7TN/uxIJ/CH7EIKdvfGDMqzd3o3A==
X-Received: by 2002:a63:d74a:: with SMTP id w10mr13321936pgi.134.1610723304767;
        Fri, 15 Jan 2021 07:08:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4881:: with SMTP id b1ls4833049pjh.1.gmail; Fri, 15
 Jan 2021 07:08:24 -0800 (PST)
X-Received: by 2002:a17:90a:8996:: with SMTP id v22mr737439pjn.235.1610723304186;
        Fri, 15 Jan 2021 07:08:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610723304; cv=none;
        d=google.com; s=arc-20160816;
        b=i81WvEBAiPdWOg92txJnu9wHdRoeatfl6RCUJHqEUbqhXBCZ5F4b86DlTkEPk2qjFX
         qluClDlkWwvIdLmTwtT1eQpZA0KnpWl+am9NR23N/ZD8BrYfNqJ/yW/UYtXZay/9UCpJ
         +mhyazjzoNb0lnseFfhQt3t3/7Q7EJXJp9NQSEMhXGcUqOQxl8fpS7HrKITHo0HjZYrL
         AuXwAeMlAKFDd+yh9qc62lUWJY1HNZkvBJGHNCj+5IBh+Gadkwo4we+34nr3lVa7EhiT
         wwdL34epU3FJ8G5oxXFNkKfvUfFBrOjs8GrLurFcZr6eVJicFP07vqWka/WKrIyhALdK
         b2wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=1u/y7JfHHHTF4L7W9VnuVUeer66Uyc3XfEP9bMd8aq8=;
        b=zGvVEbD3C2xjv2llTqVt/YX+rCdmA+JzYBfBfzg46XsfO0rIIG+1cRK+QUEXuj7CON
         XIjVeEOqniZSNiDePcL6XjUSVuK6MIMfgQmKUVr0eu33ypuVLU/RlDL39+MqJwbKvR/f
         WWjpzRiiA4KAiuj06rItwPzQ5Qz5MSp4YH2CL3LOb97K8IoyJI+Klj8KsrkB7Wl8fgqb
         mQfvxXRsItttu+gaaNMcccSDm8Khc3S4ghFlaX/BJI4T2OcgayTdzPoYKImqfrRcm2Av
         HynH+zkLqAb+CDAfaiM8M/2SFVcrf8xnAH6llfWvTo0JcsbGND9gm3atJ1AWsJaSjOTI
         SN4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ce15si774355pjb.3.2021.01.15.07.08.23
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 07:08:24 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1D92BD6E;
	Fri, 15 Jan 2021 07:08:23 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 270B53F70D;
	Fri, 15 Jan 2021 07:08:18 -0800 (PST)
Date: Fri, 15 Jan 2021 15:08:11 +0000
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
Message-ID: <20210115150811.GA44111@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115120043.50023-2-vincenzo.frascino@arm.com>
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

On Fri, Jan 15, 2021 at 12:00:40PM +0000, Vincenzo Frascino wrote:
> Architectures supported by KASAN HW can provide a light mode of
> execution. On an MTE enabled arm64 hw for example this can be identified
> with the asynch mode of execution.
> In this mode, if a tag check fault occurs, the TFSR_EL1 register is
> updated asynchronously. The kernel checks the corresponding bits
> periodically.

What's the expected usage of this relative to prod, given that this has
to be chosen at boot time? When/where is this expected to be used
relative to prod mode?

> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 18fce223b67b..3a7c5beb7096 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -231,7 +231,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  }
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define arch_enable_tagging()			mte_enable_kernel()
> +#define arch_enable_tagging(mode)		mte_enable_kernel(mode)

Rather than passing a mode in, I think it'd be better to have:

* arch_enable_tagging_prod()
* arch_enable_tagging_light()

... that we can map in the arch code to separate:

* mte_enable_kernel_sync()
* mte_enable_kernel_async()

... as by construction that avoids calls with an unhandled mode, and we
wouldn't need the mode enum kasan_hw_tags_mode...

> +static inline int hw_init_mode(enum kasan_arg_mode mode)
> +{
> +	switch (mode) {
> +	case KASAN_ARG_MODE_LIGHT:
> +		return KASAN_HW_TAGS_ASYNC;
> +	default:
> +		return KASAN_HW_TAGS_SYNC;
> +	}
> +}

... and we can just have a wrapper like this to call either of the two functions directly, i.e.

static inline void hw_enable_tagging_mode(enum kasan_arg_mode mode)
{
	if (mode == KASAN_ARG_MODE_LIGHT)
		arch_enable_tagging_mode_light();
	else
		arch_enable_tagging_mode_prod();
}

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115150811.GA44111%40C02TD0UTHF1T.local.
