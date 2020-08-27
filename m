Return-Path: <kasan-dev+bncBDDL3KWR4EBRBKVJT35AKGQEKEN6JLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C611925441F
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:10:35 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 130sf3886326pga.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:10:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598526634; cv=pass;
        d=google.com; s=arc-20160816;
        b=kR9q3pArwOIH+3P4llnqCdDteWrFtrWczPy4gIkIwW8kcwOe8SaH2QwTFANIsaLRCo
         3f4p5/MMH5qJ3BanXDHPHsq8H0YzzyRKYnqH0xSMzlBUqPw6kgiUy+zQiSyGtpAxAEKQ
         cpqRNZ6FOJVKGzs6ILgPPOn6IfqLrB0MJggSrRLTgmPo8aOz6fOiNeumpPtzO+rqw4lt
         BujABiJa8oNt9lPi2clNrfXdLnBMyaoRRxKs0+NEO+In993ECtGpmb7FYsYmDd5svVyA
         1N5BUEva7EBqkHgNGJjKJ+76TRswqp9RFTeWQVNroayMVYTmBS7KTYlQngmny3W8+Pc5
         Bc1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Z4UO3Fx1OPTp+BHvDwfTEO/YRkB5RW6t8t56w3TemBo=;
        b=TatOszOk9uDigdRcf6tyupHGGknFlx1l3lsqA5pypoqyXUlePwaYqGy3jb+0ohjr55
         pbqaI1Qazs5iIbcdweYu/k2bjWeH+UCDL2amwedADtmTTG5BYHxdimbAINfHFsopuw7d
         NG+2j76nIXpkAT/IeZZAgL7nKDKYyer6yENzspt9tWr+c5tEvWEcmizioDQKKVAigi0P
         yfgT0m4f+OQRxcoM2JnQlUez413GchmJLZpLazOgaKRG0o1PGokGJhg57IRKzv/vT2cm
         B+FRK9SfQC9z5FebI0yUQ5qUqvgIk+2EPmVtLMk1laU8zEZdHtvmhLnHxKcQwCjeIHaO
         646A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z4UO3Fx1OPTp+BHvDwfTEO/YRkB5RW6t8t56w3TemBo=;
        b=SPTpxqjcQSDCdT1fZBEg6s2wBvV8T3w0OwJQJ/tb0FwpRrbYaPogr9n8zzQ+yjR9O9
         qB8asjEprfDGb+QYj7HoIodc9mC6cmHrgQFChgq/QvX3yGN7csc43mrbZOP2dkqoPBiU
         +9CzZnF35vaOM8OzgEZlfKQ05NoL0YS/ZjDePFruy+4Sll017s+gorYjsuHUEYiD/3az
         2MYwUiJvsYS2ZlnAKoeH5ixGChqgub7hgelkn9LHY0VkuEJIT6MOjk+43lj9UHPTGq8J
         pUdjirSWB4h9aHZhLqVTo1zs8YQZsSFTnnbOx2cEeCkec07YzY1AA7LW6AxARHQwgOHA
         FBDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z4UO3Fx1OPTp+BHvDwfTEO/YRkB5RW6t8t56w3TemBo=;
        b=Y1furAm3kVlGSHOwQoLdAUvibMPL3O7uBXvQOX9e2pbRgATjgTdm71RiRyw/2sXGnN
         Fr2qWpA1Js0itl7hOABNCUTLLQ9i6cNEzBYznVvHHjRmAl4ediE9iVk/2QiGq8XMqJYX
         JtlDm6UydMzOoFIqYcwrMLwAWpCU11bgqKtEjuhs8CCIoS0/i+8Qg7GKLsaFdyDlQuwK
         1UHvzJTnNwK5BBZB4DQpZ03uxcL0Ej3oU1+vRor4WtogGPlloRmFxOsCnJ5NTPz71hlK
         Fk1qrN6ge9UCx+IvuyP8/k/mSjfgxSO8lKZ6/BC8QT4mb4t/Y8LtdEX463DNIt4Uz3fK
         2Xzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532I0nWk9k/1AzGyeiDfOPGYctwTIB9NRbq7RjdGWiASW+E62wkf
	jukk3HNolt6w+DMyD0XquoA=
X-Google-Smtp-Source: ABdhPJzwt1PMlWPbBcZskOkqJmSzmq0fvYthJBUDDBLMSzVQTttIGOhKiws8tBWZ97av6/zzANGkbg==
X-Received: by 2002:a17:90a:a61:: with SMTP id o88mr10407296pjo.201.1598526634374;
        Thu, 27 Aug 2020 04:10:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9b90:: with SMTP id y16ls1071156plp.3.gmail; Thu, 27
 Aug 2020 04:10:34 -0700 (PDT)
X-Received: by 2002:a17:90a:9c3:: with SMTP id 61mr10730639pjo.191.1598526633946;
        Thu, 27 Aug 2020 04:10:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598526633; cv=none;
        d=google.com; s=arc-20160816;
        b=nNZNRSLXep+HSi+GaH5xQ/gOTmKcrUP/ZVS4pVdmTn9gnZMgoqXbyVun68tPPkSYTO
         kZW66gr0Q7aJd2fAceT3NKpB42wY7VWVsdR5BxXCRrpTKkfL70+DOaY5l4mkUldtLuw+
         18mlw3lOczD7/FCmyin1SpZm21w5uT9cc6Z8m8n9E/YBzH9x88ouAnyC6QaJpvKolL7e
         FMxKH+GniKAsLv0yrWDsJvATVQbqn44cBAMIdVgD5c/p3sBryaLz9iqOPzZOotnymodD
         tfldv2onpn/Df292TySusRybNU5rK3SheuodRklAJ5hTFJhW5BzQcQS0352K3dzqlUCQ
         QMMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=eEvgxttD4L8zQsAhVcujlN+9o6rbvipRujLLwPmGsFg=;
        b=SPe1AEkWuxr5byrQqvWabqYrmIwgo0lW3R+rpc/QrBzTFauP1KCyOSTfBQW1zb9QML
         4kGl+52LERZ8kMfrn1WxPHfd5iprvTwfqbPvEYUCLyTiWtiM6BC8hxvcqFVqpEg0OP2T
         MVtCH2YR85en9S/C/ga8d5BxaD0GZwKNh6XW9yw59cvGdEdPQHa/y7SWSs+bxAwAWQ2L
         6NkC0MxbuqVUwvNPevGhA0wANw6YjxX46C3EObJ2JAQBuTxDHBwo/tNk94tpb7CFZlQi
         tBbJ/n5C2OU2ASsyI4bvtuAYsVExgvTFRPV2ZUq+exfGfzmaOld3Fr3bk7JHarOgtNd7
         3xhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s14si105358pgj.1.2020.08.27.04.10.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 04:10:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 39DEE22BF3;
	Thu, 27 Aug 2020 11:10:31 +0000 (UTC)
Date: Thu, 27 Aug 2020 12:10:28 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200827111027.GJ29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia>
 <588f3812-c9d0-8dbe-fce2-1ea89f558bd2@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <588f3812-c9d0-8dbe-fce2-1ea89f558bd2@arm.com>
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

On Thu, Aug 27, 2020 at 11:31:56AM +0100, Vincenzo Frascino wrote:
> On 8/27/20 10:38 AM, Catalin Marinas wrote:
> > On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
> >> +void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >> +{
> >> +	void *ptr = addr;
> >> +
> >> +	if ((!system_supports_mte()) || (size == 0))
> >> +		return addr;
> >> +
> >> +	tag = 0xF0 | (tag & 0xF);
> >> +	ptr = (void *)__tag_set(ptr, tag);
> >> +	size = ALIGN(size, MTE_GRANULE_SIZE);
> > 
> > I think aligning the size is dangerous. Can we instead turn it into a
> > WARN_ON if not already aligned? At a quick look, the callers of
> > kasan_{un,}poison_memory() already align the size.
> 
> The size here is used only for tagging purposes and if we want to tag a
> subgranule amount of memory we end up tagging the granule anyway. Why do you
> think it can be dangerous?

In principle, I don't like expanding the size unless you are an
allocator. Since this code doesn't control the placement of the object
it was given, a warn seems more appropriate.

> >> +/*
> >> + * Assign allocation tags for a region of memory based on the pointer tag
> >> + *   x0 - source pointer
> >> + *   x1 - size
> >> + *
> >> + * Note: size is expected to be MTE_GRANULE_SIZE aligned
> >> + */
> >> +SYM_FUNC_START(mte_assign_mem_tag_range)
> >> +	/* if (src == NULL) return; */
> >> +	cbz	x0, 2f
> >> +	/* if (size == 0) return; */
> > 
> > You could skip the cbz here and just document that the size should be
> > non-zero and aligned. The caller already takes care of this check.
> 
> I would prefer to keep the check here, unless there is a valid reason, since
> allocate(0) is a viable option hence tag(x, 0) should be as well. The caller
> takes care of it in one place, today, but I do not know where the API will be
> used in future.

That's why I said just document it in the comment above the function.

The check is also insufficient if the size is not aligned to an MTE
granule, so it's not really consistent. This function should end with a
subs followed by b.gt as cbnz will get stuck in a loop for unaligned
size.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827111027.GJ29264%40gaia.
