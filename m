Return-Path: <kasan-dev+bncBDBK55H2UQKRBT467HBAMGQEBI3OHWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E6963AEB0BE
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 09:59:15 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b41b99f33sf8176711fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 00:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751011152; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZsJk0GkB+KSV2nS0ekQV0V4sWdm21hZzCGm8Mtfk+b8a6KxksUSU3qBeSC6cuIN7oJ
         3Q586Di1+OHI1t02voZLtGeghrCocx5h0sfkX/T+7vWYCvKRtkK9GDO88sbHtWp80Uir
         KCO8gwH7zwaY//gBNN7V782n/SLoYS5w105BWlmSJZWBKt0e9KnqNQqBC9mLCb2t7RVS
         ASjgbdLOKt2QQNzF1AtxSah2BwwPxqEDRlcJ+7PYW8IYMqPlcBe1ZMWHxi+UKY51eht0
         JkNn4RG2LUmrOfG6ba8+hg/29AmFPWFLCg59Nja6ef4Apbs+fTRHVFipQdKgQZIUHqLt
         oV1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pIMfkJRO8/EIy0IxY2pwhuYAneKPCjI4wlc8v2IfGbU=;
        fh=4kZuWmBtqhbfUgqlzNhncgRR7mz+G7CYcDcDhqXKqwc=;
        b=RYqU6QUPBNuHgVbv7Nc5YLP+JnUxUj8JriSqO3daonPemptPz+nNOrluPgqgh2p6xl
         ewmy3Uko2hrGuEnwPFU+1RwM1EPsn69Se5GBQMwNsVqRhzIU7AdzskbMP3nf5lsigqts
         wG7vDdOzAV5fcQj6ZufufVohaBxHd620+gpPwpbqGXuR9uyoKEjNfKhDYNMreUT6C3Ag
         A+zywDVB0Tp4LJvQTZrIi9D6A0P+HMLQw2TMhfgB6dWU9xWyQFiXkpmQyKyLbs0w3/65
         tNLIIjeu3CDUdNh3nnx7vPVIaJSR1r17hyq64SG4esuFFobsRh3A+mGgAx6HZUZsl8v5
         wfUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=l379TvQw;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751011152; x=1751615952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pIMfkJRO8/EIy0IxY2pwhuYAneKPCjI4wlc8v2IfGbU=;
        b=DxTIasNq/N0554ktqKj4n/UZ23mC1E1k2Em6No/XAB4qhEz82bLpPeGfCo/GKt+3Re
         SWLOknbC7NVWNB0ts1WEiunWxvxbhVKGAB7LfJv2fKYBP4zlo522IdusmDw+zLrQIdRh
         Y08iraU+pa3ZD6a4GX/RuG1U20KOvxGorva0RkaeJO7WyeYd+ksnVOVNTNzzKK0KhJs+
         QVlj0sATmTGzf3tRIrP6CVKSbtIPQlxs17ByReTzH60aSvlL6NZGSlEiBfpTK/5OOMSQ
         xuLev7T5XBARtN7wCLco2J3Ji/7QNHmFK8UNQvT1oEnD0c6DNgiQ6gRfqoetHnt8JGIo
         YhhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751011152; x=1751615952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pIMfkJRO8/EIy0IxY2pwhuYAneKPCjI4wlc8v2IfGbU=;
        b=AfmSwAtX99ak7ivz2EghjXZrymbTQhmgabtfZmjwEG8/LOnCMypv+s6v/AhVyyzuns
         zjDufuua+LIRuG5zHdTXkflq//9Um9cSoDYe250JgMLuKN3j4trJKolcbCP+h9wNYLG9
         2Um0FTMQikA+HV4PHtcv6NTR7i5k5uwjSXeaL1HIbSTxBi3B+LMsPZ1uw1n2nesDWuuc
         7oU6xFBRi7e5FqauaCfLddTC+kHaqkZlg4McOvznIBRm+oAC0ZYwqiKoPCZavCVthmG7
         mDeLz1ERJiRcjtX6ag3FWWf86pFHcILUcobASVyOH+LzyrFgw97lCs9r9qnLFLH5Rgh6
         7DLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIt1twqBDeNSYyC4gNxamvUF0Esqr5LUOS13VrYzESzjNCoW3Y1fzkq9+CQ8gfaRGWwfw2KQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUlV4z08tsmo612aSHY724BjjiMHXZeUQ5ZG8B+1y9cmAp1xKd
	JpcfsNGYtM1SXaoj/C42vtAKa7cmHKSGoBfXhwLDLu695ICKmei56w9e
X-Google-Smtp-Source: AGHT+IGMSHkUSMAbQVznsNjhHIy9dNJPxygh9ivps+7HQRvd2NPNABA3hM9t2iCRltN9ROQhGvlh1Q==
X-Received: by 2002:a05:651c:418f:b0:32b:533a:ef74 with SMTP id 38308e7fff4ca-32cdc53c89amr5307661fa.33.1751011152075;
        Fri, 27 Jun 2025 00:59:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWoK5ifDNy6qMdDpVZ+kLYiymesS7t5H530USrRCjPtw==
Received: by 2002:a2e:8e34:0:b0:32b:800e:a2ed with SMTP id 38308e7fff4ca-32cd042c876ls2993271fa.1.-pod-prod-09-eu;
 Fri, 27 Jun 2025 00:59:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCCaWd+oOw59XIHja2jA6J/ASbLcNc5jr9oszQQHIXpfBLx/b0zf5MZGWEUgzD53dQxECYmeOqeps=@googlegroups.com
X-Received: by 2002:a05:651c:10ac:b0:32b:7111:95a7 with SMTP id 38308e7fff4ca-32cdc56bc80mr3995161fa.41.1751011148730;
        Fri, 27 Jun 2025 00:59:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751011148; cv=none;
        d=google.com; s=arc-20240605;
        b=ThaEp+RLElhnFvxMpaqi7za3c9ZD4jbODI36SXHhrm7k3rELXbwVhzsRtvWe7I+UOL
         ycqhq1KOlFy2B1VT/JMQN5z0+KJuNJgtj0g22fLU12wDwQteE2KDadMubkHrkZqVnOeu
         dXt0p/qQ0ySwry7su88c61Zgc0iYRlMf9tKsjG5M/tzeR/Ch3dWtcgKs9j0NVHtMdRQW
         fDJktsyII0onqPCbdbplz/0xAsMYERskGBxhAL4UBJyMLQ3pJx3HE6sVGBmckyn/7BLZ
         bSHhHLmuDwHgasnfDNDWKqiwDNtTl0dMCIZz1kQdbAGbNflBtiYGjbTTiyIx0nBe1HXW
         eleQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=L+ZZOa8XaEDSQVrNy6HRtl+1pHVA46x0IEJzjJWdT4s=;
        fh=Ek1jAUi3GNl8SEwqAncxOvAsWJOejJFeI61Czi5lJC4=;
        b=AzVQa0gvOIYd5PDRLPJ7NSFaduoYIB2UCmuhRYgWgWUvLgs90rqCfZ76qK7NIP0y9/
         Y8hhjF+Rvi+R7UTY/nsOP3Y1FdjJLfWe1sxHOsGtbyb3g5Bzdh0iZ3SSfYh8T73pvc9m
         zhb5u251EQT0el9Vn+jXUSTpJBBy7IT86mJG0wmzmQtIBtjDtk0ggjU3PujPcicUG85g
         Mt6yqw+Qx+e+LoQ795mxW11Y9NhvZN+2Cd9GU4lS5hCiYR9sSUe816hRIiFJpvQ5V5ZM
         j7AphBeNOW8JKQHodEq8pcZAWK5hp+XbavqCGbZsQqQL6lBnsY8A1CYrPSeLXVcnuHbT
         CyIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=l379TvQw;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2ed04fesi1022511fa.6.2025.06.27.00.59.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 00:59:08 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uV3zG-0000000DYTh-1NGh;
	Fri, 27 Jun 2025 07:59:06 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id DDCA1300222; Fri, 27 Jun 2025 09:59:05 +0200 (CEST)
Date: Fri, 27 Jun 2025 09:59:05 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 01/11] x86: kcov: disable instrumentation of
 arch/x86/kernel/tsc.c
Message-ID: <20250627075905.GP1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-2-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626134158.3385080-2-glider@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=l379TvQw;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 26, 2025 at 03:41:48PM +0200, Alexander Potapenko wrote:
> sched_clock() appears to be called from interrupts, producing spurious
> coverage, as reported by CONFIG_KCOV_SELFTEST:

NMI context even. But I'm not sure how this leads to problems. What does
spurious coverage even mean?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250627075905.GP1613200%40noisy.programming.kicks-ass.net.
