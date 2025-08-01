Return-Path: <kasan-dev+bncBCQYJOPHAQIIXFVSYQDBUBDO4CAZS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9AAB17F79
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 11:38:39 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-55b8422dbdasf878112e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 02:38:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754041101; cv=pass;
        d=google.com; s=arc-20240605;
        b=QF1nD5TqXFew1KHCNmYX5vrtH74ucLcdbDO3mtRT1hzezTRJb3sEXL6Y7iND+j2+Lq
         Xs3GMVaE8b+INjUhFIsicIIVJWru/DVqtv70CqRreUSrquDumcrvO5H3JYxhDoMcEtGe
         3MOx0sQ27J3SOi76rldNLUtN/hGYUqpnVX0v/VL3/ArlsTjbIWsPF3tx70f+vPcWcuWF
         srAM5f8uhURXVPUaSt7yFgTKogrdXags+26hTWn9bWQJYmk8aDpYNl1LkA9dIPr5J3qy
         b/bbNU+qSnZF2t1dkQ52pgsCU74h+scy5Z3lNM+25wMfivKAFEHh+uYijeqB0zQKzGnD
         Br9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g3qbJ6J+1Zpn7gEJVXpZrcZTB3EZMUtdi2GldXnL4Z4=;
        fh=tavAS9PoQP+Nf0jmqUe6AeryLSpuB+XrT1LVJSykETE=;
        b=DOyrF/zRLUCe7sws8i0JNnl8WmcwaKVW1YCW8w44+ySucX6EZVNNpvD+XqRCy+1+mW
         z7pC/hKa46gjHlCL4iqqAF9/mJKyJFpW6OLf4ol+xu9yu/UAKufazqIR0bgi80wrOR2I
         h0qLa5zu/aoJD7O8UvRyRxtraEew8YO3hFVELeMtmHvuLsJzj3Nq9oWOU3ozI5W2xANI
         du11hkZNhy/a/NhwXJvh1qt+t68NuqLrXs8Gt5vS9UNuwXjie6gWzifUjLwKuAdaFpTI
         VhJKuU1uaPqe3v9CKaK/fM114D09YrcvhD3Ifhawr0UjLgRm8gTeM/+EFMUxlElu4ylN
         9oag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hgmTsZgP;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754041101; x=1754645901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g3qbJ6J+1Zpn7gEJVXpZrcZTB3EZMUtdi2GldXnL4Z4=;
        b=ozwQ/4gBtPo0qZ8AQdbyzzG/aO84E4qNBJH5MWx1FxqitCJ21O5BdIwGWqzz+3f6Ee
         O41u/c2CXb7H2ZK7Vv/TPN0dNTsN4Be1EbocRLoO5gI1bbEBwXxBTURtheVy+doyydPN
         YSrP1knpo1H+HubwIMXtbzF+A2XKvHTbR76Npg5h4KDddip7bNZ8tzhHD5MYqL6dMqg/
         hfNEVxEZ5evDbQMhuQMte1Kw6tMHzr4hz9tR93H4jRko/wJIpAnY2rKnaLuz+t1H1WF2
         pT6KTa6I1Y+nWP9vMaMNfzkPTIX35nef66iGH5if9r8yZVmiN2Vboh670pFO+jgEK1+1
         n2ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754041101; x=1754645901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g3qbJ6J+1Zpn7gEJVXpZrcZTB3EZMUtdi2GldXnL4Z4=;
        b=dmOX8RKT4NrX27DJIkniqokRwvHHotO+uttoq8Tlm88pB1H/FmyF2EIOl0h16PRUDs
         aXmiciNLkAPLf8WISXni0AcEyC978dLVZ9UzRFzpoCn6L5U1qlsSmBqkRgmACAHDSC1B
         hK3fG8hqH1Ihe48IIk8WR/5Hgqz+DZT4F2njnjVHodR3H6GW1izQvLCJ50/LLJQUA4Xi
         s0y4ZD0DHwlVeed0oGv7l03SzN1HOoCrJodH9ieAuuOGUqT7XqBs5PMpm1aWBL1sfQQa
         s+1aLcZemgE8BcMe5TvsYupl60ejRV5SzN/33ih7C/6BFhy6TxYcLMdon14XkrXBXlcI
         IVGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8H2OddhDKxnE6lKnYtc0LGUwyVozNhJx7tPSsaoppwn9Wg0izfugzqRKVmESVuacxBtus4g==@lfdr.de
X-Gm-Message-State: AOJu0Yw+T11ACPEhWxyeq9quLrSEMRWtPzVBTStpe0c95cjjYOhIg58r
	ITGyeTD4BmDLrRo1TXy2v4BxQOmnYah55/6MrDCW6Nha/G/r38iI3bwa
X-Google-Smtp-Source: AGHT+IGV0gDAf2ePQKdmRzUw5g8I4cqmSOF3irYCqAW/9k5HXy8tymhIbsT0hJqhsE+9beCIe0fFZw==
X-Received: by 2002:a05:6512:10c5:b0:55b:760d:c2f5 with SMTP id 2adb3069b0e04-55b7c0827a2mr3114498e87.33.1754041099942;
        Fri, 01 Aug 2025 02:38:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1nqxOFZ//ewMAUOSiJly1gUoldu9lPj06NYpd6/OPdQ==
Received: by 2002:a05:6512:628e:b0:553:d125:e081 with SMTP id
 2adb3069b0e04-55b87b09f35ls330934e87.2.-pod-prod-03-eu; Fri, 01 Aug 2025
 02:38:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBnR844flAzhBdyvTbMdgu0BUG8oPQoEQqYLCSywgUwd+nF9DUX1CFsuzQnO5A+Cvy2WpDRVF7OF8=@googlegroups.com
X-Received: by 2002:a05:6512:ea8:b0:553:25e9:7f3c with SMTP id 2adb3069b0e04-55b7c0829bemr3515773e87.37.1754041096845;
        Fri, 01 Aug 2025 02:38:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754041096; cv=none;
        d=google.com; s=arc-20240605;
        b=USTwmyhlr2kpapBztEi6uP3NRiUxCcw27klZCr9puIcj3hPQdofiWjkssPz1t+erkq
         UwRRuAPRD1ntgwRrv1ZEWgYd98mJ+mWTLZvIaPgNUCodNbC78XwgFwDao7lEB3ABczEX
         WGsly0CmAku/61ecZWk74hAN9jD84YWW3ZjLoRN/9HGp/tfMVxiLes1S69GDjVWoII+k
         EzQDZ4i0/5kJ3UXQtxADhq7SnF0kVb2atCiGwDlCtBV4UsOD6cmTt++NAnuuy008SQZ1
         WU53EL65wgQWHbkQLMdbryQOz3nT8dTLnlMhSeUEOBiJggQzgRA+IBgVn4C93093HdTj
         d1cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=tGSv6RdaV6X5lnOcQToZWXgwKNlnA4P6z1e4N4UFCfU=;
        fh=XQIM03cM5vRfQUaTYiZlU3vNX1GZFFIMxQz2Y+AaHKo=;
        b=Exebw0lEd/ta2YENMOuyHxN9CqyY0PI/SABQtlNVKerEeEPiVhLglZJHZW4PrMvVl0
         EDjuaZ0I7PjMKRgnZAztllvk6ug1SFtaD1WjS0ZWJ2wsoeSZxQY+9YQr7oS3KUB5BIOW
         PXpVtTkUvgRKSrPdjp+iXJk9njRQaGTAJn/hd+CEPrdSgTp3tMyo3c/Lx292LD56++7d
         /tm+/pn2q19/46RLn2xloskR6J/7MydzJNEFrk05tvPCr4eqAZd6jMUoTdP+xyGvHmmT
         U6ISj6rZEGpPpubMjcGg9TLQaCYolQIa9lTojL1Tk3adfVfzgTRL+TPfAnzAmaeJYykE
         k5Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hgmTsZgP;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=t-8ch@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with UTF8SMTPS id 2adb3069b0e04-55b8870e498si49696e87.0.2025.08.01.02.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Aug 2025 02:38:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of t-8ch@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 1 Aug 2025 11:38:15 +0200
From: Thomas =?utf-8?Q?Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
Message-ID: <20250801113228-5a2487e0-0d90-4828-88c7-be2e3c23ad3b@linutronix.de>
References: <20250801092805.2602490-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250801092805.2602490-1-yeoreum.yun@arm.com>
X-Original-Sender: t-8ch@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=hgmTsZgP;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 t-8ch@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=t-8ch@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Fri, Aug 01, 2025 at 10:28:05AM +0100, Yeoreum Yun wrote:
> When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> triggers __fortify_panic() which kills running task.
> 
> This makes failured of kasan_strings() kunit testcase since the
> kunit-try-cacth kthread running kasan_string() dies before checking the
> fault.

"makes failured" sounds wrong. Maybe this?

"This interferes with kasan_strings(), as CONFIG_FORTIFY_SOURCE will trigger
and kill the test before KASAN can react."

> To address this, add define for __NO_FORTIFY for kasan kunit test.

"To address this" is superfluous. Maybe this?
"Disable CONFIG_FORTIFY_SOURCE through __NO_FORTIFY for the kasan kunit test to
remove the interference."

> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---

Missing link and changelog to v1.

>  mm/kasan/Makefile | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index dd93ae8a6beb..b70d76c167ca 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -44,6 +44,10 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>  CFLAGS_KASAN_TEST += -fno-builtin
>  endif
> 
> +ifdef CONFIG_FORTIFY_SOURCE
> +CFLAGS_KASAN_TEST += -D__NO_FORTIFY
> +endif

The ifdef is unnecessary. If CONFIG_FORITY_SOURCE is not enabled, the define
will be a no-op. This also matches other uses of __NO_FORTIFY.

> +
>  CFLAGS_REMOVE_kasan_test_c.o += $(call cc-option, -Wvla-larger-than=1)
>  CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
>  RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250801113228-5a2487e0-0d90-4828-88c7-be2e3c23ad3b%40linutronix.de.
