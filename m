Return-Path: <kasan-dev+bncBDBK55H2UQKRBWNM7OTQMGQE26RAWBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E1279A668
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 10:56:59 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-501bf3722dfsf4480302e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 01:56:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694422618; cv=pass;
        d=google.com; s=arc-20160816;
        b=vgfUIKf0D4VAwF5uhHPjMOpSuOSUTyPA2QERXT3C2E3AQ+xspJyaonY+utO4G9wQ5k
         8h9PFdcUzLAwuJjrPHsLrEGOOKJMpp8ZBU3ZzSNlIeVBFiMDBtRxk8KUI37Mf3CwD7OG
         9+riG+HKVj5wmlDPVUzjjyp+qZmW5JixdGilpE10MJUw4fsT6GZRp21Nbvvxs4mrgW9W
         GZjuU1nkXFlgqN4A+IOnGQy/NZvyBb8toujthJI6g3SBl+o0/Ck/SXanGQ3GKbEQfJ7A
         MC4po1qd1RVOIKVT9HBGRibUjrtR4WBYgHtOE9sDNr+LFanIQ/cbRROHPHX0g7yadAdx
         Hb9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1JIyOX2vhjVUUgydqGQHF2Ecruqz/mcAN+I1qTrD6iw=;
        fh=q2/wam+GNvyGk3CDEntjebHjhB7qc6BBBd5s8j0xr3Q=;
        b=Zj8Y+OMo6rV0mDgOgLQqv8B/Vy3Je/qFRNlfKuMNBAC5VIcw3KhezB8Du9lSPiuaPa
         2ubTgEtDEOzWsTVqkIkyWxFQUWfdjS1ZDLhDEv22IGhJsfiTHDA/0wccRnX2tMoU1owD
         GgA9qZnAN+9VDanCBBdtdRLz+89khgnKjkQHR80WZdD//4DjCjrWxBId23QJk7DzZDKa
         gffqTFfeAVdrlKFeOtKw+zRE2Ed4lHd5a7XzLDyTX6nlRnTGKYx+51IkKwWZk/UFKZU5
         X6eaEQuzoa13b9P+e74KIGTxf392R0tfKTWcL3OKFtFSNSiNDr2YZDA61JJI+MbEZ7cu
         /6EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=KynaWtg4;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694422618; x=1695027418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1JIyOX2vhjVUUgydqGQHF2Ecruqz/mcAN+I1qTrD6iw=;
        b=VxVLRnDyXhx8J7oFKh53flZVYNWQL2N7/qMpA7WE/6zpx0FV7lQKiVIKmUU0GKMLJ1
         c/QVIJ70ZeRUm6ZpP1h9k35Cd9MPHvwhAjtSGHOSHP2PM3NbTuwS0bqLSdmHKdSzhIaH
         qOPNk2G7xQDhlmUhWhgOSDnaKTnhxPw6V4nbJC0mJdzESROfbObNj23/0aoVgjRKxBWb
         hLKyGRuFam4MP7AJjNaQH4P3TohR7946pHzkWuaupsJC2zlR1APUjBXMQtwy74T/LziD
         VdIT66hKbdYyTYN4W5EUZ+l5cLztFkdV7UI6gomAph3GoKwyRjOgYDkeXI4zb4AdyNPa
         DErA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694422618; x=1695027418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1JIyOX2vhjVUUgydqGQHF2Ecruqz/mcAN+I1qTrD6iw=;
        b=ML3HGGrKW06mPD4D/J18hs3ahIY8+mZJbhYZ0sqYh+xBP02PBsqWqeYEiG1z9YbDXt
         it/lapEaoVnCb/JUb79zgCYpXPO8xIMg+nU0RbQh0+K4fv0KwBtHeXoLGwYuj4sD68WT
         n6E1xdp8A9hpNM3wufXFlU1Gc1edGGquoIONDTzzQ0OVC58MzGNyrvAG3MqcY9eDHIIS
         x0Jdgtt3lJimzZMfrsSzZ5Pk9yWBnn03sshd3l00C1b7ZJcKYzGH9/kJY0L9FbBmdWEJ
         UiSPLblVALDoXIJdUxx8YonQcXj24CyUX4gSsu+Pg+/R5qMoN+bGkKss0/sH0wNn5Pq5
         HjZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyeG2v5WUFwDlheTStSe+/UvBYgMe+JgqvOInJBrD3VCbIEa2FC
	SrkE2RUT4J5gp7VDGqHyjOA=
X-Google-Smtp-Source: AGHT+IEQKe4olNiZtRlbDTr9Xsq/sSeT6KI0hTyyaT34T3yQBrFMqDmzZCZt5vpYAmHCdKg01zoFzw==
X-Received: by 2002:a05:6512:1283:b0:4ff:8403:e88 with SMTP id u3-20020a056512128300b004ff84030e88mr9043615lfs.1.1694422618055;
        Mon, 11 Sep 2023 01:56:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4345:0:b0:500:880d:5fa5 with SMTP id m5-20020a194345000000b00500880d5fa5ls571182lfj.2.-pod-prod-05-eu;
 Mon, 11 Sep 2023 01:56:56 -0700 (PDT)
X-Received: by 2002:a05:6512:ad3:b0:500:808c:91f7 with SMTP id n19-20020a0565120ad300b00500808c91f7mr7808400lfu.13.1694422616085;
        Mon, 11 Sep 2023 01:56:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694422616; cv=none;
        d=google.com; s=arc-20160816;
        b=I0tKCTD5CGFTf2AxjCgLxHUCovp4A8wT9eYCW6jMN6q9negJAgN5ZvwYZEyZ+owefo
         OZONBRgKfwAvQ+iPdVwfFdMvQoHQ/lNb+i6GnH/Upg+WowzMfZQpRHONmdXYWi69zQHN
         Oj51IS69wzZ6b40MIoy5/KXcbLV331U7iGvMczWjXVUzV09CGEmXg8vAwLEJCMSLCybC
         BSt9nI3wv6dwINe1XPCBh7vkICBV8qSQpzS/enuYzcBAMi1pCTx+Hfm+6ko7b5zTs744
         zNHHvDHHAHC4WClZaldw9ADODp4FZr4XJsjekr+h5OS17woWpZ/ykQrCbW64gGS//b6u
         xlfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LyggSFNgiy14BwIsDV/0K7QQu/1ltroH4K6t5ZXh5Ko=;
        fh=q2/wam+GNvyGk3CDEntjebHjhB7qc6BBBd5s8j0xr3Q=;
        b=RNBzyBw3CQW0njr/5bSv0qKQjwJKf9ucbpLKs/25o0iBCIvjgg8pPt7yK8toS7FIQy
         ZoduT31JVOY8jOrxcuqwvPhL4nxKYfAcZPqyiN9uTRMzHowq99JY8ExmQuQwA72aCucO
         RCIhpoWcymCUUg+KLapGbEFOYzwWuRPOIxp5yyPQbB8pQWEEctBPdrPhaqOj9j7QcCgu
         lriSZTJW3UdyxMscpwlqladUIY8Sxa7L/7AgfOWBIyQ1bryA7xqxo5KJxoCNBiUt50D+
         2AHnJoJVO2x0y/s3keKGIVi10MvjFOgiCcsaT/XxewFwciztiK/cfKp6iy2E69ihTXjb
         4Xpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=KynaWtg4;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id c1-20020a056512074100b005009d574e14si488366lfs.6.2023.09.11.01.56.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Sep 2023 01:56:55 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1qfcii-004rWA-1F;
	Mon, 11 Sep 2023 08:56:38 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7B134300321; Mon, 11 Sep 2023 10:56:37 +0200 (CEST)
Date: Mon, 11 Sep 2023 10:56:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-um@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel@axis.com
Subject: Re: [PATCH] x86: Fix build of UML with KASAN
Message-ID: <20230911085637.GA9098@noisy.programming.kicks-ass.net>
References: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=KynaWtg4;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 09, 2023 at 01:18:54PM +0200, Vincent Whitchurch wrote:
> Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
> x86: Disallow overriding mem*() functions") with the following errors:
> 
>  $ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y
>  ...
>  ld: mm/kasan/shadow.o: in function `memset':
>  shadow.c:(.text+0x40): multiple definition of `memset';
>  arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memmove':
>  shadow.c:(.text+0x90): multiple definition of `memmove';
>  arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memcpy':
>  shadow.c:(.text+0x110): multiple definition of `memcpy';
>  arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here
> 
> If I'm reading that commit right, the !GENERIC_ENTRY case is still
> supposed to be allowed to override the mem*() functions, so use weak
> aliases in that case.
> 
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> ---
>  arch/x86/lib/memcpy_64.S  | 4 ++++
>  arch/x86/lib/memmove_64.S | 4 ++++
>  arch/x86/lib/memset_64.S  | 4 ++++
>  3 files changed, 12 insertions(+)
> 
> diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
> index 8f95fb267caa7..5dc265b36ef0b 100644
> --- a/arch/x86/lib/memcpy_64.S
> +++ b/arch/x86/lib/memcpy_64.S
> @@ -40,7 +40,11 @@ SYM_TYPED_FUNC_START(__memcpy)
>  SYM_FUNC_END(__memcpy)
>  EXPORT_SYMBOL(__memcpy)
>  
> +#ifdef CONFIG_GENERIC_ENTRY
>  SYM_FUNC_ALIAS(memcpy, __memcpy)
> +#else
> +SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
> +#endif
>  EXPORT_SYMBOL(memcpy)
>  
>  SYM_FUNC_START_LOCAL(memcpy_orig)

Urgh... 

Can we use CONFIG_UML here to clarify things? It's a bit of a bother UML
is diverging to much, but oh well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230911085637.GA9098%40noisy.programming.kicks-ass.net.
