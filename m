Return-Path: <kasan-dev+bncBDBK55H2UQKRBDPWRXCQMGQERG4WGQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 08AA1B2B147
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 21:12:15 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-333f8d315f3sf17430761fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 12:12:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755544334; cv=pass;
        d=google.com; s=arc-20240605;
        b=EMnhF6TCh10kjSHzn9hk68ggEZ3hRe3B+5efrV8LuI/sUJz570oxN8FtXg4qNfZ79o
         50mffO6TkYmJu3g/Fx0Rw99CoS0AgLXxE39Kx2GoxCAoKK03D7rfnagcBZ5DpBGj6VDV
         eTgcYTxEzhAl9binjEh/QsP30NLNN9YSj1wu5hx0OaeHF2F8gCLLoCM0GkZaWUTOE9/0
         UX4zb+Ml4dvx1uZQtWrctyyz0JFBLOhcMxONTW99vUXZVh7o7GeT8BOnW3Z0Y04+b6j8
         oVg9VyMjV3eXcRZlLM4SOOk9VkOpZFD3KXY4wnY3P6LLpfpWqh7wXLoaU+Xa0GTjpcs6
         KVrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+AltSjUc8N+F4nxwdGi7TgvE8lhZ7bZHl/T8AnLGDoc=;
        fh=KeO7z/XsMcAeIsg/3h4w02Q/e4swvZz4kpiAiqWrsmM=;
        b=R1/pO2hyzueDxKs1kyzdTSyBHfToqBFfeYK7BNb0U1FUkPbTGZlfdGSXbTBBIcUtup
         bP4wjEApuXzr/zlmD9V+lE3DLNd/Pk9ZBlAiZfVyaAfkgjZgJVP/fJ2vjScO3uBqB5xL
         Y51CDWYq9USmg0vNGY4+I6TcmZAm35bcP8FsAl+HpySihJH7y3fAteB1j6ctTAXs1gyZ
         jxc/gkl4+Qt6wSbFIh+posM7mkrh5ggVLlQsnoF6tacCLgmbCe2j7kMfXAn4tnmKdlCn
         w8BXkq2qIMMP8lTOI3DXSSZKYrFwSLqXx/2WAOZyTgM9OdRZHEHfw947PHwaRZgISohc
         f+HA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bTwjMZGf;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755544334; x=1756149134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+AltSjUc8N+F4nxwdGi7TgvE8lhZ7bZHl/T8AnLGDoc=;
        b=pMfVD1wl7231aQYjYeSgBD3vhCFdzLYj56FEkQYuFCldZ5v4cMf0JA5N+sK8h/mJDk
         8PbMPR5KpsJCLG7PzI3BrvyHzj46WzaygtF6Cy/rDqo5SSbAiTUH8y8ZGmJY3Gcz3QIv
         doOgrUv/re2kAmg3BCaxRIKNz+UsVnxge56cdBc0g/KEIs2hlsYH794RVMb6Q1FaKvKx
         rVhLAp07oc8FuSe774spSTC1O0b5lkG9T3T1hD0X4ZIzYsGbGc96T1SHv/SR2Q8JAKyE
         xpLCP9bbe2XqJTVWF7/E3fbA6JTyNUC3RPxDaFmJ/vfMA1qQmp6On4pvE5OahiKv2ENG
         xiBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755544334; x=1756149134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+AltSjUc8N+F4nxwdGi7TgvE8lhZ7bZHl/T8AnLGDoc=;
        b=o4/5ADOlE8rzn4goAfbGps+iaIgGg5HI2e7VS83AsloIBuscgD+NNdrEHadPdzQUMU
         iDCjdB1UArZuLXfuJyeiaoLF5k6J7A0YXMoPCSjgSzVlRbIbCmjseuqy7ee9wN/iO7s0
         ob6qgxpBMxO8yKgoAkqxaUivCsQ4PvD17IzuPV297Sy06TNlTFWNrm7HJCETGJWA0M0F
         ZGBeL1Mhksp6t2eDef4NVfjGNrQVW/eDHzftJUr4amy0hVcN1IMLQjO8uE+6tORr5dHA
         r0iyZ242ml6IA+XKHHu3MSlBFinhXQzogc+nLHoUn1kCih8jm2l0Tjrhsd+yUs7Ae01J
         xi9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFYUF/FTonp4p75UrNEJmiSCBq4Undm0dj8HcZkyduIw9/WuT9flrqpsCFThF7c+Rjs7tDwA==@lfdr.de
X-Gm-Message-State: AOJu0Yy4aTK+mUibKu/IWorpTIbFOOGjLWbD3HPp6EG0G5L6tUlfARHz
	SJYZ+X9/w1te19OvH3CpH2uKNXn4RFIRpuurHBqnKM2axUPNVd0QOsd7
X-Google-Smtp-Source: AGHT+IF0as+4zRzsBnhgzbKxhlHd0UvkKZq84ac5Sy8nrIEyIoNf2xSX1aHT+j4pkghMluY6O8PVsg==
X-Received: by 2002:a05:6512:3f0b:b0:55c:e857:d4b with SMTP id 2adb3069b0e04-55cf2cc5874mr2621322e87.29.1755544333908;
        Mon, 18 Aug 2025 12:12:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZczjSz691tHzpRtbFt9TtCZ9TTJJM9vQEQ3yPjCwlDojQ==
Received: by 2002:a05:6512:ac4:b0:550:eb65:d6c6 with SMTP id
 2adb3069b0e04-55ce4b3c29als1104398e87.2.-pod-prod-05-eu; Mon, 18 Aug 2025
 12:12:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9qKTUko6IZoojEonXc8tFWthkWR9eXcA+Ah57v3KIeo2W1KK2Sy0/XBH2HDZyd8+HLTy9vuXF/yE=@googlegroups.com
X-Received: by 2002:a05:6512:6817:b0:55c:cc6a:a212 with SMTP id 2adb3069b0e04-55cf2cd4680mr2062747e87.39.1755544330407;
        Mon, 18 Aug 2025 12:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755544330; cv=none;
        d=google.com; s=arc-20240605;
        b=PdbS1pwu5tA9V9YWBoBoHQHk2bBH4ZH5iB9qsqf36b2Sqq9DScGCNPpAnrilWv5oEW
         wdArBwRR0+fPxt9v0SOv1LjO9dDsgBbAWwrBsgQFWk7frL1PxuRICUWS14I3rRpwZAw/
         JdEoUQo8prvRuMAD4e+kduLnjq5V1gMsmnx3KcWbDgmkIPR8FPezU+vAkcNxWlUTuYSl
         Uc7bvUj05gBxftYuQyFQFwHvVE1gR6TSyjhVmJRVXGw6FMEH6IdXTL9TiRv+0esXVtpo
         wbLmWNF1dNQv1kYHZyCIZLbIixSg1pxXk5eoyCi+3g7sQrx6MbLgOY8PyQb8BDRhErw/
         ceVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2x+GxjZ248PmhTqsF4mLrGb7s8fcbW6kRGfC8iXWAvY=;
        fh=qYde4onWKz7F8pwInYAk3WXW/KeFmyvPpN5g+zxpc3g=;
        b=MZimsl6FVj4VEee1HO3WKfwFM1FibdUceuo7eahJH2NCq2jFvcLK0bsCW1snjy2c5m
         nWW6w4DbMbX9NTVHV2YPSEBchmjMJvt0qJGD1Xbb31bGmMq4mWxF7PaXOKiYigz6jYbh
         CAGaU6/szCYaX3XnXXM5WPARnIwyUDr5qWU+smR0dJtyKp+9r4IpvMEwivCVViBauWyG
         LOsQflcDVuS+mDywwjcuUHlfbVbpflyvX9YUWQQtX6rG4SQ/FC7EmJ/75Lh+ZKS1zFM0
         a4hooWLEWCWc1TlLnD7tkllk+9lOKyGB2kVt8Dqqu+me3m08+2ivWM3s+EFWXegiT9KZ
         xzhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=bTwjMZGf;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef3bebd4si202408e87.8.2025.08.18.12.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 12:12:10 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uo5H2-0000000HU4o-2z8W;
	Mon, 18 Aug 2025 19:12:06 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id AC00D300220; Mon, 18 Aug 2025 21:12:03 +0200 (CEST)
Date: Mon, 18 Aug 2025 21:12:03 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, patches@lists.linux.dev,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 09/10] objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
Message-ID: <20250818191203.GK3289052@noisy.programming.kicks-ass.net>
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
 <20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0@kernel.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=bTwjMZGf;
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

On Mon, Aug 18, 2025 at 11:57:25AM -0700, Nathan Chancellor wrote:
> Now that the minimum supported version of LLVM for building the kernel
> has been bumped to 15.0.0, __no_kcsan will always ensure that the thread
> sanitizer functions are not generated, so remove the check for tsan
> functions in is_profiling_func() and the always true depends and
> unnecessary select lines in KCSAN_WEAK_MEMORY.
> 
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Acked-by: Peter Zijlstra (Intel) <peterz@infraded.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818191203.GK3289052%40noisy.programming.kicks-ass.net.
