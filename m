Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUY3P4AKGQESSZR2BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B199C227E19
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 13:06:10 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id k25sf9399121edx.23
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 04:06:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595329570; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCMkiqExxMPnymU/DEOTflOdLsJcB74R4XHB9vPEwp4ugl0yh79K1QzaTxxOM9Ss00
         V+Uwm0c/s3nDOiaNF00/KVaeuv587gcMFAkr7kWHXq67q2kkOrbiA2HddnHR0iH37WHE
         nu164lKcr6gzsQQj+uThwkbT7idKM4cUw/nnd20dLzw9ZmxXAw76jlixxcUajBYNye28
         aPBz8vF1HVFVz9KQi8CJRR0Kp0LBQ/4ks2sJvczCIH3EfcPjs40+QO9vZOu8MEaATETK
         ULVWSdDTcnzFZnT2XuG9NvMQkD3vnrWjG8hR6v4jD0h4VVW8839L9dnf+wZ0oz6zrYpJ
         3tyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=f9W+AS7SCaoBv8dkA7yUI5Z5mGokXZ6WQ6MLzDJ8fpU=;
        b=IOlmSCIEuhvTGd3XGIepwt/FF49powzkyN0DUV2est4+R9pC5XXvW7e4l3A9iIli3T
         eqlbMp43Cxc6vFcJq37T5MwGdv4oYphRpwgge8AF1yBe4ekRuY9BRKgtP1tjX0g6QnIu
         u+ualxahzr7JmKg7LWV9zz8ok4IUQNX4bL8qLyaKLkiEaOTQEhnJLjGc7FUmMzVeeDOs
         WQPABDA8mdChnN43iNPNjct5uI8KTsneSdQoel9YBb4plGWpS5O6HFrxu1RQcJX/Bvhj
         MKQrDfQfDVV9QPXnjSqztI1/eJZ2ep7TEwlAyG04/lNA4ukE94DMH03rDws4258Z51sT
         zbkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B/VxyHE+";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=f9W+AS7SCaoBv8dkA7yUI5Z5mGokXZ6WQ6MLzDJ8fpU=;
        b=lQHvjNlwPOGVTOXX+n9l+CCqbPe/l6Icsn6hHeYeYWqXvrbAYdGyh2lSrihhttp9qc
         jtUkDZb6Igx/YiZT6M/+dj3YQb478Fg+hLfBpgcHT1xzp36I65K7vC+vXWcuBdElI1aB
         SKZVlclz0HSiQzjfPARpNfYmUaLORsh4YiOkoiw1lX3UE0F+8CfZ5/kmOnlxqhYa3dBk
         pckVqnYFii22HV9Y6qKtK3STK0k1Uulqdt1lxLXbr8f9B5AWUndtCFO8sXlOYyCdefJg
         XYIYF4fdYrRrckfgAOLkOZp+t8uFiHW5aS9VXQWFlnucPMOsdSeS0qW4AghomeG+XxYR
         WXnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f9W+AS7SCaoBv8dkA7yUI5Z5mGokXZ6WQ6MLzDJ8fpU=;
        b=AXVrZGbj41cFDYPX7Yhlcf9H8KYz45p1iMr+b/R8fazPeZVRXCW5cZZjy8KtbkGfpi
         LfzMZSWYQHRl7uL5IfB6L/ftYhVPE1G9Hi5LZa0nZqhwdj1XHGcZzAa+WRQD1GoXPLhr
         G5tbd7k3z5naXj2JlQ7XlX+xhgeHo3Do4ZdPNn+cFhXT+ESsQDFC2u+OFnXyaHaVfOiU
         XTStoWQPs0uGpds4ZtjtX/TKL3k+BAIyo0cMsdnjjJ9+YCuDK6jq3z7YFbWCJIx9ARjC
         8lWARBgQ6jbRwnhXg1Zqbh/a8ETyAD3s5416ULxwJE0svROPOdYFQLY1ZggZ5MOU1kmg
         WK+w==
X-Gm-Message-State: AOAM530EQvocuiiVOXz6pfDiW0synNoI643CaavwDK01uFmlY5ZuxdbC
	x6iOzULmzb//8IpIj75NOac=
X-Google-Smtp-Source: ABdhPJyiisqlHnHn0VKv86xNWbKGwZgHDiW4rllv5PvKxuBChokjfGKYkOPPNGri9IIiuwHFrTn52Q==
X-Received: by 2002:aa7:d049:: with SMTP id n9mr26393030edo.39.1595329570477;
        Tue, 21 Jul 2020 04:06:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d37:: with SMTP id dh23ls3272965edb.1.gmail; Tue,
 21 Jul 2020 04:06:09 -0700 (PDT)
X-Received: by 2002:a05:6402:1a3c:: with SMTP id be28mr26162622edb.140.1595329569800;
        Tue, 21 Jul 2020 04:06:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595329569; cv=none;
        d=google.com; s=arc-20160816;
        b=GVyPh1J6lDzMzqOzApFwsRuVFAUSmWtJovlM5B9Zli6NapJtH4OLsEXvy7+czjAWWn
         40PO9m4jIuAjvZzjX8VxGrjM/rDARRxlY4KLKa4AonMeAHhI7KBRBgH9+FtACqC1Gl2b
         DBOQwhNIeJibaTOBU7bTX4ccSL6wid8zvCNlAoHoRgzZlqdkqKx+C/jMo/hIrZmFbAgJ
         pj9Vq8sj720AgNxbzOqL+EFRUxVuQoMc/6YQwohPUoAr1776eje/LMl4GvwyQXNPOgmD
         oMUfwdakbAWmAITHFah9StaVFpEoqdOP5dXlGx8sRDNNyfliCUp0VDrw4PAGqWZmkItI
         rUSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JitW8E/Uo2q1CMw7tRyORpusuSv9wng9iRv55mMDpbM=;
        b=o9q0Gol4vdYYptmEv3lLl9b13ONHAqkJCNoHY/qqEiFBPJWGEMOP2LevBc36LWyElM
         wEEqELODcjSFo2SJkseWJ0m3yceCoe6ssS4Strj9kVgVNdXIn0O7rlCX1kzAqzANMEeF
         m8fxrXlU8+KUAgI0/WM2EMwYoYG2B6QuIIYAAyjEkKhcuoQi1DjwRPhWm0iZEvVyLgaM
         VSPSwVo+1sbHI5040U2+sBedBSOmbkZte1fT6XwOmea2PSMKINeQxwjbYgCZx0y/oOE3
         68NMbOjCmk9o/z2HEcOfdQAxPXGa9qHgr6Oxg7eZ57RxR1HG/a3TI3r3LEBqFGQDUM/i
         srhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B/VxyHE+";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id i18si1034129edr.1.2020.07.21.04.06.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 04:06:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id o2so2449002wmh.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 04:06:09 -0700 (PDT)
X-Received: by 2002:a7b:c2f7:: with SMTP id e23mr3478083wmk.175.1595329568258;
        Tue, 21 Jul 2020 04:06:08 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id s8sm37009753wru.38.2020.07.21.04.06.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 04:06:07 -0700 (PDT)
Date: Tue, 21 Jul 2020 13:06:02 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 5/8] kcsan: Test support for compound instrumentation
Message-ID: <20200721110602.GA3311326@elver.google.com>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721103016.3287832-6-elver@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="B/VxyHE+";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
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

On Tue, Jul 21, 2020 at 12:30PM +0200, Marco Elver wrote:
[...]
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 3d282d51849b..cde5b62b0a01 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -40,6 +40,11 @@ menuconfig KCSAN
>  
>  if KCSAN
>  
> +# Compiler capabilities that should not fail the test if they are unavailable.
> +config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
> +	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
> +		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param -tsan-compound-read-before-write=1))
> +
>  config KCSAN_VERBOSE
>  	bool "Show verbose reports with more information about system state"
>  	depends on PROVE_LOCKING

Ah, darn, one too many '-' on the CC_IS_GCC line.

	s/--param -tsan/--param tsan/

Below is what this chunk should have been. Not
that it matters right now, because GCC doesn't have this option
(although I hope it gains it eventually).

Paul, if you prefer v2 of the series with the fix, please let me know.
(In case there aren't more things to fix.)

Thanks,
-- Marco

------ >8 ------

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3d282d51849b..f271ff5fbb5a 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -40,6 +40,11 @@ menuconfig KCSAN
 
 if KCSAN
 
+# Compiler capabilities that should not fail the test if they are unavailable.
+config CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-compound-read-before-write=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-compound-read-before-write=1))
+
 config KCSAN_VERBOSE
 	bool "Show verbose reports with more information about system state"
 	depends on PROVE_LOCKING

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721110602.GA3311326%40elver.google.com.
