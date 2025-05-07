Return-Path: <kasan-dev+bncBD7LZ45K3ECBBRWU53AAMGQER75YWGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A8709AAE97A
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:45:28 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-22e45821fd7sf1597725ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:45:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746643527; cv=pass;
        d=google.com; s=arc-20240605;
        b=EaUYlczV/tk/na9bUdXzASCPBcuoUJklpR+0+KMsJerK3CBoEFvx7SzVxLu3ykm0Gz
         i8Twl9Rl0oSO9aK4v2piMOc48g1TzywF/x++w6O7SEj5uJiy9lzpfLjM25FEAoD2xQf/
         2nPS2pG4UX3cqh857qJlWzujQYmsK0dQRImuLlViE0yzSfUMI5wr3NJfjz8/dT2+S+kD
         blcc7rI29j7Wy1bUuiSCcDmAqly42zsWdP/WvPi4tELTdVn+i7CFWPNSM97xlYoin8jE
         4JUaQ5IYu82STd9NnCsnubRleGyD83g6qpwNbZXSgIl2DDYiY7pnmbigyhMagC6aWw5D
         6tgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=GlF10m6vFmoWVsVXGcdDc9Iskf3lMTowvgpdzWvKu1s=;
        fh=nwKf7c/w2eVah4W2wBN0lnYxLtRXokzv58s1V9+ewVQ=;
        b=MZuHT9cYGpkh12VLLkWBALTn/C9lNwRXAoqKSymfMRjt29W2QfakZbJgJNTjxXj17w
         SgFHR39CPWd/vnLkgShXQ+Q06S7Os2XVI1DH+n9zbbueNcdydCdNhOdRQJXsPfTIhrA2
         SW4zXkZmdvAoNqCD9wtqEppssPADQTrw3ThZGx5CbiwJuSlylPn0mwUqq6+y1jHs1zug
         p5+GTsxYZTuDEVqOYAIJ+ZUc7dy1tt+JpzApD/0Z9Av2zIU7StG3H46nOLheP0lFcCDp
         /p4MGBzIlIBg/apYxTi1YHfYCRB0AyrKjGFZVQ7NkC3PaqKODBDg7UOUye0yGE8pLhP8
         eSfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ex6DbSwQ;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746643527; x=1747248327; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GlF10m6vFmoWVsVXGcdDc9Iskf3lMTowvgpdzWvKu1s=;
        b=JaG+CF8ilBgBMdkzrvOo9Y2RAogQ7qyZfhgLM6InFtZlMb/jHT7SDfw0pDywYSxaEk
         8fN+vTj3NBiTzXpiWT8y0nyZtf9pQ/WGgQRmsDh7EFO/w1zfxuVB0gUIpFypz0OIHvkC
         57/zQlhvVrNFezMV9M1FBGbAEi2FPH6Cl53JwYftLniF5aGnHs9Qk6DywPAydQ4SKDGS
         /yD0C5aV5bz5IBXcMY4j8Asg+GiTzevsxXLHpK2/UF/XmEVJdpCpnQhRMwbECesi0ZV/
         Fd5u6/7R8emFIWlRtoR25tgWhaYFvFj3POvaoYUAYDHUmTv1m/UdBbgTduli5GfcCQIc
         iaeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746643527; x=1747248327;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GlF10m6vFmoWVsVXGcdDc9Iskf3lMTowvgpdzWvKu1s=;
        b=lSufaYMuBwGqgrxZewFkgJuja6WEnqu9vGmqX1a8HB2P8g+SdZ/phG+i6d0uP9o3Zt
         XXpM0JbsPvaHXW2C8ufdSvddKHGthJyYylEZrrTP5afcKSTSUuuPPqyjKgK22QvnR+vB
         r/JIfVCDDDPA+WDGwVyRxQ/v5rSYg16C1HmexST+prkNrGoGnhJMiU5E4Ej2KtUWCFKa
         lBCfUBcQkWLiOkDtkAMY8gt3HpSH11sWKhiKj7rs2rYySZkxSeVG0lPbDnLPdNou5hOf
         Uj8/k2pXOK8G7NVP1FLoKXAphEHIUqmO9AEvi9lmG7TjJgOfYi2q638KO02PwyqrV6yQ
         TsAg==
X-Forwarded-Encrypted: i=2; AJvYcCUsAd27TJkeW3yz55SKa6K+Y8wg/7g7COqvgn+EAjFDZ8b61jmgnLrqiri/PEX6Zs7IF/1LTg==@lfdr.de
X-Gm-Message-State: AOJu0YyPYkqjhQcfuo40WcghQjEQcE102dAURUQtdBgJ++lbaV8xnidh
	qK7Pnqk72Lwvvtw1RD9ovwsXIiVEXdhTMsZKbO4P+BXPzeyDbgab
X-Google-Smtp-Source: AGHT+IH7NbII25/XGDdfP6EIgiayjOFSN/9Mzo271G3lcopbnTuYz7AlX26YluoM/H2RonROto1Fig==
X-Received: by 2002:a17:903:fa4:b0:22d:e57a:2795 with SMTP id d9443c01a7336-22e5edea81bmr66495585ad.47.1746643526817;
        Wed, 07 May 2025 11:45:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFEM8CJW6LAbXUBV3FHIud9IKWQtY1dUNXbKGXtH5zxBA==
Received: by 2002:a17:902:bd8a:b0:22e:53f2:59fe with SMTP id
 d9443c01a7336-22e846f587cls987235ad.0.-pod-prod-04-us; Wed, 07 May 2025
 11:45:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoZStbEQ3MUgb/yqVuIFxl741fBmw8kgyGg3MAT/FOlI91kDHYRFaZFFC6OHfd+yl208234r+ZMgM=@googlegroups.com
X-Received: by 2002:a17:903:2351:b0:21f:6fb9:9299 with SMTP id d9443c01a7336-22e5ea7d6dbmr61325205ad.27.1746643525518;
        Wed, 07 May 2025 11:45:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746643525; cv=none;
        d=google.com; s=arc-20240605;
        b=losNvWrf1c6pNWC49SvDuaWzoXLVN903/vr9ajaBkAMR9QPvQhydn28pi1Y8obFtCN
         aM/uBcEVp2arTQG6626B9cLGR6jVKGvP6zy+sisC+l92g8vhJoQXcOnIAmPE34UuF0hw
         p6PQ6NZvEsNfInhFblLzqFYo750RGcBiZLZdl97ldgm8GJm0xhY+rtE5Zddyo5s6i1cY
         qkqGrJHB5ffkquwCwjdAQ+x+IxXd9isO1y7x4ii2yBk480gStL0fCxwFSWkKZyhYIRIn
         YwldXz6Jhwa6lmwYD1T/TD+6raYJ5ri3q090DWrNJgZVxp5sr3rWexv+zJHvN80Ty8O4
         WkNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=38gbht3KpWlsXPdZ8hJN+JDl7TnuSRKBtPBm0jl8/d4=;
        fh=MTOXfrUvzL6AqGN+vXIwnV771r5H8JfSEIOSq4Jqkgo=;
        b=gvocCqjxs9duzrddME7eW9yca1cNzVxEmUbolw+S6E7N5ESitqH02GaMeN/ihwt26c
         /S/gkee+uk6LmtH1gdCdQJJAioILrgJxabqv0sHBj2etTRwLM6plu5nKvAxPVRiK5BqO
         jl9pL0U5rgzXBYbDQ9NfEUB9ft7gAIBsnFChazxprHNe0ofZgz1rp/l2e4GUxCV2dqvC
         XKrWJsYq7x65o3Kbb1z1KljGrfOYtkZvY9iu8y83H4urvl/WEOoirpZrgkfIXXaT1Kdd
         /eFt8ESSC2eNqrN+jFZ2gIT0E3kvyWxnXhFohARYI+8KC8bzC/QyAPSK+6lk/AHvMvFm
         P2HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ex6DbSwQ;
       spf=pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=mingo@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22e730e1f0fsi693835ad.7.2025.05.07.11.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:45:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id A6406629E5;
	Wed,  7 May 2025 18:45:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43067C4CEE9;
	Wed,  7 May 2025 18:45:18 +0000 (UTC)
Date: Wed, 7 May 2025 20:45:15 +0200
From: "'Ingo Molnar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH 3/8] stackleak: Rename CONFIG_GCC_PLUGIN_STACKLEAK to
 CONFIG_STACKLEAK
Message-ID: <aBuqO9BVlIV3oA2M@gmail.com>
References: <20250507180852.work.231-kees@kernel.org>
 <20250507181615.1947159-3-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507181615.1947159-3-kees@kernel.org>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ex6DbSwQ;       spf=pass
 (google.com: domain of mingo@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=mingo@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ingo Molnar <mingo@kernel.org>
Reply-To: Ingo Molnar <mingo@kernel.org>
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


* Kees Cook <kees@kernel.org> wrote:

> -	  The STACKLEAK gcc plugin instruments the kernel code for tracking
> +	  The STACKLEAK options instruments the kernel code for tracking

speling.

Also, any chance to fix this terrible name? Should be something like 
KSTACKZERO or KSTACKCLEAR, to tell people that it doesn't leak the 
stack but prevents leaks on the stack by clearing it, and that it's 
about the kernel stack, not any other stack.

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBuqO9BVlIV3oA2M%40gmail.com.
