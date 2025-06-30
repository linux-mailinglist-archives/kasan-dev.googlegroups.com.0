Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI5HRLBQMGQEYYQPSIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 63FACAEDF53
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 15:39:54 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-313d346dc8dsf4921658a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 06:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751290788; cv=pass;
        d=google.com; s=arc-20240605;
        b=UayNlcdyUrqJre0gvBbqVuYrxPi05f7PCD+f1024A3D0o/mHRu1+2i/RirDiWGqhNO
         sAEi76AMZdwX8w89Z87W+TIyHt5nMnk59M24BXKbRCqFVSjurdBanDQZqXa7ft0sqkcT
         fFB/jlIMY46Vt8ZDh5VY0tf49pUWkFzyxFd1uQcEnzfmGr3pvCcofZ5drILtbRooDeVo
         EMVnz70uA40zurjZbScgjncBm/rv8fqoEnHStSW3Vwa0OAARosJEoxhXiMzyxqOOKdkB
         xidVQ2BwA0VzyR9aaEKWBa1QW6Bd3dSrIzHB3bWKuXm8uGLpP5vbnt4o3mztzap/RiIb
         ml7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9v9JwF25C6imoFt/+9BHgo3+mMLnHJJxCSMvar7hXFQ=;
        fh=sfoKfmPqE1UWCQl5PBwnr82GO3RuXUL9f4+61GzLH6w=;
        b=BqaW9L08jx3p2Eh8W1lRO5w/+c7d7nHLM+wMiUQF47/ujSqwaMNe6wGINnoWYkLsm9
         9wejGX55ve5ET5zbmPQITR3Bu+sGtpr9pkslmwTPfYBynir2UdwbWgQl84KrXCkmtW0c
         gYbXtOQsNnm21JY545OXfxDQ01afDzCoryrXcS1yT3jBoijVg4qxU0lOLgzk979ZxxQj
         DO/fUSaI6nqtCsPxeWbDYwdPHX5+BF1J0nhnyzy0RcOm+2P6wSfg2AD6CPBRF+kxzn/d
         6LMrUNy9UYaaUh/PFu2d0MjVraXiINL3rcIm1xQGuR76Pn8iYusOLSF77ynR6qkaPMo7
         8U8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G4vx359h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751290788; x=1751895588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9v9JwF25C6imoFt/+9BHgo3+mMLnHJJxCSMvar7hXFQ=;
        b=wSRHuO/LxqCepTldwqzy/JYDkOQtmuQP89ecXFrURH8P44ZhrvtyJ0URkJ91w9zn/s
         3wldaNTvU6fCojotwA5O+NhJnlrNlr43xPOeZPL/kggkF/Pu+gODCtRPNRKR2FPxxkt9
         30H288wCEgUvVaS4KVtQqZYqOAVdtOjutZS7lRv6fC4Jn8eES7anHkQusWYC6+0MG87i
         JpDPTCVXhvjegj8lIKE9mlvj9rJGYT+Buu78651/1FUeVh3AwOuX7O99zggzZmPYb8az
         G9NbSHnnMhXccMrphf9iK20tQNFJB8VlS1PljG1J3MiMHynr+ZUZQYbIxp6z7z4YXz++
         CLYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751290788; x=1751895588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9v9JwF25C6imoFt/+9BHgo3+mMLnHJJxCSMvar7hXFQ=;
        b=aKMFpdE6MYgJQWsiLsDWIcrGh3dpIdcW2J6HpA/BA5zl1Susi9W6I37246fvlyNJst
         yRl1pwYL1kbTplO0qlwRjuC73hLtclkt3Bek2S7JNXvobx8LdLCexnAG8sJ/T3lfYZeK
         Dz6ajgTUW70kIHcDnaiEGkHc/xjUAxgJ7AiqjYkeAqFrIbg7F4UDatfujH2g1h6NTGxA
         viTJQh/7upJFzgVbj7QRtwgMT4tqshTHYXqBO9JDE7D+U1mqptyohwGoVqAwxyiC2WOe
         rNA5TWuu/KAXWt1/zWzh8x5XY7NHO/YD+xVb/RPG1pQZToWs0WLfz6TAR5i303yHLpfW
         BMPQ==
X-Forwarded-Encrypted: i=2; AJvYcCXM7bcV7UoHWB0F+7QIyVXimwR8na9PytxJAWjaSRH6UhzY32cHx5/EDk6op4Kj0lGMeUWTXA==@lfdr.de
X-Gm-Message-State: AOJu0YwXrAGroKkmr+JAXtvWUYqxLJXhwzT6K/hN6Z8d8VpulEa2zohF
	007O/5MiROxgsAJN7w1RJ/5+JEGvpPfczFHWicfFAzt4VCudIpSC8amo
X-Google-Smtp-Source: AGHT+IGlc+kdW2ZhhQiXTs9oq9NrdZZWxH9K6ci2dgptsQtjbWIErcyjo5vY6axpDIMc+2XhmVvKkA==
X-Received: by 2002:a17:90b:1dc4:b0:313:17e3:7ae0 with SMTP id 98e67ed59e1d1-318c93252admr17031726a91.34.1751290787592;
        Mon, 30 Jun 2025 06:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJBfyLb9w1OtdwHqBUA9Y2oiE5m1yt+xu0t0FiAQKefw==
Received: by 2002:a17:90b:4a52:b0:311:9c81:48ad with SMTP id
 98e67ed59e1d1-31686f350c4ls4892492a91.0.-pod-prod-03-us; Mon, 30 Jun 2025
 06:39:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpDKMwcr8jMUolh1laZmhvt63ngqxiigUbGhpcYxGUWgkd6T5SKWFQ+WnpkHRh4icUMtQ85TF0gSE=@googlegroups.com
X-Received: by 2002:a17:90b:1dc4:b0:313:17e3:7ae0 with SMTP id 98e67ed59e1d1-318c93252admr17031565a91.34.1751290785697;
        Mon, 30 Jun 2025 06:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751290785; cv=none;
        d=google.com; s=arc-20240605;
        b=gd3UlvoPCZcOSBt28Ca7RRfgOeW0wTkuQYuSOEKCdJJBDZrrtdZK0LdmwTU2cTSoa7
         XHFOMe5CBJFGTjMtFDnvQ7wEIQwnxo8NBv57pjqLI2Czyx01TUF6nLnzQfGjHlsU8feY
         +QjOHi0yMK8EeRrW27YrKJzhJTWQOvFesMo47tJEzU0izDRDEthSL0UJVT9qLT6l4Q5t
         c36iECZ558JzZjUNkuJ7S3mxOvG15q8r+7ym5LJ71OQL0sCgjpuD3NRvONnAENVof8Sn
         ZArc/AAOMaZMtnDA7Zk+ZWymiBv3Ifv4iJ/TzpmHmNfGR6Xw2Zpw86/rjfaBx9NYO3tI
         uZ2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d9AuvsCGB4RiILp5tNnwix0tzPCkF5zQPFb/CWJ1MHU=;
        fh=FemxqUGHl5jQi22gTCHtLzJ4cPOOI1KSUP2iDKDBWAY=;
        b=kSKjVCd5Tnc0n+/I3OWB6yE4oK+jqXgV7PVyaSm9eiY+Ccn5+2K3Jzx08ai778cIml
         LSRjeenlhki8XC0z806iZDjBF7uBvEmaZ3gykaEGlzY2iwhXFXpEWiBcw1ItL2nhwdeZ
         05kevf6hmipzmYvnWA8HcyVgCjH2zYoayud8MPGQ5yTxIgIxtVEylv1gOT2ibrXPDWWr
         HPcwc8juo04hv5dQuJWSbkjZo4uajRrzUkAkxR/pIWwojcLLp2lWPf0IDfqL00q6Xyke
         6GXhaTdMzYoHZWxUaqLXTR2feSyX+IzTqTQcs2uA5H8rwWkMVjhWv09k+LCbL1wgGGcX
         VKbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G4vx359h;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-318c1378f62si550712a91.1.2025.06.30.06.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Jun 2025 06:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-700fee04941so12796966d6.1
        for <kasan-dev@googlegroups.com>; Mon, 30 Jun 2025 06:39:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfzgJKUg+Cg3P/znbjEoRHtx7dX11+nYICobuhLK/gDto8IDL5SxnV1Cf5ZvMXvL+sKbd/VP/FJ5c=@googlegroups.com
X-Gm-Gg: ASbGncslBOF5mPpGzNvX3lOmj1yF/Ax/1W4WXBmWndRfPjZcbsiaWMAkQWUIIYpBlS9
	uxyijMyL0HgyXCH739IkBTtt7xFMrkmnpKuLuvkk14XfaU0dA06/UAynkbHImJl3xECHNKTWg8Q
	cZcxn/WDzV9PpXCRw426xNEhgUqALUfYy6k3NMe1UXKQGw0xrkLDBx+K3yRw78RJIrtymuR0sLw
	0RkM65m+ISD
X-Received: by 2002:ad4:5612:0:b0:700:be60:9515 with SMTP id
 6a1803df08f44-700be609549mr124994426d6.9.1751290784445; Mon, 30 Jun 2025
 06:39:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-2-glider@google.com>
 <20250627075905.GP1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XvYNkRp00A_BwL4xRn5hTFcGmvJw=M0XU1rWPMWEZNjA@mail.gmail.com> <20250630074340.GG1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250630074340.GG1613200@noisy.programming.kicks-ass.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 30 Jun 2025 15:39:07 +0200
X-Gm-Features: Ac12FXxcEl_XsGEIGdCHbgVrVVScwiNYO8j6atWMmRubTk4CPTsJQZpUXMmqqqU
Message-ID: <CAG_fn=WYkgf3=9bTPJCpEq0HcxCtM-Kj8R-PQkjJgh4B4E16fA@mail.gmail.com>
Subject: Re: [PATCH v2 01/11] x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
To: Peter Zijlstra <peterz@infradead.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=G4vx359h;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> Anyway, looking at kcov again, all the __sanitize_*() hooks seem to have
> check_kcov_mode(), which in turn has something like:
>
>  if (!in_task() ..)
>    return false;
>
> Which should be filtering out all these things, no? If this filter
> 'broken' ?

I think this is one of the cases where we are transitioning to the IRQ
context (so the coverage isn't really interesting for the fuzzer), but
still haven't bumped preempt_count.

In this particular case in_task() is 1, in_softirq_really() is 0, and
preempt_count() is 2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWYkgf3%3D9bTPJCpEq0HcxCtM-Kj8R-PQkjJgh4B4E16fA%40mail.gmail.com.
