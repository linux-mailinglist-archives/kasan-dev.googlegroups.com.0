Return-Path: <kasan-dev+bncBCF5XGNWYQBRBM6HRWXAMGQE3DNGGIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 601F584C923
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 12:04:21 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-296ebff580asf127047a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 03:04:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707303859; cv=pass;
        d=google.com; s=arc-20160816;
        b=tQZ75jTFSuehz+R2UiixltWImTFC8IK4GH1nog3PVgNW3PGO5a7Pe8N3oGdAUFM/AP
         2rgLVDyPPUsbk5VgAtwe2AnJJVYEbawYH6Swr5ZUO+xktTQig3Aq/JlAwW9FsN6clkLZ
         dzpymJzy02dyqRuMR63E+vVRUlfLSxqhxN7e26eIBPce3nawW04lr0xU7IBaqQBj4GKN
         oDMlxDvF38W4s/jJX+T8WPlMRzm212eVjZ1HU7Ip2Gv9zQszhSxrNwjG85SxMSFbs3d9
         ZCaXY66Vrs4W4+bpwUznY6ZDQIIKIj3yNKqAmXzhihtNDARdpluRHd7T8RKE5weiRVRR
         qkJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LuaoHkiHAGYrdfgpUTZnCWGpRymxvrpq47R49mFRhN0=;
        fh=qKXvB9keensuih1eM1zgGxKkxGndqstL1JwK9YIaIBc=;
        b=dPsXi9mgWmRFIo1iYWwug5ugueidbSt99VxBFxFH/xusc1cxGAFhsub4LBovPBhDqY
         BmFf3JZZhhaXR02+I8t5IJ4eEHmSQ25CYqpwP6kt16K56Gjwu2IRYZK/JPzHcAfRrYc5
         skG+D5gNpb1WWjjQpKeZT/ApL9NM0Ag2IaCqjhdwZzXmoba45rlaLYdNYH7xjXds+QUl
         dit0IEFyRBlwephtg7B1am3cxSNdlQ1TQ6XiEGS7ZiClJl/Ng0EgZqsiEDxtm21rqq4H
         QMYvewzPL53toJjLuv3v1Jk9iRxTUdlBQCVzVEzy1E/50w6af/wx9qz+Mt7YbD8UZ9Gq
         xWxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=agF5HkqB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707303859; x=1707908659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LuaoHkiHAGYrdfgpUTZnCWGpRymxvrpq47R49mFRhN0=;
        b=N/XEtORlbRkkjjZMKB0unQxh0LMlfqzJF45BG3rX70LO0B87re8MtLpXeSLBZXg3Xl
         6iYpYSVFpCEOInsSdNg9Km3Ed5CzcjI18f6wE/+aEIqrZ71mWlUKP/ScDGlFGE+Wpv5u
         aWh2E01O0hg/UR2PL6B51R1N6VZu1rMIRu2+kMQxXGhrE2nEpemL0WoJKFeSuhJ7/zsC
         HwDe+qpijwNoTujZTgKKWqMk3sGo4GjpFTIO76ji9qdVxA7fT5tGH45jQcgw0Dhdw8uX
         qtHoUoUP71psfZCEkHKe2VXaKGf16VhRgadhhVv+hRhD/SCH59cb7mqJDzf3mYFEWWPM
         7qpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707303859; x=1707908659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LuaoHkiHAGYrdfgpUTZnCWGpRymxvrpq47R49mFRhN0=;
        b=sJ9lKx8zhBeI5asC3pmsrwuXWZoJT6OqYkHxyQZOMA4JUhrn1o8NgWrzChyiz1HBZs
         WPyN+le+LB3sGgEJzrKgxMNE4O7QjNdgkTfhbRfzFv1FFmBQU+SSWJjzIRvgET2RmGUK
         6btAK1dSbTzOeOiSQreEFneeBHIsxLNq5SBUzrMfmL6YkVg0sIwlZiFSj4w7iH0TyNQe
         MJbXHEvG4GEXnuTZw9YWZWCdqWn3mWQtAs0EokGc0GHsQeEwzYmjV/LVY/qsgpQCPdj2
         D7XzzK3z5u55Tf6GrFrOcj1jwiZuv5P6v1CBz6rz8JCeU72bcMjVFWgrWbgqWm3euTIz
         A0KQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwTMx0oQ50hdkWIMug/HpzJX/o/9ybUC4ALAfRbZIszRd7OeV8Pq5Y9nmDbLxLzjZupHpzziBULw7rflnsVQQUllpb5niY8g==
X-Gm-Message-State: AOJu0YxzDC6MeF2ZPFWxgQIDPSnkmE1NtwA2YCIUJbInO+pk/yZL5wUM
	WWQTRVXT4CkBnxSp1iRcHGQz3qchAoeFOE8qRHKgECjk5u3Oc288
X-Google-Smtp-Source: AGHT+IFO34B65yf4tcxbSjEcx/dxiRWdeSZbg/W2k6sK4AbkwMuWRn//jB1aDD4KhJivdZ9TmKewPg==
X-Received: by 2002:a17:90b:3ece:b0:295:fd18:6ebf with SMTP id rm14-20020a17090b3ece00b00295fd186ebfmr2266991pjb.47.1707303859448;
        Wed, 07 Feb 2024 03:04:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec86:b0:1d5:dad7:c276 with SMTP id
 x6-20020a170902ec8600b001d5dad7c276ls403156plg.2.-pod-prod-01-us; Wed, 07 Feb
 2024 03:04:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXQ1kmX0vRmC65lq0yR0Zi+frf2uradgOsAahntW2NGboC3+oTrXv49DHFYFrrx4XLBuKoi1ZQ6eQHLSiL93tva5E2J8dnffX7cAw==
X-Received: by 2002:a17:903:1103:b0:1d8:a93f:a5b2 with SMTP id n3-20020a170903110300b001d8a93fa5b2mr4561070plh.12.1707303856860;
        Wed, 07 Feb 2024 03:04:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707303856; cv=none;
        d=google.com; s=arc-20160816;
        b=oVzC1DO5sCXGJNj/PVsOmtVWtd88HM3jupE6pHaMXE1o7kj3WrM5vTrwzq8BDTYA26
         U+Gpa0YXBMQf9QHcevkgBNc9MRIlK5yjgLMX+8o8qoyf6qyZbAUlvdNXYxkJpZQPmVUv
         31lL1LE6W0c173k6mCgBir8IvP6A2Bcdq30zMAyYiLVtuZGS2eAKgLoTutfC+EULDFhW
         ZA3uGamltmo8Gftodt6acs8pSs0JNelXQlY0Er+QXZTo18/ejUrVhP7eDtO+ZrMYLace
         N1ivRJLk4sNmAu0O3vyEBWSz3OHfm5BKglbTgdp59yECLTNEc1mhuPZBLZAqjk9dJ0KW
         7X4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=MkHJEMhdHIEDISZVoKhCE9ifS1ot8NgYUDuuTg1ODbU=;
        fh=CoQsW1bACGDzT9qEL9o1TzApJb4TX4iCy/DO+t8mUFU=;
        b=WKBe2yEQtQHbifLdQJcevIccrAMq4ByZN+goZ1y2YHeWpgkvpCBMN0MTg9RIhARxKk
         3TgkpzWak4svevgIsqggoY0/CnFO0yPtFHOF7T/dkYUCqUCu0FdQ4mHFzjzr3wvGByEk
         rjvzo8Pq0qP92fIRMAbAHuM/b8eVs0v0jy1Xf3sjfE2+2gZujLrwcE9R12eLS9yghR3S
         lLXgrYerk3Tp+tKH7aub152ZU+UkW1/ZRkgtUg1eSO3K4rG5j7mCBl8MHp24a7nrEhMQ
         rWxZDngUrI11uqhwe1wxh8RhLDyYVmye/T2+5EyK9jwllnKPjvZx3Uz3G1hvyn2+3BT2
         9/pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=agF5HkqB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCWC6PyrPNxnkKSS709OyDOmr4qvIpmzU1xp3p0ZXJyPiEiOw3kUDHLohIoiigvIv47EH9ZxqaznI9Bv6PYtQyY9CqT4H/IHkD6bew==
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id mq13-20020a170902fd4d00b001d93b23476dsi112087plb.13.2024.02.07.03.04.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Feb 2024 03:04:16 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id e9e14a558f8ab-363b361ba6dso872405ab.3
        for <kasan-dev@googlegroups.com>; Wed, 07 Feb 2024 03:04:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUlJi0V5EIpl5W4iJQa0awRvzmkvdFS8a4BStJYzxlK4C+KpNMVDEcX3C/cy11p0jvBL7R1fHYf2Smn0QxUZrGKGWyxAVl2igQ18w==
X-Received: by 2002:a92:c20f:0:b0:363:ad00:106d with SMTP id j15-20020a92c20f000000b00363ad00106dmr5585505ilo.4.1707303856225;
        Wed, 07 Feb 2024 03:04:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWrtNEYtrYrUbd3WCx5d+Vo2gSvxdEHF0BNGt6ximizf7qYe7T5H46Ie55fL2VWgxMxlWduhoOX6KlMOKtsxeFyYCjnhIkE3L6KvmtJVxIpjw7kXgW5qPN+w4huuzEm3qwVbp0AVgQ1ZkASW5U90p88VrUkWp6nk5vR49oEi+InXGOlVot97XzK5pkmLoC/C2lIuxSGPyqlv0uv7XGoAEMGG6mOD7CY9rcJB8pP2E8YKfhqP27o1FFSVoC5YBVbtY5PZ9MkHM2h+wYCchXO4Cb0F8vo8CHqj9008WFYSz/M028lVxfT3MffozMwCJI64UcjTuNhYeBexPzgZrEmQuSK3FMTUJHePjnEMG8JGdN/epYhO8fGrZcF43GqGd7MGSkLs0TQbrG7Y1g3GzzCBrKf8uLtRggideexU9Q0w5aJ/L4dwMQvoBR9qCjBvFyTRh6Icke/q+ziPbcKh2mMkoOp3unEJyA0N6zOTMm/dlbK9WvXl3hPgy+yY0O9wlGZ62HqyqCbYDs=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ck4-20020a056a02090400b0059b2316be86sm1109248pgb.46.2024.02.07.03.04.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 03:04:15 -0800 (PST)
Date: Wed, 7 Feb 2024 03:04:14 -0800
From: Kees Cook <keescook@chromium.org>
To: Justin Stitt <justinstitt@google.com>
Cc: Marco Elver <elver@google.com>, Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
Message-ID: <202402070255.36699AE147@keescook>
References: <20240205093725.make.582-kees@kernel.org>
 <20240207014528.5byuufi5f33bl6e2@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240207014528.5byuufi5f33bl6e2@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=agF5HkqB;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::12b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Feb 07, 2024 at 01:45:28AM +0000, Justin Stitt wrote:
> I wouldn't mind also seeing a test_ubsan_div_overflow test case here.
> 
> It has some quirky behavior and it'd be nice to test that the sanitizers
> properly capture it.
> 
> Check out this Godbolt: https://godbolt.org/z/qG5f1j6n1
> 
> tl;dr: with -fsanitize=signed-integer-overflow division (/) and
> remainder (%) operators still instrument arithmetic even with
> -fno-strict-overflow on.
> 
> This makes sense as division by 0 and INT_MIN/-1 are UBs that are not
> influenced by -fno-strict-overflow.

There is actually already a test_ubsan_divrem_overflow, but because the
failure modes result in a trap even without the sanitizer, it's disabled
in the test. For testing a crashing mode, it might be interesting to add
it to LKDTM, which is the crash tester...

> 
> Really though, the patch is fine and the above test case is optional and
> can be shipped later -- as such:
> 
> Reviewed-by: Justin Stitt <justinstitt@google.com>

Thanks!

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402070255.36699AE147%40keescook.
