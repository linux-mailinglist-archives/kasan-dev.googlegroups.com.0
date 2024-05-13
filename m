Return-Path: <kasan-dev+bncBCF5XGNWYQBRB4OARGZAMGQEE7WFLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F6418C4723
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 20:48:19 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6a0e7d77b41sf68393296d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 11:48:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715626098; cv=pass;
        d=google.com; s=arc-20160816;
        b=BaJYDDIU3snAmKNBvzDN3R/HmC9e+g/vuKyj8yeY2sPlPjPgegoZB+qQhHcpee5uru
         jPNXaJpR5DkUvTkGsHVvyg4MjKyPNlPgululANWamNiPYQTcJKvhDQjNAh9wd1GoCuiz
         tbEOF6qgjZuX4MGRWv0gKN4k/lCNKKVHaU4cUgv+qlULqJGLtcKLCB5G20/7+tI/82v2
         CiyLnJ6kE+USJMpn/wsikd+5MRnD4MTs6XPy4RBIS21k0Ga5AJia3d99mtDv05n7x89I
         g5pZQxl7K9XAqJXkyGkq0sgC6EeTUp8lZdeCBUXE3b+QmUqcr5Vfw5/i++73Gutl8CdG
         PiqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6okTB0Cs/UNqac2c5Ih6tP6S2pbS8IoWrn/faZgH2xE=;
        fh=jASKpgy0z0Epk1khGIMjgBATMCh4wYffL8/lYOwu21Q=;
        b=cPbIvqx5ylSLjuEScoP6UToDM8TOAICi54jzbcXP4isfHnwfNTfn0h8GAvyO0+wcgo
         H2+wHO17ly+ivd4R5mBIfym8ASQZTfoC5U0PhhwkaJNOlYmSoTbav8HWozluX9AW4RLh
         Ao8fwk25Rnoq5Kptnc/2yyyc8i4AooKzVBgpOBupGaSSeLZLzvID5TLEQwup4hyHlp3/
         8ESQUoVkBy74WggF7ge1YumyfBlFdZAqRvnn9pnhpi4U+vz1qUw82AtkwCSMZ1X0sgsV
         DqKYhmKCFrt2GBtzTlfevmmXOY6TdWZ65MJwEyDNJuLtg5C5lvfKaA3GR0FlSw6bHQmA
         JOrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=d7swq8A6;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715626098; x=1716230898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6okTB0Cs/UNqac2c5Ih6tP6S2pbS8IoWrn/faZgH2xE=;
        b=nuWuQwF8nGqcyKa4E00j77DYd9CjA4exhTKsgbXJ39q6VdbWmMngF3gPsKsWNp9bvV
         dB/KWcT348JLsNWI13hdfFhb++dg+CmM/aZhB2B26B9zQH071q4Y0Apvgtpn+3EhLffs
         P0Wsq8pJ+TmImLEv0N9sYxpuxAzt+X+ueCLHtKWiUDCXteKnCtEeYEvBzoZX/1fovzH8
         2scuFUSe+JzKK1lfPPh3MKYUIlEFD/CGgmzm9/+lwTNATj9rmeBjskKTa2tYyukJ7Zji
         vH9rD3l2vVI0D0lN6sX6HkX7XL/rZuLed37UF2xKrMmsAo871c6Eg8fSTA2ZMvZFUTzg
         xMiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715626098; x=1716230898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6okTB0Cs/UNqac2c5Ih6tP6S2pbS8IoWrn/faZgH2xE=;
        b=fOUmCDZpPWQn4dR39Q2yZMFdczRZC4D1fmkAeuU+Y9qrCCCDjvZ9D2ImY6QufzPqIl
         K7IxOcenC1QA5Bn47QZytg1e8yc7jcT+sPyQo0+aZIoFIjZc7+4ZGuTN6tIW/ZuN8sMy
         EnyH3OCZJrl5Y34Q1ypUR6/TJ27Dx6ZXBFwC/tTZ+GehKoWWsIykXLW/Xseg2Z0K85PS
         VpdVjG/K7sDnyYkGWkn72erpI3dJBL6clj6nXS3IGfzShaNtHZ63E1dqm9lxcUf7he97
         RbP5R8WW2opDnpFOdoSM2+pfR/2qq3I/Q7sEy5Ght18kDpgTosuqB6R/geKk1rG1NJAd
         0DZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyHb8kghyWzAL0BYTS4IavQUwc0WVZ8KbzmcFi6tVYdAdLqmEhPvo3bTXtZoXgdnvUuynyxojbtoewFakqj2tDGQNzJtR6kQ==
X-Gm-Message-State: AOJu0YzXlsDwaCzsoJ/I/4RfZQNfgXLVjzf4lTC9XqxBSYKlO3s/b9ov
	nt6dH5W/FfKEcwZzbLEuEdLJIYcpvreiPKh1S7J6Guq8mSb2hhrw
X-Google-Smtp-Source: AGHT+IFosv2d9nZD29TklheTAmUdY4hXoYktl+ew6UMVoyOgerW/hH+4EWGp0Rvlsa0CHvCi5qx6Rg==
X-Received: by 2002:a0c:d848:0:b0:6a0:d3df:d965 with SMTP id 6a1803df08f44-6a16837a653mr86077786d6.62.1715626098024;
        Mon, 13 May 2024 11:48:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d2e:b0:6a0:c7a8:7ed6 with SMTP id
 6a1803df08f44-6a15d3343f9ls79532936d6.0.-pod-prod-03-us; Mon, 13 May 2024
 11:48:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnQ8agpvZzJI4g0Osvxvero7POZe1oPwc4t9vj2XAVMUDVOV4Oj58rjkDRbsPP7bioRYUQvgpi6Yw85e5iKAvZcPL5qXpLsnSLFQ==
X-Received: by 2002:a05:6122:922:b0:4da:aff6:5eee with SMTP id 71dfb90a1353d-4df8835e0damr6549199e0c.15.1715626097223;
        Mon, 13 May 2024 11:48:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715626097; cv=none;
        d=google.com; s=arc-20160816;
        b=vIjta/e/ZicMpf9mRkmuz+1EwGAw7PWf7qVNePhplH3GUh1mfCloJCq+QtAdJUXkiq
         b3PN756NRn49NxV1afYdda/jqF5p/W8RBL5p0LsmGewTXyqAsCR0ldqEfDBxx7F3vMMK
         yg7jgcSj1gKwDrnu3VSOaPfTFJ9GfkLOo8kT0YHlqBLx3AvCMNHlY5SMXjLsFpHNIO3i
         rPEwsJTPgHuSCdgjbS1vbtWbt2kgtOaJW7q5gVL8yFYG2cw04Zfs125KPXGRnuKXzJ49
         JPe34V21EpwJ8D7kiCjHhHvtxCvuGJ2lYxtIE9/s0dEWSxYsSj0hoSRRVKjhAqLq5DK5
         RQIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YMCvolyyAMKqM2SEdNiyJ59O3X5pzLBrCG8ngReTAYg=;
        fh=TlOngn2ya6cr1NIicB76vQZ5t9367ae+TshyBiz/nK8=;
        b=wHMRhwvxXu+LuqLzP/ZX1V4lFRPyetkkxJvDElxp0zjpA2LGVPUuibvdjTkdiuHH75
         ZQXzQ0e3ZWflo2B43UguJBB3OjbY5mY30halDzgmEoFSNiL+G8YnOmKV8lhsch+Wpjh0
         7aiMPntLZ86NJQ1cxwKFQVdzFJMZc0Oa7Fj2eH3Sw6KEmb8owONxxu47gEfSSOmFegEm
         jpdPeV/a4jJ0+JKj6rkRZSWanlYYCrdTtld4ZNtpUjUKt0MHflRNiLwr8OwwX1Kgv+Fu
         xF1We02X2GV2TBOEB2+t/0HJlw0W9I0bUt112Kge+FLjvZo5nyVJiaGd9ech//NN87DJ
         Ge3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=d7swq8A6;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4df7c0edf72si454196e0c.5.2024.05.13.11.48.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 11:48:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-6f47787a0c3so4264486b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 11:48:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXKkNAMJYpNFMg1Vkj0NvtHR7Qw9SUwkB54v+3f9dwcuti8n4kJG/MgCvf3pEkSGDSFEv2Q1H9kZFVTwuL5lHLI32J5yIhiL8UHVw==
X-Received: by 2002:a05:6a21:983:b0:1a7:a6f3:1827 with SMTP id adf61e73a8af0-1afde1b719fmr11220335637.46.1715626096189;
        Mon, 13 May 2024 11:48:16 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-6f4d2a87bb1sm7697326b3a.87.2024.05.13.11.48.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 11:48:15 -0700 (PDT)
Date: Mon, 13 May 2024 11:48:14 -0700
From: Kees Cook <keescook@chromium.org>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: linux-kbuild@vger.kernel.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Peter Oberparleiter <oberpar@linux.ibm.com>,
	Roberto Sassu <roberto.sassu@huaweicloud.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
Message-ID: <202405131136.73E766AA8@keescook>
References: <20240506133544.2861555-1-masahiroy@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240506133544.2861555-1-masahiroy@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=d7swq8A6;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d
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

In the future can you CC the various maintainers of the affected
tooling? :)

On Mon, May 06, 2024 at 10:35:41PM +0900, Masahiro Yamada wrote:
> 
> This patch set removes many instances of the following variables:
> 
>   - OBJECT_FILES_NON_STANDARD
>   - KASAN_SANITIZE
>   - UBSAN_SANITIZE
>   - KCSAN_SANITIZE
>   - KMSAN_SANITIZE
>   - GCOV_PROFILE
>   - KCOV_INSTRUMENT
> 
> Such tools are intended only for kernel space objects, most of which
> are listed in obj-y, lib-y, or obj-m.

This is a reasonable assertion, and the changes really simplify things
now and into the future. Thanks for finding such a clean solution! I
note that it also immediately fixes the issue noticed and fixed here:
https://lore.kernel.org/all/20240513122754.1282833-1-roberto.sassu@huaweicloud.com/

> The best guess is, objects in $(obj-y), $(lib-y), $(obj-m) can opt in
> such tools. Otherwise, not.
> 
> This works in most places.

I am worried about the use of "guess" and "most", though. :) Before, we
had some clear opt-out situations, and now it's more of a side-effect. I
think this is okay, but I'd really like to know more about your testing.

It seems like you did build testing comparing build flags, since you
call out some of the explicit changes in patch 2, quoting:

>  - include arch/mips/vdso/vdso-image.o into UBSAN, GCOV, KCOV
>  - include arch/sparc/vdso/vdso-image-*.o into UBSAN
>  - include arch/sparc/vdso/vma.o into UBSAN
>  - include arch/x86/entry/vdso/extable.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
>  - include arch/x86/entry/vdso/vdso-image-*.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
>  - include arch/x86/entry/vdso/vdso32-setup.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
>  - include arch/x86/entry/vdso/vma.o into GCOV, KCOV
>  - include arch/x86/um/vdso/vma.o into KASAN, GCOV, KCOV

I would agree that these cases are all likely desirable.

Did you find any cases where you found that instrumentation was _removed_
where not expected?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202405131136.73E766AA8%40keescook.
