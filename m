Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHARGZAMGQERM5C6OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A38588C47E5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:55:18 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1ecb78ac58bsf8221465ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:55:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715630117; cv=pass;
        d=google.com; s=arc-20160816;
        b=wejBnfJim4c+ZCldpvsyp/QDbp+zioVzBHxGDSQagSH9P9KbtqNbmXSBwN/1JfuK5d
         Z18IMPOhtbQ7Su63uczSrZfhJZke0wFr/HnBF3jP9x0u4WMyASn312PlwKV7rOXTTtfX
         PnUUVuFGt6teFDEheNeEaGyRA5XakK5vebjPYXsPGLmM5BRHunScItxxSTs0Swo22KJT
         VYJbrDVYridF/fDMwlNYszQHgNKl5bsg4RGrLbKxmz1MSdFuWMQLmF/DLAPjN+nL28+e
         GxSeTMP6VXwZQlIagNsM6gNY+Mnt2lSjkIyx0XUeeDQaAUP77Jok4WXlM+lKPdF2+kxy
         kSVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RBI/8hSRRTXq7IFyqcY6/3Ug16NLYLtt5nQbsTk6/ZA=;
        fh=2EppOir15sR87MPGSC6VfRH1uIVygOCdkEr1un+Qmpk=;
        b=z/v1/tzACWIAqGqsUvw65p3SAT1/4+GASj913rr61MBixmsA2N/E5MeSZ9lfmxJ4c4
         dowH4j1UwLtEe2V6VCt43Mn6YVVMvpHVpC7YU4VM/KTLs9XAMcs4zrMff9W2bBhaQtCd
         1q5OO3Tdv7SoLIHJXQTpqXJvkNJ9aOi17VIR3REAtgf0t74IZ1RfF2FUApPih0sCdspO
         r9u7GlgTGoy26J8ftCTY0uTxCeoLOMVIrGrQ2xujJXIevPSIWSA3t72JolFNTyXq3cFK
         F/rC1MkyS74JQbR+waplru8tmqBt/dWNarJrAeD1/GExt8Om1zAtqP3oqCHGuv5PSF6r
         b+ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q2InWxEU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715630117; x=1716234917; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RBI/8hSRRTXq7IFyqcY6/3Ug16NLYLtt5nQbsTk6/ZA=;
        b=o0zP2xQ2sVw4MGn9yDhvp9WReto8UKlUubgcWGO3yam0vXGF22lrwxHqrt0U86aRLv
         9LAcWwa1xIBljvJKy/c0oQND6NY1etDysOY9Y833E44+oi/0gxLeN0Ud7CjEIRYiLYzC
         +ywyz/RvJyk0GchAJLMkzCjAnmleoBTPx3wtn1LfR/LvFyMc0m4NxTMpJ8Dv3717biix
         LFLrV+sOtNfD1XyalpcUoAZGd5mUHdH5t6Mx0Gmv9/mHW7n28BElHsQjGpo8nvCFDqxV
         JLDgbMbd7b74ut9mNWVbAcqioxjOygtleU5+hlWt7OJbdMwnYmzCq9NrFXkjJ3SHBAoz
         afgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715630117; x=1716234917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RBI/8hSRRTXq7IFyqcY6/3Ug16NLYLtt5nQbsTk6/ZA=;
        b=F1Mj0kE/dnwVtm/mppz7LyLzUqO7QyXPa5EbzRI8YLWCWLPhQCtMusMFrqjIGTJcw9
         xCDH8SbS9iAtIPHVNsAJfTaTrLrR0g+hC5eCBN81Z/6qzNwhAUlJGY+d14snl9kfTeu6
         8qLf+WitugJbk7bT8zGzpasuMyAlZNvu3VxOTgeY1+WidKgQKK+vVK/5ecy6z7e6tcVn
         S94YHxzZCytsSyJK1m+I43VfHbTQRrpq/ggjCGZ4IHkHV2jgWcwAKE7EIeNW25SciXYJ
         HAsj2I61P6lxnAcjc9nP1Ij5xrfJBOHMqo3PevFSM+8htR3lAuwzR1mYQmXWTeXJwlHd
         e16g==
X-Forwarded-Encrypted: i=2; AJvYcCXRC93U5uZiELXyxfRVJ5VS0u0fa7Zr4RxUcKtKEqKUTakhQhmHdAvVu/vn+ecIjuiepxiCfV2W0cDFCXklYnugNFJGHA5+NA==
X-Gm-Message-State: AOJu0Yz/eNlpTx/VYr+2fCqVrWbh5P/HUwQfsp9K5IVzPi/yt4d2fEWk
	vZ/QSvnetnNYPqYUC6X0syrpXPTgzTqyT14MWm20noOYaC3EuK3B
X-Google-Smtp-Source: AGHT+IFTJdiYfQazf5M8j9PWtmfkR1HcJzCTtMKctn3cF3DUOM58Oz9eBmFcF+UChU5qMEZpiBON1g==
X-Received: by 2002:a17:902:e781:b0:1eb:2f7a:ae04 with SMTP id d9443c01a7336-1f05f3fee3fmr4667245ad.0.1715630116962;
        Mon, 13 May 2024 12:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf10:b0:2a2:6c35:b46f with SMTP id
 98e67ed59e1d1-2b6623aaaf7ls2853483a91.1.-pod-prod-09-us; Mon, 13 May 2024
 12:55:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUx+JwxD3C0SyO4gtAqiXjMXBlaorvNlPTkIoWv4XWik2DQmtrDqSYEat7BwZEcg8Kok7j6Nhn+7ln+hlPxXEJ4/daMVCMT5jjssg==
X-Received: by 2002:a17:90b:5384:b0:2b5:1f7d:7eae with SMTP id 98e67ed59e1d1-2b6cc780211mr8861131a91.24.1715630115523;
        Mon, 13 May 2024 12:55:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715630115; cv=none;
        d=google.com; s=arc-20160816;
        b=Dw6DNTS4VksRWUevps6y4S1OoWxd0tfg/Q9bJslmfYLKJYOO2BHm66tSB0E5GZ1iKk
         fXcCzdlhXoBmA7A/P/E13vdYdHXkWMYLlo0wwXlqgAblszShe3QjwJ1yswLvmJStAeIs
         mAzg9ULuXotcDS6TQ0i04g16Eb2YXuhFnqFqigFPDGgInbPoWWU3IXFfq5jCXcZAKsZC
         EuV59m6viiwY3KHNsIYhIYTXQPrESGe/rFO5ccjHi0/GsS7qO2e9Eot3LTWpryug5Q5i
         sUvQ9TOqLVTDfUSsUVzLPvLI9vSr1Uxyt6+7S0/g/9ciKrF337pTRKgVxuLPAwGmlQ7f
         2UaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+L/QJAKhm4Sma54bKYWeDhRohm5ZmYTjH6drv8r9LS0=;
        fh=gopF34O93XuxDblR1g4z34RVgNxbtylPFT7MNW5k33U=;
        b=F8zm1mam0nZBhp6WVJlcThQ/qobmZpIPbPhCKgjy3sKoLcMNsX1R1kMkBUdYRecGA+
         q9rhdG9aVhKUufIR2KyiZSE+/tn9AfEtWHOAXu6Q688EQNEsOG0qIBY/iXiqVojiYlU2
         lbctNCKO3/0esD90ZLr09/EcPHliykA2U1ZhfKWJg9tmHxYKXLKkPjyZvpxFlTCPDv9e
         U8h9a+4RwNHUXi+Yv3tpkms3bA/QVv21f/8S7C7u5yDYWsibc9mn/P6td/qN0GQ5AG1q
         iHFoIVrFK9F+KZxW7SrnrCaz6Li+wyrkYVjjk6V2nH2dgWLJ29TxzBLv4F7B+Nuemtw4
         SF/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q2InWxEU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2b67034b8fcsi990972a91.0.2024.05.13.12.55.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 12:55:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4df6e7414fdso1290051e0c.0
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 12:55:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWFmv88WucBPg4ByULRVh/pvD40Xjmdo/oQ/MzljtjPhUIM5KeDIR/WKfnGeZDScxNIlBB37lXjYd48yfKb7fFR/kYPErCi7156SA==
X-Received: by 2002:a05:6122:922:b0:4d3:39c3:717c with SMTP id
 71dfb90a1353d-4df88286086mr8285451e0c.1.1715630114304; Mon, 13 May 2024
 12:55:14 -0700 (PDT)
MIME-Version: 1.0
References: <20240506133544.2861555-1-masahiroy@kernel.org> <202405131136.73E766AA8@keescook>
In-Reply-To: <202405131136.73E766AA8@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 May 2024 21:54:38 +0200
Message-ID: <CANpmjNO=v=CV2Z_PGFu6ChfALiWJo3CJBDnWqUdqobO5X_62cA@mail.gmail.com>
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
To: Kees Cook <keescook@chromium.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, linux-kbuild@vger.kernel.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Peter Oberparleiter <oberpar@linux.ibm.com>, 
	Roberto Sassu <roberto.sassu@huaweicloud.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Q2InWxEU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
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

On Mon, 13 May 2024 at 20:48, Kees Cook <keescook@chromium.org> wrote:
>
> In the future can you CC the various maintainers of the affected
> tooling? :)
>
> On Mon, May 06, 2024 at 10:35:41PM +0900, Masahiro Yamada wrote:
> >
> > This patch set removes many instances of the following variables:
> >
> >   - OBJECT_FILES_NON_STANDARD
> >   - KASAN_SANITIZE
> >   - UBSAN_SANITIZE
> >   - KCSAN_SANITIZE
> >   - KMSAN_SANITIZE
> >   - GCOV_PROFILE
> >   - KCOV_INSTRUMENT
> >
> > Such tools are intended only for kernel space objects, most of which
> > are listed in obj-y, lib-y, or obj-m.

I welcome the simplification, but see below.

> This is a reasonable assertion, and the changes really simplify things
> now and into the future. Thanks for finding such a clean solution! I
> note that it also immediately fixes the issue noticed and fixed here:
> https://lore.kernel.org/all/20240513122754.1282833-1-roberto.sassu@huaweicloud.com/
>
> > The best guess is, objects in $(obj-y), $(lib-y), $(obj-m) can opt in
> > such tools. Otherwise, not.
> >
> > This works in most places.
>
> I am worried about the use of "guess" and "most", though. :) Before, we
> had some clear opt-out situations, and now it's more of a side-effect. I
> think this is okay, but I'd really like to know more about your testing.
>
> It seems like you did build testing comparing build flags, since you
> call out some of the explicit changes in patch 2, quoting:
>
> >  - include arch/mips/vdso/vdso-image.o into UBSAN, GCOV, KCOV
> >  - include arch/sparc/vdso/vdso-image-*.o into UBSAN
> >  - include arch/sparc/vdso/vma.o into UBSAN
> >  - include arch/x86/entry/vdso/extable.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vdso-image-*.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vdso32-setup.o into KASAN, KCSAN, UBSAN, GCOV, KCOV
> >  - include arch/x86/entry/vdso/vma.o into GCOV, KCOV
> >  - include arch/x86/um/vdso/vma.o into KASAN, GCOV, KCOV
>
> I would agree that these cases are all likely desirable.
>
> Did you find any cases where you found that instrumentation was _removed_
> where not expected?

In addition, did you boot test these kernels? While I currently don't
recall if the vdso code caused us problems (besides the linking
problem for non-kernel objects), anything that is opted out from
instrumentation in arch/ code needs to be carefully tested if it
should be opted back into instrumentation. We had many fun hours
debugging boot hangs or other recursion issues due to instrumented
arch code.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3Dv%3DCV2Z_PGFu6ChfALiWJo3CJBDnWqUdqobO5X_62cA%40mail.gmail.com.
