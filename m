Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVVY5SGQMGQELHZZBAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F77C476F54
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 12:00:39 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id g20-20020a4a7554000000b002caefc8179csf16612264oof.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 03:00:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639652438; cv=pass;
        d=google.com; s=arc-20160816;
        b=yi6HcnuAnshyvv69DeVfVr2Kiv9DHa5qNIvymf03vz2oZuQ7TPWuStjuHVlqe8a5PJ
         +mgfour/ojdMNaZ2JsxEGx5Pf+tGoTsby/Qnt6knAznZsGaUY/1Y1a89blnEQgHEA5TB
         wcF+M/9VtgXFlvxaOCK0A23s9kt+rucajgzDxU0/uJfU4DC6Y1JPTZQSQdorfrq5jRN0
         w3lNTJlopQiILpydGEzSfRKCc2KYBGdCVORjoRdskOQ0O5crp70JCHUMJ69hkz3R0RlL
         Tc68X52ggU7G4lolGqgBpj350OXpdFVmItzWjufdWjrDq0uSEiuGmvi4fsmyMsuNNRG+
         VkJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n3APfCKFO7oy1A/lYe2YBo9cv+CHdyBMic75L3Fz52o=;
        b=dWRxfAauII5TXWCm2Hl9w6V342jb54qSgqi5aB4+jPKS0gDbsRSHtLKnTCT9QqocVo
         ttZoHeDuwbL0QEUCvgm+5tbIEGLnaxLD6zG1akE8Jc9Fs8hrFoUA+O9tvssNziE2c3y9
         afsWBH1GmK8Q2rZR1MWg+s8dcR8aZ2W9bFNFfEe4cWvnPuOzy3TiNpXkVsBtAFBjY9ar
         pUErIGxiJUSYBtAmaD7O+lpz2GV8FvL45zEZOY0eeojF9QiCjL26BfmS8WzfNOYsRYaN
         K51OFaWpmOBZraN5sY+QrnyukKTuclfcb3kK+RrKRG6yWhJjElZ5jPn0Q1zEux0njMvw
         Vojg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aiqQ046+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n3APfCKFO7oy1A/lYe2YBo9cv+CHdyBMic75L3Fz52o=;
        b=mKmmZvGTWSs6hSZecb/jEORQeuFzjT6vnkrcztUYRh0V87hcQGKBwun9SaRbMGSbg5
         1YmYk+dfyJFukLYle1HWolUsjGQdUZfYOuVWUfhsoT06R916p8zen2nMfVzOpSFuR/G6
         3sY7zrn4YrDRO3yob8BDJZ83+9qj0MYnFTx4NF7WTqHamrXNLxutRVKDDkz2PkMj+Eev
         fTyHfUAtA94oEzyI/CWgtuKW3Vt536pHH83cb0rNp7v+gWy/PK0iDAkOG1NwUOVLEfzn
         U8OUoe364Ok/BeeQ69dKC8LbFioIaTJx6hjNzW79h3BV8RTVSLzjsp1LYoIoo8ytFUDx
         yc2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n3APfCKFO7oy1A/lYe2YBo9cv+CHdyBMic75L3Fz52o=;
        b=vaK1y+FQfKIc533QPbCte+CAOC2GCdSLdOLllF+s4z6HFa4PgtHDljpAkAcHAD/RXb
         8TjtKVsB05DLgi5pcXyobE3K0vie14ruT72YGUr9kvGxniBK4GkHCIN0HRMIlabHvT1P
         lNktpWjW4hPbDfG0eL1IEDGHbPAmZHFeoKCQ0hT8oNdUI+rVq+uHMWD/koOoenlhP2Ds
         Q2YkSPmg9rcmnL1y+DimKmPSse9KutNr+PO+uyFAAN0f807XHgRZyevxMUDgSX0yw3DE
         3D+NcuTiw5q4n+3xjf9SqDpg0sY6X4SBEvbQf94RaPeOkCgdH+lyP3uc7qYLSLMAfKCq
         DDpg==
X-Gm-Message-State: AOAM532I8JjNKfQH6+sE0BCOM31Q+HQyC95qH9L4C0vzCqY6atr8dvyC
	k/LWo6Kh9+D2lsUeD99RA6Y=
X-Google-Smtp-Source: ABdhPJxT0W6f8mgs77oJNojHVkwzc8gFMw3jLnS/kPize1wErypuJBQ2abT93szyCyVb3bT0VQ5o3w==
X-Received: by 2002:a9d:1b0f:: with SMTP id l15mr11934714otl.38.1639652438211;
        Thu, 16 Dec 2021 03:00:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:268b:: with SMTP id l11ls1209926otu.11.gmail; Thu,
 16 Dec 2021 03:00:37 -0800 (PST)
X-Received: by 2002:a9d:70ce:: with SMTP id w14mr11980127otj.77.1639652437890;
        Thu, 16 Dec 2021 03:00:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639652437; cv=none;
        d=google.com; s=arc-20160816;
        b=YpbXVb4LOo6uPjaM+gGFxawLfZPdtB3XQ6PTzdhzu2/NY5vybFSlfDdWj/1fTLhTuU
         7eOhnv6CMhUn6ZOQQsNj+WccocU8ppE2tFfpaJ/YskzwKrI5kQSe9kXB2qk21pJseKJS
         5oh+nKdrk0kKM3FAuwmET/jN1+Vw5OjWTWzT/gc+iEeSamehIBUSLql5PVLsNuYjn8Xs
         gEZgptpYYweCGAtxOQ/5ZGrY+Dej0uVW7N7Sd11eXfPcA7hto3sFaDTAJ/s5mRQ92w/2
         IECMFw2SVUwtcvipRkSmjkWN1Fh03JVuCGw0CUF+Px2ldbHKDn30043f1756+g7Oz8KO
         gfIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E9LMQS5ekai6MAbxEJCeesPT3tP3d4FnUmO5zDtlQSo=;
        b=xNEXy06gOlGfU42JJXsUxnZvzJS0Xv7Ya7O+pR5896V2ZPhYWieE9fvwA/O3c/En6C
         7XYcvEN11b/P88pfsYi8omHRLTzGP7MtuDoXlezLI+ziIH+pxiJ505wVFz9luJvO3TMH
         nLaFnAuM7FxWzLn/gOek7Pm8zRANfNtGrGhAqDoU5Y4FfA027JcJEWgYWaP2wv94CgWW
         SY7Yn2G6aDwGy8cyyrYlmttEnaLA/u5SQ/zgcWf+V96k1UcZaN1CN5wmYqci/TndJ8Gv
         l2J5vicuCWRbQUip1Y0SZu80UyyfxQTjPZE1uo9kq703W7cadFWnL1p3tvk2Bby7OxeA
         7nQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aiqQ046+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id ay24si358961oob.1.2021.12.16.03.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 03:00:37 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id b67so22930157qkg.6
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 03:00:37 -0800 (PST)
X-Received: by 2002:a05:620a:2955:: with SMTP id n21mr11520118qkp.581.1639652437249;
 Thu, 16 Dec 2021 03:00:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <6f430d8dd55a22e141b0000357890d872b8cd487.1639432170.git.andreyknvl@google.com>
In-Reply-To: <6f430d8dd55a22e141b0000357890d872b8cd487.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 12:00:00 +0100
Message-ID: <CAG_fn=VXu-XVd8LMqU5g-rOup=8iPWuuL8Z4MtYjGQwbNwHHTg@mail.gmail.com>
Subject: Re: [PATCH mm v3 13/38] kasan, page_alloc: move kernel_init_free_pages
 in post_alloc_hook
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aiqQ046+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Dec 13, 2021 at 10:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
> big if clause for better code readability. This also allows for more
> simplifications in the following patch.
>
> This patch does no functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVXu-XVd8LMqU5g-rOup%3D8iPWuuL8Z4MtYjGQwbNwHHTg%40mail.gmail.com.
