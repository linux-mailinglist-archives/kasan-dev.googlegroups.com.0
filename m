Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDFOQ76QKGQELQCY6WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 69C302A59E1
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 23:17:49 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id f28sf3032823lfq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 14:17:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604441869; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmxQ+MsvgKJBrmMHDS5F/fICdTTc47OhnJRRrviEhjszrrxbitM53W2HU/0fNZUxtt
         bHhJ5BxLt5b5BzvQtnvAuwmixGQfVyV+2Pcdud0M+nouK7V+2Efj3oHOa0nZrOVeSX9L
         fYwJWoZiXJ+8Qv1oqTISYF5PIPNbVID0zD/1cdKvRyNFWtQlI4HcLdWgCG+s/rxBJm1w
         5Xtzwfz3iqU+HSwC++SIbUhN/WsXFYnnapQSmAcLMrA0Sjh2XeSbqyPXeEokDjf3NPq1
         uyhUQ2460MYRvXs62cT8CdmBrm/SFF7p66xMfduldXQEEHs7IU9M6kE9CENEMh7ly2J3
         rn1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=49BnfQq8ikDcWAI19Sj7zBnu300M6xWmmREbTBeYD+Y=;
        b=IW/R9AokQI+YxZOrP7OFwne7+7O6vGqrhK8x6SJ/jo8Ak18TfVL5kyw38qc2qrvaiA
         AMgms0/B5b4URy1JI9jDTmRGc0kv7hGRBXbUaDmcuXXFrGJrGYDdbmx9deG0Kodnoee/
         DOKj1v+/1rYo/OAn+sn24K7GG9OErLlNt3iHeZjWsn/rEBMH49sxKhonAFk6LQOUvarZ
         RV/fUL4elXrR8K/wzqEwQX2sqVxRusp5iLGiQIswl00yN1iV0kf60tdtgcDopBHI03FM
         R214FxVAVRKixPTtlMm722x1Nb8MICwIE5SjhD8o5fjZfBLkZ95NUQpT1/RGSIBhXSPh
         dxVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dhSpxBoI;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=49BnfQq8ikDcWAI19Sj7zBnu300M6xWmmREbTBeYD+Y=;
        b=EfdTsEMBTLWWrZrrjWBWeF06Hk8iTQJqNfqFB+0TPDS9LacjY8tIsk4lhumMQSJ7Et
         845JzKtokkMNKtiIBzZSBAlvbs8kb0HBtmcayehVgvUZcH7LP9pvAwmO60kkA2ZT5rBl
         rN1QrFQVQHzIk2WhSn3UfZtcO5Wab9J+Xpx6i+yZwYILfvjg0hX5POPdd9XpHB4fJAkJ
         SRYg9uBuvncJDCh+KqoNjJt0IlI3Y4ImC5HPhjHZLZy5dRGC+MNsOqz5av4CKuOy1fim
         dIAhZSes8vVQjAikC+/deOgkAhiAdc+4GxnTmrV535fWEMTNSy7yatsaSAjZmt2Yo6eZ
         vL9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=49BnfQq8ikDcWAI19Sj7zBnu300M6xWmmREbTBeYD+Y=;
        b=WgAY5OCzngCFUcGLkE63OhK55jIn35lzJxmnawNv1amK+Ww7qGMtLnc/4a15WGdkZ8
         SzVgItJgv4GjdatctVy8bNXJAIRH+/y02teyRw4rnq/XdHRFgTBF8ny2pyQ3pVVRw2kf
         cR1l8LYkJcw3ZXj5y7R07aKv8vgr3qIAgjPyJgMY3PLwnVRIV3Sdjy/H7dbFAAJQkqZv
         ZD6P0JtVD3DDXkVL0lPmLBu8cy2IKSXcSnJgNTm0Rm+5jAz9tAqrSnlTzmXvsSTnScHR
         ndq2EqtiY6drxDrgqI3WwkQz+B9W8gut3ywcqOFckgmSmnbEQJAyKCnHCbdfe3+sOHGx
         SCZA==
X-Gm-Message-State: AOAM531eqfNZDN3k6oD1H/9IbnKTO9beU6/wQPUHHiE3bBMrP1UiHCFi
	vTcJsCVBqVSj8kbTRU3/aos=
X-Google-Smtp-Source: ABdhPJzUqIRf7UXBVLCBs366pQaHKuy431i+nff2ZQYcJ9FTztLlL1JsXiIJwY0/ZAnM1wevUEfFgQ==
X-Received: by 2002:a2e:9f57:: with SMTP id v23mr10211826ljk.370.1604441868982;
        Tue, 03 Nov 2020 14:17:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3fd1:: with SMTP id m200ls2127923lfa.2.gmail; Tue, 03
 Nov 2020 14:17:47 -0800 (PST)
X-Received: by 2002:a05:6512:2098:: with SMTP id t24mr9059557lfr.116.1604441867808;
        Tue, 03 Nov 2020 14:17:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604441867; cv=none;
        d=google.com; s=arc-20160816;
        b=goIzABTdEtpNlpTYXt1OmEebu47Owiurr6GBsx+X8w4FCNtBRNNJsSBhOK4MDhXA9q
         mgJpwuZUYd0vKgVkRXAWH7iOlh31QhucZbfGePIzplNG3R2zkb1bg3YFAi7FUfhDzbSz
         N/lnxMI/+cvbGYHbKj4gYvDj+ae12A3FQiV4hrOm8Ff33SBlSPfokPzhQD3McXMJ4ebK
         U5Zx2iK6x35F4Rt3GJ0YF3LY80lVn4p7VkioW5A8QUHKHYKFU93rvK5cXA1KXYDrlmD0
         Gu7Mfmkt0ZPCMTu233AwyLSOHAwxtt/N/jCc04ECEIacWKsrmnbOJB09cthA0hpFc0aW
         yWuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uu8Iml3WkQaK4KYJrSEtvCll/mhluTTPnzMhsFMYnPU=;
        b=YCk/XosRZrH+8+KkM7epFsv1XaLseX8PrUviqK87mLaidAe0wPYPN6tEjmip2XHFC3
         aw/iik1qG+6DVpK6Tm3XNIpLkMwknMKOkmkYTJ6mCRhlpXugo2yvexyFr27JVtA3e4LN
         ujyPaopYrxylJkmD2um1DYeuRoqiA40TCliW6Nmn8m2215iQSPmOv4GzJ6+HG6Ofs66O
         ZaaX/+SBSWdMJLB5quJ3z3E8HTb2F6xa0PplZZjLnKFS9rNyxaqdHUbQLuZIljLIGai/
         tgULtU9L5S2mN6rnl+NbVUSO8qbqjybbWXJ7kRVgTFR1Wv5hp6y8cSk7k+iXf6TInQeJ
         eEVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dhSpxBoI;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id n5si5712lji.5.2020.11.03.14.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 14:17:47 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id f9so24413674lfq.2
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 14:17:47 -0800 (PST)
X-Received: by 2002:a19:c357:: with SMTP id t84mr7777784lff.34.1604441867188;
 Tue, 03 Nov 2020 14:17:47 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-3-elver@google.com>
In-Reply-To: <20201103175841.3495947-3-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 23:17:20 +0100
Message-ID: <CAG48ez3ZeHbDUv_rgMrmEr7PJEzaVCgAV4SVi6A9aj6GzSh0jQ@mail.gmail.com>
Subject: Re: [PATCH v7 2/9] x86, kfence: enable KFENCE for x86
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dhSpxBoI;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::143 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Nov 3, 2020 at 6:59 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the x86 architecture. In particular, this implements the
> required interface in <asm/kfence.h> for setting up the pool and
> providing helper functions for protecting and unprotecting pages.
>
> For x86, we need to ensure that the pool uses 4K pages, which is done
> using the set_memory_4k() helper function.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3ZeHbDUv_rgMrmEr7PJEzaVCgAV4SVi6A9aj6GzSh0jQ%40mail.gmail.com.
