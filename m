Return-Path: <kasan-dev+bncBDA5JVXUX4ERBQHVSTFAMGQE2MZG7YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 473BFCCFA3D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:45:21 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-477cabba65dsf9665695e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 03:45:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766144706; cv=pass;
        d=google.com; s=arc-20240605;
        b=fjBfCQbH1qQbEbQfFDY4Kc/f+Bhq3BZUBfRwmioWBVIy1seyh/hlyGlmUX+JM4Dcii
         HuJJdQhdbNVVLT1N4x/Z9H8jopWQ2bZzhCgtsbY4wg5Mn2QM0nzmuVa8KdcKDsd2JKFi
         VkwcjDBBzfHxnUxKR/7wFwoKvby1oDDtuwy2n76LfSvKm0Gg10zF8sVioOj1/dz7bAu/
         +wK+uUz56xii7X2cYEB0D3W8/yormmAegvSduZwwLXU+gcAWdYciFdpQOPpqY324JfI2
         Tq4ZY/QXIzpBTaQlMRhbrTTiG7ttC0UBZUQXj6PwslqkeyYgVrkH2ilnd9IXe1WaDu+j
         B7hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kSVhxCu8wmMhTYTF/ACbfJJqtEm8XoJYjUYSQGoAtIY=;
        fh=n6nn/SkACFUhiUVoYGqjAkZyDhTi5qYF5GnR/HASGeM=;
        b=U15ODmxEzs3VrHdm8OqecxFwnT2Bm6c1V2NlR5rHXlXFcmOSeIBiMUwU+gVob1FfbB
         CKJJCJyzE6Fsc6yg7BLqvKICfwekfhhjJ98q2a3Z7s40rgnCbl0MYvnW2zg4Y3CqfMG5
         rhEHmhoCk5Qz4FyszE4DJ2nZzlsU5xT2HNhGPudSAnJy4L7z+EcP3WYS02aT9/T7i5fp
         eFD3bVaN/ScCIkpzZlakQ6OdDz/9lHAeaHnroOGBWScvEt85rAV8jRCZyVIUErmsbur/
         x3SiD9t7UUqME8BkUFb2nrewTMZbVF1xxag0WvgkUhvXgGnMAlLcYuTy7Xyr7mrQ+pWe
         EmVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ETQMtZ14;
       spf=pass (google.com: domain of 3vjpfaqgkczkc35df3g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vjpFaQgKCZkC35DF3G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766144706; x=1766749506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kSVhxCu8wmMhTYTF/ACbfJJqtEm8XoJYjUYSQGoAtIY=;
        b=Ru51hePIBQsFSrrQjp+FD00u1ObHLacfAD1Nvt/UiTh2RaYsQ4I1m7S415Tx1Cx3LN
         4cEslNoY6vl+5NuD0v7lQKyqwZDwEbtSjTcZXNfUu8/NkJ1hj8d/EvDg1t0drykPAnDK
         arWB6RVoq7vf7fj9QYIZSpR61xtbEwLqGdn//Sgvs69XFyTkwLGTzKW8Bt9zArHnX2SQ
         E73uy3VGNF3/kIZPnLJGJ5ZHTFCvAp2FQocUHOVJiL7EsszPB1k/OmZTugOO/ubF8x11
         jJwMNkZKjnSUFVxhKHmnDyYaHXxB2ifI2JxKtAzZ2JQymRSTydPI84+hRI/Q2F8RMWKG
         /+ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766144706; x=1766749506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kSVhxCu8wmMhTYTF/ACbfJJqtEm8XoJYjUYSQGoAtIY=;
        b=c5Exa6bmNRH0Ydj9ZJg/rx07Q5P76pF41RXTo6gdVjrAjtrH3kFf+C2f1IQcIlFESe
         zPFqqqFiIjk7KKnAXZJz2NDUJo0tRUStwXe6cHnEcwpVz/nQRb1VPsKWkDzdrkey/zfM
         uln96g3pk1ndZqj5fmdZ7ELn83Q60EM7+J48LblblMwXPcMD8djgOPiCjn9/nPP4UxOs
         Y1RqqYct50dwmNyBxBxh2r5SCExHqUlJEOOoPFBK476tdRW6oK20CXBwOL1chIs7DsKu
         +oVjyFJPQZ0U40mkgRCtIjwJhXRVIlOBM8lpcqrbNflojZjlp5J0IitVH7vqbl6KwkX1
         SakA==
X-Forwarded-Encrypted: i=2; AJvYcCWLHqbi5j6hYCyyJTD4fjx+aYmBxbT7u7dXCgvrmDbcI6Mwq/OgnhnHzOry0OVuppHKbz6P5w==@lfdr.de
X-Gm-Message-State: AOJu0YwXSsNvaS+uHJuzxslSzNd2/g/I+NElt5jbcbIvQ8a3sMzAfzvh
	+pd4UG5rgBCR7UE1vVp4SfJaSKpnbN6RQSUcgwdk1s3Kx1PaebG+yoLd
X-Google-Smtp-Source: AGHT+IHZGsPFL+DHyS5uOCqPsfTqlGMWZFIGtchSAGMHfKakCnMDdFnnxl1lfn24h3Ubm2U8rpIX1Q==
X-Received: by 2002:a05:600c:4fc6:b0:477:333a:f71f with SMTP id 5b1f17b1804b1-47d19576cc6mr24652765e9.17.1766144705331;
        Fri, 19 Dec 2025 03:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYWXC/ZuDZt8xx2cx9NchJGHijSRePgiGutG6/WRnd9JQ=="
Received: by 2002:a05:600c:4ec6:b0:477:5582:def6 with SMTP id
 5b1f17b1804b1-47a8ec639ecls48779865e9.1.-pod-prod-03-eu; Fri, 19 Dec 2025
 03:45:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWAn2TwfMfIJdlArvmprqR28qJ/Gry6TXYeX1+7AEwoHoS+QhjeftQTDZ2LSU5Z7+55shJfqQsUYY=@googlegroups.com
X-Received: by 2002:a05:600c:c174:b0:477:b642:9dc9 with SMTP id 5b1f17b1804b1-47d19582bd6mr24024615e9.28.1766144702815;
        Fri, 19 Dec 2025 03:45:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766144702; cv=none;
        d=google.com; s=arc-20240605;
        b=DCTUxsCuic4SxZX0NdmXMwYarEuWq7olaEq57lzJe8dUc/EqL+xY7earzVgfaT/B/w
         Lh0z99JO5s9GrikB0n8DAQe1SfIptk/ilLUlopI5wEDopk4oZevYvDwRFZ5BK91DdyXi
         b5qnqpoAXFMIvsG4pOD4K/PUE1uQAq47qXVjzWr6tk5rjKPkcVlqkej7DCggdfR2ZUeN
         onfuoUvVG/Aa69UCWkeZnywFs5z7TdPMYAUNMisLIJlRGVqJfaxRO/g28o0mu5Zi8cO6
         qZLG6dN/9pe+zdVCCByhijmfzCd7N4hDPnjvXCMrecrbxDJLf/oqHADrowVDZeFb5n+G
         +XJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BA99OQkf8fASdQggxqsaHMpRUroLp5LCxZSxzPBRDSg=;
        fh=rNIDzslZDBLp7cjLvG4vgybkPen3nlpEOX3qFGGab+U=;
        b=B0HQfs2oLjjIIuzzlOmTjeuw1RGgl2fVGVNzfgISX1CcQ0kXLeiQPHOWdZ2V8T8L2g
         vXcSttiYLxNP70JN8Eko+wLb4vANW38i+lLvGx36+YOJmX1ssNUXQOWVqGGrexNa6JNS
         b3UjQo0vfn974ncVH1udjh6RV13rcVy7ncr8JRhwtVgg68ECDR0VF2M8mAwrxW58ehQb
         zwhSwXi3bhiZM+wpsNh6taBSTylCzWEjBKy8EpKSZVvNZ60kvHrJQnxHECAUuNNLH9b/
         d3THgKwQNWmXUxjtDtqIaIICi0iuj8uudsSJfmq2qix6PFd7h9+BjbEgcrRQh6xNEvid
         h7Kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ETQMtZ14;
       spf=pass (google.com: domain of 3vjpfaqgkczkc35df3g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vjpFaQgKCZkC35DF3G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47d1935f992si238195e9.2.2025.12.19.03.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 03:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vjpfaqgkczkc35df3g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779d8fd4ecso9830735e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 03:45:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX1yt6sHV5snkTeXV4ZDq9h/3EALz3sFa5/wQOrNxm3dGNddEQ4BLIQ74LTdkQhAj1OtD502T4K+uc=@googlegroups.com
X-Received: from wmik22.prod.google.com ([2002:a7b:c416:0:b0:47b:e2d9:2e56])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:4746:b0:477:9fa0:7495 with SMTP id 5b1f17b1804b1-47d18be144fmr25540095e9.14.1766144702311;
 Fri, 19 Dec 2025 03:45:02 -0800 (PST)
Date: Fri, 19 Dec 2025 11:45:01 +0000
In-Reply-To: <20251218092439.GL3707891@noisy.programming.kicks-ass.net>
Mime-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
 <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
 <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
 <DF0JIYFQGFCP.9RDI8V58PFNH@google.com> <20251218092439.GL3707891@noisy.programming.kicks-ass.net>
X-Mailer: aerc 0.21.0
Message-ID: <DF261MXQUYYU.130N0WZE4DP4U@google.com>
Subject: Re: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>, Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, <kasan-dev@googlegroups.com>, 
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ETQMtZ14;       spf=pass
 (google.com: domain of 3vjpfaqgkczkc35df3g49hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vjpFaQgKCZkC35DF3G49HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

>> 
>> So in the meantime what's the cleanest fix? Going straight to the arch_*
>> calls from SEV seems pretty yucky in its own right.
>
> This is what I would do (and have done in the past):
>
>  14d3b376b6c3 ("x86/entry, cpumask: Provide non-instrumented variant of cpu_is_offline()")
>  f5c54f77b07b ("cpumask: Add a x86-specific cpumask_clear_cpu() helper")

OK, let's do it this way then.


>> > For the short term, we could avoid this by using arch___set_bit()
>
> arch_set_bit(), right?

I don't think so. Currently the GHCB accessors ar using __set_bit() i.e.
the non-atomic version. Am I missing something?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DF261MXQUYYU.130N0WZE4DP4U%40google.com.
