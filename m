Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWP3R2UQMGQENLNKNUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F1AB7BD590
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 10:46:19 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-d8997e79faesf4709223276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 01:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696841178; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jg9rhqjHBi/2S0uNirQvOoXD9RCOAhDm2Ju7QdZDDWPJ+227AJm7/DD/mB72nhpPUo
         mM2uWBRmPnROSHAlGe1nI5lfTtr4MipQ2b2VBRasXLiLTWevR5GT2JPT4AWpL8aFLX7H
         Nug/GBQmUO4njnMg4PWAlcSigvWsYAi+wegZJTqqqavWcezSJB/OYa8h9ycggcVBF4hg
         SAGSh1ofOxdpKn2Ca/Hd6usNdO43OvONOWl+8PePbsHGGZnF9oYTV6en+KQNLDnLYTqe
         O3Pc6PWhyAyDXuXVKFznG0RQhuThg467nMn8Nh9hPioLJe/28ScoUrFfqOa9ipk5pl+/
         DD5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xrmno2CFjMGp/AMmx98rCVAQsGtDdVx/39o/SsdSzVs=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=w2v3cx5EgXl5qTnkW+xfIHRaMr62tZ/Vw4/5j/9azgyOxljIK2z26BTL37RqPAT4jE
         4L6hv+Kfi0B0cx8s05c1i23eIApsFER1rgE3kYrN049Zv1N2/IyRqp2U5HeKq+ewOE3+
         4QsGMAmfKj60KJ/B8mGYgUUj1TXEB4y05dsEHNqCT2XwXK3m7zUhFVsy1VH2C1Wz+Rzw
         hHBCLkT0Y9pq55UxCk1jLfnOLUsu7RT7fRsDWABOpAlGRlL2qEAITmyzAG5vYgBEbJRZ
         0JLR2+mSxBIkDrCnCf4mc4TUoVkK+TVJzrNFUG2XB1G1+YtB7PQSA/rP5p/T4lFtM6xU
         x7vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3ESKB5px;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696841178; x=1697445978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Xrmno2CFjMGp/AMmx98rCVAQsGtDdVx/39o/SsdSzVs=;
        b=p2hEmzSBoj4ACm8SNSyxB8v4gGk60mS6oXqrCC2yEinjsWjSMizc7hiOMXQvZWi8qJ
         nrdeBoswC5QfkmVFDs1WIRFTLM+M454AC6XMh0+v5zkOPnf520fVISts10UlsTOj1Zxk
         MbUnGv2pxDTscEwTnVOhlyQBa+Ql/3fUXeIgJgGNCp3gBYvzTfjSSKqa6yAYDXz7JIyE
         kEZAWE3gRMDdG9Ni4+fzxFaBc9BEJRprc4heN2s/fVHslO9QUypSFqBXBUz3l8g/XesC
         pui81U4mJSsWpLnWjwsE2CyK16rD73xPm2FuknsDf4lUKFiw/F5yMymKpe02Z4OFRgeL
         ezwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696841178; x=1697445978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xrmno2CFjMGp/AMmx98rCVAQsGtDdVx/39o/SsdSzVs=;
        b=vx9xczgCYkA8GgcsRxpv32KQGvqwOF7BpMD3KCLzPdKESpuT63auF0Tkn0/VNumteU
         YV8a1vVyZ8S4NLNpV/84XlWGsP+vUcWUWbhqFdo8Xfm9BdNvjbAr98wkDLm8RJ0z5BK4
         1Knl0f3QUmzFrYDMBYbevvO4AXU1t2aGSx7R6FWr3Wgkd6Vb06K/F4F9hly//R9qbtqi
         ZZOeqUJmzPyPuIJGdK0zauNU5v6DnoMaljIjzcw4godM59NJBYUWEJWarBwpY78CpBQr
         FzKjZ1e2+B4DbN5GLXZxbbcg88s+6iF7XHfU+M8ofurrRiEuDz+NR17ho04b5ya6hHSm
         hkYg==
X-Gm-Message-State: AOJu0Ywx9YPWhZc507qpeLAVhShns0n+9NfCInnqdGDtX6sRsCz24Bri
	8i2HDL4MGkAC3m7vUygyUU0=
X-Google-Smtp-Source: AGHT+IG2byS1rAQAhinT4Xabq/7YjqitAGzAkHwAfH/55Rzj5KtErCdgGg49yy3vF/Wb8HNKCg2aPA==
X-Received: by 2002:a25:abeb:0:b0:d0f:213:bd3b with SMTP id v98-20020a25abeb000000b00d0f0213bd3bmr7048770ybi.2.1696841177956;
        Mon, 09 Oct 2023 01:46:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1083:b0:d84:9389:f22e with SMTP id
 v3-20020a056902108300b00d849389f22els1366482ybu.1.-pod-prod-00-us; Mon, 09
 Oct 2023 01:46:17 -0700 (PDT)
X-Received: by 2002:a0d:dd4a:0:b0:59f:7832:c6bc with SMTP id g71-20020a0ddd4a000000b0059f7832c6bcmr7830223ywe.2.1696841177073;
        Mon, 09 Oct 2023 01:46:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696841177; cv=none;
        d=google.com; s=arc-20160816;
        b=J509P2r101AUawwmvJgETWK9s+Y0e/q3kG9Q7HqiHUS7QD+5ELiprBslDumbfZXIOV
         dXTGHJer6+Hl1E8PNuy1NImk4edIkjkdRja6L7bBjLAvFjh9hEhBmOCx3aES0Lq3wR8L
         fTj6sNxvVoPe6vmMaNU/E7ZztWOSvq8EDyV/jl9hoBTeL40PQetL8ISxqScHJtwfhoG2
         0SkUn3v7QTkicWTt5UJ0NadsJvxdk7VaTbyEcXH33fhtbqnRzm/c/O9R4L0S8zsOnbQu
         IH5C3KSo7KsJWKJTBIqk6y4mTmkQIcqFpsn7mzibRkHKViGsBrem5727etIzxtdoNWiN
         cxxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z2RpbvMTdKoZ2zJiAZ7Z5I3rvjdlk66rFfj4n9j6rj0=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=0XpUCsuaPFRBZd6PLOA7Auh1thLvenmBtR1wTc5yKFoHLzfr4K70uwvNLzyHsVS8vF
         jKhEZ7iXYRE8cWq5tEOkULvsXfByLBP2BPjT6noLgn3k5s4InI871P6DOjJKK0ieEb4h
         EI39H6ZbSCLNJLfFZtvwZac62Cw33OMEOpXtJXmCZ0G8khL/EQMSh+TnxSFyYZEGaxn+
         a7LfRGNLqoEnasXPGGMFUCyPH1krcVVY4Lzw7+Z9LIv+tL1coFV0WOMFq6np4NfZosAm
         ReG9cNh/1yl0TI4VwOQEqYTG1igjVhpPHQJwDMxF7Vqar+0p4fDBFRJRPSgxmKz0/Khm
         jTZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3ESKB5px;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id ey18-20020a05690c301200b0059b516795cbsi782034ywb.2.2023.10.09.01.46.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 01:46:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id 71dfb90a1353d-49d55b90a5aso2947773e0c.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 01:46:17 -0700 (PDT)
X-Received: by 2002:a1f:6d44:0:b0:494:63f7:4e7f with SMTP id
 i65-20020a1f6d44000000b0049463f74e7fmr6815444vkc.2.1696841176576; Mon, 09 Oct
 2023 01:46:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <6f621966c6f52241b5aaa7220c348be90c075371.1696605143.git.andreyknvl@google.com>
In-Reply-To: <6f621966c6f52241b5aaa7220c348be90c075371.1696605143.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 10:45:40 +0200
Message-ID: <CANpmjNOHPRHOOPNwx04S_CE5OoQMAmfxHjxqeqy=YUpU+sY7yA@mail.gmail.com>
Subject: Re: [PATCH 3/5] kasan: use unchecked __memset internally
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3ESKB5px;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> KASAN code is supposed to use the unchecked __memset implementation when
> accessing its metadata.
>
> Change uses of memset to __memset in mm/kasan/.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Do we need a "Fixes" tag?

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/report.c | 4 ++--
>  mm/kasan/shadow.c | 2 +-
>  2 files changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ca4b6ff080a6..12557ffee90b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -538,7 +538,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>
>         start_report(&flags, true);
>
> -       memset(&info, 0, sizeof(info));
> +       __memset(&info, 0, sizeof(info));
>         info.type = type;
>         info.access_addr = ptr;
>         info.access_size = 0;
> @@ -576,7 +576,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
>
>         start_report(&irq_flags, true);
>
> -       memset(&info, 0, sizeof(info));
> +       __memset(&info, 0, sizeof(info));
>         info.type = KASAN_REPORT_ACCESS;
>         info.access_addr = addr;
>         info.access_size = size;
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index dd772f9d0f08..d687f09a7ae3 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -324,7 +324,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>         if (!page)
>                 return -ENOMEM;
>
> -       memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +       __memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
>         pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
>
>         spin_lock(&init_mm.page_table_lock);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHPRHOOPNwx04S_CE5OoQMAmfxHjxqeqy%3DYUpU%2BsY7yA%40mail.gmail.com.
