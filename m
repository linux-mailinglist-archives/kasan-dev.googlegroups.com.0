Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGXCR6UQMGQEVVTYQPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E13A7BDBB0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 14:24:59 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1dd8e6a7a86sf7343091fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 05:24:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696854298; cv=pass;
        d=google.com; s=arc-20160816;
        b=Inrn7ruFiE8eC5CbHUpQUuFr1AA15V9ZARpexJnm5XXhdFLd7BVIAPDg7pD7fEiyuj
         vJ0LRgLVJiOND5HLCyn9ydPnYLDJk/LxK0gAdg4gsZ9qskO1KaME1RyUZLwB1Bpf+BQV
         pYjd0rrwpn2F/VQf8CXRkSjJfDR6RyXhY0cvCfZVSMHp1iyGr9udwbqfMlkle8ka4IUN
         xTJXmSHOljVbbZuHExzAXN6WgLVJLCKvxr03GJajC4Qf28Qztl9+q94o4b6vnr0jGFgc
         MbCHnVXD8HeiugGEni2dAbdkcEu9pJLDB7lKODQmjzaYB2Oq9Aqbe0Zu+Ux+7SDeYasA
         c6WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rYhY80j793qtc7b5u++/UjgToRGgygGnwuevQmGC+k8=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=OLJz1/Q1ixBOs2m/E1r3QiUzZHGgjX/bMBVsGY00m4tOR9NDJSPVQYPIv5OGY7Nwcm
         Gre0/iDX/nDwAEckDuNddkUfhXbFX+jbLxYQXIbA7H9va/PWu2YtcQQ72rKX115HJuOP
         CmUiz3axSEOT0beWSuVDFwJtqrG94jkPhvcXIv378/fChyN1TOhYDW5M0UQ51NmJ0Dqp
         9ROy5dtfg/rvpjPUWcfV8Jdke9VvwAfy+jp7VcYerfu3reFKl47IJQToQWCGQoSHk4Xw
         JankVtRQjF9nC/MwXmxT0Ym96AaFMz2LyfXZl1PrJe7VBG1aCYqe6OvYUeK8GbZQTNvL
         UZyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JNj268cD;
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696854298; x=1697459098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rYhY80j793qtc7b5u++/UjgToRGgygGnwuevQmGC+k8=;
        b=CXFL5s+a4za3cp06MWFASy0q0+1+xjcV1DguIs4P13fb8xqb8FvKU9v9d4TSlnuzZT
         6OYrcH1MqhFVa1tdGKmSh8crxN2Iz52RwcVpPhXonAhKq4w8N5l0TehIDfpHV1XFP63G
         F2OSO6mAhoH822wDr3jXF3E1Fu/uE81K3r7nUFIu5B9sJ61EDv2Vx+0eVSUT4e0E1Hx5
         r1PCpplHAVVPREt584oEKXwWqqBZdZBOI8verw0KoIQ2Em2TE9J3/uRIKCRnR7NoNQTb
         Xa0ncNiYx0urRmXVBcQ/t8Nh7XlwzrtQvDWAyCiE19Ths5iwHC5gAzxEWbSZ39hn2sVN
         z/bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696854298; x=1697459098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rYhY80j793qtc7b5u++/UjgToRGgygGnwuevQmGC+k8=;
        b=Kz8ui2xRIxvNFK9XBid2CZf61y7miDc6qcu8W+iylcOuZnpJ3/1huyXq1N1lBvUgip
         oeMcgMW1KbHhnqMO60WDkDlWginuHw6fLf0aVerf9Xx2+J6H5BE7GH/I9gJHLcI5OM7t
         mYTWGOMuRxFyHH2audJzICkU+EovlU+UeHTXARR5xNJMKlaQE0+Gym9U8dWT5YzyaiPq
         ULl4a3poSBgT7CLVGXtlrAg/pIul0txThPFpzaZ1qbceUyUncjVp6D31mdw8XDD+3Dfc
         +4dJ/+sJTMCzIIVmkiGtUiTS7y+eIRUhowdgDrPGGP2A/H407UxUz5AcITr2ncmQbk/h
         f37w==
X-Gm-Message-State: AOJu0YzlXqTt0GFd7ylivLuSLlr0c3Ey19BQxk6aCvwbcPHEuw3IE7z/
	5YJBkL64CQsXgTUY4k/LJmQ=
X-Google-Smtp-Source: AGHT+IFm5qhWtegroKc1dnh7Z6jiIr+JQB1ciWQGIxMsB29DTTtxLqpWec1PL+h6btRZmQOdhwte4g==
X-Received: by 2002:a05:6870:71c5:b0:1b7:308e:6cd9 with SMTP id p5-20020a05687071c500b001b7308e6cd9mr20234019oag.5.1696854298110;
        Mon, 09 Oct 2023 05:24:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:209:b0:1dd:6b48:3e25 with SMTP id
 t9-20020a056871020900b001dd6b483e25ls597006oad.1.-pod-prod-01-us; Mon, 09 Oct
 2023 05:24:57 -0700 (PDT)
X-Received: by 2002:a05:6870:160f:b0:1da:ed0f:9c84 with SMTP id b15-20020a056870160f00b001daed0f9c84mr19483169oae.52.1696854297395;
        Mon, 09 Oct 2023 05:24:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696854297; cv=none;
        d=google.com; s=arc-20160816;
        b=xKdOrkNOSfGjIUiODUaF5nhI7IxgiF/OhmDOq6T6CVs9XoaCvXlbXzXJ5gUufUnoai
         CMWYNoCi4H/qbzHvPV6DSJLrXDtfrbTGFNbxXvDwIM5lQ8ADbF0cyLeBDtwIefh8kXZX
         /6alWf7/0wE+YMgj3KedY6zDGTLyXvlp0Xzfx0iG7TuHr/7semywo34BApbE/L4SgRlY
         tnWwT7eZR71fTtec+cCPBp4b3vKLxrS9bmbu3QdF+iy/jZWaXAShSqq15ilBqdVBj1Xq
         R2t9+6U8DDDPRqc/xCKvy4rj/hWE9cgCddL4Tak5qD6oa435lXgnVj8lqPfxT3F41bNk
         pSRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/XMSmBSmrIghDRAMwSWs7YuLmGLdnz0rmjgVzyIhrZM=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=vCnPX2IR8Qbc05W8num2RmR5UxBj4ZN1//nYBK0T/+2EldbXy5vbd2b2bEmtZ95uYL
         6+IgszO89aA/Gagy6KYMLGYh/mN/VfnZ/ylf7sip1xzTBxKiSGmGtoWsfhJUvv6alexd
         nw1vCQzAFLQLbHtRAKn/8+0wiSOmI02U8V+u19nyZB/jQl8EzVuqXL6W3K6nuck6YiKW
         uvPRh8ybLQ7r8U2aFGimlUcJvUQPffzs6WJeGzmocyqkyewCk/I6ZV0sUDuKMtOpD2TY
         uTagsk/1vG2fVJogWBgJAdoFeLvHBlmjBHrsEDhMgF+LZbOk/Gx3E2NCgO4TljZOEtH7
         N1Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JNj268cD;
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x2b.google.com (mail-oa1-x2b.google.com. [2001:4860:4864:20::2b])
        by gmr-mx.google.com with ESMTPS id ei9-20020a056830700900b006c65a8d6f61si953266otb.3.2023.10.09.05.24.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 05:24:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::2b as permitted sender) client-ip=2001:4860:4864:20::2b;
Received: by mail-oa1-x2b.google.com with SMTP id 586e51a60fabf-1dcf357deedso2932712fac.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 05:24:57 -0700 (PDT)
X-Received: by 2002:a05:6870:5252:b0:1e1:6cee:26b6 with SMTP id
 o18-20020a056870525200b001e16cee26b6mr19546563oai.8.1696854296959; Mon, 09
 Oct 2023 05:24:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <6e2367e7693aa107f05c649abe06180fff847bb4.1694625260.git.andreyknvl@google.com>
In-Reply-To: <6e2367e7693aa107f05c649abe06180fff847bb4.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 14:24:21 +0200
Message-ID: <CAG_fn=UZu3QpwTQYgXaYe8NVBsuqs8_Ado-+x4pJLaNE+Ph8Mw@mail.gmail.com>
Subject: Re: [PATCH v2 19/19] kasan: use stack_depot_put for tag-based modes
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JNj268cD;       spf=pass
 (google.com: domain of glider@google.com designates 2001:4860:4864:20::2b as
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

On Wed, Sep 13, 2023 at 7:18=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Make tag-based KASAN modes to evict stack traces from the stack depot
"Make tag-based KASAN modes evict stack traces from the stack depot"
(without "to")

> Internally, pass STACK_DEPOT_FLAG_GET to stack_depot_save_flags (via
> kasan_save_stack) to increment the refcount when saving a new entry
> to stack ring and call stack_depot_put when removing an entry from
> stack ring.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(but see the two other comments)

> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -7,6 +7,7 @@
>  #include <linux/atomic.h>
>
>  #include "kasan.h"
> +#include "../slab.h"

Why?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUZu3QpwTQYgXaYe8NVBsuqs8_Ado-%2Bx4pJLaNE%2BPh8Mw%40mail.=
gmail.com.
