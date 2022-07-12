Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4FW2LAMGQEEOWRPLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EF58571C27
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:17:56 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id j23-20020a17090a061700b001e89529d397sf5054407pjj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:17:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657635475; cv=pass;
        d=google.com; s=arc-20160816;
        b=YOpZp5g9AHB40Njirr1JlIU1CiW1T9pkVtb4HadwFhYbvwsoEFK4jLROLpPoDVa3Pe
         j9w/kV9wzDnHfclzyGsOPqmp633sujJrPwbaiHeGv0qs9sup0fknL+Pv7x0O2bS3q6Cp
         cw6Vbx8dloug3f8BepzviJec9xaDBRIhPZZVHMCIxneJ7q6oS1R59jXby7FjMJYH4aZS
         KnQd4KocNdp6gLd1jN7FPZeP1CwxALlHVkJ09FQ3g9HiQTWN9qKcuYYtT+MyXDHe8C6n
         v5UmTMoPkRuoZcH4DzcQ8vkNNKDDzyeSj3XWNqLYP6YI4ctgP6k0dK+mS2YEb8ErImnM
         mS4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1tAW9rnZtDKH55Xk8LgwmCiNHKffVg2mL9dKuV9ZmJs=;
        b=p4B6vL9j8YJ2FAU2devuajnzNIe4DvR1qn5TlbLuUqVhNUzsJGPDoGGshY+IyrNZsQ
         xbXo3vPXSHuaWZ72E0z9wtPGyYAaJV8Ev0YeK8wPBmdNgv0XGESw9348ArSUonc6AT/q
         ZmYHo079Onm9zeedqifmwse8gcSzAQbDdxO2SYABB5fw0tqHHxqU1yAQpb/B7iTe8WS+
         FZpQ/ezdtHqz1j484CrYhVQwJcN1Q3ABsWI56TuValqAgNvSIostV+0qxIht2I+E9bJH
         0dwMmhLKkvXkgTBLR8AjMHmT4DB0Yxm3jhQdJC2t5UAdufXHPhs5dHWQrXba0rutpPhb
         ul+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s50HuPFg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1tAW9rnZtDKH55Xk8LgwmCiNHKffVg2mL9dKuV9ZmJs=;
        b=fG8WWQCC5Yv7ATuZUDX5WmvQIIqJaMC8218ZvJJBWa9aUymWL/ABt6PlJBCK8PjQNA
         TjLBKJMiT4hiTvMgV3zWifCoeoPEhfAFNk9E9y9Q/ftReGXvPEnjR5D811iLaCtOgp65
         uLMkNya1+C73S6rjthUPhr9t8SrOxfuiQBXuEwz7Vk3RO8bnKSWtZZ6U0kX11flfLms+
         +qnDRlJzM1T6ztso4UVskiomgPRP8iVojkhioXNfJsTIGeezpQf76aGIMC4wWwnCb1KV
         v4C8hwzzMEC0H8gtiPxr4mfe9jOWx8cEUVDxyB54n1qA741qav6OBO5mOOSdg0Z5rLcz
         GcCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1tAW9rnZtDKH55Xk8LgwmCiNHKffVg2mL9dKuV9ZmJs=;
        b=l1ORxvL2cTOM5fcZCmksy+qivdz0uRI11hFBzJftlz/RNoyEIfFiiR/eSsc9G2CmJb
         3s9g/g8Swd8jN9ufRUrA8OFVTlXmF0iz2lX4xUHPO0Trnj+lFjRcL/oB5eYfZ3ALmmK6
         0VyXkoI2lT+ua22A9/kZrQSp7Z4Gc3zjUIjn7T8th/U8fbpcbnbcux2qvwdxCOSR0ZiC
         hD1nmBGvZztewDQlGb3F+QTZ69bWrghdu0iXAZfD/58mWAUt0nb84u8HL/k3pA5hJw6c
         ZNCbPqZZeGZmoTNfxqjU00JBPUBnTFZ/zNm8SIDgZN2CszKWwJZ/fwSeSTeylG0TyMNH
         NMXA==
X-Gm-Message-State: AJIora/Ru2OpFhY4WTwRNwoA5sp8IYJW5JbqtP1DQRMG1Wtbt7XJ+aKA
	/UYYDoZFQYDE+rYZy0xWZbM=
X-Google-Smtp-Source: AGRyM1s6N1mOK0/aH9FZ2cfqDhT2OUM7ALr4LOg8jwsOvqAdZfen9ScZ9yCMT+PKHaG9CQI/2wadDQ==
X-Received: by 2002:a17:90b:4a88:b0:1ef:e6a1:f2e5 with SMTP id lp8-20020a17090b4a8800b001efe6a1f2e5mr4791020pjb.1.1657635475326;
        Tue, 12 Jul 2022 07:17:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7143:b0:1ef:8fc4:7559 with SMTP id
 g3-20020a17090a714300b001ef8fc47559ls1323880pjs.3.-pod-control-gmail; Tue, 12
 Jul 2022 07:17:54 -0700 (PDT)
X-Received: by 2002:a17:902:e945:b0:16a:1c41:f66 with SMTP id b5-20020a170902e94500b0016a1c410f66mr24007094pll.129.1657635474551;
        Tue, 12 Jul 2022 07:17:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657635474; cv=none;
        d=google.com; s=arc-20160816;
        b=Ft5zme9y1hxyyOF/2Km8ZZPjbvEnXVCbwgqo66wIr0kAxnPwZyBiP5rqcKzJG7JJ7F
         pNF0p9dj/Z7xkMznGgphmaSjkOqaygsiVHq1+xV9PJu2KqRbq+TtCa48WzX1ujX6ZzLq
         25Y6yQWGsb5JOHblz5IQKhnSlx5TbEIg5oaZmSJ3jLyl90YGjF79No9pKD0F7kkcTGcS
         y567nn8BRtMkdnHg7gqPpguFqT1L/kL3E/YtMk7qf5CP/rUnzmmRAS3IM3CmKBHy7Vqx
         2Vh9WDYPkbjuZGzL+MOMM79jUfv9nZ5jI1f9/L9a2i8LfbxF/fbXTRwWST0Q+t7eZsu2
         UOXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BBNAmGtBjsKiAgWVGNt1epS6tn9dFMCvgo2fNVioNes=;
        b=xACO3akyGUVmTHjM+Ev38IGvKwd0hsC+CwdQ1m6uErkkBMASIIlUQKWCZJ1l/nnKsQ
         V832tA66zYI1m5HWj/PA2UBtPCT3gptRcnV7iSwgNUyrEsx8rseyYob7fu9rTSiZ9mO0
         SFhfMtbdzN9cOkhv+FR3F/BT1NaxMcjK3W7ey6xW18od/zkUgiQ493kDuojUf4g2F963
         XexvzO49lMbdv9JlMq9Hnk07E3W2LxkRF6DuIvTBf0RNVrfK6HfC4CMbc5jgxGZJ4mFw
         cb3mcYw0Fzz6lZDkFtd3ugyz3VgU5LmaP0hk+Z1WeublhEZkdWXPW6nq/h37ab4NxqJE
         B8oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s50HuPFg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id ls4-20020a17090b350400b001efe7b9d808si253102pjb.0.2022.07.12.07.17.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:17:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-31c89111f23so82777107b3.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:17:54 -0700 (PDT)
X-Received: by 2002:a81:1492:0:b0:31c:a1ff:9ec with SMTP id
 140-20020a811492000000b0031ca1ff09ecmr24431681ywu.327.1657635473811; Tue, 12
 Jul 2022 07:17:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-9-glider@google.com>
In-Reply-To: <20220701142310.2188015-9-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:17:18 +0200
Message-ID: <CANpmjNOb_aY5BrxKY=WzuDb7Y708XS1hSR0pJ8PKQi7Z8MDNCA@mail.gmail.com>
Subject: Re: [PATCH v4 08/45] kmsan: mark noinstr as __no_sanitize_memory
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=s50HuPFg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> noinstr functions should never be instrumented, so make KMSAN skip them
> by applying the __no_sanitize_memory attribute.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> v2:
>  -- moved this patch earlier in the series per Mark Rutland's request
>
> Link: https://linux-review.googlesource.com/id/I3c9abe860b97b49bc0c8026918b17a50448dec0d
> ---
>  include/linux/compiler_types.h | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index d08dfcb0ac687..fb5777e5228e7 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -227,7 +227,8 @@ struct ftrace_likely_data {
>  /* Section for code which can't be instrumented at all */
>  #define noinstr                                                                \
>         noinline notrace __attribute((__section__(".noinstr.text")))    \
> -       __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage
> +       __no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> +       __no_sanitize_memory
>
>  #endif /* __KERNEL__ */
>
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOb_aY5BrxKY%3DWzuDb7Y708XS1hSR0pJ8PKQi7Z8MDNCA%40mail.gmail.com.
