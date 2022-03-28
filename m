Return-Path: <kasan-dev+bncBC7OBJGL2MHBB26XQ2JAMGQE3SQJXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id EACD34E96CD
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 14:37:00 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id u29-20020a05622a199d00b002e06ae2f56csf10284898qtc.12
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 05:37:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648471020; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxqrRzMcNaI0RmQRZFLOWZoJX93/5bAnnRQzQetfysEsFtwAmYav60mPhi5fV99cly
         C5swtwxP7i4sefqdYduZwPY0O4gv/fIRzwwOy/eFMtQMAXWM0fHIi8ZXvRwoYsC1qSb8
         BqdVXZq3erqAFVH9+2Z0n0TEw1HhkOX9Xn4m0kJP5nBjwcB8w0UMxATc3jNfGVR15xLP
         LzuITV5NNPLbd1eRkOMMQam48RhxMluYR6tkYjq3892DJaJ70VHRb2CjxVqWrOTmgh1F
         Q5gukw6V9XAj4NK9MyNASCCEQ4CfMbQkhY1AMG4nDq2eW5ArJlN+ZV4O+lfQfgyf6Vsj
         5ktg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rrr844eGWRQSYRcTvVsJqjdNZfznAsjNACNAXSIZ+Fk=;
        b=d0AxX8mCmEMKJVVVkP1BbpQIiPWe566hgBrxs2m5pect5YmZ5bdKcZJL+/gnxYHKwb
         QtwPoVHCB42vYxnJo3tLBZgvbF6rb4mJLSz2wAkUg9NzfEgksbWFxRjDixWNCVD8sVQC
         gb4MjGrEwxDjIX+qmoooI5VYTw11mqKfhjWDMTJ5ruKWotZlCFJ0SP/DjcdknUZD9jJv
         bJjbmWAJAIGKCRlEo/NNwDLywGPBC+7O/Y0qJK8/heaJntS3rq/qOIFXg77IWvcSqZSG
         fpijDoxWdzm6YkdNlNLJv+Omxcc6osZhbGulKhMxqZd/CDSeHL9+9VxIThnr7tojXyMD
         eKZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E9+QQkZM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rrr844eGWRQSYRcTvVsJqjdNZfznAsjNACNAXSIZ+Fk=;
        b=aXgCvoInBStGsC4tFLOiwcmBuzGAsN5d5PKKi21QSCnwSwSs/zYBSjCK1c31DHIGzi
         abh3zM+u2oW+EQYvHVEDTfR34993pf8rs4XF+ol/JcVGnEgsvXhmsJLRt4nL7f5HoKgj
         Syjlw+Ngdbzo1B3pWb4juGK2zzsWSDZSPxgBDJ+xvi5jU+rAqQGf8LchS/iwgxv1z7Mw
         0qwzo7+PfmitOlXURztnxcwh5Km4E89smLe1M2NI5apYPRHrEIYyutfYS0AQf5IpQzKo
         Rj0tciLoNV5Q9uTtaM6GNQ6ZzNbQ/cQTMmuZPqa1UfaRer5C6bZkrjqIAF+1JUbtfwyb
         j5Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rrr844eGWRQSYRcTvVsJqjdNZfznAsjNACNAXSIZ+Fk=;
        b=RtEe8kG86Mzr0mH6h02FOch3DEhotrtEKca9XmogvDzhKh+vQQOMLlK0caET0OV2dc
         5DjZjTzBPy72Yt3Exi05cnoO9HRrS4TPQ7DOKQEVK/DcskX2hTpRdIs3ZSJE9vsC1G4e
         bnoCxAfMfJvFuOpMym/GBb04jGQ6PjRoX3vBHXDoDbNGVAWPyJzu3vjw7CPA/NnQ/xK4
         SV7XxWIV13/9V6bdPy2nNHCGZiiKBdRhUTHGKqbilLZnDCujH0kJ+6XBjQkKqYPYOzoR
         ErfRBLV2PQd35P9br85h6I2SXEzl/qjgk1jceXJkMN2WpepKsFe+TTpurzMwZDRE/kux
         eL8w==
X-Gm-Message-State: AOAM531v+DoepOILna0yWzwT4fhV/INequ7gtSLEawMz7h0mpVoOtwQc
	OFX1yU387/F2jQYhOd1b6Uw=
X-Google-Smtp-Source: ABdhPJwOWuFsZBkh53NzWEklr4L9Yaq8iI0+zHsojb/54hWYSpkdCOqKFaOOj3H4OiwSD3rOMt4Xdg==
X-Received: by 2002:a05:6214:b6d:b0:440:d18b:b7c3 with SMTP id ey13-20020a0562140b6d00b00440d18bb7c3mr20818049qvb.103.1648471019758;
        Mon, 28 Mar 2022 05:36:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:27e8:b0:441:216a:2707 with SMTP id
 jt8-20020a05621427e800b00441216a2707ls5965843qvb.0.gmail; Mon, 28 Mar 2022
 05:36:59 -0700 (PDT)
X-Received: by 2002:a05:6214:5010:b0:440:ec82:3d1 with SMTP id jo16-20020a056214501000b00440ec8203d1mr21063860qvb.3.1648471019281;
        Mon, 28 Mar 2022 05:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648471019; cv=none;
        d=google.com; s=arc-20160816;
        b=VFZVWYS4Ic3L+BmwaRVEFI5P+InbiFeDxLaVS2WYrWGcLWegTAt5BYM5c3yb7RlfcX
         xjLZBp9LbSQ0bOuEKThWc0+XniCwkCOSuK/SzedHxMrfi0ICOawCxJ89uOB367D0VWCY
         Kw7zX2l+51ux9F8N9BemaGmA/owG/n3Rx0AMm0YODNJ4G6LNo0fMIKPHW2sINX4bHUMf
         X0u3BSlRGQ8HJJVcFIR2ofPJNaez4n8myb/FjqECKdmaBWwflYSbba72rsKT9QeDs1Lu
         N5iHNDBCB1EzaKN9HfC784hrQ5kIJ1K50YRY3ZxzOyAb4C7EdkFZF1u5sOonILD+gZQx
         lN9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uMEZK2jSyKIkvvjIbH4GT3Fdajafv9KYrdFViGd4yCs=;
        b=auQGfmLXLtN6HA+yADnKbLCVTF1kMMhhPaOeFAuwyMha/94+iJmQJdujP54W4caOeE
         jYNTBhM8SMlAK1QTCNxbZGLOA47vXJJdK1YhUOqhQ6G8kiMzvlwjFDBmzyyLF1WM0Hak
         oESjVHPQlTWnsB3sbZ8Xo95BnZvGZSBpPvusyCRQYTVEIR7w0wIbVV7cYDtRh6jYWEcZ
         D+ZTOyPdrobVU6fG2K5IhN2T2uqABhJ3Tf/94yXU7HzvjNMOGk8EaKm5I24IhtCiJ/y2
         i8uuIhMQx583jG95cycyPGeKDunNtqRV9I7A9k03qL+38fBQPHxfLNgB+606GzSbNDC3
         2FCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E9+QQkZM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id t8-20020a37ea08000000b0067dda0219c9si694179qkj.7.2022.03.28.05.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 05:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-2e68c95e0f9so147293407b3.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 05:36:59 -0700 (PDT)
X-Received: by 2002:a81:59c4:0:b0:2e5:c7c3:5d29 with SMTP id
 n187-20020a8159c4000000b002e5c7c35d29mr25403537ywb.512.1648471018879; Mon, 28
 Mar 2022 05:36:58 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com>
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Mar 2022 14:36:22 +0200
Message-ID: <CANpmjNP_bWMzSkW=Q8Lc7yRWw8as_FoBpD-zwcweAiSBVn-Fsw@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E9+QQkZM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1129 as
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

On Wed, 23 Mar 2022 at 16:33, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> kasan, arm64, scs, stacktrace: collect stack traces from Shadow Call Stack
>
> Currently, KASAN always uses the normal stack trace collection routines,
> which rely on the unwinder, when saving alloc and free stack traces.
>
> Instead of invoking the unwinder, collect the stack trace by copying
> frames from the Shadow Call Stack whenever it is enabled. This reduces
> boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.
>
> Stack staces are collected from the Shadow Call Stack via a new
> stack_trace_save_shadow() interface.
>
> Note that the frame of the interrupted function is not included into
> the stack trace, as it is not yet saved on the SCS when an interrupt
> happens.
>
> ---
>
> To deal with this last thing, we could save the interrupted frame address
> in another per-CPU variable. I'll look into implementing this for v3.
>
> I decided to postpone the changes to stack depot that avoid copying
> frames twice until a planned upcoming update for stack depot.

That's fair.

> Changes v1->v2:
> - Provide a kernel-wide stack_trace_save_shadow() interface for collecting
>   stack traces from shadow stack.
> - Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
> - Get SCS pointer from x18, as per-task value is meant to save the SCS
>   value on CPU switches.
> - Collect stack frames from SDEI and IRQ contexts.

Do any of these new changes introduce new (noticeable) overhead (in
particular patch 2)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_bWMzSkW%3DQ8Lc7yRWw8as_FoBpD-zwcweAiSBVn-Fsw%40mail.gmail.com.
