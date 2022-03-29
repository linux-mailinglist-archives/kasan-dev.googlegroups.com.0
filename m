Return-Path: <kasan-dev+bncBDW2JDUY5AORBOFDRWJAMGQEMV23SGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F5D4EB36D
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 20:36:42 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id b16-20020a253410000000b00633b9e71eecsf13904837yba.14
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 11:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648579001; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxYOaC1D63hTsQVuFXKwVqSI+cbqEC30TxxPEAhiWjAlT9h98fCuRs4hDPovVDKJf3
         dr7NRGDJy09sMibn4VpDC/AKgq/RTsCuBxLlTlRfzwKm1vP3qYRnghTOrQOTaV2aKdXq
         84VS/QuXtA4SWM02Gi2gCAKTFNlsfDtzBG7VwcrOtQEMD9eROqD9Q9wNYkZ0IAIGSOuv
         5GLkaCgBsRnNlcSLamywnecOI/m17huCI9aFW5Ifb5crnjJGoDiKBqo4ovYtOMIUp6Nk
         9lhzPK0KhT5G9azoZKe95KxDfU1Af/9JvpzNFDqKTbCQAPcATcg2whzy+jzOiMS5SFV4
         eGrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=wj9CbOMBi0gCr/A/SitjeH/vMTDRPTh4DUDfltzLlTM=;
        b=y8XxJYeMfsE/cLoamjM22HVe4LrSeNJMnU4Ry8tciCYw+lBqFyYd0cd5Yer7gBUBUU
         hLGFXW1LWnUVtxSbYqmQuvpE1ursuAwwsl3sh1anhQfKA606FUQoriW4jQs+E2lRcAfw
         4pjTZslcow6/hVshHKMrYz1lpH4kkbbrLbqch5uQcQq2fMBahgj5VVO+GTrshcK+oi7Q
         bXYCZTJLSuR/5Up3a+qiDDvvQeoW9P8/Gk6GtbA8P7ARio4BGVWRlQYMUFw+Pf/iMn5I
         RPg46JTjiXCmmOAJqyVSKYT+f/9y1luVVqHrMTBe7qr4vSbsyZ7PV5R0aRsq/g/tiytn
         95CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pS1aGCcG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wj9CbOMBi0gCr/A/SitjeH/vMTDRPTh4DUDfltzLlTM=;
        b=DeUZK5YzxsV4ucFpija7QJb3n8b9cWfax/NVMfoRmUHNYUna1DcZxkMybA4HpXQyo+
         S0PILcKsYD7+0CUyO/N4ORTYHjuUF1T3tQWaKvXozy08IBmWquOkIbRHnzhDACh/1KXA
         J2siXJEX3OBrXE/YVFj4NnLh0O1Fv4BHvrBEHb04Ofqo5yehsVtywU/zgzOPqQKxl0eT
         pVGjwVUpq/IhMm2FCk/7/0DRWRKUXbhArLAKfXkUvjDMEdvdm187hwc5j+9e7w4XBpko
         9XbASq1Hi1Uy70dmPkU7gJgwOVmlmjM/i6LRO2cUoBMG8Ix0Y8P0kljAYYFFBEpvdWhf
         cThQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wj9CbOMBi0gCr/A/SitjeH/vMTDRPTh4DUDfltzLlTM=;
        b=A5vCqCDscq9pD8G7dLqk/YzaVvp0cABf+/ZxlWtTcsm+NdpBIuUU0puJ4moaS7CuRl
         loV8srJVXvkU2miFSdSNH1PSUu2PPMEXUeV3K9vkck7CBhB5SNNnXiTu4spEBKBuwiDW
         M48KzdKoCKhcOEaacjE/FPBX/Oi6xpKVnFJTpe3DJH5I+w38JxjSvwTuW9PrxRuJaqfe
         j+GK3PJd258kV4afCwQXdHWdV1O+GjWJPSOr/DX5REULQXtDuTYAjdtWpLCfVKINdeKw
         jWAwS2obIsYeRYumvRna+kazJ5qUhXG5WPFE/3LkUa9drIB7UvfiER/nPi/BvGibJVHh
         kNtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wj9CbOMBi0gCr/A/SitjeH/vMTDRPTh4DUDfltzLlTM=;
        b=EXIONIx3FbNBjmuN7KFIpH4ROjJnHG3OrHOP/qyt/TPI6B56lGA+MqJQCNYJyl0A/S
         p9o/vrIaJq8eklu890trivTcSdB1rX73tXdmQTDL6z8zgWAYOMSNs/Ff+mJYIpmKj4P3
         qoYoa74Fzr4Y7kA/gNVqZJq2XlD/fPUOrPhNNtnbJr8k9H15+ZN7IX5otxPwI6WpUYlB
         al7wostRsF3+kun3w5C/oTYxz6Qk7wFgfQrBPY8/nkT3NRhboKVImxAUpwLjFdmnp2kc
         pDlM/RTe7rYW+4r6NfD1AnivWxizQgxr3k4Ry9A+nU/XtWQ0fIjwh99D9no+WwU5oHjH
         3zeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lXIebGX4VAaBuafOLsXR+siZafNTDVFZrTtt13RmAuLzyHkMT
	LeaZIIBxmdXs5mg+3QFkLEw=
X-Google-Smtp-Source: ABdhPJx0pLHmtQCfyDsU71SFaJXYsxzxP8wY4/5XhGvYN6F9s86q0rDAL8z9zeaLxbwREQ+ueVYGWg==
X-Received: by 2002:a5b:98a:0:b0:633:c93e:3e17 with SMTP id c10-20020a5b098a000000b00633c93e3e17mr30449543ybq.512.1648579001027;
        Tue, 29 Mar 2022 11:36:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:609:0:b0:634:23a5:acfe with SMTP id d9-20020a5b0609000000b0063423a5acfels11058732ybq.5.gmail;
 Tue, 29 Mar 2022 11:36:40 -0700 (PDT)
X-Received: by 2002:a25:2449:0:b0:633:c9aa:b9de with SMTP id k70-20020a252449000000b00633c9aab9demr29193967ybk.255.1648579000576;
        Tue, 29 Mar 2022 11:36:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648579000; cv=none;
        d=google.com; s=arc-20160816;
        b=qjbqHeWo05YmKW9GIugQfsUeo5nzFOuZ05QxjD33tNFuLEjBgEFN3c6TCXXWsdZnMt
         q6Lcfdvf1WJqbdePdVi/c3QUMhzcrbRINv4HLMlzphGZ4lumUlIecDAt+74J6s11W+9K
         9/ZzHpJzYDgG+MSNXMgTrYnXUFlmHfZwILt0clbYA3I7Oi19H0di7scAsIj2yrfGApLI
         3rR+qugOMnrTAmVfRxb6JFHNI4Qom87u4SadBsx00N0QnaV+Y2lNMZxqLxiwK8rkz7pH
         ROyOhF6f4SfzCqtcJAuRxoxO5QDSppgk8GoJGnCq3TUvoa+9KoAH6H+d9Ghfc5Z+mW5H
         LEkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5BCw6nbHB1HhY9C/SvU0SfIcx4iHjYcssyIjUbMoR1g=;
        b=HmoGtsFnAYoJrinthYXKwmgHtkwZF4/ibKT1faGxJ74ABtdJbj9Kj0EHaX0DoB/J4z
         2h//YSyAG1X/PVVMfXWHprK4hKGBmTNKwGExQ0HqEhwGAyniAWnpkOe5BXwUu7kuSI1g
         x4g8EIDKCtHNuNn4VxuBIBTsrvDYqM9g0G8h5PZK9kUHga6sO3UI+KPnpb6FslG1w2em
         RZ8Q6s5KbPFUfF0WTmcPjwIbjM2jA2z9moaUOiD1lCY8Ly+dd8oroLopxrfW16bhSVui
         VH4eyjWQDmXfsCf/OGkNpkm8jJb+os3vC2YDETVk1XouT3oMj8uQV2jK1koSKvA6gbGH
         1LQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pS1aGCcG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id l200-20020a8125d1000000b002e5ffe8bb59si1153091ywl.1.2022.03.29.11.36.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Mar 2022 11:36:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id j15so12965969ila.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 11:36:40 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a43:b0:2c9:8e7c:ed98 with SMTP id
 u3-20020a056e021a4300b002c98e7ced98mr9055749ilv.235.1648579000098; Tue, 29
 Mar 2022 11:36:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <CANpmjNP_bWMzSkW=Q8Lc7yRWw8as_FoBpD-zwcweAiSBVn-Fsw@mail.gmail.com>
In-Reply-To: <CANpmjNP_bWMzSkW=Q8Lc7yRWw8as_FoBpD-zwcweAiSBVn-Fsw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 29 Mar 2022 20:36:29 +0200
Message-ID: <CA+fCnZeiR4v72P1fbF1AP=RqViCnkdtES0NtcmN6-R-_9NS4kQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pS1aGCcG;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 28, 2022 at 2:36 PM Marco Elver <elver@google.com> wrote:
>
> > Changes v1->v2:
> > - Provide a kernel-wide stack_trace_save_shadow() interface for collecting
> >   stack traces from shadow stack.
> > - Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
> > - Get SCS pointer from x18, as per-task value is meant to save the SCS
> >   value on CPU switches.
> > - Collect stack frames from SDEI and IRQ contexts.
>
> Do any of these new changes introduce new (noticeable) overhead (in
> particular patch 2)?

I'll measure the overheads and include the results into v3. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeiR4v72P1fbF1AP%3DRqViCnkdtES0NtcmN6-R-_9NS4kQ%40mail.gmail.com.
