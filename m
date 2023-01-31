Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE5V4OPAMGQEYKBVPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58AEA68283D
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 10:08:37 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id i7-20020a056214020700b004ffce246a2bsf7923099qvt.3
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 01:08:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675156116; cv=pass;
        d=google.com; s=arc-20160816;
        b=eFXd4QrrGIsxwGdUOjtJGxozXg2++gB3DOrTKepqGmeYSv7ecZQuaK9meD3gaxxJyW
         YqU0jGiM56FzKnqvBkunsnwfu5KqmwTYTzUE0lmCLOg93X1nC9o7vboymzVCiEb2rM8F
         KayI6O0E0V8hRvZwN3Uc/x/aHTNYNb42NnFRl81VQNAUbIn+zJ2r2IQ8WuL8di/tT5Bu
         qVKWHWS4zqLCZ5lydtypWa9JD7xBiMenei3YfVQ+d78PR27abV2dS+V0gg2suu0eDAG7
         RY9Xk/muJ2cCmTW8gN9t3X9pYY2bDOB3PiHLe+ZTJnqHaFH6QaPQCbJcPPsZ4BEwP4/t
         z57A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KZWOq4LUZSvghXFsiqSbBpIBbpMdDCaCDTdIQhbbOpY=;
        b=sa9koWsdUgSbpfDiLyHToNPPaGBZ255xzZTEUy7qi7Jqc4Qbdjf5XQWpos/4wwM1Fc
         T2N31uBnSySUEsPdlx0qOzUWZKEUCM0E+rKWmxUtTZC2JD7Mm3LYHCbPjIDFuFIkCXvV
         i2Jtv1+bZvV/lFvtHuGh61ITkhF63Dh8xB8N3nntjNqom9BrxDSOMPTtINV+VnSee9VM
         QwRwCAxjqq4ny6A6crXSsuthJRoKtyTHuWoZmt36/ZVbRn/aCAu++5wOn5ZwhLXd533n
         ZWu1E9nhH9erilJOPrWCmmC0o1dT9pAUcjuE3fuUMc8WTK7D8h/Rb2442a7KyCO2LrZY
         USug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sGuXmQgy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KZWOq4LUZSvghXFsiqSbBpIBbpMdDCaCDTdIQhbbOpY=;
        b=bz3R2PzO2lpNjblwGjKCIZ4D8/m+LVp9JspA9UfsPhBfagnzVF0EDdkvYwYMOzkIcs
         NhHTmCdaseAXnsUR4bX4y/1wrEPsstLKaYW7LmGuMnMih9rJYZZMgAb/2j055CqquNwq
         hEyQmznp+KNo/Hzbb/KlJ79yS6nbYQ9nV8GLBTqRwpqB3NlzGdk2PwMcOp3joSGjnIfe
         5Ll3fh5q+SFYOHTDd+Uecj+zvM4euAXEc9vanUAQZBlebHjIxPP8pZUo4m3bBT6tXXw7
         oknAyWNbBnXn6bcu4lPJIZF9DlqPYA+YuVc8MUt5DhP5/x3OlQR8Eq4+l/SDNw92jXM8
         +zqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KZWOq4LUZSvghXFsiqSbBpIBbpMdDCaCDTdIQhbbOpY=;
        b=EKfiSorvKmlJOPY7Lmek3l26JZNO7WWGesKJJTToMPgUuHHIm/THCuSivzuJRMEXCn
         D6aduPHKgFBgbrfl8f5OKeHcrOxNit04U13M0TVl+dyYeU+MjC3YasIBPeCjui2JPcYj
         OgWJoHDRDBzjRXAHzk4x1vARkdEAQswFXyrB02ftoeUIu+oFEWw6g9se1+e8XpxSubTI
         0dnago17Zgna/wQR4ZjeFw5Ekun0YCB7l+BBptVxQxzu72iBWJSQPsd+7lk1FqX+Qb4w
         e2QXGJk+9N3IQUCNrm7Pf9CmMOz5BpGT2t5JunlHJvVBMzYjEb55ZguJNgoVyC0OHGgb
         uVVw==
X-Gm-Message-State: AFqh2koQKgNxrKzAy9zZ47YR5oCSMDHCSnUz+ryZ1R7BAwctcCJ9KXv9
	JeiW4eSB9KTO9Z5HdEGikSs=
X-Google-Smtp-Source: AMrXdXt4RHet1JCv+CIy+OJ8wf5DbsdTup9+A6SHhdTuYIR2BFQtj1DPgz2DPlUtnSAqOP1rIwadYA==
X-Received: by 2002:a05:622a:1cc3:b0:3b6:3087:ead with SMTP id bc3-20020a05622a1cc300b003b630870eadmr3222202qtb.287.1675156116081;
        Tue, 31 Jan 2023 01:08:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4813:b0:3b8:130d:4473 with SMTP id
 fb19-20020a05622a481300b003b8130d4473ls3964591qtb.10.-pod-prod-gmail; Tue, 31
 Jan 2023 01:08:35 -0800 (PST)
X-Received: by 2002:ac8:7293:0:b0:3ab:ac3b:966f with SMTP id v19-20020ac87293000000b003abac3b966fmr72869089qto.29.1675156115512;
        Tue, 31 Jan 2023 01:08:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675156115; cv=none;
        d=google.com; s=arc-20160816;
        b=OFrhZN5f9GQzCNSL/F8nA7LDiwfeQfnwr4xWU87UrGpptYoXU6TZRW0SChpNXeEsQB
         RlGt0vYppiO+fOq7HhxZmQSVgF3F2zxjJW7cFuWQ5IWEb57rvt0zenrwWVC1qEbQPsui
         whrtSAIOvLcLEw6hx6s9p4pZ+FOJJLuBXDG5RtJjDbBRgRJ98NpL8P7fYHWJEJD3tzCo
         qktKRFPmRi2d8+mpNa0QJWhfIdTo00ejdnSpmVS6zYYe2PjHtMkGdUVpOG8DBMwpXGc/
         Tr5Us/MnRLBdAG3nwWbZlDX+Il0JI60VJALE1i+3sxsfnIZCnSKzoGkMJ2z+WJon9WLz
         GEXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ahEni0vEoNstNN4puWfSl0I1TRpDbWT6saFFu8LT9dw=;
        b=vEtq4BvPGfirBbd3x0ycltkDXPSAvcqWhY7l35mSkwF8Dc7gB+GjCcxnZNiPO1uT1a
         R9t1tH71R9N0YoaacGM58EDndERn8kEw3/i5ZnlpxUWFoDoD/iNzN6D9lUuTZvYuLgLp
         lr9xZV/NHuZcekYNTDOTvTEbk5hQ53LzQA1PIYi4rEWPSiZzvVpLKrmnGLbHtAl7FEfp
         Y40Tww9jUn/mOoebHGqmvnGHPefI9iTsVTvYHkgz7qZf/4O6ms8H9zp+6Cspn5J/PkHD
         IFDRpxYnQfLmsU7mU0cksDzMpCpr5uQ5Hj1GL3X3PH2LvnMIUNQEqU7Mz171ocGHB23v
         BuZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sGuXmQgy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id ed1-20020a05620a490100b00705bf2df50bsi194802qkb.0.2023.01.31.01.08.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 01:08:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id e9so7530668vsj.3
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 01:08:35 -0800 (PST)
X-Received: by 2002:a67:c31e:0:b0:3ed:1e92:a87f with SMTP id
 r30-20020a67c31e000000b003ed1e92a87fmr2260239vsj.1.1675156115140; Tue, 31 Jan
 2023 01:08:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
In-Reply-To: <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 10:07:58 +0100
Message-ID: <CAG_fn=U_WraAkVi9sdTNuk9sjQ8gEHWafsjcYEMYq2G8KX4HTg@mail.gmail.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sGuXmQgy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2b as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> In commit 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in
> stack_slabs"), init_stack_slab was changed to only use preallocated
> memory for the next slab if the slab number limit is not reached.
> However, setting next_slab_inited was not moved together with updating
> stack_slabs.
>
> Set next_slab_inited only if the preallocated memory was used for the
> next slab.
>
> Fixes: 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in stack_slabs")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU_WraAkVi9sdTNuk9sjQ8gEHWafsjcYEMYq2G8KX4HTg%40mail.gmail.com.
