Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF6L6DBAMGQEHGSKITY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5E1AE8A00
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 18:36:43 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-60f0ceb968fsf70853eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 09:36:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750869399; cv=pass;
        d=google.com; s=arc-20240605;
        b=NNxWmQJRvsQErs1qTvyGNRJ7QsggmkZcjVeF0yMKkCHqMaOVh/uA3DKnU/p5Kq87qq
         fxmRl+fuhWJed3K/eaHZWp9/BuXTzhvnJQglMEk+7KFS2Qn4g3pcUpm28I7bslgzKMrZ
         cgebnHKEkD6Dd6rsCmnNElyC5y9HnivIMM8TXF6T5dWrHJAgaR7ovQUjMKULz+YPfjIK
         b4O7w/vB5OXW72s1HOMwRczZ6b+CyE1fKI2Nl4RaXRuz4EPYlagcQo8jTJpsjd4olWX5
         PWhsc7MP22ZTRpZkNG4XHwfxNFIq3cWugsr/D4ZpgBJQ0zrJgZdW+DCH72sC1axSWZLB
         B4Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fiFBRjQghMwLzpLysJqpx8rY9M+K9AaXNAA5lIOR0LU=;
        fh=jAea6kqvz29yXBdDxEB2EOY75FgFn2v0bAk/aWNe76U=;
        b=GbpD2idtixhOYrjJhEu0F384qP63J/yV37+MWp3+19hO11jX8rxyhcm+sAJJGNjjLx
         NIeUJiHOz6OUH6WgAkvG9iRy80nPSVR4ZKxOoKI0d54+OOCL35ADaLlQ2RmsItK6blpW
         qumllk9CzI53morh+ikNUUlSiq7mci1c9x7eOn2NzPTaCJPepv5tcTrilEpBo9KasIqS
         tal13IHMmW45kmlfIjqiQFnXRHZI9C1ATAz4ve/+J9eVtM6BiLPrrU8VT7Q9ZxHsT2e+
         HDJF7MUdeS+MRYUa6SyaKOOkqpPBsgI+MkFw2xQhvlSQrvw3+ajc7Jnpo4HutH9XFBlo
         qfbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qVkPsT9U;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750869399; x=1751474199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fiFBRjQghMwLzpLysJqpx8rY9M+K9AaXNAA5lIOR0LU=;
        b=fru4jh9mEsL0u9HHO9xav0iG5zXAOSGz5CQYBdOYmSZqOet56GEFQo6qO3EmhRapqN
         ULl0Bx0QttvPAKLM1BFSkWPzgzg3hPqGcVj30Jxj9Pe/VxXU7S3NxlzJktJp7SBSs+JJ
         XnWcIFVtvgpg67WuHSEopvHGopVeJP59JRVZPIYwxyNWJdYvub8wIG8mXBswIHjLYyGk
         NMXcgDEwvjnAeFszXqZ75w15HThxh3rkRRVfaZENU9pg2AEKEIkkNUIw92xKW9ECWdq+
         00i/SmKkfHOqIxfwQ0NxYTfNshfk8VPF2iN4eHnoVE4g/0G0SHT/vtYj28yrAv1Zy3FP
         +gkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750869399; x=1751474199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fiFBRjQghMwLzpLysJqpx8rY9M+K9AaXNAA5lIOR0LU=;
        b=ghsvKUnmeHg5bb1B4lZiJUzH58R1e4xHmvM8QoiKQVAXy9J1PaKdU6OslfkgvQSjVt
         RrIsoeqQyNEHCg82dsNonFAv6GI2bpFdLbPV6moIoAnjQqYh7xi9Jxi5Tn9JNnzsCMXI
         rOoV1yPlCSASaHUuvtMuhclQHi7ktlpZQp+xxAfIMjhbN3UxNwgOiSM80XdCxibErcuo
         1NRzeqi3FXAaStWh3f+40dU/jusADSHDbMBsciu7bmHQ5LWe/ziOEBTUs7//Hj4JbPs/
         o5UL/Wy381oRGI21UMWhxVPwuBkko0VifWAdcR11SNq/tjtPotiR+DoHsWogvIabeRfU
         MxZA==
X-Forwarded-Encrypted: i=2; AJvYcCUInlsC075i6y+Cf3O88R6UlpcLU5A4BXfzShgz+s50T7rkOH4cZtpCauCcIKxwDqyvfePiLA==@lfdr.de
X-Gm-Message-State: AOJu0YwMcGUbilGDo6/XulFBbw6p90JtCiICuLgtgMgWoiIfF6lRpnJj
	IvpIEKP0YZmTMq71oTkNbv6pabax9OBeRS0C4L+mABkEYOEgxDWFct0E
X-Google-Smtp-Source: AGHT+IFrfxJKlOLeRMkFGv7vi4jVvkAQQCji8k/pCYfR3HWlG/QdQj5vmEm38ZxBMytZqIl20zXAVA==
X-Received: by 2002:a4a:db75:0:b0:611:3e2:22b1 with SMTP id 006d021491bc7-6119d85f2fdmr1724024eaf.5.1750869399638;
        Wed, 25 Jun 2025 09:36:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcspTTnpZ76JbmgE3dItt1eMcxaW+m3/k3ja59A2gkm8w==
Received: by 2002:a05:6820:2912:b0:611:5c0b:8788 with SMTP id
 006d021491bc7-611ab18cd2als26315eaf.1.-pod-prod-05-us; Wed, 25 Jun 2025
 09:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUj/bZ1qOblUAQER6pdGVS8jbQlqoCQh59IAwYFDMULYKEEyE9LhBjRtKG7T7xyXHWj0DqesoDZ/g0=@googlegroups.com
X-Received: by 2002:a05:6808:198f:b0:40a:56ed:a49e with SMTP id 5614622812f47-40b0573dfa2mr3144090b6e.10.1750869398771;
        Wed, 25 Jun 2025 09:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750869398; cv=none;
        d=google.com; s=arc-20240605;
        b=HrZhppkGMn15yVte5qSUPSXC5lhMQrf5kEcLdBGEMLyFLSkfqImrjNrO42ZHuyETp6
         D1PTknnH4yq1Crii+FZRk/TEllT5Q2j6JvZp2CSSlTI8NMGrDiyTv5Y5uRHItyieqMrg
         Kdqez/epOKJB5u9lOUvUrgWppByEPfC3e40xY9KZsTAwAyrOEncySf1b5VmwkDm32gT7
         qRh3StEPHFFoFO0TW8T6eUBvDeF+FeF3JtGpzx5kgcb3LcDl/vFw/e+IDbT90qFYGJZo
         YXs0QKo868kCWBFiT+1E8pSMD1iHByrJM1XVAVF0dlplhAxx2llpNYlvA189RVbqmwV+
         ObTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Qu2toIg5Y0E5CCzKk1BSuXsD4Z10VADvrjtzkS7+XE=;
        fh=29bKCq/sqVLUdmLKQ7npE8LDZcyfe1XUQ07YBjQMcZ4=;
        b=TF64G9i3dPYJ4d1SSRsnCZ4g0Kv2bxY23IoHsIONgyiPEMOMi3QX+FW/ELMs4Y8Lyz
         tRcvnlTSeqiXTvSL10MkEXRV+IDIIeCv4xt4X8lAu8XaQBbUQh4HFrAHQTEZ8mlrzbsr
         BaNM3GppkhEb5RJGFYuACOnLuhvov+BNYPKbwVQEbSJALnS/643riYJ/qJed9tOH5rge
         pxrGkWJOAeX/14DN4QCDuu19PrBanjnuIqSRNM4DQWNN9Zxs42eP1ChZ37cq89p8zehk
         3/PNvgpNNLkbDvP3xYFwxTO7KSIxwmBcuG0o3FxskshfdyujeefJKZezcqG1g73Hi2O6
         jkEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qVkPsT9U;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40ac6b57d0dsi629727b6e.0.2025.06.25.09.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 09:36:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6fadb9a0325so1127656d6.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 09:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLsjArSr3f+YE8NXGUMfBccv3vuUdjRiozYTSHTxXqm0jEhsLE6W2ayRSHTfXDa3PSEDuZE0LHSN8=@googlegroups.com
X-Gm-Gg: ASbGncscmTAGaPpH4vv4JhnNqBgkv123cmujdI4AGYmerJY7djaPn0SFRbBy74HqHyg
	eDbNRvzBtFBHya/Sq2SBZLo711Va5nVK7pQv/LE4XaxN6oea9pqg4PreIRbF+tClH5kVW4fyF24
	/bepcjkOgZneY15GcR46J0pvkd6GHGBJAoHwxhDXgFOlzv3m3wRfOpfE1sIU5GAFnLrnNuUagRY
	g==
X-Received: by 2002:a05:6214:e84:b0:6fa:b954:2c32 with SMTP id
 6a1803df08f44-6fd5efba51dmr59869306d6.35.1750869397725; Wed, 25 Jun 2025
 09:36:37 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-3-glider@google.com>
 <CANpmjNNCf+ep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ@mail.gmail.com>
In-Reply-To: <CANpmjNNCf+ep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jun 2025 18:36:00 +0200
X-Gm-Features: Ac12FXyGrTNxbXgGGfhFeRYZAXPZadlkZ6ZWurZ6L_D0Ky6s5cgzx6IHfa3uFrc
Message-ID: <CAG_fn=VwC3hx3TqWNwR7G_SKYXnVHTjX3OKHvABD3=31L8y3bA@mail.gmail.com>
Subject: Re: [PATCH 2/7] kcov: factor out struct kcov_state
To: Marco Elver <elver@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qVkPsT9U;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> >         if (data->saved_kcov) {
> > -               kcov_start(t, data->saved_kcov, data->saved_size,
> > -                          data->saved_area, data->saved_mode,
> > -                          data->saved_sequence);
> > -               data->saved_mode = 0;
> > -               data->saved_size = 0;
> > -               data->saved_area = NULL;
> > -               data->saved_sequence = 0;
> > +               kcov_start(t, data->saved_kcov, &data->saved_state);
> > +               data->saved_state = (struct kcov_state){ 0 };
>
> Unsure how the compiler optimizes this (does it create a temporary and
> then assigns it?). Maybe just memset is clearer.

Missed this one - I am not convinced a memset is clearer, but recent
patches mention that '{ }' is preferred over '{ 0 }'.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVwC3hx3TqWNwR7G_SKYXnVHTjX3OKHvABD3%3D31L8y3bA%40mail.gmail.com.
