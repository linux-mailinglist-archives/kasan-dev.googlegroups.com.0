Return-Path: <kasan-dev+bncBCT4XGV33UIBBKGU7CIQMGQECW2AHXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id DE99A4E7AB1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 21:46:33 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id o15-20020ac8698f000000b002e1db0c88d0sf6922128qtq.17
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 13:46:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648241193; cv=pass;
        d=google.com; s=arc-20160816;
        b=s9YpBIZHF6b+EvD6yZ+B2i3TnDK4fjO6prekYpH6JJmF3p2+iWKG+yVY1emJep6IhR
         /66oz24fIYHfZGohaA/OfZGMROuRSwMlWFV1+2eoKSLyZwKPS75YAnEhpc6CYBWNEzub
         Nu1ENYkwhiVWYH+BCntmaGbrDlNWsqzEfEbCumjQlSNgGqsfZlx+jRgoJVBA/wn+i88a
         HmibBgj8739MWjGvIKVzpFp7/3pTU3Puru/4CmsvtEamhqW/rw2ifpjX/V16ZGX0UPdE
         WcaxpTN+tGPM66ald2BUgnErGyKf5+YZUJp5jD4BHCLs0ezDJF3LJzWnb8I8Mm58ZgzY
         YZ2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=d2JLljTBDCVgeelM7fJUfZQIYXzeJCxhP77FH+lSOX4=;
        b=EWw1sXYw+KhIXL74luhVtCx8PaJDMmzNAxoXKneVkLRsccLxYd+Z16oOk+ReWL4bZM
         aMi/LO1oquxfR6MAdDURfX3TlCTajSIooN+D+BMYwqJfD52/QePYzEUroZnC9tKb3fdL
         VR2wzeAuXgOqiF+TdqtzUbe0JMc4bNx9PFjwwdROIAC0Clt1aSyAdlJJ5z9vAfCVKueY
         tVi2QOXXT8d8HFrvodu5Q2sv4DN1ifldUCPZ1JYrxw3CDsbUX290Bb3JALesxvteQv17
         MOmtpzU1N0SPtcgI32seG0Gkx49n2dot59KJHeLnLhC7ykh9NN343RQDfyhECSmZJaYH
         uSVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RQR4hHIL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2JLljTBDCVgeelM7fJUfZQIYXzeJCxhP77FH+lSOX4=;
        b=BtL/Zgchx8WtTeZouFQlQgvhf9F5+oEUHcAAW9FH51FoeCc9iHNEMi2XfMhrmdpX1a
         ++Csit5JWjfKWLWaGlKpf0vgFx2031JWzsYn/bS0dgXo7N6FMY4bFZGhl5nLdExa2MUb
         WDrOh2U4da07iPCznjywRNEJCWInF/J4LAuKWWr0MIqSZPDDpVsPCq5YPfziacCi3G+J
         UeL309fubPTgJ5CD2E2379FWdJ3bq/CNLYa51X0xO6aTqTFrLpt0OaIxuhxdOD/IkxYT
         2F1dQfbnN5N4PdjItkHsoyQJdIpb7IfBmvTGBdYuN3T2G6EPcZb4CtkrJwgktfDytHzr
         Q7SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2JLljTBDCVgeelM7fJUfZQIYXzeJCxhP77FH+lSOX4=;
        b=X8JcdeOwsjL1dhRHzQ9MUHcrI5im720AYM/pbLNdfLAqBJ8gnRTAqC6yp6UYmhNNdM
         6JDCPSQAxVHOmlZXQO2z4XDhO3HRCgzeAmOm02K0c2CUo4nGbizceJ0T6XvzMg7hR19Q
         2FdmfcFOuN0hZscI3X0H1TlW2HMlZkfTswnD1/OBWhfmBXrFj1snskR2UbRt0pSnQDIQ
         FLvEoK3D1JPiW0qobyg7qfWAi8DWhvo0sIC/4L/+7vXiIMYNe+99Nx+L99LtyqzKC8GJ
         1hcm7W4yGcjBGicq6i2H7PL0SjPXolNK1WS8UdGqldmQOlMViCGJujfskwHYOesDQl6B
         23XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lu9niA0P6H4bj8+tf7KSxAoOIov2DuxFe92Su+xS4G2mbhyGQ
	0hm7jpjqYpDcvyF3MoyvCHg=
X-Google-Smtp-Source: ABdhPJwj7WhCyqd/IJRJO4flf4bMV4+sNRE+wE9PH+0YhPqjkuGsIH0GC6+Thc3plv2pyWE+4bn3UQ==
X-Received: by 2002:ac8:5753:0:b0:2e1:ed23:1991 with SMTP id 19-20020ac85753000000b002e1ed231991mr11543319qtx.615.1648241192820;
        Fri, 25 Mar 2022 13:46:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9f16:0:b0:67d:372b:8957 with SMTP id i22-20020a379f16000000b0067d372b8957ls3535606qke.1.gmail;
 Fri, 25 Mar 2022 13:46:32 -0700 (PDT)
X-Received: by 2002:a37:e307:0:b0:67d:374c:aba1 with SMTP id y7-20020a37e307000000b0067d374caba1mr8006126qki.752.1648241192319;
        Fri, 25 Mar 2022 13:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648241192; cv=none;
        d=google.com; s=arc-20160816;
        b=NjNruGtFSTuQhbc5pB24ItxBKUiCYTqpGcllEGkl6xF8k/YEEVmWOlXRg1tyzNuzRq
         VjyuFPKvubPNYRrYPJT3iPgYCtSDF1mK2OWO9Ii8AIAZ5o+mUoaNRFL9nV33Y173iPlx
         l+7JtocZ283Pytc0qK1ia4n1GA7cJ6UsG8Bnmk9Y7HwZwsIFX3uLlxjtsAwH8MrEYBGa
         n9HrjOuT8y0YfpGsCFnHeyDC68mrOl+iLmNjrzK+mO9j9v/Jw5oJlW+/91dQLZIjYkc0
         LkH93K4lBaFofAWvSAaHTXqrRPJJNT1n6ncLmaDaoYtlbUjvWStjYsnQdF07hqf4OKTc
         NWmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SRRKHN6wWSWXlqOEXfCFzLcVklTCgEF59R+vZciu3sI=;
        b=GYKPFgHXu3Ttf5l14tie7OJhyfOiDN+gBmFsDYcN6BWI7Gk/3bgPqHUHNJe/+/XUI7
         08tbOhwU5QHK73cXPon8do0t4VNu+Uyzm0f89P+Kny01csyoIgPzHGIpBJwJ2TDz9WYj
         9ftjY4rz7BmMCyzyEzD2cCIrZWKoXWyLRkZtytv2jp9FSJwLut3xT37pvgH7RwkknpSR
         vBALe4qzO5PMa55deYahqeY5zk2PZdjpKRN3uWmXR/oNT132rqTe2Ye0N90NWSzHN1OP
         ufdKke6+HPppJjbeqEtN62HgDrQ/PoEY0YfrYUT5c3YvKcCXYEnt4qJKlJrnsDWPXHPX
         1rrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=RQR4hHIL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e3-20020ac84143000000b002e1cd44f786si326336qtm.3.2022.03.25.13.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Mar 2022 13:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DA70A61D49;
	Fri, 25 Mar 2022 20:46:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0282C004DD;
	Fri, 25 Mar 2022 20:46:30 +0000 (UTC)
Date: Fri, 25 Mar 2022 13:46:29 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, Mark Rutland <mark.rutland@arm.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Sami Tolvanen
 <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii
 Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>
Subject: Re: [PATCH v2 1/4] stacktrace: add interface based on shadow call
 stack
Message-Id: <20220325134629.99699c921bb8c8db413e8e35@linux-foundation.org>
In-Reply-To: <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
References: <cover.1648049113.git.andreyknvl@google.com>
	<21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=RQR4hHIL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 23 Mar 2022 16:32:52 +0100 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new interface stack_trace_save_shadow() for collecting stack traces
> by copying frames from the Shadow Call Stack.
> 
> Collecting stack traces this way is significantly faster: boot time
> of a defconfig build with KASAN enabled gets descreased by ~30%.
> 
> The few patches following this one add an implementation of
> stack_trace_save_shadow() for arm64.
> 
> The implementation of the added interface is not meant to use
> stack_trace_consume_fn to avoid making a function call for each
> collected frame to further improve performance.
> 
> ...
>
> @@ -108,4 +111,16 @@ static inline int stack_trace_save_tsk_reliable(struct task_struct *tsk,
>  }
>  #endif
>  
> +#if defined(CONFIG_STACKTRACE) && defined(CONFIG_HAVE_SHADOW_STACKTRACE)
> +int stack_trace_save_shadow(unsigned long *store, unsigned int size,
> +			    unsigned int skipnr);
> +#else
> +static inline int stack_trace_save_shadow(unsigned long *store,
> +					  unsigned int size,
> +					  unsigned int skipnr)
> +{
> +	return -ENOSYS;
> +}
> +#endif

checkpatch sayeth "WARNING: ENOSYS means 'invalid syscall nr' and
nothing else".

checkpatch also picked up a typo in a changelog.  Useful thing to run,
is checkpatch.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220325134629.99699c921bb8c8db413e8e35%40linux-foundation.org.
