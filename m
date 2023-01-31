Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ634OPAMGQEYX7QTGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E84C682A91
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:31:05 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id bh27-20020a056830381b00b00686b0589045sf6914069otb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:31:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675161064; cv=pass;
        d=google.com; s=arc-20160816;
        b=g98ZUJoLG1jDPh8ZVPKqVW08am1FYoAA6LhSzkHyjD0skBEAFoyY4HElLfzfZfA4y8
         goY1/IheuiY9fllhk0CY+P8B2rdLv2RpOLpz/+M/gYRi+UMXrfVwQVW/PpQCCblUHhy2
         FjvLiyHTt0XjBoRxkT5z/n81aYLpdSf0JjfOPOZkHL6aDKYKvSty9yowmsf6Qo6MjsBv
         VLRtZ5SMWPIDbic8nQ/8pqQOkUsz/IhMPmznO+NrgE9kheqnbaoqKcBLH/dfc/LVwMVC
         01o7+T9d08fbch4Q6u1SHMbGLlD1cJNU1DrKJZHnaNvNfnjQmiulKtNOKKesHL5+9UM7
         yNDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j8vIjbydx4JV9polifMr6B/mDP9GgnbqYBWOI4lpzho=;
        b=PoKGUQNX5RcH9JPIlVPlcYp6XyRhmjIYqUkQNiJiRT3IznvFO7fsgcVQddja3l/sMW
         wK5fmMLD65gSO2FAnsOJP5S3gRXlEgWSJ8rC7hcxL4JVfpDxu4XHRpgFYtpVjGpqjqis
         +1uliL2gU46ehZj6mcyCFFuKXHwlioVnF8IDeXlCUM8yR5lslL4s2UniJ7Qqh05FtwzB
         XUD9d5xtMj9D6iNEr/YfQ9TfxF1cbzzJVeMQF8A32giMkhWgF89WbLrE6Rt4BENETzuG
         sfboskFbeyXkE310QWT6ZsGN7IPUV75Ui7hFsvZNLVeabvCCu/y1DBqVBEkyeDRwXDhK
         bCTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N4W0VQzf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j8vIjbydx4JV9polifMr6B/mDP9GgnbqYBWOI4lpzho=;
        b=oVkk2EYEk4/aAFTlgxoJMudEvxyzWQ/z0OAIgbLMS5iU4pzrgLaX2Qi7FbY6gtxny0
         AIyUnbWLmYgLtvnW9KemyEMtIGmt6gXqBTinJY+5ekahbzh9sxIABiGcFWgZPe09/yu6
         d5Vbm0nRTKasntstejgB3u9OvMdZR+XB/++4xPFiXIRVUgP9c7WW5ztOFwU5ukSEMvJK
         FNc6dAb3Z4bCkoRrSq4XTq4Gram24NL1eUzhmbjluMfxcU27PJ9bOF3b45huOySapIMm
         U7Iiqj5CQQ88NUu7DrTSIqh6FxDa4hWVRMSQsTZEts8l1Ds037mps0BqXgZcTA6hNgcg
         HubQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=j8vIjbydx4JV9polifMr6B/mDP9GgnbqYBWOI4lpzho=;
        b=jw1F3FmdTPHObwZC+cfa6WH525PM00NnGzbFu0Cfp22Gnpghp80dDCdOgd8hAdRxAu
         01iPW+fTPppaLaPUrqaefh3Dr/o7RMMO9n6ivcSPe6tDaX76U4GCeq/sY8Kns1aH9yp0
         ukvMoVUw1MJBCCuEnHDtUdJ25LY/fcpnfN3QoPXQ5g4crCm/VQwaVK0IAyl6Xu5Kwg31
         5Wg221hts/O5CgAcmCWitah3A0w6SjMLjaw2YW8Rb3VL0j8qYk+h6EszFhcdUMKOOMjp
         h1PPZ+Kw0+uwK2TA3PIpMajX8cFqj6AggWQ6GrgFe08PVE/zSBuVU5cZPKc4rk30IRRY
         SL5A==
X-Gm-Message-State: AO0yUKW49zIhN5GCTdYchGZh/987Wt0BXsC+hu97O0J7NUVGcc4JquBc
	sbQoD4S3aw1hWxtzoUac6qc=
X-Google-Smtp-Source: AK7set+jmrPHz7arpV2mlFy0mVyzhR40M9L6yPG0JQ+aSSTXMuzm2p+WWgu4ApdUiyDmtwMR91boug==
X-Received: by 2002:a05:6871:826:b0:163:1faf:a36 with SMTP id q38-20020a056871082600b001631faf0a36mr1856951oap.147.1675161063818;
        Tue, 31 Jan 2023 02:31:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d217:0:b0:4f2:b94:2a71 with SMTP id c23-20020a4ad217000000b004f20b942a71ls197162oos.1.-pod-prod-gmail;
 Tue, 31 Jan 2023 02:31:03 -0800 (PST)
X-Received: by 2002:a4a:2a19:0:b0:4f2:88ea:54dc with SMTP id k25-20020a4a2a19000000b004f288ea54dcmr5657816oof.7.1675161063315;
        Tue, 31 Jan 2023 02:31:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675161063; cv=none;
        d=google.com; s=arc-20160816;
        b=BTh8H6Y8HBmTEAlP4p3EcEc3J+3iX7+oOWYz8z5fAsUztGrPIMBKlM5c0DD83pKchd
         BBCqaeIvgvop/gC5QY2Kkm7jRkxazZZdu1LXw9ZQ8cffTVfS4bv5YyUqUiiDGl+JBoK3
         VOoO5Nm4f8M+NN4XQGnMCk5DA88WdGWacS5wvhZwA0baOeXZRvaxg2XVsdqvmMW8C8zI
         EQcbmWFsoxAFEFeIveXdnBq01vdpfMKOxaHISvD36Hgj2vZsHciNzG/zJ5tnRQD8N5xn
         d7w0qS3pPatGONlGXmSUW/0Y1bkvVFcnuiZNavmbxhyT3jficBZ7cJQhIOlK2yPh/ciu
         If3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=biRptAnS/23/d1sfZT7OvK0Nsb2kEXEG2iefSRQIeYE=;
        b=iy6hXehz/S6M4rDv6XOTVMkTPesKN2C90w1fFLrPrF+v438REIfb4VheDWR2rOh5jr
         So/kC2KL2xzVvB5DYKR8+CgvwbtH/w66o4nSoR7xswCcgdN8ERCxS+A9S6sDdnI99zhs
         LorX1hBRb8IpHWbEkxbMBqSAzgkz3sd7uRJKQDSf8A2IHrKnEmSZWQDwmQ2aApwLvKRV
         +tvOzMpOja6HYGl/RcvIW/7Q3hS4PBNjbmrPgeOahBSDthRq5vzkVmFkWJcfDoILqUYK
         Y+V7F6dRDdBFFXNUZggkljBs6cTqraOX70BFp9cIKtmG+F+2CEz6ImkD4+EAFDKFIHKA
         8d+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N4W0VQzf;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2a.google.com (mail-vk1-xa2a.google.com. [2607:f8b0:4864:20::a2a])
        by gmr-mx.google.com with ESMTPS id w22-20020a4aca16000000b005176d876205si646819ooq.0.2023.01.31.02.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:31:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) client-ip=2607:f8b0:4864:20::a2a;
Received: by mail-vk1-xa2a.google.com with SMTP id bs10so7143437vkb.3
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:31:03 -0800 (PST)
X-Received: by 2002:a1f:ac0a:0:b0:3d5:911f:daed with SMTP id
 v10-20020a1fac0a000000b003d5911fdaedmr7024011vke.39.1675161062850; Tue, 31
 Jan 2023 02:31:02 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <be09b64fb196ffe0c19ce7afc4130efba5425df9.1675111415.git.andreyknvl@google.com>
In-Reply-To: <be09b64fb196ffe0c19ce7afc4130efba5425df9.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:30:26 +0100
Message-ID: <CAG_fn=WnxbcbjfKvRGen7fkKyx_9_S+nL9p+8xfeU8N0L93f7w@mail.gmail.com>
Subject: Re: [PATCH 06/18] lib/stackdepot: annotate init and early init functions
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=N4W0VQzf;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2a as
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

On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add comments to stack_depot_early_init and stack_depot_init to explain
> certain parts of their implementation.
>
> Also add a pr_info message to stack_depot_early_init similar to the one
> in stack_depot_init.
>
> Also move the scale variable in stack_depot_init to the scope where it
> is being used.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
...
>
> +/* Allocates a hash table via kvmalloc. Can be used after boot. */
Nit: kvcalloc? (Doesn't really matter much)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWnxbcbjfKvRGen7fkKyx_9_S%2BnL9p%2B8xfeU8N0L93f7w%40mail.gmail.com.
