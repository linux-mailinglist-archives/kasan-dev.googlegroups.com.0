Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD74RKQQMGQEW2N4TWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id E32F36CBC49
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 12:14:40 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-5417f156cb9sf115113867b3.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 03:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679998479; cv=pass;
        d=google.com; s=arc-20160816;
        b=YSB5i8Why7tqkTbMm5F96GiUTSQMf5t1jJAn4ja4iSA3rgjMaxlMBTCYWCV8uRfmOs
         RkIv6cuuEpTCEJHlxNYxHbp69KXZ3wHQEP0+nju2L96wEUl/UjMqSV2vVjg4ffO3AmDN
         GqW1dq1MUMMKGUDMt8IMoFIjipTGmuyCjlNAKeBL8uWwVVm7s/WI8aWTZlBnzUO/ylV8
         cbGc1mmVmej4YCjhYInR8l11inpmXWZKPZ0L4iD1Ss7ljjSkvLlajwcckOtigYC3ggku
         RAobQZG7YCp1MpKEzLtK8McRPTaqWANFqX6WUmfUHLQphX/iAGjbj4QzvA8o46j0TYFj
         gZtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RljYIvEJEdsYpkdVHOuSHHcY+5Ho1/Wg/0lmMQg0aus=;
        b=R7+wdxdMQ4uxz39YD1Vlj9rMRUaEGeFICQf31+4O8U77qk/sIF0VZ6E0Lnilrh5F9u
         IqRftGHbN7j2EvOq11ppB7E309bgVGkNuwA2MYkmwvVUB1O9//oEdx0bnd9eUzVVQOjK
         Lgxo/xGX6Sjb/4VKyQOziuS1tp+FBA4HRMctJVZXyF7mNEh6PcPy5vDNohR3bzoxV2S5
         xygWDG9DkDyMPn8Z9LuzvB8h5iKNWCutPN++eAgznnVLiv4jeRbq/kHsHRxuEqhdKsYO
         HmSxKfJqNg4QGIPPU55YiUKTz54kjSqAtkoRwXaY+0TUTAcjGtmtC7gDxFDHMrILmTn3
         iX9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jFhXi0OY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679998479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RljYIvEJEdsYpkdVHOuSHHcY+5Ho1/Wg/0lmMQg0aus=;
        b=gZGVDv1dWzuDFRDLFDOCKGVsO7v/ZHRtG4CFAjL8aZFQ466bwiKqPeLF2muktsdTpJ
         F4d07oJQxg1UkL1kFd6iouzj1rUXJkDwTKDWxzXADlPhNhtGGS2P9BdW8b01fAJKs+e4
         KsRFfy5dxqzjKyTftKuNhtvr9uk5Yjcv106Inf2XTbpLb+U6WYf6uishSiE+/i+0S7k/
         t1gkyS2yO6+lDBKs/BXjXAEnsDSjLrug4c9ZoJvVuKWnAZG0E8JQQr/64TzPBtdVGwAO
         F0kFCS+3g4+QI9PKHendndBkfKzRSuNMoKd1b+TkvtG4NIGHXsN/uiKp+O/bylUJyYUd
         2yoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679998479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=RljYIvEJEdsYpkdVHOuSHHcY+5Ho1/Wg/0lmMQg0aus=;
        b=bhXs97GGjtnoaVcQ+XFOjwXWjZqH+E+g5HESDD/vFKkygrkqdqILY/Z5DRAsGUYjkf
         xuqyD+qBk/lrhNwhTCLOxjeATdhPXGxUoM2u0HSKqa6DcHsQ9rnmpT2WDSZjCcNmtcs1
         9qFiY40QLehiJ4UdYio9bAcCbS9ARaJeAHdbb4RndTOMrDpkgLOemgHdkquAHdwMrclR
         nhNBAMec77xlbX2vFN9CUnRgAAbN4xxe5DYSNjpyDTDNYEGBxdpL9Xnh/YUvFrEOuoij
         fHn5SQkY16/pmSLHsdz/jaytxGVk5irJsb92H1jPPNdIak9OcbcNwTrxiWPXAcTNaVkv
         zw8A==
X-Gm-Message-State: AAQBX9ecAZenrO1uoiPAU8GA3HQ3kHh/GkUpKOfOC+f4QUh5DZU/NCO1
	vgPTIWQH716Dk7G4HobFmTM=
X-Google-Smtp-Source: AKy350bZVHngEryw1zKo4MfJPYt6/rtWC9roHbzYi0dwbW4jkjq+wg+T8R/1U3B4qhlQLgpDZulAZA==
X-Received: by 2002:a81:de0c:0:b0:52e:d380:ab14 with SMTP id k12-20020a81de0c000000b0052ed380ab14mr6446505ywj.3.1679998479573;
        Tue, 28 Mar 2023 03:14:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:180b:b0:b68:9d7b:e159 with SMTP id
 cf11-20020a056902180b00b00b689d7be159ls7461111ybb.4.-pod-prod-gmail; Tue, 28
 Mar 2023 03:14:39 -0700 (PDT)
X-Received: by 2002:a25:46c2:0:b0:b62:bb72:d952 with SMTP id t185-20020a2546c2000000b00b62bb72d952mr9684930yba.7.1679998478934;
        Tue, 28 Mar 2023 03:14:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679998478; cv=none;
        d=google.com; s=arc-20160816;
        b=Fr5KrdGurXwYoWDNLMCguG4GHuUrGYmAuGsZr25jnwmlk69/UvUEnuvrvRXbzbWMnV
         rcuI/KDW+mQi9yIgHfefyfYnum8uDzXPqotjMqghSDGflzqNXDfFdBRgoF+hQO4ELZA8
         yJqQNgsnhyJ+mjMggzvcprd5bC/NW1q3BKHFhQWpcTK+S56T1O0iZGjacV4Unihdz2og
         bF8j4uoBmTuSDFrepM8fTjbnfElH66UdzHn0HoCctYOY4Efy+6tWJUdBGt7thRQlleEr
         oPJJBsowE65jPtlh9H284DvPZO3Etg1sBuyaiz7okCdaMR3BOgTP0ZgINq9PMU9J5m2X
         Mpag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wxx7pqmkD/seHpGsWDBmNccJaAtu0PA/48RM8nZtDsM=;
        b=dDAQcl3egwwKvLCfigis/g2Dzo2CPpjra3CElSc8Oz2OofZFs6zU/aPkzWDZUvVoYG
         DWmXZvINFRh6rasaIG5fIV2tg+cF0+SWfFvQTn8RUVUMTVXZsyG9fcn39PdoNB6kzKsv
         BP4Lj3D48VNXvzutEv2bbjO8jO5jpMybST8iGDjhABaNlLalNLAq74BVJYpd4exXdE/R
         9vCjjbTh5vbxf6K2GvLecegpvaCt6ciKA21xAdsFu3ugSvm2xrnwulA7fYsBHrd3E/OA
         ubBElAVlIKBABSgbUrJiI3aAD4A8eCTYqqxcRlFn9WEIwT+U5xNZ/N/ITT16UULkrhyF
         aN1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jFhXi0OY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id bw25-20020a05690c079900b005343a841489si1898832ywb.3.2023.03.28.03.14.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 03:14:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id i7so14359662ybt.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 03:14:38 -0700 (PDT)
X-Received: by 2002:a25:aaae:0:b0:b50:de89:68da with SMTP id
 t43-20020a25aaae000000b00b50de8968damr14945884ybi.32.1679998478582; Tue, 28
 Mar 2023 03:14:38 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-3-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-3-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 12:14:02 +0200
Message-ID: <CANpmjNMVOwgc6dBnrUbGimi1oAJacwYBzRfpaZ8nqQz-ApDMXg@mail.gmail.com>
Subject: Re: [PATCH 2/6] mm: kfence: check kfence pool size at building time
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jFhXi0OY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Tue, 28 Mar 2023 at 11:58, 'Muchun Song' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Check kfence pool size at building time to expose problem ASAP.
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
>  mm/kfence/core.c | 7 +++----
>  1 file changed, 3 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index de62a84d4830..6781af1dfa66 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -841,10 +841,9 @@ static int kfence_init_late(void)
>                 return -ENOMEM;
>         __kfence_pool = page_to_virt(pages);
>  #else
> -       if (nr_pages > MAX_ORDER_NR_PAGES) {
> -               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
> -               return -EINVAL;
> -       }
> +       BUILD_BUG_ON_MSG(get_order(KFENCE_POOL_SIZE) > MAX_ORDER,
> +                        "CONFIG_KFENCE_NUM_OBJECTS is too large for buddy allocator");
> +

It's perfectly valid to want to use KFENCE with a very large pool that
is initialized on boot, and simply sacrifice the ability to initialize
late.

Nack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMVOwgc6dBnrUbGimi1oAJacwYBzRfpaZ8nqQz-ApDMXg%40mail.gmail.com.
