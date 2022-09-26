Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3GFY6MQMGQEUUWTQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 17D885EAE45
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 19:35:42 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id w10-20020a056e021a6a00b002f5f24e56aesf5618821ilv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 10:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664213741; cv=pass;
        d=google.com; s=arc-20160816;
        b=KujtOqIWX59dTHeyoYvX8/MbK+HMwJ/KZXoGFa1iGCSwXPnyKbzKaiJeCN9IYdn4HE
         t5A/TGC8PTL33dZuw2CmRyzqCG+d59sxLjV6oBmO3kE8AC0bXarPrc1MHDpoBMSdXXvv
         ncK/1Yp9qa/x7lm9U8HdqI6zhaKR+xouA7NkBaYNuFVLu40iJfVMt8uktCk6h+H7oAmT
         4vLiccMBzFeWXUNFJj/ZUYAu6X0Pwx7HH2BZdBMg+w2EJ0l/KyMMdY3Wd3vIvjbYxiiC
         y15omVZp/De940VBzqvPUzVPhSzAYTtWaDLiFbNwM+k6AiwozXmYVEwS77/A6DMQ0V6C
         ZcyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WWh+UKGAItsB1t8abcKN/NTRuj7sqwilihnBCs2Lsqw=;
        b=jBcdDHFTv0lAVSAp+VdjRIzB9WUhe77mrHShDpsw/0US+7CxNS7zjexIFijpLYsHN+
         JeUfNDRdET4O0dSBWu3qG2i39rn3S/OcSy8BMCRvIJn3UtqtHDEfRD0MwMjLRqntmrAp
         ZqKWY9s84J7KN3tnhV1fhjpFScdud2uD2eXM5IdHJaLwAOzaD3x+2Nu7zJZEFb9z34d9
         WTwWIF7RG8isFUYqyXpgm5+GjbuWGyRAgq7o48rEHg/GwSLTp4gPXID9+57+TkiX1qOF
         uyvC4omTnP1nwDNPSFFRcIiTNXcb2xCFVSqYXgwRmLS9FN2BiXK0evVOa2I/OXF+LGlj
         4OWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VCu1zsei;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=WWh+UKGAItsB1t8abcKN/NTRuj7sqwilihnBCs2Lsqw=;
        b=VdxEjzWpahRZHoRZxwG/E2KoC/yu6uKoAx3JRwgz0Fq92lqmanKZOepbMsGjpkS9SR
         wU2lmZeWdrZyn22fPT+bgvJbKx4GE2KYFU4UzatHzjRMzcvpgfV66/OXJSFbk9UWp7kS
         CrnSZxBq9YpLPTkFI7xSVtvejCkxomCjn2MYIsjRpt2zZz5gKln4n7SgzGKiieuGqvjE
         6r9A6M3Lgu3eyXqn+R+PWqmhOvzZbQ3r9znuEgAQ9B2kZIXqqkp/iURJ8BKsTYiJsWeI
         aI76lER+YKOceuaJmF9mucHt9A/Gpf5LAqZ0XcuIpFLMrVogqfoRT/02fl+mVr4XjnOX
         GUNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=WWh+UKGAItsB1t8abcKN/NTRuj7sqwilihnBCs2Lsqw=;
        b=z9+5PvSFcandaxNQ3SLqbFRejTQEJfycISnRtOAJu7Qz9iHFYrmXJiINx/rdfsKhhE
         KR5ab78cxKSgiYTzSURC3Zmpae7zFrOycD9SiaYByvq0JCXHA9P5XTeVhuEDBuHLJvz8
         8zAOWGygb6atc4vqd9q2MYDgGBiitQHurXy5k/Dmsq5poKkHMiV+tohq/oLeYqwNBvVy
         LLSPzZSAdz3DUoIWowIUtABeduTyFDjtnrgoVcoA72wcLi6mf0astVGIKvAkyPtucp7e
         fK8duTzGKWSdujsZwuyf/DCS2D7DWEWedQDUTiBkeWbFV59lrr8JnOY/zQedoTCvpBgh
         ZMYg==
X-Gm-Message-State: ACrzQf2X2U2fvu8u6C5+dNrKCpTkgDNctHi8iHxr7XO4MUVYfooJIMrC
	lVrEzQY2EubeHEGSi6oXLqc=
X-Google-Smtp-Source: AMsMyM4E0oP8HPZXnTwaE5LOTSfE2RrzfH68SHxqU2es6DdsHIRZGm9DkD5gkakEpFIojT6RtSn4Hg==
X-Received: by 2002:a05:6e02:1b83:b0:2f5:3d65:6bca with SMTP id h3-20020a056e021b8300b002f53d656bcamr10611216ili.279.1664213740893;
        Mon, 26 Sep 2022 10:35:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:5a:b0:6a1:cafe:7d5b with SMTP id
 z26-20020a056602005a00b006a1cafe7d5bls2380ioz.4.-pod-prod-gmail; Mon, 26 Sep
 2022 10:35:40 -0700 (PDT)
X-Received: by 2002:a05:6602:2c09:b0:694:51c4:8282 with SMTP id w9-20020a0566022c0900b0069451c48282mr10089983iov.203.1664213740468;
        Mon, 26 Sep 2022 10:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664213740; cv=none;
        d=google.com; s=arc-20160816;
        b=R8Co4oQojoO//qBblEIYOGjWs8t/eDZHWF3bftPetIT4wwUOhR90UWntjKZoj4GMVB
         QifzNFISXcu0Wdzryzz/7Iu9aRq0JbVTMgqZgtEbyB5xs6Fjy65k+AbMc5xY8dEJHyaQ
         bt0eYXz+mVpXfSci6Pk4SmRcCrmviedL4jmwkiFu8qfWj8wuUZs2NirENRFJByVnZcWt
         NbECCTsn4SlDAU4NKVeSqo0CTInz5KnZfTdAcPAlFKdcEAkXgYjHcBA6iwq04Sm+XM43
         pkkqqfF2HBHjBb/ThkZBFY6+Y5tYv1i7XlsW/Z4R3/JO5SJUqMdFsYRBj2DnY7Xq1gWq
         vmlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pWZXDevPROEIG0Y7tSypuKfppO0Nh7xTkG0JAbJXSUc=;
        b=lKGLAG9+7yV+9o8lTDkyUzHvXnrp8myWlxmFpzfb2I+tWl4v25zklekr4+D6Pas8Sj
         cPM56vkOdktuQfIhV2PqR48ZbrVc5bl7H1iQZuPJ9XWGWt5qCoR+MF38X0wKuoOnzXG/
         cQfrmZw5N/+AC+m6YnMyxqAorr1lIyV9iYNdcU2238ShFwV6vCBh3XUSw+YxLValw+DG
         3f2oHTzkE4kQVXInkPsQHI1pccqSkdvbPKkRfoCXGvOy1VgYBNhPxC2cVmNrk+ByKf08
         XMcbCUGZeDBy/cPGFWM01tlq/IACn1uAY/obi/y6J1cmMSTY0ArH1iU3iGnNYKdHoyzJ
         bkdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VCu1zsei;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id k1-20020a92c241000000b002f605782c7dsi1055846ilo.2.2022.09.26.10.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 10:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id c9so9327765ybf.5
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 10:35:40 -0700 (PDT)
X-Received: by 2002:a05:6902:1287:b0:6b9:c2c8:9d3b with SMTP id
 i7-20020a056902128700b006b9c2c89d3bmr10708395ybu.553.1664213739941; Mon, 26
 Sep 2022 10:35:39 -0700 (PDT)
MIME-Version: 1.0
References: <20220926171223.1483213-1-Jason@zx2c4.com>
In-Reply-To: <20220926171223.1483213-1-Jason@zx2c4.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 19:35:03 +0200
Message-ID: <CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: use better stack hash seed
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VCu1zsei;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Mon, 26 Sept 2022 at 19:12, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> As of [1], the RNG will have incorporated both a cycle counter value and
> RDRAND, in addition to various other environmental noise. Therefore,
> using get_random_u32() will supply a stronger seed than simply using
> random_get_entropy(). N.B.: random_get_entropy() should be considered an
> internal API of random.c and not generally consumed.
>
> [1] https://git.kernel.org/crng/random/c/c6c739b0
>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Reviewed-by: Marco Elver <elver@google.com>

Assuming this patch goes after [1].

> ---
>  mm/kfence/core.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..239b1b4b094f 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -864,7 +864,7 @@ static void kfence_init_enable(void)
>
>  void __init kfence_init(void)
>  {
> -       stack_hash_seed = (u32)random_get_entropy();
> +       stack_hash_seed = get_random_u32();
>
>         /* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
>         if (!kfence_sample_interval)
> --
> 2.37.3
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOsBq7aTZV%2BbWW38ge6N4awg%3D0X5ZhzsTj2d3Y2rrx_iQ%40mail.gmail.com.
