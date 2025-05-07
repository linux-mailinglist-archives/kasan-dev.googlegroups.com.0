Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZML53AAMGQEQZPOEBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 04016AAE617
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:10:16 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-22de54b0b97sf377375ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:10:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746634214; cv=pass;
        d=google.com; s=arc-20240605;
        b=J8aJvB4N9D6Mzb8v775CP4SoIFf58+5VNEUeqqBiwgRQ0W1rMFLJwlJx7zpS2Z5jj+
         FQLl2Kq92o/Ic/cvcb5Fw/9CK8Fqjxoaz6+CV20C9KTwfDJXh+bWVC9LGvf9TSUi1PaN
         Z60otPTbBbfFp5NHuCJPnCTqwDiOh2vD8RmhfFlmsZM39tMY/1SErUK5J2wUL1gT70A5
         Twn8w4vcvSbOmbOXG8tXJvDArOlkeKE6aZu88gWRxQQjzii0EjrfZUV97Pti7tD8XN9x
         BvirDkFZzpogASVBePfptP+69yi5Y/G/lkfKNAzMP3odpvQc53KWUkhATQqYSKKDOVMz
         I77g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MZk1JAq2XQNM/AoofyKw92Whc/XbKOySkx5tSG+X3SU=;
        fh=8TbJKc+J2x6ZmnkArRgYbRd0Tqy1iUKCQQR1ddcEvbA=;
        b=T7Y8EDNVIu9KLreYwpjyUpyOKuv4UTPF8Izjhf2hRpYxhX59ktiHXaEKO2LNnzzXN4
         l2DARmOQEpecWtDjqJ7h6PLS9DWcpOH2eHnSAq2GZcuIRlq907hDiocuOcaCE6qnGp4W
         ghOeBiws+zs9VCLLSTGGF92faZqsblUfKPgqOOVyMehs8I33rvOOZLkMSVGQ9szblsih
         DB3LH/9bEEhNhaqT4yHQa6eReV85EY5x1ewkN4DColW76lOZf76oKGMDvhNVdEqz25Yh
         FvNqd4ZKqYcfBEK4YYsA4vSoXHWJYE0cttwiLeD7CS6S6aR0r3vp1qOnIONpBfzyP6Ow
         N/tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rgIBt7H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746634214; x=1747239014; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MZk1JAq2XQNM/AoofyKw92Whc/XbKOySkx5tSG+X3SU=;
        b=rTCySjR7d1L7of+Q8wQ/huEEQXDN/aPzUZI9yNuEjs8j4HXypPtHz9sRkaGVII+eP4
         id5nNYrMvH33tgAsSxvCf6Z6ti57s1UovQmvkqQS7TVc3WHA04un1+b8/gk3v1kY2Yt9
         9n7wf9VreyZ43t26gMVtXaJEgIpy6Ajld4x/sqCrsyzHJkpqZ5o07LFtj0rR4zeUuGUv
         HCiQo+YyPFpMUR6c21zUwrwRMiwWGc6AeAcgKXciO7DCauklY/7iYM1PYm03E0n2uMeg
         816x/7Q2wnhX/zWYJZ4fWRhhyou7mWiMnPCCKyOzbxqBn8nOEP2Vk94vSB77PWGugvxY
         vArw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746634214; x=1747239014;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MZk1JAq2XQNM/AoofyKw92Whc/XbKOySkx5tSG+X3SU=;
        b=L2FqH+p9yYgy89k5GQ2AA6xiTdfYttmqU4UnckUa4XN32edQyAw92xnCZXe7zQAVgZ
         cYIx380spZv8FId8C8z9pBx369pR09bWOIbr1OnbCYt4K3PcuK8uJjS9UBMxPVCk6wxd
         uuM4vKx8OEKBgoFaQ3SkaHU20kZjzcXqcYo1l/fjfYIfSOKjrU3nZKA859o1EysJsnpO
         l9GVOrenOXXzm4IxLlaS9nYhHABe13OQjjSE9oK+lMvg6GNa+wyaYY78yUVlUlARSkLb
         BY3k2lB2v+aKDPPxeKHciCo3Kp86Qb4dbhWqXm7hMW1lj00nuG68Qt++f1ptnVbalFEe
         OsRw==
X-Forwarded-Encrypted: i=2; AJvYcCVBNk4kLDVyZn/GMoz3pFJPg06uX2h9/UMNfY+M4cTuOjnhijnOFcbVGsgM7sretAurygxXVg==@lfdr.de
X-Gm-Message-State: AOJu0YzQ8AWDeyAz8SFSx87jw0y8v3B3SQOaerl3++nsxea3QYe8cvIY
	ZduyTHCNOGsdqD04we58HNLZgOgS+L18ubJFRVbIMDNSmnMPBOca
X-Google-Smtp-Source: AGHT+IEoHLmqjkss1Gz/0cOOuSPwOuD+CqjWruSEX75B8x1SDBhsJTvzOogNYUx+NGvhXlSRfpTRvg==
X-Received: by 2002:a17:90b:1d43:b0:2ff:5357:1c7e with SMTP id 98e67ed59e1d1-30aac1b40a4mr6009509a91.20.1746634214091;
        Wed, 07 May 2025 09:10:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEJU7up61eptFIfGOr9nv2GZaHAfNlTSZH+FovQJjhzgg==
Received: by 2002:a17:90b:1d02:b0:2ff:4b06:9a15 with SMTP id
 98e67ed59e1d1-30ad8b04207ls70178a91.1.-pod-prod-05-us; Wed, 07 May 2025
 09:10:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX15daHK4Ez1xwH0V2WTxfBRQZrOAIOtz7RpMXzZk4yBVZgQaTWKrm9g1K0UcHjrPGvoglnMCJCiGI=@googlegroups.com
X-Received: by 2002:a17:90b:4c88:b0:2fa:15ab:4de7 with SMTP id 98e67ed59e1d1-30aac19cf0dmr7315832a91.12.1746634211773;
        Wed, 07 May 2025 09:10:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746634211; cv=none;
        d=google.com; s=arc-20240605;
        b=e74/WbycGi4M3QPbuYvs46SSDKOpd0loxAEAX0QeXMkBmpD7bAKXK8NseDbQ7jBuTH
         sXmbp0YR30GC2jb5+eHzwgCeNDzkuuilqhddd20McefMI22b+nKf24bwNs2xpSkioRQc
         SI6swFwsfzPIEh15lElZoiYtIKx6slFkdZdN3SotRU3ZK2tK14M0CLdxsTLyaGXtf58I
         1HxgEdbLIE9go22SwCEBNTwepW57k07Lj5gdJuCPYItyAARhNtL1VIHEFgvzdfabOm48
         3DgjF1LWxLU1uBd9lpy2nYMA30weddKIoPJT9AlaaJcV8bknesklrCeakCWEJDOzc3HM
         A0Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NP1IWzAxZPWttfk70bAFVVWLlYvnNyqULPRz1VjxJ5A=;
        fh=s1vt3jkKq/4TRfm+L4Uxjqd9iTOKwuOkJAlaTonAHko=;
        b=DnXt71Zr0zkTEMvh8Jgf9Rq1LpKOXXhd/O9qQNalHp3+YcegvKqx62YgKtzjg1+CI/
         cYSsZjECA1YEve6qZ+8jQ2SKhcbJOFthJDU7S/jI/t5qzLbP1iw9PWxh+yrP+GPrJGif
         X4V7GO6Cixcvh0XG2h7Yea4hR7TOws9nEukVJqkgpElvwTLdDQF8MwuiZ1zOJ4Ckmfwv
         XyDTdX3uRfFq66ykDS/H6UFctYrvYwQ7HeSppVcI35rT4/nOD2MGF7n23Wm+46V563j5
         Kq0F3zAGZDGGg+Wwgu33ebM/5vEde0v6Z1zQ1jgG9FN8h1BdDdz91VqU1Jpcu0IeXlmG
         JqAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rgIBt7H;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30ad483f220si21759a91.1.2025.05.07.09.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:10:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-30a8fd40723so96519a91.2
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:10:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJYW/mDeSJMPMrs8THM4OWphNNJCxbyOjfL+6Pqf7zF9PKs8cxFK+3xZJtJ/qFJfwNKgTs1WC+YTo=@googlegroups.com
X-Gm-Gg: ASbGncsTHS+lfcReJmyDNSxp5rA+iQBIjw9QY6NqStZAk43PaJ0d7AkMIqhRlnxCmR7
	z9lP0W1wrNBJZ46un5bxC5a6hP0zjkvUALMekKP2sWRUnbxlZgDkyE4uwJGXH69j2U4hZH67vPb
	YHZ3D8yYjqkR5ZjAfCo5HscVDLTeXCgKB23k0YG/Z7gHYnFbsuno4Jww==
X-Received: by 2002:a17:90b:2241:b0:2ee:f440:53ed with SMTP id
 98e67ed59e1d1-30aac2483e9mr5433231a91.31.1746634211085; Wed, 07 May 2025
 09:10:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-3-glider@google.com>
In-Reply-To: <20250507160012.3311104-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 May 2025 18:09:33 +0200
X-Gm-Features: ATxdqUH0mWSb1W8gFSOo12rKgcriXJX1rwTk1Z3Qj0HHv4T9Qymk1NFHYU5acZo
Message-ID: <CANpmjNMZos17oYAZsBqhhYuRRiGqsG+aLBpk+had5aWi4YA02g@mail.gmail.com>
Subject: Re: [PATCH 3/5] kmsan: drop the declaration of kmsan_save_stack()
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1rgIBt7H;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wrote:
>
> This function is not defined anywhere.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/kmsan.h | 1 -
>  1 file changed, 1 deletion(-)
>
> diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
> index 29555a8bc3153..bc3d1810f352c 100644
> --- a/mm/kmsan/kmsan.h
> +++ b/mm/kmsan/kmsan.h
> @@ -121,7 +121,6 @@ static __always_inline void kmsan_leave_runtime(void)
>         KMSAN_WARN_ON(--ctx->kmsan_in_runtime);
>  }
>
> -depot_stack_handle_t kmsan_save_stack(void);
>  depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
>                                                  unsigned int extra_bits);
>
> --
> 2.49.0.967.g6a0df3ecc3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZos17oYAZsBqhhYuRRiGqsG%2BaLBpk%2Bhad5aWi4YA02g%40mail.gmail.com.
