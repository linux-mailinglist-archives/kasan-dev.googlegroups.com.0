Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRPETPXQKGQEH72KSXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1BB112059
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 00:39:51 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id y127sf3437224yba.19
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 15:39:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575416390; cv=pass;
        d=google.com; s=arc-20160816;
        b=t17GZcdsShWiMLEjkbNNlLQI83l/zAm//kEgqnfIV0mrkUfeXUdycv1oE0ELk2LdHK
         zUX1ZZrcRNn5uYIDIUOH+smzmOuzqRU+zalxsEjt8CudH5bjOVt77qndtGMkY9B1NTtf
         AHSzDA1TOm973v67UF8MCu8WYPvGIZMain+82oXhr1Ajbkx72Gtl2D010uTz75E/M/rB
         Qbl1HZup5j3BzIjpXK9E25vT3aCAFl4LuDbi/+USgW3RtQz1LO6BRF29ceiSHZGoAooz
         sPYK9fJAJKYNLovlM5Jop13C18hjLc3T3OK9dN1az442qdMg8HoIzxzMNqm55limVvRq
         /GdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=l10OKa7AVcyY7G0b3hj19reaIY5KEfbf5axZSnAE0ek=;
        b=M83D4OhjfmqPc7atlVoksP2v1zM53X1ZdAG6HPAk79H1c/1/S5QFPRzejlkrC7cs/W
         25EuqqOzTCC3HdYhC5m7GjG1aZIkiaqbFmPCGm+LaGTbN5UsgCfmKydZan8t/Uyan91O
         xB9HstWNbxQ5LBM4NdYGu5F3IJ52OpTaZfOtixVEMZswkWlhrnv4Uacx1vWst3aZiTC2
         1suEt/MzJaGzGYd41w9oRuaFItIQ1kbonRwKY6CulrMjQlooZ+i9knUxQs7aGCzZXEOl
         NY/H5oEaDCBgLToStS6rSGdH2I/9BZIGVv+xXwog7794DC0GgUR/bYc7M744Gr12Z/zc
         mJjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BVDTej5T;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l10OKa7AVcyY7G0b3hj19reaIY5KEfbf5axZSnAE0ek=;
        b=ZOAKngJ4M8GN4zKA5LZh2BHJjN6Ewr0AS2DOgKV1dPLmuk1XDNj8pnATgcX8RhM7eQ
         t2r2x3KmJ6Z7+oyUVq1OeHsjKRx3PoqfrLcgSLgNEjK8t5/AGQT6P7+WmofH+kHLyHTk
         1mnrCjkKAW89rPYNAJfgyCxs7j1MaCe7FGG7YwQ2woGdYrjvJ2/7TMqSMtV/TiE8KTfb
         bROKUfAeCdE8xEfhIUCujALyCmobQWy6zDykWwhxbPU/hDdnTMRru06VINZ7EDC7OmlQ
         ajZJaPUUGnyyrMbKTDwdqXpQEsKKwbEDRFlyNqU/d3tUA3TUmfxTLPVM2B4yiUNDu+1d
         1pgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l10OKa7AVcyY7G0b3hj19reaIY5KEfbf5axZSnAE0ek=;
        b=lryxjS6gInIupNU7nLXcizd8LuHd/DVJXzVS348mAeCOY8VyDSt0pRmNXDiHmneZiN
         JX5mIJCNcSj2F+eKRCVTsZjr/elayhYHfZ0SJzDULj5h8P8acfqGJ0momOoefrTGJUE6
         Cwrynw0V/Exw08nBf/koYSuO19izvYI3XFRZHxfgO045ej1whFlmuv4Tohex3Re9c9jC
         un/CievfM921VTcUKJcakWJG+LvKKDAO2OfbCNqlevEPatw6hN/mAsR5BLtaqezXI6Ma
         zq1RDx7VfIVsJ8jU52st2ekFCueuDlmiga8eSZEAXEY/dfoohiwP0yD86IbDJJXYtFbi
         w2mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUZL9pHI+4TXVmuwJLtkWfwg0ZDP/2pPvp4HC7PwXKDVsqpG4MA
	ULaynkzFMrfEoPP7T1Pf3Ck=
X-Google-Smtp-Source: APXvYqwju0cdU9yGHm8mrosRS2RI6e/tKw3D5CA7sLfONxSc56xf5TkePAG5aDRwzjBtEu4YIfp2ag==
X-Received: by 2002:a25:6409:: with SMTP id y9mr363891ybb.506.1575416389951;
        Tue, 03 Dec 2019 15:39:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e851:: with SMTP id r78ls735132ywe.12.gmail; Tue, 03 Dec
 2019 15:39:49 -0800 (PST)
X-Received: by 2002:a81:7011:: with SMTP id l17mr113800ywc.440.1575416389508;
        Tue, 03 Dec 2019 15:39:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575416389; cv=none;
        d=google.com; s=arc-20160816;
        b=icZaYTLBohmy9n8jmldcFyNdBfbWNU1gy2RHdcMM5SGF8LKDvN5KYm/+h2n0pEDVnQ
         QdJFsPOqxwLLR16/E3D4ZpuOCOgC7h/NPQJCHLmKRulU0ZgnWugzIV0aSo940veyJ2/w
         X5At1OarP6yihtYxsp/TdlWkiuhAysLgEn7wmjIVtQ654tqNAks+nPpPg9vJryGzzW98
         cKqWldcwWLQKPI98j1TalQuvjjG1cxwrWsSa68fkOsflqEp7ne2GARgGdJ8fe3Nkzw01
         Oth3YP/7CYtPFziYaDLa5E1lqw9pqORESMJuk8p6k+pi6oGP/mc9ysNgSGiL+xXpRuW+
         gzaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=VLxOzUzazoD/qcDrmOBxEpKT8zDKcGdwgU5iRuwbvZA=;
        b=ezLuPQt022L1xceE5d4+f72aUkenqCKC/049PqRLPShGMhVFxEcll6M2+IT4CRZle1
         qCpyaHz7o2PFhp/vRuBf3kXv8kKF8p1iE6hyAMnRA4awn3qeHiMjHQU0fje2bB979s78
         5dR/mIyU+jIUvtJ0gAaX7qWuIt/GUH15rBEVJF6UBufZjSJAkuJZnZ6ES5CUbCnZKm1N
         RkA2h2H3+9HSnMSgiJRRXaoO4CZGYqiJSbCUh1LGVlsdczL5w10BoGblQp8D+c518/Qh
         yghF1l8S7Bknfyoba7sZfx72VDgANzVgR21Y8ya2ZLGXPnz365PbCAuxYTeImYwP3oly
         zecg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BVDTej5T;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id p187si227862ywe.1.2019.12.03.15.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 15:39:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id g6so2320857plp.7
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 15:39:49 -0800 (PST)
X-Received: by 2002:a17:90a:b706:: with SMTP id l6mr23416pjr.53.1575416388603;
        Tue, 03 Dec 2019 15:39:48 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id z26sm4463572pgu.80.2019.12.03.15.39.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Dec 2019 15:39:47 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Michael Ellerman <mpe@ellerman.id.au>, Marco Elver <elver@google.com>
Cc: linux-s390@vger.kernel.org, the arch/x86 maintainers <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <87r21lef1k.fsf@mpe.ellerman.id.au>
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net> <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com> <87a78xgu8o.fsf@dja-thinkpad.axtens.net> <87y2wbf0xx.fsf@dja-thinkpad.axtens.net> <CANpmjNN-=F6GK_jHPUx8OdpboK7nMV=i=sKKfSsKwKEHnMTG0g@mail.gmail.com> <87r21lef1k.fsf@mpe.ellerman.id.au>
Date: Wed, 04 Dec 2019 10:39:44 +1100
Message-ID: <87pnh5dlmn.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=BVDTej5T;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Michael,
> I only just noticed this thread as I was about to send a pull request
> for these two commits.
>
> I think I agree that test_bit() shouldn't move (yet), but I dislike that
> the documentation ends up being confusing due to this patch.
>
> So I'm inclined to append or squash in the patch below, which removes
> the new headers from the documentation. The end result is the docs look
> more or less the same, just the ordering of some of the functions
> changes. But we don't end up with test_bit() under the "Non-atomic"
> header, and then also documented in Documentation/atomic_bitops.txt.
>
> Thoughts?

That sounds good to me.

Regards,
Daniel

>
> cheers
>
>
> diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
> index 2caaeb55e8dd..4ac53a1363f6 100644
> --- a/Documentation/core-api/kernel-api.rst
> +++ b/Documentation/core-api/kernel-api.rst
> @@ -57,21 +57,12 @@ The Linux kernel provides more basic utility functions.
>  Bit Operations
>  --------------
>  
> -Atomic Operations
> -~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
>     :internal:
>  
> -Non-atomic Operations
> -~~~~~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
>     :internal:
>  
> -Locking Operations
> -~~~~~~~~~~~~~~~~~~
> -
>  .. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
>     :internal:
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87pnh5dlmn.fsf%40dja-thinkpad.axtens.net.
