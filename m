Return-Path: <kasan-dev+bncBCMIZB7QWENRB6UOVWKAMGQE4R4S4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D044530B16
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 10:36:11 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id w16-20020a2e9990000000b00253dceccd8esf1340945lji.4
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 01:36:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653294970; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xp43gfW0Sa2V2QwXtjag/hdNle7PPKDRVXNVQOwKCa4khY8I5Wj4XYAdxkCVfY5a82
         aVMYrFWxUi7CZAvUbWrLTaCDSUx5aSO3zMfWfSaF4KME6/znbf/s2Wgdm9OeekoJK7Ts
         Lq4YIKwTo4nGajgcLdHjrNam9CeALUMnvl5DfuOS74zqV71iKltXwWF6RiAIeDzKHnKL
         eSOTCpHxW4aUfse1DqWHi/Ile/P1IlAEV1vHmFTK7L7X4s0iXZE+svV5KZXnl/I7Wb4d
         gF/03iVCQ+9ZVOwIf7XCHDKE4sQDjm3bodAd8s8+0lfYgSwW6r1X22nwsqGC4SSvd7a+
         F4UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kK5z0U6oMHcxsJ1VDLmSNC2KBajrl1egYnxvpyj82DY=;
        b=MU3nA2QuvOai6dXk3lrSm7/Rb+qhUmjJCJ0AheAbmY2yhhFne1E23uj/rW2rmBfZMG
         yQWAnMWMrULw2kjHArHIkcUZqLYnWDVPGg8hIED9+dOFM7nR/3WDu5WVB9qo0EZuUNZL
         FQlvrYx6UGj2Wbt1opMNQqr14zOj98zpJHt4OflrD0wWQsvN55dM/wzMe+TjwV2Axn7i
         rhILd2OKnxWsDDqnq9OSnCVnO8a0KRm8zWLB6V8mLcjEkH+6UNFCpbbK6/W/m2lWm1gS
         IQtZezsJTQ/kZ6X4jSA7hu8sV28y99nayNEyQ7J+rnWxso5ajMnCmLUjSo9QBSbxgurR
         boqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B+TVMJ5d;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kK5z0U6oMHcxsJ1VDLmSNC2KBajrl1egYnxvpyj82DY=;
        b=J0TWeP2f03B6kTTTJUaoVXAZq3sNG0RorWjdUC3qotfIQ0MArK21GCvwSf1Y/BMnX8
         R9jGbO9bqa7Qy5cJTp5rY1tPLiTHcjCK56gpAE5/ATKYGSGNaIe90sV0QYkxe8uwP6uc
         8iZUp4i5DaAub5ucTiEMRqyVFNcDFZt7N/sGxUkt8uTAk5y1GCGlWslh4wdYmgSv0tl9
         hMMZNAVIhx/VlAhUUa2lhIRnxOy7mG9IZdSwpgftC0yb0SEdlztaT6K6ztCPE3WB0nA2
         ifbJ/EHl3ikIOfj39EKYXjRUICd/Q+2PXrPdSnh/JaqTnZxO9f43A+aqHrhv8Qvw0pkU
         TsKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kK5z0U6oMHcxsJ1VDLmSNC2KBajrl1egYnxvpyj82DY=;
        b=aJtya5EUo2c/n5mTd2VPwjdMRoTYOs/mD4+A36jhh6s3P7iqNEw2bBxPqpdbv+UE2z
         Zrs9UY+zcWfyWTi2UgrwQxNXSBBXdy59qvTPnI0UX8M87JXJpkF/iEUH2KX41OT9z+dM
         PXb8ElyIhJVkfMNaD/RWrVD93mAGlsVt5R8dwq2fcRmolq48UajP8XgtxfmXzYO8FZ/J
         4GliE2faQMQl4BVEZ4MmvUNs4VWMtPIUTKE0YOXyQAKZE4xG4c65oWzigceRF4UtPZOR
         eEiaLCXtGrsfklJ1RU02QRMvFwLR/lcL00KuCXdGmFPcJPUJ5d6v3FoVNNUpT9frVWwz
         BxpA==
X-Gm-Message-State: AOAM533IcjCyXUHSVNOLq+6EPt1tiDPrFxOP0aQUtQ/1RLs0BDkd9fV8
	qfgj4DB5QkI8LcAssQRbMIM=
X-Google-Smtp-Source: ABdhPJyYVwlk99p6BYPEU1G8NQQ6id2E4BPJLGDkwJG6kgad9CpYT2g1nAts5nmU1fT9DOIpn1yKjg==
X-Received: by 2002:a2e:8449:0:b0:24f:4db3:f02e with SMTP id u9-20020a2e8449000000b0024f4db3f02emr12480515ljh.140.1653294970715;
        Mon, 23 May 2022 01:36:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:551:b0:253:e9db:d804 with SMTP id
 q17-20020a05651c055100b00253e9dbd804ls372521ljp.8.gmail; Mon, 23 May 2022
 01:36:09 -0700 (PDT)
X-Received: by 2002:a05:651c:11c6:b0:253:e817:abc6 with SMTP id z6-20020a05651c11c600b00253e817abc6mr3948100ljo.164.1653294969527;
        Mon, 23 May 2022 01:36:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653294969; cv=none;
        d=google.com; s=arc-20160816;
        b=quW8hbSNrjwogPdjLkLpMyseQwCNQGnGz7XV88f1bLVYSUEhrOo8YP5rBZ0LAkbdfV
         ZMTIpGeX5Jdld+Aic2D7ON0sQKXjYjs2QLgl1YOvD0RZgYcy5dtuUl2DNhvDkQN1Fvha
         kPrks6d1ncVQTF9TOFdNNk79hC+rCgP0igZfYXQH9iYo0VtEoZHGMwnmI6ZaUMvI5oPz
         npPrBn4hNuZJbt2Oha56Kfl6or96OT0iBzsXOY94IClac8IeIz964J71CqBGshVHOJ9K
         YmxxDGZHIHj4cSRtVscdE0luQ7KiEOP3qrTTbO6xThS/yBw41oxC2UOOm4E5Xi+KvTCz
         5FdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=64FblKzsQYdGz6fqkSHe4/Mnt+TinFiqj0bwW9V3nQ8=;
        b=TlS0nbztWp3xd4bUMvPTFK4fLF/tF47rPS28LD4dzlsty2Y/iKgbAcrTI7Jhbtdp2D
         7vNGRMsT/5kN1cXKEYLmH2A+QCChMWubae7egwmya/SMHl6sEOWZrDh/YR8ImtrOum7l
         iByuAqk/O13NRNX+V/TfiDF2XDNgMScAankyylpNoaPx2HajjMvFEJAKYJTOEHIlrPkH
         AK39QiGe7Npe+KBwBy9woM5tqqmh099A0N7bzUh1TDrJP3D++5Y3W/j25LGWusqvsd+r
         LoS0uuJPbcj2tCyEYQLkHL9gjgqkS8tKXIai6kfItFW246jHYe1E/qkT+wMWOKLWCeFE
         F9WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=B+TVMJ5d;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id h26-20020a2e3a1a000000b0024f304af5b0si328924lja.7.2022.05.23.01.36.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 May 2022 01:36:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id u23so24316007lfc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 May 2022 01:36:09 -0700 (PDT)
X-Received: by 2002:a05:6512:ace:b0:473:cca7:a7fa with SMTP id
 n14-20020a0565120ace00b00473cca7a7famr15173051lfu.410.1653294969007; Mon, 23
 May 2022 01:36:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220523063033.1778974-1-liu3101@purdue.edu>
In-Reply-To: <20220523063033.1778974-1-liu3101@purdue.edu>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 May 2022 10:35:57 +0200
Message-ID: <CACT4Y+Zpasug=cr2k-17aD_EBsvMZB8kQnaJ+KPgoPOZAj___Q@mail.gmail.com>
Subject: Re: [PATCH] tracing: disable kcov on trace_preemptirq.c
To: Congyu Liu <liu3101@purdue.edu>
Cc: andreyknvl@gmail.com, rostedt@goodmis.org, mingo@redhat.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=B+TVMJ5d;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 23 May 2022 at 08:30, Congyu Liu <liu3101@purdue.edu> wrote:
>
> Functions in trace_preemptirq.c could be invoked from early interrupt
> code that bypasses kcov trace function's in_task() check. Disable kcov
> on this file to reduce random code coverage.
>
> Signed-off-by: Congyu Liu <liu3101@purdue.edu>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/trace/Makefile | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
> index d77cd8032213..0d261774d6f3 100644
> --- a/kernel/trace/Makefile
> +++ b/kernel/trace/Makefile
> @@ -31,6 +31,10 @@ ifdef CONFIG_GCOV_PROFILE_FTRACE
>  GCOV_PROFILE := y
>  endif
>
> +# Functions in this file could be invoked from early interrupt
> +# code and produce random code coverage.
> +KCOV_INSTRUMENT_trace_preemptirq.o := n
> +
>  CFLAGS_bpf_trace.o := -I$(src)
>
>  CFLAGS_trace_benchmark.o := -I$(src)
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZpasug%3Dcr2k-17aD_EBsvMZB8kQnaJ%2BKPgoPOZAj___Q%40mail.gmail.com.
