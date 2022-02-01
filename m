Return-Path: <kasan-dev+bncBCMIZB7QWENRBYOE4OHQMGQE3JBYHRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 67D244A57CA
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 08:33:55 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id h1-20020a056602008100b0061152382337sf11939272iob.18
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 23:33:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643700834; cv=pass;
        d=google.com; s=arc-20160816;
        b=yTqmTnobaBblsDmLTyXuGtPYkbGvFLhjGih8VbAzuqE/wW/gh6TJBG6jw88Zaph7W2
         7Vds64ViWWtEfYQ0MQbDHrrv4wu77GoDCxPbuy0lPtwOrHWsT1ZR10lL3Vb0Xa0uXShB
         5AqVi4HK98k6MAfl5uk4o88SlUwinxJYbLlZZqo9KNpvP3wDRigQ+WEte1Z9oL04bWW2
         cXS+zQT9AMKapqNm8IgcSuBPsQF0Y98JvqHaBtf2bO+QSbAj8u2PPZUYksMeyOKlJq9b
         +prQa2A+kp9AfLWwNlWcANU415IyiB05VzDHEp03snR0ugIjtse4Rp373/EFjsBLd1CQ
         WRJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JM+oQm937vPs17/8EUhSQHbqKjsLtfvmOj40AkWus/A=;
        b=HVwUcrHTsKY59L1ZoaHr+b185kQaIpSc6KqKI3TF89CasR/S7t08sbs0P3DxeCwoIP
         rLE/cX77Bme5bX36bRtPuqub0IDJuZftRr5ZcFw3D0+6U4Z1IRRHuAeY2MOuxlXL5eCo
         jV49ArOwhT6sbeEtjrjGBhMLIodIs2Pk5DN+yPNBSMZqncl+XZwMjSlMg17Kv9dvQgTo
         ziMHSRAs/ANvBvsHaxNpc/a5FE3nruRdkvEu9iRi9LUf9K81X6IUt2zp4Gs1htIHcxR0
         oCdAlClgXAKlgOrHq1A8XZilFNzsgVoweG7BdQh9AB8AjO/A1g5VXL7jA7CG7kcgi6ex
         xU1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aNQ2P6FI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JM+oQm937vPs17/8EUhSQHbqKjsLtfvmOj40AkWus/A=;
        b=MCDfRNvGCUlyWKeEBa4lMq/9McYdduWA1WlRV5g7MFEcAXZVat6Ck9Uf7qb2nBd7Qc
         rSScB23YYKgdcBtoTMXC1zKVPDX7kJRvZ8PGIqqc/emtl+Bev9BKUZFGa+j0lKz5bn8s
         tyHKTxaTW7L9K7MqKe7d4XNHVViAdoXPNe42Xsddyxn4zkKGys2JHxTupg+xWgaSjBM4
         3NU1RMZH+psZLhjND95JgwBTy0oI6BLEXknIVxX7VggITfntxEqIkZ0C0RIL870yBDWV
         xfGJJbAwEPqjSNiTmuQpev6d16XDiOH2bxTEzxg2Hx4Eec4S/WmpxAq6KYH9qa7KaAPX
         0BUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JM+oQm937vPs17/8EUhSQHbqKjsLtfvmOj40AkWus/A=;
        b=nBNlifpyVeVAU/MMyaUpOD+Cq+vRAE/uyin/PUIsle4IVraF/nfBWDRc4yx2K82eTT
         jygG7WXVeMqZAiqZDOZbDeMk2sOGIvuf6E+ba2Jev5eSzvJmz9WkcbqL4X4CBpzlT+P2
         oGJGxoVahcT4LUeOHhOLs4dskIi8tIUD6dRnkkH+BDfhMP2THZZgAB5EZ1h2IstpH3Jm
         P/XmNllIkswMRJ54MBIYHlng1JuY8c9n8TM4vxqJqGzhKYRSJJRGqZ3jVlXJ27EW8XSs
         CIku61I9dvWMt97n5iBHVGecVl77pJu69IpcJeuXFAFBj8OL7AABrE0BNwpgyPoSuNET
         XUkA==
X-Gm-Message-State: AOAM533rQnbFAxrciHKH33sZPQYNmzioqsgxpEiz/19WOLcqDjAetJG9
	/JRuaiYoM9nJkoxPSTPuiPQ=
X-Google-Smtp-Source: ABdhPJxFbI81zPf/uAPNLfJRkB+L70kdsFyGIUycg+TIHDrb1dg4HzXxm43HKvjPK5r2RpTdv3MlXA==
X-Received: by 2002:a05:6638:2493:: with SMTP id x19mr1737083jat.219.1643700834029;
        Mon, 31 Jan 2022 23:33:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:cc5:: with SMTP id c5ls3950902ilj.8.gmail; Mon, 31
 Jan 2022 23:33:53 -0800 (PST)
X-Received: by 2002:a05:6e02:1c8f:: with SMTP id w15mr14192316ill.69.1643700833625;
        Mon, 31 Jan 2022 23:33:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643700833; cv=none;
        d=google.com; s=arc-20160816;
        b=iXrPKajXB01HxbT1i0aufDKodiiF0nS7iCkkLgoZICGH1h5jBJxXU2h7mMLxWukBq8
         FO3nrOKBHq8yy3gjprwTkn828gt+54lRnJbU0mlgwzjxnv3+wQmSSgGnPAGH4BU7h3g0
         DklRqrtIDDGu507e6MPQT61oN1hlLRZDP6kXuip83rNoeHoi2Pq7Av7HKkwkwA8hqgak
         mkXam5+PfDkcQ9z5CsX0tdawCx71PRJfoC1MjJZBaOlRgtWnAiIGdZPza8L2o71tqEBR
         29ABJb3C56VSq5YOmzvSEHXcWApbtc4D0VROUqjcGFA0D5Hc9rKuH//PCUuv+Q9yA7jy
         iZgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q58ni/O56sdIgVA2i/gi3EPNdebcIe5HTTwsxm8hE9U=;
        b=C0wSB+2dY9Dl2CS03u6AcV2RVk3MPzrMKV/5Jieb5x6dFY9DBjlQD6LPBhlothnMY4
         WfQFNMv4ZXrScJbktvDvXRONpMmloCou76MxvqHyo104KhH3iDjnyc4I+ATaz++q/8Ei
         EOd3LajLHnB44O+ZQho9U/moZYh4mrIeZpRpH3/Xzy1/cJdB064ieQubxHxwfnoXgeW8
         x9ZKvSgJWm6C+xE1zyXoPHCYMqLtTuyofYSFK4VHQCGiWjHBMfCb2IdBjBF7PpGGLI5K
         82l/0wx14mtp+rbwLwVCLPRvypnbi5k5kMV6BNVcaqDN3f4Qp/UDpHoMozyciqJFotLM
         HlFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aNQ2P6FI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id v3si2576943jat.0.2022.01.31.23.33.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 23:33:53 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id b186so25480610oif.1
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 23:33:53 -0800 (PST)
X-Received: by 2002:a05:6808:1641:: with SMTP id az1mr440454oib.278.1643700833121;
 Mon, 31 Jan 2022 23:33:53 -0800 (PST)
MIME-Version: 1.0
References: <20220131103407.1971678-1-elver@google.com> <20220131103407.1971678-3-elver@google.com>
In-Reply-To: <20220131103407.1971678-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Feb 2022 08:33:42 +0100
Message-ID: <CACT4Y+YfHGxCKOE179LzXkpeRqfEU8OO5zTh-BhLL7NxbNPGGg@mail.gmail.com>
Subject: Re: [PATCH 3/3] perf: uapi: Document perf_event_attr::sig_data
 truncation on 32 bit architectures
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aNQ2P6FI;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22f
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

On Mon, 31 Jan 2022 at 11:34, Marco Elver <elver@google.com> wrote:
>
> Due to the alignment requirements of siginfo_t, as described in
> 3ddb3fd8cdb0 ("signal, perf: Fix siginfo_t by avoiding u64 on 32-bit
> architectures"), siginfo_t::si_perf_data is limited to an unsigned long.
>
> However, perf_event_attr::sig_data is an u64, to avoid having to deal
> with compat conversions. Due to being an u64, it may not immediately be
> clear to users that sig_data is truncated on 32 bit architectures.
>
> Add a comment to explicitly point this out, and hopefully help some
> users save time by not having to deduce themselves what's happening.
>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
>  include/uapi/linux/perf_event.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
> index 1b65042ab1db..82858b697c05 100644
> --- a/include/uapi/linux/perf_event.h
> +++ b/include/uapi/linux/perf_event.h
> @@ -465,6 +465,8 @@ struct perf_event_attr {
>         /*
>          * User provided data if sigtrap=1, passed back to user via
>          * siginfo_t::si_perf_data, e.g. to permit user to identify the event.
> +        * Note, siginfo_t::si_perf_data is long-sized, and sig_data will be
> +        * truncated accordingly on 32 bit architectures.
>          */
>         __u64   sig_data;
>  };
> --
> 2.35.0.rc2.247.g8bbb082509-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYfHGxCKOE179LzXkpeRqfEU8OO5zTh-BhLL7NxbNPGGg%40mail.gmail.com.
