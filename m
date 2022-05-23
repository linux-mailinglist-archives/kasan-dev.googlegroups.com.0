Return-Path: <kasan-dev+bncBCMIZB7QWENRBHEQVWKAMGQEYVBLLTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF47F530B19
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 10:38:52 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id l2-20020a170906078200b006fed42bfeacsf730036ejc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 01:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653295132; cv=pass;
        d=google.com; s=arc-20160816;
        b=smhSlS0vov9TOBAd0BB2864sxp5bwk3SGO2WJ5B/opsnq6wbVAuPXI3DZdf/qLqQes
         rPeS9snPCoCNKDmoUweMnyKu64eRpn/nMHJgUZB+g9UHAAlLFEJiPERrsAaGbBfpka74
         CemGBAEeFDnQtZPgyH3HjiFBnqpPbEdx0aaXMUR1QFhyQQh3MkJ7lk/cO9QxtUrSyiA3
         WwfjR8uvOc4VYhVdDwQtptjxSQGnRfgYgJ0oucuhhKXNCmoYi7jISuegwoSb+Q094NZW
         UOjYG9eRqzHiwGKwPEgHCBuUlyLTBEE7OUXikWbrz1lKoqRkJ3zWxeOOOHlj17vEGzgU
         H2gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eirKAr6mBZKNmKhjufJjwFZZZSbSt+yDyLWJiiylbkM=;
        b=jF0j5LkTGpn2iHeEX5Jlgn0RgDTikcjPaSn0oOwvPSfaJDqNeSYaXI6PqPgAphrsLp
         lXxdpIzVq5aQOxYW4mtOAQ2Ij46gAYAH/ivSe32cur4WAFy1lsEyr0eADAEIwnXHLk95
         Rl0jD0B7igcOR/n42PM10+HshhxiSlfmpEbDEqahq/lS2mDoe79NV9WTt5iEQR6M8UJm
         HxQ5MUfp3uDxGkbYXDtRdV7Tf1OJgt8ytZYclOyxRkzPl2G32QwnukS1+ZUXfgipK5b5
         W0Powj3UfsRgRQ9laa9584U7oW8tKHL7FY6UU3qdAorz0wzycQx1W8OUnVOzIimMZ/x/
         I7/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HnJDIO1D;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eirKAr6mBZKNmKhjufJjwFZZZSbSt+yDyLWJiiylbkM=;
        b=D820cBqVlMXMawKAozBQ72TJVi8JkKp8DKyh5QH2rH8Su0BUpB0sTYIP3d8Z9TrLUV
         jDAoaBbKLdEP53x+D2mIZpNE7PuiWZtOIwen+XXDkWOmk9VzdLn7x0ZTbom+edWfBQsS
         ttpkhenKyThSDTvEYLmXBfibGdAGNtcMBK+yPMeltfFHKDbLoQ3pJyUj628jsVcDeDTE
         UFQBnbkoc9mo8nnwQhCtKKnbcaxyXiLIQTT1Rcmhwf1r7Wx/ntiCJwZIFaoQ0u7b+eXv
         4gNHPGMuK3gPTvkfHAe8Pcj63TuBpyR10xPqG6R8Y05Hp8hpPj5ZfY/1rMvPBcAd2VoH
         1ErA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eirKAr6mBZKNmKhjufJjwFZZZSbSt+yDyLWJiiylbkM=;
        b=1L4XZydUrHqrkQkLRbNo8JdRs/v2HYTJHJXNfLsrKvWd+f/1o8NWqk0A3ZzOnGGztj
         qvxgASrqa9ioqiQbdoQRIf7tMjBAJcJNGsQOlF3hfUcoTUYOYHu36tmc6eTuyGsVNotW
         1x9tlA0W7XFOjhRXE55FMs7O2ZUAEsg1MazFZXKg/8r5LR7wP87tJUioh5hCsoTZLqJN
         rhTu3mBCZcnN+TiTW3ixd7kRfC38o84xFj2PydCljaDa9JJTpj1w+wogC+ABdBoSG9SK
         Gtv2oDzDR/i92sA6uC5JRszRLn7LHA2euPMs2J6o3WWMYabTG2pyyqPSn8LBKfU2175u
         YtbA==
X-Gm-Message-State: AOAM530q63e9+AKNEONs4Uedp+F0bKHyN/bXLduX2o+S0jPFBpcIZcY2
	W1Zbv1owWUwCjr2PCOAZ250=
X-Google-Smtp-Source: ABdhPJyzUvZdk4bySmrp7/R8tl79qOyraC1Cnz5sZZapMhclqJdMN9nC6afIany/lrSjWG+K/KH9mw==
X-Received: by 2002:a17:907:97d5:b0:6fe:af07:65a with SMTP id js21-20020a17090797d500b006feaf07065amr12005096ejc.20.1653295132426;
        Mon, 23 May 2022 01:38:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5415:b0:42b:305b:5501 with SMTP id
 ev21-20020a056402541500b0042b305b5501ls2375292edb.0.gmail; Mon, 23 May 2022
 01:38:51 -0700 (PDT)
X-Received: by 2002:a05:6402:d75:b0:42a:c493:3736 with SMTP id ec53-20020a0564020d7500b0042ac4933736mr22528164edb.381.1653295131372;
        Mon, 23 May 2022 01:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653295131; cv=none;
        d=google.com; s=arc-20160816;
        b=oZ08a6cfXDYUn5RCRVusOTXunt9Jw2yUsFlwWfQ9jxyRp4BGxEw1XKogz/k1kwW9Jb
         62YfVvbDL9rcDVBWSZ0B15/8Z4wCJBJIftQEJrPqJUyPrhxnb5txQKBNGLorq95rhK+s
         6VfQ0Hmmp8rUkg0g0isywfbVAe/zBnqhwm2Q9b8SiR/Nnnq3H6h8oMZxomHPguUPy9m+
         TSEjnjfNZ7d3g6n7o9NDzahHrCAH41wvswkPOxAOJvJhXtb+q9GwNYW82nbTofgiq9dE
         KpT5IbobaqeWjoq2k6gUkCG0cZoviu7gXM5KVIZvtrNJjNjHMeXv8WkPmbosb4BJxRYD
         d8Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YRSf7h1C+xevOx79dYwYdjwGLlCvPnsIvKCuQNVg6b0=;
        b=QI4gYukh+NA/8G1uZtljLIGRH0jEvOsAghAKcsy7Z/W1ehZh8w/VCNXDDNCsPXjEmg
         6/nBYOgZCc4ZeIxsT2eSuaXmxqReVwnDK/RYgJ5tOc06nyV6S1Ms4p/T2lLBBxY07DW8
         2u/G7HjW1vfxlrTnUIoqXfb25+qtIyqIEwqq2Jzt8p60yEsrVW9kXwXvjh/lZe2+S7wD
         96rvFB4pyE0S/k4Q0fXj2/09syGmeNNClaLRSgIYaso89bfJ7jAigJySmc9n4CRFOg2U
         Ty/ndEcNrhya85IAyVNFD2jxkCdNR9uh1+9YPmP8gakAmpd5gnY+xm4Z0Obze5Oj8cI9
         5KLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HnJDIO1D;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id z6-20020a509e06000000b00425adbac75dsi493032ede.2.2022.05.23.01.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 May 2022 01:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id v8so22378806lfd.8
        for <kasan-dev@googlegroups.com>; Mon, 23 May 2022 01:38:51 -0700 (PDT)
X-Received: by 2002:a05:6512:ace:b0:473:cca7:a7fa with SMTP id
 n14-20020a0565120ace00b00473cca7a7famr15178834lfu.410.1653295130619; Mon, 23
 May 2022 01:38:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220523053531.1572793-1-liu3101@purdue.edu>
In-Reply-To: <20220523053531.1572793-1-liu3101@purdue.edu>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 May 2022 10:38:39 +0200
Message-ID: <CACT4Y+Y9bx0Yrn=kntwcRwdrZh+O7xMKvPWgg=aMjyXb9P4dLw@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: update pos before writing pc in trace function
To: Congyu Liu <liu3101@purdue.edu>
Cc: andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HnJDIO1D;       spf=pass
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

On Mon, 23 May 2022 at 07:35, Congyu Liu <liu3101@purdue.edu> wrote:
>
> In __sanitizer_cov_trace_pc(), previously we write pc before updating pos.
> However, some early interrupt code could bypass check_kcov_mode()
> check and invoke __sanitizer_cov_trace_pc(). If such interrupt is raised
> between writing pc and updating pos, the pc could be overitten by the
> recursive __sanitizer_cov_trace_pc().
>
> As suggested by Dmitry, we cold update pos before writing pc to avoid
> such interleaving.
>
> Apply the same change to write_comp_data().
>
> Signed-off-by: Congyu Liu <liu3101@purdue.edu>

This version looks good to me.
I wonder how you encountered this? Do you mind sharing a bit about
what you are doing with kcov?

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks

> ---
> PATCH v2:
> * Update pos before writing pc as suggested by Dmitry.
>
> PATCH v1:
> https://lore.kernel.org/lkml/20220517210532.1506591-1-liu3101@purdue.edu/
> ---
>  kernel/kcov.c | 14 ++++++++++++--
>  1 file changed, 12 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index b3732b210593..e19c84b02452 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -204,8 +204,16 @@ void notrace __sanitizer_cov_trace_pc(void)
>         /* The first 64-bit word is the number of subsequent PCs. */
>         pos = READ_ONCE(area[0]) + 1;
>         if (likely(pos < t->kcov_size)) {
> -               area[pos] = ip;
> +               /* Previously we write pc before updating pos. However, some
> +                * early interrupt code could bypass check_kcov_mode() check
> +                * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> +                * raised between writing pc and updating pos, the pc could be
> +                * overitten by the recursive __sanitizer_cov_trace_pc().
> +                * Update pos before writing pc to avoid such interleaving.
> +                */
>                 WRITE_ONCE(area[0], pos);
> +               barrier();
> +               area[pos] = ip;
>         }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> @@ -236,11 +244,13 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         start_index = 1 + count * KCOV_WORDS_PER_CMP;
>         end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
>         if (likely(end_pos <= max_pos)) {
> +               /* See comment in __sanitizer_cov_trace_pc(). */
> +               WRITE_ONCE(area[0], count + 1);
> +               barrier();
>                 area[start_index] = type;
>                 area[start_index + 1] = arg1;
>                 area[start_index + 2] = arg2;
>                 area[start_index + 3] = ip;
> -               WRITE_ONCE(area[0], count + 1);
>         }
>  }
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY9bx0Yrn%3DkntwcRwdrZh%2BO7xMKvPWgg%3DaMjyXb9P4dLw%40mail.gmail.com.
