Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4HQSKKAMGQERU4HYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2458A52B59A
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 11:12:17 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id p5-20020ac246c5000000b0047257761087sf819694lfo.7
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 02:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652865136; cv=pass;
        d=google.com; s=arc-20160816;
        b=CGSqIFm0br+gK9i8DKNlHXerYlIjkPHbl/sKqWM/6DSQr835FtnLJ3jyetVsIrAdQ1
         VRI1f7HuMLU3NDPrcKb7w5HszWXD110JON0oc8hV0LPiqwkaWwcJ/kLctgFGfn82ls0a
         tHR60/fP37CdOpPlBB0iaPNTQUrXyXL39ih//JmUAT/nc/wyrWs0XmfaYyPzLvkNYSjE
         t68fm++pZG6vKIIIYf3iu1YMtDWg3hK7kcnAJ2HMhAHlD9XZgQnnf6kgMcm6tb4JC9oO
         qSjmRu4Bv7PoqevW1QdYiO7Du8DqoOLq0V+Pr/HBpjTkfsrJYtl/NUoiumm9WBys/Bga
         DkEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fzZ/C2PmEP6ABe53hRRSZaZBqqzaMzeQ47LgJClnArk=;
        b=E717ZXha8fvlL2VOrE6WoFi9rYx7NedY8TC4fHaUX8sXkll+pnwptcz7M8jmedeWlP
         8YqRGAWpmkN0dgKG/CTExowaRRr4OBvUNSceApySgIXa5AOM1gcR5Iy06qjDVkpz347j
         nH7i0opVhiGsFAFrjGQ3PpCek+o6Ja0WK1Fu+wYLwdJSfoLbu5hBpu1wfv5Llji2BjS5
         DbLokEsZ2Jju7XZwhqffxFhsZbL9+ocsLm1WIrgynQGHimbQ3cmFScW6/5omjSTX93ZL
         88fT4UGUBUj/pS2bN6+V8em7kk+TwFJ9FKcfuw9xyqNi5/nVVQ4GV4FDtEzkPPPXzYW9
         iMCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SOI2D2KT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fzZ/C2PmEP6ABe53hRRSZaZBqqzaMzeQ47LgJClnArk=;
        b=ELElUbId8wUpPw2RjDaeOhWbo6U0JvcczT/aYB2zD+86ICYQtEofvULdL98ZBhmchV
         WJw9cG6QVlK+KQBhEeUGYSvSzaSzYwOK9RgcdZg9qMDx8cQLh5cg7FAyCUurpiP09bya
         ki2PF6xQzmnlVgTpjPK4zS2aVu5PMRMKzIqNTYCtyy0TLyL99Ov0ZMbb3Wtiuu+rRxr9
         fprHwYS7JNxjfgpz/IJY5Xjv/eTwqx05EVrIL5Z0nszXi8RcF9Dkrgf0LydEV0YL4mds
         2LMv6pkCN4G9MZbuLNVI70bS/W4a7A6pACnN+SewAp0iZGo4AMZBEJr3zn72eV+GBr/7
         H1eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fzZ/C2PmEP6ABe53hRRSZaZBqqzaMzeQ47LgJClnArk=;
        b=O8iI5g/r6iFZJR7NC3Q5qiforZRR4aMhJEfTArIHuUhTPNFOxQ7mODK9gVB2taipcP
         v16cUoVjkLW0qxTvPbM8lzrOYPi3zdXR+5Ikhv5tkyQ6tPxPxi8cUGvb3mH41oChhY6s
         MgvV8jcR8guH1L6x5u6AXI0kDi0o4pbJwJRRjif7r2Fcad1is1XS0J7WDpx0jKlCMn5K
         lETZLsUIpkwEUqUEJdLhP2Of6PqvJUdCaeN8y/wa64EU2vg7OTKQcaf2fuAQ36wSteAB
         oUnsB0O1RofUnKfcBn12579YA85vhJLyMHG+JNNWQz8I88o04jMCNIIPMI5EM7IdUWDE
         BRgg==
X-Gm-Message-State: AOAM53036sx5lXv2jIKXCP5/F/WNVc/DVUc8/sAP10UinOxNfYDF6qIv
	OsBGHoPSSAkTWb90OATk524=
X-Google-Smtp-Source: ABdhPJxT+oyOiAlrYHfBVuRrJ1NRzZ8A8r1/p0Pb12QBP489jU43tMy10Zu3Vu7XFJOH0sqay9HoHQ==
X-Received: by 2002:a05:6512:15a9:b0:477:bc1c:f1e1 with SMTP id bp41-20020a05651215a900b00477bc1cf1e1mr809496lfb.375.1652865136597;
        Wed, 18 May 2022 02:12:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls13600120lfu.0.gmail; Wed, 18 May 2022
 02:12:15 -0700 (PDT)
X-Received: by 2002:a05:6512:33d0:b0:473:a25e:f9fb with SMTP id d16-20020a05651233d000b00473a25ef9fbmr19707749lfg.98.1652865135068;
        Wed, 18 May 2022 02:12:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652865135; cv=none;
        d=google.com; s=arc-20160816;
        b=hA/pfDkXTNJhLyApsfYQB6ZadPZNte+YLzLDFhI2w4Qo8bBWerXVz2i00X+H1GsyjI
         Re6Wo/4rT4+aW5+4trg85rU8xeZs/VOkuLK2qjPnMQg02OuDtTa9IhgA9GC8vwUj4xPi
         oeZmuai2zZQv3v+vOmldI+haf6h2E4fdBwVKeuqvXZd+JmgkNyJ0P9Jf3vJIPdNp2EHs
         8nkH81VWHnUOUEbdHB3oTD660hoaKT72jV57vwVf9rZp0Rb7/PiqHRVc53+Cj17C2Ccp
         8j4cmnnk1/Ml4hjkHswvU3uAaGMAqQyhW3TyUejHG8IUYpCIKC2LaDeTiVXffmF0S7Xp
         QD9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XHuYfz9NNkR4s+xXexwOeyYdq/ChFuLByuA+gJMb9K0=;
        b=q/oTmji2cZMqL8DG12UAZgcnvvQrdExPDuLPafS4HDFUbVqT20q0Q0tC6AlOWgYPRV
         uWB4of5T8Bga96DdFLO6T0tcs0n6D0gKlbr3fVuw9257Q+1FFKnX/wdx49t0vi2I5pG3
         GsLv8QrHp0lX7vxzhWK44reQLlkKXNLzGuto19qsIPe+wqe/vZfT5OtEaCQb1Nus5/ds
         Vf01B1jg0vpeuqiRFkFm8yNcKbIbe+3rVfJ4TSMxzLXvdhIdI2GtQAoeTIIqxL31yz6U
         ff2iPkxu5H5c9dkRijtfOK4LrtioKY80WEvXldwLceGa4d/8bnGiZ8ix/MQpt0wsZFTO
         u0Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SOI2D2KT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id be31-20020a05651c171f00b0024eee872899si83988ljb.0.2022.05.18.02.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 02:12:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id t6so1766535wra.4
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 02:12:15 -0700 (PDT)
X-Received: by 2002:a5d:6791:0:b0:20d:c9f:6b00 with SMTP id v17-20020a5d6791000000b0020d0c9f6b00mr10059512wru.462.1652865134422;
        Wed, 18 May 2022 02:12:14 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:450f:9c92:a170:5581])
        by smtp.gmail.com with ESMTPSA id y21-20020a7bcd95000000b0039489e1bbd6sm3738685wmj.47.2022.05.18.02.12.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 02:12:13 -0700 (PDT)
Date: Wed, 18 May 2022 11:12:07 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jackie Liu <liu.yun@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH v4] mm/kfence: print disabling or re-enabling message
Message-ID: <YoS4Z+zJoKkiHUY6@elver.google.com>
References: <20220518073105.3160335-1-liu.yun@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518073105.3160335-1-liu.yun@linux.dev>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SOI2D2KT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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

On Wed, May 18, 2022 at 03:31PM +0800, Jackie Liu wrote:
> From: Jackie Liu <liuyun01@kylinos.cn>
> 
> By printing information, we can friendly prompt the status change
> information of kfence by dmesg and record by syslog.
> 
> Also, set kfence_enabled to false only when needed.
> 
> Co-developed-by: Marco Elver <elver@google.com>

Signed-off-by: Marco Elver <elver@google.com>

> Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  v1->v2:
>    fixup by Marco Elver <elver@google.com>
>  v2->v3:
>    write kfence_enabled=false only true before
>  v3->v4:
>    cleanup
> 
>  mm/kfence/core.c | 6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 11a954763be9..af0489d4d149 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -67,8 +67,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>  	if (ret < 0)
>  		return ret;
>  
> -	if (!num) /* Using 0 to indicate KFENCE is disabled. */
> +	/* Using 0 to indicate KFENCE is disabled. */
> +	if (!num && READ_ONCE(kfence_enabled)) {
> +		pr_info("disabled\n");
>  		WRITE_ONCE(kfence_enabled, false);
> +	}
>  
>  	*((unsigned long *)kp->arg) = num;
>  
> @@ -874,6 +877,7 @@ static int kfence_enable_late(void)
>  
>  	WRITE_ONCE(kfence_enabled, true);
>  	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +	pr_info("re-enabled\n");
>  	return 0;
>  }
>  
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoS4Z%2BzJoKkiHUY6%40elver.google.com.
