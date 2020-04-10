Return-Path: <kasan-dev+bncBAABBOFSYP2AKGQE443QEQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CAA511A4B35
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 22:38:17 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id a8sf2723924oia.8
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 13:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586551096; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0ESffO/v/1acZcQh30uexHlzIvxB1Zpvml/QHOD+eCfEXJHQz/GB5h5YVusIF8Si5
         ZU0HYb97Npk8pfPieV+zbdYCLyRdexCeiLC2NAd52k7RP6tV5PQzSz3gCClK4hccH7FY
         pFnZRZSPTfbNr02n+1YNAil3Sur+m15x2LGX0q2Waq+j3aYV+hYeUPmFZQn9taTHBWo/
         Mp7p41KnL2qSHWsBmDFN8TQNI0Jsf5Tf+oPX6yNYV8VVt1tcwWNnHZbmDBIiP9PqSS7M
         TjnaFFkdfgeOW/gE/oYB7HaElQwHxS3XD8k44Lcy35bSin0lcTy/wLsSJnb1dGqDhP9r
         Xu0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=SHf8Vyz18Yy5TIQSEeVoUvDQ6O8dyMM8dKG9qU6pMI8=;
        b=0uPMRYg6kZQezs/KWbQl41mV9FAWG68S2r4kJwGAFnzAJHSONnll2icvz6Tk1AfkpP
         YNR7/rMWV7xxJI3Tb/yKbflzNfqT6eTh5hvoVlL4s09XZhkWfS+vnlnodYYR+0dLgjt0
         rSrYo99VEfI8p5sBL4yTyGLnpQyOvaZCwFBFgXfjciVswUeGida7RZD5bhzHsfqQwbxV
         QkCRBzrZ18BTw67OSxSi/WVrTi+Qhl85qY5aVHjyB26wZqSE3sJMuLfW6IJGxQuYyf+I
         v26MjsRLFBmK7+LdEDYKQxmOjr3Uyq3AciLMWUYcuZWYXtIBTYUjmwpDtHf2Mav9qC4p
         WATQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wqLWQQm3;
       spf=pass (google.com: domain of srs0=znyj=52=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZNyJ=52=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SHf8Vyz18Yy5TIQSEeVoUvDQ6O8dyMM8dKG9qU6pMI8=;
        b=TgK5p8Vz3X/KrqW8TLSx2gbZ2eksY4TxZPsGcrH1smWKWjh9nrJrQbEnvGTvsUKj+E
         T8oPCapsc74yQURLQqIM63Gub0nnBCPhDV16PPBxAYcqeo8SeNpQuISxmkLDTN0VPnTy
         JmNMkJP8PHlW7nrK4cwcJPumx/c8Zsy4OLSRj5AC1ewGCU6pVbMvMUAtNZixqaQr3AXv
         2SyQSVi4Xo0VIJHpbK39OZbZy/n70J3ksJ97hiN4fs9HC6DKLH2tD2Z6ipVuI1o4ubYm
         ut8a4Pbs+ZlWiqA2bEojMSlMZj4vuRFQw/5nBaaRqxNU3gJCzwskrpbQRDgS6ilY6Uyo
         bXnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SHf8Vyz18Yy5TIQSEeVoUvDQ6O8dyMM8dKG9qU6pMI8=;
        b=rY9HtUiudq7PxeNRbxU7YKRS3AHFX8YCCb5n3NFuM4+lY3+6+rexbA3nNl5BwpmE23
         7y7fwWsfmxi96s1GLu8vX10JDG+Xs3NCw6RCTWFgUg0x04Q2KfoU/M+SLOdMex6pxi8f
         mx4RX5bOyiN368TSMIukhMuX9Ulg59Jo5s86uFvRSFI1QHwtFw+0uL6/gDZt2v90DdFh
         M/YH2yRlOQa8QYH4HuHYpRfdUv0GWAHyDPx/tYDdGR+w6RpdaFS/7RPqLLE2u9G4g7PS
         jqWOHkOgUP0quhPruI20vQ6/6AVUxOL7i7QcP2bAu6fY2wowmmc1uDHTv7UoNDcKdWdF
         ULxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZnttVg3AydLVOMkM2C21WLhiwu76C8MLdeZ+Y1/lRKAoz+t9LV
	lkZ7D6OAoJKiJ/1n83rBPSI=
X-Google-Smtp-Source: APiQypL8i5pSaI1xIjxquX6DFpGRa6svjDn36SEaG6nj50MdlQppybqei+kJp33ZVLdBbLOa/5jIGA==
X-Received: by 2002:aca:f02:: with SMTP id 2mr4557221oip.4.1586551096813;
        Fri, 10 Apr 2020 13:38:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:817:: with SMTP id 23ls5884925oty.8.gmail; Fri, 10 Apr
 2020 13:38:16 -0700 (PDT)
X-Received: by 2002:a9d:6d82:: with SMTP id x2mr5719186otp.50.1586551096509;
        Fri, 10 Apr 2020 13:38:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586551096; cv=none;
        d=google.com; s=arc-20160816;
        b=bRC2zVOrwrUQpiIm7/h/DxtMOHolcQ2Psef4YJxezmfkfTcY5Un6wiQNJn8YFGrXhY
         dJWRdvqVS7ddftdqd4lOrGNOJrNB8cl/hCNgVXmhUwLHy7wOm4rFpul115JdYphQypyT
         fTC1vjFNrUy0h/vb1DEJrg3DujY+G68PhHHd5kzBS6jd/rNQ0ySY++8CJ6NlyIk0UHgm
         aZC2a6uYQgNAEl8jJ1R+B35rMO++F1WymkUr1QY69qIXOjzJkMrSz/eIsEm/iJ9fHUkv
         FZ2IPUF+KI+mk6YDxk+orKUfUIgMBCw1WF/B6fLuNK6f4ywEsg955twjvGVfccQHyr+U
         0AKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=9PoQxP09XuQHobGBv2TanCEdLvuHXf6uD8TeAODlUc8=;
        b=UU/xxfHtXT4UnFp52LCunO0Vyf834gcXpHkf56BxjGqNaSBLQEsOlwfEf6Hif65Ae4
         UUYpBTAfd2ro96AfUQN1fyjEFvTK5rQVvS4paGSfYy48sThpSRtP7GlsNyDvI5QQIxd0
         XE4XUAXvrimJvG1BxJNfiSv6F0/Sx0dv+Jz01jYQ/zPmoAd2aRaZV9841jUZtnBuIzPL
         u8Usfki963HzYv46ulUH/qDuoj5bwtptxlThy19xY29JKt678iJnr53iaQxeqeykdg7R
         gH/5WGmXHOm+qutgwmppXKhgmQHBcqcmP3I9yUND7rGHfp9rjaSp8BHPRvlJ2jC2XAc1
         bvQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wqLWQQm3;
       spf=pass (google.com: domain of srs0=znyj=52=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZNyJ=52=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x23si218149oif.2.2020.04.10.13.38.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 13:38:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=znyj=52=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8798B20936;
	Fri, 10 Apr 2020 20:38:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5D62B35226A3; Fri, 10 Apr 2020 13:38:15 -0700 (PDT)
Date: Fri, 10 Apr 2020 13:38:15 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kcsan: Fix function matching in report
Message-ID: <20200410203815.GV17661@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200410164418.65808-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200410164418.65808-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wqLWQQm3;       spf=pass
 (google.com: domain of srs0=znyj=52=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZNyJ=52=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Apr 10, 2020 at 06:44:17PM +0200, Marco Elver wrote:
> Pass string length as returned by scnprintf() to strnstr(), since
> strnstr() searches exactly len bytes in haystack, even if it contains a
> NUL-terminator before haystack+len.
> 
> Signed-off-by: Marco Elver <elver@google.com>

I queued both for testing and review, thank you, Marco!

							Thanx, Paul

> ---
>  kernel/kcsan/report.c | 18 +++++++++---------
>  1 file changed, 9 insertions(+), 9 deletions(-)
> 
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index ddc18f1224a4..cf41d63dd0cd 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -192,11 +192,11 @@ skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
>  		 * maintainers.
>  		 */
>  		char buf[64];
> +		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
>  
> -		snprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
> -		if (!strnstr(buf, "rcu_", sizeof(buf)) &&
> -		    !strnstr(buf, "_rcu", sizeof(buf)) &&
> -		    !strnstr(buf, "_srcu", sizeof(buf)))
> +		if (!strnstr(buf, "rcu_", len) &&
> +		    !strnstr(buf, "_rcu", len) &&
> +		    !strnstr(buf, "_srcu", len))
>  			return true;
>  	}
>  
> @@ -262,15 +262,15 @@ static const char *get_thread_desc(int task_id)
>  static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
>  {
>  	char buf[64];
> +	int len;
>  	int skip = 0;
>  
>  	for (; skip < num_entries; ++skip) {
> -		snprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
> -		if (!strnstr(buf, "csan_", sizeof(buf)) &&
> -		    !strnstr(buf, "tsan_", sizeof(buf)) &&
> -		    !strnstr(buf, "_once_size", sizeof(buf))) {
> +		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
> +		if (!strnstr(buf, "csan_", len) &&
> +		    !strnstr(buf, "tsan_", len) &&
> +		    !strnstr(buf, "_once_size", len))
>  			break;
> -		}
>  	}
>  	return skip;
>  }
> -- 
> 2.26.0.110.g2183baf09c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200410203815.GV17661%40paulmck-ThinkPad-P72.
