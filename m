Return-Path: <kasan-dev+bncBCV5TUXXRUIBBXHS3P4AKGQE6PQQBRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 01E702281DA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 16:19:10 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id r19sf13514403iod.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 07:19:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595341148; cv=pass;
        d=google.com; s=arc-20160816;
        b=uufI/eAZGWybKXQZLqnnt9f3nwQGU3+BEAHy3ZFOGSw0mjdUcB7xyv0OPHk18SPflg
         7sJipwVV7mKuFfRSFsILDxWVqvq+WfFZJ7MskeHFWA3UMKTsXl3Ho5xY5dki/VUHEjq3
         gBQQqcZaZpL3lQ4mUHyLXhWj/UmqS0pnR37E7ErKzdGSACIPEs4fhpE+lte0ZccCtX3Z
         pLxUVjGW6cNzZpU6SvDrTPT850FB+YVICzk9JgNVvz2WUkHP5W56+kWunm/VrRLNIYqk
         p96esGh1B0MuF9Qg34od2zjKv1o2ZugWV+kWNehWEqVslVfJh3dzE4aEnzeunQNQYFhK
         Ic4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vviBIl+vuBWPEbLpBFnMDw126SeZYBHR9b9kVDCbsdA=;
        b=MrihkePKZdDMS1NBZCyHwbQM15ZAPqFEOd2/fbtCuGLK8e1Gls2O2q64jOyVN3CCZ0
         mKfewQ6WZagL7Zc/sGn8CoOinW5PSb9w5siD+4GadKK0q1bwKmqofnIMH3hUamBDvssi
         cLfYbSwzfi5LnTYwRHnA3Qp7RulITYckP6qVUKNOhGDPxdxPch1ENmMU1L3kN/qqR8Qd
         UXwR5pRpohpWfDvAXsn3kCw2CLmSDIpqzwwFTOmyFmB+ezILIKftWVOQalTsy9llPtxm
         PcR849MCoyRL40HrXdRRcxMeruj183fT/xakPvCngqm8TCTB86bm9FfcfgbvMUfI+ctl
         oeMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=dAhgFPlV;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vviBIl+vuBWPEbLpBFnMDw126SeZYBHR9b9kVDCbsdA=;
        b=ZWK1lqCXUesGHEdT7aNkkhhd1ixM0ZePwc/OYBb9b/8N56DvDr7uA2MvAfs6CRagSJ
         RQYcSsv+s6Nha3MadGYspUB2FucMNq8tArhHIzW+1cyXsg4kgmUfX0IfmWJtsekdZkwX
         pop7ZU1SQ1MGR7P14ARks6HXXU26gx5LgMpG+Kld2UP/Ol11HwotcFj2hrHtH8HcBvzL
         bLfNysrJXsVNGfaThLC/+mDkpJo1bxMdCEC+d2K5lP0PFfxTL22VmdUxMxWPCxtqm2FZ
         tZ6Wydn+bCssQMnsL7fGRs0I0yh+UEXdB4cySSP+yedoWxQ47rouVOlV79S20D80kLQR
         ra+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vviBIl+vuBWPEbLpBFnMDw126SeZYBHR9b9kVDCbsdA=;
        b=mk7MuEAXHlNrdU7sPRTxwokncquVmi6EYndljq/y4WxVbJmnMNikiyso8DRBN8tOFU
         mu7XvBzd1nSSn0Z9M6yqjyqdd5iMbQFw9dj2sJ+pElK+wPNHLbT9sgj3jICooCGsNMFY
         m9hWfsIZekfuBvG91Oe4NzQXvfQ8kwTMqKbrW1jfXAGEBPusRpwRzs6LZRQ8xR86cPt0
         5i+83Ri3ne3iBzQXy/dUDHHVhuYb1gqPf/dKSQRvhq2wcJlggqCeX5BP0J/P5oHRV1t8
         910Vm4ebZOJmMjyOanzpMPNIdoCyOnKpqbvFtxvQ1WYX1Vg4k1HsqVW8vnBPGew7bX+9
         7Q0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LlVg8ZtjPK6DFeCrywCBN6sSvanYMH+K7RAXQqGIZjRqUof4Y
	3SbPlZDtwbW0ukZfpqBxzWI=
X-Google-Smtp-Source: ABdhPJypj3TOiZoqH/UzAbpn13qNkAWXHiJ9LTF2vtCRnmfccofytAV2DCvFh+Bfr9EzzFuEfXd4jQ==
X-Received: by 2002:a05:6638:1696:: with SMTP id f22mr765527jat.60.1595341148625;
        Tue, 21 Jul 2020 07:19:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1118:: with SMTP id n24ls24672jal.3.gmail; Tue, 21
 Jul 2020 07:19:08 -0700 (PDT)
X-Received: by 2002:a02:6d62:: with SMTP id e34mr31417175jaf.77.1595341148275;
        Tue, 21 Jul 2020 07:19:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595341148; cv=none;
        d=google.com; s=arc-20160816;
        b=nXU8DMWugT05buyPCgofgAzJ3ZrJHCZ2Y/Eap1oDyhty++D8zbJCbD64uHgIzpSQRe
         4DpO3IX8TTiVG+uYAwho1NtJAHWbq/hLMZgfYmqVz7PXSXhUhCOvqc3fgxi3GW4CObQp
         9ldhXeXLADSdsLwYtuAe569ZyQZ2xbXNVn8REHvA58OV0pPi5Qmg8J41BTi0QRU3nDZX
         5Swy+YRg46jTj1sN6fTjibP05xj+YSUUMkGL86QG/7MqweItpS0Ly72I5EL+XTjR/GvU
         +rhPV09P1eQGLMAPFXCwt3j9OI5g/wnFr0/6VnaP2oxWyzjaXm7EG8EbVDbDACQl3Luo
         King==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eXpfk1ooDp9WmjVCuYrQskrwc9qrONU71/gOTT/8jIs=;
        b=zYkTZj9fewFCwf6lsJ5naql9FMPPxHyaQ/tvMn0ddkzU27TJiOoj0w7EP0cGFL3EK7
         8CNEgN3wjk3J4g+qr+rWxWGhGxQ+inqKno4rdKi5utWUgfxUPlo1X8as+ke4Fv+tsaaG
         NfcEAJ5u8cYxF51gbX6j4E4798GO4ibKs8mvnvKc5WHQwEXDc39ltqRLrj86RG3a0yX9
         r9aszju9EclfWLt/sEazCeOX0H+k5+cYGLxRGRMjYhVGYKySUm1caBuuwNLcW5+s7TZr
         F88oeNGmgRos37uzFYDxo+dxIYV7LlGv+MCVJobCTdfCdH6/UGhedTANPPrTHAoWVk40
         PBpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=dAhgFPlV;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id p1si1116952ioh.3.2020.07.21.07.19.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 07:19:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jxt6j-0000fh-HN; Tue, 21 Jul 2020 14:19:01 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2B0323060EF;
	Tue, 21 Jul 2020 16:18:59 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 15E50203B8783; Tue, 21 Jul 2020 16:18:59 +0200 (CEST)
Date: Tue, 21 Jul 2020 16:18:59 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, arnd@arndb.de,
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
Message-ID: <20200721141859.GC10769@hirez.programming.kicks-ass.net>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200721103016.3287832-9-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=dAhgFPlV;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jul 21, 2020 at 12:30:16PM +0200, Marco Elver wrote:

> diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> index 6afadf73da17..5cdcce703660 100755
> --- a/scripts/atomic/gen-atomic-instrumented.sh
> +++ b/scripts/atomic/gen-atomic-instrumented.sh
> @@ -5,9 +5,10 @@ ATOMICDIR=$(dirname $0)
>  
>  . ${ATOMICDIR}/atomic-tbl.sh
>  
> -#gen_param_check(arg)
> +#gen_param_check(meta, arg)
>  gen_param_check()
>  {
> +	local meta="$1"; shift
>  	local arg="$1"; shift
>  	local type="${arg%%:*}"
>  	local name="$(gen_param_name "${arg}")"
> @@ -17,17 +18,24 @@ gen_param_check()
>  	i) return;;
>  	esac
>  
> -	# We don't write to constant parameters
> -	[ ${type#c} != ${type} ] && rw="read"
> +	if [ ${type#c} != ${type} ]; then
> +		# We don't write to constant parameters
> +		rw="read"
> +	elif [ "${meta}" != "s" ]; then
> +		# Atomic RMW
> +		rw="read_write"
> +	fi

If we have meta, should we then not be consistent and use it for read
too? Mark?

>  
>  	printf "\tinstrument_atomic_${rw}(${name}, sizeof(*${name}));\n"
>  }
>  
> -#gen_param_check(arg...)
> +#gen_params_checks(meta, arg...)
>  gen_params_checks()
>  {
> +	local meta="$1"; shift
> +
>  	while [ "$#" -gt 0 ]; do
> -		gen_param_check "$1"
> +		gen_param_check "$meta" "$1"
>  		shift;
>  	done
>  }
> @@ -77,7 +85,7 @@ gen_proto_order_variant()
>  
>  	local ret="$(gen_ret_type "${meta}" "${int}")"
>  	local params="$(gen_params "${int}" "${atomic}" "$@")"
> -	local checks="$(gen_params_checks "$@")"
> +	local checks="$(gen_params_checks "${meta}" "$@")"
>  	local args="$(gen_args "$@")"
>  	local retstmt="$(gen_ret_stmt "${meta}")"
>  
> -- 
> 2.28.0.rc0.105.gf9edc3c819-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721141859.GC10769%40hirez.programming.kicks-ass.net.
