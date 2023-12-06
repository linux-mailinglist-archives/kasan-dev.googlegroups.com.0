Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBAP7YCVQMGQEAHLX3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE743806AB7
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:31:46 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5905109ccb0sf417907eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:31:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701855105; cv=pass;
        d=google.com; s=arc-20160816;
        b=XcSI0wzEYzP8sPh7ocWN5//9b209njN9qknsLPFz7bF/W97A0VqW+P7C79ISgvR74P
         CCqaeZSHttA0dd/3A+bh0RduBH2HfD2oYeOK92QU/uznjqNeM1dz3Ajgk5NAPpBPcoVA
         JbMqdgTjvfcDdqhd1x6SRXT3dZXvvtJKbscoxRoTM+NtvJqgZubVYybIOZFdR+Sc5uTA
         x9irQ9obixIQGTx3FxU775zRj16+KwtpBqm5sgSuov1GQKqKE0shdfd9Z4/NA9qKrZGO
         oSxRE/WMeROh67eAczlOo57QG16RYKrvdqM9+X0ttc98v1+m/xw7TjbDuSLSrBBdVCfT
         0bNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=RFrUKIM9T0IehPsQ2VNtMIl9V77Zgywtv5ioo9ltGOQ=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Y1ZvAythMy5lv5Ckec2mDkj/Mnrmkw6nGYHDIpuLEYJ6mDxQpOZx+VFtPed6Fb1VQF
         CjnaQknjbtExX1r9oT8Bc08asBJJ4G1yGdVGu0djHmTKFkpkDnZTrJy+Gzc27wv2KqP/
         FRpLvrUAu7Mgg06HTy0QBvAAO6gfT1xGtT3FFAT84EPdjMueLUKxUp7iQ/fU7N9FMYKJ
         Ddzn91rwUauPU+8BjZJbfg1Vk43a2EgRY8cuA4kEsQydHM9Ff7z7C0swz/ZStp/vaviH
         gF9IAcUxCilAap0fJsyeWub3j/iJsMoHiZPzNMH8jK+vGJqvLaGWV91O8h0zSn4id9ZZ
         MM+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M2jqUbO5;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701855105; x=1702459905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RFrUKIM9T0IehPsQ2VNtMIl9V77Zgywtv5ioo9ltGOQ=;
        b=qvMPqgniF6VTVm7V01pe8+ycE/UvdnRQ1rHVSHzlhDOcLWuTUyAB5CsK4mYO1KFcWw
         kPkJ42ZSBf4kArTUgivzU16/N7ogaROaaa8iNXaveaWCZ6Wd65TwYtRQnIRj0dNpErNO
         yxH7jy0wrdrYBJBH1siwxPYHV1fe9mXg0lzboiYr8b0HkeOmKxpJCLIY1JAC5Y7Ow3sX
         ZfEBSnTsufB9D5zoaPV9wCShJ+GVt2d88GJ009a58gJzsxovsUJoCoM6mV5t6YyDVZxA
         io/zP/7mlDYPK68ZOmZkUm39qUmAj8dzygdY1b/ztgfA4Q9iZGfL50UprQ/TV4J8t80P
         lsUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701855105; x=1702459905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=RFrUKIM9T0IehPsQ2VNtMIl9V77Zgywtv5ioo9ltGOQ=;
        b=hBoX2sKGO2Wy0xm1y9mNVPaacpz26yQEM3idmJE+kcKCWk+shENw/aFybdppnZ4X5j
         nG/245medXe7Yz9ODI8Mfo2Vz5Dx/R5VbrXUSRVH3b0m2i8msYwt6Bcc4ppfMjflPTxh
         27plcrRKF3oqUy0dc1AClwbW6yKZ/ZERniB9X5ubIdzuPozTyYZkOq74m2YS4xtNa4+4
         EUs0MNyyCZd6djWIj7jcxQaALFE/YrlmogLaC+TVIoVoX81zyDTCbKo1C1fT0rhJAGJL
         OhJIFdF7y+vWWZU3m6IFCMyPNzYwnKVAm1Yo3KMpWto3QVRkG7yKuIjMHW/EWtIGNfn2
         RkNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701855105; x=1702459905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RFrUKIM9T0IehPsQ2VNtMIl9V77Zgywtv5ioo9ltGOQ=;
        b=fknXl5G+qtfVFHJEn6DKj24hKqNV/svNOm2gKfmhJNCjhRP+apK5nyZ1djjhlBAcZI
         Vz20dhfUV9Jc4l2HaO1S2iKSVjddKGvU+5G5s9zKPnKUUjIQ3CCEeJhVV4Wp2El6EVZ6
         kXng21iGynz6n0nsWAw21SX1oFjb9Ko4NOnOeInZ/je1MKBX21Yy7mUB1mO/WdnWA9l4
         maJo2qGxV0Cmq2X/3J5RrzT8ygACA7+UgirUMl6vsQCJkJH26xXKa44SWe6gmBPO27OP
         vkfpH0YgN70CiE+6gBoN5/XGF5rBQXo5a7aIBVwjpov43HFcDgWI5Rf5QzuSdsydz4hw
         cu5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzqiRjT6dO+znhTpSlAkVjtbxnE5Oj6pVARcLUQ8IfLTvEnaHYL
	tDaW7qJqo53i0qGGRXkrgp4=
X-Google-Smtp-Source: AGHT+IENAytTDRiaEtzjzO66Fs3dVUsvo6LXHXhiLbwc+PiljfDrRzmNGvv1aDfkDgkVIP/5B+jZlw==
X-Received: by 2002:a4a:254f:0:b0:58e:1c47:879a with SMTP id v15-20020a4a254f000000b0058e1c47879amr562713ooe.15.1701855105313;
        Wed, 06 Dec 2023 01:31:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2221:b0:58d:bf71:426b with SMTP id
 cj33-20020a056820222100b0058dbf71426bls590309oob.1.-pod-prod-04-us; Wed, 06
 Dec 2023 01:31:44 -0800 (PST)
X-Received: by 2002:a05:6830:25cc:b0:6d8:8115:4138 with SMTP id d12-20020a05683025cc00b006d881154138mr828673otu.30.1701855104558;
        Wed, 06 Dec 2023 01:31:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701855104; cv=none;
        d=google.com; s=arc-20160816;
        b=xXkh6hH+7C76h54XJf0YJ4ViJk+E4IpDEnyjx2IFKdh5KpyZjlbC2kxuhQ3p/v2vB3
         PoCHXzUuh7WPrYim0MBJH8uYmfuYBQVH4vx5zqmA0doWa9viGZixmBXDCI2zTYzvguzh
         KKrIKwttk/c6cxA2xFgT4dtmYtpAlXucWnf/ODQUM0Cp100OwSPunUKxZ0svs5nj4jzU
         lBpNVSlxBSL1ZvktOMz8kymJd4pbCAVxQcF4RKFIpgwfuKqaDs3ew8CcpASwGZ6+wRtx
         ji94Y3VgqK0DnDqqhQG50F3IC6bDB43bOzwPGoy8FatJw7OydO8lWSoft5caYNB9HkxK
         Llfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2NfF/vadIJxiqQtkbCE9WfDn53uC8FiCtOLYYf2Xy1I=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=GopR7d26oLZDPC8GFx133jrRrKC8mallLidL8asKIGQDhX884dT2fVgdAoIVaehoeT
         sObg/OfPt/fsb17fFHzgxFpIaq0/ZtfaakFzUlM47a30IGit0pksncwO/Rl1G0cnA+DR
         JhuGfv5aHhgxd+BCNJf+g7RKXvDv0qi8InEe79JCxe81mDx5AMbWZJw8pHvs64WLSxRJ
         foi42QKMuNFv4AgwfkfEkhfK/0t5dBy+2GTzW0DiUypOo4pw96LW87/MFlHweqLUhdiI
         onhsYSeL8eeaON0lfZBPxjUVtDUvDFvSqnyjoss3Ql7obhn7C2pb6CZGtBW65XVtmbvn
         AlkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M2jqUbO5;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id y21-20020a631815000000b005c624ef1158si512100pgl.0.2023.12.06.01.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 01:31:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-286867cac72so2090650a91.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 01:31:44 -0800 (PST)
X-Received: by 2002:a17:90a:18e:b0:286:a501:26eb with SMTP id 14-20020a17090a018e00b00286a50126ebmr430755pjc.48.1701855103984;
        Wed, 06 Dec 2023 01:31:43 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id w5-20020a17090aea0500b00286d686b3d9sm2062111pjy.17.2023.12.06.01.31.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:31:42 -0800 (PST)
Date: Wed, 6 Dec 2023 18:31:24 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 09/21] mm/slab: remove mm/slab.c and slab_def.h
Message-ID: <ZXA+Ur55OR1EU/5L@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-9-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-9-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=M2jqUbO5;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:20PM +0100, Vlastimil Babka wrote:
> Remove the SLAB implementation. Update CREDITS.
> Also update and properly sort the SLOB entry there.
> 
> RIP SLAB allocator (1996 - 2024)
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  CREDITS                  |   12 +-
>  include/linux/slab_def.h |  124 --
>  mm/slab.c                | 4005 ----------------------------------------------
>  3 files changed, 8 insertions(+), 4133 deletions(-)

Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> diff --git a/CREDITS b/CREDITS
> index f33a33fd2371..943a73e96149 100644
> --- a/CREDITS
> +++ b/CREDITS
> @@ -9,10 +9,6 @@
>  			Linus
>  ----------
>  
> -N: Matt Mackal
> -E: mpm@selenic.com
> -D: SLOB slab allocator

by the way I just realized that commit 16e943bf8db
("MAINTAINERS: SLAB maintainer update") incorrectly put her lastname
(Mackall is correct), maybe update that too?

>  N: Matti Aarnio
>  E: mea@nic.funet.fi
>  D: Alpha systems hacking, IPv6 and other network related stuff
> @@ -1572,6 +1568,10 @@ S: Ampferstr. 50 / 4
>  S: 6020 Innsbruck
>  S: Austria
>  
> +N: Mark Hemment
> +E: markhe@nextd.demon.co.uk
> +D: SLAB allocator implementation
> +
>  N: Richard Henderson
>  E: rth@twiddle.net
>  E: rth@cygnus.com
> @@ -2437,6 +2437,10 @@ D: work on suspend-to-ram/disk, killing duplicates from ioctl32,
>  D: Altera SoCFPGA and Nokia N900 support.
>  S: Czech Republic
>  
> +N: Olivia Mackal
> +E: olivia@selenic.com
> +D: SLOB slab allocator
> +
>  N: Paul Mackerras
>  E: paulus@samba.org
>  D: PPP driver
>
> -- 
> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXA%2BUr55OR1EU/5L%40localhost.localdomain.
