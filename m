Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSHP4KXQMGQEU6BCTKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F07687F29F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 22:53:14 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1dff9fccdbdsf19778725ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 14:53:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710798792; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZAb3urtocaFEbpy0Hazcg9SIkc47sKjCF1DCHl8gXq/ihG+zYvmIpzg+lEnm1e+zbc
         BG6EPnxggNa9qKa/RUVqANzuaylRIr3Jl8EMl7IOiuMUlAeItzZLGEjOMJIimW6RvSeo
         3UOaXXvg9LcY63s208RHKmBFMKz18ZLtDhLZCBH2WqBXIgfu/pBKRtZ9VMwbgi84vLXv
         eyDXSEUvDp9R5MAcCkD2n+1YN3dvvvIflj1F9kihV7VVjSSlJWQdn17CNJkiaribau1t
         kFrTMj7Qw1CerBJHfP6mcEUTGnmK20yXJ6K15EmUSm+eZdkh8JWCwHHqbo4ZfVCBpC8i
         bpWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2lUx3peYVQdhVbLSWO2KUDaF9st2jgxOGA4kDnhEKo8=;
        fh=BS+CLULiWSK1bZT5crOkBEcsrlQOmJclrTzgeduX2jQ=;
        b=d3698VU/xf/pHup45s+YqgIakGg9YYfy5Meb6xERL4B05Wi4vO+4j4kwzgiSzgbbtr
         AEYUuZH4AZHKq/OPm5UZF/EQm17dqmC+Q4vE5Y18hn32s8U3QfWd0Wy3ZaHJwRt8Tz5K
         beKTGEp6Gx9CXd1VkHUTZJDNyVrfkEAG6NGGjpV7vYxu1uTYkjSy0jRFZYGSfmesxT5p
         i0YMt6/xU1D9HaYOfL4Wz4gWNZU++fW5vgq6CgjrQYRHa/x4R313l4+cQAItxNpdIevF
         +Ik7odT/WYtipchTFJYvZDP6ruRaZwBWEyZKs1uQIgTt/i9EJ4I5dJo6d0xOobRpovNP
         tyyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mH8UQyoY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710798792; x=1711403592; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2lUx3peYVQdhVbLSWO2KUDaF9st2jgxOGA4kDnhEKo8=;
        b=rbgKE5+I7ovLy+tN83ABCr2JpeQfyAhtPQj1+UUfG4Em4aWb0+P4fAdhhNa1H+sCU3
         lMvTXJ6fiG6cNIadEIIsaP8u/0aaSj11u6OysDNf0tSSfw9bW3FcJIrXiHSHXpoyHnJg
         1kN2XNMjeJ9ghuAU+G99psqYid3Vl1+OvmAhT+v67THRVTgighL+CUYriOQG5oeF4Oz4
         r+IjS7O3cayZa0t1pjVQ/HIk2K4p/2YWsD3PEe4A4sa7o3FAyd8/qe32oCEDMNgeGL0l
         oFQq0vHYh5Icq4WuHJn/8fY8D9lFLiG5Or1Vhyy3GkuhZx29PRtvxeT+Uq6oXhkY+ovp
         cXeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710798792; x=1711403592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2lUx3peYVQdhVbLSWO2KUDaF9st2jgxOGA4kDnhEKo8=;
        b=tUupGad+mX+cxWTcZ3AhgRd6jm9I1ot3/zM1nMK1/0py8JSsKb/4DwoAwEDkT9jbmK
         oa7q4Urci4sr6/KQPRCpDBejaifhdy+AFF69+KN63xxUDxZnltsCPhENwk+JdH9CDc3o
         FE448MXrHsaG4xE98RhwxiM/81njd4jpgyiPC9J91dijr4UaE89q9iTqmrYorf/fGvod
         Jk4BqszDkDhAjletVNKsoX9ExhbSkbLdp/dU/bBcEbYUecYbIX9HjUf7Qhhp51thCo8S
         sfxQP+HOqfkslBZfe/SJJ3Ta/VP7HsJ9eelDnsItu2sB8luhfhkFRlBuIqLTylGYnvD8
         B7rg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWZgjpTjr0DT0Dsxhx8kvq+jk3f87tA7i6NJrbp0wvt3H41D2JayOuDbdGAF/fJTVZFmt14foGigwE7mCwzFOmtji1u82xdg==
X-Gm-Message-State: AOJu0YyemTb20sBKnJOYg3HYz0FXmihX61WP5dQFgTiX+ynf2qe8GmuF
	jvJNDcyVZpvKjuM6Y5F4wzRijLFr8zuSBwQheYXbZfCd5Vo4G31F
X-Google-Smtp-Source: AGHT+IHM0wIm4r5sd4ucpEhBStoW542+dXUlrSJsnnZEJHv/exZlGVwXkICXceME9bc/OXxAMzPgqw==
X-Received: by 2002:a17:902:dacf:b0:1e0:1bb2:b38f with SMTP id q15-20020a170902dacf00b001e01bb2b38fmr5964835plx.59.1710798792377;
        Mon, 18 Mar 2024 14:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea0e:b0:1dd:90b4:787e with SMTP id
 s14-20020a170902ea0e00b001dd90b4787els3003202plg.1.-pod-prod-03-us; Mon, 18
 Mar 2024 14:53:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyDXgjTevbYj/kCGG8evqV8Y3QQrMYTh/uQH6GoMkDLYjD+W7Db3H+pY4SnvZsjSMcNMPjs5KYOnaIjyEfiodho3GJtXvI+c6bEA==
X-Received: by 2002:a17:902:f681:b0:1e0:36e:2bb9 with SMTP id l1-20020a170902f68100b001e0036e2bb9mr9196349plg.11.1710798791090;
        Mon, 18 Mar 2024 14:53:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710798791; cv=none;
        d=google.com; s=arc-20160816;
        b=u90EvC90UefmDq5tvAknMbIA6eAPV6IZpUDhligRWugGGDSOjybw8JqZ4K0i7uVCCt
         wMHQYjoLM7Npedl67EG5p0r2Gzok+LXAB6/Dh9oR680x3hl35Q7NnXD2IW8wj4o7l4bJ
         jQXuy8uXmXqc7x8kBIXw8n0mKY5W60IyztorDkBBZ55sI9CJP2A35knojoqaqzDuTKpl
         5X1AVv5JYawxZWF/Y6OnzgTLcvFxwBVD8hlqMoWCuL2ATgPjESTROGdDtDROkBH9f/oU
         +RcBGVuVAByqI9z/TRBdxBkgnPfsJSnHOiKDhYftOK9o6FYpGfe4WyFY7wAgR/IFRUS3
         BLfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BtzX3B0TpCLSG/r678eRw7F3f4FGYZRbRXL/8dQddU4=;
        fh=c4ICq5cCOpgpRRIgeJx5J7zjMIxteDFQulL2QblhAxY=;
        b=kQNDI8LjGWN4fkDU6MEjP8Zb/G4IdDz/L3ZBz3D0XKzJVpOwR7T9DqBOKqVpG2vmck
         RqePNlkbu8VEenjxUfSgxtV6V1bWttzHnWwtOozSrbLxw9OH3J+6eg/yJF/3vwDM2Wko
         B7g9QQWKOWjECY+YMayIVHoNbpRbGDYNuLNn+2fTzjpd/4ggirxVjo9kYey+YPqBCN9q
         2FftwlW3iv+MUwNT2baTRt9pwldL9mUgnHyDI2dK1JYrwaBtCtppDISsWoTkQOIXbKvZ
         83TOj0SpYxaFx7MEBNwnwB3un5YnGomHc2MkHvb1dSVPObQY6C0nn5Yh/sNjqsuJvanB
         lIaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mH8UQyoY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id b6-20020a17090a9bc600b0029be51c3687si15571pjw.0.2024.03.18.14.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Mar 2024 14:53:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-29c7512e3b8so3774863a91.1
        for <kasan-dev@googlegroups.com>; Mon, 18 Mar 2024 14:53:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC3CSj4SH7VF43rQYVgggdnpHPL/p3tIZAtEAiFltK83xRyd83JVk/+0zmQCEHBoB+HqPrpUBRQBUjMTsqrDodomr952J6q+GN2g==
X-Received: by 2002:a17:90a:12ca:b0:29d:f086:9e44 with SMTP id b10-20020a17090a12ca00b0029df0869e44mr8248526pjg.46.1710798790706;
        Mon, 18 Mar 2024 14:53:10 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ok5-20020a17090b1d4500b0029df9355e79sm6731928pjb.13.2024.03.18.14.53.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Mar 2024 14:53:10 -0700 (PDT)
Date: Mon, 18 Mar 2024 14:53:09 -0700
From: Kees Cook <keescook@chromium.org>
To: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
Cc: elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
	Abaci Robot <abaci@linux.alibaba.com>
Subject: Re: [PATCH] ubsan: Remove unused function
Message-ID: <202403181452.500EF35300@keescook>
References: <20240315015347.2259-1-jiapeng.chong@linux.alibaba.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240315015347.2259-1-jiapeng.chong@linux.alibaba.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mH8UQyoY;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Mar 15, 2024 at 09:53:47AM +0800, Jiapeng Chong wrote:
> The function are defined in the test_ubsan.c file, but not called
> elsewhere, so delete the unused function.
> 
> lib/test_ubsan.c:137:28: warning: unused variable 'skip_ubsan_array'.
> 
> Reported-by: Abaci Robot <abaci@linux.alibaba.com>
> Closes: https://bugzilla.openanolis.cn/show_bug.cgi?id=8541
> Signed-off-by: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
> ---
>  lib/test_ubsan.c | 5 -----
>  1 file changed, 5 deletions(-)
> 
> diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> index 276c12140ee2..be335a93224f 100644
> --- a/lib/test_ubsan.c
> +++ b/lib/test_ubsan.c
> @@ -133,11 +133,6 @@ static const test_ubsan_fp test_ubsan_array[] = {
>  	test_ubsan_misaligned_access,
>  };
>  
> -/* Excluded because they Oops the module. */
> -static const test_ubsan_fp skip_ubsan_array[] = {
> -	test_ubsan_divrem_overflow,
> -};

But then I'll get warnings about test_ubsan_divrem_overflow() being
defined and not used. :)

-Kees

> -
>  static int __init test_ubsan_init(void)
>  {
>  	unsigned int i;
> -- 
> 2.20.1.7.g153144c
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202403181452.500EF35300%40keescook.
