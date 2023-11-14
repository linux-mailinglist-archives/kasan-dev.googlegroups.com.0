Return-Path: <kasan-dev+bncBCF5XGNWYQBRBMHIZOVAMGQEWI5KVEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 408467EA965
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:14:42 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-357f318d076sf354565ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699935281; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6UVzt3Z82MnR33ToXboqf9Qjx/Zz6vgy0gI9MEbMe93dmMeNPxndHRC01sEpn5/eI
         GgB7wls26s9LiEKs2KfPEB43nUwiH7I/Y5k4sH/N7beUQgFZmatId7Q1+NPB+K4SuRx3
         anUV4qWqc3jrJCmhT4nI0vZpGYGBIoDf8U1B3WClh1E+oVv9BuM+8j89Aae8meeUDZh6
         YVue4MFzXGLszZ5BF2HWJkSF51ksWxi1DIqoKN0jdUiaO6IhGqblVbt3AhTlOPtK7ttw
         o5iFEnGyjcy3GN4EFQ1QlmpuqvnTCFjpVxnRk+/ybJVUiVJccx3rgwoWD695oHk9wbgQ
         nxjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NdQtI2Qa0MCAvGZrRiuiRdVpWYgS0Zh+3Sqt3I79lZc=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=NM1oF+FfNW46jSpeFWWTj2P8fhTU6k9wiih9omn1xvydMwznr+4jBNH+GkKs2lk//e
         CEJEJABedx+6fleKFDi8381W0ZkRN0yRgNEgQsotESO+ydJ0hLfqSSGk7SqbLM+zsOIw
         KTWxdvrXXUcJA54TyWxDWbeDyKzx1EBGW7Zt2tm+t6tX6HgSLpGgPZxzo0jTY51jS32V
         Y0nrQCX7avDCCiOdvl8hcyviwN/xiauOEs66+MRK4VgHzEJ7knNzW1dITlDOU/Xs2a/n
         7JjrX4Cbc+DD806sagiFcKKNM7d7KyF3GXPBZ8Y+iajX71Ce7S+7GLBqDlDrB0qBDXZc
         f9Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=i4tIPJdC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699935281; x=1700540081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NdQtI2Qa0MCAvGZrRiuiRdVpWYgS0Zh+3Sqt3I79lZc=;
        b=R8NWkQj29PM193EM+AphEGI068UZZyr7JUTNakAy1LIZKJ3wMZE2izvXZ2alsolAej
         +6zl2xUctvhzdWEodqp4mUPQfXHEijPOcwps4cUL9Fp5A5Pj4KGkJhWyrQjERUtjm0+g
         OJa6e6ATcdonP9ITAa64QK05iBErdxJ3tI4SeOfYIhXzaZ5O+BNuIiFwnlzO7UXn6C01
         pXzsSNIUS9Zzqxwj+oBYniiC3uENQ4yDXlOdGiQcWx+yvPW05ebuDIDtSq7e/PG2mOZ4
         Dsw/yJgoSr9tgzdPFiggrMpTqi+Su4J+4DFPgB+rOzyF0b68kwnlEpAtZmh9IicxQlSC
         WWvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699935281; x=1700540081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NdQtI2Qa0MCAvGZrRiuiRdVpWYgS0Zh+3Sqt3I79lZc=;
        b=Yd6WvJ45KNcfjo540DdbPpTc/HeWw15BB5JAjPVEkSwtYv9uPR7IzpGVCYpiMsGcNH
         h+mTAKww+Mz6/UjVSJNLDVpMsJIh2p7+pAMd15GxGSvP/qB6579EfEYyaizJscim3uuX
         5uarT7ZWqrMfKIWUIvlz8bwLWDpQqgNb9Msj/ev1bgN2SBCV7cxLfi4+KeQFd4u/7LSk
         ol6g4Y7e+VxczON46QgfOwTUJOBbs2chM6OBhWKu5Ly+enJpYy2wC5PyEc4pmG6uxTZx
         0QqJ8kYkeNhAu8NaE2NzYtAft8PR3IWGxemjncgZin9v9dIXiVaoknIWe52UdON++uRz
         8Lgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzBm30GGR7zFHAsNAav+lALeVGZynslYp6IHQNJoYXfvK0LodbE
	yf/++QY1mt9kf9nJUSprZ9c=
X-Google-Smtp-Source: AGHT+IEB9vuMnv3iWdosfRlWUHVC2ueS7DrtYHRF/vA5y/i5B/4ywEJ/q38ehXVowDkANUjj2elVAA==
X-Received: by 2002:a05:6e02:1a06:b0:34b:adfb:60d2 with SMTP id s6-20020a056e021a0600b0034badfb60d2mr139291ild.14.1699935280835;
        Mon, 13 Nov 2023 20:14:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4b0a:0:b0:359:4b03:d945 with SMTP id m10-20020a924b0a000000b003594b03d945ls3350327ilg.1.-pod-prod-09-us;
 Mon, 13 Nov 2023 20:14:40 -0800 (PST)
X-Received: by 2002:a05:6602:b07:b0:7a6:7e93:6f86 with SMTP id fl7-20020a0566020b0700b007a67e936f86mr12998343iob.10.1699935280210;
        Mon, 13 Nov 2023 20:14:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699935280; cv=none;
        d=google.com; s=arc-20160816;
        b=rIJPfEggFdCgNagIx2hG5pm0quyMu4F8WaPcLBs67EQh8ku1YIuIaoRFwIbVGJ1ovr
         B/y5BoUCCOWyNmwAy0RZ1vNIVgEIoHXVKIEpqlrI0ZX9YGyU1As8h+GTnVOlEkvDg1It
         BJqAIdrLg+0+H3vzzYHkr1NzOO0bwPlqtidhYZtjuIXWJJ4uAOTVqmVUBJ1t8R/AxmpV
         Py0KRYQP/NrBFbPp26Mn3ohVXxUDxAlAMPciHM0PF+JeRI+cciPOsxqGDXvzl5jrqurM
         hGqNjKT4aMiYXtXIZdf1jANSRF/ShLrktG1sNNnAqxN4zg3OAxyW0IWfMWljrUsMNLvC
         qGHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z2Esu3+YQCIX73TjWrtGheLocNwWakeCmjYailfwoZQ=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=zFKf26Tkc2hMVD/P94+/fP2YKOanxm6o0Ksqb4HjOfJwWhz/p/vvJL1fmAwgf9EQFh
         K7FimOV0Mg+jwvCYOujeQbT+UhWhdeHck4/bReGTZJY0tqORkoNeZoxdUW8Vu/nib75u
         SLZUUiy9dEPpcmC7sjLhYAhHQaQHWwc4myPiO0wVwb2+Ld3zQHP7jVf8ABFaudh7NNBm
         Ihn9pCjT+hdj1u+yAjsKL7a5K0RHwcrhFVo5OvvLnGmiHkbBXWcmgBl/N25ukbye9sQA
         9QfHT3ifR33JQWSyejIdtXefvMNKsaZGwpkrLox5Rll0jb9tXu2gb2QfWpfu1nT//oZ/
         Nc1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=i4tIPJdC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id cs23-20020a056638471700b004312fb02a61si971834jab.4.2023.11.13.20.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:14:40 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6bb4abb8100so4303658b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:14:40 -0800 (PST)
X-Received: by 2002:a05:6a21:a598:b0:186:7842:ad0f with SMTP id gd24-20020a056a21a59800b001867842ad0fmr5685978pzc.31.1699935279698;
        Mon, 13 Nov 2023 20:14:39 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id o9-20020a170902778900b001ccb81e851bsm4739949pll.103.2023.11.13.20.14.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:14:38 -0800 (PST)
Date: Mon, 13 Nov 2023 20:14:38 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 03/20] KFENCE: cleanup kfence_guarded_alloc() after
 CONFIG_SLAB removal
Message-ID: <202311132014.809B164D@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-25-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-25-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=i4tIPJdC;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
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

On Mon, Nov 13, 2023 at 08:13:44PM +0100, Vlastimil Babka wrote:
> Some struct slab fields are initialized differently for SLAB and SLUB so
> we can simplify with SLUB being the only remaining allocator.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132014.809B164D%40keescook.
