Return-Path: <kasan-dev+bncBCF5XGNWYQBRBWPRZOVAMGQEL73KFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id ACAEC7EA991
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:34:34 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6c415e09b2csf5468450b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:34:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936473; cv=pass;
        d=google.com; s=arc-20160816;
        b=dOTIlGkl63zKVrrD+UPK1zV8aLXLKoJLsr+MvdREa9PAWSUHFt/BKHiCH9MStIxRMD
         gyPUQMKgAnrlnqVfNJyhwG8J5E4W0i5MlmOe76E1Hk9w9PUsmq1TVLVD0W+e6mnn6z/e
         NUIpa16u3TOeNLmiqg96GGJK082vy11ag3l+8D5o96cgHBAe4hvVr3Gti6bql/0l0PwM
         JRrB91gyWZTbpE023dVvwspEoQpHml6o6TtJO/J+qjhQSJGnJ6/mwxLaqT6XmXIiTHCZ
         cX88au3XXElhi4jAgRKs7NUao+Ipw8GOTx+lbBhAuNVg8+Yb+mqEJyUlO/f2xL3GSU73
         Gsxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=opjseGJG63hMLJvWibFDB7r5QchOIcCp4opO6ZABrtQ=;
        fh=YHqt3Dw+fn2eeacJMiNRTirV9wErvZHIsjqlqoiMUGY=;
        b=iBRvFgyt3sgWVm0XDRpGXbjTK5IRoCYIQpapOFBWPKdQViV+vvlpBzuWL2z6R5Aryu
         keohvd4XmFppC3syPstFmQYpZgWIu93wi7T8USwHgZ/8hkCftRcSWKraD2lgz2lfK/NE
         J0A1cuVN9qP8HZmcOD3wlIilZpl6pjuFhLJbOyd1pyRp6nvpvhV23uEQ4OyqRAru8MRz
         S2iHN6Z/WQWtMJEZnOKVNbCF2cwvVVvCl6jBiZ126NVKIro2sRg3ovr1m46XRk9opB1n
         /Q0jEkjGU2dMeZ3U01oC/xJrXslvxZwS35fyNB77859xa6XFdOaLm5bSGH9h+Wdp6xf2
         veHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FGArmrIy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936473; x=1700541273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=opjseGJG63hMLJvWibFDB7r5QchOIcCp4opO6ZABrtQ=;
        b=E3ribr8AvZ1hdIc6DX+n/W2UvZzXGVP7Xz5MzDJP87E0c7bmF9l11xmQTWAJAeyf3e
         CK48LTje8iRCJ2UpyCqhrMrOyNWbL4tyKh9GXUoSw/jVsRTgOqjPRo41KhkRLzRp9tfz
         sfRcsTTkAgLJJH2ibAdNoMujS5leVtmQJe62Tkxe0Tre4AazYrc8bBdnBC5O4LQ/dxmr
         /V0AwUOo2XTvyF79+SKyiQfthenO0LUzkyxns/JQQuOpvUyYPjkVqM9ueGeu3pRSeewW
         xurXxL5Q37UpHKy04iAfuz6rIPqIrD1l1Rz9P+MiW30SaLoOHuYT/k99Qigc4BkIZpxr
         BsPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936473; x=1700541273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=opjseGJG63hMLJvWibFDB7r5QchOIcCp4opO6ZABrtQ=;
        b=S+kEBlfdNbO8KFlgQVp9bM4L7VFPLxNo5GZWRutTSazDG4J9oYVXbzkaFFdGeMtseb
         iDQTg7TrtJvcM/r/c5vJM4sa8fMofrKYVac6wHv9vHO2NQgpJT5v8+gOpK6xuxFg8sq2
         5VJLRBPshCO+gwKgilnp7VXSiAWnR7sPBoQIwloBTeWD7aGFrsq5XKnUkASgCUJVJKfk
         y7cmA+x3vSd9EcLwf+AIzjdutuOwHMC+KLOJdeybmx7mDANSNge35nlEJ4UPYjmhMc7A
         IuQtjRGb7WKmOqAPw2VZCIOKyo9ip4NZB0eaR9xPkuSm/yR7JHelRFcTkk023G4tk18z
         5uwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwjY/nTZjKepj6lwzXcToSg/UQnG6BGEhvF2P5Vp+tTtP7gLqfK
	3zTjCxxQIOBRT0YNoVDWhSk=
X-Google-Smtp-Source: AGHT+IElCUZJkQWRMU4dw04nugG9Es6pWlkOBiNWjAbaCwo6vCD2UTHPMXG6VxyB/WGFvtGdrR8ggw==
X-Received: by 2002:a05:6a00:1790:b0:6bd:f224:c79e with SMTP id s16-20020a056a00179000b006bdf224c79emr7346946pfg.11.1699936473272;
        Mon, 13 Nov 2023 20:34:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4003:b0:6c3:dab:31f0 with SMTP id
 by3-20020a056a00400300b006c30dab31f0ls3459349pfb.1.-pod-prod-07-us; Mon, 13
 Nov 2023 20:34:32 -0800 (PST)
X-Received: by 2002:aa7:8a4f:0:b0:68e:417c:ed5c with SMTP id n15-20020aa78a4f000000b0068e417ced5cmr6238888pfa.32.1699936472308;
        Mon, 13 Nov 2023 20:34:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936472; cv=none;
        d=google.com; s=arc-20160816;
        b=G/xBKLpQ4oU8BY+I9mcufJlS0vonFttlBiiSWC9ZXQt5H3GJzYw+AP+uOxTBna3yYF
         5YXwBs133h0KPTtUmvO9BxQJiNhrC939FmEeofsqwgYjyM50JbcfnmXoCgDS3m9gk9VW
         oN31FhmymCQTU9AGxCns/+QhhOs2pWp0NIsC53Z4gB1EZ4QXvzEhN5+f1FM53aOV8Bo3
         3go3mPlfWxGGqTGnSbFzJB2uYOSrqbMxG5T7j6o6ju6pucsrWvBqirfqccMM/qxFRKGM
         OS3QBsVCwQWdwGi7TN9CuG4lYI9RjL9mnCNitfWVk1nAzUo99yLgfZgaFflnlagNOWKm
         4c2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=o11HARQxoCvg8Gx5zjjgZkRsPvVu73rMm7hpUxapQ0A=;
        fh=YHqt3Dw+fn2eeacJMiNRTirV9wErvZHIsjqlqoiMUGY=;
        b=lYzE5Y0tU099JeTZVG16t/zZoLZg9hfd3ysPR39unfjbInhenR4LPF14aZ5c3VhL+I
         x1AuaTE+fddhxWKSwAVwB3KKZSBpXji+/Ab5BJ7quA5E8ZvyY9VT9AK492uIZD8qA3Xb
         shirSVvJbGOy+uaU8n/WAy4rBilixfaYGnYU0qHBkazKv4VqysrWjX7KfHoiYTYUAcOs
         eDezBNeFns6Lkyz3S5S0jtLKklXLEpwXOqRqq/GdYL1+XGAsTvwImudQCNLcDUR0aBCM
         yAMRBWzA6xH9P92Z39RvqL7JOGpOQ/Nt5MApGvu9tCdUIkjWEj3aQHzoG3QfR041Ozqb
         C1Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FGArmrIy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ay33-20020a056a00302100b0068fc872aba7si406048pfb.0.2023.11.13.20.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:34:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6bee11456baso4443449b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:34:32 -0800 (PST)
X-Received: by 2002:a05:6a20:729e:b0:186:7ac3:41c8 with SMTP id o30-20020a056a20729e00b001867ac341c8mr4469072pzk.56.1699936472009;
        Mon, 13 Nov 2023 20:34:32 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id a13-20020a170902b58d00b001c465bedaccsm4835731pls.83.2023.11.13.20.34.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:34:31 -0800 (PST)
Date: Mon, 13 Nov 2023 20:34:31 -0800
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
	cgroups@vger.kernel.org, Mark Hemment <markhe@nextd.demon.co.uk>
Subject: Re: [PATCH 08/20] mm/slab: remove mm/slab.c and slab_def.h
Message-ID: <202311132032.1BB9A17@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-30-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-30-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=FGArmrIy;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
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

On Mon, Nov 13, 2023 at 08:13:49PM +0100, Vlastimil Babka wrote:
> Remove the SLAB implementation. Update CREDITS (also sort the SLOB entry
> properly).
> 
> RIP SLAB allocator (1996 - 2024)

/me does math on -rc schedule... Yeah, okay, next merge window likely
opens Jan 1st. So, this will land in 2024. :)

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132032.1BB9A17%40keescook.
