Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGNLR6PQMGQERWDGV7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E6B8068F3F2
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 18:02:18 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id h1-20020a17090a9c0100b00230353d4d2asf8076733pjp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 09:02:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675875737; cv=pass;
        d=google.com; s=arc-20160816;
        b=N3v7G79Kh27EDf2UpVOZMxrwRw+K9N7w7ropUbF5AlOwoaL+9BgIIAf7G+uHL63ehJ
         eUTfP9QSO6CFFFUVqRQS1T/OL6K+/liGloN3OeB6J4tVcK/v/df+mksC+28ndOCa7K0G
         /6ei1tz2NWpyHI3NC5YKgGAdSqhrt/IJPwc1BajMwI+mV2yTbA9gMz8nbYmXqmtpOAsr
         CQR8wgHvCDLquS9UIyJ8SbnqGH/835j2mJBk51JjFtR5jd9BAYVTBBqc9G0eFDWJbk6i
         YThgXGdtqG8azQ3LWRT6U0SJWqHXv3z7UGMwQ4FuQzR4qTe5PnDK+usNcdyfehKE+KOF
         NZ8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=B85mCYTDrl3PSpuLGgQzBvh+1BCQBV8QxLe3fA3+LIg=;
        b=wisqN7SuN/W/E1582Gwy84Yri7I4nOvTUgQGjZ45u1l2tibTQIyc4qoQ2hVsTw2tie
         ELdUaIB+KGRCEMz9xYLTgJuOB5lhlVor5jLiORViCYkdcfU6ovQJ5G20sGsXYdsuNQXm
         ljW+baEhXmM2Ovat3t+l6QZIYKX2hrhBw1NCCbE9mV+yei3x4p5fVh0KZ0danlBa5V4l
         nsEdv/VHfFkLYJvfwTebm0bWgPgvB+5rk310zZ7pIlRrnYy5013UDO09oYj9aCdtBRPV
         OEVvQZVgQEJcMjHbUBc0byl5iJWNABVXcaSviLrcyNIB6k0QoNxLDvsmGD6QhwCOT0ub
         Sj3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qkdR5pkq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=B85mCYTDrl3PSpuLGgQzBvh+1BCQBV8QxLe3fA3+LIg=;
        b=p0DaqV5xT/+tC2mOhCp0JWjXXgIvF/REM/NFFNa2XE8TGG367mkMzwb56wQzp+1z3V
         hJcddERmOuFklgQkQlfzTVxaJP/bAKn1Jf3Oyh9eni2kBKUUzILox68tYAhQOJx6XH+F
         /JwJ7SnIiLL1s43yQgSGIImXXA14c/+4jaC8qZ++6CiJHREHJeJT4YB2965ijxoU3EVn
         Een3y3U+shppBxAjk12Fywkq6+nL2nHX7sO7XP7JDrN/vgE+GOuSqDRRqe3h4fL9ODWH
         8gOhXfGo2ovldloMGuaDtuuo8umlRNSZEzyNbKMZslL0jFdr9gsW995NVnrTocxk3nS6
         tneQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=B85mCYTDrl3PSpuLGgQzBvh+1BCQBV8QxLe3fA3+LIg=;
        b=kJ8XqfaVUwv67sNZMaUtFXKQcfXHL5jx6jbSmpo+he/111mMVEPBXAn2WZ/HL2wZbz
         hQkFzsi6eExnPZq6MEJ/pQWQIE40E9LPG3EM39RvA8TZpF4nvlwyCbsFQyt4LiIyFGWq
         vUe9ni14T4cgHL/d3qlsGfL3KNGe3oTfuWHyvMQcGHyuMaUKvC4KIJfTb5NdsAsstaxN
         79r+/Q0L8Ff8G96DySlUEC48Pjji2dwC4tvqWaoQUHGZufGrr7BkPtDOFukLV3I6SgyL
         0zMxHtxs1MnIMW6a/U1WWBVXi7obxdbJru99jGogPD3IEYO1bDSaqhjqgmjsau/gWiDQ
         W6gg==
X-Gm-Message-State: AO0yUKWhE4I/wXQAy0cR+dfYe57SVbOjc+13RdNTHDsIL4ZXJhQPtqhH
	bbV0ZOF3k3oPyqCGmHeMO6I=
X-Google-Smtp-Source: AK7set/8TcxuqKiFi4ji9zkbPiwGrBeBM28WkPc1TSmTmxqOVWLJr1C5NXnG34/EE8vC7tb84W4pXg==
X-Received: by 2002:a63:7b1e:0:b0:4fb:37f2:59aa with SMTP id w30-20020a637b1e000000b004fb37f259aamr550157pgc.2.1675875737266;
        Wed, 08 Feb 2023 09:02:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e881:b0:198:ddfb:494 with SMTP id
 w1-20020a170902e88100b00198ddfb0494ls17575984plg.8.-pod-prod-gmail; Wed, 08
 Feb 2023 09:02:16 -0800 (PST)
X-Received: by 2002:a17:90b:3849:b0:230:cc7a:3490 with SMTP id nl9-20020a17090b384900b00230cc7a3490mr9455092pjb.5.1675875736269;
        Wed, 08 Feb 2023 09:02:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675875736; cv=none;
        d=google.com; s=arc-20160816;
        b=Zi1PUfJ/w33WlFWh2GL58SudDGFT1YK/oEuFXZiIfqRUBT1fVgVaHHRXAV5URoPkCS
         i6kKLXOj01TTq77e0nf7jJBdUGoFNTgZRRJwHHWRufWHUEnS1+fZlmG94GuvX3lMiOoD
         vNvg4CrR5CWdv7yDBGwCDRaCQ5cX8dONSF+shOMMC2D/mFBqOIuZAH4Suw+MxonJNQ35
         J0/e9BFfdZSPzVuKHq1khHYPw9eZZIJxybYCzWo564wb8CQQZGVhZWdOwy2X/DougkTW
         GX74yAas6lXjMiA2K3gjWQSMvNrToXQQ4sp+MipDMgzuwAHou+HcC53fyHtJTNLMs9IK
         CDlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J6GQ6k0SpXRf+NY/XuyN7DEx4advOeWO/TlcuNhkMx0=;
        b=Y31hKYIgBnZlOymITaizMs2Tk5app4Pp87Zi1v6L3M70yqiUife7/+BPm/ioW4SvCC
         bEK/cMt1CtRttv7Wb8LZgP3APg1Y1dto1p/wQ1Kegotgvo+YfhDtEl11/q4t5DosFnRA
         8L7GOSp4QCbjs2UsV8OM6965YCuYaPnlonwzA8DCdMlKisp+5uxmE3q9yPJds+HlfZMF
         Vw8RIurXu53iFC43UPSbmplR1UZdr3MrNIgQ/XEPoMA9Wshmx8OkMNP0eXb14Q612CRR
         uW3WBcPxpbg1pp++XwFSOXrYWjCaNJnFMS3wTQKjuCRbUdm8/+ZB7Bf2y5gQCBqXffPT
         ZrPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qkdR5pkq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id n9-20020a17090a9f0900b0022975f69761si201662pjp.0.2023.02.08.09.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Feb 2023 09:02:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id g2so22824867ybk.8
        for <kasan-dev@googlegroups.com>; Wed, 08 Feb 2023 09:02:16 -0800 (PST)
X-Received: by 2002:a05:6902:6:b0:82b:1e20:3ae6 with SMTP id
 l6-20020a056902000600b0082b1e203ae6mr599159ybh.364.1675875735798; Wed, 08 Feb
 2023 09:02:15 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org>
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Feb 2023 18:01:39 +0100
Message-ID: <CANpmjNP5fem=aueS1_--gxzFFOOqYTEOREMDZEhn0TMKwUP4qw@mail.gmail.com>
Subject: Re: [PATCH 1/4] kasan: mark addr_has_metadata __always_inline
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Arnd Bergmann <arnd@arndb.de>, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qkdR5pkq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
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

On Wed, 8 Feb 2023 at 17:40, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> When the compiler decides not to inline this function, objdump
> complains about incorrect UACCESS state:
>
> mm/kasan/generic.o: warning: objtool: __asan_load2+0x11: call to addr_has_metadata() with UACCESS enabled
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3231314e071f..9377b0789edc 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -297,7 +297,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>                 << KASAN_SHADOW_SCALE_SHIFT);
>  }
>
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>         return (kasan_reset_tag(addr) >=
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> @@ -316,7 +316,7 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
>
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> -static inline bool addr_has_metadata(const void *addr)
> +static __always_inline bool addr_has_metadata(const void *addr)
>  {
>         return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>  }
> --
> 2.39.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP5fem%3DaueS1_--gxzFFOOqYTEOREMDZEhn0TMKwUP4qw%40mail.gmail.com.
