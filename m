Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSEMQKQAMGQERFHRNYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB74C6A80EC
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 12:19:37 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id v8-20020a9d4e88000000b006942254c4bcsf3107997otk.22
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 03:19:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677755976; cv=pass;
        d=google.com; s=arc-20160816;
        b=WpX2lX4LM9h5L/KvGmSbwrdxJaQ0BO5jpesQwzCgPs0KX4fmqv6+MGF/zQgiHXifse
         /ahqmrP2pqQF5nQ162qiVCSXa/h5IURLKyDokri5iLa894TvoXa6iZaIZSGvw3FoIdS1
         iG8VwjjDZRFOIaiXwVQdVQImKIBGPYv2w/I51iXM7lsbfjJ0SdLwcT+mxoJx+Z5Wr5EE
         N9kWH+30RWQkkzZDeLg2L1qvpsFj0HmYe/Z07q0LQJ51mAu0Zyd7O+gIWCZN8vQNyMBL
         EsBUE8c1BLf8ecPKFiYGHXBky2kswCzMFOIF5z3Gf6lFob4DTl/+g2R09R0EXk5LsOGo
         KjNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WpMHWiMrUDd4gcEswmAZRyhR/RhzxJQ1SS5DvfVOFLk=;
        b=FzZdFB/IYv99EIwC1whKJEOV6eldYtoarMOwWfiUlGORdrDnG+eAFi4hJmrCl4Gfvc
         FVBF0dRTGEQ7cfZxN15j5Xo/0x4/WerMTQCVXKxEFrLePiF1+Ts+NFnX0HeEJesKIeGy
         KPHyrpZnkCDfQiKSkt73o9p3cPI3Z5ZVC/JIugF65GLwxjbdLdV6JlrYXEDPqa9IMe3G
         yys5j4JnlqzK6nsuVe4/wWLn0IPIyi61/37o4Gill4hLrt6AzUgFJUR5uixXm73auTlV
         8hXrNEsnQ93ud8ZSMmLrVBF0MMPlKEBHQ8EIMG9ZCNU944d+iFf3xmt8NZoWgbDgFYzu
         28DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LwDWn5Nt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WpMHWiMrUDd4gcEswmAZRyhR/RhzxJQ1SS5DvfVOFLk=;
        b=K4xkX6RE7L7PYE9emxH+M/9b8eIdizUjxCkkmZV2NipitBZfPH87oCbz+KsEaFl4Bt
         7P+E0wpk/4fPWff2LIe2fZdQPnRuZXO6o0ED1h/Km76MuAcq0KPPyVLuv0BTt/j+VMpP
         nRwo7QrBQakyFvPUCrQIQ9723Iu7jvzq7q7yhKb8MFJ3l8G2Y5wjBkTPpXtpesubKPIF
         Jkvfv2HFDuTLyWoA9CHWh5io8pbNN0j1oW2QtHbGoEjdtoA4H3TbgsOun158R0VDOHbm
         orqHC8WL4MMgFenmVF4EWH//L5E6zrNcX8qjEnfzu6NHcA+D/z2H8Ji6tr5PF/qtgFo9
         liAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WpMHWiMrUDd4gcEswmAZRyhR/RhzxJQ1SS5DvfVOFLk=;
        b=x30MiqRP9oBT+JUCDOyLu2FDMthQT7gxX89PjAhLSFI+VAl8BwcO2YOIrId6im01fF
         7p/MCl0NxkaS1ylYTToO4txKPBltZwcnxJBoAFRsSintNtlq+Jsr+hGYioZ5Yu1Y4ZHT
         CZrjio9TMH0hIFqkrBFHDlP3NUVSIPOyfCNRQariL+Wpw8j6xL5gJTXqQ9rY+MmK16wB
         qdyzV0UP+wewmRFBc78pkE+MGRrL/0BEl/9jTCAKBYDSBIqhCmgtOwb/CQSYl7kyJo8D
         8jQbsW4q0C+ammjiEjclnTUbu5ANnNqG/NXBpDrC0yJ64DjC41fM2aGWA91Jl1qSmtRF
         6AZg==
X-Gm-Message-State: AO0yUKVoKrt6GpxS3RklLcrnPxCH9WMtUqXuqP+BrPTTWLS2E3R710v/
	vyf2de4eQd8iKgWA3b2pDEo=
X-Google-Smtp-Source: AK7set+Hk1AGobhktdo85rQ5sRrlN7c+vjX0LskFWd7FcvExw5GNnybViWCa1emnjNgLbw909Rnh8g==
X-Received: by 2002:a4a:c585:0:b0:517:bff1:77e with SMTP id x5-20020a4ac585000000b00517bff1077emr3252501oop.1.1677755976106;
        Thu, 02 Mar 2023 03:19:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:44cc:b0:176:41ed:2af2 with SMTP id
 t12-20020a05687044cc00b0017641ed2af2ls835707oai.2.-pod-prod-gmail; Thu, 02
 Mar 2023 03:19:35 -0800 (PST)
X-Received: by 2002:a05:6870:f10a:b0:173:2f02:2931 with SMTP id k10-20020a056870f10a00b001732f022931mr6615853oac.16.1677755975582;
        Thu, 02 Mar 2023 03:19:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677755975; cv=none;
        d=google.com; s=arc-20160816;
        b=wW7IFwiyB9vchZTtlMwqn8SSvIaXpSvRlmrBu5mMjb7NZ4+JDvW1/gAHrEjW0Tjc+j
         LfvQPA1d31CDC3k3FA++GhgXtzTbfSM32f3+E/r1gzWJu3Yy0OTdB3oQudnOF6McxPh/
         Wj4sDZ4XfB2Jja3LyCbnct6vGD71hTdRydsbJhz6dl4PhYP+sAW/5x4OT2ne5ILQcTeF
         IDqeHb6lW7WFilrXVq+crDAjLjqF8ufT6Tv60pFiz3v+TCD53NMpnyxcDIu+yk7I4n7+
         JdpKTqMmVZaXNGHN+sDYNyY2c+SBxEjLXvyHuGkWW8l8tWZyyckbLzeY9rgaafDFpQeQ
         dO9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UpoYsX/wcX1BKUpmOF97rT/5TG0r4tQZUsDLiVIcjh4=;
        b=kZ5NRqwag3IRuDuuR7ZZsAKmpbcbQOMPxTfPFt1iFE8df0flfAwAWk4J7FynGBgjT3
         De7J0qKe5JKFYsdyPP9HeRAb5oyblJMVZdUpJqL5/A+UYW9gNb1xGBm4DweSVdmqP5MG
         YAu2tG6ZW07hvOW48muJE8TXWxaK4U9xPz75UVQz+Iii/cxfR0Y5moXvOiUCOR8no1Dm
         UdhPZe34RVm13b2OiR1nA6Pf/Z6lZTQpYbMhOnD/QDmnXf4KO0LytPIy93hs5i3TA0Hi
         MwCGV99ViGFFsEHiPLuJzd+KHhOtAOOSAgMp62SIEnfrjZ68LCtEnUmbg5cijNjUdI0e
         I/KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LwDWn5Nt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x934.google.com (mail-ua1-x934.google.com. [2607:f8b0:4864:20::934])
        by gmr-mx.google.com with ESMTPS id bf11-20020a056820174b00b005176d876205si1390747oob.0.2023.03.02.03.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 03:19:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) client-ip=2607:f8b0:4864:20::934;
Received: by mail-ua1-x934.google.com with SMTP id f17so5906244uax.7
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 03:19:35 -0800 (PST)
X-Received: by 2002:a05:6122:e0f:b0:406:8403:4e64 with SMTP id
 bk15-20020a0561220e0f00b0040684034e64mr5028140vkb.2.1677755975009; Thu, 02
 Mar 2023 03:19:35 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <20230301143933.2374658-3-glider@google.com>
In-Reply-To: <20230301143933.2374658-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 12:18:59 +0100
Message-ID: <CANpmjNMd6YA1FGaE2ePsHU4OvTz=-2yXxCOwPDyDpCFTD5ns2Q@mail.gmail.com>
Subject: Re: [PATCH 3/4] x86: kmsan: use C versions of memset16/memset32/memset64
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LwDWn5Nt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as
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

On Wed, 1 Mar 2023 at 15:39, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> KMSAN must see as many memory accesses as possible to prevent false
> positive reports. Fall back to versions of
> memset16()/memset32()/memset64() implemented in lib/string.c instead of
> those written in assembly.
>
> Cc: Geert Uytterhoeven <geert@linux-m68k.org>
> Cc: Daniel Vetter <daniel@ffwll.ch>
> Cc: Helge Deller <deller@gmx.de>
> Suggested-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  arch/x86/include/asm/string_64.h | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
> index 9be401d971a99..e9c736f4686f5 100644
> --- a/arch/x86/include/asm/string_64.h
> +++ b/arch/x86/include/asm/string_64.h
> @@ -22,6 +22,11 @@ extern void *__memcpy(void *to, const void *from, size_t len);
>  void *memset(void *s, int c, size_t n);
>  void *__memset(void *s, int c, size_t n);
>
> +/*
> + * KMSAN needs to instrument as much code as possible. Use C versions of
> + * memsetXX() from lib/string.c under KMSAN.
> + */
> +#if !defined(CONFIG_KMSAN)
>  #define __HAVE_ARCH_MEMSET16
>  static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
>  {
> @@ -57,6 +62,7 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
>                      : "memory");
>         return s;
>  }
> +#endif
>
>  #define __HAVE_ARCH_MEMMOVE
>  void *memmove(void *dest, const void *src, size_t count);
> --
> 2.39.2.722.g9855ee24e9-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-3-glider%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMd6YA1FGaE2ePsHU4OvTz%3D-2yXxCOwPDyDpCFTD5ns2Q%40mail.gmail.com.
