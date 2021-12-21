Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MFQ6HAMGQEDYWZGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 93CB747BF4E
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 13:05:01 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id v190-20020a1cacc7000000b003456d598510sf1175915wme.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 04:05:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640088301; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0BLiV/43YbY8H1KsXcjgigtg3HBCCstFJOMS3E9vVKabanwb1Mb8sGfYGl7FCOrmf
         Q7tDK68gfrMUgLQKmhp8dirSuI4RsvE5H+kBgXQOx5N3t8y4Kwii9OxOqnap+iaHlkvV
         zf7KahzRz9fSPBO/UU0oKkKYAwWUkU6Nau6yoe/yVHdIEIGaTvVdERpN4Uoy7KV+OmVm
         kePYwj4LkXotGXFvgYxPgpm5vKTtZe1JHGXBOwb+lM2firRaU/PdCMwAfcmb2kX8gelT
         IrvN6ZkPs1Q1JuMv0gSiRvXpg+oVRr5K1YyybIfflSP/Npi5uKvsqelvhI25hkkqVJx9
         aF5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=86GniQ/worC8PvYUrIPgFtIZ3JpRuJ6fsDucO9U79t8=;
        b=A14rB3l90EixfO+LeYMNaIiOtbI39DVyqINiehQA/yb8+ho+f+arW7N144K+GgYQZI
         e52N2IWDEaaLmZOuzxZhMC6EVVgjJCVov6T5desC2c2jBMokjI4+EDaB8hHfwr8Z/Yna
         Twbng2hk2sbkFiiayx/vQUISpEcVpzWBs9A4PilMkXOAz3zfaT/7Vfp2gVfY1P3dV+j1
         fehriTGh6CKwjyX8eo8pQXUDYt3xr7cHIAz2XVgRZ/5yo7fOsT6Oph9Q45aKqHd1xHbs
         vpByCFgLXbcHocthwCeg9pMcD8eD7z8/hjmyOIhDMOGfHo45lxqP4OLKWY+y744rybrA
         9oKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LSit2U/a";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=86GniQ/worC8PvYUrIPgFtIZ3JpRuJ6fsDucO9U79t8=;
        b=ocm2ytdW//qxfx74PlpA0m6dmDoB8rxZwXSgmqP7QBmR1pBKNxp0M7N/lsWBROrV4c
         uEf+IXzA6BBtdcnIP8+ksSxzCj8JQjwcL8eWDQXjroJNr5+0SAT3RZI3gVrfD+3XCXKC
         8aTibNQvBDBhkxxFKDnZsFQy+NfBID5OSLk0SX49UqJ5xi+Wm73y0KolqVlyVR8XXPXU
         N9CG+I/yMAQ7Rx3Sdx8lUjrqZJENxsqt4jVa/31P5p0tKnbYTUboQZww9jJ8iZhoBRrD
         i58WPCDVYv6H4A4dUcffk+0kwBarv9/6LSi4H9M/oIMX8rch1EpIWSL8c3Vpbbpxvfl4
         9azA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=86GniQ/worC8PvYUrIPgFtIZ3JpRuJ6fsDucO9U79t8=;
        b=YA5Sb52rcoel6j6Xhe6ijpCP8B5VEDRTt4DIwuOuydf5IcH01Y03gnFK4sIiQ2pxJ2
         RgDdSxymzCqgMl/4agzPoHMc0+MDZgl9Wh3GUIYRD1xnYx5jETOPRZlPvT7aY5ypXZjS
         XUHqjUNekwU8IL+ay6FB41I/Q/h2D9kHgSXh09KtNDOt12fa3Ri2osDbZkA8mI/W6PB1
         L2sSJISH4y1MtDMpU+IDniPXQqTGMN9cFzowEiDgXnC8W8zImkr9MZNiRXKKdPVf6Orb
         JRDyEFMywUV4zGs1uVvfsbyrVkODhwFb6DSmfkJIUDQdUi2X1FeoRaLvJ9ugrBc57tTr
         9rfg==
X-Gm-Message-State: AOAM531LP35XKMMv172FpOPdV4IWzyqgrnYMe6TKkVHXqUWZ5gR6yeHp
	vEbIxc3aNuN9f6wgz6Zmii8=
X-Google-Smtp-Source: ABdhPJyLOvDmgJCvQWT7/ce5A+PQv9Wlu7PyfWoLKXPY7WjQNuGyYxG0rSsqBofs48OWfB1pG3kXKQ==
X-Received: by 2002:a1c:f608:: with SMTP id w8mr2564432wmc.50.1640088301231;
        Tue, 21 Dec 2021 04:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls9143290wrt.1.gmail; Tue, 21 Dec
 2021 04:05:00 -0800 (PST)
X-Received: by 2002:a5d:4090:: with SMTP id o16mr2375795wrp.692.1640088300250;
        Tue, 21 Dec 2021 04:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640088300; cv=none;
        d=google.com; s=arc-20160816;
        b=YJoBa5eTYmN2VbuaHe7hAUNz1tvDzSmi58ypPtTqHEbNQdM5sivhPOuGyLt96oWz1C
         c6bo0MXnONxzSLUFV2d8l436r9Nj8cpBn5Z/SKvEWkNFlo4CsUlJNMmILZya7yxLsPB9
         WkhojSMF7lpx9DNVu8Wigl6Rhep/USwALXC+MhmG1loOaXE2iSXMWHyY5Tn0OwWDjyD3
         GrhbeqTEm0aooaS/bJ3US/C41JVJVJ+Yfxa18QlZrWvIQQFkJqbhqffX/+Njaq3pi3Ln
         cAn9PJpO2V8BvVcyPOzJe0boEsQrCK5GAzX41ykm4UOj/GP4yBoRkf5mFq1wDi1yDgwo
         ijBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=eXNffp5VqHHL0eX50PhTTvTADrPv+mi1B7sj1Ld1suk=;
        b=dBlI1YHZS1nO5E3Mkc3INQWc+66BZrMRC8ZK1tdRzln+NAq9c3r4/L2l2xUEnVvx1w
         ACT9Sct5vApXabwP65BNbYAs25R3EktrDwEovcE618SLI/73UVdcaBY7HYSXY/sbbqja
         RMXH2+mcGj1weAgIdbwoHnn0h1uph8ynR/0MHz+PvHRD6KYjxxCQ2T/iDkMIzZuVeYz7
         LwV2w0wP0X2D+6SeyZ/Oe6BTosFDwwpVKa8TilkG3SGCvU3xYfp9MfDpjZQQSW98vlSC
         hYO+6gC+zR/iEKpZffl+Yxqcb7NdOEbvIyiLWBveYlFt+MuLQwRTScfBhRKjJtupS8Ev
         DTDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="LSit2U/a";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id o10si119947wmq.2.2021.12.21.04.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 04:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id y196so8891554wmc.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 04:05:00 -0800 (PST)
X-Received: by 2002:a05:600c:a03:: with SMTP id z3mr2455711wmp.73.1640088299725;
        Tue, 21 Dec 2021 04:04:59 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:87ff:799:2072:8808])
        by smtp.gmail.com with ESMTPSA id e18sm12945286wrx.36.2021.12.21.04.04.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Dec 2021 04:04:58 -0800 (PST)
Date: Tue, 21 Dec 2021 13:04:53 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v4 28/39] kasan, page_alloc: allow skipping
 unpoisoning for HW_TAGS
Message-ID: <YcHC5c9ssDrcnORl@elver.google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
 <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="LSit2U/a";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
[...]
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define __def_gfpflag_names_kasan					      \
> -	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
> +	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
> +	, {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,			      \
> +						"__GFP_SKIP_KASAN_UNPOISON"}
>  #else
>  #define __def_gfpflag_names_kasan
>  #endif

Adhering to 80 cols here makes the above less readable. If you do a v5,
my suggestion is:

diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index f18eeb5fdde2..f9f0ae3a4b6b 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -51,11 +51,10 @@
 	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define __def_gfpflag_names_kasan					      \
-	, {(unsigned long)__GFP_SKIP_ZERO, "__GFP_SKIP_ZERO"}		      \
-	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
-	, {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,			      \
-						"__GFP_SKIP_KASAN_UNPOISON"}
+#define __def_gfpflag_names_kasan ,							\
+	{(unsigned long)__GFP_SKIP_ZERO,		"__GFP_SKIP_ZERO"},		\
+	{(unsigned long)__GFP_SKIP_KASAN_POISON,	"__GFP_SKIP_KASAN_POISON"},	\
+	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON,	"__GFP_SKIP_KASAN_UNPOISON"}
 #else
 #define __def_gfpflag_names_kasan
 #endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcHC5c9ssDrcnORl%40elver.google.com.
