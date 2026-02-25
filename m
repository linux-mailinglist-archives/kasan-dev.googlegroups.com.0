Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6J7HGAMGQEQCFE3VQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cNovEspknmlCVAQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBR6J7HGAMGQEQCFE3VQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 03:56:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id DD6741910FD
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 03:56:09 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-35301003062sf43215731a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 18:56:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771988168; cv=pass;
        d=google.com; s=arc-20240605;
        b=ciPFv+mJeE0YJNf9tIcBC5wCC5s1bKOtEhkNcfI+rG6U3HFhZpVMyfijLSkR4Kzbh6
         L8yk5trIIgXzmTc2W3LAurWz9n6cDY4Q0Gqw0SrQ7OfVLfybWzEeQZPa91AmHKN9saJh
         mk6AfX1MS1Ul/IzYHvPsAux8CO10c3FdjZduIa5K3FfQfaBNGpsKVlxGtLQAcKhFD/8h
         UmjdAZy9A6CaJgs+UurbAxrgBwzJT4NsVOlS+UhYpRER0pLAAjMon32yJAM1jNvyt1NN
         y6YS+qJYCWngGotoNx/KUip/nohxi6E7tFfGEmIHEAMs3p+laCHmW8c5s1DvdxhficFO
         32OA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uCR3TRnPSxfwpUZsKhWKXmvuHj8wiN5eiodp+GLY1ao=;
        fh=LgSX5kNUD7nnA+uXqBpstdf55dnxkmL9e1DZxRcllzU=;
        b=QGWCPCycpdk1WGMa4CaSpNZYr2ndd1NwZzojqe7+W4V2CNcdFWhC1KcIhQNpWP7/s+
         Z7cTaIR9426uEL2QwyYyzJSVhYs4w/ZJ7ySDwzT2suBeTFwLdsUClzl48l3tqY8sPnQP
         RkU8kExn6PG/jnQKYp+y78z6KVe8uwakv8/9LteEQQiPVFsKGk7HBp6FyFdGaTGOURuE
         m7Ol0I49jVe8urQfbDbRxOwfkWn1cS4xqDDFQF1KP2DWHWGSsDjaaAZh+7He1QitO15H
         SqLZQ7TZxZGnZC3CNk2OTb2IYc4Az4ZZr1555luONs5jVRT6RwYGDpYXdzyR2VbhReY/
         fRUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rIHe8Y1T;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771988168; x=1772592968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uCR3TRnPSxfwpUZsKhWKXmvuHj8wiN5eiodp+GLY1ao=;
        b=TSHA8KpGGykwusLwUTHoPM+FSE6cm4cY/lnC/JS8J7JbimZxLaeuI/+CPkmjaARUlK
         6dWLXWUhl2gTT5zNl9lTSQTZypzOWLfNVc8X/1b1sFoBj8Wy5qaYUxDddvzdx1f1ByDF
         oyno/M0BipzW1wTZiqnAzsM508eIKNZ7JOzQcEQZkv0dVpm6BIOSipN4beZkX7k+9VYt
         pdRufz3UcQQMONCIuQqabbuccfZQf3zPwEiDsn6Q+zmFBCdZJZdItTR1QtmXb2W8FZkg
         UGoXaD6gCQgfPU+lqdofZpzI8i3BLXbKY+jDoeVRe9t/x3PqqiU/72CjL+ZeIDcL2zh/
         lw4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771988168; x=1772592968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uCR3TRnPSxfwpUZsKhWKXmvuHj8wiN5eiodp+GLY1ao=;
        b=FiHEzyV8lc4k2ZJCDVuVPmTwnnXLLDae87oiRjvipyJkosrvllstd6dg36cvbEQSJM
         R1oaf7z+en1nAXfQmbJDeDcISf/gdGxnsunpglaG8lJ8eMsVAgnxGZdivmjp3FW3ncgm
         oEVAJ4MSLXnMstzNZLav59i4leO4G2WkJTtHhvvJ+nBHFfo0Y402GmXXR9RDoI2DhQtB
         ZsbcqTfUwrOBsJe9gqIXsajdvHCuyk08UqpJWICP/jiHbwtE6sQQ3rQHhibQbYN67beN
         p3hGWBY7Yoy6EHfOlzQekrUD6lrRhMz0tXm+1XrN9NXxDEsZKMDHlZkh2bRifwmrsER+
         C6vQ==
X-Forwarded-Encrypted: i=3; AJvYcCV9/a/S1mhiCv+w+pBdJ1ewpw6+vW3wklpF02Ax/4YarlE926LVzHyTBf41Xebs+jn4o1Wrdw==@lfdr.de
X-Gm-Message-State: AOJu0YzxNEyFZgzvk/8ToK3TuKrOv5a9gD+JPa3R+Oc+y/k02AW1tgOL
	wrYulk7uFxV/eOj1vISJRBYDtdYjuvc/MVzj1G/wFYJTiD9WAYJv8juv
X-Received: by 2002:a17:90b:55c7:b0:34c:2db6:578f with SMTP id 98e67ed59e1d1-3590f1357a2mr655454a91.19.1771988167850;
        Tue, 24 Feb 2026 18:56:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FVxgLAB4/AqBBN+T3+5y/sjcg+lUL+ZMIf4pG87QkkCQ=="
Received: by 2002:a17:90b:3f0b:b0:354:ffe7:a92b with SMTP id
 98e67ed59e1d1-359105cfd0bls233304a91.0.-pod-prod-06-us; Tue, 24 Feb 2026
 18:56:06 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV6ZtZr/lU/lDYnRmdxuUFj+JaHBRIg8chbuS1georPhW6izJlHJH6o0YAlN3C7B8GKZlG/wt+wIQk=@googlegroups.com
X-Received: by 2002:a17:903:3bcc:b0:2aa:dbf7:7449 with SMTP id d9443c01a7336-2add13fe1camr9525765ad.37.1771988166424;
        Tue, 24 Feb 2026 18:56:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771988166; cv=pass;
        d=google.com; s=arc-20240605;
        b=iOy2Lunurz4WRvONbUnwgg09nzWWY23fElzkD6N9mZO3+ZrIx+D/eug6Tsu1feBbJQ
         AhapIfySjVq+0GYXjhW0gLkGMZYx/H0r3JayujzfeY5HGq1lqrbJhYYWZi2HFj8syEHu
         HmrjKeQJHpL6MxYonEo2lQBqxWx0uN/+5uLMRs7O3KoZ91U0NnnXzq8/7YoeXDSP2yjm
         SMVrdnQ1fKS8LOyMB/IEM9myJb5lEShPIftoQitksQCCjhb9FDE4Itu/9tmV7BVwSL2X
         Zvxudek57NeSpQEkXXrocIUCPAGcxmK21mxBztNh4ChpYhrSNFtwvfSWNZkdi0fmzlZP
         Oc7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TA7qDg4NCtd1YAnZI9KvDRHNA97lBlSYLdzRKpUyISQ=;
        fh=3JrSgsX3XFNXczRkuKbfYFXf9DeleBKr82BGheTDe1U=;
        b=Kw8ipdXD6sYWIx0FNG2pxJtP+kfaSdtTOON/Ntbku55v+/fQoYifzFzU5fHTifj1BG
         4CZLPofujOYnYKuDx5BYShlsriiLPdEg5SFRCONoSBupSOFk0LVJH2EKvywu3XYeIVqp
         r2h9Ahu5aoC2hGPmuVlAiYTvy6QLIWjqxV2E5t77ZWkJNq3eTBM9jWnthg3lc52hC3ZP
         lox9je7BQCVaprBSyptZE9LSmczPKuM7iiAZBLCIcfkTcE60kFK4kAUupcbyx7TwomuM
         nJFhOPj9kqoSVq1Jxqt1p0fwxwuPYEPTVpeYs/ENh+hzXVrsUXivhmzIBlhLd+Acogqp
         OQcQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rIHe8Y1T;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1234.google.com (mail-dl1-x1234.google.com. [2607:f8b0:4864:20::1234])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ad74fe9e75si3812755ad.6.2026.02.24.18.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Feb 2026 18:56:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1234 as permitted sender) client-ip=2607:f8b0:4864:20::1234;
Received: by mail-dl1-x1234.google.com with SMTP id a92af1059eb24-1277d379936so1330109c88.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Feb 2026 18:56:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771988166; cv=none;
        d=google.com; s=arc-20240605;
        b=GqZC3CYYCWIZwozPTnZQ1rkmZ1ZScmEG77djxqng9dDuO7L41TSenhFN1lGV59WD85
         JeTpHIU8sIH2yRTq3YS9qwZjQHfTUofm6ObaMbcLVdi1Dq6aPJ9CWRtTQOYiftEGQy4x
         82eyYYBiOQVKtwb9sSvZbDsGFDexu+qmQpdRSyDmbI8H07PQ4clyBrESSgMb0H9vjtXG
         RAUVKMO3O23++qKmkl84pNLUnanDSmYdOOTX/pR+29yl+qpIKsb7kS+hGCKx58p7iAbf
         PcMCtViWCcpAmBum9ZeW5FjjahDF3xh8DvR59gusMBsIipKsdWtaT4cMKGeodOc2dgP/
         aulw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TA7qDg4NCtd1YAnZI9KvDRHNA97lBlSYLdzRKpUyISQ=;
        fh=3JrSgsX3XFNXczRkuKbfYFXf9DeleBKr82BGheTDe1U=;
        b=ff+s6y2H1x1u4jvDdvqI1QSQMz6TAgWCefMfyFxOzjs1sKh+kqHNGViMiKmZ5wTX2F
         OsMGr114myUSJGIkaD57ssc/l9xupdel6IVj9BMltszngPzDwWUwZp+9xacaE1yUpSOW
         n3dUSvCC/bIpJOiGXIOBSzm2iTCtF0MTjRu0hWGek7Xrco01L4tWRA+1VFq/uwu637gz
         jiAPFgPly4MPffx9t0A7jFdU4NzhEStjFe87xo4j6+TmAF1n9aI2q66i7L7UybUHH63X
         T2CCIZeymxZzwXsZf9hZJvdbWgfHpdHydy+bGyF1ATWz3w+4MFYmpwuz/BXTMrZcv02W
         9PQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVXtHq/jloSlsOL50v2dqN0ueB0JY+EwRquvjZC2kNEcB5W1IJoF1qIWQgfu+kJtVzueIYIJc47E8I=@googlegroups.com
X-Gm-Gg: AZuq6aJiR9mYv1r7Dsif2cYEBPgcrZBj9TnJ94jPPPEPz0Y9RHU+CEusOp+cEEGC5q7
	upkjqad10eQ3QvkjJPnFTi4NI4ZEZncOR8istqv9nj+9StazWxCYifHx7X/JWc+7F6wxMZEXgiJ
	Qi89qAoCob9PLS5XDdSa7hBrUr8ftchojy47lUjoE1/VAa53oksMqpuERhs6ezKtF4rAz9NLVFr
	i4SFIffVR7ksI0zpU0Pk2Xg5XPsQeKZNCxtzfu5MWPwhucoCRfl1o7s4opnmhZb3oO1VapdLwkV
	eVrB01UyuSpVeF7M8ppdKU139MyuyD6nB2fPKg==
X-Received: by 2002:a05:7022:608:b0:124:a8dc:c1b4 with SMTP id
 a92af1059eb24-12781eff3c9mr273321c88.45.1771988165187; Tue, 24 Feb 2026
 18:56:05 -0800 (PST)
MIME-Version: 1.0
References: <20260224232434.it.591-kees@kernel.org>
In-Reply-To: <20260224232434.it.591-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Feb 2026 03:55:29 +0100
X-Gm-Features: AaiRm514aelrg8NyTSJLn7ZpuNuUcLbDTH1_TAzrgxY3Zp5UfRGLpkjOsY51Yxs
Message-ID: <CANpmjNNyvrrOi3m6XUg+Hq39qdVHTvD88ODotYjPzTwC2Kh9pg@mail.gmail.com>
Subject: Re: [PATCH v2] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rIHe8Y1T;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBR6J7HGAMGQEQCFE3VQ];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	HAS_REPLYTO(0.00)[elver@google.com];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid,mail-pj1-x103e.google.com:helo,mail-pj1-x103e.google.com:rdns]
X-Rspamd-Queue-Id: DD6741910FD
X-Rspamd-Action: no action

On Wed, 25 Feb 2026 at 00:24, Kees Cook <kees@kernel.org> wrote:
>
> The call to kmalloc_obj(observed.lines) returns "char (*)[3][512]",
> a pointer to the whole 2D array. But "expect" wants to be "char (*)[512]",
> the decayed pointer type, as if it were observed.lines itself (though
> without the "3" bounds). This produces the following build error:
>
> ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> [-Wincompatible-pointer-types]
>   171 |         expect = kmalloc_obj(observed.lines);
>       |                ^
>
> Instead of changing the "expect" type to "char (*)[3][512]" and
> requiring a dereference at each use (e.g. "(expect*)[0]"), just
> explicitly cast the return to the desired type.
>
> Tested with:
>
> $ ./tools/testing/kunit/kunit.py run \
>         --kconfig_add CONFIG_DEBUG_KERNEL=y \
>         --kconfig_add CONFIG_KCSAN=y \
>         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
>         --arch=x86_64 --qemu_args '-smp 2' kcsan
>
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> Signed-off-by: Kees Cook <kees@kernel.org>

Reviewed-by: Marco Elver <elver@google.com>

I'm assuming you'll take it through your tree.

Thanks!

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: <kasan-dev@googlegroups.com>
> ---
>  kernel/kcsan/kcsan_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 79e655ea4ca1..ae758150ccb9 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
>         if (!report_available())
>                 return false;
>
> -       expect = kmalloc_obj(observed.lines);
> +       expect = (typeof(expect))kmalloc_obj(observed.lines);
>         if (WARN_ON(!expect))
>                 return false;
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyvrrOi3m6XUg%2BHq39qdVHTvD88ODotYjPzTwC2Kh9pg%40mail.gmail.com.
