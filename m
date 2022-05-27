Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBNPCYSKAMGQE7YHUHIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24C705367F0
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 22:14:46 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id n13-20020a5d67cd000000b0021003b039e0sf928785wrw.12
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 13:14:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653682485; cv=pass;
        d=google.com; s=arc-20160816;
        b=BY5kN0YDO1I/lQIiCa5BbEAuEpSVo5x7t6ENfON6PWxXaEy/lHG1mUSmJ6V/VA4qRk
         daB6jTPwrskhXgySGjssTlQuy+W/TiyL+fJlraujnkamPNVPwIjeD/7ubDbWRcfntJgk
         6QjBwUdxbCSSsh97j+J/ZXmnMJvXdZNr1C1azWHTPO17w7vkwgCwHa/4K/YJ3RsN1yUu
         0rmn/b6LGSrSXfYhWWb0dnE1Rky5mVdVNTgTs1rnc7MGPYEMPRvZE0a1gJn+wz3YIrFI
         nDp447md3cisF40Eg6n/ktz7La/YIA9meISqr/NpgegIjVDaU1oOW8udlhfsTIplUzXU
         kWIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=brbqWUfjKBZgx54HRVGHAANh3nXQwymZY54PvR11kbU=;
        b=ImZLqaQHQfxksoDyIflXV6q/XmXYE94eFJRIBF+Ns7+HL0ENkZU39EKDhmRt/1ixZm
         ofi5xtTH4YJIyNMcRtXYsYQGL5sm1qkg8wJKtaM9UDcHWmIG/bC1v9BEIPQQnLPBl2M6
         khJtbuA5VCMZBDCg6aA3Xvkd9t5TJLFrpn2Clv5E+RY4BRU4KkQLxXZGLjPb7P6EMm1C
         ZbLH7K5HUAIhCGoifOCVxjYiVhtIyqB/zFtUbrLxdwaMdKmqncrDfKB7r3doRir6ybU4
         HnDhVssWtlKh4cfMt+CJP7xZEuAlv6d2/PNw7qRrxme2+3WLkRoAGLXLc13/eaezptKt
         DWhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=kigg8XLp;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=brbqWUfjKBZgx54HRVGHAANh3nXQwymZY54PvR11kbU=;
        b=rDhB5iOceToa1WmR2IZ19HwNFek+tWYaz5PHOV4uEGCzZBqKjaPd0tTMyUQDbhiB5w
         Kh/9k49iPF1YaRHGHw20teHD0R5l6BPcHXYytkN7vTgUzxOv9/OhaS2aQR/Hj/PsZ+HL
         mka2b6j2CHc0dNPYwuD8XIDrRkMt5jT0FR6C1BoVPI6mXVvYH2imjj3XWscd4oD+7Wy3
         8asBh/2KbYbjhiJa2s7G+ANRElWZ9vpS5jk3fgl7pllu7w1uPk8ZnMrPWh69YKaEpv77
         hLLfyUU0YZbffKpxVGUkR3C/V/t3A2Ca4qjhUhGxFNuP7/dIF1NyRKyuPoQm+df5uatX
         3OAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=brbqWUfjKBZgx54HRVGHAANh3nXQwymZY54PvR11kbU=;
        b=nYramesnQiyJhlafOlMCQ/rkc6/NkePwzjJe41OW1Wa0iTOc/ydpjTGLvWMkt66WXS
         sbGTYUtblTs2zZ9TfNcsKZgmwTCzfxj6w3tr04JAdI82gGsMRtgNrTQ0/f1719q8Pwzh
         U9h/XKSe0gWfEzuMwFOcaZmu5caAgyCzsJHGNcY69jGBwtdcmENDF+6hwBU4C7JYP7hN
         zWRu7FQ7eNLQ6nKjwo7Zh3htpNhcKYL5x5+pvyHwySkIp+kH7Qeresxf3wfcMq/gcybB
         sqBiI4abkHWUbn/qJauiTFMFKErzY7BGmlLABRLwh9+8zQe2AwIDDgJoU+wda6clVG34
         IzQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531d6RTNlXtfi9PAOXx7OiKyg8+0HzFcmXUe3DgmMUbUWH0W6JP7
	s0SWhQpDqZ4yp/I4D+YrJBw=
X-Google-Smtp-Source: ABdhPJzG6E247kN+6oU7GjT7aU0B/5msUJYdcNDa6CfpDdUajMAlHD4KpdRYPsr8C48Rm3WhbqEHkA==
X-Received: by 2002:a05:6000:1448:b0:20c:7be8:c2e with SMTP id v8-20020a056000144800b0020c7be80c2emr35727794wrx.692.1653682485471;
        Fri, 27 May 2022 13:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:350f:b0:397:475d:b954 with SMTP id
 h15-20020a05600c350f00b00397475db954ls6406715wmq.0.canary-gmail; Fri, 27 May
 2022 13:14:44 -0700 (PDT)
X-Received: by 2002:a7b:c4d6:0:b0:397:79fc:99c2 with SMTP id g22-20020a7bc4d6000000b0039779fc99c2mr8463357wmk.127.1653682484458;
        Fri, 27 May 2022 13:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653682484; cv=none;
        d=google.com; s=arc-20160816;
        b=ebVCNnmHK5pvloUKmdX+PNJJwtXbe8XphZNZ9EYLgljE1gzBBVkBfN/CLdmOtc/H6i
         28wXHCO1TA41wDFY1f7+rA7c66PJMjD8mIboCE/ow2+TeSgmnGzKp1cF4uGOeJP7Pxp8
         2/DkjTZwFAcJxL33lYuHKnALXUsT88RQs2SMrCk8FYONQ78VXWtIZvIU1SWu/iq1DNQs
         qxzrERE0bTVaLWzhcE1VXqZWaK4PzjfU99NdYVdLbZybJ1ddg/kGM5NtHExROSxx+rz/
         73F28kAXM/8pkUYMdAbHBhz5wWLbIQ+yDiD5g8QDSTLY/n+rp3511rMrQ89GiVDX3Qf+
         d+Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=/JbY6NIfEA9XeqiPP6KIr66UKiO0C7oMhJ4ZgGJq/uk=;
        b=Ka0X3eAJEQB8NwMUjGNqQ7CF7OBV3yAdAQ2MxKWo05vX/tGPHBL4Gawpqt2Ikhos4u
         seDSMOX8o8NCw3qgJey1GArKrZsQ8EK1v0DxupC4dnhuxFO4StBWkuYoG/rbmxyExahY
         xxPC6zWIL9RfHjQCK6Dtr35mksEGRvm/SL/7ZibIJ0nLvYtTSKo7Q1HOVYeJt5UmDeyS
         c2Mcb2u/xq97RKarK95YUHylUcELx2UPLQ5P8BXEPTp7f5Aw4S5TGUEICrACnvBo9YGI
         upsxCQse7m3L9iKR2PEJRPTz0ZHLQbvz3xhS+C9K8fGVyEOefBpU2MttVfe2kORtGhgS
         gpDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=kigg8XLp;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id bd26-20020a05600c1f1a00b00394803e5756si162257wmb.0.2022.05.27.13.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 13:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nugM3-006B6d-Au;
	Fri, 27 May 2022 22:14:39 +0200
Message-ID: <de38a6b852d31cbe123d033965dbd9b662d29a76.camel@sipsolutions.net>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
 linux-mm@kvack.org
Date: Fri, 27 May 2022 22:14:37 +0200
In-Reply-To: <20220527185600.1236769-2-davidgow@google.com>
References: <20220527185600.1236769-1-davidgow@google.com>
	 <20220527185600.1236769-2-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=kigg8XLp;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 11:56 -0700, David Gow wrote:
> 
> This is v2 of the KASAN/UML port. It should be ready to go.

Nice, thanks a lot! :)

> It does benefit significantly from the following patches:
> - Bugfix for memory corruption, needed for KASAN_STACK support:
> https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/

Btw, oddly enough, I don't seem to actually see this (tried gcc 10.3 and
11.3 so far) - is there anything you know about compiler versions
related to this perhaps? Or clang only?

The kasan_stack_oob test passes though, and generally 45 tests pass and
10 are skipped.


> +# Kernel config options are not included in USER_CFLAGS, but the
> option for KASAN
> +# should be included if the KASAN config option was set.
> +ifdef CONFIG_KASAN
> +	USER_CFLAGS+=-DCONFIG_KASAN=y
> +endif
> 

I'm not sure that's (still?) necessary - you don't #ifdef on it anywhere
in the user code; perhaps the original intent had been to #ifdef
kasan_map_memory()?


> +++ b/arch/um/os-Linux/user_syms.c
> @@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
>  #ifndef __x86_64__
>  extern void *memcpy(void *, const void *, size_t);
>  EXPORT_SYMBOL(memcpy);
> -#endif
> -
>  EXPORT_SYMBOL(memmove);
>  EXPORT_SYMBOL(memset);
> +#endif
> +
>  EXPORT_SYMBOL(printf);
>  
>  /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
> diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
> index ba5789c35809..f778e37494ba 100644
> --- a/arch/x86/um/Makefile
> +++ b/arch/x86/um/Makefile
> @@ -28,7 +28,8 @@ else
>  
>  obj-y += syscalls_64.o vdso/
>  
> -subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
> +subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
> +	../lib/memmove_64.o ../lib/memset_64.o

I wonder if we should make these two changes contingent on KASAN too, I
seem to remember that we had some patches from Anton flying around at
some point to use glibc string routines, since they can be even more
optimised (we're in user space, after all).

But I suppose for now this doesn't really matter, and even if we did use
them, they'd come from libasan anyway?


Anyway, looks good to me, not sure the little not above about the user
cflags matters.

Reviewed-by: Johannes Berg <johannes@sipsolutions.net>

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/de38a6b852d31cbe123d033965dbd9b662d29a76.camel%40sipsolutions.net.
