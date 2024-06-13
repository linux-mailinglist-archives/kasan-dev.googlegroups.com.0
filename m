Return-Path: <kasan-dev+bncBCC4R3XF44KBBK4CV2ZQMGQERVJ6INQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E99A907F5D
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 01:30:54 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-7059fdafc78sf1128653b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 16:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718321452; cv=pass;
        d=google.com; s=arc-20160816;
        b=kiMXulwbB6Wo0SRhI8WriqpDUTxsPY6FGmTiPfnbLBte9VCOVjjeoS0JaPWjGTF4rp
         eQcMfgTnoXksq6G9qjFio6IFIhNo6VtWnf7Sb9efO3et5D9OhpOKMmN48jOU9PWCCUf6
         wzRjbHgZRngRnh4m3jExSE5rkfLATwDpMqy24jmxQkjmm8Prwc5tLEFR1qBZIXF2Fxhi
         S2zXJcaKf6UDWZZAz9NEOrYQRaTjDQzlrhjerIv7gJ4R7zDojWoE4uxsItKPRrc/qS9V
         OOqMWkHC5VxT88qZcrpWz5rsViWKnKlQIHW4FJXYzVnRPQPYs3w/0PpVpmwiH3M/o0sv
         /rAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Lpa5W1udDI68qClIFXROzUixVXPYfA1WnCYHj3hHq68=;
        fh=Y88X1U7LTjJKP2vQKdSD13JhhJ/uo0vK7Ph+SSORVoY=;
        b=0kA/BgRBj1y77ZEBXM1ggGOdWUabJcZVP406NlDLupviE7E0287ShdcGk0vYVDlXDl
         1P06pcebbyuXhcLGMvl6ys9nCCELYmEq/OehQ2g1WC86UdDjVHlgInokaBHZKkst5ySz
         GH6nlPhs/iflFK278TCxg4DDBfm5H+Oaw0kLs9l92re1TkaHxarYrN/FJmQ8EAwRsSEn
         44sXy3G934ChNxPaJ6XMwXQ8WIdWmYVENy3odk8FRJHe70Un4s4GexWNHWqwey5oS40N
         Pbv3ajbkwkiyT6a9J6IKzyabpRA/x14SNVhUQkTSFCJ7cSj616QzyxA/DM+plpQ5MBn+
         1Msw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZtjrlNte;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718321452; x=1718926252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lpa5W1udDI68qClIFXROzUixVXPYfA1WnCYHj3hHq68=;
        b=xsm7oZSl9pNZkbKghp6m3g26DBGhh953W/bn0//Qye3j/Fkvv9OEUiNyFeYiJEY5bb
         AuMywjvAiTBpz2iGbH+yzF52XJKcWKK1qAK1M5fZAd1xcwYNtFHsmhopEsuNPN7lkwUM
         dDkMwXfN0t9TILX1jnHVV9UgT3Ralfa5QbeQwBsDiFgjpkza/beVIdivydpB0bnxClg6
         lgk1EcbqYo31NGQDLh0XgnkcJXPFheRpX1ZaJLDY2tcxIK7WkFYiPQCdJJc4HokHy6Zt
         4jtLPL9SRFJ4mIUDNOisbL+gARjAMlE4k03ABxH3y0+/fPCXN3ifUVKnb/lypOUWSNEA
         v/pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718321452; x=1718926252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Lpa5W1udDI68qClIFXROzUixVXPYfA1WnCYHj3hHq68=;
        b=YSYnfgfLnjkJicAaEgD0RpY00gritJ3FpKEvl7iSK18rdV1Tz2+q/jkjzJkkSUwg4t
         jeRGvsh0r1jbBOUvfR4vJNVtyuykiAq8PKp4mYJFjJJXxEX6vuof7sP3HqNvF0y0EqXc
         Fmn4r5ghGOJU4FxX6xyWOlBl6TuG8kJh4QuWwgffX5cIyE8maamt0ZolP1XR5N9XqVQX
         5YkoPQHD2+7bdRXPuiPcKByi/ohv3/dnTCOVXWWOvfZKbashN9TVnJZGbGeFvVdcGTg2
         SvLEfU4Lzox82rJ3nixROoN0nGnVi0fSDerXWOdd0WGNcV2P3cOqaUSnw+we0Yf/xE5P
         zi1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/YlNJjt5RXtHQ4M/mfIjRcPZ0Fqay2fDPP0Ei4waHgZO02BHO04yK+EHq4LaprSJgIGySZr3Bc4ojgO0AMBi72UuzqJFjZQ==
X-Gm-Message-State: AOJu0YyLGufBXgvmxbD8DztJRwaRAMMdXJytc/1C3o+SP4Gro8F29Sau
	WIVFdKFlv4ihDqeCVB/OafS9y/KICQsH3fg324r+XeudgIV9lEPF
X-Google-Smtp-Source: AGHT+IHTNOu97wSKkN23xGGGj3+sID4QV22MtdmMs5PTT7THgyJJPolLdiGto9Yi8SeJis4lMRPgNA==
X-Received: by 2002:a05:6a00:52:b0:6ec:f2e7:21a8 with SMTP id d2e1a72fcca58-705d71b1505mr1177950b3a.21.1718321452009;
        Thu, 13 Jun 2024 16:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d0b:b0:705:a7ad:3fc2 with SMTP id
 d2e1a72fcca58-705c9484b45ls978028b3a.2.-pod-prod-04-us; Thu, 13 Jun 2024
 16:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUn0no12M7ODMhS2k80R2HhoRp24c8g/CT/aPpW7OqsuQZ+u9O9VfUiPRH4alR1qZsSXHqny8zkEJEbqXhQeyU8RscAWlCL6AaGQg==
X-Received: by 2002:a05:6a21:99a0:b0:1b7:cc4e:eb6 with SMTP id adf61e73a8af0-1bae7f624f0mr1458069637.8.1718321450619;
        Thu, 13 Jun 2024 16:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718321450; cv=none;
        d=google.com; s=arc-20160816;
        b=N0aEovPxYvXsq6B/jzWc5fl5COqY5trHauWyosicW4mhux+BwnbIMqzJlDHRg9Br/8
         tM07j6l/nUgiXA2Hcudu2YnaOgey0KyOvLwkN+PQfx01g+Qlm29T4TOX4QEobj3wmaMj
         cNh1iJXpR0q6DlhMNTBA1e8nqQs8rhviEeUkpFbVeXDmSBV+tz83y+i8RLxi9M+yR2GO
         TFj+kHmh1N1DOLH7NsqaqOw6ZRIp1HsBAmTlhKbYPfdS4DRk5c8mXRjCD4h0ia+El6u8
         SfHDZChdcDhREYXAF18dR1b4beOlmf58FJRbVOfVJo8dtadf5HqMo7euwoaUW1Vn2rpT
         IjAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hxaGvxkScOTKCiAV8+k9eEP+nZdOtp9Q1FaHIeD1exo=;
        fh=3VgqL3ysDGk4Fi4EyHSNk9pdzE1DL0JFC7fE/1spQD4=;
        b=dctL8AM+hUEWy8cm7AmhMHpHxhGAbo2fPPnVTxGI06OTScMG/hq3UsAhLARlz2/wnN
         zXUooLvdrlU3zUOTtoJsem9DP9XfzMPsQQurLMLAgchVBGE3oFnzhSEK5vHfpZZ+hzfH
         aP2Dqw9MELtjskeA9GXXY92AJiDvmV8Ik9RPsT70O4AqL5hG6om8p8a0YD/Xu+1OPNh4
         o/i1wDEPGuvm8QYyCD36/TqVYcBWKtpR+CC3tYxnopjSdnlWFlVcbeQV1cOFstxA2PAu
         Yaqw9F0CwgMuE+uign6juM/bG1ER93zCXDk39kpoXgM+YeJ+yx8TLml8iVtz8o3foihb
         GXNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZtjrlNte;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705cc8cac45si80333b3a.1.2024.06.13.16.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jun 2024 16:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id ED99D61DAA;
	Thu, 13 Jun 2024 23:30:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C1F9DC2BBFC;
	Thu, 13 Jun 2024 23:30:46 +0000 (UTC)
From: SeongJae Park <sj@kernel.org>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: SeongJae Park <sj@kernel.org>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Marco Elver <elver@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Pekka Enberg <penberg@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-s390@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	Mark Rutland <mark.rutland@arm.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Sven Schnelle <svens@linux.ibm.com>
Subject: Re: [PATCH v4 12/35] kmsan: Support SLAB_POISON
Date: Thu, 13 Jun 2024 16:30:44 -0700
Message-Id: <20240613233044.117000-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240613153924.961511-13-iii@linux.ibm.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZtjrlNte;       spf=pass
 (google.com: domain of sj@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

Hi Ilya,

On Thu, 13 Jun 2024 17:34:14 +0200 Ilya Leoshkevich <iii@linux.ibm.com> wrote:

> Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> kmsan_slab_free() to poison the freed memory, and by preventing
> init_object() from unpoisoning new allocations by using __memset().
> 
> There are two alternatives to this approach. First, init_object()
> can be marked with __no_sanitize_memory. This annotation should be used
> with great care, because it drops all instrumentation from the
> function, and any shadow writes will be lost. Even though this is not a
> concern with the current init_object() implementation, this may change
> in the future.
> 
> Second, kmsan_poison_memory() calls may be added after memset() calls.
> The downside is that init_object() is called from
> free_debug_processing(), in which case poisoning will erase the
> distinction between simply uninitialized memory and UAF.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  mm/kmsan/hooks.c |  2 +-
>  mm/slub.c        | 13 +++++++++----
>  2 files changed, 10 insertions(+), 5 deletions(-)
> 
[...]
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1139,7 +1139,12 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
>  	unsigned int poison_size = s->object_size;
>  
>  	if (s->flags & SLAB_RED_ZONE) {
> -		memset(p - s->red_left_pad, val, s->red_left_pad);
> +		/*
> +		 * Use __memset() here and below in order to avoid overwriting
> +		 * the KMSAN shadow. Keeping the shadow makes it possible to
> +		 * distinguish uninit-value from use-after-free.
> +		 */
> +		__memset(p - s->red_left_pad, val, s->red_left_pad);

I found my build test[1] fails with below error on latest mm-unstable branch.
'git bisect' points me this patch.

      CC      mm/slub.o
    /mm/slub.c: In function 'init_object':
    /mm/slub.c:1147:17: error: implicit declaration of function '__memset'; did you mean 'memset'? [-Werror=implicit-function-declaration]
     1147 |                 __memset(p - s->red_left_pad, val, s->red_left_pad);
          |                 ^~~~~~~~
          |                 memset
    cc1: some warnings being treated as errors

I haven't looked in deep, but reporting first.  Do you have any idea?

[1] https://github.com/awslabs/damon-tests/blob/next/corr/tests/build_m68k.sh


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613233044.117000-1-sj%40kernel.org.
