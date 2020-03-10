Return-Path: <kasan-dev+bncBCMIZB7QWENRBX7AT3ZQKGQEPGYM3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 06BEA1801A0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 16:21:05 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id p128sf1952031ywh.9
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 08:21:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583853664; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQwegFvmL1K7GUwAjdm0hYRpjhsX8XuhdUoiDGt03bluvGyA97b1nnhFpPkuaFDxq1
         wV/1E9Etb9IKD4252mB34CtL8gBExGVdl2v+6B27jWR8zLalmpDL6ESRKFTRLGtAerLq
         5V8R7MCRq4bYh9NkAZ1RFqXTtiP9w3KkhMDMCwAQqn35kSgsf0juLmE7FZkG/iB+Dddn
         syZY4ZZw8Trtpfk0Nrez5qlKWmZ8m1unfln53GH3gtt2UUDI+f1ku2Xr0NCMUzkS5tm9
         /3oV/PWvjrGkukd0RVEht1bHmj3uiqiRZoNpfyQHE9oEDwfolYwiw3xvPSrDIigoiCgK
         /1Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DfdjPOepVlsp6laRQVChxxQDJta6E1NvA6+jJ3ao1wA=;
        b=A7x+8TDz9wp3AEkBKe1OqrND9TRsdh+6GSxmMT0OukCywL2KGtHQYonpHP0I/+mfnc
         R9lVzNUaKxcSZeUIzP6tUsGtL1WGqDmhVts6nAuAXdivpp2oa0D8nCDuuJwOH8SEGkr8
         PQHFFKN7q2rQAoMidkCDvbuxsOaEtKXYRv5IXtGIWRuEyoaG+g0xi0s/IAVrOz/WocxN
         0iZQtodbAeYBkEBCMyriNrDyY83cmxsCPZWLO7dMoZLfLt/PGJIVCOFyALOI+KYGmpBK
         NADq/yGkIRooHPQ2nMC4mqQQOpAMRhywrNVponvSAd1YmbZPAQnKEfrm/kzj4jyDvRU9
         Ta9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y5RdwMNJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DfdjPOepVlsp6laRQVChxxQDJta6E1NvA6+jJ3ao1wA=;
        b=plWeYyBwKl3Pjvos1ivtHUw9K5Y/GOx2n/cot5yM3ukh7Ng64zD1GQg22aDchRrZdq
         RMVyERoM0Vz4o1FAnkaoACbvWd3xzmu8C6GboE+jR4xYIz/ZLsokSLLYyuad+j4acv/F
         Pvy8V/CNVqZjiV01ooXBQ5RQNtQPxWIHIhULrAM5sfCqftfHfub7gG2SXN3V6Ht9KLOb
         jEVKq4ePi2k8KbUHnEt06IoQFSR6R1gM7Dj1s3n9WNddXf3iq6PKK0TnCQg7HbVjLdDS
         ksyyuIzkzPteFZDKvsg/w+0nkkkIW3Y7Cvk6vNUw0EsptxL6QSEbJNsPsdvefFCzF58m
         k0Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DfdjPOepVlsp6laRQVChxxQDJta6E1NvA6+jJ3ao1wA=;
        b=kV35aX6KCiGqRhjvwMl0IuG+eOb645Xg6LNDmXqOd9pmKsHyB7HiVAhTHlvlTsi/jG
         YTP5sq8C+w5Wevk+LW/nBJ1GRuxYeopHkkq32XJkdZNWwxoxdbfpSn8zEP1gOtXKM9nn
         eItssollOBNsssWhElyO1pe3TszETVSthXBrHEfLppMchv4fLhwDSHYZTXueGmNI9hK6
         pvUqxf+GE+tPB2NlU+pUNw0TxkWkMQfndiN3SYDhkIIK2XKUz9AE20fozd5i7LfMUcpd
         O89/QM0Inc/uw0VtWtJRV66J4IOtTfOfnhAUpabSpfn8C6rB+/3dV+eM+FTNdS/Va9Cs
         uYlA==
X-Gm-Message-State: ANhLgQ3e+38Y4+rCl71bCxl8PUp5q1EYPKtxRuasLGLBZ5BAjqfsMOaU
	eSMY2dw9r/5QQB7ZSPAAba8=
X-Google-Smtp-Source: ADFU+vvNt7WfEhIRDWilB66eK5+ufMG3Qn4zPfplbiSIDXWEi6QMycbG23ij7+aN9kXIpVzVAtFwsg==
X-Received: by 2002:a25:dac9:: with SMTP id n192mr5279361ybf.285.1583853664022;
        Tue, 10 Mar 2020 08:21:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d889:: with SMTP id a131ls2794709ywe.6.gmail; Tue, 10
 Mar 2020 08:21:03 -0700 (PDT)
X-Received: by 2002:a81:af5b:: with SMTP id x27mr10882632ywj.377.1583853663625;
        Tue, 10 Mar 2020 08:21:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583853663; cv=none;
        d=google.com; s=arc-20160816;
        b=V++6Oee6qOeGvEC8eiIrTPHMwB83ly47KaL4yof6RRI0iQLZRw38GHZwf74bBTzwIU
         0Vp39qhUeAXd2YP5qtQbTbELDdQgJxsdh+iGLMInVgt57jtkb4ezW3fthlj+YtRGM7ez
         DURu5N+vsxz93nSXQghSFnJssyRBjRU4I6hsIcUR9MPdaIbiFLMUChMzAew9KSa6Tfgh
         AeIRZ2/UqlyX5+7nWZq3HJVJVVeLZVWMM0rgamxLD3E+j2xvyLS1sVTXsz2fzeMTk8+h
         Wsv9eL8CssSfeeA1xsml/phrT+G9BsWKgwru9tCSOShludp87+OT3OcglbfiHn8h6cTD
         jhYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7cxfOub78XytTahn0ib89laSCRrqzn9vDFVf61uClLI=;
        b=HZF2Lam3PAzwNh3gVmpiog7CYMc3Nb0PzU0etXd0Ku7u6mi5YN9Auars4YUFlC41W7
         FhfuUDb+nEgx4u7APAPvbHJs8CDj+Z7+O70P2YM+AOw2NcP0rruJsfFi3QMsWrpLgFTh
         QGjwH8pmLtbUGQOaQIV6TqKgemPTBt4MVOf16BP1/qJPQ4b9SKz8R2Kr2n79aeKbTNUR
         Fx3/SbbxjkFBmBRISXme3jBOyHAJXdm4RT573F4UCLwNC4BeiKOlCo5YyUW6aJwKiKyi
         8zAKmcrM8MTcHKbRyQdkXuTo0oI5z7PBqt4axaz7FxpbR9ZdgAukxvk1o4L29B6dzEEx
         BTZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y5RdwMNJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id e124si144631ywb.4.2020.03.10.08.21.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Mar 2020 08:21:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id f3so13091117qkh.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Mar 2020 08:21:03 -0700 (PDT)
X-Received: by 2002:a37:7c47:: with SMTP id x68mr20526910qkc.8.1583853661912;
 Tue, 10 Mar 2020 08:21:01 -0700 (PDT)
MIME-Version: 1.0
References: <1583847469-4354-1-git-send-email-cai@lca.pw>
In-Reply-To: <1583847469-4354-1-git-send-email-cai@lca.pw>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Mar 2020 16:20:50 +0100
Message-ID: <CACT4Y+aV9BrvEHdaadL7FXsjMi4iPDJUnK8eyJj=HuZFa4fxuw@mail.gmail.com>
Subject: Re: [PATCH -next] lib/test_kasan: silence a -Warray-bounds warning
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y5RdwMNJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Mar 10, 2020 at 2:38 PM Qian Cai <cai@lca.pw> wrote:
>
> The commit "kasan: add test for invalid size in memmove" introduced a
> compilation warning where it used a negative size on purpose. Silence it
> by disabling "array-bounds" checking for this file only for testing
> purpose.
>
> In file included from ./include/linux/bitmap.h:9,
>                  from ./include/linux/cpumask.h:12,
>                  from ./arch/x86/include/asm/cpumask.h:5,
>                  from ./arch/x86/include/asm/msr.h:11,
>                  from ./arch/x86/include/asm/processor.h:22,
>                  from ./arch/x86/include/asm/cpufeature.h:5,
>                  from ./arch/x86/include/asm/thread_info.h:53,
>                  from ./include/linux/thread_info.h:38,
>                  from ./arch/x86/include/asm/preempt.h:7,
>                  from ./include/linux/preempt.h:78,
>                  from ./include/linux/rcupdate.h:27,
>                  from ./include/linux/rculist.h:11,
>                  from ./include/linux/pid.h:5,
>                  from ./include/linux/sched.h:14,
>                  from ./include/linux/uaccess.h:6,
>                  from ./arch/x86/include/asm/fpu/xstate.h:5,
>                  from ./arch/x86/include/asm/pgtable.h:26,
>                  from ./include/linux/kasan.h:15,
>                  from lib/test_kasan.c:12:
> In function 'memmove',
>     inlined from 'kmalloc_memmove_invalid_size' at
> lib/test_kasan.c:301:2:
> ./include/linux/string.h:441:9: warning: '__builtin_memmove' pointer
> overflow between offset 0 and size [-2, 9223372036854775807]
> [-Warray-bounds]
>   return __builtin_memmove(p, q, size);
>          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>  lib/Makefile | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/Makefile b/lib/Makefile
> index ab68a8674360..24d519a0741d 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -297,6 +297,8 @@ UBSAN_SANITIZE_ubsan.o := n
>  KASAN_SANITIZE_ubsan.o := n
>  KCSAN_SANITIZE_ubsan.o := n
>  CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
> +# kmalloc_memmove_invalid_size() does this on purpose.
> +CFLAGS_test_kasan.o += $(call cc-disable-warning, array-bounds)
>
>  obj-$(CONFIG_SBITMAP) += sbitmap.o
>
> --
> 1.8.3.1
>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaV9BrvEHdaadL7FXsjMi4iPDJUnK8eyJj%3DHuZFa4fxuw%40mail.gmail.com.
