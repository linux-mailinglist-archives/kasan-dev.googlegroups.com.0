Return-Path: <kasan-dev+bncBCMIZB7QWENRBCVL37ZAKGQEWJHU3RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0ECED172060
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 15:43:24 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id v190sf5054190ywc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 06:43:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582814603; cv=pass;
        d=google.com; s=arc-20160816;
        b=gd+N/g6CHwUrRtO79Jw20yrEdW3caX6avlvjoan2EiXlybkZ/wdRD/n2AywNChpzDF
         tHuOYzB+VachFStM7RjYUYCOKMgR/jES99yr6w4R+GJHaWfFdmwin1CB5+UuBZSmXMoF
         4gjGxREWtVTVrR6YGUKmsYPNgw+73aEWu/bTHlY0fn7lrdMQR2erlheq2zGfVhcMtpfR
         ZFjn/jD8fDBLDCrhbqm4L78+WEJYGQHCMARaeWrZmFdCyPE/ZpVGeXVSVZtowafMJaLI
         Bw1ir9nbxGNgmOkT+xJwzOx6aape6Ef6fYPLyr4fRWkEL4o0vKVQPTBFahoxfktygHAl
         BK6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Mo6ptCelWF3MK4s9GLyxsyV12kuXm/+2hTVU3VnUag=;
        b=KU/H5Y9bUrl+r9QW022lkT6O2YZirdPxgocIzoOIoaLlggfzJ8UOjGkkPY1TKD835F
         BWvIfqcv3s4qmLM4IpQm8swJVjq/C92ojiFreP5gTg3IM0gDiXKlsplzgn2v1KguH346
         IXP9NoafjDa9b92yWGpSgTzjVWzdlB3C+A3PdgzhAJvMQiLHa3wRdd4MxfqKhwjNtPD1
         a+9U3pVahT+w44YD6rB8XtmKz7xnxzfAtdmB5ApWmsVnZImjqxBvvIysorKENBUQkWLA
         nM7WZurOgDKYK9y1dytMEttIHu0JDNX/TZknaOEJTbKxAzRFTP4Dvo3Ct637X/dyiTzW
         fXcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dsz/dd+K";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Mo6ptCelWF3MK4s9GLyxsyV12kuXm/+2hTVU3VnUag=;
        b=peIB3FSIWYPHfP2syk9H8UAmISNvJCGavGbO0W7MWUjIfCQzLGRmbcArpfkMRKFrcM
         o3FLC/cbajJXXI+BitNFevZCjWqHQBvQp1gE744yNGLHesTP4dfJ8UtwmTgfrfUUiYsw
         +XF6z7F2HPfqRDR1n8psUgawx60gvFRNlozN+ilbi/5C8wkoirblIXmrSRk92huk8cLw
         RzAftN3h5+BTugdpsTXIVME4TMU+ovmHyOgCuut04tiW8rJt46g7YoSzfvJr8z6zGG0o
         qnqq01qEoGpGLqTQNTacjrXWDWZA8IqQBBGplneT1RRgc02xCAF4M1apSVZ9UpAhDVO6
         rpcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Mo6ptCelWF3MK4s9GLyxsyV12kuXm/+2hTVU3VnUag=;
        b=DjcZIb6B+IYWqinqSdFzllsz2RDQxWIXN0wcZQ/LUtL/4lgB8yRFsjD7dcPoTHSvjE
         VMIyfNfQPiB4+en1fWlIEAotTJoz3yjsXxy2mJX+cXIQFbDkgGKOJWv83QbNK5RIINX0
         5GetQUaHzKMFgAAgafRPKDGyt+6e67tHRXbJDE2KTSrEsUMx1lYxJDCE4+yD3AXBbBjt
         wPlIUQoVST3Qssa/Bo3/kOtzaqkB3nZI0BcT2sRKIJXjFNfb7VlN6f6W8dVhpEPo+V4O
         QVSxGXs4WtVFfNJPfvct0uicCcOdbSPj/mFJTJt56ch/sUCwsyx9ka3CGBie47WCLeuF
         l4aA==
X-Gm-Message-State: APjAAAXR69wQVjKbaAtONt6/bRQ+gm7SzfZAVmGlE/HMDQNzU++CseVm
	ByS+0ZVJwi+KPEaMvXJ1YNo=
X-Google-Smtp-Source: APXvYqyI/dmr+V0CWrgdohlzCSwPV7IgtBPLLEQyZ+M+RQqSdwTgSOyx8o77ukeWshw2npi4csv59g==
X-Received: by 2002:a25:b904:: with SMTP id x4mr75899ybj.478.1582814602622;
        Thu, 27 Feb 2020 06:43:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:984:: with SMTP id c4ls670079ybq.1.gmail; Thu, 27 Feb
 2020 06:43:22 -0800 (PST)
X-Received: by 2002:a25:bece:: with SMTP id k14mr57021ybm.125.1582814602285;
        Thu, 27 Feb 2020 06:43:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582814602; cv=none;
        d=google.com; s=arc-20160816;
        b=mF77yOike35T5fKgHbS1W6uyLBMzzQSmGYFsPN21ha+XiPbn28eIrJaoecfHrkCIo7
         GN4yAuSmFbDjAo7zM7xiUGxhECuZkBdo9lOao4N0pQHpI/BEnt9ImOBNy0+N9w5kxFle
         /xMca3yeK7g2uQiHgNN5XlkjtcoxUnwYzdCYC041I2HHdN8QFUe0RHGVKPUa7BpSK7I1
         7WECc7YybOEqOjAdXjvT6L9eZMExx1k3gCcEFwW0sppXJTy5/g0ZbCqmH24ukVln+0Mj
         JfGg3n8kz4G/6StzooDXk2jWYnwIWDj1cRBrz1Xp+cV8C72cuHbUImfvSmMxFn4Pi1PB
         a0iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z+isuoKHbYPGILyMICbGR0T5QiMYRy4J1XMZ/c0MyCE=;
        b=SMg7mbetiRHusG7ON/TfwSTegjgpK64Opb+YAnsK9ch6e/qlXjSZescnuTgwsSvE09
         5lOmbEakvc+5L5Aao+7IYj+STGLqD1CURWA40yOPxT3p8V/4TUIsAiQBw/1qh3JlRUoC
         3REWNICVJ6LVSou+y69GVAqfvPY2ifr/nHXXU3iFFS29rw5SVgWf+/0p7OMWm1fi7LXE
         QddlQhtK8QfnLlk5Auj/4La1JcaqTu29wpgOsnm8pXy94Q9ZLPAaKnkvwSJNodArQjEe
         MsImrtoZWI1mMu+7jwhuFrqETYmo3xaYmcgoAy2YY2qcsNaLnfniDnnxchun+GMJMSIR
         B/yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dsz/dd+K";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe42.google.com (mail-vs1-xe42.google.com. [2607:f8b0:4864:20::e42])
        by gmr-mx.google.com with ESMTPS id i200si212900ywa.3.2020.02.27.06.43.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 06:43:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42 as permitted sender) client-ip=2607:f8b0:4864:20::e42;
Received: by mail-vs1-xe42.google.com with SMTP id r18so1979823vso.5
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 06:43:22 -0800 (PST)
X-Received: by 2002:a67:f318:: with SMTP id p24mr2787324vsf.240.1582814601592;
 Thu, 27 Feb 2020 06:43:21 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com> <20200227024301.217042-2-trishalfonso@google.com>
In-Reply-To: <20200227024301.217042-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Feb 2020 15:43:10 +0100
Message-ID: <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dsz/dd+K";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e42
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

On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Integrate KASAN into KUnit testing framework.
>  - Fail tests when KASAN reports an error that is not expected
>  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
>  - KUnit struct added to current task to keep track of the current test
> from KASAN code
>  - Booleans representing if a KASAN report is expected and if a KASAN
>  report is found added to kunit struct
>  - This prints "line# has passed" or "line# has failed"
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
> If anyone has any suggestions on how best to print the failure
> messages, please share!
>
> One issue I have found while testing this is the allocation fails in
> kmalloc_pagealloc_oob_right() sometimes, but not consistently. This
> does cause the test to fail on the KUnit side, as expected, but it
> seems to skip all the tests before this one because the output starts
> with this failure instead of with the first test, kmalloc_oob_right().

I don't follow this... we don't check output in any way, so how does
output affect execution?...


> --- a/tools/testing/kunit/kunit_kernel.py
> +++ b/tools/testing/kunit/kunit_kernel.py
> @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
>                 return True
>
>         def run_kernel(self, args=[], timeout=None, build_dir=''):
> -               args.extend(['mem=256M'])
> +               args.extend(['mem=256M', 'kasan_multi_shot'])

This is better done somewhere else (different default value if
KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
to be a mandatory part now. This means people will always hit this, be
confused, figure out they need to flip the value, and only then be
able to run kunit+kasan.


>                 process = self._ops.linux_bin(args, timeout, build_dir)
>                 with open(os.path.join(build_dir, 'test.log'), 'w') as f:
>                         for line in process.stdout:

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg%3DpxZv8uZA%40mail.gmail.com.
