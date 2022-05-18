Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWPVSKKAMGQETBTSLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C5F4052B5B1
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 11:22:33 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id f14-20020a0565123b0e00b004778cb5f0f0sf834999lfv.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 02:22:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652865753; cv=pass;
        d=google.com; s=arc-20160816;
        b=RLwhTfviCeGvIQByFKyJT/Jt7xC9W3GJmQDD4bPfkJuHA5lO4MTk8hFAPazLUAd0aJ
         gb/l4XvyWXr71P59eaHmoXIMgEfKHnHaDglXaCk3PWZWK+Emse0qmv1C6GVMJ8AHpRX/
         TADWqeW+fNiWQCrhgOzpxJxykWlD3U2FdvpKrTpEjO8J4qMsO/d4l7Gs6ZclnAShksur
         cpc36nzluPzZkLMASKT4+x8FAjNSpf817yvmYp/JkEQyQcN6bFCe99VSd5nFl3chVzvH
         9wEQF48LdiBinqs/b2k1/dLy4ZU90b57H5kluH6HfqygB9VarVyBijzycdysaPqq6NpK
         /Azw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=64nWiYzhh2E7H68bbvBh+CklA8kK3JO5GwVSphLvFPg=;
        b=vm2lupMSBCq2lx9xF5FxAQumT006wOKU1WN2XzM6tCcIu0thNFwnNOjRvqc0/eDSNJ
         qFZgPXOW8J/w63CJ1H6IX+s54BGXzo2S7JyU29wFTjBlMNuQ3YYETXAhiusZd0QcNllc
         OtQjmwGjcd4xqCPeRJMX1/qQwangnma7tpf+JGIiJVJTVu166GctZD21yYlrdnBVELtj
         VVsZgiGec9tyFIRDUIctjR6YwYLI2of3lHNCks7xDUsfChSJBHH3GSeAkF79YTyhyXol
         nkAlMcCWQHgUKhELjNh2q9ehFuGBODya/B8IlGOfv+mSsVTCQ/Twe0LVnV7ydxwlPHUP
         0GPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bx791FgA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=64nWiYzhh2E7H68bbvBh+CklA8kK3JO5GwVSphLvFPg=;
        b=lIUW9MeNOMGDFDJ/VdMkY4nJaySk9NvPjZuQSSEc9hAXmM3IZOOFCrhKs1jSf85mma
         4AHWwbsp5ZhK6lnCEJjsxHcvx4qRvWYJcT3rzqLGlVv3XtPu2+faoJQIRzXNN4dDNUCG
         Cwr3HFlmBrHewYSenW0uEc/LJjAnBHWD5c2nKWGs7V8JhA1vhx6LInv3kfE+UxB0ngzB
         K9cLR8AudkYuMvjKP66itIEGmOt/MT/mKdf71uRRulzB49qVqQPEhEFj0LJ8P8Kd3CfJ
         Sd3CVnrplv+sBwCwN2edfm3XXhrPNeIHcKx5VMZzTgdISwYBH6E12dyRKbIWiIlY6bM7
         cOnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=64nWiYzhh2E7H68bbvBh+CklA8kK3JO5GwVSphLvFPg=;
        b=dqvEU/cr7OT+VfHOlKSqt4uUYmgDoOw4T7wOwSPwr9OJn6TY3+PzvVCVnu7ALYSKwn
         BM87S4HAc1bjLMGWsU8cXZpwSn97Z8EsZnxioK3AOyKn1dYi9N0vU/NtwY4kzMp5QU7E
         RehFvfeX+q7RBsTgecxkIyCxHeG4c9+4C4VaSgVm0QCLg2nNdFBGXL0NK5bQyAai2oCh
         IfDA7aMInQ8A8zmVreQHpnPrMQH6lQImnnKNeKLs/eJP00g72xGdUeboK+pgKLeUgs05
         kcPZm06Hx5ttdTWA+j9lXprHdAj3wI3rXJo3Tjq9ZpjiBJo219CYEFKfNt+X7pnaWD5P
         fn4w==
X-Gm-Message-State: AOAM5317KQk6JkIAvHw4/FMYDSVSPE4Kebti/GIWFKz6rUkrkYbMTnZq
	uYvFWSP+NACMVXfKPbelAhQ=
X-Google-Smtp-Source: ABdhPJwBnk92WYdmO4DmVzNeV/bMkIiamdTBDYRszcFKzRGKjS2m+u8xv7gmx0Ge/TRNx1hp7Opkdw==
X-Received: by 2002:a05:6512:3245:b0:477:a665:75a4 with SMTP id c5-20020a056512324500b00477a66575a4mr5017451lfr.611.1652865753370;
        Wed, 18 May 2022 02:22:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls13621298lfu.0.gmail; Wed, 18 May 2022
 02:22:32 -0700 (PDT)
X-Received: by 2002:a19:5f13:0:b0:477:b3a2:30b8 with SMTP id t19-20020a195f13000000b00477b3a230b8mr2695658lfb.683.1652865752073;
        Wed, 18 May 2022 02:22:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652865752; cv=none;
        d=google.com; s=arc-20160816;
        b=bujwN8sDbHt9qYDiNR7aY3zyzjNX6ldVh+d6Aa5RNeMXyiA/JEeELzAoSz2uxktAf7
         QhtCK0rx3hvqy5TYVqU6EF1O2wfh+LxzSjOBfviiDYi1/ggTIaKMIBTG9hb9xkk01Kn4
         fKJGLYIObNN5nPGgFh3A8fCIWsUO8YEjxiTjk7Ojo1+HOoJusmDeNEbDUGzbutCCrLod
         lO4mryQIB15pU3b1Yk9oYnwP04jMAQM8t1VmD392bq21kQDHz96j3qi0dSSKZnEq4+/e
         X6TrYxcYhftk3fPChHDikj+8C7aMW5fRPukJYj3x6ut36rfHobWWiSW6VUlVsZChbJ98
         ivog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aYv9sRLI7bJwp+N2At4wjffC8t0qCPCqKx/aIfhkVRc=;
        b=RP/7wmaa5PPujdFuK7QCN1NXouPRp+oxgZYUYMX8LhWS0CL0hRPOwvl3Zkyjz9N37i
         SlXqxpc3srFahETRo1/SgDcCpx1Kmm42791n+9Hx8+WL/gU4sw/86MnrSx6T70Hk8Cev
         Kuyl3ld+VrJN7uoue+iZfnma8jzqQopyrvOf19aM5bjqWOBftQQzrzDYJKD6wnfkHL5N
         /CNJ7IZFW8bEFmNOHGFr+AjDFp3QVUKYuxYNcvAlQ86FgGYS3RaL3bBl9gzZvUfGNs9Q
         Hjegtv2sAfInd7KI6RcvlNt3wyYSDncHK7Arn/25B5Q2/gyheD/OdSlzrEohj4LoDFop
         1J+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bx791FgA;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id o7-20020a05651205c700b00473b906027fsi75313lfo.4.2022.05.18.02.22.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 02:22:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id k30so1798013wrd.5
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 02:22:32 -0700 (PDT)
X-Received: by 2002:a5d:55cd:0:b0:20d:743:6078 with SMTP id i13-20020a5d55cd000000b0020d07436078mr12731983wrw.240.1652865751403;
        Wed, 18 May 2022 02:22:31 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:450f:9c92:a170:5581])
        by smtp.gmail.com with ESMTPSA id z22-20020a05600c0a1600b003942a244f38sm3873757wmp.17.2022.05.18.02.22.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 02:22:30 -0700 (PDT)
Date: Wed, 18 May 2022 11:22:25 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP
 testing
Message-ID: <YoS60c/CIK3mHWyq@elver.google.com>
References: <20220518073232.526443-1-davidgow@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518073232.526443-1-davidgow@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Bx791FgA;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Wed, May 18, 2022 at 03:32PM +0800, 'David Gow' via KUnit Development wrote:
> Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> setup, so this is the best bet for testing things like KCSAN, which
> require a multicore/multi-cpu system.
> 
> The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> KCSAN to run with a nontrivial number of worker threads, while still
> working relatively quickly on older machines.
> 
> Signed-off-by: David Gow <davidgow@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
> 
> This is based off the discussion in:
> https://groups.google.com/g/kasan-dev/c/A7XzC2pXRC8
> 
> ---
>  tools/testing/kunit/qemu_configs/x86_64-smp.py | 13 +++++++++++++
>  1 file changed, 13 insertions(+)
>  create mode 100644 tools/testing/kunit/qemu_configs/x86_64-smp.py
> 
> diff --git a/tools/testing/kunit/qemu_configs/x86_64-smp.py b/tools/testing/kunit/qemu_configs/x86_64-smp.py
> new file mode 100644
> index 000000000000..a95623f5f8b7
> --- /dev/null
> +++ b/tools/testing/kunit/qemu_configs/x86_64-smp.py
> @@ -0,0 +1,13 @@
> +# SPDX-License-Identifier: GPL-2.0
> +from ..qemu_config import QemuArchParams
> +
> +QEMU_ARCH = QemuArchParams(linux_arch='x86_64',
> +			   kconfig='''
> +CONFIG_SERIAL_8250=y
> +CONFIG_SERIAL_8250_CONSOLE=y
> +CONFIG_SMP=y
> +			   ''',
> +			   qemu_arch='x86_64',
> +			   kernel_path='arch/x86/boot/bzImage',
> +			   kernel_command_line='console=ttyS0',
> +			   extra_qemu_params=['-smp', '8'])
> -- 
> 2.36.0.550.gb090851708-goog
> 
> -- 
> You received this message because you are subscribed to the Google Groups "KUnit Development" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kunit-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kunit-dev/20220518073232.526443-1-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoS60c/CIK3mHWyq%40elver.google.com.
