Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7VSKKAMGQEU55AL5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CF87652B5AD
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 11:21:59 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id bu4-20020a056000078400b0020e61501044sf368418wrb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 02:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652865719; cv=pass;
        d=google.com; s=arc-20160816;
        b=PD8w1QxoPLmx9RJhy2B23ShqheOEBdDxtgg9Rdac4eOyO9sacFzuIjP1GCl6v1ECe6
         w5A9UtSRojjzG1WUkm4bQXOM5HhcEWXWv+SaDU4RYXqUDF9JIP4Ho6mKtz+k/gBCsHmu
         G/a2Ve1+82QNJqO+ewp/IU/abKAmWnw4WVIyYSmmayMbzNbTxyJORB6mm49Hmg4D7oJR
         OXTG3izXr28nsm/nQ6tZlXtC/dDzRjH13lK0b0eMEm5kM1UxWgfLunvkr2bs36vmbbBE
         tASyVefO7zXJMheNXFh5sWCb/CnD9Qo1yW6dSyRMXzFNqo2Vo6UOL8WKHyh6gX0jZyrp
         UlvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1UMrpvecwjhCqF0TISkoPLwBE3GAwzTgPIKxNmRaKlE=;
        b=EjGUNjsC4ulOB/rNeigjlLz4fyKHond5Y8Nq964nwtPvP2VUpCkn8L1gq0WgRJK3aW
         eWSgMAbWMrthePNZ0vouUGRePOdkhkJqDCG8n2ncuVN2EzmZCGqDQ/kVSJM7EwDy4dcW
         d1SgNX06zhs8NI+7xd1MEvywk6BBky3Woj1lc9yeBHVhdtz/2tqObXIWgF+WP5kHb14g
         mmSF2scoPW0ERPVu5vD+7vKw8xKHyYNjhtqE9WFceZ2W1X4+FZsT2X+OYnV/InHxRwet
         rGq/jCQ9u2R0YfzIxwX8VLrgcOIPu9VzBBl+FIa6muQvkV7k4M3I/K1LLo+1EYOK6nQm
         EA9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZK4oh48g;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1UMrpvecwjhCqF0TISkoPLwBE3GAwzTgPIKxNmRaKlE=;
        b=dSx9WIXVkiogP6H/ajmGQb4j6V4stEIvQ7Ikgg1s5bgXnHXCfSibfVqKOd92L+7LiG
         gGj+/1Lkf3OPdZ20zK5DPbe5wCnwfteamX3ayijn18ySMEE8qpWjeG5c6GGPEpIfzt9V
         8UHqWVaPO0vTM7Pl0+cv/AODk6BzvkDlUobBPC2Q5ksXJ9ew+EghCSwqpC/4Hk1y71vT
         IcSNcrYWtE75fPFypwR+opfcXaEOQp79dOtmNuPifcVZc4Qx+QYk2AVNwadGGIwL4FQh
         3NjCikCLLL8pjJ0riGCJilrnCW8H+ggACZ7wiX3RYhsQrQMtToHVdaiwawCGhqa0ea4G
         SXIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1UMrpvecwjhCqF0TISkoPLwBE3GAwzTgPIKxNmRaKlE=;
        b=h25smB4fM+R6eWC2RA7Q22JQBL74Av/VAAZzwTPrMElwWSAAOQ+n5kjmkxrUIZm20/
         vTlHkgJSzL4DJC+p31yVQiE8ji2n3zGhMuhHWal+AD4jwpK2RzJngC6gG/1wnB2mWOvh
         Zmmcu9AQ7C7qXKpCZw7bKnNBiE9fFi5kRpDF1l0y2SfwNrtCJr2+YwYtvaymyNN84/AP
         mYU7usHFJjPmCSgTPAgZ7lwTl5IKGpn7Rs+7N/xTjfgU2wfzLyp30z3lbJmI2y81YINF
         hfj1O9Hl18z2vANBxci28mkZCp3ouszDuAZ6YDFTOV6B5q8UhH1vFdB2gXYYuq1ipucL
         +uIA==
X-Gm-Message-State: AOAM531T1XAdtGt5Hds76kIe/I+0LxfpkaM4j85kvKAG1iMzAkyWV9ph
	Z86eZ1DW+hR4KNDnwqEgtx4=
X-Google-Smtp-Source: ABdhPJyIvT9j3BY2B5biOD0vtgyuP8bM/65tPAw+r50sBDrgiaK9XZBZv+jxnGKPEriqj1fqXKfNVw==
X-Received: by 2002:adf:ee91:0:b0:20d:208:357f with SMTP id b17-20020adfee91000000b0020d0208357fmr15746806wro.696.1652865719620;
        Wed, 18 May 2022 02:21:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1688:b0:20c:67b9:e68b with SMTP id
 y8-20020a056000168800b0020c67b9e68bls6749659wrd.3.gmail; Wed, 18 May 2022
 02:21:58 -0700 (PDT)
X-Received: by 2002:a5d:4e4f:0:b0:20e:5fd8:6c57 with SMTP id r15-20020a5d4e4f000000b0020e5fd86c57mr2281483wrt.59.1652865718413;
        Wed, 18 May 2022 02:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652865718; cv=none;
        d=google.com; s=arc-20160816;
        b=e7TMcU77oPtJbHmlFRdgYoLW7ng7ms9kxZtgpgcmvoj92Er1vo75GtrMnQr+TOywZ4
         zlzszJ80cEBncBKh7swDapLpXspOWJniuiToraS5Jbp96LitK5e2TxaOtHjMSFFYLuPo
         gzvWfdOB584/8GjaII9UB76a6iEEpQOwXaqB0bT3EVhNVgNWYYH/DdAIEAF8Rc0zrqOC
         4pcjxZQ9xCIHhIzbT51gIYpnrE7sjYpnbyyILtcmwleIQYK0pqSNyxBuAAlL0jAvQxm3
         I1pBkNwKG0ZznF8KkCpZqV00myp7ttBRXWhWhCZuOnTb7LE85kVxy479PUn6kbxvknG2
         Npsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7rVBmjBPaKbFzXGI4xWzGXS+NQnq3w6fFhrEq69SdrY=;
        b=bNwSYUJfme9kb9+2PpHW+vO0/u6gn1nWAXU7KONiu5SmkTJq4NTL6lIM6n9rfug41K
         AdIBZ+u6Om4vXXrP6AXFrN5DlLs84u28RUf++XW3O08dmKaR2O/K3QplXBAmlxOc2hDA
         O5Ket/gMUB8gCGWhVQ1TycbHrTqaGaUWGwTrUGFQAGBpTjUBbEL0/jqq7n9q5W1GS0U/
         XJ6waWE9vn3U60xuQUrh511Gp2ix54WRltzj+Syw0A+NoGg/zCrRbXc3jhvmcoIDuVlb
         czuJmSmEGRGlZi2wB5UEGFb9oDlpWCibBGiAq3T2hHtkdjvSOzMA0Umk6ekUyD8jPsDU
         +KSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZK4oh48g;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id p33-20020a05600c1da100b0039469a105f3si260745wms.2.2022.05.18.02.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 02:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id bg25so759235wmb.4
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 02:21:58 -0700 (PDT)
X-Received: by 2002:a05:600c:4f13:b0:394:8978:7707 with SMTP id l19-20020a05600c4f1300b0039489787707mr36021295wmq.34.1652865717906;
        Wed, 18 May 2022 02:21:57 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:450f:9c92:a170:5581])
        by smtp.gmail.com with ESMTPSA id n7-20020adfc607000000b0020c6a524fe0sm1409185wrg.98.2022.05.18.02.21.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 02:21:57 -0700 (PDT)
Date: Wed, 18 May 2022 11:21:50 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>, kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
Message-ID: <YoS6rthXi9VRXpkg@elver.google.com>
References: <20220518073232.526443-1-davidgow@google.com>
 <20220518073232.526443-2-davidgow@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518073232.526443-2-davidgow@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZK4oh48g;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Wed, May 18, 2022 at 03:32PM +0800, David Gow wrote:
> Add a .kunitconfig file, which provides a default, working config for
> running the KCSAN tests. Note that it needs to run on an SMP machine, so
> to run under kunit_tool, the x86_64-smp qemu-based setup should be used:
> ./tools/testing/kunit/kunit.py run --arch=x86_64-smp --kunitconfig=kernel/kcsan
> 
> Signed-off-by: David Gow <davidgow@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks for adding this.

> ---
>  kernel/kcsan/.kunitconfig | 20 ++++++++++++++++++++
>  1 file changed, 20 insertions(+)
>  create mode 100644 kernel/kcsan/.kunitconfig
> 
> diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
> new file mode 100644
> index 000000000000..a8a815b1eb73
> --- /dev/null
> +++ b/kernel/kcsan/.kunitconfig
> @@ -0,0 +1,20 @@
> +# Note that the KCSAN tests need to run on an SMP setup.
> +# Under kunit_tool, this can be done by using the x86_64-smp
> +# qemu-based architecture:
> +# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan --arch=x86_64-smp
> +
> +CONFIG_KUNIT=y
> +
> +CONFIG_DEBUG_KERNEL=y
> +
> +CONFIG_KCSAN=y
> +CONFIG_KCSAN_KUNIT_TEST=y
> +
> +# Needed for test_barrier_nothreads
> +CONFIG_KCSAN_STRICT=y
> +CONFIG_KCSAN_WEAK_MEMORY=y

Note, KCSAN_STRICT implies KCSAN_WEAK_MEMORY.

Also, a bunch of the test cases' outcomes depend on KCSAN's
"strictness". I think to cover the various combinations would be too
complex, but we can just settle on testing KCSAN_STRICT=y.

The end result is the same, but you could drop the
CONFIG_KCSAN_WEAK_MEMORY=y line, and let the latest KCSAN_STRICT
defaults decide (I don't expect them to change any time soon).

If you want it to be more explicit, it's also fine leaving the
CONFIG_KCSAN_WEAK_MEMORY=y line in.

> +# This prevents the test from timing out on many setups. Feel free to remove
> +# (or alter) this, in conjunction with setting a different test timeout with,
> +# for example, the --timeout kunit_tool option.
> +CONFIG_KCSAN_REPORT_ONCE_IN_MS=100
> -- 
> 2.36.0.550.gb090851708-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoS6rthXi9VRXpkg%40elver.google.com.
