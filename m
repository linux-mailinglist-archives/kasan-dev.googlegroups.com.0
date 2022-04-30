Return-Path: <kasan-dev+bncBCA2BG6MWAHBBG6QWOJQMGQE5X2MM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 68531515B0C
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Apr 2022 09:41:16 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id p5-20020ac246c5000000b0047257761087sf512867lfo.7
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Apr 2022 00:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651304475; cv=pass;
        d=google.com; s=arc-20160816;
        b=uxls2eV+d1t4K+wpRufF6sjF0TZ+IO5in1z1B2d2MDbI11rC6lhQgGIBLMTq48IzS9
         0fUBbqM+g1nhLBVikM0unShlQjSwKncLnxaGLiANiS32PTb1uj9K3vfQs9OeULF33ysS
         F1C2+8oDRuEoVjumR7HnOqtP6v8Q6WbGmrVetzVRERUiovGcBS4aDjcBPBjHvY5wYaps
         Hlb81ibJ7mr+C/u5/v3KyKImaotx1/H8n+0jvgbv6jm6JrrEW5GnQzopsfm4jxxieB0x
         AKKczIYaV3ji/7LZ4jT5tRPuBNELYsOzHBQcedt3qy/qSKZSaTAuP6c6Lp9ERleOUd50
         pCfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GEqNv4ILq+cK3BGIocgG8EZUMEE8J8JkgOMBSMwHw2Q=;
        b=GjXy8TzyWP6GIKDUEkED6LVrx4eNovGzcxjwcA0ilMP//F+9ATfV0hn0I+0xsQrI+H
         j4JF+fjSOmxmoVJCaufwEc6KiCwPQNIk1J4eyTj6ZJ/+26VGlARLqaud8vjDB1VZvjRi
         DHOwegO0h2Ux4O8BBbGr3AYeMXW5/zl5inmOEVknCwsv313+J0hcNh/S2MN0vI6ILMAQ
         XZLefqNdA1aVzebPzSzXcsTTLgC+sFKVZ5W1yEg3DaLVD3pZ3VKLBprUB2zSwVeItG7f
         FHrijZnhCSjcqiPjHyehjEZBcPq36/NpvC52W8pcZn0wETIYKOuRsu5ZDR3ROQF4lMrt
         0qkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoJDMlDR;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEqNv4ILq+cK3BGIocgG8EZUMEE8J8JkgOMBSMwHw2Q=;
        b=OAG0ATcOqvxOe58I1Ny1IM+Xhk1E7tk5qzgzX5CQXD6c/ASULYhq+nIg5TWEOGFnAn
         CN/lVNCpSE6FXGg9CDGELmKewy6nhqDDNnHyJUPrMX71DkiCZvhTAvVhZsn0hEKY7gcL
         dJuXJTEgx/uqTspF4wccWmuvnDYuo/P125S+WBxKc65IypeAqGC3zTeE72Hj3IxMUlOM
         DciFuW6Un9vKDPSb5EXwSWabvtGJ23MSpuf1FVaK5gcYmWaho+tnbspaW4eWCYbzLUF7
         a2TR8I2vwipPCqHOtZthYOe0rrkhnEEszuewXKWt7TrJZBBQdwrg8tyTHfu+faa1QyO3
         9tlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEqNv4ILq+cK3BGIocgG8EZUMEE8J8JkgOMBSMwHw2Q=;
        b=CMXLYJPMvi13RUoLqtxyTB0BihLbXgTTQMUI5kg7UvMNlwYFl8QkNbIUHUVvkpWPWv
         OVY7BicBCrI5E7xe++CKxSFWhXgJzuwMENAmDRiQqqDRSqRo5WIs000+ja8aV/JpLBt8
         8PkA+gEBwHnnx7zrYuZyXhFqPOl+uQVhTAEoQWs3ktT1DWUo9LMMfxIzEMApW0OHa1RQ
         y0wBr0mSBuTfBrH752Bjqu8Z+XfI+m3aqaBw6c9scCRYwAJj/ZHddlhaprLQT/RD4nTx
         NiGkBhMyAr63ALD73eOt0TkNfy7FQ4tfkSxNDFlwD0HhM8FG9FMuCnzf+09MGQZOmdcG
         HDkA==
X-Gm-Message-State: AOAM532qWXFcLtJnFMCwuZ7Gc7SSleOgrtm88cZpI5ONjH1XtC/mubDW
	JGLlL6XslSSN8XOlsSzOrwo=
X-Google-Smtp-Source: ABdhPJwYqGPVoBZgZMx/wZ5ySWMuHLciuo5mvKfpljhmjvTWufmZK4039MIqgG/ipD37VfbbccX22A==
X-Received: by 2002:a2e:91d8:0:b0:24f:1656:eaa0 with SMTP id u24-20020a2e91d8000000b0024f1656eaa0mr1992018ljg.444.1651304475487;
        Sat, 30 Apr 2022 00:41:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:17a4:b0:24d:5627:cbb7 with SMTP id
 bn36-20020a05651c17a400b0024d5627cbb7ls933019ljb.0.gmail; Sat, 30 Apr 2022
 00:41:14 -0700 (PDT)
X-Received: by 2002:a2e:a7c5:0:b0:24f:4056:f4b3 with SMTP id x5-20020a2ea7c5000000b0024f4056f4b3mr1920398ljp.285.1651304474103;
        Sat, 30 Apr 2022 00:41:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651304474; cv=none;
        d=google.com; s=arc-20160816;
        b=F9EeM7wz3Fikjf+5t/w5YmT7Q1HokZxhin1v/jlUZma6ogTBUFrfmmUXiJr/HHlJe8
         T7ajYYrZKE3TG2zH9odDZjpLXLwE3gFVtxLY8QKC6QGyzR2/HW0thmKxC1i5wG7jb89x
         +2NZP7rRfevyJzPq5RvQl4SFdxFb7KiTjELcW74w5NgseIbgZDG83fi+IZcRy9Dn7UPK
         whXtCeKQpzbZZ5kcFpzE2Ji+gFtytKK041OHyJz9rssngb0My00pisV14T1j3kD7HDqr
         ALBgtzVpEoYd3rwQzcRSua/HW3O3xxoB29C3pXjxxolyqDQQJOpMIsIWH1SfbLnl8dDa
         ZqwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kwPZKfu//VArF+FVVE8zbUqlSbSrCotry34rYD1+ekw=;
        b=vlKdVA7QfYXFHpUWCUUZ3IuTjRzieeEDag/l8oK4CVa+XYDU3I07qmf1IVoA6jxaCe
         ewwIE5cGNo2b8W2XKl7+HxaleJp/JjuD4FWn9R62KXTqzHaA6wrlkL200JQkedWZtkqo
         FCIlJHilNVeTUWtCG5MOmStHBhWUaWBKej0A8Re0I9PdkRHoQE0+hXRnNdywP9YLgSNJ
         sy6ugvi9L12UHofdYxxmG1QBK1UGJNPXHjOqMhFWkX/yAeFZ5Ph3/yWicqg08c76YnDj
         YNFH70gbZ0l9vJx2H3kg45WCIMmpPXrtM+XtbcWd4Aid+I6EZFuvJb7ZMY4qZnhuzU3n
         SHqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZoJDMlDR;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id x24-20020a056512131800b0047216d2d1a9si516998lfu.2.2022.04.30.00.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Apr 2022 00:41:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id p4so11438861edx.0
        for <kasan-dev@googlegroups.com>; Sat, 30 Apr 2022 00:41:14 -0700 (PDT)
X-Received: by 2002:a05:6402:1cc1:b0:413:2b12:fc49 with SMTP id
 ds1-20020a0564021cc100b004132b12fc49mr3364804edb.118.1651304473460; Sat, 30
 Apr 2022 00:41:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220429181259.622060-1-dlatypov@google.com> <20220429181259.622060-3-dlatypov@google.com>
In-Reply-To: <20220429181259.622060-3-dlatypov@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 30 Apr 2022 03:41:02 -0400
Message-ID: <CAFd5g469Q2hF18HXgAhs=3ds_=Pw-s2yw3=msaCucJs-JVFmfA@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] kfence: test: use new suite_{init/exit} support,
 add .kunitconfig
To: Daniel Latypov <dlatypov@google.com>
Cc: davidgow@google.com, linux-kernel@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	skhan@linuxfoundation.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZoJDMlDR;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Apr 29, 2022 at 2:13 PM Daniel Latypov <dlatypov@google.com> wrote:
>
> Currently, the kfence test suite could not run via "normal" means since
> KUnit didn't support per-suite setup/teardown. So it manually called
> internal kunit functions to run itself.
> This has some downsides, like missing TAP headers => can't use kunit.py
> to run or even parse the test results (w/o tweaks).
>
> Use the newly added support and convert it over, adding a .kunitconfig
> so it's even easier to run from kunit.py.
>
> People can now run the test via
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=mm/kfence --arch=x86_64
> ...
> [11:02:32] Testing complete. Passed: 23, Failed: 0, Crashed: 0, Skipped: 2, Errors: 0
> [11:02:32] Elapsed time: 43.562s total, 0.003s configuring, 9.268s building, 34.281s running
>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Daniel Latypov <dlatypov@google.com>
> Tested-by: David Gow <davidgow@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g469Q2hF18HXgAhs%3D3ds_%3DPw-s2yw3%3DmsaCucJs-JVFmfA%40mail.gmail.com.
