Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMGUD5AKGQEUQWWE3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 873FE254DE6
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 21:02:26 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id j19sf2205753lfg.5
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:02:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598554946; cv=pass;
        d=google.com; s=arc-20160816;
        b=fY538uWQtsvqYknIFHsPmJF6bYAeD21ZTbEgj5losRhCrEVKcfvt/t/YbTgywPpa0L
         dN+fmepGN0kc8snhGBoWOjHOvsqXm+gGtmFDT25X01gjB7iWY9j25T6Dlzb+Kll2/eZw
         cGBC3by0aX2CI6BwRo08uPf+H+vgEL/SFxSwStcrYFZoRk7ex/Qdp/YJOs5oO/8KDLfC
         OKaDUTy3RTf4nxR6qwx534lCzDag4qM3XiU+usMmWe/RWO8RUH0oTStKSQTmb/GCJiRu
         Vo0Fdlw9lr6AKbuO5Om+6e5sLlElfiO0gnJlUSVwVK6PetcoDSTWwVcMEnhHt6ExO4JB
         9LMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=BdRyXCAityKQS1G6hjV1O9sagUw14LxyvsjhkczOoYU=;
        b=w9FaGhiMbzNw0wuy2cxD5l/Ycf72pExY9t8/6cKOCuC71fITpITj4+4dz6pkFTFQ/d
         O/YwJtvCPo3oj6zMLBed3sHHNcDkhIL/G+0vVU595iRZCcqYZVHCbh0JJllrm3yUgqdi
         arR3LfnhDARJSP1Z4PKK5aPDNK6drt1E8cWg5d9Lar5rDHESl+c3vBEk9Nt3hAAKYvnV
         W81ICKJhT//iDDtipgFv1Kfbo7uRmSGygnNoLKSzbzR8DPQBk5B7ViyuXpVf008idfp3
         53TOMFz9rvclwtgjbPljcIx5k5dypiB6V3jo2yDuaAa6GNhEwugo8/wnU1AyW6VtOYWS
         /qjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XyJ/7/Bo";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BdRyXCAityKQS1G6hjV1O9sagUw14LxyvsjhkczOoYU=;
        b=tJME1zM2FqMojlPPoK2y6qkAXZiDCKiOR+iMg07NxMr6q5eOJ9xIaRUPT8cMP0R4Yi
         ej1IXjhc3q1UAY0BSRoUj7oKDETcHkYKPT1SgeI3JGRo0BRrVBy3cBn8b+r83hcGx8fR
         PMVxlFRbrZ+Vyw8jLh8pzDTGV4ZOtx/P7Oc5yUuvqOAYuYTYjJao1YsEttnyI/Or5ZXg
         MQa/bB6XOtU4vpExROYfvdHWPs3aGMa542m2EBTe801+HD+gWg/qVcgbAl/AeDK1FeVt
         n20czwDw+ysTJD9eLL+gMT6uEQ43ukcjOe6MUKj+Om7pydXfrgxvYHQtnIQqzDoUGE7g
         4YfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BdRyXCAityKQS1G6hjV1O9sagUw14LxyvsjhkczOoYU=;
        b=E02XdInbF1qoCMcEgy1o3IGZVQPjbfqFwf4XP+19FhsiriJj5TIAg3ibVQZ6ZYpwKa
         Zf4ghQToRYI7+xQtjDI2leoSy/DUbHLegMp9bho0hB4RJg3Xh0INUKAJoI6D7SwAxYcI
         E9gIIXBE0ntPkFSzEiqBRjY2Ab6FiRcVwsDhdoaY6jtuIuJwcG4z6s/LyshnV5h/vp2d
         zyU/56T+3bgdW4kAfd+hl4sGinIl+5uZjPh+LHrlQAExTqLLkgz7sJGuOnB8d5WDU9V7
         CYEhtYuzwVn8Y02DaajQH+vE4oc0AF9X4O+sbeV2J1ncjI+z3lArfFMVrs0GWH8K+/Lh
         kspQ==
X-Gm-Message-State: AOAM530X+ZncFw9BRl5+oLvJe9FqMlNmE5P54+7Qcb0uZ5EMcHtru3jM
	lGw7OWytn8grosjMNv7lu44=
X-Google-Smtp-Source: ABdhPJxVu93tA2wWyvUCBy1pjd4YJEsAo2Qe1y9V6V6GybCsUoEhXI+y/32taU2DWKUCTGck6+Nc/Q==
X-Received: by 2002:a2e:504b:: with SMTP id v11mr3147795ljd.32.1598554946000;
        Thu, 27 Aug 2020 12:02:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e33:: with SMTP id o19ls310588lfg.1.gmail; Thu, 27 Aug
 2020 12:02:25 -0700 (PDT)
X-Received: by 2002:a19:3f87:: with SMTP id m129mr10255904lfa.44.1598554945076;
        Thu, 27 Aug 2020 12:02:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598554945; cv=none;
        d=google.com; s=arc-20160816;
        b=0+3gjFnD2PGl+tWFXiG8PI5IVvqRNjxBy661jDqNb5AGeFdL0Coh5xYGaq/QwemJD+
         YFpOhwuYiZhswEQx6YCuTiYp2g22+kEIPil9YODl3zfuM1/JsuaFQc726T+gmyl1Krqz
         O4SStT8/lDJti9fI3jI2J7kDcNYBKq+aPLY9GbSLlT5B9Zgn8znqks4DnseOUBhqszFn
         rJnodOc29CnDaLN9uX2mmJAeGK0E+ZG/qzgJjy8ti8u34JYJFpUNSX7uNnkm8m7ZrFoD
         FmeBQu9m1OJ1fugDin4jY4OE/iE/C5f88cdqpkENRjTD140nhNijCjGBOVVzpnIPVP5X
         577A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MgXI5yT9M2YWoB1R2sbphZ1sVTEoxpYWlpWN7CbOJSk=;
        b=leLldo4uAqoMX8LauNQ69pFahbjqXf/yU8KJaTG0AVbqzgrnI5Ez/dKJ4Qso2SyZsp
         PFSq7fTbOJIX1RPiEeX2wD9Ai1crh6FFs3TlE6WsEc7aW8+uid0kLXLQKYtHNotKJRQz
         6iDfNEeePC7LvsPzfileC6wR5wQYESvTSE4xZMkmEQpz0QE0t0fTe/VW29EyFHHuiDBc
         4sUgISvrgZ8rpOrHos9meVGkTB8oVtMd5JIPsl51MbNSlizgiJzuK0Sf9MS1aeb1rgz1
         PR7eGpoCD1v664H4DfoqtfYbG6KDgZiQ2WhAbnX2s1hzB4YHM03whx68nM1fwHawKeCw
         kHIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XyJ/7/Bo";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id f3si132829lfk.5.2020.08.27.12.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 12:02:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id f7so6385746wrw.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 12:02:25 -0700 (PDT)
X-Received: by 2002:a5d:43c7:: with SMTP id v7mr5200602wrr.27.1598554944300;
        Thu, 27 Aug 2020 12:02:24 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id c6sm7187094wrr.15.2020.08.27.12.02.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Aug 2020 12:02:23 -0700 (PDT)
Date: Thu, 27 Aug 2020 21:02:17 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <natechancellor@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Sedat Dilek <sedat.dilek@gmail.com>,
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Kees Cook <keescook@chromium.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-kernel@vger.kernel.org, clang-built-linux@googlegroups.com,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] compiler-clang: add build check for clang 10.0.1
Message-ID: <20200827190217.GA3610840@elver.google.com>
References: <20200826201420.3414123-1-ndesaulniers@google.com>
 <20200826214228.GB1005132@ubuntu-n2-xlarge-x86>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200826214228.GB1005132@ubuntu-n2-xlarge-x86>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="XyJ/7/Bo";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Wed, Aug 26, 2020 at 02:42PM -0700, Nathan Chancellor wrote:
> On Wed, Aug 26, 2020 at 01:14:19PM -0700, Nick Desaulniers wrote:
> > During Plumbers 2020, we voted to just support the latest release of
> > Clang for now.  Add a compile time check for this.
> > 
> > Older clang's may work, but we will likely drop workarounds for older
> > versions.
> 
> I think this part of the commit message is a little wishy-washy. If we
> are breaking the build for clang < 10.0.1, we are not saying "may work",
> we are saying "won't work". Because of this, we should take the
> opportunity to clean up behind us and revert/remove parts of:
> 
> 87e0d4f0f37f ("kbuild: disable clang's default use of -fmerge-all-constants")
> b0fe66cf0950 ("ARM: 8905/1: Emit __gnu_mcount_nc when using Clang 10.0.0 or newer")
> b9249cba25a5 ("arm64: bti: Require clang >= 10.0.1 for in-kernel BTI support")
> 3acf4be23528 ("arm64: vdso: Fix compilation with clang older than 8")
> 
> This could be a series or a part of this commit, I do not have a
> strong preference. If we are not going to clean up behind us, this
> should be a warning and not an error.

There are also some other documentation that would go stale. We probably
have to change KASAN docs to look something like the below.

I wish we could also remove the "but detection of out-of-bounds accesses
for global variables is only supported since Clang 11", but Clang 10 is
a vast improvement so I'm not complaining. :-)

Acked-by: Marco Elver <elver@google.com>

Thanks,
-- Marco

------ >8 ------

From 13d03b55c69dec813d94c1481dcb294971f164ef Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Thu, 27 Aug 2020 20:56:34 +0200
Subject: [PATCH] kasan: Remove mentions of unsupported Clang versions

Since the kernel now requires at least Clang 10.0.1, remove any mention
of old Clang versions and simplify the documentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 lib/Kconfig.kasan                 | 9 ++++-----
 2 files changed, 6 insertions(+), 7 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..4abc84b1798c 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -13,10 +13,10 @@ KASAN uses compile-time instrumentation to insert validity checks before every
 memory access, and therefore requires a compiler version that supports that.
 
 Generic KASAN is supported in both GCC and Clang. With GCC it requires version
-8.3.0 or later. With Clang it requires version 7.0.0 or later, but detection of
+8.3.0 or later. Any supported Clang version is compatible, but detection of
 out-of-bounds accesses for global variables is only supported since Clang 11.
 
-Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
+Tag-based KASAN is only supported in Clang.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
 riscv architectures, and tag-based KASAN is supported only for arm64.
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..033a5bc67ac4 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -54,9 +54,9 @@ config KASAN_GENERIC
 	  Enables generic KASAN mode.
 
 	  This mode is supported in both GCC and Clang. With GCC it requires
-	  version 8.3.0 or later. With Clang it requires version 7.0.0 or
-	  later, but detection of out-of-bounds accesses for global variables
-	  is supported only since Clang 11.
+	  version 8.3.0 or later. Any supported Clang version is compatible,
+	  but detection of out-of-bounds accesses for global variables is
+	  supported only since Clang 11.
 
 	  This mode consumes about 1/8th of available memory at kernel start
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
@@ -78,8 +78,7 @@ config KASAN_SW_TAGS
 	  Enables software tag-based KASAN mode.
 
 	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang version 7.0.0
-	  or later.
+	  is only supported for arm64. This mode requires Clang.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
-- 
2.28.0.297.g1956fa8f8d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827190217.GA3610840%40elver.google.com.
