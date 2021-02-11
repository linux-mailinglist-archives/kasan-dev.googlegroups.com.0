Return-Path: <kasan-dev+bncBDX4HWEMTEBRBC5AS2AQMGQE522VYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A44E2319411
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 21:14:04 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id z20sf5338152pgh.18
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 12:14:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613074443; cv=pass;
        d=google.com; s=arc-20160816;
        b=M1BnIyeAizHKBP7iRsX0/niv3AQ09x+Ccdoc2hAIaPGfEWOC5nDpDRRYxiVj2Hk/p4
         nI9Ue3P9neBBPF3VWLIq5fODkQAa1XB9aJUFmkCW8LDQjF8JCz6fJSsrM3XEGx3dDm3N
         gcAt58nVkVoMEv5FRTNeAVHDgqKqABlewA9OBro0tgH/0qEglFw8K9zrimnbdRkh+xui
         0NuuT193lsflNgGHyICVM+ucXNtjkY51COykqu2M7lIsEcEDdoSFfZmPgAkhmooOpqNa
         6oVZLLfEcBfByMKrt6RUSc998aW1DDFiX5WibYsSPF0TqbmVi7K6OxfTEHxmsmCQFR/6
         DI7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CnaFD79olBmKgRLi/DgzJZrsupcloEKlEYxy1cduBc4=;
        b=o6nshDvunYambVkMBG0pUMKPel3XDa4ub1X3W2c8rbCgB5he8YyEgUiZjBuvCkPMr1
         GPJr7Zhvpfi/lL4zBcnY52za/+mH7Yb+asq5Z4ajgsOzJ44thpoy7NNVxwxOiUjVLppk
         Ir6+jVq2JnGHbX7xoFHHcV+GIQUPpih7YQXYs/Y12+5y+vuHHU4Wnc2cyIjj7XRWjz5o
         eS+w7KGMHM6AMq3VeSXRO25b3n5YiUYdNOuhVJrfclUMIkAFhyl8x5nTE/UBS53/Lt6H
         qpbDSDgjZkRCdkMv3TMn1GSZkUiL79YFJdct62aWeePUNMa7Evu2Vb5j4rpcuoPrQad4
         0Evw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyBYEa2d;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CnaFD79olBmKgRLi/DgzJZrsupcloEKlEYxy1cduBc4=;
        b=axVkO8cT10/r2NdYb5T7/vj6+1NgE1+DX2QMALSyIvZdHW+0LciFOE0AyiD+GRDfVH
         1cfuh2yuMJBIZ5/MAIYPP5bl3+JvIxKUESA4sB6Ssa9kqrTKnkgJJXC4cFzwai7CCSZp
         mnTjFlw2VkrpOO2iGbAEHEv7DZb3FZAR43MVl1DkmjQjlaZSSRCmsqAHeSewm4VmlCjX
         OfiJ30HvzPZj3hrmQuQugHldRSXzxFTI+LkBkOA5PwxIlUZFPe50ml63BjsmhWr4a4j/
         L/jhDbzMbR8Sz3nAQUp2flNgfYkG8qdpyx4yL9PFCSzXqW4EGF4r55+l8CjcvQ5gjgAD
         DmOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CnaFD79olBmKgRLi/DgzJZrsupcloEKlEYxy1cduBc4=;
        b=ATlyOXRSVq7IwSCLBxF+Wg/PZZemx/mIiCrfO4/yTS15b5VmPyS9kWyFWf/GEDeMnD
         9fn96qRFmDyXInWnYjzt2yQP6xERltlFRUx/3gJUUN9JvwadFa9qxj3Om1Z0a/bbGwk5
         GT9fkwOgfvU4VKAWjvK31zD1ERno8lCy81eBuBV0aKCwNqM5yDbJu2SchNrCStCRpqhJ
         rMmd/6Z4rPsr5dNiMpdWiIN7BESI5EQwuHpccY8rXSAN0we7WxiwSEWBZA7/mGL5Iz74
         ahRO1OSCeNnreQZMXfSyl9Ih1B1O4VLIpNPEel0Eyds+IlA/0juL/exQ4JZZhv7JQhY0
         x57Q==
X-Gm-Message-State: AOAM533xusUIZn8dBWcjeVQdmurnO/t++23B1FxlSpqlx2gIAWGmYOAG
	Qolykk+Y64+VyxScVotZqn8=
X-Google-Smtp-Source: ABdhPJzR+VjekBGTRjFs4ACKrfmeZ0ZomCFud11bY0aDwmLPMtTVgt3NfTMRCxyjvO4gCQmztJD6nA==
X-Received: by 2002:a62:5303:0:b029:1d5:5b8f:ebd8 with SMTP id h3-20020a6253030000b02901d55b8febd8mr7163216pfb.25.1613074443394;
        Thu, 11 Feb 2021 12:14:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:88c7:: with SMTP id k7ls2496490pff.4.gmail; Thu, 11 Feb
 2021 12:14:02 -0800 (PST)
X-Received: by 2002:a63:db57:: with SMTP id x23mr9640024pgi.131.1613074442817;
        Thu, 11 Feb 2021 12:14:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613074442; cv=none;
        d=google.com; s=arc-20160816;
        b=F7my0ne0JPcBsy+/SwEhvz/pKBzcS13GMrAj+KzxFH+lEiPg2KBENMa3YaelRndbO6
         Xw72JGYRZtRZDZ6StGxKyyA6YucDhFQT4pg7X/J71duGa78gvTeEr7sPkntjCjLeNlOE
         bos0AZy+iSnAcIXaj1blGnNq2vvoenOL683g6ls/qcn8kh3h3LTP7XGITXW9BJFeP6Dh
         DbXKnxXWqrA+fXr7z9uC6mPJitSnR2DIIRin2sTUwSm4jhx/PfO8lulgKFBmpQf6k7h8
         ZtxtqXWjIArufO97hMjjcO+/FroFGr++yqBugoQupT0TY/9eM9q6LTwyk1Zz9FQXb6Ps
         znfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R0+Rd3SMlnTZL3B0kN7kR2b8yNSNIxsbDEg4HntAOQk=;
        b=pHjW9TWwU4D4Fa7mDx3f3+IPkOJpPAZQKPpua/ivrv8tdDE+uK6H5PX/BG+D7XBtWi
         S1gtCrjyR5bMw1xx7qrnHORCgXP5+HxJrKigmK6I/P3UiL86UG0HLANd+uQprhEEFUaw
         VVJLOw7wBbxIjGsykEnqz9DGy78M8V4Btd5HNRgULEE5vGO1FQBXmBo0VIPHjmB5/D3k
         rFgAWxTWPeaugVz9wu0a+KvcA7pZVTrY+UR9CqNuTvnVmsgLV3xyRo3KWTQFGZbzdTYs
         MB77lBMLOD8FsAxLeuh62RvYKdscdELOhsh595P5BqnyAy0yUWELyh+nI8impeezYe+9
         Ystg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyBYEa2d;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id v7si328216pgs.2.2021.02.11.12.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 12:14:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id q10so971269plk.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 12:14:02 -0800 (PST)
X-Received: by 2002:a17:90a:9ac:: with SMTP id 41mr5503516pjo.136.1613074442341;
 Thu, 11 Feb 2021 12:14:02 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-4-vincenzo.frascino@arm.com> <202102120313.OhKsJZ59-lkp@intel.com>
In-Reply-To: <202102120313.OhKsJZ59-lkp@intel.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 21:13:51 +0100
Message-ID: <CAAeHK+yB4GLCn2Xu4z7FRLNOkVDFr0xXN3-D34BdJbRmWLpSxA@mail.gmail.com>
Subject: Re: [PATCH v13 3/7] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kbuild-all@lists.01.org, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JyBYEa2d;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Feb 11, 2021 at 9:04 PM kernel test robot <lkp@intel.com> wrote:
>
> Hi Vincenzo,
>
> I love your patch! Yet something to improve:
>
> [auto build test ERROR on next-20210211]
> [cannot apply to arm64/for-next/core xlnx/master arm/for-next soc/for-next kvmarm/next linus/master hnaz-linux-mm/master v5.11-rc7 v5.11-rc6 v5.11-rc5 v5.11-rc7]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch]
>
> url:    https://github.com/0day-ci/linux/commits/Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210212-004947
> base:    671176b0016c80b3943cb5387312c886aba3308d
> config: riscv-randconfig-s031-20210209 (attached as .config)
> compiler: riscv64-linux-gcc (GCC) 9.3.0
> reproduce:
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # apt-get install sparse
>         # sparse version: v0.6.3-215-g0fb77bb6-dirty
>         # https://github.com/0day-ci/linux/commit/df25c9583cd523a49f2407e0aeee55bdec24a14e
>         git remote add linux-review https://github.com/0day-ci/linux
>         git fetch --no-tags linux-review Vincenzo-Frascino/arm64-ARMv8-5-A-MTE-Add-async-mode-support/20210212-004947
>         git checkout df25c9583cd523a49f2407e0aeee55bdec24a14e
>         # save the attached .config to linux build tree
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-9.3.0 make.cross C=1 CF='-fdiagnostic-prefix -D__CHECK_ENDIAN__' ARCH=riscv
>
> If you fix the issue, kindly add following tag as appropriate
> Reported-by: kernel test robot <lkp@intel.com>
>
> All errors (new ones prefixed by >>):
>
>    riscv64-linux-ld: mm/kasan/report.o: in function `.L0 ':
>    report.c:(.text+0x480): undefined reference to `kasan_flag_async'
> >> riscv64-linux-ld: report.c:(.text+0x5c4): undefined reference to `kasan_flag_async'

Let's do something like this (untested):

https://github.com/xairy/linux/commit/91354d34b30ceedbc1b6417f1ff253de90618a97

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByB4GLCn2Xu4z7FRLNOkVDFr0xXN3-D34BdJbRmWLpSxA%40mail.gmail.com.
