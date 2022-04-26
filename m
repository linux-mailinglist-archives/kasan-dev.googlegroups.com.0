Return-Path: <kasan-dev+bncBD52JJ7JXILRB2HNUCJQMGQEUIJBHVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 369BB51068C
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 20:16:10 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id mm2-20020a17090b358200b001bf529127dfsf1502741pjb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 11:16:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650996968; cv=pass;
        d=google.com; s=arc-20160816;
        b=LjP8NDWwgFiF1hJ6BJ99nD1NcLRUDlfiLy1OcKaVsJ2yrbn7Kxxxc6WBlQ+y211mMw
         dv93k/Ot5BWA3fEqrQB01alad4MnO+bNcunc8bUvXdWycCkpOCx8mxXUismi24xSPv7d
         Jv34XpVNjIYqQ6G1XvI5HRzzwssmit7QF1+NFr9iD+g+6XYZcVbNT4mqT8OqQRJcgDs2
         FeInU6jeJr8TptQu31oyjalMckr6bGQS054EiAXDEylCn9/VAookKiVAX7YXF4KogiBh
         Qma5IiNaLpi0u86lBlv17lzoZBQaj60u4JdGQ+37I1i60algIMpfd0sTpmVk4xhPu8dt
         Jx8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kcvbEy6uwTcKSx1vxmXw3FwDPDtIRJBMyIJmBywRlMM=;
        b=rxAJXXbojVqxdTmHwLTQRAKy3dtEtOTBOM/91vNJLuDOlEkcVSUgS8PwSy4WICCDyR
         M5gMnum6RYNV20Es693V6FgOiNW9jyL03mY3vpTGehMHub+kkj26hORfOlL4q0CcyV1c
         WcY9WYYe9CatW9+IG8hWqnRhsn3L88fy0a8lk9+F8ATCYp3bfzAgTl68ZpcatTFHhIxh
         A/hrZ2ii2wSi/kw3GkXlf6ptq2PZJv/v53bWyUcbrxivfrYss1rE/IhWnEjxizwDqbus
         QyhDc7XyH+snpjzuzInkydqIncjjHSpRjzza2GZvh0lXb2hdWkoE8pnQoYBIoqZhDLLd
         0Acg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LMed7+3W;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kcvbEy6uwTcKSx1vxmXw3FwDPDtIRJBMyIJmBywRlMM=;
        b=HxdQGHGduhuQ46bwnqA44+8nvT7IBE0TpyYqsaJa/4loDTfL9HD0phWcgvvbOCu5UL
         JKbovRkVDg9TudOAoIIx8pcgzzz/BnhOuGol3s7aG2Y0ctjWM2LY51EgkQk3ntbP5Guq
         eDZQ28P/Y6hLcK+KpWe2aNmwjsx9GL8GROOrmnF7H5mKqrmffaOF73VRTlTr639+bDJB
         GsOOQAT9b24noU/0/Hv4migY/OzWIfSRTSCadTfJiw/AjlzpmBq+BP2+KNdKw6Etp6m8
         sL2KYZbx7YJIRsCt2lCIMabbntA9Pi+YwpjqiQFYvHjAUhvSUAano68TaW4s8ljV9koc
         n2hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kcvbEy6uwTcKSx1vxmXw3FwDPDtIRJBMyIJmBywRlMM=;
        b=uU7jlc+gC4VvG2qvXO6Kqbux1C3a1ewzMU5fWhJ9uzAw64AUknQHfh4Iovryd3rUFz
         4iYA801Wg7hq2/VvzeKaZdZkNGOpUlcEyxIP4U9tRIcfjFwwnXDZxSVKd+dltyCvOnCx
         AVMIkss159jEoAgM5qc0ysdPPD0K4DKPFeqAbFScHCEx7cdj/At+ycII1Ga1So8pmmzP
         KRnYu89YvvD/uNIwlPcPs6pbEf2knYsfNOSXnOZrkvihGM8F2BK4N7Ep10y6kHNc+lnG
         Kl0eT82W2wvfreQc8fA0nRUGAye2/WedNYYKuWP9Ly+nqiHU5jvjDbPeI7HQMJkn7j9U
         5kvg==
X-Gm-Message-State: AOAM532bEJUxhsHh52c5cYOGso263XE36sEKJv7Pcydpx4urMh+b3uJW
	8tT0/p2nVd9FK37TQpiUPug=
X-Google-Smtp-Source: ABdhPJyyYePTS2uaz++LENerfgjkM0EWxMTpF88KzMOKz1K61xfuXICXIMV9q52awt2DCbtWunieag==
X-Received: by 2002:a17:902:e542:b0:15d:1ba:78d9 with SMTP id n2-20020a170902e54200b0015d01ba78d9mr13921237plf.107.1650996968612;
        Tue, 26 Apr 2022 11:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:ace:b0:505:bb88:8eb0 with SMTP id
 c14-20020a056a000ace00b00505bb888eb0ls6412778pfl.10.gmail; Tue, 26 Apr 2022
 11:16:08 -0700 (PDT)
X-Received: by 2002:a63:8b41:0:b0:3ab:6c5:79ba with SMTP id j62-20020a638b41000000b003ab06c579bamr13365014pge.382.1650996967962;
        Tue, 26 Apr 2022 11:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650996967; cv=none;
        d=google.com; s=arc-20160816;
        b=F2RTcKcQFZLuEWuVDlIkLD3h0WBoleqFJ41DX+fnf5nLxmum9F+jsRbCMB1P1oyb14
         +bmNk+RZ5yKuN/V9l2NuJzhL+flDKp7u0jdKVIc6V+xs8S4/WYZev0/JtjygAyyNveiY
         wz6J3lU24BcVLapDwbMSe+6bozmwxN9SKbQ/aoybDCnzh1I3xu1JRubmQdedatYxyqF2
         HpevFe2fxUYkv5VVJ+xSA5CEO0nYyZeM0jNITlxvdI17gkcWuFzbqGtqQ4BWuFuS2d4R
         GeD5AZkGYvPxaS6fWuqq2DXAfX6lkGHrhXbl1kbFk0MgEfUgmdVAzoOSYSlnv3iCpqRw
         1RlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NHalnczSrgV7nsCOyAK5ppIla2Ja271UVepo2Mtht40=;
        b=SDHioL16uSxvijW92tt8UHbKu/oRQavlCkYycivgfNmpKt40WzQadNwBXeu49bEMRm
         kawSQ3ONM0wJUHMFK5FQQH6BYbCJLhBof/6+KbvDF/KfM08m6/MttYYYgemoRip5bFzh
         laK6T0waIik2v5YSVYHO5fZXHHy05Qoge7jzbr5b2jkonCG89a5ZAYJqmPx0UmVEyVQY
         0G6sDxAXwoYNm4fpcvJaL3wyTeuaEJdcgl5WJyE9huoYN0ZDFHDxMNqPXL0HR7gs3xap
         NHpIlThSD4yBgB0D1Re4xDS5ANoaVLIMfd8zqfNOCgWmY0AFyWs3j6n7EZHyGoMvafWu
         KUaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LMed7+3W;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id h2-20020a170902f70200b0015a1cc64912si1438623plo.3.2022.04.26.11.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 11:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id w187so25065474ybe.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 11:16:07 -0700 (PDT)
X-Received: by 2002:a25:b3c7:0:b0:623:e9fe:e108 with SMTP id
 x7-20020a25b3c7000000b00623e9fee108mr21492504ybf.335.1650996967408; Tue, 26
 Apr 2022 11:16:07 -0700 (PDT)
MIME-Version: 1.0
References: <20220422201830.288018-1-pcc@google.com> <202204251346.WbwgrNZw-lkp@intel.com>
 <147b11c3-dbce-ccd3-3b0c-c5971135f949@suse.cz>
In-Reply-To: <147b11c3-dbce-ccd3-3b0c-c5971135f949@suse.cz>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Apr 2022 11:15:56 -0700
Message-ID: <CAMn1gO7=PEz=TbDqBV+NnjyZ6pjOgYjAhfdcp4feSTX7W=B2ZA@mail.gmail.com>
Subject: Re: [PATCH v3] mm: make minimum slab alignment a runtime property
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <lkp@intel.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, llvm@lists.linux.dev, kbuild-all@lists.01.org, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	roman.gushchin@linux.dev, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	David Rientjes <rientjes@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LMed7+3W;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::b2e as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, Apr 26, 2022 at 8:12 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 4/25/22 07:12, kernel test robot wrote:
> > Hi Peter,
> >
> > Thank you for the patch! Yet something to improve:
> >
> > [auto build test ERROR on hnaz-mm/master]
> >
> > url:    https://github.com/intel-lab-lkp/linux/commits/Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
> > base:   https://github.com/hnaz/linux-mm master
> > config: arm64-buildonly-randconfig-r002-20220425 (https://download.01.org/0day-ci/archive/20220425/202204251346.WbwgrNZw-lkp@intel.com/config)
> > compiler: clang version 15.0.0 (https://github.com/llvm/llvm-project 1cddcfdc3c683b393df1a5c9063252eb60e52818)
> > reproduce (this is a W=1 build):
> >         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
> >         chmod +x ~/bin/make.cross
> >         # install arm64 cross compiling tool for clang build
> >         # apt-get install binutils-aarch64-linux-gnu
> >         # https://github.com/intel-lab-lkp/linux/commit/3aef97055dd4a480e05dff758164f153aaddbb49
> >         git remote add linux-review https://github.com/intel-lab-lkp/linux
> >         git fetch --no-tags linux-review Peter-Collingbourne/mm-make-minimum-slab-alignment-a-runtime-property/20220423-042024
> >         git checkout 3aef97055dd4a480e05dff758164f153aaddbb49
> >         # save the config file
> >         mkdir build_dir && cp config build_dir/.config
> >         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=arm64 prepare
> >
> > If you fix the issue, kindly add following tag as appropriate
> > Reported-by: kernel test robot <lkp@intel.com>
> >
> > All errors (new ones prefixed by >>):
> >
> >    In file included from kernel/bounds.c:10:
> >    In file included from include/linux/page-flags.h:10:
> >    In file included from include/linux/bug.h:5:
> >    In file included from arch/arm64/include/asm/bug.h:26:
> >    In file included from include/asm-generic/bug.h:22:
> >    In file included from include/linux/printk.h:9:
> >    In file included from include/linux/cache.h:6:
> >    In file included from arch/arm64/include/asm/cache.h:56:
> >    In file included from include/linux/kasan-enabled.h:5:
> >    In file included from include/linux/static_key.h:1:
>
> Hmm looks like a circular include, cache.h is too "low-level" in the
> hierarchy to bring in kasan->static_key->jump_label.h definitions?
> jump_label.h does include bug.h, but we have it above already and have
> already passed #define _LINUX_BUG_H.
>
> So, a different kind of header with arm64-specific variant?

The fix that I'm pursuing starts with:

diff --git a/include/linux/printk.h b/include/linux/printk.h
index 1522df223c0f..8e8d74edf121 100644
--- a/include/linux/printk.h
+++ b/include/linux/printk.h
@@ -6,7 +6,6 @@
 #include <linux/init.h>
 #include <linux/kern_levels.h>
 #include <linux/linkage.h>
-#include <linux/cache.h>
 #include <linux/ratelimit_types.h>
 #include <linux/once_lite.h>

and fixing the fallout from code that was including printk.h and
depending on something from cache.h. So far I haven't found much, only
3 fixups required for an arm64 defconfig kernel but I'm trying some
more configs as well.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7%3DPEz%3DTbDqBV%2BNnjyZ6pjOgYjAhfdcp4feSTX7W%3DB2ZA%40mail.gmail.com.
