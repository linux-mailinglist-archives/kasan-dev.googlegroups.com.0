Return-Path: <kasan-dev+bncBDGPTM5BQUDRBHMJUHZQKGQEM7KNB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 99471180DCA
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 02:53:34 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id v205sf1190590ywb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 18:53:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583891613; cv=pass;
        d=google.com; s=arc-20160816;
        b=tbWSBtyGgc9N8Vi1QMgSEPGWTsAWUKYfaWiYQUVtbvJqdlSpwlzis688VE1rdiocvp
         c8GWjuSlf4jHOpfYmK6eY0QCh7ug4pR1q8Vyylt+iuorJqMdwNF904aYuvSHJ4OHws8N
         g39WTAULhr//+tOj10DEVavxezLysB1T0aVAJ0MHIdkpnO+BFotZ9UI+TqCO2ggVdNqi
         wYnAoEVJNt0qgILTnNgkLZweC730hhYmVJYo/5ipiF9HYaKzYP7YgDW8fKoBCm+dlSyF
         kzXlZ5RFrk7dbxQxlMkqPJ973TqK0cD6PxuYVfAkcgXEwWiqJCNz32DGt50My5m4BzfH
         48vA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=kMxgnSVsml4qsnRLUCq5e0ALNIw1Mc+IVcRadA003oQ=;
        b=IM0xGuwjn3W6QRckH8LRt+VtvC5J2MYPMA6IMHD9q0onEIXm1gr7s2law+eP29Hw9s
         BdZ96BB3CvKOPBxigPAkBH5JjMz3rD/1PEbTGoTP9rqnwLwPHz7tOI5CM/qRLHLQHR94
         6gltHTwF97MprS+RN+1rz5lB4lSf92GSTG1oUrPuqo5cHcHzcVeS9UoHxm5gKz1/62W7
         YXvN1mPT/ea3x9E/fz7vRK2bCz+ojRHlzKxzBplw7cemHvEC2ArP6dCi2lL8r59cdNkA
         HK+7x9shLPoHRKB/fYU0PTUeeLT4sF1Ufj/OqecQR1egknmHOi0vjMnp08iAIs2sC5Z4
         7vAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=KOftGtCh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMxgnSVsml4qsnRLUCq5e0ALNIw1Mc+IVcRadA003oQ=;
        b=M82dwkOBSR6g2pbqED/jahdakmZDyLeO/7igTvUMcqxwdDUKtQjY9zFZvW/oOZVzOD
         do0U0Jq2EPVoS0kCliWmqhQHnI57jV4AH5VO2QlCioxKD46JMdQvoKv5RMwbpqE/Xy3r
         waVHdkU+9ckZ6TnfRnWn0Wm58GXuHFKpU9cg75pSkuL+qul6jC0tKeb2kShPdY7Zgj8q
         C3Xu8Cj4Quvs5kNjJcC7gfeIjqn4l+HRAGOkTFEjjfUBob01LTTfEpzKyjL92RO+PW+y
         t8mcsyrBNqkuY5NPNccsachTpWHJ66CohH252MC9a6b9Bc6IPmB+MKfU/ffGjEGMpXDC
         KtOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMxgnSVsml4qsnRLUCq5e0ALNIw1Mc+IVcRadA003oQ=;
        b=fl6ZMQsEgomJmpnJFwmiCNkC6oht2INPkfiWje+n07LBNN2mCiUQ8DLnRGB965+8fg
         2yNqzxABcoYSbXFLVYUh7lrOK3zBGewdZvFjvVh66yO+SdJn1qxCfFht3sVM+rCY7ULN
         /L7AP5IER9xEW6fsuyfyRMjtQu2bUR18OxS5Fg4lPdPegYy9kT3nWVPPHXSwAMJ4zBd0
         Ux5JB5Vre48WrFNsx2xM+/u3gLI4VppEwOkzwXkLtBUpSgi5g75oFAt1j0fq3s6sVy9A
         vwNCvFH4k0K7OSZJvyKhSeeZKN5I5W6xaEWCWSFnUdxZqgB5NxQJGjcWc4Dc5HtkQag1
         gk6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1ULFpeB3IjUDAG2VJ4uAE1o9d3mxez1CtWEy/rx0irIxD9QV2b
	dJjQ7qENNTus04i5e+aEqRA=
X-Google-Smtp-Source: ADFU+vv5k+/d+aMwTSQ+kXyaprKhGk5cz9DY2marCDZQp84HwH6qX7i9mIPd3PcKYPdS38h3X7N72A==
X-Received: by 2002:a81:39c4:: with SMTP id g187mr811162ywa.42.1583891613273;
        Tue, 10 Mar 2020 18:53:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8d53:: with SMTP id w19ls139141ywj.8.gmail; Tue, 10 Mar
 2020 18:53:32 -0700 (PDT)
X-Received: by 2002:a0d:fbc6:: with SMTP id l189mr757420ywf.335.1583891612088;
        Tue, 10 Mar 2020 18:53:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583891612; cv=none;
        d=google.com; s=arc-20160816;
        b=hjwBaZInNGtJLO+HHmLNWqf52AadDRY7ZdhvojcFLslxDlP+g25AosjOgpkcA3Cmm0
         kE6mBkaqVRRYaT4C8DQIXaS4IusYqibplXPAaxcaPbJvEAtK1HzT8LxhWcHke3VEaFk0
         N16aHtu07asPDPGxyOLMSoBui4Bw5F3tn44XORZPICJzw9jdtJ7z8k8ZpEO9hy064Png
         tOoZsVcuS0okbJet1lvbjX/nXflKLPtrPUUZ8Td4ztt7VzqCm77gBVcxBuyEqEZEdyeL
         VHt/tiFWdAUl391kbSSl/daxyNjZ+Uaww4DEpg1mpL+09al/9QtJ1uBh04aaXkS2EzYd
         9uJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=MeJypbtXZBi16e+sneeWLK3w3UOQDEmwsecp62tfwK4=;
        b=CZ5up1b6Z8dOIJevLqOh30tHJYV+5tUrb4QI+2DyVFl7UN+zZ8M5fQKAwrEHKW+PBu
         lDE7yLqg2Bq0W4+DTBlFbplhoHJwBhlAs/iq2A92JM4jV5uOToTrAJ7sugBovDAGUQQo
         UvnWUZhSm3hTuqea+LC/IqOqpoPFf+GBtaSdwiul/NuGl16iagsRUU0SaVSdkEVd5byj
         KH8PTGltP3oDzmXjzTn5egQMVJginke+3kMOJOG2yj7uC9dagWfjaMgDiyxIIUXJh4up
         WDmB1KM7ZeZd9tQ6iX/MI2rB8c61nnCt5S0bOQ9hrhTNVlXsT0p81tGcPGIuWhf4NEpb
         jm5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=KOftGtCh;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l1si47754ybt.2.2020.03.10.18.53.31
        for <kasan-dev@googlegroups.com>;
        Tue, 10 Mar 2020 18:53:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 6a56e4500bd34b35bb8a16fe0d916be8-20200311
X-UUID: 6a56e4500bd34b35bb8a16fe0d916be8-20200311
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 445182679; Wed, 11 Mar 2020 09:53:25 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 11 Mar 2020 09:52:08 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 11 Mar 2020 09:53:31 +0800
Message-ID: <1583891602.17522.17.camel@mtksdccf07>
Subject: Re: [PATCH -next] lib/test_kasan: silence a -Warray-bounds warning
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
CC: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, kasan-dev
	<kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Date: Wed, 11 Mar 2020 09:53:22 +0800
In-Reply-To: <CACT4Y+aV9BrvEHdaadL7FXsjMi4iPDJUnK8eyJj=HuZFa4fxuw@mail.gmail.com>
References: <1583847469-4354-1-git-send-email-cai@lca.pw>
	 <CACT4Y+aV9BrvEHdaadL7FXsjMi4iPDJUnK8eyJj=HuZFa4fxuw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=KOftGtCh;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Hi Qian,

On Tue, 2020-03-10 at 16:20 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> On Tue, Mar 10, 2020 at 2:38 PM Qian Cai <cai@lca.pw> wrote:
> >
> > The commit "kasan: add test for invalid size in memmove" introduced a
> > compilation warning where it used a negative size on purpose. Silence it
> > by disabling "array-bounds" checking for this file only for testing
> > purpose.
> >
> > In file included from ./include/linux/bitmap.h:9,
> >                  from ./include/linux/cpumask.h:12,
> >                  from ./arch/x86/include/asm/cpumask.h:5,
> >                  from ./arch/x86/include/asm/msr.h:11,
> >                  from ./arch/x86/include/asm/processor.h:22,
> >                  from ./arch/x86/include/asm/cpufeature.h:5,
> >                  from ./arch/x86/include/asm/thread_info.h:53,
> >                  from ./include/linux/thread_info.h:38,
> >                  from ./arch/x86/include/asm/preempt.h:7,
> >                  from ./include/linux/preempt.h:78,
> >                  from ./include/linux/rcupdate.h:27,
> >                  from ./include/linux/rculist.h:11,
> >                  from ./include/linux/pid.h:5,
> >                  from ./include/linux/sched.h:14,
> >                  from ./include/linux/uaccess.h:6,
> >                  from ./arch/x86/include/asm/fpu/xstate.h:5,
> >                  from ./arch/x86/include/asm/pgtable.h:26,
> >                  from ./include/linux/kasan.h:15,
> >                  from lib/test_kasan.c:12:
> > In function 'memmove',
> >     inlined from 'kmalloc_memmove_invalid_size' at
> > lib/test_kasan.c:301:2:
> > ./include/linux/string.h:441:9: warning: '__builtin_memmove' pointer
> > overflow between offset 0 and size [-2, 9223372036854775807]
> > [-Warray-bounds]
> >   return __builtin_memmove(p, q, size);
> >          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >

When pass the negative numbers, then there are two warning. In gcc-8 the
warning is checked by array-bounds, but in gcc-9 the warning is checked
by stringop-overflow.

I try to use you patch to check the gcc-9 toolchains, but it still have
the warning, but using below the patch can fix the warning in gcc-8 and
gcc-9.


--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -289,6 +289,7 @@ static noinline void __init
kmalloc_memmove_invalid_size(void)
 {
        char *ptr;
        size_t size = 64;
+       volatile size_t invalid_size = -2;

        pr_info("invalid size in memmove\n");
        ptr = kmalloc(size, GFP_KERNEL);
@@ -298,7 +299,7 @@ static noinline void __init
kmalloc_memmove_invalid_size(void)
        }

        memset((char *)ptr, 0, 64);
-       memmove((char *)ptr, (char *)ptr + 4, -2);
+       memmove((char *)ptr, (char *)ptr + 4, invalid_size);
        kfree(ptr);
 }



> > Signed-off-by: Qian Cai <cai@lca.pw>
> > ---
> >  lib/Makefile | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/lib/Makefile b/lib/Makefile
> > index ab68a8674360..24d519a0741d 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -297,6 +297,8 @@ UBSAN_SANITIZE_ubsan.o := n
> >  KASAN_SANITIZE_ubsan.o := n
> >  KCSAN_SANITIZE_ubsan.o := n
> >  CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
> > +# kmalloc_memmove_invalid_size() does this on purpose.
> > +CFLAGS_test_kasan.o += $(call cc-disable-warning, array-bounds)
> >
> >  obj-$(CONFIG_SBITMAP) += sbitmap.o
> >
> > --
> > 1.8.3.1
> >
> 
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> 
> Thanks
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583891602.17522.17.camel%40mtksdccf07.
