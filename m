Return-Path: <kasan-dev+bncBDGPTM5BQUDRBQ6WRTZQKGQERB5S2TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6692E17CBF7
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Mar 2020 06:04:05 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id l5sf2918232ioj.14
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 21:04:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583557444; cv=pass;
        d=google.com; s=arc-20160816;
        b=NMqxn1Br/LgY5YQoSax+1f7+TZveVC3zHA6O34krwbkSJkkIZZ9jnQw488luJ4mD+m
         ELo4ulwaN9pc4M3ag2uNvNytouZIwd2Bi2DyHNwITxd7eJyK8fyoIpylEhM5xHEeflG0
         NfXwsMJHKHyGg2oJ1MECu8lnS+zK7zLIAiC8ksjtcwvoGUOseNzn3qAI7/ayV0YH86pf
         7LegFzWGDYhsH/mVQnfanag3X4O3Yxlwmzj6Ncv8AWIqjFZoJc6M7kMh49uJ6QaYagj3
         6KoFTRpsJSjXbalRNiMNc8VERxRsx4oR2tTvRpUiB6X18OiXBJFFqQSGvtz7a6LkufIW
         qcnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=2O+iPnXwUf6/Q8xICmEfTl30X1QAV1nxa1TRxptA8G8=;
        b=I2KlWjcqQOwM7AyalkNNxrEbhVzZGXGFeIPry33P/JlIkH0rfjTmO6bzhHIpiuiekg
         VTM5NaEloHetx77Mzhr6uX4OMCyaQ4fRfNU22n0p9XbiENUcS/lFKCdJYbcVX0PLiRAu
         3/SmKEDwLQ4m8vx4lN3jK7hlq9f5NNHzCVl1p8wximNIxZVQYSoIBq2zJBDv2zEkE7c7
         iSyD3Gd2CwI31A1GSWRzyi41vcI+MQpkCN24y0hVqthiTydU6tcPjiGU2m+Lkk7E+x3C
         Jdv3nBV3KuHfGvR1SIF7V92rMdLpcUPY1kEFC/2mbO87QS6HQATgK82v2/AKFHTv2w71
         vHog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=E+T4Js9K;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O+iPnXwUf6/Q8xICmEfTl30X1QAV1nxa1TRxptA8G8=;
        b=oHXeDQWaE3S1Wdq6SsDPUinpfqNmo6nJQ9sEFg68PXFPVDNEQwPwD+mrGTCual/9r7
         84Q1IMWRcaR9OFT4e77hzHE4MVelJ1/ZGq01x2/ZpVKvFEmNn3qTJrkPhEym9Zy/qV++
         CKk56M21TSJNAUr8uX1AMBwmO57UYp3duE3s+X35OKVo6WBSQCI5MZ/eZ+0LVJUagmtl
         isv9b8m++RNeg0Po3FCdgiAD2i9e5Ln7WSEwqCeOOmLC2wrSm8jg0MZy8FlZCNecojqs
         GizvOHtk0BOtvezx4gMe1IIy3SJtZoatcvGRog68m2fHWPnkgFcGQ6HkapRLlYm3MI7m
         bUdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O+iPnXwUf6/Q8xICmEfTl30X1QAV1nxa1TRxptA8G8=;
        b=EpgW84zXRPY1oaKhh5y9Ucl/dJhUTH6MB6YI/8vgEiHl5l/8cs+SEKPA+sU0G28Li0
         FXFxkeeXNnMsTPxNOs31BQb+HSmaVcf8FiJRFE/g5TPP32UDEuI3/y6PePH2QnDSI58W
         9YdWl7Z7l7xV0r/5gCaNSOqavDijcGzSkZ601I1LKRavxEw0io6YabrO4ecTfyJy4hN5
         o/INpS66+F/KopNC19QJMISAiiT5idlh+h87N6Zw41jIEEk5gVB5Q742sivhXQHyG/Al
         ZSI3tjjhXFPPYJlRiXjAI3z+XHAxSC0fdzbGqUMuC6IADsZzqiePVgWaa2khGP1SxMMn
         0wPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0lNLkDm5qjHh7sjzGOq8rgKUiVHwoozdoAjzqh7eXgh2ScX84X
	eHNwauZ4p1n5SpCuTXLO3Mw=
X-Google-Smtp-Source: ADFU+vvEC6zZuqI3cFPQxwUOjg+N+66gjH8oGKlkFQNMsm0wDcratoK0m/kDCWoJcJRTppdrK9cI1A==
X-Received: by 2002:a92:8c45:: with SMTP id o66mr5688252ild.236.1583557443916;
        Fri, 06 Mar 2020 21:04:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8b99:: with SMTP id p25ls653617iol.4.gmail; Fri, 06 Mar
 2020 21:04:03 -0800 (PST)
X-Received: by 2002:a6b:7504:: with SMTP id l4mr5671914ioh.184.1583557443498;
        Fri, 06 Mar 2020 21:04:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583557443; cv=none;
        d=google.com; s=arc-20160816;
        b=xqi8P4JDLLNjiLjPnU+xMyHED2BerQn1X4I+aGYm7PIx5IWqMzNE1WBOKLyIKVMyIQ
         oDCqGS/qTeWOV8tqPNCPrHS8gTBiDk5tKSf4YoInqE/NSsNC0sCXrbgKsBVTufky9nbI
         crffG21vwGFW25/toq0GTJy3/29OAAwOIvAWX1nItw4M0sQQX5cLkuICvKgJxaz4/lrq
         gnwjC2LVSlt8HVwNVDp6ZRgFiIgMQAcECfO0r7TqKRPyMZXokbIifjeoNFN6gWyZ4nZW
         3upQEnonPsBKcs6YF2Wwp7b5C2ir7U0OW051heAHwGkZbizcbqJLn5IZ5lAgLH9wgYDw
         KLAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=bMovNE6g0gltRurUOZloJZdwKG5nFql6EWSPoy766UM=;
        b=vILbnC3sMvg15Plt9LIFVE6wI7eeNuqjOLI/sPNN8M3KrPsnO5D9uuYV8QEX21vDl5
         v17aVjc2S6uttkZizXIXKfbuXgTFqP2yncpOA/nt/BimELgOIjNMroGYNXfOWczSo/p9
         zdcNCci23IqooCkgMtbkX71hG6hViJdDDJH8bnszmV5AvOyluTHJH+iv5QIjxu1tllrO
         YeAsfDSBh39VoEuZM4caHgp4ceJ3oaA89XS3jSWbJdyaVQTuNUqb22FAdUKs2ewJIkH3
         Xla9Kq96NMyHTYNVjQPCc1Aj8nZ0BnRqZfHir5mjC70GtZX/IQWgUGXsDTVmujyc0h2E
         WU+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=E+T4Js9K;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id t10si244903ilf.3.2020.03.06.21.04.02
        for <kasan-dev@googlegroups.com>;
        Fri, 06 Mar 2020 21:04:03 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d5b83e5d4f854bf880f1f3fc2a1c5517-20200307
X-UUID: d5b83e5d4f854bf880f1f3fc2a1c5517-20200307
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 677170337; Sat, 07 Mar 2020 13:03:58 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Sat, 7 Mar 2020 13:03:00 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Sat, 7 Mar 2020 13:01:18 +0800
Message-ID: <1583557436.8911.25.camel@mtksdccf07>
Subject: Re: linux-next: build warning after merge of the akpm-current tree
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Stephen Rothwell <sfr@canb.auug.org.au>, Andrew Morton
	<akpm@linux-foundation.org>, Linux Next Mailing List
	<linux-next@vger.kernel.org>, Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Date: Sat, 7 Mar 2020 13:03:56 +0800
In-Reply-To: <CACT4Y+ZX0xaZNnNqOzassKi2=NSPz-9K4VpxdL6FGx_Y4vWSUg@mail.gmail.com>
References: <20200305163743.7128c251@canb.auug.org.au>
	 <CACT4Y+ZX0xaZNnNqOzassKi2=NSPz-9K4VpxdL6FGx_Y4vWSUg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=E+T4Js9K;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Thu, 2020-03-05 at 06:54 +0100, Dmitry Vyukov wrote:
> On Thu, Mar 5, 2020 at 6:37 AM Stephen Rothwell <sfr@canb.auug.org.au> wrote:
> >
> > Hi all,
> >
> > After merging the akpm-current tree, today's linux-next build (x86_64
> > allmodconfig) produced this warning:
> >
> > mm/kasan/common.o: warning: objtool: kasan_report()+0x17: call to report_enabled() with UACCESS enabled
> > In file included from include/linux/bitmap.h:9,
> >                  from include/linux/cpumask.h:12,
> >                  from arch/x86/include/asm/paravirt.h:17,
> >                  from arch/x86/include/asm/irqflags.h:72,
> >                  from include/linux/irqflags.h:16,
> >                  from include/linux/rcupdate.h:26,
> >                  from include/linux/rculist.h:11,
> >                  from include/linux/pid.h:5,
> >                  from include/linux/sched.h:14,
> >                  from include/linux/uaccess.h:6,
> >                  from arch/x86/include/asm/fpu/xstate.h:5,
> >                  from arch/x86/include/asm/pgtable.h:26,
> >                  from include/linux/kasan.h:15,
> >                  from lib/test_kasan.c:12:
> > In function 'memmove',
> >     inlined from 'kmalloc_memmove_invalid_size' at lib/test_kasan.c:301:2:
> > include/linux/string.h:441:9: warning: '__builtin_memmove' specified bound 18446744073709551614 exceeds maximum object size 9223372036854775807 [-Wstringop-overflow=]
> 
> +kasan-dev
> 
> We probably need to make this 18446744073709551614 constant "dynamic"
> so that compiler does not see it.
> 
> Walter, will you take a look? Thanks

Hi Dmitry,

Yes, I have fixed it. This warning need newer gcc enough to reproduce.
Maybe I should replace original gcc-7.4.0.

Thanks.


--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -286,17 +286,19 @@ static noinline void __init
kmalloc_oob_in_memset(void)
 static noinline void __init kmalloc_memmove_invalid_size(void)
 {
        char *ptr;
-       size_t size = 64;
+       size_t size1 = 64;
+       volatile size_t size2 = -2;

        pr_info("invalid size in memmove\n");
-       ptr = kmalloc(size, GFP_KERNEL);
+       ptr = kmalloc(size1, GFP_KERNEL);
        if (!ptr) {
                pr_err("Allocation failed\n");
                return;
        }

-       memset((char *)ptr, 0, 64);
-       memmove((char *)ptr, (char *)ptr + 4, -2);
+       memset((char *)ptr, 0, size1);
+       /* the size of memmove() is negative number */
+       memmove((char *)ptr, (char *)ptr + 4, size2);
        kfree(ptr);
 }

> 
> >   441 |  return __builtin_memmove(p, q, size);
> >       |         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >
> > Introduced by commit
> >
> >   519e500fac64 ("kasan: add test for invalid size in memmove")
> >
> > That's a bit annoying during a normal x86_64 allmodconfig build ...
> >
> > --
> > Cheers,
> > Stephen Rothwell

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583557436.8911.25.camel%40mtksdccf07.
