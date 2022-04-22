Return-Path: <kasan-dev+bncBDKPDS4R5ECRB7HQRCJQMGQEVJBBMLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6888A50AF62
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 07:09:18 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id l6-20020a170903120600b0014f43ba55f3sf3802281plh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 22:09:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650604157; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpZvp8xBuufB66pTVwW/gpIJZuQMBq6kh8upESsc0UL6n8Xsr9dc+ce0hcNJvTz45p
         bgavH1JiMjanQnvL/nkW/U5QBbF8XgqGs6ex5TYeRU9hLlK8MNyMqFG2Vvwrxp+k72ja
         3gjXXKCey8ltY/irfQhebaYXUOpscPPtgGqdSSuN6R+tyMwsNxQ7uH9OWIeD213dWd4H
         30+8HGky7baGzIjwxzAtcOz8DSEp7uCaHDfdnea6/ElaPLjkUtQ0rSANOuyopa4Qb+pL
         kuopOUuHmY6wR4v78hl4zpEaSyGwNQTI8+aXk+7+Fo3W9fgUukYorXWxlJ+GZmzwo2rE
         saDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KwXvsQaAvQFLHaWERWI5UsCmhisHo7Ajjq8PKcOYmbE=;
        b=xmZK3tgegGg0h4DvPUMuaYGbGfoHzQI4+x9J6E1RAQ+EuDRKS9HXftSCdD8rDwFnkr
         t1t9J7hwqRiZf0/EG9suU+c/EiD3D2gPyOovLyA33bQUT1HxZP+sW7ksi5ETitT+pWtZ
         1J6FTM93A3QCNtki6H0oY94msd3WXFOfYgCdfCbyOM8nbHd3m0OBsjLDkXo/3TEeID6Q
         OjVv7hRbpWwHoIoT+d0lQhB82+glc2jBvI5lSAeOX2t5izNaZbZqDP/zR7+pxD64NR2B
         zlKtWYPcFdX08SV6rrwadFTj1CUaOYBrjQD2FFsqdctbJW+PhZEU4+jC58tfEj802eKe
         s98Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=Q0hcI1wq;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KwXvsQaAvQFLHaWERWI5UsCmhisHo7Ajjq8PKcOYmbE=;
        b=iAoGJEaRZYdZKsU2fnk0gc0kg9o/78JNIe78+l5u+0yW1DA7b5neY/dcLN5IKU7jLP
         ovvsNEDhHZQrJ7fNj+z/HMaBceSI5D096gZFiq38HNZvkKD4fLIK5tZZvO/yfJhHD0TD
         Mr+qaHvNJSgr2IwEFs7nN3x4eYsIht3AopYmloznBmqObFoXmdAMyFiwI8ZlgSkrc+ni
         HnQ4WLdvCuk7SCYuimGHKgm392E2P1UhR3hmAJd+WVcf/Tf0hpDU4KU/BEaAUIitqvSB
         OA98+DYFHQ+ik0pVkLUPfAXn4FjwxVEBHnokX+RSAmfETXZsOcAJj6xACOHIVdS+xVwM
         SE/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KwXvsQaAvQFLHaWERWI5UsCmhisHo7Ajjq8PKcOYmbE=;
        b=3Yp2Etazio+AsDjKtdABmoTkRJP81zzFVZb55nkIyZQr8PGd5oGQPZ0fD8c8jqgHgr
         NMIuZH9ztSjqRxmHgSsmSt4x+wMVwOZuRHrRuhbX/pCe1w0um05sT1fpHui5o2W4L6Fy
         KxGYKTDbg7D+w7YZaAXsQ1OXKrBLPBOTs9A50aa4y8pfBPOKAF/k/81ssh532xkDW4fU
         FXzrVFE37+wQkAcvNb8tyg6787whwmrwFVdVLg1WgxA0hn8xCyl95FhJOD1v9DSS4Jcj
         HqLsHqnihcnhGavRJrhYoY2kVsfn6OaXqrS5xjmIdUGeLr6K1aDVrdqCbF/gHvz/jRMf
         IKpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533E4IFoa23rFYPw+nPxXTodJrFBgky3fsKxToI56AZNaNm4Y0Rz
	FvCMt6rH+SIq5dVqFNgHla0=
X-Google-Smtp-Source: ABdhPJxk45ElPGIqHJ+fj8K1slpq3CMQm4i0GpMjjg+zScuk9jVbVnwHOJLxte0LItU02f//vStDzw==
X-Received: by 2002:a17:90b:3810:b0:1d1:b184:1ead with SMTP id mq16-20020a17090b381000b001d1b1841eadmr3404856pjb.89.1650604156786;
        Thu, 21 Apr 2022 22:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:cecd:b0:15a:b2a2:20dd with SMTP id
 d13-20020a170902cecd00b0015ab2a220ddls3441371plg.8.gmail; Thu, 21 Apr 2022
 22:09:16 -0700 (PDT)
X-Received: by 2002:a17:90b:1d09:b0:1d2:8dba:67f3 with SMTP id on9-20020a17090b1d0900b001d28dba67f3mr14266712pjb.102.1650604156165;
        Thu, 21 Apr 2022 22:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650604156; cv=none;
        d=google.com; s=arc-20160816;
        b=ZTG5u83VcS6y/VrQ2FL9VGNmw9GcwI3r90ByiLMF06dtKz7CB/h2AVwA76oFRhkn8Q
         al86bT1KS3Q19wMTkpd4V2Fw8/+yGyu2B1upwYVVJ8Vvjg4bkXznS79hHMvoY8XqlKfr
         P0wTNd+LAMuc30texpa4Sj9zmCPHPwW+i0X6IisZXf122pKbH1jsbFp+zyMZ3Ug08oNK
         1LgYR2igXuTrIR8rC+wrEd1VLB2HpXNctxa0dPzdxTOm64DjBj86AaJ0Je56I07ZW3RP
         c9Ee5FYeOOULzVHSSIABkUv6nemRLit+ATPkhdRVLMZGrwvdnA5/B9WjQUlqFQdcKHkA
         7d9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rpqDRBjWTFgnwu8hYqPDued7W5tN/z70+zi0V+kqfDQ=;
        b=NMd8SKsaP9f8SvA2tm6wdNt20w7ibLBqoMyu6egETeSOtuhkAnJvDnunmj5GV+QMI7
         f+t6ZYAkXBH8yP/CCRqJeWU3K4yr1C6Zbe5jKu2yadQirHu/80Dl6VeHkcxo3ifGBCIg
         klLFT+Y4nnVpJ0XjXR4NJHF9UVZTycFbhdm2IJvCYB9XR+5m8OUH6tnVR1yXC1rLxX3d
         IalTu7hw0mglDYXdfYo5FvhY0gktGBW3V6q7Qeg3kTt8QZVsnXhQOQhdSBMG3Uv7q7Ay
         DKCgST2x6ksg6A/OExlxajTLIve5Ez+53bOH8Z1Ht338svnMd4POLI8b2LFqegbVs1qx
         daAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=Q0hcI1wq;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id pc2-20020a17090b3b8200b001bfa3e36392si756688pjb.0.2022.04.21.22.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 22:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id q1so7225644plx.13
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 22:09:16 -0700 (PDT)
X-Received: by 2002:a17:902:bc8b:b0:158:ac00:cca0 with SMTP id bb11-20020a170902bc8b00b00158ac00cca0mr2893469plb.102.1650604155898;
        Thu, 21 Apr 2022 22:09:15 -0700 (PDT)
Received: from localhost ([139.177.225.255])
        by smtp.gmail.com with ESMTPSA id g15-20020aa7818f000000b00505ce2e4640sm844208pfi.100.2022.04.21.22.09.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Apr 2022 22:09:15 -0700 (PDT)
Date: Fri, 22 Apr 2022 13:09:11 +0800
From: Muchun Song <songmuchun@bytedance.com>
To: Marco Elver <elver@google.com>
Cc: syzbot <syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com>,
	akpm@linux-foundation.org, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com,
	Roman Gushchin <roman.gushchin@linux.dev>, cgroups@vger.kernel.org
Subject: Re: [syzbot] WARNING in __kfence_free
Message-ID: <YmI4d8xR3tafv2Cq@FVFYT0MHHV2J.usts.net>
References: <000000000000f46c6305dd264f30@google.com>
 <YmEf8dpSXJeZ2813@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YmEf8dpSXJeZ2813@elver.google.com>
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=Q0hcI1wq;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Thu, Apr 21, 2022 at 11:12:17AM +0200, Marco Elver wrote:
> On Thu, Apr 21, 2022 at 01:58AM -0700, syzbot wrote:
> > Hello,
> > 
> > syzbot found the following issue on:
> > 
> > HEAD commit:    559089e0a93d vmalloc: replace VM_NO_HUGE_VMAP with VM_ALLO..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=10853220f00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=2e1f9b9947966f42
> > dashboard link: https://syzkaller.appspot.com/bug?extid=ffe71f1ff7f8061bcc98
> > compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> > userspace arch: arm64
> > 
> > Unfortunately, I don't have any reproducer for this issue yet.
> > 
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com
> > 
> > ------------[ cut here ]------------
> > WARNING: CPU: 0 PID: 2216 at mm/kfence/core.c:1022 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
> 
> That's this warning in __kfence_free:
> 
> 	#ifdef CONFIG_MEMCG
> 		KFENCE_WARN_ON(meta->objcg);
> 	#endif
> 
> introduced in 8f0b36497303 ("mm: kfence: fix objcgs vector allocation").
> 
> Muchun, are there any circumstances where the assumption may be broken?
> Or a new bug elsewhere?

meta->objcg always should be NULL when reaching __kfence_free().
In theory, meta->objcg should be cleared via memcg_slab_free_hook().

I found the following code snippet in do_slab_free().

  /* memcg_slab_free_hook() is already called for bulk free. */
  if (!tail)
  	memcg_slab_free_hook(s, &head, 1); 

The only posibility is @tail is not NULL, which is the case of
kmem_cache_free_bulk(). However, here the call trace is kfree(),
it seems to be impossible that missing call memcg_slab_free_hook().

Thanks. 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmI4d8xR3tafv2Cq%40FVFYT0MHHV2J.usts.net.
