Return-Path: <kasan-dev+bncBDK7LR5URMGRBPE3SCNAMGQENBDYUNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC2665F9E95
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 14:19:09 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id a13-20020a2ebe8d000000b0026bfc93da46sf4459540ljr.16
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 05:19:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665404349; cv=pass;
        d=google.com; s=arc-20160816;
        b=kMZU7enzIK4klqyYIpS5msbVxSTUIFtFxb6ykd3IR3aHhBTh7FVlwBPkpaSDD6TuzZ
         giKFYqhWPvNGNX9GUgEB4/y5e/AJ1ODSyYyP9DzRwZQ9I5Fbjs5/WjW2l4de0CbYhidI
         dmlpoyK9C/One/rTaV0BiynN3Nq83sf3yKDvCSf/c1xkEmXIsHlcViMgSxl4U1ynP7lM
         9u/FR9lCBeD7g3uWM/i4c2WQJTTxClp0YzMIZ9HWQfT+R2r676l3RADeTj3akOQuQGb8
         BsSAEMYDKT4tDFIThGMlW0EDCXeCcGEAHQ6KdWbOfQyeGeoDh8LUQIr+1eqIOtuDSNbQ
         iIAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=UOj+8XUsvC8SyP7Q3fxEeJajzq4DM1ZwawmHIQVdBbY=;
        b=GQXGuYFRNnXyoLD5mxJnLWpGXVE/tqPO+oCC2QOsm8d1scg1Y1X5x8F70k4W6/s1/7
         eM3wuJLdoXoA5rDp017xCphj9L9Fn7ExV5B3R9uWyRKgGm+jdGdQmLVj6WZE3JtYG3CV
         NkfvPCTTVEn7WWDwwuTJPf2ZBB5DPY0bPdgjpROzCV7L47PV8dKLmbErW+ygxf9u7xxd
         Ckzkdih/WYwm6ngVReg4lvcaX/ImILrIQ6hvclCoacKGExwm/D0M9VCfpP4CZS/W5mv+
         ezx1fCrHa3orRgE4+96suHvMCbkJQw20rGHnZHkYRdAYhYryNk1U7rgkFpnW2smnL3Ba
         6kWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="W/IR+Eqj";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UOj+8XUsvC8SyP7Q3fxEeJajzq4DM1ZwawmHIQVdBbY=;
        b=mV/ibwDJwed3DP36CbhiH/2Q5+c24OkW53/SQIhqJCi/6uHZUz6zEqRuB3uavt82BP
         Pw6obGwvIffZ+vQKyJRUxMy1iaTVsivHf51C0WlaYLm5n+/FVUbl1Q/+8XAZcEhNFxB3
         MIplPbNCvC1Tr01uVoUmDolyJnb74YqlSP4Xa6R7zdvV8dAZFB2AF1gmNNXqWnvyjFbr
         hUBlxe1dBMr/PAabUN/Pz8hwCa70GB2wodwFLtdXAqALsVYFvnqHJEmeHTr+Mx2MtqQB
         cDOZU4Azk/DWoQEnKOXvK0sPE2sFv7j9rsqvncIc0bUsCh0b7dcsBF7mHDuyGKg0cfAj
         J2tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=UOj+8XUsvC8SyP7Q3fxEeJajzq4DM1ZwawmHIQVdBbY=;
        b=GCPdIF4GeverQRf7VZrc3M+uEd5pcWduQVH7XpTBc/e/wLeJLr9O1T5yORM6udpElm
         rP/Fto4PZe9VNTPecj1q3iWzhSFVQsmZatDEfnmiwJR3mVWFj2jldNIHCIo7tpRzfnjf
         5d6f/PUXVPggYjdhEnRUfQP4KckTmhZrrmVrVBI5zhzwMqHwmHg3ZvgzjHlFWVnLWgeq
         JjGlNTDU8WDUag3yM/HLMzPebF7gTWoOCFrO6tH7Ev/QYekxf7zo/6rcXGZWw0qRli3c
         edvKjeHvkcqp6xEkJUguz/u5lDXEk7KNsA57nU0LUWzuYZxvqhlon92/7Q2q7DyDi6ps
         jlNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UOj+8XUsvC8SyP7Q3fxEeJajzq4DM1ZwawmHIQVdBbY=;
        b=os1si/Ba7KydeB5uEESVkOQUfmky7V8rgwEw2QIBg8UbWBnG33cY3QsI2b2MsKKHgw
         YRSGA6pAd9lxw9Ftu+ll06ZcX6RZHXix8AOaSrzd5vjD7TR9K01rcK3u1dtl8/oXwHv6
         GbtCL9QXdhaSGzZISlwy+nGr2Pb7JUbc3OV+Lz44/cOUaN63w46r0EGFsyzsjaYrPeGe
         WdzNJxuYsxIbyOR0MJ/rViRF6sR8KoX0C62cSHg5HpVdABhB37HIHAJNULi68a/4g4Uk
         Nfs51x8nkZ+wkVm6kskp+iyCGJQtX1Pd4gHbjIrBrrqlR/sGaNPDLO3olUuMU6gSGrDS
         mijA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Usja1XKRpg3sKgB7lMB3l8nBzmTmJ/JX43RZHJdoBXrzCBFtO
	WvzmPNsY3yY3hLkC3jhriss=
X-Google-Smtp-Source: AMsMyM7A610vrqQZmuJApWWwkIMRgLhHOi0VqqK7yeuAkuLL9KDbrE2AEfSxcQDaqiYV9R0Y/btJAg==
X-Received: by 2002:a2e:9d8a:0:b0:26e:314c:c3fd with SMTP id c10-20020a2e9d8a000000b0026e314cc3fdmr5823585ljj.105.1665404348886;
        Mon, 10 Oct 2022 05:19:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3607:b0:48b:2227:7787 with SMTP id
 f7-20020a056512360700b0048b22277787ls440869lfs.3.-pod-prod-gmail; Mon, 10 Oct
 2022 05:19:07 -0700 (PDT)
X-Received: by 2002:a05:6512:2808:b0:4a2:7df6:4b74 with SMTP id cf8-20020a056512280800b004a27df64b74mr7018945lfb.217.1665404347512;
        Mon, 10 Oct 2022 05:19:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665404347; cv=none;
        d=google.com; s=arc-20160816;
        b=0yAK2nUM2o1m1rFhLuEYab63hJO/mkDtmI6zviEG778V+TZRgmIa8oW9YsKwHQY4BI
         vEtkMRTpC928LXNBxRFbxnGM+vFDcRffFA/l4c7+VZ1aLL3UkXUHcTEEU2UJRkNUAzY0
         8Ed+aQKqmLqYE0JvJhxZU/9POoTKNAWpYHr8GUGsXuAWdbYiGTOs2rFqE0Arxn2q330R
         2C2Mq6tR2NgI1YZLVOz2GejXbfMJWAklsVY3SuOEhbaRI9oWLuu7e79cmGDT9DXmIFRG
         RmEAWO5hyBKfCg1l7BVzAQgJZGSctpi0B2OHT2EkoI+Vz9ap39ADBlOybtGbT20Fhg48
         8yQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=KZwwuxlvVfPvUAtn+ynvGscHnlF0P4dALC17cMr1nmc=;
        b=GsD7i35y4h4/SI6NrL67hcUDzqikXF5JA9FApzTzBBcCeEwChWN00ZJkfZUCKFWKtj
         h7QEBizTrqCEbV/ZM3jHvL315Di7nIStlL1n7Uvm0B+kVI/4Vx5/FZ/e4/HVX7moxgpG
         +QMUD8AVQdfkqZ8f+9hQgmn/3hlNFdVvtqJQhncsyevLpbYFmXWMcQnu3vP+rkiZD031
         FerI4qsp85OifQo2/J4sxG3xWtGX7dwrkrrIeqIjF7bR5UbQrjizC8KHUZT+Jp1W8mfZ
         0ad14B7eOmtWFtYl+ZC0Fm2nmRN8xjUQLNuJ11QIhg5k6kpNfud1AUZ8OmzVbGFW4kCN
         CkEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="W/IR+Eqj";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id e10-20020a05651236ca00b0048b224551b6si381850lfs.12.2022.10.10.05.19.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Oct 2022 05:19:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id s20so16287385lfi.11
        for <kasan-dev@googlegroups.com>; Mon, 10 Oct 2022 05:19:07 -0700 (PDT)
X-Received: by 2002:ac2:4ecc:0:b0:4a2:2ed2:9400 with SMTP id p12-20020ac24ecc000000b004a22ed29400mr6684979lfr.432.1665404347109;
        Mon, 10 Oct 2022 05:19:07 -0700 (PDT)
Received: from pc636 (host-90-235-26-104.mobileonline.telia.com. [90.235.26.104])
        by smtp.gmail.com with ESMTPSA id v8-20020a056512348800b00494a1e875a9sm696343lfr.191.2022.10.10.05.19.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Oct 2022 05:19:06 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 10 Oct 2022 14:19:03 +0200
To: David Hildenbrand <david@redhat.com>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: KASAN-related VMAP allocation errors in debug kernels with many
 logical CPUS
Message-ID: <Y0QNt5zAvrJwfFk2@pc636>
References: <8aaaeec8-14a1-cdc4-4c77-4878f4979f3e@redhat.com>
 <Yz711WzMS+lG7Zlw@pc636>
 <9ce8a3a3-8305-31a4-a097-3719861c234e@redhat.com>
 <Y0BHFwbMmcIBaKNZ@pc636>
 <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6d75325f-a630-5ae3-5162-65f5bb51caf7@redhat.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="W/IR+Eqj";       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::134 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Oct 10, 2022 at 08:56:55AM +0200, David Hildenbrand wrote:
> > > > Maybe try to increase the module-section size to see if it solves the
> > > > problem.
> > > 
> > > What would be the easiest way to do that?
> > > 
> > Sorry for late answer. I was trying to reproduce it on my box. What i
> > did was trying to load all modules in my system with KASAN_INLINE option:
> > 
> 
> Thanks!
> 
> > <snip>
> > #!/bin/bash
> > 
> > # Exclude test_vmalloc.ko
> > MODULES_LIST=(`find /lib/modules/$(uname -r) -type f \
> > 	\( -iname "*.ko" -not -iname "test_vmalloc*" \) | awk -F"/" '{print $NF}' | sed 's/.ko//'`)
> > 
> > function moduleExist(){
> > 	MODULE="$1"
> > 	if lsmod | grep "$MODULE" &> /dev/null ; then
> > 		return 0
> > 	else
> > 		return 1
> > 	fi
> > }
> > 
> > i=0
> > 
> > for module_name in ${MODULES_LIST[@]}; do
> > 	sudo modprobe $module_name
> > 
> > 	if moduleExist ${module_name}; then
> > 		((i=i+1))
> > 		echo "Successfully loaded $module_name counter $i"
> > 	fi
> > done
> > <snip>
> > 
> > as you wrote it looks like it is not easy to reproduce. So i do not see
> > any vmap related errors.
> 
> Yeah, it's quite mystery and only seems to trigger on these systems with a
> lot of CPUs.
> 
> > 
> > Returning back to the question. I think you could increase the MODULES_END
> > address and shift the FIXADDR_START little forward. See the dump_pagetables.c
> > But it might be they are pretty compact and located in the end. So i am not
> > sure if there is a room there.
> 
> That's what I was afraid of :)
> 
> > 
> > Second. It would be good to understand if vmap only fails on allocating for a
> > module:
> > 
> > <snip>
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index dd6cdb201195..53026fdda224 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -1614,6 +1614,8 @@ static struct vmap_area *alloc_vmap_area(unsigned long size,
> >          va->va_end = addr + size;
> >          va->vm = NULL;
> > +       trace_printk("-> alloc %lu size, align: %lu, vstart: %lu, vend: %lu\n", size, align, vstart, vend);
> > +
> >          spin_lock(&vmap_area_lock);
> > <snip>
> 
> I'll try grabbing a suitable system again and add some more debugging
> output. Might take a while, unfortunately.
> 
Yes that makes sense. Especially to understand if it fails on the MODULES_VADDR
- MODULES_END range or somewhere else. According to your trace output it looks
like that but it would be good to confirm it by adding some traces.

BTW, vmap code is lack of good trace events. Probably it is worth to add
some basic ones.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0QNt5zAvrJwfFk2%40pc636.
