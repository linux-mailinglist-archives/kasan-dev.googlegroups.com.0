Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXDZKOQMGQE4VZ3GCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C39565AF8A
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Jan 2023 11:28:07 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id bf20-20020a056512259400b004b57544aad2sf9968601lfb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Jan 2023 02:28:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672655287; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVIqs+1E3YY3JjdM3oH2+Krac05LtDmrkYx5U9XFhNYgZAQC1PjzKvvwZD46PUYF/A
         4clGZYTUXgxca2+Qq7hUbSWidvInU5LgbgSNwNl0x65hBagobg9AmW9Y8AhvcN2Pq4uM
         niU5rO91XJpseHPh0kGAyDyfURohKCbofM7WlyUPTZe49VOoGbbANKcOC+0zmVt4VPFu
         xrmDEkdjfD4IpMV9pU9xMLJ/iB3fHJBXgdQV4ddKK8cuCzEqLXNX3Tb/1smaytUG4v1n
         VMN6EZhvjJ4olueOYLGQvzSP0UTr53a/+HxLj+RVFNMM8CtlC34xAz/SQJ+d1BvnmEpS
         49zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qSYNLLfP2MKFRhBctfLli/z76nAp5fVXljZRxmDU07Y=;
        b=YpSB1N1Fatd+K9CjbL+84ZHS9bW8Q8htKolgOFifqLLhw1FPrXXrYDV98+7sU13IdB
         xpCqxz4XcXlBQNqnYG9R+RnBSbkl5+eaiVLrI1IjkY+/TjyOsAlFYSdhBsmoFBLLX1q4
         58d0XgQ5KWhwHFHq9qpSmThtGTfxFIyEDP9dsSvNRz9AJG7qjf7DXJ2KXwtkV1jB4VxZ
         iJTJ5udJs41i+X3mfn7I+KFp09XHwDgg7NOO9WpN6PUVN+rXOYiwlTROKt8MpRfO+xGI
         Lw+qAS+m5xrViJDf+kfEnAuZFNbBK/8u0KqIe3/nN/ELFSPOQkppq2BErcMiRqjVHYAp
         pP6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NCpqguz+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qSYNLLfP2MKFRhBctfLli/z76nAp5fVXljZRxmDU07Y=;
        b=to6unJIw9VKi8ckJv7fT3NHTT5/blouNbMX+STx3j3gWqMzJjUw0GCJ4ZPrF5N+ukW
         y2mnGKUwn4qNf0+zG85+Kqk8DIOxRsbZccjjtl2juJF5miMHcS/tF3jmvEe2TojqlqTR
         6GwNtMrKLjsNqNnqPl8lMooAiz+KnW3LtBLiPdD9EPZAWFJU51Onv2lbR1VNFsXDEAS7
         L0NfojWyHcl6iWiX8hcjL14RI1cxipX9ydVenXr+itFvoXajkzfpFr97aC1r/Q18NuWl
         SGQLsia8wH1+MPTHpFpp1Zve7X3JZPjQgdmCuT0J4I/lUksw/fekXcR9IlwZHBuTWHJa
         0Pcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qSYNLLfP2MKFRhBctfLli/z76nAp5fVXljZRxmDU07Y=;
        b=UwOOREbI8Wf4wKbjAFJ/FFiZeGBY0nIYfGc9/Jfk6mWrtqi7rUsV4cMOTKKXH7cU2R
         fv9uD3JpAtw2IzDNnbWeqocxeGloFh3B0aWopb3eUy+jOO4ExSR2HGoh1rrkrq6newKs
         SUuHNT3Zn6emPPBAsKXe2r3/IDwoVbBCQlmTVnxFTBJPKxHRdwK4ZGAK4R8rpw2OcaS8
         NBFdYfU/7NLPvRu9DKbAv4XiRO7px3hoHnVyFywfvPMFOySHzc8+Avln7Y+f3jxUjk83
         87jmQE/P5UJJjxU5EilDaGToDYo3nRJHE6pymy3+TCeg/yN9MyPB/70582Ti1CuxkW+p
         nvPQ==
X-Gm-Message-State: AFqh2kqIPgyqgQQIwv3B4rjnARrmWcyR0RTJXCtQsKzKztOqW/UQnP3y
	n/XGtVMfgiET5XHxw+DeDEg=
X-Google-Smtp-Source: AMrXdXsEtrMLkXHCWY4jFdPR0/Y7Tz1EUs1e3yatoenEk7YnPmyY1R/tYs78k1RaJ3/0SSAT19Bp1g==
X-Received: by 2002:a05:651c:141:b0:27f:b76d:4933 with SMTP id c1-20020a05651c014100b0027fb76d4933mr1245408ljd.220.1672655286975;
        Mon, 02 Jan 2023 02:28:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d5:b0:4a2:3951:eac8 with SMTP id
 o21-20020a05651205d500b004a23951eac8ls8910752lfo.0.-pod-prod-gmail; Mon, 02
 Jan 2023 02:28:05 -0800 (PST)
X-Received: by 2002:a05:6512:304a:b0:4aa:54a:3a6e with SMTP id b10-20020a056512304a00b004aa054a3a6emr12911887lfb.41.1672655285458;
        Mon, 02 Jan 2023 02:28:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672655285; cv=none;
        d=google.com; s=arc-20160816;
        b=An1cHqs6OYU44fbsZLVrexpa064z1wuJ5L5QW7PtYD8ng9/wqAOo0a1T5SDnufBafI
         cjK3j1iVu90QdS4VexVlBi8NbCqlRvJSjAi8D7/Ty4o62zcuzYoMH56KcOqycDWsDLvl
         JK6ppfKrnV0SqZfTZ62gqvU+utMCDe6cySw1MGdrpBzzTL+XWO/TG9udmbSq0X9lfpPs
         QvntqDluvjS1UKsJTwA3V8m+abqXOcNVO0ATFUsb2kHKMJmHHZ8KpusUx1TPz2OhUy8H
         gHSFn4dlf0EGaVMYsZDVArfQZshLjtx/ZiIcWdq/dCVPOV/nbEHBcwmbamnfCZ7dRSnj
         WIMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8ruN1yQRxsJ2H59E/8nRfHXr5P9ik8d8Ya3T8OD5cP4=;
        b=i7QxM4kPDJHM6XlesMhRBeDFM2SG9dDYq+kRM9wIq2FHdjwyALJc5uaFgsknZTBo6e
         p1XueznvHiDveer8lSr5l8vWbPIYnWb7J/gJRB+EtUz2Bj3q1PNDoGQJsWUqB01xxqjw
         N8tc9nagMeYE5fwY91yyBkBsM2QpJgfhOSj7lOgIoJTbyspmUDwpQgzAXlJHElhW7S5G
         z1KtkFwbQ6PdSziRw6DI3OvE/dfCl2/z01HLDksbHvZ37BW0H0Muf0DxSIEcHNEyE3QI
         Ssc0yiXHm/QeHONJrqUOhGcBonPs2CLp3Wsk+MpBUAOFw2tTCVs4i7mXN0PVNvNkBO8J
         AOBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NCpqguz+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id y17-20020a05651c107100b0027fbb3681d9si641308ljm.1.2023.01.02.02.28.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Jan 2023 02:28:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id m3so11199567wmq.0
        for <kasan-dev@googlegroups.com>; Mon, 02 Jan 2023 02:28:05 -0800 (PST)
X-Received: by 2002:a05:600c:12c6:b0:3cf:6926:2abb with SMTP id v6-20020a05600c12c600b003cf69262abbmr30868798wmd.7.1672655284796;
        Mon, 02 Jan 2023 02:28:04 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:6950:757d:cd6e:92aa])
        by smtp.gmail.com with ESMTPSA id l13-20020a05600c2ccd00b003c70191f267sm45465878wmc.39.2023.01.02.02.28.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Jan 2023 02:28:04 -0800 (PST)
Date: Mon, 2 Jan 2023 11:27:57 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev,
	oe-kbuild-all@lists.linux.dev, linux-kernel@vger.kernel.org,
	Christoph Lameter <cl@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: mm/kmsan/instrumentation.c:41:26: warning: no previous prototype
 for function '__msan_metadata_ptr_for_load_n'
Message-ID: <Y7KxrfQ5FQmqVBAn@elver.google.com>
References: <202301020356.dFruA4I5-lkp@intel.com>
 <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NCpqguz+;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
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

On Mon, Jan 02, 2023 at 11:01AM +0100, Vlastimil Babka wrote:
> +CC kmsan folks.
> 
> I think it's another side-effect where CONFIG_SLUB_TINY excludes KASAN which
> in turn allows KMSAN to be enabled and uncover a pre-existing issue.
> 
> On 1/1/23 20:10, kernel test robot wrote:
> > tree:   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git master
> > head:   e4cf7c25bae5c3b5089a3c23a897f450149caef2
> > commit: e240e53ae0abb0896e0f399bdfef41c69cec3123 mm, slub: add CONFIG_SLUB_TINY
> > date:   5 weeks ago
> > config: x86_64-randconfig-a013-20230102
> > compiler: clang version 14.0.6 (https://github.com/llvm/llvm-project f28c006a5895fc0e329fe15fead81e37457cb1d1)
> > reproduce (this is a W=1 build):
> >         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
> >         chmod +x ~/bin/make.cross
> >         # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e240e53ae0abb0896e0f399bdfef41c69cec3123
> >         git remote add linus https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
> >         git fetch --no-tags linus master
> >         git checkout e240e53ae0abb0896e0f399bdfef41c69cec3123
> >         # save the config file
> >         mkdir build_dir && cp config build_dir/.config
> >         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=x86_64 olddefconfig
> >         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=clang make.cross W=1 O=build_dir ARCH=x86_64 SHELL=/bin/bash mm/kmsan/
> > 
> > If you fix the issue, kindly add following tag where applicable
> > | Reported-by: kernel test robot <lkp@intel.com>
> > 
> > All warnings (new ones prefixed by >>):
> > 
> >>> mm/kmsan/instrumentation.c:41:26: warning: no previous prototype for function '__msan_metadata_ptr_for_load_n' [-Wmissing-prototypes]
> >    struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,

Probably needs a fix similar to:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9dd979bae4cf76558ff816abe83283308fb1ae8c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7KxrfQ5FQmqVBAn%40elver.google.com.
