Return-Path: <kasan-dev+bncBD653A6W2MGBBDF262KQMGQEP5A6HZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DB37561ACA
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 14:54:37 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m17-20020a05600c3b1100b003a04a2f4936sf1452639wms.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 05:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656593676; cv=pass;
        d=google.com; s=arc-20160816;
        b=hNaD+RHfjdvmScgKwQe1kjzRKD5xh8beT3MdDBErbVF5Fucx5zaafDa5j/y6SFbyaE
         OngNNKBbftnmJna5hzY4cttaced8bwrfX2qroZEmdu/8MJ0F6f+OW5FwzF+fkkuV8+WR
         TF34WdTJ3JcR6MPlEPkamX8Sf+2xXz/+vF1sCuifJj/NGOhsYEKdpeOz0x9llR+XSQTa
         9l3fLkSaG9S3wLPft7tC4pgUShU+UOIwILTuqUMMYqVaaIYaTGortGw+w+OyRvTfnJfR
         uGEmgSesylsjjwiq89M4loWlMLSJYbt8C/+kT+MIAEhMzvNjmLzkumAb2zy+RKCzMQOT
         4Niw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=BRroPMDrlV+oscwq052M4kj20Gpq2hwzlgZXIcZtp1A=;
        b=BgUM9cuFfUMD59sAEt0e5fpWZ3tCHuyK0f1zawWBuYTFbAIZ40f9Bvy/J0hR+iPqxy
         9N/TVkzyrM7CuunmKjyfRWL1BDhlwXnF2fARJyhMPbxF/f2JLT2oG5/PwiwVLNJqI6Zh
         WbgXMjvwq32oUtGl0OAZzgtuKavXbFF1WbJpc9roV4uOhpaqYC2bdgksiwS3YDaX+0I3
         cny6l3uh1wQfpMvxh7i4qbMa28NrLBNN601zuBerjC7xAhaK7nrstw2W9K25pRVKJkfS
         /zLglxC7W7ZaxmotbQ+qERbb51r1rtu6wMde0qPbxmP8C++ur7Vk0abKe4ajH0B4z1Fm
         jkLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=oxnbg2Mq;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BRroPMDrlV+oscwq052M4kj20Gpq2hwzlgZXIcZtp1A=;
        b=Wa8OU3ln3eJ9vCvkn734qC293eppaOz7dZ6bakONcjR/Ivt/sQpvRQnOwdFA6xcxVh
         NNnbEqoa0I9C0E4L53ZuodOOUtCk3qOQKNO+ngVDyMlgODyFMQMvVW7PKDL2KXOEn+aU
         syhBzGtZLig8TC/twxCG4y4sx0VrpN6elAFyTQCj8y0rb7JA2ngtXqUzedpPkxPs+N8f
         DQPSB/DQT2ohW9zVVo/GbmtKc+xI+dG9pTbYYD36TWyanHNPNWa27KCnNig1rMI6tkNc
         ec3N8K6O8CMKWZD6E/6q8jt+b3eZz2P5Tw/V9qs3zS7szYrHGBURRfnxJIOgvR1UbnSk
         ap0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BRroPMDrlV+oscwq052M4kj20Gpq2hwzlgZXIcZtp1A=;
        b=4flz2+brKm51yQPFV8jNFhVmeMK9YypMvlUejt+KkXZD0fQgAFDEW3yxk9Dakbfh+j
         gXNkfXyLIlyH0pjJ4eHyrKtumb2laS0UgN6IR/39fIYXlpw49FbOvz0AwWygaINwSJoP
         TVoI/ItG35kqKqkKeeAGABrHZzqeiT/JBLuVj4Czq2802X1JJf4YWIShpI++VNlY2BWj
         1bZnnwPsW/n6duQhLT44PcC6VOCwlMc4hyDIk6Riup1lQ69niS6xeP1a0RSW4Byho0oI
         9UpbmXUa54YmTXiiJbS5i7QThfrRSZ//piDfRuks9Dk/mxuvS9l4ILkdBn1cSxOaE8Kk
         FBBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/UeDSMK8ZW5GRX+fej+khPGTeTORfMVDNKsUlKGoRkkI+ilGtg
	Mm59e3pYEyhA4EiN6WthZKQ=
X-Google-Smtp-Source: AGRyM1uXfgQysq/cv3nqrUrYTpNV65rYJthv1Z0snSkV4JoLLGLRalp8BOkRXJeVtW09Blrgp6DlRg==
X-Received: by 2002:a05:600c:4fd0:b0:39c:6565:31a5 with SMTP id o16-20020a05600c4fd000b0039c656531a5mr11789519wmq.60.1656593676723;
        Thu, 30 Jun 2022 05:54:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47ce:0:b0:21d:339f:dc1 with SMTP id o14-20020a5d47ce000000b0021d339f0dc1ls4190575wrc.0.gmail;
 Thu, 30 Jun 2022 05:54:35 -0700 (PDT)
X-Received: by 2002:a5d:6b8c:0:b0:21b:8f2b:cbdf with SMTP id n12-20020a5d6b8c000000b0021b8f2bcbdfmr8615797wrx.518.1656593675695;
        Thu, 30 Jun 2022 05:54:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656593675; cv=none;
        d=google.com; s=arc-20160816;
        b=JfXpu7C/Z/0U4YLh/0EIsc9rKN9d7jUhmGbs/yHyU9YswGQ4w123UJy/uMULYCNPf7
         XQi99Pv/gDzn6icuugZ5MDSJpsoLMGs2i2B0b3OiPtjNX4AhKmQjlgC9DUmmkx3kF52e
         TpmmNdczOOOjHFbU6uYS8FFoyQa6Zv/n25G5DITr9G/nmazMgvNbUycVYtyHzHReregr
         VGJ1rrT5rlEkTFmlUXXutv9TbjnKVPBANkqOhWGrEwubJpTKbCOhrJySQkLC0mbrjMDm
         r9JLkJ0GH45NRVifG8Zn7VCyeNz1bXf4y++/SKyOMTik2htR43q1eWx7Xk9++nY5GWmm
         wSdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=00xPuIlNNMZ8E6p+AtWP/6zDNpgBkiHKeyoEzjO0F/o=;
        b=Zd3mKJvDjymVweeTf/Ray0SFrNbQk5tgprykRpduiT5YpD0jqLMiinrb02znPr68H5
         KMm1DeyepRRHayhWIRgK2GJCt33AcoO0m0PBs+zIIc4AyRw0I2Xt3ZqDB9ymyiV5oGuC
         XnVOqDtu+usHzwc31hVtsXfzNQh9lC9nQ1l4Zq3tBycfm4REdZSuCxeXxvkLGCE93Osu
         Euiyvsct/oB0itJCpHm/nst3WIrpQxaiiIiAVW9/II+PtYwrerJDV2096i6OUoJsBZcy
         zaaRKQHkfWQpzxT+LKR5gSlcu6QWris85cguECYaFnHMrMmAm6xCpO5BpKv3GpnmHnrZ
         4F5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=oxnbg2Mq;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp1.axis.com (smtp1.axis.com. [195.60.68.17])
        by gmr-mx.google.com with ESMTPS id f17-20020a5d58f1000000b002102a7531cesi620332wrd.2.2022.06.30.05.54.35
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jun 2022 05:54:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) client-ip=195.60.68.17;
Date: Thu, 30 Jun 2022 14:54:34 +0200
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: David Gow <davidgow@google.com>, Johannes Berg
	<johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>, Jeff
 Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>, Brendan
 Higgins <brendanhiggins@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, LKML
	<linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kunit-dev@googlegroups.com"
	<kunit-dev@googlegroups.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
Message-ID: <20220630125434.GA20153@axis.com>
References: <20220630080834.2742777-1-davidgow@google.com>
 <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=oxnbg2Mq;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

On Thu, Jun 30, 2022 at 11:41:04AM +0200, Dmitry Vyukov wrote:
> On Thu, 30 Jun 2022 at 10:08, David Gow <davidgow@google.com> wrote:
> > diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> > index 1c2d4b29a3d4..a089217e2f0e 100644
> > --- a/arch/um/kernel/Makefile
> > +++ b/arch/um/kernel/Makefile
> > @@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
> >  obj-$(CONFIG_STACKTRACE) += stacktrace.o
> >  obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
> >
> > +KASAN_SANITIZE_stacktrace.o := n
> > +KASAN_SANITIZE_sysrq.o := n
> 
> Why are these needed?
> It's helpful to leave some comments for any of *_SANITIZE:=n.
> Otherwise later it's unclear if it's due to some latent bugs, some
> inherent incompatibility, something that can be fixed, etc.

I believe I saw the stacktrace code itself triggering KASAN splats and
causing recursion when sanitization was not disabled on it.  I noticed
that other architectures disabled sanitization of their stacktrace code,
eg. ARM in commit 4d576cab16f57e1f87978f ("ARM: 9028/1: disable KASAN in
call stack capturing routines"), so I did not investigate it further.

(Note that despite the name, sysrq.c is also just stacktrace code.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220630125434.GA20153%40axis.com.
