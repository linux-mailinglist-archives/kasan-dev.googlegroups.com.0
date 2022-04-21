Return-Path: <kasan-dev+bncBAABB3V7QSJQMGQE74WD7PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A32509BDA
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 11:12:16 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id pb1-20020a17090b3c0100b001d2b09b6185sf2153589pjb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 02:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650532334; cv=pass;
        d=google.com; s=arc-20160816;
        b=weAHnStrhhursKPno8Ue48AFBgmlZRnYlo+FYwjBS1t0VOSYqsixDkIFdunoHXt4ao
         vdrIKyOJ8bgoQbr+k/nlMQKrkC3xsYB44/l/KEMxqVHTLW5eeDNNm7jYej3w7PL+Ki2h
         DDmaOOmCP3UXSRbWIGyRdxsx5G9R/5eLafA9ynXZWiznqA71OziOjPyYaHcA/wKwULxq
         Vig+tt8kZkPCQp3PZe4B6UM62FWmJeIvHTjiGwIs22rcFOCQHgIag+ELyEKh0lDmd3IA
         CxpFbgw7/upCyc+58aQpLnWMoJFDgz697uzyQu71EgpWNOedWyBGmXyeSjoO0K3ztWZR
         /jBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=M5Qhf6IYbwDq51Q37s6WF96c24ygWXwy8JCxC48ttEo=;
        b=TF4S6NBVK27uve7s/gn8LgIPTb31nHa0eJMchUL2TtUctlLefl6A3Bzz2fVUyiDqrb
         j2+mCtLKJRq15kMiYo0bchkl6ElnuR9QF+8thWyrPSO5+nWKVRukDMR8wnthA46LAdOk
         ZsRz5FfX6JZtYcDYKjl1NHU0w/3ytqiwxo78NWQB6hD4k0e9BSZMGXurXIxmH2sJSdgk
         on456jSpL90xSIYIyGrmdHq6FNtL0ScZVN3V9wbY+rEH+TSaZQVUkebYblphRkU0wxy7
         1KhYt6FScHmiHjjUc8XktpTLSp8j6EArfg31S4pqcDILR4amvK+vpazVpwepR8JopekC
         qeAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M5Qhf6IYbwDq51Q37s6WF96c24ygWXwy8JCxC48ttEo=;
        b=XsioQifD/XCIvGrfPStD4RGYbwrPgmHOmHdicSettQz6mqoFBpscn+bbe3rDx1YSdf
         uBw3y+HUxIqSdIHetbbaUBcdXdP0UunFHWzqi3HUbPIX8PR9YR+E7BRw/vi3Eeglf04n
         0HFXx9/LOW1U294N6bOMZASiiZFpy3RZqeOzTH/PCqAKTkOmrE5E5mePN0Pyi4PErB+u
         5QJ1n/+zj5QkBcs2sjDZYlm6GQznhb4ybhJwHqR+CkJPdAqqll85n4RIXSwl7ApdKCFZ
         CGtgFYje7jFgCp1eOrXJxgiokJ8D6vMnvj+kQYb6XiNJV6tfkdnZnnkRj5b3OOhxEQW/
         fxQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M5Qhf6IYbwDq51Q37s6WF96c24ygWXwy8JCxC48ttEo=;
        b=ZYfavVYy1lLCWCEfWiHuUrqDyq3RztKrIDrc8TQjW+0QvtuOo4BSbUC2EsWvEetpr+
         RI69BGaFqriYrsjBjSz+ubH+9AEvvR700V7isrt5QOGZdy7gVdsm/prya9azFoHnnoiC
         hGhriT37bvvNGm4jjCNvNuIEZ5cMEQnmB9xob/L1KLrursbcpUZinciUnte0+SXsM3qE
         39eGhnDmV33UDr70pXco6zrSQ3HEnpb6SPL1yDOhIa0IRmoJMtxmak/NQIIFhu4kD1ah
         itLef79UhK+PYLXNxTyVqDzO3Gvo/o7pleABPJ0C1P+SwOlTYb8k3HUwRcF4AqaetkcN
         pmGQ==
X-Gm-Message-State: AOAM533UxzJhTGIJIigd7wB68ZUgWuZA9FqrNFSSw3ZJOwRae5uCH5GI
	r8xytKd1mXsEU5rP+tma+/g=
X-Google-Smtp-Source: ABdhPJxE8GKwdZCZLxNk3reFY/gvtDn20dy2xRTDA3dKHwjl8LsSnwwvhLs2OUDG46TWDGdy9s589w==
X-Received: by 2002:a17:903:210d:b0:158:f143:2093 with SMTP id o13-20020a170903210d00b00158f1432093mr22597814ple.43.1650532334648;
        Thu, 21 Apr 2022 02:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17cd:b0:1d2:e93d:e8f5 with SMTP id
 me13-20020a17090b17cd00b001d2e93de8f5ls6288752pjb.3.canary-gmail; Thu, 21 Apr
 2022 02:12:14 -0700 (PDT)
X-Received: by 2002:a17:90a:72ce:b0:1cb:6ec7:cd61 with SMTP id l14-20020a17090a72ce00b001cb6ec7cd61mr9399432pjk.213.1650532334193;
        Thu, 21 Apr 2022 02:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650532334; cv=none;
        d=google.com; s=arc-20160816;
        b=kkAZcOemCWbL7CH3IYpQkCz6ZbmKsyqYZn6aAPH6xFYPUKrNVVMbecPFxNEYZNXGhp
         EOWuu605e/9to+fNcTdvy+T8WUWZ8XzU5bEapkdfNHDGuGrhaOBym6YtVuzTYJENOIt4
         Tjo2hVA+/Js0y12KY8se2kmWog8G5uou7O+OZsE75Iz0jn9TMpVP1fJ2WhPIX5fL0WqQ
         ENeoy5YFG5zuP6/LIT41kNgMTdc+mkPNT/Wg4s0xkx1ghjWrXk0Rj4MYgRA0ApA/mhBa
         fabVhNMOwDDEQEn7DAv62A2XTkTWk20zIdO0O6fBh3Cjblmaurj2V9cYCLL7Scu+7W0w
         k2Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=TmZ6iBSYRNxLpRKrXFizzdteeyzKvPs4+O2KOGWov7s=;
        b=czGIo2yLFvCODh/1npED2oaDl72Ji2GjXcy4OogbPgL0c1c6LIpETZn+helA69xvgY
         SKkjA/SETdLFzz7IRIniv+TJMalinhOescsUv6OQnZ4AkK+8fvhqHaE9aKx5/puDaC/t
         XcNCl456RNSKzBSUJY5o0PqqvwLq41uUsbyBTs7O3Yw4L9wrjc53CGNQgbOGb2a7yLt/
         nRBY74xOxuGIC+nq9pXDpqimG6mMjfEUAYN3KODtYxFJda3cgoRs4YOwrPEDu0S30n62
         FyglsONNzIHPBnW7ZWcOfqyd0ND7eIRsy/hgA/oKd7KmR0RJ2za1vMCBMNl152P7r9wk
         nQfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id lx17-20020a17090b4b1100b001d040b6bbc7si378501pjb.3.2022.04.21.02.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 02:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100024.china.huawei.com (unknown [172.30.72.55])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4KkWxV1CzCz1J9wK;
	Thu, 21 Apr 2022 17:11:26 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100024.china.huawei.com (7.221.188.87) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 17:12:12 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 17:12:11 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Date: Thu, 21 Apr 2022 17:12:10 +0800
Message-ID: <20220421091210.27068-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <CANpmjNMAT_DaiOoz=k6Z13nVR_2A_5fck12h0JKQSmNQRSKwGg@mail.gmail.com>
References: <CANpmjNMAT_DaiOoz=k6Z13nVR_2A_5fck12h0JKQSmNQRSKwGg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Shaobo Huang <huangshaobo6@huawei.com>
Reply-To: Shaobo Huang <huangshaobo6@huawei.com>
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

On Thu, 21 Apr 2022 10:50:10 +0200, Marco Elver wrote:
> On Thu, 21 Apr 2022 at 10:37, Shaobo Huang <huangshaobo6@huawei.com> wrote:
> [...]
> > > >  static int __init kfence_debugfs_init(void)
> > > >  {
> > > >     struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
> > > > @@ -806,6 +832,8 @@ static void kfence_init_enable(void)
> > > >
> > > >     WRITE_ONCE(kfence_enabled, true);
> > > >     queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> > > > +   register_reboot_notifier(&kfence_check_canary_notifier);
> > > > +   atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
> > >
> > > Executing this on panic is reasonable. However,
> > > register_reboot_notifier() tells me this is being executed on *every*
> > > reboot (not just panic). I think that's not what we want, because that
>> > may increase reboot latency depending on how many KFENCE objects we
> > > have. Is it possible to *only* do the check on panic?
> >
> > if oob occurs before reboot, reboot can also detect it, if not, the detection will be missing in this scenario.
> > reboot and panic are two scenarios of system reset, so I think both scenarios need to be added.
> 
> That doesn't quite answer my question, why do you want to run the
> check during normal reboot? As I understand it right now it will run
> on any normal reboot, and also on panics. I have concerns adding these
> checks to normal reboots because it may increase normal reboot
> latency, which we do not want.

as you said, the detection will indeed increase normal reboot latency, and the
detection of normal reboot is not very meaningful. considering the cost and benefit,
I agree with your suggestion to only detect in panic.

thanks,
ShaoBo Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421091210.27068-1-huangshaobo6%40huawei.com.
