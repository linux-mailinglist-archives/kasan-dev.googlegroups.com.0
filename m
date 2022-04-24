Return-Path: <kasan-dev+bncBAABBK4MSSJQMGQELOJ7E3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D3A2350D069
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 10:11:25 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id i127-20020a625485000000b0050d3d1cab5fsf91962pfb.5
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 01:11:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650787884; cv=pass;
        d=google.com; s=arc-20160816;
        b=og2vIJj5PXimaVCfwpnrsx0BYAoZpRf7DnneVexE1nOnJimwXS/c4vm9PZ2HV9FPf/
         6igE9DeE9gZNcl01aKo1vU3XaiHAT5QmNL2oJii8mf7AypIBd6Ghq5Hl+3haLPVyWDy9
         zEHj6xiUMyibm87BGx26t/x5z7Jlrl4puXf3lHd/P1j1JcxVXPNZLiYR88mBkT0igCkR
         vIUqodDW/ek5QApDhhAj+59liQ7tiP/Lk2MGBNpUbs/xMylQg/AU44hClF2TBUjCq6qW
         B5JrwAhaJg3hZBrFBvqYPI3XXXCbsFIcy3drBn1Cz24TOUeAHBwuOkmR4FhVHOExm1wM
         XOLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yEyfK6ZHljQQHCgFJgtGzfkg34cOgXW+ii9C9muEt8U=;
        b=vbKeeRJhMlnrJqwo3qU1X4ToalgdCzqYiiHzcmNRIgmbq0bU5nvkzHZlK3iy9J47P+
         o18//P33sM8uEYFW2VGZCrxSmJnbnONgFXP3Ex/NIBwJucgQhlNHxDaoMR9LVA+owITJ
         syHlEmMDKueYmn7pkclFZ0A5dxQbNnN0iGjiE7VWwdr++kZlJyqXB/MN4u7W1xXvzw72
         MAseOQ6XoIjKtIGMAwqepYuzfWs4WG0VD10HDrYapayGPh2FsI71PigNURvopg3fGrEE
         s/vt1K0ohV7HTptm7GuyX69cwZ1uiYLdK6Bg1JSV2QkWq4MK8dQYb4FChMrHrWUKdG2I
         FC9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yEyfK6ZHljQQHCgFJgtGzfkg34cOgXW+ii9C9muEt8U=;
        b=hhBOx1gZaTvDCwpy2yvIo4K9BiT7jjQhEMlVg/hLYqLigniMuYRIcJWf+1Cbpq9i6U
         XA0mskSeb+iWozYNxW6ttZIKtYEAQyF3q9dZ1WrK5fCIRqrWqeQ5JWrXovOaAb5yJgrq
         fCDj/ddU88kVWNglkhf3AOH1tgw6Q+Q23uQJXIYvDHflr0TF9yuYj1qY3OG1yTZWfqR8
         HQdatakpOMFBDF05t5JhjL7ZW0i83aCSxghXvnUHImvptlKcYTstmp5tjtGOzKIy6FsP
         mbpEcIZAZbfHv2gqGDAJ1CJvPW/uKRkC9bzhx5hbzh0w+KUlFKYZi3hvTMdWU4pFnzmf
         bDig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yEyfK6ZHljQQHCgFJgtGzfkg34cOgXW+ii9C9muEt8U=;
        b=vFwHvns3nQO4vbybhClFqpcvLCGOCnB6cugoJCFPvu2UswUKvLZbH2qiGLh8DbTauR
         GKuyC/nQJikmOaxRcJQcBYYSTrFBpvhcRNSURhlwYvBqQFZC8Ji/i/EQAzcQV99xl5Rs
         VJbEg2lfjA0DM6uz8UKTQGxxzuXdodJEbPW5oT5LYvH55tPJoydlWMSpBo9NNVHz9fjR
         2PActveO+YrepCAdt5FyoYQKDbY70ZefQ4MA+5YVpCf2Yy7S/paZB4BNbdg7JNd7XxMg
         d1q9M0VPLDoAfoYtN+JhK1QhXIlIosaAljf4wztei5i8FYCsHf8nnZaTcrRevzajpqKE
         RSSw==
X-Gm-Message-State: AOAM531y7Hbeqbh55cxpSX8cfixTmnhQRwwQarN3Rh3JisI0j3/k6vG0
	5meFRF4cjvY+Hp6gTpRg11A=
X-Google-Smtp-Source: ABdhPJzG6JEvoD+4X5IEtQjvYKzHh7TomG/PeEBM+LTjJSsQqgB3+yUs+Wj9VX+0f3OVrjWmMKzpPg==
X-Received: by 2002:a17:902:ecd2:b0:15b:618a:2a8f with SMTP id a18-20020a170902ecd200b0015b618a2a8fmr12407902plh.140.1650787884011;
        Sun, 24 Apr 2022 01:11:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc44:0:b0:3a9:f988:c0cb with SMTP id r4-20020a63fc44000000b003a9f988c0cbls5900138pgk.0.gmail;
 Sun, 24 Apr 2022 01:11:23 -0700 (PDT)
X-Received: by 2002:a63:e24b:0:b0:399:1d7e:1503 with SMTP id y11-20020a63e24b000000b003991d7e1503mr10388251pgj.335.1650787883463;
        Sun, 24 Apr 2022 01:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650787883; cv=none;
        d=google.com; s=arc-20160816;
        b=vweyT5unG3K3sds9DI9aGkaSdXHGDyoYtGhhivUM+Fy7rQPH0Dhf3biLXgEBVhAA37
         AOqERK8BnEv+9yGZKk9bmDNaWsT4TPSHBqkWaZ/zlzbst/BDBnf5K/fDCw5UUdHv6jgk
         z+8zT/s+xNbxrOKMsv4ydjc8tLrFRxZppTyZJ9tqH0SjSUOw9+Wjumi+5+80T95v+L1R
         hQgN8mWGP4ZfjHGJCM+9s80PpiEqGpYCthUPgTA+Y7uVPumg/PU1WMM3xxEydMSiy5j5
         Bn9+Y/0bNPQx4TSG6mDqo4hvJGrb5Z2n3Cxsw3JGtXqIME0ETBVAbH4li4SJP6azFjx/
         u0TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8B7f2sAQ+h29UU0JCvw8UA5hobdEcso0blstQKIXFmA=;
        b=RZTwjslGwbIE9c4qQzAJ6w5iY7C1v8VYOdYwv4PzYAZ8D9RFX7U9vR6Y81C2U0Gc1W
         gR4ck9E0bTkzNg25x76ldFL2gMDKCNPci6FP92plBDKwI59SfWjSk3VQ456VKurAkImS
         e59TvLq21UhTreOZZGO0C0uyV6W2qbeiEbwYI17U/myhqcKAH1oq02FSQ3F4jCnPY/jp
         tM0f13jzzg0QvQN69YxuhIWmniaBZUx+5pzReW7O/tl+BNZ1i8DY3+subxE33tZOZ5cv
         HtkCz4eS3dQva8ddyyYR1w/Tv1hrp2WnehyFCcOxs3VtXHUhUjtqSyGyREi6xXnphEgX
         kf3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id n44-20020a056a000d6c00b0050cf326d9bbsi176801pfv.3.2022.04.24.01.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 24 Apr 2022 01:11:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi100026.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4KmLRD4PglzfZtP;
	Sun, 24 Apr 2022 16:10:00 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100026.china.huawei.com (7.221.188.60) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Sun, 24 Apr 2022 16:10:50 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Sun, 24 Apr 2022 16:10:50 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Date: Sun, 24 Apr 2022 16:10:49 +0800
Message-ID: <20220424081049.57928-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <CANpmjNM0qeKraYviOXFO4znVE3hUdG8-0VbFbzXzWH8twtQM9w@mail.gmail.com>
References: <CANpmjNM0qeKraYviOXFO4znVE3hUdG8-0VbFbzXzWH8twtQM9w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as
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

On Thu, 21 Apr 2022 15:28:45 +0200, Marco Elver <elver@google.com> wrote:
> On Thu, 21 Apr 2022 at 15:06, Alexander Potapenko <glider@google.com> wrote:
> [...]
> > This report will denote that in a system that could have been running for days a particular skbuff was corrupted by some unknown task at some unknown point in time.
> > How do we figure out what exactly caused this corruption?
> >
> > When we deploy KFENCE at scale, it is rarely possible for the kernel developer to get access to the host that reported the bug and try to reproduce it.
> > With that in mind, the report (plus the kernel source) must contain all the necessary information to address the bug, otherwise reporting it will result in wasting the developer's time.
> > Moreover, if we report such bugs too often, our tool loses the credit, which is hard to regain.
> 
> I second this - in particular we'll want this off in fuzzers etc.,
> because it'll just generate reports that nobody can use to debug an
> issue. I do see the value in this in potentially narrowing the cause
> of a panic, but that information is likely not enough to fully
> diagnose the root cause of the panic - it might however prompt to
> re-run with KASAN, or check if memory DIMMs are faulty etc.
> 
> We can still have this feature, but I suggest to make it
> off-by-default, and only enable via a boot param. I'd call it
> 'kfence.check_on_panic'. For your setup, you can then use it to enable
> where you see fit.

Can I implement your suggestion into the second patch and add the "Suggested-by: Marco Elver <elver@google.com>" tag to it?

> Thanks,
>-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220424081049.57928-1-huangshaobo6%40huawei.com.
