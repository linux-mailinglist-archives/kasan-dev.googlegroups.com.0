Return-Path: <kasan-dev+bncBAABBG7QS6JQMGQEOYQ43AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C837450D684
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Apr 2022 03:23:40 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id z5-20020a4a8705000000b00324936534b6sf7911491ooh.9
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 18:23:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650849819; cv=pass;
        d=google.com; s=arc-20160816;
        b=dFqwtTKv97DTCWCR1RULx0yicLo2LKU1vRzuW26VtlM5AbfgcOZt1x4S6/FBHAd6k1
         TT6y00uFjBcVp50ZL3Y4ara4woMeB5aRbncJSipQWYNOR+Kf8GPNPzrm2boEg/pRn9cl
         CVQ1AU9OfQ+yLwDbbnz4EC/6dc7+F8oza1J4p9D8bzImHijGXxGiqPZKzHl2g9/Em4pC
         NcMPR+r3UE/A62EqnCpqdgNUsc2aKqSQFj7eJrrh0heN3f+bjhsiIEd8nhc7X0dO7nCl
         Lwpnw26HCQrebM4a95NNJCCSDTHPUu0CB4zoOlrk+q5GOxbtQlLMloM8iDUWdxDS3/9q
         n3dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2Vmcb50RI3qJ7sWHtICn8v5A5x2+tm5gHsPRi0nKP2E=;
        b=ZNAutkiyE5ttKxP/eJDJmXdwEi525paco6WUbzrc4rLeroc+OfHWS94h7FK/xMfGU6
         IU+Zp/T1fhNZFwAxAlCddyJORltyP1D9VPKU57b9CDxzyQ5jJmltYAvKyDGcACcwwnx1
         eY8lAMLfy/1rFjpth3teG7vwvVTniCE0+BQPUE+LftKB1HvPK3cs3kDYC646oQ0LHmWj
         rlkuHSA7ieL+cqWu8xNJsp44k838AERFn1+7n9io8wQn6TueHatMBGjc2P9R/f9k+foy
         KAPWh9sMoCLgBpVWlTT/lakvFXcU15llE1PNHk/rEw82iiBbXDbqtLQGENM1cS9rqDgy
         ARtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2Vmcb50RI3qJ7sWHtICn8v5A5x2+tm5gHsPRi0nKP2E=;
        b=M4ixr3+eYPSGjlAqkV0ebCI2QCj4uTI9gcpt+7DT6+gSMdqqy3jpgL332bnGYQW2o0
         yTXW8x3eWePjdyer9fVeX7F5AiGCt3I8T94ptFoNdMJcsnVwIQkgg33s4MvwxNT8/uRW
         ikubsI5DYbPEhVsXN9fK7e4j8wyqGFsVIjQdO59t8+bRQb43q16C1qvqm8CQmuatdWuP
         wdKqSzSacIa91RQ5JBueZGg0LgAUADLKAwa3wVAEz5GyKge2Qah3QxEE9T2cuLGgxAhj
         gEvntwIYI+GKi+21obBOgj2EghAQ+PMyJjYVHNr9z21iGIfOhmVWqi7TJ7nIxQaRIHia
         KHPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Vmcb50RI3qJ7sWHtICn8v5A5x2+tm5gHsPRi0nKP2E=;
        b=PznI85xLEC43FJGAmwoebJz1szL7PgAaluiSqjj7DLc37uaold6ZvpKmL9ARAFR95l
         MYmR4y7tk7zHeR94p6oLqggIg3D6yFn0NfOqUtCn0UIJGx5DERQ5RF0B/3HCoWjAXTiH
         qZdXovJSbv9fyYZtdszbXvRek1OIRQK2lCsLQWqIhaX+mNLOFha1dPUcHfhuv03aqziZ
         LOQ+RtdfRNeB1Wcw+3/3xJ/9U3sHUtsRqw01B5/D/W4dwMXP1+SySpgidYZEeJfd6l33
         kncj2X6aJ8pcJzdu2S0UwvDeVco+I3tGM6niBxhDlTYP6xkW/RraS2cvzuqAKFibM+xd
         SDHg==
X-Gm-Message-State: AOAM531C0QdpnBg+w0MW2pDnG3ctR39pXx6/18e9VxPdnzZELQTK91Tn
	7Ihzb8AgImEXPgtqi1jIGiU=
X-Google-Smtp-Source: ABdhPJz5IikGuBhtSPIw4eCHMICwdZV256k59zEA+MTdrJBujQdldSrbf4jkLhvTpB4sTtHdy4YxyQ==
X-Received: by 2002:a05:6870:8327:b0:dd:b065:6a80 with SMTP id p39-20020a056870832700b000ddb0656a80mr6021526oae.167.1650849819471;
        Sun, 24 Apr 2022 18:23:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a13:0:b0:605:7fbe:4520 with SMTP id g19-20020a9d6a13000000b006057fbe4520ls1661173otn.3.gmail;
 Sun, 24 Apr 2022 18:23:39 -0700 (PDT)
X-Received: by 2002:a05:6830:2461:b0:604:349e:b8ba with SMTP id x33-20020a056830246100b00604349eb8bamr5768457otr.339.1650849819076;
        Sun, 24 Apr 2022 18:23:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650849819; cv=none;
        d=google.com; s=arc-20160816;
        b=Kdkt9NSYOexe26hRAl1rMNqpQky0cpA4rU7ljA81y4SrSXU/Zqwb4JHBkuSd0CyQyN
         DLF1nFFogvPfI/3jNbHmPCZk/qpQAxuMWjBZ6Avsf1aMBF9ewraysGezd01mePHhjlXa
         pkzuHHvbraV9rvA8sLyTUbTPaXYdKR5iiKzwym2xVsMacGGR2iIFsf1HUqMDq4eyL6ww
         YTCnJAobnL9ItQtb/UnEotz4mA3w5zq4PsTLELcEralPvY7sUt+kS2kbLrbmkoTgn3mJ
         xgKiqWyUtUsXdWubnv9uHtMAJH4vpTA8ILtHGq5U7Xy3hLbj3CJjwd2fnnUzHCzEKWi5
         bCXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=gnNnns2O0civrmjFz4szfFflY9glkzlEAvPz+SeLb6Y=;
        b=eyZyN3PyGVortbMRsXThgMYsGtsvOPYF4CNllwTew6mgTLqtTY5hLjeA4w1IZYjVVB
         +FSA+4Lz2UGH7Cf92UIyQhL0RPMo1EYbYcLTFNT43UHhdnGjbl0pIAQF2pLZW0AYkZGd
         5mi/hkvWnxqdNrCIaV0Ve2mkiPQRJqaqq3hADKs1kZxuTsnfUMbq3qBIzYFe/+W5dFgQ
         ROlCzJrBC6ZaUkJ2Z1c7bJLZrOWoQmhAAEWEE8f8AeqtRXQ1P0B0BoydMoJp0QONAfQp
         q2E4wK2hPaXUE+Wr8sFmvIVH4iB+8fv1Hiw7fsCsuay4bqy7DcnSKR0jtdAQnFTGc44r
         3Pcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id bh39-20020a056808182700b002ef895edb85si2081178oib.2.2022.04.24.18.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 24 Apr 2022 18:23:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi500013.china.huawei.com (unknown [172.30.72.54])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4KmnMd32KSzhYf0;
	Mon, 25 Apr 2022 09:23:25 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi500013.china.huawei.com (7.221.188.120) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 25 Apr 2022 09:23:36 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 25 Apr 2022 09:23:35 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH v2] kfence: enable check kfence canary in panic via boot param
Date: Mon, 25 Apr 2022 09:23:34 +0800
Message-ID: <20220425012334.46364-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <CANpmjNPEErc2mZMSB=QyT3wq08Q4yGyTGiU3BrOBGV3R5rNw-w@mail.gmail.com>
References: <CANpmjNPEErc2mZMSB=QyT3wq08Q4yGyTGiU3BrOBGV3R5rNw-w@mail.gmail.com>
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

On Sun, 24 Apr 2022 15:31:42 +0200, Marco Elver <elver@google.com> wrote:
> On Sun, 24 Apr 2022 at 13:00, Shaobo Huang <huangshaobo6@huawei.com> wrote:
> >
> > From: huangshaobo <huangshaobo6@huawei.com>
> >
> > when writing out of bounds to the red zone, it can only be
> > detected at kfree. However, the system may have been reset
> > before freeing the memory, which would result in undetected
> > oob. Therefore, it is necessary to detect oob behavior in
> > panic. Since only the allocated mem call stack is available,
> > it may be difficult to find the oob maker. Therefore, this
> > feature is disabled by default and can only be enabled via
> > boot parameter.
> 
> This description is still not telling the full story or usecase. The
> story goes something like:
> """
> Out-of-bounds accesses that aren't caught by a guard page will result
> in corruption of canary memory. In pathological cases, where an object
> has certain alignment requirements, an out-of-bounds access might
> never be caught by the guard page. Such corruptions, however, are only
> detected on kfree() normally. If the bug causes the kernel to panic
> before kfree(), KFENCE has no opportunity to report the issue. Such
> corruptions may also indicate failing memory or other faults.
> 
> To provide some more information in such cases, add the option to
> check canary bytes on panic. This might help narrow the search for the
> panic cause; but, due to only having the allocation stack trace, such
> reports are difficult to use to diagnose an issue alone. In most
> cases, such reports are inactionable, and is therefore an opt-in
> feature (disabled by default).
> """
> 
> Please feel free to copy or take pieces above to complete the commit message.
>
> [...]
> >  #include <linux/slab.h>
> >  #include <linux/spinlock.h>
> >  #include <linux/string.h>
> > +#include <linux/notifier.h>
> > +#include <linux/panic_notifier.h>
> 
> Please keep these includes sorted alphabetically.
> 
> [...]
> > +/* If true, check kfence canary in panic. */
> 
> It should be "on panic". E.g. "If true, check all canary bytes on panic."
> 
> [...]
> > +/* === Panic Notifier ====================================================== */
> 
> Blank line between /* === ... */ and function.

thank you so much for your suggestion!

thanks,
ShaoBo Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220425012334.46364-1-huangshaobo6%40huawei.com.
