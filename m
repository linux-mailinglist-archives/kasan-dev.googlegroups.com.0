Return-Path: <kasan-dev+bncBAABBSGAQWJQMGQEPUOHOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0512550A11D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 15:46:50 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-2f4dc56af69sf8782197b3.6
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 06:46:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650548809; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6PkvQcfnqv5T8bphpYLLg7l+IYdSedZiL8My01wGZYvAR20R1jlEhaHFa7vjsZMdH
         iQRmcZZYy4g9ILu3ZyWPjxTobOlXD/FRUP1tYnOvLYILkDTOG+5C1rOO0oSoJ8jg6UOz
         0F3mKrA6fW5t2aVgD/rcVlG4tlhLI0i4CxKYX8oox+kelWjIbhtbUblo+wsok81Fqa0M
         ZCcYHoQM+g6hq1pwSEuHBPjK1C5s7f4qdma+Z4dvff3jL2DrdQMZFP3hRohqliWGfDDm
         MzIST8fAaiyw93QgumibANNo3/FU1MjY1eVTrr2yBXqCivjLptZzBn2yQKwlWdw57Krh
         IZJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=6u+L+OFGWziDoqW9SoCukFqMRFU3pAQ/xhH7L/MZ0jI=;
        b=NV4AnIcJlOTIVU2UDWo7EfXRSBBswfMu7cAP/fBsSrzNyvUhouJsqoIlI9v8sApQk8
         DBUund3tJex1bNdr3J8m+hfZKhpXgNtJYhcibZHOdiEWctwcf05YY43ooJOtbMi01Iq9
         TiwAeavNiCJ48W0ETrpSIwp9nzDs7hPr8xqiYMWbn/mtZ86BszsdP4C0rfnWXgHiucbf
         hJOEtBEBsZa78X1NbSZkbUC1Wyg9POjhI2ioU5S/KWtFxWT7Y30Fs9R7+nsLwH1HXWeM
         vXZcDyXsL67+k65RZXC1BZcnClXpe/S5eEShPmac8y1WOWtCtl3n7rTipKCEjJdhgJn9
         fxPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6u+L+OFGWziDoqW9SoCukFqMRFU3pAQ/xhH7L/MZ0jI=;
        b=ZPBFCdemtM5G1S7ybsVL0cp7y1dHQvrePRfVV+cJBvViPPJli0Hmv9giTdAJa4EsED
         3dwIg2dfKSzhYYKR6bsk4OUiIzjPLdI+UMS8a3nfpr4VgKMt2DL9keyJhkX2iioaDa8s
         PgR7TWQPr8O6Scku5olaj74P72Qkbz2eQVJPg3xzRliYZ1ag5tel7m34vWnnneU2z2+5
         YuwGODOW6rx9eVOD/tZKvWH2Unoi4DnAqKOtmAaUIfP6OyoVR4muuiJRZf+orb49p6G2
         Dtl39AACShfNlb1WitwrT05x9NEn/wbp1TK1WWo2LYLfzMHLOLsqi4LKuiSjM8XMsumP
         gGog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6u+L+OFGWziDoqW9SoCukFqMRFU3pAQ/xhH7L/MZ0jI=;
        b=qr+5MCdwVOb4xFVfIdhQh9kLf/CfxWCF24Q8AVr1f3qQe4pnJ8zvAW9ReZm0HfT4eT
         z3McTaLe+RLsTn3JNm3xBQxU4BMh31vlfERn+m9bmNQQp6hcjSs4RR2Wmc32j8BId/tK
         2d+HO/PxtTX6M3S9DNNBoRr27AJTJE34AjVLDSz9NNo+l+Ah+Hqxi1Awy1OxIMlMRRTA
         +AgWNbMbsDEXyHZ9bxb34zifMeddMyTxxCjcHNuWrBhkJlj1vSUYEmogSKVJ0vjko5wA
         6vvtqadW3UZ7ALf7tcyExQdekIqVKW776A3jmKkKwqoZba/pIP8Xe4j6nkSugZ7C2veq
         qR8g==
X-Gm-Message-State: AOAM530td6qbEFPAN6IYOK4jDBbQ4u4KlJRfhewugI0LN2hL3KOJYtJq
	xc+s1E7uQKlxLkF51ZNl3cY=
X-Google-Smtp-Source: ABdhPJz5YmGwYqYPeZqrt5DU8GTMmFqiSmoI/yB01bg27xnE9L95aXLO1ArHk/Npt1e70MYG6CRlbw==
X-Received: by 2002:a25:da06:0:b0:645:380a:7ba3 with SMTP id n6-20020a25da06000000b00645380a7ba3mr12902817ybf.300.1650548808907;
        Thu, 21 Apr 2022 06:46:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5288:0:b0:641:5a3d:6f13 with SMTP id g130-20020a255288000000b006415a3d6f13ls4403001ybb.2.gmail;
 Thu, 21 Apr 2022 06:46:48 -0700 (PDT)
X-Received: by 2002:a25:a12a:0:b0:644:e94e:5844 with SMTP id z39-20020a25a12a000000b00644e94e5844mr19968068ybh.492.1650548808384;
        Thu, 21 Apr 2022 06:46:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650548808; cv=none;
        d=google.com; s=arc-20160816;
        b=fjRqyvroL3BM5BlzhQSovg57fV3pf7rlQMjD4snIym9262Q+rmn1zhNztnQndYijIS
         LyLIvCtw8ADfUXfnELAkvTqNi9AVmt3AdpbZSZ+3uQXhsHva8M52NEl+MkYKFS3yAsAD
         JhLnf9FSvs7B9HiNf8yU5+WtMzzXvZrbONTG/xFGgTtYrbX8wbO67Eeon8xqUYDydR7J
         5uPGQtTjs6TuNnu51R+eY+GHo29atL8k7XpuYgKzzF9D7MF48du1PiU2tQHOJ57RWFyP
         JgqF+2kmecO8cQPX5sFlDxc0GZVKr+sm8EF6hQbmxU9/O1Y4TVD05OAND4SqAWPcv7dh
         j/bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=pQm8XI9GupnUPQKID99HAxbd82wx7NMNZKk1eZsUzY8=;
        b=M6paQa+RoqMW1vP4MHmGf+4YpDU3+t2MZogTL9YuXeklmWWjsVExaGvJq+A2g/oylw
         +P45S6tPbdvc78mqIdhUMZ/Ai1EM0jW6y7Xg4HofOrrOXkCeOpWtMZpZ8atZz+JqGNP3
         YY/CoQ34ER/G3iKtY8hDhs35lfaxzCp/Ie/px5kQuNfHKgkojdhhOcqim2iH+4B7K1g8
         nG3xWfaQy0ZGftrE0v7Ro5+aYaMgdz1lGH+8U+RZ9kYjJHD6inbgXMQ1B/J7ddEYkZyp
         xYcn3tAS8aQnoxQTuF4FijGp4dkSa0ipznH849SvYfhI+HKDJ3O2H4XqJwPlhkWVGEVr
         wfyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id s80-20020a819b53000000b002ec27a758adsi354123ywg.0.2022.04.21.06.46.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 06:46:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100024.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4Kkf2G4P81z1J9rd;
	Thu, 21 Apr 2022 21:45:58 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi100024.china.huawei.com (7.221.188.87) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 21:46:44 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 21:46:44 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Date: Thu, 21 Apr 2022 21:46:43 +0800
Message-ID: <20220421134643.41728-1-huangshaobo6@huawei.com>
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

I agree to give users the option to use this feature.

> Thanks,
>-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421134643.41728-1-huangshaobo6%40huawei.com.
