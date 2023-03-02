Return-Path: <kasan-dev+bncBCQPF57GUQHBBRNCQKQAMGQEDUKPLIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 932A56A81E2
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 13:06:30 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-536d63d17dbsf315059967b3.22
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 04:06:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677758789; cv=pass;
        d=google.com; s=arc-20160816;
        b=AExFDJXmDSFQK16fCPAcD78WjKyVpuhzjK1+kFECbqgMpQit6DusW8vmOxqSqwMvZU
         F7yLZDREv4Uc2PMcVeHAACW2IFgu3Ud1Xhifk8CjbL6l4lbJg2qi+2wTIBH7In9bPJaX
         BZ9yU3t1Ce2YbnRwwOWy2sBLmY2iSext6CqkQsYtyoQlCwAPDWzTfeda55f7HfQnzJuo
         DUWCOzDFHr8IqdoVAEft4YkW896eUVgtAMInx2VkmE23xJ9THsTjyxBurF9x1GufGWcG
         258mARzn4Dz5XwvZ2u6ogrF1Jf0pd1O7woyonWqot2iL/2Ji4/Vd6zeZbn4dh4eKrSf0
         /xZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=bu4OGj1ewph5lTv4KYgkzrzBB4AKszVoxKRL90bTBSU=;
        b=PxNG2LdxNI3qKLxBeZzDCjYfNAKkYBYi/1OBHBoK/wjsveWfQIpW7UbB/kDrQA6iKQ
         bpK4A3xQxiBI8xXYYI5Ttu5iz+cCmXY6qiB0wVTZ6SprWJRKQEtheg1vOr/MRdaxRT1/
         NWnru+u9VgWpyKoOV+dwBJyGYSlchQADWgag5/gg59l6/jZbK3oDg1XYcu+vHOmZalgp
         vu9u6Jy72D42kIJmkDr9kCv7+AlQ/JpXuO8QfAqQ03QF02OLm3JjyEk/Y8rl1I2mHWKR
         LsFnnCdHsbPlwadcqqHFY6DHr5rVu0f6Wbih3fUiGr7VUEh6X6Q5uz1oRKCcFrb9xMvK
         tkRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rjeazakbai8bhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3RJEAZAkbAI8BHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bu4OGj1ewph5lTv4KYgkzrzBB4AKszVoxKRL90bTBSU=;
        b=fKrNANGuy+qNG+K9RKs/Ke7WZw9iiXK+1UjcETXkgi2lfjwkr7kdBGgtf73bOYsAGJ
         vXNDfoiaNH5gNEUZ9ztPIFJDPOXWtg+WEw9AnysregKidxxzAVb1jEpOaWmZMiKtnO7M
         m6+dhkKlR8BOmLt3ZxJBc0aPzuAsawVJciIIN2nnzmD7AXWmQhrDezgJ0xV5bAVyJvtf
         qknohnIWcQz5PXaFYHE0UZy9hLvRwboa5orlLu91gtA7xZcsPUfniwJkczt8vzvkOmNo
         uKXB3GGUdbGtiIZyCIyCrXJLTajNyvk0LE8q4LrE+GiFNJYb8k+0kdCCt6iPMZSx3k/a
         BefA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bu4OGj1ewph5lTv4KYgkzrzBB4AKszVoxKRL90bTBSU=;
        b=SKwmX7zVuHUsk748y4TXTVAt9/SJsWX0ewJDUDrBYKSGJ6sI/BAbrowrqIVCQ0v5vQ
         /QqDBNVnHTAif7RNuxrqwwKN02JnO688ERj1+rgcN7k0YQngzcCBSCNGUzDE0muTa4im
         lOH0IataISWQL5Uoa0vRoRg24xgNe0NY9EUEpueY1K7nyk1uQOuSQbGHdSPdqSYhHZed
         s66kWxmf+7x/WU9GYPcdeiVpJDfshGV2jb3B60xNGbxmi1S89o5ENq3oEQt3rq0hvTfR
         aX+yiIcu6Uh2U7KDvxipqaNSypf4WqdUBjB4nnJnu+4cTaypPfjpyErvRVFUriDoar1n
         5jFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXrfTeOnD6jeAk4k783GcZvvLb/7XzYqiiWjbrFS582pphBe4Er
	PnQQnIBGwBWegN8zs0aDveI=
X-Google-Smtp-Source: AK7set/ZA0wLlXyiUKDWymQhD8kerwk+S/+3tk7LeGbLI3eB4FiCBb5f/PmX9xlEJkX45EOC3Safrg==
X-Received: by 2002:a81:af5c:0:b0:534:515:e472 with SMTP id x28-20020a81af5c000000b005340515e472mr5949316ywj.4.1677758789421;
        Thu, 02 Mar 2023 04:06:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:d8f:b0:538:65bd:da4e with SMTP id
 da15-20020a05690c0d8f00b0053865bdda4els13338573ywb.0.-pod-prod-gmail; Thu, 02
 Mar 2023 04:06:28 -0800 (PST)
X-Received: by 2002:a81:7208:0:b0:52e:e408:f1f5 with SMTP id n8-20020a817208000000b0052ee408f1f5mr9836836ywc.19.1677758788843;
        Thu, 02 Mar 2023 04:06:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677758788; cv=none;
        d=google.com; s=arc-20160816;
        b=SFOsAP7T6D1yvgG05FeF4ZSDkRyENliHAB+p8NKLTEaj4Pym1PBJHIaEzvFwq1iod6
         rlfnGiOgdIOUlp/iJ/V5fvgS7J5btDvHf0rJDy1edjTaxlJ/zx1worCvG/TCZ2M6K50w
         HLAGXgL/WEGqGY97GtBAkK8gzuuRsDuNpT6fluGm2Bj3JPGHAp+8q2UEhGh8/xBKKHWi
         LJowSCJhvxZgTktkvEYkcgpP9SRb+1Zi2QaD2iyN5Lnl2Jve/+iaj6e7EiVmo8dXa+oo
         mL4cCVomJfXut7ymv+Blj1oHNsnEZiUm7kFUaTUPZmhzPOO6GLwwOtWoIrGpt8IXdWLg
         fMaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=W+vGFryJyHO/kcxpjviopstdV6X7mkFZpRf95EKbss4=;
        b=FkL9dd2YDyMEv0H6feAt0VKYHkmwsBJ0CViJVHPEhmvrjHzpm7O2wajVe8wnf5GNMA
         qLdjqJ9+jJLZGqgccUlYnXTevhTtitq/a1cNyofmI3wrus8yzwuHtxkZCJY9aTx2a+R2
         AwvI1mFHNfo6n3p/tSc3jCyDg3OtlYhgLwarvgcyIORdqYaLpk4uVASt6ERU3+EW1r4n
         tOAt6aS3kgqZmL826eNwaz71tPoiLG29+Kwes52hAWpKSbHiUGpQcrehP8+/Ccl/KPRj
         qy2RorPMrarQ2FYk3zlDeue+gO6dNTv/MtFZsiwqnYov1xwTnZfofKs+stLBVQpQBynp
         dtxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rjeazakbai8bhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3RJEAZAkbAI8BHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f197.google.com (mail-il1-f197.google.com. [209.85.166.197])
        by gmr-mx.google.com with ESMTPS id da20-20020a05690c0d9400b005343a841489si1532651ywb.3.2023.03.02.04.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 04:06:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rjeazakbai8bhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) client-ip=209.85.166.197;
Received: by mail-il1-f197.google.com with SMTP id b4-20020a92c844000000b00317983ace21so2590647ilq.6
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 04:06:28 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a02:9465:0:b0:3e0:6875:f5e2 with SMTP id
 a92-20020a029465000000b003e06875f5e2mr4612504jai.6.1677758788383; Thu, 02 Mar
 2023 04:06:28 -0800 (PST)
Date: Thu, 02 Mar 2023 04:06:28 -0800
In-Reply-To: <000000000000e794f505f5e0029c@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <00000000000099b9c905f5e9a820@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in write_cache_pages (2)
From: syzbot <syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, davem@davemloft.net, dvyukov@google.com, 
	edumazet@google.com, elver@google.com, glider@google.com, hdanton@sina.com, 
	kasan-dev@googlegroups.com, kuba@kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, netdev@vger.kernel.org, pabeni@redhat.com, 
	syzkaller-bugs@googlegroups.com, willy@infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3rjeazakbai8bhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.197 as permitted sender) smtp.mailfrom=3RJEAZAkbAI8BHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

syzbot has bisected this issue to:

commit 17bb55487988c5dac32d55a4f085e52f875f98cc
Author: Matthew Wilcox (Oracle) <willy@infradead.org>
Date:   Tue May 17 22:12:25 2022 +0000

    ntfs: Remove check for PageError

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=13fd6e54c80000
start commit:   489fa31ea873 Merge branch 'work.misc' of git://git.kernel...
git tree:       upstream
final oops:     https://syzkaller.appspot.com/x/report.txt?x=10036e54c80000
console output: https://syzkaller.appspot.com/x/log.txt?x=17fd6e54c80000
kernel config:  https://syzkaller.appspot.com/x/.config?x=cbfa7a73c540248d
dashboard link: https://syzkaller.appspot.com/bug?extid=0adf31ecbba886ab504f
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16dc6960c80000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16f39d50c80000

Reported-by: syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com
Fixes: 17bb55487988 ("ntfs: Remove check for PageError")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000099b9c905f5e9a820%40google.com.
