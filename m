Return-Path: <kasan-dev+bncBCQPF57GUQHBBROLWWGQMGQEAOHVQEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B278468E8C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 02:22:14 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id bm9-20020a05620a198900b004629c6f44c4sf9360308qkb.21
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 17:22:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638753733; cv=pass;
        d=google.com; s=arc-20160816;
        b=F3XqNAo3HbA6eDXvxZS2Xi3MC7T/82ZL8vx0QIrMLKJPe8yV9aOjvdTsacf3oITX+p
         s8yqVPKEOp4IlPcUo05TyHDAqcYrUjwPW5WDcBWNS166aFgyF0RZNQoqkdK5bmcPf4tW
         vbdb+YvyVvmiOXMfNcxdwfj8XuW3Fqu1ryr5C+GkCQve5TmmyHfZcEqwaspoJMW9ES8u
         ZeDharl2ZoXRYB5/SSJpik822C3xvP9q2pIW3J2V9MTd69MnO4w0wF+BhtRJqwxY3g9Q
         IBqus57eJLr5JNcLJkvQiKYZqzegJePxZFPB1U1KUqCcl3VrFAVl5tuUouExU6aS0EE6
         EjGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=32pHRkSUiD8aCOLLml4G+vudD5c54g9us4UQ25oXrRA=;
        b=tG5lv0P9hZcNyqURpgB/+L4pUUJgOQaUvPPNYRpCKrumD3RZ0YJKLaP2yivvl9JZwz
         ukLud1MP5fD0SJjo1NiVz4kSQ2qCC1xCugcBZpenZR3HsV17jKQ3ROmH1YdRrcb6v2Lf
         2VKHy4VXj63pWEaRMSZHuKwFkOKrlDMO/dP2baNpx7+s+xefW/DWs2AhEIzcMcZKH5Tf
         xZl722e8c1zeMRSulXMMtaa0X98c+C3e4Ax33aXzSH72mYhe3yAHdGj3uPHStqzdwZEa
         bdWvIUEXZ9d+Cm4eR+YteNwMOppKBeOS08faz+JttVTXh90swv4qq1w8RERHOEeB3+M8
         +SVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3xgwtyqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xGWtYQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=32pHRkSUiD8aCOLLml4G+vudD5c54g9us4UQ25oXrRA=;
        b=Eka5ebS/cBXMEEv6v4Gxha1uOmC2VrgjM3fY2lokPnOz9Q6h+axPrjkkNOjkLjt88D
         rAB7rjKqg+zSbPZrTyjjAMGQ6VkI4YwxIfYlGQuhuAw5osDJQ6WJHGMLTBFDLOkLg3oM
         F2ovJ8T8iOL+oszLdteMctxWzCGdVOtTJD/PZX9rom1h3ExPGY0H8TGy/SdYIbcCvRqh
         e7PbnFAWiO2JUMrJHcP2k/TQAAp/XL1/5bvdFLSJHTX1AdsoIM+QVVRkqBS8ZQAovuJk
         RNhI6nxHutfkm7/mUehVAn830tLxkS7ecgNnYPGCnsRO0J15CdVz36q5iRlgz8gGXlIx
         TbSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=32pHRkSUiD8aCOLLml4G+vudD5c54g9us4UQ25oXrRA=;
        b=ag25z8dGhB4Np7cCwg7ZPZUkvwpXH3Z1N3p3AJ7OSXYencB8tft70aT4dsKC7vIgqW
         Z9FQsQM/YZw2px/qPpAPaNpoW0B1SOGRPlHLAUjfZXSrZPuvkZ8yAB1XfSGz2aK4SofH
         wSlG6+OUbv7b2xrr91WKuwve5exK33Uqptcm7zx9++y8gZjiC4Hx2adpQMjlNVX6nZNn
         VnHcCWv/8oZPx5grPrUIgPHB1J/XKdG2/l72em0Z93mTx1IuYm81uVtzAotZMktRtEQk
         6ZkRwseHylzXG7RVhSAG0UFbugwGQa2OMiPxNxQ1f6+ylbCycrPFEPOEQ6jRLr7cmCMV
         GmbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uX8K6eqZpVLYuiqZr/y8gxEw7JSvt/mv0BuS8tG0U/b79nXw1
	6Z4D10FiKqL0bzbnhJY3hBo=
X-Google-Smtp-Source: ABdhPJxbN1YlWvx1/7AqT2hBrkX+Xvw5euGpYevhjw82N4Sj608xldfF3/PP1FL46vxVlgH1QltPmw==
X-Received: by 2002:a05:6214:8c8:: with SMTP id da8mr33295033qvb.23.1638753733366;
        Sun, 05 Dec 2021 17:22:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:19a2:: with SMTP id bm34ls10486388qkb.5.gmail; Sun,
 05 Dec 2021 17:22:13 -0800 (PST)
X-Received: by 2002:a05:620a:1659:: with SMTP id c25mr31238375qko.213.1638753732951;
        Sun, 05 Dec 2021 17:22:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638753732; cv=none;
        d=google.com; s=arc-20160816;
        b=c19S1pUPu/+y6MNsFZLyQkshqzoBXIt+MgseDqXE9U4gz2qVwvj/z5KhxVV91foZxR
         FgRfttKc2NUUZ+kyRC1KSgcTo6ElgasrgmAc++Ru6SXGIRlDjrAgEO9IPv6sksnqVfGw
         UXRL1e0h0Jn5flFTL/Y5OFKrGpbku/JOGwp2ojgf/2Z4+yheWAfzISXeQq12Gbg0WSRO
         DwnfYKGB+H0g9Naf3O8G5AzWu5u7uZQc42PczuQWgpyZbUqfJjCNsNTYo2vF3DcRJsm6
         EFrM+P5SC5/qV496Bcui4dPGtPeqw2Un9gFFQmQxfoO3tFDSW9tGBMgrYxaun8I007fv
         E1TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=fHKEKHdPjoZhYVJRZoCAKKckDq3mCm+7VXF61UEPMbE=;
        b=Pa61A+PeRGd8KH5vE7fpWWIsVVQetnEiK+DPDEWWSM7zu4ZJ/RryjIv3QB2SmyIqT7
         aj3Se61dvh25pwuZnwk78gVMK3tno2O2jbpTgmFSOQpXtvuTgRcpN9MtDK+N+s8VINLF
         kUcwsgnQajKcLUuBAqQyCdIsao64cOYV+fybPtYmLvCncws1TcWGMRurPEardKbf5XXX
         Yarpii0rz4qxAyD1HYkgJ3251FacudR0fBy/o1ns1XET2QkC9sxo10lUOwAV+OpaOX/A
         JEKGuhXFd+cB81VkvnaKXg98pIWYXEw4sPgoGiOeOpRDcsU+wbjwHz2bmFaXBDEB+IKo
         jkRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3xgwtyqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xGWtYQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id i6si2165077qko.3.2021.12.05.17.22.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 17:22:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xgwtyqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id j15-20020a056e02218f00b0029e3db8d6dfso5920144ila.13
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 17:22:12 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a05:6638:d08:: with SMTP id q8mr38383669jaj.38.1638753732571;
 Sun, 05 Dec 2021 17:22:12 -0800 (PST)
Date: Sun, 05 Dec 2021 17:22:12 -0800
In-Reply-To: <0000000000004c10220598f8a1d0@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000001ab61405d2701689@google.com>
Subject: Re: KCSAN: data-race in blk_mq_dispatch_rq_list / blk_mq_dispatch_rq_list
 (2)
From: syzbot <syzbot+2c308b859c8c103aae53@syzkaller.appspotmail.com>
To: axboe@kernel.dk, elver@google.com, kasan-dev@googlegroups.com, 
	linux-block@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzkaller-upstream-moderation@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3xgwtyqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xGWtYQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

Auto-closing this bug as obsolete.
Crashes did not happen for a while, no reproducer and no activity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000001ab61405d2701689%40google.com.
