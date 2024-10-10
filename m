Return-Path: <kasan-dev+bncBCQPF57GUQHBB7EZUG4AMGQEZGAFSDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D58E9994BE
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 23:54:05 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbe9885064sf14699816d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 14:54:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728597244; cv=pass;
        d=google.com; s=arc-20240605;
        b=YjcRU6BZ+cJZlAFw3viHEEpLfiwNJBgeLdtyD8UusVnhn+X6ToDUNyUw2Wmg7fSPBx
         CUrYuHiNU4V05FdDoy0PzG5Wq9bgJSMcPtJSUAuxwEaQUjhW/EQE/gjJaN50xu8ckGWg
         y/4esvmXDlVxDHWqPW+dDCaWpze3dr3lSJuVtNqeC1oQ65EVoA7fIPm3qJ937GRaw0y+
         0Eb2WKDMIFxc5nPEhT6xDqtxHAGancx+1KvPGnXrdDENi4aO1UrafB9O4EOvmbwWCcWO
         FdzSSGFUVdJff3nrtISpGmCIM3Sc8gHE+HszQBThjb24yxqoxFJOMWDx2vXWTn35CVut
         1HYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=Ciek/rqboc7oqhtyaeJhQC5GaxA5/teYXcHDqFZk/Ps=;
        fh=IUHphaVSLxzq9Rf7GA/9YgPEp1yELkywtBJSuGtGtaw=;
        b=i+BItT6Znwr3AtOVH0K1aXyR/9FF/dJurGO2/NEoexkKwZkxe8ISIbtQayujm3vXVa
         u5gfwHWKFsZlDaDGmI/JoSeJUDFOZ/yYS406hgeMMxX2qnYSMvi1D7BjiiwyCPyxeKYf
         bkqh8V/nwH6jQ8LEJwV6JMhUI0ac3p9wTfOzrNotMRU7fjF6WIJ3LqJz8F4x5aCbu50z
         HYzCg5Rkr7zBaD5O4SE0VOgoGGXImRaRSCe/5fdRq0WaaqRI0a9LGHHaHnl1TQS2Hl0s
         p6Jz6QZfxCkTmjV2kl/NF3EsZ1BRTpTra35yu7oir2TSiadm4YLKgAs/ntWuob6Lc6JI
         l0Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3-kwizwkbapmntufvggzmvkkdy.bjjbgzpnzmxjiozio.xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3-kwIZwkbAPMntufVggZmVkkdY.bjjbgZpnZmXjioZio.Xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728597244; x=1729202044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ciek/rqboc7oqhtyaeJhQC5GaxA5/teYXcHDqFZk/Ps=;
        b=W734hja1nZ/HyTfXeSvxZnScoJVwtaITLVyu3qDBkoROcx1/aZ57Too/wp0HXyOyo9
         cEm1y6U5zEUN9npF+FVFiq5uFnEEA2uhtwXwpMSuK9St1dhA5xJ/vhIbC3n9jj0MJ5Ks
         MQDIFuWS/GPX9MHikwSZjh+F8LWsYMT445VOsBtVmKDL3PpTxsgVviwxwTNjZvGbqB+S
         3zsjQLhH+zIasDPfK7aDHB58W0EGWWmaohneLoh1zPx17kFoXb9U8kFX9IN2Zefe+Vqg
         twvLnYIr5Ze+3cU5UPy4C82YvryVHF3DdS0iT55DLsyCWUlSdsE+fdfc+wqwqCXeE/VC
         7mcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728597244; x=1729202044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ciek/rqboc7oqhtyaeJhQC5GaxA5/teYXcHDqFZk/Ps=;
        b=aLUf9t9AmzbO16RRNSDI0KyPJC+onnoylr2WOY6MKYwLi8hYWQGCwwbOxMCWcLRqTU
         Hk+B4+vTrgBV2XL4r8bnLSszGJgvcf5KuHph3hW15V+JkMF/PniIReRhpZ45cbEmveDB
         ARbEsYpxH/UzXoyBXaGqV9TQ9z1cTjbZ0U846xlyPMjBtqx87cFHt84bnIkCnY8m4BOQ
         rCBoaEm0y00JhUvTrGoM6sgF/+X0afYGbmfjXACANDnHRXuQgob8EWrAjFHzV3axFdc8
         AXx35YlhrKjJI7tZt6LWjLhrc4gse2AUXchmTVq9BcGtEQlvET9AuxlEbU7CsRoCTk+M
         95Qw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHzHGM++mu9spllK2Zfy6yoVJENmFNteLFkmaB39usGdvVtGuGhTNj9Ebcw2U7k8O9EtRxhg==@lfdr.de
X-Gm-Message-State: AOJu0Yy0Vsa6dI5FgUznwFNYn5MQsgImCUlPMPHco4/uU+2zfwfR2PDD
	ORmP+NoMyBeULSUBdVgBSqL8QdEQv6sQd86uMgra8htOxR+tl4KM
X-Google-Smtp-Source: AGHT+IGK2lFZ9uWGZQb1PpNpTSVjTrGScR9/pnucqQXbvzOzOyY67yvKo8DMMbaxcumSm6mhsOBP7A==
X-Received: by 2002:a05:6214:5541:b0:6cb:c994:160b with SMTP id 6a1803df08f44-6cbf0044c8amr5700736d6.18.1728597244251;
        Thu, 10 Oct 2024 14:54:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c8d:b0:6cb:d0a5:f12 with SMTP id
 6a1803df08f44-6cbe54802bbls13547946d6.0.-pod-prod-01-us; Thu, 10 Oct 2024
 14:54:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0xCHomv2pLRUoyC1iXaLx+f9ea+lkD6FpqyXbajMT0WBRuaXN3Q+G2ng07cpRLuIHw0nykwDR5v4=@googlegroups.com
X-Received: by 2002:a05:620a:29c3:b0:79d:6dd8:f420 with SMTP id af79cd13be357-7b11a35f843mr72915885a.7.1728597243187;
        Thu, 10 Oct 2024 14:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728597243; cv=none;
        d=google.com; s=arc-20240605;
        b=Vn7gR5x86ByXlmEQ/daiftIfFPtRU1PKGVK1ikoeSCmjmdJ9zyJq3iuyMQm5v1PrmQ
         xsXuUgq39TzdyD77aUmbQ3O3TUxV/+Cvl+MN56gPQekDToWCJJfvu2DEMjto8Hsn6Xgi
         fpXkNi6wsxouC5Vdfsbdv9R2R39Ab2H2YF9zyill1znpk3VFNzLf3pzKffIxSp3yTG2B
         FpBUCz6pQ+0KR/ZrEOoqva5XyqAIceB7Frio3gIcC1gkPF2fK5K5VlsvTmCHtrbYAziM
         3lN6wKb2QZH0dkLsPayTjni4KEPtyjZb15czeeOs6M2C3UbiR5oDhwaNrRXsuljH7LfL
         33IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=3pWqZKYp/y2dXLz+05lbmPalE4rT1pDd54Wk7W+mtes=;
        fh=fTdkBuaQMSMto63W1XDcfri3VU43O7R8bliPmQIUiaE=;
        b=ReedktvCgbEqFTfhz6gHSb0l/pkzM3jNS0LIuwssdp/jLRaR3kbPcSA0fDe07QwTqn
         RD0wG4xlQ0tpy7mDelaSsmz/OGDTYE8/fMbFnIVFpOwKV20/iSA5bWMvJoy/fEluXeuQ
         nzTqsepRnyQOcoekkyOK81KhrWj35GyufgnMZOAWx4jHtAAVR+zpkzFsMwcxHevyCkUc
         mm+pcRy32R/ZfkxQ3WYX/MP1WhrggJgCLcaHz2oGEslaBymx5vSfjhxP1ZHOTvRmuQAP
         kVFz3BF1B4aQtcd6XFn7Fn9xv/7UAzmtPt5OpBepGgLwHNLiQI96md2O9Kv1dmU976Fm
         FNTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3-kwizwkbapmntufvggzmvkkdy.bjjbgzpnzmxjiozio.xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3-kwIZwkbAPMntufVggZmVkkdY.bjjbgZpnZmXjioZio.Xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4604807bc45si784201cf.5.2024.10.10.14.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 14:54:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-kwizwkbapmntufvggzmvkkdy.bjjbgzpnzmxjiozio.xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-3a1a969fabfso14935235ab.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 14:54:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXitIrVmOp2hplaVBl3FENi1ILiLVrsHbgcREXZUx0FL65shapqPuQijv/r/uFG5PkG8AFLUaNbYr4=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1d1d:b0:3a0:933d:d306 with SMTP id
 e9e14a558f8ab-3a3b5f51e48mr3790025ab.9.1728597242614; Thu, 10 Oct 2024
 14:54:02 -0700 (PDT)
Date: Thu, 10 Oct 2024 14:54:02 -0700
In-Reply-To: <000000000000939d0a0621818f1e@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <67084cfa.050a0220.3e960.0005.GAE@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_fault
From: syzbot <syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, keescook@chromium.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mcgrof@kernel.org, 
	mhiramat@kernel.org, mhocko@suse.com, mike.kravetz@oracle.com, 
	muchun.song@linux.dev, syzkaller-bugs@googlegroups.com, 
	torvalds@linux-foundation.org, vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3-kwizwkbapmntufvggzmvkkdy.bjjbgzpnzmxjiozio.xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3-kwIZwkbAPMntufVggZmVkkdY.bjjbgZpnZmXjioZio.Xjh@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit 3db978d480e2843979a2b56f2f7da726f2b295b2
Author: Vlastimil Babka <vbabka@suse.cz>
Date:   Mon Jun 8 04:40:24 2020 +0000

    kernel/sysctl: support setting sysctl parameters from kernel command line

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=1499efd0580000
start commit:   87d6aab2389e Merge tag 'for_linus' of git://git.kernel.org..
git tree:       upstream
final oops:     https://syzkaller.appspot.com/x/report.txt?x=1699efd0580000
console output: https://syzkaller.appspot.com/x/log.txt?x=1299efd0580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
dashboard link: https://syzkaller.appspot.com/bug?extid=7bb5e48f6ead66c72906
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17dd6327980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16d24f9f980000

Reported-by: syzbot+7bb5e48f6ead66c72906@syzkaller.appspotmail.com
Fixes: 3db978d480e2 ("kernel/sysctl: support setting sysctl parameters from kernel command line")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67084cfa.050a0220.3e960.0005.GAE%40google.com.
