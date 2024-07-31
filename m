Return-Path: <kasan-dev+bncBCQPF57GUQHBBD6NVC2QMGQEVDGMJSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 999EF942D95
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 13:57:05 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-260e4ac74a1sf7053731fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 04:57:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722427024; cv=pass;
        d=google.com; s=arc-20160816;
        b=VdG37H4ivbWL/C/b/P1lS8GQhHutDLc732usrwBof6gFVf9QhCV10UAGeH4Qn7Vrn6
         tyuvGF8zfjRbDYy30F0kZ4nIMseDl2JeDk4mP+B75jbm0V5GgQavxBezkSRkjRrMDDwn
         zupRthFs25wzh5EXAAXy/p5u1dGjd8+LH68nza+v1ZWmPc+D2MMbhcS02WpPn/F6/+5Q
         302jbTLDpMfeSn12Z6Sv/kwT8kvDtAE8mFxg8LxGiC18UUpeXFcq3VNx317YPxaIiwHj
         XIQSTJl8/580mr0QghLJ+amHJDOSlXT+L6MK9kRcr3yNJkw7wbxquMsfpjb0PHBXwEk8
         vN6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=0zqsY2lBdlADvYuE3T6kGyQp4EENhmUi2T6F2QcOu9M=;
        fh=BOKZN+MGymW5DwzEb8xnsxD0HSCOAGB3VlfUFl/Gmws=;
        b=VnTtxiwnkRsCfr0cXpEdrPC8JG+l1iQanx7ubYByQ/qf9JrJ4rgsbL8+Q6VWTp3+sQ
         LHQ7ultBlNPQzOyVpjFzQrOY34HIbKgicfcHiYUf2SiSvfWmtbgKBRLGetBd2gB8fnoS
         5YGVyFp9MrpPjjvSsPOxfWIZ/Bi/vberWkaARbIuOkkONS//7oTbaesPjdrgroSVdoi0
         Yf07lHU/uo1l5wwcnT2vF81ac3+bR9kvhAKEDAqvYR3Q2UMO98tJU9W3hn7BXfdlU9E7
         SUH67h4jbVBUVy+RPwTkY29bGAGR9422bdpDtch/3w5pKhC+AgelJdV0R0eZEowI58Ic
         Bd4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3jiaqzgkbal8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) smtp.mailfrom=3jiaqZgkbAL8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722427024; x=1723031824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0zqsY2lBdlADvYuE3T6kGyQp4EENhmUi2T6F2QcOu9M=;
        b=IJ7r+bzeYbC9tXkOT7kBtrJEK2SWI4+nanzZBLzjLhUJ+LV5DndyhnKbKA2myR9amy
         Vj5XphP3kv0ytFn2P/6lNkghL59XdlwfsQpKNxpYD48ndzriDf0wKnLhQhsnjOZ4G5VB
         MHvR8yZoy2k5/2Zbj3X+Jf99NHSCqXdatAOJrMrL+6WZT+RtsA3HP7VLPVc973IiWoFM
         kxmQuIQvWbBWaGQK8rDkokT3YLoAsXjjx5tlXt19P96Sa+eHyJoGFCMI4PI8NW9SSRNf
         mdQMYQvDHLA7Jw5rNAjbqkBlrram+JbNl06FNXaqcrC4uPYFz2K6J2m6SjYCgJQ5mhh5
         KYWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722427024; x=1723031824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0zqsY2lBdlADvYuE3T6kGyQp4EENhmUi2T6F2QcOu9M=;
        b=R9GVuTK7eT+QNz7RC7Dn8q+6a/0RxAIpKQiKplRuiCERdDsL8Zk6O+bZyg/M6ElDMp
         RjVcInDwvs+DR3xU1C1rnXTpZKVivQRgm8dx/r8DtmHkgwG2pkpRQw/BgmZBNdE6ON81
         AdAguJqgNIESQd+r2Z3o32qmLDJZcQ4bkeFXQR+TywXrH9+MukJCK/wiHeorWRv+yasr
         X17dbMLm4ZF0Bsgbtiosz6Zlb3VW6Fge1DDcBhyVi9/xgpXDQK0ZXka8wd2UsHWLGV5X
         IVX+K2rQkyVkIp+v9VND/j4WLoQBwgUtrcOk401SZmRtcl1XLkfekc+5WCx/8Q5DeusW
         I8yQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUu1TaqwpNTRlJR/Tg8GlfTBgfdjBf7VCn2adH4/V9uNMhVf8W+1aoxPweUT6346WyamcroRsWrf8gvNps81IUBOK1LkZE4Lw==
X-Gm-Message-State: AOJu0Ywyq14j34Lqynr9yYCX9tyNjxG34x03ItREpnwsL3AuDQFRH8dj
	cOgal+b0FbTK0D3GVSKLwRUUtARzsJHruoSs8++B7gu3ElZifZXF
X-Google-Smtp-Source: AGHT+IFwiQH5YrmdnMERHnXFovaaPwT5/OWmJEWd3ckB7vw/B1L3/XJEUzx4BtVt+26dDC0+b8x/AQ==
X-Received: by 2002:a05:6871:3a11:b0:25e:eab:6d32 with SMTP id 586e51a60fabf-267d4cae6ffmr17817222fac.5.1722427023972;
        Wed, 31 Jul 2024 04:57:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a00d:b0:25d:f93b:9be0 with SMTP id
 586e51a60fabf-2649fcadb21ls574658fac.1.-pod-prod-05-us; Wed, 31 Jul 2024
 04:57:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCLRl0/OMfMkoHU29SFGBIsb9MkPMidivjfbGpu3dg51xGpWXs2TQezFZTQiu4qzPmoER/sYbGYEnzOndAKq3ScRtfkCKynZdoqQ==
X-Received: by 2002:a05:6808:2010:b0:3d9:244b:b9d3 with SMTP id 5614622812f47-3db23a0ec73mr18199410b6e.23.1722427023118;
        Wed, 31 Jul 2024 04:57:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722427023; cv=none;
        d=google.com; s=arc-20160816;
        b=QK+PAPqKhTF5FU12eOMp7xn+EPDxkWCfz4l5r5nzP8KtUXa4DeObTKOHPQcTfEk2+u
         yQoVLkE9gbGiX2Xcv78nn8asVf6iawvKPWoUj8UR6HKe+PLp9JJxiWtJN5O7/OQSXq6d
         zbZRvQ/2bXZAUr9SLYqmfZwdhd/dQJBxIl9V4yjSmR2DSpuxohOI5oZM3W4GNI51pdQo
         YTCAwFy+rExRog4MWLekaKVi+0Jk0VAZHgbMfDoieOum1IB4hUSEUWI7/9sCw/2vcJQG
         eY0fwsxIAeifqQC62FfSvvBuONm6gqH3wVdRFI9F7DCuIYXN7Yy/FrFtY8iQC5YCCFbP
         hrXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=xSrgeN+yuzirQre8G4sG5Sw6kVPo4mH3hIOR53sJbwQ=;
        fh=ePUntMOUWgsv4ifL0hmkvqKLlAy/tcFXS7AbjNIzZac=;
        b=g2PjoVW6vfo0tM74YM3rkgaPG0zQb+aFJ3L0ON8Li/dslAnYhZvqkaYfQ2VqdzmRtS
         cfCXdIn/yIAibvZePQAjNLoJsp+hcWC9nPcRHGMx+IhPozCYnBBXf75Y9VZoZG7bb017
         uR5pC0f2pmMoKGAgifSMzBp3YRG0q08F44sslkt3Vv+Gj1Qiwuvjz+LSwhVnRDtDKuik
         yQC4Nvgxn4scqN/iItr1517yW6O4lJ4WmCphKZqR23+5l31ClUzWCFAJt7kSfV7Es0Wn
         KUAuVfai4ZrspdlFNtrIhh4mHh/iCEdf+jWxmKRJP/V+j2X1ONA6+L5/BGsXwJhKBBmq
         b++w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3jiaqzgkbal8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) smtp.mailfrom=3jiaqZgkbAL8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f69.google.com (mail-io1-f69.google.com. [209.85.166.69])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3db4175f058si185866b6e.0.2024.07.31.04.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 04:57:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jiaqzgkbal8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) client-ip=209.85.166.69;
Received: by mail-io1-f69.google.com with SMTP id ca18e2360f4ac-81f7fb0103fso112396039f.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 04:57:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW6OqxjhqJ5Dhw6lbzBuFJ0rYxysTWRMdUdmA0soMGPg1guuY9A50S6vR2NmxEajU8HaAbDu8l2uP7Wbo3l6DezgwaangnmS4O3kw==
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1aa2:b0:381:37d6:e590 with SMTP id
 e9e14a558f8ab-39b06af47damr3064295ab.2.1722427022641; Wed, 31 Jul 2024
 04:57:02 -0700 (PDT)
Date: Wed, 31 Jul 2024 04:57:02 -0700
In-Reply-To: <00000000000022a23c061604edb3@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000d61bb8061e89caa5@google.com>
Subject: Re: [syzbot] [usb?] INFO: rcu detected stall in __run_timer_base
From: syzbot <syzbot+1acbadd9f48eeeacda29@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, brauner@kernel.org, davem@davemloft.net, 
	dvyukov@google.com, elver@google.com, glider@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, jhs@mojatatu.com, 
	kasan-dev@googlegroups.com, keescook@chromium.org, kuba@kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, linux-usb@vger.kernel.org, luyun@kylinos.cn, 
	netdev@vger.kernel.org, pctammela@mojatatu.com, rafael@kernel.org, 
	stern@rowland.harvard.edu, syzkaller-bugs@googlegroups.com, 
	victor@mojatatu.com, vinicius.gomes@intel.com, viro@zeniv.linux.org.uk, 
	vladimir.oltean@nxp.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3jiaqzgkbal8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.69 as permitted sender) smtp.mailfrom=3jiaqZgkbAL8x34pfqqjwfuuni.lttlqjzxjwhtsyjsy.htr@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot suspects this issue was fixed by commit:

commit 22f00812862564b314784167a89f27b444f82a46
Author: Alan Stern <stern@rowland.harvard.edu>
Date:   Fri Jun 14 01:30:43 2024 +0000

    USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=14f906bd980000
start commit:   89be4025b0db Merge tag '6.10-rc1-smb3-client-fixes' of git..
git tree:       upstream
kernel config:  https://syzkaller.appspot.com/x/.config?x=b9016f104992d69c
dashboard link: https://syzkaller.appspot.com/bug?extid=1acbadd9f48eeeacda29
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=145ed3fc980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11c1541c980000

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000d61bb8061e89caa5%40google.com.
