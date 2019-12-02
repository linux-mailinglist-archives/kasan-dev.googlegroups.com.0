Return-Path: <kasan-dev+bncBCQPF57GUQHBBZU3SLXQKGQE5Z4AXBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1299C10E4FB
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Dec 2019 05:07:04 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 6sf18967859pja.23
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Dec 2019 20:07:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575259622; cv=pass;
        d=google.com; s=arc-20160816;
        b=ElEtHkl47Bj6x/TMK4A5hpjsDI3KM6QNFbuJnBdAVTI8OuO+O9b7+MQhkCpWsIRi8e
         WQeKwWh9trnJMbJoojAwEHctkZm1rA32y0VINAoRkY/rXVwUnzlbwmdtG2P6NzTt13KQ
         EgBpYRMoSg/1j9ife8ma/PBBv0SZ74eCN3AzxElRwOPJt0vpG6ahXqHwdtExvdMnR+kt
         S/gvXgpbhQciOAOt0ZF6bvH+qmSb6pMJx7ljkcsgkQAgYrZQDJLEqJVzbX1mmfBZ7iP/
         uhvcXQpsCOpj3LbsP/kxs5H0uIL+jV00QmPpdvIKIUALDKi9AQS1znasI5eX89206FYV
         a09w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=J5tlYr8vthMsYAwc5rwf6Zh1nmgemAjVXhTteGuHdnc=;
        b=ZU7Jx69v1WKF0SxBchLW2cXQYXR+VkmORLMNKEXVniZZzWazhDYThQJA2Jliq7qmR+
         LvK/YrmYDAXzPyx+PNsyK8B+OS5VdTvtX+e67mCqeIZGjO9OUDWNkOEUErL47HzKvbjx
         U1oIsuKT29a/YQEeYwuN1CL8OFtRSJzka63Hh+MR5fRJUqA1Pgby7FvmWO5qEp6hOecZ
         aymax2PcTRFLQsdWK65FEnuhS0p6W2/l3h0GY6Kf1rR2joNtzvlc4Cxy+6QHHlQu5nxw
         hHGwlDP7tT82j5AYLIabyBvoxm/61Og50iIVtY356orR54JqjX2o6tB/YCKCFkIovY2g
         hrBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 35y3kxqkbaig4abwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=35Y3kXQkbAIg4ABwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J5tlYr8vthMsYAwc5rwf6Zh1nmgemAjVXhTteGuHdnc=;
        b=JKTwG35kH+u5sglza0svPCVQFQ/g42AqLx89hobHSssFkylkAeRlGDyStFdhhORC2D
         4WcfmSVDyRPk7gtfx1tzfl02K68FvM6hqlARDBcigWHhFqgkLX7LrLxCl+Oz09nlwn6c
         0K/qatzO4JKD9Zfc9g7/385CNSUphn/7t6/sBHHVwXR0c+WcuP1Yhwi+KxXOaS3eZx0g
         Dp6NdqT1XO7gjn/2owhK9py0CmhcX2c44/Z6g8zm3BC7UecCG51d/2wj/EiVRKGqvqj+
         olIUCKouClVQ5YviPbgjIWc3aAK22uPw3Afoor8zb82qqqmgn9885sBLNHGjE0QHyjAm
         vvKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J5tlYr8vthMsYAwc5rwf6Zh1nmgemAjVXhTteGuHdnc=;
        b=b7X+4RigiIEY9pfoKMUCdhoSIzNu2Qjr6EmITzhl/vi8DQ3kRRciNJLauFP/ynn+3m
         wwKdKCGh+9KwhNCRCDR90X76g9kEhpPy/RnPzbQvqXr7p6zBAilKYRr0v4FlpO2Xnw5s
         i8B0I3MSxumBfqiaEEchq/6yLSp2rRy+oZx7SL0e39UEDdpLykA4Oj6qNsOfBEMp7ZMf
         NuGPMIYc68KCmgYebxfVTDsJC9yfcNcXNibJczPK/EYVOZS7D8lxYv7+FqzvuSDroLbn
         3mp0qUZH6UsL1gRItNQlPvijObV3O90UZCOXrs8oIxrDbaaupGwczOrThal8Drt73SXA
         VHkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWKpMK7OyweVoxRipX9Mu/q44Elv97XMKnxj+yONh/2VmTh1n6t
	y5043joP9+lyRWxyUeTMILs=
X-Google-Smtp-Source: APXvYqyUONaQ1VzuTjj8zlk+DWeMDHTCJOCOH7Uqsz+/z4fAreI3X040aI78RBZMSegVzGveegAP3g==
X-Received: by 2002:a17:902:6bc3:: with SMTP id m3mr18824380plt.185.1575259622415;
        Sun, 01 Dec 2019 20:07:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4948:: with SMTP id q8ls8733333pgs.12.gmail; Sun, 01 Dec
 2019 20:07:02 -0800 (PST)
X-Received: by 2002:aa7:8f16:: with SMTP id x22mr29193809pfr.120.1575259621945;
        Sun, 01 Dec 2019 20:07:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575259621; cv=none;
        d=google.com; s=arc-20160816;
        b=j/V+qVpOxdD5bJ8GBjH3Vz6HdxvCgjWB86yA5mWB9QF5bBH24tFVMekNnpRjB5Maeu
         mAQQ51wHxp7u2KbumlFet0PI48I9QoSDf0whUKoB8yy8ZtSsDYOsUWP7WDqrABLNYny2
         gh+fy1PzmxrWSIgDFVWZxCMejLCjjvdTv0kRhUMqJow7fQ6tZZM094ZQFz88SUTKO0e0
         CIKc5iLv/2E0FpyMf56Oc9QVCi7/K8bEfugBZ9nFsXKWRTAkEO5aZTPp8HhvxTP3RCJK
         o185WeVsPVAbuKCr1o5Q2A8UoTpv3yuRSIFdsE/bUt0RrG4839wzX2YdJImCpDSvqMrO
         5ztA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=oWsENjm7d/+QABjuPHBYSJPPMCuN6XI9dZYPsoGDEJo=;
        b=qAMGDdnoSQwEn/IGCWpwTUAO1VKW2dNx3ZlsgFmWwLAUlxfkOhqOIye4afJZJ1zZX8
         4vM1ulLq2lqtXLsMBt8qQkI7DwQRVYU01QEKFdXupXMEbTH03mdzQa2sJQOuslzL7xK5
         0TTSyZOukpdjhsFiSZG3ZWy2ORNyOq81kxT6FeNS+l/6tBZys5Mrm7r5r7PRLVmrC6yy
         +QcgrAQqQGpTRUWh/RWBnBJEPAMi3pkZbBjcMhSHcpGAIUGfv6p/ahPgRg3N0shSBVdX
         JKZRnyzIez0IHFzdph8IwR0HdxsjKUpT7ymjL3g6oZ4our0Vv6wzuYFlNZjmKe19a9qQ
         9EjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 35y3kxqkbaig4abwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=35Y3kXQkbAIg4ABwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id x13si660370pgt.3.2019.12.01.20.07.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Dec 2019 20:07:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 35y3kxqkbaig4abwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id d4so26189631ile.14
        for <kasan-dev@googlegroups.com>; Sun, 01 Dec 2019 20:07:01 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a5d:8184:: with SMTP id u4mr50614802ion.155.1575259621372;
 Sun, 01 Dec 2019 20:07:01 -0800 (PST)
Date: Sun, 01 Dec 2019 20:07:01 -0800
In-Reply-To: <000000000000c280ba05988b6242@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000293e9f0598b0b69d@google.com>
Subject: Re: BUG: sleeping function called from invalid context in __alloc_pages_nodemask
From: syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>
To: a@unstable.cc, akpm@linux-foundation.org, alex.aring@gmail.com, 
	allison@lohutok.net, andrew@lunn.ch, andy@greyhouse.net, ap420073@gmail.com, 
	aryabinin@virtuozzo.com, ast@domdv.de, b.a.t.m.a.n@lists.open-mesh.org, 
	bridge@lists.linux-foundation.org, christophe.leroy@c-s.fr, cleech@redhat.com, 
	daniel@iogearbox.net, davem@davemloft.net, dja@axtens.net, 
	dsa@cumulusnetworks.com, dvyukov@google.com, edumazet@google.com, 
	f.fainelli@gmail.com, fw@strlen.de, glider@google.com, gor@linux.ibm.com, 
	gregkh@linuxfoundation.org, gustavo@embeddedor.com, gvaradar@cisco.com, 
	haiyangz@microsoft.com, hdanton@sina.com, idosch@mellanox.com, info@metux.net, 
	j.vosburgh@gmail.com, j@w1.fi, jakub.kicinski@netronome.com, jhs@mojatatu.com, 
	jiri@resnulli.us, johan.hedberg@gmail.com, johannes.berg@intel.com, 
	jwi@linux.ibm.com, kasan-dev@googlegroups.com, kstewart@linuxfoundation.org, 
	kvalo@codeaurora.org, kys@microsoft.com, lariel@mellanox.com, 
	linmiaohe@huawei.com, linux-bluetooth@vger.kernel.org, 
	linux-hams@vger.kernel.org, linux-hyperv@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-ppp@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 35y3kxqkbaig4abwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=35Y3kXQkbAIg4ABwmxxq3m11up.s00sxq64q3o0z5qz5.o0y@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot has bisected this bug to:

commit ab92d68fc22f9afab480153bd82a20f6e2533769
Author: Taehee Yoo <ap420073@gmail.com>
Date:   Mon Oct 21 18:47:51 2019 +0000

     net: core: add generic lockdep keys

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=15769712e00000
start commit:   419593da Add linux-next specific files for 20191129
git tree:       linux-next
final crash:    https://syzkaller.appspot.com/x/report.txt?x=17769712e00000
console output: https://syzkaller.appspot.com/x/log.txt?x=13769712e00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16148e9ce00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12a1f786e00000

Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com
Fixes: ab92d68fc22f ("net: core: add generic lockdep keys")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000293e9f0598b0b69d%40google.com.
