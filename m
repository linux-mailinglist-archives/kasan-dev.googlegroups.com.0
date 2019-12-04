Return-Path: <kasan-dev+bncBCQPF57GUQHBB3OPUDXQKGQEWM2NG2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 73479113728
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 22:41:03 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id f15sf897113iol.21
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 13:41:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575495662; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5FU8vQ39s+WHjlBzqKEeAfGIcWcJ6+PU2Y5nLwqCttzfuj+Yk4R13Hn5rc7M61YP3
         TpWiAnpnmzjFopoNdJjwoW92mpVOTpgfgnmliJrHqGI4WACKt4LsEQRM9euXrfRhEi0t
         jg5zo90HLXteNuHEO/3a0ViigMdQdQ6DUaw8IrRJKnuiStaItxrY8pIxK5/cWfa63JJP
         cNJA0Uli1u42bnQaZbp2fvrm6vTK06BvhK9cm0oMRzODWWssoruHpPuulIm1eDrzRRZy
         t5iCHVhnqFSaGPhC8VsFeu6uoutjSs6wPz/4sY+Hsfz+z99DBpsSDkQ82t1C405Np9PC
         ifTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=Qt30IsTjNzkDDUu+Uhe19AfOwiKG4JBF7pr6G7tF11g=;
        b=0Vqm0mIdev7FxbxeD7g1/d0kULTDGI48IJLtWSGdezNrKJjtWp2pZl2Q8HYU735S3P
         125XhP3z4CJ9C2RWsmgSjNhfMRYGRmTt/7cdTYixWTehRZRbyEokv9ILf6T++JDwUM10
         rljdWZrgkvQ5SJoTO7nWOmqIcswjHz0IZn0xS3G2h546nB1u69UQpMAlqxHRY6XIjXl7
         U5VXABZhrfp1ooRUBSQlStxVH4C6m482ynvUBPvNpUXv04e4JanHT8asImovxcaADnmn
         6stsxekjMokL2KSdt5KWtnd08LidCw3gLFgY3ezWdot57Lmn4qpsaQDE4Y6dF9F4uh9M
         n9zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 37sfoxqkbanigmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=37SfoXQkbANIGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qt30IsTjNzkDDUu+Uhe19AfOwiKG4JBF7pr6G7tF11g=;
        b=oDyWJi/IFt4I8vEMegYI3pGsRVrJkH1LD6PpWw0GIG+UUSWzgkb5Ta/gszcJy7KYjB
         aEploofn8tkqpTt39nXm7fh/ZNr7ocxpS8eFGrmpCb31alwCCuinookroRjmSxktcx3P
         RRlO4EXQziJEKzjkwjFEXV2tZiG7rmiPSCIWhiBY5nopHI0Oa4u3T0emDgnrlQMke2wu
         mfhPEGE1RNPNR7d+wZC713X9x5KIxxMAHonBEIZpzfH5tRSiLztvFu4nLIRkAZ13ArH9
         rZ0F8r2LE25AY+yTAn5ToOM35X1qFQKVdYmR/y6gwu8HKyH902vOlZGjYzgxuqp3C6Lg
         GaNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qt30IsTjNzkDDUu+Uhe19AfOwiKG4JBF7pr6G7tF11g=;
        b=TjOn4XoPm5dQQwOr8rEnW05Y+/dFRCD5xArp8HMpS32PyBVCcLL7hfhI5+oMNYzlPX
         ALC15K7Yk/AmuwloVnM1UjG5NyOkR5+PMNVWeSABoYPBwCMbj6iY4rbmuHUvlb24HjEj
         FNCxS9mMhgELheFI4RsTeEEjX6gljjFLvLGTmWKEEzPvrQVGhjvsz7fmKK2rVMUtffGq
         DHcEr+qY+8DSqmjNqAdg6mn/Np32kKuUDY9WxQIw059xDm0Ef8J/nfmNvRoyhAb7ZHAS
         52/os2s7Onctb1+IMjkBpOHlrE0Kk/o6LFIC+kR8cyswEgU3sgNb1TQ3S9yFfWmXUyvD
         8U5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXGwjAU53ypz+w02H2OWVrytI5H3g1GrfRZXovhurDrmMYlZgDr
	98B4cEjv8a/Lc/IJMA6c2xc=
X-Google-Smtp-Source: APXvYqwJ9UQqXJ41Z2qDJpIGCuiaDeh5t/QODZZ6qd4uEwFoCrN4o+9Ts/feqsC8ejbRLxxXdyJKdg==
X-Received: by 2002:a92:c0c7:: with SMTP id t7mr5814051ilf.113.1575495662016;
        Wed, 04 Dec 2019 13:41:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:212:: with SMTP id e18ls103598jaq.0.gmail; Wed, 04
 Dec 2019 13:41:01 -0800 (PST)
X-Received: by 2002:a05:6638:93a:: with SMTP id 26mr5136491jak.16.1575495661650;
        Wed, 04 Dec 2019 13:41:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575495661; cv=none;
        d=google.com; s=arc-20160816;
        b=lfub3oUVaGTaBeRgoT9ETCCdSK4VrXquiLfcn2kZ0zVbUDVFjqlsvSwYzaPElEtpVZ
         ffKc8VbVpokDO0nLiSvIE7tz9l0VXIFdsAZrmb7b/rpoQedXODFDUJInUJJuD6rIkh23
         WtSe3hiS+6E0xArV1A3B+2Ay5L4nAlVng20c/VENXy1801sD7JzsrianXSf9PrkU5q3R
         gTyREJz30oXn0FMccVImJuJlesYIdqwNhTxtRsCEW8Hxjuv9yjeti5nvYSchUGe3rVBA
         CROGCIfbuS3A3IE1m7yUzpRcdyvN8HfPT2XSjghoEc1axopEGhU2Xu4JwkFtoJBvYA5U
         E4fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=JrNPfPX8ooL5t/Vw7RYAMqCMbF8rwCtCqkj0exct6ns=;
        b=CRGkIFj1LAg4V/lQew9Iq6IEdWkj2QndcMiEOlUq2vWYtyuEdf7yBqE/CNOS8NPwEL
         pKWFN+F9UUF4K7Vh5Cl9LjmC4hWAQLO/2l48JHT3hp7TGaQyuNdjyyQOdsxJLKG/21ZS
         /bJoYUa8hgbqWT2E0oeFIZN+8ZAA0qkRSJgll5SttW2TAKwdzG6cQ6S3cZbiKDs1kwap
         CGUmculGbG/t3SyUS8+e/PC9llNYTZcFzFcHIfQYe72YQlUhkbVp5JaRSEUXKTN0g4zH
         bgGyPBejOiDpFegWTYD0H/a7tM/VC7bds4wZj5GgznEAyEkJwt7md41wbrbYBq7FVmsQ
         K5kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 37sfoxqkbanigmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=37SfoXQkbANIGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f197.google.com (mail-il1-f197.google.com. [209.85.166.197])
        by gmr-mx.google.com with ESMTPS id j1si145914iom.2.2019.12.04.13.41.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 13:41:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 37sfoxqkbanigmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) client-ip=209.85.166.197;
Received: by mail-il1-f197.google.com with SMTP id w6so818450ill.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 13:41:01 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a05:6638:d3:: with SMTP id w19mr5157404jao.127.1575495661402;
 Wed, 04 Dec 2019 13:41:01 -0800 (PST)
Date: Wed, 04 Dec 2019 13:41:01 -0800
In-Reply-To: <0000000000002cfc3a0598d42b70@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000003e640e0598e7abc3@google.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
From: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>
To: aryabinin@virtuozzo.com, b.zolnierkie@samsung.com, 
	daniel.thompson@linaro.org, daniel.vetter@ffwll.ch, 
	dri-devel@lists.freedesktop.org, dvyukov@google.com, ghalat@redhat.com, 
	gleb@kernel.org, gwshan@linux.vnet.ibm.com, hpa@zytor.com, jmorris@namei.org, 
	kasan-dev@googlegroups.com, kvm@vger.kernel.org, linux-fbdev@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	maarten.lankhorst@linux.intel.com, mingo@redhat.com, mpe@ellerman.id.au, 
	pbonzini@redhat.com, penguin-kernel@i-love.sakura.ne.jp, ruscur@russell.cc, 
	sam@ravnborg.org, serge@hallyn.com, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs@googlegroups.com, takedakn@nttdata.co.jp, tglx@linutronix.de, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 37sfoxqkbanigmn8y992fydd61.4cc492ig2f0cbh2bh.0ca@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.197 as permitted sender) smtp.mailfrom=37SfoXQkbANIGMN8y992FyDD61.4CC492IG2F0CBH2BH.0CA@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit 2de50e9674fc4ca3c6174b04477f69eb26b4ee31
Author: Russell Currey <ruscur@russell.cc>
Date:   Mon Feb 8 04:08:20 2016 +0000

     powerpc/powernv: Remove support for p5ioc2

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=127a042ae00000
start commit:   76bb8b05 Merge tag 'kbuild-v5.5' of git://git.kernel.org/p..
git tree:       upstream
final crash:    https://syzkaller.appspot.com/x/report.txt?x=117a042ae00000
console output: https://syzkaller.appspot.com/x/log.txt?x=167a042ae00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
dashboard link: https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000

Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
Fixes: 2de50e9674fc ("powerpc/powernv: Remove support for p5ioc2")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000003e640e0598e7abc3%40google.com.
