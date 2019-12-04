Return-Path: <kasan-dev+bncBCQPF57GUQHBB3OXT7XQKGQETUJPPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A2AD21130BF
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 18:25:02 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id y127sf83106yba.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 09:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575480301; cv=pass;
        d=google.com; s=arc-20160816;
        b=ughQix97MKv1X+QM6JG8QoW7FeMOZXEGIxkISbxzOVK2aIHMMi8c4teAifaVV267CI
         9u7FmBqj7jStQzfvdfvTYrX6deh3Lf1UNQWXSbgddGggCz5qH3w4zaPBxsx8dNGjSEWL
         HxKGvMo+5GubV8neeEq59MvKIhkPn4sVayYdiIy+GO9Gv3WssulyYEBqdcav90R/WBFV
         S5sT3hMoBumu6baB4igolrmG1lsDegXinEWqB1erkGaHUhNkOi1glOiUmNjVrVVsLjwW
         fwnm/SlH2YgiKC1JcsGXTxdYMKPSflDLXUppw/gnLo7hVd+oezwq2hbeio8rBbSDtJlU
         Ingw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=a3GfuRnXTUea3waWBAmk/RfOywE9fmc14//8a0inC9k=;
        b=0HaAuR/7OHP9q/jCq2KvV5okDNrs/n+JlVOSKruxUuErtMSMzqgR7sIUEbevgsh2OF
         sLgs59P1uGO9ktCuiA5/AGLTjpyDkcWpTXrSbnouP/LTfZ0XynjaE9l6Kjh/Mj0y/2wy
         fWh48vNc9bYnijNhHm3iVp+bSiUHbRj9gEqIyqG3c8FWollRIw4rXjAgqlVIQEqoeZ0o
         9ebJplIOXaQ0U4vRfOGLdu8G7mNsBpDlmQ+2eOeF2ZFslKR4W/V23tCNx94pxlnI1wOS
         eiG2P9Y09iEZ46/dKF17ThkzQwsLnjgYa2CzV3hpq0H9708suzpNOHdMRBkhQceTnwWW
         SHDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 37ovnxqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=37OvnXQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a3GfuRnXTUea3waWBAmk/RfOywE9fmc14//8a0inC9k=;
        b=kCXDZLCfnldyFdhNxtaSN/3KUUodVaVTzYMXd9WHSr308kZ/qpvfjgR7JEeSiNsrIv
         4XF6txxW8mFUCG9A6rq5ENwc8YbhdpenIpL2TQWNKEhz+c4DIMJnGvn7366Tk5bnbm2C
         r4nvzsXAXIm4MFtLF7u8Ar/yWDOMSOkKU3D1IwMqnsYShTNatv/AiCrLdyZsytKeWQnj
         mFN4unpyeD7kSYP3Qy1DBw1UDniiWaFc1Ce5er+Iw+RIkr6bSHPOSJayI9i9PmEWr64f
         fWtwft2Mcejug8YrCheF2MRl0dum3bQhuyUeDHSNvybFheYlbDQ6UGLYz0DRV63qKVSY
         rW9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a3GfuRnXTUea3waWBAmk/RfOywE9fmc14//8a0inC9k=;
        b=q++UcVEvQAM5sIZW6AO1pfvSnNH8wXaPw76yqsAOZAaBT3kjXUH1/moJ5fHMiTJmWZ
         1CakH0/IcrzaixzaWAQAZ2vNxXUPZZA1yADjiZjDmrlKcvpwurw4llKIfwIVfBtt7E5a
         ReeMIMiOINIbkK2lNIIYqbqncO2HwMOM014Kkg4y3NIPWJzYw0Yy+FTBwPkUGJyiTr2H
         A9oUB4FuO84rWOkvt4UAqh5oADe1zerDIquXmwIC/Y3fN0+zPQ5mw1gphwtQoJubK/KW
         xRiFCl6btvnuZjjCENx6gwhjgmn30xDBq7cPd6bfxAJW1CzzU9OIN2480iToNX+A4xC/
         Tvag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW3zjEoVhPrNXQTYcLb1rI6+FUs/8XRmhaJ/BdO9e/XMDZ2Zyji
	YbBAzNBcXL02XnVmUu6eVwE=
X-Google-Smtp-Source: APXvYqy4SpscJGa1FKekWdSwK2sxLnCDlmfHzXda/yt6hBTYLN/KQLtRyHyGarEV9gj5admunFijNQ==
X-Received: by 2002:a25:211:: with SMTP id 17mr1787629ybc.206.1575480301652;
        Wed, 04 Dec 2019 09:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:264b:: with SMTP id m72ls75599ybm.0.gmail; Wed, 04 Dec
 2019 09:25:01 -0800 (PST)
X-Received: by 2002:a25:948:: with SMTP id u8mr3196383ybm.110.1575480301220;
        Wed, 04 Dec 2019 09:25:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575480301; cv=none;
        d=google.com; s=arc-20160816;
        b=J53pO7xrtgn8fZqxG0d7/WQaqVXSYoYRYDmY50HWSEw8mICkFjOiVfY3LIoZvW/9DN
         ojTMNCo52i3SIfOe7de/23DUVNHZR1jDGa/2/h8/tV5D5Sha8hsQXyEPx1NCnyKquT2j
         AyVCvVLTwxP8ndcbOMFA7b/2r+RGBxnfW0E5E5ai4JnQkaIO8IbbiA7ujpo/6C1abDcU
         i6JKHf96wBu/sAc0Bf2pyPhMtsTFACjjcKe7QAktrbwlnjf7epADhJqHzQ7nXmD7SnSr
         /gDPwYVGSufSfEGj8eGNXQ8KW5F1uvM7hOXMbTE7CMsC/vD5F11ueAGd37WLS/H5vnQE
         YPeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=7EBHqRzY74ZGF4tFe8/2rCfanQYl+zaLWG2jjw2sqJU=;
        b=W7DGh5OQR2gRBfRDAowyxPy/asyqfzKh3ry2q/DIP69zQGKMkZImn6iAApyGW8qoMP
         LoYCnua8tCh1FeF/AQRkrn7fpzo7Cd6vX/aBSx9020rM0WiCZbH6f9h8SFAgANVUc1dR
         fgSaKCyYi9IjzGDGvDApBylyHDpmWzdSGame9ileG14nUXMwf465s7qyQg4gFbB/F0w2
         AWlN/KFgDFqrk1DwG0sbwDVYWzp729Nbtq+0gr6Lh8bYMXqZlI4VYtwCdZZBG8EJOJdI
         bZWmWf5NofEbMccaAYgNj+yE5rKaKfDG1GMpuEA2DHpjKhBCdyjIgG4ZjfXHnaeSEI/s
         5VNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 37ovnxqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=37OvnXQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id v64si328532ywa.4.2019.12.04.09.25.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 09:25:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 37ovnxqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id s85so248713ild.13
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 09:25:01 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a05:6602:187:: with SMTP id m7mr3058050ioo.16.1575480300753;
 Wed, 04 Dec 2019 09:25:00 -0800 (PST)
Date: Wed, 04 Dec 2019 09:25:00 -0800
In-Reply-To: <000000000000314c120598dc69bd@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000ad595a0598e417a6@google.com>
Subject: Re: BUG: unable to handle kernel paging request in pcpu_alloc
From: syzbot <syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, andriin@fb.com, aryabinin@virtuozzo.com, 
	ast@kernel.org, bpf@vger.kernel.org, christophe.leroy@c-s.fr, 
	daniel@iogearbox.net, dja@axtens.net, dvyukov@google.com, glider@google.com, 
	gor@linux.ibm.com, kafai@fb.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, netdev@vger.kernel.org, 
	songliubraving@fb.com, syzkaller-bugs@googlegroups.com, 
	torvalds@linux-foundation.org, yhs@fb.com
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 37ovnxqkbafkjpqb1cc5i1gg94.7ff7c5lj5i3fek5ek.3fd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=37OvnXQkbAFkJPQB1CC5I1GG94.7FF7C5LJ5I3FEK5EK.3FD@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit 0609ae011deb41c9629b7f5fd626dfa1ac9d16b0
Author: Daniel Axtens <dja@axtens.net>
Date:   Sun Dec 1 01:55:00 2019 +0000

     x86/kasan: support KASAN_VMALLOC

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=166cf97ee00000
start commit:   1ab75b2e Add linux-next specific files for 20191203
git tree:       linux-next
final crash:    https://syzkaller.appspot.com/x/report.txt?x=156cf97ee00000
console output: https://syzkaller.appspot.com/x/log.txt?x=116cf97ee00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000

Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
Fixes: 0609ae011deb ("x86/kasan: support KASAN_VMALLOC")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000ad595a0598e417a6%40google.com.
