Return-Path: <kasan-dev+bncBCQPF57GUQHBBRMR4PZAKGQERQJ62MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B42C17325E
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 09:01:10 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id s4sf1011917vkk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 00:01:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582876869; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZZA+2KQjBItn7XZ+PJAh81pcWnh5jGaUHH9e95LjIc/l6Xj/jcyQhAzLMzdXLIf7C
         3hw0YrUT7OeOvVp3NvnbZ0J7AoYY6oN+nI+77SUsNeKzXQP8VTtLyJhxoB+u1r+8Zlah
         g2NhWDkVeAdAYRLKg3zeQJ9bzr92h7mZ+xOTnvuNxkA/IP0yVeofxdA7wzD7PCRikyFq
         OJcxHOeE4vgAtep4gkFoDTS3VFgZQe9kxgxTTvqsfCVxYLdmsA2ccMn7XUyvbNZI0rPV
         Tj5JCRaanozVKo8ACJQMi5RpU+lRcLcqi6XmdR8xLkooxyw4h8PyvjegelrLq8s7BGKn
         60Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=FX2Mcvx9ZJEtmxO5REma4IVeeP7oplgLf1UFbSnL2+w=;
        b=Rc0GVpyBdlR8RTbEtkVJPDiNe6qElP6quDY4NbvRrnwp3mS4uVLkHsd0YFO7h3JPcZ
         WZe/+y/m37wZ8e3aUPHz9Noz4P40J2NPle9dQyK5wihmUOnsLoyxDSbUeD+Szwx54yoa
         pgD7/N1x4mpBk5wekzVLLoqpr7KU+axWQTGp4YKvSKzKEdeczOuvYKJyyO38xa/QJYgD
         4kPc/xZaeQ7qB/EXa1WGy0juCsO9qsxajNVAqDTwEFD9H5vPSvYCS0ubWjWTonGBqkYF
         j1AL8Nd5qvFTOFeJ00kQpfcSucPwU12Q9hHsxo0xU2EeojYCkcMAAcvwBTTxc3hrdfjs
         ScPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3xmhyxgkbalejpqbrccvirggzu.xffxcvljvitfekvek.tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xMhYXgkbALEjpqbRccViRggZU.XffXcVljViTfekVek.Tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FX2Mcvx9ZJEtmxO5REma4IVeeP7oplgLf1UFbSnL2+w=;
        b=PDmw2A33cmiP/GmUu5Hg0F4HwssGBzx9kCfS8ZujZkKdPSYdxhzKQB/Y6Wj4ARRYgs
         a5E82iDuDPY6IeXxBXvcgwMeI+gdU5z1Zd6FntwEZA8x2oxWent8MF4EMu8Q3nBH4KZ3
         DUoMLJ1uu9JkQ94QNRWSJvOnZuYY3rujYZI8H2lLQmWh+TZEu+tID0FTcD0ichDokVfj
         a+ii6S9Er7G/wqbhY7FMRaiVDLjtGdsUbQGLOPkufFKpXN8E/ae+ZNukadLZhaSXzOUZ
         2+0JOYu0r85mSnmZMfsAv7td5pPNMHdaNwWO1wNG5XjGg8ANwCkEJG0VieBQCujLrT7k
         T1BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FX2Mcvx9ZJEtmxO5REma4IVeeP7oplgLf1UFbSnL2+w=;
        b=lj5wnuehvKKRbUBODAYnoSiBMvWWhkBkH+ZbSdPrUslJ/UwvLDSpR0aWzp+I9ccKe6
         VW5fBJmpY90XCkmkLASvUFkMqtUI3TDewWmic8UowsfJgrfmleBidOcTOyJzWESNmf4T
         Wf3yMCfGw4YP0Jj3+BTGOGu9/fw0dfEsOJ46AGzCmnk70/kHgDCsL2XjfRTO9cwOSt7w
         Ict8MrVycz0ZriCle8euw4oY26p7jmsh6FyUp4wn/c0P/uZrG3mOQjYAEem704C5Xpgw
         +UddPFrW+Hiulml7951yb6ek9GnNpF6aupRvXGM39nD9dTT0QzVOkJBKnvolI33ZLTZ2
         WfsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0PFLLLtle/9xULlSbk2T8qmbppwOvr6WqgsQ0gnW42iX0CQ38v
	x4VvrQjbFWwyQMzgZ/ae2LU=
X-Google-Smtp-Source: ADFU+vshYVf1gH5DKMnd5D0zWaufpLaArAoBNJow9ZWBog4HP/IqXzqqwfQC2xEanMRoBZRvVhE0Cg==
X-Received: by 2002:a05:6102:18f:: with SMTP id r15mr1886361vsq.206.1582876869139;
        Fri, 28 Feb 2020 00:01:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7d4e:: with SMTP id y75ls173877vsc.5.gmail; Fri, 28 Feb
 2020 00:01:08 -0800 (PST)
X-Received: by 2002:a05:6102:3014:: with SMTP id s20mr1911784vsa.10.1582876868763;
        Fri, 28 Feb 2020 00:01:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582876868; cv=none;
        d=google.com; s=arc-20160816;
        b=JdQrh7hmYCm9r6kUNNl7nJBtabSMAWXef++uJqAMBL1ro/4jqe+Pm3//Flysj/Xk8v
         +dE5GER8BrLMMdrXHRuHIo1/pptxmG5QzyqlTemuca+F2e+aZCJd/QRw176BBgi+L6th
         3uec9KOakycEKgU2AXn1uu+QeZFq6b/iinu8mQiPGbJGcAOrljws0U4adFqXyyFJHTGR
         N+QnwPJsgdhV4qDCJxbOpC1PUGQGLUun419aitBtRd27XW1c0nT/DScgDR/GtMZk8Ir3
         5rh8UBPiwIHflrOuqFbBXdAZE4iTfvadpapM4t55skqNeiOKb+V4CK9e0OSoecWAlOX7
         IITw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=1F6QPB2AKxQKkbwngYuex+ythgWDXEu9f8wBzkprX/k=;
        b=uGmNiCGj6TSzc4VM6tyilIMbWR2XH0EkCPY0Kv3PiYOZ+7fylzrNnQxuHHRhvJOA/z
         CLppKun1ScitIO8K5LV+w9VEgkv5WxUees0tA5CdAY04p6SdE/ieTq9tqa6GVNAGxWKG
         9GtN0BBOt8Ng7niNjGlXV6IbfbMMbY8NgftET908vRh4u7ZYqNLuHhIklYCXUUh8q87L
         nfTxkLlviev8wanLckKLNN6WJ6oYpLGlMXHIyGI6q1Ign/FqwHaL2ursOZwKYzgPwBBN
         WwIeRFmnnDxyQx4BoRVQb3i/Ktgmjh0NF3oSR4/U9uAD7fuLcLuNCm2oaNUi4rBfuOUY
         0DiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3xmhyxgkbalejpqbrccvirggzu.xffxcvljvitfekvek.tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xMhYXgkbALEjpqbRccViRggZU.XffXcVljViTfekVek.Tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id u11si178663vkb.1.2020.02.28.00.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 00:01:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xmhyxgkbalejpqbrccvirggzu.xffxcvljvitfekvek.tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id w6so2523900ill.12
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 00:01:08 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a92:d608:: with SMTP id w8mr3044015ilm.95.1582876868273;
 Fri, 28 Feb 2020 00:01:08 -0800 (PST)
Date: Fri, 28 Feb 2020 00:01:08 -0800
In-Reply-To: <0000000000005f386305988bb15f@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <00000000000074eed3059f9e3d0a@google.com>
Subject: Re: BUG: unable to handle kernel paging request in xfs_sb_read_verify
From: syzbot <syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com>
To: allison.henderson@oracle.com, bfoster@redhat.com, darrick.wong@oracle.com, 
	dchinner@redhat.com, dja@axtens.net, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-xfs@vger.kernel.org, sandeen@redhat.com, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3xmhyxgkbalejpqbrccvirggzu.xffxcvljvitfekvek.tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3xMhYXgkbALEjpqbRccViRggZU.XffXcVljViTfekVek.Tfd@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

This bug is marked as fixed by commit:
kasan: support vmalloc backing of vm_map_ram()
But I can't find it in any tested tree for more than 90 days.
Is it a correct commit? Please update it by replying:
#syz fix: exact-commit-title
Until then the bug is still considered open and
new crashes with the same signature are ignored.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000074eed3059f9e3d0a%40google.com.
