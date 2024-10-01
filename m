Return-Path: <kasan-dev+bncBCQPF57GUQHBBT4J6K3QMGQEG6VRYRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DEFC98C96C
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2024 01:25:06 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-82aa499f938sf30121739f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 16:25:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727825104; cv=pass;
        d=google.com; s=arc-20240605;
        b=devHfEWEFp51uY8uo4+v31XsMljsZKaa4qr2Cf20OyJ+7noQR90jLYOAHWHNqEjk5I
         h1SY+eOihmD7TXuDwASpldFxV1VcJvkiKf0kcHfFoM0metWhjU+oS+ghZtw9NY1HX4ey
         YufSNi83HnbTUZv+EDBERpfmrYuM4ZXGtztavDODo9Tvi4FgFoBu6TgvYSBzxMaZITU2
         ta4wcZLR7mnApmT73ST/u/I7dKYn36phvNaKEteufh0OvqzgeitFODfnE36VxNJekuM+
         l30p9y5S1d5z2ixvR2izI9aGMx9OyJlvn5tN7RsiCtNjGEKdQEmgyJJy6fvLJZIlo/h7
         NW9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=JDqeMscrwx5j+f+UZOvjb1Y+BjtrpRM8o0D9cJkQbPI=;
        fh=Yos+L69L7k7UeaEPHeuxreZcVxIrLlMurQncV7gIkIU=;
        b=dDkthx9Z5ShmIrCSGZgmW2vugBU69OhhVsdZnN3JIABigsrZ2iUCekxkHFCSbDP3Mr
         cxvMM820RaeoXBdDA/qfZz3loWJp/Z2Fby5vHt/MHI56bOetqSkrR1reb0pFqSv7mAJ9
         /ECWgiHRGa/r4Eui/ay8F8QIs7QyNzw40VSgUH068Hzo5dOINMyWpKQjrX+l7gmPDcfP
         vaIP9Ol2O3x1YMJzbJgLNByAdqLjJd6Iv/rG4llNdCzdVmOrthEhWjuJ58jZWiscJ1sc
         y1cN4n9SFr/LFfqKhNNWqY7Bk4DI2Exun58EYzAXhdQFmGIyGXL1x2etbcCo4+al/xKd
         h+BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3zot8zgkbaak178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3zoT8ZgkbAAk178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727825104; x=1728429904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JDqeMscrwx5j+f+UZOvjb1Y+BjtrpRM8o0D9cJkQbPI=;
        b=SVZgFbt0HDi3Ip/KDHgzDJRukn1g+CAEO3fvh3OSvsIYKWYK3PM+csaGOiNfa9+pmS
         qHNMJ+hBYFw2QCj4BMrmWHquNYe/hWltliQ2lfb2ksYAqT9hPqaob4N33Mn6IRQEB1ot
         Se2IyzK0y6wziwl99rkfsB1ZEyEK6WmtpAsjvsIpfPLByjgjYbmZlmq9/WayHQ1VlFYp
         PgcUlNplREdNV/Z1zd1u5uGAKkhwBJVj7meIX9ubYoQ+9XGxrCVYdFCJvPi6hG7T9vtj
         3+u/ZcppCyAGKHgyf2tBlxDDOQ2uDcWjC1H4MFYreNg+XNX3RFB6Vx/Fre5mSuZLkAFe
         qR2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727825104; x=1728429904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JDqeMscrwx5j+f+UZOvjb1Y+BjtrpRM8o0D9cJkQbPI=;
        b=Zwqja9dbRYffAAyEKJXfPn8BRC8FBpw5JBgtPkJC3Q77Tf6W1M1JpexzZtvKAQl+4u
         lLhpNj2V4e09fciAI0UDmwZ1u8zO2/tQXEclYwvslfLjzSXEj1PQUXnnBnPm9RTZ21aP
         zn50UlEsEWWTTSOB23shaLlycd48Gw4pN61TEbs16yyv7q2Qw7ago3hq7iAUuc9mZdET
         1b93FHTNq5G3gpg+BelhGPRsTswO/RmWdCrnnZpIsIDPa1SRTuiQVuq0Q0XAKtDgiP6Y
         vkQ7fMleWBq/SCaggf8rF1HaeVwHuY2N2jj7r8ttmRJgpcdOgsLJZfLt+MGwvOk7hR/Q
         fwQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTQBXJCYW8aDKeDmT3pN6QYplH/KTnjF1CLT3jK/Qmecfa5SCbfCExO4wBP51aMHXe8koCLQ==@lfdr.de
X-Gm-Message-State: AOJu0YwUass3rbwgrbNhLQtD4wJOlibq5c6K+crxf0RkidoqIqeiwLVv
	VVegCadj1tCuDijPTvrCFJH4s86cp/kAij5ohXyn6gqSuLcEYQum
X-Google-Smtp-Source: AGHT+IEOtP+exkG/fkv7PD8a9h+eRJwjQnYzk9SNcsyc64KL1aCy619zmlLUH+mj/PeTlXVirt9U3w==
X-Received: by 2002:a05:6e02:1c85:b0:395:e85e:f2fa with SMTP id e9e14a558f8ab-3a3655ffb0dmr10231455ab.1.1727825103856;
        Tue, 01 Oct 2024 16:25:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a25:b0:3a1:a4cc:f95f with SMTP id
 e9e14a558f8ab-3a27680912als18715705ab.0.-pod-prod-00-us; Tue, 01 Oct 2024
 16:25:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/QUuCs5C1vmdcGkIBWWkaaU4JdW6xLY4PDtcW5ujkIqOk8hpP9E2zc97I5SBKAw8pFtogDpP6UU0=@googlegroups.com
X-Received: by 2002:a05:6e02:1a05:b0:39f:5def:a23d with SMTP id e9e14a558f8ab-3a35eb0c259mr36340485ab.5.1727825102973;
        Tue, 01 Oct 2024 16:25:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727825102; cv=none;
        d=google.com; s=arc-20240605;
        b=TkqF+Dd2syFpCVIsyF9OGQW1ghWi8J0IpDWomT5RmNxbToUMDPvujKI933My8+IE0E
         kbISAN02oEdFqIZaCD015qtO0Pu6/8MBmILDNEes3THN98A0Lex4vh/nVI4/ZK4VGezW
         vzzD/siY+my59PK0dVZoNbZ8hLeuERpyCb32bY09WFScM5oFotOjHOAFefgIO65gFmas
         ZDWU85u6vP1vpiPucRRKPtjB70BXiaLsMpsvhVNGcg5Kl0EZwDJJkm6T6uqhdxndMZy9
         l0ROhIsqZtHflxA3v6gN2nP2/zFHzPLes9CQ/nle7zIXc5ckaQ+qI1fbDIxlCmGE5wG/
         Gnfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=UsMQId/XwYhOxE9d7W62Z2F688TIyrJGVMr93l3gO0Y=;
        fh=/GIJ95Hr2ItVDE/9BzuNHo6rOSXbAOnl54S7iGxi+2A=;
        b=ZrhRAbw3AMkXtAxU2ARR98bXNzCvlKb4MvdGYYPiKFFicAFty2CR6G3+HrqwUtVvI4
         x3TG2XW+jvflrD0eLwlnORsNa2rM8JN8R5e08W8uPjt7lQhfjCfkt3nF3klbfguQ/OFd
         7WSHd53Zgg23KperRZxrNhMeQYjzrtE/sRai5lKW0uqVkwZrzReKLV45itW3UwaIB7b+
         IFxKt7Li/bp35c1KzAsJelXmrKJuytfCY8uNkjQLxgd76etfmPOXtdRsKq5MxZ4Sk2Z0
         qfSic6BfnfjQukq/JyPtLyWPs5AIAL9o/eDVjFEXeJU7JDVMuM5hv7iNQwDXYwQo/q+5
         Z3Ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3zot8zgkbaak178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3zoT8ZgkbAAk178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d88889c126si490171173.4.2024.10.01.16.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2024 16:25:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zot8zgkbaak178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-3a1a8b992d3so3463455ab.0
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2024 16:25:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC8k+ucnLKHFHwtGUgWnLT4d5tTeT8g7uySp0cdbu4ATWMpRBHRU1tl7bSakyWbHFYX3UdtLwt/p8=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:160e:b0:39f:4e36:4b93 with SMTP id
 e9e14a558f8ab-3a35eb0c614mr36026985ab.6.1727825102642; Tue, 01 Oct 2024
 16:25:02 -0700 (PDT)
Date: Tue, 01 Oct 2024 16:25:02 -0700
In-Reply-To: <66faaa4e.050a0220.aab67.0032.GAE@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <66fc84ce.050a0220.f28ec.04db.GAE@google.com>
Subject: Re: [syzbot] [mm?] KASAN: out-of-bounds Read in copy_from_kernel_nofault
From: syzbot <syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, andreyknvl@gmail.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, snovitoll@gmail.com, 
	syzkaller-bugs@googlegroups.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3zot8zgkbaak178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3zoT8ZgkbAAk178tjuun0jyyrm.pxxpun31n0lxw2nw2.lxv@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

commit 88ad9dc30bbf1b08bd1dddedf9ff39019f469b8f
Author: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date:   Fri Sep 27 15:14:38 2024 +0000

    mm, kasan: instrument copy_from/to_kernel_nofault

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=15848307980000
start commit:   cea5425829f7 Add linux-next specific files for 20240930
git tree:       linux-next
final oops:     https://syzkaller.appspot.com/x/report.txt?x=17848307980000
console output: https://syzkaller.appspot.com/x/log.txt?x=13848307980000
kernel config:  https://syzkaller.appspot.com/x/.config?x=41a28720ed564c6a
dashboard link: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=14dbf127980000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12dbf127980000

Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
Fixes: 88ad9dc30bbf ("mm, kasan: instrument copy_from/to_kernel_nofault")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66fc84ce.050a0220.f28ec.04db.GAE%40google.com.
