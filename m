Return-Path: <kasan-dev+bncBCQPF57GUQHBB4ECUW4AMGQETHRA5SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id C400C99A754
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 17:17:05 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-45f08028281sf67059241cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 08:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728659824; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vj4Da7DLK/gpU6i4YXndOgQWg1CHx4bfW3rng1euCDJUdGnFCPub5R+kaoUvT7zsQy
         RBJCN2peNhC35KMopSvorRPRLyASrgvX6Io+HFlnImUFWHUorSYz3mfr1hKBdeWbUJDx
         j9Q+2VAvrIL2eO/HCqExPK2SGfjHd/u3f8+27I0/6/E6BtkUYY6ryXr/GeViSW8X0U1R
         1fkp8mK2XWN3ETUt/eGIlratowUCb2Y0ExEHAfCAXy4xSWJkWvrGfceSVV93C4UjtCpd
         IT+PXiaDJlI3ia508ASC873ZjGCrBQswI9S37f3ZlJNwVj7v46IcXHVG7nY2azG/+Pr2
         71Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=sbjvitXmRSBBDuJn/aesYnTgsMhyap5v4nm6BEq/2qw=;
        fh=akq1Gxms56aNnFYOBpyD6NmWBag9sw2fF/sm2Vu9uQA=;
        b=Uj+Z86gRyBWw/p7qk7i6/Hbuqxfqs10E8VqXZq4TMQ7jHttOItZFdCkP9ywccGc8LY
         4cRw6vm1pV0XGD/se5EMFvQS7648cvkxuzT4iaSvNM6lh98/012p4bJMLfzlBgcdzaxP
         PwSHq3cRAyNx42x/1tpjlPviPtIBJcNCITb1tixK4p2sIar7y+wCjLcmR1wbshRwIlkS
         V6ZUS82sme3dBZzcsPjBg6nLOC69JWE/6D4i/8qeDOCSWYIJdpfR9hAPPEspVk3xuY0k
         C18P4jZ+CGbSQrWYhCdGsMJb/rl3P7XL9rvBT0yXWzASnVvaKsrOisK1l4t0KNeLH1rW
         NCNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3bkejzwkbafuflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3bkEJZwkbAFUFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728659824; x=1729264624; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sbjvitXmRSBBDuJn/aesYnTgsMhyap5v4nm6BEq/2qw=;
        b=tVA36iM/rrOjd75fNsKWC+v2cY+83+kkYxZkGGBip3JKAOe6uYFDNXAVn1a9nP/XdA
         RJoF5yKv0ATXSaPkUD+G0vbftD8YQz0XyCQZHYp2w0DtP0XdBDRntkBidVw2Kfe1NHZ9
         72S5rNg2uup0gNAIwo3lMFWVF2BwZGOgegvBjJ7MD1Gn/QNxacnNA+gO76JH9HT4z4iF
         HW42ToUJyhtA9xExBi31zAqh61holXH8mx7DLRMri/tljcd9RyzxnlKSZzj2GcbxF07p
         Y1ckHHj02mdY1StssWDVxoI9UNioGm5y4kpUqJqAatleZw4SMbf6stoNhYB5xUAgfXJM
         sJIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728659824; x=1729264624;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sbjvitXmRSBBDuJn/aesYnTgsMhyap5v4nm6BEq/2qw=;
        b=ZmjNjsw+yjbXmHATL2cxRz0x8K3t2vOo4o6s1h3Ny1+NqEcAlx4xjvnWwvwC7yaQ9r
         J6x/tvCA7yrnT0jnTd1g9mUGpKdeFQiP6jG+uXNlIxPn9o4C4T+G3DQn6N5iUzzTKAjv
         hKBr4NWR0fuVCW6A2fpia0yWY4VxgVE6ImooQqAGZl5BPm+ui60tMfGRm42tn+gvdP7f
         b+3GDVhqHd4CowvQPwirgZLYuVzes47P1PSlECJI8i33qLMzayb2IHL8jAS2SM95xTO6
         Cd+F/Cx04ZKOy7V1JJPQEpbxhmQVtKACD5INGVmdvzrwmDagnOxoqQlIPGjtgUUTgeGJ
         PZlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtIHm6b3aD60JF1uokZIWfE8letd/GpA2tWpaA+Y0sWFc2WTsKuMmbt6FkYtbHRK8VtQK7Vg==@lfdr.de
X-Gm-Message-State: AOJu0Yx4rtYv3BTFgtE+Peo8aIue2wyxOZMSM/vaL41xLCLJf9U0H3Cf
	ju45wgkWQUsLEwd+8Pk2fFAxYYCSL/Zi/ybeGctZ/aOu7AWVs5mK
X-Google-Smtp-Source: AGHT+IHnyPc8OKuKwnTfeO+6n37q/FXc9UoRCgxk4nfF5xA59+b9fdIgVyhxVd73mc8dwgPHu7UZCA==
X-Received: by 2002:ac8:5710:0:b0:45c:9c44:ae8e with SMTP id d75a77b69052e-4603f6077aamr125125901cf.22.1728659824298;
        Fri, 11 Oct 2024 08:17:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:584d:0:b0:458:3f09:c712 with SMTP id d75a77b69052e-4603fb3492dls31866661cf.0.-pod-prod-00-us;
 Fri, 11 Oct 2024 08:17:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvbsSPixl1n+cEhYbGu9gnQQL2kpSsbtzQWwPkIsVecpBcMuJQIk3teWDpDMzYCf0xGkROUUlmLSY=@googlegroups.com
X-Received: by 2002:a05:620a:40c6:b0:7af:d00b:9c79 with SMTP id af79cd13be357-7b11252f117mr1402142185a.31.1728659822977;
        Fri, 11 Oct 2024 08:17:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728659822; cv=none;
        d=google.com; s=arc-20240605;
        b=Ue2Cul9rlMSvAK8j/Xbpc2VJzATm02mFrSsb/3+Zx6gmFQsyekVjkyhnSN4WQ8AHYg
         k/jKSm0gdAuP+I7VuyH4GhAScRFVdEGED4QkchhqeAUnNPkKcSsnhu55vzAQEtwQUMx3
         afYRhhVuNHCzZgetwoL8+nXHae7ICh+Wc6z0DwYqlt5qID7S82v71Ne68axYmnHZaGgW
         G4afJ5zj0US0v6zGqixG4B3wB4P4HM94dHnfweMX6Nqfxqg3SfgPyTiTsUdJZVk/wP9W
         AxZSWR36ZJT/DzxibfBn4mdKJ9rlOIhVB8CHIqiwEQESG7DML9yVBoALr/MLvXMhLwAZ
         VNOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=xkhsWbmpSIwr7KtaYgxACGZs+m9NItbxmU6IQ53lGPU=;
        fh=E3TrjTT2pICNHF8qtwrIvO+/CeSAINFAilH9SC5KzKg=;
        b=DkTXUuYDT+oPz9outEQCopTS7ABVdFwVG5sydL6S2XtcsqpMBTZgHnZKfKBWQYwYlS
         DefMuGIV9feVZxIdsLGNjtQCIqB61C3pSq4+67UH4zNdw8ZhLjqhs8iK96OT7J/7rjJJ
         9YUZ/sSyIRNKiZRPIQwIbqG0TJbcjNl6/EQ1itqovp3wbqNIYXyVQum2U0MfL7CxEQaJ
         OwIpQGf8d+4m+IEu69LzUACccoSxwZi3bdUZukVCIJNgQ85Scq6NJQw6mdQNOB6RBmbE
         xxv+19rlP8341thBsjOb3R711pbCOPTWvUQpchqoI6CjBqKCjhgIZCzQOTQ+b5Fxwvlo
         QdZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3bkejzwkbafuflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3bkEJZwkbAFUFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-84fd35c191asi145287241.2.2024.10.11.08.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 08:17:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bkejzwkbafuflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-3a19665ed40so13193785ab.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 08:17:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXS+zPCpOH9FJP+ngRXvuYYtkLMVR1qXsrQJsneLM5FWh/vgBqXTulEOYOnC5d/ByxSxBdWL1jLAwk=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1a45:b0:39f:507a:6170 with SMTP id
 e9e14a558f8ab-3a3b58aa871mr18180465ab.8.1728659822390; Fri, 11 Oct 2024
 08:17:02 -0700 (PDT)
Date: Fri, 11 Oct 2024 08:17:02 -0700
In-Reply-To: <0000000000005d16fe061fcaf338@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <6709416e.050a0220.4cbc0.000b.GAE@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_wp
From: syzbot <syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	keescook@chromium.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mcgrof@kernel.org, mhiramat@kernel.org, mhocko@suse.com, 
	mike.kravetz@oracle.com, muchun.song@linux.dev, 
	syzkaller-bugs@googlegroups.com, torvalds@linux-foundation.org, 
	vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3bkejzwkbafuflm7x881excc50.3bb381hf1ezbag1ag.zb9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3bkEJZwkbAFUFLM7x881ExCC50.3BB381HF1EzBAG1AG.zB9@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=14c7f380580000
start commit:   b983b271662b misc: sgi-gru: Don't disable preemption in GR..
git tree:       upstream
final oops:     https://syzkaller.appspot.com/x/report.txt?x=16c7f380580000
console output: https://syzkaller.appspot.com/x/log.txt?x=12c7f380580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
dashboard link: https://syzkaller.appspot.com/bug?extid=c391aebb8e8e8cd95c55
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=118c6fd0580000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16b6a040580000

Reported-by: syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com
Fixes: 3db978d480e2 ("kernel/sysctl: support setting sysctl parameters from kernel command line")

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6709416e.050a0220.4cbc0.000b.GAE%40google.com.
