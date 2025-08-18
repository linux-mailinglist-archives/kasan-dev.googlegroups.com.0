Return-Path: <kasan-dev+bncBCQPF57GUQHBBOF4RTCQMGQEKVIYKEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 38F69B2A1AE
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 14:36:10 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e9338ced260sf3656104276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 05:36:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755520569; cv=pass;
        d=google.com; s=arc-20240605;
        b=S9S8uIZ5GEabqJOlxYLSVLbPDKkZL+23O/0mrXYYOK9fDTJEymvEVPuGFZUKHva6Qw
         KxheqcNo+nKOe/CwKgzhXHwJNroa9U0vRHLj0K4YoV88YUbd6IPSyBQwHVuyI3nAk1bw
         TT6AxN7DwJ5kPIsKb+QrJbeQqXqwEdUrL0ogQOgWqr8PkyPdwfLhqRwGQcCb1m1tBBR3
         rdfhvOzYerilylNeFDcHDxmyVg2GKuiNOQPx7EAGRX7yEnUOKVEbP0+zAcx8o88X12br
         Rrr2Gvxo2mMGy+28rKECuTyXuSuQjB2Yh66SBMMknnVElSA/Ad3XHYwCGqzNhxRRUIRd
         /40A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=JYMRctVDI6jhdpVTY6E1Btw78XmkXxBsgEC9yu1sDMQ=;
        fh=Jj5nt/Z7HrFRdmBc1ruQfbccl87Mlozz8yU17d4ALO4=;
        b=FaOkp7BBgT+Lu/sPz9+ZCgy+Hq5mspl3qoxXVO4I26iD+hhs6PgkFDuQX6wxtng+jt
         7vYZkmr+nItaktSCz07SUhsihRTB1th6WujiBf5Ceovi3uovXpETdPHwkTty7mYE78ve
         qPl2k6WDioPYM7EwR+47/r6IEHro56ID2wIY1I9p50t2iYKy03Wr1v+cX9tr7wtR6cNM
         i7Wsv3msctZseWKWm+csIuiFivk18vO97s5fcMd1rawSqt/Lymr26X0swMZLcfcyvo0+
         wfFyGk+a2w19/YWO+bSsohQBS0oSAuyDvTwxoIozkADV0wajjNLuaToKdu7GXDGXnpqd
         g1nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mx6jaakbaeg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3Mx6jaAkbAEg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755520569; x=1756125369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JYMRctVDI6jhdpVTY6E1Btw78XmkXxBsgEC9yu1sDMQ=;
        b=U8sgpfhi6WyWLNpmCUvxuzpbxMv+ylwOv2KNZuZ3Go13yA4cTV446EkmBJ4rZ1Jlxp
         7Q1nuV2QdJ2BrHBpekO9KXCDyCqq3SNDfw+WYjWif7D8FZX+iuqM8kzQ22kNwe65NTx5
         zeR9dQJN2GEamkFkmovH33tD4IQbEo3zkxn7R+W+riqA2y215lxieRHieK1vTfi8Abrq
         7QrgKnJYAfuaJ+9onS47rsg8ySr+CiW/1dYas6CcUIubdPXUKJhJFh1iphY46kPqzI4z
         8esOd2F2dtj9iHX9bH6/8dH0rBBnCGj97sq8iyiNJr3ZAYlI4rjxLvmE0WzlsTCRffzz
         Lx8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755520569; x=1756125369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JYMRctVDI6jhdpVTY6E1Btw78XmkXxBsgEC9yu1sDMQ=;
        b=qjvjS9i9yvLA7XVoWUpoNS5NYxCc1R02FvV8BS+/Kn3S5aUajv49tKRdgSSnZK8rbX
         B7DJQZRWBJj4R48dilrGQxetb+BOL/6GfPXRgjmBKMy6j0tL7DwxGq2FUjSZldPD6t4b
         iGiaf75k2DcKgGudY1eepod4yxaB4iogGGUxB6zglCsjScXGdzsWg/UbvHXjFMs1WvNl
         MKKTlgxtgZ2vwvRqCqoUrMixTFCl4jpQuRpnWMcqcNMc/JTmZldU2Fj6OGXIdy7u8LSn
         MCe0G7U0rQC6mqlqtediU00qTKo8Ja7CUrXnZ9CXitS/9Qo8wlLRZIUZIQ+WLuL308kQ
         EYWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1IMVP8+wRtVSvOVCcpXDCfGQ02f0zueCTpOV/HFZuvtdPj1Jf+8pAh6T31AhQ7bRmi7TiRw==@lfdr.de
X-Gm-Message-State: AOJu0YxOHH37EpHPBcKBcJ0XJhDWIeqFRsMd2hwQknuym01v9wShjn7f
	fEgzZAT4nOevbHFyy+I+DlL/veCSQiN5opeZO7RxMFHg4HkhzPqJQYuo
X-Google-Smtp-Source: AGHT+IFsE5di7OpWTDZ56ASQBGkPAdqA6+tL/QrgoZB5QGpln3AJTJO5Nwg3ha64kUa3i+4EdKJ+gA==
X-Received: by 2002:a05:6902:c04:b0:e90:6f68:23ee with SMTP id 3f1490d57ef6-e93323fe092mr15081909276.12.1755520568855;
        Mon, 18 Aug 2025 05:36:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc68bnGjRc5duR6n5M2DbXckouqcNjmJrIt8ZsWd33IGw==
Received: by 2002:a05:6902:2a49:b0:e93:f92:bba9 with SMTP id
 3f1490d57ef6-e931ca869efls4285913276.0.-pod-prod-09-us; Mon, 18 Aug 2025
 05:36:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEiAseMiojyCvkDOHc/LUr/yOrQIjan19UQEZq2DH5ZUumF37b9Ey+c7zTGm+KtLesQwDFHpJFCH4=@googlegroups.com
X-Received: by 2002:a05:6902:2a90:b0:e8e:4e3:7fda with SMTP id 3f1490d57ef6-e93325726bcmr13197741276.49.1755520567884;
        Mon, 18 Aug 2025 05:36:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755520567; cv=none;
        d=google.com; s=arc-20240605;
        b=D1FumUSsIbTgEHE721mQnAko6U6fFGuQXEQ05fvnCE2Ivh4HbChipKvNPu9+fsojeR
         bmtxctLun1TWhcI3mjCZmazIqPjranrRA/Y9KedlKtr8t43jxmUrCZJIfLrjy7WeMSVn
         +qyUqqaet2kShvCOUE91zZKb7N/ELZ92BGCBkTDmytAjYS4D7Jz3hnHcMrHSW3pblM0a
         jDmOhOh27IBb8NPeshF5cuZia5R8/tcnHLqKih0h9YS3NsN9gyyID5xSTMVD4/QuH/W+
         iJAYxKRKQgqV/dQBRTAlhsyq/z6YuWRIBb8gzHWXx855bdEyk+pJ7dm3MXY3hTTtkh+w
         8VYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=zIg2ZRIh/jXrnDPxRoTtBuI34awvrkZLEoipYY5Cc1U=;
        fh=Fp0PNbyRouCvnV1lt8Gn/adbt4Kax2vOdX7eVbOl4/c=;
        b=fx4Pf58Wg/sINut1JFNzN0lj5ZVsTNNswOQ5fkHggEM0OUG+TaKlQFp2IQDGvwbOwZ
         oue51VK8UHSmT0DXTVXv9+2hj0Of18hlHs1CgqhfE7u7GRaLCW/+2uMqqR57gkHWewP6
         JGWH3MTTznB9lGPDJI/46B6XxeK9vqxKSneKYJw4bteeuCNIaf7eXJLEsrqLJ1MgMMLX
         owNy9StXzalLRCxD0Z+um/rwZypPjnAO7mQNdPA2gtVf7Ewpm56HyDaN0SZMNcvkasVC
         G2YFMcj8JoeRSZdmjjrlY8KHxdjwRp05u7VOhl7pM54uJcHlhKzYB7HvX1H2cBvK1xBC
         NvNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3mx6jaakbaeg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3Mx6jaAkbAEg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f198.google.com (mail-il1-f198.google.com. [209.85.166.198])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e933259502fsi342881276.1.2025.08.18.05.36.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Aug 2025 05:36:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mx6jaakbaeg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) client-ip=209.85.166.198;
Received: by mail-il1-f198.google.com with SMTP id e9e14a558f8ab-3e56ff20434so54784245ab.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Aug 2025 05:36:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYMxuw58qRpSsmKt9QNTpl050HVgwg1yxx/7RIsXOQ8WbvYV+p990uiX7/FdgpzS7NR3e6Kdv2hPo=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:18c5:b0:3e5:5081:eb8f with SMTP id
 e9e14a558f8ab-3e57e9a83cfmr202742425ab.11.1755520563926; Mon, 18 Aug 2025
 05:36:03 -0700 (PDT)
Date: Mon, 18 Aug 2025 05:36:03 -0700
In-Reply-To: <20250818114404.GA18626@redhat.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <68a31e33.050a0220.e29e5.00a6.GAE@google.com>
Subject: Re: [syzbot] [fs?] [mm?] INFO: task hung in v9fs_file_fsync
From: syzbot <syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, brauner@kernel.org, dvyukov@google.com, 
	elver@google.com, glider@google.com, jack@suse.cz, kasan-dev@googlegroups.com, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, oleg@redhat.com, syzkaller-bugs@googlegroups.com, 
	viro@zeniv.linux.org.uk, willy@infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3mx6jaakbaeg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.198 as permitted sender) smtp.mailfrom=3Mx6jaAkbAEg289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

Hello,

syzbot has tested the proposed patch and the reproducer did not trigger any issue:

Reported-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com
Tested-by: syzbot+d1b5dace43896bc386c3@syzkaller.appspotmail.com

Tested on:

commit:         038d61fd Linux 6.16
git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
console output: https://syzkaller.appspot.com/x/log.txt?x=1317eba2580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=515ec0b49771bcd1
dashboard link: https://syzkaller.appspot.com/bug?extid=d1b5dace43896bc386c3
compiler:       Debian clang version 20.1.7 (++20250616065708+6146a88f6049-1~exp1~20250616065826.132), Debian LLD 20.1.7
patch:          https://syzkaller.appspot.com/x/patch.diff?x=15806442580000

Note: testing is done by a robot and is best-effort only.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68a31e33.050a0220.e29e5.00a6.GAE%40google.com.
