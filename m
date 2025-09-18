Return-Path: <kasan-dev+bncBCQPF57GUQHBB2GAWHDAMGQEXDS6AWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63913B86B8F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 21:41:30 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-ea5d025ef7bsf1972828276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 12:41:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758224489; cv=pass;
        d=google.com; s=arc-20240605;
        b=d0LBJeaVGDST8sLFtrAMTKzRS2rHiAFtvID+NEQKdWJ5j+3djw19cCbarJiortv16A
         m79ylyLTMiFEA07CI8qxtnLCMyDyJoZMGcFftvm1iHT+E+mYumenVQ8DGhIs63meAcGx
         oX20O34J/s2RDhhKORwCCsjot5hS7bvieVQvPnUu2/VC9+zeCKPPZ0XQvQcvqko9X2Hh
         pi0rqsm4j0xw7wYcXYsjT8dYmtJXKtQz2N8NLEZb7VqP3usc85XbED5DuJprd1nL2AxM
         pEygM58bn7L5wQuzR1KKKJXmHzdmIfW/y6YuZhSi97vgfaPdvN2i0ESSzOrUL3uo0fzy
         SOxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=KHqC5R9MqiBOaEtc3HYlEsC6L3+fBxCB1AqrjKuVjo8=;
        fh=zD4qUwKjBMrgJsCObjOUup4ow+K+zJHghDDfU537gwI=;
        b=DKe1E1/8PZW8jkMbNoPWDt+njBuUDnFIxV3AsS6C42nZjEx4uj0uwWxW9yWyPCakvB
         5Pxh8Yp64T0v4NPHbEx+9ZtBMqjj8ZkU+235SM0NR/zl80Jwd4LJkwfoYN2ro4Rox7wV
         xH9Pg0dVX1dCrwIle0IhhB0JggY/dWUCeeR5yadAkZMolUJse2fOSb9TdHPXtW1uQ7dG
         IFaP5r9hubrCKSb7mdjpjxUa4OOamXtPWsujti8go4BX6OJc/5B7U8ElM173pY7AJ998
         Ktp+1jMuW9N+Gz9A2Vx/79o1CClS/O3M9Fk/9wYey0uZFjjJxd9fSVnya3ISpereXe0w
         /0iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3z2dmaakbakyyefqgrrkxgvvoj.muumrkaykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3Z2DMaAkbAKYYefQGRRKXGVVOJ.MUUMRKaYKXIUTZKTZ.IUS@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758224489; x=1758829289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KHqC5R9MqiBOaEtc3HYlEsC6L3+fBxCB1AqrjKuVjo8=;
        b=iXvIYjze1rBOwcpmOQGVH7A+wefhLNmeEBnzziPuL2RHjWIq/5D8cvezrfF4IV0JKr
         6k5Ozq/c6OL057k5ZOgPSwZIBKac5IUtvTZpllJFIE+SUXwDRv/tODiK2468cu2daBu1
         JgJubl2q5Jtcrv6dFTyOGLIz/mLQtzNCzUDBtupSUZs36DYMhzghOWXBFAth86fztAeT
         qldOXGEvT2udJepD88BoDHL0DSYUg/NC9U9Z8FRbbPVc8Bg0AUYNSMV+YeeARXGTDdKu
         Fp38DbrOdnFURfhez1lMu7mxqBflv5m5XSfclE1VEi8Xxg0U9svybbD8kTYrIzttit4L
         90fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758224489; x=1758829289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KHqC5R9MqiBOaEtc3HYlEsC6L3+fBxCB1AqrjKuVjo8=;
        b=FC0tlNEFjsT8W2KjDYqgZvQVvSOLfmh7hSwAO6cOYkgdQ0iBsJf3oRDLzagqLeuEpd
         E9AT7lIsfRmJOSaToDDyyV1+mcgv9AmAn48HXM6ecXlx6HqQOwMN2IodOVsJr6T95ZPc
         gtfUR8VtUVX0eqK4HHhqCyvIv/7A7ALCQMr3IQeLxlFOW52yfdtgk72QsxC6eu0Tk7a6
         W0A+75ZLvrDMZSWgIMezI4XSJote/V1+rk6GS/e/EE0oBOPoxCzQrl6nJUtciknJFSjP
         Ia1UZZrzBX5qc5loIJ6Dz4jCUQtlO8pwa1yarQG/k/Njmuea5r9J/1PzlLNU0J6B15m3
         JIlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVT0TrqQ9KJNYQiwIwnW0czs4Uz/M2cKIdQgQSgxcGDX2LKUzY1B/tCBMiKuVrYrRLGon5Vzw==@lfdr.de
X-Gm-Message-State: AOJu0YzMuBCfcgxY3uy+I0MhGxFTSLw6cN7/ytFsMFe+bDuV/chl636s
	PSw+x6h9O632AsC3tSrW6O26BHerLODoWWjaDzz+iNGUHOOOPR3ocj29
X-Google-Smtp-Source: AGHT+IEsnPzWKMYnhNGjHBUqVzg7JwdGJM5q0xACuIhHXvDswKzzdOlFZ+5lYcpt0BgTpwXN0QMLmg==
X-Received: by 2002:a05:6902:2d08:b0:ea3:feb7:cb51 with SMTP id 3f1490d57ef6-ea5cea3ed9bmr4053692276.17.1758224488835;
        Thu, 18 Sep 2025 12:41:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6stGXhNNBEbA+8dbXPQYncTXUBWw2WW9/xzau05tYRJg==
Received: by 2002:a05:6902:e0f:b0:ea4:178c:8f7a with SMTP id
 3f1490d57ef6-ea5bc468de7ls1090235276.2.-pod-prod-00-us-canary; Thu, 18 Sep
 2025 12:41:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUebUmOY9H8oZjBtLmxIdh1MDvQczVzNNY4HTxWev+Ffx68Ry4CGOoAKEYiIYWOv6OHCNsCRHcCKU=@googlegroups.com
X-Received: by 2002:a05:690c:c8e:b0:738:a712:6972 with SMTP id 00721157ae682-73cc73b54d1mr8535777b3.12.1758224487675;
        Thu, 18 Sep 2025 12:41:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758224487; cv=none;
        d=google.com; s=arc-20240605;
        b=V6tUo4/QbGCfSEo8F/RV0WpIzp08KQoxAWTqcKjmhF8zjBm8ycTrhjusMmomolSssm
         5vrMZkwabQ9KBpAt4Hm0KYpuitoOQ0wN0wJ7DTYuZzdoEgVOIgB0UlEo1X/Fpohn8Si+
         b4Wq3DvCVdjmtcKzeIgUWQDMhnV1bQFR9o1TVZ4qOBikbqI2+WpqtvKNdP/ohPVhhxmv
         euZKCYpHIWSU6tN3PsZgar5k6c1oLZbLn0/3bUubqrTIJkZEBjLC9n9mIrEsp6M28O9M
         443y5VrPxoxOUQKS2/Qf2DOOWtfrgriHDS9tIrRIRIiMCHtWKYHqTgjvGhu92XriBmVy
         bGwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=jFuQa+Y4FpaQQeM/M6InReVDIhcGmsMw+atLDwBDLk8=;
        fh=m70R6rKKEj/aDleqhiRsH5F8NhjAZy3+7+JjfhpCYvY=;
        b=QFoWD7pOVoDVBOIyE/gYkSSbk68RElkdjmsBxM/NA4O3U7UJroqWkilt2zDdEeytYA
         vNf//xVkq2yffbPzbFAESMcZk2H7febLSHWWCSW9DIBrHQS3biPVQT0tQMxEVN68nHyL
         rszPSx3A76uFeY4/gT9KBruIMlNrgq3bdDr8O5gY42GgFThPU87G4mYDYZesiQ9ecuUJ
         +s9xglFjPCpf5mtFWkF5anVP0EENkr4yXx57kxzUZEB7khDThGY61VQSb0FuMhn15LxL
         FQkXUEkEbKO8m45ayAPPoi5PLcmveCiGs771aqHaNNNiAH1th9fhnPWOFqEEbnUqpRNU
         GiSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3z2dmaakbakyyefqgrrkxgvvoj.muumrkaykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3Z2DMaAkbAKYYefQGRRKXGVVOJ.MUUMRKaYKXIUTZKTZ.IUS@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7397186e158si1580647b3.2.2025.09.18.12.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 12:41:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3z2dmaakbakyyefqgrrkxgvvoj.muumrkaykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id e9e14a558f8ab-42408f6ecaaso18035275ab.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 12:41:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqpW5QldgZjAUXlluO6Zd7xkdW7PAD41svLe+aXJYWmecTGhQzon7l57e6+XHK8vOc2wlTk96fw3k=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:184d:b0:40c:cf06:ea2a with SMTP id
 e9e14a558f8ab-424816f2c45mr17310755ab.2.1758224487064; Thu, 18 Sep 2025
 12:41:27 -0700 (PDT)
Date: Thu, 18 Sep 2025 12:41:27 -0700
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <68cc6067.a00a0220.37dadf.0003.GAE@google.com>
Subject: [syzbot ci] Re: Compiler-Based Capability- and Locking-Analysis
From: syzbot ci <syzbot+ciac51bb7578ba7c59@syzkaller.appspotmail.com>
To: arnd@arndb.de, boqun.feng@gmail.com, bvanassche@acm.org, corbet@lwn.net, 
	davem@davemloft.net, dvyukov@google.com, edumazet@google.com, 
	elver@google.com, frederic@kernel.org, glider@google.com, 
	gregkh@linuxfoundation.org, hch@lst.de, herbert@gondor.apana.org.au, 
	irogers@google.com, jannh@google.com, joelagnelf@nvidia.com, 
	josh@joshtriplett.org, justinstitt@google.com, kasan-dev@googlegroups.com, 
	kees@kernel.org, linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, linux-security-module@vger.kernel.org, 
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev, longman@redhat.com, 
	luc.vanoostenryck@gmail.com, lukas.bulwahn@gmail.com, mark.rutland@arm.com, 
	mathieu.desnoyers@efficios.com, mingo@kernel.org, mingo@redhat.com, 
	morbo@google.com, nathan@kernel.org, neeraj.upadhyay@kernel.org, 
	nick.desaulniers@gmail.com, ojeda@kernel.org, paulmck@kernel.org, 
	penguin-kernel@i-love.sakura.ne.jp, peterz@infradead.org, rcu@vger.kernel.org, 
	rostedt@goodmis.org, takedakn@nttdata.co.jp, tglx@linutronix.de, 
	tgraf@suug.ch, urezki@gmail.com, will@kernel.org
Cc: syzbot@lists.linux.dev, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3z2dmaakbakyyefqgrrkxgvvoj.muumrkaykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3Z2DMaAkbAKYYefQGRRKXGVVOJ.MUUMRKaYKXIUTZKTZ.IUS@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot ci has tested the following series

[v3] Compiler-Based Capability- and Locking-Analysis
https://lore.kernel.org/all/20250918140451.1289454-1-elver@google.com
* [PATCH v3 01/35] compiler_types: Move lock checking attributes to compiler-capability-analysis.h
* [PATCH v3 02/35] compiler-capability-analysis: Add infrastructure for Clang's capability analysis
* [PATCH v3 03/35] compiler-capability-analysis: Add test stub
* [PATCH v3 04/35] Documentation: Add documentation for Compiler-Based Capability Analysis
* [PATCH v3 05/35] checkpatch: Warn about capability_unsafe() without comment
* [PATCH v3 06/35] cleanup: Basic compatibility with capability analysis
* [PATCH v3 07/35] lockdep: Annotate lockdep assertions for capability analysis
* [PATCH v3 08/35] locking/rwlock, spinlock: Support Clang's capability analysis
* [PATCH v3 09/35] compiler-capability-analysis: Change __cond_acquires to take return value
* [PATCH v3 10/35] locking/mutex: Support Clang's capability analysis
* [PATCH v3 11/35] locking/seqlock: Support Clang's capability analysis
* [PATCH v3 12/35] bit_spinlock: Include missing <asm/processor.h>
* [PATCH v3 13/35] bit_spinlock: Support Clang's capability analysis
* [PATCH v3 14/35] rcu: Support Clang's capability analysis
* [PATCH v3 15/35] srcu: Support Clang's capability analysis
* [PATCH v3 16/35] kref: Add capability-analysis annotations
* [PATCH v3 17/35] locking/rwsem: Support Clang's capability analysis
* [PATCH v3 18/35] locking/local_lock: Include missing headers
* [PATCH v3 19/35] locking/local_lock: Support Clang's capability analysis
* [PATCH v3 20/35] locking/ww_mutex: Support Clang's capability analysis
* [PATCH v3 21/35] debugfs: Make debugfs_cancellation a capability struct
* [PATCH v3 22/35] compiler-capability-analysis: Remove Sparse support
* [PATCH v3 23/35] compiler-capability-analysis: Remove __cond_lock() function-like helper
* [PATCH v3 24/35] compiler-capability-analysis: Introduce header suppressions
* [PATCH v3 25/35] compiler: Let data_race() imply disabled capability analysis
* [PATCH v3 26/35] MAINTAINERS: Add entry for Capability Analysis
* [PATCH v3 27/35] kfence: Enable capability analysis
* [PATCH v3 28/35] kcov: Enable capability analysis
* [PATCH v3 29/35] kcsan: Enable capability analysis
* [PATCH v3 30/35] stackdepot: Enable capability analysis
* [PATCH v3 31/35] rhashtable: Enable capability analysis
* [PATCH v3 32/35] printk: Move locking annotation to printk.c
* [PATCH v3 33/35] security/tomoyo: Enable capability analysis
* [PATCH v3 34/35] crypto: Enable capability analysis
* [PATCH v3 35/35] sched: Enable capability analysis for core.c and fair.c

and found the following issue:
general protection fault in validate_page_before_insert

Full report is available here:
https://ci.syzbot.org/series/81182522-74c0-4494-bcf8-976133df7dc7

***

general protection fault in validate_page_before_insert

tree:      torvalds
URL:       https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux
base:      f83ec76bf285bea5727f478a68b894f5543ca76e
arch:      amd64
compiler:  Debian clang version 20.1.8 (++20250708063551+0c9f909b7976-1~exp1~20250708183702.136), Debian LLD 20.1.8
config:    https://ci.syzbot.org/builds/8f7ff868-4cf7-40da-b62b-45ebfec4e994/config

cgroup: Unknown subsys name 'net'
cgroup: Unknown subsys name 'cpuset'
cgroup: Unknown subsys name 'rlimit'
Oops: general protection fault, probably for non-canonical address 0xdffffc0000000001: 0000 [#1] SMP KASAN PTI
KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f]
CPU: 0 UID: 0 PID: 5775 Comm: syz-executor Not tainted syzkaller #0 PREEMPT(full) 
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
RIP: 0010:validate_page_before_insert+0x2a/0x300
Code: 55 41 57 41 56 41 55 41 54 53 48 89 f3 49 89 fe 49 bd 00 00 00 00 00 fc ff df e8 f1 3f b3 ff 4c 8d 7b 08 4c 89 f8 48 c1 e8 03 <42> 80 3c 28 00 74 08 4c 89 ff e8 17 b3 16 00 4d 8b 3f 4c 89 fe 48
RSP: 0018:ffffc90002a5f608 EFLAGS: 00010202
RAX: 0000000000000001 RBX: 0000000000000000 RCX: ffff888022891cc0
RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff888028c71200
RBP: ffffc90002a5f720 R08: 0000000000000000 R09: 1ffff11021cf81e0
R10: dffffc0000000000 R11: ffffed1021cf81e1 R12: dffffc0000000000
R13: dffffc0000000000 R14: ffff888028c71200 R15: 0000000000000008
FS:  00005555815ad500(0000) GS:ffff8880b8615000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f1788fd20b8 CR3: 000000010d8a4000 CR4: 00000000000006f0
Call Trace:
 <TASK>
 insert_page+0x90/0x2c0
 kcov_mmap+0xc3/0x130
 mmap_region+0x18ae/0x20c0
 do_mmap+0xc45/0x10d0
 vm_mmap_pgoff+0x2a6/0x4d0
 ksys_mmap_pgoff+0x51f/0x760
 do_syscall_64+0xfa/0x3b0
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1788d8ebe3
Code: f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 41 89 ca 41 f7 c1 ff 0f 00 00 75 14 b8 09 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 25 c3 0f 1f 40 00 48 c7 c0 a8 ff ff ff 64 c7
RSP: 002b:00007ffc8a37e638 EFLAGS: 00000246 ORIG_RAX: 0000000000000009
RAX: ffffffffffffffda RBX: 00007ffc8a37e670 RCX: 00007f1788d8ebe3
RDX: 0000000000000003 RSI: 0000000000400000 RDI: 00007f17867ff000
RBP: 00007ffc8a37e940 R08: 00000000000000d8 R09: 0000000000000000
R10: 0000000000000011 R11: 0000000000000246 R12: 0000000000000003
R13: 0000000000000000 R14: 00007f1788fa11c0 R15: 00007f1788e2e478
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:validate_page_before_insert+0x2a/0x300
Code: 55 41 57 41 56 41 55 41 54 53 48 89 f3 49 89 fe 49 bd 00 00 00 00 00 fc ff df e8 f1 3f b3 ff 4c 8d 7b 08 4c 89 f8 48 c1 e8 03 <42> 80 3c 28 00 74 08 4c 89 ff e8 17 b3 16 00 4d 8b 3f 4c 89 fe 48
RSP: 0018:ffffc90002a5f608 EFLAGS: 00010202
RAX: 0000000000000001 RBX: 0000000000000000 RCX: ffff888022891cc0
RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff888028c71200
RBP: ffffc90002a5f720 R08: 0000000000000000 R09: 1ffff11021cf81e0
R10: dffffc0000000000 R11: ffffed1021cf81e1 R12: dffffc0000000000
R13: dffffc0000000000 R14: ffff888028c71200 R15: 0000000000000008
FS:  00005555815ad500(0000) GS:ffff8880b8615000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f1788fd20b8 CR3: 000000010d8a4000 CR4: 00000000000006f0


***

If these findings have caused you to resend the series or submit a
separate fix, please add the following tag to your commit message:
  Tested-by: syzbot@syzkaller.appspotmail.com

---
This report is generated by a bot. It may contain errors.
syzbot ci engineers can be reached at syzkaller@googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68cc6067.a00a0220.37dadf.0003.GAE%40google.com.
