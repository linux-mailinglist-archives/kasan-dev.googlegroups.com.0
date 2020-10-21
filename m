Return-Path: <kasan-dev+bncBCT6537ZTEKRBPGRYH6AKGQE5KOQ74Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 711E8295131
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 18:58:37 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id e142sf1451011oob.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 09:58:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603299516; cv=pass;
        d=google.com; s=arc-20160816;
        b=fK9qOqO95tauDJmM4c5Lj/kWXWCN6W3FpqWu5DBgcCzfK+V1hgSXE7VVXG9mZwNz8h
         j4CGopxBWfE3MGR5nkUkfzW3V2IJcFj8xLY9kWKCURlfitE7JVcuoOcxtKaVXhxyDgvU
         FE4AJwE6DtEa4ggcp329KPhhW6My78ltQH0QdIr60E1NSGMBxsB7IksvhX5Zd7b8vd/A
         i9yQ2AV6Ut1VznMHO5BSP0ILACCprW79Y5XJHQd/lGcVdO5aRGUQ99Q/5ZU+aeKT87A/
         0I0ivibHSYI2pqqArzQvDFp7fCLiTF7SbDBWRWKtOMiWUc7nS80D1XciunJX5pm9n3zw
         YKPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=ASXn52KdLF/79p5oQDSHRbdZTrtDx+xZ0gJqwa/drnA=;
        b=FDM65LW9bM91blLmB/PXq6b/jxTCaFfS7oKrpXpdBSL9R/1v7thLqpuvPfi2yDdkeF
         A6MtSHZvTAo3rDIvUELtBKwrMOW8oJgGguh3ameiUFdP90DhT3UF+0OSCEMgArhHxOnP
         /Wa3N7aOXBhFqH0/XpHZR+s4Yv8YErycbWBqr1dMPpOhwYmR9T5CnRpWiaYr/PjHfK2v
         sr2iHcxsJSNgMAGEfXGRerTmL5DUC+S4aQunDCo5B3luY9ltCp5nq6jTjmX+dknxs0Vd
         M8wkGQ3ZsX2DIWFX6Rt4r3UbXMjIResLyGU2vfVMwMp9BU5dTH5/aekqMihyCPadiAcL
         xe2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="EWYTm/LY";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ASXn52KdLF/79p5oQDSHRbdZTrtDx+xZ0gJqwa/drnA=;
        b=Myj/uXUxByrttRvQgxXXeaUhD3qzlUdRgR2yCQs38thD1xNtoLvitAySNvnkuSP2FB
         dXKfDb0pCbeZ17D54NFUY/0ZV+eKgqQwyyd4ajcdiwur2R7z1LXreR8QOOKCDRyPJi0Z
         n3TyiPAJ+EXvpyJpmRng/XAJtKvgRPsY5Be12cpxtgYbUsixJVoYRE+R2ZRdbd6IJj2I
         uytfuAuuLsXYuibqNvrg/jmTrhxOqMzadVEYv9KCx7aKghRuvB1R+/M6v7W0Qfcx8Dmt
         9JUpxqykrHooaCA2mnxlLyGqcSLpfrWazMLuKMIJpN2cGk/lCxWxCqkXMSd2S1JvYgP7
         HyFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ASXn52KdLF/79p5oQDSHRbdZTrtDx+xZ0gJqwa/drnA=;
        b=LsGSpobhGAsMNmduwwa4Mr/V604Njmtjpi0yPDOBd6ChoiCdTDETmDk/cNZ/4gCagy
         sPqCXXAC/ooMCGb9LdwoupvTYLoxivpVU/iat5lWRLUgDibmYbmRTMWjRL5vx9ay8We/
         GE7D0QLx/kdtwuyj+WiSl4D07+X5Y6drpHWkyZBnY50ZAcwA1zcSAkFZch50a6FAwbeL
         dEjLtAkqNh5W8YGdFtyTltVJKTgZZ7pLJvEaxOkxCNeRed8hAFQ6G1uHvEGN2G/s2sCH
         O7jYYP8N3tvm8/aCdfwDohrSuOdqNaMFxOG+VkpKfvvy4fuD6HNO9BmWAVbetkDplHM2
         V3pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310DVp2MQuNMjisyA2lgKkl4genebv9nyX8RPOledQHDljrcy2c
	A32QRwbIfgXaaGmzTLBrA2k=
X-Google-Smtp-Source: ABdhPJw73ABM3CcDPcPffFMmjK0YRmTuMeRc2yMZmz/LDRx5frYjbeMHqjSFHlGPqsKjJMVH6bGZ3g==
X-Received: by 2002:a9d:1c90:: with SMTP id l16mr3325307ota.192.1603299516224;
        Wed, 21 Oct 2020 09:58:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:390b:: with SMTP id g11ls80722oia.1.gmail; Wed, 21 Oct
 2020 09:58:35 -0700 (PDT)
X-Received: by 2002:a05:6808:605:: with SMTP id y5mr3032844oih.172.1603299515815;
        Wed, 21 Oct 2020 09:58:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603299515; cv=none;
        d=google.com; s=arc-20160816;
        b=sbYiMGQ5yJQKXbSqk6KLgNsKJVGoR5LPxw1pwmSnGgj4hOD/6btzoWKxWNQdq2pLV6
         RtXvjgZBD00I9+pXG7jYIg2FVFw2AsqCL/hOCfEI+x2j5UyYvsnQhoALc8mIb4XOZiyS
         u4LN+SCFuRuXshJG8kJyD2Te28jKdQrbwk6ALNXe13XS5mRQQ1BNM2nNkLbLPd6Kc5Ca
         5/c7bCmpY2yETaTVhXvLLRMM+7h0n7a60V4g3n3BJnhEpXr8zMHlwLoyU9XAGZymR0GX
         FBZv8NMSaH/MT4EWCMbM/ivJfz746Hc53o4PYLj5y8o0i1Y1dqFLynnjXh9TmMzQQ+bo
         84Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=qgxb83JHD/Tk385y5UPYGzutMkiNL5jV5+4Vfni0TYw=;
        b=OZSomPitdPLQ4O3bfdoC49uMbtR7Gdy0IlnXHkNKallqPDwwqElwzsQy+sKOF9N/Ct
         v6S3vL/3bGZLTGA8Hht/3MHhkX5DK/gQAwRTgj6TD5QCS7HgARV5oklj/sFO9SVaT9kT
         gwks7UHWblR1CT3nQSJqnUmui1kbaJX+cSY9UWXldyQ2hRJttkdisppSnMiJxOXdMZnZ
         lavybu1EA5dJKAaxcbMaTSVdwanNXxbS4OB/dPeAiuwTz7kDHO8Ib1OwReLsQG43XYYc
         +hlt4o2SIoRIVEi9gpaksMoamV4avHGAFQszqBDFw6vHXhi3O3nGoLG0kWnfwW6OM1Gq
         8Lug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="EWYTm/LY";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id t11si206865oij.2.2020.10.21.09.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 09:58:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id z2so3159510ilh.11
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 09:58:35 -0700 (PDT)
X-Received: by 2002:a92:9944:: with SMTP id p65mr3095346ili.127.1603299515027;
 Wed, 21 Oct 2020 09:58:35 -0700 (PDT)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Wed, 21 Oct 2020 22:28:23 +0530
Message-ID: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
Subject: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: open list <linux-kernel@vger.kernel.org>, linux-m68k@lists.linux-m68k.org, 
	X86 ML <x86@kernel.org>, LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev@googlegroups.com
Cc: Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="EWYTm/LY";       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

LTP mm mtest05 (mmstress), mtest06_3 and mallocstress01 (mallocstress) tested on
x86 KASAN enabled build. But tests are getting PASS on Non KASAN builds.
This regression started happening from next-20201015 nowards

There are few more regression on linux next,
  ltp-cve-tests:
    * cve-2015-7550
  ltp-math-tests:
    * float_bessel
    * float_exp_log
    * float_iperb
    * float_power
    * float_trigo
  ltp-mm-tests:
    * mallocstress01
    * mtest05
    * mtest06_3
  ltp-syscalls-tests:
    * clone08
    * clone301
    * fcntl34
    * fcntl34_64
    * fcntl36
    * fcntl36_64
    * keyctl02
    * rt_tgsigqueueinfo01

metadata:
  git branch: master
  git repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
  git describe: next-20201015
  kernel-config:
https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/kernel.config

steps to reproduce:
  # boot x86_64 with KASAN enabled kernel and run tests
  # cd /opt/ltp/testcases/bin
  # ./mmstress
  # ./mmap3 -x 0.002 -p
  # ./mallocstress

mtest05  (mmstress) :
--------------------
mmstress    0  TINFO  :  run mmstress -h for all options
mmstress    0  TINFO  :  test1: Test case tests the race condition
between simultaneous read faults in the same address space.
[  279.469207] mmstress[1309]: segfault at 7f3d71a36ee8 ip
00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in
libc-2.27.so[7f3d77058000+1aa000]
[  279.469305] audit: type=1701 audit(1602818315.656:3):
auid=4294967295 uid=0 gid=0 ses=4294967295 subj=kernel pid=1307
comm=\"mmstress\" exe=\"/opt/ltp/testcases/bin/mmstress\" sig=11 res=1
[  279.481636] Code: 2d 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
84 00 00 00 00 00 0f 1f 44 00 00 b8 18 00 00 00 0f 05 48 3d 01 f0 ff
ff 73 01 <c3> 48 8b 0d 91 22 2d 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e
0f 1f
[  279.498212] mmstress[1311]: segfault at 7f3d70a34ee8 ip
00007f3d77132bdf sp 00007f3d70a34ee8 error 4 in
libc-2.27.so[7f3d77058000+1aa000]
[  279.516839] Code: 2d 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
84 00 00 00 00 00 0f 1f 44 00 00 b8 18 00 00 00 0f 05 48 3d 01 f0 ff
ff 73 01 <c3> 48 8b 0d 91 22 2d 00 f7 d8 64 89 01 48 83 c8 ff c3 66 2e
0f 1f
tst_test.c:1246: INFO: Timeout per run is 0h 15m 00s
tst_test.c:1246: INFO: Timeout per run is 0h 09m 00s
tst_test.c:1291: BROK: Test killed by SIGBUS!

mtest06_3 (mmap3 -x 0.002 -p) :
-------------------------------
mmap3.c:154: INFO: Seed 22
mmap3.c:155: INFO: Number of loops 1000
mmap3.c:156: INFO: Number of threads 40
mmap3.c:157: INFO: MAP[  286.657788] mmap3[1350]: segfault at
7f12179d4680 ip 00007f121859951d sp 00007f12179d1e10 error 6 in
libpthread-2.27.so[7f1218589000+19000]
_PRIVATE = 1
mm[  286.671184] Code: c4 10 5b 5d 41 5c c3 66 0f 1f 44 00 00 48 8b 15
99 8a 20 00 f7 d8 64 89 02 48 c7 c0 ff ff ff ff c3 48 8b 15 85 8a 20
00 f7 d8 <64> 89 02 48 c7 c0 ff ff ff ff eb b6 0f 1f 80 00 00 00 00 b8
01 00
[  286.677386] audit: type=1701 audit(1602818322.844:6):
auid=4294967295 uid=0 gid=0 ses=4294967295 subj=kernel pid=1348
comm=\"mmap3\" exe=\"/opt/ltp/testcases/bin/mmap3\" sig=11 res=1
ap3.c:158: INFO: Execution time 0.002000H

mallocstress01 (mallocstress) :
------------------------------
pid[1496]: shmat_rd_wr(): shmget():success got segment id 32830
pid[1496]: do_shmat_shmadt(): got shmat address = 0x7f301eae9000
pid[1496]: shmat_rd_wr(): shmget():success got segment id 328[
291.851376] mallocstress[1502]: segfault at 0 ip 0000000000000000 sp
00007f80dea3ec50 error 14
30
pid[1496]: d[  291.851466] mallocstress[1507]: segfault at
7f80dc239c98 ip 00007f80df2bf81c sp 00007f80dc239c98 error 4
o_shmat_shmadt()[  291.851485] mallocstress[1505]: segfault at
7f80dd23bc38 ip 00007f80df33fe93 sp 00007f80dd23bc38 error 4
[  291.851490] Code: 00 00 00 00 0f 1f 00 41 52 52 4d 31 d2 ba 02 00
00 00 be 80 00 00 00 39 d0 75 07 b8 ca 00 00 00 0f 05 89 d0 87 07 85
c0 75 f1 <5a> 41 5a c3 66 0f 1f 84 00 00 00 00 00 56 52 c7 07 00 00 00
00 be
: got shmat addr[  291.851565] audit: type=1701
audit(1602818328.038:7): auid=4294967295 uid=0 gid=0 ses=4294967295
subj=kernel pid=1500 comm=\"mallocstress\"
exe=\"/opt/ltp/testcases/bin/mallocstress\" sig=11 res=1
[  291.852984] mallocstress[1504]: segfault at 7f80dda3cc38 ip
00007f80df33fe93 sp 00007f80dda3cc38 error 4
ess = 0x7f301e85[  291.852988] Code: 00 00 00 00 0f 1f 00 41 52 52 4d
31 d2 ba 02 00 00 00 be 80 00 00 00 39 d0 75 07 b8 ca 00 00 00 0f 05
89 d0 87 07 85 c0 75 f1 <5a> 41 5a c3 66 0f 1f 84 00 00 00 00 00 56 52
c7 07 00 00 00 00 be
[  291.853045] audit: type=1701 audit(1602818328.040:8):
auid=4294967295 uid=0 gid=0 ses=4294967295 subj=kernel pid=1500
comm=\"mallocstress\" exe=\"/opt/ltp/testcases/bin/mallocstress\"
sig=11 res=1
5000
tst_test.c[  291.860373] Code: Unable to access opcode bytes at RIP
0xffffffffffffffd6.
[  291.860453] mallocstress[1506]: segfault at 7f80dca3ac98 ip
00007f80df2bf81c sp 00007f80dca3ac98 error 4
:1246: INFO: Tim[  291.860654] audit: type=1701
audit(1602818328.047:9): auid=4294967295 uid=0 gid=0 ses=4294967295
subj=kernel pid=1500 comm=\"mallocstress\"
exe=\"/opt/ltp/testcases/bin/mallocstress\" sig=11 res=1
[  291.871350]
eout per run is [  291.871397] mallocstress[1501]: segfault at 0 ip
0000000000000000 sp 00007f80df23fc50 error 14
[  291.871401] Code: Unable to access opcode bytes at RIP 0xffffffffffffffd6.
0h 30m 00s
[  291.871467] audit: type=1701 audit(1602818328.058:10):
auid=4294967295 uid=0 gid=0 ses=4294967295 subj=kernel pid=1500
comm=\"mallocstress\" exe=\"/opt/ltp/testcases/bin/mallocstress\"
sig=11 res=1
[  291.882113]  in libc-2.27.so[7f80df241000+1aa000]
[  291.900984] Code: ff 48 85 c0 75 d8 0f 1f 84 00 00 00 00 00 8b 35
26 11 33 00 48 83 c1 10 85 f6 0f 85 42 01 00 00 48 81 c4 88 00 00 00
48 89 c8 <5b> 5d 41 5c 41 5d 41 5e 41 5f c3 66 0f 1f 84 00 00 00 00 00
4c 8b
[  291.919351] Code: ff 48 85 c0 75 d8 0f 1f 84 00 00 00 00 00 8b 35
26 11 33 00 48 83 c1 10 85 f6 0f 85 42 01 00 00 48 81 c4 88 00 00 00
48 89 c8 <5b> 5d 41 5c 41 5d 41 5e 41 5f c3 66 0f 1f 84 00 00 00 00 00
4c 8b

Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>

full test log link,
https://lkft.validation.linaro.org/scheduler/job/1844090

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvHze%2BhKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw%40mail.gmail.com.
