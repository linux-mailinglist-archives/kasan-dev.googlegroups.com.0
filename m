Return-Path: <kasan-dev+bncBAABBV4M3C5QMGQE7JIICEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id B350E9FF5BC
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jan 2025 04:22:00 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-467b19b55d6sf142149741cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2025 19:22:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1735788119; cv=pass;
        d=google.com; s=arc-20240605;
        b=CgwohaNs3OW0Jxrof4xGAuGrcoAkVOodRd/DIVSO54RSmWQQXmnwTvFe/pqUQb1sxp
         qqKguTEJpGdRg+AYxO6P5yawAJz6I/gFI87t/I1q33o+1rOepQe7aEv04o87n1W/Rm0m
         SO2grBz4cksx8uFM7uMtzCpX+fkK5fQ26O1GHTA4PV9v1dLZRmPQelpPV5OitU9/xER6
         lfmTa0SNlXUVi73qse6+eMAWmhHZPzD4JJFmJaM80slb82VFfs+qyZtAbcwEIKA2Vhkd
         ZdwEfJbsxbsHaEKyqUoiATkJSbqONbCwK/HWok1ylGUSGakStBXro3+RDcqmVeygP6xq
         gq9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:to:cc:date
         :message-id:subject:mime-version:content-transfer-encoding:from
         :dkim-signature;
        bh=X3/6N2v9GObaGNwRscFEkgv/0dyqyH47CQmxWHigU2o=;
        fh=ZkfJhJ1hka8wofhJf0vkV8vfB1DDS8mTHIlcXjRnvcU=;
        b=ctIALLEGj1jPP/KfN57NbwfJa9tXFvS8NUnNnuVlJDqzq+1YYAsEUupouryX5CNGW4
         /8Ex9EIL1o2Ut3AXYXtX3Qd2QnRAeBkezSDQZ6oIl9Lw5xvyRoKszSh7WNFuW4B1/DGr
         d8jb7FWJbE2UX7z/5+gWXZPSN6qMJ/Nz06p8HhR8SiKV6ixSVh8KMQD4HuP6ILUMz/qz
         KGBJkEXptQsO23m+biytdm7iMkwFbBnOeZHnVa8Od+/ux2B+TuwJZz/RgQkScNEz3DAO
         CJlbWcoW8o2AH8+yF5iLD5TXRclGdDzyeScINW6KCAYobwN2eSJXJSOTiq3LMJ8Xg5dZ
         jBWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=QXizUrsF;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 52.59.177.22 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1735788119; x=1736392919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :cc:date:message-id:subject:mime-version:content-transfer-encoding
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=X3/6N2v9GObaGNwRscFEkgv/0dyqyH47CQmxWHigU2o=;
        b=NvBO07hXmPZjhPcicLRd99anS4ZByOMHdFfc22WIZDII4RDAMZuXBaq4Dy1PB3lByf
         mtP/+joNIeBYhKnvz7lKU6cBdfYM2wIqffOLvsMQoiOAagmiY+5zZ+Yhfc5wUAfhChAc
         Gn0GqgD/VjyWl1nXkQb1PwBBqSmRh4vk+9pPJRFCu22yhpDuKo8p+ee5zaloM5VvaOXR
         zwXYxABroTwDQc1VdHeKmKkmbRQVXM2flGCU6k4Xmn8NXR6mvitYfYVqWVc+/RgbC+k9
         ZYXeRgEw/z4TagO3xnRZupJ38kEVHzBmzdlzGxos8X7xDNKPCjj0duHV3kNFQ/4Arkpg
         bTEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1735788119; x=1736392919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id:to
         :cc:date:message-id:subject:mime-version:content-transfer-encoding
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X3/6N2v9GObaGNwRscFEkgv/0dyqyH47CQmxWHigU2o=;
        b=MF0GZN8CS26DBEKYBvcjpjweWbnhjZ0OiXzEgd3FwKpuxOILBzZ5Bd3ooyw7eRmYVS
         zdi/1Q+g4eWWd+R16VPFvO0yb3MLG6iL6rWE0jkYq23ToHahYwl304dWh/FikI+VqylC
         1ZXcSMgUf1OXRgeakbtMDz2GEk0FFWPHt1bref3KTW9h2TMzTcNMB6f34fNY7WZcS2NG
         JcXXmwVwxjN6i18qIFlzMe0fgzOl0hzok7WMJ9tMsAYV/kSdri5B90iWtsMGiP78eXmb
         fleKr9PXRimr5QvIIk/wg+pc+AekYIVmkI/qpffDeUnLaznUg1gAK5oJzqJplwLEHx1a
         Tmng==
X-Forwarded-Encrypted: i=2; AJvYcCUgpvz6BFhRtVOml+Hl1E9iRiqCwCeHCiRw9rArVT/I6iBadMdwTKaphcX+C1E4POtUPUTSQw==@lfdr.de
X-Gm-Message-State: AOJu0Yxp5TczFfZOAS/3M3EQBAqfesVfzCxOabn9mdtAznR/p4+HUL1x
	c5XjHklFzliiegNROjOcwJr4boiVug0LuCFiWpvENtlKRuqqwQY1
X-Google-Smtp-Source: AGHT+IGvc0fpHc+huChAiQEduya6e3j73vuslEFbZgJIq8Kym8rQBfVrdcPQhhbb8hpEXWh5uGfwfQ==
X-Received: by 2002:a05:622a:48:b0:45d:9357:1cca with SMTP id d75a77b69052e-46a4a8cc592mr700557401cf.14.1735788119561;
        Wed, 01 Jan 2025 19:21:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5205:0:b0:466:ac8d:733d with SMTP id d75a77b69052e-46a3b05aebcls162542811cf.0.-pod-prod-08-us;
 Wed, 01 Jan 2025 19:21:59 -0800 (PST)
X-Received: by 2002:a05:622a:181e:b0:469:715:d94c with SMTP id d75a77b69052e-46a4a8b6c74mr543747321cf.6.1735788118944;
        Wed, 01 Jan 2025 19:21:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1735788118; cv=none;
        d=google.com; s=arc-20240605;
        b=eB1K6u/69JZRSM32VAzrWzW1n00SW0oxzKtthFDrZkyvawkHU0C06HzXWAFXT5lSTX
         t1z/HPDlZmY1/wElLDwJUnI0+l8q2vkdUSnjUb1MPwSwZNtEqF7ZkF5o68rSRXugMWzB
         2/jQij5EQEXV60FKfd/AstFSrxrKYC9gzBsYMfXtci7XN/9wn1IWyAPZxG56Iej+h4ZZ
         aR1q+n22v2sGPZIqzXxdvETIIX0tRALyNVBe7Dpa3MxcRRDqi0WaFUIk1ACg/3X/zORs
         zkaHA2hgQqq4lRNAOP2kFGfZrKQkHpXgyYI3vWEbF2dqz4/O5nwNDliW1MWVAbUO8207
         +FiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:to:cc:date:message-id:subject:mime-version
         :content-transfer-encoding:from:dkim-signature;
        bh=LYdAe9fE2pxNVjXt+nkKiABoEtrxJQfceesrzNnuhJQ=;
        fh=YphHoG+pq10eMqP59aA1kmjZdqPO7Yqx1jSs0PMHpkI=;
        b=K7ifscTK4IMPouXyB9skEWDw1OwmZUZ1cqjql7RVcybfyBfgLGvPDYxs6w8Lvg/a5Z
         e8Yn7OQZl+liN+xP/2GZRDpHfpMqmivonj/Duq/L1PuJyEkVXcI/x5tCNgALvmIHAlR0
         3H2FSoXbNYIUqB9ZRJ7BKobIty12jZv8/Z+aSEcHrkOrenwwKTZsItMO4QT5V4HloPUg
         WO0ytPxa6/vHWSSkeegvuDtRLdYf0Zb1JhMOqpjoAnC0ZN2URYc80xfk0C14mPe83edG
         ujMyDS94xQQEBpHnehsmsGImgFmuHFitRErQFMVjYKkO4gS7T8xcky1JNIw1/KBu+CDN
         rrHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=QXizUrsF;
       spf=pass (google.com: domain of huk23@m.fudan.edu.cn designates 52.59.177.22 as permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
Received: from smtpbgeu1.qq.com (smtpbgeu1.qq.com. [52.59.177.22])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46a3e646ec3si12011641cf.1.2025.01.01.19.21.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Jan 2025 19:21:57 -0800 (PST)
Received-SPF: pass (google.com: domain of huk23@m.fudan.edu.cn designates 52.59.177.22 as permitted sender) client-ip=52.59.177.22;
X-QQ-mid: bizesmtpip2t1735788090tjm1hr8
X-QQ-Originating-IP: xUpUCfZw1KSL+IW0BnREExUmmt3R5LOo5Svr9feJciU=
Received: from smtpclient.apple ( [localhost])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Thu, 02 Jan 2025 11:21:27 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 0
X-BIZMAIL-ID: 11487057782185545285
From: "'Kun Hu' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3818.100.11.1.3\))
Subject: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
Message-Id: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
Date: Thu, 2 Jan 2025 11:21:17 +0800
Cc: kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
To: dvyukov@google.com,
 andreyknvl@gmail.com,
 akpm@linux-foundation.org,
 elver@google.com,
 arnd@arndb.de,
 nogikh@google.com
X-Mailer: Apple Mail (2.3818.100.11.1.3)
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtpip:m.fudan.edu.cn:qybglogicsvrgz:qybglogicsvrgz8a-1
X-QQ-XMAILINFO: N4KH/PyO63Qv8wqMlxoOjZLhIUCqR6EjleBBBLJPs/hyJzd7ZR+vRI2D
	RxCB2YYyNb0iQnkrGvbvR2vvGrXMFOUogTaSnThr9ACTEti+b6T/WdQxV/PPalRskhMwtSJ
	F5nEjXbqwuGk77Qy/56EkBX8zVUittPEsf9W1Dy3N3BDvWE2FfH1tV8KFyJJsflBjASwoZ4
	NfD6m+agBEzXIe1DNH8YpFcAlnwjO47dfOKT4ftxBzmCiSPWiJxOKOTZJbIrV0Y/VFS1O4i
	6CzNtx8d+53p9wffNL5HOC3PIR0MdIyiQl+69ID8RRMDlx7GlKwvlIsdTngC5FADo6IzsC7
	lhHq+M2PucDpi9NEauOe2oGOsrpcL0ZhyyWF5SVEQia4boX9bHaBToDx75oxrOingYA95Gp
	e849jZbA/VLKlYVI2x5rI4eDPYf3Jg1fd5hoydqyl/LFrfCCc30iRodQJAzVUGjZgKuerxX
	EyBrPzHYmAvYHTtJsAn6t2/1qwbbhhXX127Le5O6hkaR7ZJj5wLRV/YHb+Mnir3I5sGUKCQ
	7h6JxJM7DZU2BvsofjKi8tAmlmP01jLHvA3/P5dvMjnN2e4cbf6oSdlqDe+lDoP3J3cw67B
	WqwrEMP+N68PW0w6QD/6B0QqS7u91LrQ77xsIKsiATtPn3God4cqPZxWNwuhJg3NqxfZJPw
	URzLit2iuPU/SF/UWCuZOhvoMKC9E5wFPFFke14FgMnSXbEQreXsVces92/6/r0rWWesBGm
	dbBHyA4vYN34K0pKVXtjUkVvakrLkDL1JBsxcinlvOXB8iesZIBH0HIAB2SMSe/rgGaRZsc
	f0K/xb0QPxFriZQOBq7gMdlnCHv9HOT7jZFsLgNLS7jGuVfg1tMShKH6KFFuk1t/4HvwMA3
	YBH/9fMe0YIIMj0bQkGE9IA3YqEulBiU8vNmel0FwZK0bnSWRfi4kjKcf8hDdxrx1fGt5u7
	HOgFHA0052Dul4fiNTkd3kH2yIpSij4ufHGhttPjHMMRTEw==
X-QQ-XMRINFO: MSVp+SPm3vtS1Vd6Y4Mggwc=
X-QQ-RECHKSPAM: 0
X-Original-Sender: huk23@m.fudan.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@m.fudan.edu.cn header.s=sorc2401 header.b=QXizUrsF;       spf=pass
 (google.com: domain of huk23@m.fudan.edu.cn designates 52.59.177.22 as
 permitted sender) smtp.mailfrom=huk23@m.fudan.edu.cn;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=m.fudan.edu.cn
X-Original-From: Kun Hu <huk23@m.fudan.edu.cn>
Reply-To: Kun Hu <huk23@m.fudan.edu.cn>
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

When using our customed fuzzer tool to fuzz the latest Linux kernel, the fo=
llowing crash
was triggered.

HEAD commit: dbfac60febfa806abb2d384cb6441e77335d2799
git tree: upstream
Console output: https://drive.google.com/file/d/1rmVTkBzuTt0xMUS-KPzm9OafML=
ZVOAHU/view?usp=3Dsharing
Kernel config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzdj8KUz=
hkeHC/view?usp=3Dsharing
C reproducer: /
Syzlang reproducer: /

The crash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be rela=
ted to the handling of KCOV instrumentation when running in a preemption or=
 IRQ-sensitive context. Specifically, the code might allow potential recurs=
ive invocations of __sanitizer_cov_trace_pc during early interrupt handling=
, which could lead to data races or inconsistent updates to the coverage ar=
ea (kcov_area). It remains unclear whether this is a KCOV-specific issue or=
 a rare edge case exposed by fuzzing.

Could you please help check if this needs to be addressed?

If you fix this issue, please add the following tag to the commit:
Reported-by: Kun Hu <huk23@m.fudan.edu.cn>, Jiaji Qin <jjtan24@m.fudan.edu.=
cn>

--------------------------------
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu: 	0-....: (36 ticks this GP) idle=3D5a54/1/0x4000000000000000 softirq=
=3D28602/28602 fqs=3D20758
rcu: 	(detected by 2, t=3D105010 jiffies, g=3D53165, q=3D148274 ncpus=3D4)
Sending NMI from CPU 2 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 2946 Comm: syz.1.149 Tainted: G    B              6.13.0=
-rc4 #1
Tainted: [B]=3DBAD_PAGE
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1=
.1 04/01/2014
RIP: 0010:__sanitizer_cov_trace_pc+0x22/0x60 kernel/kcov.c:217
Code: 90 90 90 90 90 90 90 90 f3 0f 1e fa 55 bf 02 00 00 00 53 48 8b 6c 24 =
10 65 48 8b 1d 78 11 7a 6b 48 89 de e8 40 ff ff ff 84 c0 <74> 27 48 8b 93 e=
0 14 00 00 8b 8b dc 14 00 00 48 8b 02 48 83 c0 01
RSP: 0018:ffa0000000007698 EFLAGS: 00000046
RAX: 0000000000000000 RBX: ff110000386f0000 RCX: ffffffff949eb81e
RDX: 0000000000000000 RSI: ff110000386f0000 RDI: 0000000000000002
RBP: ffffffff949eb8c3 R08: 0000000000000000 R09: fffffbfff4177aab
R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: ff11000002b9ab50
R13: 0000000000000000 R14: 1ff4000000000edc R15: ff11000053a361a8
FS:  00007f403e2c1700(0000) GS:ff11000053a00000(0000) knlGS:000000000000000=
0
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000001 CR3: 0000000024264004 CR4: 0000000000771ef0
PKRU: 80000000
Call Trace:
 <NMI>
 </NMI>
 <IRQ>
 perf_prepare_sample+0x803/0x2580 kernel/events/core.c:7977
 __perf_event_output kernel/events/core.c:8079 [inline]
 perf_event_output_forward+0xd3/0x2c0 kernel/events/core.c:8100
 __perf_event_overflow+0x1e4/0x8f0 kernel/events/core.c:9926
 perf_swevent_overflow+0xac/0x150 kernel/events/core.c:10001
 perf_swevent_event+0x1e9/0x2e0 kernel/events/core.c:10034
 perf_tp_event+0x227/0xfe0 kernel/events/core.c:10535
 perf_trace_run_bpf_submit+0xef/0x180 kernel/events/core.c:10471
 do_perf_trace_preemptirq_template include/trace/events/preemptirq.h:14 [in=
line]
 perf_trace_preemptirq_template+0x287/0x450 include/trace/events/preemptirq=
.h:14
 trace_irq_enable include/trace/events/preemptirq.h:40 [inline]
 trace_hardirqs_on+0xf2/0x160 kernel/trace/trace_preemptirq.c:73
 irqentry_exit+0x3b/0x90 kernel/entry/common.c:357
 asm_sysvec_irq_work+0x1a/0x20 arch/x86/include/asm/idtentry.h:738
RIP: 0010:get_current arch/x86/include/asm/current.h:49 [inline]
RIP: 0010:__rcu_read_unlock+0xc6/0x570 kernel/rcu/tree_plugin.h:440
Code: b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 0f b6 04 02 84 c0 74 =
08 3c 03 0f 8e bf 01 00 00 8b 85 00 04 00 00 85 c0 75 57 <65> 48 8b 1d 02 a=
f 92 6b 48 8d bb fc 03 00 00 48 b8 00 00 00 00 00
RSP: 0018:ffa0000000007e08 EFLAGS: 00000206
RAX: 0000000000000046 RBX: ff11000053a3d240 RCX: 1ffffffff4177c76
RDX: 0000000000000000 RSI: 0000000000000101 RDI: ffffffff947103e2
RBP: ffffffff9ed26380 R08: 0000000000000000 R09: 0000000000000000
R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: 0000000000000001
R13: 0000000000000200 R14: ffa0000000007e00 R15: 1ff4000000000fc9
 rcu_read_unlock include/linux/rcupdate.h:882 [inline]
 ieee80211_rx_napi+0x117/0x410 net/mac80211/rx.c:5493
 ieee80211_rx include/net/mac80211.h:5166 [inline]
 ieee80211_handle_queued_frames+0xd9/0x130 net/mac80211/main.c:441
 tasklet_action_common+0x279/0x810 kernel/softirq.c:811
 handle_softirqs+0x1ad/0x870 kernel/softirq.c:561
 __do_softirq kernel/softirq.c:595 [inline]
 invoke_softirq kernel/softirq.c:435 [inline]
 __irq_exit_rcu kernel/softirq.c:662 [inline]
 irq_exit_rcu+0xee/0x140 kernel/softirq.c:678
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline=
]
 sysvec_apic_timer_interrupt+0x94/0xb0 arch/x86/kernel/apic/apic.c:1049
 </IRQ>
 <TASK>
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:=
702
RIP: 0010:__sanitizer_cov_trace_pc+0x0/0x60 kernel/kcov.c:210
Code: 48 8b 05 b3 11 7a 6b 48 8b 80 f0 14 00 00 e9 32 a1 e6 07 0f 1f 80 00 =
00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 <f3> 0f 1e fa 55 b=
f 02 00 00 00 53 48 8b 6c 24 10 65 48 8b 1d 78 11
RSP: 0018:ffa0000007f17db0 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 0000000000000200 RCX: ffffffff947854c4
RDX: 0000000000000200 RSI: ff110000386f0000 RDI: 0000000000000002
RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: ffa0000007f17ec0
R13: dffffc0000000000 R14: dffffc0000000000 R15: 1ff4000000fe2fd8
 __seqprop_raw_spinlock_sequence include/linux/seqlock.h:226 [inline]
 ktime_get_ts64+0xe4/0x3c0 kernel/time/timekeeping.c:952
 posix_get_monotonic_timespec+0x78/0x260 kernel/time/posix-timers.c:156
 __do_sys_clock_gettime kernel/time/posix-timers.c:1148 [inline]
 __se_sys_clock_gettime kernel/time/posix-timers.c:1138 [inline]
 __x64_sys_clock_gettime+0x15c/0x260 kernel/time/posix-timers.c:1138
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xc3/0x1d0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f403f808ba5
Code: c0 4c 89 63 08 48 8d 65 d8 5b 41 5c 41 5d 41 5e 41 5f 5d c3 83 f8 02 =
0f 84 e6 02 00 00 44 89 e7 48 89 de b8 e4 00 00 00 0f 05 <48> 8d 65 d8 5b 4=
1 5c 41 5d 41 5e 41 5f 5d c3 81 7e 04 ff ff ff 7f
RSP: 002b:00007f403e2c0b20 EFLAGS: 00000293 ORIG_RAX: 00000000000000e4
RAX: ffffffffffffffda RBX: 00007f403e2c0ba0 RCX: 00007f403f808ba5
RDX: 0000000000000002 RSI: 00007f403e2c0ba0 RDI: 0000000000000001
RBP: 00007f403e2c0b70 R08: 00007f403f804010 R09: 0000000000032b26
R10: 7fffffffffffffff R11: 0000000000000293 R12: 00007f403e2c0ba0
R13: 00007f403f82ff8c R14: 00007f403f830018 R15: 00007f403e2c0d40
 </TASK>


---------------
thanks,
Kun Hu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/F=
989E9DA-B018-4B0A-AD8A-A47DCCD288B2%40m.fudan.edu.cn.
