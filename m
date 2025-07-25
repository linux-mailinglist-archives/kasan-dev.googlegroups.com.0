Return-Path: <kasan-dev+bncBDXZ5J7IUEIBB5WLR7CAMGQEBAEV3NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 03279B1252D
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 22:15:52 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b350d850677sf1739007a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 13:15:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753474550; cv=pass;
        d=google.com; s=arc-20240605;
        b=IB8oE5r8TA/hDsExfh59jb8kHRM1S+odDo/ZyvtcsDHJM7icw7AS/qf0dWbhVzYrce
         2fqVPn4g+XGa6MuLwQb+gq4/VeBJjxE1zKtkngsHGLQ+ZaO/bgmSevIRCTUtsNdCwT0B
         5kboQVM9ojbpd48hJqiYPmxJXvOYYiTbkEvVBYY97k3jXH4R7/bKvj2s+8UnvMJM0PK8
         lZ0DRL+fBfQwKXjbmoFrNSlK9KcPVlYECkGgxA2qZz4qJlX/6jQAlel1JP9RvP8NMaAI
         uyokUpQsTHeymVop53irB5KEk16CqG5wYERx6gcWPtALxXWOD9T2UuFo9PWGlJTIQ76J
         jLHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6yl1ZYr2NyN1rH3J0GYJuwrIqyqUxni70ABHAH2T7Kg=;
        fh=EVQAJ236dnli2+Li9PoeYT5QgNvszGBO3WwkFfi2WvA=;
        b=Meqkuw6tfSx8FGy76gqjkLvOVLjJ8ern9skndMVwu5xb4RLB8j4uKCwgXOVinjE9XT
         F1JUhG85j+zMlmE42HXxHRdw6JC1ef18vXvVeVFKS2Sa6IlIURBfr7ScPpq6XyoiT2ka
         twBkL1NgCGjd4mfDP24PYoYViHAmqkdiif+b2BrPNsIRr94qfbgSp5IG3KVMUjkLHu8G
         thILEV0ejFfdFLlDa9gmTVbHrqHmCaC6mPwlWc1NbXUyxOpouaQqG0AFQaweRtQeAZ3A
         lpUPh7CO1iCrrZMc+kk+wdXuyiJyuwcyJ5sSD30u6s3hMkosRG/Brfj2cPrqj1rEclQi
         QnUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.53 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753474550; x=1754079350; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6yl1ZYr2NyN1rH3J0GYJuwrIqyqUxni70ABHAH2T7Kg=;
        b=D5XlmdyPllEy2liydEMtbHlD8dT4y/MEvmSsKwXgBzLM95J5iqHAByMTmzYNXRPhjJ
         GQe9JXbMClKbYUs82OY0sZffqGToho+ECeG4zgb1nQImGNHjKxc6Tzu/ij3ycgDXaq2p
         ES5LWO+ktB1H+LxpvwU4iMf0FjzfMkCXGM/Cdlwj/GclQ7ZEKvQdlPU/nzdOzTw8Sl/V
         tdfvt9WUvnKveYJDY0zOyxLXXkbCLdOQ6BBNF0hL3IZBC61Rcd3TLP4L7skesQV0FuNl
         gBkDUtHPsAsuchckLq5W2GCUfFc66muylHyQpwMlUmcn3+D5lTyJDsqzl0ji46SbOX+M
         zZIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753474550; x=1754079350;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6yl1ZYr2NyN1rH3J0GYJuwrIqyqUxni70ABHAH2T7Kg=;
        b=HT/uu9FGWpO7hXpeoi7rUemNgpBWRXs+C0BbuQUH7NWeNl5wg5ndWac83KIus9Se25
         YzY2FxlHEOp/yc/VYDg3A6bTy0zV991G/TVIGrdd+TyWzGIo8vX8tlIIOPKoVd7KIpnO
         tJAXo3GImE1lwxx2zemwQoRHArh1PAX78hQqetZ8aJ8s8iFE27MrlNc5w+JHg1AivnY4
         KgUpq/HtG6vbQ1+0TiX4eT1jMDSa8OBm5czpB4QlqqLrmLTEcFiCFGH+W0dRmzU+7ICJ
         LA0lpV6GBcBQ27t4zfUYWYQLwcJB2no2lXItjBphaZ/z2RsqeNan8tZkRV0tX1Mz/lN0
         /94Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXTNJvSyPsgJhJxbVgjJqNZfusBJ6fKGVI/d8JR95KYpj7FhO71vrJt+RQATZUlckQnGvW+mg==@lfdr.de
X-Gm-Message-State: AOJu0Yx0iaVdttM++7UljznUHaDdN3mMd1nAhi1XCSdHPhgkQF69I8PN
	9cYDP+8tGH8dYV3R+tKuISCsoU19Ucfw5eRx1ysetoQ+ZfduEc9pL1Cc
X-Google-Smtp-Source: AGHT+IENxPW+f5n/e1YHezxHDc2AuG9Qbp1fh3QhtPDmSJeOP3sg0MqMIZfoBVAGtDDlq917ekyATg==
X-Received: by 2002:a17:90b:4a44:b0:312:1ae9:1529 with SMTP id 98e67ed59e1d1-31e77a034famr3968663a91.27.1753474550335;
        Fri, 25 Jul 2025 13:15:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcI8w/Yos1vWnO4EmHWSSWvOLYdEdQqwMVSOKUapUKxxQ==
Received: by 2002:a17:90a:e18c:b0:311:adf0:406a with SMTP id
 98e67ed59e1d1-31e5f9b3adfls2090953a91.0.-pod-prod-04-us; Fri, 25 Jul 2025
 13:15:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcdBTFr+7ld/igeEFgeovbrPn3APxsMTXrb27dCZfMLG94NsIZTaBD5AvOXTqLRvLX0jUrMB+6qI4=@googlegroups.com
X-Received: by 2002:a17:90b:2d8c:b0:313:b78:dc14 with SMTP id 98e67ed59e1d1-31e77635171mr5208115a91.0.1753474548987;
        Fri, 25 Jul 2025 13:15:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753474548; cv=none;
        d=google.com; s=arc-20240605;
        b=S7koRUKIPmogv7SNzIJtYutjse/VYa75ShJ6kvwRy7MLKlkUbbNJ4PWT9rTQVs8h7K
         Aw/J/LtKPaxwump8LBTEygjzvN95SRwiR0aPW2qorehdq2UemUu8MuLZOwgirafXDQ4n
         A+La98HRcyG30oFdN3mtBBighJiqQBsgL/wYwwpwV7eEFPzQSZ37Pr8OFfZIrjAHH6dv
         4yG0MWLfSy7iQUkogy0fbbrAtpeN/GQc7j8V/Q9IM3IuzZd1jid7usOP1B4kRqCd1MVI
         qAVtkzdmOmcEp5ZolWYBvh6n36Z+9DOlIfMAvKhTLstg3B6NOpVTJC9I8nEeM1E2u80P
         jXFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=iDxcanwU1JbetZe9oiUEN/n+YFfsJR7sLnCsAScdPD4=;
        fh=qoPo/ZK+3EITCJ3a3hr9QUPLzt2TtsuJwgYDrIDeO7g=;
        b=dCFJarB/SwHfc0WrZ9/LBGl67uTPB5AS55qI9hgl4cJGh5urLFS3tXtiwdsIKn3TPm
         j58A6al7RHSwquPYdFNtjE/wNFhcctKNN1Pg3H+TZN7fhKgPrbIHcHGG9pPfWUb6m/WI
         7pXD+QN8yRgExogREelF1vaWCR5as1c5dh+E/WKtuJEVEwXFZ5UFLRDQvzyDeXmlsiVC
         VIWSB+41FZ8pq6i2+V+cit0Hck1lyw6pId9rLAuFAfCBw1YEFjswMY4p0PyAyE3aGFpZ
         rjLw+XZjWG4VDeo7iyD2eaFBvYxFD+Wo6HoWG6OeicSwtwSTdlb7JHRHCx+4XTXul4mt
         I0VQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.216.53 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pj1-f53.google.com (mail-pj1-f53.google.com. [209.85.216.53])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e609617ffsi193822a91.0.2025.07.25.13.15.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jul 2025 13:15:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.216.53 as permitted sender) client-ip=209.85.216.53;
Received: by mail-pj1-f53.google.com with SMTP id 98e67ed59e1d1-312a806f002so189979a91.3;
        Fri, 25 Jul 2025 13:15:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrzwHfldr9+Ik2nO70b4Xf8p7vzJNP8QZDCLbTTquqmScVcWC8G4gA3ZDdR/xSzwalOvChGVfEHII=@googlegroups.com, AJvYcCXWO+5KlXkaKSSwkaCBoPlGGCeTRPYVRYcRQIXsd41HTa9WPrF4Br+YIoaoKsPFJO/XtSGyerdmm7mK@googlegroups.com
X-Gm-Gg: ASbGnctbnvshZ7r2/jLQiySzFeRQx3JyL1S0eTVS2Y7zLI3YS/RuENQldxwcl2Xdwoh
	G23pDUtE0lvki2SrdeFo6b5s8Vl7WxAADPbUkjwD2J1+rc9s+BU4oO8U48/glTBmb4qbxXWBSDL
	KLTIxfNlospXBj5spsmSpahTkrV7FEe3aUvL3qi+ZYMFp3zPtOvvoQqXXG15BS6Tq2a6MKPEgyh
	Lqg8FCrvlTw/3Alz3BcCny4by6fTfiX5vEyGAToOuVkRAhK6sHwUXB2wwHD8DS8lzQTqZ4ln5dc
	T9TVTFGue7Jm9PeKBu/d4JV/Wfx33VZPGWspFVsNt827Rkq57ZD8vaSCaXi8Ecy3u7D4oCkWbCN
	+0ElE2SKFFfA7
X-Received: by 2002:a17:90b:4ad2:b0:313:f9fc:7214 with SMTP id 98e67ed59e1d1-31e77873f60mr1854586a91.1.1753474548387;
        Fri, 25 Jul 2025 13:15:48 -0700 (PDT)
Received: from localhost ([218.152.98.97])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-31e832fb798sm346993a91.8.2025.07.25.13.15.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Jul 2025 13:15:47 -0700 (PDT)
From: Yunseong Kim <ysk@kzalloc.com>
To: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Byungchul Park <byungchul@sk.com>,
	max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>,
	linux-kernel@vger.kernel.org,
	Yunseong Kim <ysk@kzalloc.com>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	stable@vger.kernel.org,
	kasan-dev@googlegroups.com,
	syzkaller@googlegroups.com,
	linux-usb@vger.kernel.org,
	linux-rt-devel@lists.linux.dev
Subject: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on PREEMPT_RT
Date: Fri, 25 Jul 2025 20:14:01 +0000
Message-ID: <20250725201400.1078395-2-ysk@kzalloc.com>
X-Mailer: git-send-email 2.50.0
MIME-Version: 1.0
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.216.53 as permitted
 sender) smtp.mailfrom=yskelg@gmail.com
Content-Type: text/plain; charset="UTF-8"
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

When fuzzing USB with syzkaller on a PREEMPT_RT enabled kernel, following
bug is triggered in the ksoftirqd context.

| BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
| in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 30, name: ksoftirqd/1
| preempt_count: 0, expected: 0
| RCU nest depth: 2, expected: 2
| CPU: 1 UID: 0 PID: 30 Comm: ksoftirqd/1 Tainted: G        W           6.16.0-rc1-rt1 #11 PREEMPT_RT
| Tainted: [W]=WARN
| Hardware name: QEMU KVM Virtual Machine, BIOS 2025.02-8 05/13/2025
| Call trace:
|  show_stack+0x2c/0x3c (C)
|  __dump_stack+0x30/0x40
|  dump_stack_lvl+0x148/0x1d8
|  dump_stack+0x1c/0x3c
|  __might_resched+0x2e4/0x52c
|  rt_spin_lock+0xa8/0x1bc
|  kcov_remote_start+0xb0/0x490
|  __usb_hcd_giveback_urb+0x2d0/0x5e8
|  usb_giveback_urb_bh+0x234/0x3c4
|  process_scheduled_works+0x678/0xd18
|  bh_worker+0x2f0/0x59c
|  workqueue_softirq_action+0x104/0x14c
|  tasklet_action+0x18/0x8c
|  handle_softirqs+0x208/0x63c
|  run_ksoftirqd+0x64/0x264
|  smpboot_thread_fn+0x4ac/0x908
|  kthread+0x5e8/0x734
|  ret_from_fork+0x10/0x20

To reproduce on PREEMPT_RT kernel:

 $ git remote add rt-devel git://git.kernel.org/pub/scm/linux/kernel/git/rt/linux-rt-devel.git
 $ git fetch rt-devel
 $ git checkout -b v6.16-rc1-rt1 v6.16-rc1-rt1

I have attached the syzlang and the C source code converted by syz-prog2c:

Link: https://gist.github.com/kzall0c/9455aaa246f4aa1135353a51753adbbe

Then, run with a PREEMPT_RT config.

This issue was introduced by commit
f85d39dd7ed8 ("kcov, usb: disable interrupts in kcov_remote_start_usb_softirq").

However, this creates a conflict on PREEMPT_RT kernels. The local_irq_save()
call establishes an atomic context where sleeping is forbidden. Inside this
context, kcov_remote_start() is called, which on PREEMPT_RT uses sleeping
locks (spinlock_t and local_lock_t are mapped to rt_mutex). This results in
a sleeping function called from invalid context.

On PREEMPT_RT, interrupt handlers are threaded, so the re-entrancy scenario
is already safely handled by the existing local_lock_t and the global
kcov_remote_lock within kcov_remote_start(). Therefore, the outer
local_irq_save() is not necessary.

This preserves the intended re-entrancy protection for non-RT kernels while
resolving the locking violation on PREEMPT_RT kernels.

After making this modification and testing it, syzkaller fuzzing the
PREEMPT_RT kernel is now running without stopping on latest announced
Real-time Linux.

Link: https://lore.kernel.org/linux-rt-devel/20250610080307.LMm1hleC@linutronix.de/
Fixes: f85d39dd7ed8 ("kcov, usb: disable interrupts in kcov_remote_start_usb_softirq")
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Alan Stern <stern@rowland.harvard.edu>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Byungchul Park <byungchul@sk.com>
Cc: stable@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: syzkaller@googlegroups.com
Cc: linux-usb@vger.kernel.org
Cc: linux-rt-devel@lists.linux.dev
Signed-off-by: Yunseong Kim <ysk@kzalloc.com>
---
 include/linux/kcov.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c3..c5e1b2dd0bb7 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -85,7 +85,9 @@ static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
 	unsigned long flags = 0;
 
 	if (in_serving_softirq()) {
+#ifndef CONFIG_PREEMPT_RT
 		local_irq_save(flags);
+#endif
 		kcov_remote_start_usb(id);
 	}
 
@@ -96,7 +98,9 @@ static inline void kcov_remote_stop_softirq(unsigned long flags)
 {
 	if (in_serving_softirq()) {
 		kcov_remote_stop();
+#ifndef CONFIG_PREEMPT_RT
 		local_irq_restore(flags);
+#endif
 	}
 }
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250725201400.1078395-2-ysk%40kzalloc.com.
