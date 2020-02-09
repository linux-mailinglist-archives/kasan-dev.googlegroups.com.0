Return-Path: <kasan-dev+bncBDCO5FWBMEILTDMC6ICRUBCR7RIES@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id E57EB156CD4
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Feb 2020 23:24:57 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id m21sf4514041edp.14
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 14:24:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581287097; cv=pass;
        d=google.com; s=arc-20160816;
        b=IV+MOPCFqnJqX5o2skIIbL560MaHXamqWenOzFauOMkQbPe4ZBPNXRUmfN+iOJCuvO
         z+YabYXp8oIrY3J+csx+WIEKYERzK0dmGFJUjaPbxaT79Qy4TP8ucr0afuYG9FrgQTc9
         83X2S/7gt5vO3YmdGd+vTbWDbDgcV/LjZOy3i1We5d/DoJ4IybaCbugccw78AZyYfBTa
         KNmZl3Sigu/scZpCWUljZljJgdVvlqDExqiookM3WeFZ4oVsIJWjSRD43d/Q7wqb42Vy
         9VTB00AAu4YICextDr/Eh8QH0W/FZvj1mPZzmJn5UnMQhGjFnmYRZS+elV7RGI9z90Fp
         DxKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=kJZE4GzKvcGO8WeRYfE7rqLuJ6eh1wYdLQCwrjJb0AM=;
        b=gAs0FLmJo0Fku+PI11gvT5t99WPGjfWmffMmAuuvd56dk+yeILNuBWFxiNJR+/Cjj9
         +gnjUmWsJQ+Gu8prkMrojjrK+2K016f/g+EYdZjEUXZTDajU03URe2zteDmHpbI6vDt7
         YYYNnQvPQD59sJQSiwdiujCL9aMm8GzpnqMYuzsw/wZ6PgCB3lIYWyxgD5SiC0rUxt++
         JWHTe+oXFLWYoYKH99scefNKY7gsVJ3VuWpBU/FzL+QrdA+eXsowSqM/TY8GvwkuLFCB
         mY7PrpNCq+1EZWuVMQ2NmzZ4BpLVxAVVxWD8xMCb97089F73L8JmvSntMjnY5LNT5ZJ+
         iTfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Q+iL70qi;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kJZE4GzKvcGO8WeRYfE7rqLuJ6eh1wYdLQCwrjJb0AM=;
        b=d5gVWF1zakMqHGTJiqW6ChL34KKW7tOuE1QFDyKCTmS9ikJO97cdnRbHaPswlYrXNR
         nTsbeGWhhauTHjPjDSCORpaaJWsRPGQmDwnoQfh8G77z02wuN1eMEjd53HaLDvHvBxca
         dt/gD2c3dh3J2ogQesfVTjgMyzOruqcSSLqUIFbXE3cj6ykR/KbP2/dwTzPdMBHD+/92
         hxY8Sp9sort1aHHpwLNCkgdhOuE6QC8/uQmWSK0gQzTONzYpbyGAPzog5//Bc5oyIlJQ
         JQ08zig8AikrWHEGYsueLC5YL3ifcCmCpHcdoqb1f2l0LV2KCNqZHjbNgsxhHxQAa9g9
         OM9Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kJZE4GzKvcGO8WeRYfE7rqLuJ6eh1wYdLQCwrjJb0AM=;
        b=LnFWqCLkPy9nHhaCbZYcdSUJjBMvyiTXwSgYpgIvf+fRmDOfOLY1AqABeCu7e19t/K
         QZM3Q8pLaHJ2c8EtxQYFoqqJbo2UNfmZfd9Hj5g3PXphkHXMrcap98IzXZpHBJYBBeFv
         GGKtaip5/N0zaCpEQOxIokle0uYZGpZVecFfXlnRN4S0nt/UX1q0VBJie4fHYbS+RoLp
         N7dVZB3GlPfqAGJg0UuBIvYlZ0W/2rhSUOeSPvYpE6E/0mqJYKLcbM4N0v5v8LZrcGU2
         /oy1h5f2JB68RcyR85MFAFWf9WuAPMpqPB+3/wKK/mK+t6zTzxKkaIRFG3SCUyegKs+7
         FFAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kJZE4GzKvcGO8WeRYfE7rqLuJ6eh1wYdLQCwrjJb0AM=;
        b=svbKJDXtNem4vhnAdhOB89AdpfUUxRYSCT1m/w9cl9zfT1jo5m0D/sRyFLmmExI/kc
         zWGce6Ol2+husrbz8tsT0UDX2ZdvqKm7J2GreBUF3zUqE+jyeutnGzU1hxLkxEoMTssZ
         FclMtf7shplnvGsDF7tK+rBX2ELSrCYeQoYaD/6YuMRJlbUEQprCd2Trv+GtNSBRmjU3
         +LKb+wwaqFK5lS0u58HMNe8OU1nnOHfptCs1+1uszk5bDKMLRs5ptc1Fe7VrqMelBrSD
         0guoMPI0/ViNgDGsqTPKj6LCe8Fl2tPxD8h/iYzZ1OaJpoxj11gii9DP30DpYdaPRCbE
         c3nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZlO+N0uHsDTGkDcawXl2OWObvl0ZqS0k5TpEO9WyaAX2SdKVb
	dHPxpuEEdboQWA6kF01db48=
X-Google-Smtp-Source: APXvYqwWKVPPhmKd2PWmArAK0Zj51TfIkTTN4MFVktdPVA0zGjPmWN7K9I5mWkpUISEMq4pvgsGYew==
X-Received: by 2002:a05:6402:19b9:: with SMTP id o25mr7673136edz.26.1581287097614;
        Sun, 09 Feb 2020 14:24:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1f97:: with SMTP id t23ls2997571ejr.11.gmail; Sun,
 09 Feb 2020 14:24:57 -0800 (PST)
X-Received: by 2002:a17:906:c7d5:: with SMTP id dc21mr9387581ejb.316.1581287096965;
        Sun, 09 Feb 2020 14:24:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581287096; cv=none;
        d=google.com; s=arc-20160816;
        b=t92arhovCmd5SojJynylkKAiOQCjKp2OLIP5eEGk0UrPTuDpRP2ONdpsZQzdlJovpk
         WDNv3gphHYdu9pt3krxDgUh/ZXsyU6v3E8HKBDGFSnWHGI8N3oKk+wk4F3S/xGeXEHSZ
         esQ4Zpv0xsCTQbu5hmFlAEKB8I418Xkt0Vh/dwAl9TxIBfUDgC0GGl3T+hz9q/NKQMXc
         EM+/RaxsiV6L/joBArn5ee5LLuRvWq4GBSV19N/3ha7UarhMIEAuwSWMixihX7tMdO15
         sGO0KOSBLdPFPFV2sYWyHQp04GBbvbPPzOVFoQcfCVMxybrMm+1csclw8baIAgJAvM4P
         HwKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pZloK1j3KMcViPM0mYOaGXZdok5Mk5NKREkeyN+dthg=;
        b=TJnfR56rIZsS7J/zTlVzu1WR+z4VFs0TeV8VNGoAertiGLv5njYReJLq6Y3/Uyfwqm
         yFAiSNZSzyVCfFKXtb8aRJzVWq/j1jAYhT1OFoiYvGk4M+1jgq02jPGK5/ZVlNRsz4fN
         7uQeI5ss1OrDH1CYQU0qSTT7cksade9UMeUrVWyAB/DVsDDEyU2KTV+HylouGspNZ7IP
         TZac3dOSzleGD3VCxc+wjLjkTOUVPhIBn12oSMBERDFHjvL/2EfscJOHI0bWxjabDTxq
         mbNXwnARcatjkgu3WG1IDzBWPEzBlgk2zNmOtsPKxFmLAUY6b/29cab71LkhLVFQgmPW
         WEAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Q+iL70qi;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id x18si221865eds.2.2020.02.09.14.24.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 14:24:56 -0800 (PST)
Received-SPF: pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id y11so5213394wrt.6
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 14:24:56 -0800 (PST)
X-Received: by 2002:a5d:51c9:: with SMTP id n9mr13045738wrv.334.1581287096541;
        Sun, 09 Feb 2020 14:24:56 -0800 (PST)
Received: from ninjahost.lan (host-2-102-13-223.as13285.net. [2.102.13.223])
        by smtp.googlemail.com with ESMTPSA id b21sm13421510wmd.37.2020.02.09.14.24.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Feb 2020 14:24:56 -0800 (PST)
From: Jules Irenge <jbi.octave@gmail.com>
To: boqun.feng@gmail.com
Cc: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	aryabinin@virtuozzo.com,
	bsegall@google.com,
	rostedt@goodmis.org,
	dietmar.eggemann@arm.com,
	vincent.guittot@linaro.org,
	juri.lelli@redhat.com,
	peterz@infradead.org,
	mingo@redhat.com,
	mgorman@suse.de,
	dvhart@infradead.org,
	tglx@linutronix.de,
	namhyung@kernel.org,
	jolsa@redhat.com,
	alexander.shishkin@linux.intel.com,
	mark.rutland@arm.com,
	acme@kernel.org,
	viro@zeniv.linux.org.uk,
	linux-fsdevel@vger.kernel.org,
	Jules Irenge <jbi.octave@gmail.com>
Subject: [PATCH 00/11] Lock warning cleanup
Date: Sun,  9 Feb 2020 22:24:42 +0000
Message-Id: <cover.1581282103.git.jbi.octave@gmail.com>
X-Mailer: git-send-email 2.24.1
In-Reply-To: <0/11>
References: <0/11>
MIME-Version: 1.0
X-Original-Sender: jbi.octave@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Q+iL70qi;       spf=pass
 (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

This patch series adds missing annotations to functions that register warnings of context imbalance when built with Sparse tool.
The adds fix the warnings and give insight on what the functions are actually doing.

1. Within the futex subsystem, a __releases(&pi_state->.pi_mutex.wait_lock) is added because wake_futex_pi() only releases the lock at exit,
must_hold(q->lock_ptr) have been added to fixup_pi_state_owner() because the lock is held at entry and exit;
a __releases(&hb->lock) added to futex_wait_queue_me() as it only releases the lock.

2. Within fs_pin, a __releases(RCU) is added because the function exit RCU critical section at exit.

3. In kasan, an __acquires(&report_lock) has been added to start_report() and   __releases(&report_lock) to end_report() 

4. Within ring_buffer subsystem, a __releases(RCU) has been added perf_output_end() 

5. schedule subsystem recorded an addition of the __releases(rq->lock) annotation and a __must_hold(this_rq->lock)

6. At hrtimer subsystem, __acquires(timer) is added  to lock_hrtimer_base() as the function acquire the lock but never releases it.
Jules Irenge (11):
  hrtimer: Add missing annotation to lock_hrtimer_base()
  futex: Add missing annotation for wake_futex_pi()
  futex: Add missing annotation for fixup_pi_state_owner()
  perf/ring_buffer: Add missing annotation to perf_output_end()
  sched/fair: Add missing annotation for nohz_newidle_balance()
  sched/deadline: Add missing annotation for dl_task_offline_migration()
  fs_pin: Add missing annotation for pin_kill() declaration
  fs_pin: Add missing annotation for pin_kill() definition
  kasan: add missing annotation for start_report()
  kasan: add missing annotation for end_report()
  futex: Add missing annotation for futex_wait_queue_me()

 fs/fs_pin.c                 | 2 +-
 include/linux/fs_pin.h      | 2 +-
 kernel/events/ring_buffer.c | 2 +-
 kernel/futex.c              | 3 +++
 kernel/sched/deadline.c     | 1 +
 kernel/sched/fair.c         | 2 +-
 kernel/time/hrtimer.c       | 1 +
 mm/kasan/report.c           | 4 ++--
 8 files changed, 11 insertions(+), 6 deletions(-)

-- 
2.24.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1581282103.git.jbi.octave%40gmail.com.
