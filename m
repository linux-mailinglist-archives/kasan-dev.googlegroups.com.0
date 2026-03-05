Return-Path: <kasan-dev+bncBDTMJ55N44FBBRGYU3GQMGQE55UATKI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gAURHkesqWmtCAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBRGYU3GQMGQE55UATKI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:07 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1500F215438
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:06 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-48071615686sf64750335e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727365; cv=pass;
        d=google.com; s=arc-20240605;
        b=MfuPs9PKgQ3NI7um+KigbrJJ5oN9XdSAUyASFUCxlk5zgRVTCYOuWg2fE91vOo+fJu
         SNu6T4NLHQvFcKIq6P8g5/l4PaociZH7uZq7qSgvkSwBjdYJR1WRRsR0OBOdYgidKPv7
         8axLI3cHur3KIWZBAET6WzmXTgcqr6vlLJ/Gv1QThrJmVPr8Mt+FuJVis75W0jLa1u0O
         IoTixh6sF5KLwgMxmRLtCu3R8BKNQl0JJCNd7a7rHrgWV+2K/alcl/vKCyHEWWgtqo7u
         MVzSRZ0JCTCiizAUsR9XQwjsh/g8yZhigMYy7FuT8chv6yJ3PGToM+U9IjRCacoI1jvE
         zBPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=rQepBhNVXIewScJy5l0F7DYahrf2clMZrHipiqofDf8=;
        fh=l1XMlwJIM6dRx3JOgCIJfNZ36kXy+7sOJyePgsG3sSs=;
        b=Mj6LhcY7JPlnI13FU6md6YggBRLlvx/94wkeTtHdoNl9paXHtHGQBpLH/EHBm76W1d
         mhZL2coNpyQy/12ai6g3K8gyE3iw1L4U4v1RJEtbkRzVvmgYOfm9adFwKKOk+LKwSM8A
         W055dmaZ6LadQqQwnFVdNgjCPy7zs/9FyKRZLRwU0uwa92+oUDQmriyUzZNJtqnB7dkj
         xMUJnTiI70BYm8tFVH4D/uy2e87QUfh0t1Tarw2kNeP4qf7euIdax1MHHImuJ+8Q32Hp
         dP68x/pux9y9p6FkUkjiRxblKLvlWyaO8NT/kD7R1iwuJZF1wvJO3oxj9Kqdrp66X6VP
         BFwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=SMetq6Iq;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727365; x=1773332165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rQepBhNVXIewScJy5l0F7DYahrf2clMZrHipiqofDf8=;
        b=MVAdeV0WQwBs8e4mZ9Fzn5bQzX31f5unp+pA32EogRaZbJUuoQK6hDghvIMGDWI0cy
         T3Si/alpdoyUGvinnWTNf+oDjNNVMThPxx+uIStSRx16o4ZEd0rCew9hoUvcBKdhqGN5
         rzXwb6P6+fOSO2ZxOBb212J+bAjF0vGwuJAZn8LWuyswWZIKxkAi822E0K/LMkgZGg9J
         z+PmkUMB2oSSJ0zsjQhXct9se++gRf4srlPV2WrOaD2ipe2/2Pw+a1m0qL2wftAratar
         w+ybL4UWyBtlBN9dxRMCOixPFyJ1S1dqn7OOkqXoGulit775qvyVW5gjmv97ZAYYyHyH
         8V9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727365; x=1773332165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rQepBhNVXIewScJy5l0F7DYahrf2clMZrHipiqofDf8=;
        b=Mt0wdmYvZ0oz/0POTJA9yQuBJ3tRuv1qSM5HPfBHVNWqUN4JdKVxrOi7eDwM+xuIzY
         a3nUiLf0BABHRKnnQCx/fYsmt9SsrrDrQ0AMZYxsxR/m5ViTesD0l0UX/UVMpjZvThYr
         hXx/WXFQayHYywKmIb73ubt3Q/WSjUqc6Je49HO8wdpgMK90vvO4seKuN9YZHe4kNtsu
         xZt5E/nLit7sh/gyKn/4CzZzwNgD5/HSGTDrUNdaw2EVEyx/KKTW1JaM6v/hqphJv7bH
         RQOaIV8V7twiNaXM+v82n7IHF7cxaeTysnUhDXnd3CW7q2+qWU0xFCE0Cq8/GBz/3BUj
         3CbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3ZmudPuuiCCfB4N5D7HoJ3K8Cn+mq64DlFbFmhKe086+SyJwnGYDbLnUgin3kGWpW4xD7cg==@lfdr.de
X-Gm-Message-State: AOJu0Yw8lCi/uB2xpTUzKAjopk5XPh3+EQFtnhjrkQbF7HXVHft7lXIE
	CdPh0rDBYWVUz1FGymHHZUalTI/Y4o1MHpWtJ5pYxdpDIcdfMmKTN0l0
X-Received: by 2002:a05:600c:3e8f:b0:477:73e9:dc17 with SMTP id 5b1f17b1804b1-485198d8b81mr111331015e9.35.1772727365043;
        Thu, 05 Mar 2026 08:16:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EH4MEYKHLyMpURcb17ZYapFfRTPOCswH3IXwN3GGPWdg=="
Received: by 2002:a05:600c:350a:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-4851d4656e5ls6484695e9.0.-pod-prod-08-eu; Thu, 05 Mar 2026
 08:16:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXA1MX4CUEegkrEbikzpkz/iGXsGjHr36eaESgTK5E7i+4+gQ5do2ZBLwxuVdwONFpRlzouMPnY+9I=@googlegroups.com
X-Received: by 2002:a05:600c:4fd6:b0:483:64b4:79da with SMTP id 5b1f17b1804b1-485198a8a0bmr104901275e9.26.1772727362962;
        Thu, 05 Mar 2026 08:16:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727362; cv=none;
        d=google.com; s=arc-20240605;
        b=P4aZDnqU963l0MaQm/kQ/IS4sBjopJ86Nte377HnxYUtOluN3gAnBC6iBQr402vDoV
         619ypRp5Q3Y8Ee8ONn8KmfQieQ38cbhPvoPFS29Kz3Oj0TdBXeTLgSaP0+HH4ROuQMsX
         ZUcMG2lzpAj6xDwG7cVcSqJ1Kdc6+RK21KsSMNau8zdL1uCYSGsgYp7Bzn53ZsLX5BpR
         fT43yzUs/7PaUYOn4gfebCLB9YxryeGrqU+8s0otq0mP/p7AOZTukjKK0tq2E7Xe5Yht
         Vz2Y4AQeWLWXu0ufVD1Vew5Ul1y603/g83tqJ5TzxPQ0oG1/ZeBSicVob8wh4kVkKUm6
         Qrkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=gAbgyAsT9TtC81lH4Y/jQr/BkNpJoyjPGoY83nTcQMw=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=jfOP3s4Em+AXKcUdH1Jchd+HxRto5b9Os/gOzd2gTQWfwGGc77FhTx6481QDX7ENSC
         BpQrEjOSnN1ko2G1f/ItRNq4k/TXJvuiHEn3qFWXBTw9VQVrRsJxAv+s5KXGSCum9xdp
         H4GDMNRxXh0b5IAgJ/wnDDA8T7Gn2820TNNuTmrYZnmEE7LkatjcCUIFLM8B5gpG8jiv
         SbFYCOYE0fGLPU4NxVRmyqD60BZViuxYhJnUK2rc2eq3y6BC5isbyUOq4rNQb9eQxxUA
         CPqrpJdgCWvL92AbhXJD0XdKFsPc9TW0Dv7BJJipxQQF4vyHbamSh88jLdpYUVyhUBCY
         IN3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=SMetq6Iq;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4851aca3b8dsi674575e9.2.2026.03.05.08.16.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:02 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMe-00Gqq5-N2; Thu, 05 Mar 2026 16:15:53 +0000
From: Breno Leitao <leitao@debian.org>
Subject: [PATCH v2 0/5] workqueue: Detect stalled in-flight workers
Date: Thu, 05 Mar 2026 08:15:36 -0800
Message-Id: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIACmsqWkC/2XNyw6CMBCF4VdpZk1NW/FSVr6HIWYKI4wxoJ2KG
 sK7GzCuXJ7kz3dGEIpMAoUaIdLAwn0HhXKZgqrFriHNNRQKnHFb46zRz7skvF5PkjAmjUnTbm0
 9GrPBkEOm4BbpzK+FPJbfLY9woSrNzly0LKmP7+VzsHP34+0/P1htdKh97j3afWX9oabA2K362
 EA5TdMHq6YERMMAAAA=
X-Change-ID: 20260210-wqstall_start-at-e7319a005ab4
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=5488; i=leitao@debian.org;
 h=from:subject:message-id; bh=BS/RITeYj/f1b7ekg/tvxn8XU+UtVb+pBdBhbPFHQFA=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqawzbK8bSaaxjKTV3jtHp1yYKwh6M88DGc2o4
 PTam1dhgkeJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsMwAKCRA1o5Of/Hh3
 bSTmD/47Zx4/113ovAT0p3wzY7nTeforO2Eoh0UFWCt9zCEUrbIWm84dgt7iqB7qJrQ8sHqM856
 rhJYoDPertlwDym0+Z5HU4ywnL46cXRXWijzroC5LOETgxE12BtXsSirJp3Xjflb+iJ15ayn5Bg
 /29Dger8ImboNFYg07Yvo+IhrEDrHZ57tFNgT4fLi9FavDrdb/VQsvIaHPq6QS4C3Y/MHL9cNu0
 aqpaQyRhIJYOhAQCsuawcm8IWG/Q11eyQGPpasgo6e4+A7A7Dpik0hQ7lb3Ziemxbe65S3yThws
 u99XSZ7IepQ+rz5Agi4A5gJuBkrQjn/g9pBI+Mi1mUj2Q54S2GcVDgv6GUFNDN/6urMF1n88liv
 TcE+0oBgChyewlCSCELdp6f4k352f/W2+NMYbxsqqTmWm147wKI/ESYttgu2fqPX51+TWhtxtZV
 2QBGNMqaRFGV7qQjllmBUSsTHEn/a9bXC11SItwnqnS7XyDjfLCsGBpSor1ERBiwVyXd9QRtvEo
 EJFQPuwFBEqmTs/aQz+F0+Tm4M5qB2WYMy3o/3czyNigkaM0RFfAoTz7yJGOZqc9/E1+BfESXiP
 9IeyStKW2gxIJLJTISuo1n+S+t3P2zTZHZ1k5nLhRxbQcNh+lQgx19SA5X3yG0PZwEHo0MHr82t
 IZEpb1K1550tObQ==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=SMetq6Iq;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Rspamd-Queue-Id: 1500F215438
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,linux-foundation.org];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBRGYU3GQMGQE55UATKI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[msgid.link:url,googlegroups.com:dkim,googlegroups.com:email,mail-wm1-x33d.google.com:rdns,mail-wm1-x33d.google.com:helo]
X-Rspamd-Action: no action

There is a blind spot exists in the work queue stall detecetor (aka
show_cpu_pool_hog()). It only prints workers whose task_is_running() is
true, so a busy worker that is sleeping (e.g. wait_event_idle())
produces an empty backtrace section even though it is the cause of the
stall.

Additionally, when the watchdog does report stalled pools, the output
doesn't show how long each in-flight work item has been running, making
it harder to identify which specific worker is stuck.

Example of the sample code:

    BUG: workqueue lockup - pool cpus=4 node=0 flags=0x0 nice=0 stuck for 132s!
    Showing busy workqueues and worker pools:
    workqueue events: flags=0x100
        pwq 18: cpus=4 node=0 flags=0x0 nice=0 active=4 refcnt=5
        in-flight: 178:stall_work1_fn [wq_stall]
        pending: stall_work2_fn [wq_stall], free_obj_work, psi_avgs_work
	...
    Showing backtraces of running workers in stalled
    CPU-bound worker pools:
        <nothing here>

I see it happening on real machines, causing some stalls that doesn't
have any backtrace. This is one of the code path:

  1) kfence executes toggle_allocation_gate() as a delayed workqueue
     item (kfence_timer) on the system WQ.

  2) toggle_allocation_gate() enables a static key, which IPIs every
     CPU to patch code:
          static_branch_enable(&kfence_allocation_key);

  3) toggle_allocation_gate() then sleeps in TASK_IDLE waiting for a
     kfence allocation to occur:
          wait_event_idle(allocation_wait,
                  atomic_read(&kfence_allocation_gate) > 0 || ...);

     This can last indefinitely if no allocation goes through the
     kfence path (or IPIing all the CPUs take longer, which is common on
     platforms that do not have NMI).

     The worker remains in the pool's busy_hash
     (in-flight) but is no longer task_is_running().

  4) The workqueue watchdog detects the stall and calls
     show_cpu_pool_hog(), which only prints backtraces for workers
     that are actively running on CPU:

          static void show_cpu_pool_hog(struct worker_pool *pool) {
                  ...
                  if (task_is_running(worker->task))
                          sched_show_task(worker->task);
          }

  5) Nothing is printed because the offending worker is in TASK_IDLE
     state. The output shows "Showing backtraces of running workers in
     stalled CPU-bound worker pools:" followed by nothing, effectively
     hiding the actual culprit.

Given I am using this detector a lot, I am also proposing additional
improvements here as well.

This series addresses these issues:

Patch 1 fixes a minor semantic inconsistency where pool flags were
checked against a workqueue-level constant (WQ_BH instead of POOL_BH).
No behavioral change since both constants have the same value.

Patch 2 renames pool->watchdog_ts to pool->last_progress_ts to better
describe what the timestamp actually tracks.

Patch 3 adds a current_start timestamp to struct worker, recording when
a work item began executing. This is printed in show_pwq() as elapsed
wall-clock time (e.g., "in-flight: 165:stall_work_fn [wq_stall] for
100s"), giving immediate visibility into how long each worker has been
busy.

Patch 4 removes the task_is_running() filter from show_cpu_pool_hog()
so that every in-flight worker in the pool's busy_hash is dumped. This
catches workers that are busy but sleeping or blocked, which were
previously invisible in the watchdog output.

With this series applied, stall output shows the backtrace for all
tasks, and for how long the work is stall. Example:

	 BUG: workqueue lockup - pool cpus=14 node=0 flags=0x0 nice=0 stuck for 42!
	 Showing busy workqueues and worker pools:
	 workqueue events: flags=0x100
	   pwq 2: cpus=0 node=0 flags=0x0 nice=0 active=1 refcnt=2
	     pending: vmstat_shepherd
	   pwq 58: cpus=14 node=0 flags=0x0 nice=0 active=4 refcnt=5
	     in-flight: 184:stall_work1_fn [wq_stall] for 39s
 	 ...
	 Showing backtraces of busy workers in stalled CPU-bound worker pools:
	 pool 58:
	 task:kworker/14:1    state:I stack:0     pid:184 tgid:184   ppid:2      task_flags:0x4208040 flags:0x00080000
	 Call Trace:
	  <TASK>
	  __schedule+0x1521/0x5360
	  schedule+0x165/0x350
	  stall_work1_fn+0x17f/0x250 [wq_stall]
	  ...

---
Changes in v2:
- Drop the task_running() filter in show_cpu_pool_hog() instead of assuming a
  work item cannot stay running forever.
- Add a sample code to exercise the stall detector
- Link to v1: https://patch.msgid.link/20260211-wqstall_start-at-v1-0-bd9499a18c19@debian.org

---
Breno Leitao (5):
      workqueue: Use POOL_BH instead of WQ_BH when checking pool flags
      workqueue: Rename pool->watchdog_ts to pool->last_progress_ts
      workqueue: Show in-flight work item duration in stall diagnostics
      workqueue: Show all busy workers in stall diagnostics
      workqueue: Add stall detector sample module

 kernel/workqueue.c                          | 47 +++++++-------
 kernel/workqueue_internal.h                 |  1 +
 samples/workqueue/stall_detector/Makefile   |  1 +
 samples/workqueue/stall_detector/wq_stall.c | 98 +++++++++++++++++++++++++++++
 4 files changed, 124 insertions(+), 23 deletions(-)
---
base-commit: c107785c7e8dbabd1c18301a1c362544b5786282
change-id: 20260210-wqstall_start-at-e7319a005ab4

Best regards,
--  
Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305-wqstall_start-at-v2-0-b60863ee0899%40debian.org.
