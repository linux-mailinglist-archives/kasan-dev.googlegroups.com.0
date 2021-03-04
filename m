Return-Path: <kasan-dev+bncBCJZRXGY5YJBBC6ZQCBAMGQEWBULI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5557632C3A7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 01:40:44 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d19sf14291179plr.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 16:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614818443; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYDjIbAuW3BxAVnlZFodhhPWtqvyj2TTk+yZ7ojoSWoGVrxQdL9ScY7YKADnPliCMG
         ufZ8S61CPhEJUT5ZUoiPTO+ZDMxk0SCKaZ8Q19NitksEzov6ccjYKPy2qivQa/G6zRxj
         9LpPrEQPXDXMt9FrtTc1TTr+MbPAUYWNKjjCcLH+Z97pKBDDl9LP+BKrEQ+M7jVD/RWK
         9vZvYS3hANongoHd0/uGirJFCgXlZE8Hl8jXqHcT2/7JMyPfW59eXbPitsqCat7bN7p9
         UHCXrw+bHv3EtpqVKv5ibgdBOk2XT3BKAljI06CZPphzkMKiyfveZb0GajZMLaNOGUYj
         Sqbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=RJDGBTzkespjXtpT02ppGosPRTEbTu+Iuc+NeBm3TqM=;
        b=Ctsrd0ShKyiG8DWNTKWsGhZnHFP7fM843aNAr1Tk5zHI5qpxhNcLrrOd/oFYdrPdt8
         dZmiJUeUv30cA6Dqlu9DPFUHJYuZxVrGaGp849OwUYptDAwt2lDxuACyWtSj9m8h6aME
         yAjlC6fpSgJzm8E3ZDBAALPNPkKgxCgnbqz7AugDN1ZQ1QWKGbJwpM6LRa+c3vJzG0cV
         J88rWl7vPbKOmBgt9BDx01hlxVmi317TL/VFIq+fahzruNrIje8MaynmPh0/cpXUAWjO
         cySLhWs90yrdHljbM/3xLZcvfWtChvat2CAWNMCz++REtRjLEpQ4wn6w/320RiQSfpBd
         hSig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=batTImm8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RJDGBTzkespjXtpT02ppGosPRTEbTu+Iuc+NeBm3TqM=;
        b=PsCt4ptnT4c2HtANXokeAMFiieEdh/JBOpBpeSIALPdqbEJmj6RoVcxMSGfUnPdVXQ
         3uN23ko5oKwpDUom0gzz8UrIBv6ofLGvI+Wu4QBXue/50/N8NG4Khyw/Ckrc2p7sXF+0
         Ops1NEu5Z3bncf4bUflCMAFTYyFVf6fjx1HaAKpM7Nmcsa6VoGz9FmbOx1RXEg9ReUBu
         FUMK/qSkrjp9xYoOyQOpghdwIECRunZa4PxWN2flBs/N2Us28j0Bzj4RRdoiTVn5br/X
         aUqLvp0bDA4c9Od0YOI/j9+KtfY8iCRtbFD0WFMbCag0umH4wLywkmONHERA5p6hZngI
         UQzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RJDGBTzkespjXtpT02ppGosPRTEbTu+Iuc+NeBm3TqM=;
        b=BoqZgG5cANfcdd7YjARVOH/tnPsQpFH/IICUfaC3KgIcaE0rkbrmmKOLNcELIKFptR
         e/2io26DREgpqM10c0VhBJ2az5ZPW6LmKIN1uKPO1W8Mhw+mmD+yiw+VwraE5YvtsO5R
         UjskuLGNOc0cUmcBRO5QZUmJxsEVqpcSAaVF1/wwflpfKxh03tHTtiUfBq3ZlTW3wOfF
         V90VADgEgYBGgVdViXrr/ba5+5IVcSIRRu2M7xgkfurbnAsB8END/Qe+6fPGvgV/+5oB
         U6pHlB6uWzRtg+RBnEkpKznktZ0TSm95LHTuHeqw/CFgz1LTyXgqgcNWNptOuTQ0De2N
         WjRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ruWaO+783XxO2M6JIlQzfkhtVE8oKhJYw1nwrKbuTeI8hnPWr
	8YbB9ZJfp8NsdjbS8/qllKc=
X-Google-Smtp-Source: ABdhPJxm1bUOlzNxTlERx6nUHWpJuvPUIULyEooz9ql1xDlRw+R7K0ZDKg4L4NbaSDYN61dx7jfelg==
X-Received: by 2002:a17:902:edc6:b029:e4:6dba:415e with SMTP id q6-20020a170902edc6b02900e46dba415emr1514586plk.65.1614818443146;
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8b:: with SMTP id z11ls2171986pjr.1.gmail; Wed, 03
 Mar 2021 16:40:42 -0800 (PST)
X-Received: by 2002:a17:90a:5507:: with SMTP id b7mr1753152pji.174.1614818442623;
        Wed, 03 Mar 2021 16:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614818442; cv=none;
        d=google.com; s=arc-20160816;
        b=Q7p9H6wpwM+WnXX75dvhczil4dBQrgWDXTf8eHkCWQjvfwx7WDUI+LZ3dp9SigEWmw
         lFjNT8r+XbPtsIIiE4ykj7RVySIP6xNFhrSuxPR9+USJdvTyiOiqb0xUu5YWKAwwAUUS
         Q7nHtOSlYcSO56yeCUff6dbec9m5vsvBYoBMWlK1o5hg4ndUkKnIyULhEsbh0N/DRPbV
         JtqWyQt6Ck30AGi3fVqAhaK2WaB+YIcS1stRy2I5doeGzxOoRXzF8hetJ+hCXgqvad21
         6p+pvO12yVUmsInynIuVhimiVFoibNGfnVXwgyXXSCOxT1uk3jz4M4agyBi5O79S/s/7
         npeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=0z1IsPGbEedQCeB+flm1uJRlXHNNhhhjygUwJXiX8cM=;
        b=0wQDLJKWk9iqepwKYmDnl9C7ZCOU/yWU9w1OFQwyeYcPRg1CQ+kYBXpp88kgrc4NXW
         KGarL6USLSrxM0zzUWylJmE7OVBRxDbufbpEtPplZdwQVjjrH5ZX1c6tjuwB0tkET//K
         BYU9nPt9t++J9SecXXX/i4yOEFRfKaTNlJqY0hAxtYVSQaWoIXC9oz5TDZCuDEMH5kwz
         Zixbr3g23Wm3N5Td4jxaUf5DMSzMH6sJuiS6ooPB3M6wC30JdbikgHU08IU8LXFlHKA+
         cCZgQLSOKZbfNdAw7jXsDjHRR7zC3kkWvqPBxlGVW8XDN+NZOaw1gaNmRMxaRS2ZIQ3Q
         tSjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=batTImm8;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a20si960698pls.0.2021.03.03.16.40.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 16:40:42 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4F8AC64E56;
	Thu,  4 Mar 2021 00:40:42 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	stable <stable@vger.kernel.org>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/4] kcsan, debugfs: Move debugfs file creation out of early init
Date: Wed,  3 Mar 2021 16:40:37 -0800
Message-Id: <20210304004040.25074-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210304003750.GA24696@paulmck-ThinkPad-P72>
References: <20210304003750.GA24696@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=batTImm8;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Commit 56348560d495 ("debugfs: do not attempt to create a new file
before the filesystem is initalized") forbids creating new debugfs files
until debugfs is fully initialized.  This means that KCSAN's debugfs
file creation, which happened at the end of __init(), no longer works.
And was apparently never supposed to work!

However, there is no reason to create KCSAN's debugfs file so early.
This commit therefore moves its creation to a late_initcall() callback.

Cc: "Rafael J. Wysocki" <rafael@kernel.org>
Cc: stable <stable@vger.kernel.org>
Fixes: 56348560d495 ("debugfs: do not attempt to create a new file before the filesystem is initalized")
Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c    | 2 --
 kernel/kcsan/debugfs.c | 4 +++-
 kernel/kcsan/kcsan.h   | 5 -----
 3 files changed, 3 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3bf98db..23e7acb 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -639,8 +639,6 @@ void __init kcsan_init(void)
 
 	BUG_ON(!in_task());
 
-	kcsan_debugfs_init();
-
 	for_each_possible_cpu(cpu)
 		per_cpu(kcsan_rand_state, cpu) = (u32)get_cycles();
 
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 3c8093a..209ad8d 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -261,7 +261,9 @@ static const struct file_operations debugfs_ops =
 	.release = single_release
 };
 
-void __init kcsan_debugfs_init(void)
+static void __init kcsan_debugfs_init(void)
 {
 	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
 }
+
+late_initcall(kcsan_debugfs_init);
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 8d4bf34..87ccdb3 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -31,11 +31,6 @@ void kcsan_save_irqtrace(struct task_struct *task);
 void kcsan_restore_irqtrace(struct task_struct *task);
 
 /*
- * Initialize debugfs file.
- */
-void kcsan_debugfs_init(void);
-
-/*
  * Statistics counters displayed via debugfs; should only be modified in
  * slow-paths.
  */
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304004040.25074-1-paulmck%40kernel.org.
