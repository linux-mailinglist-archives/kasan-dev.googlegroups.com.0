Return-Path: <kasan-dev+bncBDS57ZERWYERBB6J4HBQMGQEAJUVGWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F22B0831A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 04:48:41 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-748fd21468csf524789b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 19:48:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752720520; cv=pass;
        d=google.com; s=arc-20240605;
        b=NWWTqf3WloUDe0jcIUivVHoxX5ucIrappi4H4loOEPygmp/QM/g8akGPfn7NT6vezh
         KVehFN/tVuJEHwxIwCx4+ffENXnRHAAuOcIuRYS/VnSrnMNJ/DYJp9tvbb+NuVg0dYJQ
         cI/Kz3hXtvYJkXyOH7AhZbsWiwhoFSLPyqWuJG9z7bPceAi3C3ZzCZZ2p2Mx/22ZFVPk
         aCRgm0vEHqoTnH33UbZ7Hjix1zP6xxHWxfRApMvuIdmYTRJjSEMujFZgMwlvWuQX7iiF
         wMC1BqimcoIn+UZl1Uud9mTUgi1x1dU9zx/kUzt9hhn1IwEyc3opaJQbJ4Ib06dUZL6r
         HfwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=d/7q3WDKOhbNUSOFVhKxJIUuvAztxg5ctVXspbZzmo4=;
        fh=zhzdIho0+FC9AIZzK264YK71FyyhyKdcIT2FgjJc574=;
        b=IdXCpUP2tPP6oXqQsvTl3H9bntJLqXDsBMkSxjW0parekPFyaOWeQg1XSZAnHgFS9K
         /OVALr32rX7WAyK8G24pwjXXs42E3Nmaoes1ynIkeEPd8zutun3lbscGjdoojnDUepNr
         2kWIg5GJarfZkcxXH4gUnah+IHtvNygSSmAHViOgSz/CyFeZimp4lTmcfc1P3yHJCyaS
         DzljDKp9UBYJPiHxWjuQLaLkqGpmWntoadZ7VADQol9z080Xe1tcdYNDot/CfF173W93
         z+LkW+ROTw/YPODhZ8lGvNuND+B9BUssPtel/O14e9FlqQqPdOU7i7E2hBvImqLjBMzu
         NHdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.36 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=fail (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752720520; x=1753325320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d/7q3WDKOhbNUSOFVhKxJIUuvAztxg5ctVXspbZzmo4=;
        b=awPidckXxKRrS8pO0QpLAPwN5zERPZuGFUHD7iBjuYDhfuFI1cJQtLqJ3BNQuSuQjn
         l/qs/VrWup6SZ6R7rj9+AymN1eoVlgnYTC26aGyBtom66GIQ1vjROFeBS7bKQJ7EG0Hn
         qXKB6+ST0eyArZVkvF6Swl08sWap5SrtRLDJ0PBVJ+IPscFjquxzCtWEMhPPysNb+ZIH
         6unrnRJMF3T0ST5IVG3+fodDyts6+B+zS3sLZPxSiH8/f6gkc9fnUqKSDBZZ61/UABqA
         wrgoY7wbXJMZbcGzxwyEcAjKsCqJcqc6ranl4NNuE2xuqKXhbc/aYgUheZgyM2Vt4Cz0
         vkAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752720520; x=1753325320;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d/7q3WDKOhbNUSOFVhKxJIUuvAztxg5ctVXspbZzmo4=;
        b=W+7EPqCmMi7qbz4REKZLRv3ZE6Y6kQ4NSEK8wWcZeevQXJlzhOXnPQrsnVDuAHtRmn
         3Ol7RgiS2pyfzP4LFnyML+pdxPnNwYdskt8D+TLyYLUXNliVqOmYcCwXoDB3i3LZBC6B
         lceolNeRPAg/kz8OoEgigDqUNx25Wc2nWgvE+S7aEc5lqJlkRXLVqu2Oij390Gs+CoOW
         jtgn8v9BxHI0pIkDVUnBmn7bRvEbbKRximUWXSUig+czG0J66umFXEsZEBYvWldU2JV+
         p1YDkIFKHT2WJsFns28BucTDuXOFsYFsSrzJFr2SelT+PAiaTMi7b9xz0PCKYORVg7xq
         hr0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUt7o9q/hXADOh+IyzpX4WsxRzn1DhajS0IopnFt0Lk9+vc/7Ebbvmol6iX9M4eXd0TqNgTXA==@lfdr.de
X-Gm-Message-State: AOJu0YwGwBBK5x2xuzJYMRxpcXNSNAO+JJtyFHE6E1bxQulVmEs8u0mv
	FBe38qcZGlZuox/FS2/wm2vCIVsktluYQAikeWnPS6s+FI1B4jxskoRZ
X-Google-Smtp-Source: AGHT+IFuVR14L5d7jxrKiTH+fn3EPnJoJbHCh0V9nG9lryg8jxuwoLcWG9lMaJCpetWsLlZD2v6pSw==
X-Received: by 2002:a05:6a00:3e0a:b0:742:aecc:c46b with SMTP id d2e1a72fcca58-756e99fc423mr7309877b3a.15.1752720520047;
        Wed, 16 Jul 2025 19:48:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSdKyvxSHmo6Iv0OnVhE6BcdFyPY7mel9unk0mionDLw==
Received: by 2002:a05:6a00:2351:b0:742:c6df:df28 with SMTP id
 d2e1a72fcca58-75827017ca6ls522317b3a.2.-pod-prod-01-us; Wed, 16 Jul 2025
 19:48:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5t1TLasU+3JslDTDnPT8DWnllcSw1BQhIjv2/P5re4IeZP0gIbHbg3T43UdbXWO4sxEbUBqRVXKA=@googlegroups.com
X-Received: by 2002:a05:6a00:240d:b0:73d:fefb:325 with SMTP id d2e1a72fcca58-756e7acfeb3mr6270676b3a.5.1752720518179;
        Wed, 16 Jul 2025 19:48:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752720518; cv=none;
        d=google.com; s=arc-20240605;
        b=akIJ7jtW9U2W7DelzhTeoHNmV5UXOjZTmpeoTWevjmVgWe2hj0xs4EBBU7m3ZygVNb
         Ga97sJOIHjtreE9NpzwlvucIh1fl52hbzFelm+Lwuh8+GCsbCGmARwa3qCEN9LiMTds6
         pj3m/BJR9sAKy6Nr+gzM6wHo9ljRjXGdAmo7lLg11cKUeUmtN63nb1Kly0eWZ8GwlaEf
         IfhWOWClIA74JI/mquCClfBSH/izajx5CraP8QNfEGu3GXZBdwU/2UoyJSoFJRU1qEQi
         rNijSm7v7AjIKRiX3vDq/Yepv8sL2YlBssaPuzLS6GL4smIwLdPxm2ov+HgVY4SXBk8Q
         ECyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from;
        bh=uVBTJYDoE3CTwiyZ+iPp2IvpC3xzk0UwxkIw18YyUbU=;
        fh=MUYNtN5EDJlVzFGuDoc1cLXowvJu7tZ4DRYjDx/Hkhc=;
        b=TKxtRCaGrch368Yi7q/nPVle4FfAFNL3KuBUUe+611d9O8S5ITqXt992arwhBr+PxY
         7PiJhB1HG59sFDEuZbVSdUd8aw+pbFH74RMrHWdkskok7/k5feoRNJhgOwEfR/EHyfCr
         OhEV5F+BycaNcRoSbl1pPB1orGfcn5KrVl3SlMIUXep9O1hEzxXmXOjqgduIHGq28n7x
         7nL0Y9JugepikdgJCOBJSGPmQnbIen4BLi8aUL+MayK1v/13xlwQ6rLwLQf2tH1NLuKO
         jAsh6FearqliO5We/0DaR/A4D0XhcrtCLBNuV+1Lra/tTiEyXuvmpHXmG053DucTy8fG
         2WaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.36 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=fail (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from ipo6.cc.utah.edu (ipo6.cc.utah.edu. [155.97.144.36])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74eb9e220e7si628755b3a.1.2025.07.16.19.48.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Jul 2025 19:48:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.36 as permitted sender) client-ip=155.97.144.36;
X-CSE-ConnectionGUID: PtUaXuSkQEK39q3iMm/F3w==
X-CSE-MsgGUID: 8CCVDYOAR5O+Xjf2s9ij/A==
X-IronPort-AV: E=Sophos;i="6.16,317,1744092000"; 
   d="scan'208";a="122990153"
Received: from rio.cs.utah.edu (HELO mail-svr1.cs.utah.edu) ([155.98.64.241])
  by ipo6smtp.cc.utah.edu with ESMTP; 16 Jul 2025 20:48:37 -0600
Received: from localhost (localhost [127.0.0.1])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id EC504301D66;
	Wed, 16 Jul 2025 20:46:59 -0600 (MDT)
X-Virus-Scanned: Debian amavisd-new at cs.utah.edu
Received: from mail-svr1.cs.utah.edu ([127.0.0.1])
	by localhost (rio.cs.utah.edu [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id vAeJmofh4QWz; Wed, 16 Jul 2025 20:46:59 -0600 (MDT)
Received: from memphis.cs.utah.edu (shell.cs.utah.edu [155.98.65.56])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id 9829F301201;
	Wed, 16 Jul 2025 20:46:59 -0600 (MDT)
Received: by memphis.cs.utah.edu (Postfix, from userid 1628)
	id DEE3B1A029A; Wed, 16 Jul 2025 20:48:36 -0600 (MDT)
From: Soham Bagchi <sohambagchi@outlook.com>
To: dvyukov@google.com,
	andreyknvl@gmail.com,
	elver@google.com,
	akpm@linux-foundation.org,
	tglx@linutronix.de,
	sohambagchi@outlook.com,
	arnd@arndb.de,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] smp_wmb() in kcov_move_area() after memcpy()
Date: Wed, 16 Jul 2025 20:48:34 -0600
Message-Id: <20250717024834.689096-1-sohambagchi@outlook.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: sohambagchi@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of soba@cs.utah.edu designates 155.97.144.36 as permitted
 sender) smtp.mailfrom=soba@cs.utah.edu;       dmarc=fail (p=NONE
 sp=QUARANTINE dis=NONE) header.from=outlook.com
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

KCOV Remote uses two separate memory buffers, one private to the kernel
space (kcov_remote_areas) and the second one shared between user and
kernel space (kcov->area). After every pair of kcov_remote_start() and
kcov_remote_stop(), the coverage data collected in the
kcov_remote_areas is copied to kcov->area so the user can read the
collected coverage data. This memcpy() is located in kcov_move_area().

The load/store pattern on the kernel-side [1] is:

```
/* dst_area === kcov->area, dst_area[0] is where the count is stored */
dst_len = READ_ONCE(*(unsigned long *)dst_area);
...
memcpy(dst_entries, src_entries, ...);
...
WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
```

And for the user [2]:

```
/* cover is equivalent to kcov->area */
n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
```

Without a write-memory barrier, the atomic load for the user can
potentially read fresh values of the count stored at cover[0],
but continue to read stale coverage data from the buffer itself.
Hence, we recommend adding a write-memory barrier between the
memcpy() and the WRITE_ONCE() in kcov_move_area().

[1] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/kcov.c?h=master#n978
[2] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/dev-tools/kcov.rst#n364

Signed-off-by: Soham Bagchi <sohambagchi@outlook.com>
---
 kernel/kcov.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bd..d6f015eff56 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -978,6 +978,15 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 	memcpy(dst_entries, src_entries, bytes_to_move);
 	entries_moved = bytes_to_move >> entry_size_log;
 
+	/**
+	 * A write memory barrier is required here, to ensure
+	 * that the writes from the memcpy() are visible before
+	 * the count is updated. Without this, it is possible for
+	 * a user to observe a new count value but stale 
+	 * coverage data.
+	 */
+	smp_wmb();
+
 	switch (mode) {
 	case KCOV_MODE_TRACE_PC:
 		WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717024834.689096-1-sohambagchi%40outlook.com.
