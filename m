Return-Path: <kasan-dev+bncBD3JJNUUIQIOZNNNZQDBUBCS5JRUC@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AM2GH+9ai2ljUAAAu9opvQ
	(envelope-from <kasan-dev+bncBD3JJNUUIQIOZNNNZQDBUBCS5JRUC@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 17:21:03 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1238.google.com (mail-dl1-x1238.google.com [IPv6:2607:f8b0:4864:20::1238])
	by mail.lfdr.de (Postfix) with ESMTPS id 10E2C11D119
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 17:21:03 +0100 (CET)
Received: by mail-dl1-x1238.google.com with SMTP id a92af1059eb24-126e8ee6227sf1060234c88.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 08:21:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770740461; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bu24PfPm42WvX+vFUvz5S6d1bhPwrROvkVjgHyh6/sJMBoXuB9Z3sRKHtWhULr/60x
         7zc8qNQp0l56xCHuQviHZX9GviZVlST8j6TUs/99+dqVEZsik/LQ5tNmArQLtXbIde+g
         JTQ1PgHnOUinGV3PrwfO05yVvLvYB4y5pHrqr1YIBl2YlIVWdiwfrcUS1IHkfV0et2RW
         a2hvGndpJbjAHcQl3o7OPb79PCl6fpSxRR+QEsGtLRK1LbXNZ28EwJtbbUy9515n7RlW
         aR5brldoAzn11Ja1WrNbxRTd9PQz4Q8skHLYZRJxRa3TowumEd3k8Wor08jNqv8gRfsR
         SMgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=4i/jysH0kXSKuhePcYYeouBzQJIQc4evoZzRas2+F44=;
        fh=BEopG/1vaJtvKWKGv0AMSEGUiM46qtPoGk+XOqJqGZw=;
        b=Tid0L077F10WTmKbMwEOW3RJJ4hUEmpqntq0gayByxiiqMQS2KcFdO7L4HnrvsUd6Z
         kJmIYvuLr0IGnLmxB4CBeh5RplfR1M7amlTF6ypRypkbHhnBNJnRn4wwJsD/kSUnLSgV
         o8j6sUiVFz39wCv4W5zV6ptU23jgxGievrWFj+Vt52rPxD4vXqA2EpxTFTJLgEX1ycbG
         FezcsvBW+dM+C2vHc1B9LWBrtA3Hn+Uujxy7QX0uUlT3jQBHYq5neeXYapq12XwIJUnk
         VNpOohs+VMP1EPNNyosA2+TckxywLjDfjLBXPNFweHnBvN4T2p8d1nn3oNtoH4qcuTOe
         313w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=izdaravX;
       spf=pass (google.com: domain of tglx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770740461; x=1771345261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4i/jysH0kXSKuhePcYYeouBzQJIQc4evoZzRas2+F44=;
        b=JCw9Pm0iHPxXoXTCpik1FpWfAppIVx2mNrkOa1BGAsUdirZ55PsHz1K1C8UKCJrL9S
         9pSBwP3bFVNHFd7KNdYEpS6c/2v1wdWShIfwS8INAt0BD57mkYJVkVBWZ9Vbzh+Z/mY6
         LlXLvM1h6bKEs9gejaMQZYHbSVpopHQr6JHdg3XHGoYtxjtCJ0WyNAysCyGrNBqoWPCi
         G/G/rirlRDtjDwfbq78GdfZTDNGauE4wCPfUcAgWWvaMzqDwDg0lJnYg3tZuWMbPBVfR
         Drmcai4DsVQp7a5dds6bq6Q6BbGYqdYt9eK8MNZr0z3K4JMqGz1fZili9a4mNlyhimEA
         Q0/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770740461; x=1771345261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4i/jysH0kXSKuhePcYYeouBzQJIQc4evoZzRas2+F44=;
        b=HB6Wl6Gr3s2H5G28qoQ2K7P/bcuHiZO4voK03P79aoHMQZDUZYhoIbse0e+YGNDqm2
         6/u6xK5NUh1JaOJZvfiWvji2vYTRRkjuMCzZL9rnSQ6f/osQA/cAJsBfgmByu6i37nb+
         0fAMbZ/9kf5DmgasBTevAmQMHcs4POqN0JeTcxoRAq76Pfb1QpuUhse/ERx6/CyErTzX
         fR7mKYJ5rPCOFdpOaGViAtmj990+iopVIQuU6w/oWVL0un7j9kQS71nldIYuiQhuKVm6
         KrkZ9HcdfGFnvA3k+MMBw7plqz43JTh+U2J/SNhn6FTy1ABb6IP2kN1fPZkGhsAcHb3T
         Ksdw==
X-Forwarded-Encrypted: i=2; AJvYcCXHJSQoUmX6aFnTc87LEk+YINiTgYlHHcznvCrSBmL5WA+EV6n+ictKj8d3PG3CmgNhKgZZsA==@lfdr.de
X-Gm-Message-State: AOJu0YzVv0bxh8Vb460sNfzxx57P5CzwncP0sfO4tqkJxXVq+hqVKe7g
	ws5QJLO+9ExewQxzYMoxRqzdreLgCs8FZbUMrZr9VRTqkKtC5SnLacs0
X-Received: by 2002:a05:7022:68c:b0:11b:9386:a38d with SMTP id a92af1059eb24-127040996f8mr5967557c88.48.1770740460680;
        Tue, 10 Feb 2026 08:21:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EOQmiP13BJ+sk9mIAIExs5f9Aehxehnsa+r1RPtz+5aw=="
Received: by 2002:a05:7022:23aa:b0:11b:519:bafe with SMTP id
 a92af1059eb24-126fc140212ls2150536c88.2.-pod-prod-09-us; Tue, 10 Feb 2026
 08:20:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVhhcu0+nxvtH82o3AspmeZZ2g9yDQlXcWJQU432tTt5lDjJedmGwWEgdprChHkxyU2QikqtGm4unM=@googlegroups.com
X-Received: by 2002:a05:7300:a144:b0:2ba:8496:498 with SMTP id 5a478bee46e88-2ba84962a08mr1880194eec.7.1770740459111;
        Tue, 10 Feb 2026 08:20:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770740459; cv=none;
        d=google.com; s=arc-20240605;
        b=W6RlO8yS4EagFYZqgEqCOBnY18NS0kSzJMF8J0tWJEKMM9lI4djvFSb4YINxzHSI0+
         iB6IccSROjIOXOUYqIWJI0mW7gBw5f6S/lJE+vtT52nK/IbFsAfWF3GA+msyySUhd/RU
         irXMEdTeVOPXoBqNu+LQBnuN8O1lJwxSB/H1It3goJVqrSN2oFkfknyxLj6m4TPq5y2q
         z5EI0Yi7Zq2HekVMPw4mVXAHSKxzCFfG5kMwv1/H2G6fJHp86t0Vq+6mb8OjHH6bGno3
         znmc/d9jrlJdnbgiyZfTlezUuFdnDztE8/KOpAFu4pPLKJQbgc8fnOu8HHPNte3TlrPR
         upMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=e24UH3aVlDLWiEe7yyTRfulExPd4P+UdDsn1Oty4D6U=;
        fh=3jfenXqmOsh28/lUBzv/+w5hR5+TucjgTCmEylYb5HQ=;
        b=jSSHZKhDmTl5ooJtV7D9SscQSia/IJLxsTBAiRsnnmBZUsRq7SJ6nA62zmI2pUktD6
         f/K/SS3fqMg2cOrwZnpPfPXlbVY3FwnHz/qcCEIXBcqOW3lWeWuTuqaetskxB00jlAiN
         IA2UOjRNiRxvXZY03FBeEF9zxTcgvvqZYPP1FjqOstzu90qck1HaV4+CnZfswqKW2Xw2
         Yc78JxsH1YisoAB1W0CzPzekaGuoZ2w4s8c6tGXPpfCdRag9A9IAf8lSrn215yVvl2rk
         tIn/8ljeLkObMiRDRSfBZ8Zzof/eRJEPOoUJAc5r7nMdHlz+CQzlVMEp/GSZwLb21TOM
         9Tdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=izdaravX;
       spf=pass (google.com: domain of tglx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b855ac2b50si477870eec.1.2026.02.10.08.20.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Feb 2026 08:20:58 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id A887460097;
	Tue, 10 Feb 2026 16:20:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 33C60C116C6;
	Tue, 10 Feb 2026 16:20:55 +0000 (UTC)
From: "'Thomas Gleixner' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>, Linus Torvalds
 <torvalds@linux-foundation.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Ihor Solodrai
 <ihor.solodrai@linux.dev>, Shrikanth Hegde <sshegde@linux.ibm.com>, Peter
 Zijlstra <peterz@infradead.org>, Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>, Michael Jeanson <mjeanson@efficios.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>
Subject: [PATCH] sched/mmcid: Don't assume CID is CPU owned on mode switch
In-Reply-To: <aYtE2xHG2A8DWWmD@shinmob>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob> <87wm0kafk2.ffs@tglx>
 <aYtE2xHG2A8DWWmD@shinmob>
Date: Tue, 10 Feb 2026 17:20:51 +0100
Message-ID: <87tsvoa7to.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=izdaravX;       spf=pass
 (google.com: domain of tglx@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=tglx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Thomas Gleixner <tglx@kernel.org>
Reply-To: Thomas Gleixner <tglx@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBD3JJNUUIQIOZNNNZQDBUBCS5JRUC];
	FROM_HAS_DN(0.00)[];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	FREEMAIL_CC(0.00)[vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[tglx@kernel.org];
	RCPT_COUNT_SEVEN(0.00)[11];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,wdc.com:email]
X-Rspamd-Queue-Id: 10E2C11D119
X-Rspamd-Action: no action

Shinichiro reported a KASAN UAF, which is actually an out of bounds access
in the MMCID management code.

   CPU0						CPU1
   						T1 runs in userspace
   T0: fork(T4) -> Switch to per CPU CID mode
         fixup() set MM_CID_TRANSIT on T1/CPU1
   T4 exit()
   T3 exit()
   T2 exit()
						T1 exit() switch to per task mode
						 ---> Out of bounds access.

As T1 has not scheduled after T0 set the TRANSIT bit, it exits with the
TRANSIT bit set. sched_mm_cid_remove_user() clears the TRANSIT bit in
the task and drops the CID, but it does not touch the per CPU storage.
That's functionally correct because a CID is only owned by the CPU when
the ONCPU bit is set, which is mutually exclusive with the TRANSIT flag.

Now sched_mm_cid_exit() assumes that the CID is CPU owned because the
prior mode was per CPU. It invokes mm_drop_cid_on_cpu() which clears the
not set ONCPU bit and then invokes clear_bit() with an insanely large
bit number because TRANSIT is set (bit 29).

Prevent that by actually validating that the CID is CPU owned in
mm_drop_cid_on_cpu().

Fixes: 007d84287c74 ("sched/mmcid: Drop per CPU CID immediately when switching to per task mode")
Reported-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Signed-off-by: Thomas Gleixner <tglx@kernel.org>
Tested-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Cc: stable@vger.kernel.org
Closes: https://lore.kernel.org/aYsZrixn9b6s_2zL@shinmob
---

Linus, can you please take that directly?

---
 kernel/sched/core.c  |    7 +++----
 kernel/sched/sched.h |    6 ++++--
 2 files changed, 7 insertions(+), 6 deletions(-)

--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -10729,10 +10729,9 @@ void sched_mm_cid_exit(struct task_struc
 					return;
 				/*
 				 * Mode change. The task has the CID unset
-				 * already. The CPU CID is still valid and
-				 * does not have MM_CID_TRANSIT set as the
-				 * mode change has just taken effect under
-				 * mm::mm_cid::lock. Drop it.
+				 * already and dealt with an eventually set
+				 * TRANSIT bit. If the CID is owned by the CPU
+				 * then drop it.
 				 */
 				mm_drop_cid_on_cpu(mm, this_cpu_ptr(mm->mm_cid.pcpu));
 			}
--- a/kernel/sched/sched.h
+++ b/kernel/sched/sched.h
@@ -3762,8 +3762,10 @@ static __always_inline void mm_unset_cid
 static __always_inline void mm_drop_cid_on_cpu(struct mm_struct *mm, struct mm_cid_pcpu *pcp)
 {
 	/* Clear the ONCPU bit, but do not set UNSET in the per CPU storage */
-	pcp->cid = cpu_cid_to_cid(pcp->cid);
-	mm_drop_cid(mm, pcp->cid);
+	if (cid_on_cpu(pcp->cid)) {
+		pcp->cid = cpu_cid_to_cid(pcp->cid);
+		mm_drop_cid(mm, pcp->cid);
+	}
 }
 
 static inline unsigned int __mm_get_cid(struct mm_struct *mm, unsigned int max_cids)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87tsvoa7to.ffs%40tglx.
