Return-Path: <kasan-dev+bncBD3JJNUUIQIMHZ5MZQDBUBDQSMQIU@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gFcmNMUzi2mhRgAAu9opvQ
	(envelope-from <kasan-dev+bncBD3JJNUUIQIMHZ5MZQDBUBDQSMQIU@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 14:33:57 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF9011B3B3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 14:33:57 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-81e81fbbb8csf5818809b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 05:33:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770730435; cv=pass;
        d=google.com; s=arc-20240605;
        b=d67lMwmRwGGjyRQFitgKYFFXnz0jSkYqzMurMQ0yuo93zGlaa9XA9OjIVufQrWwrgg
         L18MozyqBBKPuW8cOBJClg3O24PAJNfxx3jt6BNRtqL5D5LWC5Berh022D+ER779YQkz
         PgcrGvWCKaC/87iv3H51mr3W6J+fTdKzYbOgmY3zqti+cTQ3z/mnu3q1n6BNe6PH+zO5
         aYCsPw+jl+2OB0F/68azxHAFdq2cCpEzoNmaBTeoXCLO/St9w2X1qU8v2p0HcfUI+fRM
         H3HaTBE6EaNqWs8wWU8VlQeGVRNUtepn++rE5Uebga6d5aH1c/53KqgO93IoPqLudhRI
         KJwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=fWMhKJQYMZreQJ5yZPMmVkV/8tT/Vc7dqzknQ62bkL8=;
        fh=8qyQrwsP5w/Txy+04dlOub4hiuoO6Wpj0ywSZQUhP3A=;
        b=YrNi57IVqOMGLZ82jposw9c/rIuehdmXYSxR10Uon3sbCdzZwwebNRxk1H7GMFQzDJ
         tk0DMv/JNopsqF3CG47aooWaDw3fEWXKNSKoNmp95foHF+JsG3JNf8KkEil71LxbMUUf
         wQnJWpOQBXMV4hoe8V/nroPb+tZLZFOdOmtNuVIy1ojdyf0vRf2oktCsfjkE6qOeI91e
         RGXmVqNv7AGqYov8+GlZr+3p23ufWC9tZnJHUvWoxEG8/Lii3An8Z/r396Nayca4jCrP
         2RGqj5p6HgceahIiC0iyaZBFZ6EmYocHRiFJBo+sRot5xaBR0DgSGJbQGij/pDPzpyS7
         l02Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iTlBpSnf;
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770730435; x=1771335235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fWMhKJQYMZreQJ5yZPMmVkV/8tT/Vc7dqzknQ62bkL8=;
        b=FReqU9SnVYvgJVVTD37kh7mCuXgahsivTPFrBZQSistaDdrxytexOEWatPV0TT9OaT
         S3mkV+Wm2SOC3wAL0jr7eHiK6FRiIR5+tMeBK8hbxYr7mxkp4+X7YsyIjj8eQ9IJ9GOG
         GaNSm/QKM7jXOWbrRILrJXzHh7vxn27/KeGYEdYXf6w8ctrGS8ZEpHJZMcOT5S8sy1vG
         kdEjABZ+zE+ycCINHvbCNGAUEmPKtPI27VmqsrXGzpcajX8WH277XYS2TEI/PJY1qwnH
         5T4zDBREyIGm8cfXhsbzVZITHctuMWJvk0LFtl6jv7zgvUpBUSF9ZLafZNkRunVjqTKk
         nw7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770730435; x=1771335235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fWMhKJQYMZreQJ5yZPMmVkV/8tT/Vc7dqzknQ62bkL8=;
        b=W7zfi3FKNpIPbHBRB37beBzx5cTKdKUxG+TXC+08Gp+zJoufD+fCIQfEwmNkACpLUh
         YNuakMsjvc3eFFRD2Ce4QF5XFLH+W3f/1/RN8i6Q6QLTJ1YScAKiXhfqkOVwoP6FMBby
         tg5A5OmvhXv4K37GHNSWg9hUOEIM1X+vsiEtCw24/vCmu6dnz68rRIvamNU+iTNmnaFH
         vGWgDXI0q1McrMUeZNCOQGoDUK78/J7HRFQf9wvWbObLFWcsJmC53ZlJtYM5RUTkAU/f
         L8zkJkdSX0lH+u5vfpT6c1EcB4AZmpm+sc0ELr70IztuFhLQDKhIKt6EHgyVmvzf3GtV
         aOjw==
X-Forwarded-Encrypted: i=2; AJvYcCU2L3o5WVeDapYOyyK2Pc6pUrERRrOItnfwjgcw1U92gaf7vDu2thYXMdWbqREKuifZNTtjdg==@lfdr.de
X-Gm-Message-State: AOJu0YxgsFZqggKQPwID1Hdd7RrYOC3rFZMEo2ZI0WHpeqVQlQWCVPYV
	wmI8pMJun5rISqGuSWDOztwOivXgl6pgQ20q9cBHYtqVp/2aPP7U39oG
X-Received: by 2002:a05:6a00:2405:b0:7a2:7458:7fc8 with SMTP id d2e1a72fcca58-82487978e20mr2040145b3a.13.1770730435415;
        Tue, 10 Feb 2026 05:33:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E+nU5OTOlU6Yd/A0YlfklNDR+llac4Gi6/IY015dIqyw=="
Received: by 2002:a05:6a00:1914:b0:7b8:4330:bc3b with SMTP id
 d2e1a72fcca58-8242cf34f26ls6541591b3a.0.-pod-prod-02-us; Tue, 10 Feb 2026
 05:33:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFyBdO+dnBT5Bu8T8UAOy6Jo2neSwLADI/qlgwMMtD/W03V0QRXdsHrSfTDMvVZCjyII5X5gaOkwE=@googlegroups.com
X-Received: by 2002:a05:6a00:66e2:b0:81f:9937:2d50 with SMTP id d2e1a72fcca58-82487b039d9mr1839383b3a.62.1770730433952;
        Tue, 10 Feb 2026 05:33:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770730433; cv=none;
        d=google.com; s=arc-20240605;
        b=hDMMbHbpXRNzIhWzpZjw0CLyXgA4zdoa+BLuMK8tSk5UKLe6FvylHCtGGs5Enb4bP5
         +YNTbaPB5OLLaUAdMATjEYkV6VKha6mBRis9LIbnG3FPZlMaS5YzgZZCY/L28DUSjB65
         pa2zl8SlxgRUQ4LtGKaDM/jYzMutsLhaIcMbN8ypoVCb1D7GZEYTGGdMtVRrpEfOS7qS
         1JXNDHMUbOL1FDdMel/sFLCB1msjz2fW7AimfK0W51Ywy5EmawSeDmOt3ekCEK3s854u
         dvjDriw/hdCQ7VuOW+Dsd0AleSqKzKX5OwRgql1vUzVQyL1IKEHRtUP/yw6FAioZZBgh
         qB2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=80t/MzlwjMhst56lm/XISGdDlINSjm3D6bfj3GS7l90=;
        fh=qTnQ7pXroJgkhqbkwdc6fsOsnLapUJnLw6RFWiunw9A=;
        b=P9gbJda5/rgGLiBldIgcIFzLTOSVN8t40bj0Nw0DKJf5Vztn9pazi2w5i9zWeXQXxo
         tlifeKmyViJkF+LRIk1wqwDF0aBXDP5G4eBggwgvQUQf8vdRtw/Q7+XICAyMjvgg/DQo
         yDqDK7sI4ZGHbLigoK4RldIMN0eVJN8ChbzMGTW4qdUd71rpmEVY/WTbNlAKE+Ddq8Sd
         W4xhfWXkVAiByd/U4DBMeKq7dMbkeN1rZ1Fsahf5iXINWNvZdoER5IQ4ZOktQ0m+7/lu
         yy9Nm7KVD5dZ+cffCBgn02OFml0WbmEW9JJ39PMCyZrx3kpH6i8bFTXSyjtHRw8TTs34
         PULw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iTlBpSnf;
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8244166f94fsi418461b3a.2.2026.02.10.05.33.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Feb 2026 05:33:53 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9814D444E6;
	Tue, 10 Feb 2026 13:33:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9F23C116C6;
	Tue, 10 Feb 2026 13:33:52 +0000 (UTC)
From: "'Thomas Gleixner' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Ihor Solodrai
 <ihor.solodrai@linux.dev>, Shrikanth Hegde <sshegde@linux.ibm.com>, Peter
 Zijlstra <peterz@infradead.org>, Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>, Michael Jeanson <mjeanson@efficios.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>
Subject: Re: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
In-Reply-To: <aYsZrixn9b6s_2zL@shinmob>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob>
Date: Tue, 10 Feb 2026 14:33:49 +0100
Message-ID: <87wm0kafk2.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iTlBpSnf;       spf=pass
 (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=tglx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBD3JJNUUIQIMHZ5MZQDBUBDQSMQIU];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[tglx@kernel.org]
X-Rspamd-Queue-Id: 6FF9011B3B3
X-Rspamd-Action: no action

On Tue, Feb 10 2026 at 11:51, Shinichiro Kawasaki wrote:
> On Feb 10, 2026 / 11:44, Thomas Gleixner wrote:
>> > [   65.768341] [   T1296] BUG: KASAN: slab-use-after-free in sched_mm_cid_exit+0x298/0x500
>> 
>> Can you please decode these symbols (file/line) so that we actually see
>> which access is flagged by KASAN?
>
> Sure, faddr2line points to the line the patch touched:
>
> $ ./scripts/faddr2line vmlinux sched_mm_cid_exit+0x298/0x500
> sched_mm_cid_exit+0x298/0x500:
> arch_clear_bit at arch/x86/include/asm/bitops.h:79
> (inlined by) clear_bit at include/asm-generic/bitops/instrumented-atomic.h:42
> (inlined by) mm_drop_cid at kernel/sched/sched.h:3746
> (inlined by) mm_drop_cid_on_cpu at kernel/sched/sched.h:3762
> (inlined by) sched_mm_cid_exit at kernel/sched/core.c:10737

Ok. That's useful and I think I know what's going on.

fork() switches to per CPU mode and sets the TRANSIT bit on the task and
the CPU.

While the task is out in user space and therefore not scheduling, other
tasks are exiting and when this task exits it hits the mode change.

It still has the transit bit set in both task::mm::mm_cid:cid and in the
per CPU cid store. sched_mm_cid_remove_user() clears the TRANSIT bit in
the task and drops the CID, but it does not touch the per CPU storage.

That's functionally correct because a CID is only owned by the CPU when
the ONCPU bit is set, which is mutually exclusive with the TRANSIT flag.

Now mm_drop_cid_on_cpu() assumes for the wrong reason that the CID is
CPU owned because the prior mode was per CPU. So it clears the (not set)
ONCPU bit and then invokes clear_bit() with an insanely large bit
number because TRANSIT is set (bit 29). Duh.

Can you please try the fix below?

Thanks

        tglx
---
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 854984967fe2..61c2d65156b5 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -10729,10 +10729,9 @@ void sched_mm_cid_exit(struct task_struct *t)
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
diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
index bd350e40859d..1b4283e9edc3 100644
--- a/kernel/sched/sched.h
+++ b/kernel/sched/sched.h
@@ -3758,8 +3758,10 @@ static __always_inline void mm_unset_cid_on_task(struct task_struct *t)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87wm0kafk2.ffs%40tglx.
