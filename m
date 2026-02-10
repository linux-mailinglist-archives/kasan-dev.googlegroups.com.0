Return-Path: <kasan-dev+bncBDBK55H2UQKRBEWZVTGAMGQELSY2AHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CLGrDpksi2lEQgAAu9opvQ
	(envelope-from <kasan-dev+bncBDBK55H2UQKRBEWZVTGAMGQELSY2AHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 14:03:21 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 23AF311B158
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 14:03:16 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-b8709d4ff20sf143001166b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 05:03:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770728595; cv=pass;
        d=google.com; s=arc-20240605;
        b=WheyXrQhn0eTTHbm5iZDopQVUINc3mdYhG8IHGc4hd6lR/fAqVzsaHh0vCusz/K326
         yBs8mAASeHMPtOJC57qRdQRYO6OUrsMV3CsihDeNhA1oDSh30L4H4VbdBNw3vVkJV0vg
         Z9uqvbCX4SeQrCaWgEcPaPvH6/sdlaXl+hq3jR2YgcNLFv9cvVJGT2iwItrDEpxtvD8L
         bE4uYrBlHsR/5oaVmSpjLNSjtrvUfKWuTaIXSFpcoqHzmHCaJnPKQ92sNSaFI7z1y06H
         jXjpA+zwdKknA2CD4mhTiU6aBGkcoiEjGj2oOQ8YeV7lTljzFbQNhHU/b1Jf4PE8ywt5
         HG8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4Y/hRHANezAT9ymydZSolbb7q3JfE+NVKS34PxFStAE=;
        fh=Ygc/JMdpIK+yj5yO2miuLAwn9UfTI83DKHQ/xUXETR0=;
        b=WOurs/HJ/nOe/FsngjNuifBjaUd8gemZG7VKs9pRt1js360MtMj2Glb3f3Yuk5mTN0
         +S/jwpcxKD6VK1un+yhkVTfNhLNwBXKRLL1wQaUylsX5sD9MjzFUeg9MT6Pkk8071+YY
         kevpntjQStoYh4Fnl8pYkrihb5bN8l9vgLue1/wwMqcVZyjpiYCXadPCbC3o3merfax/
         TJ4zWN2NXlSB/ISrkxdor49Jakn/VHfU/IfGzfYbxEZ/It9M9ZQvgrmszW7SCWxeBa3h
         WPori/LPGKLukg5kzYAocFGYDgjqCzXZN7ZQYUhDQl+/fxZsvRKf7HGFrc/hRes34kzx
         bPvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="EtP/dlOQ";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770728595; x=1771333395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4Y/hRHANezAT9ymydZSolbb7q3JfE+NVKS34PxFStAE=;
        b=k1ppWRiMNoJN5OjybFvlBRERZuoDJJLIE52sjoshOv+fzqr2S4KgH38YC65RAxaitQ
         /Et4EEeXICEQSzIroGf+7Swd5XpZAJzto3O04lsD6bqlTu6pPIjvyIx+jqrA/BVD+cXb
         Ei8w/kPM0mdhnmoFX06PDrugQE/8lqo1qiUNfzmUbFz7K98RGtenlkhVY+sz4MrHFsJN
         t1Kp6qCmBd+mUrKFNlQlLHUeqGdykZG0llJO1f/ciQG+LBykiZ7jrKD/VaVA7yGWI+IS
         VpKT8215NYCP2PFX6wTK5MI5lExsk0xFcvsApVn3e9RyeVBKhKXSMugxN4ibGrhmu5Ny
         BrRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770728595; x=1771333395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4Y/hRHANezAT9ymydZSolbb7q3JfE+NVKS34PxFStAE=;
        b=HOFYp0TxvWZiT6vaDuov07mON4misEK9kAQoyYWBiV2GI8mmKuOoPi697Q2om4vsF2
         4G/6H6svr78BwzoQRb6ClqPRb7g+Y00fMiqINQRnv9TCCQS7GLV8dlf1+KjXwBPD4QLn
         BtSQXtfigqmyhpGkhqB/dAwZV9sRoYqylJYezzHOD7ZlTiPPS2CGMCLJcwe+SEpGodKv
         8sBzDOtJSLRwBoiTRG7vDyrW/RPGODNjR6HQSF1alJOnBlHCioKxdL1tCyRR2JAvjziZ
         SqAs6v8qeztlAqmZ8tA1SuSalDuXm8xONzodl9AE16o47Q3zYgGlfvz5Gv+AGGgu9hU/
         CeJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUiIktvbLShzzR3bY4rKvfB9tJ85bauQkyTvJBE0w8YLfB8q0489VoVpgkud2NgZry83hA1ig==@lfdr.de
X-Gm-Message-State: AOJu0Yw/1VsZV9xORJExZcUrh4oOzN3tObxq82r/PtcA6UkPaqztMaDE
	Ho2NNFHpccODt8amBt4ZSzUkPGCIlMxvVUtYrynUS0H5/MpwuEv7RRkB
X-Received: by 2002:a17:907:9483:b0:b86:e937:d097 with SMTP id a640c23a62f3a-b8edf34deb4mr914826266b.38.1770728594648;
        Tue, 10 Feb 2026 05:03:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F7oyxNDfnt3oQH4UT0hVsTmlJbGi6b4JPa/3jPX0QYyw=="
Received: by 2002:a05:6402:22e4:b0:64b:597a:6c07 with SMTP id
 4fb4d7f45d1cf-659621fcf53ls4901643a12.0.-pod-prod-09-eu; Tue, 10 Feb 2026
 05:03:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/fQfjFl01R6+B7N9TubgZj6CtC5/WdAosSBhMd2HS9CbO6kJSzGaaNbGVm8YbnTvInsTxq5ycy2M=@googlegroups.com
X-Received: by 2002:a17:907:849:b0:b87:720c:f182 with SMTP id a640c23a62f3a-b8edf173b94mr785907866b.9.1770728591849;
        Tue, 10 Feb 2026 05:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770728591; cv=none;
        d=google.com; s=arc-20240605;
        b=SCkZwAo4OaiTKm9fiBI8hqofz9IQeQVwbaGNcT74wTL5GggjsGDVc2wEowgpxFJ7PJ
         ou4+cWJ8i+UW4TjjuI7/Y8IvSkvRY6GGoM2hObIDZGJtzHuhI6u3cOd1YK8SCDmKwoOx
         KZ4u34wp1MA/veema9ti0T5Egm0TllwI9Bn0EbL+33lkPTrO3GYRwkl+n8aYvjjshqrV
         g+DPRJZEcR4y97niX0EF0vvzcUGhMKdWDnlPo4NOZUqZ1efvacK8rHLvHEPtHdZ9IfYE
         YYvTKKzHhhOFqyJG7sGNqm1Or0q9h6/hOfD4kCgMcf+9OaUHb9qLmGxIaQywd+TQIBvb
         Dh1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=i/zBtisYtjrdVvQ/FDQxbIL22fhD5YUfBd/rImcs+ZQ=;
        fh=HXUhR5V5/V/yGdbWW1ZGz3QX5MGCo1r9mmuVpQkG2CQ=;
        b=QVGtcepaPTiaLkVWp7BBUmHThtnZOxy7S+pUcPpTIt+bwAzVKdqGRUhS4RNa152O0x
         6nhzrTs4C2BVh3MVzHkZlhQNh6Opzg0TNk96ggBhsk7pTNfbPl/abd1I5IK6r3lolXKc
         czevSSfI5NEu4srWFdNDICy51RJbD06aw06gndPVIcxW5X1G+so1F/VUV1WVbFjwcll+
         AicvcL+7rlbIa8yJXhviE9d5X4l9DHzO8VPT/3mFqO+QgUOUA3aoqXXshxsGc2dHjZOJ
         Lr/kmjwl55ekyf6fY6sJaYQXAEzKsDbJLYNyqFuwrI6fvxgoMtYPqX5RYUsnwRAwaoJX
         CPZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="EtP/dlOQ";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8eda72a7fesi30525366b.1.2026.02.10.05.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Feb 2026 05:03:11 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vpnOX-0000000B6bH-2S16;
	Tue, 10 Feb 2026 13:03:09 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 14B64300754; Tue, 10 Feb 2026 14:03:08 +0100 (CET)
Date: Tue, 10 Feb 2026 14:03:08 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Cc: Thomas Gleixner <tglx@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	Ihor Solodrai <ihor.solodrai@linux.dev>,
	Shrikanth Hegde <sshegde@linux.ibm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Michael Jeanson <mjeanson@efficios.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
Message-ID: <20260210130308.GH3016024@noisy.programming.kicks-ass.net>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org>
 <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx>
 <aYsZrixn9b6s_2zL@shinmob>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aYsZrixn9b6s_2zL@shinmob>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="EtP/dlOQ";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	DMARC_POLICY_SOFTFAIL(0.10)[infradead.org : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBDBK55H2UQKRBEWZVTGAMGQELSY2AHI];
	FORGED_SENDER_MAILLIST(0.00)[];
	RSPAMD_URIBL_FAIL(0.00)[googlegroups.com:query timed out];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	ASN_FAIL(0.00)[0.4.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.4.6.8.4.0.5.4.1.0.0.a.2.asn6.rspamd.com:server fail];
	FREEMAIL_CC(0.00)[kernel.org,vger.kernel.org,linux.dev,linux.ibm.com,efficios.com,gmail.com,google.com,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[peterz@infradead.org,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-ej1-x640.google.com:helo,mail-ej1-x640.google.com:rdns,noisy.programming.kicks-ass.net:mid]
X-Rspamd-Queue-Id: 23AF311B158
X-Rspamd-Action: no action

On Tue, Feb 10, 2026 at 11:51:10AM +0000, Shinichiro Kawasaki wrote:
> On Feb 10, 2026 / 11:44, Thomas Gleixner wrote:
> > On Tue, Feb 10 2026 at 07:33, Shinichiro Kawasaki wrote:
> [...]
> > > [   65.768341] [   T1296] BUG: KASAN: slab-use-after-free in sched_mm_cid_exit+0x298/0x500
> > 
> > Can you please decode these symbols (file/line) so that we actually see
> > which access is flagged by KASAN?
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

Could you please reproduce with the below added?

Just to double check that that cid value isn't out of bounds.

---
diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
index bd350e40859d..dadfd6abc1fa 100644
--- a/kernel/sched/sched.h
+++ b/kernel/sched/sched.h
@@ -3743,6 +3743,7 @@ static __always_inline bool cid_on_task(unsigned int cid)
 
 static __always_inline void mm_drop_cid(struct mm_struct *mm, unsigned int cid)
 {
+	WARN_ONCE(cid >= nr_cpu_ids, "XXX cid(%x) out of range(%x)\n", cid, nr_cpu_ids);
 	clear_bit(cid, mm_cidmask(mm));
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260210130308.GH3016024%40noisy.programming.kicks-ass.net.
