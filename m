Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2MC4SQAMGQEANJJYVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E52E26C26A2
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 01:59:22 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-17abfe9fd10sf7871741fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 17:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679360361; cv=pass;
        d=google.com; s=arc-20160816;
        b=htIaPB/Frnz5l3yIWzDantgY3PkuFYV4zIk/GJ5U5D3yIGGgXgN5l1pjDQ0Rzrztrm
         0aGmC2rVHCA9nYs6/Q+BW13pSJ6aIyw9X0aQ+wn0RZp+G2rr7xG6VhF8dr0SMjwz4veO
         BSDT8Xv0epD04a/8t3hH+gBw2bSc4Hv7YfICwCBN4GIbXuBmhO87xvV00iZjTfpDbdKw
         cosIDdLEZeB6QvFyVd3Il0LlIuF/Sos6okHrg1ebs3qnXGWY9GArof9jgnF7nx/w9Fdz
         C10knWAlv14bmZp0n4S1brvOguydqdgxHvYE7mfQK2dHX5vNfGD+D+lC4+3/NB2/Cg06
         +S/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pH16nGFjipwC/tVZ58KqpVpshVnLXMaSfeMRtl1W5+Q=;
        b=kqaRw81DEtAS9eNXIE/Lokph5jy7EyG7VMdjwMHC9bUqBoyiqZK3+qbamq2Pdu4ckO
         6T7lNdBoG5083mkpM5fBtwMWbspxXaWO51XnjxJprwCFJ8m4B8Xg4S/bTuJvMR69LhZv
         N4jmn6tmanwIApdM6+I3zLZq8sdRLlK+2rr66/OgpGsRaOvHglY5Ho1QjWSRkJjeHqxu
         +qGKQK85wRF0w66W7SuZtp705bNoQweW7sZ/lpJUW+5+d8ZO3pz87SAe66Ii+23lkCRm
         kONhakwBE7s5EoWvYKYwqi43XmxZ2TzcA8M1dHoXz3D1oxm4UJ4VELgUb0HMo4ZrEl/V
         133g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LT+TRtQR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679360361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pH16nGFjipwC/tVZ58KqpVpshVnLXMaSfeMRtl1W5+Q=;
        b=iXp/KXsTsMG3LZOo1+HWKrnvAMsinU/1ymKKMM1lP5sGHIrhiLeBj2Ap9ZDC6gbdQn
         XF4puy7GFlQX7kN79LDqk5oFztFt/ZpmQ4S71kyJ4JiL95CoE6jvub0tuXY1E0A7OQ3k
         /RCwOZj6tzu00FEMgCkE+8FdcUarPlhadS1PwkWc/SxT9dZcBx08rr9bQZkUpbPRfXuv
         OMO5iwmrGalPt4fbdB/PF2dGO2QyJGelmBMnJ7GBKcGwSSqqX/tZhLHIeEX2FV8mY1GE
         aVarLeW4/9h40pmPNLIEmzptADTe7r0L8CfdPzkeGxgce9veGOJ6DG/E8LnYM/2QI1Rq
         UYIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679360361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pH16nGFjipwC/tVZ58KqpVpshVnLXMaSfeMRtl1W5+Q=;
        b=Oos2DrvKw3gREq8qhCquiOQr2OpFHKCuWb4PQcxW0WfU4Jb+5UuxoBR87kppGHQndm
         M8v11EzprcK3Ip2eO/Ti0TQQev0j7lPAhJrUxOeeptjTYm7979DbEL7yESGOiJCgz+jy
         WfJoq/JHldbOkC+i++tmD9qEj3Q0baGpPKX+d1Xfr/iRHQi9s6RA5BQN5fCVAom8f/YB
         lDGE9SOAPexRx93R4jU7EijdVbqLaE54DeOxhbOZbAZHLLOgSFz++LODmk5Cm9iPryox
         QA9FW9KfSIVZqL8x127rHKY7Z9a79x0EwG8rPVfBMgSLsCHv0DFpxrds8LC7IbPATuvN
         cMaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUhT+I+hXxAo9dvl0QlbSF5abr3Qr4fNBvf/36xyrrvkNZqfzNG
	AAKRrXIHpdWNYvwI9waNr/pApg==
X-Google-Smtp-Source: AK7set/eXWGjaN4wYLCKXr/dkwgey0fzFx5HQ3Cs7ogVLespNbEMbs5T8L1S/E0BTdslCSiKRp1yzA==
X-Received: by 2002:a05:6871:e83:b0:17a:a52d:9df7 with SMTP id vl3-20020a0568710e8300b0017aa52d9df7mr93997oab.4.1679360361204;
        Mon, 20 Mar 2023 17:59:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d0e:b0:176:30d5:30b9 with SMTP id
 pp14-20020a0568709d0e00b0017630d530b9ls4938791oab.9.-pod-prod-gmail; Mon, 20
 Mar 2023 17:59:20 -0700 (PDT)
X-Received: by 2002:a05:6870:702a:b0:177:8ae3:4f7b with SMTP id u42-20020a056870702a00b001778ae34f7bmr176302oae.33.1679360360674;
        Mon, 20 Mar 2023 17:59:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679360360; cv=none;
        d=google.com; s=arc-20160816;
        b=pnv7Z+B2Mxe7tA13GbwLRkuN+mE6bzIw7Li8P4RT89ZZnjaEc974VYGWiJvfiC/pmy
         UB1Kp5980tLtGsn4oRB3PdFQUpAl1csCIjJUNe/lziWU/7OREdae153hGBkB7my2JnAZ
         fJtrGr1UrYcIbFRu1T/dVkGtbs3/I0rKVKTznLCcG7sASqSRvJ3Dek6snns29fnLcB4z
         DsKeImdPZPq+oJ2xsXLto35wCoM/+p86dJStNruLL5KthhKcXKHy2IMxJKiFFutz2vlH
         114iKmYVlyI7UXGErJeVb2JolCArfCNszphYd0PX+oGJfyCBeyRSCigrHOJrSYY2684n
         YqpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S8bnayLZDLGhD8KnMoZ8NWh3xtXEOtQCCpoXsHo/doc=;
        b=vFSwQT195Ptbr1ryT+RtmJ1qc7AVYT4VXI1G3z1Iu9BDTdKl7nlp73vbwFajIYzV9i
         m09+KnICFpWcrSPWMDpsGVht+2zdGR8MnJT/wh/M5+25Y9LTopYEX8/TMGRNeVkrLRa8
         JICgeUO/Gh+jtOYZM0OjnEqIZict0sE1ss4OYkkRc/OTWzbL7ukSQ1yUpFn/+YhZo4hQ
         uDdtDfJh+sB+Bmd6HeZE6yS73/OFJGv9KRJakyJvSzkMpx0aXG2nGe1ekxITylz5Rtru
         eReYf0i91/GP/IwLle37RJYK/qFO0UYokKiNm9b9LcAFIpB4SQAprLSSt/DHkZL8GeRV
         CaTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LT+TRtQR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id lm9-20020a0568703d8900b0017b0d68e731si720684oab.2.2023.03.20.17.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Mar 2023 17:59:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 49053CE173A;
	Tue, 21 Mar 2023 00:59:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 935B1C4339B;
	Tue, 21 Mar 2023 00:59:16 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 28DF9154039B; Mon, 20 Mar 2023 17:59:16 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@meta.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Haibo Li <haibo.li@mediatek.com>,
	stable@vger.kernel.org,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 2/2] kcsan: Avoid READ_ONCE() in read_instrumented_memory()
Date: Mon, 20 Mar 2023 17:59:14 -0700
Message-Id: <20230321005914.50783-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.0.rc2
In-Reply-To: <a26f2bdb-1504-487b-8ec8-001adafc5491@paulmck-laptop>
References: <a26f2bdb-1504-487b-8ec8-001adafc5491@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LT+TRtQR;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 2604:1380:40e1:4800::1
 as permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Haibo Li reported:

 | Unable to handle kernel paging request at virtual address
 |   ffffff802a0d8d7171
 | Mem abort info:o:
 |   ESR = 0x9600002121
 |   EC = 0x25: DABT (current EL), IL = 32 bitsts
 |   SET = 0, FnV = 0 0
 |   EA = 0, S1PTW = 0 0
 |   FSC = 0x21: alignment fault
 | Data abort info:o:
 |   ISV = 0, ISS = 0x0000002121
 |   CM = 0, WnR = 0 0
 | swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000
 | [ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,
 | pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707
 | Internal error: Oops: 96000021 [#1] PREEMPT SMP
 | Modules linked in:
 | CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted
 |   5.15.78-android13-8-g63561175bbda-dirty #1
 | ...
 | pc : kcsan_setup_watchpoint+0x26c/0x6bc
 | lr : kcsan_setup_watchpoint+0x88/0x6bc
 | sp : ffffffc00ab4b7f0
 | x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001
 | x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80
 | x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71
 | x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060
 | x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000
 | x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0
 | x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8
 | x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007
 | x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70
 | x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000
 | Call trace:
 |  kcsan_setup_watchpoint+0x26c/0x6bc
 |  __tsan_read2+0x1f0/0x234
 |  inflate_fast+0x498/0x750
 |  zlib_inflate+0x1304/0x2384
 |  __gunzip+0x3a0/0x45c
 |  gunzip+0x20/0x30
 |  unpack_to_rootfs+0x2a8/0x3fc
 |  do_populate_rootfs+0xe8/0x11c
 |  async_run_entry_fn+0x58/0x1bc
 |  process_one_work+0x3ec/0x738
 |  worker_thread+0x4c4/0x838
 |  kthread+0x20c/0x258
 |  ret_from_fork+0x10/0x20
 | Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )
 | ---[ end trace 613a943cb0a572b6 ]-----

The reason for this is that on certain arm64 configuration since
e35123d83ee3 ("arm64: lto: Strengthen READ_ONCE() to acquire when
CONFIG_LTO=y"), READ_ONCE() may be promoted to a full atomic acquire
instruction which cannot be used on unaligned addresses.

Fix it by avoiding READ_ONCE() in read_instrumented_memory(), and simply
forcing the compiler to do the required access by casting to the
appropriate volatile type. In terms of generated code this currently
only affects architectures that do not use the default READ_ONCE()
implementation.

The only downside is that we are not guaranteed atomicity of the access
itself, although on most architectures a plain load up to machine word
size should still be atomic (a fact the default READ_ONCE() still relies
on itself).

Reported-by: Haibo Li <haibo.li@mediatek.com>
Tested-by: Haibo Li <haibo.li@mediatek.com>
Cc: <stable@vger.kernel.org> # 5.17+
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 17 +++++++++++++----
 1 file changed, 13 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 54d077e1a2dc..5a60cc52adc0 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -337,11 +337,20 @@ static void delay_access(int type)
  */
 static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
 {
+	/*
+	 * In the below we don't necessarily need the read of the location to
+	 * be atomic, and we don't use READ_ONCE(), since all we need for race
+	 * detection is to observe 2 different values.
+	 *
+	 * Furthermore, on certain architectures (such as arm64), READ_ONCE()
+	 * may turn into more complex instructions than a plain load that cannot
+	 * do unaligned accesses.
+	 */
 	switch (size) {
-	case 1:  return READ_ONCE(*(const u8 *)ptr);
-	case 2:  return READ_ONCE(*(const u16 *)ptr);
-	case 4:  return READ_ONCE(*(const u32 *)ptr);
-	case 8:  return READ_ONCE(*(const u64 *)ptr);
+	case 1:  return *(const volatile u8 *)ptr;
+	case 2:  return *(const volatile u16 *)ptr;
+	case 4:  return *(const volatile u32 *)ptr;
+	case 8:  return *(const volatile u64 *)ptr;
 	default: return 0; /* Ignore; we do not diff the values. */
 	}
 }
-- 
2.40.0.rc2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230321005914.50783-2-paulmck%40kernel.org.
