Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSWIUGQAMGQEW632DMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id BF99E6B0466
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 11:32:43 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id p36-20020a056402502400b004bb926a3d54sf23108206eda.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Mar 2023 02:32:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678271563; cv=pass;
        d=google.com; s=arc-20160816;
        b=erCArCjOlh/B0/5oCnjSJelZrc0/8Q70BRxPgt+ivkZPXnX+plZL4lcHQUNi95okTw
         xW4N+O2ahMP5KqN33EI7co0eCH5XzsX+r4JV1I2Kf/DVCKNluOwI+ACstHpH4GASP7sG
         faWNjARL/y1OENmnRcCs+W+FFFyZ4c9XreHRYKPg1l8hO3a3djtI77FbO/UYDJA/PrF1
         mz0Kpx0YGKnBgdK6rDYuPP9ZQjzZAWcYnlNDo6MPuUKX4GhzKIs11YfUIh2V/pIUErc7
         OcfD7qJhuthV+Z4HlToxG5FHrzzctqdVLnXhSGfs7pzHNTXPltlsdm3dSfuyeseYpfir
         OngA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fl6KSB6FrYeftlx65OyRSe8qz7vqYnaDS5NYQ4w+BOY=;
        b=GXLVfPrg7cprxkT9qgLyuX5tLPmIF2wzpqCMlQ9GI2r6YflfBGZwe7IMqTjQx8h2TT
         vTazTTUSPeqJW8w6HHMKb5vk1zffskG+Kn9rk+y9m3VeQVyhBo1Mo9BEYb81j0CTkujk
         n9fdGSYRzJRgxR+5rPAi8r72vCKp/BlxPIHCKuNEWxA6fPbY5XIxVLtqUiem9WBr/gOa
         xMJV/XdHDyLrKlZ9dDAvi7lxRjRXcYuYCO0a5mUAL097gDMCu0//kGuPbUOIA3TVRVoI
         jYMDOKJHj40B/6jLlgMBG6+L+Pya7VqM6yZoVavtmTJBxc9v5cxpePj/D4KSoapa2aeB
         7yew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GwQXQzmm;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678271563;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fl6KSB6FrYeftlx65OyRSe8qz7vqYnaDS5NYQ4w+BOY=;
        b=EGOMuAxmeR3P1VYUaQeOzoCxpI8SW8b6YmRcLDGqsaKaZvdxY7aAqjUd0yPNpYIlTs
         CaAcZ8Ja374Qp/vP7Qg/LJtSpwzZ5G3UYbdx0NBsV+BWteRsPPreGMF1qLVn9GYHWTOM
         OwBRy3oFsJn6zjIw8Dx+BgSV+jVR4TIJg9cZe9otINcaaBLBceQOGkhbRvYKezwvPdHo
         p/dnXgepaT7Bj+4oym7upHwmAo+1gS71TMntg/9KvKdErWV4YB2+JamLxQYL8rk37Wav
         98997RpHaTDecAqzn7blBO2QuSMdYZKnHcXB4RsDRdCzATcJluYzQRghzlTco569mb2t
         51Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678271563;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fl6KSB6FrYeftlx65OyRSe8qz7vqYnaDS5NYQ4w+BOY=;
        b=f78ADeMtwTZUTFtYPj+cECswA606hxG5x8HFlTmYM2GMnFKyN1uNJpZVBSggw61htC
         WaOAXYnmneo2sTQeFmy9kOpk570TSJ4jVJ+IZw28YJhi3J9vpmA1e39NMTahg8/5kQGs
         4hUFH5B/d6z75sSjDWzStLm5YcBayV8c1aV2/9ABI7QXQVOLI8188uOMKozW9E3dh3uD
         vkbuVefodw8ke5VvldoyQ7heOQaAF8lGlnymJG1jBQE7+8KDr16Tox+Kka5uP30DMuqw
         SFSELiAP4KvqZNYJOqtQlP0mUjc5N6hnvQRwLeAZFj4B/5Atfx1+MeccV3F7HyKIg/qu
         AtEg==
X-Gm-Message-State: AO0yUKX4j0qDOP0FqCamDtTZmS4ED3Zxeh+2o3qIiExT7z5LVjAhETQh
	qSGpxcz5qFeqTo0YUE7Eq0Y=
X-Google-Smtp-Source: AK7set+kt69qlCIiJkvK1M0fyOovS6rSHnz86mRTLJid1p06UU9dpVFghhwLepq0usnVZjoJsUf+Ng==
X-Received: by 2002:a17:906:a14:b0:8b2:d30:e728 with SMTP id w20-20020a1709060a1400b008b20d30e728mr8920090ejf.1.1678271563056;
        Wed, 08 Mar 2023 02:32:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2216:b0:4ad:73cb:b525 with SMTP id
 cq22-20020a056402221600b004ad73cbb525ls4086733edb.3.-pod-prod-gmail; Wed, 08
 Mar 2023 02:32:41 -0800 (PST)
X-Received: by 2002:a05:6402:3d2:b0:4ac:bde4:ff14 with SMTP id t18-20020a05640203d200b004acbde4ff14mr16619044edw.42.1678271561571;
        Wed, 08 Mar 2023 02:32:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678271561; cv=none;
        d=google.com; s=arc-20160816;
        b=OUfYRFy2cS8rfgHEWs6cUt02xFPJv/UwsVMIwyBYYsaQEloZcGLu7O9v1JiJFNlqcH
         3h10Z5e59C+o/z344V7AqlJE85CFNMyAqKwLf+9b1sck2NSd2ZgxibKXXmaymnO3HG4R
         kKO9rPVZUetjcinxYnMY5DFr4HFC9vcfuP1C/H36nEqnDmyMkWFp73Gmi6V/yZrTLorN
         LR5rcH80XkTUv/DgHsMVcnDbxirCyXGgLmN3ZgwKSmpG3cqoq6LJN5HGBiuQ+fM33ojN
         yoNriLIjYu68qdgHCezAFdTEVuv5rr7vfxXvQ5BXNZmkYnIwjNEDu9iVGlT813u8HU7s
         Lskg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QTpI/ATF+c54SwR4NIfut5ZP/DAkJSYP7eEYSoHEoTg=;
        b=h42NgVselBF7G8neUP0nfYhrQEImAWGm1STa8TrY4fWkeOEkWhox8qfyfmKzrppSDn
         78bmhQvpN/UfN2Z4lSBV457Rwt/jdEMQwb/O2lFNZcUsu0D5N2/40k3ayfRmp3ZEHS7x
         hrIXZazG+PBkBVJsQ0CufD409eJ2AAPFBkBOqDGLmQHUHTwUaoAuE0lmAbUSaTXAnR/B
         WpoHonbHPi5GFpW0tZ5IE17t3fS/8DJ7prGbEoYmMIFhAAswl5eHyAZbAfBtGrpm43Go
         I6NB8uwGqp/iYmh/3qO1+8YsurBCfEPvdkKNusL3j5wllHBy+TP7wr/K4do/4becPse8
         /seA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GwQXQzmm;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id m1-20020aa7c481000000b004bbea073a82si571826edq.5.2023.03.08.02.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Mar 2023 02:32:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id p16so9477715wmq.5
        for <kasan-dev@googlegroups.com>; Wed, 08 Mar 2023 02:32:41 -0800 (PST)
X-Received: by 2002:a05:600c:4692:b0:3ea:f73e:9d8a with SMTP id p18-20020a05600c469200b003eaf73e9d8amr15409084wmo.30.1678271561077;
        Wed, 08 Mar 2023 02:32:41 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:ba88:6ccc:13c7:4bae])
        by smtp.gmail.com with ESMTPSA id s25-20020a05600c319900b003db03725e86sm15243907wmp.8.2023.03.08.02.32.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Mar 2023 02:32:40 -0800 (PST)
Date: Wed, 8 Mar 2023 11:32:33 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Haibo Li <haibo.li@mediatek.com>
Cc: angelogioacchino.delregno@collabora.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, linux-mediatek@lists.infradead.org,
	mark.rutland@arm.com, matthias.bgg@gmail.com,
	xiaoming.yu@mediatek.com, will@kernel.org
Subject: Re: [PATCH] kcsan:fix alignment_fault when read unaligned
 instrumented memory
Message-ID: <ZAhkQUmvf1U3H4nR@elver.google.com>
References: <CANpmjNMj3JX6d=HS=CNzxZPZcJZWfz0G5wKmJjfGb_N525NNLw@mail.gmail.com>
 <20230308094101.66448-1-haibo.li@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230308094101.66448-1-haibo.li@mediatek.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GwQXQzmm;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, Mar 08, 2023 at 05:41PM +0800, Haibo Li wrote:
[...]
> > > x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000 Call
> > > trace:
> > >  kcsan_setup_watchpoint+0x26c/0x6bc
> > >  __tsan_read2+0x1f0/0x234
> > >  inflate_fast+0x498/0x750
> > 
> > ^^ is it possible that an access in "inflate_fast" is unaligned?
> Here is the instruction for inflate_fast+0x498:
> ffffffc008948980 <inflate_fast>:
> ...
> 	ffffffc008948e10: e0 03 1c aa   mov     x0, x28
> 	ffffffc008948e14: 06 3a e9 97   bl      0xffffffc00839762c <__tsan_unaligned_read2>
> 	ffffffc008948e18: e0 03 17 aa   mov     x0, x23
> 	>ffffffc008948e1c: 9a 27 40 78   ldrh    w26, [x28], #2
> 
> And the instruction for kcsan_setup_watchpoint+0x26c:
> 	ffffffc00839ab90 <kcsan_setup_watchpoint>:
> 	...
> 	>ffffffc00839adfc: a8 fe df 48   ldarh   w8, [x21]
> 
> The instruction is different.READ_ONCE uses ldarh,which requires the access address is aligned.
> As ARM v8 arm said:
> "
> Load-Acquire, Load-AcquirePC and Store-Release, other than Load-Acquire Exclusive Pair and
> Store-Release-Exclusive Pair, access only a single data element. This access is single-copy atomic. The address of the data object must be aligned to the size of the data element being accessed, otherwise the access generates an
> Alignment fault."
> 
> while ldrh accepts unaligned address.
> That's why it is ok while disable KCSAN.

I understand now what's going on, thanks for the analysis.

Can you test the below patch, I think it is the correct solution for
this - compared to your approach of opting out unaligned accesses, with
the below there is no loss of functionality.

Thanks,
-- Marco

------ >8 ------


From 889e9d5ce61592a18c90a9c57495337d5827bbc2 Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Wed, 8 Mar 2023 11:21:06 +0100
Subject: [PATCH] kcsan: Avoid READ_ONCE() in read_instrumented_memory()

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
Cc: <stable@vger.kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
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
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZAhkQUmvf1U3H4nR%40elver.google.com.
