Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX7EU2QAMGQEDIVRAGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id F339F6B211E
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 11:18:07 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id e17-20020a05600c219100b003e21fa60ec1sf589988wme.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 02:18:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678357087; cv=pass;
        d=google.com; s=arc-20160816;
        b=cYaODGycaRpxlRfNIlQm4lbkU7Zmtv8/2jTzmR9AyaPELNh+qUpydJGGf/891ZuzB5
         YQk+1Yr8D0QaycKOdgmnkjY3MvmvhU6n0FiJIH/0f4bKc+yOYqH3ipElQm+ml2kdjx9H
         snvPqtH/5/f+N6MQIazGkBng8BORBOeG9RAwlJsN58KJSXex/M60MGuRAdaRyQi5OgST
         KM7v0dJCvVfjujfWSqvF7/R4ifwlntorKvb3ulcrBBh1sBhLmOtEP/Fax2+FGogktPhm
         Zs4mogumg3ZamTgi4+phNy0EMYYrvsKbX3sg2wyxCw9tKQG0blLS/d4TcI7lDJ/6uaii
         B4VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=z5fwV5+MEkNkGCoP8Sc/HxkQXwCcQDBF4XUUGzkDhKQ=;
        b=QfyE68kxiKtlhenbITAXiG/0Ostl5PpO34Z2dTPDtBayLP8AEG04MbjSGtNFtqUukE
         yJIYe8gw25hahCS3oR1GL+2H6CsawtsWBPeLNSptosbT6sowTsoIyHggzEZv2XHOcfRW
         4/QUmYhbS4rd4shoAf2o3Ujwtwnl0F/UreWvNul6KdiAh6eU8f65YlwFtk7svVWQQEey
         F7CDhMvbb/JWlKMr8eZ6fAkD4K3THRL01fvzS+sZAGTlgyIkFlXXZyWAFR5NaoIDKbP0
         8nJimdQl9R8LlljMOciMnVVwwxqa7tH+NNpJqDoE7srA6HlepkMbvDuE7SIJ8/Xjq0Ty
         hpSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="e/3pzWXG";
       spf=pass (google.com: domain of 3xbijzaukcrau1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XbIJZAUKCRAu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678357087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z5fwV5+MEkNkGCoP8Sc/HxkQXwCcQDBF4XUUGzkDhKQ=;
        b=T7poQdPC3AuEAbQHSQ8B4yqDL8ABQ3LpOTHbH1vbbDsZpPiLWQR9ioUK4UGzVZuyqC
         d97KRuWXwm2NTlN6zgKOr0vzkkheGQRjJ1Li2oRCj4Up5TMB3RBrI+/H58QBRaF8QmFY
         0L9DeHDeNYZw3Y413izLgJcj/mUEXtmXieuld65uR3h11IjB27yT3kp26Lyp+Z9IOOgK
         U3W+kmS8IcQo+kw2gfMJsRxWhPBOckBEhDcTiALVw8fPPc9O5OgFzBpxvNUp4FqrI5Pz
         0l/79aow4xhiYdpe0OCZJomZ1brnCwrJF+6dkRgI01xEwa9j3DxDORFpm29gqz6s9eIX
         HjNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678357087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z5fwV5+MEkNkGCoP8Sc/HxkQXwCcQDBF4XUUGzkDhKQ=;
        b=mFx6k6wmM9pid4VAmMqcFcUA5mCga9hNilaVPgsgr2CH6ZvY6/R6M53YzIOV9SMvD1
         b4u6fSTjYDWBTOrKHW1bJ+yQ1ezYa3aP3OWCQyj8z1E/qGZBOPl1lZmB94IP/1lqptyw
         f3pq9/Un17TkxCbGWGftZx1AQ8PRGTjfuh0EHTmeHLqzPmklkcansfPza8GdeM3ocTEk
         EESfvWRZcQSPjHKnsKu88eGJ5r7yP65ZUtCAs9vAD3KqNS1AnBjup4ndR70Uzsu8fOWq
         W3ftyQRFV9IZZUS9SNvUxMZfFL6/Rw2yes3xO9Xncw4EklWTAHK9Cb0WSZe8FuUqXbBC
         hlTQ==
X-Gm-Message-State: AO0yUKXf/q/92Rvzyn/fyqtaxPTGnHhn9OW4DlsZlruYRNCSXYiKZJt8
	rsb5zn+Iao/6sy/jqd2Rwmg=
X-Google-Smtp-Source: AK7set9e+bMpsDwwWS56SBdt1tl14nRsKK8PShKK6rjTGxa3u80AE5Gs/IbunbB861oP7eBOGThhzw==
X-Received: by 2002:adf:f006:0:b0:2c5:5aee:a2a4 with SMTP id j6-20020adff006000000b002c55aeea2a4mr4636444wro.6.1678357087310;
        Thu, 09 Mar 2023 02:18:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47a5:0:b0:2c5:953c:231b with SMTP id 5-20020a5d47a5000000b002c5953c231bls679282wrb.0.-pod-prod-gmail;
 Thu, 09 Mar 2023 02:18:05 -0800 (PST)
X-Received: by 2002:adf:f8c7:0:b0:2c5:52c3:3f05 with SMTP id f7-20020adff8c7000000b002c552c33f05mr13767136wrq.37.1678357085444;
        Thu, 09 Mar 2023 02:18:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678357085; cv=none;
        d=google.com; s=arc-20160816;
        b=UsjCH6840dEdND44VDiQ2Ic5IBh5NrYDTGL00JPiblhhqo3uAcwQb8dDQgiz1e3PAR
         AXugBHweHxKLBNivKqyPxXz6QTdrociMik6lr3MWEKjhALwbun/Wc5FYCIBPrL8zu6KW
         FWpooLEYwBOAjhyXf/ZxhhnXBO4UDi1Kb0yiwkiipNsFcj32GhCiZPUJXNvafT59zGDG
         Px1HyYMzQp9R+nSh281S1AyPhzEOXDlPxhFNXMD9jNPO7xIX6m5Tz1FMnLbeCZ4ejcuw
         yRuMkqRCf+oQXnAokwZiAUcYbw7oD4aDSlw+GCVart7+vjrP77mM3PfGydMHttdLzqrO
         D2Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=/g34wc/bzNoY5huESod7peN9hpH8a494unvdVXAlQmU=;
        b=Z6FgCUjqeX55RiVSpwf3599fuDc2UOeDSRqFY5kApfKwck/GzzOutwJakzVW4QmZ3w
         1Pfy72c99K6equ0LKEBvUam5KxXaD+OoDcQCitZydMAMtZy+k4dOM/0CPDnf34ECi4sE
         B+BjYa7D715Ks368ChdmT7k5LNa6wm41pkgqX0TWK4x8Y2Cbasd+kVwMigifuvOSJVdO
         SXTKfHfhR8DLWuRFIMmX1Rrqcwi8JYb0uyDSwzwBzfknNQ82wonvhhIUPipjST/VUSYA
         3P6gccyonWRxQ1c58IiI8IodsA7oL9y632VWNUGXDmHqwg07CcJO0LP0WloDZWpY129E
         O1SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="e/3pzWXG";
       spf=pass (google.com: domain of 3xbijzaukcrau1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XbIJZAUKCRAu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id by7-20020a056000098700b002c685ef5fe8si857592wrb.5.2023.03.09.02.18.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 02:18:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xbijzaukcrau1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id g2-20020a056402320200b004e98d45ee7dso2321076eda.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 02:18:05 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:2628:265b:fcee:2ca0])
 (user=elver job=sendgmr) by 2002:a17:906:d041:b0:8bf:e82a:2988 with SMTP id
 bo1-20020a170906d04100b008bfe82a2988mr11015180ejb.4.1678357085082; Thu, 09
 Mar 2023 02:18:05 -0800 (PST)
Date: Thu,  9 Mar 2023 11:17:52 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230309101752.2025459-1-elver@google.com>
Subject: [PATCH] kcsan: Avoid READ_ONCE() in read_instrumented_memory()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Haibo Li <haibo.li@mediatek.com>, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="e/3pzWXG";       spf=pass
 (google.com: domain of 3xbijzaukcrau1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XbIJZAUKCRAu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230309101752.2025459-1-elver%40google.com.
