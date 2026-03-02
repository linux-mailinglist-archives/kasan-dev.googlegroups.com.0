Return-Path: <kasan-dev+bncBCM3NNW3WAKBBQPISPGQMGQECS5E6WQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eLjcKUT0pGmcwgUAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBQPISPGQMGQECS5E6WQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 45D521D2723
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:56 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2adda5a44d8sf39696505ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 18:21:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772418114; cv=pass;
        d=google.com; s=arc-20240605;
        b=TX2S42qExY0FRmN+zg7k/EjlqYHG+/5u/UcWdOE6uvRwNtok3sgeBuQTbtNkbr77Ee
         o7XvkDltZJ5LQfCSpx09d6nsiSZ5nKYky1C/sNEjzvCWs3wpoAC9iZVU1Qjw9qJfo0LP
         xPo4K5ccGq9mctOQB9cdVLzt+lZQeLDEm/19VBi+nNvZFQXzyLlZurqrH7FBt0pBD0in
         vYmNLgVYAnwxkFrJ2OuVITXfq+XEQdGj4MRBS0ACAP1dnuM6+PdwV4BYeKmKyTzjTd+2
         njbnXCDE9wKF6VaKklA6P+h3xxUVTRar0Kk0vBzmq8StdD4vjOcOJJooh1XoOesGwW9h
         qnCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=L2OWPPAKSJ8yFv8bFWMH69XSzx/36Ymak3ZVRX/xfJk=;
        fh=42cka1FdojebTNjM/lkcFV97IGVCx2zveF9XFmmV61s=;
        b=h4+JEe2YhVAR3E/wes6a7DXcyAsM/mqXDJfPom+kXA2W5Fk3kcTG2bUAWbzIPX7y38
         riW/745Q1Ha9UDM/O6tA9JZNILFgaMOEOh/xGVTkWoAiGEHNIFegJbfVTRN2sCwNUJeo
         R0+XgYbfc6OP0twC/doAudRK+3s+tsOZPNFS6759QWkUFj1VZzRDPzSp95+zpdFeSUIu
         H1wE98y8pO9ga9xxOkS/vDd0BDgOGjeoZ5j5FIuac5UB68LA0T7LG6lAKIeiqVqcgLlF
         E9u5h0Jb5tHGl+APkaEiEvVPTgc8GAkHxtyBJ9SwcpaekWkDc+xh/LNw00UVa27TncyD
         2Jmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772418114; x=1773022914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=L2OWPPAKSJ8yFv8bFWMH69XSzx/36Ymak3ZVRX/xfJk=;
        b=fliu7uFzfi+SXImIq/KKfyog8lw2d073Ui1BvUqm2YVICnlp6buDpsv8ZGNN71C/ek
         fM3fVpeAuN5GoaQSEWY/TscGZPs4/UjjWE0siQlxAE1rouzmis+lxmRRIg7SF9FLImpp
         Sd/ymS4by2FUKGo5S3lhDiX7wwDZNKaqycS3UMWlDh2Y9TFT9S2N4yM+PwQ87pgRXYno
         5Rw30Cg5Xx/iLnL3tlbgCyvdWrXW6v9BNt1AL7PuiaYQDnA0SsalqaWZX196ryxOeknO
         0wy79yjnCFyNMIlct/UdrmcmH10SDkko6DTYuHbOwBuyJeZCb30CE4hTe4J+6J4OAodN
         FqvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772418114; x=1773022914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L2OWPPAKSJ8yFv8bFWMH69XSzx/36Ymak3ZVRX/xfJk=;
        b=dkqON0N427rBtENn4j7gOAApd3G3M4c6eOXgWXnAMjmuDv+ThtglSEBWaIdmCjmPk1
         xrhTGsUZs0mlmgdH5GZrO1NmT9f08mnU0ev9bAA2eTE3xB3tvaSC2XoXmwuVIA35iIBN
         a6gy9OHfBaKexvEXG1O7ihb/dc60OWJfi/61lgfSXhwZ6r0iCLBWJIsfm0qOewOr3GAb
         iGNTaVb8+Zq5EHg0XAEp2TSnNVmJWgp5itDNb41rur5TRNMf1m4nceQffEiKq7OMlCUM
         ddRHLIQ/byvT2hhnUAoMdoRuDwqHpZpTHecEl+OVgeJ6XWLT68MnX6ljKs/OzTD0b9TC
         i78g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7XSAUCGu7CQ79ZyA9n4OHHmtDaasQg27ja4sV6fYR+5U0vN2K+fpjuGkv8RvvfqU9NLMMIw==@lfdr.de
X-Gm-Message-State: AOJu0YyjnS3dXF3yMb8kxa9P3zpqWUF48bijcxsVinOFF0Pn3H7EKVoc
	5aiqeH1aBrXiJW1c39+inZ5FdL69Dn+nQH+v1YElikNIDvylvwnmpnDr
X-Received: by 2002:a17:902:fc46:b0:2ae:3f3f:67b8 with SMTP id d9443c01a7336-2ae3f3f7187mr64569775ad.15.1772418114263;
        Sun, 01 Mar 2026 18:21:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HjuY21xxLYqPYLP8dK4LSAFS34URwZv0s2rt5w7a0ZEg=="
Received: by 2002:a17:902:fb10:b0:2ae:5102:3027 with SMTP id
 d9443c01a7336-2ae51024d65ls1896075ad.1.-pod-prod-07-us; Sun, 01 Mar 2026
 18:21:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWSeQd1xctGEAIy8IcXBhFoqgikunVLxvev0GFBaS9pZcrw12a/xjEJBUCChMJSiPcrDVvdkQGpk3s=@googlegroups.com
X-Received: by 2002:a17:903:2a84:b0:2ae:3d7d:d905 with SMTP id d9443c01a7336-2ae3d7ddc86mr51165705ad.23.1772418112859;
        Sun, 01 Mar 2026 18:21:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772418112; cv=none;
        d=google.com; s=arc-20240605;
        b=aIAx8Nb7ThQJZXxvA2TmvZ9c6ef1m5AtyURwgEbfix4CtahhXNjYcyLi+NEeTH7DIV
         DfHXikEmQmiGDv/l/rJoUyptv2SpzWrfZnbkHtMIYcFeMan1diB3QfXA8CsLyILubv1C
         6srgjYBWC0f4y+0QMBdq1i0kxJUdMK4G6gSvyjY9wzVYnlXuilWy4ptUbAoto0u7X25s
         9iHGEgh4JniNY8hkiOCerzkjqB47w/kHOmm+t/gbixOer0xwQy6HxifbzF7C7sw+/JNw
         XQAVd4cogid4uun/OfNrPO7NnjgjOMrBZOu9z844D/bayC7XmsQIHCi7aLLwMXXVSGIl
         iTaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from;
        bh=RVgX48zUsTPjy9gnqQJabjOI9k3H02zDsF4rOyY/cUE=;
        fh=dhysk1ONviw3/t5HYidDze+Xu1ALgmkIH4J6t8FdpRo=;
        b=GdV/S+YKPrt/9HozeSoc44wn9f96JsU6xmecFphRKnU3Cgs5LL91FA0PAvj7D1wMjm
         rB9XlYe1BG7noXUM+lPX5ub3+naQ+x3hyRxftST7SXoUsbvVR8nBYd8x3Z66R6r4OoUi
         A7uHnntjk9xPUGkX/4OT08EAF1bavmRkwVsthtM9uFtbozRvVlrgRjpaeRjEmTcAXKfB
         EJBi2r7Woom0eNxam4QkoL/vFmd6bm0I1QvJqztC3xBWooyN9V/MpaKw2A4+Xf5Ug6K6
         gOyIVBEnfO9ZeciFepmD7RRcVxskGBS6tsodp/3+ydf5vnLf/84G+mLXXw9pAnTOaRgJ
         XgqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ae490e0e17si924745ad.0.2026.03.01.18.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2026 18:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAD3E9s39KRp6CWmCQ--.11902S2;
	Mon, 02 Mar 2026 10:21:43 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Subject: [PATCH 0/3] riscv: kfence: Handle the spurious fault after
 kfence_unprotect()
Date: Mon, 02 Mar 2026 10:21:29 +0800
Message-Id: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIACn0pGkC/yWNQQ6CMBAAv0L27JpSDShfIZiUstWNQHHbEhPC3
 23kOHOY2SCQMAVoig2EVg7s5wzlqQD7MvOTkIfMoJWulNY3zHIYCd+OZku4iI9kI4YlCfsU0Jk
 0Rqx0qZRx/b2+XCGnFiHH3/+m7Q4W+qR8i4eE3gRC66eJY1Os9Vmh2PKx7dDt+w98ojvypQAAA
 A==
X-Change-ID: 20260228-handle-kfence-protect-spurious-fault-62100afb9734
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>, stable@vger.kernel.org, 
 Yanko Kaneti <yaneti@declera.com>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAD3E9s39KRp6CWmCQ--.11902S2
X-Coremail-Antispam: 1UD129KBjvJXoWxCF13tr4ftFy8Xw1DurWktFb_yoW5urW5pF
	s3JryfKr4DJryxXw13Z3Wjqr1rJw1xtw1Fg3WfJw1Fyw15Zr4Dtrn5trZ5XF98Wr97Ar1U
	Aa10vr1UCrn0k37anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUU9E14x267AKxVW8JVW5JwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK02
	1l84ACjcxK6xIIjxv20xvE14v26ryj6F1UM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j
	6F4UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVWxJr
	0_GcWle2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E
	2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJV
	W8JwACjcxG0xvY0x0EwIxGrwACjI8F5VA0II8E6IAqYI8I648v4I1lFIxGxcIEc7CjxVA2
	Y2ka0xkIwI1lc7CjxVAaw2AFwI0_Jw0_GFylc2xSY4AK67AK6r4UMxAIw28IcxkI7VAKI4
	8JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xv
	wVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjx
	v20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwCI42IY6xAIw20E
	Y4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267
	AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7VUbBMNUUUUUU==
X-Originating-IP: [210.73.43.101]
X-CM-SenderInfo: pzdqw2pxlnt03j6l2u1dvotugofq/
X-Original-Sender: wangruikang@iscas.ac.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as
 permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	DMARC_NA(0.00)[iscas.ac.cn];
	SUSPICIOUS_AUTH_ORIGIN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBQPISPGQMGQECS5E6WQ];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[iscas.ac.cn:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 45D521D2723
X-Rspamd-Action: no action

kfence_unprotect() on RISC-V doesn't flush TLBs, because we can't send
IPIs in some contexts where kfence objects are allocated. This leads to
spurious faults and kfence false positives.

Avoid these spurious faults using the same "new_vmalloc" mechanism,
which I have renamed new_valid_map_cpus to avoid confusion, since the
kfence pool comes from the linear mapping, not vmalloc.

Commit b3431a8bb336 ("riscv: Fix IPIs usage in kfence_protect_page()")
only seemed to consider false negatives, which are indeed tolerable.
False positives on the other hand are not okay since they waste
developer time (or just my time somehow?) and spam kmsg making
diagnosing other problems difficult.

Patch 3 is the implementation to poke (what was called) new_vmalloc upon
kfence_unprotect(). Patch 1 and 2 are just refactoring. In particular
Patch 1 is just a substitution job, to make reviewing easier.

How this was found
------------------

This came up after a user reported some nonsensical kfence
use-after-free reports relating to k1_emac on SpacemiT K1, like this:

    [   64.160199] ==================================================================
    [   64.164773] BUG: KFENCE: use-after-free read in sk_skb_reason_drop+0x22/0x1e8
    [   64.164773]
    [   64.173365] Use-after-free read at 0xffffffd77fecc0cc (in kfence-#101):
    [   64.179962]  sk_skb_reason_drop+0x22/0x1e8
    [   64.179972]  dev_kfree_skb_any_reason+0x32/0x3c

    [...]

    [   64.181440] kfence-#101: 0xffffffd77fecc000-0xffffffd77fecc0cf, size=208, cache=skbuff_head_cache
    [   64.181440]
    [   64.181450] allocated by task 142 on cpu 1 at 63.665866s (0.515583s ago):
    [   64.181476]  __alloc_skb+0x66/0x244
    [   64.181484]  alloc_skb_with_frags+0x3a/0x1ac

    [...]

    [   64.182917] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 7.0.0-rc1-dirty #34 PREEMPTLAZY
    [   64.182926] Hardware name: Banana Pi BPI-F3 (DT)
    [   64.183111] ==================================================================

In particular, these supposed use-after-free accesses:

- Were never reported by KASAN despite being rather easy to reproduce
- Never contain a "freed by task" section
- Never happen on the same CPU as the "allocated by task" info
- And, most importantly, were not found to have been caused by the
  object being freed by anyone at that point

An interesting corollary of this observation is that the SpacemiT X60
CPU *does* cache invalid PTEs, and for a significant amount of time, or
at least long enough to be observable in practice. Or maybe only in an
wfi, given how most of these reports I've seen had the faulting CPU in
an IRQ?

---
Vivian Wang (3):
      riscv: mm: Rename new_vmalloc into new_valid_map_cpus
      riscv: mm: Extract helper mark_new_valid_map()
      riscv: kfence: Call mark_new_valid_map() for kfence_unprotect()

 arch/riscv/include/asm/cacheflush.h | 27 +++++++++++++----------
 arch/riscv/include/asm/kfence.h     |  7 ++++--
 arch/riscv/kernel/entry.S           | 44 +++++++++++++++++++------------------
 arch/riscv/mm/init.c                |  2 +-
 4 files changed, 44 insertions(+), 36 deletions(-)
---
base-commit: 6de23f81a5e08be8fbf5e8d7e9febc72a5b5f27f
change-id: 20260228-handle-kfence-protect-spurious-fault-62100afb9734

Best regards,
-- 
Vivian "dramforever" Wang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c%40iscas.ac.cn.
