Return-Path: <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4M9GHQ1ypmnLPwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 023BC1E93D8
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:52 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-506ab115571sf437708411cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515851; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cr36B607go+u8l7LQ8a4UL6NFF8969OnWumBhTEhyDOJwLl+umgZwnaCA0cNX5BPqI
         4TUv/3aeHIDn+ic1wYDyLD6mieqN1bjUSPF0IXVrGOcYj88iHWZ0DIt/WNXrlzudvlba
         UtBKXknZ98tfB72+Uf37JODA4p6lFJXAx8S/bhf2b8FgSxnmjtWxrO6fAC5Fj/hQXvOa
         EYvDimG+T21L2ZgpOU4KxZWEZkZwC9bptWjYnAXyjk0whS1+926JVdKKLH76hUP6oEmY
         qA3i2Hs/g0/nUwcL1DQ1dlTiEAdqA2UguftbhY4DUPxZweXYnoQrl4YSTLG0LD0ztFXv
         NMwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=0KnjMFyeatxghuuDTJLD/VQpvaNTzhcdSa/pWqK71iU=;
        fh=cCBsBLUlJUV21dNaWKFIayd27FKz/A3VXqXdsZ3Pslo=;
        b=S04lb8QLWa//5f+vpPbuTRx2VSP0/8DixIpFUbJZZjW6SlbFUcO9Gvu1prHdGb6XJT
         3N+0iL/YOMurWLRWQbKZQclth7jbDDT2wKpxc7QuFJsV2IbXsT4Yne/FnxjoHiJtb3Xk
         XDXZFTd6U3zqxZtKKy4EJAn6/McRvdBlNolAroEglKjMuC9pc9XzEKnKFJjeIkMWbq88
         gDLPKerZIPAwFs9GFpms6k80YrzY2PXyGQ2/96nZJcbn0clWwk8OJyKvYNlMcZIiF8bZ
         9+X3RT9WG8S/28eNonUFJS92lkRh+rl4k/tGe290Z/Y/RXXoNTKW5e9t4R6oz7aUj4NV
         IYzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515851; x=1773120651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0KnjMFyeatxghuuDTJLD/VQpvaNTzhcdSa/pWqK71iU=;
        b=CB6LpMoU9V2G+upkYW9MVLeGsgATEzjp+gQMgyCtbfIYgznH1ZchGRjI8tV9xX3y9x
         K2wKz2G2Sc2/bm4tOQwF7khfSdpARr3bLsKg03kypeJ7VKTHiNYLwngL0O3pVk7lBQ2w
         gmDFyyTmXBROgI/pHgYpShf+N1qsvio0XaipXD3/XcpRktPPZD36ukGgGzB0g/laGi2p
         ixVeAh1A63ohGDBOvlw6vTtKyBhVUv2vONAIFJdh6+0uO3cGWF9zLSA0ZDDoxGeiVwwj
         u8ewDykTxKSycmR+Pr4qZoRCOZWWvJN4jYE7PJMplTREef4SOtM39znMlzcsxgCRqB7A
         ZfsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515851; x=1773120651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0KnjMFyeatxghuuDTJLD/VQpvaNTzhcdSa/pWqK71iU=;
        b=NeoQL0iIudpthCxQnVDAN2CZB97jq5Jl2gRbqN2TL0mtiRU82jWGozKJeHzs9ltkqa
         Fq+iDG4w9dqD9f2iwEaPqKAgCvMuFjs/Rw9n792xmBqcopcG+RmvsdHxbgK7kg42go7X
         E8zJloa+NXihl/XZ/9bSpqxgyyzI0ZHzet1l2kuGzZU59ZTBwAQN2EsDh5sT7SuY9jOf
         AiJTUH2v9wI1yllh9BAPUA3PV5pPIjdcHhTHlQXEWA8L6TMzN/eQie78RCu/WS0oT3hF
         XGyAN99Jd6niszDQ4Xxca+bKamn5rPySkbX0KFdfmlh3+HYrl42e9n2SZJA/jwBjBL2P
         ZTqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUP+tJeX6q0RUepC06Bqaxo2mOjKnvSWQJKJU4kv5YM+rDtmGzvfIyRcOK2tR8i+GKkretvvg==@lfdr.de
X-Gm-Message-State: AOJu0Yzzk9ZK8JAUVhbll8BfMWyPODWmc1nFVw8XrL65XOG9lhjYM5QK
	SiPbg4lpeqJtChgb/8J7pIVPCgjr+ThnYTQUqMRFyRDf3wRX9l5JaOka
X-Received: by 2002:a05:622a:4ce:b0:501:4807:6162 with SMTP id d75a77b69052e-50752a21a58mr170740071cf.72.1772515851596;
        Mon, 02 Mar 2026 21:30:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G5fzQ8xJHsaI0hSSK9rJ79atQVMlpomgvo/oq/nbuxpA=="
Received: by 2002:a05:622a:15d1:b0:506:ba84:e7d3 with SMTP id
 d75a77b69052e-5073bece4d2ls103234751cf.0.-pod-prod-01-us; Mon, 02 Mar 2026
 21:30:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXqaKDqXKbLwf60/VPId65wanAIWtMNd/W5xprnWtpsJtDEntfBnn+H0gl/XgDA7Ah0w5W0aROofE=@googlegroups.com
X-Received: by 2002:a05:622a:190f:b0:4f1:b63f:a165 with SMTP id d75a77b69052e-5075299110fmr192073391cf.35.1772515850580;
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515850; cv=none;
        d=google.com; s=arc-20240605;
        b=eS3e+t9/hQOXoKGGp8+JrqXqQ7B8iD1Xc/adGh4uQvUe/5rZqx3b/o9Xg4RsAtxNIq
         G/Ot1axff6PWswsDNrjC64kVgrS92TSLmGFphqDG1C9hBGwwMtJw9hZP3OHO0/l7Cf0U
         uLUUTvidHFHkLofZSQPG4I33FnJp0gOhCY9txE1BsRyr3Z67qmx0JEGX59LwYSiuxgea
         uwJCoge+uOeEyz84qaJii5KLZfL5niOxwokv/75ae1Clc5dToTIBlAMuZI4D2wgOGepD
         o/1eT+d0dB//0IooMquzPft9KvTXQmgNJXvjAt+MwKA7vVCnxIef8llCUOWD/jq+ToVC
         aeTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from;
        bh=KLQz14ZlBUgMu0zEsi7z32vSKjHNDfDv5eYDgz/kfYY=;
        fh=hyK0JTWcQaa/VDIQLgzWS/nA5iK7kT7CJKRUx9aN3l4=;
        b=fXll5Qf8YmiQ6tPWk+ruRuusRBaXSoBTQcpmuHH4AL1/jP108Rlx9MeJ0ZMwCiCPXg
         8CC72LaUDEEq5jljEGwB0qOP7QqN5uXlVKzGdOB/+CrUkTCuPWSiKqwRhoa+aqdPrqKf
         PMINNxJsiwCsYjzXR6EcJsqYKaGGX3Ia0RNvbtll9FEeImxHXJ/DSRhk3bHSquklNlHj
         trILZFbCrANQPpW1bxk+5ecntdPNovjL6W3o/tt2VrqvjjJ3o0gUwTMeaXS7+yvO8bzi
         eZPUSrPX23bQOdT0n7Em6Oz6Ctcjp7t0E7mReC9/PT0DnljvpvX6fm3nj/5dEj1HESlb
         Sw/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-5074497abc2si5363671cf.2.2026.03.02.21.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:49 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S2;
	Tue, 03 Mar 2026 13:30:38 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Subject: [PATCH v2 0/5] riscv: kfence: Handle the spurious fault after
 kfence_unprotect(), and related fixes
Date: Tue, 03 Mar 2026 13:29:44 +0800
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAMhxpmkC/42OXW6DQAyEr4L8XKPF+QHy1HtUqbQxprGasHS9o
 FaIu2dDLtDHbzSa+RYwiSoGp2KBKLOahiEDvRXAVz98CWqXGcjR0RE1mMPuJvjdy8CCYwxJOKG
 NU9QwGfZ+uiU8UuWc7y9tvdtDnhqj9Pq73XycXxzlZ8pv6RXCxZsgh/td06mY69Jh5OpzWeFZv
 6qlEP82ybna+pvPztH/fOYKHdKBG+KmbruW39XYW+m55AHO67o+ACFd/4UJAQAA
X-Change-ID: 20260228-handle-kfence-protect-spurious-fault-62100afb9734
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 stable@vger.kernel.org, Vivian Wang <wangruikang@iscas.ac.cn>, 
 Yanko Kaneti <yaneti@declera.com>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S2
X-Coremail-Antispam: 1UD129KBjvJXoWxCF13tr4kAryUCr15XF4kXrb_yoWrJw4xpF
	s3Jr93Gr4DJryxXw13Z3WjqFn5Jw1Iqr1rK3Z3Gw1Fyw13Zr4jyrn7Kws5XF98ur97Ar1j
	yw1F9F4UCrn0kwUanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUU9014x267AKxVW8JVW5JwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK02
	1l84ACjcxK6xIIjxv20xvE14v26r4j6ryUM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j
	6F4UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oV
	Cq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0
	I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r
	4UM4x0Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628v
	n2kIc2xKxwCY1x0262kKe7AKxVWUtVW8ZwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7x
	kEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E
	67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCw
	CI42IY6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1x
	MIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIda
	VFxhVjvjDU0xZFpf9x0JUqeHgUUUUU=
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
X-Rspamd-Queue-Id: 023BC1E93D8
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
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,iscas.ac.cn:mid]
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

Patch 2 is the implementation to poke (what was called) new_vmalloc upon
kfence_unprotect(). Patch 1 is some refactoring that patch 2 depends on.
Patch 3 through 5 are some additional refactoring and minor fixes.

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
Changes in v2:
- Reordered patches 1 through 3 to minimize what needs to be backported
- (New patch 4) Change the bitmap to use DECLARE_BITMAP (Alexander)
- (New patch 5) Additional fix
- Link to v1: https://lore.kernel.org/r/20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn

---
Vivian Wang (5):
      riscv: mm: Extract helper mark_new_valid_map()
      riscv: kfence: Call mark_new_valid_map() for kfence_unprotect()
      riscv: mm: Rename new_vmalloc into new_valid_map_cpus
      riscv: mm: Use the bitmap API for new_valid_map_cpus
      riscv: mm: Unconditionally sfence.vma for spurious fault

 arch/riscv/include/asm/cacheflush.h | 25 +++++++++---------
 arch/riscv/include/asm/kfence.h     |  7 +++--
 arch/riscv/kernel/entry.S           | 51 ++++++++++++++++++++-----------------
 arch/riscv/mm/init.c                |  2 +-
 4 files changed, 47 insertions(+), 38 deletions(-)
---
base-commit: 6de23f81a5e08be8fbf5e8d7e9febc72a5b5f27f
change-id: 20260228-handle-kfence-protect-spurious-fault-62100afb9734

Best regards,
-- 
Vivian "dramforever" Wang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d%40iscas.ac.cn.
