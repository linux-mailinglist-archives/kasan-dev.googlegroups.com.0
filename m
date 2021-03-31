Return-Path: <kasan-dev+bncBAABBQGISKBQMGQEFMOA7TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 96609350497
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:33:05 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id 13sf1704465pfx.21
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:33:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208384; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jkhw+Q1JBvzg7OwNApLboGfDjJ0aak7aq9Tl5Al1uMO4O7S35jymx1oSuYXPtXINlP
         1fjNJls6o87f4VZOt/7By2l2wrGKRyoKjWQwCV7DmdJoO0KMd9NxA2gp5Jh++k+Ww7V6
         bvieI5ppc9k8zSqL6A6cnuuAVM0oTAzuEcuy8ZGQ/d95sNq8YC7f5cE6jt6kbAOdicYs
         94XIhTjum+vSRLepmWoGJ6Qr/rKZs0UZqfJTloQus3dMKN722ClzsM5Ssj2BXchx8E93
         MKf3bmL+wBZNOpjlJL/onp+azudPKiuOEqxgZrPOVMmKO5ZAzfx/buPRjJ5pcvQuiWqR
         4l3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=th6cs3xnZXIsrJHQylJe1lMDfW4qqVwgV32nrQ79dB4=;
        b=V8OW2EkCAHkulO1TkcK9bxxccnC0/O3aBT9mr1PUPumBdsx3cTYE7R3IQcOcsiZSmN
         p1zxgFsVXU41LBL9o1mH4BbejxZWMN8o2j47G98amlpu/i0A0XrVzEHmgFNfigrlEThp
         V+WHuCQ+9Lvj9nB6zz4DtIYo8rbyIPxG0qj62QrqeQTX9btfQN7lR9aHN4fkS1fx1L5B
         gm8Vg0u1tSllspM2AyxM4KUXuLsQ+HDHsWfYyWp499mtTV4S060aTmTDErzn7eMVRprV
         Lkom+oDdLm3CCWia/9tW2yTT+4GPxAunYQhy2B2CxJm7haXYQZDznwdDfDoh/RitHdVD
         Rtew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=FUvRSIYB;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=th6cs3xnZXIsrJHQylJe1lMDfW4qqVwgV32nrQ79dB4=;
        b=j3qKxhdBujqtQmTl4ttuO4X1ASNdmvIrvz6ca2zK4cQNsHaTvUaTmN9owmNgjlx1BL
         SlU88PZr4tKonFIBherX+PPJMjiqohg/p6r3Lh9JM5w9Rx8GP2CHwgbeNQ/LXc8aFryA
         U/CNmFZJ/auRGYuZMuKDzOcpuobde1IQuDUWwfcqVx/Q8NxBlIJCE7kBnegoknDMOF39
         TpUYMhbMS3zAiS5gSnuZMjZKTq67TX7aM0zbc5GmQl/jo5mk1mFxDdpcF0kTosKP1xZP
         8l93sbbYzvhyV7EsmH9u61iOBIjb1gOo0AeOninwvChtc27TeaM8VwGI5ttLcY1oqT0J
         0hMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=th6cs3xnZXIsrJHQylJe1lMDfW4qqVwgV32nrQ79dB4=;
        b=MA5JRbpWsc1v343jYMvHUqdYUnCAPrf66/mIGaDOqJDmwQ9jaVnwTPXYSkpoAQNkQ9
         jvD5QkpnTuZ2btWrWJoS+XRw4UhytOyCIHQ9nmHtdJjk98zpEOr3HM5a3/LXS4Ngzm8a
         7wtLDGQVwPZavDpCop1r0Wkk6N9kHG6tqKUk5vxvnwWuQLgtmOHjyL/kGb1fwd3e5C0F
         kHmoF1/jfMhIyFiEjqEgfCLPvIBVW4bXPZqBarmj7NNOZ9AnquxDupflfrxqOLE+mFyc
         AiZKTNP1TNhUW6rVN3GzrTa7VtZ8k7pqw4pcczwJCSAc19chX0MoxMcQfhEkMfxdx9sQ
         p6lg==
X-Gm-Message-State: AOAM532AYud5VUP1CI7BCeV+Jvbf4HSGd0GxckMY/0RW6HtXD5bDlyRo
	Kt1+JbzhbJGSdHEuOaHrDQA=
X-Google-Smtp-Source: ABdhPJw2dJbSmHzDCSPwYY7sUJNzngKLnMu7EtheZV3MrawbhU6+ihNw0pPJm0wEGMaDAZxdNJl1Fw==
X-Received: by 2002:a17:90a:1b08:: with SMTP id q8mr4144939pjq.203.1617208384296;
        Wed, 31 Mar 2021 09:33:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:545b:: with SMTP id e27ls1160315pgm.3.gmail; Wed, 31 Mar
 2021 09:33:03 -0700 (PDT)
X-Received: by 2002:a65:654e:: with SMTP id a14mr3976281pgw.328.1617208383873;
        Wed, 31 Mar 2021 09:33:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208383; cv=none;
        d=google.com; s=arc-20160816;
        b=BttLzEBlnzhyd+c6zMnTSDarl4w/iogxeJhVA0nCiJ/7hwjT8uDUty1serda71KIr9
         B2jaPsNMcDSbVmRig/AqQGntme74X5VF42pDBzMluzDi2cjwlTkkTH+47mRrp6+btmuA
         7vjsnqvagDcWg5o2ty0ZnDHRQ5JYB3obhJmuzV4ectP78FtDJsI9+1tAFVHoQwtFqTxv
         Fdozmjxl44+upwE6AnkEDqugqnByY8LYCMWQa3eaFe1owFoOuzCFwwjCer++XbNRhk2Q
         Mx0C+Ng1gyiyQYYCXWOxDEa77eBvkRvb3cX4iRGxR7B2nK1qnVsVC1C4cjmXDKiOvsfQ
         yT4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8lRS5PKRg+wSW2+e9kKETn+Cn0NAuvZahdIC8PRgBYM=;
        b=OrrsvcPjccCeOwbiITj9F3TTLkqnBBJZVInqteXGub+wc1W0DLS1tsF+f+gey7qGW1
         e7ovgtkLlst4gZNU4TWXNuU9Zto5qJRFk9JJx65Mtspey/xOtmZ3uF0+524wLQK+eSC1
         8L9sYPrDxO7jHVtg6T+xlHQapgYQpqyICKaSl0Pyz+zFEs0/ibVdsxe6oIAzmxadSEeF
         rl8jsdhQk7k1B9e296Kk2GrZPJwvGqS1nDYQdb3KFpfkUIQoSjp+PYoZo9M1yoltk/ob
         4d80C0A8y6WBENkrZwTVGv0bLQOvv8KOtVNKcfzuPHNO7tjbZLAIYRnKUBMFlmg6hWIb
         4O9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=FUvRSIYB;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id y17si113115plr.4.2021.03.31.09.33.02
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:33:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygB3gqw2pGRgQr56AA--.16223S2;
	Thu, 01 Apr 2021 00:32:55 +0800 (CST)
Date: Thu, 1 Apr 2021 00:27:58 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt 
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin 
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey 
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, " 
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov 
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko 
 <andrii@kernel.org>, Song Liu  <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend  <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson  <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2 6/9] riscv: bpf: Write protect JIT code
Message-ID: <20210401002758.78c29f92@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygB3gqw2pGRgQr56AA--.16223S2
X-Coremail-Antispam: 1UD129KBjvdXoW7GFyfAF4xCFy7WrW5tr4UXFb_yoW3XFg_Z3
	W8ta4xW3s3Jr4xAr4DZr4rZr10yw1FkFZ5Zr1xXryUAas0gr15KasaqrWFgr97ursYqrW3
	Wr97JryxXw4aqjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUb4AYjsxI4VW3JwAYFVCjjxCrM7AC8VAFwI0_Xr0_Wr1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l8cAvFVAK0II2c7xJM2
	8CjxkF64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVW7JVWDJwA2z4x0Y4vE2Ix0
	cI8IcVCY1x0267AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUAVWUtwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVW8JVW3JwCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU8S1v3
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=FUvRSIYB;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

Call bpf_jit_binary_lock_ro() to write protect JIT code.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/net/bpf_jit_core.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/net/bpf_jit_core.c b/arch/riscv/net/bpf_jit_core.c
index 3630d447352c..40d5bf113fee 100644
--- a/arch/riscv/net/bpf_jit_core.c
+++ b/arch/riscv/net/bpf_jit_core.c
@@ -152,6 +152,7 @@ struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
 	bpf_flush_icache(jit_data->header, ctx->insns + ctx->ninsns);
 
 	if (!prog->is_func || extra_pass) {
+		bpf_jit_binary_lock_ro(jit_data->header);
 out_offset:
 		kfree(ctx->offset);
 		kfree(jit_data);
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002758.78c29f92%40xhacker.
