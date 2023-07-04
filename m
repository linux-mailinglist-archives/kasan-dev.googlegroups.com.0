Return-Path: <kasan-dev+bncBAABBXVMSCSQMGQEAKDHTBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B8D887471CE
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 14:53:52 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3405fdc0c2bsf4560435ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 05:53:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688475231; cv=pass;
        d=google.com; s=arc-20160816;
        b=R1jSMIk7UHkK5JHj5LR6jlLQrY2JmsMlnmWDEQ8eqjGaFu1//pH+eGnJzscvzyBckG
         r99ompMLhUxuFHHeYcEVu2uBFczJ9bv+DOjD/BvJhJFp7+MCEEmJXf4KsXtyRw18DPui
         4nVVZ8MciDn2/7ibesPeAvYuYked9NXIGLvzsa2uVKZo7/OZF6czxEldCrALi1bsppai
         dgVCnT30ak8b46ng7OYu5npTuCnltka2T/zbjEoORMhg03JogSsX7UsT3f/hoec1C9wF
         BNUvdA4K98X3z/kyxt+eUVXpO8fI5WVklIwZuH+JjV2xUhKqhn373JtrIyBvTmr44rCn
         eb6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xQJY8cK/+5WHdUcKb2Sk2LqAab6z0P548hQVsrMCKpY=;
        fh=fXH6L5Mdmplg4a8NGnzKpUgjBUQSOHCe40EEq+EMn8I=;
        b=i+D9lVQqewKxa0a8VjSQ0O5El10GNRoVEQ0XGMPIdr1wbrFad251vTWShmjIw8054k
         Liw3TNwCODsOOc53YPLmP80ozobYvWMbRCmNuaAN5psawdBMkpYvgeUvC3YdtaEQidB1
         bB06Iz+m05KVcsXkh+Rg3ox2tzlxilwi3ADg2qScSWyigzyPCxp6qMqFpmBQmJD9UjGK
         frYjqir0J9h1w95C9m8zCPjR9OMDE2Q6Jmhtjh1wmVP/7UKcy0Z8cuZjKXpT5ThdQcjn
         TyCNpwuW3E6XG+QmjK6yPkcvbLnXnaC2dGJDdRk8m2Vm0lcUkWGk1p9Kj1AzdDc+MtLT
         VOGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688475231; x=1691067231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xQJY8cK/+5WHdUcKb2Sk2LqAab6z0P548hQVsrMCKpY=;
        b=TbEgUQ7sc+/OP0QgnU+nYYfWntNO2LNR5HW9KpQJFhkSOfj3FIS++OtKnkIpcwbL7F
         yZNWybx2/j9WWl4wheu+O68R/Bcj9hOoCEo3Kd/uIn5c6Jf21YSmTD3hU8zNGw8nn1Dx
         72dkbMHOwOM+1kF4dTFMvZaHygvlATHp2gy3u7nrS0E4JO12JMZw501UGw2JaZKG1HJq
         AGzqc9sqcSZ3MHLKACEnXvmlgOWClgHYebBPbN9nU17PtXFTsI8RXMBTrdZa6/g4WcnC
         ioPUpvvmrEzE0kPSzrpuQT7RZOPEncXne7cezzmzYDIt7EXmujD//2lbpVG9eGrtkDz1
         JMxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688475231; x=1691067231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xQJY8cK/+5WHdUcKb2Sk2LqAab6z0P548hQVsrMCKpY=;
        b=I9ssGqPx1WnwJELtl1oNCzv142+802M2b40d3PqLbgZ06aUgI7i5N8DcR/5bUgPls9
         Xu0xhJ8svLXYxbSR1z1xGWLJSL2OjRPuyj1VB4TM8nR8airUM7yV854XYm2TkuT/LyjU
         l9XBoXYQyCfLqEk7RnP0RzXHUASN37MnsrA2k5156tEJnBe+i89EikTrN6lAX+66r14h
         xpYRWcQxxKYXnmdnZ6vv04RQa0tajHagQwYVEcCgNjka5kBm5d79vKZlT6HyiUQcMFru
         yv+JINFTh8GM1wCn69P5Y00Jo6SNw1Bx+7JbOGT68Zh0DgwliF1JNzt/kye3TON7qLaN
         2J5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLa5mYPmnwjRqs2nxpPAjOPxAtiSkgGbzCUdTMCnWgZhsaC7cwcr
	2OERYPNsOs9UldlMM26PHlM=
X-Google-Smtp-Source: APBJJlHbWTrg7kSb9aCgrrJHnWvDAlZUqqAUHMfV9mZRomnG/y2yId+VXdJo7VcndZ76TE1f54foXA==
X-Received: by 2002:a05:6e02:188f:b0:346:1bdb:1735 with SMTP id o15-20020a056e02188f00b003461bdb1735mr137093ilu.2.1688475231194;
        Tue, 04 Jul 2023 05:53:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8688:0:b0:669:ebfa:b1c6 with SMTP id x130-20020a628688000000b00669ebfab1c6ls4303134pfd.2.-pod-prod-06-us;
 Tue, 04 Jul 2023 05:53:50 -0700 (PDT)
X-Received: by 2002:a05:6a00:2389:b0:67e:6269:6ea8 with SMTP id f9-20020a056a00238900b0067e62696ea8mr20294861pfc.22.1688475230445;
        Tue, 04 Jul 2023 05:53:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688475230; cv=none;
        d=google.com; s=arc-20160816;
        b=l8yBXWytvL3MdzoO/90jxqF4z5BuZmEp5BOK9/aHaH3IbCE5ZJqEPtV/AtAtlaheC2
         ITVOc/+lIH7veEwZguEuMtLqUFtaImWR25c2dZO8O/3kosVXLhuqGD1VkeB78D4/svc6
         1gIVG9TnBHTon5u6ojkIw/e2dy2zK3jv2uk1cj5EOkNZLR7EeS8uwLCbZOlX/Y3J9nJ/
         5qwl29LwZaB+fH0TAnDCrTYybuxwBYXKgQmuDeWeHEXZpqAAdeo5zX8HhLY6nTmWJTpS
         NX7dtNpzSroKRH6RkoIV6VFErFgYAc9iBUUKyspdcxNrLNm8+dfyPvE1cXcNqsX4D+GL
         8tuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=7GP1bRNvIKUG7HOinxB4C1i5O1A5gdhIeRL9KkvBRAU=;
        fh=9EPwvLZGe7pBtJfS2ZpQbGC913fAHqL1RrW/UsdYWYA=;
        b=O1ww/eKXGf+xvbknyvV4ZyWz/bms/VIfAR1NMr0mDNMgiuBDtjU128AgINFkjNYYJE
         7utaKjNBJ3K+/XwxU47mPrAPLXSvXyj2WEjqeq5wdiWQ5QhWEAg9yrv9WR0mxSMg3qTe
         eGPiX2Ieg/UwpbIuYm3ct0M62ii+kbWXSxQmfTRW/Ei3RAnX3P0Y2OuJDJsuD7NNNLaM
         u84s99wy4P885psga2DgXu/9VXeqZoobob52RfT29m8Qyjy1Qqt2SNW7HQEEVMkxvtzg
         HGS5biWdw87tCQ5M9SWt+5Gl0yPr+FQyhu4Ad0EVrretkf2IHRkJblJkEm252gu9cKR1
         0/6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id eb14-20020a056a004c8e00b006819db556a2si1009828pfb.3.2023.07.04.05.53.49
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Jul 2023 05:53:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8BxpPBbFqRkwgQAAA--.49S3;
	Tue, 04 Jul 2023 20:53:47 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Ax98xaFqRkXDAbAA--.63241S2;
	Tue, 04 Jul 2023 20:53:47 +0800 (CST)
From: Feiyang Chen <chenfeiyang@loongson.cn>
To: chenhuacai@kernel.org
Cc: Feiyang Chen <chenfeiyang@loongson.cn>,
	hejinyang@loongson.cn,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	loongarch@lists.linux.dev,
	kasan-dev@googlegroups.com,
	chris.chenfeiyang@gmail.com,
	loongson-kernel@lists.loongnix.cn
Subject: [PATCH 0/2] LoongArch: Allow building with kcov
Date: Tue,  4 Jul 2023 20:53:30 +0800
Message-Id: <cover.1688369658.git.chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8Ax98xaFqRkXDAbAA--.63241S2
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29K
	BjDU0xBIdaVrnRJUUUkjb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26c
	xKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vE
	j48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxV
	AFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIEc7CjxVAF
	wI0_Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx
	1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r106r15McIj6I8E87Iv
	67AKxVWUJVW8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41l42xK82IYc2
	Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s02
	6x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0x
	vE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r1j6r4UMIIF0xvE
	42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6x
	kF7I0E14v26r1j6r4UYxBIdaVFxhVjvjDU0xZFpf9x07jUsqXUUUUU=
X-Original-Sender: chenfeiyang@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
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

Provide kaslr_offset() and allow building with kcov.

Feiyang Chen (2):
  LoongArch: relocatable: Provide kaslr_offset() to get the kernel
    offset
  LoongArch: Allow building with kcov coverage

 arch/loongarch/Kconfig             |  1 +
 arch/loongarch/include/asm/setup.h |  6 ++++++
 arch/loongarch/kernel/relocate.c   | 18 ++++++++----------
 arch/loongarch/kernel/setup.c      |  3 +++
 arch/loongarch/vdso/Makefile       |  2 ++
 5 files changed, 20 insertions(+), 10 deletions(-)

-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1688369658.git.chenfeiyang%40loongson.cn.
