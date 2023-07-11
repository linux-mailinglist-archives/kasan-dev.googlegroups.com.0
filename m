Return-Path: <kasan-dev+bncBAABBBMBWSSQMGQEOCPT72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 061EC74E7B5
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:11:03 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-635ed44d2afsf43701846d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 00:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689059461; cv=pass;
        d=google.com; s=arc-20160816;
        b=eGm8cyObvU+JzB2oN7MtazgoWjpp2vckEVncKSe41ri7Vd8P57sZBtYUJe68zszoQl
         F9znYo9V6lSkVkUvAgjUTr5kohOnfICtrEnIDLxubkNeiSV7CSybIJeOtx4cR8dq7HH/
         iVRvvRM2ON6sPN5/5wwEpGi4JoIY2pxWQAFlHlJ7AE0ItcqHfFhDUCxkFM/QP+QT4FD6
         O4EIOgCpeFFmrfAFNpIMQ3109JFsAokI8VzdrGcBgInZbuCzzwFDojrtIjBOwe/p5QFE
         s+OSapst+r6IONpPc29w1Cnw4kAViKYMaE9/p9jvis8JMfRsJyhuwBiYP4Q8dDzVrap2
         Az9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MbB5Z4yB2eVQDVYeE3tbxkCR2oF5W5kQlJgYa2MX/QI=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=OX7C3gbRJFyUwWBvWz7xtWY4eIwadvVFtPmnMHbW0MzKhoj3M/AE474XnDdODgl3U+
         hrluuWUQki115h3DRFF1/goVBg7wQ4xgtdRLzEgz4WV+93H7IFY9Ghr6out+Ky8TdvSH
         wiFIB1252pVDTUDfGy7JMfjp6sr2AGoVzx0FW/Li4uLsSR7XLFO+rrpHv7uEs1OOwexJ
         RPZvBNVswe8nPpVPgT9CPn4Hljsn3CkTkn6FSmQXi5s42BS6IU2OHRfPX8OQx/S1TBmG
         NCirSaG/kpFy83/9PmOOlTqYq1fERfwKJY+uI9jvFJx06G4aTR1PY0Xwa8C9Qqq5tZMq
         wgew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689059461; x=1691651461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MbB5Z4yB2eVQDVYeE3tbxkCR2oF5W5kQlJgYa2MX/QI=;
        b=VvYAaNl7pjo3f7VFkdsJgv3VrmzhfHAmT5EpUfxAF2UWafJZRd5vtTR0J4O3sSY4zO
         XOsUS2vidXa6YNbPE7PMbkBi9dp5aztAPQWFcSWpwbvoop3j00wD/k5JIzZHPjNNm5Bp
         YaQoaxtqw2G68xVlSzkHm8zTyT1a8n/bsg0H1NdjqMk+1UcFjid/5mLJjpwjV6RMurwh
         /gVzccY5+8+Biq51I2y6a0RUU8KoJ7r9GwdEIY0NVcZDbNsaVoYEVamK6He3hrkEi36m
         hz8UhCLBG3kLcEqGKpXhna7SjvXP8SbFzSeI+IJHFrduA0MEVwQUnsGtoB57ySevlUjU
         k14A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689059461; x=1691651461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MbB5Z4yB2eVQDVYeE3tbxkCR2oF5W5kQlJgYa2MX/QI=;
        b=Ckn9OQ8jYvMOR+PcxX36yuxoR+JOHUhzLLLhezJckW93Rfz+Ggp4X6wj/hJBxQEEvg
         RrlrDJsjx1xNjdaYLVQjrMyuii+ImnaHIV02/mL1SrzYDcaipY6XBrAgfI2ZmFcPredg
         xGr5gaTKFqU/AvIGR2gk6ksAnq9Ufvyl2EMjUgosbLPjcV7IwLhH4XBzar/+bu56LsNi
         MbKnGjQ20r+Qqjt3UyQFF1Ih8jo0f/gp4w3Qro/HGMVbPl5rrFQDUMXPtTXFYLCkqehi
         RZ544E4uXffvxPm7eXyh5mBHNBvu11I7cem2v0akCVCHkfgRfCP/wH1KIZ/eUVwcycsa
         yoJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaZ/ZX050QN5WOgqMnC4gCk1aiHMSjhCmvLEirPLoCxd0naVBfm
	nO51Cl0yDrLne9RBxxfmuwc=
X-Google-Smtp-Source: APBJJlE3c96vOb1+TsuJ6iK4m7ewPjd20zqrbwIerPyACf0FR0Fm/4/NMKNQSelSbCXSWQ8PtipA3A==
X-Received: by 2002:ac8:5e53:0:b0:403:a1e0:e3e with SMTP id i19-20020ac85e53000000b00403a1e00e3emr10600309qtx.24.1689059461569;
        Tue, 11 Jul 2023 00:11:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4a09:0:b0:3f8:3f:7349 with SMTP id x9-20020ac84a09000000b003f8003f7349ls5022437qtq.1.-pod-prod-08-us;
 Tue, 11 Jul 2023 00:11:00 -0700 (PDT)
X-Received: by 2002:a05:620a:4011:b0:767:7843:973f with SMTP id h17-20020a05620a401100b007677843973fmr15305693qko.35.1689059460747;
        Tue, 11 Jul 2023 00:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689059460; cv=none;
        d=google.com; s=arc-20160816;
        b=zbhLgG+W/TlIzjxQxjg2NRxYQ+jwUHhN7Hj4mUpslOLQ3ptre51UGmTEnqFwCT2gGx
         3JKcHFAhyBbAoE/mpoLBp0HAtrxfpzufUN7Hae7YmbBug3YeBrdnkwry5bradFvB+IzS
         2alK7f4VLA6G3kFg4PdNEoUngJR2ZflkeOE7Mv9zwzZkjD1mqsxCeqXGFSFjQu6u/cu5
         bqWe1yH0cQDDYzd6y3PyEhg+v9jhucSg66rn973LJV64gWplpqimPVGe/kxpGq/8mLfO
         KqAaYkZ745Thng67SjxSb6YrhDU5lDt8UT60fIFQHaR2yVJc5kVR7zHk9WLxBL/OeEGf
         FjGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=yHs3ihkF7ExrMs9WgSKshcfMUHuHzpOgK23qip+hzAU=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=ORqfNyJz1cW5oGZZegBhLkPY4d1SnCfl8MJ9x1GzOOX4orCNABEWCfFG1teFPpZoRn
         cEtKrbWUOn0aeqIo6gZQETnZvwQViWV/Iha15gQyZ7BIlMzE66/uOyOJQzq+TtNIL6TA
         BcsDfM8rz/Kom8xxSIdMj/1HdnY2TkA6/kkqmbw24KOVu/pbvm/A6pzLIG+hTRNOtgMj
         G+Ix7AaCgVw6z7lPYcrWtKRZKzlZ5SYVy8mnLAtcpAqpqnWGfx6M5Dj8iQCuOKm2HKcr
         opKAD8UpU6M81f7sLVFAebrC3gbE0Ki1T0iRnyZNPgsGNH2guK0vAtF9qZH3r+vOUm7s
         UHuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id ed3-20020a05620a490300b007593c43f6edsi88317qkb.0.2023.07.11.00.10.59
        for <kasan-dev@googlegroups.com>;
        Tue, 11 Jul 2023 00:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8Ax1fCBAK1kS2oDAA--.9943S3;
	Tue, 11 Jul 2023 15:10:57 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxF81_AK1k308oAA--.46365S2;
	Tue, 11 Jul 2023 15:10:56 +0800 (CST)
From: Feiyang Chen <chenfeiyang@loongson.cn>
To: chenhuacai@kernel.org
Cc: Feiyang Chen <chenfeiyang@loongson.cn>,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	corbet@lwn.net,
	loongarch@lists.linux.dev,
	kasan-dev@googlegroups.com,
	loongson-kernel@lists.loongnix.cn,
	chris.chenfeiyang@gmail.com
Subject: [PATCH v2 0/2] LoongArch: Allow building with kcov coverage
Date: Tue, 11 Jul 2023 15:10:41 +0800
Message-Id: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8CxF81_AK1k308oAA--.46365S2
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29K
	BjDU0xBIdaVrnRJUUUkYb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26c
	xKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vE
	j48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxV
	AFwI0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x02
	67AKxVWxJr0_GcWle2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44
	I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2
	jsIE14v26r1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20x
	vY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I
	3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIx
	AIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAI
	cVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2js
	IEc7CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8j-e5UUUUU==
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
  LoongArch: Provide kaslr_offset() to get kernel offset
  LoongArch: Allow building with kcov coverage

 Documentation/features/debug/kcov/arch-support.txt | 2 +-
 arch/loongarch/Kconfig                             | 2 ++
 arch/loongarch/include/asm/setup.h                 | 6 ++++++
 arch/loongarch/vdso/Makefile                       | 2 ++
 4 files changed, 11 insertions(+), 1 deletion(-)

-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230711071043.4119353-1-chenfeiyang%40loongson.cn.
