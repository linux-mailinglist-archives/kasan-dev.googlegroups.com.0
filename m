Return-Path: <kasan-dev+bncBAABBG7XQGXAMGQEK7TAW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 856488493AF
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 07:09:33 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-68c52361422sf50098256d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Feb 2024 22:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707113372; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gto4IBuADa9dZHcWP+1lELBeiEO74eSajKQbHpQsCNrw9YQJ/f+jochMmczQFFeXXl
         nXjTS0kRrz57hAPJj86BfUBq4DpTDm34Sp7GskT4260f0T6cPkcWTuePKic7SDcy4Bz1
         QoZWQ86K9goLQKDVAdB0WvPYH+YWgxBeKlLlKccGrNRZd5af8dp5qaBtDJPttii6rcqg
         HIK8WLY5k4TZIoAc8ndNeDvRBipT3DBbFRmnYYl/KmlgsUZvmVYVGunRFaTmpHt1M2JQ
         78Z1Lte2TPYyon1p6Om7em465RqIKy8vHAL4jApB/FLjkmHgUzWNtp7iPCCKdIQQSHiz
         4WSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6kb4ULQiXu6WmTXQC5DX9GPzLpnaTTrHzn6yK882Mxw=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=a/lO+lfRS0PIRm6yMze2R8vQ/Ay42BtEVCBUxz1iaYAsQ+K7Iu4yLKC++LPIXCmvEt
         j9PzrdKW5R3UacNNmmSwtGu42vknt2Zp9dMOb+v1uJu5j15FQzsumDP7wunBQlC5U+YW
         sr3fdQij7UUyKkjlm4g4okzjDFkfSAJnxKPgIrNPcYOlw7khQkLL0CPwPsh5oJgiq5Zr
         VGSHpH+iysp5k28OW4yPv3h4uFB1TLOc1mkGcGjXcU8MAVwypiKY8X14Toihz+YBm4KV
         GO9aKg/VbjV4Tt2W7ltq/q+f4dFU2k1N99jk2lORWmlPt4zhgIdt64lUCpCLZdABTnu2
         NwDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707113372; x=1707718172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6kb4ULQiXu6WmTXQC5DX9GPzLpnaTTrHzn6yK882Mxw=;
        b=uMUZ/MSg2KXcsiqGmzjcy5/iHgfM38ALRzBceuBWUbWWh/stzGg6qIZo9tDmUuC7cc
         Gh/wjm+1bYAwH+aGCBLkHUdmL5EiGGwaAcB8YcmNWsTWIanARj5fV3yRaAEA8xaOSDgY
         Fwk/ALgMKbYy+gzvUCR+igshvyfOt/N0Utk2TSDXkDMf84PMk43R1amjvagsmbhVKs8j
         cyHkxsCdXBbKme1ndfuxmK8jiWwd0vGLAVha0v+SsMwwW7mhrD0nKkd2xzSv+Lhi8cQU
         VB+JflATpGVvIyxTKe+0LpQbhOS0v3r5zTnOm8IkY2Dj6XWVORoi7KOzSx1PakUIwhYH
         kzkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707113372; x=1707718172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6kb4ULQiXu6WmTXQC5DX9GPzLpnaTTrHzn6yK882Mxw=;
        b=tGXcuBQJhg3a4c2JGmLcM90ib+cfEawYzrtQjEm0k5brJmjFG3FrAbBJd5ghpjCttJ
         tueK62JfWsUS3Ye5NYDazeN8sGSREGCWdc+j47Kg2O/tFv+ZL4WHVbURcZgKSst9OuCP
         QnMxl660isj9z73/dKKqPhp1GIn4MikgAStM+bNcrgPY4UpsSj8571/YoH8f7GVb9vBy
         l1PWa1fgzGoggNoqZNR2kKY5B3aCTZ0NB21yOp4nsd2W91/+k4AQM82VWnvK/RdRCdqM
         9J0VEy9bitakRCxXQPpwYrmZOw4G3z+9WvpgA9mazLpsN1EDP1FeXzkPfnGJe5c78EZC
         WdnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz9ks/iC1nfOCeYBRKv1IkV/30tQBNFTx1xJfMNUmwWIt+NybjL
	VVS07l3x8hfDdQHmjWjdduHk16F1Yx3YaPtjLcMtvOe2oSjcH7kn
X-Google-Smtp-Source: AGHT+IHB2meLpJujClSEuB52IM66M8/SaFTqy++5u7oxpiI6lWJkqPZnWtQKcL72pnp1s8cmHX2u9g==
X-Received: by 2002:a05:6214:246b:b0:68c:7f0e:abf9 with SMTP id im11-20020a056214246b00b0068c7f0eabf9mr5642369qvb.42.1707113371912;
        Sun, 04 Feb 2024 22:09:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f70a:0:b0:681:7940:52c0 with SMTP id w10-20020a0cf70a000000b00681794052c0ls2410613qvn.1.-pod-prod-08-us;
 Sun, 04 Feb 2024 22:09:31 -0800 (PST)
X-Received: by 2002:a0c:e28d:0:b0:68c:777e:f187 with SMTP id r13-20020a0ce28d000000b0068c777ef187mr4095294qvl.23.1707113371271;
        Sun, 04 Feb 2024 22:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707113371; cv=none;
        d=google.com; s=arc-20160816;
        b=e8T/VsFZA9F631idEfHx4eMXf9V6//J96bXyS92x7V9SqdbSrVBCU6YBkoCWI0zfGp
         XHeOfrA0CkFfHu/vFS9/jDsqcNxO8+73W+gNxSQbN0ST+IUJ5XMrltx9dhyPRCksFwPO
         jVBw5+2YhcjpV3dPv2rfpznP1DNl3s4TaCVCJztdxc24eDJ80xk8ACh00Ka7mEigmcGY
         Juop1tA+oCvQ1gZeIMnO0zY9AUGx8T1XXanGlaHBxmSISdoHh1Tgd9NulxkWwDjg4WpL
         p02V4s3SE+re0RnXETcrX11cUEWFyWgcuT7HbBgktxVW0O/J0vhcz4iDXpVfhiyzlylh
         upbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=OIJpegrsies3PJ89GZ7rZiMWECyNHxYJavGTo2IrDuY=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=bL69CagMhHOfwxHJojFe1JRI9pPZBUKfYrPae7IZU1hc0O6wK8lLmVoIW3f5C5jOUc
         IczRdvvmlOFx81Mjp8Lq24OCU0eT8fYxVqMyS+3Kqfe8Y5UvhoeJpvw6n/MjklPbcvO4
         wa/9+WwF8hbdoym1sQgvKQWMrkFE69SS8a1S04h+56ySF9qCwkMSnuFfkAVfymR5rhfk
         pIgzLs8brGKzxnIc8f8zjU3fq2wo29ib8cnhsb0YRye2T/Opf6karvXyiQFa1BJTSkC6
         L2FPmajklVRWNN6FgAU3gS/bSlqFMI+kz2MPLzZhBHIAVX4cvo8HsOFF/C19SEZM4Lnt
         XKiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id r10-20020a0c9e8a000000b0068c907ba310si568302qvd.8.2024.02.04.22.09.29
        for <kasan-dev@googlegroups.com>;
        Sun, 04 Feb 2024 22:09:30 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8DxfeuWe8Bl5ckKAA--.30170S3;
	Mon, 05 Feb 2024 14:09:26 +0800 (CST)
Received: from linux.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxHs+Ve8BluusvAA--.49177S2;
	Mon, 05 Feb 2024 14:09:25 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 0/2] Update kasan docs and tests
Date: Mon,  5 Feb 2024 14:09:20 +0800
Message-ID: <20240205060925.15594-1-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.42.0
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8AxHs+Ve8BluusvAA--.49177S2
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29K
	BjDU0xBIdaVrnRJUUUkYb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26c
	xKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vE
	j48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxV
	AFwI0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E
	14v26r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44
	I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2
	jsIE14v26r1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20x
	vY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I
	3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIx
	AIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAI
	cVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2js
	IEc7CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8j-e5UUUUU==
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

Tiezhu Yang (2):
  kasan: docs: Update descriptions about test file and module
  kasan: Rename test_kasan_module_init to kasan_test_module_init

 Documentation/dev-tools/kasan.rst             | 20 +++++++++----------
 .../translations/zh_CN/dev-tools/kasan.rst    | 20 +++++++++----------
 .../translations/zh_TW/dev-tools/kasan.rst    | 20 +++++++++----------
 mm/kasan/kasan_test_module.c                  |  4 ++--
 4 files changed, 32 insertions(+), 32 deletions(-)

-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205060925.15594-1-yangtiezhu%40loongson.cn.
