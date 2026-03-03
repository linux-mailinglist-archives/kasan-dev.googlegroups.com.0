Return-Path: <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2DddKQ5ypmnePwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBC7ETHGQMGQEOPQ3K5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123a.google.com (mail-dl1-x123a.google.com [IPv6:2607:f8b0:4864:20::123a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46C0D1E93EE
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:54 +0100 (CET)
Received: by mail-dl1-x123a.google.com with SMTP id a92af1059eb24-126e8ee6227sf9443619c88.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515852; cv=pass;
        d=google.com; s=arc-20240605;
        b=W17D6+vxp1dl+oUgRjkwjlclhnTcro9zKy1j2EdDrjQqlhqvXDYFUHrae1SwkuWcnw
         ybseXa4glewVYw/VffICvxczPGhrPKOrBh2mEjmSKcHQLlMa8bqGmLk8jwi1LYhZ/H98
         hYqZZKJd2ryXg9lUhIdS4V/3t5GGpGIMDOQilbNAD/ydBTxkydJol3qrMBsTi6oErZ7T
         LSJcM4l8yBcxJOioZ+enDc1giec5nnHfAHi6rA6PoO3Gb5zft5Lr0yNsjyDBPyRniXJj
         Is/c9+sHDSdOv6aw79qrnbGGN5F3ubBWax3ZQSIbNwAk9y1kw9/F/hI/P6/20fz8lKJW
         oCyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=7ciVNvqSCDcEjWUK0iUd1okalUoebSI/v96bvy4mlVw=;
        fh=zo7/ZaXyYWIe7+j9m6VaI7V5tACZTWv8gmvMXJJy3uQ=;
        b=h5CVW0lXRqBp5L79pRUbW44R1/4YNalgIWANNhYHlT5dIJQUWlBGcaWffVIuHOAx0z
         rfOjCd2Fo/uNCW1mXii1ptTqw645CnY7qt9yzIqdZQv8z+KrK2B3mFe2vtNN7nIHpM+n
         +tE/2ym2oDLJKVRyzmSqX3t6fTMvs4m0+BnC/oUvlwaYM9+Mq9aqUZIwjmwyD8/QqSdD
         YvEOWwv4B1bv6ENmRFpmEl+yNTBAtnPdx1opnuBjDHqBVV0BrPTrWEx7cQ2AFAmJel+6
         7IUpZDksBqWj85k1XdW+CdYR2AtSeIwPfnZsgiWkQXrl1KskmxOo6W5hES2tnJn4aO40
         /9Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515852; x=1773120652; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7ciVNvqSCDcEjWUK0iUd1okalUoebSI/v96bvy4mlVw=;
        b=feMCvfKdXRNOpkrHejTJ0vtk3JoG1ZjMJus04UO23alovzvjfTHlH7eEtsj/offakZ
         0Fjd29CgFgKV896oDd1eEWSav5HTaR1n8+H5UdyxBobrjb9lf0zfhSVmh0oe8UAmRpbh
         S6+1vpwQsFCV5X8EH7hM8F3PYd4s3eFHH7WPAnZexCqRNjqHU5YsPDSzZO4sGSx3AYRH
         EMDx36D/kw5UynrD9+wWV9FBbnii01Edm/w4i4cW7XfRKpETnCFhh9XAGK5rJ4ZJB8nA
         b882gC4mnGN/vD1zOcEy1yuWgJM+481KnRugYlzcsiLe8YyJuD8pnMYAeXC2ofPotjYQ
         gSNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515852; x=1773120652;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7ciVNvqSCDcEjWUK0iUd1okalUoebSI/v96bvy4mlVw=;
        b=Qrme9OfWwPyUg0Ih52ePinWxNZD7CnIOGYABwrlRcgRUDBFs5GtTHDFiWRSJmnQeFY
         dR0W/m0XATRx+AMSgSDXfAv1kDSo86bkHMqLOJq/BPz9c6ZZSuFpWTEtgOCpn4IbDmao
         pEZndrLHGTuagR27jREcJhQGu8IfqrVxViEe7bU4MQObqJebmGjvx8fJNYvSeeeRviaB
         ad8ILL5skLj3NFc++UYNPNnxAX5u9O+D5j1a/9yWCtgsFETaQJrlENGbkH4nkxqCRXik
         y4n6kd4Ld2QGl2CwRdsHqvWkXuImqtm6w7iSCpNSCOVnYocjwm9RPTWHdpOMSFp1mwwR
         8A8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXe48VDq/ECEqd/nQuvf1xxHKrOZueHCh5w5Jnuk//wfdftVE8Xtf7iTxTYrU2zhFu2571lzQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywej350ME5NI6oFba4NzSiISd2kPBFzoC/3LwbK46PPgit3sThQ
	Z9ASAZ19sXqhP8J5GUrgrMYzw6Zv1eS/Nwh5BSl4wM4woD5m6r1r+TIu
X-Received: by 2002:a05:7022:4381:b0:11e:528:4185 with SMTP id a92af1059eb24-1278fc568a2mr5571260c88.38.1772515852267;
        Mon, 02 Mar 2026 21:30:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hwamnzni+07GbQsjmeDwWMa1A820r+jL1J7prspypsvQ=="
Received: by 2002:a05:7022:2207:b0:11b:519:bafd with SMTP id
 a92af1059eb24-12782604291ls3091086c88.1.-pod-prod-09-us; Mon, 02 Mar 2026
 21:30:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVh7/PhqU613/PbChfdWkVKtNOYpmoBZ0LnRF8jyc1ZnRUfYZAQcP4Ox2d0DAJ3321onbfvk9AzjlM=@googlegroups.com
X-Received: by 2002:a05:7022:6082:b0:119:e55a:9be4 with SMTP id a92af1059eb24-1278fa9f6fdmr7438704c88.0.1772515850747;
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515850; cv=none;
        d=google.com; s=arc-20240605;
        b=cugdL6/pfRNPG+KK/9l5QjiqHhyr01tXo3CMv1jRJx5IFE6E6OQbBJt51vscFn5syk
         njwhOXqiNVC0b1RLC/BYv0zmMvIg4RTkC7g8vT4ueSw7kTKTFLnRaYzDgbmN7bNGLtCf
         wxL/B9IwWIKH0eTFo6KRX+zxcjCap3b4vP8x/yqnzfiZ9LtjZG7+mcnfTVyIoZ2yaeyB
         JdAYvaNTevM4bc/cBiFdZsDCab3s2DG93Za8WR9UX7i6KrS9ePHXn7vNbrIEPSwt2eMQ
         W+1D4KjfKnJKjAc57GE1wLFRLHg6Nn2JweqidUop+dNfO1x8HjajVi+kpQoMslNH2k71
         ImbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=Jey7zz6vCE0Q8hXlyerv0btBlEXXQP7Hc0bAa2Wgfxo=;
        fh=SdftT8st9Mc1yZfaIFEwgRMwSCuwzBPE+XriZKimrSU=;
        b=URiMBqKFFL1C9MHIPIT3VvJAamqOmA+9bssfWe3NY8ncOgGQJKdi+2rvEcMN9s/aCs
         kpaigkIDzPyrPKZYztP+FN0XzqJMSe+oAsw7PbPfnYC8mdXyIOKCREQLruxOW3Eg0X4a
         mflY3uQcTL8yV2tVdOLsl0RwW+kXa0V9hBrxFuWt3AQCDneMskxL4wTuS7LOc9LO5Lur
         Qt45ycjyMLfGbjjHk7KCedOUiztoq7VvBneh53A55SgidEUvNRVaGPc82eH+6hb9Ry/a
         /rq2jK4Hul80kKGvzae8P5GYd/zppXvIgvtz/WyT9yzsdg/k1Kq9Q+4uQdSHQKFyVQSx
         AU/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-1279e66b99fsi181025c88.0.2026.03.02.21.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S6;
	Tue, 03 Mar 2026 13:30:39 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Tue, 03 Mar 2026 13:29:48 +0800
Subject: [PATCH v2 4/5] riscv: mm: Use the bitmap API for
 new_valid_map_cpus
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-4-f80d8354d79d@iscas.ac.cn>
References: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
In-Reply-To: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S6
X-Coremail-Antispam: 1UD129KBjvJXoW7ZF45Gr4xCr45Jw4kXF1rCrg_yoW8AFWkpr
	Z8Cw1kGrWrur1xZ3y2yw4Uur4rGa4qgFySkayFk345Za1Dtr47JrZ5Ga47Jry7GFZ8XF4x
	Cw43CryruryUAa7anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmI14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JF0E3s1l82xGYI
	kIc2x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2
	z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr
	1UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq
	3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7
	IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4U
	M4x0Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2
	kIc2xKxwCY1x0262kKe7AKxVWUtVW8ZwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkE
	bVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67
	AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI
	42IY6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCw
	CI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnI
	WIevJa73UjIFyTuYvjfUeLvNUUUUU
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
X-Rspamd-Queue-Id: 46C0D1E93EE
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
	RCPT_COUNT_TWELVE(0.00)[12];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,iscas.ac.cn:mid,iscas.ac.cn:email]
X-Rspamd-Action: no action

The bitmap was defined with incorrect size. Fix it by using the proper
bitmap API in C code. The corresponding assembly code is still okay and
remains unchanged.

Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/cacheflush.h | 8 +++-----
 arch/riscv/mm/init.c                | 2 +-
 2 files changed, 4 insertions(+), 6 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index 8c7a0ef2635a..8cfe59483a8f 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -41,19 +41,17 @@ do {							\
 } while (0)
 
 #ifdef CONFIG_64BIT
-extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
+/* This is accessed in assembly code. cpumask_var_t would be too complex. */
+extern DECLARE_BITMAP(new_valid_map_cpus, NR_CPUS);
 extern char _end[];
 static inline void mark_new_valid_map(void)
 {
-	int i;
-
 	/*
 	 * We don't care if concurrently a cpu resets this value since
 	 * the only place this can happen is in handle_exception() where
 	 * an sfence.vma is emitted.
 	 */
-	for (i = 0; i < ARRAY_SIZE(new_valid_map_cpus); ++i)
-		new_valid_map_cpus[i] = -1ULL;
+	bitmap_fill(new_valid_map_cpus, NR_CPUS);
 }
 #define flush_cache_vmap flush_cache_vmap
 static inline void flush_cache_vmap(unsigned long start, unsigned long end)
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 9922c22a2a5f..a2fc70f72269 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -37,7 +37,7 @@
 
 #include "../kernel/head.h"
 
-u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
+DECLARE_BITMAP(new_valid_map_cpus, NR_CPUS);
 
 struct kernel_mapping kernel_map __ro_after_init;
 EXPORT_SYMBOL(kernel_map);

-- 
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-4-f80d8354d79d%40iscas.ac.cn.
