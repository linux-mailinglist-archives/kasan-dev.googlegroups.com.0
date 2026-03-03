Return-Path: <kasan-dev+bncBCM3NNW3WAKBBCXETHGQMGQEC4NB4JA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qH5jBw1ypmnLPwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBCXETHGQMGQEC4NB4JA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FDC81E93D7
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:52 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-45f104c0ef1sf55096148b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515851; cv=pass;
        d=google.com; s=arc-20240605;
        b=J1fBFlb8OfRPeYveUEHvQi6y2DtIme+GaKZW7Xgx2O5Tk81LFBMTMyGaddP0DfWB1S
         BiwJSjvTG7WP6sEoqPuAj4dWhpQiwHhNpkLm1PFg+/fdXiTYKvAv85BNHpFl46v6hWmz
         U+2TrN9qw5B3Iuka3cjuc2tfCFMon+FrE+391KD7/VTG0bR2vOW0aj6loKUBIlukGbA2
         DZxqTjWMODcEYDcHVSJmdUm4JMX59ejp9UzFKk2JLGrXqkYARfHo0Y7SE+a4B5uzmotC
         Q2dkYTw3+P/SspeXeYLcT3CYi86xfp7JXJ4CAAatB4uk3BjGo66+m/Vq1VroF7BuwmTC
         b8jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=UiZCEFiRcFK23WCWsrcJV73meiAOPOE0KVp5w5y0S0A=;
        fh=/4NuZ5lb4VHT/CoYhwpmuteomHodlyAzjS7MSO417Ec=;
        b=XHcskfONZMcbG07HzzjitRGhr5O0gjSUQYdnIXVuuV/zrPuA1Sbc3osxNty9uK5KaQ
         ERqDb+YleSVmCKg5y/ELqW5LOAN17VWy+qmpAVJ67EunHky1WlIgzjG+IAudXIVLmHiJ
         b4GVrlSOf9sUPHFsmLqIzgSaEUZsxrerzSrzbxXciQY8raMZErv7ks1JWHF3rXqI5B2r
         MblHm60VeKzdx0YgSirYwB0NpdfLyFqpkXyLBpKNvgj8DJz21sI+CxJEJDBdzZ2xZ3sU
         lQlWw59E4Hi7ER18+y/ASPex4QfPxtfElmKDK1065YQpML5dyx6ARQru0R9eD5Hz7ay1
         Nkvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515851; x=1773120651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UiZCEFiRcFK23WCWsrcJV73meiAOPOE0KVp5w5y0S0A=;
        b=N/fHlWS8bVB74TFMng5n5di7/i6mOSH/kJ76YBO0+xHYB+cZK9lfqF7Rp4L1YvEgWF
         nCqLSjnkhGLRpj9B+DOZxlxU69x9ys4O0CFmOcX0WUFrQK7iWl/UQU/vNe7PnCsaeuvg
         620Qm7hpeiKv/ccfJCT7CPHoZbOnGWHcJ0dEfOyoaP6hLAozLtdahe6yAljhXIYsqMpx
         MapJGo6VAWVcs8+8XXQXdX24xtArz0QGjkW1gdYxuqabjGPMTo1bt99YCNlSDxoWrfXs
         rijqsFzS7Uu7ECH96wlfd9EiYeVJDHMyuAYs4drGTP6M1/f9A8vxHqUQAY5m0az58SNA
         wLMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515851; x=1773120651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UiZCEFiRcFK23WCWsrcJV73meiAOPOE0KVp5w5y0S0A=;
        b=uecDAIOp78avJb9Y4iTPBSLGC3HEA59WWbfnjgH4iT4KkEVS+TZxlcqG+PyLcbqC7e
         8PCKP5lqmdVkYbHLAyL1svfCHt6IzmsxMhE8B9yXqg7rIZmJ8t6HdGexYrnBPuhU1y20
         vVeRnQkbxXcgOPQFsKLPW9jLNiycT7Al1rcxZFg0kTz1Q3bdLpnD/v+dxgIMMPX9Vl2Z
         dUT+/xaP3+pi8bgaZBcKrK2LWnNR6CysVkD4/7V2okS3K8dvsrw70pBWrFKREMCFdp2I
         qW3fCwfIqL/EE762eAyWg4rKJ85KW0X2dj8Y4pm9f1pNp4V9MW8/1+K01Kq6/ee/2z/y
         KezQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4kLLPfEYrmtRkxY4ZoRNu8VYxFp0TzrroHEtOIL8KbgVtTlxnei4Sfr3gD0X6vrcvcPF1UA==@lfdr.de
X-Gm-Message-State: AOJu0YytdUY3k9cbFecJokZWgE9Cc4K1Fn4DjiGX8gUsp2TT/p/HjyiJ
	hEaThw35Epd3wGByFEfZXPbUT3P8Pkd/my+dcl/7YGz0Rsiwp3BxfotQ
X-Received: by 2002:a05:6808:1184:b0:45f:1747:ff54 with SMTP id 5614622812f47-464beb471aemr7408335b6e.37.1772515850683;
        Mon, 02 Mar 2026 21:30:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G6MITEzpRqOCu4Gq37JRS1jJojTiIclpe8CAdEEtR/AQ=="
Received: by 2002:a05:6870:1755:b0:40e:fc09:2e2e with SMTP id
 586e51a60fabf-415f0bb89fels3567067fac.1.-pod-prod-05-us; Mon, 02 Mar 2026
 21:30:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUshlXPDW5EDLV3EE3s6Zgx4E9fXpaaQ0mHqYPsEYu1AqD2E0JQdAcj98fFsFvT/ZRS92vD1YxOYOQ=@googlegroups.com
X-Received: by 2002:a05:6870:a79c:b0:409:dd35:2a51 with SMTP id 586e51a60fabf-41626e0d678mr7983328fac.16.1772515849869;
        Mon, 02 Mar 2026 21:30:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515849; cv=none;
        d=google.com; s=arc-20240605;
        b=OLBXZ9VAhp5Zd5NEsGeD7Wb1k/pQxvtoIIw4tvWiAxShQoF9rSsuVe5/E3Hj7NTS/5
         vXuoI9NRUsJBDygamJZTtkzNcUTvNFyAAVRF+z8QDK5PjWFKhpfXrOuiodiWfMLIfAi1
         Iq9/dabiRKhdIwO5Kn+EV1PN/bPcIpF+ZbP+VQb0tkll++d9djqbgrpcFIK052iZpMmb
         v7Lmy7oz0kG2EI/qi3sxnj7duNAlGX1BTQsaO6kUP9BG3du5RG/BrmLKg0T9ctXOZ/XL
         1QAbxla35EEI5ZxgcN2E9d9eDpJq/ui/pSKdC0bJNqnR4FayTIFriF+FLA7yHYH8Xl9r
         ZffQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=X89AUjDLgQpXvdX4Qd5XB+P5WKqHAPOPossTBOOQmSw=;
        fh=gT/s64yHh0Xs6H3zrWXXukiPDBj0+fd8/hEQlbq05js=;
        b=P/aXCrZRfs7Q6F4jJFakSUvTIXhmv0P5gZwQ2rIv5te0BxeEjUCDAcAz5AknmF912C
         YHIAbpHZwcvYkVP5d+9HzUEuY0pSc8BXc9h4IdleStlWCNBhShHta06V7/3vw4kOrJe1
         IjlOq83FLLyxq3hWFqVzDkyvCtJ31kU30OMYz++whDAEfblf3bLOa24boyEVAFaGNdfm
         GTxvyDuQwC4ddrTiG9f2ToKx/FeX2RbzTs9TFTHebCnymt3OY2P6HA9qMgcbvMwxXfnJ
         coWKcGW9vznlWRVImsFBhdfgPDkKaeSCL0RIRpdEfdq+IxY0b22nMDqtmB+tZR1A3qy4
         qi8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4160cf6000asi567383fac.1.2026.03.02.21.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:49 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S3;
	Tue, 03 Mar 2026 13:30:39 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Tue, 03 Mar 2026 13:29:45 +0800
Subject: [PATCH v2 1/5] riscv: mm: Extract helper mark_new_valid_map()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-1-f80d8354d79d@iscas.ac.cn>
References: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
In-Reply-To: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 stable@vger.kernel.org, Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S3
X-Coremail-Antispam: 1UD129KBjvJXoW7AF1kKF18CF47GFW8WFW8Crg_yoW8Ar1fpF
	ZIkwn5trWfCr1fX39Ivw429r43X34DWa48t3ZIv34rZwn8JrWUWr95Kay8Xr13JFWxXF47
	ua1Skr98uFWUAFJanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmj14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_Jr4l82xGYIkIc2
	x26xkF7I0E14v26r4j6ryUM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1l84
	ACjcxK6I8E87Iv67AKxVWxJr0_GcWl84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2AI
	xVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20x
	vE14v26r1j6r18McIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xv
	r2IYc2Ij64vIr41lF7I21c0EjII2zVCS5cI20VAGYxC7M4IIrI8v6xkF7I0E8cxan2IY04
	v7MxkF7I0En4kS14v26r1q6r43MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j
	6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7
	AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE
	2Ix0cI8IcVCY1x0267AKxVW8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcV
	C2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2Kfnx
	nUUI43ZEXa7VUU66zUUUUUU==
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
X-Rspamd-Queue-Id: 7FDC81E93D7
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
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBCXETHGQMGQEC4NB4JA];
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

In preparation of a future patch using the same mechanism for
non-vmalloc addresses, extract the mark_new_valid_map() helper from
flush_cache_vmap().

No functional change intended.

Cc: <stable@vger.kernel.org>
Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/cacheflush.h | 25 ++++++++++++++-----------
 1 file changed, 14 insertions(+), 11 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index 0092513c3376..b1a2ac665792 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -43,20 +43,23 @@ do {							\
 #ifdef CONFIG_64BIT
 extern u64 new_vmalloc[NR_CPUS / sizeof(u64) + 1];
 extern char _end[];
+static inline void mark_new_valid_map(void)
+{
+	int i;
+
+	/*
+	 * We don't care if concurrently a cpu resets this value since
+	 * the only place this can happen is in handle_exception() where
+	 * an sfence.vma is emitted.
+	 */
+	for (i = 0; i < ARRAY_SIZE(new_vmalloc); ++i)
+		new_vmalloc[i] = -1ULL;
+}
 #define flush_cache_vmap flush_cache_vmap
 static inline void flush_cache_vmap(unsigned long start, unsigned long end)
 {
-	if (is_vmalloc_or_module_addr((void *)start)) {
-		int i;
-
-		/*
-		 * We don't care if concurrently a cpu resets this value since
-		 * the only place this can happen is in handle_exception() where
-		 * an sfence.vma is emitted.
-		 */
-		for (i = 0; i < ARRAY_SIZE(new_vmalloc); ++i)
-			new_vmalloc[i] = -1ULL;
-	}
+	if (is_vmalloc_or_module_addr((void *)start))
+		mark_new_valid_map();
 }
 #define flush_cache_vmap_early(start, end)	local_flush_tlb_kernel_range(start, end)
 #endif

-- 
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-1-f80d8354d79d%40iscas.ac.cn.
