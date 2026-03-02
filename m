Return-Path: <kasan-dev+bncBCM3NNW3WAKBBQHISPGQMGQECH2ELCA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UFRVKUP0pGmcwgUAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBQHISPGQMGQECH2ELCA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x1338.google.com (mail-dy1-x1338.google.com [IPv6:2607:f8b0:4864:20::1338])
	by mail.lfdr.de (Postfix) with ESMTPS id 44CB71D271C
	for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 03:21:55 +0100 (CET)
Received: by mail-dy1-x1338.google.com with SMTP id 5a478bee46e88-2b81ff82e3csf2254339eec.0
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2026 18:21:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772418113; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fr2SNuqzbkLHgj7lVA+zFdQgVo0SGhrzhGc7KQL45ZxOyA5bMBkJD+YP5CWaKF+Vvx
         9r1oYQh8RpJm8NnQxD+MDGfiQRJsvcCnOZzjt/qyeKsJR7V/5XF2MGJXp7GJq/pr0t8U
         S9dNKW0FiKT3QfSA+2IWC2EAJna231mQmSVyVLxrwWh5YlM0DnIE/wfmEfi4BWrWpgg+
         QVBqQfIslR0/eDJ5YKJR7aDzyGEMVfCWYWsFcCj80SqOtqiirDZhxs3L9RIVGh8mCpYw
         4uoQT1Bwsk22gk44bOPy9uyaxEsuMSEmqZkiQrgRYw6/zAjpaLtDMRGBQ5IPgavUtM0G
         /XOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=0ub9BiYJf0XykaJDibW7+x4Yih61mD2PMCBn2ASwbkE=;
        fh=YaYU+GyMW/4dApaxfXLIAc3NMBv/+x97yLs9Ymbl+Xc=;
        b=HqD0S24JwFm1CFrhku3VxEurPrhLcoZzH4Zaf1IguSMcu/mXRGDE4y59EsbeVKDNLw
         HruPTcOgZXb54DMZQ0h2dAvQ1F4DJRG30Pd7SVfz/jAJPz1qyV/rIdB5H4fWJyNlHL9/
         9RVjkf5YS4Sx0qixhAsTexMLTtv2khmWm+pxwK2VORkGKvCrvxWHexbUQ60YO+CVI/5d
         BwLYouAn0akkFJi0gs6bY2S9DdkT/Rj3dSmrn6PGXE2zIwEF7iwkdXXfTl8Jk+rOuqBd
         rE8NDL63OtjXt9tyDBTiPn8I9UjDOdBDIVjYWuEUM/5lwrG5qYe4Gj34mRCNjYcC7aOJ
         3ejA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772418113; x=1773022913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0ub9BiYJf0XykaJDibW7+x4Yih61mD2PMCBn2ASwbkE=;
        b=sh5IXk9ZtCsuYblGmTzQNqartDgJShrBqQs67GfFFkUoGzHxcuCozQTlk1sX/Y146u
         aa3mEe+Z67e27SsSQG7V/WMTe23cOJYo4KyJjLfBc5N34mbXzzHNHAR6gbxTjHVAp1xq
         4n0lybc7TjVrMGZuXOZ+sQPtmV994F/Jaq1pT8OzOPOJnKYKN3AW3Ui0X2W3GIM+QZU8
         Ez3gmfLFOjYrbNFU+2T0mJb3ezazp281/F1XFh2ZNeZ1z8cmKYKNBg+eVhhBqHR3z5FO
         zbyzVSQ0H9GGQotUER1+XQhADf51NKNWF1mW1cr/30Qv/1QcQTeYzmLKBYWgZ/vS3OzY
         luug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772418113; x=1773022913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0ub9BiYJf0XykaJDibW7+x4Yih61mD2PMCBn2ASwbkE=;
        b=l3RPVr1vsUq0auhyCEdptFVo5yNDIOVLCE2AVecPqBYF5eI7P2Bq/RoTNJY6/Amxro
         +gJONCu7Zb11AcBzyRzQySl1y7JI72q4ls+ldW9nZMEr0nhNn2cpoVAs0zcBPEPdSCOO
         EwXPkYq5gHxmRD561jcZtPJo+qjOhgaW1jguGPTLbS+sWIGAjZfZil466+4m8MDZ2mi7
         3Tajg2cUQetQRhnnbjRg9KZ9SAtLSktJ/9blvwZlIRPA/IXuDQXP+PBn4AgXA++4GAna
         haF+YSkk9gl5th3gXBLLg6CVW1DqTSENIUYU+acrqYmkI2PgOPsUB0WRs4ZLVJCjEwT3
         CgtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7sV2sIXn5hUDBF4a940VABanCLr/L/cf83wu4NpIEjq3N/WPbvLPktpLrecxVUeXVdz18gg==@lfdr.de
X-Gm-Message-State: AOJu0YzXBjAmxbvxgn5Di4YopEgv5OBM54D2Nor+0FCtFRY5fk4m1FWF
	6qk2kEuJ7OLT0wbVjE0DwdBGSpwm5xwTLStB1jCneB1JrBeDS4khVYls
X-Received: by 2002:a05:7022:a86:b0:11d:fd41:62c8 with SMTP id a92af1059eb24-1278f82a1b4mr3767392c88.13.1772418113278;
        Sun, 01 Mar 2026 18:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hnbr8aaVijMn4OD2fJs6d6aYicgBZU1nBBkAO4LhaT+w=="
Received: by 2002:a05:7022:eb46:20b0:124:75a3:847d with SMTP id
 a92af1059eb24-1277a28fa1cls1111193c88.1.-pod-prod-00-us-canary; Sun, 01 Mar
 2026 18:21:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXI59wRubS3XjKt3gwZGf4a8wcrWk1iD0KD3Rdus+AZNJ0UBKDAZqnTjI/MTmPRchsONDbm6JVNE8o=@googlegroups.com
X-Received: by 2002:a05:7300:8b84:b0:2bd:816b:734d with SMTP id 5a478bee46e88-2bde20f9244mr3448506eec.18.1772418111812;
        Sun, 01 Mar 2026 18:21:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772418111; cv=none;
        d=google.com; s=arc-20240605;
        b=Bn5CFS4A3fFb/ONlexU3hO2YyTP0FODTWbBcELbiHQWjwgQrK23UQ6FBbcoWrush7J
         hQ0ZgRTzSY8IpnY6jnHjszlzw5nZlHuIVOe1AlngwFM+lZAj3HxEWYDDdwj2ELhoxIHr
         3t0Ks9/6B+Xn1c+nslRrYaecYUuPG+1+C8e3ZoczIllriCsknl9ran3fhhQp8663Xd9j
         dlqWIsZbOKS0vydGMrHsXyXcbr+GhB2i4n8O2b6S/BHahFiSb/P03fqKvmlzWyXp8TKn
         F4Sge6vRdfbdPFqSEm2UUxSwnBG/t2u/9FtECy2QfGPPSnRTqggZxYJSBeWDH2Io7KG8
         goyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=ipuRegqSYXeimIg6ufI/AkhLMt3/ujyQb0qbaFT4VbE=;
        fh=L8rAVU/Y///N6DPc9GQrjb2RcG4PA6dV6b84bmkByNc=;
        b=UGI1avqpF3ARzkKGvnAmG1O5vUvVWKO2Dil7UGzUaAsGqw2zk+Bajz7Opc8ZdgQfKC
         VKE2efDxoADJEV5VRhKAZm40wPFmfN7VVEPYHtam9vqclosne71QwEJh38iVFhYJCo0N
         4JNQJwyM2GdiSgXecbcYNE78f3b6B13iH81INIj8xatdTGUCF435P7dRIUcSd4AvamFN
         /b35Umxq5ExE0129pmj742wnMRJjqg3vb7GLbVOniMkAohg1ivLoAbYsZs7bfFb7Vhdc
         dfD42jBmA9ZJS9/tJwDT4O/lykqnQwz9IfktUpRBkYA2J3zFdngmyUxteraekpPIDWyL
         X7HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2be10665ad5si62945eec.2.2026.03.01.18.21.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2026 18:21:51 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAD3E9s39KRp6CWmCQ--.11902S4;
	Mon, 02 Mar 2026 10:21:44 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Mon, 02 Mar 2026 10:21:31 +0800
Subject: [PATCH 2/3] riscv: mm: Extract helper mark_new_valid_map()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260302-handle-kfence-protect-spurious-fault-v1-2-25c82c879d9c@iscas.ac.cn>
References: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
In-Reply-To: <20260302-handle-kfence-protect-spurious-fault-v1-0-25c82c879d9c@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAD3E9s39KRp6CWmCQ--.11902S4
X-Coremail-Antispam: 1UD129KBjvJXoW7AF1kKF18CF4kKw1Duw15Jwb_yoW8Ar4xpF
	Wakwn5GrWrCr1fX3yavw42g3yrX34DWa4rKasIy345A3WDJFW7GrZ5KayrXr13JFW7XF17
	ua1akr98uryUZFJanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmK14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_Jryl82xGYIkIc2
	x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq3wAS
	0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2
	IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0
	Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2kIc2
	xKxwCY1x0262kKe7AKxVWUtVW8ZwCY02Avz4vE14v_Gr1l42xK82IYc2Ij64vIr41l4I8I
	3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxV
	WUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAF
	wI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcI
	k0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j
	6r4UJbIYCTnIWIevJa73UjIFyTuYvjfUO0PSUUUUU
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
	RCPT_COUNT_TWELVE(0.00)[12];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBQHISPGQMGQECH2ELCA];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,iscas.ac.cn:mid,iscas.ac.cn:email]
X-Rspamd-Queue-Id: 44CB71D271C
X-Rspamd-Action: no action

In preparation of a future patch using the same mechanism for
non-vmalloc addresses, extract the mark_new_valid_map() helper from
flush_cache_vmap().

No functional change intended.

Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/include/asm/cacheflush.h | 25 ++++++++++++++-----------
 1 file changed, 14 insertions(+), 11 deletions(-)

diff --git a/arch/riscv/include/asm/cacheflush.h b/arch/riscv/include/asm/cacheflush.h
index b6d1a5eb7564..8c7a0ef2635a 100644
--- a/arch/riscv/include/asm/cacheflush.h
+++ b/arch/riscv/include/asm/cacheflush.h
@@ -43,20 +43,23 @@ do {							\
 #ifdef CONFIG_64BIT
 extern u64 new_valid_map_cpus[NR_CPUS / sizeof(u64) + 1];
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
+	for (i = 0; i < ARRAY_SIZE(new_valid_map_cpus); ++i)
+		new_valid_map_cpus[i] = -1ULL;
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
-		for (i = 0; i < ARRAY_SIZE(new_valid_map_cpus); ++i)
-			new_valid_map_cpus[i] = -1ULL;
-	}
+	if (is_vmalloc_or_module_addr((void *)start))
+		mark_new_valid_map();
 }
 #define flush_cache_vmap_early(start, end)	local_flush_tlb_kernel_range(start, end)
 #endif

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260302-handle-kfence-protect-spurious-fault-v1-2-25c82c879d9c%40iscas.ac.cn.
