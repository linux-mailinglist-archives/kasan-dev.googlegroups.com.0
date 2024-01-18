Return-Path: <kasan-dev+bncBD55D5XYUAJBB65YUSWQMGQE3XYQCXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 667A483194C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 13:41:32 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-204047a3789sf17082585fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 04:41:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705581691; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0EyFgroRMQj44ZnykLpN28yVc/CCo5acdP4PCVG7l8bE1ey8InReY6XMHPnj2YhAW
         H9L6XCvHJVbBwYOwUYJV6Jl8TKN028bMBsvsMChUWQAY+1P0Y+hyKAdWUiuaDLC+kgQk
         MuBtOYbHnqbSPvPnLsN5DWDudnz8gDUTxeX7aWlQ5r7ymO0CtwsRD+2mt4XvzHSPjuoK
         esUoCOkMMgoNaHiHeO1uWlOOvPb3z+CVT+Yqf35OrbNK3CRPLbAroKb+2GThBCcqqOHu
         QSS7f0jyMVyDod2tDfUq3/ss31mJtZBC4JuSNJF4+Z3jRPr6PMiPFBGXNgZ8bSzovk2Z
         n28A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Sofz8huaYgexU3BWs+24HdBCI0KABpjXoKluAbAz2Gw=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=M9dpFYtuwDPAEAesf4pIrqarg0jTJXDYmLhx5+8UrtZMs4IRzFZvXNeSkgGh181xNt
         dbRrNX0Xj4yT6fgSHAofeJI+heiyooLcaSFEHcE+DPO8FFB6DNKJNZQeGm2ZxtMq0zYh
         C3h7vMIl6hn63eU/hLsVhRZA7z56k2qrqhdOotGAQkbMeG5jd6CMD31NckU8erobajxo
         iPeUveuzaJh+97lNckqHqbb03vE1Pc/1mo/X055l81+UMYkiLb5O1UXD3i2fuNXecI5a
         5odJWDaIHTYypJzVtoqkSOvYLaIEVMKTQaPY2f/1PzLlXAJAX1ldJPE/smbJVzLnDLmo
         H/sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=KOYwh0hd;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705581691; x=1706186491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Sofz8huaYgexU3BWs+24HdBCI0KABpjXoKluAbAz2Gw=;
        b=KRAAlxwXykHEFMzKSMDTlUV/xgK97gFSA6U/SD4Mq/ixQ7E2SuoQcdS1npq9bzBQm0
         iziRbWIfUXBH3tv9xbcEvVstux6GYKaU5SS7wv8fjoVuRP6y9ISEEkwQPwML8DDDGWJi
         DTXVMYAp7S7jUa5dezpbiOEwh1TSV+4Rncv6UON+VOTlFGOeTW1W4OCqFypuuMH28pWb
         0kWuv3K6U8pCKWBUcEzsbwiueAilhA1/dEMfcP8S4Me2xWaJzZtYW/jvsMqeZzXsLy/9
         YI5aPj4NFYAH/avfkEI3mSBIED7TqzHNH8HlYFXjzMpj95ly8wYkdBy11NGWDQQPePI/
         b36A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705581691; x=1706186491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Sofz8huaYgexU3BWs+24HdBCI0KABpjXoKluAbAz2Gw=;
        b=gLf2NR4KYRR8poNLyLlf1z1BsC4keIO893w6DnnkCCRdHJglvtuOcbc61e+eggE8+5
         C/L1gZj5lYOOBMxWZFiH1eXrMSNONEitl/boEk7fMXwxRDDchwSLg3YCOCKbP0Uh+Vcd
         9UENHfAoAk7YBtULxhnUvs2pBszKyLGJZfmbE17uvtr/qefd9dDWY5Cn/nhRu0W57HM1
         bD9JCVYKenUALapBm+VORI/BJfU/6HtHHVFAkRS4ozT0VX0AL98x66VOdwpX9Na9d+E1
         U9BXGF4QZPUqjq7ZdMpuPjB4SFHNqvlrr/qFZfFFV0RKYXR3r4iHYJhHeqtcdGuY8dM+
         Gnzg==
X-Gm-Message-State: AOJu0Yz5z1NmiBFTAztY73z2zlMt/qlw76UWzX5hYHMBZgsIVa3MFaNb
	9By40KoUkGuMLoRpzZxrAmOdz8dUmCGgt+PtmNJlx/nyWB1wsymn
X-Google-Smtp-Source: AGHT+IEahYpy1oTPm+jvDJjNbUTgWV6OpTnvfQV4UaqRFj1WesSfLkbLH/P3xw7MZyDLIYUnm1Je6g==
X-Received: by 2002:a05:6870:b4a1:b0:210:7332:36d1 with SMTP id y33-20020a056870b4a100b00210733236d1mr614782oap.17.1705581691093;
        Thu, 18 Jan 2024 04:41:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:35cb:b0:206:b891:5006 with SMTP id
 c11-20020a05687035cb00b00206b8915006ls176388oak.1.-pod-prod-04-us; Thu, 18
 Jan 2024 04:41:30 -0800 (PST)
X-Received: by 2002:a05:6870:d60d:b0:204:1590:2044 with SMTP id a13-20020a056870d60d00b0020415902044mr713308oaq.5.1705581690367;
        Thu, 18 Jan 2024 04:41:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705581690; cv=none;
        d=google.com; s=arc-20160816;
        b=u0qTblJg4tUbeVHlYUENu+xTStuwYsVKGg7WdOHLDPB0MXoY5dTplWfSFswCXeOKbq
         7B4mmHCgpu9NF7t6X4zLJ+ywmR3mfe/BeigvWk8sKuzAFYZNY2nCK5E6gUDMxY82PK/9
         D5220Mtvlb2DIRJN7ULQBU33gkwIh3J/NSgof1Fyb+FNXQoOSDPRyMw0INQSCjmvK3S2
         gbG7DQxxxZtLx7qL7932jmPAfYte/z7VayyWrzqTDgwb2zBsrhcxVIYuC6q7JwCdf/EV
         NOph1huO3J5Kwswau4brJc+35yvOezoyOHK3n9RNxF9A3lacKCMPfCJHJnyTRpooMhCR
         BXdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7X0c+MMnT5ixfOkPAVKJUdxf0xJI7ufL6KL0JiMq+9I=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=R1cZ2PCMI9BWqR+rj7iddvAkMazy1g24FyuXgX6mW6vldmPKvoec9xW/7hPcTWISX9
         z7Ub3pt1DCQx1elhxdBvfB1WWAfrvgeoZpO1BkjOskApTe1oNdPXkUtkfuyMj5cRcyHw
         JsngXgrjy/qO9Hqrx4UL3ZIM32pI/jISSYszvF9TiknJpU/9RY9ZJgAhecvuyMYuIg4c
         bqDb24L1XCQkCzOsk4xSgH7yR+Xv8NVIWZ13KrZ2PMuxsZWyLtqft3d8c6thT+eWq9qg
         g2E+ouCKu3GkLuR7wc4sLmfQZaVtrUfeU/ZrVS3PRIRzCfINDD8EhQDCTagEbN2bEEsk
         oClw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=KOYwh0hd;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id g25-20020a9d6b19000000b006df9f60b802si116603otp.3.2024.01.18.04.41.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 04:41:30 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-6dac225bf42so6531019b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 04:41:30 -0800 (PST)
X-Received: by 2002:aa7:998a:0:b0:6db:dae:c5aa with SMTP id k10-20020aa7998a000000b006db0daec5aamr709361pfh.63.1705581689774;
        Thu, 18 Jan 2024 04:41:29 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.13])
        by smtp.gmail.com with ESMTPSA id y17-20020a056a00191100b006d977f70cd5sm3199744pfi.23.2024.01.18.04.41.25
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Thu, 18 Jan 2024 04:41:29 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com
Subject: [RFC 1/2] kasan: introduce mem track feature base on kasan
Date: Thu, 18 Jan 2024 20:41:08 +0800
Message-ID: <20240118124109.37324-2-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240118124109.37324-1-lizhe.67@bytedance.com>
References: <20240118124109.37324-1-lizhe.67@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=KOYwh0hd;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42a
 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: lizhe.67@bytedance.com
Reply-To: lizhe.67@bytedance.com
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

From: Li Zhe <lizhe.67@bytedance.com>

This is a feature based on KASAN_GENERIC.

The current implementation of kasan can help us locate memory's
problems such as out-of-bounds, use-after-free, etc. But it cannot
identify memory tramples on allocated memory by software. This type
of problem may appear in our daily development. Generally, the
phenomenon is rather strange and problem is difficult to locate.
With this tool, we can easily locate memory corruption on allocated
memory.

In the current kernel implementation, we use bits 0-2 of each shadow
memory byte to store how many bytes in the 8 byte memory corresponding
to the shadow memory byte can be accessed. In addition, for inaccessible
memory, the highest bit of its shadow mem is 1. Therefore, we can use the
free bits 3-6 of shadow mem to record the track information corresponding
to 8-byte of memory, that is, one bit records track information of 2 bytes.
If the track bit of the shadow mem corresponding to a certain memory is
1, it means that the corresponding 2-byte memory is tracked. Of course,
if we configure a byte to be tracked, when we access its paired byte,
the track check will also be successfully triggered, which will cause us
some interference. But for this type of false positives, we can easily
identify them by checking kasan logs. And I think this shortcoming should
not overshadow the convenience that this feature brings to our debugging.

Signed-off-by: Li Zhe <lizhe.67@bytedance.com>
---
 lib/Kconfig.kasan         |   9 ++
 mm/kasan/generic.c        | 276 +++++++++++++++++++++++++++++++++++---
 mm/kasan/report_generic.c |   6 +
 3 files changed, 275 insertions(+), 16 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index e6eda054ab27..d96e28757fb7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -183,6 +183,15 @@ config KASAN_VMALLOC
 	  With Hardware Tag-Based KASAN, only non-executable VM_ALLOC mappings
 	  are checked. There is no additional memory usage.
 
+config KASAN_MEM_TRACK
+	bool "Capture allocated memory corruption based on KASAN"
+	depends on KASAN_GENERIC && KASAN_OUTLINE
+	help
+	  Enable memory tracking bases on kasan. This is a tools to capture
+	  memory corruption on allocated memory.
+
+	  If unsure, say N.
+
 config KASAN_KUNIT_TEST
 	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
 	depends on KASAN && KUNIT && TRACEPOINTS
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 24c13dfb1e94..a204ddcbaa3f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -42,9 +42,94 @@
  * depending on memory access size X.
  */
 
-static __always_inline bool memory_is_poisoned_1(const void *addr)
+#ifdef CONFIG_KASAN_MEM_TRACK
+#define KASAN_SHADOW_VALUE_MASK_ONE_BYTE	0x07
+#define KASAN_TRACK_VALUE_MASK_ONE_BYTE		0x78
+#define KASAN_SHADOW_VALUE_MASK_TWO_BYTE	0x0707
+#define KASAN_SHADOW_VALUE_MASK_EIGHT_BYTE	0x0707070707070707
+#define KASAN_TRACK_VALUE_MASK_EIGHT_BYTE	0x7878787878787878
+#define KASAN_TRACK_VALUE_OFFSET			3
+static __always_inline bool is_poison_value_1_byte(s8 shadow_value)
+{
+	if (shadow_value & 0x80)
+		return true;
+	return false;
+}
+
+static __always_inline bool is_poison_value_8_byte(u64 shadow_value)
+{
+	if (shadow_value & 0x8080808080808080)
+		return true;
+	return false;
+}
+
+static __always_inline s8 to_shadow_value_1_byte(s8 shadow_value)
+{
+	if (is_poison_value_1_byte(shadow_value))
+		return shadow_value;
+	return shadow_value & KASAN_SHADOW_VALUE_MASK_ONE_BYTE;
+}
+
+static __always_inline s8 to_track_value_1_byte(s8 shadow_value)
+{
+	if (is_poison_value_1_byte(shadow_value))
+		return shadow_value;
+	return (shadow_value & KASAN_TRACK_VALUE_MASK_ONE_BYTE) >>
+				KASAN_TRACK_VALUE_OFFSET;
+}
+
+static __always_inline u64 to_shadow_value_8_byte(u64 shadow_value)
+{
+	if (is_poison_value_8_byte(shadow_value))
+		return shadow_value;
+	return shadow_value & KASAN_SHADOW_VALUE_MASK_EIGHT_BYTE;
+}
+
+static __always_inline u64 to_track_value_8_byte(u64 shadow_value)
+{
+	if (is_poison_value_8_byte(shadow_value))
+		return shadow_value;
+	return shadow_value & KASAN_TRACK_VALUE_MASK_EIGHT_BYTE;
+}
+
+static __always_inline s8 get_shadow_value_1_byte(const void *addr)
 {
 	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);
+	return to_shadow_value_1_byte(shadow_value);
+}
+
+static __always_inline u16 get_shadow_value_2_byte(const void *addr)
+{
+	u16 shadow_value = *(u16 *)kasan_mem_to_shadow(addr);
+
+	return shadow_value & KASAN_SHADOW_VALUE_MASK_TWO_BYTE;
+}
+#else
+static __always_inline s8 to_shadow_value_1_byte(s8 shadow_value)
+{
+	return shadow_value;
+}
+static __always_inline u64 to_shadow_value_8_byte(u64 shadow_value)
+{
+	return shadow_value;
+}
+static __always_inline s8 get_shadow_value_1_byte(const void *addr)
+{
+	return *(s8 *)kasan_mem_to_shadow(addr);
+}
+static __always_inline u16 get_shadow_value_2_byte(const void *addr)
+{
+	return *(u16 *)kasan_mem_to_shadow(addr);
+}
+static __always_inline bool memory_is_tracked(const void *addr, size_t size)
+{
+	return 0;
+}
+#endif
+
+static __always_inline bool memory_is_poisoned_1(const void *addr)
+{
+	s8 shadow_value = get_shadow_value_1_byte(addr);
 
 	if (unlikely(shadow_value)) {
 		s8 last_accessible_byte = (unsigned long)addr & KASAN_GRANULE_MASK;
@@ -57,34 +142,30 @@ static __always_inline bool memory_is_poisoned_1(const void *addr)
 static __always_inline bool memory_is_poisoned_2_4_8(const void *addr,
 						unsigned long size)
 {
-	u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
-
 	/*
 	 * Access crosses 8(shadow size)-byte boundary. Such access maps
 	 * into 2 shadow bytes, so we need to check them both.
 	 */
 	if (unlikely((((unsigned long)addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
-		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
+		return get_shadow_value_1_byte(addr) || memory_is_poisoned_1(addr + size - 1);
 
 	return memory_is_poisoned_1(addr + size - 1);
 }
 
 static __always_inline bool memory_is_poisoned_16(const void *addr)
 {
-	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow(addr);
-
 	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
 	if (unlikely(!IS_ALIGNED((unsigned long)addr, KASAN_GRANULE_SIZE)))
-		return *shadow_addr || memory_is_poisoned_1(addr + 15);
+		return get_shadow_value_2_byte(addr) || memory_is_poisoned_1(addr + 15);
 
-	return *shadow_addr;
+	return get_shadow_value_2_byte(addr);
 }
 
-static __always_inline unsigned long bytes_is_nonzero(const u8 *start,
+static __always_inline unsigned long bytes_is_nonzero(const s8 *start,
 					size_t size)
 {
 	while (size) {
-		if (unlikely(*start))
+		if (unlikely(to_shadow_value_1_byte(*start)))
 			return (unsigned long)start;
 		start++;
 		size--;
@@ -93,7 +174,7 @@ static __always_inline unsigned long bytes_is_nonzero(const u8 *start,
 	return 0;
 }
 
-static __always_inline unsigned long memory_is_nonzero(const void *start,
+static __always_inline unsigned long shadow_val_is_nonzero(const void *start,
 						const void *end)
 {
 	unsigned int words;
@@ -113,7 +194,7 @@ static __always_inline unsigned long memory_is_nonzero(const void *start,
 
 	words = (end - start) / 8;
 	while (words) {
-		if (unlikely(*(u64 *)start))
+		if (unlikely(to_shadow_value_8_byte(*(u64 *)start)))
 			return bytes_is_nonzero(start, 8);
 		start += 8;
 		words--;
@@ -126,7 +207,7 @@ static __always_inline bool memory_is_poisoned_n(const void *addr, size_t size)
 {
 	unsigned long ret;
 
-	ret = memory_is_nonzero(kasan_mem_to_shadow(addr),
+	ret = shadow_val_is_nonzero(kasan_mem_to_shadow(addr),
 			kasan_mem_to_shadow(addr + size - 1) + 1);
 
 	if (unlikely(ret)) {
@@ -135,7 +216,7 @@ static __always_inline bool memory_is_poisoned_n(const void *addr, size_t size)
 		s8 last_accessible_byte = (unsigned long)last_byte & KASAN_GRANULE_MASK;
 
 		if (unlikely(ret != (unsigned long)last_shadow ||
-			     last_accessible_byte >= *last_shadow))
+			     last_accessible_byte >= to_shadow_value_1_byte(*last_shadow)))
 			return true;
 	}
 	return false;
@@ -161,6 +242,168 @@ static __always_inline bool memory_is_poisoned(const void *addr, size_t size)
 	return memory_is_poisoned_n(addr, size);
 }
 
+#ifdef CONFIG_KASAN_MEM_TRACK
+static __always_inline s8 get_track_value(const void *addr)
+{
+	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);
+
+	/* In the early stages of system startup, when Kasan is not fully ready,
+	 * some illegal values may be obtained. Ignore it.
+	 */
+	if (unlikely(shadow_value & 0x80))
+		return 0;
+	return (shadow_value >> KASAN_TRACK_VALUE_OFFSET);
+}
+
+/* ================================== size :	  1     2     3     4     5     6     7    8 */
+static const s8 kasan_track_mask_odd_array[] = {0x01, 0x03, 0x03, 0x07, 0x07, 0x0f, 0x0f};
+static const s8 kasan_track_mask_even_array[] = {-1,  0x01,  -1,  0x03,  -1,  0x07,  -1, 0x0f};
+static s8 kasan_track_mask_odd(size_t size)
+{
+	return kasan_track_mask_odd_array[size - 1];
+}
+
+static s8 kasan_track_mask_even(size_t size)
+{
+	return kasan_track_mask_even_array[size - 1];
+}
+
+/* check with addr do not cross 8(shadow size)-byte boundary */
+static __always_inline bool _memory_is_tracked(const void *addr, size_t size)
+{
+	s8 mask;
+	u8 offset = (unsigned long)addr & KASAN_GRANULE_MASK;
+
+	if ((unsigned long)addr & 0x01)
+		mask = kasan_track_mask_odd(size);
+	else
+		mask = kasan_track_mask_even(size);
+
+	return unlikely(get_track_value(addr) & (mask << (offset >> 1)));
+}
+
+static __always_inline bool memory_is_tracked_1(const void *addr)
+{
+	u8 last_accessible_byte = (unsigned long)addr & KASAN_GRANULE_MASK;
+
+	return unlikely(get_track_value(addr) & (0x01 << (last_accessible_byte >> 1)));
+}
+
+static __always_inline bool memory_is_tracked_2_4_8(const void *addr, size_t size)
+{
+	/*
+	 * Access crosses 8(shadow size)-byte boundary. Such access maps
+	 * into 2 shadow bytes, so we need to check them both.
+	 */
+	if (unlikely((((unsigned long)addr + size - 1) & KASAN_GRANULE_MASK) < size - 1)) {
+		u8 part = (unsigned long)addr & KASAN_GRANULE_MASK;
+
+		part = 8 - part;
+		return ((unlikely(get_track_value(addr)) && _memory_is_tracked(addr, part)) ||
+					_memory_is_tracked(addr + part, size - part));
+	}
+
+	return _memory_is_tracked(addr, size);
+}
+
+static __always_inline bool memory_is_tracked_16(const void *addr)
+{
+	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
+	if (unlikely(!IS_ALIGNED((unsigned long)addr, KASAN_GRANULE_SIZE))) {
+		u8 part = (unsigned long)addr & KASAN_GRANULE_MASK;
+
+		part = 8 - part;
+		return ((unlikely(get_track_value(addr)) && _memory_is_tracked(addr, part)) ||
+			_memory_is_tracked(addr + part, 8) ||
+			_memory_is_tracked(addr + part + 8, 8 - part));
+	}
+
+	return unlikely(get_track_value(addr) || get_track_value(addr + 8));
+}
+
+static __always_inline unsigned long track_bytes_is_nonzero(const s8 *start,
+					size_t size)
+{
+	while (size) {
+		if (unlikely(to_track_value_1_byte(*start)))
+			return (unsigned long)start;
+		start++;
+		size--;
+	}
+
+	return 0;
+}
+
+static __always_inline unsigned long track_val_is_nonzero(const void *start,
+						const void *end)
+{
+	unsigned int words;
+	unsigned long ret;
+	unsigned int prefix = (unsigned long)start % 8;
+
+	if (end - start <= 16)
+		return track_bytes_is_nonzero(start, end - start);
+
+	if (prefix) {
+		prefix = 8 - prefix;
+		ret = track_bytes_is_nonzero(start, prefix);
+		if (unlikely(ret))
+			return ret;
+		start += prefix;
+	}
+
+	words = (end - start) / 8;
+	while (words) {
+		if (unlikely(to_track_value_8_byte(*(u64 *)start)))
+			return track_bytes_is_nonzero(start, 8);
+		start += 8;
+		words--;
+	}
+
+	return track_bytes_is_nonzero(start, (end - start) % 8);
+}
+
+static __always_inline bool memory_is_tracked_n(const void *addr, size_t size)
+{
+	unsigned long ret;
+
+	ret = track_val_is_nonzero(kasan_mem_to_shadow(addr),
+			kasan_mem_to_shadow(addr + size - 1) + 1);
+
+	if (unlikely(ret)) {
+		const void *last_byte = addr + size - 1;
+		s8 *last_shadow = (s8 *)kasan_mem_to_shadow(last_byte);
+
+		if (unlikely(ret != (unsigned long)last_shadow ||
+				_memory_is_tracked(
+				(void *)((unsigned long)last_byte & ~KASAN_GRANULE_MASK),
+				((unsigned long)last_byte & KASAN_GRANULE_MASK) + 1)))
+			return true;
+	}
+	return false;
+}
+
+static __always_inline bool memory_is_tracked(const void *addr, size_t size)
+{
+	if (__builtin_constant_p(size)) {
+		switch (size) {
+		case 1:
+			return memory_is_tracked_1(addr);
+		case 2:
+		case 4:
+		case 8:
+			return memory_is_tracked_2_4_8(addr, size);
+		case 16:
+			return memory_is_tracked_16(addr);
+		default:
+			BUILD_BUG();
+		}
+	}
+
+	return memory_is_tracked_n(addr, size);
+}
+#endif
+
 static __always_inline bool check_region_inline(const void *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
@@ -177,7 +420,8 @@ static __always_inline bool check_region_inline(const void *addr,
 	if (unlikely(!addr_has_metadata(addr)))
 		return !kasan_report(addr, size, write, ret_ip);
 
-	if (likely(!memory_is_poisoned(addr, size)))
+	if ((likely(!memory_is_poisoned(addr, size))) &&
+		(!write || likely(!memory_is_tracked(addr, size))))
 		return true;
 
 	return !kasan_report(addr, size, write, ret_ip);
@@ -196,7 +440,7 @@ bool kasan_byte_accessible(const void *addr)
 	if (!kasan_arch_is_ready())
 		return true;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+	shadow_byte = (s8)to_shadow_value_1_byte(READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr)));
 
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index f5b8e37b3805..e264c5f3c3e6 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -120,6 +120,12 @@ static const char *get_shadow_bug_type(struct kasan_report_info *info)
 	case KASAN_VMALLOC_INVALID:
 		bug_type = "vmalloc-out-of-bounds";
 		break;
+#ifdef CONFIG_KASAN_MEM_TRACK
+	default:
+		if (!((*shadow_addr) & 0x80))
+			bug_type = "memory-track";
+		break;
+#endif
 	}
 
 	return bug_type;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118124109.37324-2-lizhe.67%40bytedance.com.
