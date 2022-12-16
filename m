Return-Path: <kasan-dev+bncBDXY7I6V6AMRBFNY6KOAMGQE4AUYHLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 154F664EEFE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:25:58 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id w2-20020ac24422000000b004b567ec0ec1sf1214591lfl.15
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:25:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671207957; cv=pass;
        d=google.com; s=arc-20160816;
        b=z1d5gWMHXNOsFE3V+QJM6VxJihgtxO+fJ/OjhcF860ZCOfLiqMSzM9p0xuY90M50VE
         WsD9vqmRsL+2GDnNlivvyi4kBXxT0/koMszIhuDeiXaM5tdMfQ2dIL3el6xnqkEeQ7zk
         jYAi3Tmven6l5TQdR6rbGYXoSKVRAx15pbiPMneHLJr4PrM5X20+OPc/aZzoLw6RVppz
         YKW8E21far9I+hceZEnpw7T0mqkGFgjVwixr/M0YJzcXBcdiUQuBiWkrDEsQziUsHFV7
         o4EOc75/a/NBC3dD9oMh+DQl8/4o0u1zQrMjuUb6ycpR5w+XhdSSxRGjI76ut0Awn3V0
         +Vwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mp1/ommzKNn+QN7z+11xE1QQJwhtF8nO83PkXEIIhfk=;
        b=MGJJXduU8+Q9OFfXN/fLogIhRW/a0gNuVBiYVBywd6kKKjAGfJTQsOfXv34ry8hZmQ
         9HoM9rV5qK/cnDolStB9zQq5itFyDLGkaWd15kssxy2sjrMZesOnUtydUREswoUN69Zc
         6eYh6HUJG+5/QwjM7em4OxV8dTXEGEU4XaNmupnQvt5Bh3A9MFWs+uhlLvBNDQhEa3Tq
         RAV5OLDKmXt0E9goWO9CCdKOFXsmmS1jxyvdi6HoOtxeZvUSalI2pgsU3Vade+W7Qgk6
         1RtI8eQ8m6Q/pdHgckT/66Wt45RZw/o6KvQDac1MLe2L53eDdoXmqZ2Fao5yHEcT9KKf
         Wd8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=6wp5stVF;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mp1/ommzKNn+QN7z+11xE1QQJwhtF8nO83PkXEIIhfk=;
        b=MmHkPgpUrLwZhkSRLFhJGmj/sqYiFK6fL7bbNlNj4bjUwqEcF0B4NdAwBqYUZ3nhcH
         bDh1b8tfu5klcG4bTw9Y9kVdBviwuFBjxN+2Zi6SVgl6a+7oTcfpPkCh+gMQfGSnRADg
         OYAB7Nz1byAj6SVSPAZlzDx+on6SSr8ElM1+H1HcGmipzeAhQUSkjorDK6MxiweFr8uB
         RHcV2tJSRTdnGFSzBRmhSTzsL+4gduGuHAXE4VEGL01uGA7sKlHTR9PmuAI2mpcVfpKg
         G8rIOue/C7nbz4dS+ZXPnn9kgJ3ju5iHiGk3q61aqmB2m25T9afhJC/uJZYfcWlKZbYm
         0a4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mp1/ommzKNn+QN7z+11xE1QQJwhtF8nO83PkXEIIhfk=;
        b=3N8pCZs5ffx/Fs/M6uCFGtu2NAAjzI3pdZootX8ejlyCuxvrEYoZ9aQXWpnL85wECi
         vYL2KneLkNF8dTFOpQmuT9CiOaBOLJQ566xfwVKe2sXcab/67UQISod4YVu26moS31YB
         jFhhXiD51ER4i7zM5MIggLQZHVGx7AUPxKCN+mIKC4MT3YSitJHU/VcTmIh91KZKxAAB
         tCos8i6Cjg3hWY3PJAMbOKzUl8ON7jdCYeiwRnpP/xoj20KyJuEIjXCQWathHtArhl1I
         8SmX5tVBTgHgMpM7zutH75cqGu6xeIPj94W2F1kdTLDHQ+CIJeiEMo9wgudmMDSlJ1VS
         g3Lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnVkQpqjK80lZ1Mt8yMjRtzjVKXr2SNlKMWb1hDd4rbPL1fYSjx
	Zij3hZkFxnNnbQIRfF8apvg=
X-Google-Smtp-Source: AA0mqf5rDgvHgKElUiUhztd15Bi4BDg4sM80GIUeq9jmQwIKblITfEMkF+E0w3cgk9OFoK0T7/pVxQ==
X-Received: by 2002:a2e:bd06:0:b0:277:2437:e977 with SMTP id n6-20020a2ebd06000000b002772437e977mr33757595ljq.195.1671207957509;
        Fri, 16 Dec 2022 08:25:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be25:0:b0:279:9f0a:bf59 with SMTP id z37-20020a2ebe25000000b002799f0abf59ls437370ljq.9.-pod-prod-gmail;
 Fri, 16 Dec 2022 08:25:56 -0800 (PST)
X-Received: by 2002:a2e:a90f:0:b0:26f:db35:7e40 with SMTP id j15-20020a2ea90f000000b0026fdb357e40mr8320177ljq.15.1671207956451;
        Fri, 16 Dec 2022 08:25:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671207956; cv=none;
        d=google.com; s=arc-20160816;
        b=MM7ssEz78xuwG9yCsaEl35ChUDBeE+q6fsCI7GtTo265v+q0Wy5Y5GbOqJl2lr9Drj
         F6zP7j1Oa1xlIWSsNjPNSD6b9CYkt4WnvQ0QWWXPZFRpRTC12MaeTsOtmV/qK++JJ+0h
         OiIWef1cBoSH5ASVbus8phHVcLmkDGNU244spXy2rL9Lww3xWbrdOv3T7SdlUNjr7GOx
         Up4P79LuvRUb7lF6G6cLtYbRBBbsV0XnRyPGyiY4ipxXr4uh6qDlrkcxXktV9P3/BED/
         iJYkD2Y8TYymLdJ3TsCZkqPyRKnbcnWvEtU5FNNeKrgmSEPWnHzzAQxVqxcVKhhaC8iO
         hPKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ny2TExHkEZdNiam4GgngpmtWZKCcqjrEUo0Wf99rwww=;
        b=ELv3CVNy/oAjYNKfSbHw9dR1Pyj5K12YV7fIjNCM2+hUYVkPSUS/hnJo1Ce3rfCSlM
         G6Mdql+dk9cC5Coo3B7tCDSR98ZftCZRM/rR3rttIPHol2kug1xJgwLa+TRun/tPuRjn
         dJcKs2iJxDwiR9gkV2GFvoFYVtrIL/4/mJRxVkBAuxtVHF/JHCHuAjQHsu0feQw/n2Yz
         GwnJ5VEGrdEp1IBSkRuShFjHjMLsRDGo2PA33yfqx7GKrtLzlvTj7dtUYoqcB5PeauZT
         wrBt+VP4uUgLQ/vYCgoVcm7yZx7cwip2p9shtyEYUxuq5CzYpxoGrQaTY16JnEroYjJc
         mKgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=6wp5stVF;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id b8-20020a2eb908000000b00277385b7372si127987ljb.4.2022.12.16.08.25.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:25:56 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id p13-20020a05600c468d00b003cf8859ed1bso2178826wmo.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:25:56 -0800 (PST)
X-Received: by 2002:a05:600c:554b:b0:3d2:1761:3742 with SMTP id iz11-20020a05600c554b00b003d217613742mr20371748wmb.15.1671207955923;
        Fri, 16 Dec 2022 08:25:55 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id j9-20020a05600c190900b003b4cba4ef71sm11838404wmq.41.2022.12.16.08.25.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:25:55 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 4/6] riscv: Fix EFI stub usage of KASAN instrumented string functions
Date: Fri, 16 Dec 2022 17:21:39 +0100
Message-Id: <20221216162141.1701255-5-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=6wp5stVF;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The EFI stub must not use any KASAN instrumented code as the kernel
proper did not initialize the thread pointer and the mapping for the
KASAN shadow region.

Avoid using generic string functions by copying stub dependencies from
lib/string.c to drivers/firmware/efi/libstub/string.c as RISC-V does
not implement architecture-specific versions of those functions.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/kernel/image-vars.h        |   8 --
 drivers/firmware/efi/libstub/Makefile |   7 +-
 drivers/firmware/efi/libstub/string.c | 133 ++++++++++++++++++++++++++
 3 files changed, 137 insertions(+), 11 deletions(-)

diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
index d6e5f739905e..15616155008c 100644
--- a/arch/riscv/kernel/image-vars.h
+++ b/arch/riscv/kernel/image-vars.h
@@ -23,14 +23,6 @@
  * linked at. The routines below are all implemented in assembler in a
  * position independent manner
  */
-__efistub_memcmp		= memcmp;
-__efistub_memchr		= memchr;
-__efistub_strlen		= strlen;
-__efistub_strnlen		= strnlen;
-__efistub_strcmp		= strcmp;
-__efistub_strncmp		= strncmp;
-__efistub_strrchr		= strrchr;
-
 __efistub__start		= _start;
 __efistub__start_kernel		= _start_kernel;
 __efistub__end			= _end;
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index b1601aad7e1a..031d2268bab5 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -130,9 +130,10 @@ STUBCOPY_RELOC-$(CONFIG_ARM)	:= R_ARM_ABS
 # also means that we need to be extra careful to make sure that the stub does
 # not rely on any absolute symbol references, considering that the virtual
 # kernel mapping that the linker uses is not active yet when the stub is
-# executing. So build all C dependencies of the EFI stub into libstub, and do
-# a verification pass to see if any absolute relocations exist in any of the
-# object files.
+# executing. In addition, we need to make sure that the stub does not use KASAN
+# instrumented code like the generic string functions. So build all C
+# dependencies of the EFI stub into libstub, and do a verification pass to see
+# if any absolute relocations exist in any of the object files.
 #
 STUBCOPY_FLAGS-$(CONFIG_ARM64)	+= --prefix-alloc-sections=.init \
 				   --prefix-symbols=__efistub_
diff --git a/drivers/firmware/efi/libstub/string.c b/drivers/firmware/efi/libstub/string.c
index 5d13e43869ee..5154ae6e7f10 100644
--- a/drivers/firmware/efi/libstub/string.c
+++ b/drivers/firmware/efi/libstub/string.c
@@ -113,3 +113,136 @@ long simple_strtol(const char *cp, char **endp, unsigned int base)
 
 	return simple_strtoull(cp, endp, base);
 }
+
+#ifndef __HAVE_ARCH_STRLEN
+/**
+ * strlen - Find the length of a string
+ * @s: The string to be sized
+ */
+size_t strlen(const char *s)
+{
+	const char *sc;
+
+	for (sc = s; *sc != '\0'; ++sc)
+		/* nothing */;
+	return sc - s;
+}
+EXPORT_SYMBOL(strlen);
+#endif
+
+#ifndef __HAVE_ARCH_STRNLEN
+/**
+ * strnlen - Find the length of a length-limited string
+ * @s: The string to be sized
+ * @count: The maximum number of bytes to search
+ */
+size_t strnlen(const char *s, size_t count)
+{
+	const char *sc;
+
+	for (sc = s; count-- && *sc != '\0'; ++sc)
+		/* nothing */;
+	return sc - s;
+}
+EXPORT_SYMBOL(strnlen);
+#endif
+
+#ifndef __HAVE_ARCH_STRCMP
+/**
+ * strcmp - Compare two strings
+ * @cs: One string
+ * @ct: Another string
+ */
+int strcmp(const char *cs, const char *ct)
+{
+	unsigned char c1, c2;
+
+	while (1) {
+		c1 = *cs++;
+		c2 = *ct++;
+		if (c1 != c2)
+			return c1 < c2 ? -1 : 1;
+		if (!c1)
+			break;
+	}
+	return 0;
+}
+EXPORT_SYMBOL(strcmp);
+#endif
+
+#ifndef __HAVE_ARCH_STRRCHR
+/**
+ * strrchr - Find the last occurrence of a character in a string
+ * @s: The string to be searched
+ * @c: The character to search for
+ */
+char *strrchr(const char *s, int c)
+{
+	const char *last = NULL;
+	do {
+		if (*s == (char)c)
+			last = s;
+	} while (*s++);
+	return (char *)last;
+}
+EXPORT_SYMBOL(strrchr);
+#endif
+
+#ifndef __HAVE_ARCH_MEMCMP
+/**
+ * memcmp - Compare two areas of memory
+ * @cs: One area of memory
+ * @ct: Another area of memory
+ * @count: The size of the area.
+ */
+#undef memcmp
+__visible int memcmp(const void *cs, const void *ct, size_t count)
+{
+	const unsigned char *su1, *su2;
+	int res = 0;
+
+#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
+	if (count >= sizeof(unsigned long)) {
+		const unsigned long *u1 = cs;
+		const unsigned long *u2 = ct;
+		do {
+			if (get_unaligned(u1) != get_unaligned(u2))
+				break;
+			u1++;
+			u2++;
+			count -= sizeof(unsigned long);
+		} while (count >= sizeof(unsigned long));
+		cs = u1;
+		ct = u2;
+	}
+#endif
+	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
+		if ((res = *su1 - *su2) != 0)
+			break;
+	return res;
+}
+EXPORT_SYMBOL(memcmp);
+#endif
+
+#ifndef __HAVE_ARCH_MEMCHR
+/**
+ * memchr - Find a character in an area of memory.
+ * @s: The memory area
+ * @c: The byte to search for
+ * @n: The size of the area.
+ *
+ * returns the address of the first occurrence of @c, or %NULL
+ * if @c is not found
+ */
+void *memchr(const void *s, int c, size_t n)
+{
+	const unsigned char *p = s;
+	while (n-- != 0) {
+		if ((unsigned char)c == *p++) {
+			return (void *)(p - 1);
+		}
+	}
+	return NULL;
+}
+EXPORT_SYMBOL(memchr);
+#endif
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-5-alexghiti%40rivosinc.com.
