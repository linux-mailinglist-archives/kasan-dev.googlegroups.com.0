Return-Path: <kasan-dev+bncBDQ27FVWWUFRBB47VDVAKGQEQPEEHMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F6C683DE0
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 01:38:48 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id j96sf3375242plb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 16:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565134727; cv=pass;
        d=google.com; s=arc-20160816;
        b=oR0CRvP70Y/l14oAstR2RengmAhmTn1i1i1bORistIFX1DQNVIjkJkyLDytCOEw3WQ
         CDCs/6x0Y0tAIgqMD98woIf/pJ7aRXhreC2J5T9O4cW9ODRcAOLaqsXwCsw01YQDxKpf
         loyZ1HQUSd+oqr9TglaJySzzRpBGAeVDvouqjUtAtVybiTmfTFnDwliPdlEv5qUWkssq
         rG5z/Rc4xxViHzVUTMgw22OYwsCIqdUhAyYmGOZ1JpuX3BDnCP8ZvvunwcrB8opR7/oX
         Z67wJHzGihN7F5/ofzhBj23WGghN2JF3v9HbHVgYi6LeEALTzyg6nWNYD2ix5GMcjJ1H
         L/tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r9OF4vaVOG+J5EnH8A5pdu7dC+/6y+MnNTarVvoaGuw=;
        b=WrrXeOtmM+sAK26DK0vqOAxyqGVPCqw3OVqy//gT1lxQOwypHpa09nVJl2OqBEuRI0
         bfI+h6hIW3BrMV7hFae6gmuQmsVv8ptTRCe8WgXxzZwngd6ABYWiYAtE62YXW+2/j20w
         90AgUCW1kjujoNEy3k1+KYQtdkXDZ7l+J5UyxMq1q9VSWtukJMsi4rMwWw4Z6fYV2q8B
         2mBT/FjyKtOsMI0x7fHw6wYl9tdSh6Nxnq6kETGGtHrXMpU8IMoms3Qvd4xV9st/BSSD
         B1ne8gfgkLKMe8jt2FRnfQMRh5YH+b/w64zWP5X/nqD0orNvhzZr95Nf59xwmS9YSHFm
         dRBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HTTyLudw;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9OF4vaVOG+J5EnH8A5pdu7dC+/6y+MnNTarVvoaGuw=;
        b=UJzonC6kTEwJ9Fl077rdFg9MQvrxy9hIOscI8ETrDKM47XZcQ/awjD0LBtqqQ6hTdb
         xI/P3GeBJzjPpsvAuaXTPM/1OJOJm05mwJLfE6ipuVaWlXPPtsWNCUZgKwEiuwXVcrUj
         qiJX4qAjUgxJ3VdN1Sn1NqDle/jbB4ZLAOWO1sb1dRWv8dsU8lyLiWVYgPelgsma2Z4B
         s+Xqyq7mMUWn+ruIoZJ6aBmRPg73+DgtUxIv6M8BhN5zaD6v0hnU46CQYqgVpkrOWH/Q
         J81sTupU74yfCnSkMZUQoEVOCwpGiYobWox6dZ1AaOC9lfuzm/WmMe6IUi/H45cmaZwz
         zkiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9OF4vaVOG+J5EnH8A5pdu7dC+/6y+MnNTarVvoaGuw=;
        b=q+fO+0G6TGOQoLYlsF8ynjDPr4/Z42rUqUKBE/hEOzGfcOATvpVV6vz61KhF8jVWzZ
         JfzmfrtghPbNRMqnJOVvsuIZ2/h4Au0AyCsc98rWG1Wz9CDWoL04RzZJpc3+E35i/lZf
         SQ8fkjrYC47sPdEsB7gV5bOA62ro4a1xhmGPd6MfJZjVVvQTtqYlVZ3+N1QnkVmok87A
         1GkdqzIqhmGUzjUDv8nOO3o20ELyRBm7fOumqGgBdZ4Dj5KhoNWzvt0D2T2tlWbegyKL
         RYZ2raPRnX54dLaX+IsQ1ET0uZA229Wxb8BeVHNEcehcgiSz10ZC/H1+EYi3Bf89zFQB
         GJpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJ+JH1iPXbGcrzNLIaEO0eAiU8FJMwocsufEdzUBNI7kOdVOco
	h50/ZKRCM+b3NlAkP1ADSho=
X-Google-Smtp-Source: APXvYqwg7uZEJzU63OVcbTFJcWUR2OZ3vH3VExVgJW2Nex8LmvMjqO0E/cQGAziCiJcSZgLa7kH4QA==
X-Received: by 2002:a17:90a:80c4:: with SMTP id k4mr5700493pjw.74.1565134727266;
        Tue, 06 Aug 2019 16:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0b:: with SMTP id u11ls20115862pfh.15.gmail; Tue, 06
 Aug 2019 16:38:47 -0700 (PDT)
X-Received: by 2002:a63:7245:: with SMTP id c5mr5280377pgn.11.1565134726837;
        Tue, 06 Aug 2019 16:38:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565134726; cv=none;
        d=google.com; s=arc-20160816;
        b=vhMO5EWSSsRbTUO28Yp1Qeb+9aD2+12F1Kdmms14L5nEDALI2f+a0bnUieQEmiGCl/
         iB5P7TBnvnDToaySJThblAqsh8HfS17K85dEeJN20TggX0zgJgde7mxMvCFCTHgPDjOR
         LopbgdcBudqASU5XzCvH4Ja4PFOdhMYlkuQywuGUedTephshQUJ2hfVvOmWn0vThknTl
         KUJ1IleEn+Eb4N7ZJGRf2N8efxzNnTqREIkquIvR1nqrtYTwN9si4UxDW5aBegkwGLjK
         OpkiwBdKtdf1b0Mu2Czvxa+B6Tjc0YnR1/b9HzRoBnPSUeGSU11z6dY1CN8lA7vGdxNa
         rm2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e8DlPQSIeZqk6llpFmdndU3NDgbdbTIawHyJaggIQoo=;
        b=EAWkMPjwYBzCDFD91d1x//MRH8E/6MGjumGvoRkYTzraWt/ZiHpLpWk7BtQP59AfG+
         D4/XTzUOb/GlLHX9iVe55khlCAuftP0lCCK94yYdO98Ag8PHLMaS9HpTYzsyoANIZJ9Y
         pISUqD12MiPyoCedalsUx+ULRrNijPfp/ASc1bhxygNCKiOXiMl0gL2ItxqSuxkyrXxR
         5ZWuVx+I0fenkBLtZh9b7LMq8Z9D76z4uGeOO1n7gztOEtiCqU0tbJC6rYSvqHp0wvhP
         wydaLmyTXYkXElP/hDwsRut/nFVmEHg7QuN/6G0v11rUevu6jwfcQyPaw/jbh1PCumc4
         5iFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HTTyLudw;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id m128si1219054pfb.5.2019.08.06.16.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 16:38:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id i189so42360085pfg.10
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 16:38:46 -0700 (PDT)
X-Received: by 2002:a63:c054:: with SMTP id z20mr5168572pgi.373.1565134726349;
        Tue, 06 Aug 2019 16:38:46 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id d15sm45809221pjc.8.2019.08.06.16.38.44
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 06 Aug 2019 16:38:45 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 2/4] kasan: support instrumented bitops with generic non-atomic bitops
Date: Wed,  7 Aug 2019 09:38:25 +1000
Message-Id: <20190806233827.16454-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190806233827.16454-1-dja@axtens.net>
References: <20190806233827.16454-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HTTyLudw;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Currently bitops-instrumented.h assumes that the architecture provides
both the atomic and non-atomic versions of the bitops (e.g. both
set_bit and __set_bit). This is true on x86, but is not always true:
there is a generic bitops/non-atomic.h header that provides generic
non-atomic versions. powerpc uses this generic version, so it does
not have it's own e.g. __set_bit that could be renamed arch___set_bit.

Rearrange bitops-instrumented.h. As operations in bitops/non-atomic.h
will already be instrumented (they use regular memory accesses), put
the instrumenting wrappers for them behind an ifdef. Only include
these instrumentation wrappers if non-atomic.h has not been included.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/asm-generic/bitops-instrumented.h | 144 ++++++++++++----------
 1 file changed, 76 insertions(+), 68 deletions(-)

diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
index ddd1c6d9d8db..2fe8f7e12a11 100644
--- a/include/asm-generic/bitops-instrumented.h
+++ b/include/asm-generic/bitops-instrumented.h
@@ -29,21 +29,6 @@ static inline void set_bit(long nr, volatile unsigned long *addr)
 	arch_set_bit(nr, addr);
 }
 
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___set_bit(nr, addr);
-}
-
 /**
  * clear_bit - Clears a bit in memory
  * @nr: Bit to clear
@@ -57,21 +42,6 @@ static inline void clear_bit(long nr, volatile unsigned long *addr)
 	arch_clear_bit(nr, addr);
 }
 
-/**
- * __clear_bit - Clears a bit in memory
- * @nr: the bit to clear
- * @addr: the address to start counting from
- *
- * Unlike clear_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___clear_bit(nr, addr);
-}
-
 /**
  * clear_bit_unlock - Clear a bit in memory, for unlock
  * @nr: the bit to set
@@ -116,21 +86,6 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
 	arch_change_bit(nr, addr);
 }
 
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___change_bit(nr, addr);
-}
-
 /**
  * test_and_set_bit - Set a bit and return its old value
  * @nr: Bit to set
@@ -144,20 +99,6 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 	return arch_test_and_set_bit(nr, addr);
 }
 
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_set_bit(nr, addr);
-}
-
 /**
  * test_and_set_bit_lock - Set a bit and return its old value, for lock
  * @nr: Bit to set
@@ -187,30 +128,96 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 }
 
 /**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_change_bit(nr, addr);
+}
+
+/*
+ * If the arch is using the generic non-atomic bit ops, they are already
+ * instrumented, and we don't need to create wrappers. Only wrap if we
+ * haven't included that header.
+ */
+#ifndef _ASM_GENERIC_BITOPS_NON_ATOMIC_H_
+
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___set_bit(nr, addr);
+}
+
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit(nr, addr);
+}
+
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___change_bit(nr, addr);
+}
+
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
  * @addr: Address to count from
  *
  * This operation is non-atomic. If two instances of this operation race, one
  * can appear to succeed but actually fail.
  */
-static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_clear_bit(nr, addr);
+	return arch___test_and_set_bit(nr, addr);
 }
 
 /**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
  * @addr: Address to count from
  *
- * This is an atomic fully-ordered operation (implied full memory barrier).
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
  */
-static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_change_bit(nr, addr);
+	return arch___test_and_clear_bit(nr, addr);
 }
 
 /**
@@ -237,6 +244,7 @@ static inline bool test_bit(long nr, const volatile unsigned long *addr)
 	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_bit(nr, addr);
 }
+#endif /* _ASM_GENERIC_BITOPS_NON_ATOMIC_H_ */
 
 #if defined(arch_clear_bit_unlock_is_negative_byte)
 /**
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190806233827.16454-3-dja%40axtens.net.
