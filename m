Return-Path: <kasan-dev+bncBCMIFTP47IJBB6MN3S4AMGQEMFXVGVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D50C99A95C9
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:22 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cbec7fbf1csf79613206d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562361; cv=pass;
        d=google.com; s=arc-20240605;
        b=g7Yexm7/88zFqWmGOUBsMiAhHWnLMPnrOxFdqPYRCi0kiQuqpuDX9BbuyX48dzEEr4
         OA4ktAeTgBJNeWKdLwTJ7oWbgLZyMPB7gIJ1sP2j81t058VDKiIIgALLwA2H6lOnPp+w
         zR5llkz3+cMymCv+c8+MsvKhDV08VIBS0BcjGPgo7katpzDG/Xic/ZYKbi4ezI7nf1+o
         i1UbF2aVhDfJJSlVXurqrQbrwJRvHLwbvWQ0K70LxXyexwzC6ysBKrZuHk6ftD7PAoZS
         1Gpv1q1niQYVXNcw082750imlizOUxrI0vp5HiT0t0+/5dTFaz2M8puX6u8wtD5wCRxM
         /dHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xpaXnNfE4ftxHuj/Qlujmo3Vxhfn55Jsgv3UKz3H6bg=;
        fh=35dLJugShABxCKOt968gEID2kYKllt8bo4WpJ621GEI=;
        b=LoOyXB8CARIoclPrm+rr0slWG3QjLQVAe7rql4M1BhZFZ3MPiat/usnBP9+Fk5atxj
         1VxeOkOd2sCUiC74KRJ4v6fqntW/ldadqL8TQMQmGEb3x2udCDNWXvk1uhiOWJSB0tet
         7ZkxKEkIrt3jcU7syus3ZDGnorAfq1j9rEPr1mRLOAkMUN1wb5eA7E/Nb49dXRuqOOvP
         8zT2cpIb2L4SGFwF66CNzlz5K3Oo2PvkTalMwhZvFDFsO1VZYk8wL9+GgsIy470aN7PC
         MwWUNi0IXRZ/OmyNSNfa/Pq6NVdeJnCg2wqP2HD859s+qcCGEsZR8b4s/96MNySGuJ/l
         1X5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Ptj2b6vr;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562361; x=1730167161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xpaXnNfE4ftxHuj/Qlujmo3Vxhfn55Jsgv3UKz3H6bg=;
        b=do7U/LUKngnPErELPgBSCgAtc6XYck17oDKsmXXdE6qJH5YUFoHZusDDqSNytqQl5C
         gaebwM8ugw4FWx0M8/TrGG6cYVqcsSScpD0VuubwC8yd8NtpAWHOk2ZHnhKUBpsw3j9M
         IYIkF0OvfCqZgUHDc1Em2dpKaMtCoIXi4koga0SXbl+JURvxbP9YrLvaFfIDqs+e8sqh
         ces+45wzpE9aJnA4cdHJz1W+fqC6hCwpOYa8DDRoXYv/dgy7i1f2ne9QDLlIJyv+OxBy
         28ST7JtxRRH5Xl7SvpLZyvDQaNbuK6r7JkG0ULN+PEspTD/mzsbFQIoMQ+ZhIicGIufe
         vgHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562361; x=1730167161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xpaXnNfE4ftxHuj/Qlujmo3Vxhfn55Jsgv3UKz3H6bg=;
        b=Jpqbmfh98xKvOVkK1bGTHr7mHvbZOaxhiJblHZk2/b/MutKbrNonJ8knYu/nKw/os8
         OCcgh7E/ny0sSIayrVK4+0+1j+9gnjwompDEGHYJme4rPGxZwv5+nw0qiZ/7Xiq2f8n0
         lKXYJZoGfD+ZOhh6js/2qflC8Q53WV85HfLtwH7HaALLFPsfgDDMc38Cq/7zWnHi3Lyv
         NL/KoZMAuNNXUqJcHVdUNo98C9pIoDT816yuDBV/X+UfjTK7F3pmusL9yL0nRAZv7quc
         /PN9DHDZNMy+iEk8vgAe7CrYuS3yDx/YtbKu8P0BfUSScW3WFb01qpcqm9RYHBtxfQRQ
         MF4g==
X-Forwarded-Encrypted: i=2; AJvYcCWpyIGoFHRWPQK81SfOEaeWrJKTxKKSYNHTAnphM0b/i2MWL6Gj73bBG5o87L6YKAEerymOTA==@lfdr.de
X-Gm-Message-State: AOJu0Yygfs1sYeg7RyDJpMB1ZLRSJdLP53LYwrJox3hzOA6j4DCyGBCh
	14ZLpS77i0dx5AROlTimbuB4XNWCg9N58fC3NsjsYVSLr+LrjA+l
X-Google-Smtp-Source: AGHT+IENb0AusJ6ZYHv40GsAT5170ou3JkzCuR0oS5WazA/6GjcriWaiVSuLdu8HYAntI5RmAr53pQ==
X-Received: by 2002:a05:6214:5988:b0:6cb:e76b:d90 with SMTP id 6a1803df08f44-6ce203e45damr31284316d6.13.1729562361624;
        Mon, 21 Oct 2024 18:59:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d01:b0:6c5:e73:a956 with SMTP id
 6a1803df08f44-6cc375ba040ls96406216d6.1.-pod-prod-01-us; Mon, 21 Oct 2024
 18:59:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6iOXABiB28zSE/paaV5/SNk77nmOu5ID6V4UXvw9nNbQywv7jH2H+V5v+1osQm+SUBFvtOZFjb+o=@googlegroups.com
X-Received: by 2002:a05:6214:458e:b0:6cb:ade7:de63 with SMTP id 6a1803df08f44-6ce20396bd8mr26360576d6.5.1729562361025;
        Mon, 21 Oct 2024 18:59:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562361; cv=none;
        d=google.com; s=arc-20240605;
        b=VuhqVMGVn3JgiSx2BG3MXCJy3lAjONKqNOIr700ljl00NG3IXZkygvyFeG8/GC775G
         FI1Zj5Xhh5g2ZWuBrJjOj5F6QaktCpwTMw25C4EygIv6H+o5ijPFccEyLmeleR4F7qkT
         NZK1BI446InpSJFFnyGqhj7nk0wg4rQWTDmFNKS/D+ObdAix39yFA9A0pu9iFkVjYwdu
         h+KglaAcsb4K3gxheL6WwITe8xCUBjmnvWneyWxL3PSU2QGNg8gBXI+3LBz3o8mIr62P
         tMuAlfPTwBvZuASkVoJl4JZkoK80eWPWRRmHsCCBcJnutzONVrvlVDs86gouU6p+/YeS
         5zgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Af9tK0JLBBTeDXRGuA1c/z94Xn/abI+OOOquUfcf3I8=;
        fh=8w7wJ/+I7uLJj+auFXmJEPUTfyWVSi7Xa/1HOIQTIiI=;
        b=GSpD5Q+EPG0FfrtGlu/JisAO7tnU5oGglGCG8rKVqY31Yi0YeJszCf+xQUr83Lrw6M
         8V+6V+AeDSiKyoTR6LCPiPwENGfCK9nt304ndVGREjrcFjQNJJ7VqrQqZHlaG56gF4PR
         gJxoH5mwvcA0ZX9mvpsle+cssxs+92QBHDal3DPW+ZZWbtv0HowM5YlUtfmeQ9jD+s/R
         lCPN2dP91BPFRqV8C6HCtnNHRDgjO9yH25ncLzbLP9Y9R6YD+E3FgaklO473/ZmaOrIi
         duGzHZgQyR3t+hwwu03wBE3IPr6czzOaD/k2ALn/TNtfh8iJkLaSFBNiZXIo+J8jAy7w
         LZyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Ptj2b6vr;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ce008f5a76si1997106d6.2.2024.10.21.18.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-71ec997ad06so1150477b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWrzPYojJJqNJM1ka3yooXEhutBUZAjId78pBbQakAZijfKk7Rjny6TfXMTosoqpTl4dPRBpvIHXYQ=@googlegroups.com
X-Received: by 2002:a05:6a00:4610:b0:71e:6489:d06 with SMTP id d2e1a72fcca58-71edb972451mr3011651b3a.0.1729562359943;
        Mon, 21 Oct 2024 18:59:19 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:19 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 2/9] kasan: sw_tags: Check kasan_flag_enabled at runtime
Date: Mon, 21 Oct 2024 18:57:10 -0700
Message-ID: <20241022015913.3524425-3-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Ptj2b6vr;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

On RISC-V, the ISA extension required to dereference tagged pointers is
optional, and the interface to enable pointer masking requires firmware
support. Therefore, we must detect at runtime if sw_tags is usable on a
given machine. Reuse the logic from hw_tags to dynamically enable KASAN.

This commit makes no functional change to the KASAN_HW_TAGS code path.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

(no changes since v1)

 include/linux/kasan-enabled.h | 15 +++++----------
 mm/kasan/hw_tags.c            | 10 ----------
 mm/kasan/tags.c               | 10 ++++++++++
 3 files changed, 15 insertions(+), 20 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 6f612d69ea0c..648bda9495b7 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,7 +4,7 @@
 
 #include <linux/static_key.h>
 
-#ifdef CONFIG_KASAN_HW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
@@ -13,23 +13,18 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
-static inline bool kasan_hw_tags_enabled(void)
-{
-	return kasan_enabled();
-}
-
-#else /* CONFIG_KASAN_HW_TAGS */
+#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
 {
 	return IS_ENABLED(CONFIG_KASAN);
 }
 
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_hw_tags_enabled(void)
 {
-	return false;
+	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
 }
 
-#endif /* CONFIG_KASAN_HW_TAGS */
-
 #endif /* LINUX_KASAN_ENABLED_H */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9958ebc15d38..c3beeb94efa5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -43,13 +43,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
-/*
- * Whether KASAN is enabled at all.
- * The value remains false until KASAN is initialized by kasan_init_hw_tags().
- */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
-EXPORT_SYMBOL(kasan_flag_enabled);
-
 /*
  * Whether the selected mode is synchronous, asynchronous, or asymmetric.
  * Defaults to KASAN_MODE_SYNC.
@@ -257,9 +250,6 @@ void __init kasan_init_hw_tags(void)
 
 	kasan_init_tags();
 
-	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
 		kasan_vmalloc_enabled() ? "on" : "off",
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index d65d48b85f90..c111d98961ed 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -32,6 +32,13 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized by kasan_init_tags().
+ */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
+EXPORT_SYMBOL(kasan_flag_enabled);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
@@ -92,6 +99,9 @@ void __init kasan_init_tags(void)
 		if (WARN_ON(!stack_ring.entries))
 			static_branch_disable(&kasan_flag_stacktrace);
 	}
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
 }
 
 static void save_stack_info(struct kmem_cache *cache, void *object,
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-3-samuel.holland%40sifive.com.
