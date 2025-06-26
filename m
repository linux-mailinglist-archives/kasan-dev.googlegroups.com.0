Return-Path: <kasan-dev+bncBDAOJ6534YNBBQWQ6XBAMGQEFUOJZ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 54176AEA2AC
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:33:26 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-553bc3e1d21sf625495e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:33:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750952003; cv=pass;
        d=google.com; s=arc-20240605;
        b=HJRNbdvz4a5G9Jif9/OfWdCvR75SrOq1TQ0Fhe884MB35iZ/JE6X5/qNBJa1qXt6lE
         T0+O5bhWH4OOKx2cR1vmBVlT/jaYQhyQ69hllyjyhF4wXYUxqWAB2nLrlNJaxOh42Ifb
         gAiij0f3dm5wucH+hxsnu5tA3lkSgikdMt1haTBQFNRroDkaj/zqvj/hHNFknQX6czeF
         XTfwPUv9EXFqp6eX36qbB5k4+f04zycQRGUGtgLUrKp43np9a3p7+PDWBl8UOPdXEHeL
         V3oMJ2WPynTxP3v5NN2Y9OJDitsUAtnzULcq/X32PHMcG0Ppp9xDs6W4oEAiZrY0xmWl
         UJRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=vz5FIrRJP0J+9ErXghQe+mf0JdVyCQ1sYFd7iP2ZJ5o=;
        fh=GETdmmt0TX3rhvYCdxxFJMviZ/LLUEPTzkohhJc7nDY=;
        b=SswoQH544o5hUopIr7mLZVUVdQYt6oNqs1NUAIPskVhTcFKnDCZiTzHRQMuNYfscJJ
         xIn5aizEXqyGzEnLId6kKjAbRAAaSe3uZ5A9qD1uBKTPz/mG6KFudDhvDA5hS8yAalpG
         rGrE3VG6ETfixuzc0b/v95b7cCJfezykntrUSKW34yTQxH4m/QaJPZXPAlbef1ts/OO3
         3YSkW4EMj9UUN9TJaUOaIFA3D8zo0DM0TKx1ymTQVyfqrRU+dA26Bdh9l0vHyPWN/XDN
         xIniV5vPOAcQ+zz8gzOTP4Bx8IAsDH4jW6t/aHlhYrqF7zHieDmU9KnExYl+FOKzU0H7
         C9nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jb5qYMt0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750952003; x=1751556803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vz5FIrRJP0J+9ErXghQe+mf0JdVyCQ1sYFd7iP2ZJ5o=;
        b=YkzwxGyXv4p3Z5A4CZST2o3fRUjpIo0NzZ1YFz+cJ7cY8owG7FV000A2zY+S4qWz2Q
         UYK1shZ7jygmmUeJVp5P2VXWYW0LumVBc52K0/3QdL49KFSvTOCtkv1Brd8p171V6bUX
         OHE4fZbLYCVk+6Cwffz+XUma8UKdgYzHW3rb0oYyjjixclJUXb57xIVHTcAHXywyOxdg
         qzBnpxP6uXBstalQtXoVn9C4hPce9JusJRUJjhAuvkxKpJYXWzqJEitR20UpD4KgugK3
         tYgMXc7DFbjxyZ66V41hhD+99/b3q1hEoyUgy+1ytAyZn+ojrtVwPKPXpiVsEICyri0h
         Ey+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750952003; x=1751556803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vz5FIrRJP0J+9ErXghQe+mf0JdVyCQ1sYFd7iP2ZJ5o=;
        b=KqZcwR9CdlBCIjB+73YFkQi3QLs9y73Ljor84lUl8sXbimEXGotrmfSQ3OvuwG16pj
         govO3OJQcBPvnoBxXxXlF/yNdu1tZOC3k2URPKHPYgHQar/keO7i2Wp2C7D0w+VXUBxk
         IZDn41khon2iWjAQE89aFx7VB2JDTNXAjfQZVgHJCRUNz6sfSXCPSiUUwjHAKkHkEfST
         Ab5shoCOP1nybQT/MqmLTULD9QMZUs4CFVubmtGsQ40mrAbE7Kl0Bc9IyEKhKARhe+fk
         MazvWbae036Li3IxVYwU7KioDwqbSZuTQoV5RPLlLRAiOM4NGOLyO5DCaVaTONRojO6x
         tY3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750952003; x=1751556803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vz5FIrRJP0J+9ErXghQe+mf0JdVyCQ1sYFd7iP2ZJ5o=;
        b=YExXawvPjqImtH8e36g7wr2V4ad+qYWdFoerUSYXoqgp9yFU65kEDkXerAiCIOvjB9
         GDnlMkiuE6/22d3qyGgqmzmmytI1Hm4bfstuEtnDL0MTnq+50SSALbEynHS3sny4MC3O
         KiHYGbJpHiCsbUEm0+FwGAUAlIC3UVK6BeMFOmw/7KzJTTuFvYVawazeBU0TEmzM3LCy
         ndhpI7QCgj1Zaq6xnu1R/Q8AyH631Lhk7jMy4BoVowkGZeeS67M5WNmv7Iu+jRjmpPu7
         piMFSIHYS4A7b1p7Z5bpGPIk12MIU8AtqcKuDlIq1ztiJjruzbc8Eh2zVkWigWPHftbe
         jDXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4a2t9O6UUI56dylKI4KkfoXrAblo1+Cdu9nXqMaeVMVO6IygsSeAKUc9J+dtEi9jkMyBxBQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMvUuQKqPBXwq6Ejyt/vl+mJHB0YGQuAs+B97lcN0ypsK234P3
	X7CVJ8CFUkhiWGcjcSwF+1E9tarzvN0ncwCj1cp/BLvIgukKYGw14RHg
X-Google-Smtp-Source: AGHT+IE75K3r4qdR/+j3gFiYovJfc8PizjCSminJZi9h5MIINo1LbHNR5DobMXV71ZRIx4UClEhfsg==
X-Received: by 2002:a05:6512:ac3:b0:553:28a3:63e6 with SMTP id 2adb3069b0e04-554fdce00b5mr2236754e87.5.1750952002892;
        Thu, 26 Jun 2025 08:33:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfqOHoUMf2935nZlMAnd88UGyqcna0nPHIWEDtDimBgXA==
Received: by 2002:ac2:4da7:0:b0:553:2f32:96ef with SMTP id 2adb3069b0e04-55502ce8411ls256601e87.1.-pod-prod-06-eu;
 Thu, 26 Jun 2025 08:33:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSbmLNSyfVQJmStsSZ70jCz4uGP7tyTQBBAQbohl54aS6zc6ytWW7NrG7y369POCTzQgVadEyBEHg=@googlegroups.com
X-Received: by 2002:a05:6512:3d1b:b0:554:e7f2:d759 with SMTP id 2adb3069b0e04-554fdd46f08mr3128469e87.28.1750952000446;
        Thu, 26 Jun 2025 08:33:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750952000; cv=none;
        d=google.com; s=arc-20240605;
        b=f3b4e+VH8lJuFsxS8sfri2s1MyGQTkFQnyCOjLeepHPIjyKKRRByCFCrGenoklWgND
         pkY55JdLzBhfBlDcO6CkNIuqnzu/3ta0UDsEgitPaeBe77zz+DHGRN6YCDBe1iOqUvkY
         V/stCL2GsQ4KVAQOTF4MEG5IGLIlH3B/u3Zl00Hwi0kb4bERWA+oKoPBVr9iPhu88FHP
         Oj92D3P78llrxccRh6CnGbzYBtCj8qNcHjIMYENypTMTfk4PxeWMKtTKn9kVsAIGUKAo
         f7g1ll4O7OnpHDyIol1BheCy5y8G4DyA9DGOiAYiH8y+9EcSNxTTcIaCSLRv+PQZhr4a
         QqLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+pDrLO6USAZl/TGsifgnkWPVKgGBnMCumXxL7y5KwTQ=;
        fh=bUg2EWUJ5k3+c06vbiz6GRRqFfGFkZLwCurEJQjTVIM=;
        b=iP+L95fEIewSP0yxnBifIHUpc5slvwB8vVoTmjqTX2J/V+BvIhUDCyw/N1sAIBNT1S
         HkCUibSUNv/JcMZIgPn03KvkG5FVuoq7pUW2GydPpQsdOfo+6C3zJyn3iUq7jgUtv0p5
         HzNdcYoJPmxvBqUSkVF25j3KDQC0J51/ZUTtUWiKHQeuGD8D2je/IiA4VUyqxCqoZDTL
         hSWNovKTDCvDtt65HboH/eQVtPpJ9EyRtIYTKSilwpmgayozJJAz/MZvTXTKXdQCX5gj
         5f10IMr2J3SlscfmW/clLM5BJuUP7TsRicSwXd79DfmtuVQOv9bSZ3qopojsYoksUTnO
         BsEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jb5qYMt0;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b23ad3bsi6693e87.1.2025.06.26.08.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:33:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-55502821bd2so1199055e87.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:33:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXm8CkoT+3j5G3NBHo9mMZ/aqQzBTMRhr+z5ClUUZJAUcy2RN+lxuSVi9P08HQDhdr1Bwk2nZ5vxIA=@googlegroups.com
X-Gm-Gg: ASbGncuFrYAh6sB4ZcLrCKnYsjuMkbM+pdMG4bIGCshXVfSkzAtpWlGOU/XKVl2IedR
	T0kvQg8HuQy1ihvcC2MlRbB6WuneRXMq+AiyWVRsLpKIf2KkTscTbhAnWaNMSCqrUqw8e/jetJm
	cXV6YRE2P406Us7qWT6r/RhMaqDFunqVUOQattnvKOUJ++9ln1XyfT3pDZvpBecJIPQ/V1YOaEb
	9hAT0ih587JATvWll7S38JEmlgFHJOmZ8BX77bEmOsp/lwCZRPbYuDZYT7h1PHQTOEp8CffRu5F
	lu66Z8j8WTgiJUO0ac3eoDFCGvbF7RrPumpHBzdLqnpDQhQehU3kIs1RjyWpkhm3KIjSnTdaSBZ
	Q0AQUrhYpp+jLLJbLPLyKH8HnwYMplw==
X-Received: by 2002:a05:6512:12c2:b0:553:28f1:66ec with SMTP id 2adb3069b0e04-554fdd47009mr2940330e87.31.1750951999683;
        Thu, 26 Jun 2025 08:33:19 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.33.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:33:18 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 11/11] kasan: replace kasan_arch_is_ready with kasan_enabled
Date: Thu, 26 Jun 2025 20:31:47 +0500
Message-Id: <20250626153147.145312-12-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jb5qYMt0;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Replace the existing kasan_arch_is_ready() calls with kasan_enabled().
Drop checks where the caller is already under kasan_enabled() condition.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 include/linux/kasan-enabled.h | 20 ++++++++++++--------
 mm/kasan/common.c             |  8 ++++----
 mm/kasan/generic.c            |  6 +++---
 mm/kasan/kasan.h              |  6 ------
 mm/kasan/shadow.c             | 15 +++------------
 5 files changed, 22 insertions(+), 33 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 2b1351c30c6..2436eb45cfe 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -5,32 +5,36 @@
 #include <linux/static_key.h>
=20
 #ifdef CONFIG_KASAN
+
 /*
  * Global runtime flag. Starts =E2=80=98false=E2=80=99; switched to =E2=80=
=98true=E2=80=99 by
  * the appropriate kasan_init_*() once KASAN is fully initialized.
  */
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
-#endif
-
-#ifdef CONFIG_KASAN_HW_TAGS
=20
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
=20
-static inline bool kasan_hw_tags_enabled(void)
+#else /* !CONFIG_KASAN */
+
+static __always_inline bool kasan_enabled(void)
 {
-	return kasan_enabled();
+	return false;
 }
=20
-#else /* CONFIG_KASAN_HW_TAGS */
+#endif /* CONFIG_KASAN */
+
+#ifdef CONFIG_KASAN_HW_TAGS
=20
-static inline bool kasan_enabled(void)
+static inline bool kasan_hw_tags_enabled(void)
 {
-	return IS_ENABLED(CONFIG_KASAN);
+	return kasan_enabled();
 }
=20
+#else /* !CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 525194da25f..0f3648335a6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -257,7 +257,7 @@ static inline void poison_slab_object(struct kmem_cache=
 *cache, void *object,
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (!kasan_enabled() || is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
@@ -265,7 +265,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, vo=
id *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 		       bool still_accessible)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (!kasan_enabled() || is_kfence_address(object))
 		return false;
=20
 	poison_slab_object(cache, object, init, still_accessible);
@@ -289,7 +289,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *=
object, bool init,
=20
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return false;
=20
 	if (ptr !=3D page_address(virt_to_head_page(ptr))) {
@@ -518,7 +518,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned =
long ip)
 		return true;
 	}
=20
-	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+	if (is_kfence_address(ptr) || !kasan_enabled())
 		return true;
=20
 	slab =3D folio_slab(folio);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index ab9ab30caf4..af2f2077a45 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -176,7 +176,7 @@ static __always_inline bool check_region_inline(const v=
oid *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return true;
=20
 	if (unlikely(size =3D=3D 0))
@@ -204,7 +204,7 @@ bool kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte;
=20
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return true;
=20
 	shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
@@ -506,7 +506,7 @@ static void release_alloc_meta(struct kasan_alloc_meta =
*meta)
=20
 static void release_free_meta(const void *object, struct kasan_free_meta *=
meta)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
=20
 	/* Check if free meta is valid. */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e6..e0ffc16495d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -544,12 +544,6 @@ static inline void kasan_poison_last_granule(const voi=
d *address, size_t size) {
=20
 #endif /* CONFIG_KASAN_GENERIC */
=20
-#ifndef kasan_arch_is_ready
-static inline bool kasan_arch_is_ready(void)	{ return true; }
-#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
-#error kasan_arch_is_ready only works in KASAN generic outline mode!
-#endif
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
=20
 void kasan_kunit_test_suite_start(void);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb..9db8548ccb4 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -125,7 +125,7 @@ void kasan_poison(const void *addr, size_t size, u8 val=
ue, bool init)
 {
 	void *shadow_start, *shadow_end;
=20
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
=20
 	/*
@@ -150,9 +150,6 @@ EXPORT_SYMBOL_GPL(kasan_poison);
 #ifdef CONFIG_KASAN_GENERIC
 void kasan_poison_last_granule(const void *addr, size_t size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow =3D size & KASAN_GRANULE_MASK;
@@ -390,7 +387,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned=
 long size)
 	unsigned long shadow_start, shadow_end;
 	int ret;
=20
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return 0;
=20
 	if (!is_vmalloc_or_module_addr((void *)addr))
@@ -560,7 +557,7 @@ void kasan_release_vmalloc(unsigned long start, unsigne=
d long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
=20
-	if (!kasan_arch_is_ready())
+	if (!kasan_enabled())
 		return;
=20
 	region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
@@ -611,9 +608,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
=20
-	if (!kasan_arch_is_ready())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
=20
@@ -636,9 +630,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
=20
--=20
2.34.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250626153147.145312-12-snovitoll%40gmail.com.
