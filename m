Return-Path: <kasan-dev+bncBDLKPY4HVQKBB45C77BAMGQED4PFRYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DC24AEC6AA
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 13:26:48 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3a4f6ff23ccsf1865994f8f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jun 2025 04:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751110004; cv=pass;
        d=google.com; s=arc-20240605;
        b=MnG7O0QEe/dXRQ5wu51k0Bp/UBlcksFWNRQOQBlou3k8npK3V0OnDgb4r/HoZyVjPb
         rzMVyE+f8Lxu90iX2E84Cp1Tg4haEnghOIiKEuZ2Q0oN98JUZ3CiixHfVcdxYcO5/SMm
         QFntMr02pth4IpTEk5HTh7OX9kxJ9vL/r9N0ISpIrhYOyLSa/csoqntCnpV2rfWCtPTB
         mCnpqVKcVu4CwKjCvUkkhSQlllfemIUGmrSG8aczGXUg0Brzw7vuQO5VRNBOLzjXpv2l
         Po23Psi/uDaEtgdl/j8ISSN64qTVVK1xX63yHx489vF2R8fZ+qQtGUk6kKWZt9hlkxAj
         QdWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=XWnoCdCNdlDMNr7O/HRZ+n27brgh8EechauIu795yBw=;
        fh=S7qDRHI739+ZP/nbtb2NzIkNgQHgEw/Yf/SZRveSZGc=;
        b=dYv2yNJUR0RVvV4aQ+vOK9LHhUWkmGO8hC15tYV7WjcNWakOEp+zix5d2ZdSeAIroZ
         ZxGY6Leu2n8cJicParKTZ97uC5bDCxQadZesDa9NmzjQRlQ02CdE5vPWx7bQHrxS7unq
         zdJPIqBn9qNTjU0NJCSXPUPmL/uiPhzIpq5YReS4wwuTUob0TqdQsugUXskDbeZSysQY
         bbOHoO27gXwJXdf6o9TFhkvVSFfTDB0KQ8hXGeYKIr9qFNWJT51xnK93aa9n+507WbhW
         /i3nILicoTw8ONVntBFzCRvzWPIcxrjdx0RvtKRNoo2N96malVtRkDnsLp3vriGJqxyb
         5fCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751110004; x=1751714804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XWnoCdCNdlDMNr7O/HRZ+n27brgh8EechauIu795yBw=;
        b=cLp5h6PH8Fhm7px4OxhIR9rNIRqJxVfNp8g1b0E5/WEXyQFllG02ZxXjq45hH/Kmp+
         NNKFTCfQ0lZ+HpN8ZfrecQPp2XkS+UIIoOkbl5KOrwfwBZPJ7XKU80ZczeNE0PlPbrE3
         Wx9u8kaAhq+WkJG+XnzcAT4/Bq8+qFSWFBjgaLQr+1w3EdSeEXbQITEbRpBsOQBuwFnC
         k640wRF9BX4ZPJ7Qyf8cnWEO//WA0nl35ewuQBlfPsd2X7pnuDx7bSRwHy2/yZ3Jznl1
         BKC+Fhr/e4gtd7tdaKCYWuzvO7wxWgbBaB8nqWl0yRSDDvevpikoMHEILadahVO7MzKK
         pdVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751110004; x=1751714804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XWnoCdCNdlDMNr7O/HRZ+n27brgh8EechauIu795yBw=;
        b=AUtDVCOMqFFYQMSgXL/xraiovkLNvBwpUEKCGK7MVVVdmD325UkHs0zQBA/7c9ZKsC
         0eMkFv3Cq20YIy8hJM8VEYSxK92DmbOWLF01pfARCyoEu6JBwJHWAZgPYo5VvtqvSDxc
         aT7emedYVNbPRiWgyScS6xc62/+nxKqcChcFnnuJ1OPMZ4jTrrDWURZj5J+mFR1Rr5fJ
         K2djW43BgmXOzJ66wPo6Ht59b9ramOQsYDwW9oNsWyGi09KxC9AG8dhzzSUHyMkSBK+0
         dV7EJugIZjmgKiQNSl1sbgeqiPbEkbPWlzptf5Wn+/1tE/OfDT8UfW6kPyYKOiMWRIxX
         RNXw==
X-Forwarded-Encrypted: i=2; AJvYcCUSU1NC8mSt2+X/iUpS6DE0amm1F7Jn4ESSOxJ+yjesNrcXx7wDTZIPGEUWDaUtsMxkbnCjeg==@lfdr.de
X-Gm-Message-State: AOJu0Yza4HO2Qr/TAdT66n9VE1Dz+JHM+n/8B9YwQTPejGkWDzP7jLAY
	VWvuXqZidvf1hODq+Dqd/eIdAFd8md+xNcT6LdbIPPJEw1+DwJRkd3mO
X-Google-Smtp-Source: AGHT+IENy9BaX5hp7ZtDLfGVPpAWUFtSOV0PK+JY4u48fniq9Zcxqg09zmnJMh4BiQMJ+LY46HYc6w==
X-Received: by 2002:adf:fdca:0:b0:3a4:e4ee:4c7b with SMTP id ffacd0b85a97d-3a90d5a7cfemr5379022f8f.15.1751110003840;
        Sat, 28 Jun 2025 04:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehCEazW//rPsSr2AdlaBRc+y8xjIgckaKi0ccbuvv01w==
Received: by 2002:a05:600c:3545:b0:43c:ef03:56fa with SMTP id
 5b1f17b1804b1-4538a20fd18ls17941735e9.2.-pod-prod-02-eu; Sat, 28 Jun 2025
 04:26:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXC2vs0VElH3GVKH/aN62Yq7F2lYMzYIyyPAeAe0pZ5b3prDhBCvdMm20PMFBrwwVe9AhcUS73PzKE=@googlegroups.com
X-Received: by 2002:a05:6000:481c:b0:3a6:f2a7:d0bb with SMTP id ffacd0b85a97d-3a90d0d6cd6mr5599778f8f.12.1751110000910;
        Sat, 28 Jun 2025 04:26:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751110000; cv=none;
        d=google.com; s=arc-20240605;
        b=RHYxWVtOAnNShnqEck6O658pwFXwkUlvUOB6ojRS18EHBl71R0t9Pqa1ZjCNR0Rs85
         VeCVEA4mQtvBeJ+ny+51AF8QJ0iVrI8R10t+QyKwtXW9Vqt4gqCIBx4QSieZojMb93JP
         U6iMZhw3iyz6GcYS9rLTNOjAYQPZVDQ5vGhBxi9wxJ9karj1FTarbvnl3e+cDv9m50qj
         e3r+Qn7UNfDOmmqU4mr9dzva4xs92PxFCjq0Xxsy2z4sLmftzWcXBNg/D9KL6cJLA87+
         rlZl4J7CX4lu39IQkWwojBQQQ1xZ+U1/fMsT5yJVXCLFWJf4MApjbnx1Ok4H0cbh+5yV
         W0eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=1Y0qjLu4ESsXOC1mIMGmrpenXtMUUzktqWjzTMVxwvs=;
        fh=xRwgWESjjEnonZSgTetfyhhDMTRuGr9zEyCRlHvXuEM=;
        b=fYl6x3XA9I/XIObqwb9IThZh5jitoxrt0v9MMdKRpY+6GeHYZR/51NLMheaXyAOaHC
         GshCi4NV+E7UA/IPANZpTlBCsh7Sq2yyZUpL5BbrAjqpMf22VxjpgnKMzmOcEIUapLUN
         huI5J9QfB++OGRLb7Gcxr2OnbhjlZLpnn2DJQCpwhSYF5V7/G72NGS+KuiK4SRu6EaoB
         +fWGwHfIEDcXX9vf78TKpwFk7/wjRWzmgkkA0laJkF6ezLO3h5yQr5WoOewiEHYdMhGJ
         fkQyGOToC87CN31QwxPXUsCOgir9sKKmh8/TWKJXOREWIxDvEeOxvduMtOzbJNKxecjP
         NUGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fced22si3180075e9.0.2025.06.28.04.26.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Jun 2025 04:26:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bTqrJ288Cz9vJx;
	Sat, 28 Jun 2025 13:26:40 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id pfMuphSsT2Ir; Sat, 28 Jun 2025 13:26:40 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bTqrH3wCPz9vJs;
	Sat, 28 Jun 2025 13:26:39 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 78EDB8B765;
	Sat, 28 Jun 2025 13:26:39 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id SOtpdDiBEncU; Sat, 28 Jun 2025 13:26:39 +0200 (CEST)
Received: from [192.168.202.221] (unknown [192.168.202.221])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 93EA18B763;
	Sat, 28 Jun 2025 13:26:35 +0200 (CEST)
Message-ID: <ffae82a6-26dd-4c25-80d3-dbb55c889b52@csgroup.eu>
Date: Sat, 28 Jun 2025 13:26:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 00/11] kasan: unify kasan_arch_is_ready with
 kasan_enabled
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, linux@armlinux.org.uk, catalin.marinas@arm.com,
 will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name,
 maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com,
 paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
 alex@ghiti.fr, hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com, svens@linux.ibm.com, richard@nod.at,
 anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org, nathan@kernel.org,
 nick.desaulniers+lkml@gmail.com, morbo@google.com, justinstitt@google.com
Cc: arnd@arndb.de, rppt@kernel.org, geert@linux-m68k.org, mcgrof@kernel.org,
 guoweikang.kernel@gmail.com, tiwei.btw@antgroup.com, kevin.brodsky@arm.com,
 benjamin.berg@intel.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org, llvm@lists.linux.dev
References: <20250626153147.145312-1-snovitoll@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 26/06/2025 =C3=A0 17:31, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> This patch series unifies the kasan_arch_is_ready() and kasan_enabled()
> interfaces by extending the existing kasan_enabled() infrastructure to
> work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).
>=20
> Currently, kasan_enabled() only works for HW_TAGS mode using a static key=
,
> while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-time
> constant) or rely on architecture-specific kasan_arch_is_ready()
> implementations with custom static keys and global variables.
>=20
> This leads to:
> - Code duplication across architectures
> - Inconsistent runtime behavior between KASAN modes
> - Architecture-specific readiness tracking

You should also consider refactoring ARCH_DISABLE_KASAN_INLINE, there is=20
a high dependency between deferring KASAN readiness and not supporting=20
inline KASAN.

>=20
> After this series:
> - All KASAN modes use the same kasan_flag_enabled static key
> - Consistent runtime enable/disable behavior across modes
> - Simplified architecture code with unified kasan_init_generic() calls
> - Elimination of arch specific kasan_arch_is_ready() implementations
> - Unified vmalloc integration using kasan_enabled() checks

I dislike that modes which can be enabled from the very begining now=20
also depends on the static key being enabled later.

The size is increased for no valid reason:

$ size vmlinux.kasan*
    text	   data	    bss	    dec	    hex	filename
13965336	6716942	 494912	21177190	1432366	vmlinux.kasan0 =3D=3D> outline=20
KASAN before your patch
13965496	6718422	 494944	21178862	14329ee	vmlinux.kasan1 =3D=3D> outline=20
KASAN after your patch
13965336	6716942	 494912	21177190	1432366	vmlinux.kasan2 =3D=3D> outline=20
KASAN after your patch + below change
32517472	6716958	 494912	39729342	25e38be	vmlinux.kasani0 =3D=3D> inline=20
KASAN before your patch
32518848	6718438	 494944	39732230	25e4406	vmlinux.kasani1 =3D=3D> inline=20
KASAN after your patch
32517536	6716958	 494912	39729406	25e38fe	vmlinux.kasani2 =3D=3D> inline=20
KASAN after your patch + below change

Below change (atop you series) only makes use of static key when needed:

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index c3e0cc83f120..7a8e5db603cc 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -122,6 +122,7 @@ config PPC
  	# Please keep this list sorted alphabetically.
  	#
  	select ARCH_32BIT_OFF_T if PPC32
+	select ARCH_DEFER_KASAN			if PPC_RADIX_MMU
  	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
  	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
  	select ARCH_ENABLE_MEMORY_HOTPLUG
@@ -219,7 +220,7 @@ config PPC
  	select HAVE_ARCH_JUMP_LABEL
  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
  	select HAVE_ARCH_KASAN			if PPC32 && PAGE_SHIFT <=3D 14
-	select HAVE_ARCH_KASAN			if PPC_RADIX_MMU
+	select HAVE_ARCH_KASAN_DEFERED		if PPC_RADIX_MMU
  	select HAVE_ARCH_KASAN			if PPC_BOOK3E_64
  	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
  	select HAVE_ARCH_KCSAN
diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 2436eb45cfee..fda86e77fe4f 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,7 +4,7 @@

  #include <linux/static_key.h>

-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_DEFER

  /*
   * Global runtime flag. Starts =C3=A2=E2=82=AC=CB=9Cfalse=C3=A2=E2=82=AC=
=E2=84=A2; switched to =C3=A2=E2=82=AC=CB=9Ctrue=C3=A2=E2=82=AC=E2=84=A2 by
@@ -17,13 +17,21 @@ static __always_inline bool kasan_enabled(void)
  	return static_branch_likely(&kasan_flag_enabled);
  }

-#else /* !CONFIG_KASAN */
+static inline void kasan_enable(void)
+{
+	static_branch_enable(&kasan_flag_enabled);
+}
+
+#else /* !CONFIG_KASAN_DEFER */

  static __always_inline bool kasan_enabled(void)
  {
-	return false;
+	return IS_ENABLED(CONFIG_KASAN);
  }

+static inline void kasan_enable(void)
+{
+}
  #endif /* CONFIG_KASAN */

  #ifdef CONFIG_KASAN_HW_TAGS
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..e0c300f55c07 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -13,6 +13,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
  config HAVE_ARCH_KASAN_VMALLOC
  	bool

+config ARCH_DEFER_KASAN
+	bool
+
  config ARCH_DISABLE_KASAN_INLINE
  	bool
  	help
@@ -58,6 +61,9 @@ config CC_HAS_KASAN_MEMINTRINSIC_PREFIX
  	help
  	  The compiler is able to prefix memintrinsics with __asan or __hwasan.

+config KASAN_DIFER
+	def_bool ARCH_DIFER_KASAN
+
  choice
  	prompt "KASAN mode"
  	default KASAN_GENERIC
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 0f3648335a6b..01f56eed9d20 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -36,8 +36,10 @@
   * Definition of the unified static key declared in kasan-enabled.h.
   * This provides consistent runtime enable/disable across all KASAN modes=
.
   */
+#ifdef CONFIG_KASAN_DEFER
  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
  EXPORT_SYMBOL(kasan_flag_enabled);
+#endif

  struct slab *kasan_addr_to_slab(const void *addr)
  {
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index a3b112868be7..516b49accc4f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -42,7 +42,7 @@
   */
  void __init kasan_init_generic(void)
  {
-	static_branch_enable(&kasan_flag_enabled);
+	kasan_enable();

  	pr_info("KernelAddressSanitizer initialized (generic)\n");
  }
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 8e819fc4a260..c8289a3feabf 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -253,7 +253,7 @@ void __init kasan_init_hw_tags(void)
  	kasan_init_tags();

  	/* KASAN is now initialized, enable it. */
-	static_branch_enable(&kasan_flag_enabled);
+	kasan_enable();

  	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s,=20
vmalloc=3D%s, stacktrace=3D%s)\n",
  		kasan_mode_info(),
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 525bc91e2fcd..275bcbbf6120 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -45,7 +45,7 @@ void __init kasan_init_sw_tags(void)

  	kasan_init_tags();

-	static_branch_enable(&kasan_flag_enabled);
+	kasan_enable();

  	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=3D%s)\n=
",
  		str_on_off(kasan_stack_collection_enabled()));


>=20
> This addresses the bugzilla issue [1] about making
> kasan_flag_enabled and kasan_enabled() work for Generic mode,
> and extends it to provide true unification across all modes.
>=20
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
>=20
> =3D=3D=3D Current mainline KUnit status
>=20
> To see if there is any regression, I've tested first on the following
> commit 739a6c93cc75 ("Merge tag 'nfsd-6.16-1' of
> git://git.kernel.org/pub/scm/linux/kernel/git/cel/linux").
>=20
> Tested via compiling a kernel with CONFIG_KASAN_KUNIT_TEST and running
> QEMU VM. There are failing tests in SW_TAGS and GENERIC modes in arm64:
>=20
> arm64 CONFIG_KASAN_HW_TAGS:
> 	# kasan: pass:62 fail:0 skip:13 total:75
> 	# Totals: pass:62 fail:0 skip:13 total:75
> 	ok 1 kasan
>=20
> arm64 CONFIG_KASAN_SW_TAGS=3Dy:
> 	# kasan: pass:65 fail:1 skip:9 total:75
> 	# Totals: pass:65 fail:1 skip:9 total:75
> 	not ok 1 kasan
> 	# kasan_strings: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:1598
> 	KASAN failure expected in "strscpy(ptr, src + KASAN_GRANULE_SIZE, KASAN_=
GRANULE_SIZE)", but none occurred
>=20
> arm64 CONFIG_KASAN_GENERIC=3Dy, CONFIG_KASAN_OUTLINE=3Dy:
> 	# kasan: pass:61 fail:1 skip:13 total:75
> 	# Totals: pass:61 fail:1 skip:13 total:75
> 	not ok 1 kasan
> 	# same failure as above
>=20
> x86_64 CONFIG_KASAN_GENERIC=3Dy:
> 	# kasan: pass:58 fail:0 skip:17 total:75
> 	# Totals: pass:58 fail:0 skip:17 total:75
> 	ok 1 kasan
>=20
> =3D=3D=3D Testing with patches
>=20
> Testing in v2:
>=20
> - Compiled every affected arch with no errors:
>=20
> $ make CC=3Dclang LD=3Dld.lld AR=3Dllvm-ar NM=3Dllvm-nm STRIP=3Dllvm-stri=
p \
> 	OBJCOPY=3Dllvm-objcopy OBJDUMP=3Dllvm-objdump READELF=3Dllvm-readelf \
> 	HOSTCC=3Dclang HOSTCXX=3Dclang++ HOSTAR=3Dllvm-ar HOSTLD=3Dld.lld \
> 	ARCH=3D$ARCH
>=20
> $ clang --version
> ClangBuiltLinux clang version 19.1.4
> Target: x86_64-unknown-linux-gnu
> Thread model: posix
>=20
> - make ARCH=3Dum produces the warning during compiling:
> 	MODPOST Module.symvers
> 	WARNING: modpost: vmlinux: section mismatch in reference: \
> 		kasan_init+0x43 (section: .ltext) -> \
> 		kasan_init_generic (section: .init.text)
>=20
> AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
> is placed in own section ".kasan_init", which calls kasan_init_generic()
> which is marked with "__init".
>=20
> - Booting via qemu-system- and running KUnit tests:
>=20
> * arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results.
> * x86_64 (GENERIC): no regression, no errors
>=20
> =3D=3D=3D NB
>=20
> I haven't tested the kernel boot on the following arch. due to the absenc=
e
> of qemu-system- support on those arch on my machine, so I defer this to
> relevant arch people to test KASAN initialization:
> - loongarch
> - s390
> - um
> - xtensa
> - powerpc
> - riscv
>=20
> Code changes in v2:
> - Replace the order of patches. Move "kasan: replace kasan_arch_is_ready
> 	with kasan_enabled" at the end to keep the compatibility.
> - arch/arm, arch/riscv: add 2 arch. missed in v1
> - arch/powerpc: add kasan_init_generic() in other kasan_init() calls:
> 	arch/powerpc/mm/kasan/init_32.c
> 	arch/powerpc/mm/kasan/init_book3e_64.c
> - arch/um: add the proper header `#include <linux/kasan.h>`. Tested
> 	via compiling with no errors. In the v1 arch/um changes were acked-by
> 	Johannes Berg, though I don't include it due to the changed code in v2.
> - arch/powerpc: add back `#ifdef CONFIG_KASAN` deleted in v1 and tested
> 	the compilation.
> - arch/loongarch: update git commit message about non-standard flow of
> 	calling kasan_init_generic()
>=20
> Sabyrzhan Tasbolatov (11):
>    kasan: unify static kasan_flag_enabled across modes
>    kasan/arm64: call kasan_init_generic in kasan_init
>    kasan/arm: call kasan_init_generic in kasan_init
>    kasan/xtensa: call kasan_init_generic in kasan_init
>    kasan/loongarch: call kasan_init_generic in kasan_init
>    kasan/um: call kasan_init_generic in kasan_init
>    kasan/x86: call kasan_init_generic in kasan_init
>    kasan/s390: call kasan_init_generic in kasan_init
>    kasan/powerpc: call kasan_init_generic in kasan_init
>    kasan/riscv: call kasan_init_generic in kasan_init
>    kasan: replace kasan_arch_is_ready with kasan_enabled
>=20
>   arch/arm/mm/kasan_init.c               |  2 +-
>   arch/arm64/mm/kasan_init.c             |  4 +---
>   arch/loongarch/include/asm/kasan.h     |  7 -------
>   arch/loongarch/mm/kasan_init.c         |  7 ++-----
>   arch/powerpc/include/asm/kasan.h       | 13 -------------
>   arch/powerpc/mm/kasan/init_32.c        |  2 +-
>   arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
>   arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
>   arch/riscv/mm/kasan_init.c             |  1 +
>   arch/s390/kernel/early.c               |  3 ++-
>   arch/um/include/asm/kasan.h            |  5 -----
>   arch/um/kernel/mem.c                   |  4 ++--
>   arch/x86/mm/kasan_init_64.c            |  2 +-
>   arch/xtensa/mm/kasan_init.c            |  2 +-
>   include/linux/kasan-enabled.h          | 22 ++++++++++++++++------
>   include/linux/kasan.h                  |  6 ++++++
>   mm/kasan/common.c                      | 15 +++++++++++----
>   mm/kasan/generic.c                     | 17 ++++++++++++++---
>   mm/kasan/hw_tags.c                     |  7 -------
>   mm/kasan/kasan.h                       |  6 ------
>   mm/kasan/shadow.c                      | 15 +++------------
>   mm/kasan/sw_tags.c                     |  2 ++
>   22 files changed, 66 insertions(+), 84 deletions(-)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
fae82a6-26dd-4c25-80d3-dbb55c889b52%40csgroup.eu.
