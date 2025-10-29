Return-Path: <kasan-dev+bncBAABBEWMRHEAMGQEWBE33VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FCDCC1CE90
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:08:04 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-272b7bdf41fsf2293235ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:08:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764883; cv=pass;
        d=google.com; s=arc-20240605;
        b=cmtFJK9A5JCqKGTJE5UMAfFup71ES07lq14fkafoUIBrj+M7JSuoa61gBOEvQdl0Gj
         NYMGBIG6Zba8NTtgawn8AL4hr64wYOaeUq8ifbZGZLhNmnuo9g0N9Ycq1VUuDJd5XfLy
         98hd2782eH3zNGPgkxpQ3wKPeZpHmGRe+6wJl7FGALU4CkMk+qSSS4QVEI972tBd9aPd
         6d+54E7IWQGChEZ5lej+f54gt8Sk8690RWEjuEqBu0uWlOwNQYLlF86pzCgraSDALJx1
         6hd7TwAj19N3wNZ4vMbOG2ioZk/7hdIiqBal3uc5+Q6aIhjHwsMl6HLUoJkzJ/y+K9By
         1NPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=T7zjV2o0F4DjNvQjzFD4UgpAZGhpSO4JGJ/oa1MjOG4=;
        fh=herQPEG5mRm+vy19Ik6z+WITwoG7dWjc//OMGlP8h9s=;
        b=QyVpdJNcu5upTYmFUmJNIHJ6/iWqv2ws41n0oS4d65bTH5aQu2oPOe117wEMafcmNb
         xK1SQBllrfAlsCZ4+cVDIQtguEw5iaKze2I87OLMWgCbF0iUmkz/741m2Kj9ZbukKXbg
         8yPvwBIlg+xHRwhxvoK7bcU3vGn3DV1i0eCuTBxFOmF//hT92hLISlifIUuL06FX1ezV
         GjFhHg+APwsP+m6aXAF8K+oHdusmml7VxohRWvQ+enB//CTRKn+V3wDwlaU2g+md99gT
         Zda8MXzVebIgmDxEbIhcUztW+meXtq2lUEXkrL2XdUhCWlYNjey2KMbXY+Z8hrs5MzI1
         m8Mg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IJcPNw3y;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764883; x=1762369683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=T7zjV2o0F4DjNvQjzFD4UgpAZGhpSO4JGJ/oa1MjOG4=;
        b=o5InTtfr3DX/aMmu5QRGa20pS6Dl+6mssU9wHTVEXQnWhOZS+gBzoaI0HUh7LxWSJ2
         I4UCCCqjOxNZDcJ1vFgsnAThafsY6yZmlQ+hJpYG50Y255md+rqOGSVuexbZoWlF5dis
         hTpFYzHs4qky/pIYZEyDD6StHU/ocsqoBi9du0xg7ssFCfCM1Kcbh83V8m3yqgOgbyUp
         YENmzAUhqNt8JRiOJI0Rsq4o106nU5LPSn9g7cEDiVQqh2G6b5u3uTFK5q3Ggbc965po
         La+5Y2HcM42EZVwmvUMp+9WsTvCntSoVNvbUskBNYq0doFPIsh4aLUPlbQGOBp8mpSwl
         ICnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764883; x=1762369683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T7zjV2o0F4DjNvQjzFD4UgpAZGhpSO4JGJ/oa1MjOG4=;
        b=tSKst3o3DJEDKbtg4C+6oRCPny9D6KD8r25ZqyNJZgVrGTMsB8bMCiM2dbmsK1TXsc
         rfleGcj1KLM072UayX7b9Of4xUrveZkHvYi3wK63FEozfa4dEOTECWASCdhKyN5xTls0
         tS2T3XONKHwBmuSVip+I9JVr3hfgszfJVfAsbgKo7Yu5QL4nKZnYyR5nI3wOJm/7aeg1
         FALaw/iX2QT4Drz9b3EE6f3Hb0QQWH+eyXeGmKmhvEe5Ksy9uCpA0FiA2dsDY0DXVXg7
         yb2IGVzpiQzERReLD64p91/31JutxSVyVTidE8+l9/wOV2/0mSdWRQunPgnEC9F4LKDN
         YW4w==
X-Forwarded-Encrypted: i=2; AJvYcCUHjaK3u0rcl10e+sEwYQqnLPewUYyodkVdp2Nmf/2V4OBQAbwac+MzyP/uoknZO3302cOLaA==@lfdr.de
X-Gm-Message-State: AOJu0YwebnpaCk9A6EJbGISkQ5bxiazGzMrqvCEls8ilwZLtDm242Gld
	D0Nk0K2rHFt2X1yK+XUuJjWYfda5Tljikrw0udt6C3Klv22O1rXlLpE2
X-Google-Smtp-Source: AGHT+IGMHHrp4dFJIIGg1c3ztyNAKAuPRpx8eghsFSiFQJaI4x6Mo2linLlJvQERYrLPM0rBF1bYWQ==
X-Received: by 2002:a17:902:e5c4:b0:28e:756c:707e with SMTP id d9443c01a7336-294deedaf43mr45839495ad.33.1761764882799;
        Wed, 29 Oct 2025 12:08:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ag/rnCDznFJKaiOnB1PtN2gXLZA8AbVCGQ/ufaLmQyjw=="
Received: by 2002:a17:902:a50b:b0:267:b739:fb with SMTP id d9443c01a7336-294edbe4aa0ls917045ad.1.-pod-prod-01-us;
 Wed, 29 Oct 2025 12:08:00 -0700 (PDT)
X-Received: by 2002:a17:903:2290:b0:275:7ee4:83bc with SMTP id d9443c01a7336-294dedfc8d2mr42752805ad.2.1761764880644;
        Wed, 29 Oct 2025 12:08:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764880; cv=none;
        d=google.com; s=arc-20240605;
        b=efcw18gQ142x12KUnsl9gtjl4Ni7HOmKeQcndAElumktD8ZEgh9xs4ES1hF5/KDPYD
         JFX63pgO29UwY/WJs7lVnNPoFIsxjNpGW6yENw/TkJ5LrUwA+PJUspjbiyQaCFEQX+W5
         WpSail4vHJtoT7nV+IzNRwCWCgrsuXAi+45VqBChAUoivPt01T3hmLaRHy57wBqzxg2/
         mTFJObeZ58N85dOEi/SscDTGfNdY0jq7SU8aBbT6/06P28nqDsrfBavO0CMQfz2d7MWf
         VPKYMb2hHgZd1XwNIrz1FfVn0w6tqxhTqOZQzrhoS7u81P0ytPJj2dfdady6mzUDZW/F
         LKQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=wC6RWC0BysYEjK4tLyl5sRrziRZnxpuWzjQ8a6tBeM4=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Q4AekzH/XxjFERfJhfXeWHFLHMyK81HLcDSq0BrnSnt1OBvuO3dluPjX/8zor02/J/
         ouv3tYolGRXSEPTjBohBLYdioSt3eAmkJVBI3S0Ii9Ypk4U+BehH72Z3RklR3IGkofvA
         UlFnDPnuNV/hQ+zzB4kvdIQZRsmQQM314Bt83HYqxV7AEbzdQ2MyV7bEo/cQFmcUSanp
         l+p5fqQ+DRMpaJWEcK6nax4B7gUXFbw5f1HapTdPv75vn0TIHyXdvM0r6iIUS9O+pcQe
         O8V1Qs/Oi9hXYLZJ5UP8eHV/yKo4NQ0tiHC2QJkuttbXjC9b2MmcH84FxqVkWQ+jjNxq
         Q9kA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IJcPNw3y;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2949a8d31c8si8209615ad.8.2025.10.29.12.08.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:08:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Wed, 29 Oct 2025 19:07:50 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 09/18] mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
Message-ID: <d6443aca65c3d36903eb9715d37811eed1931cc1.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 63b0d2f639705dfa0c06cb457ca2d9660abebfed
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=IJcPNw3y;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
vm_reset_perms() calculates range's start and end addresses using min()
and max() functions. To do that it compares pointers but, with KASAN
software tags mode enabled, some are tagged - addr variable is, while
start and end variables aren't. This can cause the wrong address to be
chosen and result in various errors in different places.

Reset tags in the address used as function argument in min(), max().

execmem_cache_add() adds tagged pointers to a maple tree structure,
which then are incorrectly compared when walking the tree. That results
in different pointers being returned later and page permission violation
errors panicking the kernel.

Reset tag of the address range inserted into the maple tree inside
execmem_vmalloc() which then gets propagated to execmem_cache_add().

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v6:
- Move back the tag reset from execmem_cache_add() to execmem_vmalloc()
  (Mike Rapoport)
- Rewrite the changelogs to match the code changes from v6 and v5.

Changelog v5:
- Remove the within_range() change.
- arch_kasan_reset_tag -> kasan_reset_tag.

Changelog v4:
- Add patch to the series.

 mm/execmem.c | 2 +-
 mm/vmalloc.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/execmem.c b/mm/execmem.c
index 810a4ba9c924..fd11409a6217 100644
--- a/mm/execmem.c
+++ b/mm/execmem.c
@@ -59,7 +59,7 @@ static void *execmem_vmalloc(struct execmem_range *range, size_t size,
 		return NULL;
 	}
 
-	return p;
+	return kasan_reset_tag(p);
 }
 
 struct vm_struct *execmem_vmap(size_t size)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 934c8bfbcebf..392e3863d7d0 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3328,7 +3328,7 @@ static void vm_reset_perms(struct vm_struct *area)
 	 * the vm_unmap_aliases() flush includes the direct map.
 	 */
 	for (i = 0; i < area->nr_pages; i += 1U << page_order) {
-		unsigned long addr = (unsigned long)page_address(area->pages[i]);
+		unsigned long addr = (unsigned long)kasan_reset_tag(page_address(area->pages[i]));
 
 		if (addr) {
 			unsigned long page_size;
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d6443aca65c3d36903eb9715d37811eed1931cc1.1761763681.git.m.wieczorretman%40pm.me.
