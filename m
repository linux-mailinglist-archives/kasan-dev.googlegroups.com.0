Return-Path: <kasan-dev+bncBAABBXXJRHEAMGQEKHYNW4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 91E46C1D29A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:11:11 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-63c251265absf146349a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:11:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768671; cv=pass;
        d=google.com; s=arc-20240605;
        b=DiUfn5KADpMltVLE96bd0anFCmtr0GkgcLYfCBi5iDxQj/2/nI3rMvywsmtsBEgQub
         IKwbvDOIf2A5TiPik2QpkykwUCc6sF4tsdeh+6T1DdT/U2b0hYog2nkWfqecOEh9FAad
         Cap1eWcQpF82mE6jAFfoj9EPSgCbCmvkAYsds3ca6s7zOMBesOWLJpmMeQ52dmk20WED
         mGlxzEp8cgEdIE07ZaADicQGmxso9d3UVMY3w5v+MmbiXe9cvgWZXwx6CIXOdTN+QcM5
         Fy70qxhO8OreJ/H5jzpbDVx7snOilK/eeKjVI+uQLO86WHrvvXqrv/tBPk7T7uxI8cqq
         0bhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=7DjPD68vxPIdeeniPNWRCSw5UFNBjTTzrDe7JaRd0sk=;
        fh=hZSxMlDMD5iy7wSaDPkXrkvTXNY3diYIXeBSjTRcAO8=;
        b=iCB3pUk+s+OVWKBw9kr1YrJmGbJTb91FUEAxJIa6mZTIWgbmRnMkml0vbJifm/iA9w
         jub52P8G+evcl+W2z75ywEQJ0AyXDHsQB74Usy9u+81vLQsIkuWN5/2l5WN0aQCkdX8R
         9WypWaU1frPcJ/PSDYthOwXpe/Hlpancyg+jXlYi3aOmXP3ZsHLF/SX1vNeeZKGLIDgE
         Mk4Tk7ZHtLZzNWIaVbeUialQMIAHxg5OfYnMp59yEJ7w02chEkW0fKsovT12bTJqo0NR
         o1An1BA236I7pimPeO4VerSktGRo3sEVryjOH+6gwyySQOgKXFOoDEUEo3hdoXWA91xq
         iXWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="fzcdT/Mg";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768671; x=1762373471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=7DjPD68vxPIdeeniPNWRCSw5UFNBjTTzrDe7JaRd0sk=;
        b=KWk5JCIITR4oxdXDiVrSsDFZMKCwOCrjf3iZ1DPMcE1XQFFfmSct5OsM6fx5zd+Ry0
         3DGcDdrENQ0BfDRyds5alj9ko3xQPEpfLNbXbnXLJwTib4Zw0LalfAlarINuYqFTn1JP
         eXHznqz54EE7ipxEyCcE2yPEjzaUr30CXuLe4x19YmdSKPaa35TBV5tI1xk8MLvUtGO4
         zDcj5kXNC38H9oe2Mzu0deOSy2/WZfuLa+JGx/gfMeTnXwpcuQ/rmXq4PsLFh0r5sS3K
         KfF4Kb5GRERx9VeK4a3w/10qh+CIX8Sg0W1+CI9wiLEc3r+RlPyf3GNdlRQ21J6m40yi
         NRSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768671; x=1762373471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7DjPD68vxPIdeeniPNWRCSw5UFNBjTTzrDe7JaRd0sk=;
        b=flWWaHb41fWcoYgfxsVlIYuryujttvcsmYjNWJG0UkLzZqKGe3/S6CXsLS9OQ8KafF
         1sBSp0MUwVtkibCnxW2udct9NmKdgL7y76mkLGNynXw6lbx/ZFtyePaMPtBttVbRIesF
         /SkMNXLp1gUVdwasG2zkyXESFW5oCL8ypgqH/jzFh3OmVNaLRpKbYjiVDyfZoIsUb7fr
         HkaBQIxKknjw9tybWO42iNvIDS6M75PzGirjTtgdRUi9mf4MPlC0ohZJOlcluD0uLgWW
         JJD9ezGVAkVV7NA9rr9hIgcKxWZX0C+ogik+K1j4WneytPtl4rTXHbmGXnVLKkHz3MTg
         N1Cg==
X-Forwarded-Encrypted: i=2; AJvYcCXA4G1kPzIsBSIKH6YfS6XR8OWmNkJcbMdv9QEs+Rq0XnrZAnai1B3ssuobB3zISamqhKdKow==@lfdr.de
X-Gm-Message-State: AOJu0YzSmed3Ejkvt6p8lgnxlrCohJWLjfaRXxfdsGmRvRPpHcUQ4Nm6
	dgeF9cVWmCn9lCVPonnYATimmgy4Ri9m80Jg6mIYnrK5CScSD80qwDIs
X-Google-Smtp-Source: AGHT+IHryNU9GuNm6t89x1Hq/vmpBBa727peDLNm42uP+l8Cwi5DOFabZoWqqpwYGjUH5uHdufEwvA==
X-Received: by 2002:a05:6402:50cd:b0:62e:de67:6543 with SMTP id 4fb4d7f45d1cf-6404418a9e9mr3339297a12.4.1761768670834;
        Wed, 29 Oct 2025 13:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YKb/qv7Ycj+CXArOS7uiPL42ZUn3zUUxNGxQM1XDJuPg=="
Received: by 2002:a50:9988:0:b0:640:342e:51db with SMTP id 4fb4d7f45d1cf-64060578699ls135127a12.2.-pod-prod-05-eu;
 Wed, 29 Oct 2025 13:11:09 -0700 (PDT)
X-Received: by 2002:a17:907:7f13:b0:b6d:5718:d43f with SMTP id a640c23a62f3a-b703d4d5f6amr390443666b.39.1761768668789;
        Wed, 29 Oct 2025 13:11:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768668; cv=none;
        d=google.com; s=arc-20240605;
        b=Hd1DjFOVCzgNjspY0P1fpRO/wsl6Ca4VH7EjjFZMehPfYid+05+RJ/THaexONRNYOh
         ARSAyWPoqKHpvr03tOWMGtYtAmeXH9VrqdiYtMIfcJkFblll266HKAraDCc2K8o6VOJn
         Adh4WGkObA6ATkEhNpyNgcm22VrrF1J+zsE3mMi8DlQ4fztfeUDWrdhIbVfEsUqxqMQV
         Cpe7tnbJdByzlVDPlSv2GqNUOUCPJ8x+gAQ2W5ui7O5sVUQ4f6GMX1hDyhduFGaryfUZ
         NQ69CcmAEv2APX3Hr2g301csBXyHCm3woXclyvr3glbDliGtuYODMeckrjdydezdVYmi
         iYUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=qpGuNHZZR4hchfLUKKttSmaxG+W37eMF01r5+dBbCBY=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Qxou4jVcVTH3kGFtOsnAEU/shzqER0/SzlE5MnbPuA4tV6Oeu6pIiHEl/IKQCY0n3/
         YQb+0rAoXunRRXwOsgMhVzfSdpM9yhfHIx567lIGu8l2zdOK8NBo+gtUIgSWCGwPZYKg
         i+pQ/WrnJZiisbXB7v2ZJqaHhTtaB/kloMRFQQy8BC9WWa1bspoeuoegiZ9D127CkDLY
         DzEuzWVTiL1QI+C/E3RgjbcgBIG8bG88rbdlvC4stuWobqmUlrFz4ekaNpws+u53NhOG
         9EsgcnQn1lQ8mHlRuZQFPXhkbTIZLclrliq2Ey43zmcsgMPgx6UZSiaQ+9RWCwdqUZCw
         ydsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="fzcdT/Mg";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e814b0616si223833a12.5.2025.10.29.13.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:11:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Wed, 29 Oct 2025 20:11:00 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 17/18] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <81848c9df2dc22e9d9104c8276879e6e849a5087.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 1962ec27b7155c20b7f866d92710251ffdf5f53c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="fzcdT/Mg";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
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

While generally tag-based KASAN adopts an arithemitc bit shift to
convert a memory address to a shadow memory address, it doesn't work for
all cases on x86. Testing different shadow memory offsets proved that
either 4 or 5 level paging didn't work correctly or inline mode ran into
issues. Thus the best working scheme is the logical bit shift and
non-canonical shadow offset that x86 uses for generic KASAN, of course
adjusted for the increased granularity from 8 to 16 bytes.

Add an arch specific implementation of kasan_mem_to_shadow() that uses
the logical bit shift.

The non-canonical hook tries to calculate whether an address came from
kasan_mem_to_shadow(). First it checks whether this address fits into
the legal set of values possible to output from the mem to shadow
function.

Tie both generic and tag-based x86 KASAN modes to the address range
check associated with generic KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 7 +++++++
 mm/kasan/report.c            | 5 +++--
 2 files changed, 10 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 375651d9b114..2372397bc3e5 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -49,6 +49,13 @@
 #include <linux/bits.h>
 
 #ifdef CONFIG_KASAN_SW_TAGS
+static inline void *__kasan_mem_to_shadow(const void *addr)
+{
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+		+ KASAN_SHADOW_OFFSET;
+}
+
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 50d487a0687a..fd8fe004b0c0 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -642,13 +642,14 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
 	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
 	 * both x86 and arm64). Thus, the possible shadow addresses (even for
 	 * bogus pointers) belong to a single contiguous region that is the
 	 * result of kasan_mem_to_shadow() applied to the whole address space.
 	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64)) {
 		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0UL)) ||
 		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0UL)))
 			return;
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/81848c9df2dc22e9d9104c8276879e6e849a5087.1761763681.git.m.wieczorretman%40pm.me.
