Return-Path: <kasan-dev+bncBDUNBGN3R4KRBXXQQH2QKGQEAMSBGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BD6A81B4B2D
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 19:01:18 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id f128sf1090176wmf.8
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 10:01:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587574878; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zgpl0u97CAdlhHtAzir5Msja4ImDpqGfOPx5wXDnW4hNmucdqD9ol4QlLxQihlSxHB
         zHjaXi2m1AoE/jH6DNsSi8V/0Rjd3KWuT0Xfylji6CnS3rhZl2kUxBBV04vLnD08e2ZL
         ZBLKEFCcbaYuoZg9OBJl/0XR8p8yNSui1QdtUOLROGPRHe0Ph3QcG6RINEvj9DTLOSaJ
         Tkxjh7uOUor7i117SGYAcIqqPWKTw/0X3SCz+qRX6sDMj6B16v99PWzKyvt3ggDJdpke
         NBV/PuLGCU3ztF6K+7h/2PGBF+okdg7bKNBYXJqABhbXam9sNT4+bNw7t0ekot0oGYge
         EOxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=U4M4KUXHWpTf4k2jJLfV2MwKjP1kxkdqih/RvDd/p/0=;
        b=cTI9G0SftwCOfY1coBTiby8wTe3DxcngdtR1Ul4E2CsJhVWU3TJ/clrD9dkSCZ3SVK
         jKEh5e5Gt8k1JWOZVNeg1pRqbIEht0jOGgFi6mEccpdVuORIZnFIkbpRR00EHXU7kS+6
         eCGIT6wkKc1FtBiWmxHeQPZVnuOZezJal4k0p8mcQTPFE1SQ9B2qKq9xNYWWgkT8CY39
         gUmNR6z55KwA8sKeoDGMfzRqMWXKbRJEKEbu9YXqtDU3Qec1VJlh+aT4yNbLadbNsehx
         /KsVOh4j6vyX71A3DyRAqE9bh0mRi7CKe1G0h7VTu5AZM7HDop+Ju1fnKR05l5nYRXh9
         NTRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U4M4KUXHWpTf4k2jJLfV2MwKjP1kxkdqih/RvDd/p/0=;
        b=BTmhJfjrBGGlzGUcPh8c62G6Cm19zwJC1nBfE6lsSMu7TbBxdaDSMMd+XmvH2+VDgk
         4i9AZ5ugNCzWtsv8sxzYWlNl98WF3HxHmVzZCMRHhEixmq8V8ypF2alTPJn8hdBwPnPr
         hTylsbOUAybvlYej9PhbUDWzX5NhIDUPpDh9Jw9fzMNsL7CdUQ/+NQj0iyCZt8NqCA59
         H93LpxEcBipRTTrUeMgAp/kD9508QF0LWCwKcc6KUGY1x0bbdNJUM0T2W6gQicYFR5uj
         Y41mtSeJsMGPlgnXKyT8gDNx8znEIHCgNzApH4X4oUt1Ku6eiRMmKdwqWKoBuRXBdPiy
         Y3Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U4M4KUXHWpTf4k2jJLfV2MwKjP1kxkdqih/RvDd/p/0=;
        b=JAYtTFsCW5qpyYhZlBJdUlQP7BP6I3ZfPRDfk6UxAxXWfPOmP0jVVdDGESZa1lrnzy
         RqNtCUAmXXudEQCZv0+B5WBd/6Xdz7jY2LY2ddR0bua2SaKq832BjquM7JG2w3aDhvzV
         atWZtfCQiZ3IRWRsLZ70ZT//poDfw2qICotbAp1NWV5eK8qHAn8J+2BFhCPKiCwKRBim
         uvj19zGQt79bvCdsr7KBnLv/BpemmmK5HsBWyiXu/0LDXG/7GX5F+oFXH5s6TR4q1f6k
         oWtVkmdnCK2KB0jA9BGlAoh9kffwT9cGvKuFLziH0gp3TJYErXx9nTAr9u/LqG0ioxL0
         oKqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubU9blKPTdeYJvPMkQfeyXwyToKDQ+WAYe9nNFFWBqC5FIuIIAi
	PclteOajset4lxoi+xtVWdA=
X-Google-Smtp-Source: APiQypLltBdvfcrSpZy7lnQFkwLafLfS7h/mwGua58uyaX7hn9D9H8d6agkr2PWPXCer2hAKTcImww==
X-Received: by 2002:adf:fd46:: with SMTP id h6mr28905wrs.90.1587574878431;
        Wed, 22 Apr 2020 10:01:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e44e:: with SMTP id t14ls2220688wrm.1.gmail; Wed, 22 Apr
 2020 10:01:17 -0700 (PDT)
X-Received: by 2002:adf:f34f:: with SMTP id e15mr31388074wrp.275.1587574877810;
        Wed, 22 Apr 2020 10:01:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587574877; cv=none;
        d=google.com; s=arc-20160816;
        b=T1uvZlXummQiCuhnA7L1Zx5t7PzNg+YJyk7u1uEv16sPUPOmEGZNIc+ZmUNfzgTlTX
         utv/MR2bHZoNEeHlpBERKhXPmvK3LVeo5xuFV59Y6rLx9Kd9+H5ou/HYefD4fDD6GxGN
         ycWsecGhpcLG6tzBYySAHvRjGJD4vlPwcwCIR/QCwIUfDFHNju+WFZ+nTuzuyaTXamFR
         LNrANU14Y+xl9PtO/doabgUvNrbD1ixlEpM3zsa/AcHB/HF/JFAsPs8ncK4g/49IqJwh
         DhDG8Ta0dG55u9XXis+bLEst3lld81fq/76JPBPZHcC3Avhcrx2H7n8KFXoeemseP5q9
         msqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=QCOhu8y6jcDa7Xa/hP0pPsvNknCJHsRI68OSk0LUzHk=;
        b=OcFr/NF3/+DnQEtQkYJf8bPahcl5H2+DZmtIp1eNV+qaEnxth8SYExouVUZ0dwkMUb
         9ZSLuxq32tRUiB2dPn6zu40zPQ/NrlOtAg8Yb5t6Zy6D604AHMdFV6ZdBsbHcmdlL6/o
         B6Pr23eb6L7lxGsVdXIjBtWG6n9dKvm9BgnYbEbBf4Y9wNEbZoV/D/P/tyGHmeh9njdG
         bAtjiebGrRNO8vMqFI9FjnChnpsd7vcK8Y7KwdsYjvxaQasAwpDUIXAKnabRvF/qKK9q
         z91GIAbycoReIE0Ub3lo5n0rSKGbP136sH1UrcvI239LytBaz0zqEAdzyJQxyO0aL3K2
         trMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id o186si412260wme.4.2020.04.22.10.01.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 10:01:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 485BF68C4E; Wed, 22 Apr 2020 19:01:16 +0200 (CEST)
Date: Wed, 22 Apr 2020 19:01:16 +0200
From: Christoph Hellwig <hch@lst.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>, Borislav Petkov <bp@suse.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200422170116.GA28345@lst.de>
References: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="LQksG6bCIzRHxTLp"
Content-Disposition: inline
Content-Transfer-Encoding: 8bit
In-Reply-To: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of hch@lst.de designates
 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
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


--LQksG6bCIzRHxTLp
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

On Wed, Apr 22, 2020 at 11:55:54AM -0400, Qian Cai wrote:
> Reverted the linux-next commit and its dependency,
>=20
> a85573f7e741 ("x86/mm: Unexport __cachemode2pte_tbl=E2=80=9D)
> 9e294786c89a (=E2=80=9Cx86/mm: Cleanup pgprot_4k_2_large() and pgprot_lar=
ge_2_4k()=E2=80=9D)
>=20
> fixed crashes or hard reset on AMD machines during boot that have been fl=
agged by
> KASAN in different forms indicating some sort of memory corruption with t=
his config,

Interesting.  Your config seems to boot fine in my VM until the point
where the lack of virtio-blk support stops it from mounting the root
file system.

Looking at the patch I found one bug, although that should not affect
your config (it should use the pgprotval_t type), and one difference
that could affect code generation, although I prefer the new version
(use of __pgprot vs a local variable + pgprot_val()).

Two patches attached, can you try them?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200422170116.GA28345%40lst.de.

--LQksG6bCIzRHxTLp
Content-Type: text/x-patch; charset=us-ascii
Content-Disposition: attachment; filename="0001-x86-Use-pgprotval_t-in-protval_4k_2_large-and-pgprot.patch"

From 71829ed28a4f3d616382e7a362d501eb9ea7dc13 Mon Sep 17 00:00:00 2001
From: Christoph Hellwig <hch@lst.de>
Date: Wed, 22 Apr 2020 18:53:08 +0200
Subject: x86: Use pgprotval_t in protval_4k_2_large and pgprot_4k_2_large

Use the proper type for "raw" page table values.

Signed-off-by: Christoph Hellwig <hch@lst.de>
---
 arch/x86/include/asm/pgtable_types.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/pgtable_types.h b/arch/x86/include/asm/pgtable_types.h
index 567abdbd64d3..7b6ddcf77d70 100644
--- a/arch/x86/include/asm/pgtable_types.h
+++ b/arch/x86/include/asm/pgtable_types.h
@@ -478,7 +478,7 @@ static inline pteval_t pte_flags(pte_t pte)
 
 unsigned long cachemode2protval(enum page_cache_mode pcm);
 
-static inline unsigned long protval_4k_2_large(unsigned long val)
+static inline pgprotval_t protval_4k_2_large(pgprotval_t val)
 {
 	return (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
 		((val & _PAGE_PAT) << (_PAGE_BIT_PAT_LARGE - _PAGE_BIT_PAT));
@@ -487,7 +487,7 @@ static inline pgprot_t pgprot_4k_2_large(pgprot_t pgprot)
 {
 	return __pgprot(protval_4k_2_large(pgprot_val(pgprot)));
 }
-static inline unsigned long protval_large_2_4k(unsigned long val)
+static inline pgprotval_t protval_large_2_4k(pgprotval_t val)
 {
 	return (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
 		((val & _PAGE_PAT_LARGE) >>
-- 
2.26.1


--LQksG6bCIzRHxTLp
Content-Type: text/x-patch; charset=us-ascii
Content-Disposition: attachment; filename="0002-foo.patch"

From e5a6c2e84accad3d528c5c90c74071d10079db9a Mon Sep 17 00:00:00 2001
From: Christoph Hellwig <hch@lst.de>
Date: Wed, 22 Apr 2020 18:54:45 +0200
Subject: foo

---
 arch/x86/include/asm/pgtable_types.h | 11 ++++++++---
 1 file changed, 8 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/pgtable_types.h b/arch/x86/include/asm/pgtable_types.h
index 7b6ddcf77d70..c6d4725269bb 100644
--- a/arch/x86/include/asm/pgtable_types.h
+++ b/arch/x86/include/asm/pgtable_types.h
@@ -485,7 +485,10 @@ static inline pgprotval_t protval_4k_2_large(pgprotval_t val)
 }
 static inline pgprot_t pgprot_4k_2_large(pgprot_t pgprot)
 {
-	return __pgprot(protval_4k_2_large(pgprot_val(pgprot)));
+	pgprot_t new;
+
+	pgprot_val(new) = protval_4k_2_large(pgprot_val(pgprot));
+	return new;
 }
 static inline pgprotval_t protval_large_2_4k(pgprotval_t val)
 {
@@ -495,9 +498,11 @@ static inline pgprotval_t protval_large_2_4k(pgprotval_t val)
 }
 static inline pgprot_t pgprot_large_2_4k(pgprot_t pgprot)
 {
-	return __pgprot(protval_large_2_4k(pgprot_val(pgprot)));
-}
+	pgprot_t new;
 
+	pgprot_val(new) = protval_large_2_4k(pgprot_val(pgprot));
+	return new;
+}
 
 typedef struct page *pgtable_t;
 
-- 
2.26.1


--LQksG6bCIzRHxTLp--
