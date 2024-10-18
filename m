Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBLNWZK4AMGQEPYU6TMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69A999A449B
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:23 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-7c6a9c1a9b8sf1713942a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272622; cv=pass;
        d=google.com; s=arc-20240605;
        b=fI8kEf3l3w0vQ6g9+GmEwLb9B29NNPtIAQKZPb0pq12higauzH0Oxi+P0eSEj7jS4f
         YW/OrX+jwfRmAo/3pKcheUm+oXfoNVQVB9DjJN2//clh2SjlAwJD+VpJsR33ly56a+8B
         UFatuIfOEgjHopwmazmUWZqecq0JaUV/EorWCdoV5BN7aaYAssrGrE+2h1LvCATZgKdD
         OAbm4/R9+QR4iKeE7o5Aw1liRbVHUy3XLe4AcK88fhB8GVskHewUHSBYsZucX2T5c3Ag
         2vGlW/vcpqgfTN7Z3B7lEROGyYA5Uo89gbyaktAU+Ej4qK8L6Xsewp8SLLp8z7nfJ18W
         kCkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=uTQbr1R3PO/VbZ3V/s1269ohwvLJKQmdRBJ/YzakITg=;
        fh=EusBfk89U0JK75mitAvtd1ugxlxjgbEdht2TO3egA40=;
        b=i9Hyj+rkaJq3dM18L+1O8RBExKNdAR0q1Rm5uzz+1CiN/TqpB3R41p3gm79C9qqrZp
         BAnzpLXqgReEuc/wWI18BIK8rLxY8LVyEgS53PR38MAhXtt998oJvy2Ie0RzZ5ShQr47
         Kfbb4jf36uV5MXzWQoslnEh3jo5h5iCIbcJkufJAmK2hRoUnO9QeoUTbtqSVx9UzByUL
         1YF9qczQAGksrgA+9x5wpUBtbS06S3pwBjSRjHuQYq33ZC0dQU379eFFVLdFF70vfLtu
         VD5/ixhh4xe58cBxG8unEvcw7iZvXHPOkl273jDZsaLmHjDtSRkm/ZAhdOk5lZZAhHVx
         rmcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=alLbsVzM;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272622; x=1729877422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uTQbr1R3PO/VbZ3V/s1269ohwvLJKQmdRBJ/YzakITg=;
        b=K7dHlj4OAZQ3XLDRCLQO6S2p17IxtfnngeKX3KuI2Ihh84mkRmhTmqOdTjKmWzpX1Z
         u92LJSLG3EsW7nfxvRnipO5IAIFe9/kYknJI//0rbzCQXRsRnx13QlfxbYZnPSrM+8AC
         TlWmDCD0cyAPqttnEBWgZtnEl2r19GwdUKhHxjY+SPSAk8NU1uFtLadMyiY/ESNsqyVO
         zmW6/hwv+IeFZwQ6+gUVT/c7mUn8ZTUzPuBPCNm5j60zGSWzZ5Zl0aFjm8LM6HQXR6yA
         y/RZsPNAsdUkvG6Vuc4O+ryBH74laWNgEgWS/Vy1KPFzaAdZ1EHxEL6iTDRYScBZVD8J
         BiSQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272622; x=1729877422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uTQbr1R3PO/VbZ3V/s1269ohwvLJKQmdRBJ/YzakITg=;
        b=nf9lpFJD3HDRy874D1OOc4jwazQIeGRHU0LIIqGxLSg8DKd2hn2STpQNdKDynqUSFU
         570QNF8Dte1vhB1ndhdBd4sZR6xJGokQyMwyovOrbQeEHPldoMGyuiZ1WupkMv+DJUhm
         OSPkWtk8DebZmRKKSpz+gQTAKaeaE4u+NNx5fogOOA685Y95t38nO+S/sOORefsJ0QnN
         kszacoYuhhd6PwASTMgIP6w4sdAGYl25hQBHM3bfGVohmE4B71xaX4lXeC24qHtnpEcz
         Tn3VWQzQ6a25NsS6j8rCknFDEK83sT0+CIexkmtjP1Jfl+z031aYfwemqrK8aiH8v4Vm
         DwyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272622; x=1729877422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uTQbr1R3PO/VbZ3V/s1269ohwvLJKQmdRBJ/YzakITg=;
        b=mh7xwoWlsNOhbIq3I4c+br3Pd8VCgXEJQ3Zr969TvZyfWK7JFL2QESXe7DjwCs/N2T
         w+GhOf2LxXtptdhkVx3F4SdRBAFvNeLuWztShrPKW+iFAZ3s70Y9jcy2HIRcu3QZ3YJP
         5je8iQQ4gbJnoFDUD4jhyqxm7udSN+BiYnrGEnkQFAyTJkY6krepFOpbL5tlScYNOj8n
         Lb5A1iYZ7yGmdGCwQd7PKUDdMzsd3iWtu3FWINX0/HTpfEeRmI+QOCJyAZglDkrOVxB3
         sdTTLv6wJYJCc48VDHMEvgqdNTLemE/Rlq2J5aDTCgJeGyN/KZAqPtukYdrgGjEG5GAc
         +rAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyoggkpt+4PhOWnOtan8wtF4s7yjwTiDKGSfQUsfxCdFN0n+uJkmNn3zlf1W/0WlnM3//2EA==@lfdr.de
X-Gm-Message-State: AOJu0YwRSJPwqRrAQmzFhZUM5JFaOxLy/NmSaso/VRqvsqaczEO43eOT
	JrB23KWZBThHnXWBYUgjzUwmgEtEcaJDbFZbrXLVwbUNfpSZrogC
X-Google-Smtp-Source: AGHT+IHXct5ojEAqdQtbUUx0Pdu/oEu9FxEMr5XUbwUW4uOs16uL3H4D6vVz3339jjjTBCzsI9qUJw==
X-Received: by 2002:a17:902:e544:b0:20c:d04a:a53f with SMTP id d9443c01a7336-20e5a9440cbmr40636325ad.58.1729272621296;
        Fri, 18 Oct 2024 10:30:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e843:b0:206:ba3c:2b96 with SMTP id
 d9443c01a7336-20d47b11d9cls17842865ad.1.-pod-prod-07-us; Fri, 18 Oct 2024
 10:30:20 -0700 (PDT)
X-Received: by 2002:a17:902:dac9:b0:20b:a5b5:b89 with SMTP id d9443c01a7336-20e5a8bd5a7mr49381155ad.35.1729272619773;
        Fri, 18 Oct 2024 10:30:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272619; cv=none;
        d=google.com; s=arc-20240605;
        b=BB93SuIxcqW+Qsu2GliIv0bDRiLciK1HY0ORM1bWkf9X0xfBenY51e1uMJnJhXD52Q
         KC5ubg/g7cUzypU5IJF5UP86utd+jrrpYVXXl5ChT8kHDfoJ4NxKsLGXLWY/D5gqH/S3
         3fxcPl0Qn14JDIEaWBzkPEyVYBuqK2eiCYkWM3CjvaKK8c+7QSz6/Goqu4dKci25zjYd
         Yf0GOqovas9AXqz02+x7Dr7caK2shYLTYQmP0m1GlnNy3UBOsW0H48CMNxgxh+noCBKQ
         YLmdTPrdbXyqzhkxckKbabkTnc8xGMuzR/eopPvh4fsUUknpvzmLaxCojEOavnFkxBqw
         S97Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/kexGPHg7BP7JEy0b70rSKtUMi9zN66ceCEdb7Ha4D0=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=TDwZxxqaZ9VhFn4NiKut240BDU4ZUETFNcAYTuHWmFck9r0Q94cJAWbDXjk8ECl25J
         W6bw+uIr5OAb/36dcgjVI0aSXMgBtRYfHoZj/DBHPqGbbKrh77W7jAtIMD5JV/605CR/
         SLdH31JZp/zTOlA0xbeac2AErf9wIBd592wwBMJ5sYbLTpnTYB6PiUAY58rjMaq1WyFz
         JDX3YSS0uyDFBN+diGiJ6jR7VK6SLzkw+y+xLCVrbwmYlyBBk3deT7UO4WWIzYiWccls
         36FjH1m6r1+tOjERQrAEyOP26YnTCpDXyCj1vxioLAPgFt8vRXabGGd7EF4fedgkKUPw
         rhHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=alLbsVzM;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20e5a8f15d2si837405ad.8.2024.10.18.10.30.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-7db637d1e4eso2452979a12.2
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:19 -0700 (PDT)
X-Received: by 2002:a05:6a21:164a:b0:1d6:e6b1:120f with SMTP id adf61e73a8af0-1d92c4dffb5mr4996670637.11.1729272619178;
        Fri, 18 Oct 2024 10:30:19 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:16 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 00/12] powerpc/kfence: Improve kfence support (mainly Hash)
Date: Fri, 18 Oct 2024 22:59:41 +0530
Message-ID: <cover.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=alLbsVzM;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52c
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

v2 -> v3:
============
1. Addressed review comments from Christophe in patch-1: To check for
   is_kfence_address before doing search in exception tables.
   (Thanks for the review!)

2. Separate out patch-1, which will need a separate tree for inclusion and
   review from kfence/kasan folks since it's a kfence kunit test.

[v2]: https://lore.kernel.org/linuxppc-dev/cover.1728954719.git.ritesh.list@gmail.com/

Not much of the change from last revision. I wanted to split this series up
and drop the RFC tag so that this starts to look ready for inclusion before the
merge window opens for powerpc-next testing.

Kindly let me know if anything is needed for this.

-ritesh

Summary:
==========
This patch series addresses following to improve kfence support on Powerpc.

1. Usage of copy_from_kernel_nofault() within kernel, such as read from
   /proc/kcore can cause kfence to report false negatives.

   This is similar to what was reported on s390. [1]
   [1]: https://lore.kernel.org/all/20230213183858.1473681-1-hca@linux.ibm.com/

   Patch-1, thus adds a fix to handle this case in ___do_page_fault() for
   powerpc.

2. (book3s64) Kfence depends upon debug_pagealloc infrastructure on Hash.
   debug_pagealloc allocates a linear map based on the size of the DRAM i.e.
   1 byte for every 64k page. That means for a 16TB DRAM, it will need 256MB
   memory for linear map. Memory for linear map on pseries comes from
   RMA region which has size limitation. On P8 RMA is 512MB, in which we also
   fit crash kernel at 256MB, paca allocations and emergency stacks.
   That means there is not enough memory in the RMA region for the linear map
   based on DRAM size (required by debug_pagealloc).

   Now kfence only requires memory for it's kfence objects. kfence by default
   requires only (255 + 1) * 2 i.e. 32 MB for 64k pagesize.

Summary of patches
==================
Patch-1 adds a fix to handle this false negatives from copy_from_kernel_nofault().

Patch[2-8] removes the direct dependency of kfence on debug_pagealloc
infrastructure. We make Hash kernel linear map functions to take linear map array
as a parameter so that it can support debug_pagealloc and kfence individually.
That means we don't need to keep the size of the linear map to be
DRAM_SIZE >> PAGE_SHIFT anymore for kfence.

Patch-9: Adds kfence support with above (abstracted out) kernel linear map
infrastructure. With it, this also fixes, the boot failure problem when kfence
gets enabled on Hash with >=16TB of RAM.

Patch-10 & Patch-11: Ensure late initialization of kfence is disabled for both
Hash and Radix due to linear mapping size limiations. Commit gives more
description.

Patch-12: Early detects if debug_pagealloc cannot be enabled (due to RMA size
limitation) so that the linear mapping size can be set correctly during init.

Testing:
========
It passes kfence kunit tests with Hash and Radix.
[   44.355173][    T1] # kfence: pass:27 fail:0 skip:0 total:27
[   44.358631][    T1] # Totals: pass:27 fail:0 skip:0 total:27
[   44.365570][    T1] ok 1 kfence


Future TODO:
============
When kfence on Hash gets enabled, the kernel linear map uses PAGE_SIZE mapping
rather than 16MB mapping. This should be improved in future.

v1 -> v2:
=========
1. Added a kunit testcase patch-1.
2. Fixed a false negative with copy_from_kernel_nofault() in patch-2.
3. Addressed review comments from Christophe Leroy.
4. Added patch-13.


Ritesh Harjani (IBM) (12):
  powerpc: mm/fault: Fix kfence page fault reporting
  book3s64/hash: Remove kfence support temporarily
  book3s64/hash: Refactor kernel linear map related calls
  book3s64/hash: Add hash_debug_pagealloc_add_slot() function
  book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
  book3s64/hash: Refactor hash__kernel_map_pages() function
  book3s64/hash: Make kernel_map_linear_page() generic
  book3s64/hash: Disable debug_pagealloc if it requires more memory
  book3s64/hash: Add kfence functionality
  book3s64/radix: Refactoring common kfence related functions
  book3s64/hash: Disable kfence if not early init
  book3s64/hash: Early detect debug_pagealloc size requirement

 arch/powerpc/include/asm/kfence.h        |   8 +-
 arch/powerpc/mm/book3s64/hash_utils.c    | 364 +++++++++++++++++------
 arch/powerpc/mm/book3s64/pgtable.c       |  13 +
 arch/powerpc/mm/book3s64/radix_pgtable.c |  12 -
 arch/powerpc/mm/fault.c                  |  11 +-
 arch/powerpc/mm/init-common.c            |   1 +
 6 files changed, 301 insertions(+), 108 deletions(-)

--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1729271995.git.ritesh.list%40gmail.com.
