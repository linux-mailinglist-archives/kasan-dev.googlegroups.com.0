Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB2GRVPEQMGQEQX4ZONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1932FC93D86
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 13:36:59 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b969f3f5bb1sf3796491a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 04:36:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764419817; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZinPmIQoD1i5/jgLMR6XAyTJj6w/wVnwrUfAXrpBa/tEjGwIb7OYbIEQueHeuyuhKd
         mMBNHWTDtDx+i1f9PS6Unn7pT5OHfBtZmq5TQnHQl9+RfKnlzOYks8dfwmYlBK4rduhV
         AYi8JOsZYrMGjq9Xihd1tbnuaoV768uL4UuKAOProqRoC4P4+6CXvOMvpgNTHE596dcR
         CkHjwyKib8Pe8vAwBeqtis09hxQ58CmqtLwAkoJgUKB2O953cjMOLnqqS/d0zXzfixvH
         DKg+oKeFbZuoQf6urmHEzqfdNRLAouqTHpAPLQNMJnfcgQMjFExlTX1vAPqlbQrZk6q2
         f0Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=FooH7Q2/0bJKOr0QIr6LBepgX27+ErA1mGZS6uJEqkY=;
        fh=v3yc2aPo7HeOrJJs9433JY2bqnw6ykypfoD1owkl4HQ=;
        b=TN1NQTUQFEYPUK2FmtoSliyni/yJTHMaKKgriY+BkzAvOwMaH/N4VpyVmUmVjv0emD
         GlH1jpemK0CbRExIFF1O84GQtO3YrlB0ESnDr5RcBlc8H7duYDDuojOgw6FM4/CW3vGk
         G0iUmZPKA/gt2Dfgx9Ezrvxmx0TZVXCwV6xW7a3I8s8SN2b9gZm4r7sTzA9e2MvkhVwm
         9phUbx/tDyL33qEd+tpZjWhmH9fPSrD8s50hDiUZ9gK7wW6VYhUjfcY6LM3UyizNKYxe
         vV35gNK5r1vPSH2zYueaUBVZrvPDri8lg7NdjpmCd5BdZK421PKs7Q4f+0MDcIndmYec
         fzfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764419817; x=1765024617; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FooH7Q2/0bJKOr0QIr6LBepgX27+ErA1mGZS6uJEqkY=;
        b=Sf8+TPM/oJ/vs+vEbsx5djArT0FiV4mC2kCt9IPOmR7BQ6y+fD7b1eGbu7hxfqOuTs
         cHbEPlgIrgeafH4nCTP3QD2GqkUekHSqezwfEzukKPQsG6JdmVh+iGnbhtqnqnSVBd5c
         nbGayMxaM4t+hHhtDTQR7dF2Ynws+f4X8u6uRdizB8yzpmMFONd003ylq/Aq5Q6f04b/
         BJ4r0DSVBs+w2g+6sb4TVVf0MtuxTvEl9s7ti+3wYNYCCCtr1brkP66/9tAqE7YimAiG
         tEGMJ9ZjkADT5D0GA3DvGCkXQTzX7lOOUmrc87YbmQhjhGt4lZG5UVOi8X4YIUPKbJqS
         xtcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764419817; x=1765024617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FooH7Q2/0bJKOr0QIr6LBepgX27+ErA1mGZS6uJEqkY=;
        b=m7RzoiAOWWoVfGNKpx63eE0teAd7VQlFuWY+fAHnyB4RjBAByFXgfqEPFZPHkFVehd
         h5u0BpDw5zzi7FU63LYhug4IgzEUVcfxAV7lO5lT2x5ol6D9o02NiweSJ/eH4zkHu0q0
         D3FG2WiwLhCkABWYnd0nGhV1SMjPGrEDfhZAuDuxXukCHGi4LUWhXK15L7XB9ub8D4qc
         TT8Ogfx0BVa7AX1e9pEL0V0VUBERAZ7QxGTxuLb4KqInKCDV4c71O0ignjcOSOFie4J9
         DITf0H1mHLZlDx+VkQKtRJNbM2hd2uYFKhiSQylVMmTUO6YnF6/pTVu4fS7k0EWH4Esu
         xqPg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8dT8uKsUS2+GCX9w9pE9yvNQuW5PXQ9VyX7MUXg0Bkn80ft854PcfhKa6rrpkVFkWrzCxtQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+JU5P7N4Xit2yKkUQYw7wLRe3In1UZg6/ubSo9DdzCxolOdWJ
	Ftd0WVXpl6eru+VoSyzJmZ7HIWj43TOrFh0rnCS/JucJsfGdz86ITifM
X-Google-Smtp-Source: AGHT+IHm9b8bMc8ITsd64qn5/Mn7pTasKAVtRFlT5EOlSPHemBWsmu9x+eiw8HsKslXDZOE3CoupmQ==
X-Received: by 2002:a05:7022:412:b0:11a:4ffb:9849 with SMTP id a92af1059eb24-11c9d811985mr23843260c88.21.1764419816980;
        Sat, 29 Nov 2025 04:36:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bDM21nhOza8i6A+kmAlQ8XF30rK5dCRjIQPZuy8Iqskg=="
Received: by 2002:a05:7022:52b:b0:11b:50a:6265 with SMTP id
 a92af1059eb24-11dc8e50fd9ls1878799c88.1.-pod-prod-06-us; Sat, 29 Nov 2025
 04:36:55 -0800 (PST)
X-Received: by 2002:a05:7022:90f:b0:119:e569:f60b with SMTP id a92af1059eb24-11c9d60e25emr23647580c88.4.1764419815458;
        Sat, 29 Nov 2025 04:36:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764419815; cv=none;
        d=google.com; s=arc-20240605;
        b=AsUbjsJ5pVTttLZshtFlPU4oihwLS78HrrYQS/al1FQD26MUcIZieJIE6yjumjo41n
         iI1CrqoaMGKD03OVkENhrMSv3jY4bux9+Ddp2m+UAVDGnP/9Lqafsg8af4ZQ2rKUdm6c
         qgsLo+LAq9+s1CIMNwtIfwXgN80Vx744UMG0g+0MU0HRFnN5IAi8dofbuZGw0QHpDqks
         oDgcu2T72D7mZQFeffTuEPcHhIcYw6ZS325xiHOHj3Dhm5/4DhFJcvUFmEv0GeMeCqu+
         PLcZuXVMx9o7TM1fyCB7uxCyXCQTnxbkkG3IOkCD9RU5U4XoEUCA+TnO07oRlA+8qkpd
         eeJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=Ot2Tg1xiAoyo3U7a294MLHTQILR+1RrXETLgGihLK+8=;
        fh=QbGfcW+uMvO2D8ckw7KMnx+kuqJ4FxjUDWxf8aqzPN0=;
        b=hkrZr2oSgXY43xVpSpMoPOUxemch/QkhRBEFOILmRsfeh2+DCBFXoR+I7KPw3nVKPV
         AEJ95mXtgiQhjNGHGMHT/pzyR6Df6BmrNk6km7VZzoV4Bk+TwE9yR/dTPuk/jIqs4StU
         q5zczX7Nh312be9jawF7g6BEuzGyagB7R139b4Y6E+t6CKPKD7iNgTr59F78No3254k1
         LX0TTpSKuKIEfNT8vZpsJvYAEMzA9ARAMZzCPVY+GptYcl5BdL6kINoxDYINbeOQfHeJ
         NTvawBkcqPgQp6zT5Sc9pXj5KY4GdUPE6+Yqr2nzcHidlPo6tf/NedXOCzCgiS7TrXme
         qBNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a92af1059eb24-11dcb042557si63864c88.7.2025.11.29.04.36.54
        for <kasan-dev@googlegroups.com>;
        Sat, 29 Nov 2025 04:36:54 -0800 (PST)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6D1E51063;
	Sat, 29 Nov 2025 04:36:46 -0800 (PST)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id AF5043F66E;
	Sat, 29 Nov 2025 04:36:51 -0800 (PST)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: catalin.marinas@arm.com,
	kevin.brodsky@arm.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	urezki@gmail.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	bpf@vger.kernel.org,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	stable@vger.kernel.org
Subject: [PATCH] kasan: hw_tags: fix a false positive case of vrealloc in alloced size
Date: Sat, 29 Nov 2025 12:36:47 +0000
Message-Id: <20251129123648.1785982-1-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

When a memory region is allocated with vmalloc() and later expanded with
vrealloc() =E2=80=94 while still within the originally allocated size =E2=
=80=94
KASAN may report a false positive because
it does not update the tags for the newly expanded portion of the memory.

A typical example of this pattern occurs in the BPF verifier,
and the following is a related false positive report:

[ 2206.486476] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[ 2206.486509] BUG: KASAN: invalid-access in __memcpy+0xc/0x30
[ 2206.486607] Write at addr f5ff800083765270 by task test_progs/205
[ 2206.486664] Pointer tag: [f5], memory tag: [fe]
[ 2206.486703]
[ 2206.486745] CPU: 4 UID: 0 PID: 205 Comm: test_progs Tainted: G          =
 OE       6.18.0-rc7+ #145 PREEMPT(full)
[ 2206.486861] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
[ 2206.486897] Hardware name:  , BIOS
[ 2206.486932] Call trace:
[ 2206.486961]  show_stack+0x24/0x40 (C)
[ 2206.487071]  __dump_stack+0x28/0x48
[ 2206.487182]  dump_stack_lvl+0x7c/0xb0
[ 2206.487293]  print_address_description+0x80/0x270
[ 2206.487403]  print_report+0x94/0x100
[ 2206.487505]  kasan_report+0xd8/0x150
[ 2206.487606]  __do_kernel_fault+0x64/0x268
[ 2206.487717]  do_bad_area+0x38/0x110
[ 2206.487820]  do_tag_check_fault+0x38/0x60
[ 2206.487936]  do_mem_abort+0x48/0xc8
[ 2206.488042]  el1_abort+0x40/0x70
[ 2206.488127]  el1h_64_sync_handler+0x50/0x118
[ 2206.488217]  el1h_64_sync+0xa4/0xa8
[ 2206.488303]  __memcpy+0xc/0x30 (P)
[ 2206.488412]  do_misc_fixups+0x4f8/0x1950
[ 2206.488528]  bpf_check+0x31c/0x840
[ 2206.488638]  bpf_prog_load+0x58c/0x658
[ 2206.488737]  __sys_bpf+0x364/0x488
[ 2206.488833]  __arm64_sys_bpf+0x30/0x58
[ 2206.488920]  invoke_syscall+0x68/0xe8
[ 2206.489033]  el0_svc_common+0xb0/0xf8
[ 2206.489143]  do_el0_svc+0x28/0x48
[ 2206.489249]  el0_svc+0x40/0xe8
[ 2206.489337]  el0t_64_sync_handler+0x84/0x140
[ 2206.489427]  el0t_64_sync+0x1bc/0x1c0

Here, 0xf5ff800083765000 is vmalloc()ed address for
env->insn_aux_data with the size of 0x268.
While this region is expanded size by 0x478 and initialise
increased region to apply patched instructions,
a false positive is triggered at the address 0xf5ff800083765270
because __kasan_unpoison_vmalloc() with KASAN_VMALLOC_PROT_NORMAL flag only
doesn't update the tag on increaed region.

To address this, introduces KASAN_VMALLOC_EXPAND flag which
is used to expand vmalloc()ed memory in range of real allocated size
to update tag for increased region.

Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS=E2=80=
=9D)
Cc: <stable@vger.kernel.org>
Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 include/linux/kasan.h |  1 +
 mm/kasan/hw_tags.c    | 11 +++++++++--
 mm/vmalloc.c          |  1 +
 3 files changed, 11 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..0608c5d4e6cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -28,6 +28,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 #define KASAN_VMALLOC_INIT		((__force kasan_vmalloc_flags_t)0x01u)
 #define KASAN_VMALLOC_VM_ALLOC		((__force kasan_vmalloc_flags_t)0x02u)
 #define KASAN_VMALLOC_PROT_NORMAL	((__force kasan_vmalloc_flags_t)0x04u)
+#define KASAN_VMALLOC_EXPAND		((__force kasan_vmalloc_flags_t)0x08u)

 #define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
 #define KASAN_VMALLOC_TLB_FLUSH  0x2 /* TLB flush */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..d768c7360093 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -347,7 +347,7 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 	 *
 	 * For non-VM_ALLOC allocations, page_alloc memory is tagged as usual.
 	 */
-	if (!(flags & KASAN_VMALLOC_VM_ALLOC)) {
+	if (!(flags & (KASAN_VMALLOC_VM_ALLOC | KASAN_VMALLOC_EXPAND))) {
 		WARN_ON(flags & KASAN_VMALLOC_INIT);
 		return (void *)start;
 	}
@@ -361,7 +361,14 @@ void *__kasan_unpoison_vmalloc(const void *start, unsi=
gned long size,
 		return (void *)start;
 	}

-	tag =3D kasan_random_tag();
+	if (flags & KASAN_VMALLOC_EXPAND) {
+		size =3D round_up(size + ((unsigned long)start & KASAN_GRANULE_MASK),
+				KASAN_GRANULE_SIZE);
+		start =3D PTR_ALIGN_DOWN(start, KASAN_GRANULE_SIZE);
+		tag =3D get_tag(start);
+	} else
+		tag =3D kasan_random_tag();
+
 	start =3D set_tag(start, tag);

 	/* Unpoison and initialize memory up to size. */
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..6bfbf26fea3b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4176,6 +4176,7 @@ void *vrealloc_node_align_noprof(const void *p, size_=
t size, unsigned long align
 	 */
 	if (size <=3D alloced_size) {
 		kasan_unpoison_vmalloc(p + old_size, size - old_size,
+				       KASAN_VMALLOC_EXPAND |
 				       KASAN_VMALLOC_PROT_NORMAL);
 		/*
 		 * No need to zero memory here, as unused memory will have
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251129123648.1785982-1-yeoreum.yun%40arm.com.
