Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBX6M63GAMGQEYXTLFNQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SO/1J2KmnWmgQwQAu9opvQ
	(envelope-from <kasan-dev+bncBDS6NZUJ6ILRBX6M63GAMGQEYXTLFNQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 14:23:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2320D187981
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 14:23:45 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-358f8b01604sf588356a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 05:23:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771939424; cv=pass;
        d=google.com; s=arc-20240605;
        b=MZe6H7m3LsUEoX4KoND2FBpHMXZIjcQV3xUMuNlKo7tbYX9ozfscNSEghlY+lIbmVD
         q/50iZ3NeadSZthBMJCws5gqFcwjNt1TuYgjopGnCKr6r4503n/0Ii1F3zaK0LeSLwxY
         VC/eINl4649zsv28JRDKesLwYJ32/9Uio90Ac67XLCP1Gz2B2ZTkHKRo0O5xfQHg91WS
         y1yfqBrWFCwfDzGoJCJnXpAfnIVbU19yeZh3o+4NlxdLbPX7A0LHQs4uFFYB5ec/ovMu
         LFdHSSr3kMpqGbuRjgWWApfD8P291bIUBYs8c02Q9peOMVqTGQ81AyDBg1qEBWdWgkyx
         m3Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=RjHqtOB/rBdO4jyHTAae5Utv9J+xnCdW4hg17GpkrYg=;
        fh=3ScocptXapjrjADpP34meX83tK6AtYn645YtVFUA2qg=;
        b=KGDSlcY40F+bkm5PQUZQNMbGTnjTWytT6m7keViPQHApxlEZ6DcgtBXOKnzZjRJt54
         L6+k1GNCrSuLKcYxr/eeIPDasOM3QC++fauHSPmNzM2mACLfTqwqhpysWys+xsC8dRcL
         1QkQ7w+Z00wz2qri/dCln3/sTVrr0Dge9mSOws8NyZOMywZVVHp1Ulq3xb2HDqHTbF6V
         c8s35YeVbbNEuaCz/O2bEkvFnrWwzFzZQ/Hax5uY6aSveuycqo5uUS0Z8cv5xuQM9xk8
         n00Y0rEPlu3buAB4aWPaFBC0Al8OifYetKGxl5rz4+uAGIzL0eLSlVTbPzJyKLItI4/Z
         r21Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NiH46ppu;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771939424; x=1772544224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RjHqtOB/rBdO4jyHTAae5Utv9J+xnCdW4hg17GpkrYg=;
        b=OA0dUAaD8VPCsMagbitjaWdIMeseZbgm7NAt76AoK3/o2Cwb+KDbhZ41b5oWMI6zQR
         4+fLlQcS1suK3giRAu8HhnaB0CtmGnPNp7/UwrgUrkbrh4bKTbgkOSyMK/PNP9Q4Ceny
         rKFv73c/64h6heV2UH3AYSGB+ML06dGFP/7xF1j4HoU3aMxHKcmNsZEbdzutmnoMquqy
         RYmTIMzD55VayEBxCYKzJ4Szq9fSBgAEUuK6u0M7IlpUcBzDUHFZU7q4ziM+X2u5KDkx
         CsaSwM+RQllmepZWhgq/Ivk6G/4LUnLRwGsE6Tx+RM6CT77DFMAmbUzgQ0WIaS3pL6L9
         bj/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1771939424; x=1772544224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RjHqtOB/rBdO4jyHTAae5Utv9J+xnCdW4hg17GpkrYg=;
        b=k6ze+y6HDlUtnofDOmnihci5U47KmhDVNG2zTg7VHmAY2/S8YBoWncA36btxn7qQ8K
         XFDMnqRnEaVOs5XeqLcfBx59cUaGM84e2rd2lSjxcXo0O3Ar2wvf+711b5377hE3dXHy
         IfTu9VllMbBzgLcecErru7FqfTInO9dTf8QGIFCANx/xdSUm332MErYfWAvsO2073WqF
         +ot7sedWtjSAcPgR4gyPg9NMAJZjNZ6TJeNgZG/pvpHpkxUHnNEQEHRkbpspsMgLT44h
         2G9aq7XM5BhXu1BJfes3/OnFztx9NkR+ZkImOesKbzFAAbpvpqHUpUnWNE5uiCB91uO/
         QCqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771939424; x=1772544224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RjHqtOB/rBdO4jyHTAae5Utv9J+xnCdW4hg17GpkrYg=;
        b=SnTUOOV9oWpSIKeyNPbmGO0ihh//2lE7/emZdVWpb9DZRMmvxoinOIiMX0HvuMn9fV
         JWfdbrbVF4NZS9IRt5HPM+97efTYUSJoEtAbS4MxLQEl8+BWjeXpwf9ojSE5woUmtbqC
         o5eV/kPwYofBLJP7Of5FYKVK6mC9Ov92WjkbaVSFvJIFr89nEeZ+j9VT3+z+oyE6Bxc2
         U1rhyVsHHuVLgL/aN4MsEmiEyTKCVWuAcwNxuaZrwzX+8Y7wcFj7U1WqiL/dvpocQ/IU
         opLm4R0zKuj1gRG0YAISY/yhL4c8giJ0t31NTwJ4z+IfRrCQytZzCPjEjdng2mvvJWDm
         vm1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWniiLx/pccwbTUT5snrvlSDYGVEitjjeO+g7Qlkirlt3V1ECs9IFUIeJaRhFu1XQDZYLFtqQ==@lfdr.de
X-Gm-Message-State: AOJu0YzWgtwg307NSFCDLsdkY/umKehIfIq7imXv93SldUmYyLOl+Y8N
	KOqoytuJQj5Mto46U48y6S4Npro8WwLvmDjGYbJiQvvhESoBQhpVLrDW
X-Received: by 2002:a17:90b:2cc5:b0:356:3cfd:3ee1 with SMTP id 98e67ed59e1d1-358ae8c26e8mr10853164a91.23.1771939423653;
        Tue, 24 Feb 2026 05:23:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H7eS3p3vqFsybyeenwDs5XoNSqd9+AQZ7Afwb+mEWs8g=="
Received: by 2002:a17:90a:ea8e:b0:341:765d:bfe1 with SMTP id
 98e67ed59e1d1-35693b3a4cbls11413615a91.1.-pod-prod-06-us; Tue, 24 Feb 2026
 05:23:42 -0800 (PST)
X-Received: by 2002:a17:90b:3881:b0:354:c629:efaf with SMTP id 98e67ed59e1d1-358ae8dc667mr9592333a91.35.1771939422062;
        Tue, 24 Feb 2026 05:23:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771939422; cv=none;
        d=google.com; s=arc-20240605;
        b=EBz+RK3ZcIZ3By/JcnBW0bideAlcLPknIdnAwySHHlzsnHkvL0k2psva27ioUCpfFk
         nHA/GLcRLwdYSM8isT6kQyYadG4wTnPgvsGPbSXhtNZaEvyX5N96vSmKs7mO0qwgzKmn
         JjrmsTZd7dzppr4LhDdKoDUvDNs2jfYcrtxrsUzARQ6Tgvt9Zlhgl6lijn09gUKlPtwb
         q2fF+wgrRhGK8r55+yL2gAQ42b5VDxdSH+IH8T8TfGteuHIh3iqyfqxAsh6yG3V4hi3v
         X35UKs+4dciG7ez+yS6kbZdnTss9qQ//HZLE8A4rK/8cTjLzg3x//T21mXgEX0EwgBUk
         ZypQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=h/vTWhMTFB0Dk21wQu2UrghHtfm/CBbtvTcuyWrVL08=;
        fh=tVvzbyjZWgB1230nhY3XYrHUpCCgWuSn8fzJrv5o1S8=;
        b=jcqwW8a6dJQ+byOrbHjP0ABPbuJGmaWiQJNf3jTKw9V/zkOEEm6j8CXexsMW5+MVb/
         pnAS2BLHxBBc0I0QSibyDw0Umbm1uOpvks4/VfeqXRDqoUCLW+5S02nUDNzSNSn+Bn43
         PQcUk6y23wJadbrkMHDgCPLAsevOC819p6CmoXK4KGMA/U2keqQUNZsMwSbmPxWEntWq
         XxTgguYhsSpuQNeUqEOlqEYAISLYrd7Q3umpuEXnQ4pW+0i0CPAtW/0xhnNUq+TcvQ4f
         iRybHRHNjUwb6gNknvL6gorbQIKJDqZQg1ECJtCeomQmg3X/j1jL+9wrhviEtjPW+hfQ
         vk+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NiH46ppu;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-358af6fa903si301762a91.1.2026.02.24.05.23.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Feb 2026 05:23:42 -0800 (PST)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-c70bfef17a4so1610755a12.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Feb 2026 05:23:42 -0800 (PST)
X-Gm-Gg: ATEYQzx42LcnNFyYszJrjTh4USHagj/EX20AkkoNzvBfd7kRPu1i0hnjHweICX/xLDx
	RokaPH22VFAO5T0lAerRvXdc9+5tcQguLElPwYfn/9bv80lhcq6WuBjwTpn1YkvjwW6fn0XAhVe
	slCLjY3MMtdXwzk0vbxdarXlWKqWoaQ6iqkJBmphALr6kFm8/zFp2I6LWf2xgfEayGlC3ljmDHf
	r7/LaktG8IF0MF46Of6FdwOnMCIqeBCfmVmFKGyLDiUoeauhdgq/PtxSWxnEdtOH5IFyW4mWw+V
	2hoRg2t91HdgkIjuNA2KJQramwW0qyMpd2QQDP4PD2T8Ip5TFZypvFnEJX1pI9v9J0v8i7/b3dD
	DAghVu2pBk+1tngQxCO7kdqpaApdF9Jr/x31+2blpqArNEP+3HEXb/5z7oWYdbyyL820Y6wnSyi
	GmNEMs8LwpYImfSyBQhg==
X-Received: by 2002:a17:902:e787:b0:2a9:3396:738 with SMTP id d9443c01a7336-2ad74547d8dmr105272735ad.44.1771939420973;
        Tue, 24 Feb 2026 05:23:40 -0800 (PST)
Received: from dw-tp ([203.81.243.253])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2ad7500e1cbsm96620195ad.50.2026.02.24.05.23.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 05:23:40 -0800 (PST)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linuxppc-dev@lists.ozlabs.org,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	stable@vger.kernel.org,
	Venkat Rao Bagalkote <venkat88@linux.ibm.com>
Subject: [PATCH v2] mm/kasan: Fix double free for kasan pXds
Date: Tue, 24 Feb 2026 18:53:16 +0530
Message-ID: <2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.53.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NiH46ppu;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::529
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,arm.com,lists.ozlabs.org,vger.kernel.org,linux.ibm.com];
	TAGGED_FROM(0.00)[bncBDS6NZUJ6ILRBX6M63GAMGQEYXTLFNQ];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FREEMAIL_FROM(0.00)[gmail.com];
	NEURAL_HAM(-0.00)[-0.996];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[riteshlist@gmail.com,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 2320D187981
X-Rspamd-Action: no action

kasan_free_pxd() assumes the page table is always struct page aligned.
But that's not always the case for all architectures. E.g. In case of
powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let's
just directly pass the start of the pxd table which is passed as the 1st
argument.

This fixes the below double free kasan issue seen with PMEM:

radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB pages
==================================================================
BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
Free of addr c0000003c38e0000 by task ndctl/2164

CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted 6.19.0-rc1-00048-gea1013c15392 #157 VOLUNTARY
Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006 of:IBM,FW1060.00 (NH1060_012) hv:phyp pSeries
Call Trace:
 dump_stack_lvl+0x88/0xc4 (unreliable)
 print_report+0x214/0x63c
 kasan_report_invalid_free+0xe4/0x110
 check_slab_allocation+0x100/0x150
 kmem_cache_free+0x128/0x6e0
 kasan_remove_zero_shadow+0x9c4/0xa20
 memunmap_pages+0x2b8/0x5c0
 devm_action_release+0x54/0x70
 release_nodes+0xc8/0x1a0
 devres_release_all+0xe0/0x140
 device_unbind_cleanup+0x30/0x120
 device_release_driver_internal+0x3e4/0x450
 unbind_store+0xfc/0x110
 drv_attr_store+0x78/0xb0
 sysfs_kf_write+0x114/0x140
 kernfs_fop_write_iter+0x264/0x3f0
 vfs_write+0x3bc/0x7d0
 ksys_write+0xa4/0x190
 system_call_exception+0x190/0x480
 system_call_vectored_common+0x15c/0x2ec
---- interrupt: 3000 at 0x7fff93b3d3f4
NIP:  00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000
REGS: c0000003f1b07e80 TRAP: 3000   Not tainted  (6.19.0-rc1-00048-gea1013c15392)
MSR:  800000000280f033 <SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE>  CR: 48888208  XER: 00000000
<...>
NIP [00007fff93b3d3f4] 0x7fff93b3d3f4
LR [00007fff93b3d3f4] 0x7fff93b3d3f4
---- interrupt: 3000

 The buggy address belongs to the object at c0000003c38e0000
  which belongs to the cache pgtable-2^9 of size 4096
 The buggy address is located 0 bytes inside of
  4096-byte region [c0000003c38e0000, c0000003c38e1000)

 The buggy address belongs to the physical page:
 page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x3c38c
 head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
 memcg:c0000003bfd63e01
 flags: 0x63ffff800000040(head|node=6|zone=0|lastcpupid=0x7ffff)
 page_type: f5(slab)
 raw: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
 raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
 head: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
 head: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
 head: 063ffff800000002 c00c000000f0e301 00000000ffffffff 00000000ffffffff
 head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000000000004
 page dumped because: kasan: bad access detected

[  138.953636] [   T2164] Memory state around the buggy address:
[  138.953643] [   T2164]  c0000003c38dff00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953652] [   T2164]  c0000003c38dff80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953661] [   T2164] >c0000003c38e0000: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953669] [   T2164]                    ^
[  138.953675] [   T2164]  c0000003c38e0080: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953684] [   T2164]  c0000003c38e0100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  138.953692] [   T2164] ==================================================================
[  138.953701] [   T2164] Disabling lock debugging due to kernel taint

Fixes: 0207df4fa1a8 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
Cc: stable@vger.kernel.org
Reported-by: Venkat Rao Bagalkote <venkat88@linux.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---

v1 -> v2:
1. cc'd linux-mm
2. Added tags (Fixes, CC, Reported).

 mm/kasan/init.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index f084e7a5df1e..9c880f607c6a 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -292,7 +292,7 @@ static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 			return;
 	}

-	pte_free_kernel(&init_mm, (pte_t *)page_to_virt(pmd_page(*pmd)));
+	pte_free_kernel(&init_mm, pte_start);
 	pmd_clear(pmd);
 }

@@ -307,7 +307,7 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
 			return;
 	}

-	pmd_free(&init_mm, (pmd_t *)page_to_virt(pud_page(*pud)));
+	pmd_free(&init_mm, pmd_start);
 	pud_clear(pud);
 }

@@ -322,7 +322,7 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
 			return;
 	}

-	pud_free(&init_mm, (pud_t *)page_to_virt(p4d_page(*p4d)));
+	pud_free(&init_mm, pud_start);
 	p4d_clear(p4d);
 }

@@ -337,7 +337,7 @@ static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
 			return;
 	}

-	p4d_free(&init_mm, (p4d_t *)page_to_virt(pgd_page(*pgd)));
+	p4d_free(&init_mm, p4d_start);
 	pgd_clear(pgd);
 }

--
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2f9135c7866c6e0d06e960993b8a5674a9ebc7ec.1771938394.git.ritesh.list%40gmail.com.
