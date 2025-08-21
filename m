Return-Path: <kasan-dev+bncBCQPF57GUQHBBC5DT3CQMGQE5XBRA7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id DA288B30872
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:37:16 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70a9289280dsf31190236d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:37:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755812236; cv=pass;
        d=google.com; s=arc-20240605;
        b=WMtYEohn8BZhy6CQcrdd+nRT+4OTOdP3wtSeZeq9Q3dNASDxU4sTk45/sdkwhxZ9ws
         c1lGSefcFKqv9wro65BIZebFPz4/Kkm/pWni+N2LPkpkWlv7oSQ4icPwFDJJ8tsC0qYS
         KDr03kO8DT3JJoLjP5/XDOYS7nfb1VoaTUJ6G5/6LbxUVTTrXcRRdQASHjm7Y/VYhpWn
         QNh5Qj42lsludFJ5jg+sK+mspJ62LcO2DsnJib1oGftblf/3tfCGpQH/Ip+EyQi3p89c
         Sx9y3KN2lPkQIz8690yuS7St/4vILjoVw2AAM9b0RbRzBnrN4vB0blxplUN9fYSuC36s
         9Yqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=Bar5KVyrw32pmSr0f57AvHy4jbbXwSx512X8CwmOXfA=;
        fh=DLEkHvkNGJ7CfYKbEFD/ckdBfosr4Jz0xRpsvYfo+BI=;
        b=M7YZVv6Q5pbhayLK4ZYEdlc1/aCKIk2qnCDDy0PjtiGYOHf7tE39XhSAq0umR9HVBB
         Z3U89Rvnq/IsZ3UNd4scivT3xBchFVE7wJjKJ8nE77nTwLmni58c8q7ujXc2N+vZO21H
         DNxFNKRpuKE8HFnzkNjkTT7RPK06T1smFsAaaiyGBaTHxSVS3vIFprS0f7QlsptPK5qm
         6ImEeByA7QEaP4hSR696Jg+nf89XHWjoMEEr2cloHEbm6SQ4M7QsKGjLn/sT9Oi+gHKK
         jK1d3MxsAnJHiG1jqYsViW2APpMuI0Klfziwg6fg0dBpdH3cjvQD47H3gDwL8Lq7+cR+
         jcfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3izgnaakbajyiopa0bb4h0ff83.6ee6b4ki4h2edj4dj.2ec@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) smtp.mailfrom=3iZGnaAkbAJYIOPA0BB4H0FF83.6EE6B4KI4H2EDJ4DJ.2EC@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755812236; x=1756417036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Bar5KVyrw32pmSr0f57AvHy4jbbXwSx512X8CwmOXfA=;
        b=DHsBsv+hXwTfrdFpuLlFCTofk53fIPmvPEBvRSLy/uo+5KObt/oArLd9HwDzcjFIrb
         KXG6/w4M4sXVISy4lrpx6QdyinRrZaTpXXVjmOjn1lkH6YNCX+6S7gTmfk8gLlVagyNB
         czfrLuExDtFGlnalGFpWsCKoS5iCfs7KvUxaa0SLBc/rT1RAAtsomh6LN/PHD6swTwA6
         WxcB+mBwn8pKmkAgFI/fpzlczu0sQwWdL2PvFAcbQMNdaSrXya7LL1AYgFUUyrBFukuX
         xzeQxs99SWxEmxPNZ3CXZbPN83QQb5VDztkKvlbycXwJvizU5FfdU/Nwbk7IULt4o3aB
         H+Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755812236; x=1756417036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bar5KVyrw32pmSr0f57AvHy4jbbXwSx512X8CwmOXfA=;
        b=b0TdN9hmEfkbgKN+JRjdP0LlUhWoHmBY24FDpjiijt6gHA56+MHd0UnsQBbgZkxfYP
         qZ810nqXit8vYqu3qAyP64sZD44jMMhIv6zYG6WqbISL6hhF2tlEohbLN/EzZsR8rqe9
         i5A/f6j7RN/DLUMVZbDCaSSB6JA1spBaHtk8V61EStoZMwGLnEKOZGqPKAEMPX/jvfHn
         4OczNWQ5U1Xxwe/R2TKcAb4fz9xiRXCsluzmeoc81PB0p+/Y+i/LlTSPlZ4Fb/mlS9Xp
         nhEJW54AWauFtQwamjtQQ0FRx566xOBydIgFXPUGxfYlneJ69ettrFPFWsuFsEjMZQSM
         5m+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfGQE36S5tvni3zNOq7apb94YRY0AXRPPsAd0+eBv3J1IZgqyIB+OsmGSHzQ4kBpLLc6aUUA==@lfdr.de
X-Gm-Message-State: AOJu0YxWTBKhSpkKMuHol1Rwup8+KHmeXkdnxuvo3ZXKvOKPb277W2uR
	AbnNnD7gJOMefsrm3YI+U8BqAiOsf4B1QcIAesVdy+y1mUbrGoPTrEn7
X-Google-Smtp-Source: AGHT+IHP1iGitIO5uAPG1ZkCJshAQYIYys1bs0kzsprfBKP1FYlDZrIHcVe/WXlmjONFDYU6so9ivA==
X-Received: by 2002:ad4:574a:0:b0:709:e3ae:d598 with SMTP id 6a1803df08f44-70d970c41ffmr13687956d6.14.1755812235598;
        Thu, 21 Aug 2025 14:37:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeWLrepFwpAW3N17HqZRrsQ1gBxe0ywQvchNwFgCisF4Q==
Received: by 2002:ad4:5c4a:0:b0:707:56ac:be47 with SMTP id 6a1803df08f44-70d859fbedals19761236d6.0.-pod-prod-01-us;
 Thu, 21 Aug 2025 14:37:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr8ghpdQbZKwwNoUc5Kc5qsZLr4uckbtWZiQa2RrR6fkMmZ2ph8Z11o6jaMBY3uK5TN3+VEnOjh1Q=@googlegroups.com
X-Received: by 2002:a05:6102:5492:b0:4f9:6a91:133a with SMTP id ada2fe7eead31-51d0f2f9762mr252337137.27.1755812234500;
        Thu, 21 Aug 2025 14:37:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755812234; cv=none;
        d=google.com; s=arc-20240605;
        b=IkVAzNsl74tM2zDQ9WYC8xaVDAKnUEipCxuC2E5xI561xIEEWBIzPY2TcyFw++VnN7
         RvWBiiHxO8H8mnB64CEI2EQKdKn2XUWXzNK4joeJ5stDgS3/tzUO2fgtreaBUod3orRh
         XKHnSeJKKMrZ53+707sJKH2XXEbol1oVDS+V1ZocfeTjky6zVYnI9PdwqiTvW1tvUA7h
         61sdx8E7zbkNve2iqXfq3xmsbtwfzGvRm9P1ENWHPr28/3E0A0pgmLXXaMb3kKeB2RR1
         tJBsnlGTWLxmf/aFiD2Mu2lojigQIFxUDuiTElHzgJDjkujDiAnWn9WEfTW2lwuzcQk0
         E2Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=Q4cr6QMqKu3ZXE5LbmZFl5rCj+PzGQQulyaw1Vp4aNc=;
        fh=0PrhIki803kDSGvpHW3rnEmz0tS1Kg5To1wGRJRKFM4=;
        b=HHAzmvo7O0cTmT2kCAGS4dwDORfcybSnht/DfE4CYivWrAFdccacoOZL4HWBGc6kD3
         R1rmglwMEAv8E+7+9i1mSbJ1TaIJQtSOlqoWRkYYSF6TcuwIz6zyQtLM5/Hkl+1HTZSZ
         jIAhdat3Uydd3a1BNm4ehtl3uuq4LiTuiUoUx3/ooEXVpmNRtKjlH7DiWlC5BPvk+QMv
         ElVG96D5wgNPEsUsM5JKH3C+zr3RZzFrLgEVEn4902AirVT5W7qTA72Rksfgjw0LRFfl
         FNtbO11ac871xPk51gVEA/eCtyw87GuiuOHpltKdttNeCFFRHOeISNKzD5j56CdRvbAP
         FibA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3izgnaakbajyiopa0bb4h0ff83.6ee6b4ki4h2edj4dj.2ec@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) smtp.mailfrom=3iZGnaAkbAJYIOPA0BB4H0FF83.6EE6B4KI4H2EDJ4DJ.2EC@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f69.google.com (mail-io1-f69.google.com. [209.85.166.69])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5127d4dbe17si623396137.1.2025.08.21.14.37.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 14:37:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3izgnaakbajyiopa0bb4h0ff83.6ee6b4ki4h2edj4dj.2ec@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.69 as permitted sender) client-ip=209.85.166.69;
Received: by mail-io1-f69.google.com with SMTP id ca18e2360f4ac-88432cb438cso325404539f.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 14:37:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW8MX6HkUNg1ZEhXNbkOlvKkmEVhlNcznnDqKLLVeR0T/T28DieORwH/JOWfTngBwIDRk9RyIm4F9w=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:19c6:b0:3e6:6c55:643 with SMTP id
 e9e14a558f8ab-3e9201f3d92mr16380665ab.7.1755812233632; Thu, 21 Aug 2025
 14:37:13 -0700 (PDT)
Date: Thu, 21 Aug 2025 14:37:13 -0700
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <68a79189.050a0220.cb3d1.0004.GAE@google.com>
Subject: [syzbot ci] Re: mm: remove nth_page()
From: syzbot ci <syzbot+ci0b43493baa45553d@syzkaller.appspotmail.com>
To: agordeev@linux.ibm.com, airlied@gmail.com, akpm@linux-foundation.org, 
	alex.williamson@redhat.com, alex@ghiti.fr, andreas@gaisler.com, 
	aou@eecs.berkeley.edu, axboe@kernel.dk, borntraeger@linux.ibm.com, 
	bp@alien8.de, brett.creeley@amd.com, cassel@kernel.org, 
	catalin.marinas@arm.com, chenhuacai@kernel.org, christophe.leroy@csgroup.eu, 
	cl@gentwo.org, dave.hansen@linux.intel.com, davem@davemloft.net, 
	david@redhat.com, dennis@kernel.org, dgilbert@interlog.com, 
	dlemoal@kernel.org, dri-devel@lists.freedesktop.org, dvyukov@google.com, 
	elver@google.com, glider@google.com, gor@linux.ibm.com, hannes@cmpxchg.org, 
	hca@linux.ibm.com, herbert@gondor.apana.org.au, 
	intel-gfx@lists.freedesktop.org, io-uring@vger.kernel.org, 
	iommu@lists.linux.dev, jackmanb@google.com, 
	james.bottomley@hansenpartnership.com, jani.nikula@linux.intel.com, 
	jason@zx2c4.com, jesper.nilsson@axis.com, jgg@nvidia.com, jgg@ziepe.ca, 
	jhubbard@nvidia.com, joonas.lahtinen@linux.intel.com, 
	kasan-dev@googlegroups.com, kernel@xen0n.name, kevin.tian@intel.com, 
	kvm@vger.kernel.org, lars.persson@axis.com, liam.howlett@oracle.com, 
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-scsi@vger.kernel.org, lorenzo.stoakes@oracle.com, 
	m.szyprowski@samsung.com, maddy@linux.ibm.com, martin.petersen@oracle.com, 
	maximlevitsky@gmail.com, mhocko@suse.com, mingo@redhat.com, 
	mpe@ellerman.id.au, muchun.song@linux.dev, netdev@vger.kernel.org, 
	npiggin@gmail.com, oakad@yahoo.com, osalvador@suse.de, palmer@dabbelt.com, 
	paul.walmsley@sifive.com, peterx@redhat.com, robin.murphy@arm.com, 
	rodrigo.vivi@intel.com, rppt@kernel.org, shameerali.kolothum.thodi@huawei.com, 
	shuah@kernel.org, simona@ffwll.ch, surenb@google.com, svens@linux.ibm.com, 
	tglx@linutronix.de, tj@kernel.org, torvalds@linux-foundation.org, 
	tsbogend@alpha.franken.de, tursulin@ursulin.net, ulf.hansson@linaro.org, 
	vbabka@suse.cz, virtualization@lists.linux.dev, will@kernel.org, 
	wireguard@lists.zx2c4.com, x86@kernel.org, ziy@nvidia.com
Cc: syzbot@lists.linux.dev, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3izgnaakbajyiopa0bb4h0ff83.6ee6b4ki4h2edj4dj.2ec@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.69 as permitted sender) smtp.mailfrom=3iZGnaAkbAJYIOPA0BB4H0FF83.6EE6B4KI4H2EDJ4DJ.2EC@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

syzbot ci has tested the following series

[v1] mm: remove nth_page()
https://lore.kernel.org/all/20250821200701.1329277-1-david@redhat.com
* [PATCH RFC 01/35] mm: stop making SPARSEMEM_VMEMMAP user-selectable
* [PATCH RFC 02/35] arm64: Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
* [PATCH RFC 03/35] s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
* [PATCH RFC 04/35] x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
* [PATCH RFC 05/35] wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
* [PATCH RFC 06/35] mm/page_alloc: reject unreasonable folio/compound page sizes in alloc_contig_range_noprof()
* [PATCH RFC 07/35] mm/memremap: reject unreasonable folio/compound page sizes in memremap_pages()
* [PATCH RFC 08/35] mm/hugetlb: check for unreasonable folio sizes when registering hstate
* [PATCH RFC 09/35] mm/mm_init: make memmap_init_compound() look more like prep_compound_page()
* [PATCH RFC 10/35] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
* [PATCH RFC 11/35] mm: sanity-check maximum folio size in folio_set_order()
* [PATCH RFC 12/35] mm: limit folio/compound page sizes in problematic kernel configs
* [PATCH RFC 13/35] mm: simplify folio_page() and folio_page_idx()
* [PATCH RFC 14/35] mm/mm/percpu-km: drop nth_page() usage within single allocation
* [PATCH RFC 15/35] fs: hugetlbfs: remove nth_page() usage within folio in adjust_range_hwpoison()
* [PATCH RFC 16/35] mm/pagewalk: drop nth_page() usage within folio in folio_walk_start()
* [PATCH RFC 17/35] mm/gup: drop nth_page() usage within folio when recording subpages
* [PATCH RFC 18/35] io_uring/zcrx: remove "struct io_copy_cache" and one nth_page() usage
* [PATCH RFC 19/35] io_uring/zcrx: remove nth_page() usage within folio
* [PATCH RFC 20/35] mips: mm: convert __flush_dcache_pages() to __flush_dcache_folio_pages()
* [PATCH RFC 21/35] mm/cma: refuse handing out non-contiguous page ranges
* [PATCH RFC 22/35] dma-remap: drop nth_page() in dma_common_contiguous_remap()
* [PATCH RFC 23/35] scatterlist: disallow non-contigous page ranges in a single SG entry
* [PATCH RFC 24/35] ata: libata-eh: drop nth_page() usage within SG entry
* [PATCH RFC 25/35] drm/i915/gem: drop nth_page() usage within SG entry
* [PATCH RFC 26/35] mspro_block: drop nth_page() usage within SG entry
* [PATCH RFC 27/35] memstick: drop nth_page() usage within SG entry
* [PATCH RFC 28/35] mmc: drop nth_page() usage within SG entry
* [PATCH RFC 29/35] scsi: core: drop nth_page() usage within SG entry
* [PATCH RFC 30/35] vfio/pci: drop nth_page() usage within SG entry
* [PATCH RFC 31/35] crypto: remove nth_page() usage within SG entry
* [PATCH RFC 32/35] mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
* [PATCH RFC 33/35] kfence: drop nth_page() usage
* [PATCH RFC 34/35] block: update comment of "struct bio_vec" regarding nth_page()
* [PATCH RFC 35/35] mm: remove nth_page()

and found the following issue:
general protection fault in kfence_guarded_alloc

Full report is available here:
https://ci.syzbot.org/series/f6f0aea1-9616-4675-8c80-f9b59ba3211c

***

general protection fault in kfence_guarded_alloc

tree:      net-next
URL:       https://kernel.googlesource.com/pub/scm/linux/kernel/git/netdev/net-next.git
base:      da114122b83149d1f1db0586b1d67947b651aa20
arch:      amd64
compiler:  Debian clang version 20.1.7 (++20250616065708+6146a88f6049-1~exp1~20250616065826.132), Debian LLD 20.1.7
config:    https://ci.syzbot.org/builds/705b7862-eb10-40bd-a4cf-4820b4912466/config

smpboot: CPU0: Intel(R) Xeon(R) CPU @ 2.80GHz (family: 0x6, model: 0x55, stepping: 0x7)
Oops: general protection fault, probably for non-canonical address 0xdffffc0000000001: 0000 [#1] SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f]
CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted syzkaller #0 PREEMPT(full) 
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
RIP: 0010:kfence_guarded_alloc+0x643/0xc70
Code: 41 c1 e5 18 bf 00 00 00 f5 44 89 ee e8 a6 67 9c ff 45 31 f6 41 81 fd 00 00 00 f5 4c 0f 44 f3 49 8d 7e 08 48 89 f8 48 c1 e8 03 <42> 80 3c 20 00 74 05 e8 f1 cb ff ff 4c 8b 6c 24 18 4d 89 6e 08 49
RSP: 0000:ffffc90000047740 EFLAGS: 00010202
RAX: 0000000000000001 RBX: ffffea0004d90080 RCX: 0000000000000000
RDX: ffff88801c2e8000 RSI: 00000000ff000000 RDI: 0000000000000008
RBP: ffffc90000047850 R08: ffffffff99b2201b R09: 1ffffffff3364403
R10: dffffc0000000000 R11: fffffbfff3364404 R12: dffffc0000000000
R13: 00000000ff000000 R14: 0000000000000000 R15: ffff88813fec7068
FS:  0000000000000000(0000) GS:ffff8880b861c000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffff88813ffff000 CR3: 000000000df36000 CR4: 0000000000350ef0
Call Trace:
 <TASK>
 __kfence_alloc+0x385/0x3b0
 __kmalloc_noprof+0x440/0x4f0
 __alloc_workqueue+0x103/0x1b70
 alloc_workqueue_noprof+0xd4/0x210
 init_mm_internals+0x17/0x140
 kernel_init_freeable+0x307/0x4b0
 kernel_init+0x1d/0x1d0
 ret_from_fork+0x3f9/0x770
 ret_from_fork_asm+0x1a/0x30
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:kfence_guarded_alloc+0x643/0xc70
Code: 41 c1 e5 18 bf 00 00 00 f5 44 89 ee e8 a6 67 9c ff 45 31 f6 41 81 fd 00 00 00 f5 4c 0f 44 f3 49 8d 7e 08 48 89 f8 48 c1 e8 03 <42> 80 3c 20 00 74 05 e8 f1 cb ff ff 4c 8b 6c 24 18 4d 89 6e 08 49
RSP: 0000:ffffc90000047740 EFLAGS: 00010202
RAX: 0000000000000001 RBX: ffffea0004d90080 RCX: 0000000000000000
RDX: ffff88801c2e8000 RSI: 00000000ff000000 RDI: 0000000000000008
RBP: ffffc90000047850 R08: ffffffff99b2201b R09: 1ffffffff3364403
R10: dffffc0000000000 R11: fffffbfff3364404 R12: dffffc0000000000
R13: 00000000ff000000 R14: 0000000000000000 R15: ffff88813fec7068
FS:  0000000000000000(0000) GS:ffff8880b861c000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: ffff88813ffff000 CR3: 000000000df36000 CR4: 0000000000350ef0


***

If these findings have caused you to resend the series or submit a
separate fix, please add the following tag to your commit message:
  Tested-by: syzbot@syzkaller.appspotmail.com

---
This report is generated by a bot. It may contain errors.
syzbot ci engineers can be reached at syzkaller@googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68a79189.050a0220.cb3d1.0004.GAE%40google.com.
