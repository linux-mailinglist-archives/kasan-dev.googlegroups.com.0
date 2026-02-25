Return-Path: <kasan-dev+bncBCKPFB7SXUERB5W67LGAMGQEBANMLHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cMrSGnivnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERB5W67LGAMGQEBANMLHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:14:48 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 057CA193F9E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:14:47 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-899b88b0ec7sf2547766d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:14:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007286; cv=pass;
        d=google.com; s=arc-20240605;
        b=RyQtfosFgaMYA+3HV0JnY2OzR5KpzelJcqydFLukUq/5O0+g2geZADBnvm2h1enx5Q
         15qq4r+X0gbtOqJwiUP2WAuMRvFAme9+OYVXHdJCLA8jwUrjCg6/60n6jY2kguS6D5af
         NzxCIORwn3sEvlUk5LWTEHyLjoZhwtd3fdQr3HBe3mEyMWzN42MmujPXaIr+mf3OlSBj
         faW0VPsIQRFaU26Uvew3BXWns4+CZktYRxhY5MelLBssR9FLXw/nhQEkpO28gRYk1VQz
         /+Zv4mhsr4swW1r3mUHjDKwwMVqhafLjGUvnP63lpsaLOu3ovc20mep1ObttKOJy5L0U
         BYEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=UqXeFrsF25k/M1UuXgiB3/sW8YLT6R++XZkGyapAmnw=;
        fh=ClJQqA5QvCseof56/RPKYdvC6c+rhHmmwbMXi8dRQaw=;
        b=ZOk+YRZekkJ+EI4jrcUCTodAxGijcFrzPc5Yo/KQ9QexQ17O/Bbz21dlciU06GiF36
         DRPg/CybaQAhIznX5uQm9486n8qq6JWQMV7+f8K7f4xn8FGAYz1COrTnpvFTT4GCJrni
         t86Z9S248t27zlgvChuGJgaEz26GSN3T2lGEHvUSBBqK9Aibl9DW2TwRqV6UfhYJDX7m
         ZXWBx/xYVwDD5JOZfBDkLfEfW1SDsS5YpoOu6zJd3s3JiYMAh5sZva1pqpFJfkfqlHQ6
         aMzpG5y2DT872cZOvviE9iu9V2FsWU5espa/jvauZv/BfizxJSY5o/YsCHQl80p+s50S
         gxNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A5QC44Tg;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007286; x=1772612086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UqXeFrsF25k/M1UuXgiB3/sW8YLT6R++XZkGyapAmnw=;
        b=OYxd4GwzcgtbYXR9qggZr1bm2JmUgzYOacG17hEXnq6IrXTb7PNZCCO79HSdsDOn/1
         5ud/2VLlyF+L+dDiaqeML5piLMaSl72K8yZF9sKfNlvGOgoTPug1b8Vf+q5v3JGdBJwD
         vT1XG1Q9PpCAoSh05PaK28IlicKwFZUkITR4sLBd4uYdLHH06AxmJoQkhnSR4So1u450
         HKQjHzcnS/iGjCEt0TU7z097cCqW/S2FSNY7sDgGfEEhrg2OPBt4G1IXANXGJ+tWmC2i
         A+iD+CyV8AgLFXkymvm+R5b3T96Z9ODQh38lizS4uBZR6WHZej+mSBAMsxz2mTUo94hw
         MAgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007286; x=1772612086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UqXeFrsF25k/M1UuXgiB3/sW8YLT6R++XZkGyapAmnw=;
        b=ped/xY/nhd0dhsHftVptU4P5M7L2n6jatd6RXeeJsxmBBTKNmxT0tPp9om3pyGB5Qs
         fKsUn84lDqVU6mlf61TA/kCOGTQTwttP7nhc//OX/CBjllO62gKox6oX7hpweWX/+jqc
         WzcO/yH6+PpttUAp57w2OeEABTu3BDhFp7RAdTpLvK5ATF9w0CDvpqUA2WHLtqwJwVfB
         bwAkOqiZCeqvBA+PRwdbSzQp0n7e8zSQzCOPVsLRQBO0EG2KbMYeU5fN9sobf+PiR2F1
         0ctXa4CpikUXtpsJB02Up9nJQ1vt9aKZUlJfJ0552o/y6PoNu58bFnEKfpJllOf6ETAQ
         1oFg==
X-Forwarded-Encrypted: i=2; AJvYcCVUSXfrZkNzeQYfyAtD83HxUziCqHplrrT1H+TkOQbgF7Ota41iJ1KmrB8uJ4hqKG0iZApMdw==@lfdr.de
X-Gm-Message-State: AOJu0YwlNyA2PGolt7sR1UimiXBm+6QiU+Q1Rh+EqYbPQRT5QiCofiS9
	TLpytTVgailbCGCG8JfZKFqIMMRI6UsuhnwqLJu1xvdNIz/pmPXbukyX
X-Received: by 2002:a05:6214:4709:b0:896:f2d4:1df3 with SMTP id 6a1803df08f44-89979da9834mr156174406d6.6.1772007286376;
        Wed, 25 Feb 2026 00:14:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F6mhC/qqpr1WgMCEL1fKERYyyD1ndou/QIRlUIv6jb4g=="
Received: by 2002:a05:6214:20ea:b0:888:1f20:6a87 with SMTP id
 6a1803df08f44-899b9c9a3c8ls10234126d6.0.-pod-prod-04-us; Wed, 25 Feb 2026
 00:14:45 -0800 (PST)
X-Received: by 2002:a05:6122:470f:b0:567:638a:ce16 with SMTP id 71dfb90a1353d-56a81313ec1mr560617e0c.14.1772007285435;
        Wed, 25 Feb 2026 00:14:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007285; cv=none;
        d=google.com; s=arc-20240605;
        b=FpSDgCxdu/yY6bLHgfbckEC6GRtmwO/FSe3v/O95UomESVVBFYxZDIBXmQZ9p2ET8e
         DfvxXDCcfRtkepAPaG5BSFQvDjlNVt7XNEnN/ZfgsFpNjkqRCwYux2v0N9bb0uxlujaN
         d5IDVPqUQXsw5Bdv61E/ZZM862VA2p4TifElp160xQvnajLI4aLm+A7bv26lG3933SVV
         deGd0N6veUXWs1IH/RUJXmhN0xonKtWYH+tmUL9HeOOxoTz/zmLgtqm2V46blVZKfGhl
         VfiR2bJeoMA8MSysVnkKC5pr52tVfGAj9g+sRBv2u9lmJowe31MGRXGh9JubzGTojIkk
         Kj5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=re7E4sxplbVcSJsRUE0dixF3rx550iAmXm+wmG0q1R4=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=l3fwJr4ZAvex9cS4M6HHsbjDm3g/XGS/jA0ry8bWyG9jDMVZaqdzID2LyDtz1JMLeh
         W6jHrQC76GwGR1j45ZT5dDZJYEEWIWf7Bk9Rx4FoauwIZKTAz69MfL5NJO0Jzt7IGYk1
         0UttZcRWjHen0xz/6fNE3JpQDsZM2G/JNlZk46vkvQYt2iFCcvX3GnWTTG/+/2gwufzw
         jumRfL/74mPn8+CxfHFWmxntUE4DVnstLMGnbtg65PVA6G9flJQlQUNWsEHp2vGTyFp/
         A4Tzi1RXaRUrOCb/0ROgN4FuQJ9l62frwwuv9sIUkYbtquRSujUIWtV+wINFoP8GF2ef
         NtnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A5QC44Tg;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56a7ef26a0csi62646e0c.3.2026.02.25.00.14.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:14:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-497-8STCbgGpNdSEQd8WeY9I3A-1; Wed,
 25 Feb 2026 03:14:40 -0500
X-MC-Unique: 8STCbgGpNdSEQd8WeY9I3A-1
X-Mimecast-MFC-AGG-ID: 8STCbgGpNdSEQd8WeY9I3A_1772007278
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6A1281956067;
	Wed, 25 Feb 2026 08:14:37 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7C6291800465;
	Wed, 25 Feb 2026 08:14:26 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 00/15] mm/kasan: make kasan=on|off work for all three modes
Date: Wed, 25 Feb 2026 16:13:57 +0800
Message-ID: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: mUi7aAOItPdK1r71P_JP9eNIWDgmmUQb2eUrp1yo-bw_1772007278
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=A5QC44Tg;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERB5W67LGAMGQEBANMLHI];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.964];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-qv1-xf3d.google.com:helo,mail-qv1-xf3d.google.com:rdns]
X-Rspamd-Queue-Id: 057CA193F9E
X-Rspamd-Action: no action

Currently only hw_tags mode of kasan can be enabled or disabled with
kernel parameter kasan=on|off for built kernel. For kasan generic and
sw_tags mode, there's no way to disable them once kernel is built.

This is not convenient sometime, e.g in system kdump is configured.
When the 1st kernel has KASAN enabled and crash triggered to switch to
kdump kernel, the generic or sw_tags mode will cost much extra memory
while in fact it's meaningless to have kasan in kdump kernel

There are two parts of big amount of memory requiring for kasan enabed
kernel. One is the direct memory mapping shadow of kasan, which is 1/8
of system RAM in generic mode and 1/16 of system RAM in sw_tags mode;
the other is the shadow meomry for vmalloc which causes big meomry
usage in kdump kernel because of lazy vmap freeing. By introducing
"kasan=off|on", if we specify 'kasan=off', the former is avoided by
skipping the kasan_init(), and the latter is avoided by not building the
vmalloc shadow for vmalloc.

So this patchset moves the kasan=on|off out of hw_tags scope and into
common code to make it visible in generic and sw_tags mode too. Then we
can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
kasan.

Note that this hasn't been supported on s390 since I am not familiar
with s390 code. Hope s390 developer will make it work.

Testing:
========
Testing is done on upstream kernel 6.19.0+:

- For generic mode, testing is taken on below systems and passed.
  - x86_64 baremetal system
  - aarch64 baremetal system
  - ppc64le baremetal system (Model 9183-22X)
  - risc-v kvm guest

- For sw_tags mode, testing is taken on below system and passed.
  - aarch64 baremetal system 

- For hw_tags mode, testing is taken on below system and passed.
  - aarch64 kvm guest with "-machine virt,mte=on -cpu max" qemu command.

Changelog:
====
v4->v5:
- Add helper __kasan_cache_shrink() in mm/kasan/generic.c so that the
  kasan_enabled() checking done in kasan_cache_shrink() which is in
  include/linux/kasan.h. This change is made in patch 1.
- Carve out the change of renaming 'kasan_arg' to 'kasan_arg_disabled'
  into a separate patch from the old patch 2.
- put the old patch 12 to earlier place as patch 4 in this sereis so
  that the ifdeffery scope embracing kasan_flag_enabled definition is
  meaningful and understandable.
- Remove the stale and incorrect comment above kasan_enabled() in the
  old patch 12.
- Add comment 'If KASAN is disabled via command line, don't initialize
  it.' to all places where kasan is initialized and kasan_arg_disabled
  is checked.
- Add document in kernel-parameters.txt to note kasan=on|off.
- Remove unneeded ARCH_DEFER_KASAN and kasan_arch_is_ready().
- All these changes are made according to reviewers' suggestion in v4,
  thanks to Andrey Konovalov, Andrey Ryabinin and Alexander Potapenko.
  

v3->v4:
- Rebase code to the latest linux-next/master to make the whole patchset
  set on top of
  [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
  [PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific implementations

v2->v3:
- Fix a building error on UML ARCH when CONFIG_KASAN is not set. The
  change of fixing is appended into patch patch 11. This is reported
  by LKP, thanks to them.

v1->v2:
- Add __ro_after_init for kasan_arg_disabled, and remove redundant blank
  lines in mm/kasan/common.c. Thanks to Marco.
- Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
  this is found out by SeongJae and Lorenzo, and also reported by LKP
  report, thanks to them.
- Add a missing kasan_enabled() checking in kasan_report(). This will
  cause a KASAN report info even though kasan=off is set:
- Add jump_label_init() calling before kasan_init() in setup_arch() in these
  architectures: xtensa, arm. Because they currenly rely on
  jump_label_init() in main() which is a little late. Then the early static
  key kasan_flag_enabled in kasan_init() won't work.
- In UML architecture, change to enable kasan_flag_enabled in arch_mm_preinit()
  because kasan_init() is enabled before main(), there's no chance to operate
  on static key in kasan_init().

Baoquan He (15):
  mm/kasan: add conditional checks in functions to return directly if
    kasan is disabled
  mm/kasan: rename 'kasan_arg' to 'kasan_arg_disabled'
  mm/kasan: mm/kasan: move kasan= code to common place
  mm/kasan: make kasan=on|off take effect for all three modes
  mm/kasan/sw_tags: don't initialize kasan if it's disabled
  arch/arm: don't initialize kasan if it's disabled
  arch/arm64: don't initialize kasan if it's disabled
  arch/loongarch: don't initialize kasan if it's disabled
  arch/powerpc: don't initialize kasan if it's disabled
  arch/riscv: don't initialize kasan if it's disabled
  arch/x86: don't initialize kasan if it's disabled
  arch/xtensa: don't initialize kasan if it's disabled
  arch/um: don't initialize kasan if it's disabled
  mm/kasan: add document into kernel-parameters.txt
  mm/kasan: clean up unneeded ARCH_DEFER_KASAN and kasan_arch_is_ready

 .../admin-guide/kernel-parameters.txt         |  4 +++
 Documentation/dev-tools/kasan.rst             |  2 --
 arch/arm/kernel/setup.c                       |  6 ++++
 arch/arm/mm/kasan_init.c                      |  3 ++
 arch/arm64/mm/kasan_init.c                    |  7 +++++
 arch/loongarch/Kconfig                        |  1 -
 arch/loongarch/mm/kasan_init.c                |  3 ++
 arch/powerpc/Kconfig                          |  1 -
 arch/powerpc/mm/kasan/init_32.c               |  6 +++-
 arch/powerpc/mm/kasan/init_book3e_64.c        |  4 +++
 arch/powerpc/mm/kasan/init_book3s_64.c        |  4 +++
 arch/riscv/mm/kasan_init.c                    |  4 +++
 arch/um/Kconfig                               |  1 -
 arch/um/kernel/mem.c                          |  5 +++-
 arch/x86/mm/kasan_init_64.c                   |  4 +++
 arch/xtensa/kernel/setup.c                    |  1 +
 arch/xtensa/mm/kasan_init.c                   |  4 +++
 include/linux/kasan-enabled.h                 | 10 +++----
 include/linux/kasan.h                         |  7 ++++-
 lib/Kconfig.kasan                             | 12 --------
 mm/kasan/common.c                             | 21 ++++++++++++--
 mm/kasan/generic.c                            | 16 +++++++++--
 mm/kasan/hw_tags.c                            | 28 ++-----------------
 mm/kasan/init.c                               |  6 ++++
 mm/kasan/kasan.h                              |  6 ----
 mm/kasan/quarantine.c                         |  3 ++
 mm/kasan/report.c                             |  4 ++-
 mm/kasan/shadow.c                             | 11 +++++++-
 mm/kasan/sw_tags.c                            |  7 +++++
 29 files changed, 128 insertions(+), 63 deletions(-)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-1-bhe%40redhat.com.
