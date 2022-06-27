Return-Path: <kasan-dev+bncBDPYNU65Q4NRBN7C46KQMGQED54XEZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 999E455BB71
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 20:04:40 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id h18-20020a5d9712000000b00674f83a60f0sf6068458iol.4
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 11:04:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656353079; cv=pass;
        d=google.com; s=arc-20160816;
        b=at+zaIk/YF2CRDk7YtsZaHixoiVurPkGpDHD/8KbT4eU/juI9kzi7yDBYQ/fZT0AEZ
         EP/OKbVSAG1oQ5EzKbZ4HuBVf3yxme9Eck7QT0bEaZjBEbfU20t6gyT2u5RZctbCbBMz
         c64lIGgxvmd5FIfeVFQsx/vQHXGb4k6yyZTzKlE/u5GO7mCyrfJqjfBf+GWkApBS3lYS
         8QYMXpi6GrBuHoQisE81P7rnBqD6jityPmgiql3htpiAMsGuCschAEhXZ+bSf950ahqm
         fGulBS0S7iqFK5RXSOOFroffJdEmwn/K1GFAIvuF4RCyKmEtIlWcXJDee1fgNY6Xb3Fm
         MatA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=x6MF++dXeQp/cBVThtG88+YOK+XLSZqWtil/zM3Nu3c=;
        b=ncMFKREX3PLQajVZ1mhvAHEfZEyZev/TvLW7yb5LdHBNNKqrPuVsQ3R3hE4+JMiT5N
         2Nba/6vgGUxO1zHbd1cME/BlsHXSYBr19TosKogkxp8g6l7X5Z5B9YA4CEJbcexhnoKA
         RmC0EzmyiYHBpxKe7BW5mQNQ6rXXeB7NHBYGAMRQb7bOBChMa921CGjpGBeTY7Fy84yP
         xZfJh4ssA0QU/ud9GJ91AiyaivXqZeriTFdb8CLUBaODw4SInU+zLX83/4wjbFvG8gjO
         A5eBMHXl6PHB+OtjLVF2Urr7d1BiWTUuNVeYrFe/RihGRjztxxRGfqFtf1zGas636hK9
         OP3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q4QOvRQe;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x6MF++dXeQp/cBVThtG88+YOK+XLSZqWtil/zM3Nu3c=;
        b=CFu95C1opP05RSwhQInCTxZH4gdppnKxcnYxRv2U9m+F1y7qct2g2NqLP1ICyEGoNo
         LB6hkU//rnLQkfxDScnBCxH21FIrlE8/APYaEhtCwwFgsnwTmmIBM11MZ8FubUXVyRsU
         VIV0ziSE4r1gupr0uc2CXLBW5/34ohfh1MxTitRtwpHrznPZLbpw9b49DIbKCZrJ4TEN
         wmVlcEyN3rMZzxf10XxUDbo7oh9Yz7LQg4ELtLRpmnmF+s5u0r8SgO+FgynkZCY/5czY
         Fl/84Hk2MKjPdWDNBeIilOKUAdSJMxmcQ8ywLEMLJ08t/aQ6US5uGKMXIfzUdtWlk3LG
         U9Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x6MF++dXeQp/cBVThtG88+YOK+XLSZqWtil/zM3Nu3c=;
        b=XhsDOsA62nQXdUUjPCFIeDzQvMQhN4Mbl/XU/UiN/B2KqXRvBA1gYMB1vqoYo7ee/v
         Lu65jLET8ooNWV8rjFmrvF8+3BKxUDOW6d/rpzkQOFlgbeWgcbG+VfVS81in6erJRkSb
         Eu9t77kVVkZB9zfoLbr1hYT3dLL5c7O3Svs6t8zE69vaLqgtKh5SrcVJIOiqkqFzM1kM
         7DA1GhT9I8HVjMRdoUfIJ/KOZ6c8U7FFTYiFQKJ1Q1h0TcaDU5250VHl1BPl7Q3BdnAC
         seVxe0v4E5TX3SzfxC+GEVsgbVCbLb6Xxfw44z6qk8wfwgfaJZlepoAReisuMNunatej
         o/mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9x1+Gmqxy8G2Zi+ocDhMIhKB7/tXyFg6S2A+BHyylPxjHqh+LE
	qXa0QVrdn6RpfzZ26RmJZAA=
X-Google-Smtp-Source: AGRyM1uSaCY+cYcozhrIFZWThG/PbUMbndUIEsLaLDBoVLerxebfGDaEOeHgiFblK5f72KXv9u7Aaw==
X-Received: by 2002:a05:6e02:219e:b0:2d9:50c7:e12a with SMTP id j30-20020a056e02219e00b002d950c7e12amr8516038ila.79.1656353079150;
        Mon, 27 Jun 2022 11:04:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c8c4:0:b0:675:2866:cec8 with SMTP id y187-20020a6bc8c4000000b006752866cec8ls439629iof.8.gmail;
 Mon, 27 Jun 2022 11:04:38 -0700 (PDT)
X-Received: by 2002:a6b:fa13:0:b0:64f:d480:30d3 with SMTP id p19-20020a6bfa13000000b0064fd48030d3mr7142729ioh.179.1656353078580;
        Mon, 27 Jun 2022 11:04:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656353078; cv=none;
        d=google.com; s=arc-20160816;
        b=g+iwPphs+liEcoip/O8D/TqPRmnTk6K29IC0wHkLxSn5CWcJWhMulfkT5Ti3kT3ZZm
         bIexHbxR4ByxdUFPq2xOVYuS0J67hhc64Y3Jb8F/RHCuqFqEwACIZKjZHiissGz9tyIj
         FF4f4/tY6nlOIwOThchIe2ngv1+xlvkN7la+8Orf+UpkLGlQoDTJ0IY+wtMJnWflNxhL
         0F5NJqI3+KZOu3Gsuqn+KRuByj5taIeO+1nnHxVRb0Qxtl4vixjyLF92VOC5ZMkOUjpV
         RsE2/Nou7wdbBxUBXQedcImhdVuqq2HT770B+mAjAF+rV5HGM4ZpCjOMrl5xwVecZUfC
         fj5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Zb11ya1TLTKLOMP89kpgiwL0b7NrnAoFKYoFcNol6so=;
        b=fhY9iPv4q/Ta3jcwovDF2jmjoRX6QXpMGrOCyCagnZWzyQ0zyrz2WzlSyB3SAFviLC
         xDafdcALNjMOMYx8QyF+5G1rOzYAsUGx6X8QSKKFZNxDHR8ZKnhEceBAn2/zvxdvumUK
         u2ATm+cSUOR+QrAHswfWBLc9lVAaxEcqomHUDTTUPt9YbkLFF3R7BSNdO4t6a2tAIQLy
         5Cnoui/qkl12yeggcuIHkJgg9qVy3dc/7V/AeXJFdG5oaFd/1sKFklcbcKnvqNX7w911
         2UroV/WP+9TF5WPjqFeB8gPWJ5tKPFvSgCDhqJHv7QIM+cvjs0zSHtr9UpK5CbYif+Ww
         inVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q4QOvRQe;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id u10-20020a92ccca000000b002d3c49040dasi375484ilq.5.2022.06.27.11.04.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 11:04:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 04A5661526;
	Mon, 27 Jun 2022 18:04:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8180FC3411D;
	Mon, 27 Jun 2022 18:04:34 +0000 (UTC)
Date: Mon, 27 Jun 2022 20:04:32 +0200
From: "Gustavo A. R. Silva" <gustavoars@kernel.org>
To: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org
Cc: x86@kernel.org, dm-devel@redhat.com, linux-m68k@lists.linux-m68k.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	kvm@vger.kernel.org, intel-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, netdev@vger.kernel.org,
	bpf@vger.kernel.org, linux-btrfs@vger.kernel.org,
	linux-can@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
	nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
	alsa-devel@alsa-project.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org
Subject: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220627180432.GA136081@embeddedor>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q4QOvRQe;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

There is a regular need in the kernel to provide a way to declare
having a dynamically sized set of trailing elements in a structure.
Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[1] f=
or these
cases. The older style of one-element or zero-length arrays should
no longer be used[2].

This code was transformed with the help of Coccinelle:
(linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-file scrip=
t.cocci --include-headers --dir . > output.patch)

@@
identifier S, member, array;
type T1, T2;
@@

struct S {
  ...
  T1 member;
  T2 array[
- 0
  ];
};

-fstrict-flex-arrays=3D3 is coming and we need to land these changes
to prevent issues like these in the short future:

../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; destinatio=
n buffer has size 0,
but the source string has length 2 (including NUL byte) [-Wfortify-source]
		strcpy(de3->name, ".");
		^

Since these are all [0] to [] changes, the risk to UAPI is nearly zero. If
this breaks anything, we can use a union with a new member name.

[1] https://en.wikipedia.org/wiki/Flexible_array_member
[2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#zero-leng=
th-and-one-element-arrays

Link: https://github.com/KSPP/linux/issues/78
Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE71vtF%25l=
kp@intel.com/
Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
---
Hi all!

JFYI: I'm adding this to my -next tree. :)

 arch/m68k/include/uapi/asm/bootinfo.h         |  4 +-
 arch/mips/include/uapi/asm/ucontext.h         |  2 +-
 arch/s390/include/uapi/asm/hwctrset.h         |  6 +-
 arch/x86/include/uapi/asm/bootparam.h         |  2 +-
 arch/x86/include/uapi/asm/kvm.h               | 12 ++--
 include/uapi/drm/i915_drm.h                   |  6 +-
 include/uapi/linux/blkzoned.h                 |  2 +-
 include/uapi/linux/bpf.h                      |  2 +-
 include/uapi/linux/btrfs.h                    | 10 +--
 include/uapi/linux/btrfs_tree.h               |  2 +-
 include/uapi/linux/can/bcm.h                  |  2 +-
 include/uapi/linux/connector.h                |  2 +-
 include/uapi/linux/cycx_cfm.h                 |  2 +-
 include/uapi/linux/dm-ioctl.h                 |  8 +--
 include/uapi/linux/dm-log-userspace.h         |  2 +-
 include/uapi/linux/ethtool.h                  | 28 ++++----
 include/uapi/linux/fanotify.h                 |  2 +-
 include/uapi/linux/fiemap.h                   |  2 +-
 include/uapi/linux/firewire-cdev.h            | 12 ++--
 include/uapi/linux/fs.h                       |  2 +-
 include/uapi/linux/if_alg.h                   |  2 +-
 include/uapi/linux/if_arcnet.h                |  6 +-
 include/uapi/linux/if_pppox.h                 |  4 +-
 include/uapi/linux/if_tun.h                   |  2 +-
 include/uapi/linux/igmp.h                     |  6 +-
 include/uapi/linux/inet_diag.h                |  2 +-
 include/uapi/linux/inotify.h                  |  2 +-
 include/uapi/linux/io_uring.h                 |  2 +-
 include/uapi/linux/ip.h                       |  4 +-
 include/uapi/linux/ip_vs.h                    |  4 +-
 include/uapi/linux/iso_fs.h                   |  4 +-
 include/uapi/linux/jffs2.h                    |  8 +--
 include/uapi/linux/kcov.h                     |  2 +-
 include/uapi/linux/kvm.h                      |  8 +--
 include/uapi/linux/minix_fs.h                 |  4 +-
 include/uapi/linux/mmc/ioctl.h                |  2 +-
 include/uapi/linux/ndctl.h                    | 10 +--
 include/uapi/linux/net_dropmon.h              |  4 +-
 include/uapi/linux/netfilter/x_tables.h       |  4 +-
 include/uapi/linux/netfilter_arp/arp_tables.h |  6 +-
 .../uapi/linux/netfilter_bridge/ebt_among.h   |  2 +-
 include/uapi/linux/netfilter_ipv4/ip_tables.h |  6 +-
 .../uapi/linux/netfilter_ipv6/ip6_tables.h    |  4 +-
 include/uapi/linux/perf_event.h               |  2 +-
 include/uapi/linux/pkt_cls.h                  |  4 +-
 include/uapi/linux/raid/md_p.h                |  2 +-
 include/uapi/linux/random.h                   |  2 +-
 include/uapi/linux/romfs_fs.h                 |  4 +-
 include/uapi/linux/rtnetlink.h                |  2 +-
 include/uapi/linux/sctp.h                     | 10 +--
 include/uapi/linux/seg6.h                     |  2 +-
 include/uapi/linux/seg6_iptunnel.h            |  2 +-
 include/uapi/linux/stm.h                      |  2 +-
 include/uapi/linux/target_core_user.h         |  2 +-
 include/uapi/linux/usb/audio.h                |  2 +-
 include/uapi/linux/usb/cdc.h                  |  6 +-
 include/uapi/linux/usb/ch9.h                  |  2 +-
 include/uapi/linux/usb/raw_gadget.h           |  4 +-
 include/uapi/linux/usbdevice_fs.h             |  4 +-
 include/uapi/linux/vhost_types.h              |  4 +-
 include/uapi/linux/virtio_9p.h                |  2 +-
 include/uapi/linux/xfrm.h                     | 10 +--
 include/uapi/rdma/hfi/hfi1_user.h             |  2 +-
 include/uapi/rdma/ib_user_verbs.h             | 72 +++++++++----------
 include/uapi/rdma/rdma_user_cm.h              |  2 +-
 include/uapi/rdma/rdma_user_ioctl_cmds.h      |  2 +-
 include/uapi/scsi/fc/fc_els.h                 | 18 ++---
 include/uapi/scsi/scsi_bsg_fc.h               |  2 +-
 include/uapi/sound/asound.h                   |  2 +-
 include/uapi/sound/firewire.h                 |  6 +-
 include/uapi/sound/skl-tplg-interface.h       |  2 +-
 include/uapi/sound/sof/header.h               |  2 +-
 include/uapi/sound/usb_stream.h               |  2 +-
 tools/arch/x86/include/uapi/asm/kvm.h         | 12 ++--
 tools/include/uapi/drm/i915_drm.h             |  6 +-
 tools/include/uapi/linux/bpf.h                |  2 +-
 tools/include/uapi/linux/fs.h                 |  2 +-
 tools/include/uapi/linux/if_tun.h             |  2 +-
 tools/include/uapi/linux/kvm.h                |  8 +--
 tools/include/uapi/linux/perf_event.h         |  2 +-
 tools/include/uapi/linux/pkt_cls.h            |  4 +-
 tools/include/uapi/linux/seg6.h               |  4 +-
 tools/include/uapi/linux/usbdevice_fs.h       |  4 +-
 tools/include/uapi/sound/asound.h             |  2 +-
 84 files changed, 218 insertions(+), 218 deletions(-)

diff --git a/arch/m68k/include/uapi/asm/bootinfo.h b/arch/m68k/include/uapi=
/asm/bootinfo.h
index 203d9cbf9630..95ecf3ae4c49 100644
--- a/arch/m68k/include/uapi/asm/bootinfo.h
+++ b/arch/m68k/include/uapi/asm/bootinfo.h
@@ -34,7 +34,7 @@
 struct bi_record {
 	__be16 tag;			/* tag ID */
 	__be16 size;			/* size of record (in bytes) */
-	__be32 data[0];			/* data */
+	__be32 data[];			/* data */
 };
=20
=20
@@ -168,7 +168,7 @@ struct bootversion {
 	struct {
 		__be32 machtype;
 		__be32 version;
-	} machversions[0];
+	} machversions[];
 } __packed;
=20
 #endif /* __ASSEMBLY__ */
diff --git a/arch/mips/include/uapi/asm/ucontext.h b/arch/mips/include/uapi=
/asm/ucontext.h
index 2d3bf8eebf1f..6122ef97c6ff 100644
--- a/arch/mips/include/uapi/asm/ucontext.h
+++ b/arch/mips/include/uapi/asm/ucontext.h
@@ -60,7 +60,7 @@ struct ucontext {
 	sigset_t		uc_sigmask;
=20
 	/* Extended context structures may follow ucontext */
-	unsigned long long	uc_extcontext[0];
+	unsigned long long	uc_extcontext[];
 };
=20
 #endif /* __MIPS_UAPI_ASM_UCONTEXT_H */
diff --git a/arch/s390/include/uapi/asm/hwctrset.h b/arch/s390/include/uapi=
/asm/hwctrset.h
index 3d8284b95f87..e56b9dd23a4b 100644
--- a/arch/s390/include/uapi/asm/hwctrset.h
+++ b/arch/s390/include/uapi/asm/hwctrset.h
@@ -30,18 +30,18 @@ struct s390_ctrset_start {		/* Set CPUs to operate on *=
/
 struct s390_ctrset_setdata {		/* Counter set data */
 	__u32 set;			/* Counter set number */
 	__u32 no_cnts;			/* # of counters stored in cv[] */
-	__u64 cv[0];			/* Counter values (variable length) */
+	__u64 cv[];			/* Counter values (variable length) */
 };
=20
 struct s390_ctrset_cpudata {		/* Counter set data per CPU */
 	__u32 cpu_nr;			/* CPU number */
 	__u32 no_sets;			/* # of counters sets in data[] */
-	struct s390_ctrset_setdata data[0];
+	struct s390_ctrset_setdata data[];
 };
=20
 struct s390_ctrset_read {		/* Structure to get all ctr sets */
 	__u64 no_cpus;			/* Total # of CPUs data taken from */
-	struct s390_ctrset_cpudata data[0];
+	struct s390_ctrset_cpudata data[];
 };
=20
 #define S390_HWCTR_MAGIC	'C'	/* Random magic # for ioctls */
diff --git a/arch/x86/include/uapi/asm/bootparam.h b/arch/x86/include/uapi/=
asm/bootparam.h
index bea5cdcdf532..cdd6c7f6cfa6 100644
--- a/arch/x86/include/uapi/asm/bootparam.h
+++ b/arch/x86/include/uapi/asm/bootparam.h
@@ -52,7 +52,7 @@ struct setup_data {
 	__u64 next;
 	__u32 type;
 	__u32 len;
-	__u8 data[0];
+	__u8 data[];
 };
=20
 /* extensible setup indirect data node */
diff --git a/arch/x86/include/uapi/asm/kvm.h b/arch/x86/include/uapi/asm/kv=
m.h
index 21614807a2cb..ec53c9fa1da9 100644
--- a/arch/x86/include/uapi/asm/kvm.h
+++ b/arch/x86/include/uapi/asm/kvm.h
@@ -198,13 +198,13 @@ struct kvm_msrs {
 	__u32 nmsrs; /* number of msrs in entries */
 	__u32 pad;
=20
-	struct kvm_msr_entry entries[0];
+	struct kvm_msr_entry entries[];
 };
=20
 /* for KVM_GET_MSR_INDEX_LIST */
 struct kvm_msr_list {
 	__u32 nmsrs; /* number of msrs in entries */
-	__u32 indices[0];
+	__u32 indices[];
 };
=20
 /* Maximum size of any access bitmap in bytes */
@@ -241,7 +241,7 @@ struct kvm_cpuid_entry {
 struct kvm_cpuid {
 	__u32 nent;
 	__u32 padding;
-	struct kvm_cpuid_entry entries[0];
+	struct kvm_cpuid_entry entries[];
 };
=20
 struct kvm_cpuid_entry2 {
@@ -263,7 +263,7 @@ struct kvm_cpuid_entry2 {
 struct kvm_cpuid2 {
 	__u32 nent;
 	__u32 padding;
-	struct kvm_cpuid_entry2 entries[0];
+	struct kvm_cpuid_entry2 entries[];
 };
=20
 /* for KVM_GET_PIT and KVM_SET_PIT */
@@ -389,7 +389,7 @@ struct kvm_xsave {
 	 * the contents of CPUID leaf 0xD on the host.
 	 */
 	__u32 region[1024];
-	__u32 extra[0];
+	__u32 extra[];
 };
=20
 #define KVM_MAX_XCRS	16
@@ -516,7 +516,7 @@ struct kvm_pmu_event_filter {
 	__u32 fixed_counter_bitmap;
 	__u32 flags;
 	__u32 pad[4];
-	__u64 events[0];
+	__u64 events[];
 };
=20
 #define KVM_PMU_EVENT_ALLOW 0
diff --git a/include/uapi/drm/i915_drm.h b/include/uapi/drm/i915_drm.h
index a2def7b27009..b28ff5d88145 100644
--- a/include/uapi/drm/i915_drm.h
+++ b/include/uapi/drm/i915_drm.h
@@ -2123,7 +2123,7 @@ struct i915_context_engines_load_balance {
=20
 	__u64 mbz64; /* reserved for future use; must be zero */
=20
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
 } __attribute__((packed));
=20
 #define I915_DEFINE_CONTEXT_ENGINES_LOAD_BALANCE(name__, N__) struct { \
@@ -2161,7 +2161,7 @@ struct i915_context_engines_bond {
 	__u64 flags; /* all undefined flags must be zero */
 	__u64 mbz64[4]; /* reserved for future use; must be zero */
=20
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
 } __attribute__((packed));
=20
 #define I915_DEFINE_CONTEXT_ENGINES_BOND(name__, N__) struct { \
@@ -2288,7 +2288,7 @@ struct i915_context_engines_parallel_submit {
 	 * length =3D width (i) * num_siblings (j)
 	 * index =3D j + i * num_siblings
 	 */
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
=20
 } __packed;
=20
diff --git a/include/uapi/linux/blkzoned.h b/include/uapi/linux/blkzoned.h
index 656a326821a2..b80fcc9ea525 100644
--- a/include/uapi/linux/blkzoned.h
+++ b/include/uapi/linux/blkzoned.h
@@ -130,7 +130,7 @@ struct blk_zone_report {
 	__u64		sector;
 	__u32		nr_zones;
 	__u32		flags;
-	struct blk_zone zones[0];
+	struct blk_zone zones[];
 };
=20
 /**
diff --git a/include/uapi/linux/bpf.h b/include/uapi/linux/bpf.h
index f4009dbdf62d..e4b33ba06f00 100644
--- a/include/uapi/linux/bpf.h
+++ b/include/uapi/linux/bpf.h
@@ -79,7 +79,7 @@ struct bpf_insn {
 /* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
 struct bpf_lpm_trie_key {
 	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
-	__u8	data[0];	/* Arbitrary size */
+	__u8	data[];	/* Arbitrary size */
 };
=20
 struct bpf_cgroup_storage_key {
diff --git a/include/uapi/linux/btrfs.h b/include/uapi/linux/btrfs.h
index d956b2993970..3d0edbe3b991 100644
--- a/include/uapi/linux/btrfs.h
+++ b/include/uapi/linux/btrfs.h
@@ -93,7 +93,7 @@ struct btrfs_qgroup_inherit {
 	__u64	num_ref_copies;
 	__u64	num_excl_copies;
 	struct btrfs_qgroup_limit lim;
-	__u64	qgroups[0];
+	__u64	qgroups[];
 };
=20
 struct btrfs_ioctl_qgroup_limit_args {
@@ -561,7 +561,7 @@ struct btrfs_ioctl_search_args_v2 {
 	__u64 buf_size;		   /* in - size of buffer
 					    * out - on EOVERFLOW: needed size
 					    *       to store item */
-	__u64 buf[0];                       /* out - found items */
+	__u64 buf[];                       /* out - found items */
 };
=20
 struct btrfs_ioctl_clone_range_args {
@@ -632,7 +632,7 @@ struct btrfs_ioctl_same_args {
 	__u16 dest_count;	/* in - total elements in info array */
 	__u16 reserved1;
 	__u32 reserved2;
-	struct btrfs_ioctl_same_extent_info info[0];
+	struct btrfs_ioctl_same_extent_info info[];
 };
=20
 struct btrfs_ioctl_space_info {
@@ -644,7 +644,7 @@ struct btrfs_ioctl_space_info {
 struct btrfs_ioctl_space_args {
 	__u64 space_slots;
 	__u64 total_spaces;
-	struct btrfs_ioctl_space_info spaces[0];
+	struct btrfs_ioctl_space_info spaces[];
 };
=20
 struct btrfs_data_container {
@@ -652,7 +652,7 @@ struct btrfs_data_container {
 	__u32	bytes_missing;	/* out -- additional bytes needed for result */
 	__u32	elem_cnt;	/* out */
 	__u32	elem_missed;	/* out */
-	__u64	val[0];		/* out */
+	__u64	val[];		/* out */
 };
=20
 struct btrfs_ioctl_ino_path_args {
diff --git a/include/uapi/linux/btrfs_tree.h b/include/uapi/linux/btrfs_tre=
e.h
index d4117152d907..5f32a2a495dc 100644
--- a/include/uapi/linux/btrfs_tree.h
+++ b/include/uapi/linux/btrfs_tree.h
@@ -575,7 +575,7 @@ struct btrfs_inode_extref {
 	__le64 parent_objectid;
 	__le64 index;
 	__le16 name_len;
-	__u8   name[0];
+	__u8   name[];
 	/* name goes here */
 } __attribute__ ((__packed__));
=20
diff --git a/include/uapi/linux/can/bcm.h b/include/uapi/linux/can/bcm.h
index dd2b925b09ac..f1e45f533a72 100644
--- a/include/uapi/linux/can/bcm.h
+++ b/include/uapi/linux/can/bcm.h
@@ -71,7 +71,7 @@ struct bcm_msg_head {
 	struct bcm_timeval ival1, ival2;
 	canid_t can_id;
 	__u32 nframes;
-	struct can_frame frames[0];
+	struct can_frame frames[];
 };
=20
 enum {
diff --git a/include/uapi/linux/connector.h b/include/uapi/linux/connector.=
h
index 3738936149a2..5ae131c3f145 100644
--- a/include/uapi/linux/connector.h
+++ b/include/uapi/linux/connector.h
@@ -75,7 +75,7 @@ struct cn_msg {
=20
 	__u16 len;		/* Length of the following data */
 	__u16 flags;
-	__u8 data[0];
+	__u8 data[];
 };
=20
 #endif /* _UAPI__CONNECTOR_H */
diff --git a/include/uapi/linux/cycx_cfm.h b/include/uapi/linux/cycx_cfm.h
index 51f541942ff9..91778c8024b1 100644
--- a/include/uapi/linux/cycx_cfm.h
+++ b/include/uapi/linux/cycx_cfm.h
@@ -91,7 +91,7 @@ struct cycx_firmware {
 	unsigned short	    reserved[6];
 	char		    descr[CFM_DESCR_LEN];
 	struct cycx_fw_info info;
-	unsigned char	    image[0];
+	unsigned char	    image[];
 };
=20
 struct cycx_fw_header {
diff --git a/include/uapi/linux/dm-ioctl.h b/include/uapi/linux/dm-ioctl.h
index 2e9550fef90f..8c97d75f3104 100644
--- a/include/uapi/linux/dm-ioctl.h
+++ b/include/uapi/linux/dm-ioctl.h
@@ -182,7 +182,7 @@ struct dm_target_spec {
 struct dm_target_deps {
 	__u32 count;	/* Array size */
 	__u32 padding;	/* unused */
-	__u64 dev[0];	/* out */
+	__u64 dev[];	/* out */
 };
=20
 /*
@@ -192,7 +192,7 @@ struct dm_name_list {
 	__u64 dev;
 	__u32 next;		/* offset to the next record from
 				   the _start_ of this */
-	char name[0];
+	char name[];
=20
 	/*
 	 * The following members can be accessed by taking a pointer that
@@ -216,7 +216,7 @@ struct dm_target_versions {
         __u32 next;
         __u32 version[3];
=20
-        char name[0];
+        char name[];
 };
=20
 /*
@@ -225,7 +225,7 @@ struct dm_target_versions {
 struct dm_target_msg {
 	__u64 sector;	/* Device sector */
=20
-	char message[0];
+	char message[];
 };
=20
 /*
diff --git a/include/uapi/linux/dm-log-userspace.h b/include/uapi/linux/dm-=
log-userspace.h
index 5c47a8603376..23dad9565e46 100644
--- a/include/uapi/linux/dm-log-userspace.h
+++ b/include/uapi/linux/dm-log-userspace.h
@@ -426,7 +426,7 @@ struct dm_ulog_request {
 	__u32 request_type;  /* DM_ULOG_* defined above */
 	__u32 data_size;     /* How much data (not including this struct) */
=20
-	char data[0];
+	char data[];
 };
=20
 #endif /* __DM_LOG_USERSPACE_H__ */
diff --git a/include/uapi/linux/ethtool.h b/include/uapi/linux/ethtool.h
index e0f0ee9bc89e..2d5741fd44bb 100644
--- a/include/uapi/linux/ethtool.h
+++ b/include/uapi/linux/ethtool.h
@@ -257,7 +257,7 @@ struct ethtool_tunable {
 	__u32	id;
 	__u32	type_id;
 	__u32	len;
-	void	*data[0];
+	void	*data[];
 };
=20
 #define DOWNSHIFT_DEV_DEFAULT_COUNT	0xff
@@ -322,7 +322,7 @@ struct ethtool_regs {
 	__u32	cmd;
 	__u32	version;
 	__u32	len;
-	__u8	data[0];
+	__u8	data[];
 };
=20
 /**
@@ -348,7 +348,7 @@ struct ethtool_eeprom {
 	__u32	magic;
 	__u32	offset;
 	__u32	len;
-	__u8	data[0];
+	__u8	data[];
 };
=20
 /**
@@ -752,7 +752,7 @@ struct ethtool_gstrings {
 	__u32	cmd;
 	__u32	string_set;
 	__u32	len;
-	__u8	data[0];
+	__u8	data[];
 };
=20
 /**
@@ -777,7 +777,7 @@ struct ethtool_sset_info {
 	__u32	cmd;
 	__u32	reserved;
 	__u64	sset_mask;
-	__u32	data[0];
+	__u32	data[];
 };
=20
 /**
@@ -817,7 +817,7 @@ struct ethtool_test {
 	__u32	flags;
 	__u32	reserved;
 	__u32	len;
-	__u64	data[0];
+	__u64	data[];
 };
=20
 /**
@@ -834,7 +834,7 @@ struct ethtool_test {
 struct ethtool_stats {
 	__u32	cmd;
 	__u32	n_stats;
-	__u64	data[0];
+	__u64	data[];
 };
=20
 /**
@@ -851,7 +851,7 @@ struct ethtool_stats {
 struct ethtool_perm_addr {
 	__u32	cmd;
 	__u32	size;
-	__u8	data[0];
+	__u8	data[];
 };
=20
 /* boolean flags controlling per-interface behavior characteristics.
@@ -1160,7 +1160,7 @@ struct ethtool_rxnfc {
 struct ethtool_rxfh_indir {
 	__u32	cmd;
 	__u32	size;
-	__u32	ring_index[0];
+	__u32	ring_index[];
 };
=20
 /**
@@ -1201,7 +1201,7 @@ struct ethtool_rxfh {
 	__u8	hfunc;
 	__u8	rsvd8[3];
 	__u32	rsvd32;
-	__u32   rss_config[0];
+	__u32   rss_config[];
 };
 #define ETH_RXFH_CONTEXT_ALLOC		0xffffffff
 #define ETH_RXFH_INDIR_NO_CHANGE	0xffffffff
@@ -1286,7 +1286,7 @@ struct ethtool_dump {
 	__u32	version;
 	__u32	flag;
 	__u32	len;
-	__u8	data[0];
+	__u8	data[];
 };
=20
 #define ETH_FW_DUMP_DISABLE 0
@@ -1318,7 +1318,7 @@ struct ethtool_get_features_block {
 struct ethtool_gfeatures {
 	__u32	cmd;
 	__u32	size;
-	struct ethtool_get_features_block features[0];
+	struct ethtool_get_features_block features[];
 };
=20
 /**
@@ -1340,7 +1340,7 @@ struct ethtool_set_features_block {
 struct ethtool_sfeatures {
 	__u32	cmd;
 	__u32	size;
-	struct ethtool_set_features_block features[0];
+	struct ethtool_set_features_block features[];
 };
=20
 /**
@@ -2087,7 +2087,7 @@ struct ethtool_link_settings {
 	__u8	master_slave_state;
 	__u8	reserved1[1];
 	__u32	reserved[7];
-	__u32	link_mode_masks[0];
+	__u32	link_mode_masks[];
 	/* layout of link_mode_masks fields:
 	 * __u32 map_supported[link_mode_masks_nwords];
 	 * __u32 map_advertising[link_mode_masks_nwords];
diff --git a/include/uapi/linux/fanotify.h b/include/uapi/linux/fanotify.h
index f1f89132d60e..197df344307d 100644
--- a/include/uapi/linux/fanotify.h
+++ b/include/uapi/linux/fanotify.h
@@ -162,7 +162,7 @@ struct fanotify_event_info_fid {
 	 * Following is an opaque struct file_handle that can be passed as
 	 * an argument to open_by_handle_at(2).
 	 */
-	unsigned char handle[0];
+	unsigned char handle[];
 };
=20
 /*
diff --git a/include/uapi/linux/fiemap.h b/include/uapi/linux/fiemap.h
index 07c1cdcb715e..24ca0c00cae3 100644
--- a/include/uapi/linux/fiemap.h
+++ b/include/uapi/linux/fiemap.h
@@ -34,7 +34,7 @@ struct fiemap {
 	__u32 fm_mapped_extents;/* number of extents that were mapped (out) */
 	__u32 fm_extent_count;  /* size of fm_extents array (in) */
 	__u32 fm_reserved;
-	struct fiemap_extent fm_extents[0]; /* array of mapped extents (out) */
+	struct fiemap_extent fm_extents[]; /* array of mapped extents (out) */
 };
=20
 #define FIEMAP_MAX_OFFSET	(~0ULL)
diff --git a/include/uapi/linux/firewire-cdev.h b/include/uapi/linux/firewi=
re-cdev.h
index 5effa9832802..92be3ea3c6e0 100644
--- a/include/uapi/linux/firewire-cdev.h
+++ b/include/uapi/linux/firewire-cdev.h
@@ -118,7 +118,7 @@ struct fw_cdev_event_response {
 	__u32 type;
 	__u32 rcode;
 	__u32 length;
-	__u32 data[0];
+	__u32 data[];
 };
=20
 /**
@@ -142,7 +142,7 @@ struct fw_cdev_event_request {
 	__u64 offset;
 	__u32 handle;
 	__u32 length;
-	__u32 data[0];
+	__u32 data[];
 };
=20
 /**
@@ -205,7 +205,7 @@ struct fw_cdev_event_request2 {
 	__u32 generation;
 	__u32 handle;
 	__u32 length;
-	__u32 data[0];
+	__u32 data[];
 };
=20
 /**
@@ -265,7 +265,7 @@ struct fw_cdev_event_iso_interrupt {
 	__u32 type;
 	__u32 cycle;
 	__u32 header_length;
-	__u32 header[0];
+	__u32 header[];
 };
=20
 /**
@@ -355,7 +355,7 @@ struct fw_cdev_event_phy_packet {
 	__u32 type;
 	__u32 rcode;
 	__u32 length;
-	__u32 data[0];
+	__u32 data[];
 };
=20
 /**
@@ -803,7 +803,7 @@ struct fw_cdev_set_iso_channels {
  */
 struct fw_cdev_iso_packet {
 	__u32 control;
-	__u32 header[0];
+	__u32 header[];
 };
=20
 /**
diff --git a/include/uapi/linux/fs.h b/include/uapi/linux/fs.h
index bdf7b404b3e7..b7b56871029c 100644
--- a/include/uapi/linux/fs.h
+++ b/include/uapi/linux/fs.h
@@ -90,7 +90,7 @@ struct file_dedupe_range {
 	__u16 dest_count;	/* in - total elements in info array */
 	__u16 reserved1;	/* must be zero */
 	__u32 reserved2;	/* must be zero */
-	struct file_dedupe_range_info info[0];
+	struct file_dedupe_range_info info[];
 };
=20
 /* And dynamically-tunable limits and defaults: */
diff --git a/include/uapi/linux/if_alg.h b/include/uapi/linux/if_alg.h
index dc52a11ba6d1..578b18aab821 100644
--- a/include/uapi/linux/if_alg.h
+++ b/include/uapi/linux/if_alg.h
@@ -42,7 +42,7 @@ struct sockaddr_alg_new {
=20
 struct af_alg_iv {
 	__u32	ivlen;
-	__u8	iv[0];
+	__u8	iv[];
 };
=20
 /* Socket options */
diff --git a/include/uapi/linux/if_arcnet.h b/include/uapi/linux/if_arcnet.=
h
index 683878036d76..b122cfac7128 100644
--- a/include/uapi/linux/if_arcnet.h
+++ b/include/uapi/linux/if_arcnet.h
@@ -60,7 +60,7 @@ struct arc_rfc1201 {
 	__u8  proto;		/* protocol ID field - varies		*/
 	__u8  split_flag;	/* for use with split packets		*/
 	__be16   sequence;	/* sequence number			*/
-	__u8  payload[0];	/* space remaining in packet (504 bytes)*/
+	__u8  payload[];	/* space remaining in packet (504 bytes)*/
 };
 #define RFC1201_HDR_SIZE 4
=20
@@ -69,7 +69,7 @@ struct arc_rfc1201 {
  */
 struct arc_rfc1051 {
 	__u8 proto;		/* ARC_P_RFC1051_ARP/RFC1051_IP	*/
-	__u8 payload[0];	/* 507 bytes			*/
+	__u8 payload[];	/* 507 bytes			*/
 };
 #define RFC1051_HDR_SIZE 1
=20
@@ -80,7 +80,7 @@ struct arc_rfc1051 {
 struct arc_eth_encap {
 	__u8 proto;		/* Always ARC_P_ETHER			*/
 	struct ethhdr eth;	/* standard ethernet header (yuck!)	*/
-	__u8 payload[0];	/* 493 bytes				*/
+	__u8 payload[];	/* 493 bytes				*/
 };
 #define ETH_ENCAP_HDR_SIZE 14
=20
diff --git a/include/uapi/linux/if_pppox.h b/include/uapi/linux/if_pppox.h
index e7a693c28f16..9abd80dcc46f 100644
--- a/include/uapi/linux/if_pppox.h
+++ b/include/uapi/linux/if_pppox.h
@@ -122,7 +122,7 @@ struct sockaddr_pppol2tpv3in6 {
 struct pppoe_tag {
 	__be16 tag_type;
 	__be16 tag_len;
-	char tag_data[0];
+	char tag_data[];
 } __attribute__ ((packed));
=20
 /* Tag identifiers */
@@ -150,7 +150,7 @@ struct pppoe_hdr {
 	__u8 code;
 	__be16 sid;
 	__be16 length;
-	struct pppoe_tag tag[0];
+	struct pppoe_tag tag[];
 } __packed;
=20
 /* Length of entire PPPoE + PPP header */
diff --git a/include/uapi/linux/if_tun.h b/include/uapi/linux/if_tun.h
index 454ae31b93c7..2ec07de1d73b 100644
--- a/include/uapi/linux/if_tun.h
+++ b/include/uapi/linux/if_tun.h
@@ -108,7 +108,7 @@ struct tun_pi {
 struct tun_filter {
 	__u16  flags; /* TUN_FLT_ flags see above */
 	__u16  count; /* Number of addresses */
-	__u8   addr[0][ETH_ALEN];
+	__u8   addr[][ETH_ALEN];
 };
=20
 #endif /* _UAPI__IF_TUN_H */
diff --git a/include/uapi/linux/igmp.h b/include/uapi/linux/igmp.h
index 90c28bc466c6..5930f2437cd1 100644
--- a/include/uapi/linux/igmp.h
+++ b/include/uapi/linux/igmp.h
@@ -48,7 +48,7 @@ struct igmpv3_grec {
 	__u8	grec_auxwords;
 	__be16	grec_nsrcs;
 	__be32	grec_mca;
-	__be32	grec_src[0];
+	__be32	grec_src[];
 };
=20
 struct igmpv3_report {
@@ -57,7 +57,7 @@ struct igmpv3_report {
 	__sum16 csum;
 	__be16 resv2;
 	__be16 ngrec;
-	struct igmpv3_grec grec[0];
+	struct igmpv3_grec grec[];
 };
=20
 struct igmpv3_query {
@@ -78,7 +78,7 @@ struct igmpv3_query {
 #endif
 	__u8 qqic;
 	__be16 nsrcs;
-	__be32 srcs[0];
+	__be32 srcs[];
 };
=20
 #define IGMP_HOST_MEMBERSHIP_QUERY	0x11	/* From RFC1112 */
diff --git a/include/uapi/linux/inet_diag.h b/include/uapi/linux/inet_diag.=
h
index 20ee93f0f876..50655de04c9b 100644
--- a/include/uapi/linux/inet_diag.h
+++ b/include/uapi/linux/inet_diag.h
@@ -104,7 +104,7 @@ struct inet_diag_hostcond {
 	__u8	family;
 	__u8	prefix_len;
 	int	port;
-	__be32	addr[0];
+	__be32	addr[];
 };
=20
 struct inet_diag_markcond {
diff --git a/include/uapi/linux/inotify.h b/include/uapi/linux/inotify.h
index 884b4846b630..b3e165853d5b 100644
--- a/include/uapi/linux/inotify.h
+++ b/include/uapi/linux/inotify.h
@@ -23,7 +23,7 @@ struct inotify_event {
 	__u32		mask;		/* watch mask */
 	__u32		cookie;		/* cookie to synchronize two events */
 	__u32		len;		/* length (including nulls) of name */
-	char		name[0];	/* stub for possible name */
+	char		name[];	/* stub for possible name */
 };
=20
 /* the following are legal, implemented events that user-space can watch f=
or */
diff --git a/include/uapi/linux/io_uring.h b/include/uapi/linux/io_uring.h
index 776e0278f9dd..7822ef9d8628 100644
--- a/include/uapi/linux/io_uring.h
+++ b/include/uapi/linux/io_uring.h
@@ -486,7 +486,7 @@ struct io_uring_probe {
 	__u8 ops_len;	/* length of ops[] array below */
 	__u16 resv;
 	__u32 resv2[3];
-	struct io_uring_probe_op ops[0];
+	struct io_uring_probe_op ops[];
 };
=20
 struct io_uring_restriction {
diff --git a/include/uapi/linux/ip.h b/include/uapi/linux/ip.h
index e00bbb9c47bb..961ec16a26b8 100644
--- a/include/uapi/linux/ip.h
+++ b/include/uapi/linux/ip.h
@@ -112,13 +112,13 @@ struct ip_auth_hdr {
 	__be16 reserved;
 	__be32 spi;
 	__be32 seq_no;		/* Sequence number */
-	__u8  auth_data[0];	/* Variable len but >=3D4. Mind the 64 bit alignment!=
 */
+	__u8  auth_data[];	/* Variable len but >=3D4. Mind the 64 bit alignment! =
*/
 };
=20
 struct ip_esp_hdr {
 	__be32 spi;
 	__be32 seq_no;		/* Sequence number */
-	__u8  enc_data[0];	/* Variable len but >=3D8. Mind the 64 bit alignment! =
*/
+	__u8  enc_data[];	/* Variable len but >=3D8. Mind the 64 bit alignment! *=
/
 };
=20
 struct ip_comp_hdr {
diff --git a/include/uapi/linux/ip_vs.h b/include/uapi/linux/ip_vs.h
index 4102ddcb4e14..1ed234e7f251 100644
--- a/include/uapi/linux/ip_vs.h
+++ b/include/uapi/linux/ip_vs.h
@@ -254,7 +254,7 @@ struct ip_vs_get_dests {
 	unsigned int		num_dests;
=20
 	/* the real servers */
-	struct ip_vs_dest_entry	entrytable[0];
+	struct ip_vs_dest_entry	entrytable[];
 };
=20
=20
@@ -264,7 +264,7 @@ struct ip_vs_get_services {
 	unsigned int		num_services;
=20
 	/* service table */
-	struct ip_vs_service_entry entrytable[0];
+	struct ip_vs_service_entry entrytable[];
 };
=20
=20
diff --git a/include/uapi/linux/iso_fs.h b/include/uapi/linux/iso_fs.h
index a2555176f6d1..758178f5b52d 100644
--- a/include/uapi/linux/iso_fs.h
+++ b/include/uapi/linux/iso_fs.h
@@ -137,7 +137,7 @@ struct iso_path_table{
 	__u8  name_len[2];	/* 721 */
 	__u8  extent[4];	/* 731 */
 	__u8  parent[2];	/* 721 */
-	char name[0];
+	char name[];
 } __attribute__((packed));
=20
 /* high sierra is identical to iso, except that the date is only 6 bytes, =
and
@@ -154,7 +154,7 @@ struct iso_directory_record {
 	__u8 interleave			[ISODCL (28, 28)]; /* 711 */
 	__u8 volume_sequence_number	[ISODCL (29, 32)]; /* 723 */
 	__u8 name_len			[ISODCL (33, 33)]; /* 711 */
-	char name			[0];
+	char name			[];
 } __attribute__((packed));
=20
 #define ISOFS_BLOCK_BITS 11
diff --git a/include/uapi/linux/jffs2.h b/include/uapi/linux/jffs2.h
index 784ba0b9690a..637ee4a793cf 100644
--- a/include/uapi/linux/jffs2.h
+++ b/include/uapi/linux/jffs2.h
@@ -123,7 +123,7 @@ struct jffs2_raw_dirent
 	__u8 unused[2];
 	jint32_t node_crc;
 	jint32_t name_crc;
-	__u8 name[0];
+	__u8 name[];
 };
=20
 /* The JFFS2 raw inode structure: Used for storage on physical media.  */
@@ -155,7 +155,7 @@ struct jffs2_raw_inode
 	jint16_t flags;	     /* See JFFS2_INO_FLAG_* */
 	jint32_t data_crc;   /* CRC for the (compressed) data.  */
 	jint32_t node_crc;   /* CRC for the raw inode (excluding data)  */
-	__u8 data[0];
+	__u8 data[];
 };
=20
 struct jffs2_raw_xattr {
@@ -170,7 +170,7 @@ struct jffs2_raw_xattr {
 	jint16_t value_len;
 	jint32_t data_crc;
 	jint32_t node_crc;
-	__u8 data[0];
+	__u8 data[];
 } __attribute__((packed));
=20
 struct jffs2_raw_xref
@@ -196,7 +196,7 @@ struct jffs2_raw_summary
 	jint32_t padded;	/* sum of the size of padding nodes */
 	jint32_t sum_crc;	/* summary information crc */
 	jint32_t node_crc; 	/* node crc */
-	jint32_t sum[0]; 	/* inode summary info */
+	jint32_t sum[]; 	/* inode summary info */
 };
=20
 union jffs2_node_union
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index 1d0350e44ae3..ed95dba9fa37 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -13,7 +13,7 @@ struct kcov_remote_arg {
 	__u32		area_size;	/* Length of coverage buffer in words */
 	__u32		num_handles;	/* Size of handles array */
 	__aligned_u64	common_handle;
-	__aligned_u64	handles[0];
+	__aligned_u64	handles[];
 };
=20
 #define KCOV_REMOTE_MAX_HANDLES		0x100
diff --git a/include/uapi/linux/kvm.h b/include/uapi/linux/kvm.h
index 5088bd9f1922..74dc8bafcb9e 100644
--- a/include/uapi/linux/kvm.h
+++ b/include/uapi/linux/kvm.h
@@ -542,7 +542,7 @@ struct kvm_coalesced_mmio {
=20
 struct kvm_coalesced_mmio_ring {
 	__u32 first, last;
-	struct kvm_coalesced_mmio coalesced_mmio[0];
+	struct kvm_coalesced_mmio coalesced_mmio[];
 };
=20
 #define KVM_COALESCED_MMIO_MAX \
@@ -621,7 +621,7 @@ struct kvm_clear_dirty_log {
 /* for KVM_SET_SIGNAL_MASK */
 struct kvm_signal_mask {
 	__u32 len;
-	__u8  sigset[0];
+	__u8  sigset[];
 };
=20
 /* for KVM_TPR_ACCESS_REPORTING */
@@ -1221,7 +1221,7 @@ struct kvm_irq_routing_entry {
 struct kvm_irq_routing {
 	__u32 nr;
 	__u32 flags;
-	struct kvm_irq_routing_entry entries[0];
+	struct kvm_irq_routing_entry entries[];
 };
=20
 #endif
@@ -1341,7 +1341,7 @@ struct kvm_dirty_tlb {
=20
 struct kvm_reg_list {
 	__u64 n; /* number of regs */
-	__u64 reg[0];
+	__u64 reg[];
 };
=20
 struct kvm_one_reg {
diff --git a/include/uapi/linux/minix_fs.h b/include/uapi/linux/minix_fs.h
index 95dbcb17eacd..8d9ca8b2c357 100644
--- a/include/uapi/linux/minix_fs.h
+++ b/include/uapi/linux/minix_fs.h
@@ -97,11 +97,11 @@ struct minix3_super_block {
=20
 struct minix_dir_entry {
 	__u16 inode;
-	char name[0];
+	char name[];
 };
=20
 struct minix3_dir_entry {
 	__u32 inode;
-	char name[0];
+	char name[];
 };
 #endif
diff --git a/include/uapi/linux/mmc/ioctl.h b/include/uapi/linux/mmc/ioctl.=
h
index 27a39847d55c..e7401ade6822 100644
--- a/include/uapi/linux/mmc/ioctl.h
+++ b/include/uapi/linux/mmc/ioctl.h
@@ -58,7 +58,7 @@ struct mmc_ioc_cmd {
  */
 struct mmc_ioc_multi_cmd {
 	__u64 num_of_cmds;
-	struct mmc_ioc_cmd cmds[0];
+	struct mmc_ioc_cmd cmds[];
 };
=20
 #define MMC_IOC_CMD _IOWR(MMC_BLOCK_MAJOR, 0, struct mmc_ioc_cmd)
diff --git a/include/uapi/linux/ndctl.h b/include/uapi/linux/ndctl.h
index 17e02b64ea2e..73516e263627 100644
--- a/include/uapi/linux/ndctl.h
+++ b/include/uapi/linux/ndctl.h
@@ -30,25 +30,25 @@ struct nd_cmd_get_config_data_hdr {
 	__u32 in_offset;
 	__u32 in_length;
 	__u32 status;
-	__u8 out_buf[0];
+	__u8 out_buf[];
 } __packed;
=20
 struct nd_cmd_set_config_hdr {
 	__u32 in_offset;
 	__u32 in_length;
-	__u8 in_buf[0];
+	__u8 in_buf[];
 } __packed;
=20
 struct nd_cmd_vendor_hdr {
 	__u32 opcode;
 	__u32 in_length;
-	__u8 in_buf[0];
+	__u8 in_buf[];
 } __packed;
=20
 struct nd_cmd_vendor_tail {
 	__u32 status;
 	__u32 out_length;
-	__u8 out_buf[0];
+	__u8 out_buf[];
 } __packed;
=20
 struct nd_cmd_ars_cap {
@@ -86,7 +86,7 @@ struct nd_cmd_ars_status {
 		__u32 reserved;
 		__u64 err_address;
 		__u64 length;
-	} __packed records[0];
+	} __packed records[];
 } __packed;
=20
 struct nd_cmd_clear_error {
diff --git a/include/uapi/linux/net_dropmon.h b/include/uapi/linux/net_drop=
mon.h
index 1bbea8f0681e..84f622a66a7a 100644
--- a/include/uapi/linux/net_dropmon.h
+++ b/include/uapi/linux/net_dropmon.h
@@ -29,12 +29,12 @@ struct net_dm_config_entry {
=20
 struct net_dm_config_msg {
 	__u32 entries;
-	struct net_dm_config_entry options[0];
+	struct net_dm_config_entry options[];
 };
=20
 struct net_dm_alert_msg {
 	__u32 entries;
-	struct net_dm_drop_point points[0];
+	struct net_dm_drop_point points[];
 };
=20
 struct net_dm_user_msg {
diff --git a/include/uapi/linux/netfilter/x_tables.h b/include/uapi/linux/n=
etfilter/x_tables.h
index b8c6bb233ac1..796af83a963a 100644
--- a/include/uapi/linux/netfilter/x_tables.h
+++ b/include/uapi/linux/netfilter/x_tables.h
@@ -28,7 +28,7 @@ struct xt_entry_match {
 		__u16 match_size;
 	} u;
=20
-	unsigned char data[0];
+	unsigned char data[];
 };
=20
 struct xt_entry_target {
@@ -119,7 +119,7 @@ struct xt_counters_info {
 	unsigned int num_counters;
=20
 	/* The counters (actually `number' of these). */
-	struct xt_counters counters[0];
+	struct xt_counters counters[];
 };
=20
 #define XT_INV_PROTO		0x40	/* Invert the sense of PROTO. */
diff --git a/include/uapi/linux/netfilter_arp/arp_tables.h b/include/uapi/l=
inux/netfilter_arp/arp_tables.h
index bbf5af2b67a8..a6ac2463f787 100644
--- a/include/uapi/linux/netfilter_arp/arp_tables.h
+++ b/include/uapi/linux/netfilter_arp/arp_tables.h
@@ -109,7 +109,7 @@ struct arpt_entry
 	struct xt_counters counters;
=20
 	/* The matches (if any), then the target. */
-	unsigned char elems[0];
+	unsigned char elems[];
 };
=20
 /*
@@ -181,7 +181,7 @@ struct arpt_replace {
 	struct xt_counters __user *counters;
=20
 	/* The entries (hang off end: not really an array). */
-	struct arpt_entry entries[0];
+	struct arpt_entry entries[];
 };
=20
 /* The argument to ARPT_SO_GET_ENTRIES. */
@@ -193,7 +193,7 @@ struct arpt_get_entries {
 	unsigned int size;
=20
 	/* The entries. */
-	struct arpt_entry entrytable[0];
+	struct arpt_entry entrytable[];
 };
=20
 /* Helper functions */
diff --git a/include/uapi/linux/netfilter_bridge/ebt_among.h b/include/uapi=
/linux/netfilter_bridge/ebt_among.h
index 9acf757bc1f7..73b26a280c4f 100644
--- a/include/uapi/linux/netfilter_bridge/ebt_among.h
+++ b/include/uapi/linux/netfilter_bridge/ebt_among.h
@@ -40,7 +40,7 @@ struct ebt_mac_wormhash_tuple {
 struct ebt_mac_wormhash {
 	int table[257];
 	int poolsize;
-	struct ebt_mac_wormhash_tuple pool[0];
+	struct ebt_mac_wormhash_tuple pool[];
 };
=20
 #define ebt_mac_wormhash_size(x) ((x) ? sizeof(struct ebt_mac_wormhash) \
diff --git a/include/uapi/linux/netfilter_ipv4/ip_tables.h b/include/uapi/l=
inux/netfilter_ipv4/ip_tables.h
index 50c7fee625ae..1485df28b239 100644
--- a/include/uapi/linux/netfilter_ipv4/ip_tables.h
+++ b/include/uapi/linux/netfilter_ipv4/ip_tables.h
@@ -121,7 +121,7 @@ struct ipt_entry {
 	struct xt_counters counters;
=20
 	/* The matches (if any), then the target. */
-	unsigned char elems[0];
+	unsigned char elems[];
 };
=20
 /*
@@ -203,7 +203,7 @@ struct ipt_replace {
 	struct xt_counters __user *counters;
=20
 	/* The entries (hang off end: not really an array). */
-	struct ipt_entry entries[0];
+	struct ipt_entry entries[];
 };
=20
 /* The argument to IPT_SO_GET_ENTRIES. */
@@ -215,7 +215,7 @@ struct ipt_get_entries {
 	unsigned int size;
=20
 	/* The entries. */
-	struct ipt_entry entrytable[0];
+	struct ipt_entry entrytable[];
 };
=20
 /* Helper functions */
diff --git a/include/uapi/linux/netfilter_ipv6/ip6_tables.h b/include/uapi/=
linux/netfilter_ipv6/ip6_tables.h
index d9e364f96a5c..766e8e0bcc68 100644
--- a/include/uapi/linux/netfilter_ipv6/ip6_tables.h
+++ b/include/uapi/linux/netfilter_ipv6/ip6_tables.h
@@ -243,7 +243,7 @@ struct ip6t_replace {
 	struct xt_counters __user *counters;
=20
 	/* The entries (hang off end: not really an array). */
-	struct ip6t_entry entries[0];
+	struct ip6t_entry entries[];
 };
=20
 /* The argument to IP6T_SO_GET_ENTRIES. */
@@ -255,7 +255,7 @@ struct ip6t_get_entries {
 	unsigned int size;
=20
 	/* The entries. */
-	struct ip6t_entry entrytable[0];
+	struct ip6t_entry entrytable[];
 };
=20
 /* Helper functions */
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_even=
t.h
index d37629dbad72..4653834f078f 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -491,7 +491,7 @@ struct perf_event_query_bpf {
 	/*
 	 * User provided buffer to store program ids
 	 */
-	__u32	ids[0];
+	__u32	ids[];
 };
=20
 /*
diff --git a/include/uapi/linux/pkt_cls.h b/include/uapi/linux/pkt_cls.h
index 9a2ee1e39fad..ffbe230ef90b 100644
--- a/include/uapi/linux/pkt_cls.h
+++ b/include/uapi/linux/pkt_cls.h
@@ -256,7 +256,7 @@ struct tc_u32_sel {
=20
 	short			hoff;
 	__be32			hmask;
-	struct tc_u32_key	keys[0];
+	struct tc_u32_key	keys[];
 };
=20
 struct tc_u32_mark {
@@ -268,7 +268,7 @@ struct tc_u32_mark {
 struct tc_u32_pcnt {
 	__u64 rcnt;
 	__u64 rhit;
-	__u64 kcnts[0];
+	__u64 kcnts[];
 };
=20
 /* Flags */
diff --git a/include/uapi/linux/raid/md_p.h b/include/uapi/linux/raid/md_p.=
h
index e5a98a16f9b0..6c0aa577730f 100644
--- a/include/uapi/linux/raid/md_p.h
+++ b/include/uapi/linux/raid/md_p.h
@@ -303,7 +303,7 @@ struct mdp_superblock_1 {
 	 * into the 'roles' value.  If a device is spare or faulty, then it doesn=
't
 	 * have a meaningful role.
 	 */
-	__le16	dev_roles[0];	/* role in array, or 0xffff for a spare, or 0xfffe f=
or faulty */
+	__le16	dev_roles[];	/* role in array, or 0xffff for a spare, or 0xfffe fo=
r faulty */
 };
=20
 /* feature_map bits */
diff --git a/include/uapi/linux/random.h b/include/uapi/linux/random.h
index dcc1b3e6106f..e744c23582eb 100644
--- a/include/uapi/linux/random.h
+++ b/include/uapi/linux/random.h
@@ -41,7 +41,7 @@
 struct rand_pool_info {
 	int	entropy_count;
 	int	buf_size;
-	__u32	buf[0];
+	__u32	buf[];
 };
=20
 /*
diff --git a/include/uapi/linux/romfs_fs.h b/include/uapi/linux/romfs_fs.h
index a7f1585accef..6aa05e792454 100644
--- a/include/uapi/linux/romfs_fs.h
+++ b/include/uapi/linux/romfs_fs.h
@@ -27,7 +27,7 @@ struct romfs_super_block {
 	__be32 word1;
 	__be32 size;
 	__be32 checksum;
-	char name[0];		/* volume name */
+	char name[];		/* volume name */
 };
=20
 /* On disk inode */
@@ -37,7 +37,7 @@ struct romfs_inode {
 	__be32 spec;
 	__be32 size;
 	__be32 checksum;
-	char name[0];
+	char name[];
 };
=20
 #define ROMFH_TYPE 7
diff --git a/include/uapi/linux/rtnetlink.h b/include/uapi/linux/rtnetlink.=
h
index 83849a37db5b..eb2747d58a81 100644
--- a/include/uapi/linux/rtnetlink.h
+++ b/include/uapi/linux/rtnetlink.h
@@ -440,7 +440,7 @@ struct rtnexthop {
 /* RTA_VIA */
 struct rtvia {
 	__kernel_sa_family_t	rtvia_family;
-	__u8			rtvia_addr[0];
+	__u8			rtvia_addr[];
 };
=20
 /* RTM_CACHEINFO */
diff --git a/include/uapi/linux/sctp.h b/include/uapi/linux/sctp.h
index c4ff1ebd8bcc..ed7d4ecbf53d 100644
--- a/include/uapi/linux/sctp.h
+++ b/include/uapi/linux/sctp.h
@@ -365,7 +365,7 @@ struct sctp_assoc_change {
 	__u16 sac_outbound_streams;
 	__u16 sac_inbound_streams;
 	sctp_assoc_t sac_assoc_id;
-	__u8 sac_info[0];
+	__u8 sac_info[];
 };
=20
 /*
@@ -436,7 +436,7 @@ struct sctp_remote_error {
 	__u32 sre_length;
 	__be16 sre_error;
 	sctp_assoc_t sre_assoc_id;
-	__u8 sre_data[0];
+	__u8 sre_data[];
 };
=20
=20
@@ -453,7 +453,7 @@ struct sctp_send_failed {
 	__u32 ssf_error;
 	struct sctp_sndrcvinfo ssf_info;
 	sctp_assoc_t ssf_assoc_id;
-	__u8 ssf_data[0];
+	__u8 ssf_data[];
 };
=20
 struct sctp_send_failed_event {
@@ -463,7 +463,7 @@ struct sctp_send_failed_event {
 	__u32 ssf_error;
 	struct sctp_sndinfo ssfe_info;
 	sctp_assoc_t ssf_assoc_id;
-	__u8 ssf_data[0];
+	__u8 ssf_data[];
 };
=20
 /*
@@ -1029,7 +1029,7 @@ struct sctp_getaddrs_old {
 struct sctp_getaddrs {
 	sctp_assoc_t		assoc_id; /*input*/
 	__u32			addr_num; /*output*/
-	__u8			addrs[0]; /*output, variable size*/
+	__u8			addrs[]; /*output, variable size*/
 };
=20
 /* A socket user request obtained via SCTP_GET_ASSOC_STATS that retrieves
diff --git a/include/uapi/linux/seg6.h b/include/uapi/linux/seg6.h
index 286e8d6a8e98..13bcbc8bba32 100644
--- a/include/uapi/linux/seg6.h
+++ b/include/uapi/linux/seg6.h
@@ -30,7 +30,7 @@ struct ipv6_sr_hdr {
 	__u8	flags;
 	__u16	tag;
=20
-	struct in6_addr segments[0];
+	struct in6_addr segments[];
 };
=20
 #define SR6_FLAG1_PROTECTED	(1 << 6)
diff --git a/include/uapi/linux/seg6_iptunnel.h b/include/uapi/linux/seg6_i=
ptunnel.h
index eb815e0d0ac3..a74294211290 100644
--- a/include/uapi/linux/seg6_iptunnel.h
+++ b/include/uapi/linux/seg6_iptunnel.h
@@ -26,7 +26,7 @@ enum {
=20
 struct seg6_iptunnel_encap {
 	int mode;
-	struct ipv6_sr_hdr srh[0];
+	struct ipv6_sr_hdr srh[];
 };
=20
 #define SEG6_IPTUN_ENCAP_SIZE(x) ((sizeof(*x)) + (((x)->srh->hdrlen + 1) <=
< 3))
diff --git a/include/uapi/linux/stm.h b/include/uapi/linux/stm.h
index 7bac318b4440..de3579c2cff0 100644
--- a/include/uapi/linux/stm.h
+++ b/include/uapi/linux/stm.h
@@ -36,7 +36,7 @@ struct stp_policy_id {
 	/* padding */
 	__u16		__reserved_0;
 	__u32		__reserved_1;
-	char		id[0];
+	char		id[];
 };
=20
 #define STP_POLICY_ID_SET	_IOWR('%', 0, struct stp_policy_id)
diff --git a/include/uapi/linux/target_core_user.h b/include/uapi/linux/tar=
get_core_user.h
index 27ace512babd..fbd8ca67e107 100644
--- a/include/uapi/linux/target_core_user.h
+++ b/include/uapi/linux/target_core_user.h
@@ -152,7 +152,7 @@ struct tcmu_tmr_entry {
 	__u32 cmd_cnt;
 	__u64 __pad3;
 	__u64 __pad4;
-	__u16 cmd_ids[0];
+	__u16 cmd_ids[];
 } __packed;
=20
 #define TCMU_OP_ALIGN_SIZE sizeof(__u64)
diff --git a/include/uapi/linux/usb/audio.h b/include/uapi/linux/usb/audio.=
h
index 76b7c3f6cd0d..c917c53070d5 100644
--- a/include/uapi/linux/usb/audio.h
+++ b/include/uapi/linux/usb/audio.h
@@ -341,7 +341,7 @@ struct uac_feature_unit_descriptor {
 	__u8 bUnitID;
 	__u8 bSourceID;
 	__u8 bControlSize;
-	__u8 bmaControls[0]; /* variable length */
+	__u8 bmaControls[]; /* variable length */
 } __attribute__((packed));
=20
 static inline __u8 uac_feature_unit_iFeature(struct uac_feature_unit_descr=
iptor *desc)
diff --git a/include/uapi/linux/usb/cdc.h b/include/uapi/linux/usb/cdc.h
index 6d61550959ef..acf3852bb676 100644
--- a/include/uapi/linux/usb/cdc.h
+++ b/include/uapi/linux/usb/cdc.h
@@ -171,7 +171,7 @@ struct usb_cdc_mdlm_detail_desc {
=20
 	/* type is associated with mdlm_desc.bGUID */
 	__u8	bGuidDescriptorType;
-	__u8	bDetailData[0];
+	__u8	bDetailData[];
 } __attribute__ ((packed));
=20
 /* "OBEX Control Model Functional Descriptor" */
@@ -379,7 +379,7 @@ struct usb_cdc_ncm_ndp16 {
 	__le32	dwSignature;
 	__le16	wLength;
 	__le16	wNextNdpIndex;
-	struct	usb_cdc_ncm_dpe16 dpe16[0];
+	struct	usb_cdc_ncm_dpe16 dpe16[];
 } __attribute__ ((packed));
=20
 /* 32-bit NCM Datagram Pointer Entry */
@@ -395,7 +395,7 @@ struct usb_cdc_ncm_ndp32 {
 	__le16	wReserved6;
 	__le32	dwNextNdpIndex;
 	__le32	dwReserved12;
-	struct	usb_cdc_ncm_dpe32 dpe32[0];
+	struct	usb_cdc_ncm_dpe32 dpe32[];
 } __attribute__ ((packed));
=20
 /* CDC NCM subclass 3.2.1 and 3.2.2 */
diff --git a/include/uapi/linux/usb/ch9.h b/include/uapi/linux/usb/ch9.h
index 17ce56198c9a..31fcfa084e63 100644
--- a/include/uapi/linux/usb/ch9.h
+++ b/include/uapi/linux/usb/ch9.h
@@ -818,7 +818,7 @@ struct usb_key_descriptor {
=20
 	__u8  tTKID[3];
 	__u8  bReserved;
-	__u8  bKeyData[0];
+	__u8  bKeyData[];
 } __attribute__((packed));
=20
 /*------------------------------------------------------------------------=
-*/
diff --git a/include/uapi/linux/usb/raw_gadget.h b/include/uapi/linux/usb/r=
aw_gadget.h
index 0be685272eb1..c7d2199134d7 100644
--- a/include/uapi/linux/usb/raw_gadget.h
+++ b/include/uapi/linux/usb/raw_gadget.h
@@ -60,7 +60,7 @@ enum usb_raw_event_type {
 struct usb_raw_event {
 	__u32		type;
 	__u32		length;
-	__u8		data[0];
+	__u8		data[];
 };
=20
 #define USB_RAW_IO_FLAGS_ZERO	0x0001
@@ -90,7 +90,7 @@ struct usb_raw_ep_io {
 	__u16		ep;
 	__u16		flags;
 	__u32		length;
-	__u8		data[0];
+	__u8		data[];
 };
=20
 /* Maximum number of non-control endpoints in struct usb_raw_eps_info. */
diff --git a/include/uapi/linux/usbdevice_fs.h b/include/uapi/linux/usbdevi=
ce_fs.h
index cf525cddeb94..74a84e02422a 100644
--- a/include/uapi/linux/usbdevice_fs.h
+++ b/include/uapi/linux/usbdevice_fs.h
@@ -131,7 +131,7 @@ struct usbdevfs_urb {
 	unsigned int signr;	/* signal to be sent on completion,
 				  or 0 if none should be sent. */
 	void __user *usercontext;
-	struct usbdevfs_iso_packet_desc iso_frame_desc[0];
+	struct usbdevfs_iso_packet_desc iso_frame_desc[];
 };
=20
 /* ioctls for talking directly to drivers */
@@ -176,7 +176,7 @@ struct usbdevfs_disconnect_claim {
 struct usbdevfs_streams {
 	unsigned int num_streams; /* Not used by USBDEVFS_FREE_STREAMS */
 	unsigned int num_eps;
-	unsigned char eps[0];
+	unsigned char eps[];
 };
=20
 /*
diff --git a/include/uapi/linux/vhost_types.h b/include/uapi/linux/vhost_ty=
pes.h
index 634cee485abb..391331a10879 100644
--- a/include/uapi/linux/vhost_types.h
+++ b/include/uapi/linux/vhost_types.h
@@ -107,7 +107,7 @@ struct vhost_memory_region {
 struct vhost_memory {
 	__u32 nregions;
 	__u32 padding;
-	struct vhost_memory_region regions[0];
+	struct vhost_memory_region regions[];
 };
=20
 /* VHOST_SCSI specific definitions */
@@ -135,7 +135,7 @@ struct vhost_scsi_target {
 struct vhost_vdpa_config {
 	__u32 off;
 	__u32 len;
-	__u8 buf[0];
+	__u8 buf[];
 };
=20
 /* vhost vdpa IOVA range
diff --git a/include/uapi/linux/virtio_9p.h b/include/uapi/linux/virtio_9p.=
h
index 441047432258..374b68f8ac6e 100644
--- a/include/uapi/linux/virtio_9p.h
+++ b/include/uapi/linux/virtio_9p.h
@@ -38,7 +38,7 @@ struct virtio_9p_config {
 	/* length of the tag name */
 	__virtio16 tag_len;
 	/* non-NULL terminated tag name */
-	__u8 tag[0];
+	__u8 tag[];
 } __attribute__((packed));
=20
 #endif /* _LINUX_VIRTIO_9P_H */
diff --git a/include/uapi/linux/xfrm.h b/include/uapi/linux/xfrm.h
index 65e13a099b1a..e8191e0c3b56 100644
--- a/include/uapi/linux/xfrm.h
+++ b/include/uapi/linux/xfrm.h
@@ -33,7 +33,7 @@ struct xfrm_sec_ctx {
 	__u8	ctx_alg;
 	__u16	ctx_len;
 	__u32	ctx_sid;
-	char	ctx_str[0];
+	char	ctx_str[];
 };
=20
 /* Security Context Domains of Interpretation */
@@ -96,27 +96,27 @@ struct xfrm_replay_state_esn {
 	__u32		oseq_hi;
 	__u32		seq_hi;
 	__u32		replay_window;
-	__u32		bmp[0];
+	__u32		bmp[];
 };
=20
 struct xfrm_algo {
 	char		alg_name[64];
 	unsigned int	alg_key_len;    /* in bits */
-	char		alg_key[0];
+	char		alg_key[];
 };
=20
 struct xfrm_algo_auth {
 	char		alg_name[64];
 	unsigned int	alg_key_len;    /* in bits */
 	unsigned int	alg_trunc_len;  /* in bits */
-	char		alg_key[0];
+	char		alg_key[];
 };
=20
 struct xfrm_algo_aead {
 	char		alg_name[64];
 	unsigned int	alg_key_len;	/* in bits */
 	unsigned int	alg_icv_len;	/* in bits */
-	char		alg_key[0];
+	char		alg_key[];
 };
=20
 struct xfrm_stats {
diff --git a/include/uapi/rdma/hfi/hfi1_user.h b/include/uapi/rdma/hfi/hfi1=
_user.h
index d95ef9a2b032..1106a7c90b29 100644
--- a/include/uapi/rdma/hfi/hfi1_user.h
+++ b/include/uapi/rdma/hfi/hfi1_user.h
@@ -180,7 +180,7 @@ struct hfi1_sdma_comp_entry {
 struct hfi1_status {
 	__aligned_u64 dev;      /* device/hw status bits */
 	__aligned_u64 port;     /* port state and status bits */
-	char freezemsg[0];
+	char freezemsg[];
 };
=20
 enum sdma_req_opcode {
diff --git a/include/uapi/rdma/ib_user_verbs.h b/include/uapi/rdma/ib_user_=
verbs.h
index 7dd903d932e5..43672cb1fd57 100644
--- a/include/uapi/rdma/ib_user_verbs.h
+++ b/include/uapi/rdma/ib_user_verbs.h
@@ -158,18 +158,18 @@ struct ib_uverbs_ex_cmd_hdr {
=20
 struct ib_uverbs_get_context {
 	__aligned_u64 response;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_get_context_resp {
 	__u32 async_fd;
 	__u32 num_comp_vectors;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_device {
 	__aligned_u64 response;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_device_resp {
@@ -278,7 +278,7 @@ struct ib_uverbs_query_port {
 	__aligned_u64 response;
 	__u8  port_num;
 	__u8  reserved[7];
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_port_resp {
@@ -308,12 +308,12 @@ struct ib_uverbs_query_port_resp {
=20
 struct ib_uverbs_alloc_pd {
 	__aligned_u64 response;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_alloc_pd_resp {
 	__u32 pd_handle;
-	__u32 driver_data[0];
+	__u32 driver_data[];
 };
=20
 struct ib_uverbs_dealloc_pd {
@@ -324,12 +324,12 @@ struct ib_uverbs_open_xrcd {
 	__aligned_u64 response;
 	__u32 fd;
 	__u32 oflags;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_open_xrcd_resp {
 	__u32 xrcd_handle;
-	__u32 driver_data[0];
+	__u32 driver_data[];
 };
=20
 struct ib_uverbs_close_xrcd {
@@ -343,14 +343,14 @@ struct ib_uverbs_reg_mr {
 	__aligned_u64 hca_va;
 	__u32 pd_handle;
 	__u32 access_flags;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_reg_mr_resp {
 	__u32 mr_handle;
 	__u32 lkey;
 	__u32 rkey;
-	__u32 driver_data[0];
+	__u32 driver_data[];
 };
=20
 struct ib_uverbs_rereg_mr {
@@ -362,13 +362,13 @@ struct ib_uverbs_rereg_mr {
 	__aligned_u64 hca_va;
 	__u32 pd_handle;
 	__u32 access_flags;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_rereg_mr_resp {
 	__u32 lkey;
 	__u32 rkey;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_dereg_mr {
@@ -380,13 +380,13 @@ struct ib_uverbs_alloc_mw {
 	__u32 pd_handle;
 	__u8  mw_type;
 	__u8  reserved[3];
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_alloc_mw_resp {
 	__u32 mw_handle;
 	__u32 rkey;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_dealloc_mw {
@@ -408,7 +408,7 @@ struct ib_uverbs_create_cq {
 	__u32 comp_vector;
 	__s32 comp_channel;
 	__u32 reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 enum ib_uverbs_ex_create_cq_flags {
@@ -442,13 +442,13 @@ struct ib_uverbs_resize_cq {
 	__aligned_u64 response;
 	__u32 cq_handle;
 	__u32 cqe;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_resize_cq_resp {
 	__u32 cqe;
 	__u32 reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_poll_cq {
@@ -492,7 +492,7 @@ struct ib_uverbs_wc {
 struct ib_uverbs_poll_cq_resp {
 	__u32 count;
 	__u32 reserved;
-	struct ib_uverbs_wc wc[0];
+	struct ib_uverbs_wc wc[];
 };
=20
 struct ib_uverbs_req_notify_cq {
@@ -585,7 +585,7 @@ struct ib_uverbs_create_qp {
 	__u8  qp_type;
 	__u8  is_srq;
 	__u8  reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 enum ib_uverbs_create_qp_mask {
@@ -624,7 +624,7 @@ struct ib_uverbs_open_qp {
 	__u32 qpn;
 	__u8  qp_type;
 	__u8  reserved[7];
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 /* also used for open response */
@@ -669,7 +669,7 @@ struct ib_uverbs_query_qp {
 	__aligned_u64 response;
 	__u32 qp_handle;
 	__u32 attr_mask;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_qp_resp {
@@ -703,7 +703,7 @@ struct ib_uverbs_query_qp_resp {
 	__u8  alt_timeout;
 	__u8  sq_sig_all;
 	__u8  reserved[5];
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_modify_qp {
@@ -824,7 +824,7 @@ struct ib_uverbs_post_send {
 	__u32 wr_count;
 	__u32 sge_count;
 	__u32 wqe_size;
-	struct ib_uverbs_send_wr send_wr[0];
+	struct ib_uverbs_send_wr send_wr[];
 };
=20
 struct ib_uverbs_post_send_resp {
@@ -843,7 +843,7 @@ struct ib_uverbs_post_recv {
 	__u32 wr_count;
 	__u32 sge_count;
 	__u32 wqe_size;
-	struct ib_uverbs_recv_wr recv_wr[0];
+	struct ib_uverbs_recv_wr recv_wr[];
 };
=20
 struct ib_uverbs_post_recv_resp {
@@ -856,7 +856,7 @@ struct ib_uverbs_post_srq_recv {
 	__u32 wr_count;
 	__u32 sge_count;
 	__u32 wqe_size;
-	struct ib_uverbs_recv_wr recv[0];
+	struct ib_uverbs_recv_wr recv[];
 };
=20
 struct ib_uverbs_post_srq_recv_resp {
@@ -869,12 +869,12 @@ struct ib_uverbs_create_ah {
 	__u32 pd_handle;
 	__u32 reserved;
 	struct ib_uverbs_ah_attr attr;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_create_ah_resp {
 	__u32 ah_handle;
-	__u32 driver_data[0];
+	__u32 driver_data[];
 };
=20
 struct ib_uverbs_destroy_ah {
@@ -886,7 +886,7 @@ struct ib_uverbs_attach_mcast {
 	__u32 qp_handle;
 	__u16 mlid;
 	__u16 reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_detach_mcast {
@@ -894,7 +894,7 @@ struct ib_uverbs_detach_mcast {
 	__u32 qp_handle;
 	__u16 mlid;
 	__u16 reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_flow_spec_hdr {
@@ -1135,7 +1135,7 @@ struct ib_uverbs_flow_attr {
 	 * struct ib_flow_spec_xxx
 	 * struct ib_flow_spec_yyy
 	 */
-	struct ib_uverbs_flow_spec_hdr flow_specs[0];
+	struct ib_uverbs_flow_spec_hdr flow_specs[];
 };
=20
 struct ib_uverbs_create_flow  {
@@ -1161,7 +1161,7 @@ struct ib_uverbs_create_srq {
 	__u32 max_wr;
 	__u32 max_sge;
 	__u32 srq_limit;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_create_xsrq {
@@ -1175,7 +1175,7 @@ struct ib_uverbs_create_xsrq {
 	__u32 max_num_tags;
 	__u32 xrcd_handle;
 	__u32 cq_handle;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_create_srq_resp {
@@ -1183,7 +1183,7 @@ struct ib_uverbs_create_srq_resp {
 	__u32 max_wr;
 	__u32 max_sge;
 	__u32 srqn;
-	__u32 driver_data[0];
+	__u32 driver_data[];
 };
=20
 struct ib_uverbs_modify_srq {
@@ -1191,14 +1191,14 @@ struct ib_uverbs_modify_srq {
 	__u32 attr_mask;
 	__u32 max_wr;
 	__u32 srq_limit;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_srq {
 	__aligned_u64 response;
 	__u32 srq_handle;
 	__u32 reserved;
-	__aligned_u64 driver_data[0];
+	__aligned_u64 driver_data[];
 };
=20
 struct ib_uverbs_query_srq_resp {
@@ -1269,7 +1269,7 @@ struct ib_uverbs_ex_create_rwq_ind_table  {
 	 * wq_handle1
 	 * wq_handle2
 	 */
-	__u32 wq_handles[0];
+	__u32 wq_handles[];
 };
=20
 struct ib_uverbs_ex_create_rwq_ind_table_resp {
diff --git a/include/uapi/rdma/rdma_user_cm.h b/include/uapi/rdma/rdma_user=
_cm.h
index ed5a514305c1..7cea03581f79 100644
--- a/include/uapi/rdma/rdma_user_cm.h
+++ b/include/uapi/rdma/rdma_user_cm.h
@@ -184,7 +184,7 @@ struct rdma_ucm_query_addr_resp {
 struct rdma_ucm_query_path_resp {
 	__u32 num_paths;
 	__u32 reserved;
-	struct ib_path_rec_data path_data[0];
+	struct ib_path_rec_data path_data[];
 };
=20
 struct rdma_ucm_conn_param {
diff --git a/include/uapi/rdma/rdma_user_ioctl_cmds.h b/include/uapi/rdma/r=
dma_user_ioctl_cmds.h
index 38ab7accb7be..ab1aef17feb1 100644
--- a/include/uapi/rdma/rdma_user_ioctl_cmds.h
+++ b/include/uapi/rdma/rdma_user_ioctl_cmds.h
@@ -81,7 +81,7 @@ struct ib_uverbs_ioctl_hdr {
 	__aligned_u64 reserved1;
 	__u32 driver_id;
 	__u32 reserved2;
-	struct ib_uverbs_attr  attrs[0];
+	struct ib_uverbs_attr  attrs[];
 };
=20
 #endif
diff --git a/include/uapi/scsi/fc/fc_els.h b/include/uapi/scsi/fc/fc_els.h
index c9812c5c2fc4..16782c360de3 100644
--- a/include/uapi/scsi/fc/fc_els.h
+++ b/include/uapi/scsi/fc/fc_els.h
@@ -264,7 +264,7 @@ struct fc_tlv_desc {
 					 * Size of descriptor excluding
 					 * desc_tag and desc_len fields.
 					 */
-	__u8		desc_value[0];  /* Descriptor Value */
+	__u8		desc_value[];  /* Descriptor Value */
 };
=20
 /* Descriptor tag and len fields are considered the mandatory header
@@ -1027,7 +1027,7 @@ struct fc_fn_li_desc {
 					 * threshold to caause the LI event
 					 */
 	__be32		pname_count;	/* number of portname_list elements */
-	__be64		pname_list[0];	/* list of N_Port_Names accessible
+	__be64		pname_list[];	/* list of N_Port_Names accessible
 					 * through the attached port
 					 */
 };
@@ -1069,7 +1069,7 @@ struct fc_fn_peer_congn_desc {
 					 * congestion event
 					 */
 	__be32		pname_count;	/* number of portname_list elements */
-	__be64		pname_list[0];	/* list of N_Port_Names accessible
+	__be64		pname_list[];	/* list of N_Port_Names accessible
 					 * through the attached port
 					 */
 };
@@ -1104,7 +1104,7 @@ struct fc_els_fpin {
 					 * Size of ELS excluding fpin_cmd,
 					 * fpin_zero and desc_len fields.
 					 */
-	struct fc_tlv_desc	fpin_desc[0];	/* Descriptor list */
+	struct fc_tlv_desc	fpin_desc[];	/* Descriptor list */
 };
=20
 /* Diagnostic Function Descriptor - FPIN Registration */
@@ -1115,7 +1115,7 @@ struct fc_df_desc_fpin_reg {
 					 * desc_tag and desc_len fields.
 					 */
 	__be32		count;		/* Number of desc_tags elements */
-	__be32		desc_tags[0];	/* Array of Descriptor Tags.
+	__be32		desc_tags[];	/* Array of Descriptor Tags.
 					 * Each tag indicates a function
 					 * supported by the N_Port (request)
 					 * or by the  N_Port and Fabric
@@ -1135,7 +1135,7 @@ struct fc_els_rdf {
 					 * Size of ELS excluding fpin_cmd,
 					 * fpin_zero and desc_len fields.
 					 */
-	struct fc_tlv_desc	desc[0];	/* Descriptor list */
+	struct fc_tlv_desc	desc[];	/* Descriptor list */
 };
=20
 /*
@@ -1148,7 +1148,7 @@ struct fc_els_rdf_resp {
 						 * and desc_list_len fields.
 						 */
 	struct fc_els_lsri_desc	lsri;
-	struct fc_tlv_desc	desc[0];	/* Supported Descriptor list */
+	struct fc_tlv_desc	desc[];	/* Supported Descriptor list */
 };
=20
=20
@@ -1231,7 +1231,7 @@ struct fc_els_edc {
 					 * Size of ELS excluding edc_cmd,
 					 * edc_zero and desc_len fields.
 					 */
-	struct fc_tlv_desc	desc[0];
+	struct fc_tlv_desc	desc[];
 					/* Diagnostic Descriptor list */
 };
=20
@@ -1245,7 +1245,7 @@ struct fc_els_edc_resp {
 						 * and desc_list_len fields.
 						 */
 	struct fc_els_lsri_desc	lsri;
-	struct fc_tlv_desc	desc[0];
+	struct fc_tlv_desc	desc[];
 				    /* Supported Diagnostic Descriptor list */
 };
=20
diff --git a/include/uapi/scsi/scsi_bsg_fc.h b/include/uapi/scsi/scsi_bsg_f=
c.h
index 3ae65e93235c..7f5930801f72 100644
--- a/include/uapi/scsi/scsi_bsg_fc.h
+++ b/include/uapi/scsi/scsi_bsg_fc.h
@@ -209,7 +209,7 @@ struct fc_bsg_host_vendor {
 	__u64 vendor_id;
=20
 	/* start of vendor command area */
-	__u32 vendor_cmd[0];
+	__u32 vendor_cmd[];
 };
=20
 /* Response:
diff --git a/include/uapi/sound/asound.h b/include/uapi/sound/asound.h
index 2d3e5df39a59..3974a2a911cc 100644
--- a/include/uapi/sound/asound.h
+++ b/include/uapi/sound/asound.h
@@ -1106,7 +1106,7 @@ struct snd_ctl_elem_value {
 struct snd_ctl_tlv {
 	unsigned int numid;	/* control element numeric identification */
 	unsigned int length;	/* in bytes aligned to 4 */
-	unsigned int tlv[0];	/* first TLV */
+	unsigned int tlv[];	/* first TLV */
 };
=20
 #define SNDRV_CTL_IOCTL_PVERSION	_IOR('U', 0x00, int)
diff --git a/include/uapi/sound/firewire.h b/include/uapi/sound/firewire.h
index 39cf6eb75940..3532ac7046d7 100644
--- a/include/uapi/sound/firewire.h
+++ b/include/uapi/sound/firewire.h
@@ -38,11 +38,11 @@ struct snd_efw_transaction {
 	__be32 category;
 	__be32 command;
 	__be32 status;
-	__be32 params[0];
+	__be32 params[];
 };
 struct snd_firewire_event_efw_response {
 	unsigned int type;
-	__be32 response[0];	/* some responses */
+	__be32 response[];	/* some responses */
 };
=20
 struct snd_firewire_event_digi00x_message {
@@ -63,7 +63,7 @@ struct snd_firewire_tascam_change {
=20
 struct snd_firewire_event_tascam_control {
 	unsigned int type;
-	struct snd_firewire_tascam_change changes[0];
+	struct snd_firewire_tascam_change changes[];
 };
=20
 struct snd_firewire_event_motu_register_dsp_change {
diff --git a/include/uapi/sound/skl-tplg-interface.h b/include/uapi/sound/s=
kl-tplg-interface.h
index a93c0decfdd5..f29899b179a6 100644
--- a/include/uapi/sound/skl-tplg-interface.h
+++ b/include/uapi/sound/skl-tplg-interface.h
@@ -151,7 +151,7 @@ struct skl_dfw_algo_data {
 	__u32 rsvd:30;
 	__u32 param_id;
 	__u32 max;
-	char params[0];
+	char params[];
 } __packed;
=20
 enum skl_tkn_dir {
diff --git a/include/uapi/sound/sof/header.h b/include/uapi/sound/sof/heade=
r.h
index 5f4518e7a972..dbf137516522 100644
--- a/include/uapi/sound/sof/header.h
+++ b/include/uapi/sound/sof/header.h
@@ -23,7 +23,7 @@ struct sof_abi_hdr {
 	__u32 size;		/**< size in bytes of data excl. this struct */
 	__u32 abi;		/**< SOF ABI version */
 	__u32 reserved[4];	/**< reserved for future use */
-	__u32 data[0];		/**< Component data - opaque to core */
+	__u32 data[];		/**< Component data - opaque to core */
 }  __packed;
=20
 #endif
diff --git a/include/uapi/sound/usb_stream.h b/include/uapi/sound/usb_strea=
m.h
index 95419d8bbc16..ffdd3ea1e31d 100644
--- a/include/uapi/sound/usb_stream.h
+++ b/include/uapi/sound/usb_stream.h
@@ -61,7 +61,7 @@ struct usb_stream {
 	unsigned		 inpacket_split_at;
 	unsigned		 next_inpacket_split;
 	unsigned		 next_inpacket_split_at;
-	struct usb_stream_packet inpacket[0];
+	struct usb_stream_packet inpacket[];
 };
=20
 enum usb_stream_state {
diff --git a/tools/arch/x86/include/uapi/asm/kvm.h b/tools/arch/x86/include=
/uapi/asm/kvm.h
index bf6e96011dfe..e135f4dcb19d 100644
--- a/tools/arch/x86/include/uapi/asm/kvm.h
+++ b/tools/arch/x86/include/uapi/asm/kvm.h
@@ -198,13 +198,13 @@ struct kvm_msrs {
 	__u32 nmsrs; /* number of msrs in entries */
 	__u32 pad;
=20
-	struct kvm_msr_entry entries[0];
+	struct kvm_msr_entry entries[];
 };
=20
 /* for KVM_GET_MSR_INDEX_LIST */
 struct kvm_msr_list {
 	__u32 nmsrs; /* number of msrs in entries */
-	__u32 indices[0];
+	__u32 indices[];
 };
=20
 /* Maximum size of any access bitmap in bytes */
@@ -241,7 +241,7 @@ struct kvm_cpuid_entry {
 struct kvm_cpuid {
 	__u32 nent;
 	__u32 padding;
-	struct kvm_cpuid_entry entries[0];
+	struct kvm_cpuid_entry entries[];
 };
=20
 struct kvm_cpuid_entry2 {
@@ -263,7 +263,7 @@ struct kvm_cpuid_entry2 {
 struct kvm_cpuid2 {
 	__u32 nent;
 	__u32 padding;
-	struct kvm_cpuid_entry2 entries[0];
+	struct kvm_cpuid_entry2 entries[];
 };
=20
 /* for KVM_GET_PIT and KVM_SET_PIT */
@@ -389,7 +389,7 @@ struct kvm_xsave {
 	 * the contents of CPUID leaf 0xD on the host.
 	 */
 	__u32 region[1024];
-	__u32 extra[0];
+	__u32 extra[];
 };
=20
 #define KVM_MAX_XCRS	16
@@ -515,7 +515,7 @@ struct kvm_pmu_event_filter {
 	__u32 fixed_counter_bitmap;
 	__u32 flags;
 	__u32 pad[4];
-	__u64 events[0];
+	__u64 events[];
 };
=20
 #define KVM_PMU_EVENT_ALLOW 0
diff --git a/tools/include/uapi/drm/i915_drm.h b/tools/include/uapi/drm/i91=
5_drm.h
index 05c3642aaece..239b91b13c60 100644
--- a/tools/include/uapi/drm/i915_drm.h
+++ b/tools/include/uapi/drm/i915_drm.h
@@ -2060,7 +2060,7 @@ struct i915_context_engines_load_balance {
=20
 	__u64 mbz64; /* reserved for future use; must be zero */
=20
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
 } __attribute__((packed));
=20
 #define I915_DEFINE_CONTEXT_ENGINES_LOAD_BALANCE(name__, N__) struct { \
@@ -2098,7 +2098,7 @@ struct i915_context_engines_bond {
 	__u64 flags; /* all undefined flags must be zero */
 	__u64 mbz64[4]; /* reserved for future use; must be zero */
=20
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
 } __attribute__((packed));
=20
 #define I915_DEFINE_CONTEXT_ENGINES_BOND(name__, N__) struct { \
@@ -2225,7 +2225,7 @@ struct i915_context_engines_parallel_submit {
 	 * length =3D width (i) * num_siblings (j)
 	 * index =3D j + i * num_siblings
 	 */
-	struct i915_engine_class_instance engines[0];
+	struct i915_engine_class_instance engines[];
=20
 } __packed;
=20
diff --git a/tools/include/uapi/linux/bpf.h b/tools/include/uapi/linux/bpf.=
h
index f4009dbdf62d..e4b33ba06f00 100644
--- a/tools/include/uapi/linux/bpf.h
+++ b/tools/include/uapi/linux/bpf.h
@@ -79,7 +79,7 @@ struct bpf_insn {
 /* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
 struct bpf_lpm_trie_key {
 	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
-	__u8	data[0];	/* Arbitrary size */
+	__u8	data[];	/* Arbitrary size */
 };
=20
 struct bpf_cgroup_storage_key {
diff --git a/tools/include/uapi/linux/fs.h b/tools/include/uapi/linux/fs.h
index bdf7b404b3e7..b7b56871029c 100644
--- a/tools/include/uapi/linux/fs.h
+++ b/tools/include/uapi/linux/fs.h
@@ -90,7 +90,7 @@ struct file_dedupe_range {
 	__u16 dest_count;	/* in - total elements in info array */
 	__u16 reserved1;	/* must be zero */
 	__u32 reserved2;	/* must be zero */
-	struct file_dedupe_range_info info[0];
+	struct file_dedupe_range_info info[];
 };
=20
 /* And dynamically-tunable limits and defaults: */
diff --git a/tools/include/uapi/linux/if_tun.h b/tools/include/uapi/linux/i=
f_tun.h
index 454ae31b93c7..2ec07de1d73b 100644
--- a/tools/include/uapi/linux/if_tun.h
+++ b/tools/include/uapi/linux/if_tun.h
@@ -108,7 +108,7 @@ struct tun_pi {
 struct tun_filter {
 	__u16  flags; /* TUN_FLT_ flags see above */
 	__u16  count; /* Number of addresses */
-	__u8   addr[0][ETH_ALEN];
+	__u8   addr[][ETH_ALEN];
 };
=20
 #endif /* _UAPI__IF_TUN_H */
diff --git a/tools/include/uapi/linux/kvm.h b/tools/include/uapi/linux/kvm.=
h
index 6a184d260c7f..37ce8cbac322 100644
--- a/tools/include/uapi/linux/kvm.h
+++ b/tools/include/uapi/linux/kvm.h
@@ -539,7 +539,7 @@ struct kvm_coalesced_mmio {
=20
 struct kvm_coalesced_mmio_ring {
 	__u32 first, last;
-	struct kvm_coalesced_mmio coalesced_mmio[0];
+	struct kvm_coalesced_mmio coalesced_mmio[];
 };
=20
 #define KVM_COALESCED_MMIO_MAX \
@@ -618,7 +618,7 @@ struct kvm_clear_dirty_log {
 /* for KVM_SET_SIGNAL_MASK */
 struct kvm_signal_mask {
 	__u32 len;
-	__u8  sigset[0];
+	__u8  sigset[];
 };
=20
 /* for KVM_TPR_ACCESS_REPORTING */
@@ -1216,7 +1216,7 @@ struct kvm_irq_routing_entry {
 struct kvm_irq_routing {
 	__u32 nr;
 	__u32 flags;
-	struct kvm_irq_routing_entry entries[0];
+	struct kvm_irq_routing_entry entries[];
 };
=20
 #endif
@@ -1335,7 +1335,7 @@ struct kvm_dirty_tlb {
=20
 struct kvm_reg_list {
 	__u64 n; /* number of regs */
-	__u64 reg[0];
+	__u64 reg[];
 };
=20
 struct kvm_one_reg {
diff --git a/tools/include/uapi/linux/perf_event.h b/tools/include/uapi/lin=
ux/perf_event.h
index d37629dbad72..4653834f078f 100644
--- a/tools/include/uapi/linux/perf_event.h
+++ b/tools/include/uapi/linux/perf_event.h
@@ -491,7 +491,7 @@ struct perf_event_query_bpf {
 	/*
 	 * User provided buffer to store program ids
 	 */
-	__u32	ids[0];
+	__u32	ids[];
 };
=20
 /*
diff --git a/tools/include/uapi/linux/pkt_cls.h b/tools/include/uapi/linux/=
pkt_cls.h
index 12153771396a..3faee0199a9b 100644
--- a/tools/include/uapi/linux/pkt_cls.h
+++ b/tools/include/uapi/linux/pkt_cls.h
@@ -180,7 +180,7 @@ struct tc_u32_sel {
=20
 	short			hoff;
 	__be32			hmask;
-	struct tc_u32_key	keys[0];
+	struct tc_u32_key	keys[];
 };
=20
 struct tc_u32_mark {
@@ -192,7 +192,7 @@ struct tc_u32_mark {
 struct tc_u32_pcnt {
 	__u64 rcnt;
 	__u64 rhit;
-	__u64 kcnts[0];
+	__u64 kcnts[];
 };
=20
 /* Flags */
diff --git a/tools/include/uapi/linux/seg6.h b/tools/include/uapi/linux/seg=
6.h
index 286e8d6a8e98..f94baf154c47 100644
--- a/tools/include/uapi/linux/seg6.h
+++ b/tools/include/uapi/linux/seg6.h
@@ -30,7 +30,7 @@ struct ipv6_sr_hdr {
 	__u8	flags;
 	__u16	tag;
=20
-	struct in6_addr segments[0];
+	struct in6_addr segments[];
 };
=20
 #define SR6_FLAG1_PROTECTED	(1 << 6)
@@ -49,7 +49,7 @@ struct ipv6_sr_hdr {
 struct sr6_tlv {
 	__u8 type;
 	__u8 len;
-	__u8 data[0];
+	__u8 data[];
 };
=20
 #endif
diff --git a/tools/include/uapi/linux/usbdevice_fs.h b/tools/include/uapi/l=
inux/usbdevice_fs.h
index cf525cddeb94..74a84e02422a 100644
--- a/tools/include/uapi/linux/usbdevice_fs.h
+++ b/tools/include/uapi/linux/usbdevice_fs.h
@@ -131,7 +131,7 @@ struct usbdevfs_urb {
 	unsigned int signr;	/* signal to be sent on completion,
 				  or 0 if none should be sent. */
 	void __user *usercontext;
-	struct usbdevfs_iso_packet_desc iso_frame_desc[0];
+	struct usbdevfs_iso_packet_desc iso_frame_desc[];
 };
=20
 /* ioctls for talking directly to drivers */
@@ -176,7 +176,7 @@ struct usbdevfs_disconnect_claim {
 struct usbdevfs_streams {
 	unsigned int num_streams; /* Not used by USBDEVFS_FREE_STREAMS */
 	unsigned int num_eps;
-	unsigned char eps[0];
+	unsigned char eps[];
 };
=20
 /*
diff --git a/tools/include/uapi/sound/asound.h b/tools/include/uapi/sound/a=
sound.h
index 2d3e5df39a59..3974a2a911cc 100644
--- a/tools/include/uapi/sound/asound.h
+++ b/tools/include/uapi/sound/asound.h
@@ -1106,7 +1106,7 @@ struct snd_ctl_elem_value {
 struct snd_ctl_tlv {
 	unsigned int numid;	/* control element numeric identification */
 	unsigned int length;	/* in bytes aligned to 4 */
-	unsigned int tlv[0];	/* first TLV */
+	unsigned int tlv[];	/* first TLV */
 };
=20
 #define SNDRV_CTL_IOCTL_PVERSION	_IOR('U', 0x00, int)
--=20
2.27.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220627180432.GA136081%40embeddedor.
