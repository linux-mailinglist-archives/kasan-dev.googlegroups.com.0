Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBJWFUSNAMGQEMCZZSAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 548295FEAEE
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:43 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf1827487ljj.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737383; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUV3GcjQidl5klnwlOs7pMOd2m45Mbt4P6jCQlWKsVTReO8xbJkLFEAXOlOySujDjx
         XB/oGUaLv16tpQzEUhfMbmXqgyP26i5EI8ci+IqOYEjWUD51wUdfuqd0lbap59xibKMo
         RzN0B5VO5UprbWiaEtTGEaslwsD+22l2frLvdiLofkyo3F/GmpM4ZgJoKQkB7fiTPVPE
         XXdLjRAgwI0Z8+JJvEgL+XvYbRXB6hHU7akh8G01/9cGwTzS7uphaPIpJiJ+m475TnRZ
         Fs137uG3QrTf8Xyjz5xK1yltITYabb6QmAiuDKw/w3RS3+2KymRmsDpDlZPkFEVT2fsg
         b8iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=dTdhgTZqBs/HoI2EvMcLSkcH5Kf2mEzKmVayeI3j2jQ=;
        b=b3H4dejVAVamH6vSZLZk3FO4rR2suJTRk/+m81PXxVApNzfgxTvrGRTIb977rx/Dox
         RjXbpP+KrlyN52+2KcnVo7Bb3H+XP64HGzA5RZx6FY/1PjOC5w0gMmmOkzW7Xhxiu4+Z
         KdS8Xyx/wz+WBAtv5H0w+AD1P1bPxCANmZLGHB7+JQEKFcTjVGJ9pOSZjz+FgQCpkIfU
         sBvsCEGK19u2iSaGDp1g6yOT+k/CJ9zDLkJZ6PRFsA3c/CkxCvBrENGudXxHhXIx7Ooj
         N5bwf+50qx7zVOLzRG6KF68Apv6hWLIjbdgFO6R7haVXExmfwEs4l2mTDqnfaWyiPrGM
         Rfzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=N9gYQbXa;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dTdhgTZqBs/HoI2EvMcLSkcH5Kf2mEzKmVayeI3j2jQ=;
        b=iKKdD0UuVuo74vh7aYtNTMl9z/+E9O2w4zWQOowbTAksAzW+7p1EfgG5IUEW3HcrRE
         O48jfdER+MQOCdTR6EddzYnCqAeCn6CqZTH/lp8dikTASHex9PBFnXr2UZvn0r51nzW8
         hKBwFOg9SUpEsKvrIAb5j8U1cSEO3Iu9Kx1ka8rRErnxpd0J7T8UyLZhnkmYG4B9YvyT
         o1ucJvjscz8ds1cy3DGUyO9lNuBWBc0cgbuePd7e3MkZXsIKzZRq/wK4dntkBNS+x5nB
         3SmZQLXqlP//FBI89ePLVlBdccu0RiV5JIDwgcv2SdcyKw4XNBsOguEdYQmvSvfmK6/3
         aiRQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dTdhgTZqBs/HoI2EvMcLSkcH5Kf2mEzKmVayeI3j2jQ=;
        b=lZMB11WT4dHtw9S5PZBWaeGENwb5+jUdXmuKb/7GFc19nSn0bATwakXlphra0iIVn+
         2pGqAMnmcGwpGAlP7j29tn+1tpMMWksnz61MkKYwxXxF0W/HGQeB/j09PSKvBz6hf+fY
         VpOeqBiuQrtWEzgsApOtPs8KG9v7sa0HgNSLZ7Gqa3L/0dITxic1UmQD56fKKCNlcPVo
         e9Oa35Dno867yW+tyH4Stq19tj0VXHzhMzBkqDIzzzPg06dNIm7V3NDjmZ8Bg54VH/va
         GP05nDkyqeIVZ5WXXr3mplQje2cmH0X4R/quJ5HEt/GzOlPiSLt9MDMQa4hWyHFqJR04
         vcww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dTdhgTZqBs/HoI2EvMcLSkcH5Kf2mEzKmVayeI3j2jQ=;
        b=shFxRqDC2nYLnemQZ8boDucahvyhFZNzzid59j0GXFx77ShmUSSHi/fSQ1QxHo6HkZ
         vuOM5Ef66s9ya6u6Lbx4dn08oEh9DBqRy+E9CfMwcU+7xzFptZrllbsyvB2g7XULjJoV
         D9MZhQHp0ou19Iqo+0noA4/p3E4A2INRUNdNGhj8w+v4ZnbEubRz7kYMUuTRGdUtSApr
         kFxg3PA9edllqm2FrhGsIICEP0GymT+WW4IM9E6S230hbfs1/efM0HhZvfD+zO2fMMUK
         +2HG555+fe07HbxPS1a5xCysLZN2CM4TWh0TZ8fnaBrFfWqbZB4nBdpwXjdbhciJhoEa
         mqbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1wLyBBnylzbQeyTG1oPdrBM7CTH3HRtAuXQbUWrdoD7XWWYFnq
	qXAEYm5VJsC1ZXIK9tAxTtg=
X-Google-Smtp-Source: AMsMyM4qYuD0U7LR5cYG8CkhbgoLxAStaZC6tyanbVu6KKvXkvd6DQjOt5/9sUepgvWCHHrogCIGQQ==
X-Received: by 2002:a2e:2d0a:0:b0:26c:a1c:cdf with SMTP id t10-20020a2e2d0a000000b0026c0a1c0cdfmr1544453ljt.352.1665737382650;
        Fri, 14 Oct 2022 01:49:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:150f:b0:26e:76e9:3567 with SMTP id
 e15-20020a05651c150f00b0026e76e93567ls887158ljf.11.-pod-prod-gmail; Fri, 14
 Oct 2022 01:49:41 -0700 (PDT)
X-Received: by 2002:a2e:9f16:0:b0:26e:6fd:980c with SMTP id u22-20020a2e9f16000000b0026e06fd980cmr1309346ljk.145.1665737381458;
        Fri, 14 Oct 2022 01:49:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737381; cv=none;
        d=google.com; s=arc-20160816;
        b=q4cv/UZ0CAdRJOGVFH5qW+S+/C+xo04yQ053886l/KxsOXn7gx00dkcg9xrYfTz3Kd
         t509u0qGAvMNrt4HCd9P5wTXADZAOsGPeoOovy0B9sQzvPSTvbQG4MS1L95qWhH901cP
         ywAkAQkUvxJZqkPzV/Xdzdmi56roJ2cNhPZi1XYZQqL47p0E0kHT4rYHez3kkrNssqih
         b7A7rGTzyDJMUQOdBXDcyWPDL53fCi3UnD+LSly6Xupi9/gXfWbOk5H4torv1K/tQ0XM
         a5IWw/Ij1pq6TJAfOESjAHZ2+1v1yR9bb1HQKNtTEFpeMMAOBwtR5MaawBVvJ+WAXWXC
         sDvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wHqdtxQx6Lod0jir/zBNpgI20jHW/S0hFQeJ5vK6PO4=;
        b=tW4VdRQaDhiDLrH6IZ7zVs1+28SlTlvC9nxYxr1HQXq2Q/ZSVQ4oxuI/5iCYzvWGcN
         aV9cW4WqU6lisWUJ4e4VQan4k9GBkpjscwFo0d08PtFrsl2uWYzqOO2s8/4zr1n+CxJC
         QtqdvW/baiA0UC8rqCNPWInF1hei1oj5TCIQF5sRUQ81CL7VeW+oeILv307LakNtb/OC
         Pzu1plSbEBhPCjRadi4lhbn5KTW0ArwPn0OyZbnwl9XSRL7Fgb8xafpvRibC+0swA7d1
         uoLiRjRcddz+5WYNg8ieYWr7b9aGqjIf1dcedLF1PVG7hr3r8FHt6c7wQQsubqGWp0wr
         TMcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=N9gYQbXa;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id g11-20020a2eb5cb000000b0026fcb9f003csi48741ljn.6.2022.10.14.01.49.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id n9so2680889wms.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:41 -0700 (PDT)
X-Received: by 2002:a05:600c:19c9:b0:3c2:7fff:a689 with SMTP id u9-20020a05600c19c900b003c27fffa689mr9647430wmq.85.1665737380822;
        Fri, 14 Oct 2022 01:49:40 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:40 -0700 (PDT)
From: Hrutvik Kanabar <hrkanabar@gmail.com>
To: Hrutvik Kanabar <hrutvik@google.com>
Cc: Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org,
	Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>,
	linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>,
	linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: [PATCH RFC 0/7] fs: Debug config option to disable filesystem checksum verification for fuzzing
Date: Fri, 14 Oct 2022 08:48:30 +0000
Message-Id: <20221014084837.1787196-1-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=N9gYQbXa;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Hrutvik Kanabar <hrutvik@google.com>

Fuzzing is a proven technique to discover exploitable bugs in the Linux
kernel. But fuzzing filesystems is tricky: highly structured disk images
use redundant checksums to verify data integrity. Therefore,
randomly-mutated images are quickly rejected as corrupt, testing only
error-handling code effectively.

The Janus [1] and Hydra [2] projects probe filesystem code deeply by
correcting checksums after mutation. But their ad-hoc
checksum-correcting code supports only a few filesystems, and it is
difficult to support new ones - requiring significant duplication of
filesystem logic which must also be kept in sync with upstream changes.
Corrected checksums cannot be guaranteed to be valid, and reusing this
code across different fuzzing frameworks is non-trivial.

Instead, this RFC suggests a config option:
`DISABLE_FS_CSUM_VERIFICATION`. When it is enabled, all filesystems
should bypass redundant checksum verification, proceeding as if
checksums are valid. Setting of checksums should be unaffected. Mutated
images will no longer be rejected due to invalid checksums, allowing
testing of deeper code paths. Though some filesystems implement their
own flags to disable some checksums, this option should instead disable
all checksums for all filesystems uniformly. Critically, any bugs found
remain reproducible on production systems: redundant checksums in
mutated images can be fixed up to satisfy verification.

The patches below suggest a potential implementation for a few
filesystems, though we may have missed some checksums. The option
requires `DEBUG_KERNEL` and is not intended for production systems.

The first user of the option would be syzbot. We ran preliminary local
syzkaller tests to compare behaviour with and without these patches.
With the patches, we found a 19% increase in coverage, as well as many
new crash types and increases in the total number of crashes:

Filesystem | % new crash types | % increase in crashes
=E2=80=94----------|-------------------|----------------------
  ext4     |        60%        |         1400%
  btrfs    |        25%        |         185%
  f2fs     |        63%        |         16%


[1] Fuzzing file systems via two-dimensional input space exploration,
    Xu et al., 2019, IEEE Symposium on Security and Privacy,
    doi: 10.1109/SP.2019.00035
[2] Finding semantic bugs in file systems with an extensible fuzzing
    framework, Kim et al., 2019, ACM Symposium on Operating Systems
    Principles, doi: 10.1145/3341301.3359662


Hrutvik Kanabar (7):
  fs: create `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/ext4: support `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/btrfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/exfat: support `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/xfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/ntfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
  fs/f2fs: support `DISABLE_FS_CSUM_VERIFICATION` config option

 fs/Kconfig.debug            | 20 ++++++++++++++++++++
 fs/btrfs/check-integrity.c  |  3 ++-
 fs/btrfs/disk-io.c          |  6 ++++--
 fs/btrfs/free-space-cache.c |  3 ++-
 fs/btrfs/inode.c            |  3 ++-
 fs/btrfs/scrub.c            |  9 ++++++---
 fs/exfat/nls.c              |  3 ++-
 fs/exfat/super.c            |  3 +++
 fs/ext4/bitmap.c            |  6 ++++--
 fs/ext4/extents.c           |  3 ++-
 fs/ext4/inode.c             |  3 ++-
 fs/ext4/ioctl.c             |  3 ++-
 fs/ext4/mmp.c               |  3 ++-
 fs/ext4/namei.c             |  6 ++++--
 fs/ext4/orphan.c            |  3 ++-
 fs/ext4/super.c             |  6 ++++--
 fs/ext4/xattr.c             |  3 ++-
 fs/f2fs/checkpoint.c        |  3 ++-
 fs/f2fs/compress.c          |  3 ++-
 fs/f2fs/f2fs.h              |  2 ++
 fs/f2fs/inode.c             |  3 +++
 fs/ntfs/super.c             |  3 ++-
 fs/xfs/libxfs/xfs_cksum.h   |  5 ++++-
 lib/Kconfig.debug           |  6 ++++++
 24 files changed, 86 insertions(+), 25 deletions(-)
 create mode 100644 fs/Kconfig.debug

--=20
2.38.0.413.g74048e4d9e-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221014084837.1787196-1-hrkanabar%40gmail.com.
