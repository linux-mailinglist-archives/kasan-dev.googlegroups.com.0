Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXGGXTXQKGQE4I5Y7JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 57B49117F17
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 05:47:25 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id u20sf4565150uap.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 20:47:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575953244; cv=pass;
        d=google.com; s=arc-20160816;
        b=TLvlU3WQewCnOgz7lnya6dW3u8VGzTh9Ne104ijqhT7Tw/iCCO+R8ctWVuM3T3jgDG
         qnEgSxsnp68J1KDb/nRT5BMt/oEdYXk7/StL1x7yxePuW4O5J0OkK21q11bJhOHL1dRc
         MnzPXb++Yn0amd2I15Z+HvOZonCczHUQAqjpSibEJSbOj3WreSlGLTlbBmKIlvbO40fU
         T7YUMwDS18RXeao5jZuIYyGUfUWXR+rMdGfpyeUmxC/vdMHVxdbUml8aiyAgBR69Qmzg
         XTaw3Z3T28w9Sosr5fw6ves8E33fiPgf2hF3XKp+cN6D13CmI+6VExlbNp/hewFiBsYV
         nyUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BNFIHbXb1Y8OgMwSonK9EuhwwWWtmJlJ7DHaQYaPfgA=;
        b=t7viGfYp/FwmSHEztR0uVvj/W3hc9G6t4CsY6UrM3fwC/OAKK2AuQMFtbSdS5IQBkw
         y94b5YfGRl7p3dxdGKGM+60svCHcY7erxoyLwCTqtaAoh4Z8BsJRN8SKd10MO5QJ/dRj
         8hQOXlpbesSu3TVmer4iETRuCQifFMn27DbxeHgXdEpKIEUsXG3e/9eE3hCHLDx8qhyl
         AMNKHBnC2qyyd1Am5Ca8GWGyAp0aGAY38VaN9zKBL/5nt4vWTO1VldMbSSGL+qvDIaNu
         C8IAb+M4mdJ+fFoKSGKO3wqqvn1EH48I0GY3EyK6NRU9hnlAwiLy0RRuyEotm5Ko7sNQ
         M4zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Q5ohWjCI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNFIHbXb1Y8OgMwSonK9EuhwwWWtmJlJ7DHaQYaPfgA=;
        b=IC0uZGQ+SxOWbHF9+WGBZo4GW+1YcPls5obDRne3Wl0pBtnJkbKK9sFOad4tF5wals
         s9Fp6WKf2HNaWnAaVzqMo/tKQ+jXMlxnOR3jteJVMB4PoLw0uuTwpO5GppFEZamqwD7O
         FxfxCiTnItXrtBh1mRMLzxhPmPtfU/eeklYATlnOAH2fvwWtQIYCp4dLC0xODmQTXYSF
         Uk32zBt9G3zW6548YMZ39/ZlwUhwi7AJCQecZpt6K82aMAeR78+BApcawUrhbdMw64UO
         AgoPlEoT0xUXbO4y7tgCOtNyogjTY+VmUT26t/tQE1p1QdhITzRCagTPQBMjx8xt2Ua4
         eINQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BNFIHbXb1Y8OgMwSonK9EuhwwWWtmJlJ7DHaQYaPfgA=;
        b=YkvWdhJjnzzaXAiYBZkryMygy+IDxwacBi4kl8F3mltQvn/UZZJ7LMNrFvk0xF3er8
         YUsl+hRK2bY/z2jeKfI+4KIsQBHXQS9QHwNUJ1sFGU1SDbRm3a0NWtl9Q0H7SdWQ1Hrh
         WVozDYyDTvNiHfBr6avZQux2DugD5JhjB/f9wI4HInFOQgzAEoGU0GExqZz1HbPhxeJg
         dA9O1eYvIeziD53hfwtw7CFF2sr/6We5hU/NccHVTQqUXx1Z3OmS9FN/AcAyRVMNnbDL
         /WIAVfJqzgX85o8Rw7TD0+c7kCQYLKMXoyQPb6/I4dD70GOPOZ/Tv82/7PLe6rdh2JMF
         WFxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXwSYlbZogZhOdls3EvBmuk42q1iZO0UtOe0BJgcrLTEjqCqLC/
	5KZwkzGgLxhpvXpDutSbXHw=
X-Google-Smtp-Source: APXvYqxFqhgFQN4qZn6HoVF0Sm7ANgCvs6VPhnlSMoNjKr+GaWRFT9u3kwivOOpW3KB81iBHSgnkTA==
X-Received: by 2002:a67:fa16:: with SMTP id i22mr22147748vsq.137.1575953244364;
        Mon, 09 Dec 2019 20:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:517:: with SMTP id l23ls2082652vsa.11.gmail; Mon,
 09 Dec 2019 20:47:23 -0800 (PST)
X-Received: by 2002:a67:ead6:: with SMTP id s22mr23413363vso.69.1575953243881;
        Mon, 09 Dec 2019 20:47:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575953243; cv=none;
        d=google.com; s=arc-20160816;
        b=XwucqtZ75EQfmDnxZucdzKr2i9ITd7KS5Cw35nXBo/RPUqCtP5zbo37kbHHk8HmymL
         5KGrcD1UXrLyOetOV/Pl2r/PO7NqLyggBBCL/JwtatPl8v1TqN4iBmnsHSWxlvnsbNke
         fw7Q12wkgFkybomkgCkKl3xsmB0mcFixFVT2NJr72TETB+2Y4TGIdijc1O+gn3vrXkZ8
         mRCUQxJqRn01FpxgPcAVDyixSlVGzByvnFXjkMEfKd5bE5IFXpi76B4DrXZ27UEMsf9i
         jNJEuJXy/izL4FdPNijNr+mRlkkT27ckgzwQr/QJUIPHbIcgFdSIb2ORaOSFZ214pfaN
         OIUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=y8tQSVFZXpglTzCwnCQJ/H8jDbSquTv0j0/ujEPlW6k=;
        b=hibuuCTPNV0iCTe3UWnckk7eG6tvPiaC+tAtbxSDEir711x0Tn3NTDjsu9QRa3wM7M
         x0TSEz9yL0hdo8C8J2oVUhY0gYuF/NSVI96X7kxD7sh7SBgZluRm+MuFKSt40uctet5B
         KSmuIMByZgUt7teo4vWoRtb16ysGobMDm23qE5Y81/vQ7/XQCFYG+cBNNdrgDs+Ps9y+
         YiB2Cb6rcWKfOac8kUEETxDDcpo8UPwFJahc54auiK9SUmyaC4YN/ubZAbHaXcKxy0rV
         vahILV6gqJRgyD+2ZTAW5gS2LgxqpGFtTG7wvZNRgLIoQDzgqAGi4TyL9ain2uE4xc7r
         704w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Q5ohWjCI;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id i27si121028uat.1.2019.12.09.20.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 20:47:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id c13so6134467pls.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 20:47:23 -0800 (PST)
X-Received: by 2002:a17:902:9f83:: with SMTP id g3mr30957647plq.234.1575953242726;
        Mon, 09 Dec 2019 20:47:22 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id e16sm1159270pgk.77.2019.12.09.20.47.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 20:47:21 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	linux-arch@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 0/4] KASAN for powerpc64 radix, plus generic mm change
Date: Tue, 10 Dec 2019 15:47:10 +1100
Message-Id: <20191210044714.27265-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Q5ohWjCI;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of physically contiguous memory
on the system at compile time. More details in patch 4.

The big change from v1 is the introduction of tree-wide(ish)
MAX_PTRS_PER_{PTE,PMD,PUD} macros in preference to the previous
approach, which was for the arch to override the page table array
definitions with their own. (And I squashed the annoying intermittent
crash!)

Apart from that there's just a lot of cleanup. Christophe, I've
addressed most of what you asked for and I will reply to your v1
emails to clarify what remains unchanged.

Regards,
Daniel

Daniel Axtens (4):
  mm: define MAX_PTRS_PER_{PTE,PMD,PUD}
  kasan: use MAX_PTRS_PER_* for early shadow
  kasan: Document support on 32-bit powerpc
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 Documentation/dev-tools/kasan.rst             |   7 +-
 Documentation/powerpc/kasan.txt               | 112 ++++++++++++++++++
 arch/arm64/include/asm/pgtable-hwdef.h        |   3 +
 arch/powerpc/Kconfig                          |   3 +
 arch/powerpc/Kconfig.debug                    |  21 ++++
 arch/powerpc/Makefile                         |  11 ++
 arch/powerpc/include/asm/book3s/64/hash.h     |   4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |   7 ++
 arch/powerpc/include/asm/book3s/64/radix.h    |   5 +
 arch/powerpc/include/asm/kasan.h              |  20 +++-
 arch/powerpc/kernel/process.c                 |   8 ++
 arch/powerpc/kernel/prom.c                    |  59 ++++++++-
 arch/powerpc/mm/kasan/Makefile                |   3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |   0
 arch/powerpc/mm/kasan/init_book3s_64.c        |  67 +++++++++++
 arch/s390/include/asm/pgtable.h               |   3 +
 arch/x86/include/asm/pgtable_types.h          |   5 +
 arch/xtensa/include/asm/pgtable.h             |   1 +
 include/asm-generic/pgtable-nop4d-hack.h      |   9 +-
 include/asm-generic/pgtable-nopmd.h           |   9 +-
 include/asm-generic/pgtable-nopud.h           |   9 +-
 include/linux/kasan.h                         |   6 +-
 mm/kasan/init.c                               |   6 +-
 23 files changed, 353 insertions(+), 25 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210044714.27265-1-dja%40axtens.net.
