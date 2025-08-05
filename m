Return-Path: <kasan-dev+bncBCKPFB7SXUERB5OGY3CAMGQEV7DHNEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D82C8B1AE2D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 08:23:50 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-7073d7fbfe6sf90068546d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 23:23:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754375029; cv=pass;
        d=google.com; s=arc-20240605;
        b=fXo6mUpLmdennnfAycY5Gkdk2xGqPtxSjsH00mfmoCAjYQ5P3DYDYQH38ABqPPRfYv
         cl9NZoqUwimpz/MndBbKgXkG/6MdG52XAN8/AaqMUrecvvaZg1FNtZ7/q3wdQE2JhOZv
         d0GW5zj6FOE004z8ggs/07X23XLbHOWIHVz71gNGhjOk2pUe4BlYznxM/nbpNhogcvAF
         63wVPD0sRSmwDfxo1rq9Lps4MOxVoUtzECUbcEHWlQSOUXc313joBoTzA6FRayfig/RW
         uv5pqftmTfIG8hN3LLWvYFPQQ9JLoZRl+4M4dOK/3vKs2+U1iw1tcomOs5VGz4K0Giip
         C+YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=cAXNge5dhFQeKLOSBONFY759tl7ci8N7kpDU2O9Pwo0=;
        fh=GN96wZ9GbJCszBPqb5U/rASYxFJnIa5y8zvguph/UpY=;
        b=ORnNNh9S1emio3iUP6BM5yQain5uZa7V1dvmQntNCAbMR0gHGxpJnk2kvcCUEO8/iS
         SaBOGjNMy3QVULt2IUWA/cQxTdo4PEPfOZVg3imtAcB7WYptn8/5Nbfn5pOHM1FSYZaT
         uOX34/JqRYYHIN625815tao8HhaGX3NYfoITQOZZ1/D+WhPhdH1xmSQ/KXf3sm+j6lVx
         qaWU9MUQkbXHsObuU80EkOXQBoS27dx+Fxg5cRLXQPksjc+ARhhlBvhZh4PMhKb+HE/4
         tbOytnWyiQE4/B4I8ptCDgLP2fhQfTAA2Xtvyhx1OJx+kgNiqFEUxwB1LrgP/L4cPpyG
         XRZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eTm92kw5;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754375029; x=1754979829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cAXNge5dhFQeKLOSBONFY759tl7ci8N7kpDU2O9Pwo0=;
        b=H/VqJIGWzKy7HaDK8MLjg8V0GFFzTrAvvnPlMXtCKh4de5tx3Ji6AvT3C1+fgeMjJP
         +ZAaAnJAWqiUeoMNJzxZuInDPAQijMg+UDZcbXp7eQvUwbnyTFXQml5RYfxQwGpEMfXG
         wo25Lk4fuRWgUMO4vWT5BR/ngT91zKsodr9IndqAEWy+j5JOLe+Gos884nM3Odhu1gB1
         xkz8PtV8NlAxomSU3eN40At4R6wl2H21yqQxC1WWlpdKzMFa4ONBmymcR3UradN0KQeY
         iZJze2RabGQM53jde5YPtCXV+dhWXL2K1E+Welhff8fMyyyV0JNk653jZqISNprKJrSz
         VZRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754375029; x=1754979829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cAXNge5dhFQeKLOSBONFY759tl7ci8N7kpDU2O9Pwo0=;
        b=XPf2DIjEk1WCCKhjZHGcWqc31eFTwELG7DXPdOHEBpZT2kgEzdA6StkN8VhLpHoqOT
         DUy4C4RayxbHEVfebjcLxHNnn9GvdOX3ZufvSTNUfniUscpgASg88x4hc7PYFdCBtQSL
         x5KbcSmVhCb2LuLLIgEia1iigpOdXt+qIKc3jfiOSAQ4d/EDm2db3VkZJmH45wtYXh1R
         VtqPlbVYa1oD6fLzh2vnHueDKZhEnngPJo+xKIHqVLk6fhy4rRfH110BYQ9oRY6FS3Y0
         542w9xqEvIgQLfKOfank5BCWg/X0AMuZL9oLIS/M6rsnaUMLfX3Snir+2+6Y65yA8AMT
         /NRA==
X-Forwarded-Encrypted: i=2; AJvYcCWE40uCyXR/BLlouytG6pDpwoLrcu7gyhYdpPGrcvLsXtY+L/dlwmdP12rKrz4sJttYKyWRTg==@lfdr.de
X-Gm-Message-State: AOJu0Yy0knCX+ymcLj/sHF70oxLC3TWYfLRbkPClFg5mTOlJoQkj+I/P
	YPB4TYW3lVJcN5eqWVfLoz9Ojlgw078ppiHmf6qY4yK2vF30vw8KRknm
X-Google-Smtp-Source: AGHT+IGtTkPJAcWrRL25wS3OUV5gtLT265MW/P1Gmbody0DJGYVnX6H6Qgqj9GRrIkhhhkQqxKAn0A==
X-Received: by 2002:a05:6214:2525:b0:707:5bc5:861a with SMTP id 6a1803df08f44-70935f7b226mr162288746d6.17.1754375029307;
        Mon, 04 Aug 2025 23:23:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhrBrcGqH85zKc0iMKy7JGTKAsYhg15yU35NOOEQqHLQ==
Received: by 2002:ad4:5aed:0:b0:707:1963:15ba with SMTP id 6a1803df08f44-70778dc23f6ls82954616d6.2.-pod-prod-02-us;
 Mon, 04 Aug 2025 23:23:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWhao30JNXoJPxaPC0ue0GDzn+oyjmquVFx9CfOXfbvIKvt9SPRep7pqliKkbDhZYFqfLzVdBT06o=@googlegroups.com
X-Received: by 2002:a05:6122:6599:b0:539:1dd2:22fa with SMTP id 71dfb90a1353d-5395f101b85mr5329581e0c.1.1754375028541;
        Mon, 04 Aug 2025 23:23:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754375028; cv=none;
        d=google.com; s=arc-20240605;
        b=kpqoxYEyiksi5/Cclqgt6XvX62+2bIPtkLKj1HfEvYpUiP4s+Na99gv5LOz+iFh+LB
         Jo0M87C+YbIkydD3ypUnAHaT2912vonUgYE7K0iBP5WMMjS/Lv7CDqHzI7PmsQjamESI
         l4i+Cj1u18mddMgMuWv1SDh0nedWUq+9M9kzvNSjHwhVuyZJPwGma/X+J+aQcnvdU+5v
         2ByIMM1e19IRPOFPMu/PVhHCS26cdNO9rvasowp3NPOTUGU7/rpCbfZOxfRHK7lbl3FM
         J5MTHrtHwQsmCa0KTLkh3N4CcdEyCFFn1QUgeNTPUow29MMLYV8G5tIK3Zg16KDrVVAs
         /5+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YSXKdaD3IZAs8uieY7LPn8yhD3PkW5u9fBN/Is1bw+s=;
        fh=zdgUGJ5AVcpjW6c3+faZMlslsU1+4WtDOSxOnvwQO5s=;
        b=EAR4hxKQrHxRACAGIc2VspRvyVy5z/+4dWfjUGkvF0U3xT+6WPxJ7XqYpan5qnFZUf
         TRV5NnVhaF4+5TWpCTfCPRb0jaGOiz52V6x1eZPZ++Sf6F2OCvcX8UGx5X/ubs2QAhJe
         wivmKsLEFMQfJgEQRjuOcCVj4eJ94ZnD9ONhqFBWXD5CJelSmibGZTuRROKQkpUykRWB
         YfzMaa96q29BB33A+syGkDuQOTVTbD5nj3fFONS6/St86vwI9CTh52hOF5Ox40H+vWx0
         SEmbTyFixRoZW0cgZjuc8KScRENjb/A5odANVhq3r1A8ULrF+CLcLOiruDyMgBrSlxPw
         dVMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eTm92kw5;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539369375adsi518424e0c.0.2025.08.04.23.23.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 23:23:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-620-L51CUMXUOgaWzMV0lMozWg-1; Tue,
 05 Aug 2025 02:23:44 -0400
X-MC-Unique: L51CUMXUOgaWzMV0lMozWg-1
X-Mimecast-MFC-AGG-ID: L51CUMXUOgaWzMV0lMozWg_1754375023
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8D3CD180045C;
	Tue,  5 Aug 2025 06:23:42 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.136])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9AF5F1956094;
	Tue,  5 Aug 2025 06:23:36 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
Date: Tue,  5 Aug 2025 14:23:29 +0800
Message-ID: <20250805062333.121553-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=eTm92kw5;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

Currently only hw_tags mode of kasan can be enabled or disabled with
kernel parameter kasan=on|off for built kernel. For kasan generic and
sw_tags mode, there's no way to disable them once kernel is built. 
This is not convenient sometime, e.g in system kdump is configured.
When the 1st kernel has KASAN enabled and crash triggered to switch to
kdump kernel, the generic or sw_tags mode will cost much extra memory
for kasan shadow while in fact it's meaningless to have kasan in kdump
kernel.

So this patchset moves the kasan=on|off out of hw_tags scope and into
common code to make it visible in generic and sw_tags mode too. Then we
can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
kasan.

Test:
=====
I only took test on x86_64 for generic mode, and on arm64 for
generic, sw_tags and hw_tags mode. All of them works well.

However when I tested sw_tags on a HPE apollo arm64 machine, it always
breaks kernel with a KASAN bug. Even w/o this patchset applied, the bug 
can always be seen too.

"BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8"

I haven't got root cause of the bug, will report the bug later in
another thread.
====

Baoquan He (4):
  mm/kasan: add conditional checks in functions to return directly if
    kasan is disabled
  mm/kasan: move kasan= code to common place
  mm/kasan: don't initialize kasan if it's disabled
  mm/kasan: make kasan=on|off take effect for all three modes

 arch/arm/mm/kasan_init.c               |  6 +++++
 arch/arm64/mm/kasan_init.c             |  7 ++++++
 arch/loongarch/mm/kasan_init.c         |  5 ++++
 arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
 arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
 arch/riscv/mm/kasan_init.c             |  6 +++++
 arch/um/kernel/mem.c                   |  6 +++++
 arch/x86/mm/kasan_init_64.c            |  6 +++++
 arch/xtensa/mm/kasan_init.c            |  6 +++++
 include/linux/kasan-enabled.h          | 11 ++------
 mm/kasan/common.c                      | 27 ++++++++++++++++++++
 mm/kasan/generic.c                     | 20 +++++++++++++--
 mm/kasan/hw_tags.c                     | 35 ++------------------------
 mm/kasan/init.c                        |  6 +++++
 mm/kasan/quarantine.c                  |  3 +++
 mm/kasan/shadow.c                      | 23 ++++++++++++++++-
 mm/kasan/sw_tags.c                     |  9 +++++++
 18 files changed, 150 insertions(+), 46 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-1-bhe%40redhat.com.
