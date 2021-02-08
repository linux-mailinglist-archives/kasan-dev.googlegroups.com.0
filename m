Return-Path: <kasan-dev+bncBDL2VT427MERBC6MQWAQMGQEH2LFMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 61049313950
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:25:48 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id c9sf2933456wrq.18
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:25:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612801548; cv=pass;
        d=google.com; s=arc-20160816;
        b=QPMv/t1tTWCw0fN4/AMFTI5x5caOWM5XhOKNXuYuYtoUgPIU0ninyVtfl73jFw050j
         qZvMeHHDlsfhkn50haRwwhApSRk9Xyvx8iVIeHu/GY7AKsUwhVyQ07HQMezmaLmatWZN
         ldU4gNVlhWx4QBzvWpN9ekGojr/YKoAxEkKBHkodlh8FXDeVFOItH0ciDeN3VKiW1cd2
         E6zx+yJ2rtAuM1aOjykSQlMdcKjSVefUmU/Vq0mUenND5gh9/jmU2DtjN1YkAfCA7DME
         53VBUJhMRx2ZYapUB+PMbxJ9FI01BkxQSfA1aqVZuPzVxwjYGxN3jPa+1On2zNrdV7jw
         O3Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kilgAb9Srgm1a4mMhhprCRNTnX2RDWU4+hc98uy1dAM=;
        b=eQchV4hotMQMs+pn3TY/slHg954exdo/kQzr3qhJkJ1HqURLIEkJMycevi5vIwLJTh
         APsJw+6058ybRcSvGkk2HbxJi21BRkjlW3ONpdAnOrXxnWDJBwNWc+RI/+xjH37kPjNS
         4sebtNtnhRKro50K+JUgjBgtmxpo9q0ygIwEI3On04b5wdqOG0ATmlQ6yPQ0pM30dygH
         1b2StHdaWYlNPHBv2cNs+9GwBgxKoRD3BCQMWtp5VH57DYGdaqMug2WKyDhFcRVTLiy/
         ad+miU/UmkSW2jb1KHkbjdQvik17Th/eTrQBHe6W5tTT5bI2cZAAnwNgiCuDh/R7ODW5
         yIXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kilgAb9Srgm1a4mMhhprCRNTnX2RDWU4+hc98uy1dAM=;
        b=nRirBRnCXhV/hw2cWfVSMrcbQGr2+BLQfEX8t+Yjqbtus/X9o1H1/R88KLQdzxRpwd
         701G5QyPyfVyt5uPDm8cgs1y5KeP1o9udnY1xVJ4Rf0XXsz8Jo4CCH8m3aBt7pMV+MSu
         tpo3xgoFeRZDzQ9Nlg65jh15wm8u3vp65fyu3A1i0bjHn4B1QuBnzjFyg2N7OebWDxvb
         iLw7cxuhJmGB2MADe4Z7rfPL9ARsDY07FjJHCwI25RquQqVfbZGDxx4mlRoPnjVEaqX/
         azKHvUgNgH31AaQ1RXMQxCYbPDPmieup0ryO790YbeiDVtpvTtgzS9WVUydjgXlBfJTE
         yuIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kilgAb9Srgm1a4mMhhprCRNTnX2RDWU4+hc98uy1dAM=;
        b=Sys0Er0QyNsPmL86JgAyLnBZZMB2+LWVeKRKioCyd2c3Dv/btTMXZvbpaP5iWjPyPs
         aU3Np1heSgmsn7q1nTf2X8dLEIo0hwHIdczFeH8bEjTCk+yi54ibiGKQj7qQeiBfpCuB
         1D7Nx4fQidKUrh1uiUT6XpiYjykgt0aG554BDRo4wwAX35PBUqkWYocDMarAkBYkVbH0
         qmJFq7Vt7sclcDh/HLH2jE3OuFfWZ+Dt6Cyvwpt5IsDdoWYEW9Oi4ZmDO+57Zn2nmpqY
         YDNae6Ibyi40BVrhQ0BXHEJ2ClwsfRMe/2Bs0khkBc6EAlgdUK+B2VfRZ88mXmRcjLAB
         2RSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Cp4zHXFZnoZOaXf4Qis7G/hxC8UjTTNa10kMVydEqczvMxXGL
	JeMdGdJSstGTUfs9u4s6Gjs=
X-Google-Smtp-Source: ABdhPJx44R+HRuwy+LW9IeN5wUHwzlEq0Zk3sWoLmj/Chkc/ne2Lxp2Fcrbw/79EFaBB70EmHTM/Dw==
X-Received: by 2002:a7b:cb81:: with SMTP id m1mr15444423wmi.117.1612801548104;
        Mon, 08 Feb 2021 08:25:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4485:: with SMTP id j5ls776965wrq.1.gmail; Mon, 08 Feb
 2021 08:25:47 -0800 (PST)
X-Received: by 2002:a5d:67cd:: with SMTP id n13mr7576108wrw.96.1612801547367;
        Mon, 08 Feb 2021 08:25:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612801547; cv=none;
        d=google.com; s=arc-20160816;
        b=v9g4ZiSb1RAJ0j7Knw+IMwkcHwj/S3FOipifBHTRzNKte8UTZ3VaeGYRVuvNrxV6lb
         dZNkC2xJCL7/b3RzC6seBTADthzMcV0Hl2ItgF/SId3FZUfvO+JWmSI9jAVhg2e9o0PW
         6WOhtMGG3rvjLupMjKl+B58Ugso6B4/91rJi5QtrWGtrbkE0adCibsieQzFUhmDtjDwq
         mmlwCZ0l4ehGlCQrSDp697q1iCq/55BqcYTG9KI/W24wWwDB5FIQQumXoi7K1TfyDw4s
         ZFx7ywXkDkup70PsYcfAoPT2ACAAQStnIU9D5+kZtaiXpmRUVX+Gj3P/HSRbBG2H6v4f
         Sslg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=wGuYNMvIqC5ZtZ1Y4dnmge82juotiewzLc0GCby57SA=;
        b=O7nceDbjA1n0Bh6oBJjcZlVMrLWQ+coV/j8fFg7IRUZFc/KeK6FjcpRi7nP9CCuXt8
         erdubKzlBMCYhUSVQ/1svPfx1L4LqRiHAcIVbUHnZp32mM4m2hSdb47HsLv0fZg6pU21
         LiJIhX4T0KslaX1ok7zI8MDSjbCo1DEzg8YJnqr7i5M7lymGCyWFq2y+CBBuw2K5b5Ef
         0TCjLKJGNBfVZD0or3W7r4CJNcl/INfmedb/R/LCLqLbcQRrZZYoREOuw360+tKRNAcB
         RKzxsuNhKJAzLQz89rRHWJe9NNQTPCsj8inCx64LvCYota7+6hjRyNTkXQeVjbzSlV3Q
         c73A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id t16si19559wmi.3.2021.02.08.08.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Feb 2021 08:25:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id EC98CAD6A;
	Mon,  8 Feb 2021 16:25:46 +0000 (UTC)
Date: Mon, 8 Feb 2021 17:25:43 +0100
From: Borislav Petkov <bp@suse.de>
To: AC <achirvasub@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	jpoimboe@redhat.com, nborisov@suse.com, seth.forshee@canonical.com,
	yamada.masahiro@socionext.com
Subject: [PATCH] x86/build: Disable CET instrumentation in the kernel for
 32-bit too
Message-ID: <20210208162543.GH17908@zn.tnic>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
 <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
 <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
 <20210208121227.GD17908@zn.tnic>
 <82FA27E6-A46F-41E2-B7D3-2FEBEA8A4D70@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <82FA27E6-A46F-41E2-B7D3-2FEBEA8A4D70@gmail.com>
X-Original-Sender: bp@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=bp@suse.de
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

On Mon, Feb 08, 2021 at 10:19:33AM -0500, AC wrote:
> That did fix it, thank you!

Thanks!

---
From: Borislav Petkov <bp@suse.de>
Date: Mon, 8 Feb 2021 16:43:30 +0100
Subject: [PATCH] x86/build: Disable CET instrumentation in the kernel for 3=
2-bit too

Commit

  20bf2b378729 ("x86/build: Disable CET instrumentation in the kernel")

disabled CET instrumentation which gets added by default by the Ubuntu
gcc9 and 10 by default, but did that only for 64-bit builds. It would
still fail when building a 32-bit target. So disable CET for all x86
builds.

Fixes: 20bf2b378729 ("x86/build: Disable CET instrumentation in the kernel"=
)
Reported-by: AC <achirvasub@gmail.com>
Signed-off-by: Borislav Petkov <bp@suse.de>
Tested-by: AC <achirvasub@gmail.com>
Link: https://lkml.kernel.org/r/YCCIgMHkzh/xT4ex@arch-chirva.localdomain
---
 arch/x86/Makefile | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/x86/Makefile b/arch/x86/Makefile
index 109c7f86483c..b9f58b8993b3 100644
--- a/arch/x86/Makefile
+++ b/arch/x86/Makefile
@@ -50,6 +50,9 @@ export BITS
 KBUILD_CFLAGS +=3D -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
 KBUILD_CFLAGS +=3D $(call cc-option,-mno-avx,)
=20
+# Intel CET isn't enabled in the kernel
+KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
+
 ifeq ($(CONFIG_X86_32),y)
         BITS :=3D 32
         UTS_MACHINE :=3D i386
@@ -120,9 +123,6 @@ else
=20
         KBUILD_CFLAGS +=3D -mno-red-zone
         KBUILD_CFLAGS +=3D -mcmodel=3Dkernel
-
-	# Intel CET isn't enabled in the kernel
-	KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
 endif
=20
 ifdef CONFIG_X86_X32
--=20
2.29.2

--=20
Regards/Gruss,
    Boris.

SUSE Software Solutions Germany GmbH, GF: Felix Imend=C3=B6rffer, HRB 36809=
, AG N=C3=BCrnberg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210208162543.GH17908%40zn.tnic.
