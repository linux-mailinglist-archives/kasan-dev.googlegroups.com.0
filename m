Return-Path: <kasan-dev+bncBAABBIWKX3CAMGQEIYVRHLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 189EEB194B4
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Aug 2025 20:06:28 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e8fdcedb1b9sf3833913276.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Aug 2025 11:06:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754244387; cv=pass;
        d=google.com; s=arc-20240605;
        b=X6bHl/W369Uhp9ufMh/P5UnVxI4lxDK00pYFQY6PKKrAYd8i2CgFbScR3rU2kJIOQJ
         NjawgMeauKkdBmttofXGQde9Ue5tKqXaObB0R56mForf/R+WfzcifwgCDtOQN5zGLs/I
         mEzfr/gO1Aik3KNKhiULPilZpV923Id/APiNwvjUB1GFMLcTULdfDPaEtuZjNKHcE1XT
         Cq/MFtdGN/NP4wI9BLKeprjMRXbyxHv9hqQG2PDqwSRuVWuGNyfdSj4kbtL6eLu5Y9Yd
         DOiGRFkVS1PfqE8AX6iLtWa6POFrj0FginMpTAL8rWDXLFMq+dJZ1XhZhNIvNo8qozwz
         UdYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Fa+etAD+3s2WExy49XS05SD97va+0ehBS/xXqVO8xs=;
        fh=Yib9eTyuWihYp//mO/3tOU8kmrzp8/wIIpKUo6ItdMI=;
        b=N8iZ6m/rjsHdyOlNG7mgbMvcsyhgn1eiKG25iyzNLaJshww+YXl4P0ew/p+rdXJqQk
         xFeWmZn51X0mScb7SD/Jl+nTlLFwgeX7Lz5FpGeXEqD+o8OtrGYtAwtIn8RJ3RHjsyvK
         NNwo6Y7jYtZvPDWOhUUMkcIjYuhCc7n5AeT+0i0iCcQGBVGsZldNGo1kv4Ph3ylnWOZF
         lybPwBy9at2klnPoE+mJGHLK455LQpz4cPkn6MGnOHlagVk3o979rn9Ug4YWPNLGPpj1
         qYGPcNXCUdHajAXZWPXeBtzZDb8EY6yNkRhpim9pvKMpdzSmjH/atYngyiAHlyDHKnvW
         pHRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=WevG1IE4;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754244387; x=1754849187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Fa+etAD+3s2WExy49XS05SD97va+0ehBS/xXqVO8xs=;
        b=iOt2UnpB4Vz60Bx9mHzMmiTaUiaOogCW/5DVtiy7kT0Qq0Ihc3E3qeq+52ECGMv55/
         vAmo+IdL9aN1+iTycCJ2kuHHedTrqSZaOf5YcqzZfkE4nq+o6mmrOQuqrizVOqjUWXi7
         tGfVcvhH1CgeHFr5IdYcUox54hyGgaf0hq6/a43clUeFzYXBzUDYjORS5Y7Frp4Zfipz
         tjNo2OeJcVOv0i42vFg2cMUAPYFSGMBIWtY5RHZ9gV16uLZ/C6d7JPbh0hcL27ftFbau
         dhSHk9axjvZcO/a2ZGceDV3+u4p+hcHe65yKLTXWEE1Y4g3bUoXTqBNmArFv30KY8Z3g
         9Kuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754244387; x=1754849187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Fa+etAD+3s2WExy49XS05SD97va+0ehBS/xXqVO8xs=;
        b=Dm1YApxQurm0M8BEUuVF3TFXs76Rkwh6Z2yG0d2So1vAKmVucNX3Go0ahNTJQHPjDb
         1kHrNxvJt5oaVR3C9buVCbfSd5hQZnBGRBFZlsUKKA/utxXBDhqHFPy0MBLtmJODszjT
         QiupWqntAAgsMT8PeYlw+Os/ztXi+wXo747zV33WzqBZkGOvBmU107mgbtled14ZqpeU
         8DozlFcL2Yjgt7Ic7yUxISjDkI1g0deo8Bilwc3ZZr//nMG9HEk/pYfS14yYAoBLpPbb
         az6TFVXNE8+9Lj9vxKn43Wzk2g4wlYOwt2Gtki0diRLP/G8si0s2m5H/k/xI4RyVIZ4c
         KCaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUL5LBR0J0TRM/62c2g9Jpa6QJsn4AxuIsROA9TC6SVC1O1K+UPAUHHuSZt6hhQoPLM8hFj6w==@lfdr.de
X-Gm-Message-State: AOJu0Yz0bIFJuyjc6nJFXXVZb9EDWCEEHWZUxiWK10PHhfrnZXys2guQ
	Bab+iBGuOXsFvyGV2IWGx+oHzgwfthRQK+FRrLm9JD3IUT5vt8UT+Ghu
X-Google-Smtp-Source: AGHT+IFvuDPBJDnaiUHnLbRAszHAM+E/pSuo7ZocIbc0nlPMIth0kG1X9C/LDAxKJfd+As8eUWzLqA==
X-Received: by 2002:a05:6902:708:b0:e8f:fff1:9d20 with SMTP id 3f1490d57ef6-e8ffff1a14amr2071357276.3.1754244386587;
        Sun, 03 Aug 2025 11:06:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdncX1NE3EvMLGSUcreDyE+UaMq5lba/9NgQuZmmiO34Q==
Received: by 2002:a05:6902:4102:b0:e7d:c43d:b109 with SMTP id
 3f1490d57ef6-e8fe1eabb7fls2600795276.1.-pod-prod-05-us; Sun, 03 Aug 2025
 11:06:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUbxlfuQ1xTyloAo46IMDNxakY1QZRQooRcl8+leD4pvG8/tqzM6dOSud7dlI/C8YKAZmmCPu+3lQU=@googlegroups.com
X-Received: by 2002:a05:6902:1587:b0:e8e:2bdb:cbaa with SMTP id 3f1490d57ef6-e8fee1c74fdmr7027195276.37.1754244385966;
        Sun, 03 Aug 2025 11:06:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754244385; cv=none;
        d=google.com; s=arc-20240605;
        b=UagsCkgNLQdlnYPAZTBP+YqxNlaHK2AasAozC2Sjxj+LCXl/uIT6nKsjqSpqYXp/+R
         z+A7jAMD0+VR2MoceDnbxg00ty5DhWOT6nDaTdS7CT8/OyFDtzo37J4GJ6RkDBizKj27
         CwiHhciXCfGTOWKMIo9LZWfoUCXqiMeCJSmoxt6DwuypJWMVi5836yGfujWn2fZAaMt+
         h9w1PqY49UAVDaCHaiwqeVMC1ZB5OLLgFo9hdsOhpMggpCW0UO9uQc+e42zb07wd3LBp
         AtzHqn+Z/QwH7X4x0O/+fV/E+9rVPJY4fzYqarikh+kuP5nGV2m0ZAGy2iptoqLpeS+e
         Mc8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZLvlv0mxlOxDMkUf5+djXwgcB52TxZA1ATxIa1n04r0=;
        fh=CWh0tYT+K9D+nuC0vGPeTtdwtsqN/166jCDU7lzOfa0=;
        b=YXwUgfSjaRBMxOS6Y6kqJbQEz/EUHYOzHbNbbo70dxrIhgZRpGjPU8Fpu84oSFdD8q
         +OvYuBLGOyIKKIESly9S/W1EcNH48FD2bcvjpgvIk5GjjIwIwebaEwNMYXGAS4DrRcsy
         apK8/ss2lsCEAOPy9vyuTtajTNrVV27Anu5eyYVQ0ko984iWxgVrme7wK+M+OAHDF/+O
         Y3rvTv+ewTivDejCvr/1A1OIWhFt5uKnEBvRyEja5WdRs+n3yp1/IyMIr5bRuLLB80+M
         BSGfs4OQE+RbR/vkszeyxzTyGJqgl306/cRHg1Xen8biB60YPVUp8GQfx8SkaLsXZ0k+
         iNWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@utah.edu header.s=UniversityOfUtah header.b=WevG1IE4;
       spf=pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
Received: from ipo7.cc.utah.edu (ipo7.cc.utah.edu. [155.97.144.42])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8fe5f98c5fsi208859276.3.2025.08.03.11.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 03 Aug 2025 11:06:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of soba@cs.utah.edu designates 155.97.144.42 as permitted sender) client-ip=155.97.144.42;
X-CSE-ConnectionGUID: utDoHAfgT9SGo0rMuZyK5w==
X-CSE-MsgGUID: NDOkl7e+TgG5+Tw5I7xwpw==
X-IronPort-AV: E=Sophos;i="6.17,258,1747720800"; 
   d="scan'208";a="399802573"
Received: from rio.cs.utah.edu (HELO mail-svr1.cs.utah.edu) ([155.98.64.241])
  by ipo7smtp.cc.utah.edu with ESMTP; 03 Aug 2025 12:06:15 -0600
Received: from localhost (localhost [127.0.0.1])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id 251E230228C;
	Sun,  3 Aug 2025 12:03:51 -0600 (MDT)
X-Virus-Scanned: Debian amavisd-new at cs.utah.edu
Received: from mail-svr1.cs.utah.edu ([127.0.0.1])
	by localhost (rio.cs.utah.edu [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id unZkAccHvwO4; Sun,  3 Aug 2025 12:03:50 -0600 (MDT)
Received: from thebes.cs.utah.edu (thebes.cs.utah.edu [155.98.65.57])
	by mail-svr1.cs.utah.edu (Postfix) with ESMTP id BA7F03018A8;
	Sun,  3 Aug 2025 12:03:50 -0600 (MDT)
Received: by thebes.cs.utah.edu (Postfix, from userid 1628)
	id DC8F115C2742; Sun,  3 Aug 2025 12:06:13 -0600 (MDT)
From: Soham Bagchi <soham.bagchi@utah.edu>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	arnd@arndb.de,
	corbet@lwn.net,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	soham.bagchi@utah.edu,
	sohambagchi@outlook.com,
	tglx@linutronix.de,
	workflows@vger.kernel.org
Subject: [PATCH v2] kcov: load acquire coverage count in user-space code
Date: Sun,  3 Aug 2025 12:05:58 -0600
Message-Id: <20250803180558.2967962-1-soham.bagchi@utah.edu>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF+h0hdoQUwGuxfA@mail.gmail.com>
References: <CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF+h0hdoQUwGuxfA@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: soham.bagchi@utah.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@utah.edu header.s=UniversityOfUtah header.b=WevG1IE4;
       spf=pass (google.com: domain of soba@cs.utah.edu designates
 155.97.144.42 as permitted sender) smtp.mailfrom=soba@cs.utah.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=utah.edu
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

Updating the KCOV documentation to use a load-acquire
operation for the first element of the shared memory
buffer between kernel-space and user-space.

The load-acquire pairs with the write memory barrier
used in kcov_move_area()

Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>
---

Changes in v2:
- note for load-acquire shifted to block comment
  in code rather than in the preceding paragraphs
---
 Documentation/dev-tools/kcov.rst | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd..40a4b500073 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -361,7 +361,12 @@ local tasks spawned by the process and the global task that handles USB bus #1:
 	 */
 	sleep(2);
 
-	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+        /*
+         * The load to the coverage count should be an acquire to pair with 
+         * pair with the corresponding write memory barrier (smp_wmb()) on 
+         * the kernel-side in kcov_move_area().
+         */
+	n = __atomic_load_n(&cover[0], __ATOMIC_ACQUIRE);
 	for (i = 0; i < n; i++)
 		printf("0x%lx\n", cover[i + 1]);
 	if (ioctl(fd, KCOV_DISABLE, 0))
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250803180558.2967962-1-soham.bagchi%40utah.edu.
