Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2GC222AMGQE7KZSCVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BC3F931D23
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2024 00:23:37 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6b22e2dfa6csf74567436d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 15:23:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721082216; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOfRoFgAiFB5EMl3ARTj5+xX9xpAgrG/duelbPWISfh9zgbqfc+Ic85YcJ3FhqDppe
         7pgew5CGOcRPZe7hnLC8Uy+10kryhmhVI/a6k37TPPKVA00nWigme21iC8Rwe1R2YyRj
         umncgfL7b4lz8GULKlZBpEyD3XEOKEY/eaI9sQkvqjVyZMQM6Z+BV1xi9rA/JFkSLwMU
         H5pR/RKB4eUrAbpdQ9AQF1XywmjCB/tL75n/Rdk/X76QY/hl6TWO6DhTvsjSI0idAJHf
         cEKqDz1WXDUFEZFJIejhi4Hl8mUVNDWLaS7+rIy0qCm/HNYNIURc48JVxQpN3h7xBFCm
         V4ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TJiZ8XMTOB5PxVx2GobsP85oWInCl0g3+LhjSWAeFBY=;
        fh=ZP7rmYQptx8lOJP+vJz5Wn/MJl8bb1sC+3tBOustnSM=;
        b=HqLMdsvExAA1x4hi3eBNV7XnVQsk+dYIhly0dZI9n+sYghZOvetFBW8ASQQhtk0tW5
         aVovh/k+JhCufuFhJN5CYHCHOX8ff9tbP3pPU8mzaVIE5rF4oh0PCPRIZblePdfkbo8h
         8GL2oWN35oKagGCYp/DMZ7Ws3jhCSdX5zyz7ar5fWhdp+5kkSZsoj1I2Xiyh4xHwgrUv
         O2YGBQ3DYBvTKe9qbxUAVNH5AYdxJHA12iEvZaehAcG66hvnzvjQsYQRo0ZBw8IcbNLt
         Q/Ds4mpMOyyaLxYs2KE3fto/2zfgAzG9/nKfw61o2M3CgHxJoKeCv1FErtLMSxAE3EFS
         qDrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eErREg8f;
       spf=pass (google.com: domain of srs0=2mb0=op=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2mb0=OP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721082216; x=1721687016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TJiZ8XMTOB5PxVx2GobsP85oWInCl0g3+LhjSWAeFBY=;
        b=htafk/knJqsTZU9mfeKDL3qEn8urZkpTVgbr+xF40n7PAfLwicJP21ZasQrJcXcWla
         MtVjRuq7I3EYkDd7Z2CndKuvsQP5tlaCaP+HKvDXZoSYkmaqHAVrbTONutJQFDWmQm88
         7tW2pqJYObrkmOvFpDgOu8vE4hzM3ql5npcFz3rjRbGXDmQ8kbjXV3PACIhgWE60CF/3
         LVsN8pg+ujfoD6u5qEmhFx4qizzI8jgJUv43OaLQih7cKE19d5wlPGWerq/6KJg7vUmq
         Mn/zBlpKvWmQoHraBh7wegQpMC3ZtTtznIVS6gZ0mJGkecoFUl26GgI89wGD52wD0AH9
         uC6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721082216; x=1721687016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TJiZ8XMTOB5PxVx2GobsP85oWInCl0g3+LhjSWAeFBY=;
        b=EZiT4jOau7f+0mQRIQnislN6CjfHcQzVQA85H9wex3LcCx11Zhf/quUJA3bLehqqCb
         EbRQY7YP1BSSSbQyTKBxqGFOGJ0UyJ5cvFwkPpF8PPUiXr+Aag6BA3E88RiKGqfNAxQM
         dm1KRbu0ONxUH4SaJEl85LzxGalkVFJhpb9/w+c9rmJ5ZXmxKTMrqQZYNMXnw056q1Cd
         FmrQRRodHehoyOAIAkiRsTPLPe3PtYZBSZP/cevphrGosyIWFBj9kdA9gveGliQMmxyX
         ZA8mpMLv8JJaLW73euEfYNQMqALckeXLPG4EWpAkqTW+zo0lOQbnR21SukfnMAWt5zcc
         OJMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2oCbU8wGyR0dSGou8j5QQNcF3/YsPq0bBSDS8eNvmKUBg/g0InQlkAZvE79AnU2pvQAfIV/JrmNu4etE8I64PDr3PBf+t8A==
X-Gm-Message-State: AOJu0YzGTU0FHch7hB6hSE6qDlsjQpEKMSrdCIwac+dunCVfXJuZLzCh
	/j5RMt1142lNfvV3UZLXm4uiCKaraLTI6ioWKOZHaqiLa5yH6AKU
X-Google-Smtp-Source: AGHT+IHMtkZly8TOO88XGfqA4BXtuI1VzlL6I5d86OmVctxAYeE8FzNTCd7EcfXqHZP6nEYT4GkqCA==
X-Received: by 2002:ad4:5c8c:0:b0:6b0:7f0c:d30e with SMTP id 6a1803df08f44-6b77f4c178dmr8267716d6.10.1721082216213;
        Mon, 15 Jul 2024 15:23:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4a4f:b0:6b0:7204:3b2 with SMTP id
 6a1803df08f44-6b74b43be7als76193266d6.2.-pod-prod-09-us; Mon, 15 Jul 2024
 15:23:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6Onl1GKS7T+dAvBtBFIm4r/wl3gJziaM+XXRs79F3idTaY8q9R1VZtrNGYk6ZzLg/wLBYq52rsbTL1rVUoK4aA/He460aFRYWOA==
X-Received: by 2002:a05:6122:318d:b0:4ef:630f:d579 with SMTP id 71dfb90a1353d-4f4d07a808emr465765e0c.8.1721082215106;
        Mon, 15 Jul 2024 15:23:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721082215; cv=none;
        d=google.com; s=arc-20160816;
        b=MGLuFrMA4hqWyPMukbxh+JXGb+opRQNdVKKo+oPHEUatpbmpcbfG9qDxKIliDKNIns
         16vSoeSXzPYFL8VTfLVrSUn/NKXcFayaR/wcFk1u0UYRpUCUn+/N4r0oCxyr3f39udek
         Go09oSXaqCkAzY98GvEPuzYv6+xbSIUPHFEI7QFjE8+QUPh+1fP4atss1HrKHOo2mE1g
         RrgQc133KDXhzLUzL2R57T98rSX4A6XE9EshOYl2TJsipm4TzRKG8xntrZP3prBmc8VP
         ACktFdFFXC5Y480IyT5Yykvx4shJlbm6f1Vl8lcP2d8Ty3MMpCl+dejHox2GlQGX9Y1L
         qzug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=uPT1V2OcHL7MsNs5RjhfjtHDRW+PK9eFa7vo/WTV1jY=;
        fh=G7sqrgAaALmWVZS1ZT2F8c0AG8i05U1wDYGNS3SYC7M=;
        b=hTVpnBuQi8Zqx8NK64c465Cr5YldAei6+k7E4p/SkkzLuIk9WtrTZuISDYiVgEAVub
         HNFWtAfCg47vK5ut6m9mrwrQEeQKR5t+eYt/w76dKyVA9gxBnS5Y/9HX1SZ38fWqToZI
         7fYL9YD4lEu5AictMQncPkoDLNKgZQEomK7Y7cw/6JxWPXBc3oQv21DeI5+Mp7un4b4l
         Xv5bPlX2+UVFsdfgD+b/BbzK1BX4DQkIu1miK7YHOgx/LXcWdPrBiOReV3nGgFKsMxSX
         NX5Mmtx6Wxu+AVRF/QqPgmvq9DE9CvAAqT6RsYMiEG3K/4M+3Hr9zuYt1fxBR8jFp1ff
         76jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eErREg8f;
       spf=pass (google.com: domain of srs0=2mb0=op=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2mb0=OP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f4a468e6a4si205589e0c.0.2024.07.15.15.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jul 2024 15:23:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=2mb0=op=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 488CB612A1;
	Mon, 15 Jul 2024 22:23:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E9826C32782;
	Mon, 15 Jul 2024 22:23:32 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8E245CE134B; Mon, 15 Jul 2024 15:23:32 -0700 (PDT)
Date: Mon, 15 Jul 2024 15:23:32 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, elver@google.com, quic_jjohnson@quicinc.com
Subject: [GIT PULL] KCSAN changes for v6.11
Message-ID: <6d532a3c-709f-4038-8482-34dc2dcbfaae@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eErREg8f;       spf=pass
 (google.com: domain of srs0=2mb0=op=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2mb0=OP=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello, Linus,

Please pull the latest KCSAN git commit from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.07.12a
  # HEAD: ddd7432d621daf93baf36e353ab7472d69dd692f: kcsan: Add missing MODULE_DESCRIPTION() macro (2024-06-06 11:21:14 -0700)

----------------------------------------------------------------
kcsan: Add __data_racy documentation and module description

This series contains on commit that improves the documentation for the
new __data_racy type qualifier to the data_race() macro's kernel-doc
header and to the LKMM's access-marking documentation.

----------------------------------------------------------------
Jeff Johnson (1):
      kcsan: Add missing MODULE_DESCRIPTION() macro

Paul E. McKenney (1):
      kcsan: Add example to data_race() kerneldoc header

 include/linux/compiler.h                           | 10 ++++++++-
 kernel/kcsan/kcsan_test.c                          |  1 +
 .../memory-model/Documentation/access-marking.txt  | 24 +++++++++++++++++++++-
 3 files changed, 33 insertions(+), 2 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d532a3c-709f-4038-8482-34dc2dcbfaae%40paulmck-laptop.
