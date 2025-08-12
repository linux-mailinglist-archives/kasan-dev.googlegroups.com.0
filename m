Return-Path: <kasan-dev+bncBCKPFB7SXUERBI725TCAMGQEHO3SKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F200B227D2
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:10:10 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b42249503c4sf5092836a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755004196; cv=pass;
        d=google.com; s=arc-20240605;
        b=cl6aHIJXrpo9JVcv2vlN8KrXvI7yU30ngwD0i0WpPB1o3nitu2r2H+DFPbiM4hq2IE
         ruv+Ixc4Qg1EyqBjQIVc6rV1zdLdQKgt/RH6y2aKQ0u65YT2WIVxTn45xIlHNBgiT4CV
         1nK3/GMld5qbttnJZWpZrOwWS8I7dKSa+Oe1a3FedGOgJ3QTFk7HJB3fNT8bZLgVvGMM
         5WWehUQ0LmxWpH5Xm+5pD0Gy3fFgoB5EuSBnTpsy1xOQjravhJfGzuXEHxmLhVkjYPvU
         Pxnlif+kZRxftK704Ar4J3dfFbYg6+tu9KwQuxb/9R9EqJ24vs3UawsfLaqNLDfFONmB
         7EDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=KPeFxoTOZ35jpymXChMhwxIlw9TovStkCoJUwGL2Pa0=;
        fh=I3HLJQzz+ELbyesM9lFNhRKOBUO83+l06z8WB2NyPNg=;
        b=T46pMYFTHZzeiq6qU4RK5Jle0CCXrLSzkn2MoSRjUIsUSV94CH2miIA91kBQ78DfPz
         CJ9D/YIsnogkC2VnnUmonAwuA1MOM96Z6lwk/Ja6tEsfywcx6tZwoXeRminvvS4ftO66
         NMC4HYVY6TuxiWnxELZCF5SoHtTjMFLiVlC09U5D7Do6fqatMLEgmlR3spkpVRNZmADF
         SFVTbx8X1ZI2xCxdpfb1BxTsNThF6Z4i9Ze+PzABIlLXJpTy8u8bhzSIMwT8XcT1/1/M
         DruiTB3ENVqmTgOHYJSEXBOwFtLQVvZs35ijvBOHtsy4ohV0o3rD4RMPeYF/E8Dnt1qp
         37Bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SjJeihN3;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755004196; x=1755608996; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KPeFxoTOZ35jpymXChMhwxIlw9TovStkCoJUwGL2Pa0=;
        b=boS7G93BeyiHgxj0lD6Jiv1Mj/XQJ87Br5UPXWvh0+dZNXocOrdpGgO8WeTS3fHe/8
         5btFz7fFoN+IYYYiE9gKDODfmNQXTYD6uNKADrHTnrC6pdAW+p8GPK8qeOZo4pX+G5lp
         OBeB2mATq2sz3rRe6a/l0dJvkCOoTpeEzI0FgfvfrjvYgINbVzkW8Q6yQJJr5FAEJvXl
         7Mz5/v8bEmrNpSyUKvM65Pphuoxhm/UUcvJY5LMsIybXYikjFmSHqx3+WcM5IAO4v79Y
         tL1TAmb80zh7yPCgE++eAImJRmMe3lqk/h5eDh3hdad/56o0bmtgsdjnjnCXB0q08uyb
         ak6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755004196; x=1755608996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KPeFxoTOZ35jpymXChMhwxIlw9TovStkCoJUwGL2Pa0=;
        b=rE15YGR+iDlGVh+dEss3IUAtbT9/tz0l1+v93SbekMiTGAEWQXUVFu5tq2JJAP1LuY
         NqmM7vT9W9Cn6bz8Ebo54hEXTrsBeuUanL/SC1dtp+77ThFk95qP0WVJrNiXNd9CCujr
         sPEvYni8u4DrBpT9FWaWQXszwblwgyYBgVmRknWKZth5lmLoEx5yaF2rZToCteQa2ptb
         c7HMVQr6YHKdPVBWWjp1+PaDwjwtYqoXEBAx49G/pBEuxslW2p3p8m+MQ8dQ7OirOhRt
         cVoEnskEGs5YbiilqYC+HRO9dhsdfvJ1rg4mXI/W3itwqaQJ6nTkJ6E0M4YbxlvlFWtr
         S77g==
X-Forwarded-Encrypted: i=2; AJvYcCVekgyWfqGzePjpJdJ9cMCqzsatIbXGjOD2AhOsEfuJcwvgzF0QIzixqVKSUhUW4v+Ws5dn6g==@lfdr.de
X-Gm-Message-State: AOJu0YxjwU0iNrTrr8yUGBXRR/us68y4KpoWTUS/QVJ28kTIw1ly51xJ
	dNUtGb0F7pN0CwLDJUiMqQhgqDsZgrDq3vYPbSgp9XHFQ8jjbrvxdkRY
X-Google-Smtp-Source: AGHT+IG8WbrbQ9f67ceIVYq3Rqp8S0B5R5xdOTfNLdGeE1Sk6qd6oMEragwsiGVFU+WF68s+slipjQ==
X-Received: by 2002:a17:903:1a8d:b0:234:986c:66cf with SMTP id d9443c01a7336-242fc3645b8mr48972625ad.16.1755004195700;
        Tue, 12 Aug 2025 06:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeacY2R0P+6RdB/ZdM4hzVzvVLDoOLqksrcqBZzdrf56A==
Received: by 2002:a17:903:3c24:b0:23f:8cfc:8dee with SMTP id
 d9443c01a7336-2429df7d72els31440805ad.1.-pod-prod-00-us-canary; Tue, 12 Aug
 2025 06:09:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJdqx0RqeYZnP3LSoi8f8Bq4mdeoH6fXQIjYhQkYSt2wWTwIn3rUDJarxc8AZZAEnOB0OcoS/VJAU=@googlegroups.com
X-Received: by 2002:a17:903:28e:b0:234:595d:a58e with SMTP id d9443c01a7336-242fc3fca04mr49355105ad.25.1755004194126;
        Tue, 12 Aug 2025 06:09:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755004194; cv=none;
        d=google.com; s=arc-20240605;
        b=RMKEPTG2qE++3aewncw7XkhRkzCTG68qB6FtoJOVnrpoc/dXxvevx5lTbHifH9EQlc
         A04/5D4fg2kvMm4/jVsDXhNrji7rDTZE0X+P0m3X9TkdPYVFXkBqi8/CwPVTIcJQMUt5
         ciTk4kttW4wxA4LGc0iGr546zzIMxjq9FssS1cvMbqHd/kQPUtR9zpZyxGYYF/OTmNHH
         yO1xS4NdSkJZNPelNyWEq8/XCN4g/ZlNde/nJJwLzO5IMunrHmy1sD1KkM2Rxpb0+y78
         ZseeQqfX31kVd0olOniIN/L0kE+L983DR8wr78td3C+C3sxOZ+o68Q4fqtVckWKJ0bKe
         QXnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/cuxRnTF/+sbokXrks651YRr5s4tLHJAN7bhV7Yv7fM=;
        fh=tJzQ5qxkJm0zG4QpcVmXzoBYu5DFFVue0Z3QtfeLqEI=;
        b=IGCOJJcLs+B8KHlIA0oR1h4pvsDvqMEwSXd9HcjHX0W1cuFHDpwDdPW+k8gF8NTwO+
         /9D5VC+5il2ZsUtXiFOW8IDqOyJUpzCtycFU1MpOvkqWGP9BdRCBEHU7QDvJpngf9Rns
         JDG+Bdguu6sWZl3svHDx50TOCH/BAQcU6i5LC3TRp5/qawl1yTlTOPz/UTdYOX7ea9EP
         /A93FrBVu8dOW3Xwh295xFf3KSzBjMFzJryOqqNv0dAutH7d5Jtoc+QXTzR/ys+i5Jtz
         2n18j0Oj8apFojay1nrh1WQdaWBcEoeAuk73D/1ublBsY1atR+XpuTb1bzcwUP2m5e24
         wmuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SjJeihN3;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241afb2714dsi12564585ad.0.2025.08.12.06.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 06:09:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-524-SArAZdPZOtigwjx2dT9jhA-1; Tue,
 12 Aug 2025 09:09:49 -0400
X-MC-Unique: SArAZdPZOtigwjx2dT9jhA-1
X-Mimecast-MFC-AGG-ID: SArAZdPZOtigwjx2dT9jhA_1755004186
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 87D20180036F;
	Tue, 12 Aug 2025 13:09:45 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7BEA8195608F;
	Tue, 12 Aug 2025 13:09:36 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: snovitoll@gmail.com,
	ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com,
	kasan-dev@googlegroups.com,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-um@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	agordeev@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH 0/4] mm/kasan: remove kasan_arch_is_ready()
Date: Tue, 12 Aug 2025 21:09:29 +0800
Message-ID: <20250812130933.71593-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SjJeihN3;
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

These are made on top of below patchset in which all functional functions
will be skipped if kasan is disabled by checking kasan_enabled(). With
the changes, kasan_arch_is_ready() can be easily cleaned up to simplify
code.

[PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
https://lore.kernel.org/all/20250812124941.69508-1-bhe@redhat.com/T/#u

The 1st three patches are from Sabyrzhan Tasbolatov's patchset. After
clean up the kasan_arch_is_ready() definition in loongarch, power and UM, 
we can simply remove kasan_arch_is_ready() checking in mm/kasan since
all the checking has been covered by kasan_enabled().

[PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific implementations
https://lore.kernel.org/all/20250810125746.1105476-1-snovitoll@gmail.com/T/#u

Test:
======
I have tested the effect of this patchset on loongarch, power and UM.
Will try to find machine to do testing.

Baoquan He (1):
  mm/kasan: remove kasan_arch_is_ready()

Sabyrzhan Tasbolatov (3):
  arch/loongarch: remove kasan_arch_is_ready()
  arch/powerpc: remove kasan_arch_is_ready()
  arch/um: remove kasan_arch_is_ready()

 arch/loongarch/include/asm/kasan.h     |  7 -------
 arch/loongarch/mm/kasan_init.c         | 10 +++-------
 arch/powerpc/include/asm/kasan.h       | 13 -------------
 arch/powerpc/mm/kasan/init_book3s_64.c |  4 ----
 arch/um/include/asm/kasan.h            |  5 ++---
 arch/um/kernel/mem.c                   |  6 +++++-
 mm/kasan/common.c                      |  9 +++------
 mm/kasan/generic.c                     |  9 ---------
 mm/kasan/kasan.h                       |  6 ------
 mm/kasan/shadow.c                      | 18 ------------------
 10 files changed, 13 insertions(+), 74 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812130933.71593-1-bhe%40redhat.com.
