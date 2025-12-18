Return-Path: <kasan-dev+bncBAABBHGDR3FAMGQE54DHQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9660ACCA7F1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 07:39:26 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-6579875eaa2sf337532eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 22:39:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766039965; cv=pass;
        d=google.com; s=arc-20240605;
        b=aO6EkihF1/Kyal+yu5V51oiLIFjnO0Mgxa1UPYFs1KDgUFNehAT7dm1PONfgya/bOV
         YlcYDq3/XB97vatYdkQ5Cwwgjy5/aS9CRZuzcP9idhDM4CSEAnTR122XJ6W4BgtdlOzL
         CVDd4a8aSNFw0Vwac3N16AxSReVs7A76uNUJm8d/9ErDcaaQEnsQ2JWO8l2WS6qMlUoV
         KpeZ8M4/+GNXzbjSJ6APJZPmivnf0QhTJXisk4sBsskzqK9toal7ySM4wlYzPNP3i7J7
         AemGQGjOx7D/cc9OgqbLally1E4ckU3UN+e8cJNfPiyD4gZbWT3h4AHNZxs+QEv1KWLB
         fhaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XLBGrJ+t8exxIaUqUlh/dg50zFp24xhomLz84/lFcXQ=;
        fh=LS5l3y+Q583TxIADmx1bYDL5/uyAb2ZtJVep419WkKc=;
        b=OfBrd2m8kbytXN6MPo2nQPIEhSSVjAisEpT+aZP0LK5a06UWwYdkoZ//0RU2erBZdM
         Duoyewjytud0q6Bzo9HHm4VJNqjv30E+uds9PENmeMgFZsNlUltKGoh/UxeSp4/gEMLK
         Ai7spki9ju8zc8HBmkcIU7FV1YKgvZohgH77n3uzKVsqsIpWVNhzPoDKg/xlJ/J83Jiu
         m81Ndye7FDenzK+WbgMQKFeETrMJ5wHwzjsgi3f8TovgX6355UssW5u+Pzqt+OlkEkIk
         GrfdZidjzLYM/FIk33fjcDnnxO2UAfChA+OOOPu1usY0vdgHx9WA4l87LDZOKnbV6GLH
         ifbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=DtwNyro9;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766039965; x=1766644765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XLBGrJ+t8exxIaUqUlh/dg50zFp24xhomLz84/lFcXQ=;
        b=pYEETZMBY4S17Y5Qe9XaDhRuHcLKSPrGTDVAJWsFZJqd3mbCPS9Ms80bPQ1MUWRm63
         eI9NItZuwyVfaHgqSVXC1yxmRLrzODRsWxXwZ3nVlfpkMENfu1oJeU4CcDJy2UnLnjGe
         HgbSx/8ToX655GJKXejVqqLMQitbQgYs6Rhf/PWqM6D4W2t2THY1Vgsnw/D5UoJzR3d+
         W3YXknVHt4/bNvXYuELEpNt8UjqGs+Z+JDKhRN1Ez4GkhNzjpxryfRaLakAQKLgRllrZ
         Rv+yyWKBuWfZi+6xfcFplbceFaGZdO43EpJ/QyxukdJ4h2/LakjNLtoPqUuUlj79ygk8
         cClg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766039965; x=1766644765;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XLBGrJ+t8exxIaUqUlh/dg50zFp24xhomLz84/lFcXQ=;
        b=MXK1Hd/C2Ap/f25EmwJGV8aNz4GUSGkG7W6XCh6x7Xe5QBtNWZIMTF2gjzXy/We+sH
         CmeauQzC03g9i1a0SJ1NBTCEUyUEi0cMvFbi2ZjBah74VmsA7jKjSBT5JntfwtIfAZUA
         VT+8iaH72ER48QCHMSQsnc0VpgSdF4xcocj4guko8wcZYjVv2Z2gOLW1+u3dysoWkso6
         kcHKE+5yfVRPx725nNH2Z3N5h4X1O5H33adZ9pnppx1OtPEzJdBaPg/YUuc6rriJMO1R
         XO61GTNYYZvAa5exf4KWfU3QupeyZlQ0BkoE9xMRIz62wBL27gQCfTmGsypVi1drNULU
         4Iog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtUphavAAqM3UIHyYAVPHxH7XbQyItsFfF+0qNDkExE1DbcCrmak+wQLWJI6/1y0tnyPxKLg==@lfdr.de
X-Gm-Message-State: AOJu0Yzt2JlG5aWbUHZQdeYo4hRN8VlU/EHxpjDnW0my6GW9bIRXS7vP
	t7AAUHKkrnCmBREggXt+7HUyun9AB4Ci+4iJGVJerLF+0uA9PdFd2M0o
X-Google-Smtp-Source: AGHT+IH08r3vfJlyfc4J4Ov7wg6IpfVphrwqW+D/8vFTn+HKCmJHWHClNHM4LphfQhPsTg9RpX/39w==
X-Received: by 2002:a05:6820:1c9a:b0:659:9a49:8fbb with SMTP id 006d021491bc7-65b45257500mr8663980eaf.52.1766039964847;
        Wed, 17 Dec 2025 22:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYz5C5U99kVlB9axnUFxxxl0vAa3SO6o98tPNHLYHZZJQ=="
Received: by 2002:a05:6820:7404:b0:65c:f62a:5ab1 with SMTP id
 006d021491bc7-65cf62a60c1ls579211eaf.1.-pod-prod-05-us; Wed, 17 Dec 2025
 22:39:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZRwP8bhK4OtY4D3Ck0gpsrTCRygTYmHZmRPC+TXlDrF24pYOFq/H8+2/y4RvxgR2GdazCenGKBwY=@googlegroups.com
X-Received: by 2002:a05:6830:6747:b0:7c7:595d:abbd with SMTP id 46e09a7af769-7cae82e4083mr8879505a34.15.1766039963787;
        Wed, 17 Dec 2025 22:39:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766039963; cv=none;
        d=google.com; s=arc-20240605;
        b=lBtXFVtRFqlX43GyRl6WcMx3RmyAEmIuJXc5h23NtRRjuMa4Z1kg4/n7s9Kmy6yGJ2
         M+e8CBHtQ6S5jCW+QzPyjOrU+m5MpXcX58P4q44p4lF5o/jU/y0lShLfxHK0/fD9J6r9
         n2OGY5i+6mMoPmsib+pkPbv9x75+No6hJmSEErwyS8w9muz+2Fkf4REZLu/5HlVK0uoz
         vd9KZ9pHrtXYrKU0R8N9cBkh6eM3SeVxPF1412OECx9kUucWZIFhEngm6ojpBRIz1fic
         nuubaPjghHdHM2N7MRDwcbu8D/eRreykQONdkQFLkNfHZNYbtf/O+blbMli7j1nrVwAh
         q0HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RURcNCeCYd6BsieRLTf6v+zeOuKA6NvzwDD7Kc6byDw=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=V3aNIrszksrmfo/E0j7jGWumX4Pjmt0cLbBiblP+BtKEfyRuPl5PCNTnb1zy1/Umvo
         ya1UFMHtlC7I74/dpk+M+AqXRHH5/qPysTw22Eq3z9GPYleWqDCnoHgIkjDEFCIYrtmt
         +ncNpiXBAexQKs7mCyZJjuI/SoxSDt2VTXCHr3nes1ZDR2dgPTSjKED4z3kfRW1g3nef
         jV5xFi6nNrSQnl4Do+wKGEcEcP6SHwQ1H0A1gKh8r1dicHL9VwzKqSK3GlBXkV/UGVlb
         FAgl1P2BfocnEPK0wSm0TkdBZw7RoVCzy6Uub448VvftSBbaIeFgQvHmrl4s4i6oRw+w
         8CVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@honor.com header.s=dkim header.b=DtwNyro9;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta22.hihonor.com (mta22.honor.com. [81.70.192.198])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc59b38ba4si82131a34.6.2025.12.17.22.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 22:39:23 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as permitted sender) client-ip=81.70.192.198;
Received: from w002.hihonor.com (unknown [10.68.28.120])
	by mta22.hihonor.com (SkyGuard) with ESMTPS id 4dX1Db2T2YzYlQ6R;
	Thu, 18 Dec 2025 14:37:19 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w002.hihonor.com
 (10.68.28.120) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:18 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:18 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH v2 0/2] kfence: allow change objects number
Date: Thu, 18 Dec 2025 14:39:14 +0800
Message-ID: <20251218063916.1433615-1-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w010.hihonor.com (10.68.28.113) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@honor.com header.s=dkim header.b=DtwNyro9;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.192.198 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

patch01 use common KFENCE_POOL_SIZE for LoongArch
patch02 allow change objects number

v1: https://lore.kernel.org/lkml/20251218015849.1414609-1-yuanlinyu@honor.com/
v2: remove patch02 in v1

yuan linyu (2):
  LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
  kfence: allow change number of object by early parameter

 arch/loongarch/include/asm/pgtable.h |   3 +-
 include/linux/kfence.h               |   5 +-
 mm/kfence/core.c                     | 122 +++++++++++++++++++--------
 mm/kfence/kfence.h                   |   4 +-
 mm/kfence/kfence_test.c              |   2 +-
 5 files changed, 98 insertions(+), 38 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218063916.1433615-1-yuanlinyu%40honor.com.
