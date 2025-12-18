Return-Path: <kasan-dev+bncBCT4XGV33UIBBH5KSLFAMGQEKJRGGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB13CCE02E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 00:58:25 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-88a3822c06bsf28843496d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 15:58:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766102304; cv=pass;
        d=google.com; s=arc-20240605;
        b=W6OYWZqZlilgNC7Noh6ZHwipyD/ZpyoRxNeTL4+C8KrVnwL9f0askjpgYKgI/NRK7s
         DicKJWl0AJGXq2Io9g2ia89sirZ5zqhnha41637jdpYSuaw8x5lRCILS11mfFrqJxkzM
         JxmO/k0DykQMrLypqX5Hd5ewcda8qE4lOtrMC0kjuprPD51C75q8W2V5Rfqh5Ifyc4qc
         oIC0L+FcCzdvYWxaBUuYcub8aLxOtFIJbTCWw1NqAdbKLkhxl4uLLQy4l374ULaZ4Leu
         YIJz5cXOq/o/e4KWocWVL1lSEvaJun81cjbTQXMvh73Y2QySahBBuqHK6DUP2a1rDHoW
         s+yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pDnvhnWh5ZlADJRHmo2yjqQU9lwxW03Vym7lT43PWus=;
        fh=m5EO+bNZN/MOvRvcpUei9taNnqeIJhYXss0VQmtb8iI=;
        b=kgrppgGQ3brLpstAeQU1iOYEkmpWSVhpEktPh2sMW2rs6jfymv+IyBYU2FGaZdJCik
         j3dZ4BLH9EIkitm+s3BUT6cXqimaAmXOf+6mgI6EcLPbkZiZmM7e4Y/+mR6sxGilGP47
         lZHmiQZXrjzuqDvSH08ynCbbr5myMmP4nncypF37UJXoOMgIK/hvQO6v9/2HzQBiQQsn
         S2dZ6xlnQrtu0qd4sMfX4N78HRFaHvONhQSp3fm0KVg5xnaC/bbN0lGnafwcyq5/R2bX
         ur2j+GwT5tIK+PumAriWOb4ywuPRoexTTwpi2t6D9tp/WYF88u2eF6jh/2CavCJD52yg
         XVYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zoDH5EiM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766102304; x=1766707104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pDnvhnWh5ZlADJRHmo2yjqQU9lwxW03Vym7lT43PWus=;
        b=wyKNdS0mDWlFowKA059czVfruLEzyAacgvYbyb9ky8GSsblSYV+gTNjUs8xOdk3fpz
         BfC3QRDQcHa9hjnYIU5SGWSD+xEe9zLOkiYtpmxkMz78ZMmahnAmwhRPOdJYqdKqvHo3
         EiU8153AI308t4JWKPJ59V4IBeRLBLd9pDnjYHJP7ltJ6lHVAMWlrX2p/vCAJHOA/Hqz
         deeOXkmnO1RRisKGYmTy/u3psZqJGWjxfeRL8itEp4jBaMNCRFsAjJUJWfpVoHWOWw57
         3j+W35e41bPDfGKVKcA3EuKKLyISwxK/uIoiJuG+glSpVXVWe/qlyzCOPUhiqUwbMm/3
         u9Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766102304; x=1766707104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pDnvhnWh5ZlADJRHmo2yjqQU9lwxW03Vym7lT43PWus=;
        b=MTmNnsEGOqZ0X178Y3Y3M16FozwbEcs/HBvjMmsYgcAtQV2cQ49Z1DLSatT9FnQP+R
         oU7r18I17IcwuTIpi6hCROLAmQdVnRweeovOWs9mrx1oEEbCymk9vtDXD1yLLS0MYfmQ
         mDrAgFraTJtW0itCMBhJkB/fG574gTBwh4bn0OOqHUgtQG78IIHcFgujipXBZHBIEqJD
         sYeLKIkDJkeOo4sNwO4hfhysuTuZuEAiKCdoptBGCSIC+o9KVCQCJypQMmMN4/It6wgv
         3EEOMrERkvDI6gImqKwxZUVaXUZ5UXR1gHqtcUw8pDDoU6v3s7PNFdrDAyabBhWJj/2o
         6bwg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXU3D3DJkCJu4bhm33bBOFVgXmes1x8m+lNSajkQ0lAJHU1DLAShwcvlCEOSl0U5zkEFz7Q3A==@lfdr.de
X-Gm-Message-State: AOJu0Yy8mzzcsdLL3PUHl0zXQHJtZ9N2iCvO59Pg0yGNHZlKLTBQrWsg
	QffTm/9LOSFd4YSWRyZeSxiZWJlBIPHK12kUcwIDJpJBaUYk8VaDi13O
X-Google-Smtp-Source: AGHT+IGTLtlPeUtmcQo0Cq4u4oabxVL+NTuVvn3p55OuUhLTONP7qCJMFFBj5gL3Zqzy3MVejOQk+A==
X-Received: by 2002:a05:622a:1e93:b0:4f1:ba4d:deb1 with SMTP id d75a77b69052e-4f4abd97f2dmr17636681cf.46.1766102303913;
        Thu, 18 Dec 2025 15:58:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbOYpJ7s7rrpmAH4khzAGYmUkgO0Z5VGnn4Zf0m8itxnw=="
Received: by 2002:a05:6214:4006:b0:880:31e4:d7e4 with SMTP id
 6a1803df08f44-8887cd58997ls119306836d6.1.-pod-prod-07-us; Thu, 18 Dec 2025
 15:58:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAb8nKNHmqKMRbqPXL8xUOTumQ4B2OsDU/TjNRxVXu0QCIjoJ1C+T44Bl9maAmrTo6r8+ewIhR6I0=@googlegroups.com
X-Received: by 2002:a05:6214:598e:b0:87c:2c76:62a1 with SMTP id 6a1803df08f44-88d856daa80mr21334026d6.67.1766102302919;
        Thu, 18 Dec 2025 15:58:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766102302; cv=none;
        d=google.com; s=arc-20240605;
        b=i6y43LmqzV/jruHS3PeDqVhQZmV2VtLwr9Uf8XX5YaXOt3N7AQysTZgsqIxxIYw117
         sn1BZKtaAyuRVOKK7ZNpVm7dFEK5mHIvCaCka3Mbx1YpUJXbOI/4fbHf0vsO2WeOHpZv
         p4CAmYnnl6zjzdrRbwvIBhX4mmL06f3VaM1fTGcFDKTRlni63+/KEoXWP5aDhLl6dh6u
         vBDJ1aCexP1Jhj/gLuYasu7Cvw1UzxJp9CZMa0YTYD09LJcF418B6fme+jW/p2g+4UOx
         G6fXsdpN5e06t+p0KbVwLvIW03cRIqLfNm6wY2ltktO+vsEDyF8fQlhj9JNXbtgmQL+k
         Twjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=evpGQd403RyTq2+Wy7kNHnZPf39hVGXm3tsfr/+j2c8=;
        fh=W2kIiof99fyTkq63gpfBRUfh3fr3QIdqKw0G4/0A4iQ=;
        b=Z/M4dautkyRhSg11yfIT2DpFur45CYZpr7RO3qW8OKHRC+LTp/+F4ZacjlcJQfrQHy
         w0lkimW1j+2cciVk5CWnLLcJNXwmGt53PnGlHXskl1AuN5EOni+F6B2Av52dMdWdaDSj
         TUrVU8B27J7xEqXJriL8FbzqMW5fcIp+O3hLtBEchr0McQYFGk/3LphVDdBWJe0H43Gy
         L4gAS3K4+NPriPmmTSbPqgxQwM76+NhBmVfba/MFbECb4FsyFAjACHL6jpPEkeVhSO1u
         4pT7xQcayTtXgoFJGGdVldCb194VDDo/NzvX7ta/DAxT0/IJ3Gfv2hq4yvl/MkvU+rBm
         A3/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zoDH5EiM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88d977911c6si149876d6.8.2025.12.18.15.58.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 15:58:22 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5F68D6000A;
	Thu, 18 Dec 2025 23:58:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C0087C4CEFB;
	Thu, 18 Dec 2025 23:58:21 +0000 (UTC)
Date: Thu, 18 Dec 2025 15:58:21 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: yuan linyu <yuanlinyu@honor.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Huacai Chen <chenhuacai@kernel.org>,
 WANG Xuerui <kernel@xen0n.name>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <loongarch@lists.linux.dev>,
 <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 3/3] kfence: allow change number of object by early
 parameter
Message-Id: <20251218155821.92454cbb7117c27c1b914ce0@linux-foundation.org>
In-Reply-To: <20251218015849.1414609-4-yuanlinyu@honor.com>
References: <20251218015849.1414609-1-yuanlinyu@honor.com>
	<20251218015849.1414609-4-yuanlinyu@honor.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=zoDH5EiM;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 18 Dec 2025 09:58:49 +0800 yuan linyu <yuanlinyu@honor.com> wrote:

> when want to change the kfence pool size, currently it is not easy and
> need to compile kernel.
> 
> Add an early boot parameter kfence.num_objects to allow change kfence
> objects number and allow increate total pool to provide high failure
> rate.
> 
> ...
>
>  include/linux/kfence.h  |   5 +-
>  mm/kfence/core.c        | 122 +++++++++++++++++++++++++++++-----------
>  mm/kfence/kfence.h      |   4 +-
>  mm/kfence/kfence_test.c |   2 +-

Can you please add some documentation in Documentation/dev-tools/kfence.rst?

Also, this should be described in
Documentation/admin-guide/kernel-parameters.txt.  That file doesn't
mention kfence at all, which might be an oversight.

Meanwhile, I'll queue these patches in mm.git's mm-nonmm-unstable
branch for some testing.  I'll await reviewer input before proceeding
further.  Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218155821.92454cbb7117c27c1b914ce0%40linux-foundation.org.
