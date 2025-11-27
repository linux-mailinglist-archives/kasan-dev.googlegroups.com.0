Return-Path: <kasan-dev+bncBCT4XGV33UIBBT6IULEQMGQENYNQA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 05C94C90009
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 20:19:45 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-3f0d1a7a9c2sf208275fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 11:19:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764271183; cv=pass;
        d=google.com; s=arc-20240605;
        b=WaROIonhmWNh2wqexDltGDuinwoTiSgoF55fVz6gLFXulPEBPZe2PAFR6/57k9Tfpo
         B1cilZ/rePZPD03WiobWIpxT8cgv9Q6WihxU+Dg93aE7rVLZAnQdmmVjWi/vfda2AcYU
         x6/dgopMEtUigbuQ2gdgL05sDy/B1c8J1CSPDV43kLxl84cgypX7EO6or5scPfDj6YFv
         aXMVKjWdsgz74LPZ0oBqqhSQhMoKHDpJrbeWMa+tilTHaK4g/0sjvBZD882/e8I0H3dJ
         Koon7645F1AwZD6XQTz3QnHpGl+BrLheyNOGg8Wp4vZhpwpdh6imYYzTpBmyQUsoPOVN
         W1UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qlRLRXQrtkR2v/ZTiqutSq/GNwqCqJgwFSCdVjQC1as=;
        fh=RrQQmc9gBBhuWpeU1/r4dT4bPxUbrXZ42k5f0M9it4E=;
        b=J383/NWCORaKcA77+IEEGiVXUnRT3j6ab93IbIw2qbhBaBa/jAnkQZluAPVW9ZPgGm
         tTj3dXGfZ6IKpkxLIw1GWkm3D+5bimvcflPt743KokHRPyo/u9AE7DFOSfaFdX8jdXwF
         3Q7ZpdLJPzQyorVtZ2skeg+Eb7CE+2NSFr5Xo9dTv+k66aDTPOqzPKp4Lh6GrOxiaKF/
         wtgqBLpqRWy/NKhmh9gZj1TFqU7VHSPLFLLlVVehSUIGq8L/GcR1UivJqd2SwZZspRs1
         WBYwTVJQoE5/WPp6ERRqJg5f4rt2vJUh4BVGJW6NXUwJIbXrTOMRvkuyMTUWDeDPmyJd
         KH7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ElJMCl2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764271183; x=1764875983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qlRLRXQrtkR2v/ZTiqutSq/GNwqCqJgwFSCdVjQC1as=;
        b=p794WeGbRKlqIBd86HVIGxyNwL/rf8q9iowMAXdwV4HbAN7MpJOpEUn40NmHAvrlOQ
         Y90T6xZ2TKdngWSIAeLa8BRnFt3Ro6hcZ8aPZKvtN/3Jp3hNsuXzugSu+nEDo3bdazcv
         ut7k3NhEmrU293pNOFtNx96GHHnRsXlm+Ukl9rMqGL/qYQp1oq8I+y7218Tmkz1XXi0Z
         x1QOBzhF+exStjyU07mS7WWUdjx8qa6Iio2M/6MxTBksf3sbGhMhl8ZYkp96S9HGjzZo
         GEoMZt/EMJFzlcGYn8VG7kEKV4wpJU7RD+/K2oRsNrHdbrGij+oaz14834pkI9i5vaTX
         D7Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764271183; x=1764875983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qlRLRXQrtkR2v/ZTiqutSq/GNwqCqJgwFSCdVjQC1as=;
        b=KUcGjobV00CFW3Pa1x7OtYh/Cq5xZ+AyUwxxRXQso0piFY8ZiwBhcnBsVSgxGmK4St
         8XUOKT2PBxK3EFkj+4AzCEeUplLq/UESHChS60dD39b0Cccx/Y3biimpd4rNATIVhTNC
         civrmaXqA0juyFqBqiPeRuXwz53lqrUwruSkM3RoiEFYPAkBMldxXrWDpA7qkgJ2MALi
         aDGFwCDJlvs+9vWkTJMq9pwgo9mWlFPZvz2AvlYAY5f5Fm61dYon1QEELypiU+o6/GyI
         Jyem/98odbIcYtIjMUnxiCI708sUWNQoRsmHGdgvLAExoWAw0kjgAwmIIqF/+OIY8OwN
         E2vQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnfZvmjW2cSxOr0w7A1Z3plNsUIf1UNdu8nbyZ6IVLHnk5f3yMf05EQ9mVP2x9U2l81WK+Zw==@lfdr.de
X-Gm-Message-State: AOJu0YywJOCIBnLv+rh2kkbMMJhfyfmglDpawj9sqNqTL9HV1sTLUwN/
	bc95IPTTH0DOxu7l9ZY9aE0XDsaWQWx+md1Y9LD6W4qr1k7HOacRDHSo
X-Google-Smtp-Source: AGHT+IGrklYmH0O8FrRK+zD44Dao7ydm1L+2j+uXo6cDErtKHWGmDFA/zOhq5E4dS9Meot4kmO49xg==
X-Received: by 2002:a05:6870:c147:b0:2ff:a27f:9c67 with SMTP id 586e51a60fabf-3ecbe4184e6mr10269598fac.30.1764271183298;
        Thu, 27 Nov 2025 11:19:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZpM+vODkIs8phZtDQ/f/6lFqAZrVt0SRhchMy0nVrf3A=="
Received: by 2002:a05:6870:d6a7:b0:3ec:53ac:b3af with SMTP id
 586e51a60fabf-3f0d28c24c3ls453580fac.1.-pod-prod-06-us; Thu, 27 Nov 2025
 11:19:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMJdX9ksOqShVHYUraNFN9tZZELjsTs6enHIYnsV+QxD/fXEHI2bY9AKO3yJRgypHucQfwJdwAhnE=@googlegroups.com
X-Received: by 2002:a05:6808:c2d3:b0:450:125d:d9e with SMTP id 5614622812f47-451159c7a91mr8855321b6e.21.1764271182396;
        Thu, 27 Nov 2025 11:19:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764271182; cv=none;
        d=google.com; s=arc-20240605;
        b=chzwxUB9oY5lXcW4LlH+EHGviWqlpBjocy/sEonZDo6XM9JUWnFzgJZ+5nHrN4hzQJ
         MB8lruSwTBW1wx2R675FddgZp1yVHDCEKHw9ZpH5/31rVhL33W6Sn0unz6UZPBx2L91L
         3lc46ykmGrm1+0g9azyvcPTVb7PnHJbtmfwr6mQQnwP9NXt6m1DecPQ8+gDguWr2kHd/
         vNsEUkjchvFWviYH8QqEmY5dRh4628j+DMx9YaCnZ1DjF3/wseUG9v9hqhjU0aXi0riA
         i+G7CeSuOPvDqGFlk6dNjzs9FXG8PeyIx0IxkyWT6F/c4xJVI6oyumpoZ3MgKjLnt4YO
         drWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lFl+9yBh6HzJeenYsOozHNbeB1WeA78wq/bgtcQN7n0=;
        fh=UaJGxuFybwe1NskxHfCsG66Q3oBYKTBpuGPjp82ZYLI=;
        b=HBoJ5p2OgBiGx9qvIzHvnxBf8cZWJJ6iVJHcnTWMhAGFmYDWTRSwNiKsjEtpdqL4zd
         syFBZynbZolE71u/41/kdMHA6OGfFDM7xKtpwAwTVceZUro1w40tMYDvJ0PuTG4C9tFK
         FVpp7cKQy0A/krcqRCB0tMgHz2sIYxl6wt+wXXhwqlkzio1lo8R08W2yp7ODOIUEOCTb
         tiu+56TgpUcXzJQ/2gCpD8C+XQFc0qXKRAAUiDwG/909+8xdsbxElmh+7rb9NVudwVeh
         cXWzn/oUS2HRDv0nKroP9GTjw1sEZmISYU5FVwC6oTD08AZe9WFPyv0DSZgP/Jq5qgdf
         Nc+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ElJMCl2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4531707bf1asi68264b6e.6.2025.11.27.11.19.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 11:19:42 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 768B140BF1;
	Thu, 27 Nov 2025 19:19:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1801BC113D0;
	Thu, 27 Nov 2025 19:19:41 +0000 (UTC)
Date: Thu, 27 Nov 2025 11:19:40 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Breno Leitao <leitao@debian.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
Message-Id: <20251127111940.8549bd7aa82cfae5e9be1b0e@linux-foundation.org>
In-Reply-To: <nqzny5rxn27exzhfzaaxg4tfbshhmr5aum76ygficd46b54c4r@tqrelxeucsti>
References: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
	<20251126101453.3ba9b3184aa6dd3c718287e6@linux-foundation.org>
	<nqzny5rxn27exzhfzaaxg4tfbshhmr5aum76ygficd46b54c4r@tqrelxeucsti>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ElJMCl2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 27 Nov 2025 03:12:10 -0800 Breno Leitao <leitao@debian.org> wrote:

> > > This fixes a late kexec CSD lockup[1] when kfence is trying to IPI a CPU
> > > that is busy in a IRQ-disabled context printing characters to the
> > > console.
> > > 
> > > Link: https://lore.kernel.org/all/sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu/ [1]
> > 
> > 6.13 kernels and earlier, so I assume we'll want a cc:stable on this. 
> > And I assume there's really no identifiable Fixes: target.
> 
> This infrastructure showed up when kfence was created, so, a possible
> Fixes: target would point to commit 0ce20dd84089  ("mm: add Kernel
> Electric-Fence infrastructure")

Great, thanks, I added that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251127111940.8549bd7aa82cfae5e9be1b0e%40linux-foundation.org.
