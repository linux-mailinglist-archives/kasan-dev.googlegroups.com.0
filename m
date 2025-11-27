Return-Path: <kasan-dev+bncBDTMJ55N44FBBFPEUDEQMGQEWX4VZCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id A754EC8DE97
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 12:12:22 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id a640c23a62f3a-b736bec949asf7241066b.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 03:12:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764241942; cv=pass;
        d=google.com; s=arc-20240605;
        b=ifNLZRrQh6r06MtLte0Tosiy92kbWow6pAFq9ff2tQBXyLdE0mvm3IGN1HfhAYVlpG
         B4YhNO68VBAMNEUW2PtLaotMwYbfy7NDsrou9pPxDQMA1j1Fs7Z+csP+Q4xgYWceEI+2
         DCPk3hbQArXklwprQv7tLqfQTWsDIObhnUBOu4xUpExjETZztux9+EKdUY4rqrEdBmJg
         KH8MapkoFLSfjD2rpkJ248GKtUdcL5yTXcyoPUdl/LeChlQQISiTnhB4A8CuR1mW5ymf
         5NMrr2CA0vAYixbz+cybb5CFDjUKVHrLUl+bAyHvUBmn/2KLyGJ2ZrNAWK+l/8mpcH4V
         vugA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/42GyJ0Ly/PYphmtlkn4D61h5KuGIA+bP27szUKUF5Y=;
        fh=3u36XFG0EEKqQ8N8WAEegf3p/vlnTdcWY+1EkjyR91s=;
        b=gGAF9IgDuja8Zy0lZQtpAybvgbuF73fQ7px6c3NqHC7V8tfzNi6psd+KZfk7tgUwOg
         NW2YPU4iJQyeQ2ps8BrymlqSBob6TqMuWOjD8dUHPZbG5TcEUQFzvCj+X6485W+UzQ5B
         4Ibq7YBe/1lniCPYEklDGabUHLPaC2lcro/JdOr38bHEMcVWerWfI29vFAyoSlDE6b1q
         T58rT1uupsBpxVsjHNBBls3pgXR6MysRsRLdrYw4ERnXgnFjkx36Kn46wZpmM082z5NJ
         eanHlTECB/gZ7Rg3mEnsMfbnyHaShO+b7A8MrFD0E5heGfXvMSkja2t/0SEnOUd4a0HG
         0yiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=LXBPzZV0;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764241942; x=1764846742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/42GyJ0Ly/PYphmtlkn4D61h5KuGIA+bP27szUKUF5Y=;
        b=EVRkJJGcHE7XO2E/7RHR4y/rcwjP+3ngiAaHRLMduPYBtEFGDT6Do4JrgI4JdwOYW+
         a8yernzrUfSRt6BTR5TMiddt3dYhpWCrffKX9nll3R+ovbd2EiCZistjOufKEWyqFka2
         LtFgO9Anj6WIsPd+Ph6iKc0zU8MTfH15gUN9MvF8h/qKIWLuMkFUVT6Hi4p2RAlAEjZv
         TNmzvz1P8GYPCW1BHgYqadkKKcoyluf/5q/0P3TwEAEVz3x+HaO1qzD5LRHNsVl/YeGr
         LCbdmnezxJPdxqD2z/t/VBKbhjrQYP6q2vBNBzBCCBEVSRY4PSnvEKQLHxiZsStNsCq2
         pJUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764241942; x=1764846742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/42GyJ0Ly/PYphmtlkn4D61h5KuGIA+bP27szUKUF5Y=;
        b=r9BPdp2cFZ8/4JWPoQccDHjj7k6RouCsCEonFCzUDFlc/N9RjGCKPIplg+xKXXKRCn
         Jm1PkhOn1jwT6eheqPT748y+6V6VefdMLOnzcRWKNAxL5dVreZEUu7DlgIaiM938H67X
         jOVZOiLKuW/Rgt9PsVeSXZR9nbXdEXM7lv+VlPpBdDSmz7Mc3Qjy/QGd5Yw+DeEVMtc2
         7pFPugqAdiQpF1GJto3EULlREVtOdQYdOCc/2zIYqOuvUEGJV0srT+3xjwhntvWk35yl
         +LxaA0fn9pbKxfqO292UaiOHD1ec7HvtjfynHiEaJFQXuJjFtnUxKqIDkNziIvuU6q0c
         6iKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7Lpfm/ld/Z+1mY2oXmlhCSUN65830h/ayrRGgLLWkleDqW15l0E+7KqkQlrZ4gp5XHInsrQ==@lfdr.de
X-Gm-Message-State: AOJu0YwlAh1ljqYnzDRY5w7N2Qi5JkZUSCzI++vfs7PBzmEcd8iIbiB3
	eA6UuAyKn3QCxfOPoKFWLYy25/QdvzHzK3mjzpCwfFgkNyvaDNns8/k6
X-Google-Smtp-Source: AGHT+IFBZEx+d3e/4nZ4358ku1hCt98cvdW2G8l+a0cBKgpl4f4RdYTOIXYn+HDHaHsHeIRrAurdQg==
X-Received: by 2002:a05:6402:f09:b0:645:e986:5f08 with SMTP id 4fb4d7f45d1cf-645e9865f6cmr3894863a12.8.1764241941807;
        Thu, 27 Nov 2025 03:12:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b3qyWal+HY+J2Sx/bAX4dsiKwX7dM6L+MNaIHIF4RCug=="
Received: by 2002:a05:6402:4046:10b0:640:8bcf:e502 with SMTP id
 4fb4d7f45d1cf-647419cc626ls637729a12.0.-pod-prod-05-eu; Thu, 27 Nov 2025
 03:12:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjCzGW93CpxK1lSubgDFFR5uDn/DDIIW8ywll37MqvMLFuNCEde+0alCKE5zGH+mJ6mm4NiXuD4Lw=@googlegroups.com
X-Received: by 2002:a17:907:d05:b0:b73:7ca6:220d with SMTP id a640c23a62f3a-b7671a4728bmr2493812466b.59.1764241939136;
        Thu, 27 Nov 2025 03:12:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764241939; cv=none;
        d=google.com; s=arc-20240605;
        b=bZmiWL+SFD0PvAevDBXy9NN7Ytgc1b78t895W2BeOAMDBqBAwLtYgocbs3G+ngRSr7
         f/XTy3hyo/Hx7ziuJjwCZtSD+8vxoct1e0Ib21Q3p30lWfo3qbmasEQHc6dDth7kkutj
         YW/EWNvGgE595et1JxTcpxiJGnKuUKxSBCDYRyIL+0bS9+pigMBVjVQEmiAG5y5l4Wvl
         b0mQw5zT0fwybdjV7noQuqPmLBIXJBNgUlAjHvPG6fIJ55o5KMpSvHsxXa0+bG4E5Mez
         e05YZkiCsBd9sitHT1LPCpiNmUiaQCR4rGn5Vst1T9SS+m3QnHWfDCuLSi6JUl8ynnnV
         R0RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=t2lrLpSRcHNo+/6QyI3Yf/wIv62AmlzJCb3KPciCVus=;
        fh=xNJQ/dfBGakZLGEwBYHwThAfIk3uBByzNlRxPpHpmLs=;
        b=j+UHxnaoRZ9M60EIZzrjJGkkvqanwYz5uEzAUpTPKw23+Lc3qzWscjb/ClrddUhj2N
         tdQlzMK90OeaTWd8rD7X0IY1ik3XKIFTAWqRDZkhqu2HoS2o8265qG+VlaH1LUU5ww0C
         TLv1fTF/2ief46CE5lwC/UtERukybCYHFONWbV6f8eaUH/D+dCYdNjfjzbb00BefO2Bh
         QyJ6VbtCBlnxmsEsIw5tSZyTqePcValiVH+Cplgg7P0t60RF7Lo24xFe2m62nQz7VqBG
         jzWY8IIfQ78itA5z7X5AvGOaJ7XImUimxscAt0g+O6NM5NfUdAOdciqMJijTquKFdFkJ
         bvfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=LXBPzZV0;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64750a3dd2asi18747a12.2.2025.11.27.03.12.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 03:12:19 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vOZv4-004zti-U0; Thu, 27 Nov 2025 11:12:15 +0000
Date: Thu, 27 Nov 2025 03:12:10 -0800
From: Breno Leitao <leitao@debian.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
Message-ID: <nqzny5rxn27exzhfzaaxg4tfbshhmr5aum76ygficd46b54c4r@tqrelxeucsti>
References: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
 <20251126101453.3ba9b3184aa6dd3c718287e6@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251126101453.3ba9b3184aa6dd3c718287e6@linux-foundation.org>
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=LXBPzZV0;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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

On Wed, Nov 26, 2025 at 10:14:53AM -0800, Andrew Morton wrote:
> On Wed, 26 Nov 2025 09:46:18 -0800 Breno Leitao <leitao@debian.org> wrote:
> 
> > During system shutdown, KFENCE can cause IPI synchronization issues if
> > it remains active through the reboot process. To prevent this, register
> > a reboot notifier that disables KFENCE and cancels any pending timer
> > work early in the shutdown sequence.
> > 
> > This is only necessary when CONFIG_KFENCE_STATIC_KEYS is enabled, as
> > this configuration sends IPIs that can interfere with shutdown. Without
> > static keys, no IPIs are generated and KFENCE can safely remain active.
> > 
> > The notifier uses maximum priority (INT_MAX) to ensure KFENCE shuts
> > down before other subsystems that might still depend on stable memory
> > allocation behavior.
> > 
> > This fixes a late kexec CSD lockup[1] when kfence is trying to IPI a CPU
> > that is busy in a IRQ-disabled context printing characters to the
> > console.
> > 
> > Link: https://lore.kernel.org/all/sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu/ [1]
> 
> 6.13 kernels and earlier, so I assume we'll want a cc:stable on this. 
> And I assume there's really no identifiable Fixes: target.

This infrastructure showed up when kfence was created, so, a possible
Fixes: target would point to commit 0ce20dd84089  ("mm: add Kernel
Electric-Fence infrastructure")

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/nqzny5rxn27exzhfzaaxg4tfbshhmr5aum76ygficd46b54c4r%40tqrelxeucsti.
