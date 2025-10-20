Return-Path: <kasan-dev+bncBCT4XGV33UIBB3XY3HDQMGQECVV3HGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A7F93BF2E5D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 20:16:16 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-651dc603a23sf3076115eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 11:16:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760984174; cv=pass;
        d=google.com; s=arc-20240605;
        b=K0H7HWNgWKDgxo3e1ia/9S8nUJWZEHob5vl10orBWoMpX6eMWwzslXI4CiScMeiA2D
         0xfojJrKTXGxaijPBYzknPYYPMnXy41sWY/6dc4VtI5AADcNekh+3Si8Z0iDJaVpemWc
         ZBSMi7qnoiWLzw5D+EqSjXZ3vteFV7dzALx2gPy0KksPRJCcLsV8pvsc0Ysp9JfMhiOZ
         2bRCRmiafDx7JVD6TwD6ri7SUS8nCtCamff1z0sFmsNHkFNfmDtcBxqryXfFyeKyEd0B
         jwJPzlxW3W1PGxzRGrVVTqk9KxO2zcxsjxMVgpw76UWOvL9UsKIeeGvwVkkdPm0dnDCb
         Dfiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=R2CwhaUqE8sFnsHJv8HPBuWfqLZDgHoOqr2ie38oJCU=;
        fh=qFYIqbMBqwt1tEEEjdcdLMGf017sc5ZQVg9PNIevbMs=;
        b=YTMdXZhC9OPesY/aHBfXcKvYfi5zyCC6u/VDqc53AGlsNIcFpBn848L7q2JMucu8Z7
         b/irkhLBUGYQGDhQfgIIRLiLTOW5r4KwdlwvMwhg6J+exWKG8H/ZVyDR85CESd2/zpsz
         Bae23KRNJkK56u86e0F6IO2juO8MBewJM/37VOlngaxo5PS99nXRwRV52Qpm6LWERTKF
         lGv3jyOzVAfRTr9eMRbxgnaMVMRB59C2xfBCnHbJoxeVSh2FhL9fk3gwrCzcJkixtBWs
         xHRwgkeDlWTdyoTvLyhQ8C1L+GuFwH4ldZamTtginJcjPOg3DOiJn32RWM+giaRWpikx
         cJhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=SFAdAhGZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760984174; x=1761588974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R2CwhaUqE8sFnsHJv8HPBuWfqLZDgHoOqr2ie38oJCU=;
        b=ttAfAs9o1MMXMREyPsxYMUlvbVSD9DLtR/OCHGKNfX5NrWKf6kwixg/RWxnkqvwYiB
         yfw520xrqujtQO5PzlEO+a9kEUVtciXemxmHwF6jtYRfBpsbK1RXATN6H4BHp12fEh0N
         jV6+0gyTglZcXapBSEkTua+p9JgXTmg1n7Qvr1ofX5s8IEJRDjIQfgjwKhGXzJil1VKT
         XbpSjqrV6skV0ckBQHocOfsimARBR8GPjQpPsgK6Guxy9O9arU9A5CZqv75b3m6WrfgW
         EJxaS7RcyHq+WuZ7V+fyiTEsXdRvCk6w5Cm8Jpn+MxhOoDaL5qKzEEPH3nBonIBSaQyJ
         Xtww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760984174; x=1761588974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R2CwhaUqE8sFnsHJv8HPBuWfqLZDgHoOqr2ie38oJCU=;
        b=cprQ8HzdX7u7hqedkd+KOTl63eAtIjvgT019XAJ4jSfiKnTZZMcEAT+xb7nV69bZyd
         2/oEg8WFJ9csRLHAqJk9B7k89PKagG75yY0EhwHHviFdCTWNCAD64bq0Pnje/lfUXTBG
         WgDpnTPDQwBrnnuXmXDe/dKWSYSZyLcdH/tnhi9TKa9TtneQbx2Z7vmc2fbmlxg11dG6
         2CpIx+iWcCMQUe0Mz68G0t431LPNpYI3yV8rCNxopXzpd6/FJT5xAFuAwTfwnJaR90nY
         Pg+La96yM5vYSzdIT53iXlwjKx/jwpjGKBkHCssGRAfjnmvKJUN69K7cv/ZUqXeopkr3
         DlJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXt0l3ZiDZZZLolsjqcQ0LFDeylg/VAnayxyOenCFcxIXGawl4LFE9wFUqk30PXVzOkw5wfSg==@lfdr.de
X-Gm-Message-State: AOJu0Yz3o/fpa3QPkgJQsQNqXDWY/cjdX6hQQaB9YpwsN6qX7qCuL1jR
	kqv8HZzOhfAHsTVUWne0bq6FSg3o7x5mM1TsCdPLjehX7xMeoQBy/KqI
X-Google-Smtp-Source: AGHT+IEH3moBSXw0l2c9KcvIEydlG1zbP9/L06TPKwOTH2/EdITQ/pgt4s90JQOyPX/X1YSlzSyX3g==
X-Received: by 2002:a05:6808:1993:b0:43a:2e17:3ba8 with SMTP id 5614622812f47-443a2b0e64bmr6403929b6e.0.1760984174386;
        Mon, 20 Oct 2025 11:16:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6VtKr+dRJgofuOxyyscTneoqK+WSoE701hcAjrZsneMQ=="
Received: by 2002:a4a:b40d:0:b0:650:2558:792c with SMTP id 006d021491bc7-651bea7c8dels2271838eaf.2.-pod-prod-08-us;
 Mon, 20 Oct 2025 11:16:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsAQrOitE7eNHb4WChtW7VuoBjC0RtzRHdUKKlk6QXITpr0YwPDIZTOcnyUeP3QFtIgcLQuWHW9vg=@googlegroups.com
X-Received: by 2002:a05:6808:178a:b0:43f:7e97:397f with SMTP id 5614622812f47-443a2ff4819mr6130566b6e.41.1760984173000;
        Mon, 20 Oct 2025 11:16:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760984172; cv=none;
        d=google.com; s=arc-20240605;
        b=kkJzceEFUVl2uhTXg8YyqzI0DLMXU6alrZHlZX1YEcjl0nHcXeZeZ1f7s0ciVGUQNu
         KsP2r4Db1F/uyUkbctgjwMEpndPf//g2dA7P2OzpwndGFfrfnLsFYmKGlFc0L4Lgzn34
         tXmUccdeVTqwUxp52qsJQ/vxdsHEciG2BIfsmLED9jTmJatncjc7Aw3ZQxTNZ4koabCk
         KQsbJDReFQ3nhw0isJhQKb5z+nCJ0RW6iiaVZnHrqUEzjmQjbx/JkXtgEMRkKONr7ck0
         4/EVc0+Y8dhXPf9yrjIfoYPoTmD1SU00gNjlRPEsGr90xGAWKCPNG0iwxrwrcQ1MHgeR
         Ntcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/Ajt0HVVq8ZKPdL86X9rKEhtCiIfSqXtFposI8V9XtI=;
        fh=Lc5vd3t5OlrSKwkigZZUvjmvYeKFZAfMoYu753+jB0A=;
        b=UjTACWuPPLP6WUndBK7l/OQ/QRojCz3WqIdPtWzfSI43kfRvC8IhYBCMoxTBHgZrV2
         3pdUyAkMyc7mNidIAUqVgyBYzV59rEo8RkbzviUWGu6n2rCJla36crnk2Xh34LY+JJ/z
         JbBzD3DeXXrSMjz8SUK7XK1aEyUyRbCOoSAPiIBReETDqL6KB9DbJgu7xJx1nwBfbAI7
         jVR27nSHESMK9I/thETc3peyXhvj9Cu0HOU1Iq3Y3tp6oqbJCAygm8yqh6WZf+5d45ph
         CCPWZzzSSvM1iaeKV86g8ZpNrCCQxLQdwlcOgHRUmGSeju+lpA9mgYQ4Eu62UleWbAZF
         +tbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=SFAdAhGZ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-443df32a64bsi473074b6e.5.2025.10.20.11.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 11:16:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E790A620DF;
	Mon, 20 Oct 2025 18:16:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C732AC4CEF9;
	Mon, 20 Oct 2025 18:16:09 +0000 (UTC)
Date: Mon, 20 Oct 2025 11:16:09 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>, Vasily
 Gorbik <gor@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>,
 Christian Borntraeger <borntraeger@linux.ibm.com>, Sven Schnelle
 <svens@linux.ibm.com>, "David S . Miller" <davem@davemloft.net>, Andreas
 Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Dan Williams
 <dan.j.williams@intel.com>, Vishal Verma <vishal.l.verma@intel.com>, Dave
 Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>, Muchun Song
 <muchun.song@linux.dev>, Oscar Salvador <osalvador@suse.de>, David
 Hildenbrand <david@redhat.com>, Konstantin Komarov
 <almaz.alexandrovich@paragon-software.com>, Baoquan He <bhe@redhat.com>,
 Vivek Goyal <vgoyal@redhat.com>, Dave Young <dyoung@redhat.com>, Tony Luck
 <tony.luck@intel.com>, Reinette Chatre <reinette.chatre@intel.com>, Dave
 Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>, Alexander
 Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan
 Kara <jack@suse.cz>, "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren
 Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Hugh
 Dickins <hughd@google.com>, Baolin Wang <baolin.wang@linux.alibaba.com>,
 Uladzislau Rezki <urezki@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
 Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
 iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>, Will Deacon
 <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>, Sumanth Korikkar
 <sumanthk@linux.ibm.com>
Subject: Re: [PATCH v5 00/15] expand mmap_prepare functionality, port more
 users
Message-Id: <20251020111609.cfafaa22c20ac33be573898f@linux-foundation.org>
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=SFAdAhGZ;
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

On Mon, 20 Oct 2025 13:11:17 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
> callback"), The f_op->mmap hook has been deprecated in favour of
> f_op->mmap_prepare.
> 
> This was introduced in order to make it possible for us to eventually
> eliminate the f_op->mmap hook which is highly problematic as it allows
> drivers and filesystems raw access to a VMA which is not yet correctly
> initialised.
> 
> This hook also introduced complexity for the memory mapping operation, as
> we must correctly unwind what we do should an error arises.
> 
> Overall this interface being so open has caused significant problems for
> us, including security issues, it is important for us to simply eliminate
> this as a source of problems.
> 
> Therefore this series continues what was established by extending the
> functionality further to permit more drivers and filesystems to use
> mmap_prepare.

Thanks, I (re-)added this series to mm.git.  I suppressed the usual
emails.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251020111609.cfafaa22c20ac33be573898f%40linux-foundation.org.
