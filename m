Return-Path: <kasan-dev+bncBCT4XGV33UIBBSM7VDDAMGQE6XONI4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B71BB7E2DA
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:43:40 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b49715fdfbsf212415081cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758113019; cv=pass;
        d=google.com; s=arc-20240605;
        b=JSsNIjQYMC5CLSKJk8bqLbRB1RukyuMVesD3Znyb4KABBnTwzB32pel4gO33/xa4ml
         WaM9nI7jpVP5yOGLBMIqVxQ7lHmHsiPduKIv5SQZmg8x2Mr+gJ1ZtAAsK3TagOXFhfsj
         wBzZ+MPT4BF7Q609Va0f1tHVeay59kA/QVPAXk/uGW71o4HNifhx+dl5ti3pAfy3KtYR
         XdAXnRggLmPYbc8ncpugXL9EG4scFZFGzE46bcualwjaaDhfHXYupxz54Gux8G1fPGtn
         HeetZ6ssr4T8oI6gTnt+AX+ENmcuoEIGE8Ap7cSBfiWnmEJIjIEWApnZqAqRTql52uRW
         atjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=WBe8gsz2A/IR6SGiPvZPUtVkHIdKswNbNG3DrWuJzlo=;
        fh=zafFUc5DUTpT+xswMrmH0uuWMabPJ0iyharYccq8iIU=;
        b=N7JKnn/Kt5nLA510ADTWfTzeQ8qbQk8YRacuK5MzjNeqkjEAXtymXyUlAdsBeBcjue
         FmCTjpby1I9Y4SFKwOW5udfkM1CfJ4hzPuGNgzDZw/dCC++Z1DEzw+ZiKlN19eG8250W
         BuG5ohUFXtkbC6jKjDV7W6iuE8TUgE4TXYLAZQwoJENnZ0kEtvPV0wRbNCfZwUU84JIz
         iG6/I/Fm+v2XsGq9fYAxyEeE78q6YOvErDg8zqYx976Dw0xs0lDSfb4TT1IgZz+SAwdc
         r2Zm4+l/t8u3DWkdZx4cOZgj2+nQNc2UBPieGDjHxDpsH7/D7AvbfGhk8D270XwnRAlZ
         Wghg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Cz58pDdz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758113019; x=1758717819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WBe8gsz2A/IR6SGiPvZPUtVkHIdKswNbNG3DrWuJzlo=;
        b=fZkGfcyuPQIREIlWDFrCDoEgmiN/TWwKeXoVjGdZ+z3KglpDkUux30alcgDqwNuCJj
         S2kh/VtZkGyHE2h1fYsjzAgXqhIPPDVHgnySMJEO+4GH6r/nqRstePhyZ/mNAjQouNzJ
         nx6MX4UpGqTNFflps0fDCQLYb8IDbW2MQ0QBCjK9b4Y3iixGGgu0ZI1doc2zR5bCT74S
         a99b4FYdrxwq0t97EFPTgLphQVzTM95fUTGAlv0cQTz2Hssq/Bv5Q9UUKBmvnaDs8eZx
         Dr8D68mRuWuPV4PlErYJaquIRKBC7V3NLyg4iGOMauirUN18dy9HryrRcC4sB+GStl4q
         L0iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758113019; x=1758717819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WBe8gsz2A/IR6SGiPvZPUtVkHIdKswNbNG3DrWuJzlo=;
        b=P7Cx0xoBAjHjqe+1VF1jbAtJeQNRdOJ5A58uwIpp85U05guPJ71NP18Zu/lPQmCt5c
         QzajfW3fkeLv9t7Pm45WhblLjpLfaz+5oPg3c1SG74OfOVBx4sAOmi+/fMQyLrGKHclQ
         7eeqitVfjcuOurM2nBdnFiEztrBWVwIcc82vo+icG9GbBWO4RS4XVLr9mlzyXzhaBIxl
         6D3Xcn2d+/KCwFoCxEg3sVwC3YDSnL2mcPoXBgU+GUCp/hJYUdGqVvEfvO/AM2mc292I
         aHCBCB83gGONhM+Q1vvPF17KlCN7jD3dLFyIahiwwb8/q5yAfgQN/m+UkoMMzC25PcGf
         KJ4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJM21MObV75GmWdXFX8ubxmBf5pnopabAvASuEnY63xnUw/zlEdt89+Np3Vxz+ay07AleLog==@lfdr.de
X-Gm-Message-State: AOJu0YyD7II/bS196IE2CyvgQpmuwjCdk273SLr0YvQ1vXk/AblZIw3V
	tPYfNsyh8phQjf1N9Fb0412xZmX1XMd/0NT/nynZ5GXslOwqw7v/6dwK
X-Google-Smtp-Source: AGHT+IGOtiK2JBShn60wQuUABuDMabprU3a8vHNFh7e7yOWBo0oiNIJOHlP9jN178JWykHz/5h+sCw==
X-Received: by 2002:a05:6870:8a0c:b0:2ff:9ed6:2268 with SMTP id 586e51a60fabf-335be1ae82bmr224123fac.15.1758072777428;
        Tue, 16 Sep 2025 18:32:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6XCg7MzB8xlP+hIawGmDZBWEzmeEbBCN9hG/JkYry44A==
Received: by 2002:a05:6870:2e83:b0:31d:8f7d:c062 with SMTP id
 586e51a60fabf-32d021d73d6ls1626722fac.0.-pod-prod-06-us; Tue, 16 Sep 2025
 18:32:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvy22JA0GdD5mwt8B/UDsPqPb3KMblQLhUVhFwljUHajW9oVGUZHhntN5u5h54HrqeHwl2o1tYmys=@googlegroups.com
X-Received: by 2002:a05:6808:228b:b0:43d:2405:b5bd with SMTP id 5614622812f47-43d50afd670mr173942b6e.20.1758072776523;
        Tue, 16 Sep 2025 18:32:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758072776; cv=none;
        d=google.com; s=arc-20240605;
        b=XYDZqR5roZ6qSI0coNh6a1kyGKpvkFEqWg1EpOnfIXnHwLN4tPsDX75qdJXqOZAhT7
         RBoFcPcJSaw4ZEq20MwukUWITkFU6cWeUeueG/SXvYmoRtwToAggt+O+Sv+Yyvxauxux
         zl6Q4r7fi6vtaguALBu3ebzOz1l02SFCCR+AiE80YCEkhS6RKGHpfnjZzWVBWUmxzohS
         NqsdVJpBix/0uccNuo+oX5RAe1O8NcymQ0UcHb854wDi4rBoK7QCQ/NjMIIC6J4mQTXP
         wsTyWct+gGx4umKMJRf6LR87Z9Hs9uMkuCdFz3qsbKWPiTPh2O6rvYz7qIMD9LDomwWq
         yo/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=PvexwmzCNrp51tkFXBAFmsX6wCYeaz9zSCCiWiVuAwY=;
        fh=Xu8mvllbBIlOjUFgp0pFWhyh331ag97ullTQqwv7fNE=;
        b=HhkCkjlF8LLg6p4H+/iOs5b8iVnYEzJV4H7IPB4Dl0zoEr0gAggpxbxlj8oKVRNDr4
         eqeOZHM6/+8llBfxUX3nBkPcmlKmnm4ouKgaJaMQq1Z7xFai67hPK8BrLCrtssQ51DDs
         VULibpDO6K+MBYG2KBKmGPqcbpCnxEYjGmaFgs8xwiLss/W0yo1kBTQhTEMHmMRRpGVh
         63eR/8elUX3/U8tLCUkt0eLlNI8Rezc4yDBq+c3M8JzHqTX1sTB0ttMCRKkKVJdx/vXk
         sYpzp68NEekz0ILGMihVf++hQSGieSrKcWCZQHKlVpq5aVpVFRQ5UZtg7kygcl+cXzKj
         EcsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Cz58pDdz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43d232c216bsi122796b6e.0.2025.09.16.18.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 18:32:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 839A343C6A;
	Wed, 17 Sep 2025 01:32:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 93CFFC4CEEB;
	Wed, 17 Sep 2025 01:32:53 +0000 (UTC)
Date: Tue, 16 Sep 2025 18:32:53 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>, Jonathan Corbet <corbet@lwn.net>,
 Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>, Thomas
 Bogendoerfer <tsbogend@alpha.franken.de>, Heiko Carstens
 <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger
 <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>,
 "David S . Miller" <davem@davemloft.net>, Andreas Larsson
 <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>, Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>, Baoquan He
 <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>, Dave Young
 <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>, Reinette Chatre
 <reinette.chatre@intel.com>, Dave Martin <Dave.Martin@arm.com>, James Morse
 <james.morse@arm.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Christian
 Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, "Liam R . Howlett"
 <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport
 <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>, Pedro Falcato
 <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, iommu@lists.linux.dev, Kevin Tian
 <kevin.tian@intel.com>, Will Deacon <will@kernel.org>, Robin Murphy
 <robin.murphy@arm.com>
Subject: Re: [PATCH v3 13/13] iommufd: update to use mmap_prepare
Message-Id: <20250916183253.a966ce2ed67493b5bca85c59@linux-foundation.org>
In-Reply-To: <a2674243-86a2-435e-9add-3038c295e0c7@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
	<59b8cf515e810e1f0e2a91d51fc3e82b01958644.1758031792.git.lorenzo.stoakes@oracle.com>
	<20250916154048.GG1086830@nvidia.com>
	<a2674243-86a2-435e-9add-3038c295e0c7@lucifer.local>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Cz58pDdz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 16 Sep 2025 17:23:31 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> Andrew - Jason has sent a conflicting patch against this file so it's not
> reasonable to include it in this series any more, please drop it.

No probs.

All added to mm-new, thanks.  emails suppressed due to mercy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916183253.a966ce2ed67493b5bca85c59%40linux-foundation.org.
