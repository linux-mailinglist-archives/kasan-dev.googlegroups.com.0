Return-Path: <kasan-dev+bncBCLMHO6ARMORBLVVY3CQMGQEYOIOK6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FCDEB3BB03
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:18:59 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-248abeb9242sf18032395ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:18:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756469937; cv=pass;
        d=google.com; s=arc-20240605;
        b=LSJqpqINpIWYP20HhD308aaKY/cRSNEQR542EqY92d/c376GbGVZsy1lysqQxgscra
         Lk6OFKsyUnse3eZdNYJO5krgp7ltOtF3sXvLBPYRvFMI2ls5+5MNn5U78yZyb498ByVc
         VZLvAOlxvGVytmb5fjtUUu3kqGR5CVV2pOHEeYaMJabvdkjLCLLAMSck3HC/owbVwPp1
         l4sdkcyhv7H6r6QgFhfkfDfxN3J603V77PoypaXx4eJgYKqXZz8WLJOQ1SRExf9abiVd
         NxTBH+8OKvc0tnA62CqIqHxKlzTMF9pOEI7/ahWWaOBb9cRJ9RfYmmQwtN6MQDglQtM8
         UMhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:organization:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=peTbpwQalPntVSj3qjiMCIsYZ3tEB6AQ4kokmChIJ4Y=;
        fh=h/Cmmg3GPgWme+Yqb6aAWVPCio7i0GLzpVriK5cWz9o=;
        b=hjyhDrqFSUcbFzQkp54FzEU4Ht7v42mvx5Fb/fkOipUYdZjAbEK1CWSVXf5ewGkoaV
         /LDbOYf2SWTwiQ/sS1kXcUiwk1E1etRj8HoZJUoZIREghXryfsQDUqyeUE8cCyx/WRs3
         d2typRWRaX2xHgPIbndCGic9Hwu6L8cH35OpQm73lBomLDweobZt5Csj/TLnontB77Az
         GsVdL8jSIMUlqB2+k8VEOOKJ4VMtTKvtUiUIyk+aQ1s5+q73+c0qXZRPGZ4qWECr3iXP
         VETya3C8P1mwlzPzbKcNhBRMkweMx1nXzshptYAjgTB51VQpZExpl6pZMgCy+Bioii7F
         c71g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="JQ0/AxIO";
       spf=pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756469937; x=1757074737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :organization:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=peTbpwQalPntVSj3qjiMCIsYZ3tEB6AQ4kokmChIJ4Y=;
        b=w5ZIoQsxy+TfdYOvTnuSyiorbHsXYHP7ZCg2Ya3an0dIbICkifpblc0+p4kzcK93tF
         vl0srTiSVQ9/IcQ4QosCq4MHmFA5GQ4ehctvxo1QjsuHihStDKPYtujuTI7pkkG8hDyC
         F7TRquIODPwf2kaJh2f6M5UqZ4x3uwpa4GNqVt3JPqpVb9U42bVViXkxeiMdx3TN1YWh
         lJaDi5ztiRtc4ltKk77QKXvymBhNplxouwwzJ45xlTGz9Gizo6+fYkGKp25XFc1+OPx4
         yt07iF+0cuPS5dMa5Euio44J1OVDbebiGWVaH/KkLjWXyOVBv5wIc5BxMT6KQoP7LzlY
         7LyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756469937; x=1757074737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:organization:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=peTbpwQalPntVSj3qjiMCIsYZ3tEB6AQ4kokmChIJ4Y=;
        b=DtM75t2D8bzWh8mMAcQ+29/NmlBa2Lp8kWNrzHu/gaRoVwrwd4WKm4UFYK6AdmTn9X
         TDNe8idf3oUQVbc/NOWK3UUKRGM5I4Najv/igVrwAZJNsZeMWvkBY5ML6B4fNynFu+u/
         YT9lCsSu98Pvbp3ZFOZTlOcX7CnPIgwV0Qpg31xJY+QoXJlkSmTy5BIFHd3iCsUQm1bc
         tvHQmd80YEhwOM99WnKuBAqghSyt+28TAmtOWHQIC54l+gMuwB54EHbH0kuISvR2MXSM
         PVp922OptBJCSkfUI06k63N7YLWlos5eWL8RhKa8Win30ncVi/UeOXj/luPnNS657DzW
         7jaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU54h2cOUYLoNG/Ycf+sXWoc6qYxa8AtXpZ6b15se3BSRBVSv8q6TufLddBJqwHCJPhGCvEcg==@lfdr.de
X-Gm-Message-State: AOJu0YzmxnNGpdu5vAlS+y/IRmLL4U+AgpS6Dv7xEhxtJ1X/nLtAkkyI
	ajdbi4HGAjlR4fMalWzlqjEeKcQAguM6uga+9KxXFl9W9Nms5zI0lMYM
X-Google-Smtp-Source: AGHT+IHIW6yY8hlQW94RJGcMrbtoUQ+wcu/PuDCsOu1GQMNvD83CypISm6fdj3tbnfPBez0Z0pIBNQ==
X-Received: by 2002:a17:903:198e:b0:242:9bc4:f1ca with SMTP id d9443c01a7336-2462efda1f2mr364733735ad.57.1756469935066;
        Fri, 29 Aug 2025 05:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcDpFyNaaLv79rgr5bQ8E2bSQhbGt/Kcn0ISnXV2QQPCQ==
Received: by 2002:a17:903:112:b0:248:8bf8:375f with SMTP id
 d9443c01a7336-248d4e86a54ls16260465ad.2.-pod-prod-05-us; Fri, 29 Aug 2025
 05:18:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeaQDnOheHw5wIbweNG/8RWDhLX1kOrKPfkYYRCWk8UBCTQFaPYWm02M2vA55JmHVr8ag4A+hcWCE=@googlegroups.com
X-Received: by 2002:a17:903:2c0f:b0:248:cd0b:342e with SMTP id d9443c01a7336-248cd0b3830mr101125405ad.7.1756469933851;
        Fri, 29 Aug 2025 05:18:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756469933; cv=none;
        d=google.com; s=arc-20240605;
        b=KlkNWrv3nZnezXzEoD2J3vpSs+/73KEfGel9GFAtTVQJqzxiDt76BgiEXmNodh9Ryp
         zQyh9M3St3IDXWbDY1Kd1aXs9FIh8UyVxB0wKvRU6yK9k9zGj71/COkzpukRPe76rpus
         HOrz+M1KYSRwmGR1ll2l0kYI0koUBU/ws1loHrQRO8Q88+3vEhd0AsrV7JrmTTCh4czn
         RZWD8Q/0ZBXlCOsrFiEcfMie1cJBdA4EVfBjEcP8t42CuEKdz/0XT79P2fVu1lAnY2/b
         xCqEBuwm+LoA5OVUAsE2m3EmpxogDpzpU1Q7LZ3Jn6afc22t3U4BffgTF4ypkIbgaq+C
         Rkgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:organization:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=OkTpztyu5K0pji7lFFHFbR3zLFIlVYGSxPUV/Ti6gpY=;
        fh=tOv9RC0N63vvvcBDulWzgHVOSC65mtD9Dz0+JYJMFvA=;
        b=MfMaz+NZE/Y8Makch+NGEx4s0sx40g2/ZZ7enMDxDMZt8yC/H0IytUdHu0kkWZP89u
         Caq9cfqgYWaPSmV5Klb5K9Y6a8r3Lp/MHuDMhrjPoiL7gy8DIODL75f+oMSLObHkKI4J
         yOcMymnG8jTEM0IWYidjydgmsug+yKbD55rWyaEXkbcebp3E7YXweERqJ/NQJm2BQxM8
         LNTAY+R8esoKFv8ggHcDTSFVu2OgtI2B+/mwPkrgVdANU8A82woUG+CnQDugdw5BptQa
         1x54GY1DPVt5pXbDaHSnEWWleI6TeMQ55sbgUf7tRwfw1r3TrDtc//QLjlNVOOnyANOO
         C3Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="JQ0/AxIO";
       spf=pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.19 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327b61686e0si74564a91.0.2025.08.29.05.18.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 29 Aug 2025 05:18:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: i2/aJRVuQNC4sK1AZyXIUA==
X-CSE-MsgGUID: bj5FigAbRRyhcOGIjyObhg==
X-IronPort-AV: E=McAfee;i="6800,10657,11536"; a="58603840"
X-IronPort-AV: E=Sophos;i="6.18,221,1751266800"; 
   d="scan'208";a="58603840"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Aug 2025 05:18:52 -0700
X-CSE-ConnectionGUID: FceyOGKfTMK8J/ArNXLz6w==
X-CSE-MsgGUID: nahg4MG6QSGDgmwgF/j0Ug==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,221,1751266800"; 
   d="scan'208";a="170753940"
Received: from hrotuna-mobl2.ger.corp.intel.com (HELO localhost) ([10.245.246.58])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Aug 2025 05:18:22 -0700
From: Jani Nikula <jani.nikula@intel.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux Documentation
 <linux-doc@vger.kernel.org>, Linux DAMON <damon@lists.linux.dev>, Linux
 Memory Management List <linux-mm@kvack.org>, Linux Power Management
 <linux-pm@vger.kernel.org>, Linux Block Devices
 <linux-block@vger.kernel.org>, Linux BPF <bpf@vger.kernel.org>, Linux
 Kernel Workflows <workflows@vger.kernel.org>, Linux KASAN
 <kasan-dev@googlegroups.com>, Linux Devicetree
 <devicetree@vger.kernel.org>, Linux fsverity <fsverity@lists.linux.dev>,
 Linux MTD <linux-mtd@lists.infradead.org>, Linux DRI Development
 <dri-devel@lists.freedesktop.org>, Linux Kernel Build System
 <linux-lbuild@vger.kernel.org>, Linux Networking <netdev@vger.kernel.org>,
 Linux Sound <linux-sound@vger.kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
 Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf
 <jpoimboe@kernel.org>, Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
 Jonathan Corbet <corbet@lwn.net>, SeongJae Park <sj@kernel.org>, Andrew
 Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett"
 <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport
 <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Huang Rui <ray.huang@amd.com>, "Gautham R. Shenoy"
 <gautham.shenoy@amd.com>, Mario Limonciello <mario.limonciello@amd.com>,
 Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>, Alexei
 Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau
 <martin.lau@linux.dev>, Eduard Zingerman <eddyz87@gmail.com>, Song Liu
 <song@kernel.org>, Yonghong Song <yonghong.song@linux.dev>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Stanislav
 Fomichev <sdf@fomichev.me>, Hao Luo <haoluo@google.com>, Jiri Olsa
 <jolsa@kernel.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>, Lukas Bulwahn
 <lukas.bulwahn@gmail.com>, Joe Perches <joe@perches.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Rob Herring
 <robh@kernel.org>, Krzysztof Kozlowski <krzk+dt@kernel.org>, Conor Dooley
 <conor+dt@kernel.org>, Eric Biggers <ebiggers@kernel.org>, tytso@mit.edu,
 Richard Weinberger <richard@nod.at>, Zhihao Cheng
 <chengzhihao1@huawei.com>, David Airlie <airlied@gmail.com>, Simona Vetter
 <simona@ffwll.ch>, Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann
 <tzimmermann@suse.de>, Nathan Chancellor <nathan@kernel.org>, Nicolas
 Schier <nicolas.schier@linux.dev>, Ingo Molnar <mingo@redhat.com>, Will
 Deacon <will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Waiman Long
 <longman@redhat.com>, "David S. Miller" <davem@davemloft.net>, Eric
 Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo
 Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>, Shay Agroskin
 <shayagr@amazon.com>, Arthur Kiyanovski <akiyano@amazon.com>, David
 Arinzon <darinzon@amazon.com>, Saeed Bishara <saeedb@amazon.com>, Andrew
 Lunn <andrew@lunn.ch>, Liam Girdwood <lgirdwood@gmail.com>, Mark Brown
 <broonie@kernel.org>, Jaroslav Kysela <perex@perex.cz>, Takashi Iwai
 <tiwai@suse.com>, Alexandru Ciobotaru <alcioa@amazon.com>, The AWS Nitro
 Enclaves Team <aws-nitro-enclaves-devel@amazon.com>, Jesper Dangaard
 Brouer <hawk@kernel.org>, Bagas Sanjaya <bagasdotme@gmail.com>, Laurent
 Pinchart <laurent.pinchart@ideasonboard.com>, Steve French
 <stfrench@microsoft.com>, Meetakshi Setiya <msetiya@microsoft.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, "Martin K. Petersen"
 <martin.petersen@oracle.com>, Bart Van Assche <bvanassche@acm.org>, Thomas
 =?utf-8?Q?Wei=C3=9Fschuh?= <linux@weissschuh.net>, Masahiro Yamada
 <masahiroy@kernel.org>
Subject: Re: [PATCH 00/14] Internalize www.kernel.org/doc cross-reference
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
References: <20250829075524.45635-1-bagasdotme@gmail.com>
Date: Fri, 29 Aug 2025 15:18:20 +0300
Message-ID: <437912a24e94673c2355a2b7b50c3c4b6f68fcc6@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jani.nikula@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="JQ0/AxIO";       spf=pass
 (google.com: domain of jani.nikula@intel.com designates 198.175.65.19 as
 permitted sender) smtp.mailfrom=jani.nikula@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, 29 Aug 2025, Bagas Sanjaya <bagasdotme@gmail.com> wrote:
> Cross-references to other docs (so-called internal links) are typically
> done following Documentation/doc-guide/sphinx.rst: either simply
> write the target docs (preferred) or use :doc: or :ref: reST directives
> (for use-cases like having anchor text or cross-referencing sections).
> In some places, however, links to https://www.kernel.org/doc
> are used instead (outgoing, external links), owing inconsistency as
> these requires Internet connection only to see docs that otherwise
> can be accessed locally (after building with ``make htmldocs``).
>
> Convert such external links to internal links. Note that this does not
> cover docs.kernel.org links nor touching Documentation/tools (as
> docs containing external links are in manpages).

FWIW, I'd much prefer using :ref: on rst anchors (that automatically
pick the link text from the target heading) instead of manually adding
link texts and file references.

i.e.

.. _some_target:

Heading After Some Target
=========================

See :ref:`some_target`.

Will generate "See Heading After Some Target".


BR,
Jani.


-- 
Jani Nikula, Intel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/437912a24e94673c2355a2b7b50c3c4b6f68fcc6%40intel.com.
