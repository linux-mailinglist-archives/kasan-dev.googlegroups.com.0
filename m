Return-Path: <kasan-dev+bncBCJ455VFUALBB55ZYXCQMGQETDOMBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id F0E76B3B4CF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:36 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3f2b8187ec9sf8937485ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454135; cv=pass;
        d=google.com; s=arc-20240605;
        b=MyuUev6qxB2TCw2GJE+yg7HHyDJSO0/PlfN3pBdqncXQ40qfT3/Zw1qPxAlGlcwNe4
         rxZOvUT/1dnCJoOMufwPNTWZWBnTHoUTj+Hc7YRXrW9XG4kiTNrTUa/58csjPEuHlRq9
         76gEKdANrkigzCYdb2+72r373AuToXYrGzJVOlqF9QUc7W3kTgUfpC8V+lPNQgjQdnCk
         u9Y03k6Smmf4sky16Mj2e1PX8I4yj7ogUZ7dW1AGRWrVt3ZmrcyxPnmG3wNelqdRkZCI
         ukRM1Z1OqKX7sLPxU9U3fSpVMYHWAvcq4ufZbGQvzOoVAURtdR6rf1ba54TeznXvJcDz
         RyfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=S52pG2/8QzmrRlqCKsLkLoSjmjL+DLK2kaXiPp+EP44=;
        fh=VRf+07Q143q0KhJ2SLhqSJhEpTf1SJrslvOcCpTD35s=;
        b=LFeG/C+QzccDzFG2uV7kI10bWkqdtTiyaw8LP0Pf6wjJrkCFo+l4sZUPtbydwYhbZu
         pryHzggUd0V3wQ9Nqr4b+zRkzQjVKd0F5EZYpnYu3ti2bN2aARnoLDQU3X2MTCDaJdBs
         wK3u8/FLTNT7ArPt2T32R4t/J3d32d/HaVe4ynywIeQZI/m+6StEMoQHTq0ndww10o8b
         dH9HO43DAeZjkqT8WNbItf0u/qx1Q78+UZkGnWnP8XtHZgjiqgiN6nK/MNcuR/D95Vso
         PH7aLeX475uqF5DKSjpSTHUmnuegKW5fOezmE9xRBsbWpmovCJeCFxBzXhIHAZRJX515
         ZLvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FKkcekd1;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454135; x=1757058935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S52pG2/8QzmrRlqCKsLkLoSjmjL+DLK2kaXiPp+EP44=;
        b=hwqa15Nq/phycp+8IdVAWFUBJKM4IaTgWWhm/pLJRZjomDEVhu9OXqNQaCRESOnLBb
         wOBBUzzw0OJqAH8hQ6uHPjSYIq0hO0+BUTe2c4zBnVRb65MIidO94+RdpJhktwehNObV
         5vuU32cGTNKVFXqr6U7bnd8R9xH4e1VCiwUxvm7vyfcejTJsxE4sq/hge+ey9OEwbvke
         QCoJMmcY0crX1+tt7dspQtZ/Jeb04US9VW2mvJR/S0RXpR/jH46Q7Fmfhou1M3KabXD3
         2LJWXzFq22odXIweBz1VqixznjNXo+AHD/3uOs1R0rR0YlilE8X/XhHd9lalOJtP9O5b
         ZIFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454135; x=1757058935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S52pG2/8QzmrRlqCKsLkLoSjmjL+DLK2kaXiPp+EP44=;
        b=mGxsdDkt9YNMgXXi921Aur3eYO+UZ+p6wMlPcTKKKVkN+1G45hY8f06UIKwSNTiuSj
         XnaIsQ8LnPfXgdQk+IpQimRletvSN+oGa70/Pi1WIiSP8AN6eOfPK412x+kM6G9xsVXL
         J1WBW7hDbx3lrDL40CTuWB5e1oSsMM4f2NTbyKIetl3Am+NRI87+dKp/wDkwQ7Xo2fZj
         aDV/cHGXiXVgEBXMVjBT4HSgOqcTuIvyiHwprCMGaoFj5tI49vck61CLrrI6L0csLArz
         mHzfjLItHEpSr7LkmZbdAkYsrCs8bwQkezChsRLnL84kiWlYDMQ6dk6aMFq9coDipGBm
         mNOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454135; x=1757058935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S52pG2/8QzmrRlqCKsLkLoSjmjL+DLK2kaXiPp+EP44=;
        b=lomkV8jmHh0uAbVKvqVV3lmT4cfJEeus75ndI/6chaWHNy+dBlMTdCGqaMXEdqg9ak
         jI9icTdepClWNc3aPbC1uELf1KiRUm4RDXDQeXFPepGVAIeIcjE1NBxSqGKLxkn+BcUy
         OPQrHRIQXn84q3Gmoz34sMAZ6WhNkcLtdb3Fp3etmzJkS0ZDTKTlOp2ZsiSGfa7b1YlP
         ySlVOpcWZEhVDP51yvKrjNEcEquwAEPulw1LulfpRbmxzccuQuqVOJTob7XoIVs+rY6Q
         leZLcTLoLE2hM8n7r2jTwS4mQABVdSXSpMIhFb7IlDNARG13k6cwfeeluLQagdQDbmG3
         An8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVso8I8IKP5e2KfUkACUWbHS3OTPVUhHhjFFzmpYu7LE5gliXARfHCuGBJzU34qWLNpd4xjWw==@lfdr.de
X-Gm-Message-State: AOJu0YwoziKFMqikczGaSFjE+KF10fF0PiMiMdvgYV2QtZISZouj9xEz
	MGM4PItSAirzd7SQpuEOKf8Q26eRiIGJrLwotNM7Lu/yRPjP8NKCpOtV
X-Google-Smtp-Source: AGHT+IFmw8DEfet5jjZlbUB5HmilazFmKFyRFezuzNOGkjKmOjAWptSiQG5zAs7gP4UIUHViLHdsEg==
X-Received: by 2002:a05:6e02:1789:b0:3f0:62bf:f28 with SMTP id e9e14a558f8ab-3f062bf10bcmr115210735ab.30.1756454135349;
        Fri, 29 Aug 2025 00:55:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeHXXowwcUWg/izmo2w3ouYmM6AnHGAxCNWhCu+QfYJ2g==
Received: by 2002:a05:6e02:def:b0:3e5:1b1e:ec7c with SMTP id
 e9e14a558f8ab-3f13b180f26ls12782965ab.1.-pod-prod-01-us; Fri, 29 Aug 2025
 00:55:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNSzYH5B3qbpCTFBiGtIrd//8fD++j8aNQ9TMwTpT/yVzbsAjTx8en7B4Phbw6rjPyj6pitGSPGtw=@googlegroups.com
X-Received: by 2002:a05:6e02:3c03:b0:3e5:4b2e:3aeb with SMTP id e9e14a558f8ab-3e91fc22de2mr397285615ab.5.1756454134475;
        Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454134; cv=none;
        d=google.com; s=arc-20240605;
        b=kC+SocrGSwYUBvf4UDTCbQHTaI3ePQhyqU0x1n3DsfxdoNhYymN4yOPd0p6k4l4DMK
         XLnUb0AT9n1RWwkOH0TPBP5uYKKV1lz+tYGBgyzP0uXnWirrCl1f9sSmUdWdl5mAPNOI
         lSqVN+I22mmAKDSDwqi4lcWdg1xQPd+kPB7xDKiKMUubYmkv2/oXyIDsVACeCYefHqiS
         OTxLfKC+jyp/BiEg2gLEW0Mvr09zANA0BZZIjJ9hc1caG5l0aXfS1Y2MAUjruc/cJaKI
         nrFqS5r53Eg+EQGfFfVL1N+Sr+g8/AInJ5OjxZ0IK8Z7B038iEGYBonTz/9lF0g7pqgd
         xE2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=e1dzl/9HN9fCmWWoku2EUAe+4oZJtgdEcU9UZmXN/7A=;
        fh=KwJzJtAcK9CB6+bGajZWGufMJ/tdXnXprBdAXpXmXkA=;
        b=Zdkn01JfNQqfP/1GZCTc2vX855LoLVcFsDnrW6SjfjWGDuXZmI7JviMTNng/CTjQMV
         AHYMBQQ93+ecBMrt8mCe45QaJM4gUiA5NZQV0Z9AjJqPFqRqnrzFJNkl3x4zvSnwu4Mu
         3h8YR+FRzIIBTaA2ssVUkbbAlsE0h2RxpkH/vtX2ZRb1ZNBTApqwC0N4b7rCIZoGWDon
         s9WifhNAJeMEBded9YQq/ilDEkaChWpLNZ91TIolMaab1Rm3pFfQkBB7PB+FI7f3cN1d
         hQnSk7UT+83y33lKkBlVtlifbVQHEB3mTYEcVUAZ7ijrZ91qXmMBlEMA4vqWCFVnQL2V
         lb3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FKkcekd1;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d7be499c5si46806173.2.2025.08.29.00.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2487104b9c6so16370045ad.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmSzvQ5sIoltByQ8UP6AdNPgl4hHMFmpJ5oQi4xSGSAf3xkcqksPTPWczdP2I0CRIjzEsmJEAFLcM=@googlegroups.com
X-Gm-Gg: ASbGncs55Aj4FLma80I9WQ9hdvOj+FrrFgrs/Nkx5L3dXgEIuE890719kBrlZGRKlLD
	YwhIYrDz4tAQU0BRAZbJfUTt96EkqHUU2NQYAziFQmcAhO5f3iWICCUQ+YcB6UcDZrBsTV0Oq6G
	UhJW9vpES28Mz+YHBq6xt1U5qjdniZ5JgkmfkWOkjGZcUtDLvNAtcNqO1tDKRm4+dx7xdMJfNRI
	spfqAT+JNs8WpgT0CE3jiLP+dbY0hdDZjUq59CiF8HY72V+Nz8BkLBik2dm+TCMyK6V2qMfMLb7
	WbPhdD22Pl4yOhIwPkiBfHxeYNYzMV8pH9DNueA7QTDYp6UCW5bdRCpsUOVkxBJ0O2v469tBN1f
	gqxqj8eZMtFciBkXLumOPesLTBA==
X-Received: by 2002:a17:902:e888:b0:23d:d0e7:754b with SMTP id d9443c01a7336-2462ee0853dmr343021795ad.18.1756454133662;
        Fri, 29 Aug 2025 00:55:33 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-327da90e423sm1914004a91.20.2025.08.29.00.55.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:32 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 92CC9411BF96; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux Documentation <linux-doc@vger.kernel.org>,
	Linux DAMON <damon@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Power Management <linux-pm@vger.kernel.org>,
	Linux Block Devices <linux-block@vger.kernel.org>,
	Linux BPF <bpf@vger.kernel.org>,
	Linux Kernel Workflows <workflows@vger.kernel.org>,
	Linux KASAN <kasan-dev@googlegroups.com>,
	Linux Devicetree <devicetree@vger.kernel.org>,
	Linux fsverity <fsverity@lists.linux.dev>,
	Linux MTD <linux-mtd@lists.infradead.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Kernel Build System <linux-lbuild@vger.kernel.org>,
	Linux Networking <netdev@vger.kernel.org>,
	Linux Sound <linux-sound@vger.kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Huang Rui <ray.huang@amd.com>,
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Perry Yuan <perry.yuan@amd.com>,
	Jens Axboe <axboe@kernel.dk>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Andrii Nakryiko <andrii@kernel.org>,
	Martin KaFai Lau <martin.lau@linux.dev>,
	Eduard Zingerman <eddyz87@gmail.com>,
	Song Liu <song@kernel.org>,
	Yonghong Song <yonghong.song@linux.dev>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@kernel.org>,
	Stanislav Fomichev <sdf@fomichev.me>,
	Hao Luo <haoluo@google.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Dwaipayan Ray <dwaipayanray1@gmail.com>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Joe Perches <joe@perches.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Rob Herring <robh@kernel.org>,
	Krzysztof Kozlowski <krzk+dt@kernel.org>,
	Conor Dooley <conor+dt@kernel.org>,
	Eric Biggers <ebiggers@kernel.org>,
	tytso@mit.edu,
	Richard Weinberger <richard@nod.at>,
	Zhihao Cheng <chengzhihao1@huawei.com>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Waiman Long <longman@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Shay Agroskin <shayagr@amazon.com>,
	Arthur Kiyanovski <akiyano@amazon.com>,
	David Arinzon <darinzon@amazon.com>,
	Saeed Bishara <saeedb@amazon.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>,
	Jaroslav Kysela <perex@perex.cz>,
	Takashi Iwai <tiwai@suse.com>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: [PATCH 00/14] Internalize www.kernel.org/doc cross-reference
Date: Fri, 29 Aug 2025 14:55:10 +0700
Message-ID: <20250829075524.45635-1-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3498; i=bagasdotme@gmail.com; h=from:subject; bh=UJUK8/oCaP8or4xMM6dYj2gtHalMI9xq0zTRRM+Er48=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY17c4br6T35GuJHFF8Yt24416R5lZZr0d5nIjOkLd Wbtjd2k0FHKwiDGxSArpsgyKZGv6fQuI5EL7WsdYeawMoEMYeDiFICJxIow/NNvVZZWvf59gvln 8f09a96zlV1ddP/qfkeet3OelO1bF7GW4X+WSslpN8ZtovrZdcGNj+0m353MlHX12bkXf15P2h5 ctoADAA==
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FKkcekd1;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::631
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Cross-references to other docs (so-called internal links) are typically
done following Documentation/doc-guide/sphinx.rst: either simply
write the target docs (preferred) or use :doc: or :ref: reST directives
(for use-cases like having anchor text or cross-referencing sections).
In some places, however, links to https://www.kernel.org/doc
are used instead (outgoing, external links), owing inconsistency as
these requires Internet connection only to see docs that otherwise
can be accessed locally (after building with ``make htmldocs``).

Convert such external links to internal links. Note that this does not
cover docs.kernel.org links nor touching Documentation/tools (as
docs containing external links are in manpages).

This series is based on docs-next tree.

Bagas Sanjaya (14):
  Documentation: hw-vuln: l1tf: Convert kernel docs external links
  Documentation: damon: reclaim: Convert "Free Page Reporting" citation
    link
  Documentation: perf-security: Convert security credentials
    bibliography link
  Documentation: amd-pstate: Use internal link to kselftest
  Documentation: blk-mq: Convert block layer docs external links
  Documentation: bpf: Convert external kernel docs link
  Documentation: kasan: Use internal link to kunit
  Documentation: gpu: Use internal link to kunit
  Documentation: filesystems: Fix stale reference to device-mapper docs
  Documentation: smb: smbdirect: Convert KSMBD docs link
  Documentation: net: Convert external kernel networking docs
  ASoC: doc: Internally link to Writing an ALSA Driver docs
  nitro_enclaves: Use internal cross-reference for kernel docs links
  Documentation: checkpatch: Convert kernel docs references

 Documentation/admin-guide/hw-vuln/l1tf.rst    |   9 +-
 .../admin-guide/mm/damon/reclaim.rst          |   2 +-
 Documentation/admin-guide/perf-security.rst   |   2 +-
 Documentation/admin-guide/pm/amd-pstate.rst   |   3 +-
 Documentation/block/blk-mq.rst                |  23 ++--
 Documentation/bpf/bpf_iterators.rst           |   3 +-
 Documentation/bpf/map_xskmap.rst              |   5 +-
 Documentation/dev-tools/checkpatch.rst        | 121 ++++++++++++------
 Documentation/dev-tools/kasan.rst             |   6 +-
 .../bindings/submitting-patches.rst           |   2 +
 .../driver-api/driver-model/device.rst        |   2 +
 Documentation/filesystems/fsverity.rst        |  11 +-
 Documentation/filesystems/smb/smbdirect.rst   |   4 +-
 Documentation/filesystems/sysfs.rst           |   2 +
 .../filesystems/ubifs-authentication.rst      |   4 +-
 Documentation/gpu/todo.rst                    |   6 +-
 Documentation/kbuild/reproducible-builds.rst  |   2 +
 Documentation/locking/lockdep-design.rst      |   2 +
 .../can/ctu/ctucanfd-driver.rst               |   3 +-
 .../device_drivers/ethernet/amazon/ena.rst    |   4 +-
 Documentation/networking/ethtool-netlink.rst  |   3 +-
 Documentation/networking/snmp_counter.rst     |  12 +-
 Documentation/process/coding-style.rst        |  15 +++
 Documentation/process/deprecated.rst          |   4 +
 Documentation/process/submitting-patches.rst  |   4 +
 Documentation/sound/soc/codec.rst             |   4 +-
 Documentation/sound/soc/platform.rst          |   4 +-
 Documentation/virt/ne_overview.rst            |  10 +-
 28 files changed, 165 insertions(+), 107 deletions(-)


base-commit: ee9a6691935490dc39605882b41b9452844d5e4e
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-1-bagasdotme%40gmail.com.
