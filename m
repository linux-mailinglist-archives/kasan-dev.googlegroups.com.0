Return-Path: <kasan-dev+bncBCJ455VFUALBB3OLQPDAMGQEQYALHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 41952B50B39
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:43:59 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3f66546ad68sf1997645ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:43:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472238; cv=pass;
        d=google.com; s=arc-20240605;
        b=T6rSi4lTvMXs9aSqzhU9DnPdIG+z7MUG4XJRTnC7/pVxLL3ztIvJfuEy0cuGdvcdBG
         0bzqG5UpGXsH/dH85fBxXId0XEYHAt7PgTF295aHgxRIs3/fF4Klb9nj974EOzNqLPJ9
         ZNJVqlsHIuJdcOB0RWJJzze4YxHmFA9Fgcs2dDqRytaE0T8g4XqY1WcAn+jTnsYTcmB6
         aOVuGF9kmE0+oN2/YibEH4MZISjvS+ir3D1kRr8YvZflfYKcSCMp60+cvsyLGPJ95WQp
         LyXWq4cDoI82oOcktXjur4nXft9GgeaU64ZPQsxN81jPMy2fqCkoWYDZAaZRZV5pZ9Cv
         3H3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=N7nvfhmM+/FjUCbRF8PqHiakM5iSOdvqqLtJlvDoMpg=;
        fh=qo3YYYCB72yirPy5YXDy9+LfxZqrie0ibi7Elp30Q+I=;
        b=kH9ljNq5diS/VFLNJ4UlbZ+MX8XMJ7VSCAJKKs5+A07fumrxQ6OGE3z3LIANzfEB5w
         UTZcg2mm7MeQKKFZsrbYWd+LwhZgpTFRzBiSr7adZ+mNkzfFDSbR+iT+O4iEruYIAMvw
         A3Ds1oE3fBwACfOoUx7gSEIAmNPbDtltiPBbCBmstYHyitGzMJHAqiZystxhBL9iez5s
         yC2pKEdzva5l3fuIW8OkjIg8CLXrKeY7vHB6odpCLZivylWNy3GfahJqqTtZwKJMtVJv
         fGCEIaUPN/zGpPyQPseU72aYmNhVDwlIEZQZDWosCeGr2HBvRjquw5+v6rC4xXd3o+i2
         XUWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JUUOpu+w;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472238; x=1758077038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N7nvfhmM+/FjUCbRF8PqHiakM5iSOdvqqLtJlvDoMpg=;
        b=owoHivCnlqk5zo00/Z7NA4KYVck+I7wL6h6EH2SqC+mnSICznA8sywmtdhl4YfvAzj
         Y3hkWRrY1IjHOQm+38mCFhq5RvJC1MtKdisTC3d2X79btW9I9WIaBE1niW0HvS94A9Yo
         iuuT4t5QZbxOZv4sZtfjkvqyKMmmf33gr3A8h+mcY4tjh9V5C1cJjQObGa7mj1OpufUn
         KmQtB7qHApWt9KYX3cS6PtKmlh69/g1eUe84H98s9IbM29uN3grKcGMV8PLXdrMTnETz
         VIH+Z1A6psVg+6OwgL3kO9ueeOcuXDdUh+IGNrzApwBbtpYPnBuTZyD32FCWo4Esiu5e
         dwrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472238; x=1758077038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=N7nvfhmM+/FjUCbRF8PqHiakM5iSOdvqqLtJlvDoMpg=;
        b=Sqqr3QOlFuITDo3ldBGrabNXCMv2iOi7U1WbtV34owF1burEqYd8uIb0saj1Ig6vEW
         IWBTwXjeTxcrf4gIHw7AMKfptxR6GasS6tIAUbiNfJbtYRlXD+Bo8mnT/12DFigfOAGc
         ALS8GP8rxE+Q07wexmgCY0ViG7ZgSMpVKh975MYNGczzwYwaksPNFfaJHqG4WyyR/wdM
         yNAplfrxAziTPa4Q06HRXb/WA8mO0itjCUMGeLkt5nNuK+hG7rMxnnydz90FMe1viVOD
         A5UV9/4pWbBnj0nFDGyQOCAwYDGOmbDO3Usa9qm6d5pECZwn4mDddwFloVZ06ij8ee57
         mySA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472238; x=1758077038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N7nvfhmM+/FjUCbRF8PqHiakM5iSOdvqqLtJlvDoMpg=;
        b=edwgmQKH42Hfcds1Tdu7L7u1XurfpckP6PgKjmk5XHHF4bWNBZu3JPLiZxaAnx56fY
         yxEynA0YwK0urxRKvrTuu9PCr9r4hrTvvPeUNcR1aby3jfsZ1h/HVXV+4Wje7ei74M7q
         /Hgk/kxwJAATY+48+E8tZmoLSjGHvOBOTsKTLRalEJMXdyVi45H9YcqgvGaLOZo3TvK1
         MXcbOQUNlrw3nOLDWZ23hYyykca1J+76Q7aKeCg0Hn7DNAfTuLbYaP3vU5KLFreXZBjg
         M8zs08e4QK4W4YUPIu/nRkHh6W7wHwFxqwaq4RJbT5OS7ha3PZdyAPFVaxi4iHD/QL+Z
         hA+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8WAKBbAVTEiU2d4/1o1bdpzJptcd+A9VLll/JPvij83wZSomayCTxLQKio8lXtSCGceIDEA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5Hs1pKzZ8/rPfGwQYfbihbpbq670UfCFMXCoBJX9cSDr6CvT0
	pAkSmKSpM8k0XID27cTOcegQcs2L+I4KluZ3UYfofWqzg/89KEr5Shez
X-Google-Smtp-Source: AGHT+IGCFSxPIfYSWvLzcMaZL9lVt2CN00Ks3wLmykqCUfa1mcdJpca6+JRMURhKK517GmZyU62m4Q==
X-Received: by 2002:a05:6e02:4417:10b0:3e5:8344:49ed with SMTP id e9e14a558f8ab-3f7bed387efmr231443525ab.1.1757472237823;
        Tue, 09 Sep 2025 19:43:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekYypcep8oKAQgb9pKamcIzNiGZ6V3tDQaDM7YNKA5nA==
Received: by 2002:a05:6e02:308d:b0:414:703b:1d8d with SMTP id
 e9e14a558f8ab-4168c5609b8ls1520065ab.1.-pod-prod-00-us; Tue, 09 Sep 2025
 19:43:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQCf32kk06JE08MkB98Rn7jGCEc/PlDTkk0euRmRczORXx5nizsTJ6o+ES8FLDenrFT6pOtQAc1yI=@googlegroups.com
X-Received: by 2002:a05:6e02:1d82:b0:3f6:55e5:18fd with SMTP id e9e14a558f8ab-3fdfaf2e3e1mr213830155ab.3.1757472236248;
        Tue, 09 Sep 2025 19:43:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472236; cv=none;
        d=google.com; s=arc-20240605;
        b=cB2N29kJl08rKwbmaXp/C3hsqwSvUtLpmrX2XUotOLnT1p5Ge4KkgaUnbtNjlLyi+X
         J5nFbKV6KlMgNTHTcbbUlHuodltMmW9VO+jVFQGQR5OdTgrFsfiGU2p5hcDSjcMtorXm
         gfmxhkLiFmVDD0uE0BYvauKGXo+lITMlAnFl9AbtnUH7C8qvxVKANroAB2pfQLJfV9pB
         uxR3E8VRgxxVzKn+8xpwoucoOLK/L0HRjAkW455LB3rn4vfkwP5Yo/NPs38s3cDGubvP
         jH1U9adQQcQ/hq+WJzJbPSc+v3eGLjAeocBlpNAQkby/49RF5FZYTrUSn6jRxFXAEokK
         g76w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NJdcHxX57XebbZj4zrMMfWynAEuJyyuoNM4CHXO3dik=;
        fh=kCb52ALu4biG0F7iNKC4oSRP466caznddYFkRNstT9g=;
        b=UMGDbSmAWOh+1F4qa7BX3gDhXJokjRudAWyt006bSagBArpvY2I8qxSQy0ngz/xSjC
         +SZ6S5bg8fM8K8oeYeK26uCzDzijObpCtlgHy1ERykM1MmCfuzYZj8gAO19ORJYY+mj3
         8yIvQzQX1C2NB1fHB2OE/9puxqHC5+4/fwph+Ad7PfZ3VoHf17+OKXVrec/XKMGIX9UI
         zFXB6g3wWatziFElf4f31QtkcRRVRvkkuoL70h+W2J4PoEsHozJaUzB1E+4E0B0ntLQI
         FNt0+37wuyQZmaa29AgEmkdoBtb4ZVynUVB9YSm2t5k3cEPxnBiP9UQzTi0MEd0/1Rkf
         Ql+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JUUOpu+w;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-406b652dbedsi2516945ab.0.2025.09.09.19.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:43:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-76e2ea933b7so149096b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:43:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkNzJS4P9P1FqUvzsNi3Vq/Ug+zXDpKrjmxQM/YOqhiAMYVqLnzmKMhtvqzpVC8zsKIh2gSxueucM=@googlegroups.com
X-Gm-Gg: ASbGncvL/1hpYVBwu7f4VTqToZoiS2nf4/tsqqCwfLcazM3PxszyljAJ7o9dsPfq4wz
	y2MSJ119x03qpExZtJIVgRfmSYUlvZ8VrQ+Vi0ZIQiy1Q1PrBYEuHg2oqPiIPsnRyIDDL5lyg/B
	Tl2DK1ZTnYphzvtmnkKpm20buCX2gaOBY1dUhsk1byljpMUTcItrPf+tlTHzipI9zZvRNqLyI8a
	vfqgRZLEkKt0OTfEmbE9eHbO+nF2cYw7BSzaqYUIGF2bF/5Kb+ey554IW2RAxudE7DXaN5lZYjQ
	e62hGT/ZyMdPw0h1UH7nIJkCOzQBnbffCw6IaxfRsT658pbiNLy35Pv0RExlXmPIAT9FJFO2Ym1
	od666pwc8mYvawsdXHSThzZI7uQ==
X-Received: by 2002:a05:6a00:4c99:b0:76b:f7da:2704 with SMTP id d2e1a72fcca58-7741bf3f8a4mr22435837b3a.11.1757472235618;
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-775f6b4202esm573646b3a.55.2025.09.09.19.43.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:53 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 0C94B41FA3A4; Wed, 10 Sep 2025 09:43:51 +0700 (WIB)
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
	Linux Kernel Build System <linux-kbuild@vger.kernel.org>,
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
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@gmail.com>,
	Simona Vetter <simona@ffwll.ch>,
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
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Bagas Sanjaya <bagasdotme@gmail.com>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Ranganath V N <vnranganath.20@gmail.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Jani Nikula <jani.nikula@intel.com>
Subject: [PATCH v2 02/13] Documentation: damon: reclaim: Convert "Free Page Reporting" citation link
Date: Wed, 10 Sep 2025 09:43:17 +0700
Message-ID: <20250910024328.17911-3-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=883; i=bagasdotme@gmail.com; h=from:subject; bh=TM7A3b/55JCgQfCA5kxK7YxN6xbvfSMV2ctBC+dU0+o=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnih2mgVe6tXtn33sQOG2JKN6npsV2+KuvrWb+KLwo YbPrZOKHaUsDGJcDLJiiiyTEvmaTu8yErnQvtYRZg4rE8gQBi5OAZiIgi7D/1T1Zd+0q3NfXbSR WTM/c6Nt+dI0hVcvJi2QWSN+/Q/fJyVGhivi20SiX0RwBzyI4fPfm+rzyfPWB2YZV73+/5GK7JN 5GAE=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JUUOpu+w;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430
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

Use internal cross-reference for the citation link to Free Page
Reporting docs.

Reviewed-by: SeongJae Park <sj@kernel.org>
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/mm/damon/reclaim.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/admin-guide/mm/damon/reclaim.rst b/Documentation/admin-guide/mm/damon/reclaim.rst
index af05ae6170184f..92bb7cf1b5587a 100644
--- a/Documentation/admin-guide/mm/damon/reclaim.rst
+++ b/Documentation/admin-guide/mm/damon/reclaim.rst
@@ -298,4 +298,4 @@ granularity reclamation. ::
 
 .. [1] https://research.google/pubs/pub48551/
 .. [2] https://lwn.net/Articles/787611/
-.. [3] https://www.kernel.org/doc/html/latest/mm/free_page_reporting.html
+.. [3] Documentation/mm/free_page_reporting.rst
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-3-bagasdotme%40gmail.com.
