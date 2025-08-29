Return-Path: <kasan-dev+bncBCJ455VFUALBBA52YXCQMGQE3QXF47Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id AF1FAB3B4DC
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:49 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-24457f59889sf19545975ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454148; cv=pass;
        d=google.com; s=arc-20240605;
        b=TLoCD9FL5SH0Zn6W2sLuFd9FtoQc683MiaZyf3r+V4XM7jFs/UsW4VakvktZr9qTbI
         aPX7NY8zb3Ph0ffWYcCM+GRdRHxB3NV5itlvsgVRWzotDWKUGqJKsDzPeMBDce5N7Vzt
         u1T79UW+eXZddXAwCV0LDmX9q9Xr0aYP7RySwZyT39G8rDBdYMmhc67MUHIaA1HRYM0k
         9pIqTolddCDcVOlYr1oWP9XHe29JJ9J/7lYokUj/7PfxmGFsyIUP4EFMiTmF1JOa5cm8
         3CTwVaoj41tKK+V5J02Hwgssj4PQsdV8YZIYmyhwB3xX3Pa1/QqwtZ2nOkXYtcp+zhRL
         B0Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cT+Kn2PXJL4myK+FHya0rita45doNWSWD0E8/ba//nc=;
        fh=84hgxOPBaMSe+lkZFR6i9DgKpBgnP86c00zW7nlSVXE=;
        b=VUWAsDXrpEl0p1CVaV/UmmA1WepsY8Hi82jeRX92cgDp8MBkscHKtZDyAZo4RtXA+C
         XTxqJ6DRdFi0sOoLNKYiENfFPCPq5uXYQ/rmwWu+JrCbj+tV2YDlmiH/yDXgI0Ffx6Zo
         vqzeawuUDNI//T/b1FYV4uzRQjAYAoX+SBZ2liRg/yLKPjw6sBExWzgZQbx/bOTiX8hs
         3jHEFO1x7xsndHxTRsLygW1Ij6ERcZB6BD6v6LRiaRrZuFX4BOqnmzgeb0ht0RzhSCS6
         90YqgKajN9z45uVcbcDQcs5EUDRfYs1RRTdHQS6ZWVIuwEB/B97OkqLiEy+2GMSeT7yB
         60CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="T8/A1PbK";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454148; x=1757058948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cT+Kn2PXJL4myK+FHya0rita45doNWSWD0E8/ba//nc=;
        b=WIAkcQsCdN0BkCYCQvgVIq2+e6Otn1xjGNlsKppP1WvHO4kHCI5oSC0DxIIm3Z8+Jh
         TFurJlDG5UTVSyVFuwz9UTBXYiF0bc54Lm+dYKA8mT+S+m/pJ4odZUYdDUcCQIJdPUxE
         TJK4bq/VnzmwQ9e67LGt8Qk5WYa6AhHJxUl0WAHdWYlH96B7LGsVrx0+scgIwduov4je
         yhMdYDO55Pq+te3EMLt66Go6Y9fWWh6Mi4/owF1n2a+0uawe2ly8KMb+d1l8aSxrEh0b
         9TBOcyaGp648/4b7IDJFlrSbs15Bh1wdXA8kcqLkIRE2nAQ21KMC2/0nUHDN1Ep0aw5G
         T8Uw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454148; x=1757058948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cT+Kn2PXJL4myK+FHya0rita45doNWSWD0E8/ba//nc=;
        b=M639r1iyqTDrJ45Raa4hvSDaIsN3+QYWC2MeG0oOfBtydIRkX4OxT7aqE4+DGFiC2Q
         PkqvtV/DMFdUZy86KyckVRmkPklPyQbrUyszEVdvOw8whK2Hli29zD5z9xQ3cP3nXvjV
         A+JJqhdqfdQjmoo5V6XvtOAwC+pw76wEyJxPFVPEm0oPHaHlwVCNWPTWgswRxeCeUC+o
         W++P65TYk44srOMDGgUAfuILM8dPGw+0DATpVETRmO0F4kRgVfyvlruFJgeNiR0Z8w+a
         0VNBEdUf8eNMIZzMdzK13NlUF1EivPnqoApgbFiOcw5rmbqE6FL9eCbfCbJcPWnk1L75
         Mfyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454148; x=1757058948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cT+Kn2PXJL4myK+FHya0rita45doNWSWD0E8/ba//nc=;
        b=jc8dmSeBK1zrzwdj1MGhrLDDsyVS8ayqPfdUA8AEPtlofLRT+qL5AIqwWc40bvlQWO
         t5Sd4hZAqc4X+PtnhRgGxI2BEOPAN8IGEE9ToUB5n3/9dUhpsR8u1NBS4ueos5m3+Ztg
         mkO0bhITTlfytBQvQt+HTTbaVZcet+g6V2UE5bMLvC7Y3osgSdAm2P/YLAykNTWx7ASL
         nHHXmY1q0ccBKRM0H1yHgu5SDHA7bnACXY47H5rNlndgfT7rsUws8ce6zNSkSosBbLIi
         jJtMHbzl3pGPxJda7bkUaamP2yk4nWB/yXqb25YaEC0VQpPHvIb3O88STLk4cIC8FTh/
         GTRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxUAG0VJuK4vfyvqpSFHFqruRzdjmBIqAdJkqjf10mENC7+9PkNSoHAhq/PW/cD/1Wgddx6w==@lfdr.de
X-Gm-Message-State: AOJu0Yx+yFipW8/6mT4Rn18/F0a4WWE9YXHh4EiIqNivGb0UkiUXmtj9
	exyVZ/5/H0gd/r2rNnx2H38DHmHPnR8E3B5WV6osEty00m9vLtSVlr94
X-Google-Smtp-Source: AGHT+IErtk6uVEaY7Hqx7mHwtvpMfR5ZOs2wtXI6H1S7B7INobOBMIv0FU2Y6GJYy+BCV/uFAlGXKw==
X-Received: by 2002:a17:902:da4b:b0:246:fbeb:b66c with SMTP id d9443c01a7336-246fbebce43mr208697735ad.19.1756454148127;
        Fri, 29 Aug 2025 00:55:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeVy76Ii+RpDr67obeoN+uZl5ijLUX/yNJbmgwV4eSa0w==
Received: by 2002:a17:902:e810:b0:246:570:cbdd with SMTP id
 d9443c01a7336-248d4de7f52ls21312535ad.2.-pod-prod-02-us; Fri, 29 Aug 2025
 00:55:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4DMLpR0BYV0KGwW5XjclaiyvVixlzGaiKUOj59xhMF4cdicugTmMRQvlgpMFlJOoYoVu5Ec/H8Uk=@googlegroups.com
X-Received: by 2002:a17:903:32d1:b0:246:fdf7:2c71 with SMTP id d9443c01a7336-246fdf72d26mr211984135ad.47.1756454146824;
        Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454146; cv=none;
        d=google.com; s=arc-20240605;
        b=jUJHkQnQk1EfmCKgHPuoPQuipnN+1H0N5tE7/FcOPUHLqDTfQ+E0GpJ55I8sikxTyb
         B6z8dRy6UGTTT08hlos0rMeclEXTeqCXHri/+adTa2J/Tajt+iMamLDTPHKa1Fm7IoUN
         gRf1+8WyifafxpsXuNymwUmDIFzOT452tzkEBqzr1qSiWwYvoWe7x9Pyr3MFGetM4Emk
         XOGZ757maBDchsfkXWtgmCe3wXsKqw9Vom3fVt40/hiPU/2jAXr4RLtnAh3SBj1oXexZ
         fc/z85dPfoHZ7OpC5DuyPoibWSKasX1d9qNptLGv61h09YOBx5IU/cohQuRb2G9TcNnd
         zdUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fK0hEDM5Yyao3a7xqBzpr49p9H5HB+om5vfXDIKLdeg=;
        fh=ppy6ac8yWCmwkRD0SdQPNaqMC4RF9JiDviYZAHjlFeU=;
        b=bD1g283et8eFnPIQYFc8nyoRZ9ST+jr8Y3epz4lLlIf2/7H7TvwJ2dA7I25UQD5bj/
         SSsIAhohPm4fW9kf46agROldFM7zSFsJfyBmz06iMfr0eo8EaIPodGsJTQlDFrIpDlsy
         mKZTIfY33ubSeZrr3HdoleEypgBSkAP1fGhzOoZhtjleDn2usXamV8MNnB5Vr+WXiFvC
         87wHwRR1RgTZjy9DioWAR8qFKx+7LFeMt5vJACvFaHrsq+ydObbfnT2H1jmj1po9E35m
         j4M99a4x4fM45UV4sMojNC4fnVmGL4FUv/wSWbbABqOj35c5aEl5Xb5m2Eg4FrmuneU7
         bNxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="T8/A1PbK";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327415067d9si475276a91.0.2025.08.29.00.55.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-b474d0f1d5eso1353906a12.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWf6MuAcFmN3ZqMLBd7/19RRi1+yGUWDA93VMXnKqinIuhLX6VNp6Q2PSDg7zngbPgfNkYGaTzFqU8=@googlegroups.com
X-Gm-Gg: ASbGncsIOhwRXVwN47WBQIinTB7XQLJw04slpcB42/aLK/t+Ch334vPPo/GmoXEfNdF
	GLXgMfA3zBax1URqfBJG5k3DeN7Su7gOazfXiiOBPnykRwTH03lLMIV5Y9lxstK/Be1Z8ubfcwY
	YAf1df7xlharOBIX40uLVhTk/gbKmWSaCqaDxIRWiWeYcMvVb7+lzPV5LeI43JbNMOtSRp+4LBm
	Er2ndaNaetab/HCIFlysj26MpC0E4p+PMgCmqAGR2UByhd3sz/dM4BgoPE8ZJFVizIQDeRmdSL4
	3E5FiLavxZzEXs6KkdJeSpGnKMPImYDVXCAR/BXOJBDQGAOimGLHgX02CytHL5iXupXlmnvsTSg
	udj9LHlWbQMAMFNXEWJUahrZ1GuB09fVyVxMS
X-Received: by 2002:a17:90b:2f87:b0:31f:8723:d128 with SMTP id 98e67ed59e1d1-32517b2db8fmr33644513a91.34.1756454146128;
        Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-3276fcf0567sm7404095a91.27.2025.08.29.00.55.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:43 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id C98394480991; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 09/14] Documentation: filesystems: Fix stale reference to device-mapper docs
Date: Fri, 29 Aug 2025 14:55:19 +0700
Message-ID: <20250829075524.45635-10-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2828; i=bagasdotme@gmail.com; h=from:subject; bh=Ip9RCWVx3N2eFboDnh1dVntKjUKs5RT6sbpEBdmz23c=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY16ybj++M2M+e9AK28XZP75VaZfxL/rvM//ttckLa 3oE7/o/6yhlYRDjYpAVU2SZlMjXdHqXkciF9rWOMHNYmUCGMHBxCsBEPq1l+Ke0Kqr32Tmn3/wy 503l2Fb8+Tb1i0vpkb/b//3YUvkmUo6bkeGv6MSGx38SK429ymz0txt6/t/hdS/prR+npRZPk6W qGg8A
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="T8/A1PbK";       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52e
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

Commit 6cf2a73cb2bc42 ("docs: device-mapper: move it to the admin-guide")
moves device mapper docs to Documentation/admin-guide, but left
references (which happen to be external ones) behind, hence 404 when
clicking them.

Fix the references while also converting them to internal ones.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/filesystems/fsverity.rst             | 11 +++++------
 Documentation/filesystems/ubifs-authentication.rst |  4 ++--
 2 files changed, 7 insertions(+), 8 deletions(-)

diff --git a/Documentation/filesystems/fsverity.rst b/Documentation/filesystems/fsverity.rst
index 412cf11e329852..54378a3926de7b 100644
--- a/Documentation/filesystems/fsverity.rst
+++ b/Documentation/filesystems/fsverity.rst
@@ -15,12 +15,11 @@ of read-only files.  Currently, it is supported by the ext4, f2fs, and
 btrfs filesystems.  Like fscrypt, not too much filesystem-specific
 code is needed to support fs-verity.
 
-fs-verity is similar to `dm-verity
-<https://www.kernel.org/doc/Documentation/admin-guide/device-mapper/verity.rst>`_
-but works on files rather than block devices.  On regular files on
-filesystems supporting fs-verity, userspace can execute an ioctl that
-causes the filesystem to build a Merkle tree for the file and persist
-it to a filesystem-specific location associated with the file.
+fs-verity is similar to :doc:`dm-verity
+</admin-guide/device-mapper/verity>` but works on files rather than block
+devices.  On regular files on filesystems supporting fs-verity, userspace can
+execute an ioctl that causes the filesystem to build a Merkle tree for the file
+and persist it to a filesystem-specific location associated with the file.
 
 After this, the file is made readonly, and all reads from the file are
 automatically verified against the file's Merkle tree.  Reads of any
diff --git a/Documentation/filesystems/ubifs-authentication.rst b/Documentation/filesystems/ubifs-authentication.rst
index 106bb9c056f611..9fcad59820915d 100644
--- a/Documentation/filesystems/ubifs-authentication.rst
+++ b/Documentation/filesystems/ubifs-authentication.rst
@@ -439,9 +439,9 @@ References
 
 [DMC-CBC-ATTACK]     https://www.jakoblell.com/blog/2013/12/22/practical-malleability-attack-against-cbc-encrypted-luks-partitions/
 
-[DM-INTEGRITY]       https://www.kernel.org/doc/Documentation/device-mapper/dm-integrity.rst
+[DM-INTEGRITY]       Documentation/admin-guide/device-mapper/dm-integrity.rst
 
-[DM-VERITY]          https://www.kernel.org/doc/Documentation/device-mapper/verity.rst
+[DM-VERITY]          Documentation/admin-guide/device-mapper/verity.rst
 
 [FSCRYPT-POLICY2]    https://lore.kernel.org/r/20171023214058.128121-1-ebiggers3@gmail.com/
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-10-bagasdotme%40gmail.com.
