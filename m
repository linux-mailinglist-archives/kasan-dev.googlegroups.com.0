Return-Path: <kasan-dev+bncBCJ455VFUALBB75ZYXCQMGQEVROGHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 67DEAB3B4D8
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:45 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-437d0c6fda4sf548498b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454144; cv=pass;
        d=google.com; s=arc-20240605;
        b=d+KWfSONL4zHB1FhTH85zXCdbr+yWuoc2I4fIpwcGELEMTnpZZGJUhUSqI2bdNoHix
         YoIYqzsWFcR+dGyHtG/GQvLCukFyUb+1NuIpTx7m0hoyHE66Xt+mvWUZ2coGNEz9Vn0/
         D7YFOaLxB7t+S4ckxc0GuOQV6DpEQBsa8vGC+zNGPvnvHcCLn2n5CHuhftY0hJyGKmRH
         zUF+akkOlbhNFyUDnT7QsDBZbKpOANJnQHBInrl1hc3OFXEinrqWfXXZnNHV/PealjiE
         bQQECJf46ZAXw9PslD+qPVAarkksxRK9PffjDKTWxrCm3WEv5UJxSRY+z7QJ3RMNM1CV
         pBnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PKKFXbPlXE9ZZFoz8oSMQHHrE8wFHkuyWKUCROPizcE=;
        fh=3n5yxZKu90vMs815IUOoKstfebsN6TB0qeGvpWVb6ew=;
        b=h56hmUCngrm/J959tavnogkMIxMDyJRzColwVdT0Tu6AyJyAVBnwUGnKCW5q5Z3rVL
         zsiczteTdSAYuxFHQzOzk23sfJcHZiXslIytvtftZ6mOnSTms+1t1R9mf2n2tWaAy4f4
         zSWIVAFY0ZylrgAcyNLTHhyQiZ1lbip4OqmoZBCcP1H1ijplP+8fhAZ/1U1L+7kzkuOW
         yDK2lmxts+3ibNvu8G13Wqxqh7H3qHbriY3sY6WWYKyrwufG4PcGRv+26iFd2xsDazYt
         ZvOWWt8yrOsXCmq7tuszXaY60ykjUATDXqWIamCjSiFiJgktX/WarSfAqkFBMGZUIWWS
         C9KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Buy9PLZT;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454144; x=1757058944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PKKFXbPlXE9ZZFoz8oSMQHHrE8wFHkuyWKUCROPizcE=;
        b=PvYHEO/PiYjiYFYX2iHPOFEao7oa4af7bV+93yg2fq7/Dr3KFMD2lKoJ9gdMYP2W3p
         bUQ9uipWsxCox1BQos0to5mUMvoPG1lS3lVV3f5dkwbxqjrVhsQYDTce/jMjsTj8PuAx
         QS1NDY/bDylKS85ZBc1dTJQ5qfEyuHOqPGAt6ShPPxWgNXOv28llvj+ihv5Ly7ZWHmcX
         eEijKEzr11WaLrPv5ZiGx5mTPO0UAtf91ndbyR3FHupZlVqkxP9chuoq990XhZPzc3NF
         0yvVA3eijuecPx63tPvT7U9y+axV9rcl60kwlBnV/wxKdt7Vuq7AZhjTIgDCRZyhBEKX
         aDfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454144; x=1757058944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=PKKFXbPlXE9ZZFoz8oSMQHHrE8wFHkuyWKUCROPizcE=;
        b=J5FF9MJuB7jKkpnvD3/VUplDig0fcmDkxALmTFKrkrWDA4MxHD3h1tb5GGG7p9kcsz
         pvsyiBTlk/LDvgeFTe8ZUOncfbQymcglU0DCshhS4T8AWK2z6W4GGToO5Y+Jc5FuLois
         tBxtFlehV8DbpEvjXsmxuc966EVDKf7IcKF5UaIfelqNOr8VSv+pJLvpiM2YbHEBps4u
         SqnCPP74sbgeJwz/+ZvSO3DSM7TU/Fcl6ZM9uTTPSX7trwprx3+c04ZRR6hpVg3cdzV8
         cI4dCqof5M7iQUlGoCs9a/OLGq6gsQ1PELfrJ/Cxi8xR+3juaroXdpNCaDfFV/p2OCH9
         z0qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454144; x=1757058944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PKKFXbPlXE9ZZFoz8oSMQHHrE8wFHkuyWKUCROPizcE=;
        b=IJ7DaHQkNxwoc03aRgpithZ6X0GavaNavj3Ffmn5HVVIq2awrvK3WohUkEP2yQ6Hmp
         hzX1WltJpG3tScPG/K8ij0xRYafBQWf1k7pm5XS7Ci4+oiadjO2Iadcck1oZRbl1u6N8
         VLDPoTOKlH6JIzRGfWrmMdV6IfkDgysOm7ncIbibh+Qngb6RoaMTqRXcNPY672Z26hRT
         gb8rDCq0O439u95aKAVyAC+cAOXpQbZNWxePYGVsuNLroK0+ntjZBHEdh7nfQYgo3ZUv
         blQJSOnmh4pbccQHdJAtpJjYYUhCenCQqIt2+K+qaR7GgnbkOz17F1rEJu7gG8pMKLT/
         YAqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpeKusFMjD4s5G4zeX+qYMyULcBpkpdSrIS9pII9r1pW2i0sJrg4EScHnIzisDbkA5TqMxBw==@lfdr.de
X-Gm-Message-State: AOJu0YxmTSe4LP6dC2+Ckf1QLH9oh6O6OubWqK5wedZzdqwKC8rk2KMe
	YqLWPKtPIVAlp9Wzff0VBMc60jTKtcQAsx4zk6kdTKIBdsJOb3J+gO1U
X-Google-Smtp-Source: AGHT+IEIBAQk+I6xrVjr07udJchZNIcm9nBbyhW8PzbUMWPTSzarN9mJ3KGbOsoOnoWUBre3Icpq7g==
X-Received: by 2002:a05:6808:13d6:b0:437:b83d:de82 with SMTP id 5614622812f47-437b83de863mr7345798b6e.48.1756454143794;
        Fri, 29 Aug 2025 00:55:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdlNobqwGg1JSS4a9gRbphwO7Cr9z05A4/OshJEwa4GEQ==
Received: by 2002:a05:6870:fba4:b0:315:531e:fdba with SMTP id
 586e51a60fabf-315961bb027ls671692fac.1.-pod-prod-02-us; Fri, 29 Aug 2025
 00:55:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4v+lAxlK7Gz8hmDPJZ8vegzxwcq3Quw4ko0t1Tx0RjpfcDHEocjwEnH8ekj8r95dkxphVJyxeEs4=@googlegroups.com
X-Received: by 2002:a05:6870:6114:b0:314:b6a6:6873 with SMTP id 586e51a60fabf-314dcdc12d6mr14428727fac.41.1756454142905;
        Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454142; cv=none;
        d=google.com; s=arc-20240605;
        b=LjSEC+eOg8ptm8j3GrKuKmIywXptQbmwge9oykiii3tKrQTHppE0Wr61m1pGnzZba9
         2iRqMbH9726AFPuoIikl5g/iRtHBPD5TbOnfOkmR/Dz070rxVAjkgSbUALKqVs4A2ycO
         YdOfjzfe70fdSJ+DgZrOyBh0OUANEjT0aPlnZs1jVDl5XE4KXpfOBFRuHVjhlYT/H58b
         fmUGxYFhI5RhJx51WyXbEnPkZUW0ADs47dNprcbCton70L7RbYmATtwRYYS42hOY+eKx
         Aic+fozcQKE6cVfORaAOPlW9fdVaeyI6XjhqSwlp1ChFubpcBUaUNhTTFpcI18b9Fh+e
         vWJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rNDvUkQSM5YXWXIzm38SWG/hRRo/bsx6SYKE7k7lSmY=;
        fh=c7R61njYuXiVDgf7iq7KvFheQK31XQyx1XqkDjuFdqs=;
        b=G/nYUKoAfbNt18DGjushGhSry5jxGU2NUHFvFJU9ejQXRHhjuAr0w4xSL4x43Y23MH
         r9B65KNpwg3BX1IWqvrBwm3QLcxiaurZB6dUFcxK4XpCm2lbmpgzQqjXhcMQ9G8XVhbW
         XJNhytRfG5MSKEYFwSbJc1S0o0w8JOumsB+OJZPvpQuCO2ENk4ULZCgvvnzYPJRS8BrD
         HzNdtHr2txKJwWFUckRl4+fNDhb6ObNAXtAC5t4sV9Zfekr38iUEQKLZBRwCmw8j0rsB
         /f6G0kzPyneHhH92m83n28Zf/z4SQv6ze5aVC0YlNE0WBAFtImo0OxrsS0H2X88bnlTS
         b+NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Buy9PLZT;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afdefa46si92522fac.3.2025.08.29.00.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-248cb0b37dfso17378085ad.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbUHeFNfA5gOWCqoHN+VO4MoWT1bsrqd2c800ntW1c9Hy1JftbUIPlcxRL9mw/2HiAuI48I2w9eZ4=@googlegroups.com
X-Gm-Gg: ASbGnctJeVfX2gAo0AqFUHw5IvI9ptO3UpXuAD98zM+4g7Rl3de9kBlyMBsk+PK3bGh
	rBmpubJQZN1TqnCS81H1zqD5ja8RI1OVZ871tzcC9B4KqLK0G3TiEdJ+DDjtBmu5ZaGkKPC0cUX
	rQC923h+ywXB2g+XmGw4mfMbWplrB01uP5bR/nm9nWfH4ZVjNi4u0Tyo3jhESvHnAXbQvnl0506
	I+My0gbqD4W43E8wopTuJtmVlBRAIGDX2yTlvNGdr4kIXuCRw50ZDECuJA+1/ocFRMV/X+s0GGO
	Zn4+vcLnlv+kVrGZ0LFpSYfAexZGatQ/JhzPMKUEZsnLPaoczREcZFNfSmSc4EE2DXNeMNG8jKC
	MfjefR3qzyVeDYpt1BvQC/s9ElQ==
X-Received: by 2002:a17:902:ec87:b0:246:6a8b:8473 with SMTP id d9443c01a7336-2466a8b8672mr314430065ad.45.1756454141954;
        Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-24905da28a2sm16370945ad.71.2025.08.29.00.55.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 8D99044808FE; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 06/14] Documentation: bpf: Convert external kernel docs link
Date: Fri, 29 Aug 2025 14:55:16 +0700
Message-ID: <20250829075524.45635-7-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2744; i=bagasdotme@gmail.com; h=from:subject; bh=IiAjp2UiG4E4i0m+2wynqH3PCAcCcaK0of1KdBtx1KU=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY162Whs7TnrT1LggM0BOd5LEqfAiXtc37zS3e5gl8 vnwGP7sKGVhEONikBVTZJmUyNd0epeRyIX2tY4wc1iZQIYwcHEKwES+TGNkWCZ94c28TXy5tQ2r bD/4zPoTU9D/g2m/U+vihV++Li1Y5MvI8PjMzk3qf6eEm+VfELaazHDuklKIXI/3z+ub9I0rLF5 X8QIA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Buy9PLZT;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::636
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

Convert links to other docs pages that use external links into
internal cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/bpf/bpf_iterators.rst | 3 +--
 Documentation/bpf/map_xskmap.rst    | 5 ++---
 2 files changed, 3 insertions(+), 5 deletions(-)

diff --git a/Documentation/bpf/bpf_iterators.rst b/Documentation/bpf/bpf_iterators.rst
index 189e3ec1c6c8e0..c8e68268fb3e76 100644
--- a/Documentation/bpf/bpf_iterators.rst
+++ b/Documentation/bpf/bpf_iterators.rst
@@ -123,8 +123,7 @@ which often takes time to publish upstream and release. The same is true for pop
 tools like `ss <https://man7.org/linux/man-pages/man8/ss.8.html>`_ where any
 additional information needs a kernel patch.
 
-To solve this problem, the `drgn
-<https://www.kernel.org/doc/html/latest/bpf/drgn.html>`_ tool is often used to
+To solve this problem, the :doc:`drgn <drgn>` tool is often used to
 dig out the kernel data with no kernel change. However, the main drawback for
 drgn is performance, as it cannot do pointer tracing inside the kernel. In
 addition, drgn cannot validate a pointer value and may read invalid data if the
diff --git a/Documentation/bpf/map_xskmap.rst b/Documentation/bpf/map_xskmap.rst
index dc143edd923393..58562e37c16a01 100644
--- a/Documentation/bpf/map_xskmap.rst
+++ b/Documentation/bpf/map_xskmap.rst
@@ -10,7 +10,7 @@ BPF_MAP_TYPE_XSKMAP
 
 The ``BPF_MAP_TYPE_XSKMAP`` is used as a backend map for XDP BPF helper
 call ``bpf_redirect_map()`` and ``XDP_REDIRECT`` action, like 'devmap' and 'cpumap'.
-This map type redirects raw XDP frames to `AF_XDP`_ sockets (XSKs), a new type of
+This map type redirects raw XDP frames to AF_XDP sockets (XSKs), a new type of
 address family in the kernel that allows redirection of frames from a driver to
 user space without having to traverse the full network stack. An AF_XDP socket
 binds to a single netdev queue. A mapping of XSKs to queues is shown below:
@@ -181,12 +181,11 @@ AF_XDP-forwarding programs in the `bpf-examples`_ directory in the `libxdp`_ rep
 For a detailed explanation of the AF_XDP interface please see:
 
 - `libxdp-readme`_.
-- `AF_XDP`_ kernel documentation.
+- Documentation/networking/af_xdp.rst.
 
 .. note::
     The most comprehensive resource for using XSKMAPs and AF_XDP is `libxdp`_.
 
 .. _libxdp: https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp
-.. _AF_XDP: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
 .. _bpf-examples: https://github.com/xdp-project/bpf-examples
 .. _libxdp-readme: https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp#using-af_xdp-sockets
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-7-bagasdotme%40gmail.com.
