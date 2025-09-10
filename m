Return-Path: <kasan-dev+bncBCJ455VFUALBB5WLQPDAMGQE5ZQLXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id ECA18B50B4A
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:08 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-314f332e0d2sf6579648fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472247; cv=pass;
        d=google.com; s=arc-20240605;
        b=LL3v1Woya/cBE50Ft9HizkmfNsyg3l+5NWyHnjcuXIRu74D/l6Co8v4YHjY0ML3PQs
         bzQ6kxjzctGmGtsboMhCJfnPlULJoRPTE0BOnq9hHuk89x5Iydw2smMyBUcEyY+U/ZUs
         EOY30B7BBaCUjl0GZBW0OnhpTG6TYTRFbsHcb3Qm7HE4Aj98DcYJ4AlGv5tnudQETrjX
         jbyzIPZIKRQngeuukN0kZe7YHlnfGdNR23qdH21KtuJmi/S3KeJMIoD8nQXPbz5x1hV+
         qhlbAd+QK+1xGOYm4UD7CY0pA6QPRZK/shPqTfLQG0f/YBXtxdF9v+a5U1wD5cBmv6LU
         Mg1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=l0Ez4UZQ8dUgpK6IFBxdOIjF0b08LaRSyXRm5e4VKKc=;
        fh=cuI8rASHi19EG62agZshEXy34dPlF1a+UPVlXkwNIvk=;
        b=NaqyKl67Rj3H7o0wT8JlPugqCGj2j3iW/TI+BgYZd5Wd/uYOLqsZ/E/BFg7R59IdOJ
         0i4mZBFO50WYoLBl1qi1Qjsb3wiPacwzl6Uo1vRzL8D+lwDe6hbd4izE/Stbm1Tf4MQW
         jClU5gKFNFoY+E3d3nYdzCWzC3Qu0ZJnR98Z34IaR6SkLuijSIdb2f5CEfWCXraBcEVx
         6Mo0RE3UVBH3N5V6lknNl862GoZN2yqrLGXk8iwEFFys3B3Y3S5eAOCBlJm/xCQT1jnY
         yV+ol5embOxh0KQAvPcdl4CTFIt/WQVaWCl547Kosgt5nVeC35Ulr/Vys94++BcwLMLr
         411Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Dm0XyPIs;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472247; x=1758077047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l0Ez4UZQ8dUgpK6IFBxdOIjF0b08LaRSyXRm5e4VKKc=;
        b=k41NkEwVMWFcCEuh+1OmgFb+YUyjDgv1/8NS5PntSWwAYj9vqXWbG38JtYkP5KWOR4
         Lw57scp5h+UKQNsvGSH877p+6NnY627pneXr7Vk5lYGluUhcx3VWSUCvJeJ5zRNAthx3
         C4E/wGWJ6lNdxVYdhMmux2mUYq7a7kPZWXMHDsEWa07ZP2UCc3iVv7Cbvyam8Do/efF2
         o1qXvUETytgrxvOrL7GRzx6UCPEmyNHJcsuSKuoPssmqKfgQ3PN254rEIH51s8vHBHjU
         N39NmwiSSEiPLToywNn4vGZ9Ed36JTEQ7smjeHARwWR3zwxOwMn11wOqLg5/WD4kLfHN
         nfiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472247; x=1758077047; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=l0Ez4UZQ8dUgpK6IFBxdOIjF0b08LaRSyXRm5e4VKKc=;
        b=Ja5FqKVqgucWotOpI9Sc4MFAy0UhugjItJxWBAT8i2N6hbN6ueXolJtXTBC1+fqVqK
         FRO7JOpah7oSDUUtl99iUjdy/telTzWu7hy2TcZzeoJZlEEWwajRqytXmU28/nCL0IVJ
         nq3b6g9Rpx1wLh0aX5sNcAYhgKRDZFBBlsnO67kkoEaQFLrT19Jl5iVU738yZkML0AJz
         JHkMj1y3Q7TF2h+0wUBuxmoPQtzfxHuT9KFNmr+DVEVvdGOX+/7grEV4GyamN/UGOFbB
         ITNQ71S9GOUlPKYh2qXdNqw7Or162jLIf1o+60us5f/ZnBsgsmcaKI+A8OXTKdTTevBU
         Rd2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472247; x=1758077047;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l0Ez4UZQ8dUgpK6IFBxdOIjF0b08LaRSyXRm5e4VKKc=;
        b=eUKwS9dA0W0TqBU5JrK/qCxNKYk82vWtGJatfbRkaE2wmgdwULBJD71JoaO7/6x9ig
         YtleLGBKFRpNFxtWcJuiS4w/fKMqAsqG9CdoHkixiZsBGPmG4ei88xiS4P/cVL43lgYI
         o/tCh9lVT4vPeOAgxQfqjg8HQblc9zwWT5id8nRDCFbHRx8bgFf8leTlVP6GqxBKhJAP
         TIQY30y4bctbEC6WAqS6b+0fPThM3Sk/aFvsZP0TWzk0zkDahfz9/qPFFI+M+l4rUTOz
         rf+rd7yMDeHg6PMSvaclrVAbHJUO8W7adskL2WLqdw2pp6Mbt8cNQI0a77aVB4xQd+bS
         xR0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3couPmhLuJ/9OyhwE0HiUqRYOf8RmCpOKhk8Uuhaq8hxnvDdF46oAeFEcKqJVN1pPhuNCgQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJ2Ahl+fyqaQQ0/tiLGWEvX1SXeCGmTkAB6uMFwO9agDkoEZc+
	2wB2fo9Ov1u8cyj1/cYgFpsChOBLGE08eg8yO5sis+JefMpKNsn86Ow/
X-Google-Smtp-Source: AGHT+IGWMyPRaroCh9btAv5XDjsN+OtInXbmhrJ9wrmboxtwWY8ZFzmJELLWQIMdbRup10KiLBgSbw==
X-Received: by 2002:a05:6870:e391:b0:2ea:1e55:a596 with SMTP id 586e51a60fabf-322644fb5cemr6380786fac.30.1757472247442;
        Tue, 09 Sep 2025 19:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5kswC6i225JDyEyF4kRhpTZreti3neNzOhGdT6ZY4C0w==
Received: by 2002:a05:6871:ea87:b0:30b:d6e4:3de6 with SMTP id
 586e51a60fabf-321270448d8ls3215011fac.2.-pod-prod-01-us; Tue, 09 Sep 2025
 19:44:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnhVnamluyhCIqng9Phr9hmZ3YnZgal4VlpdZTIq7uitr00hL+ZexUwjzMeKgHVLqO1+Psy/KGn2E=@googlegroups.com
X-Received: by 2002:a05:6808:1b10:b0:439:ba45:96b1 with SMTP id 5614622812f47-43b29a12c03mr6888383b6e.11.1757472246407;
        Tue, 09 Sep 2025 19:44:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472246; cv=none;
        d=google.com; s=arc-20240605;
        b=B+R9EO3v9ev2e/ONvtLUO5bfF8AePw0634xe8bllKXmQwnSqpUScfsrISuss7T75+6
         ZjLyvSGTCQCfVDRCeyO07qgpNEnDLo5iuWWzhU+tGrYHD9G6W9ibVym6UymoToh0iv3j
         knYXSWAm64bDYtPAN6IHmLyOr2A8EKXfCW0BEcU8Q/Bw9/HXQEG/Nn529viJ6O8RQBgF
         DPBGEHTvJSiJ57RBu91xrw4jRj22/+es10u5794hscT5Ii6peWz49JWGQ4/CMdx6RKX1
         gpWTVpL7BT7QFT6YDGv5sk1Y3q1X5FOiRvpFnXO9/hW2UrA8GzVnvVngTIP43O+n1Xlx
         A0LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BATnrPttTGOeKRCCT0K3V4HzIU9KTE8stAVBRczt2LY=;
        fh=pRTSNP2NIWqo0UuEsWZsPT8HaJrQmPEQsczeVK9i780=;
        b=SuqRoMc5gb67MRsuLZEqhHByMzLtLR53bLZk8GjVixy8qY2OW8G/gNq8n8YFbOooed
         pXPZP+LdP5C18Zv2u3SViM9M/mtS/r2KXcSLsH6An1HLL7VmdcugYOXYgjUvAxzA9M6H
         xaPGbp57QjLj6sxyIQQfPpgHlQRQ6sGqTiBEO1Kl62a5WCTu/cuAbJWq2GSXynajThxA
         MzIAPDLNx2IjQT+PjQ7K1Y38PXAdNL1wkY48qlNdhh/oE3GZ2aocQcpxURh2Mrh/Flvs
         PZlult2FNSSin2r+zeZF1WxAEYV01PLllaquCEkubGHgTOmRg77rwajLteBd+ZcTxits
         kZsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Dm0XyPIs;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43a81beb9d7si338010b6e.5.2025.09.09.19.44.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-32b6132e51dso4848309a91.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVfiglPl7rzcy2Yqd/mgsE3huOZpSu859zcxZxziTKOxXCFvALnTk2+X5aZ3yWS9YSivjS+BulKK94=@googlegroups.com
X-Gm-Gg: ASbGncuHY8Xgg5mlVF31bX4R3WLHEHZh0jURX2V+X09yx+8tog6ZLsPvKk6kxWN7Fpe
	fHPMJu7MGMvDvjOiDVfEa79pKRVVEt1GE2Jv2aZmcAwdVY0qc0omLHCBOn6USF5Gw6rbSzAz3HE
	VJB3ZqFYyeEy+hgNJg8vNIA1NUSMgeJGMTdpNHZeGwYgTOri1cK6s4UEcxE2FJ+D7DZi48FB4Do
	dM7uvhWt+Fujvqc8VwIaN/uphURRnPTH7VYMrdnk2QrF3dUyS0PrXU73FSFCv+CoZxaL8OkngQq
	hC8mgh0TXnAHFhdXECPA9qxLFlDYBsdEgOXC7Nh+qWoO10w89JzhxiEyti3/9918DhzdmSac28N
	C93cddLthyeVzpLRkF45joO+v8ztNVr0brbxVN6PhgzuMkl8=
X-Received: by 2002:a17:90b:1dcb:b0:32b:ca6f:123f with SMTP id 98e67ed59e1d1-32d43ee718dmr16516547a91.5.1757472245395;
        Tue, 09 Sep 2025 19:44:05 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dbb5ef7f2sm621303a91.13.2025.09.09.19.44.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id AD39841BEA9E; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 08/13] Documentation: gpu: Use internal link to kunit
Date: Wed, 10 Sep 2025 09:43:23 +0700
Message-ID: <20250910024328.17911-9-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1173; i=bagasdotme@gmail.com; h=from:subject; bh=WOOeaeuC9/RH4phIV+H+QiLxF/prahARBSHjeoa181M=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnijZrvnhN9eJ1+LvAp2zslcUft9O2uC6e1HKcd4J/ rFLDLiudJSyMIhxMciKKbJMSuRrOr3LSORC+1pHmDmsTCBDGLg4BWAiyg8Y/lmtiNJu8EtVbugK fub0kTH31Gy3pLdrgoTZz7qUXricksHI8GebzZaeM9lhFZ8KFVTdJ9stibqczP1vypfAmIZda2d 1MwIA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Dm0XyPIs;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1031
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

Use internal linking to kunit documentation.

Acked-by: Thomas Zimmermann <tzimmermann@suse.de>
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/gpu/todo.rst | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/Documentation/gpu/todo.rst b/Documentation/gpu/todo.rst
index be8637da3fe950..efe9393f260ae2 100644
--- a/Documentation/gpu/todo.rst
+++ b/Documentation/gpu/todo.rst
@@ -655,9 +655,9 @@ Better Testing
 Add unit tests using the Kernel Unit Testing (KUnit) framework
 --------------------------------------------------------------
 
-The `KUnit <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
-provides a common framework for unit tests within the Linux kernel. Having a
-test suite would allow to identify regressions earlier.
+The :doc:`KUnit </dev-tools/kunit/index>` provides a common framework for unit
+tests within the Linux kernel. Having a test suite would allow to identify
+regressions earlier.
 
 A good candidate for the first unit tests are the format-conversion helpers in
 ``drm_format_helper.c``.
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-9-bagasdotme%40gmail.com.
