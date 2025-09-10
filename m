Return-Path: <kasan-dev+bncBCJ455VFUALBB3GLQPDAMGQEET3HJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C37CB50B37
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:43:58 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-7296c012f86sf130332876d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472237; cv=pass;
        d=google.com; s=arc-20240605;
        b=R/NF3MglDIKvjwnadWonWKFEUYT6n7YqcgxuuRGmRvv2iFvF4bVn2eGAJpm75soqBv
         C1jMsXsCey2vBMbiBa1y/Inf03Jt4HkM9hVPT4Ec3G/+0t3rZ2BR7Od96aLk+fjJbCc8
         SRUjNrxAOFfsd5cIOl7Dv5MHwYRLcXfu/ChITm6nHEfnLpCUvtczFVS/sVL3HJV2J+YT
         R9PFVC+nJPiig6+5bHH3gufpxfGBiMpVidA2V0E7usHWDrAGIVT7RKyE2k/ElgDQ6lFC
         0SxUuPDUD6qNRwoXF4ukhYVeqzlh/e1NVfBowjJUH7BbX34ZCV5SAHvujqzByYMmBtSE
         HLxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Hl25n27VzBax4Lrgrfr9ywh6dYJakwYAuXgYWmUlYO0=;
        fh=xI38x4f1hOSbXQg3QJboETbHmPBBo1f/J3rBHO2YrL4=;
        b=jzn7vPu2gg06DZAGmVOsfLHxk+YbwEgNgXwWtE5kJhSLeB56IUlhYiwEBr1QJIIDC2
         faPq+iMFZ5sippn3wFRJVw85HC8tO2XqCBG1feqmIOW+uKf1gypUUv3ol7Q7hSWrbZE4
         yAdHWNeTksat5/QEm+jsTBzIjmx3DUTHDUFxhM3/0vRk7DejxtaRLG+ig9cX8GrdWgIS
         zM9CYk57hgyCu+/YX9KfD3k+jgDyhYyeaRwWtSwOgWCjxzgpCAFvn7VcBrz2pDMM4TAa
         BKQ1sKIkBYxxr3kr5m1xnQ6+EszNj/K5aSpuUQ+Pk30aq+PrvY5wundSC8kBsG9eH3oZ
         75Ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NHCeLh60;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472237; x=1758077037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hl25n27VzBax4Lrgrfr9ywh6dYJakwYAuXgYWmUlYO0=;
        b=wMzvrJuqrfk6/1YTmcYIMoLw5ZaEr3r22v27rbhSUKfeNWrp/YRU5dOAqSQEJzzWUZ
         3D7Jy9Inws0DPGz5Mi0XH6HztmdjjcVxSyLnhcJgPnxs4nE2RlHKsVM/SLRJ6U6Es35X
         x5wGtGA500ruJbXl61G8BwmejPWvb7frwLpFsaU5tsxIpmWUYb+IOz8usw2Zc2fruun5
         Ha8O7t7al4elMer7+P5G4mff2iTGhHVePTv3iHFkqC0zIcMODNHzxCguQXZ0IE7ng13y
         WGwDvz5TRd7DU4J/ijavOsXNKshGF/RTdt4taoWjyZqqD3oYBOL0g4rfYTku0x4I5rdI
         vi/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472237; x=1758077037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Hl25n27VzBax4Lrgrfr9ywh6dYJakwYAuXgYWmUlYO0=;
        b=njTEiuNhK2sTr3uh0rpoTiN/hBwUBulWpPiZcGptKjsbvuYJwZVmBUz4mj4s3Pqt3e
         +s3uJyv/AUtZQKA74sCbxfp0TrcNF02IyVU/mk/D7/CIlyAn9Tm669lSQrU5Jjh4JIwO
         Aj343t1vYagU6DoBsd3gXgrdvjIZr7IKb/ITNqRA9iMkm/SE2y6lQfS7Xw1wnohjt88P
         0QRVArV2MzBKJLp9ShlGO0AVsANGZTLD09BvlKWRiksC4Zf/z4R6YqfSIisttDvZjhhr
         I/Hq7Vvl5LBj+1R0HSvV3nNW33WhziT53TJ7hWd8dAkpzU4yw7aDgw8S7HIiIIsjm1E8
         CYUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472237; x=1758077037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hl25n27VzBax4Lrgrfr9ywh6dYJakwYAuXgYWmUlYO0=;
        b=ARK0hTPQZmv3feRSci2H6HjQPSF3+5jy8wiS6GUcN5Vk6At60OzSrwLnbyuZHQriEd
         tC7VP1LiVU6Mv+3ouJCIpNJxlzxvIvV9Ty9lh5w2xUn4ZI1gxLGCP2QBBhJ94dV/m/IA
         l8IUFXJWksg6Bu1LgCxdZDcUhoVtCGDLz0hvJAIi3jv7vrabS2a8Ycr01Kv4QXBpwpvE
         xrd4LMoBHvG9D+3yxzMtT+jwRQ7MdiAnFMCI0WNFYZpiQ1KxBNz4pyPNZDevsMlCqbDL
         uBZBsHU5664Wfy2jo13yZTWzxB6bPe5/0U4CkGOilBmVXAOKdefhkoMFYVfg7UVXobCy
         blsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4+N3/9fTgd38q7CDR5q0Tln0XdR5Jc9B0OtDdygWfJloYiV5pv5rl2LktznFjhgdAc6/kSQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz3cQ/32KdcQqrfDZYZf0A5WoijFl0oNlFdNVED/UOE0PYPupVO
	wXMUtOm5b5Hs7zpmQF1FSbnWL53ucfh3NNV8m/6a6oNCKFlxZy5xPDnL
X-Google-Smtp-Source: AGHT+IF0XCAwlk7lv9yM6o/NkOLrt7MIFUFts2mxtTs1oZL6phN3iyOmUFjS7cYk7/oenlYXxjyxnA==
X-Received: by 2002:ad4:5961:0:b0:726:e744:8dc5 with SMTP id 6a1803df08f44-7393950ea34mr134826486d6.32.1757472237082;
        Tue, 09 Sep 2025 19:43:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7C3jMA2U7XWlXu32EbSfU8fNvOr0Fe50yEK/atapns0g==
Received: by 2002:a05:6214:ac8:b0:709:ad61:71b0 with SMTP id
 6a1803df08f44-72d3c128912ls78573246d6.1.-pod-prod-02-us; Tue, 09 Sep 2025
 19:43:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbmoBYYtKiZgqkIYfKxK7AV2lh3IuuapxCwBsaH5Ut+bu88mrQQjbYIcqQpt+VWFxV4FAufLxR83Q=@googlegroups.com
X-Received: by 2002:a05:6102:f83:b0:524:b9b7:af01 with SMTP id ada2fe7eead31-53d1c3d6e5cmr4659558137.10.1757472235934;
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472235; cv=none;
        d=google.com; s=arc-20240605;
        b=ld/Z8bmmY+0Bgsv1PsjOIrOHaTclOfAVWB3Klqm8baK7r4jMGh4fweON/YRlKfDhbS
         PfZQsGWii0enIYbN9QjwKRvNol6XdbhBJoq6zjR/3iffgsg7OoeDAfmcUh4ls+2PT1sp
         g56RsqpRzncnKLj8RD7CsT3tSWaAhWTJQWgUKEmejQFXGDFLJ4NTqP5TqK95+nDr6Djo
         ECj3X0nrqWgq05uiJX+/rWM9XyuFPUyrA4NdSk2VXVsVbwofnzPMJcWg56IjV+Emy+E1
         L+woAN/rM3SOxQ9VhAdrNtevPNbzQpJM1tupmY0S9OsjrSnSVWzhoYmi7FHz8shvZWCi
         feLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PKHUedwTpnE+6902OLKWJUrKeeyE0icmaP4M6h8VeIM=;
        fh=6KZw60hYW7eM0go3/wWwGv0pp3u7Rz4mlz26KegFBQU=;
        b=aUs2JlE005rn5DNd5sRPkTFV5iwLfIJEjSOwVSbE3cOdXNnyesUXRIyEQXPbAB4Y5K
         EV6RgKdKkTRAXT5m1Cz3CVPv6HQc3Zn7k43ffAti75y0ASc8ZDR1x7W5teoo5h5etxkI
         gfHYPuoIy0TW1QVpPBwk55NDHA448bHHfGidkvdlJ+ajQtlO+na/CAnbKtICuHXsVOVy
         wuz/6vP6DvPPvtZ7AjP4jPm0lFVIYpuUxGOctEYVobjKGbsA8i8ZL0yGvPoHLN1E4Vuu
         ouJkLE9S8CsUkF3+uE+bINoZpWX9fWQPxlBsGG75UAe88IMh/7fJqCKPolsiRr/wX6UE
         1T6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NHCeLh60;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943b821ea3si1100025241.1.2025.09.09.19.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-77287fb79d3so5007746b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXTjQIM6wUXwMsCGjlgZ2rRYaSLY5jjP7KoOum7HppDNKrUoa7iho9P9lR+48R7kYCVHT23Zu71G8c=@googlegroups.com
X-Gm-Gg: ASbGnctPv5IU0vl5eF0rcypO0DvrgPTmUIpJVav7ek5WND+JdwsyEmp9cD/uv4XAylX
	MPJImO2JgMat9Br8I8ancFxIxITsdi1fIdbW01L/6+PqH5+TpwQw2jAaMOJQ7Nyub66LKM1rWJl
	9YNicum1tNPBvnw1cqO019+J0RHLXYGFwqp+/zknDC+1c10tCq3mM6BduTl2njzOt7nm1uyAEH4
	t8ztnWViZkm/wha6Bd6kxR9ksO1qAahW+KWiMncGhY6XR1cnxscO2Zv2rhRMdMkHsbBuYa/mSIO
	9fFyVU0KRyabxcZzsc0VQTZvI1wVzIoHTdmteZzu+ISTNJa+yXr81e1uZFoHe1Ff3EMzXM5Dizq
	f528dOuN0Fc8nRSvJJkqXsN4x8gB4j37GECKl
X-Received: by 2002:a05:6a00:148a:b0:772:10e0:dc41 with SMTP id d2e1a72fcca58-7742dddc23cmr17652030b3a.15.1757472235226;
        Tue, 09 Sep 2025 19:43:55 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77466293765sm3395798b3a.47.2025.09.09.19.43.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:53 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id E4226420A809; Wed, 10 Sep 2025 09:43:51 +0700 (WIB)
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
Subject: [PATCH v2 01/13] Documentation: hw-vuln: l1tf: Convert kernel docs external links
Date: Wed, 10 Sep 2025 09:43:16 +0700
Message-ID: <20250910024328.17911-2-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1333; i=bagasdotme@gmail.com; h=from:subject; bh=oQ/U51BIIgNGsRun+kwInz/tmig5xTqHruGeEvNRxQQ=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnig6a/JZLY81M41OfrJ5W/1jtyyro8lZM99fCflwN Zg5yrW3o5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABOplmZkWLE7pDLv7RVG0Wlf H5ewasZymzr2NV7tNPkiErzi6eK/vxgZzoS7uJzLvPvRJPIa/z7RCs5jTcdeb3Q8EmZgt2n66RO ZTAA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NHCeLh60;       spf=pass
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

Convert external links to kernel docs to use internal cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/hw-vuln/l1tf.rst | 9 +++------
 1 file changed, 3 insertions(+), 6 deletions(-)

diff --git a/Documentation/admin-guide/hw-vuln/l1tf.rst b/Documentation/admin-guide/hw-vuln/l1tf.rst
index 3eeeb488d95527..60bfabbf0b6e2d 100644
--- a/Documentation/admin-guide/hw-vuln/l1tf.rst
+++ b/Documentation/admin-guide/hw-vuln/l1tf.rst
@@ -239,9 +239,8 @@ Guest mitigation mechanisms
    scenarios.
 
    For further information about confining guests to a single or to a group
-   of cores consult the cpusets documentation:
-
-   https://www.kernel.org/doc/Documentation/admin-guide/cgroup-v1/cpusets.rst
+   of cores consult the :doc:`cgroup cpusets documentation
+   <../cgroup-v1/cpusets>`.
 
 .. _interrupt_isolation:
 
@@ -266,9 +265,7 @@ Guest mitigation mechanisms
 
    Interrupt affinity can be controlled by the administrator via the
    /proc/irq/$NR/smp_affinity[_list] files. Limited documentation is
-   available at:
-
-   https://www.kernel.org/doc/Documentation/core-api/irq/irq-affinity.rst
+   available at Documentation/core-api/irq/irq-affinity.rst.
 
 .. _smt_control:
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-2-bagasdotme%40gmail.com.
