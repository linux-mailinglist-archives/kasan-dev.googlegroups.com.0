Return-Path: <kasan-dev+bncBCJ455VFUALBB5NZYXCQMGQEA3LO65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 881E3B3B4CE
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:35 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-61bfb3b3c4dsf686695eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454134; cv=pass;
        d=google.com; s=arc-20240605;
        b=ji8e/BkxLniELuLdhWdylD8QorUeoFIJOWL8NrLahnDEBAamrrzX/S4qX7eEwcL8Yo
         fB5/AsfmcVKVG0Y9zppeLbLgyWmmophARG2vgS5sknWnZkwVcrkgHXDUGME14YQR8CUx
         1bOEvOfl/c+1cVBxFGpm1egLj9gKfGrnBEFA24hGA5GvyCpTuFdLu1Y58p02UzWVsLH8
         Teg2SAVkD/8AieSeYo3C4BbmXqV5DXc5sN9ofPStI8S42BS8FiC7fcoDh8bFAn7sI4al
         gsB67zQj8rkhGCeTt/Y1dS7CcZIFG45fASpYK6glvyHy3WkLNsJ802gf/HoHBBJG4J6K
         ysSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=OWExfE7ACc2RZEdmwszYd2hE5vZ8p4Og0EGj5B6HomY=;
        fh=hdjXavVTur7rMKVmlaIFn9d5NINyzOWvRhOyk1ffe/Q=;
        b=ERcYtNedLjFRtCnHUv9PyEzIroMZbGYsTZmC0PSrYCZ6zAovrLL5LNBI9oRqKSJjMQ
         avt7ARweSD1Jd05PF/4+XxqLTMCdU/pqkc8f13yPyeeX/l6t7NEgGVYvMOeMXWx1qN0C
         4xo/C8t3OhNoGYqtGfm1BUY8P2PWJxnzdrTCreTQJK2UK9TIHlPs1XhMdGFougWS4fPd
         4e3gVfIyQiaqJjcdgAgP8tuMocMWiDfcBc8gu1Q2v6bQJh3luj/w7fOIKv70sSLqI+xI
         hevsBzuJio/sb6dhv3ANbZDihzPFF7ZHBkUBmHj4A7Il0PlmVVpEIGtp3xuHh6uKCmTt
         uSoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WKcaMBm2;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454134; x=1757058934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OWExfE7ACc2RZEdmwszYd2hE5vZ8p4Og0EGj5B6HomY=;
        b=ZmQR2M8azoP4XZBrdYdPFC1Cq5RZAAYYTG84di1C1AatlEmTcBpWz7vuXn00edWjxk
         /+3J30aX7d6yyrwVNWWM0gqxkrTdH66QwnJOmdorR9NKckr+dbTAGpFDIqtEHaphnuT8
         0pubHXOtq/v1tZAkGcyztoX7AfKmAVPplMkE/+xpyJhIOGIyHfH06YSje2Zuxemape2U
         P7C8zySU+n/tMRqFytQyKgAovhcXRgGL6JZz3sW6ISNlXN+jicgTeSqCRk152TUbUWQQ
         3gZoh6llaFrFtzio8XdG00lpWov7fQEmcQHF4jHm4ffB2I1J9Ai9FHGFmSknahuCQXin
         MiVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454134; x=1757058934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=OWExfE7ACc2RZEdmwszYd2hE5vZ8p4Og0EGj5B6HomY=;
        b=mNKo1QLktMW6ncDYDTl631wUyjKaJqIEZGsJFZJUbQiYJyRaUX4zjmDDVcnXIpHcQa
         QljCMq0UBkAlIrLTG8+7ixcfxaBA33DkOj/ablRhK5iDzaTmrsvKU0QGbu+5idqTRQQo
         hxKl1gfhWOlM/8YvfLZ7m1YTwl+8CJV5RRO63HeYm4OolngbUmJ+Nra9nu8RiBOMQdU+
         SqJHE/dk7pg3vIofxKC6RTOx+fj47XlhwEyzJc9cw2Lx7I/lFfl0hmCyltNmga9E3kPK
         Yi3RHBHyIo3KhHF01MuJVKFscHo+N/cFBlbcIrHwbLmQdCTKuAq1/ikJJD2CrYTVgCAu
         W+nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454134; x=1757058934;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OWExfE7ACc2RZEdmwszYd2hE5vZ8p4Og0EGj5B6HomY=;
        b=oFVyfyEcpktjRQfdhhdVDPs3dnHc+8+8lw7UV/JcjDdWHLfhllsqQsXwj2xvReMuTi
         KteqedboVX9S/nAuXNiLrh4X3AkV07nZfHqS3aAy7qRVj7l9A+qhKyctSNkkSGUctvy/
         sriAnh+WdW1B3sMb/iPxi5hD8RlmQD9LdiqTbOOxtNBS87/+SCBY+TU1p0T0gpBT5DjW
         y4+RqcfEM8l1g/5lrLJEtYFdk27p4J6HtZOaV/fZqyf0p5igephWSbkFHWtr67CDSbM7
         v5iy0cE00GuQqy4vFlC8XQ3UB/FPpZ3V61SYJHIvajRlasyoHJqrfstfBjntHN4D6r/J
         Ccvw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGR0pCQEouiivZIwhIPufy97Oor/vYzlxQ1RFgLD1Ixx106Na/efzkDlKSRQlT0KtNC6tH5w==@lfdr.de
X-Gm-Message-State: AOJu0YwyC+w0cZa3v4dlRYoO8beLb2RA1qmfHtXVFcXfB/kv84Bmb2PL
	ewUaiTVU7LeElFNhgtWJ/cldyTFnJVdhgV0GfLPD9IaNE1rWjyL9F/Mw
X-Google-Smtp-Source: AGHT+IF7R2cjckRoI4XvCjK5bjLdt/9Ql6iUU3b13rNV564cVPiNL4uOCd78/ba7QZLbtakLGKH0ng==
X-Received: by 2002:a05:6820:1c9f:b0:61e:1ad6:133a with SMTP id 006d021491bc7-61e1ad6490bmr2148021eaf.4.1756454133985;
        Fri, 29 Aug 2025 00:55:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe+6vB0ThA/0KG5gWT5vx7lUgD5lCtyRyJ2ToIP+xNy/g==
Received: by 2002:a05:6820:a082:b0:61b:fff7:a291 with SMTP id
 006d021491bc7-61e124f7591ls500013eaf.0.-pod-prod-05-us; Fri, 29 Aug 2025
 00:55:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXM+87iQX3F0zHdqgrsKZ7PQPteDc3FnJqbqhIqIQYSMlSQzo/o+C79LgWZNVTVmrv7ilKE8tO/uoU=@googlegroups.com
X-Received: by 2002:a05:6808:a611:20b0:437:9427:125f with SMTP id 5614622812f47-43794271be0mr8494296b6e.14.1756454133257;
        Fri, 29 Aug 2025 00:55:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454133; cv=none;
        d=google.com; s=arc-20240605;
        b=O2lc7LSzmiMCjSjPXHkL3qOdXElQp678iNbt/oCpiX+iNk3NAlU6rcH4NxmyOGDDJn
         O9KOlgpYodbzEoMCIAqaGo6AUp0OkYP8DGh8DLKVd6l6gQA72IZ7BLDu8577Ah+rJGTp
         sSygIQKeULfCxP2nxxaXATse1hRQ5ePti8pMXda3VEKYPaYcdR0bbetT9ArMRNzBvvDh
         zueNWPvxqEY3SIxDKifi/saR/9DmZoWEHP4w5q1ZvsRulfh1P06Iv1xz3pzL3hPA1hFJ
         7UyVXPJCWhiA68IlE2LfQfP0PFyrGo5xd3kZGtQozZW2G58a91JE1zJL5Wp2Uhr3/ujq
         doLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GkZ2LL+fO6oH27E7YsqUKpWK9h0JvMFOl/W1FWHyGxk=;
        fh=Hy62y0ud+EMzniPmTvW3RrvCFKH0/42n/R4IMmylWrk=;
        b=Vb2Wr7bL7WhQ/2392Cto+GoPpfRI9ewpPnGlLKz4CZlbIw63/Hj+JZwg04M2DiP1Oc
         nyHzM9bBHHZKCHPm/DHw0jwDUllm6dUdNxEzQ6khCT4U1taAhSuz0oRKml5/QFdWiBwv
         Okt4yDjCw0q41tyATpwbMDTCIDqW+QFgz/E34sicYM+Q9Xb6fCXxceVdulbN80oKyMLo
         J6CIvI7jE+IYswfqMCxbAtbXTHkzbWFfVbXeplXNHN8CRl35i5EuYkPBo1w0FcuijDRd
         s2oUVfqDnkqYM5ctqUC4EhB4wG8Tyhnoh040r2PoV/Ds//Ia9VUDUak1duzja1okq3nu
         4SKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WKcaMBm2;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437e8c6ac06si56740b6e.5.2025.08.29.00.55.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7720f23123dso1815537b3a.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMxTTcoHpoVYStAHVoFObrTJQPcjeW2gKaYok8McL/Nd//YPeO4yYiaiyA56c5ZPJBDzBaokx/9tc=@googlegroups.com
X-Gm-Gg: ASbGncskruYcBU70HClvSQOzJ3cKAgXebIWZGLSFt1TyOYzGjGuBKveGpo54sKUu3kD
	iiPajYUAVuJeH9R8IaZ9ATJiDVUlKJAtSpK2MMdozlamGbJd4XHUTqa0CmQeJP8i1pQiguEPtIo
	6wZYXbIDDNvJZLhtOVvuPKRgX5InL1aZfgiA12S4eh/B7lVvgVfhljX9BvhyyA3p7KZL3Ce26LJ
	ieULRVeI+rlqyIYVC/c8DKR2sbO+CvXYYH7G1Zs6sX38lyycV6yvOO77fugZ3WUZKObnv3J3VjZ
	467BUcbD3sC0iI+RVfncLL4juQwVh451wdDWFIA4pQYggq4baJKkUCX3w2ady9x/HqFFA3weIT4
	qb/C5YHKYlKYj5uhC1scM2REj2jfb6KZvI87f
X-Received: by 2002:a05:6a20:938c:b0:243:b839:8282 with SMTP id adf61e73a8af0-243b83984a8mr5923510637.54.1756454132557;
        Fri, 29 Aug 2025 00:55:32 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b4cd0164c38sm1447923a12.10.2025.08.29.00.55.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:31 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id EF6DE4444CA3; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
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
Subject: [PATCH 02/14] Documentation: damon: reclaim: Convert "Free Page Reporting" citation link
Date: Fri, 29 Aug 2025 14:55:12 +0700
Message-ID: <20250829075524.45635-3-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=839; i=bagasdotme@gmail.com; h=from:subject; bh=br/gH56HVzhrfYYqrTP3c/xceN5BBvTsvI3pBYQ/yVo=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY14UOzeckV2lWTlnxluBwiWvpt1jF+xvT61/ejpwa tSzw60XO0pZGMS4GGTFFFkmJfI1nd5lJHKhfa0jzBxWJpAhDFycAjAR0x5GhlnvrvsFdd3e6TjZ g2FTa8uK3U48C+++2yu+oPH13XO8khKMDP0RbvPq2Hk2WQbMuFkV7P77fsRatst+E/e4qhe89eI LYAcA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WKcaMBm2;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-3-bagasdotme%40gmail.com.
