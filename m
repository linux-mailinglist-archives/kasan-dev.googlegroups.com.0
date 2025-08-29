Return-Path: <kasan-dev+bncBCJ455VFUALBBM55YXCQMGQEWUK63YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDCFBB3B54D
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 10:03:01 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61e1f76edb3sf647154eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 01:03:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454580; cv=pass;
        d=google.com; s=arc-20240605;
        b=GTvnisnldZ5wIV9nP4JKMfKl4vf5k9ufgKo0bjQBkJa9DSoBzsIXqD0jI/MJ2WUtdW
         gP6xBe9kp7fZEum+jCNuna0zszK/KT+3R7NK+KeR5T5a3dusF06UkAWyh3KAhNHUaj3I
         o3AGmNQ4ZA/VvAG0Q+RuLTYL0oprJROQ19M0NYbpcSQNxvhgpbx5Lw5B3eic5d4l3xff
         HxVojDgL6VCuXL+zbLL12NSzRbhS8pFDvyFqw4E9lb7c1zKOIFjKesAHBN30bxyr4U9E
         3IGyRIy06lvTgLQ8K8/21L02K8VeuKyUqcT4j9SvZOCEsejYZkQy8J//iV9bPgeyQ8Kh
         x52g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Ynvg9i5E/Eu3T0yuOSKaPhMSI9VX3hQ6sSx3ZGl5pKo=;
        fh=huTmL2iS+xo18NlIrAWQnASWRXDnsU4JCt+Yk886DxU=;
        b=IVlUPFX2cN+2fhzLrtWWq/UdGTLoCuULl8DnQS5XU8901MLK5r5yrsUbSi/bCqJUWg
         4GO5Ev0a3AdoiEIFgAXwnk64x+lrXj25QyXrYcwck4QU5RH+L3mllj39ozAeEjoPjymY
         JB2mQ/JaMBpN/VEXtSdC3uFKuo6AP6uDJHiBd7rHE+/MJOOEm0uQxxrFu0IzsHkhjsMs
         4q0JBvYLQDPppQ5Xl8QNDWvuO/dLDOI6aEHk3yYmNd1GDPcyZJq4jvxfzqkNlMiH/R2l
         z6j1wg/eYNlCfjd6eqT73QhTOOew9JLDrdLvkrDXStaQz7+JVW6vGLy8nFOe+6Ftd2Tx
         bKYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsBgdp2p;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454580; x=1757059380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ynvg9i5E/Eu3T0yuOSKaPhMSI9VX3hQ6sSx3ZGl5pKo=;
        b=rl7CbilLg3f1/RZlEfq03UFT6LBN+9jKHuq0W4+m/b0hQW75qDPm8mbjUqIDfiVJtk
         4x2Km2tlXzXM95pAjIFd5raEjDS9j77ggPwhS0cFGNHMG+mo5HOA05R4lDV3KOODUg28
         eYHebzAwXLl4RW/v0Yn2/G+F5CyMFDzl6nopA6zqId3GQEvjE2v9AeDKa6IXnyVVhNjC
         mCn+XEZdqGp1R+njFZQrMoK8Cc8RuB0ADNEcEtolNY1JtLk9EyxNY6B0hD/yYx/5l014
         f0WiT6ZWXAs5gaE4BMctvKJT9bc7u8Qkzrm9x564D0jC0jAgwXbOculup5A1eeqlM/aL
         RUQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454580; x=1757059380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Ynvg9i5E/Eu3T0yuOSKaPhMSI9VX3hQ6sSx3ZGl5pKo=;
        b=HAVvZeMRT8wgpAocEXDrJr0jQFrqnS7eIQ456cdhv0aLjGtKiWwD7xOXEUEFwd3+LZ
         2ZACFYFa8fDaBf7RHaGS2Bw7A9M7odjuFCWLlWB3U5l88eI55TwkmPS1z2dBho90n6bp
         +CDCg1cN6P9wzpNsmOff5nPcxiGKdk01Q6PmqtZigOphUG+yhba/87itZcr5RmC/ERE8
         fS0StmPOprpM2bcSG2m1x1bzgBSVNfbdLF0tEX8dem4PIkbJ54qHAslSINpogLVQeUA+
         IehzzBSteeVgcei2B9pg/M1ZinBHqc+VTCHFWPpci3QOYQeEDWr0Z8FAHM+TpJQP8G6v
         y3zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454580; x=1757059380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ynvg9i5E/Eu3T0yuOSKaPhMSI9VX3hQ6sSx3ZGl5pKo=;
        b=DBzVZ3dtxhHUPaRPl1AMaSAK5hpePgtfSTHAWnQkmom5S8KUxoj/gkGsAvrMhymkWv
         QkYG0DNstv3nOPd/5gqDGTt599HQ9XMjFKozUY9cPo1E0vqA8kCqXuAgfVLHX8hRRfak
         zQeyHUHejzAij+RN3lTEbOK0EgwWDSz+DWHQZudNh/eRuFN2vJ8tYNPWP0kCt3WyPaX8
         8UEQw0BpSnXSmVyB1BIj6a6GjVCbGjpLG+7sY84c0cdXWIIVkvHYpMbj681U5UdFpr/U
         E24T4Ldf/2pVwwRGNqcFFRZdiC8A9N833sBoN2+Wx0lXM3L7h7YJNOis163wxgFcChph
         vdog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/PiVmnane3BH7H2Wj5Cl0T1Hg49RiFrRVJYA/qvqv2B+6FJLGlRH7f/at2AiTQyvhhax7ww==@lfdr.de
X-Gm-Message-State: AOJu0Yw5w6HYSMazn4QbmmYW0K+LY9JzAuTuggMYjDZ3vDjRWRdgnTS6
	4JaY+ka7Kl3JisuX/JI6zuHjaPqppzXfd7xeaOG75fMKSmKGGx4exa2n
X-Google-Smtp-Source: AGHT+IHx/P+n5Dzj4ntN2mPFWmwVFDc4iVSui8EmpM8Fjs5B1d65aoQamkzxVG9mwi1Z6iuvFEsBzA==
X-Received: by 2002:a05:6870:9f88:b0:315:c161:f175 with SMTP id 586e51a60fabf-315c161f3b7mr83524fac.12.1756454580045;
        Fri, 29 Aug 2025 01:03:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcSVMjCbqvmc6bw+XoBiT0E+19MrTrLtPieKC3Gz1v09A==
Received: by 2002:a05:6871:4396:b0:30b:8494:7c57 with SMTP id
 586e51a60fabf-3159603da1els840349fac.2.-pod-prod-09-us; Fri, 29 Aug 2025
 01:02:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3SimwBMGHw1EYZglIP6PxWdYm9iKTJf1wLsIv6eSnrqvnx1torNPN3J45tMhgf0bAzfZBuBYWPmk=@googlegroups.com
X-Received: by 2002:a05:6870:aa08:b0:30b:ca29:cf8d with SMTP id 586e51a60fabf-314dced5eacmr13432726fac.35.1756454579228;
        Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454579; cv=none;
        d=google.com; s=arc-20240605;
        b=lxWmjG32+YK+gzXKGYRVSrYWxmLyezIpMQotG8geC7C6uek/ACJKf8A9fPkeXki+8A
         WBbYCHzQWCC6vd8x9s5evCSEc6ij4nTqf+RzgHLPgP2sXxJ61qmMYsl/Ow7YjW6w2Odb
         3bElw5pvullUrYeSKIWxn257f3zMnRXyBzKhoIvXRgV/u+fuVpOlT19w7TsQSNBpExGo
         YAvzNWXjB2MHHN2bD3EkAD2t93ndC0C0HHpQE0SrCKBWkbb14eUxvVeGuWrypvV7H/Qr
         kpq+iVxoM/KNtAdKQTvTh0o9RXYz66FYMCkoeUdFU4A/Muuucjgw9cg2g2sXf7+fGbsP
         LnEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0AfZlK+2PpvnkbeUUWLESRnsPEd9fz1tduXIyE8HjWg=;
        fh=opnY9W5yggZGizutBbVNLRNTCLBfnaj1gO+bGEbi9OY=;
        b=UDDPBKwyqTRXhRyGO9yf/8PP6Qm0UzBJIWOmVxaQ5KsM2SgEgSCzPw0uyxEXQSyZmF
         4c90GxWH0TuwVj5fgmoeeXVCm1BkXS2V/3D23dTPYkSNv2toTHfor3rRAFv0684zGVza
         NRUd+0Tl9cTqT0IYvFSQQKxPtsWFMaMQ0L4UIYxOOnhqIjzzsQ6b+ZeMSr4UP6ZVM7gF
         T0FxpWXxfE8P3c7iAeFpbFG3qh+W+8QBEJGogt7G5DKOp+RBybkY9JOiL89zKNpXO1Nh
         vfPAIH6G9Hc9aubOfrjDsxcY1GgZ8DfzmxG+i75phU7AnGkVySnzY7OsfidPFLaLUK33
         23Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OsBgdp2p;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745582b708dsi68894a34.1.2025.08.29.01.02.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-24457fe9704so19526055ad.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUxAleYU2ETqd0Akb0t3AvzFVgL99vyQ/nR9QNUkXSZYtrvR6JM84rhJ5XrbPaVroAJJKwMwW7hNJY=@googlegroups.com
X-Gm-Gg: ASbGncss6rhyMJ2wiEXhM2kygbb8DRUsQJ17AhqrPYET2QBHx0ySVUfev+1aaNyCW85
	B9+VJdSl7XG+uKAU8rINr8BUkoOFjEmCG3z4MdxMTdqtBdjuJsDuV5EsL65PMgXmurOQjjfwLfM
	XYDJx8Ye5sxJhCamcjKCd3pxynsn97D0VmNoWy89ZmkjPCvQxNK5a1wlllSll9RRwnKOdLa0oUo
	ZAysxX8BCOFI+gRKX9ULuuL77mSpbrRK7UmGH8I6GUm23NTaCHomJswrOqRgB6qT5BQ8hu6fWFm
	S7VCenq1ZzE1aWMcy+2vJNQ7/LdBjvK3f1L8kjoS/p6HcFYyxIVt6LuKNWE21Gk5b1tIsJ1ULSK
	jgJUyeJlOS67CPKSB05pmM2iGWMZ16HgiwDIP
X-Received: by 2002:a17:903:38cd:b0:240:3c0e:e8c3 with SMTP id d9443c01a7336-2462ef8580emr326320245ad.51.1756454578299;
        Fri, 29 Aug 2025 01:02:58 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-249067d9a42sm16769725ad.147.2025.08.29.01.02.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 01:02:57 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 08D794489F50; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 11/14] Documentation: net: Convert external kernel networking docs
Date: Fri, 29 Aug 2025 14:55:21 +0700
Message-ID: <20250829075524.45635-12-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4099; i=bagasdotme@gmail.com; h=from:subject; bh=eMX/Qh24hdl/D8upWlphNzasCNRD/YCgXxsSIbz5MxY=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY16d1mKOz99m1qX25ldgn5beybqta3f6vFwaVK3P9 qU9Ts6io5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABP5Y8vIsLj5nquL3YaGH+H5 K1M/GSvVfagoWJf+Wf//FmmeVbsWnGJk2HnZqfzd057r3t1TvvSsKTBp/5q8NJD5d+PrUJ8N/JZ PmQE=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OsBgdp2p;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b
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

Convert cross-references to kernel networking docs that use external
links into internal ones.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 .../device_drivers/can/ctu/ctucanfd-driver.rst       |  3 +--
 .../device_drivers/ethernet/amazon/ena.rst           |  4 ++--
 Documentation/networking/ethtool-netlink.rst         |  3 +--
 Documentation/networking/snmp_counter.rst            | 12 +++++-------
 4 files changed, 9 insertions(+), 13 deletions(-)

diff --git a/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst b/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
index 1661d13174d5b8..4f9f36414333fd 100644
--- a/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
+++ b/Documentation/networking/device_drivers/can/ctu/ctucanfd-driver.rst
@@ -40,8 +40,7 @@ About SocketCAN
 SocketCAN is a standard common interface for CAN devices in the Linux
 kernel. As the name suggests, the bus is accessed via sockets, similarly
 to common network devices. The reasoning behind this is in depth
-described in `Linux SocketCAN <https://www.kernel.org/doc/html/latest/networking/can.html>`_.
-In short, it offers a
+described in Documentation/networking/can.rst. In short, it offers a
 natural way to implement and work with higher layer protocols over CAN,
 in the same way as, e.g., UDP/IP over Ethernet.
 
diff --git a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
index 14784a0a6a8a10..b7b314de857b01 100644
--- a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
+++ b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
@@ -366,9 +366,9 @@ RSS
 
 DEVLINK SUPPORT
 ===============
-.. _`devlink`: https://www.kernel.org/doc/html/latest/networking/devlink/index.html
 
-`devlink`_ supports reloading the driver and initiating re-negotiation with the ENA device
+:doc:`devlink </networking/devlink/index>` supports reloading the driver and
+initiating re-negotiation with the ENA device
 
 .. code-block:: shell
 
diff --git a/Documentation/networking/ethtool-netlink.rst b/Documentation/networking/ethtool-netlink.rst
index ab20c644af2485..3445b575cb5d39 100644
--- a/Documentation/networking/ethtool-netlink.rst
+++ b/Documentation/networking/ethtool-netlink.rst
@@ -1100,8 +1100,7 @@ This feature is mainly of interest for specific USB devices which does not cope
 well with frequent small-sized URBs transmissions.
 
 ``ETHTOOL_A_COALESCE_RX_PROFILE`` and ``ETHTOOL_A_COALESCE_TX_PROFILE`` refer
-to DIM parameters, see `Generic Network Dynamic Interrupt Moderation (Net DIM)
-<https://www.kernel.org/doc/Documentation/networking/net_dim.rst>`_.
+to DIM parameters, see Documentation/networking/net_dim.rst.
 
 COALESCE_SET
 ============
diff --git a/Documentation/networking/snmp_counter.rst b/Documentation/networking/snmp_counter.rst
index ff1e6a8ffe2164..c51d6ca9eff2c7 100644
--- a/Documentation/networking/snmp_counter.rst
+++ b/Documentation/networking/snmp_counter.rst
@@ -782,13 +782,11 @@ TCP ACK skip
 ============
 In some scenarios, kernel would avoid sending duplicate ACKs too
 frequently. Please find more details in the tcp_invalid_ratelimit
-section of the `sysctl document`_. When kernel decides to skip an ACK
-due to tcp_invalid_ratelimit, kernel would update one of below
-counters to indicate the ACK is skipped in which scenario. The ACK
-would only be skipped if the received packet is either a SYN packet or
-it has no data.
-
-.. _sysctl document: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.rst
+section of the Documentation/networking/ip-sysctl.rst. When kernel
+decides to skip an ACK due to tcp_invalid_ratelimit, kernel would
+update one of below counters to indicate the ACK is skipped in
+which scenario. The ACK would only be skipped if the received
+packet is either a SYN packet or it has no data.
 
 * TcpExtTCPACKSkippedSynRecv
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-12-bagasdotme%40gmail.com.
