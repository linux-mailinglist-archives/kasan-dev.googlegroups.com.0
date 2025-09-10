Return-Path: <kasan-dev+bncBCJ455VFUALBB5GLQPDAMGQEHF6CXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C1C71B50B45
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:05 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf101829836d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472244; cv=pass;
        d=google.com; s=arc-20240605;
        b=SLVrGVL2OSxeAu4I4Mu9qamM2x0PTNw+9C0TXQXGHzcV1nXJ6BPU9BiGa7eYSGKnC3
         16BSXpwgwfix5vutTrXD5FeLfE+a07Cf/75tvSCKgcBpmn7dw++bjVo9YhyxnVDiBNyx
         scDHpgAkSJbLNMay6rXKLT1xdTrqCgOdF9/6o2T/1R5nI+w5vL3u4ihUaxFkzXkjNnkU
         xo68uWM4ZmpitP1SxysF40Swmy7Aa1oJYYWIPdKArmoWi03bfFRBPdVE9JpIUgm7HO2y
         y1gnjphzew7ozZJlHiwH52ZKN4M1SEwt9r8dfqxo74Tb0NuCw+y7n08BqDgic3UFxQbH
         wZ8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=3FHXFuyE+LJxlSQhf/MEW4jyvAPvI3HHlpFvURTTeW0=;
        fh=ll1kGf+32P+i8LhB8XgNa0ckoP1TmQivVC7ubm11MF8=;
        b=SydOLpz9hX40lW6U+xFS+/uMIiLFCBf2iP5+3De4lbFH1Vv0QrDKyHEuttznS6/6uD
         jgghYvAhO91DGzBLR8Ly4xgax1ya9VxhkJeYCTcDALA6Bqd1KXcZtCTQ6hdJr0gVQXgg
         ljUuEa7tFHMUP6fGpyBW2BlhMBd8pJHeQftZzUSVXAKOnTVRNKSadM9szG/RDpTFcxlv
         0+Jl8w8HCF75wvVPCmC2YGy6flutk9VdhykXD5Yl0ss9B/AcAlFuSEtOSxZ3UASFpq36
         vQ0xkWO1pbJrnOsFE7ICyN2L5ZI+ICe5vrQovTec09vVvZylUhnx1cdqPEN2HFwz6TK9
         Mfaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hd1qyiiH;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472244; x=1758077044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3FHXFuyE+LJxlSQhf/MEW4jyvAPvI3HHlpFvURTTeW0=;
        b=Pdp2b0wdk52en/KsOuPUj75OoyZaq+H5zUOJVI+F39uZzipUCtNhvqZeFiJx57qCcZ
         fxz3eLPIIRSeSh9kwP8yFCoC+crNxX6ybOztYD3um8RY3xLGL8Uo2iXXuCTtqQwHS0NZ
         CaTtstoDmplNlHEw/jC2n+D6DcZMhniqnoXiWTu7P8SfJTEBVqGKuE8whpsxskfGODIT
         gKZZ9XJBXgB3ng6PPfe5UFqn2rkJUhy1MlyITpTA8Q10O6WBUX9UOtBE2MG6WMuz8gpo
         79iARP8XY2fPNJtRPy46otcENQKVDxGKrhBXTvy1jmEoYHBiInnZaVxjq5UK4ojjaotp
         9VcA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472244; x=1758077044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=3FHXFuyE+LJxlSQhf/MEW4jyvAPvI3HHlpFvURTTeW0=;
        b=gY/meIQ3+dlRji2gui9o6SPTz6w1LsLt1gBR4OTGy6TBJl2K4vLEk7cKtjGlmb3VN1
         HC/awrIsZhK86pMQl6ztLysycRt2Zp25JOJkQXqfbPoOLvdOnSuglGXqoZsYem/EHviu
         19dY/KPG7kh1zCIa1j3jM/qHzGceWkAVHv4JnwxUcPQay129fQnca5ThL6WmNksG7mYn
         Of38BeVaM1Eyuq4l2Pc9HMw7b9Z1OPKDBMMLj+1O9wI+ty/rkbvU7nM3e+PZSKCy32aw
         79LfWAnLpvARkGUOKUH4EifOq5fhEAojJBmX+Y6NaxWZBgcM1CnNllPcTUkA6DStJ9fU
         h1WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472244; x=1758077044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3FHXFuyE+LJxlSQhf/MEW4jyvAPvI3HHlpFvURTTeW0=;
        b=QAWAw9lYcxHf+zstPKNEDYxym5eCg+ntLx/g0l3F3EkflPQNXYelNhs2ElR9M7KXa1
         T8oGbMb3QNidGcGwT17YUb4bs8owqQl8nMDFzcXLxd8j4VoG+kA9R1gTbLYMZmf/TxIT
         2hfklwgL1Aq1CDJMfNQvmLEFiace8oZqrYDsnB4vIpxtrRVPSCYjsi11DzjgHv+u/eus
         uFC9B1w9U+ONC85qC5HYqbGBB6bIfQmS5E4kp4Ssgiq1OToQi77bO7InPOpBZS9XzE6b
         oD/uV8opjYPU+6ReK2MgIFucxfnQlsjgyt6zuMgxe5y+Q34PMAy3Qy1SjNU5dPk/4RQ6
         USyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFh19AwkqOstiXbNfp6PEhJsuiUyREwNtqMuOX8Xf5o0WJD4TErSYXACo5fdNwFEb9psQM5w==@lfdr.de
X-Gm-Message-State: AOJu0YxqfaagNGFv+YOUdTlWaE9PqMbvMUpoC7kpu8zGW26pdALk5zsY
	v83zw4iQmEZOtq20fmqOpVkse5I+3kMDnTh/W9KPYoYCqym4l5gZiW5W
X-Google-Smtp-Source: AGHT+IGaiD5cyRjVHGKunvbXEjqzXS53/7FNF/41cVjuWnTLeHZyvlRCXPYhLq0twYJHfN/W07LCeQ==
X-Received: by 2002:a05:6214:20a9:b0:727:e0b5:beaa with SMTP id 6a1803df08f44-7391f3041a4mr148073046d6.6.1757472244597;
        Tue, 09 Sep 2025 19:44:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7lYHc4rZNy8m/8xP302Dxg24n1m1JMVY9pxx1/gkiobw==
Received: by 2002:a05:6214:ac8:b0:70d:9fb7:756b with SMTP id
 6a1803df08f44-72d3c4076c0ls80243566d6.2.-pod-prod-03-us; Tue, 09 Sep 2025
 19:44:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkHaAFWjEDfYi9cAATo8Aqq4Pkls1NOpWGSMef1O5sp/YowDreSRG/hl3P2YD0reG5plW1c35+ojo=@googlegroups.com
X-Received: by 2002:a05:6102:1608:b0:524:2917:61a9 with SMTP id ada2fe7eead31-53d16b671d1mr3815404137.34.1757472243821;
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472243; cv=none;
        d=google.com; s=arc-20240605;
        b=b37N1HNYWGxLW3inUXoPMZEdZw20klTx4ojaub5AooEOpNRWiiiKAovSwtMJE449KL
         QX7o1nq/B61l9SpF3bq9Zl3g0AV3Ixqrya9OsIZiuJlpP9/D7r/CzllC6BWgFK5OESW5
         BjUBxLz7OY/Pr1tHqB6a1aL8vkde1DjUN1dNzUVtJFsNNiVCSgqdIxbuhE9Cst4VUkmg
         FGjPazdS8HJfLgzScDW4bXjxnc/doL4rQWMySJKnnXqqLtRLazvDtYxwziUGIG/kvjP6
         4x37n6R4VIPR+09C4U9vS41BeKoHFNWFZpZaIcyOo93Blbq7G64dzTEACscGjoxyqKDD
         O2Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2kNx/lgQaweLHCKpOd5HxLBg5NtnJ9f3nOi2hx/97zs=;
        fh=w6+UiI2sCnAi/A63NvOnwZjwSdCreWyc6iuS6RIumG8=;
        b=RDG8JVY/UgQiyTiLOZy1h9sCT4K70F7nKSIcqounY7xNcuj+It4Bum43sM/zl+vv2d
         NYyEk4GZ7Oyf+wTqBdmecgp6fvNU7BWUl7dOlfIwGZkTF4URtBX+HhwSTcRQjCft1RLO
         7U5ySzD+sTZEjzn7OszMJ5JYSPy58ZeCAxrU2b7naUpCyEiEOL3X/yQd6sRXAOX3b+Vz
         JKB3+Wh6seIvB9hg/oOIrnExZpIWdT6VzY6zh/vlPGhQgpi1/OsGRoiethaD6UYXRXAt
         f3hPb8qqD3g5TgkJkagUWHz5PoI/RkkIpWENLn8DFR86cXauBFB4HpX665bD2dqPzscY
         GCjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hd1qyiiH;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943b854f03si1128728241.2.2025.09.09.19.44.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-77246079bc9so7425138b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtYyAFQew2OT7IjnCESHdOgpERRuYkbhpnb3JxCrsRJHNNXfENFJS6k5I1hREpcBZB+7C9P9UzUh0=@googlegroups.com
X-Gm-Gg: ASbGncuUekfesx7v6QWcmnzPT+aZibdLRmZibeVFVO+YPHuDYy7Ef4NXBIyEEVWaJN/
	3EvqLu913qP1BnOQBtzwjMNAyV88y0fqAIV8tjhMgBa+GYFx7Wtd+MgO0ai27z/doVB8AcX+n43
	8DObw65WgZg4uIzW/Ir5zSMzzrqGl5Wx15bzg7XAN+gAWoETfjJJPcCn+MvQzqH6kKHFm+4dg8r
	38qMWNZa36vmfE8pbEdua/GmsaH94/Jdc9DmDFiSHsOnSml/2dGVzx5vmnfaeSBbUNIm+Zphj+2
	dd6LCHq7rDmg0rgcP4DFR79R2mzSoajinE1scq94JDlkTb77+3OfEUGeBjPbvCmPAmAU8DNfT+i
	tyxYmZo6wGi0FfBxosJm1J7YySg==
X-Received: by 2002:a05:6a00:2308:b0:770:3b56:7945 with SMTP id d2e1a72fcca58-7742db9329emr16048091b3a.0.1757472242613;
        Tue, 09 Sep 2025 19:44:02 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-774662c39e0sm3469279b3a.69.2025.09.09.19.43.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 999D241BEA9D; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
Subject: [PATCH v2 07/13] Documentation: kasan: Use internal link to kunit
Date: Wed, 10 Sep 2025 09:43:22 +0700
Message-ID: <20250910024328.17911-8-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1129; i=bagasdotme@gmail.com; h=from:subject; bh=yEY9P3BA6E4kqaGTHyjuJlgmOOGj2m2ZOET4fPd8xcs=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnihdUeC/XH99x9zD0/p/z/9z+OvEiwfuXjriUbHJw 5Al4fDvwo5SFgYxLgZZMUWWSYl8Tad3GYlcaF/rCDOHlQlkCAMXpwBMpGYSI8Phu5uLfVhjJryT C+XOkO/82KnH+HRZtlehgA+3hxWLXwPDX5ny7U3LZzLMPNBzWixMoIP59nkt/0fGhV4ZjM5rXH1 d+AA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hd1qyiiH;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::429
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

Use internal linking to KUnit documentation.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/dev-tools/kasan.rst | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0a1418ab72fdfc..c0896d55c97af8 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -562,7 +562,5 @@ There are a few ways to run the KASAN tests.
    With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it is also
    possible to use ``kunit_tool`` to see the results of KUnit tests in a more
    readable way. This will not print the KASAN reports of the tests that passed.
-   See `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
-   for more up-to-date information on ``kunit_tool``.
-
-.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
+   See :doc:`KUnit documentation <kunit/index>` for more up-to-date information
+   on ``kunit_tool``.
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-8-bagasdotme%40gmail.com.
