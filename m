Return-Path: <kasan-dev+bncBCJ455VFUALBBIWAZ3CQMGQEYYB2OIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 3650DB3D084
	for <lists+kasan-dev@lfdr.de>; Sun, 31 Aug 2025 03:06:45 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-77241858ec1sf707480b3a.0
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 18:06:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756602403; cv=pass;
        d=google.com; s=arc-20240605;
        b=iTAjcw+PKk1TKUU/+MQvP5P42QGSvb1W3SntMekU4Gl7i5VarAdHBrbwLYosALKgmo
         AviFtzwd/cfLm1iOHiEFv8aKwaWCqN2AvD+VcBGFG0fQq3ik/Lrf3wq7BPXiuk0YB3Cu
         yRiPDw2kiaip792pWUQpf/UD7+tdCSHtnL0k6PwpqtDQDUI73Py0H7HEgbet9TRGm9Hm
         qHXoxUL2L8hUlTBEq0eNtdJUNtXjuJl/yIhtRujmrmRJh9XAU1Gy89r9qw9BNePjgVRd
         KURhsorDPnXUgAlyoVhec2nBmuxNnCfocmp9KbCoLtLnAHuKjpD1h5xhFJorMAuhezbj
         kr7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=qXzuvz5dq0vXga6BMHwzCTPZKn45IJ6tDKYLx7KcMQk=;
        fh=fJWH0vlTkWRlhf0wVBQNyWOlX3KIQDJVpOfPNsJoHKQ=;
        b=cdj3kK/Ecd9jU1iRG8BgrEx5LnuRpRUI416yyLUlUjd+A/CLf74brSdeLG6oScmR9L
         kIPOH1fEOSMAHkINwGPO/PwGfL5uMWXb9r1P/toyXkPwwaCZOQ+JHhk0zz65h+Vm+OI8
         80C/n1dgyoHV8WPq+/5hCrmCktpm+x9SS97jWB95hEGyJqbFzsXfeH8XRWs0+ffnTVGG
         lMtmF5lTppVJQsQlP2ecsuFZju20QEeNUlTKuLXCvdm1c363gJ040XDWc4mphhMsMwnF
         kgr3CTWKsMev3voX/LnLutskKBDvO1ClvKeoWgxhiLflM2rFfdoaccq9udE3r1nnjdVF
         Gdkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XRl5wneD;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756602403; x=1757207203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qXzuvz5dq0vXga6BMHwzCTPZKn45IJ6tDKYLx7KcMQk=;
        b=woOGrchNgna9jvz5BWnKJiWYKQjoC5cxoqXO1YLnFT2zijDW4NlEI7FKyi4014Wdrt
         7Ckfvrxy2ELNFOW1e16PgGBeeveu9OZWwbQZb/Ra37JehRJKQDHkW4LVRgQu34CnOgv/
         kirvkUGPY+MEbTX5Axkc5Dh3eo8k6uvuzKgpsbxAF6f8e7qil2JzGUSW8ePFawCeG/1e
         +KPRboAKLifAMCxRly1OnFGpRCl0vGLs9sbPjppqx2InO3ZIGEda5PQLuFXhNZTGMkQZ
         nk705EJWHSr4uoWCi9QhlTgO0/K+I+T9UdzaofRBaDuStkT33DHGM4J5QP0ZGehdS2vG
         eH8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756602403; x=1757207203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=qXzuvz5dq0vXga6BMHwzCTPZKn45IJ6tDKYLx7KcMQk=;
        b=mLJEFsbzMxhJNmye7vU83RVv3TILhAq6+tOzR4z4d7VuRaaMRPp6beTUf9srCLRKPL
         PbcmeJ02SmxPTFztTXunDvanWbJWZO0ZEjsJSFjvOJRqqSq9z7M3++sCPrKs4WuLTL3d
         +16ynFZWoxeK+SkejabrQaKjgnP7aUUUJvYevO0o4IWSZkxzKKs1j0eKi3dFU/15wMSJ
         Vk8rOh1S/KzeOsiCW7ZztmiHCEMRtChA1cRBJIZdzmyg/bZjmUsC6kJDv0ilVc7+FRo8
         OOLOf5S0XMyXck56f0K6nWWlOXLu++xH5lro01lngDHLMEEIjDJYNCeJ8MWEQ60/ebBa
         8h5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756602403; x=1757207203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qXzuvz5dq0vXga6BMHwzCTPZKn45IJ6tDKYLx7KcMQk=;
        b=VWlMlJal//R97AcxZBHqMCFEPpZvyEQ2Kh+qxrnaGsht4ovU6GC5jxzCVh+Pkfwei+
         ObM57Vi50q/RuXvesbcQsqbo7P5rjmEfAmYA5zLhR9UUKuMntoXiBQmRRb0X5M861zQZ
         9JKM5QynxWaqO4WUnTQB4cbKpWpTHfoss1mfKyjJzVgORQMOa+G7utbJJhHiNAJzNPft
         E0+6+ZfwczT3Dpz65NO9RDVaII7RoQiEgSPJiALtZqtL97s6qMF8SeczMS8TV0OW17Pd
         hp6hig2OmsTC5U+5FnDOsEk7PCjC7UYSCn8m1nFuKQ2t45Bl8E+uPmWOsTLnJm7vesDb
         2fcA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7kUmUeoAPYd0dyUgu+7WhiA8proZeIwa6XIEt4lOul6Q8H06ujKMRN3vMz/m//tAJPqihPg==@lfdr.de
X-Gm-Message-State: AOJu0YwdopXOmFvKGY6i8ZLHTW/TdeUfgFtm9ikUIFPdTS3ffA/wORRA
	C2W6PZfrbm4QElfW2GUaQ4E3exSzbq1dId+OZfEBk5yf88l9cmON3KTb
X-Google-Smtp-Source: AGHT+IG1TRQKPvr/7phBa3ECbMQotVypPpPGWt+n0SG4LrUdQ6K4Zeou131FS1hl7BrID6mYINSQdQ==
X-Received: by 2002:a05:6a20:42a3:b0:243:98b1:395c with SMTP id adf61e73a8af0-243d6f0a63dmr4372989637.31.1756602403209;
        Sat, 30 Aug 2025 18:06:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGdZZ2Tv7pMV07KLZ7GC20qwRvaIZ5RLc3bpJAkf0Teg==
Received: by 2002:a05:6a00:2d0c:b0:769:ebe1:e48c with SMTP id
 d2e1a72fcca58-7723bad6059ls1447204b3a.1.-pod-prod-07-us; Sat, 30 Aug 2025
 18:06:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXV2pv2hmjwE11ggENTgwycUrB/zuSuXghnetJ3OHv6XDDogpZ9lL5coPS28BEAW99gEm+aEGOzFGw=@googlegroups.com
X-Received: by 2002:a05:6a20:728f:b0:243:be7c:2d7e with SMTP id adf61e73a8af0-243d6dd564dmr4662413637.11.1756602401828;
        Sat, 30 Aug 2025 18:06:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756602401; cv=none;
        d=google.com; s=arc-20240605;
        b=fd75HX9S4efySjGG0f3o8GZEJkGAsIpre81eMcqjaK9DsjY0o7XWFg7aox1ZEF3gWR
         hxgBMtjW1X5BSIByss3uv0lizTtn0XuBKR8eNIwd2P43N7extLUlzG5abI0jjUbn9C89
         0RGqbPf3k7JU0LD3yh2f6Ett2cdx+COnXxNTBUT1zgJD7fHMB0XJEOJY8e4r59TMIm8Z
         rTJ10UZjZiDio5De0GBBw2GqlvfQG+FuDXWdKFiYsmey/V7EfHTcORYETowDpX5B/X20
         i7vWYXAumlVDwID/g5o8oBkGpOL9/POE/QOvZkKWmUY0CjdyPYuzyKFyiwp+w31EFncs
         K7oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pKJR3d1y6/pE646jp/qQ2LVHmuXD7qWjBS7Rpy0QVAg=;
        fh=jr54PtjP79G7xYoGJMOWyhAN8cucsfeSnm29q6QhRN8=;
        b=SIRuYxqHTnx7GTByCi5fP7H4K4lUH/BOgu5+8V7m/N93mocF1flrjdr+4vF6Tvl0Pj
         Sc9YJQ/kmxz10epLM23iKgnNEZQwjp9071RSevjZ/FOitSoRCJRkenjnKY4UMiLaxEK/
         ZPO/kny03n9QUy0ICPBgFPGPcEg3zRudG53cLLOHCWku7TT+LNtqCcNzMKY4k01i8QG1
         vT5FMJoeLHU5qDeNqEpZ/VHjnXDDof0S3rESd3uaB99ApDOhlEfwq7UvHKXJzUwVYmJx
         qoG8AqDW1QRqi/6RZ0MnJcgnFagLa+mj31Vk9XW/o1MWySF4j80Z52Jg+620r9erfp8B
         tGww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XRl5wneD;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327415067d9si670681a91.0.2025.08.30.18.06.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Aug 2025 18:06:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id af79cd13be357-7f04816589bso311094985a.3
        for <kasan-dev@googlegroups.com>; Sat, 30 Aug 2025 18:06:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVn+gNUyQgJDPJuUNPgsylHFbjQtIn0n4RbiAnFgvbAcI9tjeYBBZ25swNSD4AEn1t4OFcgrIvHfyE=@googlegroups.com
X-Gm-Gg: ASbGnct4EnCftl1Y6XX+v9tw2z3c7+2ScxpIgbkMBuW7I1gRT9+BVJqG0Y9qOCmrYrK
	ZYfsw9XKXvF3c2DqDW8X8DfCu+oWbFD2GyyMTFmz4SEB3km8lVDybsHPM41zfB6iUEnX0A7Zfq0
	/9d0Eo4V01r1m4pKG0tmcQoyADxiK0V23XEBURWcH29p/0q8PG03oN23YsOS5eyY7dts8p/evay
	WA/bJ9JW25Ex55hV1SX0A58N6wflW99/Jsx3OnVfnyL9BKEy99x3B116rHJ0fi7TBRoL7HPoj7j
	k+ukdc2WmgbiFpGx10hRmrZNp6TeExN/84RwwSxtffjruO3i6aCLMTnJk00ZKTGBI/3XlK6+6al
	m020Gw/VuF2aoLc+6ACgnpW4Q9w==
X-Received: by 2002:a17:903:284:b0:248:db40:daf0 with SMTP id d9443c01a7336-24944aa3d39mr45078855ad.31.1756595493230;
        Sat, 30 Aug 2025 16:11:33 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-24906390b55sm62020245ad.97.2025.08.30.16.11.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Aug 2025 16:11:31 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 3F63E4222987; Sun, 31 Aug 2025 06:11:28 +0700 (WIB)
Date: Sun, 31 Aug 2025 06:11:28 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
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
	Linux Sound <linux-sound@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>,
	Jonathan Corbet <corbet@lwn.net>, SeongJae Park <sj@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Huang Rui <ray.huang@amd.com>,
	"Gautham R. Shenoy" <gautham.shenoy@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Andrii Nakryiko <andrii@kernel.org>,
	Martin KaFai Lau <martin.lau@linux.dev>,
	Eduard Zingerman <eddyz87@gmail.com>, Song Liu <song@kernel.org>,
	Yonghong Song <yonghong.song@linux.dev>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@kernel.org>, Stanislav Fomichev <sdf@fomichev.me>,
	Hao Luo <haoluo@google.com>, Jiri Olsa <jolsa@kernel.org>,
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
	Eric Biggers <ebiggers@kernel.org>, tytso@mit.edu,
	Richard Weinberger <richard@nod.at>,
	Zhihao Cheng <chengzhihao1@huawei.com>,
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>, Shay Agroskin <shayagr@amazon.com>,
	Arthur Kiyanovski <akiyano@amazon.com>,
	David Arinzon <darinzon@amazon.com>,
	Saeed Bishara <saeedb@amazon.com>, Andrew Lunn <andrew@lunn.ch>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>, Jaroslav Kysela <perex@perex.cz>,
	Takashi Iwai <tiwai@suse.com>,
	Alexandru Ciobotaru <alcioa@amazon.com>,
	The AWS Nitro Enclaves Team <aws-nitro-enclaves-devel@amazon.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>,
	Meetakshi Setiya <msetiya@microsoft.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Thomas =?utf-8?Q?Wei=C3=9Fschuh?= <linux@weissschuh.net>,
	Masahiro Yamada <masahiroy@kernel.org>
Subject: Re: [PATCH 12/14] ASoC: doc: Internally link to Writing an ALSA
 Driver docs
Message-ID: <aLOFIEknbxQZ6FM2@archie.me>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
 <20250829075524.45635-13-bagasdotme@gmail.com>
 <20250830224614.6a124f82@foz.lan>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="q50L9+H94gXo88jD"
Content-Disposition: inline
In-Reply-To: <20250830224614.6a124f82@foz.lan>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XRl5wneD;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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


--q50L9+H94gXo88jD
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Sat, Aug 30, 2025 at 10:46:22PM +0200, Mauro Carvalho Chehab wrote:
> Em Fri, 29 Aug 2025 14:55:22 +0700
> Bagas Sanjaya <bagasdotme@gmail.com> escreveu:
> > -Please refer to the ALSA driver documentation for details of audio DMA.
> > -https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html
> > +Please refer to the :doc:`ALSA driver documentation
> > +<../kernel-api/writing-an-alsa-driver>` for details of audio DMA.
> 
> Don't use relative paths for :doc:. They don't work well, specially
> when one uses SPHINXDIRS.
> 
> The best is o use Documentation/kernel-api/writing-an-alsa-driver.rst
> and let automarkup figure it out. As we have a checker, broken
> references generate warnings at build time.

Thanks for the tip!

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLOFIEknbxQZ6FM2%40archie.me.

--q50L9+H94gXo88jD
Content-Type: application/pgp-signature; name=signature.asc

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQSSYQ6Cy7oyFNCHrUH2uYlJVVFOowUCaLOFGwAKCRD2uYlJVVFO
o9MMAPwIm+r4BZdTF0jZV4Naj+z2WrUBji4gRFJQ4f97vYNhfgEAwX/UGgC71a9U
lMJHF+utPAWnldcv9PoyPOBgO71EEAA=
=C7rV
-----END PGP SIGNATURE-----

--q50L9+H94gXo88jD--
