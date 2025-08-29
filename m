Return-Path: <kasan-dev+bncBCJ455VFUALBBRWRY3CQMGQE77RUC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC346B3BC51
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:19:04 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-772248bb841sf1964699b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 06:19:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756473543; cv=pass;
        d=google.com; s=arc-20240605;
        b=IUJgfUwW1BxkN4+ifT4rXBJoaLk7ypN1YOI6LZVZChWHvg7Fq7Vp8mD7r6j4rOS7yn
         2JCHmZ7nKN7UFqouujK5lxFWZBedQZLvSbDKg6HxHCCbZmVk8cHjX2pz66mMgk8s6fDM
         23rMFNSVeBPlt6iZBZ7+YMpXabgmlXIcJrZmhGQsMEvP25SI9iWWtTgJ07J+x2RlBTs7
         98jPRFCtf6ZD6nvXIE/xeL1pFbMPgf/bA5XNyTaF07knQnxssiqQRRXn124F5GmWpr9A
         +eoWWXPJylRZbRe1XVExCtjRg1wS9GzGEbZwjcsX0PtBuVLtvcKBsh82aW4uJ6czO2Fs
         oUJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=BTKkPaWskm+lNRnPhGTRH6GNCBOGY1LZSVqyStQLThc=;
        fh=PZG1b68ZIW4AbQXyl6fBRm1LwVVf8eYoWsudc/tlcRc=;
        b=GCFvhRTmAXMLIruJgG6TOnFYxyjcU2dob28sAkVREyFShJrFL4oW+QpCQUugXlEGCX
         wYhpcrVB1v0dHOYd4bjK0FHhczzwTauVuWRjvU1X71wedN0Ps0X1WKo6913hpBXHbjtB
         QDGKHEbEr+xqsgvmcdKPzTwOZqycFS6tp7VzbSt+0hs8mFNfeDrC6qt8UCSGF+xha54B
         XxKJMzBiKjKt49K8YCaYE7Q6bozRN2PLRIphlt3gUgFx6a2XQ5He75nDZrGha2ZOMEHx
         xBsYFVSnHZNNCAW209UDdvO9Xspjtvouv96iZvsjGJgQ/wcGj8bcATvjX2h5UPDriU4b
         C2NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S41xqldr;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756473543; x=1757078343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BTKkPaWskm+lNRnPhGTRH6GNCBOGY1LZSVqyStQLThc=;
        b=m94QVbWMHOlft3CeHdjy5Gxrk1FQoK+jDRvwYBH1Tr5aY/AUM5bSzwFpNNqaDB8nCZ
         MzroLvsd2Gl27ptI429HEUdXeQYs3U1zXGnWCbSl706AX5t04CgIJQa/KBMXaekyP4P+
         +4q1E/r2AC0JB3tgdUhux4k7cgw97kVMpesfB/oRC52+HKgabdI7POBVhw1lEVFEgNpE
         t4zSGhoLHZPPU5cSJ/WxDwjF30zaYDSByHdLTr7JZz6MFVKcjA5WDYI4KCrg1dkl9cFs
         ozofSvMmAibmyJRrG3GI7nAhJGCz6NkVJZlkzoXPDVhsHKDoFyQxCbdjD7IuqDKzkFuA
         2fdA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756473543; x=1757078343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BTKkPaWskm+lNRnPhGTRH6GNCBOGY1LZSVqyStQLThc=;
        b=TVcfUfbPDiVJ9zkxMDfQly6Nckmwo158EKjhm9VcDkRmPGeKlqmCLF8BN3Bri858qO
         SdnZrG4/HEl6ZewF+I29UvjOlJpC/vf23C6LEvXZzmo8mVD8a4W/fRhxS7Uj9tTf1AGv
         A+r407TBj55iw0UZ/5QpAbKpHyVce6P2wRXqyioE2vZABWQOrP3Yt2JJP4IPfhqVy4+y
         qMvbYvQbkinJ4ESj5wo55zDYTRNN3BHGizMx+F3VHUwzSj9VOB+NrzjlzsVOKJx3PJr/
         SO4bv1qW+0dEltlyTwSGveXmzjeyAaXp03RzBx8gcIJnJbKPFYVnz/jfj7gPj/00pk25
         4Okg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756473543; x=1757078343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BTKkPaWskm+lNRnPhGTRH6GNCBOGY1LZSVqyStQLThc=;
        b=ti0jLHiUxjzMGJ7JetB/mviBxLqSMYtQ8sj7VyH+a251gCtPk14vVlzGeF693nWLhK
         /UFMgsD+PbY4+f4VCvN2RU0BGpFVk0gzJ9iCYVezzMvXyM30McylV1QbM0752mWYz+5B
         LUFM+hFbv26zv4uVXBLShwk86mnkNoe7Zpayph4Cy5Vj52HX64r/CcvFIOCb2jw3QXQ+
         kki9Tmns2o42OoRuYCldGxbvyZgD2Q+k7baSHNB4FQhEmV3Dy5q1I2q5EM8Hrwz87L8d
         UgIfvZ4NHG2laofTI8k1bfaa+AA842+Ygo48ntqWIk67h1INxhDFWGFArbVGfO2q1TGZ
         XgYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXM9C6SV/5CicI+WcYUKaiIIH4bNDhaCaXq5xf5Gua+ssGOHv6DtgQW2PU4m/UZv5a4hCE6vQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMBYUiheNggbrrg2IagtAnuKi62enxTNwAUvjoEm9b6qd4uF0N
	XYf2wSTrZrI44OFvn6Csnio4C0Pui31REv1rZqG7w/mze29kiey0XOe+
X-Google-Smtp-Source: AGHT+IG+Dm6/zl8EPiBl7E+5j7P5D8nxjNKN4Bu/NTInAqzV7SDNDr78FwxWRnMzPKe0cA5nzgN/0A==
X-Received: by 2002:a05:6a00:1783:b0:770:53ed:b7b0 with SMTP id d2e1a72fcca58-77053edb8dcmr26205429b3a.0.1756473542845;
        Fri, 29 Aug 2025 06:19:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3XzQQ4GZKE45e+2TLoIGIdVWkN8vMj+JV7oYhTku+Vw==
Received: by 2002:a05:6a00:1d84:b0:771:f987:3f6b with SMTP id
 d2e1a72fcca58-77217e567a6ls2284842b3a.0.-pod-prod-08-us; Fri, 29 Aug 2025
 06:19:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD725ae/QpPZi5jRpPzUuQByLcKxERS5+nKco/tPYls9+l3LAEmW7Joaul/xy7CpItjdddR1R9tbI=@googlegroups.com
X-Received: by 2002:a05:6a00:17a3:b0:772:2e09:bfcc with SMTP id d2e1a72fcca58-7722e09c11amr2527001b3a.30.1756473541195;
        Fri, 29 Aug 2025 06:19:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756473541; cv=none;
        d=google.com; s=arc-20240605;
        b=A3Qv6n78M13LvrFz6+6D8+TvpTFHNKtipEleAZmD01T7JO9TZu8Bi3QiMEM9cqMvRq
         IS6DrznwFA9LNmwKgIgupGDyiDf4wDWS/SHpOugWFlIl5wkIf9TMegw37i0Z7a+0co2x
         zUS0cpFBuTvvtQfwA+YCPk/4sTONd8NmMptf1SuEFptY6zWGFPMvUgYEUF7I/3UID2BQ
         f5njzIgdrdmJ9I64ycLDwap9x/Nlc1QneLkPY/SQwb9ss4/kHFqE6QoxtmOVGdg7iB6k
         pmWuNxQlXNv5CIvdDJ7cOf7c71bQgq0E6uqU3B8HN9jQSHODm4PWxUn8lY4oa3G2G/g4
         9B3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xtU8o3RRKlATt1ZkDZoqGZInz4LA3xlvTSiKt6WYT3E=;
        fh=JpHsLrkhLKYpwI2PQOhvmC3tW0huSzFNZDfQlHZoUY8=;
        b=TaNmJ+cVYWqqSYfOG9W8B3nvCKTckW3hV/kmtnoEHAUDfWd3cgxVLW7WX3c/zYm7II
         ROX/B979xpk9CXLdNeNmouRWxXkTka31DoN4qoZwxk9w+XvQLnkD+KVjkygGXbkVs2RP
         tf3SDgogOGFMeJ5sooM6o7wltApDjhz8EF1FauH8Y208aajHg1Siiqj/22UuDUyk6JTp
         ZBkLbVDcQ6ydhgxFO781CActDPuuw5bETedme2JQGyZjG5NrALFeTOJUynrVaYsa+brE
         POHeKadhlmKuEwfQZgVgHLVTRk9w7TNHt5GXBVgOUpfK8ecFTunwEMFDMVuuWQWCFqI4
         HsqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S41xqldr;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7722a425f90si45442b3a.4.2025.08.29.06.19.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 06:19:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-246aef91e57so28492745ad.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 06:19:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5ycSEA7oqkpoN3N523X8+DjmTaQJq7sied7AohzzFBONj6TCn9sRxeEZ/NmRqzo+XPS3Izz0w8KA=@googlegroups.com
X-Gm-Gg: ASbGncvf3/V8XAxNY5DmLzdpER2Ckg8vJ8VzEenghjRroXtDK6IxKi8D6kqeE3dc1x4
	cqYC3pzNMH0SLTmgK1OzzIFhEC9y+ikFGO6nZcJigv4B0j4mlvzRQMeTVVodrFof/IjTkdimjoX
	Wbi/Oi40O0X2r2uyYkeZFEv6udnwB3yawb3sr2HexVbQs11BMzl3PEiStA16a2kAMZ7QzTAMRfi
	/ApUCSWK6DK047wOCycWUFSH2dHnSLX/12ffk7/Wdn9ApUuBjdAKYXIy6S1PUQ+BhG4h0cGdx9A
	j3mntFyEz4IXDxoL5xoVUpbnDwzaZA9oO+ysNkjr4/e3/UvaBvJqp37Xpivkd3lDnd3wFKXByrK
	43fNxQe08eDHhPl29iu60fY/0Og==
X-Received: by 2002:a17:903:1249:b0:246:1f24:5f56 with SMTP id d9443c01a7336-2462edee969mr375920675ad.7.1756473540520;
        Fri, 29 Aug 2025 06:19:00 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-24903702396sm25810885ad.14.2025.08.29.06.18.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 06:18:59 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 51DA0409D7C0; Fri, 29 Aug 2025 20:18:56 +0700 (WIB)
Date: Fri, 29 Aug 2025 20:18:55 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Jani Nikula <jani.nikula@intel.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
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
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
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
Subject: Re: [PATCH 00/14] Internalize www.kernel.org/doc cross-reference
Message-ID: <aLGovx7OpL_85YTf@archie.me>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
 <437912a24e94673c2355a2b7b50c3c4b6f68fcc6@intel.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="v+QeNeXg1wIV/8Z8"
Content-Disposition: inline
In-Reply-To: <437912a24e94673c2355a2b7b50c3c4b6f68fcc6@intel.com>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S41xqldr;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::633
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


--v+QeNeXg1wIV/8Z8
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Fri, Aug 29, 2025 at 03:18:20PM +0300, Jani Nikula wrote:
> FWIW, I'd much prefer using :ref: on rst anchors (that automatically
> pick the link text from the target heading) instead of manually adding
> link texts and file references.
> 
> i.e.
> 
> .. _some_target:
> 
> Heading After Some Target
> =========================
> 
> See :ref:`some_target`.
> 
> Will generate "See Heading After Some Target".

I did that in patch [14/14], but I had to write out explicit anchor text
considering people reading rst source. When they encounter checkpatch warning
and they'd like to learn about solution by following See: links, they should be
able to locate the actual docs and section mentioned without leaving the
terminal. Before this series, however, they need to click the https link
provided, which leads to relevant docs in docs.kernel.org that its source is
already in Documentation/.

Thanks.

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLGovx7OpL_85YTf%40archie.me.

--v+QeNeXg1wIV/8Z8
Content-Type: application/pgp-signature; name=signature.asc

-----BEGIN PGP SIGNATURE-----

iHUEABYKAB0WIQSSYQ6Cy7oyFNCHrUH2uYlJVVFOowUCaLGougAKCRD2uYlJVVFO
oyLxAP95mJgSRTOQ+hTC3+7/hjakAGgQRjyWnfFgZF9dKlXeHgD/bJRCDtPLAnbQ
JLSf5TwAGdo1LgUd0wgEgetqhpMKwQI=
=82dj
-----END PGP SIGNATURE-----

--v+QeNeXg1wIV/8Z8--
