Return-Path: <kasan-dev+bncBCJ455VFUALBBBF2YXCQMGQE3EGEWVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FA47B3B4DD
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:50 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7438205f726sf2095355a34.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454148; cv=pass;
        d=google.com; s=arc-20240605;
        b=iEH5tSUcXlmNz9Eo5VqKIjEMIkFyfwHV/VI1ei7VWoJN9I5j2smDWUrKgtPN8jPNu6
         2K+XGldHP3gNPV9NtEcV2tr5TSsvBWrWYHgrTzwujv5yWrVotC7CfZDqVpPm7zVRZiz9
         FJmt6Qzxhmy8GRDdD3SjccEM6hzB8kMKUTDMizp5dLT8Fc8Q67eR30Jlg1YKdBixxPDJ
         fdurnd75zZoPBt9iQ17q8IDmTL0zFKA+Q6f8lSViMyW7+qWrPNgZx/JoP1UAs7M4XZXn
         T6yTZTYvVDjmhDUgVg9gqBLCKUteaGoiYtSvkma+RCDCSDy1iheyJuv1wNZSwX13lrIi
         EtDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ZFwprkrTeG0bFzeLYiEGNVgr/mAlmhi2sa+TgCsc4n0=;
        fh=KYWceBHr2DwU1uBHcwfDOpU+DmNUGJKB4+om8XH1xNw=;
        b=JiLTvTpr9v8PN51a3AsRUi9axAIKD9upXaPChPCDcCd81SQbjmWZJocWvVI0a1mbwk
         8IkmBnPC6+Gwr+BZ/+BsGfR3mfqU3li10OpBv8xpfeJCUrNYVFOF73YpA70iakoVRTka
         GY6GGM8NioWkZPmPWVYyET6W3Tm3sZK66wGNAlBzO2KmL0StmHhGZhGsXJDxVRuoEo8P
         CHDw+z/VWN3MSk9RpQ70aYCGev+EK6eHDfiqp+570zERTn9b441sk/zCbA4V8TK5K8N+
         ygf30gGCIWL37SgF2WPBaGGJAqNhAre5MWtWx2lyaxqDZ7r59FGc0wkgKDCesgIZeURD
         ZhqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hVROityS;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454148; x=1757058948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZFwprkrTeG0bFzeLYiEGNVgr/mAlmhi2sa+TgCsc4n0=;
        b=UY1BTtu+OxDX56FVO3umuvHXEPxLDrbAD4qecLOf/KUz1BH9DTHKwP7oGZv45lD3W+
         o17UnKVz+/vTt2ZgXphs5+SgRj0p4EHK7+0iTKoXYF08Ah6RG15hbRqrbD/aJl0+2ftW
         lYX3oUQ8rYNQgZOAGn21qE4M8lUPPQJ10FLsyIaXjQ5eIzWf+vbBFLyUgVJL7Gul3U3v
         h4Eoo9EtsxIzgxkFy91iOFTBd4dM3D2OJiHuohR8iMiaOFnw7m71olRRPo4ibyuFzYh7
         KLnqQudh4X8coqzStrQSBNiulUJWFWOPvUg/HUKzJzg5J4C/vVeswqFHmVCwYdjgAicL
         2AvQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454148; x=1757058948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ZFwprkrTeG0bFzeLYiEGNVgr/mAlmhi2sa+TgCsc4n0=;
        b=bMUqefSxDnd9bxwazC1NrDJbeOgFsb0xk69pFFrWgQRHtb4DxPfDDHw/nZ/EGhgofU
         K3kJVNJ8547Z6ZiQ9/SyXfv+LDI9BhDE1FVrGMsu6tF6FR1xHm6qHYb1zfPXbyuGW0Sh
         7LiSKB4rPJh79IuJGNvH6fbxRZWtIMzfhtGa6balU0E35lZlNklUT545vu4m6tp+NaVY
         4yWdZRKZEfFEJ5hjHguTQYpL71tCB5Z7ncoLARY5aB5DqKs9SQfSoUuy0CfdCKkCC7iU
         RHnxr1FVGZLeVm+5yPp7Pm0nxgbMPtAk10ecIfJvhMnqhHsFt16uu+zgrAKtRjkBEqSw
         OfJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454148; x=1757058948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZFwprkrTeG0bFzeLYiEGNVgr/mAlmhi2sa+TgCsc4n0=;
        b=VAQYbm7ehrvUSLLjozWWFJaI397Hqq/q8eXd3AQcDOzu+dTs2ZtJ0XNI+xyPNU44Fa
         i1WMDB+IquL5zex+ex45Rv/iQRCC7cQjWX5hHpwk1ZFllJ7eSA+aCv1iU+aVy8B3dp+H
         2qlEF3PqOTjAZniIrvEiO6FOW8aiBTAb8E51ATo+FbgmCCgTZPK8w2G/B0X+gsPoopKC
         QmwFXKIVbBaQczu+iPK7p2pAIE5KXuq6/8QxlvJyHnDhNIs42/R3TUQZU1dN61zg9u65
         LNtpe8hv1Tlb0GucVA9hUP0Ds9p0MpmTcbf0iMcyXQPKKuCmQBzgz4JUAqlplLraivx6
         h0QA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwW2zLtWARd1RPGrCS1DID0u0/sIb9+Zt84A+zSYcBVFxX/JobaDbsot/+TbMzIh/ahbCBwQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywwv7KLw24CN/FMjxBDD/RI0lPMGKK+H2qkSZxbKsVPFnkUBuUw
	m7dwB7BSD5hcKTLAg5fXhp6z3eckU5n88RO96PQvOVFrwxgslVMg5gOA
X-Google-Smtp-Source: AGHT+IFN7sWqTvac7qJtSJ8QiDDlJxz8/X64ijNzA2RzOUG1EElOOzR/5RWmhYXvkTSfBhVtFySoMw==
X-Received: by 2002:a05:6830:6589:b0:745:57da:b532 with SMTP id 46e09a7af769-74557dabca0mr1098300a34.29.1756454148696;
        Fri, 29 Aug 2025 00:55:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTIvzsm9sB22/bBHOlU/MclGvPp/W4e9J+dj7W/8Mqeg==
Received: by 2002:a05:6820:a082:b0:61b:fff7:a291 with SMTP id
 006d021491bc7-61e124f7591ls500048eaf.0.-pod-prod-05-us; Fri, 29 Aug 2025
 00:55:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7URr9ieOvH3m4+wdzS/w9039i+edqQ37sU4hIohRWlKHIEjJot6VJpuL3qs9RNvxUaXj9BF6yt/M=@googlegroups.com
X-Received: by 2002:a05:6808:152b:b0:433:f07e:eeb1 with SMTP id 5614622812f47-437851b5612mr12972715b6e.11.1756454147833;
        Fri, 29 Aug 2025 00:55:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454147; cv=none;
        d=google.com; s=arc-20240605;
        b=khCUzp1/pj+A+6sgiJ/gS5I3ANU6B7hj0MpfBUr7Ydp5BZ4hrzeX+bXniBPWKLe8IY
         /18CtFd9aKP0M/wJ0c/yimCTFL5t5WCN5jaect47qM95FiXgG2+gEIujPrf+HChJmPjO
         T42PW9gcYNJXsrX498zRSFuGTCYK7BzJ5yklxIwZFDtRM+EK6ID+M685C907Z+EvZ+/T
         Va4n7H8K2mfOOpwiNR/BDDED5SWOu7DTkxaDKvpb728HxwWsMGi1oz6RSf/psHAh0+2v
         x2VRmDBoUQd+qYriq9TL3C4bos9e6UewPhaZdvGsw59SntAWfID3bPm1yG2Ss7zReADQ
         y29A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jdhbTSK6p9ht0YngyCDiyyRtcLCfpgxS9tGDrcGiJGs=;
        fh=sg1kOKdCFu7cGedIo7aYf0/XtSsOTbdCj95MyiU8ICc=;
        b=Ghs5mKzKYuqORKkhp5P80gmjIOB//PgIG+4g/W9HDzMUdPka021FId7bUv9TR4hE+2
         X/cvIjt5mSToc0sEOVgSGuglYAwtjQLTT7Ed9jxzBQPitGsG5CJ242kwJ+jIPuqG5QpA
         rV/vWu+Srmk7B3095FJluLx1isFyXPFZLt0386UybHxudoaSzFUY92tnF2oI72dPohe0
         tnEmgVEQRZlBhFjlXPJguYjHB55u8WquNt6hWIV4hAyfqIbXVMOsAZyiXwH4lT09pYjq
         eo6sX4srjpXSsD6nj4Xn1VvDAUqNwBCtn9/YgiDL9HZWhbgaP2YMtDiKvUjycOfgUz+i
         eFBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hVROityS;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afbf87bdsi126699fac.2.2025.08.29.00.55.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b4d1e7d5036so157140a12.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWIB4sR1SB6VyDHiGpdZUZRP9vmL6rWA2iZt6oscGSBQcSOkqUufHdpjNKtMisnFIt9VX1BoI+WZgM=@googlegroups.com
X-Gm-Gg: ASbGncuHTRKZX2ywekzSJZ9ixbE3NiokYigHbW/MoYJE91SdtzLXgkyFSZTmod74pyK
	GnaTAogBog4Rmu84htPxGEyIunuw/aQs24xM8qlLS/y/IUSGKe6WK3FXpOry4SOSr5e/pgU/3Pz
	8g/kQeouuzCw+G9vpMB48V6oxqHYulEvrk+MljWPFGbB2Oi5qR7kTatGBvgHtjsK27HNeJE3Occ
	s4eNmDGOccZcJDr+V63H3q/tgp9i2WoVwXSCjgPkki2iHczxiBrnvKGn7w9KEMS4QbKJ0Z3wrUJ
	m7Xf+s+KmqrwY6vOlKGRn7cEVpQ/MxIVVfNn2fk5fdzNgdim7OXLe8mvFSw0axQLUqIu+GPp9mp
	WItG8LA6sImSNwuMo235j7Bp0QA==
X-Received: by 2002:a17:90b:3a87:b0:327:c9c1:4f2a with SMTP id 98e67ed59e1d1-327c9c1642bmr4947042a91.27.1756454146916;
        Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7722a4e2f42sm1523160b3a.80.2025.08.29.00.55.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:43 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id E8F6644809A5; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 10/14] Documentation: smb: smbdirect: Convert KSMBD docs link
Date: Fri, 29 Aug 2025 14:55:20 +0700
Message-ID: <20250829075524.45635-11-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1002; i=bagasdotme@gmail.com; h=from:subject; bh=tVZea1ikNA4Sssls4g09ZchJ08JhUaFOY8Mmt8T2Tzg=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY15VZXUEfpV/XXVSre/C87lNIRyCV5IjnItu7ShZU PiphvtYRykLgxgXg6yYIsukRL6m07uMRC60r3WEmcPKBDKEgYtTACbSt4OR4WixGWdF367Ci0f0 5/VHVx3YxHrvMF/c3LtfDf1enBJSvMrwV9hALHj9kQNbWF8l9WcGsahNXW7scuzOjYlmr0LWbpu 3gQUA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hVROityS;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c
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

Convert KSMBD docs link to internal link.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/filesystems/smb/smbdirect.rst | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/Documentation/filesystems/smb/smbdirect.rst b/Documentation/filesystems/smb/smbdirect.rst
index ca6927c0b2c084..6258de919511fa 100644
--- a/Documentation/filesystems/smb/smbdirect.rst
+++ b/Documentation/filesystems/smb/smbdirect.rst
@@ -76,8 +76,8 @@ Installation
 Setup and Usage
 ================
 
-- Set up and start a KSMBD server as described in the `KSMBD documentation
-  <https://www.kernel.org/doc/Documentation/filesystems/smb/ksmbd.rst>`_.
+- Set up and start a KSMBD server as described in the :doc:`KSMBD documentation
+  <ksmbd>`.
   Also add the "server multi channel support = yes" parameter to ksmbd.conf.
 
 - On the client, mount the share with `rdma` mount option to use SMB Direct
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-11-bagasdotme%40gmail.com.
