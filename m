Return-Path: <kasan-dev+bncBCJ455VFUALBBAF2YXCQMGQEO5FJSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 898F7B3B4DA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:46 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b2f78511e6sf55653741cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454145; cv=pass;
        d=google.com; s=arc-20240605;
        b=VdMvj9KvvPAIJQD5WH+l63wyyDmvzzBqaKCf29uGZDCJWcIBMdtDDUV+1nj+8Lad+L
         z0XQzw6FpOeRxEbsJrKASrLajlfNTekCNuOby65NYE0t2Ka0ZGImevntAx/j0Wzizunl
         R28HsxFOt5GXW3e9KmR04anTMuk9qFWvsMdkum3v69N8EZhGnLhmtrxwbAiJo9s+oNUR
         AR9N2LJ4g9gBn+aiD4R5T4oDzK9aimwC/wZB8dFwt2B9ttdAL4cJ1jbyFxsQgFWLoRJD
         n2fLGHkX3Ncu/i01+jsi81cYzoYbpqFsXpYtrOHJ8y+HgVGgqv3VPfrC8mBex7bDfKZa
         HcHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dvsL3yEOB5PXWc/y6LOICrfa0r/HTTkvvvc9P8u+zkI=;
        fh=5ccCFXVKqRTPscerxbR1nFE7u1A9c3wIn0dIdZTHvpw=;
        b=Gzf2YOoovto6wE9fzCRUWe9KBXhaaEZV40cKGbE7AcmZ/jZfaWsuji7voyCx6513pW
         aDTPgLoAmHIC7P7VZbiiKpaz7/rgbYMmb60AgzrgiUfJ6PyCRlLpkmchoAodbrX5HKZV
         Hh3so/AoEeO9VpaLSH2BgZ3Lj6u20arFNwb43IO70taLaUzG+l6BcxHAMGodsqqwa1gc
         DSso1Yi81yNdyNNAgSima/Iug2hDgJOytkaovKlu65oittUIEttvfhYXqmiCFYEMtRRW
         PXdmUPYWDq2GTSA5gnHRD0CvFxELFVWuEKC37gsQYdr5OmQw6ez0iq/7wiF9lnvQqygi
         o8PQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CXRc991R;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454145; x=1757058945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dvsL3yEOB5PXWc/y6LOICrfa0r/HTTkvvvc9P8u+zkI=;
        b=ltVpdVBJ5LJmKkZX+XNqwxfdVBXVnQUGJxlpzorG8hHbj6qMJmw7bo0f2TMINhr19j
         3fFGMDZ21XTi2ER8cPoIg+Is1MWLK6LN4+bHuy51qaiN0XahueKWkA+Pblm6qlSz3xdR
         I/WkDOh9fv59mZZTGbeS0Vn5O1B9AGjISZdQJgFL88qrwV06dae8I+wi1bpp4JUcbCPG
         Ty+caVZ0Q4X2V6DV1gYdI8RPddZvaSkh2iOo5Tb/Foa6lNY2jlpmQrAQTt0tuHIuqWRB
         6y2wbIIGMI5q9ilqybfywdtf94WLp9OvT3lSVZJ2aVKipAN55iGp3q3b2ilc3QZ/Fo5/
         rCCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454145; x=1757058945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dvsL3yEOB5PXWc/y6LOICrfa0r/HTTkvvvc9P8u+zkI=;
        b=PiJzqoB4UrbObXXsALl6jGn52+Z1lRdZlP8BQLYQFs8EUYkF0rca8CrbZW4pzd2IA3
         JItZC7X12JFb8P8flLK83gQvMbkYJAe5f3RnPFOLgYTQY/FyoRsrJQS5zCjUuNYavi05
         NqnYORBhqX6i351yu6fRj2dnm+lm/jOmhtbqxgHiu3el+e5WSmQl/NDB5eN80yy705oU
         MTUSI6CzULt4kUiWY4KsMMG8/+MXMJ1FCyyw/skkFZHOBHgRNP0CjGvmIEFE0RWrUvXS
         03s7/80gNJTdmP+vWleFKu9VYRPM7c3J42/76I6h8K65UHR8uSKGGRfJ3fdGz7JrZALe
         nl0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454145; x=1757058945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dvsL3yEOB5PXWc/y6LOICrfa0r/HTTkvvvc9P8u+zkI=;
        b=QS8B3imSfLdnyt1bVmFYacmuHus1OGV2CY0ZL75pY44tE9s26tQhzvfV7vy5Rgywcn
         hThm5n71ZBolhhyiE13DRrJb2rYh0dlJWD2FXPHquqZdgTVgUdG5/VwRdNVeV4I6wGeK
         bfIcpRd2TlqCJN8XcySx7BeYT3zjhCGKU1kNzpUmomrGgSYuCCwgqrvI62r8dglW39Qu
         nDsJDRsQhUCynxNAYF6RnWa227bW+Yp4a1WT76D1Hg23ANeFZM9ROncy2PiYQA1FfvGs
         ad6w7z7NL3qSa/q75TRgYiaW6QBQAj+FCQjGKRAkDU5x+1F/jLadlabm9XUHPQ37KR6J
         Nvlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2zSZymH/Yut50XgxHJq0X/+xZO2b0PKegBMDPMY9GX8j3AjhaKwmM+3RgupCQJweknTDfKQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxf8WUtyeU6r+ahrEESRdi+Kg0y2+ReP/kve0srHYLlEwXuMerw
	Fzbk46r9OFhf1VuA177NUrMfOVMr+m1I3dTHiC/uwjDAiIbrooJ1xjLY
X-Google-Smtp-Source: AGHT+IHnTy8GNwwgdD+JJVnhTI4KwE3sTbn8tTFlG9GFdI0Qvm1XFeCQ0Lhse/JmUD+iFPEICHi8GQ==
X-Received: by 2002:ac8:5804:0:b0:4b3:11af:dfc6 with SMTP id d75a77b69052e-4b311afe047mr7324511cf.14.1756454144791;
        Fri, 29 Aug 2025 00:55:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe2srGXNPwrKHWZKpUJEeIHyHMxa/PohEp39u+rECPmtA==
Received: by 2002:a05:622a:1190:b0:4ab:9462:5bc0 with SMTP id
 d75a77b69052e-4b2fe8be050ls26201831cf.2.-pod-prod-06-us; Fri, 29 Aug 2025
 00:55:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxN3VIgTJ86ezvEySA2hpQWj6Y5ANjHUaJuUxT6yFgYCLKY4Oq0/1KxFTuMpsoxHEBkpwnHwEwZew=@googlegroups.com
X-Received: by 2002:a05:620a:4111:b0:7fa:ce3e:357c with SMTP id af79cd13be357-7face3e3a3dmr481268285a.15.1756454144063;
        Fri, 29 Aug 2025 00:55:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454144; cv=none;
        d=google.com; s=arc-20240605;
        b=JwyV6dzs1WACPHLyHc1tuBpl2lGHrA44ivUxWZ9hhFp3rgXNBvxJx+NgFsgByVvnP8
         R6kI5nYnePJCYHLMuTQA442OBSUJzpP/8DTTrOS0ZKsxaGfjnQbMLx8nAF2Vumt6Um9S
         8eKfsgYmoB6INiWY5sel6PRiiYaT3S0CAqTVFowRdL37LlaRT/b9QXmtRn0eQ2xUrP2u
         nwUGxYkrTIx49R+eCwuBZ8XF5CU0CjFR0g7pKhZixElxSvCwrIrET5j/MjM/yUxs85z0
         AM1tvAr6BYvx+Hi8MwTMilWZvfJX2FSUclTcqwYGAH5xaX89vLo2VAuxqkRIT1FGVwzc
         ha+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2kNx/lgQaweLHCKpOd5HxLBg5NtnJ9f3nOi2hx/97zs=;
        fh=pJpltn8cdSxvjgGUh04xxgiYJoPEb69tUhVZMxWHs7M=;
        b=ZCo093KsjN534z1ziAO1CEFkHloJwIc3RsTUdcOLF2F74NdIZZDxuf3c63WmEoVUt2
         EtITuCf731PlguONoQiPuO02tgr4hgO0EvgekeOU6iEwbb2iUyJwqlIrtp+vaXFrHlzc
         zNRBk4ZZ2YETGY0UFKUGB+U9yQZGiQNLBgqSn/ilBeAKxC/3BNgbtLIRIwSrmyryzIG6
         +Uckj1/urTz2Col+kaLpY8dQxL/hN711+QdHqaI7iCrywo3c3zwlY/uryWHobtrZo4iJ
         AXoFBW2YePMEomf5t2KwiYR5jBmjiasDSe2CwyzizyTxqJl7VN98m+KMYcZT13SrHzsk
         YFiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CXRc991R;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc0ff05a7bsi7544185a.3.2025.08.29.00.55.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-2445827be70so20891255ad.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGvaEqC1M3U0znd/6lYaDLfFZ7l+t8EwI8hzOTxezSpkk2fxyYX2o5R/Kqf2ZYJIUViYmfLtMimAk=@googlegroups.com
X-Gm-Gg: ASbGncvtugJgfd5Po0Ilt3YJqopw/9IJ4b2bTGs7NjkVeyUhV+kHnVGtv7RU3OqJlfp
	n5MlJ1rVu5dS4Lexgu6HE0EmsZvMnC+C21tgxVrUi+gPLSvBrCuKegVP2hpOdVKcLhUTuM7abxI
	lT0fGLssXe22N/3ay+IATttqgc724Wo6nIaVfQZppSL5+vLehDgb3PqLNuoUSPC8LFH2RAGgXyp
	nf7aF0IO8/ZdhU4+9kv+TRufC3m8ODwndANhwCAVnnqBsjXJ33pGMf68TN9ZqKODPq5x6xhQOrc
	y3uTqlTmyVhbsVoySMA/bdsdHlBc3BFcRZXexHNQiiPXeCt7f3yNEFwsaRFEbzd5jGdkVNNDNT9
	Qb+Gk8xugYig5DXBTVyP5m7Huyhi88RCHvEpZpI9kGk+ka3U=
X-Received: by 2002:a17:903:3c2b:b0:242:bba6:fc85 with SMTP id d9443c01a7336-2462ef4a02fmr380582595ad.56.1756454142993;
        Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-327d9331244sm1938408a91.3.2025.08.29.00.55.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id A15474480905; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 07/14] Documentation: kasan: Use internal link to kunit
Date: Fri, 29 Aug 2025 14:55:17 +0700
Message-ID: <20250829075524.45635-8-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1129; i=bagasdotme@gmail.com; h=from:subject; bh=yEY9P3BA6E4kqaGTHyjuJlgmOOGj2m2ZOET4fPd8xcs=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY15eUeC/XH99x9zD0/p/z/9z+OvEiwfuXjriUbHJw 5Al4fDvwo5SFgYxLgZZMUWWSYl8Tad3GYlcaF/rCDOHlQlkCAMXpwBMZOZehv8FVlI3eaYvZbZV FT1yZ4VwhOvUr/8ro6tZD8+s1FyQW17C8E8vzE754pXFu0SKjG4wxTc6XF7j/+Pma/mjrVH18/Y ypfEAAA==
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CXRc991R;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-8-bagasdotme%40gmail.com.
