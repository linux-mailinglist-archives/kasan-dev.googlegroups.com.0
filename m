Return-Path: <kasan-dev+bncBCJ455VFUALBB7NZYXCQMGQE3XP5B2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E6C05B3B4D5
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:42 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70edbfb260fsf7960946d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454142; cv=pass;
        d=google.com; s=arc-20240605;
        b=dbvg+eXpYXfSdqguQ40NGTDmpTroNJlJZMZGvrXCuW3IIS+eVYeOKJN3uJjvQEN20/
         Yf8DtZMTb35FB4t5lmAnIJ6Q/D+KmJur9hC3V0eny5SPEY1JUlLdzO7rRFuwGpA0HfH5
         VKIuz+I3ovlV5QjaY6yCBxADSDAzi8q4fCMIlmboZI9ZQBLnQxzUmsQM0GRc3s4f6V43
         8LE2OsvqJcTT8mruIO0mnc3ualP++HedlqwoaltsoGDAuOdYp0v2kmd6XbrjLbelfcpc
         581eBDyFW9FA0QqpcyaRmO46+LHZTzvmXM82cTner7BK1Fbyw5YjussHbdeZ0cjxKvz8
         D2zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6kpWz7SL6ECpOvZPSVTpLHRK0aRmuAKA+9OIoRMDoGI=;
        fh=eGR6GlVOyBKliueovAlEollnFSGY4yiFxchwkCPQYLQ=;
        b=RSAk4HmRHVysWUI8/8zrAaoepRkoRpQwwgIPp21T3r/3itCFpFv+n34LlUoL+VJ9TI
         K/9aPE8+C1RJAgxurkOmakH+ssH4rIa7+bVy7WpiA13KCmGDc07IKMjfsCu/nfRY/0UH
         depa4Kru8TcTS9beOBrv8Xi0KOGcOqH9UXzRslITwQX+O4BuvHiJwPBz8PlNuiUU0NuF
         YLE8MDt9aoUag8XZ65UULzPtuPa9sdav3rzb7zcJjORij0ctadKaPoU2aApiMJh0MR71
         5H22Y3+hk1QN8OKuQ7ePXcFfUEMTaXoL8hfFtkgI2qzN4JiuximFpYv1WdLaYy7lRNLe
         DL0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="F1/OHXzd";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454142; x=1757058942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6kpWz7SL6ECpOvZPSVTpLHRK0aRmuAKA+9OIoRMDoGI=;
        b=O/yrS8PsRvgPl14S8I0H6Leuu62mPkT/spUfl6rBfeK8ZdiAyMEL2qSOcIcW3kRBri
         TbtDQ3OSTe5CiG4HKjUkDDp8YTRPvlJGoxPw+5aI8JGbbgHyIx3jGqrM+S9ndmnfCwZo
         CAqXrevaexJlBgf/p2RQOftsVaqheCaEyhdq4Lq24Ir0dtZ31mCrMPfjwYgK9guoEBUv
         sgsBOIWpIKE6GLxOLVHunHNQqz9u5iz6nV+80x6OUKA1hi/5ouvPZE38ArpZQCD8nTt+
         7bmApDGMV85PWTMo0eZILLGarGVGcXswIxYlUx6mCwj6fyqRDuTTORpYzlFaSz0LH+b6
         FM2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454142; x=1757058942; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6kpWz7SL6ECpOvZPSVTpLHRK0aRmuAKA+9OIoRMDoGI=;
        b=mO/H36Lds+eNX1XPFyw6Sc+qIUY14uexJ6XMXZCelWpwFyISbPFjtD/6WR8S9MRr3o
         A5p9X3cguIM7BO9P861a1HZtp/QhC1FvCuZDezVXN7DQT4HwiKlkgqovThR0ZdpTu/y2
         Sx+U+//DvVhV5KPvmkyQQvO7La6k8LEXg7debL+8sZMU63/Q82MDWhHmNfw0pN/oo+6F
         BwH1hPZvdEVmZ5In5XE7+BN2iw/SY1mJCORb9PNBE+iP7A3lCR2HCDUgm9Wcsq7FTro4
         vMtqQirDmmmsYM6vkvwOkdmImCHaQWZ0r0FR8NOr20oYGzwIG7y85j331KPV7kZiClaT
         Mpbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454142; x=1757058942;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6kpWz7SL6ECpOvZPSVTpLHRK0aRmuAKA+9OIoRMDoGI=;
        b=ib4bosuQySuGnFXgG/W8oK0mddZlSQLaRa+YaKvsvQuaO+djftNoWLpE7PrNJpoz0c
         MavqJAejjWIJvH2e7sb3bvMKqVBfrXYgNMtQUJ5YsxUXpD+jRj9Kx1KSVaa9V0IsrCnu
         KNKRLEiU/mFr8O2PQSS3cAq3v1Zanrsyvb2MllWUabcG8rekVN40NwnBn3UDjsoodqEu
         RJWEr7Z4kNFeu5i7l3Xa/Npd5r4R+Nd9RjWDytPs3NMML/IrQLDF/kyB/zfr2z8oyc6R
         K0s59ZVUBF6HX+M1HkioUThot6+V93h+1YrGIN3S8Wt84esHF+s9TFPhYCWWQeMyd6Mx
         BmGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhcF00FQEgbLLNOgLyZlC1RoAZhPtugRKD24aB5tmiJ6sEydhrdWagqWeSjDiZwmJedABN7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzduhMfSB1j9kIRWmptHZ42edHuKBNSxlUQZAiZM6sdIor/+DJX
	540sLhM81j/k4FR38u6qHEvip7xObtQlPv7e5iNv+6eFtNn+2tVU23Xl
X-Google-Smtp-Source: AGHT+IFIOgMTM2oUn3MZw1VToqHVKR7wu4f8pDdgkzQXML7rFCMD5gvVhX1/tt1fMNEf2MScafLv6w==
X-Received: by 2002:a05:6214:1d2c:b0:70d:dc44:dc6a with SMTP id 6a1803df08f44-70ddc44e598mr139161436d6.2.1756454141654;
        Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNdztv6ybWa/4JW8D49HNFHAgOKGTxm8FXlBapidNseQ==
Received: by 2002:a05:6214:29e5:b0:70d:9fb7:7561 with SMTP id
 6a1803df08f44-70df0540d16ls24273946d6.2.-pod-prod-05-us; Fri, 29 Aug 2025
 00:55:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIIEeLx26hd6MNzn9TmFdCcCAeJCaGVuyaMlJgB2s8iMARbKmyoH5MAYjqonDOVkaP0wkU6At9XKQ=@googlegroups.com
X-Received: by 2002:a05:6122:3291:b0:530:7747:80a7 with SMTP id 71dfb90a1353d-53c8a3d7988mr8195663e0c.9.1756454140729;
        Fri, 29 Aug 2025 00:55:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454140; cv=none;
        d=google.com; s=arc-20240605;
        b=i98Z6+KyJKw5YWeXhpNiV0xMRkXDEI1aHvTjQxHyOFqLz/0F9+kqVBK59Qo26xNkBt
         ak3j8a9VSgzCJqljzOJtJrkmEz4ma+LJRKd8rXC7QmZg8fE4F4VjbjnD/qV5B1U0YYNN
         wCBZlI48zZuvyKe5/QRSV5frLbNQf1S8quwZ6BzcyD9ZLL1pnZ5Ie8Te8ziP0pNsgIQh
         b3NWSu4msEL1IgQQxByIhIgfHRUQDlMkU+jd1wfOEyZVRtzl3kO5NEVTZjz8GDxHjqCa
         vbMQOmoieULWqYjNDgms185imrcGFCYSaT1j0YkPOB2o7nu4ReWVlgWvBKamfUeiciRu
         0fvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=exY9byyl4etH+4IQEKnm6qXO5lYPceGxvCuurSN7fh0=;
        fh=ITj3OBH/jFDhtH8OG3xxgjh92v1fJBLrPdZ8un9JqxE=;
        b=Jo6vrkbY4PGUfZ+XCiLaDjSo1sTMolwflMkoGkPytW4SzuyRWyPnMH170arCOmALLN
         xtx00bdg3Cz77nJd/6Yk6j6JxOs/NmrsrsjRXYTvC/Z0u4hrJNSlNaJdKipOZD/J4iSj
         QYf73ika+qbN7QUYAWIxtX+IMzgZMBGgnCugaVtAkqRWCO64tnfN4iRW16oLxtyK+E7F
         QfVUURlpMAzvBI56wI3+p+UBpm1IGZseeR0MDsPEm2/ZGovZ1C+Ws08AuZKuir5i/ZM+
         DJ1s2dQ8FlgE9kfnS/h+I4smc86idyTYYpxnxWaaKVzZXHw1oEe/0lFj/c6RjoECIH4I
         zOmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="F1/OHXzd";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914bc7f0si37819e0c.4.2025.08.29.00.55.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b4d4881897cso174792a12.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6FscLNzjpt0RUQQwL4QhOFIKpBWHoO1ga2EvT8JMokaM5fQbCvFEnpP9axOL5Qo4aIs/epvUiZ78=@googlegroups.com
X-Gm-Gg: ASbGnctX5XsqxshEJU9elkPhTt+5P7DL9RXrzHd+3dOePTupIF5Y6hELqGQkHKFC+g0
	aj5a0ZP5UXE0/sgtfcFWvx0j+P8R7EeSo/7VtJx7j/3Wx/RZ7UmHPipaC7zOAhyV1Nm7M2YC60S
	uiiswIlou5YZ2xV+O9V6U4qJzKsbeCDQ2gW6bx6Jhp9X0oQBMBqlAaNANaNrSnMGTvQub5wb2yl
	owuAa1tGnDgksK/KrMl+KyUvqWm8NTw/Inb5fVUkHIYmP7R0kxc6i+627bMb1gORBujXXyJvNss
	AnZSKFx9mbSPEFDpGfd8COur6w7VzfcLE5Y/S/4XGoAjb6wKrsk32ZSvYOm0ECKJdqnv37/y29b
	B9fro5DBDTZ1pkbW6HYBDHzFtAw==
X-Received: by 2002:a17:902:d2d1:b0:240:48f4:40f7 with SMTP id d9443c01a7336-2462ef423e2mr373981905ad.39.1756454139603;
        Fri, 29 Aug 2025 00:55:39 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-24906395cfdsm16718985ad.101.2025.08.29.00.55.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 7A9CF44808EB; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
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
Subject: [PATCH 05/14] Documentation: blk-mq: Convert block layer docs external links
Date: Fri, 29 Aug 2025 14:55:15 +0700
Message-ID: <20250829075524.45635-6-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2751; i=bagasdotme@gmail.com; h=from:subject; bh=7QXrNRuCbHeHgCYdGUN3dSXlo+bJ6ZwXyeTt5Kf+8Ys=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY17q3TFftH6q+kyOiIzsCLYVR/ZOd/GUnnS+Yu6/k 6t6/fl6OkpZGMS4GGTFFFkmJfI1nd5lJHKhfa0jzBxWJpAhDFycAjARpWqGfwYJyctD8hT/NwY/ sO81mNZXoe/tpx8864flkqYm66Aruxn+V81fprfBrut+sv/0I1K75vi+e3t4WtGyeRzBVy1DeSv K+QE=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="F1/OHXzd";       spf=pass
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

Convert external links to block layer docs to use internal linking.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/block/blk-mq.rst | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/Documentation/block/blk-mq.rst b/Documentation/block/blk-mq.rst
index fc06761b6ea906..4d511feda39cfd 100644
--- a/Documentation/block/blk-mq.rst
+++ b/Documentation/block/blk-mq.rst
@@ -87,17 +87,16 @@ IO Schedulers
 There are several schedulers implemented by the block layer, each one following
 a heuristic to improve the IO performance. They are "pluggable" (as in plug
 and play), in the sense of they can be selected at run time using sysfs. You
-can read more about Linux's IO schedulers `here
-<https://www.kernel.org/doc/html/latest/block/index.html>`_. The scheduling
-happens only between requests in the same queue, so it is not possible to merge
-requests from different queues, otherwise there would be cache trashing and a
-need to have a lock for each queue. After the scheduling, the requests are
-eligible to be sent to the hardware. One of the possible schedulers to be
-selected is the NONE scheduler, the most straightforward one. It will just
-place requests on whatever software queue the process is running on, without
-any reordering. When the device starts processing requests in the hardware
-queue (a.k.a. run the hardware queue), the software queues mapped to that
-hardware queue will be drained in sequence according to their mapping.
+can read more about Linux's IO schedulers at Documentation/block/index.rst.
+The scheduling happens only between requests in the same queue, so it is not
+possible to merge requests from different queues, otherwise there would be
+cache trashing and a need to have a lock for each queue. After the scheduling,
+the requests are eligible to be sent to the hardware. One of the possible
+schedulers to be selected is the NONE scheduler, the most straightforward one.
+It will just place requests on whatever software queue the process is running
+on, without any reordering. When the device starts processing requests in the
+hardware queue (a.k.a. run the hardware queue), the software queues mapped to
+that hardware queue will be drained in sequence according to their mapping.
 
 Hardware dispatch queues
 ~~~~~~~~~~~~~~~~~~~~~~~~
@@ -143,7 +142,7 @@ Further reading
 
 - `NOOP scheduler <https://en.wikipedia.org/wiki/Noop_scheduler>`_
 
-- `Null block device driver <https://www.kernel.org/doc/html/latest/block/null_blk.html>`_
+- Documentation/block/null_blk.rst
 
 Source code documentation
 =========================
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-6-bagasdotme%40gmail.com.
