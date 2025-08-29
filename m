Return-Path: <kasan-dev+bncBCJ455VFUALBB7VZYXCQMGQEZHOPJCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 344A6B3B4D7
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:44 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61bd4cf74easf1398936eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454143; cv=pass;
        d=google.com; s=arc-20240605;
        b=EWJ3lrzMTIDNcmcrz3LEkOKR8SIAXTu9585EdnnYkNs2Js/AUV+wLqqVNT58DWAAhO
         RY5vWhwFuOgDfeIpzLm3tFsSA0FCNxsGw+H+sr/mGfnXb4nsxpJdOw/oS3Dglrqk3OK6
         sHK+uMu5Ygha2UCUEjHzNC31q+WgSARp52idr5/D6ZnLgWj2oHfQ5f5/S2K1MKm6M6aC
         RJxZ+wTfxd7F0qVvklXfhMmBrpktnWRMtxrmPfMp271yxZdVqj0AeSixqPhRfiiMH2/d
         JJsPAQA0PDaYTbuhf+7jwMDrLTJ5wGUj+xWuALUPl3ManV0xQYTxVodfSCz4SQU3Km10
         wIPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=8+xRvo7u923CoL86ayBqL7yktImy5rg3Q3EPvpgxqwc=;
        fh=1mjK6YrRqfEHiqN9j3crR21CM8yvIr4FGtfPuPQhrv8=;
        b=lPuDM3w6RL2rF3qOkupsb6bi8CBSX+quGZeIGqG3jdyLp58y22/nGbSqNjuJFvF3uV
         N72EF3IehNICu0ysgHZiQnJKUgG4cOeMLHIBz2OGltDMSEdb6R/w5fnjGhJfA6OQgT6p
         +uNlaVQIO8ifymowAZvk7hap0n5lJfysMlhy1JhP4ByBC55bFYWnsCixfRsNkO5QfgpW
         UA65/npwpg9XdUWFul1ZWosBzID5V5o8Y3rKVEvUI731+x5YXVc/qheAOaqOf1KIXNHi
         NHI3H1qZcTwCfQT02IThfA/GShhe1x7nR5N2/2pT7huB9Cn8dXQrv2DX57+zsce3mrPc
         CzGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iNTCHJcw;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454143; x=1757058943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8+xRvo7u923CoL86ayBqL7yktImy5rg3Q3EPvpgxqwc=;
        b=BRly6VdmOca4f008zTIsO4glMQfOlNb6cdiN6vOVq/VxX/R3Orw8ns198DINU2iHbj
         rYDRkBLI2yemBJSssL1sAJbfrnM7pdyfpL6/5QviFJZdBd/GsO3cYUFoJUeCFqrffOWE
         66MP1PGa7Gttiso9gRZO7H7DuBNq/gZzg5TFw4si9fzt2WO/COktleUrtzxEoxfNLxfl
         Z2fkY8L/2RETntley3hirGb00reruc/DKSYCBvtVX2vza2JyVZceSH2c147wCG4e57T1
         XY2UUeieyarnp1Aq7BKtYH2o7hgOKZnvQ1Kb641LWCdnF4ISenPoKu0L++m+HkfB7bfa
         KIlQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454143; x=1757058943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=8+xRvo7u923CoL86ayBqL7yktImy5rg3Q3EPvpgxqwc=;
        b=lhaormubvGfmeOx+nY32mbAC1KVBhcASuAnHVWhpzj4LFEbqxtlQb09gLc2H0SzdTz
         LZ/o6TXzx++uHGockEyP3vSNgknMPB4fE55pvji4mALzeFGRboe+V0CAu5mPAuN9Qlu6
         16GzdikO0qtEKlnnE4vvQzRzjvia9XwDs6HqOiP8yRMNPMV7n8n2gQuo/0hJ9z6ZQF2n
         9Z+GxOVr9cY7SISivkKxJLmsKdqrubV9iB67ZFvZZoDBSXxTW6PID01iixxcOLvF3KhN
         U0BpJFplWNyuSARuyCs/172+g94uosXBjPY+P9dhXWj2DdUP60FFSTOAAKJlJnaXyIp0
         7KSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454143; x=1757058943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8+xRvo7u923CoL86ayBqL7yktImy5rg3Q3EPvpgxqwc=;
        b=PKoMihfqUpq0+ljw4GFHDn+G3PVlPLGQRQ8BYuXbzZmNnRK+Pn8l4hPVslhmOgUa/7
         8jIasuuDPb+03mI3XC8d4v1U/xaAqLJPH2Bd+addjScZGuMrMehWYfLc7Puff1tgnyQY
         QTr5/C/S92xlF/2bysdO2lZLeoJL/DzHBGipwvy/DXSvlZbYn0XJElPoZJnVE+Lcbnxa
         2i2LVkiZ/Dc0wGWww51N7d1+wyqIDmz4IFHF/SrJ+NfMgJIpIJfRFsuBLLTgboTwiL27
         i6E6TXs/3Hs0hCyuuwmrJOKTCfam9oOZRbXHBdR4ONOhwFgEKwnoVpxjtE25OaCmotKN
         oWtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVd2MOhQKLsOd2VCrzkXzxHnojZyh9rLVE6CMAV5nzajKcshEvaH0r0neIFX6Yw9BL9+UebEQ==@lfdr.de
X-Gm-Message-State: AOJu0YwmNNWGmpUxkR2Cf9K3pbS4jdhIxIX8/F21YXAwZ+n9PK+Mhrrf
	+l4BRwsFsnhUEyYyV+OuUqLTvDYK6m3VC9d4e1OPpo+Varfh2gxc7IMn
X-Google-Smtp-Source: AGHT+IEYuA3lw5sr4Z/jwlOTOB+ytUbFnEwj1AeBZV9D+IJDC+gsaIh4qAbnrnBTieR7TgetQE/udw==
X-Received: by 2002:a05:6820:812:b0:61b:7d22:d55e with SMTP id 006d021491bc7-61db9ab1364mr14227314eaf.2.1756454142778;
        Fri, 29 Aug 2025 00:55:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeeKwP+arramGe1KjsstAT7/tzGryneEb8mlEHjDNgrUQ==
Received: by 2002:a05:6820:c083:b0:61c:477:c6d5 with SMTP id
 006d021491bc7-61e1274f577ls280527eaf.2.-pod-prod-09-us; Fri, 29 Aug 2025
 00:55:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXec4HYyfQZkkCkAl8TRC62/eAiZ2SskvljLfk/Ar2UNFAimWZxJDfOcbNQBINtR8qkJWpcIcpo6BM=@googlegroups.com
X-Received: by 2002:a05:6830:64cb:b0:745:49ef:d74a with SMTP id 46e09a7af769-74549efe9c1mr3080459a34.26.1756454141169;
        Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454141; cv=none;
        d=google.com; s=arc-20240605;
        b=NGxLokFrWnqXbM0Rkfbs+RB3EvJ8PRZ9Kg7+eXqY04MGVfnj99lsc6O0zPCC0blMl5
         aFVkQ0DIL7Eff9eeQMzAMMOG6Z75VpjgIGb8A65ZyP8s1Yw6nd4mQCKedFlpMHqpqFB3
         XiIRH8f+F930kvBW2pJJXAyWnDtQFW67L3rhmZMEPz3tsTc6D5Kf0hcjrsjmXIxDbGUJ
         9h8koLLaYWVQCVWbvJQJ6XHyK2M/q/kYbF9E82c/0wZe6hhtz8ougOmO7tNS74ombGLN
         kIXVRGnGbr8w7pXxYEYQa8BzIH90cTnn1NKxUCNq3w3j1V5s6EZg/UtHHxa5NYvmtMTg
         wtog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GUuceR9E3vzJz5a/JHCoOJAb1uIOOWcnyWbxLYGhp7M=;
        fh=5e8Mf1JYZjBjDnSk1VUdeFTR8A/Zzjl4Ov7ouCT7Xok=;
        b=gZeRhXVaPJT64ql2+2eMKNcrZq12dzO1HCdIzyPLOZtAtYmpt9FoLAqyQrz+FJ2caR
         o/B2wiJBoDV0xONM8xxUNwCpaUL8qgerDPQi2YviXOYQlZLXziY8RdeAp+qx+88X0C2X
         7rpMhWrLFtixNAg7NoyjxPSh5UpYmT/hwNWnItUsYxW9ODcGTQF3BK+mAJQ+ZT+agjyz
         T1gEBh+Y6njC4FC+kCMr5g9HfMdWzG5/BRfeExJ1V4WE+7AkEcaq70KICRDieTcEYD8M
         QaixhDM9BlqepKEuL4tFLEuyD9Ig7gzDfWs2cKsD+xBDbk6rmSGEo/z7YniXChF3YfUE
         uYsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iNTCHJcw;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afeeabb9si127916fac.5.2025.08.29.00.55.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-2489acda3bbso14143055ad.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBFNiXNeWxfEruZJUbgevO+LV9kvCIjcrGZn6YSEwNuZtDDhVC3SxCyP0JFGRIqx+piagt2/Ruq9o=@googlegroups.com
X-Gm-Gg: ASbGnctcdZhm7qmSVO7/4CAvayO3CdYPgHTobk612JjMbrWMjr+maNyqD6Qd5rqgfss
	zk52pv6kLk7WjxoAYb4ukv4Sk/9loJ7OFQ/J/spuzOHXdOn7f0XC5497LDaZL1syYSWgJ20k8WK
	KV2vBTXLtmkf0dk730xGJGyDFMDqN3JapmDo37OlEgZYGRftR1rlzTJ8yJRW3SuAZk8YeHoo2Wr
	UrnXsMJwGxuSP4Z0lqbsr5FGSnJd6mkG9n1SyQPQ3VAsZo/+ClwzPx9SnTctvVg50do9XZKQkEz
	9jiH2davr9G4PyubINMk5s1QYh2lCnURavbCBg3+VsDhIicfJ28K9/0zj3jM51BQJEjWJX08Ex2
	M93IJUkqJzY/KOtNsgIlYcO9JvRVoKA5LgpnF
X-Received: by 2002:a17:902:dacc:b0:248:96af:518 with SMTP id d9443c01a7336-24896af07d5mr127952805ad.59.1756454140172;
        Fri, 29 Aug 2025 00:55:40 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-24905da4d5bsm16781545ad.94.2025.08.29.00.55.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id B95C34480990; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 08/14] Documentation: gpu: Use internal link to kunit
Date: Fri, 29 Aug 2025 14:55:18 +0700
Message-ID: <20250829075524.45635-9-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1122; i=bagasdotme@gmail.com; h=from:subject; bh=lGvjj6RPPbr58GqrWqgYvJfKnQd0kE/Khje7rmfw55Q=; b=kA0DAAoW9rmJSVVRTqMByyZiAGixXOmjSTNEt/JFR6AhPDWfGCcGj/Np82/Az7wMJic3oIar2 Ih1BAAWCgAdFiEEkmEOgsu6MhTQh61B9rmJSVVRTqMFAmixXOkACgkQ9rmJSVVRTqNRJAD+IU+J KWDSPb94prUVj+FntqxPO7boU221XL2jEkITc6cBAKhpWT1CuLYVAMm4rv4hGzdOOa9sljkO4cB hdLolzx8O
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iNTCHJcw;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::629
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-9-bagasdotme%40gmail.com.
