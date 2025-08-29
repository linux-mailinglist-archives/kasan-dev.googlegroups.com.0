Return-Path: <kasan-dev+bncBCJ455VFUALBB6VZYXCQMGQEQ3CQ2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id DE494B3B4D1
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:41 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70dfcc58904sf18438066d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454139; cv=pass;
        d=google.com; s=arc-20240605;
        b=JzSf9X2Yp2qobiC7ETLx+w+NUdoIOMS8GOodocp5ZXemQhQ3Vvz76ttSxRfoOet6pH
         yZiBKSsKLeKaehv6RSvtGe3cehiIWuq0hPK4qXHovlT1s9eo79tMFeUO2Ze7iOBH4Cmd
         mm78+CH7vjdquIUvlz4tTeqJqA0m76j1qiamZjWu7QovoaWqHU+0+dVNIeeLEssI6rPF
         gCDrFz45jmuiW/W4SyDZlGIgeFB4QxEkJqU+WXL08zf9YxJvWTFVaZG1ZbQkAGOfXCIv
         230oOGmr5x+pvAQX/cmTXUdhFZNJIp5SDQBUaB1lN8hlH6PtE2HVFnnMCSMH7OlVaBwT
         dy9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=/ImTYWWLBG6pXI6UW8yLvWBr8O5exRJKbPqs2Dval98=;
        fh=YfbwOdX9tuzhY5xANR0Akbev94l7zSEyZt1s2WXVcPw=;
        b=hBiliJ+l+/2C4NTaDa3wxtcxgwSW6wS5J0ZMHtcexIgKqHD2yy/Af1/+9uIWMr45u2
         j1eBzsJkB1tJD8xugA4K1EEr7haUtO4xGBLFJvGOJ+EB60Sx1BietN3UW3vdqx+pLMdU
         SDLK5l7UE9QvoQz18jVbMSr89wxC+gs0leBUTOuOQJ/sOQqHVB6LsAaTEVQ4dfv+yoTF
         RkyIklgPiegJyp9kYLcjZuyl4y8blIMj1EMCyMps0Qpsh680ETjAKOU4msGmsNFOf32i
         v/L3YRsKViD+QF5Q8aq8C/Cr6BNlYRzdbIQhOwBSqcsAigoHDIEZ2AvbHuClz4KTa5zV
         PI1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aD3jUsUL;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454139; x=1757058939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/ImTYWWLBG6pXI6UW8yLvWBr8O5exRJKbPqs2Dval98=;
        b=PRJTlcPP3i9VHs+jK65HByvAsfw7xTzT4GeFen28y/27xLnz0ZFEsUOMOlOIBJ0Hu0
         3uPCWM5UU+tJrBSQdglzGERa7RbtbOrsouuU/S+Wb9qyJitGxq31aNFTsvxe88l4NDkN
         HzUM60k4QzWC/I14SPumUtvdnKXgBkvWaQvzf/Z9+Tw9Fv20Cfi+kg/YiInX4fWUddC8
         BxNQSEdxer3JC/ec1TPDCUXYwKf1aW/72TTmKlhyKoJAj5OVlowBPQQe/GoKLtnNGIan
         dOFyUH8jr4c0ellcgnhZBfKHU8Nq9gQvSB5BvBt63W4aZZWS/Whlm3hbjdWrbaSUSGbq
         AZxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454139; x=1757058939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=/ImTYWWLBG6pXI6UW8yLvWBr8O5exRJKbPqs2Dval98=;
        b=biu0SdS1KGcZSHFd2+A6ZGa6i52RGLOOr31ZuwQCXbhjKjZGrpsDzfMP8U2y+7RtDQ
         htPiu7j+By5uCmiKWZN8A9rwte6lKC5WCK0YGvgO4KdtaqMX5JiNOoVuqieDa4+eC8D9
         iqBPVZa3lx0LuFSGR5WRk+82SXdzcOD8ZFlFzvXJmwbW0KJC+06hXXW6A7idvHOi1Ozk
         BDVR5x5dX71uYW1/mpUSw7LDir3SLpKcGrdG7DB9cygsENAG5LLGJEHdgumEnN/Joxqz
         CRwZ3YBTL7iwjSTyhPxnKkX0rNm1yLURf6ywr+oX8itBBVeOsoz0h/Vy30gma0q2blA0
         hwdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454139; x=1757058939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/ImTYWWLBG6pXI6UW8yLvWBr8O5exRJKbPqs2Dval98=;
        b=Qc1n30PZI26nOoWDdF4g7w/ba//rzzllzwUDzop+62r6F0Lh7VrgQ8r82bD6DDWMt+
         fCKnaI4jRk1Kd6YNIsdkJwehOCXI/pVD6tbCnqKOfnYyS9+mSzDRPvYp7kdbMcObphbv
         YmLhg/AblC2/++2gQOWrbALcj9vaTrJOls4SVWoACRbwAAyonKkhJZJZSPb4XrhMFJ+Y
         Hzbu9BTsZluPt9ydHsnHd2ktxyjVIpVdzfhwivKyAvAbWP7GXI24OcL85bmeZqEkyC7Z
         TVGsC2RBENRVoEI5/QsCAoTHbzzdgEiZ8+3OdoCzy8TMwGDpdcky1tA2W/cDfnsdToUu
         LOYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+xoDNaqkz1tKRpV7TiIaprFD3s9fVQbbfxtOnCjIiz+cWr9AATTsU7+1vHi3t3I1SLhnaig==@lfdr.de
X-Gm-Message-State: AOJu0Yw6lweJby9ZOtjvqkbPtP2UucrZj3qwJF+6aXktwoFJ4N3aysyJ
	cr4H88Z+uwlBvxOGm3EFehaHR9FXupT4sQWNI9457lkGLyYtqqsyBVok
X-Google-Smtp-Source: AGHT+IGcFD6XDY3WhXzzoSJKzxRBfyx/XvNhE4T6XVXtl1PW8SFA0XWL4EMk0tqBo0+QcdttYzNTfg==
X-Received: by 2002:ad4:5ae7:0:b0:70d:7751:4309 with SMTP id 6a1803df08f44-70d970c4224mr324983586d6.8.1756454138789;
        Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcpIfqWXrjXzlsinPfLXDKbTGoPzf7a2HtGaHrvabq0eg==
Received: by 2002:a05:6214:3002:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-70df0580637ls21807226d6.2.-pod-prod-01-us; Fri, 29 Aug 2025
 00:55:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzJ/rUhWcEmMkoH2EGUz/9+59Sf2o+PnOzQoO1zO3kinIiF02K1IFiYVP1HDWaymppsocfgxTAF3E=@googlegroups.com
X-Received: by 2002:a05:6214:f04:b0:70f:9ef5:931d with SMTP id 6a1803df08f44-70f9ef5a395mr8237886d6.9.1756454138122;
        Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454138; cv=none;
        d=google.com; s=arc-20240605;
        b=bp5jDx7j9Dc0H4KaOoGmL5UzAutQ+uFZJCD2oNnaKnBij4upYjS+S6Q2lkOUer2d3m
         sR4ez9mBauXi3BnxcQ/OeFMoXhKYvIUVoVDrxJh1jXbdFRBsf29FXx+H7uPR0wyUFgBe
         +Eiu/Eqshw9S2vcLlAGN/qi1iJzVXj+6ucjD5rHIeCXxrqM+W/CrGKZHCU5q1jsHBSky
         5P2/QRtxqiOruT2AH1t2JhyE6R/QJLKJZ74HTSaXex/gB3wYJqbFwTJAwaEFfncK0v1e
         wIutNCWTK8+faSEzAu2cNQm8Wvtja4psTi83wAzmp9Y2vYAYLmNCHmB0Nxm7tO/pjtoM
         pV0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0koFSnJrv2UowuMhMeqtiJIslvN7BbZv6mHXQ/mKo7A=;
        fh=U/PG7R76wOttoGfck8pM4+gIllaFE6ZBF5dLsXK0Usw=;
        b=Tz8uE+VoMZXtMdSIOJ2Bxtl8bSH5WvUQ9O2BSP1X3rwxoVgonSvMEN5rayp4TEqWY5
         ZVdof7rEx19sEZYCPgE6X6efOzLSr+f32oZGpJsxJDvDYkgtd/M7yGyY2FjzlwPGBNwx
         Az9c0fJAXdL/mCPTegAeypIlOqucquJcoIsD5k7zGfKRTe9SY1l3FEPgCAO4Hm+tvHKg
         2yTbG1/LsbIcXxhvuQxAakpPp1pjNlCO3CM3up+tSxAs5ibD7q9kwqP+Kcw7Vt4gyPw9
         qxT48HcjE1i4y31qNn+2PKpCHTVx5hhpQMDx4Q3lHVT09tYTdIlagp2MtcSDYZqUdKWT
         H6Fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aD3jUsUL;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e4c562ac4si683886d6.0.2025.08.29.00.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-b49c1c130c9so1291808a12.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrLuecWLcZPLEQsthtAfmmnUx4ZYNKPigEr+YxXhJK6EK5eY6Dlfl/KlttFJNL74fE2LJg6rdns/4=@googlegroups.com
X-Gm-Gg: ASbGncvdrcDEo06o+tMyAXKyzQ9y2o+ZpibxEkh65+4UWiTsRxn9ZxHGZIOYMHda8Rn
	fg2pz93TGx0/aAL/uhwG0Dzak+BOp9gwcXdyEd01Z7MyXov2ye+0OoY9bPm3A2BlD4b/PDWsFLi
	CB37NA86YTKT4d+KiAnq8JmSN0u/DG2Ubdg/wIfaYHdUHmjVlF8STCscHk8RrQYl2c0f9aHQRBa
	C+zkokjM7SE71Xwq3jG1qWuYJYtqXVarXgKbf/ZN+ToLSHXrdaUrod5dsbUzJAjawnc9aRy8gAl
	4YNBO25jDUIjvUkNb+2mNvZz+yJQILPrubYz1Ni3LF2RHjjV3debRDL1C7f9iTjab4EOwKBWRS3
	OLXr+KYI4Zga0QdTaH1mGpvWgfg==
X-Received: by 2002:a05:6a20:2450:b0:243:b38b:eb94 with SMTP id adf61e73a8af0-243b38beeebmr7409312637.50.1756454137051;
        Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7722a2b362dsm1593126b3a.32.2025.08.29.00.55.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:35 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 2F80944808DE; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
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
Subject: [PATCH 03/14] Documentation: perf-security: Convert security credentials bibliography link
Date: Fri, 29 Aug 2025 14:55:13 +0700
Message-ID: <20250829075524.45635-4-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1135; i=bagasdotme@gmail.com; h=from:subject; bh=OYt2QegR/+u0q3CRKm7Zg38q7SY9D/3L6tdzv43Jflg=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY17WLH+uxHuD5TvzhcJo65MVRz8evf+ht/Kg8H3eu d3xR8redZSyMIhxMciKKbJMSuRrOr3LSORC+1pHmDmsTCBDGLg4BeAmZzL8r1qVsXFN0aQnhlcd HbX/7Z5y0OBc87cVSY827u/OC7GTfMTI8J1f/vkt1YY1nGfMLy+IOlnmXaYQu3XLZy7bCT/2T+u /xQUA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aD3jUsUL;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::534
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

Use internal cross-reference for bibliography link to security
credentials docs.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/perf-security.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/admin-guide/perf-security.rst b/Documentation/admin-guide/perf-security.rst
index 34aa334320cad3..ec308e00771427 100644
--- a/Documentation/admin-guide/perf-security.rst
+++ b/Documentation/admin-guide/perf-security.rst
@@ -311,7 +311,7 @@ Bibliography
 .. [2] `<http://man7.org/linux/man-pages/man2/perf_event_open.2.html>`_
 .. [3] `<http://web.eece.maine.edu/~vweaver/projects/perf_events/>`_
 .. [4] `<https://perf.wiki.kernel.org/index.php/Main_Page>`_
-.. [5] `<https://www.kernel.org/doc/html/latest/security/credentials.html>`_
+.. [5] Documentation/security/credentials.rst
 .. [6] `<http://man7.org/linux/man-pages/man7/capabilities.7.html>`_
 .. [7] `<http://man7.org/linux/man-pages/man2/ptrace.2.html>`_
 .. [8] `<https://en.wikipedia.org/wiki/Hardware_performance_counter>`_
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-4-bagasdotme%40gmail.com.
