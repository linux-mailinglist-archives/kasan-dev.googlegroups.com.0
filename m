Return-Path: <kasan-dev+bncBCJ455VFUALBB4OLQPDAMGQEB4UHRXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C188B50B41
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:03 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-4141a91a7dasf12971855ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472242; cv=pass;
        d=google.com; s=arc-20240605;
        b=DS8IK6iafpHnd8J8dUaDSAlKAOIvR0c/0BSsWc6e4at41zwKpRL405ZTWGYVizjQLl
         d5uF7qf4nJnynuCC16fJidDW1aHQ33iD+8EKyfgRFUEtb5MPHyllXoLBJiULILCDCdxo
         XmNic2XNmdvvVMqL7lYF3scOR/vsiTagaH24XtlaICioplYaX07jueCa40CdtLovfaEJ
         22J79A66oyiSUUc9Xw7T08fW/O6d4lWhCDugKqnrMvE8A5YwzLrGOw5NKAaWHI7kwThF
         d+x8o1tuLDUk9H6YICSLuCrHLf6UWvQpJWJLkyynsLvtJrSR/jzYFzbTv8PWPeAPa05Z
         qToA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=j3ApeVlzaAcdlixCjUPq07BD8B/IWcCqj8OhQ9JM+dU=;
        fh=PERqJZ6M8R4u8svoI5yQlOMxKBzhtBLxVLxNpuVDfKw=;
        b=Jjshf3pu4dEBL+f+tt+5K4Cxnr3LMLepce9N7p8VrXVV9wCmwZmuDMMYGHEZzALpaX
         5BBtnQt758qRuSPew62XZkByVBMtCnVeUtcloSWeT+XfuFNOvKVEgTkm2xrxcmmErJ7N
         VBybbDPp5gDXfD+2YMaiuNL/vkSnTou7yNFqTbwGM6myw0SiJAeoevCnSz7o0d1VXScE
         Ih60/L8XPDTsXnJcr/cRYBVG6r2HsfVRLT9Gr65Kxom9u1cjYJPjXkkQ0GUdg/PdW5n3
         LDipjEz+o4WzZAWHvtSF7ITIuudLRoC8ksHWllr5zUvvJhbmtHCSr70nJnYQkK9XGGTf
         FHHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fQrXFe+R;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472242; x=1758077042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j3ApeVlzaAcdlixCjUPq07BD8B/IWcCqj8OhQ9JM+dU=;
        b=BsXza0E55+2if/kRLNxi6/pXGO8dNh8H1ECoJg1gBFTtXYAecD9O3Q8O7SYnRm3OPY
         RO21kidKEUAsZ/PS9MOcK4spZMTq7YbNLpUjsP0gTHebdLlo5fEYoAsLyVUYyRMY78aQ
         r1GUMhXAubtlRFDIwbhmnmJ5ABwFdxk3+3PCJ2ngpgmVHRmZ7koPK5PgdKqmGqgcm++t
         EPF9BkN/tkpV2TnlPDB96hDVJyFwMhC0uzn+sO4DENe+V1vqJHwGNdFj3hngi+oyPlV9
         9lCaEKQzGQG2NMTHINbzPJgTevkZZm7JYGtNioIa7Ydvy+ZCcrZYBoz2Pv5fuCixh20Y
         2x/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472242; x=1758077042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=j3ApeVlzaAcdlixCjUPq07BD8B/IWcCqj8OhQ9JM+dU=;
        b=M196xy34NyDsgSj1aGrDw1954CxS/X1JzmavOGLNDBA/GMhtUgkHhslousfV77hhkp
         gOQykf1uabfio2LIMOl+7+2quhRrzpaBRYoXqF55/szGpVoNk/ObAor4s5rE0ajhbUGT
         XD81hQAgjVOAmJPzyCHcfAnlhklhhHbgOdKQOxKnKCAeKax6pmwNd/P6wywr+NC7w3FD
         qEj1kR7cZp+tuWPbXjAIPL+3dvmC9jtOBWIhc8Sh+dGiFdkjDXWNXDerMcCayMYL+URI
         +MqDBh1LC4KMFDERywQc43t7G4E6yc86uaawEcAqfaEMdxoLbmE9N3tTDvxjjsMxIKFp
         peZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472242; x=1758077042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j3ApeVlzaAcdlixCjUPq07BD8B/IWcCqj8OhQ9JM+dU=;
        b=p/Saa+wf4ZHiKOMHX6QLYQMJmSFks4G0sZDmifKHbqzwtqHUauS3jnt0iZEpLWlc3E
         2AXQBJXUy6sS4wn7dJ0zWl6g+u9BJr4r/Q0jCVJZywe/7LACzj80ebMPL0F9xsL9ANv4
         U0Gp98hN4PP+JXyy9AQQP1be5H7tApIIFN1wc3drr/veZyZxqnmyyEAiOoX4A7/F55G6
         QE2GW8Pjl8gJYZ4aoX3iUAtxbvip8xpLr4Rvdt79pFXqbEoxLagESK8N4vPw2HZld245
         vrAEb7DxIxsUDvnjHnloHHYJy9fVo704O5efYlv/UisfDl/TWJYR3qvXXfdW5plWZEBR
         /4Hw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUs7L+ZAPrkkTVyuSrH1LEdiWUMmEhcU2fagL4ks6tsO7WlOMqPxXGPwBJSN8CaMCwx/58D3g==@lfdr.de
X-Gm-Message-State: AOJu0Yy8DGEWa7ImPeoxyhft+zKUOg8PZhyr5zxQjEjq1csDg1+bLLX6
	z9fR4UQ83/F6p/52q6tQb0iODQ5Mvt0LCCdil5+0u+KFOGeP+SbqW6I2
X-Google-Smtp-Source: AGHT+IGQpkwAt6C1M5OjOx0FKZg/YI2oShLk/XBdNDArKQHMKFX7J2qKkb6JU89ymABJC55eSpcdFw==
X-Received: by 2002:a92:c26a:0:b0:40e:adf8:ca2a with SMTP id e9e14a558f8ab-40eadf8cc5bmr95136985ab.6.1757472242264;
        Tue, 09 Sep 2025 19:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZexE2oxUdf9XWRTcXThztX0jbsdN663PdDr5VZeymzWXg==
Received: by 2002:a05:6e02:4512:b0:3f0:8c08:16f5 with SMTP id
 e9e14a558f8ab-3f8ae2722c3ls32113785ab.1.-pod-prod-09-us; Tue, 09 Sep 2025
 19:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRuhzsEoDiYmwGgZIH+K9X+UPsl3jECpzs9O6267XA0umelkR+9ImKaL0IDGshjsJ6OyKJEJ+hoxE=@googlegroups.com
X-Received: by 2002:a05:6e02:2198:b0:405:b792:32f0 with SMTP id e9e14a558f8ab-405b79234cemr151902455ab.32.1757472241196;
        Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472241; cv=none;
        d=google.com; s=arc-20240605;
        b=QdWU8C7/7vsJoa7QnMXLYx5e+HuGp3Z6+eoxW3iznqk1wisrafo5beihexwO1UO3K5
         jeEvV+Esi4xbxu87GApzkA3AehwdI1rB54135I9JEW3Qr67/fyq+FOx4IAftqK9yD7if
         buOn5pDE1YgVkhQRzFPGV+Ri38I8LnAHyo8g2fLLeg1snBgBAdfCV4zVigSL6QRGP9Tf
         kU0UbzKvYvMKhq0uBtpEUzIZbz3N8A9DlEUWwGDaWjYujBzlDrMtTz15dTXoBvXAkr+c
         5/2SGPskfSODLzR1dtZ6aU/Ao7rjOuxkl/8kC8VObw+6Wjk1QLCQcSqa7pQy+46aDQPh
         av2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=isRfEajvq74JD8Gx5JZkbk62qSgMtw6IJwcPrIolSGc=;
        fh=q/0+zVgwHa0NpViHU/OXuhycxmN4xtQi5qdsapZxW/o=;
        b=JKtUG617S/0INIq045CMBDLyGb49GlQvxjTbh49DpymIxiTAinhYCm+MrzgFeTs3to
         civdkvNBBl0359dGw/GAG0GJtQeSJNDcxYKyNzfZaBruKEEtJ8QGNB2+OnW2yHa2DXQG
         Zovt272uL/zBMbIprcC4IOqtC5kVoI98fRDHaP6DYxB2i0fYF5HsUM0NI56ON+RZSbx6
         Iug22175NLD79y7ZjmSuDMkKH01a2AjUvfrD5tyJ1hvSTUbShpInMh+GxLc6jHu3QTlu
         dlYvwmgmlRIo5kunNeMevQsFLo4csYuH4kkEGmTB1k1gBv4EQsNX7oBV7qBEYw1Irerr
         mSbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fQrXFe+R;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-406b652dbedsi2517295ab.0.2025.09.09.19.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-25634c5ebdeso31062685ad.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHvWYZ0RWUBlF2FbctmNWwS+E3bE45kPrf02e6LHEDae7y6xO6PtZrOEqrQ6yYxyIrlIi7fsc8WIY=@googlegroups.com
X-Gm-Gg: ASbGncupfKx/eJKfbvwdyget9tefUyINMpHUaiAP2OlRhgIgOduZW5uZBNarxACG7F3
	ZGLNiXos/nzBbHyDQU1Qq5P7DmTiskr8I02JBCL/LssFG4sug7WZUBtwnWRvK2Q3ML3SWv6K6rc
	V5kDmjvcCuNUgfikuDDhFhpQXhL/alI32S284SYE+W1CuFLrIN3N8ENEfdADziI7vBo+I3S7pby
	8jCBIKhw/Hq+h2BQNU9aspVJE+MQhwZA4Nnn2YiofPK23ygNrwasFj//mHBLzZz6pbJIRExX0mj
	fFYHsNd2E+CwvUv3Dv2m/whkDBOtS0w1yxYR0s8O0JZxdqpSREAGM8RFPfKtSbIjow0ibGn45UE
	mT150KzBCAn5rsffMM3fA3/jMNg==
X-Received: by 2002:a17:903:2350:b0:252:1d6e:df75 with SMTP id d9443c01a7336-2521d6ee123mr177312055ad.41.1757472240600;
        Tue, 09 Sep 2025 19:44:00 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27af540esm11471515ad.47.2025.09.09.19.43.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:43:58 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 4B76441F3D85; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
	Jani Nikula <jani.nikula@intel.com>,
	"Mario Limonciello (AMD)" <superm1@kernel.org>
Subject: [PATCH v2 04/13] Documentation: amd-pstate: Use internal link to kselftest
Date: Wed, 10 Sep 2025 09:43:19 +0700
Message-ID: <20250910024328.17911-5-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=945; i=bagasdotme@gmail.com; h=from:subject; bh=Rg8Js/mQ+ji0aVDnd3uUR+wPkIV7f8cZoyAXSG+WzrA=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnihuCjbtUDpafXJnbOHtXRdvzJjhG/D0b9KEh6svl Jx1Ocjf0VHKwiDGxSArpsgyKZGv6fQuI5EL7WsdYeawMoEMYeDiFICJSHcx/FNfPsFU6huDt7vJ kh1V1uZRLxRT1SOqp3E8VV6+6XDdK15GhiW/r34XtloUdOCT982MLd7bz2VGXmhWZatxbn38c0u qDSMA
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fQrXFe+R;       spf=pass
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

Convert kselftest docs link to internal cross-reference.

Acked-by: Mario Limonciello (AMD) <superm1@kernel.org>
Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/pm/amd-pstate.rst | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/Documentation/admin-guide/pm/amd-pstate.rst b/Documentation/admin-guide/pm/amd-pstate.rst
index e1771f2225d5f0..37082f2493a7c1 100644
--- a/Documentation/admin-guide/pm/amd-pstate.rst
+++ b/Documentation/admin-guide/pm/amd-pstate.rst
@@ -798,5 +798,4 @@ Reference
 .. [3] Processor Programming Reference (PPR) for AMD Family 19h Model 51h, Revision A1 Processors
        https://www.amd.com/system/files/TechDocs/56569-A1-PUB.zip
 
-.. [4] Linux Kernel Selftests,
-       https://www.kernel.org/doc/html/latest/dev-tools/kselftest.html
+.. [4] Documentation/dev-tools/kselftest.rst
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-5-bagasdotme%40gmail.com.
