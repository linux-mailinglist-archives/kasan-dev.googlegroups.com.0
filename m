Return-Path: <kasan-dev+bncBCJ455VFUALBB55ZYXCQMGQETDOMBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C775AB3B4D0
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:55:37 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-246a8d8a091sf38238045ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 00:55:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454136; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHTXMUOAPvmvDgCSEG65KjdJs+Z84sVLjzNUhal4W529k591RkjRl9zaF+PPfPcYn5
         jPfs/kKdSjmiKdc+BeKfcSUMclPESc4GDacHQBFys6XMnWprM0gOBKfII9Y4lM2Pgy2C
         MoW1nfoslifvimjPUkpmy85RbL8sOfpdMumml6Pd73wFoJAf/V5pQLPqEVESJfaUMBfQ
         HID3z7VZkEeowAzXMP7PWPI0S+Qu7RrkPdXuOTba0elkWgM/ZNJQIHT4+zwYlvKDGMY2
         bm3cWnJSbXOvYt8xlORMis0bSnShlsghuhqvtBMrtMHuL8WiU0LTH6MHUwcF81ClJ+dP
         ciEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QgfmfphieLdy+VrPZqXwAg/YuqHMPZi3QCMkDuSRkj4=;
        fh=DgddQB04smriDpzm33Wlrt8orWvMS5CpoCzgo/n7kgE=;
        b=YpMk5MlnXuthRW/k+FOKgfJ8BhdqH1QS0MeOz8faIfUueuI0SqnC/FrQSvHeX562xq
         l6HWbCEB3Ua/RQT+Su/uhPR0f2gGtNsiln8yvYOZDtBNH+OI8MzIW4Bap7VhhXGwZEsA
         sFmfFFntVZ/wIcGM/O9gaHFXYyFPZ/vEiu8g7We0c7Zed1wi3A9b2h31LXYY8cXD0Hhx
         dR1doprQDVE18iI7nSAHuMlz/rybpJVNq+aPpVhhua4TFMylChoHtD3WUM8SVDznHM7/
         71nBA2fG1RLeHPfYcSku1nqGDBXuapVKEwmiYpbseXjUQUPxGY6SaKlUsVCd55Id1r94
         5u+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f1tGWH7F;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454136; x=1757058936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QgfmfphieLdy+VrPZqXwAg/YuqHMPZi3QCMkDuSRkj4=;
        b=j7QmVN1NsThrl/UP7ivDbrC3ETtks2hp7lTT4H5x26DZq2Rk6k5tYghC2L59DNHyWZ
         eoM1aGQ9DES8ZG7knfQu+codvsYDVA8ED1AA6G9X43HZI6QtrRgt7xIFHpZu9vWd1TY0
         M27DqCNltcyf47HpMWKrZJt1s/HusB1dVY9+cB+tedhfI2V8lSJGnk8M+k7WdNFr80dt
         9g9o6YltkdJ9wYns+N4lkNXQ0CAGhjhFfXAEIZrUcAOoYKSDX0WVwd9DAKcTITgC1mPz
         k1nRbxYaSajnGIj4dBgJpDpuYhUJVioM2v6tRJlAnHBfKUAe5lna9TMGFxmCWUs4lwq6
         /K0A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454136; x=1757058936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QgfmfphieLdy+VrPZqXwAg/YuqHMPZi3QCMkDuSRkj4=;
        b=JK/2bgmhapvPcfUHSgVAtGNN/rtLXvvYMPo0VOPfiMDyD4RmGcdYdbwEMpysyYYG3A
         29mzJfJ559J4b8F1QNM4ZTPEge0/8hiny45lFfgVvjQgMsmeTFTojAU0dC0I+ArEXWK7
         IUAy3HzNaDDSY4ky/TVPSFLRy8zzEJlL1x0r+1FBlZQ4z6raxdL9PahtigbpHzO8eOxN
         dXPiooU3w/7TZjPnPoeJvVF8swP6bLtiEzXg45PCQ00qMzxMLzqqEusP25eTYVNSK8fM
         CtDYQJx5mqYEPUdb1mJYLKigTH9GYLTFGCKUxu7FkTdi9cafMv0o3zV83ztkaUaRjfj7
         I3/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454136; x=1757058936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QgfmfphieLdy+VrPZqXwAg/YuqHMPZi3QCMkDuSRkj4=;
        b=ps7uhW07INP4RMRqVSgmMOIZCgt9iMcI3tpooe82H9f0uroXec61gltusp52pN7l4v
         AAior/NmDZM9/0vABuyfY7LTrOLZnh7TDHgl5UNIOt/zvi7oeomx4mk9u2tlkEQOhF6w
         j5SNVfpn4oZQ7D1+S9CkbATl4WU118TzEWPvL5kA5OPvVBXRqSBwrQMvTik/Z63TIdI5
         31Yl4fq80DHZKBgE26uS3kEdt1lylL/4N62jmWumlUB+W8odmP1OkAM5Xi1/DZSac44T
         9DZxmZR66uKSXMeVcrv267OE6vayRmKyXg2Zd4P3YVW5P/GPG2/uV6ftZfnsHrEGYHc+
         cSqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPcNpjgEHkqpBGcBVWZlVBo+KF2gwoYV7QZkbbwAXm5GLjgDCHDxiQEa8RUfgU1srBmgqZIw==@lfdr.de
X-Gm-Message-State: AOJu0YyjRQR8u4oOU6CGa0S4YBbUMt9Sx9VSdSad0W94MArmkVzLrKcf
	0JxEAFqSQi8Awr8k/F/KKMG3/rq5Rcjl/MGvonRcJTmlV0WBkghUaddW
X-Google-Smtp-Source: AGHT+IFqDy+vWqXFW0azMUzKrt7wFQU8yx3voTlI7jJBhxqjx9lh0RyfB5yO3/AmRLJ4CH61p+/X2A==
X-Received: by 2002:a17:902:d4d0:b0:249:1bd6:8a2f with SMTP id d9443c01a7336-2491bd68ef0mr8196595ad.3.1756454136232;
        Fri, 29 Aug 2025 00:55:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZciDKT+5d6R7i64yfaepAEEMoW3vr0rvnVGbDKr1c6c+g==
Received: by 2002:a17:902:fa48:b0:246:7bc8:5845 with SMTP id
 d9443c01a7336-248d4b8defdls12926775ad.0.-pod-prod-08-us; Fri, 29 Aug 2025
 00:55:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIx2ug3rxbLxk1tb7w1Oy+AID1SDOqiu9Yk1LH8FaS2qq09f2wto8jowN6ZuYgJhwsVDiuj3iCcrw=@googlegroups.com
X-Received: by 2002:a17:903:2f44:b0:240:1850:cb18 with SMTP id d9443c01a7336-2462efaee75mr344339175ad.53.1756454134982;
        Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454134; cv=none;
        d=google.com; s=arc-20240605;
        b=R+0nzTh5hoUhWSpqlJ5gUVz9Mn2H8XZUnl68TvecARXz/oF6J/qowD/opmus9HgnYI
         lY2ZiQRp/x/JH/QVdo0jXjUUcgoweCLvpzEkvPFcmNpgQE/i9gO/VRh85sVvcTUmDUnD
         tCC6hWyRjaqYsSMXP6mImO4OgAG/bRD3bXOE8905M55GbJrTvPJ/e6UAMNmpS9ECA6UP
         AuKGVmaiXdsN83zQB+Uq7mujR2I04ojmYe0bKhcgHvLY6TnM/pC64HnDryoJkB3dDvpr
         D1+P7vSC33uBogT4jtDLrVWucx7kC9z85ZNM2MzKpxRW15Gk85C3LfMX/i6QyukH42Xj
         Vu/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PKHUedwTpnE+6902OLKWJUrKeeyE0icmaP4M6h8VeIM=;
        fh=EECM/1pn7zSjzWoJh1+3hajD4fmH1iBTf+zXoiuieRg=;
        b=a6rTPkurmk4dvkMeM0LfARkhLPXBf+W26u/tPfLESbWslsewCjKSGKYX/P73BmXlVj
         Bo3flWcL2Sd68fAiLPj2xh7UF0OlQ7CZbmP4+DhUEoyJfv0NBJsSJOFdTJGNQMmhEzMc
         fh0LtOH3DtbPT7IizabKssG5IDnIOsw6O6GTETtjl98TcQwwO7cr5Cmt7EGz98OAVwxR
         uksdRE2iiBHlYnAySQZ4soPwbjagWjdP+ixC3OcNJvM6MAqw1i9i8DS8+y0md0bSoa/E
         KvYJogfGSgFfB/IfczHUSpd4hZs1G3tuq2NYySLrjMMHZiefy0lyU5O6ukYTTaUB6l1/
         aFMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=f1tGWH7F;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2490371b344si809125ad.2.2025.08.29.00.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-327f87275d4so102856a91.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYjb8f3GvyIYpCNSRDwEqc+pM+YjfHdfT1Uzjf5skvbCfajkmYFS9XBollA6wBrKBSt5XdbRBz3Eo=@googlegroups.com
X-Gm-Gg: ASbGncsEt4tVOl1RsSde0MA0kygXmLyI03qiRqwvlqimOadNOaqD5/iqZgBC42ao9Tm
	Pr5zYR+/I3RAFa0kqXAFsWFcwrCQ0XaPEF5LOEDKNVMANYcIItPE5ivLcoAgcZqWvPWqHg7/Cv3
	l+JIveHk0BNg2dd26v2YqJR6geQmtiA1xDFbvyH+XZaGgOyJ0bcEUjIMQbf58XvAYQlwB0q9EFA
	F9JKCuR9M8RdUm4CKU53fiS/fYx9DQo7Gm4gAoebSH1i62TSEvPrkgphtkc6h9akqzin0HGAPAG
	cIhj0UABGYwci+PzboREHpGeiFyB8Z8B10YujZi9BEVqdN9TDoeT1Wsfu943A6qX2BY6cojwbQt
	OQMQ90B/rHqnSU9a3cwJZFRvzOQ==
X-Received: by 2002:a17:90b:56c3:b0:321:c0e3:a8ce with SMTP id 98e67ed59e1d1-3251774b8edmr32920663a91.22.1756454134316;
        Fri, 29 Aug 2025 00:55:34 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-327cf042f97sm1035123a91.8.2025.08.29.00.55.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 00:55:32 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id CE9134016442; Fri, 29 Aug 2025 14:55:27 +0700 (WIB)
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
Subject: [PATCH 01/14] Documentation: hw-vuln: l1tf: Convert kernel docs external links
Date: Fri, 29 Aug 2025 14:55:11 +0700
Message-ID: <20250829075524.45635-2-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1333; i=bagasdotme@gmail.com; h=from:subject; bh=oQ/U51BIIgNGsRun+kwInz/tmig5xTqHruGeEvNRxQQ=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY144a/JZLY81M41OfrJ5W/1jtyyro8lZM99fCflwN Zg5yrW3o5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABMpCGH4p3zu88Pdlu95fhsv /CZ2ieHwual5ab7C13i5XivpL/Ip/M7IMI9vYUN6A5f856j5POvK+r6kxCYoXlPd7vthl2/zPqb NrAA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=f1tGWH7F;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102e
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

Convert external links to kernel docs to use internal cross-references.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/admin-guide/hw-vuln/l1tf.rst | 9 +++------
 1 file changed, 3 insertions(+), 6 deletions(-)

diff --git a/Documentation/admin-guide/hw-vuln/l1tf.rst b/Documentation/admin-guide/hw-vuln/l1tf.rst
index 3eeeb488d95527..60bfabbf0b6e2d 100644
--- a/Documentation/admin-guide/hw-vuln/l1tf.rst
+++ b/Documentation/admin-guide/hw-vuln/l1tf.rst
@@ -239,9 +239,8 @@ Guest mitigation mechanisms
    scenarios.
 
    For further information about confining guests to a single or to a group
-   of cores consult the cpusets documentation:
-
-   https://www.kernel.org/doc/Documentation/admin-guide/cgroup-v1/cpusets.rst
+   of cores consult the :doc:`cgroup cpusets documentation
+   <../cgroup-v1/cpusets>`.
 
 .. _interrupt_isolation:
 
@@ -266,9 +265,7 @@ Guest mitigation mechanisms
 
    Interrupt affinity can be controlled by the administrator via the
    /proc/irq/$NR/smp_affinity[_list] files. Limited documentation is
-   available at:
-
-   https://www.kernel.org/doc/Documentation/core-api/irq/irq-affinity.rst
+   available at Documentation/core-api/irq/irq-affinity.rst.
 
 .. _smt_control:
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-2-bagasdotme%40gmail.com.
