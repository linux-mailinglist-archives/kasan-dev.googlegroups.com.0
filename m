Return-Path: <kasan-dev+bncBCJ455VFUALBBNF5YXCQMGQE7P6UAZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C8CAAB3B54B
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 10:03:01 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3f0d4ad1c3asf25051715ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 01:03:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756454580; cv=pass;
        d=google.com; s=arc-20240605;
        b=i7lwDubV3pkyTyqWLdbHClfS0Asqn0l8CeH8xrZi1Dfcz9eDAHp2K8o+PUhpxrHK8Q
         xxMwsk4q7wi6NlkJRryVdnkU3r3lDXjqocaitwLCTqSMecfoSngrXwNzzzLUkkm7/JfI
         7zdfz1yvYWTIIUS++zfhfKJb9Mru5LO7OHmVkomXPmIffTuFUDraAMmSZquvOuADNkjr
         6z/n2HGj/SaPWcX/ksrtY1ctwAN84P+hZLT3sW4EDWPLS6KQgSqBt5Emhf5Byli6L8yr
         jC3Lu/G6TvsQ0MKHiQRFuxdILWLbNIBg6/U0gxZgVkNgs4MuJJkIq5A6JCaJhF7QJnQQ
         M98A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=qMmYfcnu5pPLYD/gMpp7nXfS41JIFxX6fx1cVeXdfmI=;
        fh=lQgua3t25FIWgWMb9dBSqHcFbaS1cIyd0tRNZN/liVs=;
        b=eBgzKVQ06UIawSjkpzZJg/4kdOlu9a+guARIkvxkJWSP8YhRKbBMNmGdoaMNXxDv4s
         erwHJbWZyVDOGTcKiJvyGpO8TCtNbl3g9CQCkkGM0HV9AJGFWFCXlvSWbaG6EoFNo/9M
         wNeq+i3zU3IezP+OsLPMu0eRdnA5vbqiRUZtiOdMSJS4AsPYfAorjxQjfWKnZoaXoElt
         47k6LSi2SzbdoPhUOVZ4OQ08IFJF3in2aBQvBvBqaf4X1EXy/JTu6quUr0GoAvyteuhx
         v658XbE9kFlIsIxLm8AzcIo7K5lxaGn/6mnePFjXp0lB7jiLdX0Qkk88hnmGj8F1tIe1
         SlcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HFhUGww5;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756454580; x=1757059380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qMmYfcnu5pPLYD/gMpp7nXfS41JIFxX6fx1cVeXdfmI=;
        b=RmohgDV3FZJJywhsLIst4i2dThthsGb6y1RagSh+ZmM2AZZXuDxbjcuyTumlwzlMh5
         8Dvcp6PA7z4lcq3PB+mpzNJQ+hz/MCp8g7MHqSYh3NKujQGO6mTupRknGFmWqjcDgJ0E
         aSn9qyLB503LSbnkKZDuVJegeU9GWqpx1ulQMe2KNIpXHDUplhUfjep3KEPM+uCMntkH
         y/kGRY9KjcYKwauNMX4Txw3G1pSgTNHPgpxf1hf2MehRCOhDhpS2/WHi4szS7cyw4/Eu
         VBsj5IAa14oTWpXWtGOIDMRFplfBkPpn3q32mxCreRkkzz4KU8/741w9lWqA2N71xctc
         /57Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756454580; x=1757059380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qMmYfcnu5pPLYD/gMpp7nXfS41JIFxX6fx1cVeXdfmI=;
        b=nRYFqhysfVfHHMezPjvpeCSUMP9XWRpMcQlui5ILpm0DrcdiwWN6rtkK5AWfBqY/O3
         7nvwa+fDIQWTCxLMv1QGtqf+zM5cotAdO8mi03JN6PIcfNbli0b7xU4OttxhyOccleUq
         ZDol/bU6Qo+8yf93mRfr1jgyV8qb9Ip3A+wfA4kftsqUp2k80lANAC9SfglmIZnQYJ+5
         iWNvycYpHCiLHa2Hx8uCKG0qVeD4Rf7uML01XyAUB5ztfm4pNh6iyCKTFYUFKgMfhQkk
         /2Z3TPpXVUsDbVhUIIxCFigoRKpDT82/BfZAOP9taKr3EqKoaa9IDTalaf+aIMR+KXjR
         kPNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756454580; x=1757059380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qMmYfcnu5pPLYD/gMpp7nXfS41JIFxX6fx1cVeXdfmI=;
        b=Sh1U3C8aDDIHbXyJcffxiRuORm8ZG2AL0r3rhrPQsdUYhcSY3p8rPoXNe2SQDkI73T
         vCRaLWPs95eBQLyLog1FAyw2SjvGMka6U+BaGJ5OxchRKovHMHbg+1A0mCJ6oT9a+DiX
         8spRsFHZeVaJG+KTW3u/sUTMyBQdGDN90WTDOID4O7vCzltaSE/O+42980GiM2tyEkPY
         R8MUZBtDfnWoZVP+lhp0bFjjB7UBoxrq6NaNapunQ6uizQSNxG8BPFfpw92a4e245d9w
         3cyQoAa1lwOM6Zp00X7Qlywbkaz7YB24Wb/ti1aN1eDXluOzEmMK61Wlxz1wEOf7xIqA
         Y0/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVc2Ex+KilzY3v2RhN4oweUkV66jJXftSYicPTilSBKecZIR8SIDHAvWmAG43kJ6EdsdlqVzA==@lfdr.de
X-Gm-Message-State: AOJu0YzZW4hFOAKH/pLOjaGSc8XhYMNUexldqBJ/CmVWP+P9afo1S9oO
	BQ+9jpPpOeLMXuQ0MXCTvlj7N1poiDB/fi/hH+dWhWs0lNB9BneZFL4B
X-Google-Smtp-Source: AGHT+IFm4027CvJkI4DikCj1OpOOBAD8wVYitgo40ZjiXbwPX37qeKKj1MY63EPPit7cLtq/N5l62Q==
X-Received: by 2002:a05:6e02:188d:b0:3ef:969c:c91 with SMTP id e9e14a558f8ab-3ef969c0caamr187642185ab.6.1756454580467;
        Fri, 29 Aug 2025 01:03:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfv7i9w/1sQ/EQICYPCE4tW4F6kfxdqMMYeU/86pqlUPg==
Received: by 2002:a05:6e02:12c2:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3f13bb1d7f1ls13848905ab.2.-pod-prod-04-us; Fri, 29 Aug 2025
 01:02:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIAlqwneeQ2ciZ1T+HjwmrCK4Dn4yUN0I1NicGnNQfm4Q4kIs5FqVCk9W5ve8HxBZ3ExWQIEpo4Q0=@googlegroups.com
X-Received: by 2002:a05:6e02:194d:b0:3ec:e669:7d76 with SMTP id e9e14a558f8ab-3ece669823emr231690775ab.14.1756454579667;
        Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756454579; cv=none;
        d=google.com; s=arc-20240605;
        b=btFFnHdljXrIxqWDc9cYLCGBza3otP7elh0DQXsEuqWLaWaVZA5Yhi55jvqs6u7Haa
         h1S8S9h78diLobj7Djlzz7Gp9Ls1K9PjUmQbPNnq38eVawKj3aqBT6+uzNTFOOJXPV6y
         Cey6h9gm6F50yzxZuvTJ/JrZmdTZIJsglQ4qpVl0Dvs4B7vAuWSK63LWTetUlBV9e6yM
         xuqp/bIeBb2FgYV+wn3fBsu23hpkRHqNn0k7RLnC91pVhlPK+95MMwKOExIL72DV9gTB
         gJVzxvMtM5MByOxb9nKmBuCDmZkt9du1L5cvOz2G41tUWQFEDaM9gnYLVmwhWxyIuyM6
         r6GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ji3KkW3qUsiM430Q8CaZBzXxSVywrfxa2oAywWyFSjA=;
        fh=HFN4IqVy0jo5QBzGfd/BcAZH1nUhQv+Y60prIDgE0PI=;
        b=OeryKzvqDi3a3AQjSQbuZXUucQp2MPjmUt4kixO3yr4FztWrKN+zNiDRtsdPQHHiBn
         KB2vfm0CZrobhdrF/w7c6V/ULrJk4bPjZj8cYP8B5TfRAeMvs2j02g+ORv7hDkcObeUy
         8wpS+VdvWk5uYibaQMzonIFbXuuuwjZfSaCfjVfnwa/pt3BSGZ3r/gJ0HtoJPhU2yT0J
         NDcyjuel45Bj0hHjY1fqYdpwdSmAHg01upK1+ZdIhkxbxL/pC0xZjLRUsLG+CerBF/M3
         UEoNUsxSTRLw6Oygdwswg2ssaFekAx4M/F16VmzJc3fhL9Q0S2Ip6I0UQi0srImGHq0o
         QcAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HFhUGww5;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d7bc5bb24si61968173.0.2025.08.29.01.02.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-327d47a0e3eso802056a91.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 01:02:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXc0WNx3KN2nGmHebjs7HgnJrmFvmSI0mRLqJzNepzYJS07syFEWMiZp1u6t+q3jMFl02Ayzdg2Ww=@googlegroups.com
X-Gm-Gg: ASbGnculo55oFSaRKRGntvsXCcVKOHvM8KXszN1Yr5fyv/KgpEfzSBMou81LEetPJ0O
	LnsmilU60A+OwN/XlYMGehJqHmDPujkYEvy0z0tD9P2Ft9t6qFGysyxr9H36pre3DMsbaw1scmE
	gGmpZdWAeMMzcSywMNq5S6X/nUSN+uoKws5ccptipG+Zqevg3pS8ViXaNX2WKO2a5YbQUPCE17Z
	CzhImzlrp+vcPR6WTDiz/GGO56pgApN25wosHgQvAITHCdCu8L4bPmXHYRVkYF4JXVLXeCD/rol
	ozwL5ZvGs/Rao4FEMsvNF5XY1qRb1j2UarAG286W4Av0owOl0+vGGzKpOSgcZtuPwfEcjafhalr
	bmIAmK9KawfO1ao7iYKuWjUlQog==
X-Received: by 2002:a17:90b:2f87:b0:321:b953:85ad with SMTP id 98e67ed59e1d1-325177447c5mr33608858a91.30.1756454578801;
        Fri, 29 Aug 2025 01:02:58 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b4cd366f95asm1461795a12.51.2025.08.29.01.02.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 01:02:57 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id 1E9654489F51; Fri, 29 Aug 2025 14:55:28 +0700 (WIB)
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
Subject: [PATCH 12/14] ASoC: doc: Internally link to Writing an ALSA Driver docs
Date: Fri, 29 Aug 2025 14:55:22 +0700
Message-ID: <20250829075524.45635-13-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250829075524.45635-1-bagasdotme@gmail.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1684; i=bagasdotme@gmail.com; h=from:subject; bh=QIAPxg2EoM7XBiBH/OfCd9SfIrsCdhbBl57WJdF7gOo=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkbY14FftK8Ic/EqPdDdzlDXfSrtOCCiCo1tq0af6f2T rxS2nS/o5SFQYyLQVZMkWVSIl/T6V1GIhfa1zrCzGFlAhnCwMUpABP5M42RYQe/RHjLfYX8tv8L 9vQt6eKUm/OnRm/3gUlFq/44pi2Xf8HI0BjxjsH0R+yFD+urVrRxaVu1SiT8M9vxwkWu7L/ecZP DfAA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HFhUGww5;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::1032
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

ASoC codec and platform driver docs contain reference to writing ALSA
driver docs, as an external link. Use :doc: directive for the job
instead.

Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
---
 Documentation/sound/soc/codec.rst    | 4 ++--
 Documentation/sound/soc/platform.rst | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/Documentation/sound/soc/codec.rst b/Documentation/sound/soc/codec.rst
index af973c4cac9309..b9d87a4f929b5d 100644
--- a/Documentation/sound/soc/codec.rst
+++ b/Documentation/sound/soc/codec.rst
@@ -131,8 +131,8 @@ The codec driver also supports the following ALSA PCM operations:-
 	int (*prepare)(struct snd_pcm_substream *);
   };
 
-Please refer to the ALSA driver PCM documentation for details.
-https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html
+Please refer to the :doc:`ALSA driver PCM documentation
+<../kernel-api/writing-an-alsa-driver>` for details.
 
 
 DAPM description
diff --git a/Documentation/sound/soc/platform.rst b/Documentation/sound/soc/platform.rst
index 7036630eaf016c..bd21d0a4dd9b0b 100644
--- a/Documentation/sound/soc/platform.rst
+++ b/Documentation/sound/soc/platform.rst
@@ -45,8 +45,8 @@ snd_soc_component_driver:-
 	...
   };
 
-Please refer to the ALSA driver documentation for details of audio DMA.
-https://www.kernel.org/doc/html/latest/sound/kernel-api/writing-an-alsa-driver.html
+Please refer to the :doc:`ALSA driver documentation
+<../kernel-api/writing-an-alsa-driver>` for details of audio DMA.
 
 An example DMA driver is soc/pxa/pxa2xx-pcm.c
 
-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250829075524.45635-13-bagasdotme%40gmail.com.
