Return-Path: <kasan-dev+bncBCJ455VFUALBB6GLQPDAMGQEW2ZBGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B36CDB50B4C
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:44:10 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-40194dd544esf46129085ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 19:44:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757472249; cv=pass;
        d=google.com; s=arc-20240605;
        b=ir6B+cc12Fg1PDGeZbcYRfrZzJ7vJlSZEg3qJ26QJcVb0di3o11LSroR0NcBzdXOF6
         AUUWLSugK2kwMtte9KwVzIB5g9qLr46WJDxW2meon+voeZ9MFv/ShH64wnD8MIE83b4m
         r9SMiMQxL6r1ITyrsDrkfrhqpO5Lmw5cEyx03ewlPu+8Jp5ZTG9oHWULoj+CS2muYmLT
         S4de1eoHoDvBU9F90J4mA2wZEwO34l2zRYQThjdaaHDqd+OJGP47/ebPCGgq1llrgnO4
         ZiFqvgSJEbOo9PNV3AjFot7umUSw5l2BiGP3vTM4TZEF65+uPQXqQqdPIUEWW/w3bN7Z
         vfSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KV6Ze37PMKLq46EFkkKqlVZP6hyEGTrL9iKmbRO+0TI=;
        fh=kQoC42IvBnOlHGU5Rk5vbXqMH0undd6gjkTpJ7W8ge0=;
        b=SQrfrtE3ct3tfJmck5Md+Zqrf2D2zNdgTKCwvN+ROM9jLPLyXYT45wMHgTC9RRX+GE
         J102wz0b0FhwTj+v5Yn1BQbCmSO8NKPohdr+0XT0dZ1rBlBF0fJYZAzy9ZIoVB53rdiJ
         cpZPcShYclaDHkUZTQCJRQH2RAjGwrhWJB+OT7/EefgI4COI3f3Lql7vBbXhn3ijmYUU
         w5fyG50DHxhmX1RnEdMAxL4WDt3z7e2Kg05UyhAB6zOfSq7vF/MjHhHMT2YixxkaquXq
         nD78PJUZp+8SnLPl9FDH36xjZtxF4jeWxZ2XoPxeY2GZ1V+UpWX3QM3b4gMkl2y9pJg9
         DJvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bSRQ1Bcu;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757472249; x=1758077049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KV6Ze37PMKLq46EFkkKqlVZP6hyEGTrL9iKmbRO+0TI=;
        b=kyvuoJokO+zbcPAFPyheOK7CjoMZ6lqlR33a+4A5qByS8sBrwAgfPeM31zvaqcfnCo
         H/zDguL7RXJi6f/sjspydiidSGTs5AhJXN4l83O9PqFz2UsF0khcXGrgfdvf6zswle4v
         lNAtvGHDLClP2fKQ2XXQl+H6T3+2ACAPoCt4WoH7mW57PI1BVLM/L8ww7mhlIrY/XpEZ
         rloVLWtbJZzlWy5l5USVTBQjRNqTMKY88ZuGIuDsWfEVomSRsebqnRvPwviv2gZEzhqt
         nviyUyQfQLB1fNp4nvjPyfuCGMBbGzCmc2PMZz/h+cQXYdrRjgnDJRCM7+VRcJuRrKo3
         5BZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757472249; x=1758077049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KV6Ze37PMKLq46EFkkKqlVZP6hyEGTrL9iKmbRO+0TI=;
        b=jJkeX4s/KSIzcGfJDtMG6o2Y0S/rTOJph5fMi7KAB5F8IzemLmh7J+q8ab9kTXnbYx
         6g2aRWLURkrFnDv+HfRI52L2dXpx7G8SVRa2mwuXgHpC62UPlitUqus1B/wXEToY9zRu
         MiLPemXjpzpOTd8rnXh5CodszKEteK4fjNam2GpjOYFnGL8F4MRcQyRJsn+GSep14+bm
         NuHbPBdCG6KkEVePOm2zO2zFBZQN2yYENRlMlBlZtBTrMYtCwDZOewRSi07M13o+yRXl
         Xt+z7kInIZtuhWVz0JeCrU/5uCU5OLa0wKVjn4rh9NLvfDagzxZSax8jgeB6ywj5xEAk
         l25Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757472249; x=1758077049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KV6Ze37PMKLq46EFkkKqlVZP6hyEGTrL9iKmbRO+0TI=;
        b=ruMrydLNAJSMl49gDBPoeClxkkL4isGK7zIS/jmTL1ixkMBSY9U4ySw89otelBsXDP
         awkTPKYIiTExtqJ6Kah60sAZG/y2sD/U3HJAzz1Y1wQIXaFKRt0VIaaFCexqsBYUx9Tu
         YbdjypOdpL02DFBjU+HTXxGL/swE0JF0LVTTo4kz24GcZDjwXkR4Sl10e2ucp4V96yV5
         aAQZgjPVyKej1WbUBeSuVEy7mcJ7BXlvI7BO0aH3JwjijbnBs37FSfY6/nVLcwI7QXok
         ghkVC3HBNgTPgRcHIqPdcJ9u/dWFpsdBebQ2GJLY9ic1E1JyuRbB9akJFYGDQxprmfmJ
         WAhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8YItLOJvzUoOdRO1dywhjCQZIv0tM5z/Qzpx74T5HpRUPmCvIssIM2lA+0Jw87G4raFHCEw==@lfdr.de
X-Gm-Message-State: AOJu0YzvbDZqkbvjZIXPt/hdHSJuhZ+adPOGV2xMPH4PJXeWt/MIyh9k
	Z23epwNCIAS24uFMZXi9q/dnj1ATThNYMktRx4EqIA9JEhN05cfiduc+
X-Google-Smtp-Source: AGHT+IEqBU3QbU5srd5ItJLm0qnDcF/IrPfHcYI5Ol+uXIb59M0vegAHZt2JhoC9YoCRliRltV99RA==
X-Received: by 2002:a92:ca0f:0:b0:3f2:a7ef:bd88 with SMTP id e9e14a558f8ab-3fd7db98f5emr169282715ab.5.1757472249296;
        Tue, 09 Sep 2025 19:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfmKgoTcqjz7ShaLYwIQr76m3Wzl/0iGLFQspANIV9KiQ==
Received: by 2002:a05:6e02:4607:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-403efbbf98bls23740215ab.2.-pod-prod-06-us; Tue, 09 Sep 2025
 19:44:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBRZ3PXhVGN0iu0Stjc89q1WaP85JPyOAYvVkmqMJQl2L323h7Shg88h7GYi+yAX8VqgU6n4rbUNo=@googlegroups.com
X-Received: by 2002:a05:6e02:12c3:b0:416:c09f:d57c with SMTP id e9e14a558f8ab-416c09fdd57mr19106045ab.18.1757472248267;
        Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757472248; cv=none;
        d=google.com; s=arc-20240605;
        b=fZ2dmWBAyQ6vvKqFyeRX2X03KGQ3G1sW4P9ZPoZVzq8NS7Giz5aoZQr173AfrX+lLq
         IndiAf8P3wAo8+zxAmyLtaraH/XCkkpBHwUZsfvOVt8gNpyrxovTPi37C9ewAmrRLuZn
         1L5nF8EuA00KbGuq5Y1idhkolukdFppM10Ej3KFf0dLQH+2zjxLSeSvcLxXTjuN6mnB5
         LIIxdiwFSAO92e50trrsEC3SO3OY5kbWk5aRT2aVuJ0bXkOC78W+rerff5HmgdPKlL/7
         5IIj9RJ2RFr4BH70vo8DGfcTChehLlC58Dalq73jVtouq66PabPIbl+9P9vDpP52h59u
         tCYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jdhbTSK6p9ht0YngyCDiyyRtcLCfpgxS9tGDrcGiJGs=;
        fh=j42llfgPsse2W7JfZTbZoherfHRQgy5AgaWgv2/K6iI=;
        b=XF9yv8ZxLhTevvh0iRUUWJmHCjYLg6Zcswc8h+deNwahLOX3p7dlUO9lV7bi02hxBS
         uq77m+580bAFXdYH6yCJKNj7CNgrFPXVGQlSzdu3upehM7OY7gUXel5ZyoDD5yCdRbfI
         a66EKcV3RTqQIyYSna505Rg14VSHVZh7BKZQPaD2Aq4dEBW/ToIitR/2X95vf/C70HB5
         gXotPB6m8XXdWUahnPgfYhFmODU+PqZRWLdaiVJ8ZdS9qZMZmPb+l4oAlfewLHWfAIr4
         1uE0LJJRvCvp1zh0muO2wqYry9ylLIIQRkp3nv6asjMuveV3Rw87LqD5KK6zb46g5Pgi
         vGOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bSRQ1Bcu;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8f1f1f47si864592173.3.2025.09.09.19.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-24af8cd99ddso80582585ad.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 19:44:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXC7o0gMGcTqFg4zAZu0y8fnq2/Dk2s+tCWwa8Pd7zskUAyV5SQHJL6z9GEw3hkPOym/EZO8Ak8kDs=@googlegroups.com
X-Gm-Gg: ASbGncvUhfIlRRojWVotX0yd5p4dPlTl15kymOfkVl7QYJZqWfyhfUdYKXw/SLr6HBu
	OhreFCtC9MXWKjPCQdi5OzqwrnnB+uGJs26UPkMJexSXYWov0x7mtEJ81z94PgMImvqjGqlM8z2
	7eQ1WetbfYdQkpAy2yirHYHMzqvjRJhRQITUJZlQGP7A5sUy44suM/Zk71TKGVnw+obYHqxzESn
	pAus7RQBphsEL4b3JCVwV8HxHisrA5N/xAgUSi4xnnK0uEzO4SGnlktSt3y5+jkDMQGtvzuWGK6
	4bDIc5rmJG1ewuAJs26DSjr2OG61XZRt0O2m9gnYwv9jRUvsp9cRmjlxNM/cvWT3RRALPhldLFI
	PaBshG06R05xIviwdTiG67gjZjOKBEkmA0wGD
X-Received: by 2002:a17:902:e80e:b0:246:cfc4:9a52 with SMTP id d9443c01a7336-251736def47mr174671125ad.52.1757472247512;
        Tue, 09 Sep 2025 19:44:07 -0700 (PDT)
Received: from archie.me ([103.124.138.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a2aeee44esm10827695ad.134.2025.09.09.19.44.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 19:44:03 -0700 (PDT)
Received: by archie.me (Postfix, from userid 1000)
	id DC0B441BEAA1; Wed, 10 Sep 2025 09:43:52 +0700 (WIB)
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
	Jani Nikula <jani.nikula@intel.com>
Subject: [PATCH v2 10/13] Documentation: smb: smbdirect: Convert KSMBD docs link
Date: Wed, 10 Sep 2025 09:43:25 +0700
Message-ID: <20250910024328.17911-11-bagasdotme@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20250910024328.17911-1-bagasdotme@gmail.com>
References: <20250910024328.17911-1-bagasdotme@gmail.com>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1002; i=bagasdotme@gmail.com; h=from:subject; bh=tVZea1ikNA4Sssls4g09ZchJ08JhUaFOY8Mmt8T2Tzg=; b=owGbwMvMwCX2bWenZ2ig32LG02pJDBkHnihVZXUEfpV/XXVSre/C87lNIRyCV5IjnItu7ShZU PiphvtYRykLgxgXg6yYIsukRL6m07uMRC60r3WEmcPKBDKEgYtTACZych0jw9MiYfOuPx0mkkFP UiIWTa/TFphmY/DisofsPrHQd/6Zwgx/paxTd1xaG72+5ivH8bnS+nm3e6W3try5uGL6W3UVsUu 32QA=
X-Developer-Key: i=bagasdotme@gmail.com; a=openpgp; fpr=701B806FDCA5D3A58FFB8F7D7C276C64A5E44A1D
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bSRQ1Bcu;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910024328.17911-11-bagasdotme%40gmail.com.
